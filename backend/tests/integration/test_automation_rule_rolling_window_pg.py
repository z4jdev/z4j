"""PostgreSQL arbitration for exact automation-rule rolling windows."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from alembic.util import CommandError
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, inspect, select, text, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from z4j_brain.auth.csrf import CSRF_HEADER_NAME
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    AutomationRule,
    AutomationRuleAdmission,
    Membership,
    Project,
    User,
)
from z4j_brain.persistence.models import Session as SessionRow
from z4j_brain.persistence.repositories import (
    AutomationRuleDispatchCandidate,
    AutomationRuleRepository,
    CircuitDecision,
    dispatch_candidate,
)
from z4j_brain.settings import Settings

from tests.integration.conftest import _upgrade_integration_database
from tests.integration.test_migration_pg import _run_alembic

pytestmark = pytest.mark.asyncio


async def _automation_schema_manifest(engine: AsyncEngine) -> tuple[tuple[object, ...], ...]:
    """Exact ordered PG columns, constraints, and indexes for 0014 objects."""
    tables = "'projects', 'automation_rules', 'automation_rule_admissions'"
    async with engine.connect() as connection:
        columns = (
            await connection.execute(
                text(
                    f"""
                    SELECT
                        'column', table_name, ordinal_position, column_name,
                        udt_schema, udt_name, is_nullable, column_default,
                        identity_generation, is_generated, generation_expression,
                        collation_name
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name IN ({tables})
                    ORDER BY table_name, ordinal_position
                    """,
                ),
            )
        ).all()
        constraints = (
            await connection.execute(
                text(
                    f"""
                    SELECT
                        'constraint', relation.relname, constraint_row.conname,
                        constraint_row.contype,
                        pg_get_constraintdef(constraint_row.oid, true)
                    FROM pg_constraint AS constraint_row
                    JOIN pg_class AS relation
                      ON relation.oid = constraint_row.conrelid
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE namespace.nspname = current_schema()
                      AND relation.relname IN ({tables})
                    ORDER BY relation.relname, constraint_row.conname
                    """,
                ),
            )
        ).all()
        indexes = (
            await connection.execute(
                text(
                    f"""
                    SELECT 'index', tablename, indexname, indexdef
                    FROM pg_indexes
                    WHERE schemaname = current_schema()
                      AND tablename IN ({tables})
                    ORDER BY tablename, indexname
                    """,
                ),
            )
        ).all()
    return tuple(tuple(row) for row in [*columns, *constraints, *indexes])


async def _seed_rule(
    sessions: async_sessionmaker[AsyncSession],
    *,
    name: str,
    limit: int = 3,
    window: int = 3600,
) -> tuple[uuid.UUID, AutomationRuleDispatchCandidate]:
    async with sessions() as session:
        project = Project(
            slug=f"automation-{uuid.uuid4().hex[:8]}",
            name="Automation",
        )
        session.add(project)
        await session.flush()
        rule = AutomationRule(
            project_id=project.id,
            name=name,
            trigger="task.failed",
            conditions={},
            actions=[{"type": "notify"}],
            max_executions_per_window=limit,
            window_seconds=window,
        )
        session.add(rule)
        await session.commit()
        return project.id, dispatch_candidate(
            rule,
            project_revision=project.automation_revision,
        )


async def test_postgres_concurrent_claims_share_one_locked_budget(
    migrated_engine: AsyncEngine,
) -> None:
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    _, candidate = await _seed_rule(sessions, name="bounded")

    start = asyncio.Event()

    async def claim_once() -> CircuitDecision:
        await start.wait()
        async with sessions() as session:
            # No test clock: production samples PostgreSQL's wall clock after
            # taking the arbiter lock, so replicas cannot age admissions with
            # local process-clock skew or a backdated transaction timestamp.
            decision, _ = await AutomationRuleRepository(session).claim_execution(
                candidate=candidate,
            )
            await session.commit()
            return decision

    tasks = [asyncio.create_task(claim_once()) for _ in range(16)]
    await asyncio.sleep(0)
    start.set()
    decisions = await asyncio.gather(*tasks)

    assert decisions.count(CircuitDecision.EXECUTE) == 3
    assert decisions.count(CircuitDecision.TRIPPED_NOW) == 1
    assert decisions.count(CircuitDecision.TRIPPED) == 12
    async with sessions() as session:
        count = await session.scalar(
            select(func.count(AutomationRuleAdmission.id)).where(
                AutomationRuleAdmission.rule_id == candidate.rule_id,
            ),
        )
        persisted = await session.get(AutomationRule, candidate.rule_id)
    assert count == 3
    assert persisted is not None
    assert persisted.cb_execution_count == 3
    assert persisted.cb_tripped is True


async def test_postgres_exact_window_rejects_boundary_burst(
    migrated_engine: AsyncEngine,
) -> None:
    """The half-open rolling boundary is exact on the production dialect."""
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    _, candidate = await _seed_rule(sessions, name="boundary", limit=2, window=60)
    base = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

    async def claim(at: datetime) -> CircuitDecision:
        async with sessions() as session:
            decision, _ = await AutomationRuleRepository(session).claim_execution(
                candidate=candidate,
                now=at,
            )
            await session.commit()
            return decision

    assert await claim(base) == CircuitDecision.EXECUTE
    assert await claim(base + timedelta(seconds=59)) == CircuitDecision.EXECUTE
    assert await claim(base + timedelta(seconds=60)) == CircuitDecision.EXECUTE
    assert await claim(base + timedelta(seconds=60, milliseconds=1)) == (
        CircuitDecision.TRIPPED_NOW
    )


async def test_postgres_admission_uses_post_lock_wall_clock(
    migrated_engine: AsyncEngine,
) -> None:
    """A pre-existing transaction timestamp must not backdate admission."""
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    _, candidate = await _seed_rule(sessions, name="database-clock")

    async with sessions() as session:
        transaction_started = await session.scalar(select(func.current_timestamp()))
        assert transaction_started is not None
        await session.execute(text("SELECT pg_sleep(0.2)"))
        decision, _ = await AutomationRuleRepository(session).claim_execution(
            candidate=candidate,
        )
        assert decision == CircuitDecision.EXECUTE
        await session.flush()
        admitted_at = await session.scalar(
            select(AutomationRuleAdmission.admitted_at).where(
                AutomationRuleAdmission.rule_id == candidate.rule_id,
            ),
        )
        assert admitted_at is not None
        assert admitted_at >= transaction_started + timedelta(milliseconds=150)
        await session.rollback()


@pytest.mark.parametrize("authority", ["rule_edit", "project_kill_switch"])
async def test_postgres_mutation_cannot_overtake_authoritative_claim(
    migrated_engine: AsyncEngine,
    authority: str,
) -> None:
    """Claim waits for concurrent authority, then refuses stale selection."""
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, candidate = await _seed_rule(sessions, name=f"race-{authority}")
    claim_started = asyncio.Event()

    async with sessions() as editor:
        if authority == "rule_edit":
            await editor.execute(
                update(AutomationRule)
                .where(AutomationRule.id == candidate.rule_id)
                .values(
                    actions=[{"type": "cancel"}],
                    config_revision=AutomationRule.config_revision + 1,
                ),
            )
        else:
            await editor.execute(
                update(Project)
                .where(Project.id == project_id)
                .values(
                    automation_enabled=False,
                    automation_revision=Project.automation_revision + 1,
                ),
            )

        async def claim_while_mutation_is_uncommitted() -> CircuitDecision:
            claim_started.set()
            async with sessions() as claimant:
                decision, _ = await AutomationRuleRepository(claimant).claim_execution(
                    candidate=candidate,
                )
                await claimant.commit()
                return decision

        claim_task = asyncio.create_task(claim_while_mutation_is_uncommitted())
        await asyncio.wait_for(claim_started.wait(), timeout=3)
        # The edit/kill switch owns the same row authority as the claim. If
        # the claim did not lock/revalidate it would have completed against
        # the old state and admitted an action before this commit.
        await asyncio.sleep(0.2)
        assert not claim_task.done()
        await editor.commit()
        decision = await asyncio.wait_for(claim_task, timeout=3)

    assert decision == CircuitDecision.STALE
    async with sessions() as session:
        count = await session.scalar(
            select(func.count(AutomationRuleAdmission.id)).where(
                AutomationRuleAdmission.rule_id == candidate.rule_id,
            ),
        )
    assert count == 0


@pytest.mark.parametrize("authority", ["rule_edit", "project_kill_switch"])
async def test_postgres_aba_mutation_invalidates_prechange_candidate(
    migrated_engine: AsyncEngine,
    authority: str,
) -> None:
    """Edit-away/edit-back never resurrects an already-matched token."""
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, candidate = await _seed_rule(sessions, name=f"aba-{authority}")
    claim_started = asyncio.Event()

    async with sessions() as editor:
        repo = AutomationRuleRepository(editor)
        if authority == "rule_edit":
            rule = await repo.get_for_update(candidate.rule_id)
            assert rule is not None
            original = list(rule.actions)
            await repo.update_configuration(rule, {"actions": [{"type": "cancel"}]})
            await repo.update_configuration(rule, {"actions": original})
        else:
            project = await editor.get(Project, project_id)
            assert project is not None
            await repo.set_project_automation_enabled(project, enabled=False)
            await repo.set_project_automation_enabled(project, enabled=True)

        async def claim_while_aba_is_uncommitted() -> CircuitDecision:
            claim_started.set()
            async with sessions() as claimant:
                decision, _ = await AutomationRuleRepository(claimant).claim_execution(
                    candidate=candidate,
                )
                await claimant.commit()
                return decision

        task = asyncio.create_task(claim_while_aba_is_uncommitted())
        await asyncio.wait_for(claim_started.wait(), timeout=3)
        await asyncio.sleep(0.2)
        assert not task.done()
        await editor.commit()
        assert await asyncio.wait_for(task, timeout=3) == CircuitDecision.STALE

    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(AutomationRuleAdmission.id)).where(
                    AutomationRuleAdmission.rule_id == candidate.rule_id,
                ),
            )
            == 0
        )


async def test_postgres_prior_schema_upgrade_preserves_legacy_breaker_debt(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
) -> None:
    """An actual pre-0014 schema gets a conservative bounded epoch."""
    await _upgrade_integration_database(
        integration_settings,
        "v1_9_agent_worker_legacy_slot",
    )
    # The frozen initial migration now materialises the genuine prior shape;
    # no synthetic DROP/re-add holes are needed (and none may skew PG attnums).
    async with integration_engine.connect() as connection:
        prior_columns = {
            tuple(row)
            for row in (
                await connection.execute(
                    text(
                        "SELECT table_name, column_name "
                        "FROM information_schema.columns "
                        "WHERE table_schema = current_schema() AND ("
                        "(table_name = 'projects' "
                        " AND column_name = 'automation_revision') OR "
                        "(table_name = 'automation_rules' "
                        " AND column_name IN ('config_revision', 'cb_config_digest')))"
                    ),
                )
            ).all()
        }
    assert prior_columns == set()

    sessions = async_sessionmaker(integration_engine, expire_on_commit=False)
    rule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    old_start = datetime.now(UTC)
    async with sessions() as session:
        await session.execute(
            text(
                """
                INSERT INTO projects (id, slug, name, automation_enabled)
                VALUES (:id, :slug, :name, true)
                """,
            ),
            {
                "id": project_id,
                "slug": f"legacy-automation-{uuid.uuid4().hex[:8]}",
                "name": "Legacy automation",
            },
        )
        await session.execute(
            text(
                """
                INSERT INTO automation_rules (
                    id, project_id, name, is_enabled, dry_run, trigger,
                    conditions, actions, max_executions_per_window,
                    window_seconds, cb_tripped, cb_window_start,
                    cb_execution_count
                )
                VALUES (
                    :id, :project_id, :name, true, false, :trigger,
                    CAST(:conditions AS jsonb), CAST(:actions AS jsonb),
                    3, 3600, false, :window_start, 2
                )
                """,
            ),
            {
                "id": rule_id,
                "project_id": project_id,
                "name": "legacy-bounded",
                "trigger": "task.failed",
                "conditions": "{}",
                "actions": '[{"type":"notify"}]',
                "window_start": old_start,
            },
        )
        await session.commit()

    await _upgrade_integration_database(integration_settings, "head")

    async with sessions() as session:
        rule = await session.get(AutomationRule, rule_id)
        assert rule is not None
        project = await session.get(Project, project_id)
        assert project is not None
        candidate = dispatch_candidate(
            rule,
            project_revision=project.automation_revision,
        )
        assert rule.config_revision == 1
        assert project.automation_revision == 1
        assert rule.cb_config_digest == candidate.config_digest
        admissions = list(
            (
                await session.execute(
                    select(AutomationRuleAdmission).where(
                        AutomationRuleAdmission.rule_id == rule_id,
                    ),
                )
            ).scalars(),
        )
        assert len(admissions) == 1
        assert admissions[0].weight == 2

        # The first post-upgrade claim consumes only the one remaining slot;
        # the next is denied. Legacy debt was neither discarded nor expanded
        # into an unbounded number of rows.
        decision, _ = await AutomationRuleRepository(session).claim_execution(
            candidate=candidate,
        )
        assert decision == CircuitDecision.EXECUTE
        await session.commit()
    async with sessions() as session:
        rule = await session.get(AutomationRule, rule_id)
        assert rule is not None
        project = await session.get(Project, project_id)
        assert project is not None
        decision, _ = await AutomationRuleRepository(session).claim_execution(
            candidate=dispatch_candidate(
                rule,
                project_revision=project.automation_revision,
            ),
        )
        assert decision == CircuitDecision.TRIPPED_NOW
        await session.commit()

    async with integration_engine.connect() as connection:
        physical = await connection.run_sync(
            lambda sync: {
                table: [column["name"] for column in inspect(sync).get_columns(table)]
                for table in (
                    "projects",
                    "automation_rules",
                    "automation_rule_admissions",
                )
            },
        )
    assert physical["automation_rules"] == [
        column.name for column in AutomationRule.__table__.columns
    ]
    assert physical["automation_rule_admissions"] == [
        column.name for column in AutomationRuleAdmission.__table__.columns
    ]
    assert physical["projects"] == [column.name for column in Project.__table__.columns]

    # Compare the complete physical shape with a genuinely fresh head in a
    # separate database. The prior path above ALTER-appended 0014's columns;
    # the fresh path materialises them from live model metadata. Ordinal
    # position, defaults, nullability, constraints, and indexes must converge.
    fresh_name = f"z4j_automation_fresh_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{fresh_name}"')
    finally:
        await admin.close()
    fresh_plain_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{fresh_name}"
    fresh_async_url = fresh_plain_url.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    fresh_settings = integration_settings.model_copy(
        update={"database_url": fresh_async_url},
    )
    fresh_engine = create_async_engine(fresh_async_url)
    try:
        await _upgrade_integration_database(fresh_settings, "head")
        assert await _automation_schema_manifest(integration_engine) == (
            await _automation_schema_manifest(fresh_engine)
        )
    finally:
        await fresh_engine.dispose()
        admin = await asyncpg.connect(dsn=postgres_admin_url)
        try:
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                fresh_name,
            )
            await admin.execute(f'DROP DATABASE IF EXISTS "{fresh_name}"')
        finally:
            await admin.close()


async def test_postgres_upgrade_rejects_malformed_same_name_objects_atomically(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """A wrong same-name 0014 shape is never accepted or version-stamped."""

    await _upgrade_integration_database(
        integration_settings,
        "v1_9_agent_worker_legacy_slot",
    )
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "ALTER TABLE automation_rules ADD COLUMN config_revision text DEFAULT 'bogus'",
            ),
        )
        await connection.execute(
            text(
                "ALTER TABLE automation_rules ADD COLUMN "
                "cb_config_digest integer NOT NULL DEFAULT 7",
            ),
        )
        await connection.execute(
            text(
                "ALTER TABLE projects ADD COLUMN automation_revision text",
            ),
        )
        await connection.execute(
            text(
                "CREATE TABLE automation_rule_admissions ("
                "rule_id uuid, admitted_at integer, weight text, id uuid)",
            ),
        )

    with pytest.raises(
        CommandError,
        match="incompatible same-name schema object",
    ):
        await _upgrade_integration_database(
            integration_settings,
            "v1_9_automation_rolling_window",
        )

    async with integration_engine.connect() as connection:
        version = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        malformed = tuple(
            tuple(row)
            for row in (
                await connection.execute(
                    text(
                        "SELECT table_name, column_name, data_type, is_nullable, "
                        "column_default FROM information_schema.columns "
                        "WHERE table_schema = current_schema() AND ("
                        "(table_name = 'automation_rules' AND column_name IN "
                        " ('config_revision', 'cb_config_digest')) OR "
                        "(table_name = 'projects' AND column_name = "
                        " 'automation_revision')) "
                        "ORDER BY table_name, column_name",
                    ),
                )
            ).all()
        )
    assert version == "v1_9_agent_worker_legacy_slot"
    assert malformed == (
        ("automation_rules", "cb_config_digest", "integer", "NO", "7"),
        ("automation_rules", "config_revision", "text", "YES", "'bogus'::text"),
        ("projects", "automation_revision", "text", "YES", None),
    )


async def test_postgres_downgrade_reanchors_staggered_rolling_debt(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """The legacy fixed-window edge cannot reopen while newer debt is live."""

    await _upgrade_integration_database(
        integration_settings,
        "v1_9_automation_rolling_window",
    )
    project_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    async with integration_engine.begin() as connection:
        seed_now = await connection.scalar(select(func.clock_timestamp()))
        assert seed_now is not None
        oldest = seed_now - timedelta(seconds=55)
        newest = seed_now - timedelta(seconds=1)
        await connection.execute(
            text(
                "INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)",
            ),
            {
                "id": project_id,
                "slug": f"collapse-{project_id.hex[:8]}",
                "name": "Collapse",
            },
        )
        await connection.execute(
            text(
                "INSERT INTO automation_rules ("
                "id, project_id, name, trigger, max_executions_per_window, "
                "window_seconds, cb_window_start, cb_execution_count, "
                "cb_config_digest, cb_tripped) "
                "VALUES (:id, :project_id, :name, :trigger, 2, 60, "
                ":window_start, 2, :digest, false)",
            ),
            {
                "id": rule_id,
                "project_id": project_id,
                "name": "staggered",
                "trigger": "task.failed",
                "window_start": oldest,
                "digest": "d" * 64,
            },
        )
        for admitted_at in (oldest, newest):
            await connection.execute(
                text(
                    "INSERT INTO automation_rule_admissions "
                    "(id, rule_id, admitted_at, weight) "
                    "VALUES (:id, :rule_id, :admitted_at, 1)",
                ),
                {
                    "id": uuid.uuid4(),
                    "rule_id": rule_id,
                    "admitted_at": admitted_at,
                },
            )

    await _run_alembic(
        integration_settings,
        "downgrade",
        "v1_9_agent_worker_legacy_slot",
    )

    async with integration_engine.connect() as connection:
        window_start, count, tripped = (
            await connection.execute(
                text(
                    "SELECT cb_window_start, cb_execution_count, cb_tripped "
                    "FROM automation_rules WHERE id = :rule_id",
                ),
                {"rule_id": rule_id},
            )
        ).one()
        table_count = await connection.scalar(
            text(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'automation_rule_admissions'",
            ),
        )
    assert count == 2
    assert tripped is False
    assert window_start >= seed_now
    assert oldest + timedelta(seconds=60, milliseconds=500) < (window_start + timedelta(seconds=60))
    assert table_count == 0


async def test_postgres_delete_reauthorizes_after_destructive_edit(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """An OPERATOR delete waits for and sees a concurrent ADMIN escalation."""

    app = create_app(integration_settings, engine=migrated_engine)
    app.state.lifespan_ready = True
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    csrf = "automation-delete-race-csrf"
    async with sessions() as session:
        session.add(Project(id=project_id, slug="delete-race", name="Delete race"))
        session.add(
            User(
                id=user_id,
                email=f"delete-race-{uuid.uuid4().hex[:8]}@example.invalid",
                password_hash=PasswordHasher(integration_settings).hash(
                    "correct horse battery staple 9",
                ),
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.OPERATOR,
            ),
        )
        session.add(
            SessionRow(
                id=session_id,
                user_id=user_id,
                csrf_token=csrf,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            ),
        )
        session.add(
            AutomationRule(
                id=rule_id,
                project_id=project_id,
                name="notify-then-retry",
                trigger="task.failed",
                conditions={},
                actions=[{"type": "notify"}],
            ),
        )
        await session.commit()

    async with sessions() as editor:
        await editor.execute(
            update(AutomationRule)
            .where(AutomationRule.id == rule_id)
            .values(
                actions=[{"type": "retry"}],
                config_revision=AutomationRule.config_revision + 1,
            ),
        )

        async def delete_while_edit_uncommitted():
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://testserver",
            ) as client:
                client.cookies.set(
                    cookie_name(environment=integration_settings.environment),
                    SessionCookieCodec(integration_settings).encode(session_id),
                )
                return await client.delete(
                    f"/api/v1/projects/delete-race/automation/rules/{rule_id}",
                    headers={CSRF_HEADER_NAME: csrf},
                )

        delete_task = asyncio.create_task(delete_while_edit_uncommitted())
        # The request reaches its SELECT FOR UPDATE and remains behind the
        # editor's row lock. The production lock timeout is longer than this
        # bounded observation window.
        await asyncio.sleep(0.2)
        assert not delete_task.done()
        await editor.commit()
        response = await asyncio.wait_for(delete_task, timeout=3)

    assert response.status_code == 403, response.text
    async with sessions() as session:
        persisted = await session.get(AutomationRule, rule_id)
        assert persisted is not None
        assert persisted.actions == [{"type": "retry"}]
