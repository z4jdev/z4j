"""Integration test: ``alembic upgrade head`` against Postgres 18.

The unit-suite migration test runs against SQLite which silently
skips every Postgres-only branch. This test exercises the WHOLE
migration on real Postgres so the regex CHECK, the ENUM types,
the partial indexes, the GIN indexes, the partition pre-create,
and the audit_log triggers all run for real.

It also covers the bidirectional contract documented in
``z4j.dev/operations/database-migrations``: every additive 1.4.x
migration must round-trip ``upgrade head -> downgrade base ->
upgrade head`` against a populated database without leaving stray
objects behind. ``TestMigrationRoundTrip`` enforces that.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from z4j_brain.settings import Settings

from tests.migration_head import code_head

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers for the bidirectional round-trip test
# ---------------------------------------------------------------------------


def _alembic_config(settings: Settings):
    """Build an Alembic ``Config`` pointing at the per-test database."""
    from alembic.config import Config

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    return cfg


async def _run_alembic(
    settings: Settings,
    action: str,
    target: str,
    *,
    config_attributes: Mapping[str, object] | None = None,
) -> None:
    """Run ``alembic upgrade <target>`` or ``alembic downgrade <target>``.

    Mirrors the env-var wiring from the ``migrated_engine`` fixture
    so alembic's ``env.py`` resolves the same per-test Settings.
    """
    from alembic import command

    cfg = _alembic_config(settings)
    if config_attributes is not None:
        cfg.attributes.update(config_attributes)
    saved = {
        k: os.environ.get(k)
        for k in (
            "Z4J_DATABASE_URL",
            "Z4J_SECRET",
            "Z4J_SESSION_SECRET",
            "Z4J_AUDIT_CHAIN_SECRET",
            "Z4J_ENVIRONMENT",
            "Z4J_REQUIRE_DB_SSL",
        )
    }
    try:
        os.environ["Z4J_DATABASE_URL"] = settings.database_url
        os.environ["Z4J_SECRET"] = settings.secret.get_secret_value()
        os.environ["Z4J_SESSION_SECRET"] = settings.session_secret.get_secret_value()
        assert settings.audit_chain_secret is not None
        os.environ["Z4J_AUDIT_CHAIN_SECRET"] = settings.audit_chain_secret.get_secret_value()
        os.environ["Z4J_ENVIRONMENT"] = "dev"
        os.environ["Z4J_REQUIRE_DB_SSL"] = "false"
        runner = command.upgrade if action == "upgrade" else command.downgrade
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: runner(cfg, target),
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


async def _schedule_rollback_state(
    integration_settings: Settings,
) -> tuple[str, tuple[tuple[object, ...], ...] | None, set[str]]:
    """The three things a 1.9 rollback must not quietly change.

    ``holds`` is ``None`` once ``paused_at`` is gone, so a released hold and a
    dropped column cannot compare equal to each other.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(integration_settings.database_url, future=True)
    try:
        async with engine.connect() as conn:
            version = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            columns = {
                row[0]
                for row in (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'schedules'",
                        ),
                    )
                ).all()
            }
            holds = None
            if "paused_at" in columns:
                holds = tuple(
                    tuple(row)
                    for row in (
                        await conn.execute(
                            text("SELECT paused_at FROM schedules ORDER BY id"),
                        )
                    ).all()
                )
        return version, holds, columns
    finally:
        await engine.dispose()


async def _seed_stacked_release_evidence(
    integration_settings: Settings,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Put a row in 0014 so a refused downgrade must preserve real data."""

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from z4j_brain.persistence.models import (
        AutomationRule,
        AutomationRuleAdmission,
        NotificationDelivery,
        Project,
        User,
        UserSubscription,
    )

    engine = create_async_engine(integration_settings.database_url, future=True)
    rule_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            project_id = (await session.scalars(select(Project.id).limit(1))).one()
            session.add(
                AutomationRule(
                    id=rule_id,
                    project_id=project_id,
                    name=f"downgrade-preflight-{rule_id}",
                    trigger="task.failed",
                    conditions={},
                    actions=[],
                    cb_config_digest="d" * 64,
                ),
            )
            await session.flush()
            session.add(
                AutomationRuleAdmission(
                    id=uuid.uuid4(),
                    rule_id=rule_id,
                    admitted_at=datetime.now(UTC),
                    weight=7,
                ),
            )
            user = User(
                id=uuid.uuid4(),
                email=f"downgrade-preflight-{uuid.uuid4()}@example.invalid",
                password_hash="not-a-login-credential",
            )
            subscription = UserSubscription(
                id=uuid.uuid4(),
                user_id=user.id,
                project_id=project_id,
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            )
            session.add(user)
            await session.flush()
            session.add(subscription)
            await session.flush()
            session.add(
                NotificationDelivery(
                    id=delivery_id,
                    subscription_id=subscription.id,
                    recipient_user_id=user.id,
                    project_id=project_id,
                    trigger="task.failed",
                    status="sent",
                ),
            )
            await session.commit()
        return rule_id, delivery_id
    finally:
        await engine.dispose()


async def _stacked_release_evidence(
    integration_settings: Settings,
    rule_id: uuid.UUID,
    delivery_id: uuid.UUID,
) -> tuple[object, ...]:
    """Snapshot the version plus schema/data introduced above 0012."""

    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(integration_settings.database_url, future=True)
    try:
        async with engine.connect() as connection:
            version = await connection.scalar(text("SELECT version_num FROM alembic_version"))
            columns = tuple(
                tuple(row)
                for row in (
                    await connection.execute(
                        text(
                            "SELECT table_name, ordinal_position, column_name, "
                            "data_type, is_nullable, column_default "
                            "FROM information_schema.columns "
                            "WHERE table_schema = current_schema() "
                            "AND table_name IN ("
                            "'projects', 'automation_rules', "
                            "'automation_rule_admissions', "
                            "'notification_deliveries'"
                            ") ORDER BY table_name, ordinal_position",
                        ),
                    )
                ).all()
            )
            constraints = tuple(
                tuple(row)
                for row in (
                    await connection.execute(
                        text(
                            "SELECT relation.relname, constraint_row.conname, "
                            "pg_get_constraintdef(constraint_row.oid, true) "
                            "FROM pg_constraint AS constraint_row "
                            "JOIN pg_class AS relation "
                            "ON relation.oid = constraint_row.conrelid "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = relation.relnamespace "
                            "WHERE namespace.nspname = current_schema() "
                            "AND relation.relname IN ("
                            "'projects', 'automation_rules', "
                            "'automation_rule_admissions', "
                            "'notification_deliveries'"
                            ") ORDER BY relation.relname, constraint_row.conname",
                        ),
                    )
                ).all()
            )
            indexes = tuple(
                tuple(row)
                for row in (
                    await connection.execute(
                        text(
                            "SELECT tablename, indexname, indexdef FROM pg_indexes "
                            "WHERE schemaname = current_schema() "
                            "AND (tablename = 'automation_rule_admissions' "
                            "OR indexname IN ("
                            "'ux_agent_workers_legacy_agent', "
                            "'ix_notification_deliveries_recipient_sent'"
                            ")) "
                            "ORDER BY tablename, indexname",
                        ),
                    )
                ).all()
            )
            rule = tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT id, name, config_revision, cb_config_digest "
                            "FROM automation_rules WHERE id = :rule_id",
                        ),
                        {"rule_id": rule_id},
                    )
                ).one()
            )
            project = tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT project.id, project.slug, "
                            "project.automation_revision "
                            "FROM projects AS project "
                            "JOIN automation_rules AS rule "
                            "ON rule.project_id = project.id "
                            "WHERE rule.id = :rule_id",
                        ),
                        {"rule_id": rule_id},
                    )
                ).one()
            )
            admissions = tuple(
                tuple(row)
                for row in (
                    await connection.execute(
                        text(
                            "SELECT id, rule_id, admitted_at, weight "
                            "FROM automation_rule_admissions "
                            "WHERE rule_id = :rule_id ORDER BY id",
                        ),
                        {"rule_id": rule_id},
                    )
                ).all()
            )
            delivery = tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT id, subscription_id, project_id, "
                            "recipient_user_id, status, sent_at "
                            "FROM notification_deliveries WHERE id = :delivery_id",
                        ),
                        {"delivery_id": delivery_id},
                    )
                ).one()
            )
        return version, columns, constraints, indexes, project, rule, admissions, delivery
    finally:
        await engine.dispose()


async def _create_one_schedule(
    integration_settings: Settings,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Create one z4j-owned schedule, returning ``(project_id, schedule_id)``.

    Through the control repository rather than an INSERT, because Boundary D
    refuses a direct write and because a hold that no operator could have
    placed proves nothing about what a rollback would destroy.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.enums import ScheduleKind
    from z4j_brain.persistence.models import Project
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )

    engine = create_async_engine(integration_settings.database_url, future=True)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            project = Project(id=uuid.uuid4(), slug="hold", name="Hold")
            session.add(project)
            await session.flush()
            schedule = await ScheduleControlRepository(session).create_current(
                project_id=project.id,
                data={
                    "engine": "celery",
                    "scheduler": "z4j-scheduler",
                    "name": "nightly",
                    "task_name": "app.tasks.nightly",
                    "kind": ScheduleKind.CRON.value,
                    "expression": "0 3 * * *",
                    "timezone": "UTC",
                    "is_enabled": True,
                },
                planning_at=datetime.now(UTC),
            )
            project_id, schedule_id = project.id, schedule.id
            await session.commit()
        return project_id, schedule_id
    finally:
        await engine.dispose()


async def _pause_one_schedule(integration_settings: Settings) -> datetime:
    """Create one schedule and put it on hold, then return the hold time."""
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Schedule
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )

    project_id, schedule_id = await _create_one_schedule(integration_settings)
    engine = create_async_engine(integration_settings.database_url, future=True)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            transition = await ScheduleControlRepository(session).set_paused(
                project_id=project_id,
                schedule_id=schedule_id,
                paused=True,
                occurred_at=datetime.now(UTC),
            )
            assert transition.outcome == "applied"
            await session.commit()

        async with database.session() as session:
            row = (
                await session.execute(select(Schedule).where(Schedule.id == schedule_id))
            ).scalar_one()
            assert row.paused_at is not None
            return row.paused_at
    finally:
        await engine.dispose()


async def _wait_until_a_session_queues_for_table(
    integration_settings: Settings,
    running: asyncio.Task[None],
    table_name: str,
    *,
    give_up_after_seconds: float = 60.0,
) -> None:
    """Block until some session is waiting for a lock on ``table_name``.

    Watching the lock queue rather than sleeping a guessed interval is what
    makes the interleaving deterministic: it proves the rollback has reached
    the point where it wants the table, while the pause behind it is still
    uncommitted.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    loop = asyncio.get_running_loop()
    deadline = loop.time() + give_up_after_seconds
    engine = create_async_engine(integration_settings.database_url, future=True)
    try:
        async with engine.connect() as conn:
            while loop.time() < deadline:
                queued = await conn.scalar(
                    text(
                        "SELECT count(*) FROM pg_locks WHERE NOT granted "
                        "AND relation = to_regclass(:table_name)",
                    ),
                    {"table_name": f"public.{table_name}"},
                )
                # pg_locks reads shared memory rather than a snapshot, but the
                # surrounding transaction must still end or this connection
                # pins an ever-older one for the length of the poll.
                await conn.rollback()
                if queued or running.done():
                    return
                await asyncio.sleep(0.05)
        raise AssertionError(
            f"the rollback never queued for a lock on {table_name}",
        )
    finally:
        await engine.dispose()


async def test_alembic_upgrade_shares_the_schema_transition_lock(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    from z4j_brain.schema_transition import (
        SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
    )

    async with integration_engine.connect() as holder:
        transaction = await holder.begin()
        await holder.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )
        upgrade = asyncio.create_task(
            _run_alembic(integration_settings, "upgrade", "head"),
        )
        await asyncio.sleep(1.0)
        assert not upgrade.done()
        assert (
            await holder.scalar(
                text("SELECT to_regclass('public.users')"),
            )
            is None
        )
        await transaction.rollback()
        await asyncio.wait_for(upgrade, timeout=30)

    async with integration_engine.connect() as connection:
        assert (
            await connection.scalar(
                text("SELECT version_num FROM alembic_version"),
            )
            == code_head()
        )


async def test_populated_1_7_upgrade_completes_manifest_ceremony_and_boot_gate(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The existing-install path must preserve rows and pass the boot gate."""

    from z4j_brain import cli
    from z4j_brain.domain.audit_activation import read_activation_manifest
    from z4j_brain.domain.schedule_cadence import (
        CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint,
    )
    from z4j_brain.domain.schedule_fire_authority import (
        derive_scheduler_fire_id,
    )
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Schedule
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )
    from z4j_brain.startup import verify_production_authority_at_startup

    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    legacy_last = datetime(
        2026,
        7,
        28,
        5,
        10,
        35,
        357644,
        tzinfo=UTC,
    )
    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_7_security_hardening",
    )
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects (id, slug, name) "
                "VALUES (:project_id, 'populated-17', 'Populated 1.7')",
            ),
            {"project_id": project_id},
        )
        await connection.execute(
            text(
                "INSERT INTO users (email, password_hash, is_admin, is_active) "
                "VALUES ('populated-17@example.com', 'test-only-hash', true, true)",
            ),
        )
        await connection.execute(
            text(
                "INSERT INTO schedules("
                "id, project_id, engine, scheduler, name, task_name, kind, "
                "expression, timezone, is_enabled, last_run_at, total_runs"
                ") VALUES ("
                ":schedule_id, :project_id, 'celery', 'z4j-scheduler', "
                "'legacy-subsecond', 'jobs.legacy_subsecond', 'interval', "
                "'5s', 'UTC', true, :last_run_at, 23"
                ")",
            ),
            {
                "schedule_id": schedule_id,
                "project_id": project_id,
                "last_run_at": legacy_last,
            },
        )

    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_8_audit_chain_prepare",
    )
    monkeypatch.setenv("Z4J_DATABASE_URL", integration_settings.database_url)
    monkeypatch.setenv(
        "Z4J_SECRET",
        integration_settings.secret.get_secret_value(),
    )
    monkeypatch.setenv(
        "Z4J_SESSION_SECRET",
        integration_settings.session_secret.get_secret_value(),
    )
    assert integration_settings.audit_chain_secret is not None
    monkeypatch.setenv(
        "Z4J_AUDIT_CHAIN_SECRET",
        integration_settings.audit_chain_secret.get_secret_value(),
    )
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_REQUIRE_DB_SSL", "false")
    tmp_path.chmod(0o700)  # noqa: ASYNC240 - one test-fixture metadata call
    manifest_path = tmp_path / "activation.json"

    assert (
        await asyncio.to_thread(
            cli.main,
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
            ],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["classification_failures"] == [
        "existing-empty-audit-table",
    ]
    assert manifest["requires_ambiguity_attestation"] is True

    # Empty legacy audit history is ambiguous, not fresh. The manifest's
    # exact digest is required; a generic --apply remains safely parked.
    assert (
        await asyncio.to_thread(
            cli.main,
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 1
    )
    async with integration_engine.connect() as connection:
        assert (
            await connection.scalar(
                text("SELECT version_num FROM alembic_version"),
            )
            == "v1_8_audit_chain_prepare"
        )

    assert (
        await asyncio.to_thread(
            cli.main,
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
                "--attest-manifest-digest",
                str(manifest["manifest_digest"]),
            ],
        )
        == 0
    )
    async with integration_engine.connect() as connection:
        head, projects, users, state = (
            await connection.execute(
                text(
                    "SELECT "
                    "(SELECT version_num FROM alembic_version), "
                    "(SELECT COUNT(*) FROM projects), "
                    "(SELECT COUNT(*) FROM users), "
                    "to_regclass('public.audit_chain_state')::text",
                ),
            )
        ).one()
    assert (head, projects, users, state) == (
        code_head(),
        1,
        1,
        "audit_chain_state",
    )

    report = await verify_production_authority_at_startup(
        db=DatabaseManager(integration_engine),
        settings=integration_settings,
    )
    assert report.clean

    database = DatabaseManager(integration_engine)
    async with database.session(write=True) as session:
        schedule = await session.get(Schedule, schedule_id)
        assert schedule is not None
        assert schedule.control_token is not None
        assert schedule.definition_digest is not None
        assert schedule.schedule_revision is not None
        assert schedule.last_run_at is not None
        assert schedule.next_run_at is not None
        assert schedule.last_run_at.microsecond == 0
        assert schedule.next_run_at.microsecond == 0
        slot = schedule.next_run_at.astimezone(UTC)
        successor = slot + timedelta(seconds=5)
        transition = await ScheduleControlRepository(
            session,
        ).accept_current_fire_progress(
            project_id=project_id,
            schedule_id=schedule_id,
            fire_id=derive_scheduler_fire_id(schedule_id, slot),
            scheduled_for=slot,
            observed_control_token=schedule.control_token,
            definition_digest=schedule.definition_digest,
            expected_revision=schedule.schedule_revision,
            expected_last_run_at=schedule.last_run_at,
            expected_next_run_at=slot,
            prepared_next_run_at=successor,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=slot + timedelta(seconds=1),
        )
        assert transition.disposition == "applied"
        assert schedule.total_runs == 24
        await session.commit()


async def test_activated_postgres_subsecond_cursor_is_repaired_and_executes(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """The follow-up head must recover a database already activated by the RC."""

    from z4j_brain.domain.schedule_cadence import (
        CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint,
    )
    from z4j_brain.domain.schedule_fire_authority import (
        derive_scheduler_fire_id,
    )
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Schedule, ScheduleChangeLog
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )

    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    legacy_last = datetime(
        2026,
        7,
        28,
        5,
        10,
        35,
        357644,
        tzinfo=UTC,
    )
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects (id, slug, name) "
                "VALUES (:project_id, 'activated-subsecond', "
                "'Activated subsecond')",
            ),
            {"project_id": project_id},
        )
        await connection.execute(
            text(
                "INSERT INTO schedules("
                "id, project_id, engine, scheduler, name, task_name, kind, "
                "expression, timezone, is_enabled, last_run_at, total_runs"
                ") VALUES ("
                ":schedule_id, :project_id, 'celery', 'z4j-scheduler', "
                "'activated-subsecond', 'jobs.activated_subsecond', "
                "'interval', '5s', 'UTC', true, :last_run_at, 23"
                ")",
            ),
            {
                "schedule_id": schedule_id,
                "project_id": project_id,
                "last_run_at": legacy_last,
            },
        )

    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_8_schedule_control_activate",
        config_attributes={
            "z4j_test_preserve_legacy_cursor_precision": True,
        },
    )
    async with integration_engine.connect() as connection:
        old_head, old_last, old_next, old_runs = (
            await connection.execute(
                text(
                    "SELECT "
                    "(SELECT version_num FROM alembic_version), "
                    "last_run_at, next_run_at, total_runs "
                    "FROM schedules WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id},
            )
        ).one()
    assert old_head == "v1_8_schedule_control_activate"
    assert old_last.microsecond == 357644
    assert old_next.microsecond == 357644
    assert old_runs == 23

    await _run_alembic(integration_settings, "upgrade", "head")
    database = DatabaseManager(integration_engine)
    async with database.session(write=True) as session:
        schedule = await session.get(Schedule, schedule_id)
        assert schedule is not None
        assert schedule.control_token is not None
        assert schedule.definition_digest is not None
        assert schedule.schedule_revision is not None
        assert schedule.last_run_at is not None
        assert schedule.next_run_at is not None
        assert schedule.last_run_at.microsecond == 0
        assert schedule.next_run_at.microsecond == 0

        repair_log = (
            await session.execute(
                select(ScheduleChangeLog).where(
                    ScheduleChangeLog.schedule_id == schedule_id,
                    ScheduleChangeLog.revision == schedule.schedule_revision,
                ),
            )
        ).scalar_one()
        assert repair_log.snapshot is not None
        assert repair_log.snapshot["transition"]["kind"] == ("repair_legacy_cursor_seed")

        slot = schedule.next_run_at.astimezone(UTC)
        transition = await ScheduleControlRepository(
            session,
        ).accept_current_fire_progress(
            project_id=project_id,
            schedule_id=schedule_id,
            fire_id=derive_scheduler_fire_id(schedule_id, slot),
            scheduled_for=slot,
            observed_control_token=schedule.control_token,
            definition_digest=schedule.definition_digest,
            expected_revision=schedule.schedule_revision,
            expected_last_run_at=schedule.last_run_at,
            expected_next_run_at=slot,
            prepared_next_run_at=slot + timedelta(seconds=5),
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=slot + timedelta(seconds=1),
        )
        assert transition.disposition == "applied"
        assert schedule.total_runs == 24
        await session.commit()


async def test_activated_postgres_invalid_quarantine_cursor_is_parked(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """An affected-RC invalid quarantine must not strand migration at old head."""

    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    legacy_last = datetime(
        2026,
        7,
        28,
        5,
        10,
        35,
        357644,
        tzinfo=UTC,
    )
    legacy_next = legacy_last + timedelta(seconds=5)
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects (id, slug, name) "
                "VALUES (:project_id, 'invalid-quarantine-repair', "
                "'Invalid quarantine repair')",
            ),
            {"project_id": project_id},
        )
        await connection.execute(
            text(
                "INSERT INTO schedules("
                "id, project_id, engine, scheduler, name, task_name, kind, "
                "expression, timezone, is_enabled, last_run_at, next_run_at, "
                "total_runs"
                ") VALUES ("
                ":schedule_id, :project_id, 'celery', 'z4j-scheduler', "
                "'invalid-quarantine-repair', "
                "'jobs.invalid_quarantine_repair', "
                "'interval', 'not-an-interval', 'UTC', true, "
                ":last_run_at, :next_run_at, 17"
                ")",
            ),
            {
                "schedule_id": schedule_id,
                "project_id": project_id,
                "last_run_at": legacy_last,
                "next_run_at": legacy_next,
            },
        )

    await _run_alembic(
        integration_settings,
        "upgrade",
        "v1_8_schedule_control_activate",
        config_attributes={
            "z4j_test_preserve_legacy_cursor_precision": True,
        },
    )
    async with integration_engine.connect() as connection:
        (
            old_head,
            old_enabled,
            old_quarantine_code,
            quarantine_matches_control,
            old_last,
            old_next,
        ) = (
            await connection.execute(
                text(
                    "SELECT "
                    "(SELECT version_num FROM alembic_version), "
                    "is_enabled, quarantine_code, "
                    "quarantine_control_token = control_token, "
                    "last_run_at, next_run_at "
                    "FROM schedules WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id},
            )
        ).one()
    assert old_head == "v1_8_schedule_control_activate"
    assert not old_enabled
    assert old_quarantine_code == "migration_definition_invalid"
    assert quarantine_matches_control
    assert old_last.microsecond == 357644
    assert old_next.microsecond == 357644

    await _run_alembic(integration_settings, "upgrade", "head")
    async with integration_engine.connect() as connection:
        (
            head,
            is_enabled,
            quarantine_code,
            quarantine_matches_control,
            last_run_at,
            next_run_at,
            total_runs,
            snapshot,
        ) = (
            await connection.execute(
                text(
                    "SELECT "
                    "(SELECT version_num FROM alembic_version), "
                    "s.is_enabled, s.quarantine_code, "
                    "s.quarantine_control_token = s.control_token, "
                    "s.last_run_at, s.next_run_at, s.total_runs, c.snapshot "
                    "FROM schedules s "
                    "JOIN schedule_change_log c "
                    "ON c.schedule_id = s.id "
                    "AND c.revision = s.schedule_revision "
                    "WHERE s.id = :schedule_id",
                ),
                {"schedule_id": schedule_id},
            )
        ).one()
    assert head == code_head()
    assert not is_enabled
    assert quarantine_code == "migration_definition_invalid"
    assert quarantine_matches_control
    assert last_run_at.microsecond == 0
    assert next_run_at is None
    assert total_runs == 17
    assert snapshot["transition"]["kind"] == "repair_legacy_cursor_seed"
    assert snapshot["transition"]["repaired_next_run_at"] is None


# Tables and ENUM types we expect to NOT exist after ``downgrade base``.
# Sourced from the explicit drop list in ``v1_3_0_initial.downgrade()``
# plus ``alembic_version`` (which alembic itself drops at base).
_Z4J_TABLES_THAT_MUST_BE_GONE = (
    "schedule_change_log",
    "schedule_revision_state",
    "users",
    "projects",
    "memberships",
    "agents",
    "queues",
    "workers",
    "tasks",
    "events",
    "schedules",
    "commands",
    "audit_log",
    "first_boot_tokens",
    "sessions",
    "invitations",
    "password_reset_tokens",
    "notification_channels",
    "user_channels",
    "user_subscriptions",
    "project_default_subscriptions",
    "user_notifications",
    "notification_deliveries",
    "saved_views",
    "schedule_fires",
    "alert_events",
    "task_annotations",
    "pending_fires",
    "agent_workers",
    "api_keys",
    "z4j_meta",
    "scheduler_rate_buckets",
    "extension_store",
    "feature_flags",
    "export_jobs",
    "user_preferences",
    "project_config",
    # 1.7 rule engine: dropped by the consolidated v1_7_schema.downgrade()
    # (its _down_automation_rules step) on the way down to base.
    "automation_rules",
    # 1.9 exact rolling-window breaker history: dropped by 0014 before the
    # consolidated 1.7 automation-rule table is removed.
    "automation_rule_admissions",
    # 1.7 automation firing outbox: dropped by v1_7_schema.downgrade()
    # (its _down_automation_firing_outbox step) on the way to base.
    "automation_firing_outbox",
    # 1.7 durable misfire dedup: dropped by v1_7_schema.downgrade()
    # (its _down_misfire_alerts step).
    "misfire_alerts",
    # 1.8 Boundary B: downgrade is permitted only when this parent table is
    # empty, then both durable-operation tables must be removed.
    "bulk_retry_requests",
    "bulk_retry_request_children",
)

# The seven native enum types the baseline actually creates. The old
# list used stale 1.0-era names that were never created, so the
# downgrade assertion below passed VACUOUSLY (empty intersection) and
# could not catch the real types being orphaned -- which they were,
# until the migration's _SQL_ENUM_NAMES was corrected to match these.
_Z4J_ENUMS_THAT_MUST_BE_GONE = (
    "agent_state",
    "command_status",
    "project_role",
    "schedule_kind",
    "task_priority",
    "task_state",
    "worker_state",
)


class TestMigrationStructure:
    async def test_every_table_present(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' "
                    "ORDER BY tablename",
                ),
            )
            tables = {r[0] for r in rows.all()}
        # Core tables, the partitioned events parent, and one of
        # the pre-created daily partitions should all exist.
        expected_core = {
            "users",
            "projects",
            "memberships",
            "agents",
            "queues",
            "workers",
            "tasks",
            "events",
            "schedules",
            "commands",
            "audit_log",
            "first_boot_tokens",
            "sessions",
            "alembic_version",
        }
        assert expected_core.issubset(tables)
        assert any(t.startswith("events_20") for t in tables), (
            "expected at least one daily events partition pre-created"
        )

    async def test_enum_types_present(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT typname FROM pg_type "
                    "WHERE typtype = 'e' AND typnamespace = "
                    "(SELECT oid FROM pg_namespace WHERE nspname = 'public') "
                    "ORDER BY typname",
                ),
            )
            enums = {r[0] for r in rows.all()}
        assert {
            "agent_state",
            "command_status",
            "project_role",
            "schedule_kind",
            "task_priority",
            "task_state",
            "worker_state",
        }.issubset(enums)

    async def test_extensions_installed(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text("SELECT extname FROM pg_extension"),
            )
            extensions = {r[0] for r in rows.all()}
        # The migration installs three.
        assert {"pgcrypto", "citext", "pg_trgm"}.issubset(extensions)

    async def test_partial_indexes_present(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """Partial indexes that SQLite cannot represent."""
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'",
                ),
            )
            indexes = {r[0] for r in rows.all()}
        for expected in (
            "ix_users_active_partial",
            "ix_projects_active_partial",
            "ix_commands_pending_timeout",
            "ix_schedules_next_run",
            "ix_tasks_args_gin",
            "ix_tasks_kwargs_gin",
            "ix_tasks_search",
            "ix_sessions_user_active",
        ):
            assert expected in indexes, f"missing index {expected}"

    async def test_audit_action_prefix_index_uses_varchar_opclass(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """0016 installs the exact PostgreSQL prefix-search authority."""

        async with migrated_engine.connect() as conn:
            definition = (
                await conn.execute(
                    text(
                        "SELECT pg_get_indexdef(index_relation.oid) "
                        "FROM pg_class AS index_relation "
                        "JOIN pg_namespace AS namespace "
                        "ON namespace.oid = index_relation.relnamespace "
                        "WHERE namespace.nspname = current_schema() "
                        "AND index_relation.relname = "
                        "'ix_audit_log_action_pattern'",
                    ),
                )
            ).scalar_one()
            opclasses = (
                (
                    await conn.execute(
                        text(
                            "SELECT operator_class.opcname "
                            "FROM pg_class AS index_relation "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = index_relation.relnamespace "
                            "JOIN pg_index AS index_row "
                            "ON index_row.indexrelid = index_relation.oid "
                            "CROSS JOIN LATERAL unnest(index_row.indclass) "
                            "WITH ORDINALITY AS class_row(class_oid, position) "
                            "JOIN pg_opclass AS operator_class "
                            "ON operator_class.oid = class_row.class_oid "
                            "WHERE namespace.nspname = current_schema() "
                            "AND index_relation.relname = "
                            "'ix_audit_log_action_pattern' "
                            "ORDER BY class_row.position",
                        ),
                    )
                )
                .scalars()
                .all()
            )
            authority = tuple(
                (
                    await conn.execute(
                        text(
                            "SELECT index_row.indisunique, "
                            "index_row.indnullsnotdistinct, "
                            "index_row.indisprimary, index_row.indisexclusion, "
                            "index_row.indimmediate, index_row.indisvalid, "
                            "index_row.indcheckxmin, index_row.indisready, "
                            "index_row.indislive, constraint_row.contype "
                            "FROM pg_class AS index_relation "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = index_relation.relnamespace "
                            "JOIN pg_index AS index_row "
                            "ON index_row.indexrelid = index_relation.oid "
                            "LEFT JOIN pg_constraint AS constraint_row "
                            "ON constraint_row.conindid = index_relation.oid "
                            "WHERE namespace.nspname = current_schema() "
                            "AND index_relation.relname = "
                            "'ix_audit_log_action_pattern'",
                        ),
                    )
                ).one(),
            )

        assert str(definition).endswith(
            "USING btree (action varchar_pattern_ops, occurred_at DESC, source_ip)",
        )
        assert list(opclasses) == ["varchar_pattern_ops", "timestamptz_ops", "inet_ops"]
        assert authority == (False, False, False, False, True, True, False, True, True, None)

    @pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
    @pytest.mark.parametrize(
        ("hostile_ddl", "expected_constraint_type"),
        [
            (
                "CREATE TABLE ix_audit_log_action_pattern (value integer)",
                None,
            ),
            (
                "CREATE TABLE audit_action_pattern_decoy (value integer); "
                "CREATE INDEX ix_audit_log_action_pattern "
                "ON audit_action_pattern_decoy (value)",
                None,
            ),
            (
                "ALTER TABLE audit_log ADD CONSTRAINT ix_audit_log_action_pattern "
                "EXCLUDE USING btree ("
                "action varchar_pattern_ops WITH =, "
                "occurred_at DESC WITH =, source_ip WITH =)",
                "x",
            ),
        ],
        ids=["table", "foreign-table-index", "exclusion-constraint"],
    )
    async def test_audit_action_pattern_reserved_name_conflicts_preserve_version(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
        direction: str,
        hostile_ddl: str,
        expected_constraint_type: str | None,
    ) -> None:
        """0016 rejects every conflicting owner in PostgreSQL's relation namespace."""

        from alembic.util import CommandError

        index_name = "ix_audit_log_action_pattern"
        await migrated_engine.dispose()
        if direction == "upgrade":
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_9_delivery_recipient",
            )
            expected_version = "v1_9_delivery_recipient"
        else:
            expected_version = code_head()

        catalog_query = text(
            "SELECT named_object.relkind, table_class.relname, "
            "CASE WHEN named_object.relkind IN ('i', 'I') "
            "THEN pg_get_indexdef(named_object.oid) END, "
            "CAST(constraint_row.contype AS text) "
            "FROM pg_class AS named_object "
            "JOIN pg_namespace AS namespace "
            "ON namespace.oid = named_object.relnamespace "
            "LEFT JOIN pg_index AS index_row "
            "ON index_row.indexrelid = named_object.oid "
            "LEFT JOIN pg_class AS table_class "
            "ON table_class.oid = index_row.indrelid "
            "LEFT JOIN pg_constraint AS constraint_row "
            "ON constraint_row.conindid = named_object.oid "
            "WHERE namespace.nspname = current_schema() "
            "AND named_object.relname = :index_name",
        )
        engine = create_async_engine(integration_settings.database_url, future=True)
        try:
            async with engine.begin() as connection:
                if direction == "downgrade":
                    await connection.execute(text(f"DROP INDEX {index_name}"))
                for statement in hostile_ddl.split("; "):
                    await connection.execute(text(statement))

            async with engine.connect() as connection:
                before = tuple(
                    (
                        await connection.execute(
                            catalog_query,
                            {"index_name": index_name},
                        )
                    ).one(),
                )
            assert before[-1] == expected_constraint_type

            with pytest.raises(CommandError, match="unexpected definition"):
                if direction == "upgrade":
                    await _run_alembic(integration_settings, "upgrade", "head")
                else:
                    await _run_alembic(
                        integration_settings,
                        "downgrade",
                        "v1_9_delivery_recipient",
                    )

            async with engine.connect() as connection:
                assert (
                    await connection.scalar(
                        text("SELECT version_num FROM alembic_version"),
                    )
                    == expected_version
                )
                after = tuple(
                    (
                        await connection.execute(
                            catalog_query,
                            {"index_name": index_name},
                        )
                    ).one(),
                )
            assert after == before
        finally:
            await engine.dispose()

    async def test_events_is_partitioned(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT relkind::text FROM pg_class "
                        "WHERE relname = 'events' AND relnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
            ).scalar_one()
        # 'p' = partitioned table. We cast relkind::text in the
        # query because asyncpg returns the raw 1-byte ``"char"``
        # type as bytes rather than str.
        assert row == "p"

    async def test_schedule_fires_is_partitioned(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """A5: schedule_fires is RANGE-partitioned by scheduled_for, with the
        DEFAULT partition, at least one daily, and the Boundary-D
        generation-scoped unique including the partition key."""
        async with migrated_engine.connect() as conn:
            relkind = (
                await conn.execute(
                    text(
                        "SELECT relkind::text FROM pg_class "
                        "WHERE relname = 'schedule_fires' AND relnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
            ).scalar_one()
            assert relkind == "p"

            parts = {
                r[0]
                for r in (
                    await conn.execute(
                        text(
                            "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                            "AND tablename LIKE 'schedule_fires\\_%'",
                        ),
                    )
                ).all()
            }
            assert "schedule_fires_default" in parts
            assert any(p[:16].startswith("schedule_fires_2") for p in parts), (
                "expected at least one daily schedule_fires partition"
            )

            uq = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conname = "
                        "'uq_schedule_fires_fire_receipt' "
                        "AND conrelid = 'schedule_fires'::regclass",
                    ),
                )
            ).scalar_one()
            assert "(fire_id, receipt_control_token, scheduled_for)" in uq
            legacy_uq = (
                await conn.execute(
                    text(
                        "SELECT indexdef FROM pg_indexes "
                        "WHERE schemaname = 'public' "
                        "AND tablename = 'schedule_fires' "
                        "AND indexname = "
                        "'uq_schedule_fires_legacy_fire'",
                    ),
                )
            ).scalar_one()
            assert "(fire_id, scheduled_for)" in legacy_uq
            assert "receipt_control_token IS NULL" in legacy_uq
            pk = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conname = 'pk_schedule_fires' "
                        "AND conrelid = 'schedule_fires'::regclass",
                    ),
                )
            ).scalar_one()
            assert "(id, scheduled_for)" in pk

    async def test_schedule_fires_partition_worker_drops_expired(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The partition worker drops a daily partition older than retention
        (MAX-bounded: an empty old partition is safe to drop)."""
        from z4j_brain.domain.workers.schedule_fires_partition import (
            ScheduleFiresPartitionWorker,
        )
        from z4j_brain.persistence.database import DatabaseManager

        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS schedule_fires_2019_01_02 "
                    "PARTITION OF schedule_fires "
                    "FOR VALUES FROM ('2019-01-02') TO ('2019-01-03')",
                ),
            )
        worker = ScheduleFiresPartitionWorker(
            db=DatabaseManager(migrated_engine),
            settings=integration_settings,
        )
        await worker.tick()
        async with migrated_engine.connect() as conn:
            still = (
                await conn.execute(
                    text("SELECT to_regclass('public.schedule_fires_2019_01_02')"),
                )
            ).scalar()
        assert still is None  # dropped by DROP-PARTITION retention

    async def test_partition_retention_preserves_unresolved_legacy_evidence(
        self,
        integration_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """A backfilled receipt-NULL row blocks its whole old partition."""

        from z4j_brain.domain.workers.schedule_fires_partition import (
            ScheduleFiresPartitionWorker,
        )
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import ScheduleFire
        from z4j_brain.persistence.repositories.schedule_fires import (
            ScheduleFireRepository,
        )

        await _run_alembic(
            integration_settings,
            "upgrade",
            "v1_8_audit_chain_activate",
        )
        project_id = uuid.uuid4()
        schedule_id = uuid.uuid4()
        fire_id = uuid.uuid4()
        row_id = uuid.uuid4()
        async with integration_engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE schedule_fires_2019_01_03 "
                    "PARTITION OF schedule_fires "
                    "FOR VALUES FROM ('2019-01-03') TO ('2019-01-04')",
                ),
            )
            await conn.execute(
                text(
                    "INSERT INTO projects (id, slug, name) "
                    "VALUES (:id, 'legacy-retention', 'Legacy retention')",
                ),
                {"id": project_id},
            )
            await conn.execute(
                text(
                    "INSERT INTO schedules "
                    "(id, project_id, engine, scheduler, name, task_name, "
                    "kind, expression) VALUES "
                    "(:id, :project_id, 'celery', 'z4j-scheduler', "
                    "'legacy-retention', 'jobs.legacy_retention', "
                    "'interval', '5m')",
                ),
                {"id": schedule_id, "project_id": project_id},
            )
            await conn.execute(
                text(
                    "INSERT INTO schedule_fires "
                    "(id, fire_id, schedule_id, project_id, status, "
                    "scheduled_for, fired_at) VALUES "
                    "(:id, :fire_id, :schedule_id, :project_id, 'failed', "
                    "'2019-01-03T12:00:00Z', '2019-01-03T12:00:00Z')",
                ),
                {
                    "id": row_id,
                    "fire_id": fire_id,
                    "schedule_id": schedule_id,
                    "project_id": project_id,
                },
            )

        await _run_alembic(integration_settings, "upgrade", "head")
        database = DatabaseManager(integration_engine)
        async with database.session(write=True) as session:
            fire = await session.get(ScheduleFire, row_id)
            assert fire is not None
            original_nonce = fire.state_write_nonce
            assert original_nonce is not None
            retained_fire, changed = await ScheduleFireRepository(
                session,
            ).acknowledge_legacy_history(
                fire=fire,
                command_id=None,
                status="success",
                new_task_id="legacy-pg-history",
            )
            assert changed is True
            assert retained_fire.status == "failed"
            assert retained_fire.acked_at is None
            assert retained_fire.state_write_nonce != original_nonce
            await session.commit()
        worker = ScheduleFiresPartitionWorker(
            db=database,
            settings=integration_settings,
        )
        await worker.tick()
        async with integration_engine.connect() as conn:
            still = (
                await conn.execute(
                    text(
                        "SELECT to_regclass('public.schedule_fires_2019_01_03')",
                    ),
                )
            ).scalar()
            retained = (
                await conn.execute(
                    text(
                        "SELECT receipt_control_token, protocol_marker, "
                        "scheduler_ack_status, scheduler_ack_task_id "
                        "FROM schedule_fires WHERE id = :id",
                    ),
                    {"id": row_id},
                )
            ).one()
        assert still == "schedule_fires_2019_01_03"
        assert retained.receipt_control_token is None
        assert retained.protocol_marker == 1
        assert retained.scheduler_ack_status == "success"
        assert retained.scheduler_ack_task_id == "legacy-pg-history"

    async def test_audit_log_triggers_present(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE tgrelid = 'audit_log'::regclass "
                    "AND NOT tgisinternal",
                ),
            )
            triggers = {r[0] for r in rows.all()}
        assert {"audit_log_no_update", "audit_log_no_delete"} <= triggers

    async def test_slug_check_constraint_enforced(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """The CHECK regex on projects.slug must reject bad input."""
        async with migrated_engine.begin() as conn:
            try:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) VALUES ('BAD_UPPER', 'X')",
                    ),
                )
                bad_accepted = True
            except Exception:
                bad_accepted = False
        assert bad_accepted is False

        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO projects (slug, name) VALUES ('valid-slug', 'X')",
                ),
            )
        # Cleanup so the next test sees a clean table.
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM projects WHERE slug = 'valid-slug'"),
            )

    async def test_activated_boundary_f_refuses_downgrade_without_mutation(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The irreversible D/F fence fails before authority-state changes."""
        from alembic.util import CommandError
        from sqlalchemy.ext.asyncio import create_async_engine

        async def _snapshot() -> tuple[object, ...]:
            engine = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with engine.connect() as conn:
                    version = (
                        await conn.execute(
                            text("SELECT version_num FROM alembic_version"),
                        )
                    ).scalar_one()
                    state = (
                        await conn.execute(
                            text(
                                "SELECT generation, head_id, head_row_hmac, "
                                "active_row_count, frozen_row_count, state_mac "
                                "FROM audit_chain_state "
                                "WHERE singleton_id = 'audit-chain'",
                            ),
                        )
                    ).one()
                    markers = (
                        await conn.execute(
                            text(
                                "SELECT id, action, row_hmac, chain_generation "
                                "FROM audit_log ORDER BY occurred_at, id",
                            ),
                        )
                    ).all()
                    preparation_count = (
                        await conn.execute(
                            text("SELECT COUNT(*) FROM audit_chain_preparation"),
                        )
                    ).scalar_one()
                    state_trigger = (
                        await conn.execute(
                            text(
                                "SELECT COUNT(*) FROM pg_trigger "
                                "WHERE tgrelid = 'audit_chain_state'::regclass "
                                "AND tgname = 'audit_chain_state_no_update' "
                                "AND NOT tgisinternal",
                            ),
                        )
                    ).scalar_one()
                return (
                    version,
                    tuple(state),
                    tuple(tuple(marker) for marker in markers),
                    preparation_count,
                    state_trigger,
                )
            finally:
                await engine.dispose()

        await migrated_engine.dispose()
        before = await _snapshot()
        assert before[0] == code_head()
        assert before[1][3:5] == (2, 0)
        assert [marker[1] for marker in before[2]] == [
            "audit.chain_generation_started",
            "schedule.control_migration_activated",
        ]
        assert before[3:] == (0, 1)

        with pytest.raises(
            CommandError,
            match="refusing downgrade below Boundary D",
        ):
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_8_bulk_retry_requests",
            )

        # Alembic steps down one revision at a time and commits each step, so
        # revisions ABOVE the guarded one used to be dropped, and committed,
        # before the guard aborted the run. env.py now decides the whole plan
        # up front, so a refused rollback moves nothing at all: the head stays
        # where it was rather than stopping at the floor.
        after = await _snapshot()
        assert after == before

    async def test_paused_schedule_survives_both_refused_rollbacks(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """A hold must outlive both a plan-level and a single-step refusal.

        ``paused_at`` is the only record that a hold exists, so a rollback that
        drops it releases every held schedule at once, and the re-upgrade an
        operator makes next re-adds the column empty with no error and no audit
        row. Postgres exercises what SQLite cannot: env.py holds a
        session-scoped advisory lock across the whole invocation, and the
        refusal has to survive being taken while that lock is held.

        The hold here is committed and its connection closed before the
        rollback starts, so this covers the quiet case only. The hold that
        lands while a rollback is already in flight is
        ``test_pause_committed_during_the_rollback_still_refuses_it``.
        """
        from alembic.util import CommandError

        held_at = await _pause_one_schedule(integration_settings)
        evidence_ids = await _seed_stacked_release_evidence(integration_settings)
        await migrated_engine.dispose()

        before = await _schedule_rollback_state(integration_settings)
        stacked_before = await _stacked_release_evidence(
            integration_settings,
            *evidence_ids,
        )
        assert before[:2] == (code_head(), ((held_at,),))

        # Planned through the Boundary-D fence: refused before the 1.9 step.
        with pytest.raises(
            CommandError,
            match="refused before running any step of this downgrade",
        ):
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_8_bulk_retry_requests",
            )
        assert await _schedule_rollback_state(integration_settings) == before
        assert (
            await _stacked_release_evidence(integration_settings, *evidence_ids) == stacked_before
        )

        # Planned entirely above the fence, so 1.9 has to refuse for itself.
        with pytest.raises(CommandError, match=r"1 schedule\(s\) are paused"):
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_8_schedule_cursor_repair",
            )
        assert await _schedule_rollback_state(integration_settings) == before
        assert (
            await _stacked_release_evidence(integration_settings, *evidence_ids) == stacked_before
        )

        await _run_alembic(integration_settings, "upgrade", "head")
        assert await _schedule_rollback_state(integration_settings) == before
        assert (
            await _stacked_release_evidence(integration_settings, *evidence_ids) == stacked_before
        )

    async def test_revoked_agent_refuses_before_any_release_column_is_dropped(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The older hygiene worker must never receive an unmarked tombstone."""
        from alembic.util import CommandError
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from z4j_brain.persistence.enums import AgentState
        from z4j_brain.persistence.models import Agent, Project
        from z4j_core.transport import CURRENT_PROTOCOL

        project_id = uuid.uuid4()
        agent_id = uuid.uuid4()
        revoked_at = datetime.now(UTC)
        async with async_sessionmaker(migrated_engine, expire_on_commit=False)() as session:
            session.add(Project(id=project_id, slug="revoked", name="Revoked"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name=f"revoked:{agent_id}",
                    token_hash=f"revoked:{agent_id}:{revoked_at.isoformat()}",
                    protocol_version=CURRENT_PROTOCOL,
                    framework_adapter="bare",
                    engine_adapters=[],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.OFFLINE,
                    revoked_at=revoked_at,
                ),
            )
            await session.commit()
        evidence_ids = await _seed_stacked_release_evidence(integration_settings)
        await migrated_engine.dispose()

        async def snapshot() -> tuple[str, set[str], set[str], datetime | None]:
            engine = create_async_engine(integration_settings.database_url, future=True)
            try:
                async with engine.connect() as connection:
                    version = (
                        await connection.execute(
                            text("SELECT version_num FROM alembic_version"),
                        )
                    ).scalar_one()
                    rows = (
                        await connection.execute(
                            text(
                                "SELECT table_name, column_name "
                                "FROM information_schema.columns "
                                "WHERE table_name IN ('agents', 'schedules')",
                            ),
                        )
                    ).all()
                    marker = (
                        await connection.execute(
                            text("SELECT revoked_at FROM agents WHERE id = :id"),
                            {"id": agent_id},
                        )
                    ).scalar_one()
                return (
                    str(version),
                    {str(row.column_name) for row in rows if row.table_name == "agents"},
                    {str(row.column_name) for row in rows if row.table_name == "schedules"},
                    marker,
                )
            finally:
                await engine.dispose()

        before = await snapshot()
        stacked_before = await _stacked_release_evidence(
            integration_settings,
            *evidence_ids,
        )
        assert before[0] == code_head()
        assert "revoked_at" in before[1]
        assert {"paused_at", "overlap_policy"} <= before[2]
        assert before[3] is not None

        with pytest.raises(CommandError, match=r"1 agent\(s\) are revoked"):
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_8_schedule_cursor_repair",
            )

        assert await snapshot() == before
        assert (
            await _stacked_release_evidence(integration_settings, *evidence_ids) == stacked_before
        )

    async def test_pause_committed_during_the_rollback_still_refuses_it(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Counting the holds and dropping the column must see one table state.

        The two happen at different instants, and Postgres puts a usable window
        between them: an ordinary pause writer takes only row-level locks, so
        the count reads past it while it is uncommitted, and the DROP then
        queues behind it and lands after that hold has committed. That ordering
        is the one where a guard that counted too early waves through exactly
        the silent release it exists to prevent, so the rollback has to take
        ``schedules`` against writers before it counts.
        """
        from alembic.util import CommandError
        from sqlalchemy.ext.asyncio import create_async_engine
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
        )

        project_id, schedule_id = await _create_one_schedule(integration_settings)
        await migrated_engine.dispose()
        before = await _schedule_rollback_state(integration_settings)
        assert before[:2] == (code_head(), ((None,),))

        engine = create_async_engine(integration_settings.database_url, future=True)
        database = DatabaseManager(engine)
        rollback: asyncio.Task[None] | None = None
        try:
            async with database.session(write=True) as session:
                transition = await ScheduleControlRepository(session).set_paused(
                    project_id=project_id,
                    schedule_id=schedule_id,
                    paused=True,
                    occurred_at=datetime.now(UTC),
                )
                assert transition.outcome == "applied"
                assert transition.schedule is not None
                held_at = transition.schedule.paused_at

                # Deliberately still uncommitted. Any count the rollback runs
                # from here reads the pre-pause NULL.
                rollback = asyncio.create_task(
                    _run_alembic(
                        integration_settings,
                        "downgrade",
                        "v1_8_schedule_cursor_repair",
                    ),
                )
                await _wait_until_a_session_queues_for_table(
                    integration_settings,
                    rollback,
                    "schedules",
                )
                assert not rollback.done(), (
                    "the rollback finished without ever waiting for schedules, "
                    "so this run proves nothing about the interleaving"
                )
                await session.commit()

            with pytest.raises(CommandError, match=r"1 schedule\(s\) are paused"):
                await asyncio.wait_for(rollback, timeout=120)
        finally:
            if rollback is not None and not rollback.done():
                rollback.cancel()
            await engine.dispose()

        version, holds, columns = await _schedule_rollback_state(integration_settings)
        assert version == code_head()
        assert {"paused_at", "overlap_policy"} <= columns
        assert holds == ((held_at,),)

    async def test_revoke_committed_during_the_rollback_still_refuses_it(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The agents lock must close the same count-then-drop race."""
        from alembic.util import CommandError
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import AgentState
        from z4j_brain.persistence.models import Agent, Project
        from z4j_brain.persistence.repositories.agents import AgentRepository
        from z4j_core.transport import CURRENT_PROTOCOL

        project_id = uuid.uuid4()
        agent_id = uuid.uuid4()
        async with async_sessionmaker(migrated_engine, expire_on_commit=False)() as session:
            session.add(Project(id=project_id, slug="revoke-race", name="Revoke race"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="revoke-race",
                    token_hash=f"live-{agent_id}",
                    protocol_version=CURRENT_PROTOCOL,
                    framework_adapter="bare",
                    engine_adapters=[],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.commit()
        await migrated_engine.dispose()

        revoked_at = datetime.now(UTC)
        engine = create_async_engine(integration_settings.database_url, future=True)
        database = DatabaseManager(engine)
        rollback: asyncio.Task[None] | None = None
        try:
            async with database.session(write=True) as session:
                agent = await AgentRepository(session).get_live(agent_id, lock=True)
                assert agent is not None
                await AgentRepository(session).revoke(agent, at=revoked_at)

                # The marker is still uncommitted. A preflight that runs before
                # taking the table lock can count zero, then drop the column
                # after this transaction commits.
                rollback = asyncio.create_task(
                    _run_alembic(
                        integration_settings,
                        "downgrade",
                        "v1_8_schedule_cursor_repair",
                    ),
                )
                await _wait_until_a_session_queues_for_table(
                    integration_settings,
                    rollback,
                    "agents",
                )
                assert not rollback.done(), (
                    "the rollback finished without waiting for agents, so "
                    "this run proves nothing about the interleaving"
                )
                await session.commit()

            with pytest.raises(CommandError, match=r"1 agent\(s\) are revoked"):
                await asyncio.wait_for(rollback, timeout=120)
        finally:
            if rollback is not None and not rollback.done():
                rollback.cancel()
            await engine.dispose()

        verify = create_async_engine(integration_settings.database_url, future=True)
        try:
            async with verify.connect() as connection:
                version = await connection.scalar(text("SELECT version_num FROM alembic_version"))
                marker = await connection.scalar(
                    text("SELECT revoked_at FROM agents WHERE id = :agent_id"),
                    {"agent_id": agent_id},
                )
        finally:
            await verify.dispose()
        assert version == code_head()
        assert marker == revoked_at

    async def test_single_step_downgrade_proceeds_when_no_schedule_is_paused(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The hold guard must be a guard, not a blanket refusal.

        This crosses all three 1.9 revisions and proves their schema removal is
        still allowed after the whole-plan state preflight succeeds.
        """
        await migrated_engine.dispose()

        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_8_schedule_cursor_repair",
        )
        version, holds, columns = await _schedule_rollback_state(integration_settings)
        assert version == "v1_8_schedule_cursor_repair"
        assert holds is None
        assert not {"paused_at", "overlap_policy"} & columns
        engine = create_async_engine(integration_settings.database_url, future=True)
        try:
            async with engine.connect() as connection:
                revoked_column_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_name = 'agents' AND column_name = 'revoked_at'",
                    ),
                )
                admissions_table_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'automation_rule_admissions'",
                    ),
                )
                digest_column_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'automation_rules' "
                        "AND column_name = 'cb_config_digest'",
                    ),
                )
                rule_revision_column_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'automation_rules' "
                        "AND column_name = 'config_revision'",
                    ),
                )
                project_revision_column_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'projects' "
                        "AND column_name = 'automation_revision'",
                    ),
                )
                legacy_index_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_indexes "
                        "WHERE schemaname = current_schema() "
                        "AND indexname = 'ux_agent_workers_legacy_agent'",
                    ),
                )
                recipient_column_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'notification_deliveries' "
                        "AND column_name = 'recipient_user_id'",
                    ),
                )
                recipient_index_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_indexes "
                        "WHERE schemaname = current_schema() "
                        "AND indexname = 'ix_notification_deliveries_recipient_sent'",
                    ),
                )
        finally:
            await engine.dispose()
        assert revoked_column_count == 0
        assert admissions_table_count == 0
        assert digest_column_count == 0
        assert rule_revision_column_count == 0
        assert project_revision_column_count == 0
        assert legacy_index_count == 0
        assert recipient_column_count == 0
        assert recipient_index_count == 0

        await _run_alembic(integration_settings, "upgrade", "head")
        assert (await _schedule_rollback_state(integration_settings))[0] == code_head()


# ---------------------------------------------------------------------------
# Bidirectional round-trip below the Boundary-F activation fence: upgrade
# the pre-F head -> seed -> downgrade base -> verify clean -> upgrade the
# pre-F head. This is the load-bearing test for the
# 1.4.x compatibility-floor promise that schema migrations are
# bidirectional. If this ever fails, the bidirectional claim in
# z4j.dev/operations/database-migrations is no longer true.
# ---------------------------------------------------------------------------


class TestMigrationRoundTrip:
    """Pre-F head -> seed -> ``downgrade base`` -> pre-F head.

    Proves the legacy bidirectional promise without crossing Boundary F,
    whose authenticated audit state is intentionally irreversible. The downgrade path
    DESTROYS data by design (it returns the database to an empty
    state); the contract is bidirectional **schema**, not
    bidirectional **data**. Operators who need data-preserving
    rollback use ``z4j backup`` + ``z4j restore``, which is a
    separate workflow documented under ``backup-restore``.
    """

    async def test_round_trip_clean(
        self,
        pre_boundary_f_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Pre-F head, ``downgrade base``, then pre-F head again.

        After downgrade, no z4j table or ENUM type may remain. After
        the second upgrade, every expected table and ENUM is back.
        """
        # Sanity: the pre-F upgrade already ran via the fixture
        # fixture. Confirm a key z4j table exists before we knock
        # everything down.
        async with pre_boundary_f_engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT to_regclass('public.audit_log')::text",
                    ),
                )
            ).scalar_one()
        assert row == "audit_log", (
            "fixture should have installed the pre-F head; audit_log table missing"
        )

        # Seed a small fixture so the downgrade has real rows + FK
        # references to chew through. This proves DROP TABLE CASCADE
        # actually handles the FK web on Postgres rather than
        # silently succeeding against an empty schema.
        async with pre_boundary_f_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO projects (slug, name) "
                    "VALUES ('round-trip-test', 'Round trip test')",
                ),
            )
            _project_id = (
                await conn.execute(
                    text(
                        "SELECT id FROM projects WHERE slug = 'round-trip-test'",
                    ),
                )
            ).scalar_one()
            # Minimal user insert: PKMixin supplies id (server-default
            # gen_random_uuid), TimestampsMixin supplies created_at/
            # updated_at, is_admin/is_active have server defaults.
            await conn.execute(
                text(
                    "INSERT INTO users (email, password_hash) VALUES (:email, 'x')",
                ),
                {"email": f"round-trip-{secrets.token_hex(4)}@example.com"},
            )

        # Engine must be disposed before downgrade so alembic's
        # connection-management can take over without contending for
        # an open pool.
        await pre_boundary_f_engine.dispose()

        # Downgrade to base. Every z4j object should be gone after.
        await _run_alembic(integration_settings, "downgrade", "base")

        # Reconnect with a fresh engine to verify the empty state.
        from sqlalchemy.ext.asyncio import create_async_engine

        verify_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with verify_engine.connect() as conn:
                # Every z4j table must be gone.
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    ),
                )
                surviving = {r[0] for r in rows.all()}
            stragglers = surviving & set(_Z4J_TABLES_THAT_MUST_BE_GONE)
            assert not stragglers, f"downgrade left tables behind: {sorted(stragglers)}"

            # Every z4j-specific ENUM must be gone.
            async with verify_engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT typname FROM pg_type "
                        "WHERE typtype = 'e' AND typnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
                surviving_enums = {r[0] for r in rows.all()}
            enum_stragglers = surviving_enums & set(_Z4J_ENUMS_THAT_MUST_BE_GONE)
            assert not enum_stragglers, (
                f"downgrade left ENUM types behind: {sorted(enum_stragglers)}"
            )

            # Audit-log triggers must be gone (their function too).
            async with verify_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'audit_log_forbid_mutation'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is False, "downgrade left audit_log_forbid_mutation function behind"

            # Schedules NOTIFY trigger function must be gone.
            async with verify_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'z4j_schedules_notify'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is False, "downgrade left z4j_schedules_notify function behind"

            # alembic_version is alembic's own bookkeeping table, not
            # a z4j artifact. Alembic preserves it across downgrade
            # base and clears the version_num row instead. Confirm
            # the row is gone (no migration applied) but the table
            # itself can stay - that's the normal alembic contract.
            async with verify_engine.connect() as conn:
                applied = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM alembic_version"),
                    )
                ).scalar_one()
            assert applied == 0, (
                f"alembic_version should have zero rows after downgrade base; found {applied}"
            )
        finally:
            await verify_engine.dispose()

        # Now reinstall the pre-F head and re-verify the schema is back.
        # Proves the migration is replayable against a previously
        # migrated-then-downgraded database (catches state-leak bugs
        # in the install helpers).
        await _run_alembic(
            integration_settings,
            "upgrade",
            "v1_8_bulk_retry_requests",
        )

        replay_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with replay_engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    ),
                )
                tables = {r[0] for r in rows.all()}
            # Every must-be-gone table is now back, plus alembic_version.
            for tbl in (
                "users",
                "projects",
                "agents",
                "tasks",
                "events",
                "audit_log",
                "alembic_version",
            ):
                assert tbl in tables, f"replay pre-F upgrade left {tbl} missing"

            # Audit-log function is back (the trigger needs it).
            async with replay_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'audit_log_forbid_mutation'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is True, (
                "replay pre-F upgrade did not reinstall audit_log_forbid_mutation"
            )

            # Smoke insert proves the schema actually works after replay,
            # not just that the tables got created.
            async with replay_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) VALUES ('replay-smoke', 'Replay smoke')",
                    ),
                )
                count = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM projects"),
                    )
                ).scalar_one()
            assert count == 1, f"expected 1 project after replay smoke insert, got {count}"
        finally:
            await replay_engine.dispose()

    async def test_bulk_retry_parent_refuses_rollback_below_1_8(
        self,
        pre_boundary_f_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """A live destructive-operation parent makes pre-1.8 rollback unsafe."""

        from alembic.util import CommandError
        from sqlalchemy.ext.asyncio import create_async_engine

        async with pre_boundary_f_engine.begin() as conn:
            project_id = (
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) "
                        "VALUES ('boundary-b-rollback', 'Boundary B') "
                        "RETURNING id",
                    )
                )
            ).scalar_one()
            await conn.execute(
                text(
                    "INSERT INTO bulk_retry_requests ("
                    "id, project_id, idempotency_key, canonicalizer_version, "
                    "canonical_request, canonical_digest, effective_request, "
                    "plan_digest, child_count, max_in_flight, deadline_at"
                    ") VALUES ("
                    ":id, :project_id, 'rollback-fence', 1, :canonical_request, "
                    ":digest, CAST(:effective_request AS jsonb), :digest, "
                    "0, 8, NOW() + INTERVAL '15 minutes'"
                    ")",
                ),
                {
                    "id": uuid.uuid4(),
                    "project_id": project_id,
                    "canonical_request": b'{"action":"bulk_retry"}',
                    "digest": "0" * 64,
                    "effective_request": '{"action":"bulk_retry"}',
                },
            )
        await pre_boundary_f_engine.dispose()

        with pytest.raises(CommandError, match="refusing downgrade"):
            await _run_alembic(
                integration_settings,
                "downgrade",
                "v1_7_security_hardening",
            )

        verify_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with verify_engine.connect() as conn:
                version = (
                    await conn.execute(
                        text("SELECT version_num FROM alembic_version"),
                    )
                ).scalar_one()
                parents = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM bulk_retry_requests"),
                    )
                ).scalar_one()
            assert version == "v1_8_bulk_retry_requests"
            assert parents == 1
        finally:
            await verify_engine.dispose()

    async def test_kill_switch_column_round_trip(
        self,
        pre_boundary_f_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The 1.7 kill-switch change is bidirectional at the COLUMN level:
        ``projects.automation_enabled`` drops when the consolidated
        ``v1_7_schema`` migration is downgraded to the v1_6_6 floor (the
        whole 1.7 delta, which includes the kill-switch column) and returns
        on re-upgrade.

        Complements the full base round-trip above by exercising the
        ADD/DROP COLUMN path specifically (a column drop is a different
        Postgres code path from a table drop). The thirteen dev-time 1.7
        migrations are now one atomic revision, so the only downgrade
        boundary below the kill-switch column is the v1_6_6 floor.
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        async def _column_exists() -> bool:
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    return bool(
                        (
                            await conn.execute(
                                text(
                                    "SELECT EXISTS (SELECT 1 FROM "
                                    "information_schema.columns WHERE "
                                    "table_name = 'projects' AND "
                                    "column_name = 'automation_enabled')",
                                ),
                            )
                        ).scalar_one()
                    )
            finally:
                await eng.dispose()

        # The pre-F fixture includes the column without crossing Boundary F.
        await pre_boundary_f_engine.dispose()
        assert await _column_exists() is True

        # Downgrade the whole 1.7 delta to the v1_6_6 floor: the
        # kill-switch column is dropped along with the rest of the delta.
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )
        assert await _column_exists() is False

        # Re-upgrade restores it (idempotent add-column guard).
        await _run_alembic(
            integration_settings,
            "upgrade",
            "v1_8_bulk_retry_requests",
        )
        assert await _column_exists() is True

    async def test_schedule_fires_partition_data_round_trip(
        self,
        pre_boundary_f_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Populated-DB round-trip across the consolidated ``v1_7_schema``.

        The consolidated migration's partition step recreates
        ``schedule_fires`` as a RANGE-partitioned table and copies every
        row across with an explicit column list (upgrade), then copies
        back into the plain table (downgrade). The structural tests above
        prove the SHAPE survives; this test proves REAL rows survive both
        copies with identical values.

        The thirteen dev-time 1.7 migrations are now one atomic revision,
        so the only downgrade boundary below the partition step is the
        v1_6_6 floor. At that floor ``schedule_fires`` is the plain
        (id)-PK table WITHOUT ``triggered_by_user_id`` -- that column is
        added by the same consolidated migration, so we seed the twelve
        floor columns and let the migration backfill the new column NULL
        as it partitions:

        1. downgrade the whole 1.7 delta to the v1_6_6 floor (plain
           schedule_fires, no ``triggered_by_user_id``),
        2. seed a project + user + schedule + fires whose
           ``scheduled_for`` spans a recent daily partition, a future
           daily, and a row old enough that it can ONLY land in the
           DEFAULT partition,
        3. upgrade head (runs the recreate-and-copy) and assert every
           seeded column of every row survived, the new
           ``triggered_by_user_id`` column is present and backfilled
           NULL, and each row landed in the expected partition,
        4. downgrade to the v1_6_6 floor again (copy-back) and assert the
           plain table holds the same rows.
        """
        import uuid
        from datetime import UTC, datetime, timedelta

        from sqlalchemy.ext.asyncio import create_async_engine

        # The twelve schedule_fires columns present at the v1_6_6 floor
        # (the migration's _COLUMNS copy list MINUS triggered_by_user_id,
        # which the same consolidated migration adds). snapshot() selects
        # exactly these so it works against both the plain floor table and
        # the partitioned head table.
        fire_columns = (
            "id",
            "fire_id",
            "schedule_id",
            "project_id",
            "command_id",
            "status",
            "scheduled_for",
            "fired_at",
            "acked_at",
            "latency_ms",
            "error_code",
            "error_message",
        )
        col_list = ", ".join(fire_columns)

        project_id = uuid.uuid4()
        user_id = uuid.uuid4()
        schedule_id = uuid.uuid4()
        now = datetime.now(UTC)

        # scheduled_for spread: the upgrade pre-creates daily
        # partitions for CURRENT_DATE-31 .. CURRENT_DATE+7 only, so
        # the 400-day-old row can only land in the DEFAULT partition
        # while the recent/future rows land in droppable dailies.
        fires: list[dict] = [
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "delivered",
                "scheduled_for": now,
                "fired_at": now + timedelta(milliseconds=250),
                "acked_at": now + timedelta(seconds=1),
                "latency_ms": 42,
                "error_code": None,
                "error_message": None,
            },
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "failed",
                "scheduled_for": now - timedelta(days=3),
                "fired_at": now - timedelta(days=3) + timedelta(seconds=2),
                "acked_at": None,
                "latency_ms": None,
                "error_code": "dispatch_timeout",
                "error_message": "agent did not ack within deadline",
            },
            {
                # Older than the pre-created daily window: DEFAULT
                # partition is the only possible landing spot.
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "acked_success",
                "scheduled_for": now - timedelta(days=400),
                "fired_at": now - timedelta(days=400, milliseconds=-5),
                "acked_at": now - timedelta(days=400, seconds=-3),
                "latency_ms": 3120,
                "error_code": None,
                "error_message": None,
            },
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "buffered",
                "scheduled_for": now + timedelta(days=3),
                "fired_at": now,
                "acked_at": None,
                "latency_ms": None,
                "error_code": None,
                "error_message": None,
            },
        ]
        default_partition_fire_id = fires[2]["id"]

        def expected_row(fire: dict) -> tuple:
            """The seeded column tuple a survived row must equal (the twelve
            floor columns, in ``fire_columns`` order)."""
            return (
                fire["id"],
                fire["fire_id"],
                schedule_id,
                project_id,
                None,  # command_id stays NULL throughout
                fire["status"],
                fire["scheduled_for"],
                fire["fired_at"],
                fire["acked_at"],
                fire["latency_ms"],
                fire["error_code"],
                fire["error_message"],
            )

        async def snapshot() -> tuple[str, dict, dict]:
            """(relkind, rows-by-id, partition-placement-by-id)."""
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    kind = (
                        await conn.execute(
                            text(
                                "SELECT relkind::text FROM pg_class "
                                "WHERE relname = 'schedule_fires' AND relnamespace = "
                                "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                            ),
                        )
                    ).scalar_one()
                    rows = (
                        await conn.execute(
                            text(f"SELECT {col_list} FROM schedule_fires"),
                        )
                    ).all()
                    placement = (
                        await conn.execute(
                            text(
                                "SELECT id, tableoid::regclass::text FROM schedule_fires",
                            ),
                        )
                    ).all()
                return (
                    kind,
                    {row[0]: tuple(row) for row in rows},
                    {row[0]: row[1] for row in placement},
                )
            finally:
                await eng.dispose()

        # The fixture installed the pre-F head. Downgrade the whole 1.7 delta to
        # the v1_6_6 floor so schedule_fires is the plain (id)-PK table
        # without triggered_by_user_id (the only boundary below the
        # partition step now that the 1.7 chain is one revision).
        await pre_boundary_f_engine.dispose()
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )

        seed_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with seed_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO projects (id, slug, name) "
                        "VALUES (:id, 'fires-round-trip', 'Fires round trip')",
                    ),
                    {"id": project_id},
                )
                await conn.execute(
                    text(
                        "INSERT INTO users (id, email, password_hash) VALUES (:id, :email, 'x')",
                    ),
                    {
                        "id": user_id,
                        "email": f"fires-rt-{secrets.token_hex(4)}@example.com",
                    },
                )
                await conn.execute(
                    text(
                        "INSERT INTO schedules "
                        "(id, project_id, engine, scheduler, name, "
                        " task_name, kind, expression) "
                        "VALUES (:id, :project_id, 'celery', 'celery-beat', "
                        "'fires-round-trip', 'app.tasks.noop', 'cron', "
                        "'*/5 * * * *')",
                    ),
                    {"id": schedule_id, "project_id": project_id},
                )
                for fire in fires:
                    await conn.execute(
                        text(
                            f"INSERT INTO schedule_fires ({col_list}) VALUES "
                            "(:id, :fire_id, :schedule_id, :project_id, NULL, "
                            ":status, :scheduled_for, :fired_at, :acked_at, "
                            ":latency_ms, :error_code, :error_message)",
                        ),
                        {
                            **fire,
                            "schedule_id": schedule_id,
                            "project_id": project_id,
                        },
                    )
        finally:
            await seed_engine.dispose()

        pre_kind, pre_rows, _ = await snapshot()
        assert pre_kind == "r", "expected the plain table below the partition migration"
        assert len(pre_rows) == len(fires)

        # Upgrade THROUGH the partition migration: recreate-and-copy.
        await _run_alembic(
            integration_settings,
            "upgrade",
            "v1_8_bulk_retry_requests",
        )

        part_kind, part_rows, placement = await snapshot()
        assert part_kind == "p", "upgrade should have partitioned schedule_fires"
        assert len(part_rows) == len(fires), (
            f"partition copy lost rows: expected {len(fires)}, got {len(part_rows)}"
        )
        for fire in fires:
            assert part_rows[fire["id"]] == expected_row(fire), (
                f"fire {fire['id']} changed across the partition copy"
            )
        assert placement[default_partition_fire_id] == "schedule_fires_default", (
            "the 400-day-old fire should land in the DEFAULT partition"
        )
        for fire in fires:
            if fire["id"] == default_partition_fire_id:
                continue
            assert placement[fire["id"]].startswith("schedule_fires_2"), (
                f"fire {fire['id']} expected in a daily partition, found in {placement[fire['id']]}"
            )

        # The consolidated migration also ADDED triggered_by_user_id as
        # part of the same upgrade: it must exist on the partitioned table
        # and be backfilled NULL for every copied row.
        add_col_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with add_col_engine.connect() as conn:
                nulls = (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM schedule_fires "
                            "WHERE triggered_by_user_id IS NOT NULL",
                        ),
                    )
                ).scalar_one()
            assert nulls == 0, (
                "upgrade should backfill triggered_by_user_id NULL on every copied row"
            )
        finally:
            await add_col_engine.dispose()

        # Downgrade the whole 1.7 delta to the v1_6_6 floor: the copy-back
        # into the plain table must preserve the rows too.
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )

        post_kind, post_rows, post_placement = await snapshot()
        assert post_kind == "r", "downgrade should restore the plain table"
        assert len(post_rows) == len(fires), (
            f"downgrade copy-back lost rows: expected {len(fires)}, got {len(post_rows)}"
        )
        for fire in fires:
            assert post_rows[fire["id"]] == expected_row(fire), (
                f"fire {fire['id']} changed across the downgrade copy-back"
            )
        # No partitions remain; every row lives in the plain table.
        assert set(post_placement.values()) == {"schedule_fires"}

        # Re-upgrade to the pre-F head with the table POPULATED: the partition
        # migration must also apply cleanly on the way back up (this
        # is the 1.6 -> 1.7 upgrade path operators actually take).
        await _run_alembic(
            integration_settings,
            "upgrade",
            "v1_8_bulk_retry_requests",
        )
        final_kind, final_rows, _ = await snapshot()
        assert final_kind == "p"
        assert len(final_rows) == len(fires)

    async def test_upgrade_head_twice_is_idempotent(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """``alembic upgrade head`` a second time is a clean no-op.

        The ``migrated_engine`` fixture already ran ``upgrade head`` once.
        Running it again must exit cleanly and leave the schema
        byte-identical (same tables + enum types). Catches a migration
        that fails to stamp its version -- and would thus re-execute its
        DDL on every boot -- or that is unsafe to re-apply against an
        already-migrated database. The events partitions must not
        multiply either (the partition-creator path is idempotent).
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        async def _snapshot() -> tuple[frozenset[str], frozenset[str]]:
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    tables = {
                        r[0]
                        for r in (
                            await conn.execute(
                                text(
                                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                                ),
                            )
                        ).all()
                    }
                    enums = {
                        r[0]
                        for r in (
                            await conn.execute(
                                text(
                                    "SELECT typname FROM pg_type "
                                    "WHERE typtype = 'e' AND typnamespace = "
                                    "(SELECT oid FROM pg_namespace WHERE "
                                    "nspname = 'public')",
                                ),
                            )
                        ).all()
                    }
                    return frozenset(tables), frozenset(enums)
            finally:
                await eng.dispose()

        # The fixture already upgraded to head.
        await migrated_engine.dispose()
        before = await _snapshot()
        assert any(t.startswith("events_20") for t in before[0])

        # Second upgrade head: must be a clean no-op.
        await _run_alembic(integration_settings, "upgrade", "head")
        after = await _snapshot()

        assert after == before, (
            "second `alembic upgrade head` changed the schema "
            f"(added tables: {sorted(after[0] - before[0])}; "
            f"added enums: {sorted(after[1] - before[1])}) -- a migration "
            "is re-executing DDL instead of no-opping at head"
        )
