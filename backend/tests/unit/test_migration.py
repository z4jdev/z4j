"""Tests for the alembic initial migration.

Runs ``alembic upgrade head`` against an in-memory SQLite database.
The Postgres-only branches are dialect-guarded, so SQLite skips
extensions, ENUM types, partitioning, triggers, and GIN indexes -
the test still proves that the SQLAlchemy ``create_all`` half of
the migration is internally consistent and that downgrade reverses
cleanly.

Postgres-specific behaviour is exercised by the integration suite
(B7) against a real Postgres 18 container.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from tests.migration_head import code_head


@pytest.fixture
def alembic_cfg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Config]:
    db_path = tmp_path / "brain.sqlite"
    sync_url = f"sqlite:///{db_path}"

    # Settings reads Z4J_DATABASE_URL - we point env.py at the
    # async-sqlite version, but the migration test uses the sync
    # variant via a forced override below.
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = Path(tempfile.mkdtemp(prefix="z4j-migration-", dir="/tmp"))
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    # We expose the sync URL for the test only - env.py normally
    # uses the async one.
    cfg.attributes["test_sync_url"] = sync_url
    cfg.attributes["test_db_path"] = db_path
    try:
        yield cfg
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


async def _pause_one_schedule(db_path: Path) -> datetime:
    """Create one schedule and put it on hold, then return the hold time.

    Through the control repository rather than an INSERT, because Boundary D
    refuses a direct write and because a hold that no operator could have
    placed proves nothing about what a rollback would destroy.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.enums import ScheduleKind
    from z4j_brain.persistence.models import Project, Schedule
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
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


def _as_stored(moment: datetime) -> str:
    """SQLite keeps a DATETIME as the string SQLAlchemy formatted it into."""
    return moment.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")


def _schedule_state(sync_url: str) -> tuple[str, set[str], list[object]]:
    """The three things a rollback must not quietly change."""
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version",
            ).scalar_one()
            columns = {column["name"] for column in inspect(engine).get_columns("schedules")}
            holds = [
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT paused_at FROM schedules ORDER BY id",
                ).fetchall()
            ]
        return version, columns, holds
    finally:
        engine.dispose()


def _seed_stacked_release_evidence(sync_url: str) -> None:
    """Put data in 0014 so a preflight test can detect an earlier drop."""

    from z4j_brain.persistence.models import (
        AutomationRule,
        AutomationRuleAdmission,
        NotificationDelivery,
        Project,
        User,
        UserSubscription,
    )

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            project_id = session.scalars(select(Project.id).limit(1)).one()
            rule = AutomationRule(
                id=uuid.uuid4(),
                project_id=project_id,
                name="downgrade-preflight-evidence",
                trigger="task.failed",
                conditions={},
                actions=[],
                cb_config_digest="d" * 64,
            )
            session.add(rule)
            session.flush()
            session.add(
                AutomationRuleAdmission(
                    id=uuid.uuid4(),
                    rule_id=rule.id,
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
            session.flush()
            session.add(subscription)
            session.flush()
            session.add(
                NotificationDelivery(
                    id=uuid.uuid4(),
                    subscription_id=subscription.id,
                    recipient_user_id=user.id,
                    project_id=project_id,
                    trigger="task.failed",
                    status="sent",
                ),
            )
            session.commit()
    finally:
        engine.dispose()


def _stacked_release_evidence(sync_url: str) -> tuple[object, ...]:
    """Snapshot the version plus every schema/data object above 0012."""

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version",
            ).scalar_one()
            objects = tuple(
                tuple(row)
                for row in connection.exec_driver_sql(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE name IN ("
                    "'projects', "
                    "'automation_rules', "
                    "'automation_rule_admissions', "
                    "'ix_automation_rule_admissions_rule_time', "
                    "'ux_agent_workers_legacy_agent', "
                    "'notification_deliveries', "
                    "'ix_notification_deliveries_recipient_sent'"
                    ") ORDER BY type, name",
                ).all()
            )
            rule_columns = {
                str(row[1])
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info('automation_rules')",
                ).all()
            }
            rules: tuple[tuple[object, ...], ...] | None = None
            if {"cb_config_digest", "config_revision"} <= rule_columns:
                rules = tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        "SELECT id, name, config_revision, cb_config_digest "
                        "FROM automation_rules ORDER BY id",
                    ).all()
                )
            project_columns = {
                str(row[1])
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info('projects')",
                ).all()
            }
            projects: tuple[tuple[object, ...], ...] | None = None
            if "automation_revision" in project_columns:
                projects = tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        "SELECT id, slug, automation_revision FROM projects ORDER BY id",
                    ).all()
                )
            admissions: tuple[tuple[object, ...], ...] | None = None
            if inspect(engine).has_table("automation_rule_admissions"):
                admissions = tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        "SELECT id, rule_id, admitted_at, weight "
                        "FROM automation_rule_admissions ORDER BY id",
                    ).all()
                )
            delivery_columns = {
                str(row[1])
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info('notification_deliveries')",
                ).all()
            }
            deliveries: tuple[tuple[object, ...], ...] | None = None
            if "recipient_user_id" in delivery_columns:
                deliveries = tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        "SELECT id, subscription_id, project_id, recipient_user_id, "
                        "status, sent_at FROM notification_deliveries ORDER BY id",
                    ).all()
                )
        return version, objects, projects, rules, admissions, deliveries
    finally:
        engine.dispose()


def test_migration_runs_on_sqlite(alembic_cfg: Config) -> None:
    """``alembic upgrade head`` should produce all 12 tables on SQLite."""
    command.upgrade(alembic_cfg, "head")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    finally:
        engine.dispose()

    assert tables >= {
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
        # alembic's own bookkeeping table
        "alembic_version",
    }


def test_audit_action_pattern_index_is_canonical_and_used(
    alembic_cfg: Config,
) -> None:
    """Fresh and upgrade paths converge on the bounded setup-prefix index."""

    index_name = "ix_audit_log_action_pattern"
    command.upgrade(alembic_cfg, "v1_9_delivery_recipient")
    engine = create_engine(alembic_cfg.attributes["test_sync_url"])
    try:
        # The persisted 0015 schema has no such index.  Advancing one revision
        # exercises the real upgrade path rather than only current metadata.
        command.upgrade(alembic_cfg, "head")

        with engine.connect() as connection:
            definition = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                (index_name,),
            ).scalar_one()
            plan = connection.exec_driver_sql(
                f"EXPLAIN QUERY PLAN SELECT count(*) FROM audit_log INDEXED BY {index_name} "
                "WHERE action LIKE 'setup.%' ESCAPE '\\' "
                "AND action >= 'setup.' AND action < 'setup/' "
                "AND occurred_at >= '2026-01-01T00:00:00Z' "
                "AND source_ip = '127.0.0.1'",
            ).all()
        assert " ".join(str(definition).lower().split()).endswith(
            "(action, occurred_at desc, source_ip)",
        )
        assert any(index_name in str(row) for row in plan)
    finally:
        engine.dispose()


def test_audit_action_pattern_index_conflict_fails_closed(
    alembic_cfg: Config,
) -> None:
    """0016 never blesses a same-name index with weaker semantics."""

    index_name = "ix_audit_log_action_pattern"
    command.upgrade(alembic_cfg, "v1_9_delivery_recipient")
    engine = create_engine(alembic_cfg.attributes["test_sync_url"])
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE INDEX {index_name} ON audit_log (source_ip)",
            )
        with pytest.raises(CommandError, match="unexpected definition"):
            command.upgrade(alembic_cfg, "head")
    finally:
        engine.dispose()


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize(
    "hostile_ddl",
    [
        "CREATE TABLE ix_audit_log_action_pattern (value INTEGER)",
        "CREATE TABLE audit_action_pattern_decoy (value INTEGER); "
        "CREATE INDEX ix_audit_log_action_pattern "
        "ON audit_action_pattern_decoy (value)",
    ],
    ids=["table", "foreign-table-index"],
)
def test_audit_action_pattern_reserved_name_conflicts_preserve_version(
    alembic_cfg: Config,
    direction: str,
    hostile_ddl: str,
) -> None:
    """0016 owns its reserved schema name, not only one table's indexes."""

    index_name = "ix_audit_log_action_pattern"
    if direction == "upgrade":
        command.upgrade(alembic_cfg, "v1_9_delivery_recipient")
        expected_version = "v1_9_delivery_recipient"
    else:
        command.upgrade(alembic_cfg, "head")
        expected_version = code_head()

    engine = create_engine(alembic_cfg.attributes["test_sync_url"])
    try:
        with engine.begin() as connection:
            if direction == "downgrade":
                connection.exec_driver_sql(f"DROP INDEX {index_name}")
            for statement in hostile_ddl.split("; "):
                connection.exec_driver_sql(statement)

        with engine.connect() as connection:
            before = tuple(
                connection.exec_driver_sql(
                    "SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?",
                    (index_name,),
                ).one()
            )

        with pytest.raises(CommandError, match="unexpected definition"):
            if direction == "upgrade":
                command.upgrade(alembic_cfg, "head")
            else:
                command.downgrade(alembic_cfg, "v1_9_delivery_recipient")

        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                == expected_version
            )
            after = tuple(
                connection.exec_driver_sql(
                    "SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?",
                    (index_name,),
                ).one()
            )
        assert after == before
    finally:
        engine.dispose()


def test_audit_action_pattern_model_uses_postgres_varchar_opclass() -> None:
    """The consolidated fresh schema retains non-C collation prefix support."""

    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex
    from z4j_brain.persistence.models import AuditLog

    index = next(
        item for item in AuditLog.__table__.indexes if item.name == "ix_audit_log_action_pattern"
    )
    ddl = str(CreateIndex(index).compile(dialect=postgresql.dialect()))
    assert "action varchar_pattern_ops" in ddl
    assert "occurred_at DESC" in ddl
    assert ddl.endswith("source_ip)")


def test_initial_revision_freezes_agents_before_soft_revoke(
    alembic_cfg: Config,
) -> None:
    """A current ORM field must not leak backward into the old revision."""
    command.upgrade(alembic_cfg, "v1_3_0_initial")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        initial = [column["name"] for column in inspect(engine).get_columns("agents")]
    finally:
        engine.dispose()

    assert "revoked_at" not in initial
    assert initial[-3:] == ["id", "created_at", "updated_at"]


def test_downgrade_refuses_revoked_agent_before_dropping_any_column(
    alembic_cfg: Config,
) -> None:
    """Older hygiene code must never receive an unmarked tombstone."""
    from z4j_brain.persistence.enums import AgentState
    from z4j_brain.persistence.models import Agent, Project
    from z4j_core.transport import CURRENT_PROTOCOL

    command.upgrade(alembic_cfg, "head")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    revoked_at = datetime.now(UTC)
    sentinel = f"revoked:{agent_id}:{revoked_at.isoformat()}"

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            session.add(Project(id=project_id, slug="revoked", name="Revoked"))
            session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name=f"revoked:{agent_id}",
                    token_hash=sentinel,
                    protocol_version=CURRENT_PROTOCOL,
                    framework_adapter="bare",
                    engine_adapters=[],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.OFFLINE,
                    revoked_at=revoked_at,
                ),
            )
            session.commit()
    finally:
        engine.dispose()

    _seed_stacked_release_evidence(sync_url)
    stacked_before = _stacked_release_evidence(sync_url)
    engine = create_engine(sync_url)
    try:
        before_agent_columns = {column["name"] for column in inspect(engine).get_columns("agents")}
        before_schedule_columns = {
            column["name"] for column in inspect(engine).get_columns("schedules")
        }
    finally:
        engine.dispose()

    with pytest.raises(CommandError, match=r"1 agent\(s\) are revoked"):
        command.downgrade(alembic_cfg, "v1_8_schedule_cursor_repair")

    engine = create_engine(sync_url)
    try:
        assert {
            column["name"] for column in inspect(engine).get_columns("agents")
        } == before_agent_columns
        assert {
            column["name"] for column in inspect(engine).get_columns("schedules")
        } == before_schedule_columns
        with engine.connect() as connection:
            version, retained_token, retained_marker = connection.exec_driver_sql(
                "SELECT (SELECT version_num FROM alembic_version), "
                "token_hash, revoked_at FROM agents WHERE id = ?",
                (agent_id.hex,),
            ).one()
        assert version == code_head()
        assert retained_token == sentinel
        assert retained_marker is not None
    finally:
        engine.dispose()
    assert _stacked_release_evidence(sync_url) == stacked_before


def test_migration_downgrade_runs(alembic_cfg: Config) -> None:
    """The pre-F additive line still has its historical empty round-trip."""
    command.upgrade(alembic_cfg, "v1_8_bulk_retry_requests")
    command.downgrade(alembic_cfg, "base")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    finally:
        engine.dispose()

    # Only the alembic bookkeeping table should remain.
    assert tables <= {"alembic_version"}


def test_boundary_f_activation_refuses_downgrade(alembic_cfg: Config) -> None:
    command.upgrade(alembic_cfg, "head")
    with pytest.raises(CommandError, match="refusing downgrade"):
        command.downgrade(alembic_cfg, "v1_8_audit_chain_prepare")


def test_downgrade_through_a_refusing_revision_runs_no_step(
    alembic_cfg: Config,
) -> None:
    """A refused rollback must leave everything above the fence alone.

    Alembic steps down one revision at a time and commits each step, so the
    additive 1.9 columns used to be dropped, and committed, before the
    Boundary-D refusal below them was reached. The operator saw "refused",
    upgraded back to head, and got ``paused_at`` re-added empty: every hold in
    the fleet released with no error and nothing in the audit trail.
    """
    command.upgrade(alembic_cfg, "head")
    held_at = asyncio.run(_pause_one_schedule(alembic_cfg.attributes["test_db_path"]))
    sync_url = alembic_cfg.attributes["test_sync_url"]
    _seed_stacked_release_evidence(sync_url)
    before = _schedule_state(sync_url)
    stacked_before = _stacked_release_evidence(sync_url)
    assert before[0] == code_head()
    assert {"paused_at", "overlap_policy"} <= before[1]
    assert before[2] == [_as_stored(held_at)]

    with pytest.raises(
        CommandError,
        match="refused before running any step of this downgrade",
    ):
        command.downgrade(alembic_cfg, "v1_8_bulk_retry_requests")

    assert _schedule_state(sync_url) == before
    assert _stacked_release_evidence(sync_url) == stacked_before

    # And the move an operator makes next must not be the one that loses it.
    command.upgrade(alembic_cfg, "head")
    assert _schedule_state(sync_url) == before
    assert _stacked_release_evidence(sync_url) == stacked_before


def test_single_step_downgrade_refuses_while_a_schedule_is_paused(
    alembic_cfg: Config,
) -> None:
    """The 0012 state guard protects every later 1.9 step stacked above it.

    Dropping ``paused_at`` releases every hold at once. With 0013 and 0014
    above the guard, checking only inside 0012 would also commit their schema
    and data loss before discovering the hold.
    """
    command.upgrade(alembic_cfg, "head")
    held_at = asyncio.run(_pause_one_schedule(alembic_cfg.attributes["test_db_path"]))
    sync_url = alembic_cfg.attributes["test_sync_url"]
    _seed_stacked_release_evidence(sync_url)
    before = _schedule_state(sync_url)
    stacked_before = _stacked_release_evidence(sync_url)

    with pytest.raises(CommandError, match=r"1 schedule\(s\) are paused"):
        command.downgrade(alembic_cfg, "v1_8_schedule_cursor_repair")

    after = _schedule_state(sync_url)
    assert after == before
    assert _stacked_release_evidence(sync_url) == stacked_before
    assert after[2] == [_as_stored(held_at)]

    command.upgrade(alembic_cfg, "head")
    assert _schedule_state(sync_url) == before


def test_single_step_downgrade_proceeds_when_no_schedule_is_paused(
    alembic_cfg: Config,
) -> None:
    """The hold guard must be a guard, not a blanket refusal."""
    command.upgrade(alembic_cfg, "head")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        before_inspector = inspect(engine)
        assert before_inspector.has_table("automation_rule_admissions")
        assert "cb_config_digest" in {
            column["name"] for column in before_inspector.get_columns("automation_rules")
        }
        assert "config_revision" in {
            column["name"] for column in before_inspector.get_columns("automation_rules")
        }
        assert "automation_revision" in {
            column["name"] for column in before_inspector.get_columns("projects")
        }
        assert "ux_agent_workers_legacy_agent" in {
            index["name"] for index in before_inspector.get_indexes("agent_workers")
        }
        assert "recipient_user_id" in {
            column["name"] for column in before_inspector.get_columns("notification_deliveries")
        }
        assert "ix_notification_deliveries_recipient_sent" in {
            index["name"] for index in before_inspector.get_indexes("notification_deliveries")
        }
    finally:
        engine.dispose()

    command.downgrade(alembic_cfg, "v1_8_schedule_cursor_repair")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version",
            ).scalar_one()
        schedule_columns = {column["name"] for column in inspect(engine).get_columns("schedules")}
        agent_columns = {column["name"] for column in inspect(engine).get_columns("agents")}
        automation_rule_columns = {
            column["name"] for column in inspect(engine).get_columns("automation_rules")
        }
        project_columns = {column["name"] for column in inspect(engine).get_columns("projects")}
        agent_worker_indexes = {
            index["name"] for index in inspect(engine).get_indexes("agent_workers")
        }
        has_admissions = inspect(engine).has_table("automation_rule_admissions")
        notification_delivery_columns = {
            column["name"] for column in inspect(engine).get_columns("notification_deliveries")
        }
        notification_delivery_indexes = {
            index["name"] for index in inspect(engine).get_indexes("notification_deliveries")
        }
    finally:
        engine.dispose()
    assert version == "v1_8_schedule_cursor_repair"
    assert not {"paused_at", "overlap_policy"} & schedule_columns
    assert "revoked_at" not in agent_columns
    assert not {"cb_config_digest", "config_revision"} & automation_rule_columns
    assert "automation_revision" not in project_columns
    assert "ux_agent_workers_legacy_agent" not in agent_worker_indexes
    assert has_admissions is False
    assert "recipient_user_id" not in notification_delivery_columns
    assert "ix_notification_deliveries_recipient_sent" not in notification_delivery_indexes

    command.upgrade(alembic_cfg, "head")
    assert _schedule_state(sync_url)[0] == code_head()


def _sqlite_catalog_snapshot(sync_url: str) -> tuple[tuple[object, ...], ...]:
    """Complete user-visible SQLite catalog snapshot for atomicity checks."""

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            return tuple(
                tuple(row)
                for row in connection.exec_driver_sql(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
                ).all()
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "conflicting_ddl, error",
    [
        (
            (
                "ALTER TABLE automation_rules ADD COLUMN config_revision TEXT DEFAULT 'bogus'",
                "ALTER TABLE automation_rules ADD COLUMN "
                "cb_config_digest INTEGER NOT NULL DEFAULT 7",
                "ALTER TABLE projects ADD COLUMN automation_revision TEXT",
                "CREATE TABLE automation_rule_admissions ("
                "rule_id TEXT, admitted_at INTEGER, weight TEXT, id TEXT)",
            ),
            "incompatible same-name schema object",
        ),
        (
            (
                "ALTER TABLE automation_rules ADD COLUMN "
                "config_revision INTEGER NOT NULL DEFAULT '1'",
            ),
            "already or only partially present",
        ),
    ],
)
def test_automation_rolling_upgrade_rejects_conflicting_schema_atomically(
    alembic_cfg: Config,
    conflicting_ddl: tuple[str, ...],
    error: str,
) -> None:
    """Same-name or partial 0014 objects can never be treated as installed."""

    command.upgrade(alembic_cfg, "v1_9_agent_worker_legacy_slot")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            for statement in conflicting_ddl:
                connection.exec_driver_sql(statement)
    finally:
        engine.dispose()
    before = _sqlite_catalog_snapshot(sync_url)

    with pytest.raises(CommandError, match=error):
        command.upgrade(alembic_cfg, "v1_9_automation_rolling_window")

    assert _sqlite_catalog_snapshot(sync_url) == before
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version",
                ).scalar_one()
                == "v1_9_agent_worker_legacy_slot"
            )
    finally:
        engine.dispose()


def test_automation_rolling_upgrade_preserves_sqlite_debt_and_digest(
    alembic_cfg: Config,
) -> None:
    """Typed UUID backfill binds and its epoch digest matches runtime ORM data."""

    from z4j_brain.persistence.models import AutomationRule, Project
    from z4j_brain.persistence.repositories.automation_rule import dispatch_candidate

    command.upgrade(alembic_cfg, "v1_9_agent_worker_legacy_slot")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    project_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO projects (id, slug, name) VALUES (?, ?, ?)",
                (project_id.hex, f"legacy-{project_id.hex[:8]}", "Legacy"),
            )
            connection.exec_driver_sql(
                "INSERT INTO automation_rules ("
                "id, project_id, name, trigger, max_executions_per_window, "
                "window_seconds, cb_window_start, cb_execution_count"
                ") VALUES (?, ?, ?, ?, 3, 3600, "
                "strftime('%Y-%m-%d %H:%M:%f', 'now'), 2)",
                (rule_id.hex, project_id.hex, "legacy-debt", "task.failed"),
            )
    finally:
        engine.dispose()

    command.upgrade(alembic_cfg, "v1_9_automation_rolling_window")

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            rule = session.get(AutomationRule, rule_id)
            project = session.get(Project, project_id)
            assert rule is not None
            assert project is not None
            assert (
                rule.cb_config_digest
                == dispatch_candidate(
                    rule,
                    project_revision=project.automation_revision,
                ).config_digest
            )
            assert rule.is_enabled is True
            assert rule.dry_run is False
            assert rule.cb_tripped is False
        with engine.connect() as connection:
            admission = connection.exec_driver_sql(
                "SELECT rule_id, weight FROM automation_rule_admissions",
            ).one()
            assert admission == (rule_id.hex, 2)
    finally:
        engine.dispose()


def test_automation_rolling_upgrade_preserves_future_legacy_anchor(
    alembic_cfg: Config,
) -> None:
    """Clock-skewed future legacy debt cannot be re-anchored earlier."""

    command.upgrade(alembic_cfg, "v1_9_agent_worker_legacy_slot")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    project_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    future = datetime.now(UTC) + timedelta(seconds=30)
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO projects (id, slug, name) VALUES (?, ?, ?)",
                (project_id.hex, f"future-{project_id.hex[:8]}", "Future"),
            )
            connection.exec_driver_sql(
                "INSERT INTO automation_rules ("
                "id, project_id, name, trigger, max_executions_per_window, "
                "window_seconds, cb_window_start, cb_execution_count"
                ") VALUES (?, ?, ?, ?, 3, 60, ?, 2)",
                (
                    rule_id.hex,
                    project_id.hex,
                    "future-debt",
                    "task.failed",
                    future.replace(tzinfo=None),
                ),
            )
    finally:
        engine.dispose()

    command.upgrade(alembic_cfg, "v1_9_automation_rolling_window")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            projected, admitted = connection.exec_driver_sql(
                "SELECT rule.cb_window_start, admission.admitted_at "
                "FROM automation_rules AS rule "
                "JOIN automation_rule_admissions AS admission "
                "ON admission.rule_id = rule.id WHERE rule.id = ?",
                (rule_id.hex,),
            ).one()
        assert datetime.fromisoformat(projected).replace(tzinfo=UTC) >= future
        assert datetime.fromisoformat(admitted).replace(tzinfo=UTC) >= future
    finally:
        engine.dispose()


def test_automation_rolling_downgrade_reanchors_staggered_debt(
    alembic_cfg: Config,
) -> None:
    """Rolling admissions cannot fall through the legacy fixed-window edge."""

    command.upgrade(alembic_cfg, "v1_9_automation_rolling_window")
    sync_url = alembic_cfg.attributes["test_sync_url"]
    project_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO projects (id, slug, name) VALUES (?, ?, ?)",
                (project_id.hex, f"collapse-{project_id.hex[:8]}", "Collapse"),
            )
            now_text = connection.exec_driver_sql(
                "SELECT strftime('%Y-%m-%d %H:%M:%f', 'now')",
            ).scalar_one()
            now = datetime.fromisoformat(now_text).replace(tzinfo=UTC)
            oldest = now - timedelta(seconds=59)
            newest = now - timedelta(seconds=1)
            connection.exec_driver_sql(
                "INSERT INTO automation_rules ("
                "id, project_id, name, trigger, max_executions_per_window, "
                "window_seconds, cb_window_start, cb_execution_count, "
                "cb_config_digest, cb_tripped) "
                "VALUES (?, ?, ?, ?, 2, 60, ?, 2, ?, 0)",
                (
                    rule_id.hex,
                    project_id.hex,
                    "staggered",
                    "task.failed",
                    oldest.replace(tzinfo=None),
                    "d" * 64,
                ),
            )
            for admitted_at in (oldest, newest):
                connection.exec_driver_sql(
                    "INSERT INTO automation_rule_admissions "
                    "(id, rule_id, admitted_at, weight) VALUES (?, ?, ?, 1)",
                    (
                        uuid.uuid4().hex,
                        rule_id.hex,
                        admitted_at.replace(tzinfo=None),
                    ),
                )
    finally:
        engine.dispose()

    command.downgrade(alembic_cfg, "v1_9_agent_worker_legacy_slot")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            window_start, count, tripped = connection.exec_driver_sql(
                "SELECT cb_window_start, cb_execution_count, cb_tripped "
                "FROM automation_rules WHERE id = ?",
                (rule_id.hex,),
            ).one()
        anchor = datetime.fromisoformat(window_start).replace(tzinfo=UTC)
        assert count == 2
        assert tripped == 0
        assert anchor >= now
        # The legacy algorithm would reset at oldest+W. Re-anchoring means a
        # claim just beyond that old edge is still inside the conservative
        # fixed window and cannot admit a third execution in 60 seconds.
        legacy_edge_probe = oldest + timedelta(seconds=60, milliseconds=500)
        assert legacy_edge_probe < anchor + timedelta(seconds=60)
    finally:
        engine.dispose()


def test_offline_downgrade_sql_fails_closed_at_stateful_guard(
    alembic_cfg: Config,
) -> None:
    """No SQL artifact may pretend it evaluated live holds or tombstones."""

    with pytest.raises(
        CommandError,
        match="offline downgrade SQL cannot evaluate live database-state preflight",
    ):
        command.downgrade(
            alembic_cfg,
            f"{code_head()}:v1_8_schedule_cursor_repair",
            sql=True,
        )


def test_every_unconditionally_refusing_migration_declares_itself(
    alembic_cfg: Config,
) -> None:
    """The pre-flight is only inherited by migrations that say they refuse.

    ``env.py`` decides the whole plan by reading ``DOWNGRADE_REFUSED`` off each
    planned module. A migration whose ``downgrade`` is nothing but a ``raise``
    refuses unconditionally, so if it does not declare that, everything stacked
    above it silently goes back to being dropped and committed first.
    """
    import ast

    from alembic.script import ScriptDirectory

    undeclared = []
    for script in ScriptDirectory.from_config(alembic_cfg).walk_revisions():
        tree = ast.parse(Path(script.path).read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name != "downgrade":
                continue
            body = [
                statement
                for statement in node.body
                if not (
                    isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                )
            ]
            unconditional = len(body) == 1 and isinstance(body[0], ast.Raise)
            if unconditional and not hasattr(script.module, "DOWNGRADE_REFUSED"):
                undeclared.append(script.revision)

    assert undeclared == []


def test_boundary_f_sqlite_activation_is_atomic(
    alembic_cfg: Config,
) -> None:
    alembic_cfg.attributes["z4j_test_fail_audit_activation_after_state"] = True
    with pytest.raises(
        RuntimeError,
        match="injected Boundary-F activation failure",
    ):
        command.upgrade(alembic_cfg, "head")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version",
            ).scalar_one()
            preparation_count = connection.exec_driver_sql(
                "SELECT COUNT(*) FROM audit_chain_preparation",
            ).scalar_one()
            state_table = connection.exec_driver_sql(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type='table' AND name='audit_chain_state'",
            ).scalar_one()
            activation_rows = connection.exec_driver_sql(
                "SELECT COUNT(*) FROM audit_log WHERE action='audit.chain_generation_started'",
            ).scalar_one()
    finally:
        engine.dispose()

    assert version == "v1_8_audit_chain_prepare"
    assert preparation_count == 1
    assert state_table == 0
    assert activation_rows == 0


def test_v1_6_6_scrub_worker_conf_strips_existing_rows_r7_h1(
    alembic_cfg: Config,
) -> None:
    """Pre-1.6.6 worker rows carrying credentialed Celery conf
    must be scrubbed when ``alembic upgrade head`` runs.

    The migration is dialect-aware; this test covers the SQLite branch
    by stamping to the pre-1.6.6 head, manually inserting a
    representative ``workers`` row, then running ``upgrade head`` and
    asserting the JSON column no longer contains the secret values.
    The Postgres branch is exercised by ``test_migration_pg.py``.
    """
    import json
    import uuid

    from sqlalchemy import text as _text

    # Bring the schema up to just before 1.6.6 so the workers table
    # exists and we can pre-populate it.
    command.upgrade(alembic_cfg, "v1_6_mfa_totp")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    project_id = uuid.uuid4()
    worker_id = uuid.uuid4()
    leaky_metadata = {
        "stats": {"pool": {"max-concurrency": 2}},
        "active": [],
        "active_queues": [{"name": "celery"}],
        "registered": ["myapp.task"],
        "conf": {
            "broker_url": "redis://:LEAKED_CRED@redis.internal/0",
            "result_backend": "db+postgresql://u:LEAKED_PG@db/celery",
            "broker_transport_options": {"aws_secret_access_key": "LEAKED_AWS"},
            "task_serializer": "json",
        },
    }
    try:
        with engine.begin() as conn:
            # Insert a project parent so the FK is satisfied (the
            # workers row carries a project_id NOT NULL FK).
            conn.execute(
                _text(
                    "INSERT INTO projects (id, slug, name, created_at) "
                    "VALUES (:id, :slug, :name, datetime('now'))",
                ),
                {"id": str(project_id), "slug": "p1", "name": "P1"},
            )
            conn.execute(
                _text(
                    "INSERT INTO workers (id, project_id, engine, name, "
                    "state, last_heartbeat, metadata, created_at, updated_at) "
                    "VALUES (:id, :project_id, 'celery', 'celery@w1', "
                    "'online', datetime('now'), :md, datetime('now'), "
                    "datetime('now'))",
                ),
                {
                    "id": str(worker_id),
                    "project_id": str(project_id),
                    "md": json.dumps(leaky_metadata),
                },
            )

        # Now run the new migration.
        command.upgrade(alembic_cfg, "v1_8_bulk_retry_requests")

        with engine.connect() as conn:
            row = conn.execute(
                _text("SELECT metadata FROM workers WHERE id = :id"),
                {"id": str(worker_id)},
            ).fetchone()
            assert row is not None
            md = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            assert isinstance(md, dict)
            # conf was scrubbed to empty object.
            assert md.get("conf") == {}
            # Other sub-keys are untouched.
            assert md.get("stats", {}).get("pool", {}).get("max-concurrency") == 2
            assert md.get("registered") == ["myapp.task"]
            # And the raw secret values must not be anywhere in the JSON.
            blob = json.dumps(md)
            for needle in ("LEAKED_CRED", "LEAKED_PG", "LEAKED_AWS"):
                assert needle not in blob, f" migration left {needle!r} in workers.metadata"
    finally:
        engine.dispose()
