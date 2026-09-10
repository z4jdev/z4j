"""Executable SQLite gates for the authenticated Boundary-D activation."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine, func, inspect, null, select, text
from sqlalchemy import text as sa_text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from z4j_brain import cli as cli_module
from z4j_brain import management_reset as management_reset_module
from z4j_brain import management_restore as management_restore_module
from z4j_brain import management_restore_postgres as postgres_restore_module
from z4j_brain.backup import (
    backup_sqlite,
    restore_sqlite,
    rollback_restore,
)
from z4j_brain.domain.audit_chain import (
    authenticate_state,
    build_audit_keyring,
)
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.management_restore import (
    DatabaseRestorePending,
    DatabaseRestoreRefused,
)
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_engine_from_settings,
)
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    AuditChainState,
    AuditLog,
    Command,
    Event,
    PendingFire,
    Project,
    Schedule,
    ScheduleChangeLog,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleFire,
    ScheduleOccurrenceResolution,
    ScheduleOwnerCutover,
    ScheduleRevisionState,
    User,
)
from z4j_brain.persistence.models import (
    Session as UserSession,
)
from z4j_brain.persistence.repositories import (
    AgentRepository,
    CommandRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)
from z4j_brain.persistence.repositories import (
    schedule_external as schedule_external_repository_module,
)
from z4j_brain.persistence.repositories.pending_fires import (
    PendingFiresRepository,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.repositories.schedule_external import (
    ScheduleExternalRepository,
)
from z4j_brain.persistence.repositories.schedule_fires import (
    ScheduleFireRepository,
)
from z4j_brain.persistence.schedule_external_guard import (
    arm_external_lifecycle_transition,
    assert_external_lifecycle_consumed,
)
from z4j_brain.persistence.schedule_guard import arm_schedule_transition
from z4j_brain.secret_store import ensure_secret_store_directory
from z4j_brain.settings import Settings
from z4j_brain.websocket.gateway import (
    _issue_external_schedule_activations,
)
from z4j_core.redaction import RedactionConfig, RedactionEngine
from z4j_core.schedule_external import (
    EXTERNAL_SCHEDULE_RUNTIME_FEATURE,
    EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
    external_projection_body,
    external_projection_digest,
    external_snapshot_frame_body,
    external_snapshot_frame_digest,
)

from tests.migration_head import code_head

_SQLITE_AUDIT_STATE_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER audit_chain_state_boundary_f_no_update
BEFORE UPDATE ON audit_chain_state
FOR EACH ROW
BEGIN
  SELECT z4j_audit_guard('state_update', '');
END
"""


def test_reset_manifest_datetime_is_canonical_across_session_timezones() -> None:
    instant = datetime(2026, 7, 25, 18, 30, 15, 123456, tzinfo=UTC)
    same_in_new_york = instant.astimezone(
        timezone(timedelta(hours=-4)),
    )

    utc_value = management_reset_module._normalize_manifest_value(instant)
    local_value = management_reset_module._normalize_manifest_value(
        same_in_new_york,
    )
    assert utc_value == local_value == "2026-07-25T18:30:15.123456+00:00"
    assert management_reset_module.release_manifest_digest(
        {"observed_at": utc_value},
    ) == management_reset_module.release_manifest_digest(
        {"observed_at": local_value},
    )


@pytest.mark.parametrize("address", ["192.0.2.1", "2001:db8::1", "192.0.2.1/24", "2001:db8::1/64"])
def test_reset_manifest_preserves_postgres_inet_values(address: str) -> None:
    value = ipaddress.ip_interface(address) if "/" in address else ipaddress.ip_address(address)
    assert management_reset_module._normalize_manifest_value(value) == address
    assert management_reset_module._normalize_manifest_value({"ip": [value]}) == {"ip": [address]}


def test_reset_manifest_still_refuses_unknown_objects() -> None:
    with pytest.raises(management_reset_module.GenerationResetRefused, match="cannot canonicalize"):
        management_reset_module._normalize_manifest_value(object())


def test_postgres_schema_contract_covers_supported_server_majors() -> None:
    """Restore/reset attestation covers both documented production majors."""

    assert set(
        management_reset_module._POSTGRES_SCHEMA_CONTRACT_DIGESTS,
    ).issuperset({17, 18})
    assert set(
        postgres_restore_module._RELEASE_SCHEMA_DEFINITIONS_DIGESTS,
    ).issuperset({17, 18})
    assert set(
        postgres_restore_module._LEGACY_SCHEMA_DEFINITIONS_DIGESTS,
    ).issuperset({17, 18})


def test_postgres_restore_coordinator_pins_utc_session() -> None:
    target = postgres_restore_module._Target(
        database_url="postgresql+asyncpg://z4j:secret@127.0.0.1:5432/z4j",
        libpq_url="postgresql://z4j:secret@127.0.0.1:5432/z4j",
        host="127.0.0.1",
        hostaddr="127.0.0.1",
        port=5432,
        database="z4j",
        username="z4j",
        password="secret",
        sslmode="disable",
        sslrootcert=None,
        sslcert=None,
        sslkey=None,
    )
    parameters = postgres_restore_module._pinned_connection_parameters(
        target,
        autocommit=False,
    )

    assert parameters["options"] == "-c timezone=UTC"


@pytest.fixture
def boundary_d_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Config, str, str]]:
    private_home = ensure_secret_store_directory(
        tmp_path / "z4j-boundary-d",
    )
    db_path = private_home / "z4j.db"
    sync_url = f"sqlite:///{db_path}"
    async_url = f"sqlite+aiosqlite:///{db_path}"
    backend_root = Path(__file__).resolve().parents[2]
    alembic_ini = backend_root / "alembic.ini"

    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(backend_root)

    config = Config(str(alembic_ini))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    try:
        yield config, sync_url, async_url
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


def _project(project_id: uuid.UUID, slug: str) -> Project:
    return Project(id=project_id, slug=slug, name=slug.title())


def _insert_historical_project(
    session: Session,
    *,
    project_id: uuid.UUID,
    slug: str,
) -> None:
    """Insert through a pre-0014 project schema, not today's ORM mapper."""

    session.execute(
        text(
            "INSERT INTO projects(id, slug, name) VALUES (:project_id, :slug, :name)",
        ),
        {
            "project_id": project_id.hex,
            "slug": slug,
            "name": slug.title(),
        },
    )


def _schedule(
    project_id: uuid.UUID,
    *,
    schedule_id: uuid.UUID,
    name: str,
    scheduler: str = "z4j-scheduler",
    expression: str = "5m",
) -> Schedule:
    return Schedule(
        id=schedule_id,
        project_id=project_id,
        engine="celery",
        scheduler=scheduler,
        name=name,
        task_name=f"jobs.{name}",
        kind="interval",
        expression=expression,
        timezone="UTC",
        queue=None,
        priority="normal",
        args=[],
        kwargs={},
        is_enabled=True,
        last_run_at=None,
        next_run_at=None,
        total_runs=0,
        external_id=None,
        catch_up="skip",
        source="dashboard",
        source_hash=None,
        last_fire_id=None,
    )


def _insert_pre_boundary_d_schedule(
    session: Session,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    name: str,
    scheduler: str = "z4j-scheduler",
    expression: str = "5m",
) -> None:
    """Insert through the actual pre-D schema, not the current ORM shape."""

    session.execute(
        text(
            "INSERT INTO schedules("
            "project_id, engine, scheduler, name, task_name, kind, expression, id"
            ") VALUES ("
            ":project_id, 'celery', :scheduler, :name, :task_name, "
            "'interval', :expression, :schedule_id"
            ")",
        ),
        {
            "project_id": project_id.hex,
            "scheduler": scheduler,
            "name": name,
            "task_name": f"jobs.{name}",
            "expression": expression,
            "schedule_id": schedule_id.hex,
        },
    )


def _insert_pre_boundary_d_command(
    session: Session,
    *,
    command_id: uuid.UUID,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    timeout_at: datetime,
) -> None:
    session.execute(
        text(
            "INSERT INTO commands("
            "project_id, action, target_type, target_id, payload, status, "
            "timeout_at, id"
            ") VALUES ("
            ":project_id, 'schedule.fire', 'schedule', :target_id, '{}', "
            "'failed', :timeout_at, :command_id"
            ")",
        ),
        {
            "project_id": project_id.hex,
            "target_id": str(schedule_id),
            "timeout_at": timeout_at.replace(tzinfo=None).isoformat(sep=" "),
            "command_id": command_id.hex,
        },
    )


def _insert_pre_boundary_d_fire(
    session: Session,
    *,
    row_id: uuid.UUID,
    fire_id: uuid.UUID,
    schedule_id: uuid.UUID,
    project_id: uuid.UUID,
    scheduled_for: datetime,
    command_id: uuid.UUID | None = None,
) -> None:
    session.execute(
        text(
            "INSERT INTO schedule_fires("
            "id, fire_id, schedule_id, project_id, command_id, status, "
            "scheduled_for, fired_at"
            ") VALUES ("
            ":row_id, :fire_id, :schedule_id, :project_id, :command_id, "
            "'failed', :scheduled_for, :fired_at"
            ")",
        ),
        {
            "row_id": row_id.hex,
            "fire_id": fire_id.hex,
            "schedule_id": schedule_id.hex,
            "project_id": project_id.hex,
            "command_id": None if command_id is None else command_id.hex,
            "scheduled_for": scheduled_for.replace(tzinfo=None).isoformat(
                sep=" ",
            ),
            "fired_at": scheduled_for.replace(tzinfo=None).isoformat(sep=" "),
        },
    )


def _insert_pre_boundary_d_pending_fire(
    session: Session,
    *,
    row_id: uuid.UUID,
    fire_id: uuid.UUID,
    schedule_id: uuid.UUID,
    project_id: uuid.UUID,
    scheduled_for: datetime,
    enqueued_at: datetime,
    expires_at: datetime,
) -> None:
    session.execute(
        text(
            "INSERT INTO pending_fires("
            "id, fire_id, schedule_id, project_id, engine, payload, "
            "scheduled_for, enqueued_at, expires_at"
            ") VALUES ("
            ":row_id, :fire_id, :schedule_id, :project_id, 'celery', '{}', "
            ":scheduled_for, :enqueued_at, :expires_at"
            ")",
        ),
        {
            "row_id": row_id.hex,
            "fire_id": fire_id.hex,
            "schedule_id": schedule_id.hex,
            "project_id": project_id.hex,
            "scheduled_for": scheduled_for.replace(tzinfo=None).isoformat(
                sep=" ",
            ),
            "enqueued_at": enqueued_at.replace(tzinfo=None).isoformat(sep=" "),
            "expires_at": expires_at.replace(tzinfo=None).isoformat(sep=" "),
        },
    )


def _audit_keyring() -> dict[str, bytes]:
    settings = Settings()  # type: ignore[call-arg]
    secrets = settings.all_audit_chain_secrets_for_verification()
    assert secrets
    _, keyring = build_audit_keyring(secrets[0], secrets[1:])
    return keyring


async def test_legacy_subsecond_cursor_executes_after_boundary_d_upgrade(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """A 1.7 wall-clock cursor must not permanently reject 1.8 slots."""

    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
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
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="legacy-subsecond",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="legacy-subsecond",
                expression="5s",
            )
            session.execute(
                text(
                    "UPDATE schedules SET last_run_at = :last_run_at, "
                    "total_runs = 23, is_enabled = 1 "
                    "WHERE id = :schedule_id",
                ),
                {
                    "last_run_at": legacy_last.isoformat(
                        sep=" ",
                        timespec="microseconds",
                    ),
                    "schedule_id": schedule_id.hex,
                },
            )
            session.commit()
    finally:
        engine.dispose()

    # Upgrade to head, not to the revision that happened to be head when
    # this test was written. Everything below exercises RUNTIME behaviour
    # through the ORM and the fire authority, and in production those
    # always run against head, so parking the schema earlier tests a
    # combination that never occurs and breaks on the next migration.
    await asyncio.to_thread(command.upgrade, config, "head")
    database = DatabaseManager(create_async_engine(async_url))
    try:
        async with database.session(write=True) as session:
            schedule = await session.get(Schedule, schedule_id)
            assert schedule is not None
            assert schedule.control_token is not None
            assert schedule.definition_digest is not None
            assert schedule.schedule_revision is not None
            assert schedule.last_run_at is not None
            assert schedule.next_run_at is not None

            expected_last = schedule.last_run_at.replace(tzinfo=UTC)
            expected_next = schedule.next_run_at.replace(tzinfo=UTC)
            slot = expected_next.replace(microsecond=0)
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
                expected_last_run_at=expected_last,
                expected_next_run_at=expected_next,
                prepared_next_run_at=successor,
                cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
                cadence_fingerprint=cadence_runtime_fingerprint(),
                occurred_at=slot + timedelta(seconds=1),
            )
            assert transition.disposition == "applied"
            assert schedule.total_runs == 24
            assert schedule.last_run_at.replace(tzinfo=UTC) == slot
            assert schedule.next_run_at.replace(tzinfo=UTC) == successor
            await session.commit()
    finally:
        await database.dispose()


async def test_existing_activated_subsecond_cursor_is_repaired_at_head(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """The post-D repair must recover databases that ran the affected RC."""

    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    disabled_schedule_id = uuid.uuid4()
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
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="activated-subsecond",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="activated-subsecond",
                expression="5s",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=disabled_schedule_id,
                name="disabled-subsecond",
                expression="5s",
            )
            session.execute(
                text(
                    "UPDATE schedules SET last_run_at = :last_run_at, "
                    "total_runs = 23, is_enabled = 1 "
                    "WHERE id = :schedule_id",
                ),
                {
                    "last_run_at": legacy_last.isoformat(
                        sep=" ",
                        timespec="microseconds",
                    ),
                    "schedule_id": schedule_id.hex,
                },
            )
            session.execute(
                text(
                    "UPDATE schedules SET last_run_at = :last_run_at, "
                    "next_run_at = NULL, total_runs = 11, is_enabled = 0 "
                    "WHERE id = :schedule_id",
                ),
                {
                    "last_run_at": legacy_last.isoformat(
                        sep=" ",
                        timespec="microseconds",
                    ),
                    "schedule_id": disabled_schedule_id.hex,
                },
            )
            session.commit()
    finally:
        engine.dispose()

    config.attributes["z4j_test_preserve_legacy_cursor_precision"] = True
    try:
        await asyncio.to_thread(
            command.upgrade,
            config,
            "v1_8_schedule_control_activate",
        )
    finally:
        config.attributes.pop(
            "z4j_test_preserve_legacy_cursor_precision",
            None,
        )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            pre_repair = connection.execute(
                text(
                    "SELECT last_run_at, next_run_at, total_runs "
                    "FROM schedules WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id.hex},
            ).one()
            assert ".357644" in str(pre_repair.last_run_at)
            assert ".357644" in str(pre_repair.next_run_at)
            assert pre_repair.total_runs == 23
            disabled_pre_repair = connection.execute(
                text(
                    "SELECT last_run_at, next_run_at, is_enabled "
                    "FROM schedules WHERE id = :schedule_id",
                ),
                {"schedule_id": disabled_schedule_id.hex},
            ).one()
            assert ".357644" in str(disabled_pre_repair.last_run_at)
            assert disabled_pre_repair.next_run_at is None
            assert not disabled_pre_repair.is_enabled
    finally:
        engine.dispose()

    await asyncio.to_thread(command.upgrade, config, "head")
    database = DatabaseManager(create_async_engine(async_url))
    try:
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

            disabled_schedule = await session.get(
                Schedule,
                disabled_schedule_id,
            )
            assert disabled_schedule is not None
            assert not disabled_schedule.is_enabled
            assert disabled_schedule.last_run_at is not None
            assert disabled_schedule.last_run_at.microsecond == 0
            assert disabled_schedule.next_run_at is None

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

            expected_last = schedule.last_run_at.replace(tzinfo=UTC)
            expected_next = schedule.next_run_at.replace(tzinfo=UTC)
            successor = expected_next + timedelta(seconds=5)
            transition = await ScheduleControlRepository(
                session,
            ).accept_current_fire_progress(
                project_id=project_id,
                schedule_id=schedule_id,
                fire_id=derive_scheduler_fire_id(
                    schedule_id,
                    expected_next,
                ),
                scheduled_for=expected_next,
                observed_control_token=schedule.control_token,
                definition_digest=schedule.definition_digest,
                expected_revision=schedule.schedule_revision,
                expected_last_run_at=expected_last,
                expected_next_run_at=expected_next,
                prepared_next_run_at=successor,
                cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
                cadence_fingerprint=cadence_runtime_fingerprint(),
                occurred_at=expected_next + timedelta(seconds=1),
            )
            assert transition.disposition == "applied"
            assert schedule.total_runs == 24
            await session.commit()
    finally:
        await database.dispose()


async def test_existing_invalid_quarantine_cursor_is_parked_at_head(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """Repair an affected-RC quarantine without reparsing invalid cadence."""

    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
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
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="invalid-quarantine-repair",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="invalid-quarantine-repair",
                expression="not-an-interval",
            )
            session.execute(
                text(
                    "UPDATE schedules SET last_run_at = :last_run_at, "
                    "next_run_at = :next_run_at, total_runs = 17 "
                    "WHERE id = :schedule_id",
                ),
                {
                    "last_run_at": legacy_last.isoformat(
                        sep=" ",
                        timespec="microseconds",
                    ),
                    "next_run_at": legacy_next.isoformat(
                        sep=" ",
                        timespec="microseconds",
                    ),
                    "schedule_id": schedule_id.hex,
                },
            )
            session.commit()
    finally:
        engine.dispose()

    config.attributes["z4j_test_preserve_legacy_cursor_precision"] = True
    try:
        await asyncio.to_thread(
            command.upgrade,
            config,
            "v1_8_schedule_control_activate",
        )
    finally:
        config.attributes.pop(
            "z4j_test_preserve_legacy_cursor_precision",
            None,
        )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            # Read explicit columns, not session.get(Schedule, ...). The
            # database is deliberately parked at an intermediate revision
            # here, and the ORM model belongs to the CURRENT release, so a
            # whole-entity load asks for columns a later migration has not
            # created yet.
            quarantined = (
                connection.execute(
                    sa_text(
                        "SELECT is_enabled, quarantine_code, quarantine_control_token, "
                        "control_token, last_run_at, next_run_at "
                        "FROM schedules WHERE id = :schedule_id",
                    ),
                    {"schedule_id": schedule_id.hex},
                )
                .mappings()
                .one_or_none()
            )
            assert quarantined is not None
            assert not quarantined["is_enabled"]
            assert quarantined["quarantine_code"] == "migration_definition_invalid"
            assert quarantined["quarantine_control_token"] == quarantined["control_token"]
            assert quarantined["last_run_at"] is not None
            assert quarantined["next_run_at"] is not None
            assert "357644" in str(quarantined["last_run_at"])
            assert "357644" in str(quarantined["next_run_at"])
    finally:
        engine.dispose()

    await asyncio.to_thread(command.upgrade, config, "head")
    database = DatabaseManager(create_async_engine(async_url))
    try:
        async with database.session(write=True) as session:
            schedule = await session.get(Schedule, schedule_id)
            assert schedule is not None
            assert not schedule.is_enabled
            assert schedule.quarantine_code == "migration_definition_invalid"
            assert schedule.quarantine_control_token == schedule.control_token
            assert schedule.last_run_at is not None
            assert schedule.last_run_at.microsecond == 0
            assert schedule.next_run_at is None
            assert schedule.total_runs == 17

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
            assert repair_log.snapshot["transition"]["repaired_next_run_at"] is None
            await session.commit()
    finally:
        await database.dispose()


def test_sqlite_restore_rebases_above_target_authority_and_signs_marker(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """A restored old snapshot must be newer than every pre-restore cursor."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "v1_8_audit_chain_activate")
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="restore-rebase",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="source-name",
            )
            session.commit()
    finally:
        engine.dispose()
    command.upgrade(config, "head")

    backup_path = Path(sync_url.removeprefix("sqlite:///")).parent / "source.db"
    backup_sqlite(async_url, backup_path)

    async def _advance_target() -> int:
        database = DatabaseManager(create_async_engine(async_url))
        try:
            async with database.session(write=True) as session:
                updated = await ScheduleControlRepository(
                    session,
                ).update_current(
                    project_id=project_id,
                    schedule_id=schedule_id,
                    data={"name": "target-newer-name"},
                    planning_at=datetime(2026, 7, 25, 14, 0, tzinfo=UTC),
                )
                assert updated is not None
                await session.commit()
                return int(updated.schedule_revision or 0)
        finally:
            await database.dispose()

    target_revision = asyncio.run(_advance_target())
    assert target_revision >= 2

    result = restore_sqlite(async_url, backup_path)
    assert result["known_head_result"] == "ROLLBACK_NOT_ASSESSED"

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            restored = session.get(Schedule, schedule_id)
            state = session.get(
                ScheduleRevisionState,
                "schedule-revision",
            )
            allocator = session.get(
                ScheduleExternalEpochAllocator,
                "schedule-external-epoch",
            )
            assert restored is not None
            assert state is not None
            assert allocator is not None
            assert restored.name == "source-name"
            assert state.change_log_pruned_through > target_revision
            assert restored.schedule_revision > state.change_log_pruned_through
            assert state.current_revision == restored.schedule_revision
            assert allocator.current_epoch_number > 0
            marker = (
                (
                    session.execute(
                        select(AuditLog)
                        .where(
                            AuditLog.action == "audit.database_restored",
                        )
                        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
                    )
                )
                .scalars()
                .first()
            )
            assert marker is not None
            assert marker.audit_metadata["revision_rebase"] == {
                "captured_target_revision": target_revision,
                "restored_revision": 1,
                "barrier_revision": target_revision + 1,
                "final_revision": target_revision + 2,
                "schedule_count": 1,
            }
            assert marker.audit_metadata["known_head_result"] == "ROLLBACK_NOT_ASSESSED"
    finally:
        engine.dispose()


def test_sqlite_restore_assesses_and_signs_supplied_known_head(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """Restore persists one retained anchor and reports its exact result."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            state = session.get(AuditChainState, "audit-chain")
            assert state is not None
            known_head = {
                "row_hmac": state.head_row_hmac,
                "hmac_version": 2,
                "hmac_key_id": state.head_hmac_key_id,
                "generation": str(state.generation),
                "occurred_at": state.head_occurred_at.isoformat(),
                "id": str(state.head_id),
            }
    finally:
        engine.dispose()

    backup_path = Path(sync_url.removeprefix("sqlite:///")).parent / "known-source.db"
    backup_sqlite(async_url, backup_path)
    operation_id = uuid.uuid4()
    result = restore_sqlite(
        async_url,
        backup_path,
        operation=str(operation_id),
        known_head=known_head,
    )
    assert result["known_head_result"] == "CURRENT_MATCH"

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            marker = (
                session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.database_restored",
                        AuditLog.target_id == str(operation_id),
                    ),
                )
            ).scalar_one()
            assert marker.audit_metadata["known_head"] == known_head
            assert marker.audit_metadata["known_head_result"] == "CURRENT_MATCH"
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "known_head",
    [
        {"row_hmac": "not-a-hmac"},
        {"row_hmac": "0" * 64},
    ],
    ids=["invalid", "unprovable"],
)
def test_sqlite_restore_keeps_invalid_or_unprovable_known_head_pending(
    boundary_d_install: tuple[Config, str, str],
    known_head: dict[str, object],
) -> None:
    """A bad retained anchor can neither disappear on resume nor sign success."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "bad-known-source.db"
    backup_sqlite(async_url, backup_path)
    target_before = management_restore_module._file_digest(target)
    operation_id = uuid.uuid4()

    with pytest.raises(
        DatabaseRestoreRefused,
        match="candidate audit state is not clean",
    ):
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
            known_head=known_head,
        )
    assert management_restore_module._file_digest(target) == target_before

    # Omitting the option on resume must reuse, not discard, the phase-bound
    # envelope and therefore reach the same refusal.
    with pytest.raises(
        DatabaseRestoreRefused,
        match="candidate audit state is not clean",
    ):
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
        )
    assert management_restore_module._file_digest(target) == target_before
    rollback_restore(async_url, operation=str(operation_id))


def test_pending_sqlite_restore_fences_startup_and_resumes_exact_operation(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    backup_path = Path(sync_url.removeprefix("sqlite:///")).parent / "source.db"
    backup_sqlite(async_url, backup_path)
    operation_id = uuid.uuid4()

    with pytest.raises(
        DatabaseRestoreRefused,
        match="does not match --expected-sha256",
    ):
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
            expected_sha256="0" * 64,
        )

    with pytest.raises(
        DatabaseRestorePending,
        match=str(operation_id),
    ):
        create_engine_from_settings(Settings())  # type: ignore[call-arg]
    with pytest.raises(
        DatabaseRestorePending,
        match=str(operation_id),
    ):
        command.upgrade(config, "head")

    result = restore_sqlite(
        async_url,
        backup_path,
        operation=str(operation_id),
    )
    assert result["operation_id"] == str(operation_id)

    async def _prove_startup_fence_cleared() -> None:
        engine = create_engine_from_settings(
            Settings(),  # type: ignore[call-arg]
        )
        try:
            async with engine.connect() as connection:
                assert (
                    await connection.scalar(
                        text("SELECT COUNT(*) FROM audit_chain_state"),
                    )
                    == 1
                )
        finally:
            await engine.dispose()

    asyncio.run(_prove_startup_fence_cleared())


def test_postgres_restore_fence_terminates_rejected_precheckout_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A catalog-fenced connection must not outlive connect-event rejection."""

    captured: dict[str, object] = {}

    def capture_listener(
        _engine: object,
        event_name: str,
        listener: object,
    ) -> None:
        captured["event_name"] = event_name
        captured["listener"] = listener

    monkeypatch.setattr(
        management_restore_module.event,
        "listen",
        capture_listener,
    )
    engine = SimpleNamespace(sync_engine=object())
    management_restore_module.install_database_restore_fence_engine_hook(
        engine,  # type: ignore[arg-type]
        "postgresql+asyncpg://z4j@example/z4j",
    )

    class RejectedConnection:
        terminated = False

        def run_async(self, _inspect: object) -> None:
            raise DatabaseRestorePending("restore is unfinished")

        def terminate(self) -> None:
            self.terminated = True

    connection = RejectedConnection()
    record = SimpleNamespace(dbapi_connection=connection)
    listener = captured["listener"]
    assert callable(listener)
    with pytest.raises(DatabaseRestorePending, match="unfinished"):
        listener(connection, record)

    assert captured["event_name"] == "connect"
    assert connection.terminated is True
    assert record.dbapi_connection is None


def test_sqlite_restore_binds_union_executor_attestation_and_staged_bytes(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    project_id = uuid.uuid4()

    async def _create_external_authority() -> uuid.UUID:
        database = DatabaseManager(create_async_engine(async_url))
        try:
            async with database.session(write=True) as session:
                session.add(_project(project_id, "restore-authority"))
                await session.flush()
                stream = await ScheduleExternalRepository(
                    session,
                ).ensure_activation_epoch(
                    project_id=project_id,
                    owner="celery-beat",
                    source_scope=('{"kind":"scheduler-owner","owner":"celery-beat","version":1}'),
                    occurred_at=datetime(
                        2026,
                        7,
                        25,
                        15,
                        0,
                        tzinfo=UTC,
                    ),
                    adapter_instance_id="restore-adapter",
                    executor_agent_id=uuid.uuid4(),
                    executor_registry_owner_id=uuid.uuid4(),
                    executor_session_generation=uuid.uuid4().hex,
                )
                await session.commit()
                return stream.id
        finally:
            await database.dispose()

    stream_id = asyncio.run(_create_external_authority())
    backup_path = Path(sync_url.removeprefix("sqlite:///")).parent / "source.db"
    backup_sqlite(async_url, backup_path)
    operation_id = uuid.uuid4()

    with pytest.raises(
        DatabaseRestoreRefused,
        match="requires the exact stopped-executor",
    ) as required:
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
        )
    challenge_match = re.search(r"\b[0-9a-f]{64}\b", str(required.value))
    assert challenge_match is not None
    challenge = challenge_match.group(0)

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            stream = session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            assert stream.phase == "ACTIVATING"
    finally:
        engine.dispose()

    moved_source = backup_path.with_name("source-moved-after-stage.db")
    backup_path.replace(moved_source)
    result = restore_sqlite(
        async_url,
        backup_path,
        operation=str(operation_id),
        stopped_executor_attestation=challenge,
    )
    assert result["operation_id"] == str(operation_id)

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            stream = session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            assert stream.phase == "RESTORE_REACTIVATION_REQUIRED"
            epoch = session.get(
                ScheduleExternalStreamEpoch,
                stream.current_epoch_uuid,
            )
            assert epoch is not None
            assert epoch.phase == "RESTORE_REACTIVATION_REQUIRED"
    finally:
        engine.dispose()


def test_sqlite_legacy_restore_has_bound_activation_continuation(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1.7 database can activate only through its exact restore phase."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    legacy_path = target.parent / "legacy-source.db"
    legacy_async_url = f"sqlite+aiosqlite:///{legacy_path}"
    backend_root = Path(__file__).resolve().parents[2]
    legacy_config = Config(str(backend_root / "alembic.ini"))
    legacy_config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    monkeypatch.setenv("Z4J_DATABASE_URL", legacy_async_url)
    command.upgrade(legacy_config, "v1_7_security_hardening")
    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)

    operation_id = uuid.uuid4()
    with pytest.raises(
        DatabaseRestoreRefused,
        match="awaiting manifest-bound audit activation",
    ):
        restore_sqlite(
            async_url,
            legacy_path,
            operation=str(operation_id),
        )
    with pytest.raises(DatabaseRestorePending, match=str(operation_id)):
        create_engine_from_settings(Settings())  # type: ignore[call-arg]

    phase_path = target.parent / ".z4j-restore" / str(operation_id) / "phase.json"
    phase = management_restore_module._read_phase(phase_path)
    assert phase["state"] == "AWAITING_AUDIT_ACTIVATION"
    settings = Settings()  # type: ignore[call-arg]
    manifest = management_restore_module.build_restore_activation_manifest(
        async_url,
        operation=str(operation_id),
        settings=settings,
        legacy_key_window_complete=False,
        known_head=None,
    )
    assert manifest["requires_ambiguity_attestation"] is True
    wrong_manifest = {
        **manifest,
        "preparation_id": str(uuid.uuid4()),
    }
    with pytest.raises(
        DatabaseRestoreRefused,
        match="does not bind the SQLite restore preparation",
    ):
        management_restore_module.apply_restore_activation_manifest(
            async_url,
            operation=str(operation_id),
            settings=settings,
            manifest=wrong_manifest,
            attestation=wrong_manifest["manifest_digest"],
        )
    activated = management_restore_module.apply_restore_activation_manifest(
        async_url,
        operation=str(operation_id),
        settings=settings,
        manifest=manifest,
        attestation=manifest["manifest_digest"],
    )
    assert activated["state"] == "AUDIT_ACTIVATED"

    result = restore_sqlite(
        async_url,
        legacy_path,
        operation=str(operation_id),
    )
    assert result["operation_id"] == str(operation_id)
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            marker = (
                session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.database_restored",
                        AuditLog.target_id == str(operation_id),
                    ),
                )
            ).scalar_one()
            assert marker.audit_metadata["source_migration_head"] == "v1_7_security_hardening"
            assert (
                marker.audit_metadata["activation_manifest_digest"] == manifest["manifest_digest"]
            )
    finally:
        engine.dispose()


def test_sqlite_restore_refuses_same_named_altered_source_before_target_open(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Immutable exact-schema preflight precedes target recovery capture."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    source = target.parent / "altered-legacy-source.db"
    source_async_url = f"sqlite+aiosqlite:///{source}"
    backend_root = Path(__file__).resolve().parents[2]
    source_config = Config(str(backend_root / "alembic.ini"))
    source_config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    monkeypatch.setenv("Z4J_DATABASE_URL", source_async_url)
    command.upgrade(source_config, "v1_7_security_hardening")
    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)
    connection = sqlite3.connect(source)
    try:
        connection.executescript(
            """
            DROP INDEX ix_audit_log_action_occurred;
            CREATE INDEX ix_audit_log_action_occurred
            ON audit_log (action);
            """,
        )
        connection.commit()
    finally:
        connection.close()
    target_before = management_restore_module._file_digest(target)
    operation_id = uuid.uuid4()

    with pytest.raises(
        DatabaseRestoreRefused,
        match="source schema signature mismatch",
    ):
        restore_sqlite(
            async_url,
            source,
            operation=str(operation_id),
        )
    assert management_restore_module._file_digest(target) == target_before
    operation_dir = target.parent / ".z4j-restore" / str(operation_id)
    assert not (operation_dir / "target-recovery.db").exists()
    rollback_restore(async_url, operation=str(operation_id))


def test_restore_stage_refuses_operator_source_symlink(tmp_path: Path) -> None:
    """The no-follow check applies to the operator-supplied path itself."""

    source = tmp_path / "source.db"
    source.write_bytes(b"operator backup bytes")
    source_link = tmp_path / "source-link.db"
    source_link.symlink_to(source)

    with pytest.raises(
        DatabaseRestoreRefused,
        match="regular file, not a link",
    ):
        management_restore_module._stage_source(
            source_link,
            tmp_path / "staged.db",
            expected_sha256=None,
        )
    assert not (tmp_path / "staged.db").exists()


def test_sqlite_restore_recovers_activation_commit_before_phase_update(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed activation cannot be stranded by a local-phase crash."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    legacy_path = target.parent / "legacy-crash-source.db"
    legacy_async_url = f"sqlite+aiosqlite:///{legacy_path}"
    backend_root = Path(__file__).resolve().parents[2]
    legacy_config = Config(str(backend_root / "alembic.ini"))
    legacy_config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    monkeypatch.setenv("Z4J_DATABASE_URL", legacy_async_url)
    command.upgrade(legacy_config, "v1_7_security_hardening")
    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)
    operation_id = uuid.uuid4()
    with pytest.raises(DatabaseRestoreRefused):
        restore_sqlite(
            async_url,
            legacy_path,
            operation=str(operation_id),
        )
    settings = Settings()  # type: ignore[call-arg]
    manifest = management_restore_module.build_restore_activation_manifest(
        async_url,
        operation=str(operation_id),
        settings=settings,
        legacy_key_window_complete=False,
        known_head=None,
    )

    class SimulatedProcessCrash(BaseException):
        pass

    real_replace_phase = management_restore_module._replace_phase

    def crash_before_activated_phase(
        path: Path,
        phase: dict[str, object],
    ) -> None:
        if phase.get("state") == "AUDIT_ACTIVATED":
            raise SimulatedProcessCrash
        real_replace_phase(path, phase)

    monkeypatch.setattr(
        management_restore_module,
        "_replace_phase",
        crash_before_activated_phase,
    )
    with pytest.raises(SimulatedProcessCrash):
        management_restore_module.apply_restore_activation_manifest(
            async_url,
            operation=str(operation_id),
            settings=settings,
            manifest=manifest,
            attestation=manifest["manifest_digest"],
        )
    monkeypatch.setattr(
        management_restore_module,
        "_replace_phase",
        real_replace_phase,
    )
    recovered = management_restore_module.apply_restore_activation_manifest(
        async_url,
        operation=str(operation_id),
        settings=settings,
        manifest=manifest,
        attestation=manifest["manifest_digest"],
    )
    assert recovered["state"] == "AUDIT_ACTIVATED"

    def crash_before_marker_phase(
        path: Path,
        phase: dict[str, object],
    ) -> None:
        if phase.get("state") == "MARKER_COMMITTED":
            raise SimulatedProcessCrash
        real_replace_phase(path, phase)

    monkeypatch.setattr(
        management_restore_module,
        "_replace_phase",
        crash_before_marker_phase,
    )
    with pytest.raises(SimulatedProcessCrash):
        restore_sqlite(
            async_url,
            legacy_path,
            operation=str(operation_id),
        )
    monkeypatch.setattr(
        management_restore_module,
        "_replace_phase",
        real_replace_phase,
    )
    result = restore_sqlite(
        async_url,
        legacy_path,
        operation=str(operation_id),
    )
    assert result["operation_id"] == str(operation_id)


@pytest.mark.parametrize(
    "crash_point",
    ["after_target_displaced", "after_candidate_installed"],
)
@pytest.mark.parametrize("resolution", ["resume", "rollback"])
def test_sqlite_restore_resolves_both_install_crash_windows(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
    resolution: str,
) -> None:
    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "source.db"
    backup_sqlite(async_url, backup_path)
    operation_id = uuid.uuid4()
    operation_dir = target.parent / ".z4j-restore" / str(operation_id)

    class SimulatedProcessCrash(BaseException):
        pass

    if crash_point == "after_target_displaced":
        real_fsync = management_restore_module._fsync_directory

        def _crash_after_displacement(path: Path) -> None:
            if (
                Path(path) == target.parent
                and not target.exists()
                and (operation_dir / "displaced-main.db").exists()
            ):
                raise SimulatedProcessCrash
            real_fsync(path)

        monkeypatch.setattr(
            management_restore_module,
            "_fsync_directory",
            _crash_after_displacement,
        )
    else:
        real_replace = Path.replace

        def _crash_after_install(
            path: Path,
            destination: Path,
        ) -> Path:
            result = real_replace(path, destination)
            if path.name == "candidate.db":
                raise SimulatedProcessCrash
            return result

        monkeypatch.setattr(Path, "replace", _crash_after_install)

    with pytest.raises(SimulatedProcessCrash):
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
        )

    if crash_point == "after_target_displaced":
        monkeypatch.setattr(
            management_restore_module,
            "_fsync_directory",
            real_fsync,
        )
    else:
        monkeypatch.setattr(Path, "replace", real_replace)
    if resolution == "resume":
        result = restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
        )
        expected_action = "audit.database_restored"
    else:
        result = rollback_restore(
            async_url,
            operation=str(operation_id),
        )
        expected_action = "audit.database_restore_rolled_back"
    assert result["operation_id"] == str(operation_id)
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action=:expected_action "
                        "AND target_id=:operation_id",
                    ),
                    {
                        "expected_action": expected_action,
                        "operation_id": str(operation_id),
                    },
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "rollback_crash_point",
    [
        "before_installed_phase",
        "before_marker",
        "after_marker_commit",
        "after_marker_commit_changed_target",
    ],
)
def test_sqlite_rollback_resumes_after_candidate_was_installed(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
    rollback_crash_point: str,
) -> None:
    """Rollback resumes after its candidate has been atomically consumed."""

    config, sync_url, async_url = boundary_d_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "rollback-resume-source.db"
    backup_sqlite(async_url, backup_path)
    operation_id = uuid.uuid4()

    class SimulatedProcessCrash(BaseException):
        pass

    real_replace = Path.replace

    def crash_after_restore_candidate_install(
        path: Path,
        destination: Path,
    ) -> Path:
        result = real_replace(path, destination)
        if path.name == "candidate.db":
            raise SimulatedProcessCrash
        return result

    monkeypatch.setattr(Path, "replace", crash_after_restore_candidate_install)
    with pytest.raises(SimulatedProcessCrash):
        restore_sqlite(
            async_url,
            backup_path,
            operation=str(operation_id),
        )
    monkeypatch.setattr(Path, "replace", real_replace)

    if rollback_crash_point == "before_installed_phase":
        real_replace_phase = management_restore_module._replace_phase

        def crash_before_installed_phase(
            path: Path,
            phase: dict[str, object],
        ) -> None:
            if phase.get("state") == "ROLLBACK_INSTALLED":
                raise SimulatedProcessCrash
            real_replace_phase(path, phase)

        monkeypatch.setattr(
            management_restore_module,
            "_replace_phase",
            crash_before_installed_phase,
        )
    elif rollback_crash_point == "before_marker":
        real_marker = management_restore_module._record_database_rollback_marker

        async def crash_before_rollback_marker(
            *args: object,
            **kwargs: object,
        ) -> str:
            raise SimulatedProcessCrash

        monkeypatch.setattr(
            management_restore_module,
            "_record_database_rollback_marker",
            crash_before_rollback_marker,
        )
    else:
        real_marker = management_restore_module._record_database_rollback_marker

        async def crash_after_rollback_marker(
            *args: object,
            **kwargs: object,
        ) -> str:
            await real_marker(*args, **kwargs)
            raise SimulatedProcessCrash

        monkeypatch.setattr(
            management_restore_module,
            "_record_database_rollback_marker",
            crash_after_rollback_marker,
        )

    with pytest.raises(SimulatedProcessCrash):
        rollback_restore(
            async_url,
            operation=str(operation_id),
        )

    if rollback_crash_point == "before_installed_phase":
        monkeypatch.setattr(
            management_restore_module,
            "_replace_phase",
            real_replace_phase,
        )
    else:
        monkeypatch.setattr(
            management_restore_module,
            "_record_database_rollback_marker",
            real_marker,
        )

    if rollback_crash_point == "after_marker_commit_changed_target":
        engine = create_engine(sync_url)
        try:
            with Session(engine) as session:
                session.add(_project(uuid.uuid4(), "rollback-mutated"))
                session.commit()
        finally:
            engine.dispose()
        with pytest.raises(
            DatabaseRestoreRefused,
            match="rollback marker names a changed target",
        ):
            rollback_restore(
                async_url,
                operation=str(operation_id),
            )
        return

    result = rollback_restore(
        async_url,
        operation=str(operation_id),
    )
    assert result["operation_id"] == str(operation_id)
    assert result["marker_id"] is not None

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action='audit.database_restore_rolled_back' "
                        "AND target_id=:operation_id",
                    ),
                    {"operation_id": str(operation_id)},
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_fresh_activation_is_authenticated_and_catalog_guarded(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, _ = boundary_d_install
    command.upgrade(config, "head")

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            state = session.get(ScheduleRevisionState, "schedule-revision")
            assert state is not None
            assert state.current_revision == 0
            assert state.change_log_pruned_through == 0
            assert state.guard_version == 1
            assert state.activation_id is not None
            assert state.activation_manifest_digest is not None
            assert state.activation_audit_id is not None

            audit_state = session.get(AuditChainState, "audit-chain")
            assert audit_state is not None
            authenticate_state(audit_state, _audit_keyring())
            activation = session.get(AuditLog, state.activation_audit_id)
            assert activation is not None
            assert activation.action == "schedule.control_migration_activated"
            assert activation.audit_metadata["manifest_digest"] == state.activation_manifest_digest
            assert activation.audit_metadata["manifest"]["schedule_count"] == 0

        with engine.connect() as connection:
            triggers = {
                row[0]
                for row in connection.execute(
                    text("SELECT name FROM sqlite_master WHERE type='trigger'"),
                )
            }
        assert {
            "z4j_schedule_update_guard_v1",
            "z4j_schedule_command_insert_guard_v1",
            "z4j_schedule_fire_insert_guard_v1",
            "z4j_pending_fire_insert_guard_v1",
        } <= triggers
    finally:
        engine.dispose()


def test_activation_backfills_distinct_generations_and_legacy_evidence(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, _ = boundary_d_install
    command.upgrade(config, "v1_8_audit_chain_activate")
    project_id = uuid.uuid4()
    valid_id = uuid.uuid4()
    invalid_id = uuid.uuid4()
    external_id = uuid.uuid4()
    command_id = uuid.uuid4()
    fire_row_id = uuid.uuid4()
    fire_id = uuid.uuid4()
    pending_id = uuid.uuid4()
    scheduled_for = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="legacy",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=valid_id,
                name="valid",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=invalid_id,
                name="invalid",
                expression="not-an-interval",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=external_id,
                name="external",
                scheduler="celery-beat",
            )
            _insert_pre_boundary_d_command(
                session,
                command_id=command_id,
                project_id=project_id,
                schedule_id=valid_id,
                timeout_at=scheduled_for + timedelta(minutes=1),
            )
            _insert_pre_boundary_d_fire(
                session,
                row_id=fire_row_id,
                fire_id=fire_id,
                schedule_id=valid_id,
                project_id=project_id,
                command_id=command_id,
                scheduled_for=scheduled_for,
            )
            _insert_pre_boundary_d_pending_fire(
                session,
                row_id=pending_id,
                fire_id=uuid.uuid4(),
                schedule_id=valid_id,
                project_id=project_id,
                scheduled_for=scheduled_for + timedelta(minutes=5),
                enqueued_at=scheduled_for,
                expires_at=scheduled_for + timedelta(days=7),
            )
            session.commit()
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            rows = list(
                session.execute(
                    select(Schedule).order_by(Schedule.id),
                ).scalars()
            )
            assert {row.schedule_revision for row in rows} == {1, 2, 3}
            tokens = {row.control_token for row in rows}
            assert None not in tokens
            assert len(tokens) == 3
            assert all(row.definition_digest for row in rows)
            assert all(row.legacy_fire_control_token is None for row in rows)

            invalid = session.get(Schedule, invalid_id)
            assert invalid is not None
            assert invalid.is_enabled is False
            assert invalid.quarantine_control_token == invalid.control_token
            assert invalid.quarantine_code == "migration_definition_invalid"

            state = session.get(ScheduleRevisionState, "schedule-revision")
            assert state is not None
            assert state.current_revision == 3
            assert state.change_log_pruned_through == 3
            assert state.guard_version == 1
            activation = session.get(AuditLog, state.activation_audit_id)
            assert activation is not None
            manifest_rows = {
                row["schedule_id"]: row
                for row in activation.audit_metadata["manifest"]["schedules"]
            }
            assert manifest_rows[str(invalid_id)]["classification"] == (
                "reserved-invalid-quarantined"
            )
            assert manifest_rows[str(invalid_id)]["quarantine_code"] == (
                "migration_definition_invalid"
            )

            legacy_command = session.get(Command, command_id)
            assert legacy_command is not None
            assert legacy_command.schedule_protocol_marker == 1
            assert legacy_command.schedule_state_nonce is not None
            assert legacy_command.schedule_id == valid_id
            assert legacy_command.schedule_fire_id == fire_id
            assert legacy_command.schedule_scheduled_for is not None
            assert legacy_command.schedule_scheduled_for.replace(tzinfo=UTC) == scheduled_for
            assert legacy_command.schedule_receipt_control_token is None

            fire = session.get(ScheduleFire, fire_row_id)
            assert fire is not None
            assert fire.protocol_marker == 1
            assert fire.state_write_nonce is not None
            assert fire.receipt_control_token is None
            pending = session.get(PendingFire, pending_id)
            assert pending is not None
            assert pending.protocol_marker == 1
            assert pending.state_write_nonce is not None
            assert pending.receipt_control_token is None
    finally:
        engine.dispose()


async def test_external_activation_is_strictly_sequenced_and_replay_safe(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    sync_engine = create_engine(sync_url)
    try:
        with Session(sync_engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="external-stream",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="external",
                scheduler="celery-beat",
            )
            session.commit()
    finally:
        sync_engine.dispose()
    await asyncio.to_thread(command.upgrade, config, "head")

    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session() as session:
            stream = (
                await session.execute(
                    select(ScheduleExternalStream).where(
                        ScheduleExternalStream.project_id == project_id,
                    ),
                )
            ).scalar_one()
            allocator = await session.get(
                ScheduleExternalEpochAllocator,
                "schedule-external-epoch",
            )
            assert allocator is not None
            assert allocator.current_epoch_number == 1
            assert stream.phase == "ACTIVATING"
            assert stream.authorized_adapter_instance_id is None
            assert stream.activation_requirement == ("legacy_emitters_must_be_quiesced")
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            source_scope = stream.source_scope

        projected = {
            "source_key": "external",
            "engine": "celery",
            "scheduler": "celery-beat",
            "name": "external",
            "task_name": "jobs.external",
            "kind": "interval",
            "expression": "10m",
            "timezone": "UTC",
            "queue": None,
            "priority": "normal",
            "args": [],
            "kwargs": {},
            "is_enabled": True,
            "last_run_at": None,
            "next_run_at": "2026-07-25T12:10:00+00:00",
            "total_runs": 0,
            "external_id": None,
            "catch_up": "skip",
            "source": "agent",
            "source_hash": None,
        }
        body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        digest = external_projection_digest(body)

        async with database.session(write=True) as session:
            refused = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 0, tzinfo=UTC),
            )
            assert refused.disposition == "upgrade_required"
            await session.rollback()

        project_id = uuid.uuid4()
        source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
        async with database.session(write=True) as session:
            session.add(_project(project_id, "fresh-external-stream"))
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="celery-beat",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 12, 1, tzinfo=UTC),
                adapter_instance_id="adapter-one",
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
            )
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            await session.commit()

        body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        digest = external_projection_digest(body)
        async with database.session(write=True) as session:
            applied = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 1, tzinfo=UTC),
            )
            assert applied.disposition == "applied"
            assert applied.inserted == 1
            schedule_id = (
                await session.execute(
                    select(Schedule.id).where(
                        Schedule.external_stream_id == stream_id,
                    ),
                )
            ).scalar_one()
            await session.commit()

        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            schedule = await session.get(Schedule, schedule_id)
            assert stream is not None
            assert schedule is not None
            assert stream.phase == "ACTIVE"
            assert stream.accepted_sequence == 1
            assert stream.authorized_adapter_instance_id == "adapter-one"
            assert stream.last_projection_digest == digest
            assert stream.last_snapshot_digest == digest
            assert stream.activation_requirement is None
            assert schedule.external_source_sequence == 1
            assert schedule.expression == "10m"
            assert schedule.schedule_revision == 2
            assert (await session.get(ScheduleChangeLog, 2)).change_kind == "gap"

        async with database.session(write=True) as session:
            replay = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 2, tzinfo=UTC),
            )
            assert replay.disposition == "exact_replay"
            await session.commit()

        projected_b = dict(projected)
        projected_b.update(
            {
                "source_key": "second",
                "name": "second",
                "task_name": "jobs.second",
            },
        )
        second_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=2,
            kind="snapshot",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[projected, projected_b],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            second = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=2,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected, projected_b],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(second_body),
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 3, tzinfo=UTC),
            )
            assert second.disposition == "applied"
            assert second.inserted == 1
            assert second.updated == 1
            await session.commit()

        async with database.session(write=True) as session:
            delayed = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 4, tzinfo=UTC),
            )
            assert delayed.disposition == "exact_replay"
            names = set(
                (
                    await session.execute(
                        select(Schedule.name).where(
                            Schedule.external_stream_id == stream_id,
                        ),
                    )
                ).scalars(),
            )
            assert names == {"external", "second"}
            await session.commit()

        gap_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=4,
            kind="updated",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[projected],
            deleted_source_keys=[],
            complete=False,
            stable_source=False,
        )
        async with database.session(write=True) as session:
            gap = await ScheduleExternalRepository(session).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=4,
                kind="updated",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[projected],
                deleted_source_keys=[],
                complete=False,
                stable_source=False,
                payload_digest=external_projection_digest(gap_body),
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 12, 5, tzinfo=UTC),
            )
            assert gap.disposition == "sequence_gap"
            await session.rollback()

        mismatch = dict(projected)
        mismatch["expression"] = "20m"
        mismatch_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=2,
            kind="snapshot",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[mismatch, projected_b],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            fault = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=2,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="adapter-one",
                schedules=[mismatch, projected_b],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(
                    mismatch_body,
                ),
                operation_id=None,
                occurred_at=datetime(
                    2026,
                    7,
                    25,
                    12,
                    6,
                    tzinfo=UTC,
                ),
            )
            assert fault.disposition == "protocol_fault"
            await session.commit()

        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            schedule = await session.get(Schedule, schedule_id)
            assert stream is not None
            assert schedule is not None
            assert stream.phase == "AMBIGUOUS"
            assert stream.accepted_sequence == 2
            assert schedule.expression == "10m"

        with pytest.raises(
            IntegrityError,
            match="external schedule update is not current",
        ):
            async with database.session(write=True) as session:
                schedule = await session.get(
                    Schedule,
                    schedule_id,
                    with_for_update=True,
                )
                assert schedule is not None
                old_revision = schedule.schedule_revision
                old_token = schedule.control_token
                assert old_revision is not None
                assert old_token is not None
                revision = await ScheduleControlRepository(
                    session,
                )._allocate_revision()
                session.add(
                    ScheduleChangeLog(
                        revision=revision,
                        project_id=project_id,
                        schedule_id=schedule_id,
                        schedule_owner="celery-beat",
                        change_kind="gap",
                        protocol_version=1,
                        snapshot=null(),
                        occurred_at=datetime(
                            2026,
                            7,
                            25,
                            12,
                            7,
                            tzinfo=UTC,
                        ),
                    ),
                )
                await session.flush()
                await arm_schedule_transition(
                    session,
                    operation="update",
                    schedule_id=schedule_id,
                    old_revision=old_revision,
                    new_revision=revision,
                    change_kind="gap",
                    old_token=old_token,
                    new_token=old_token,
                )
                schedule.schedule_revision = revision
                schedule.external_source_sequence = 3
                schedule.expression = "forged-without-projection"
                await session.flush()

        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            schedule = await session.get(Schedule, schedule_id)
            assert stream is not None
            assert schedule is not None
            assert stream.accepted_sequence == 2
            assert schedule.external_source_sequence == 2
            assert schedule.expression == "10m"
    finally:
        await async_engine.dispose()


async def test_external_stream_allocation_is_monotonic_and_guarded(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    sync_engine = create_engine(sync_url)
    try:
        with Session(sync_engine) as session:
            session.add(_project(project_id, "external-allocation"))
            session.commit()
    finally:
        sync_engine.dispose()

    source_scope = '{"kind":"scheduler-owner","owner":"rq-scheduler","version":1}'
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="rq-scheduler",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 13, 0, tzinfo=UTC),
                adapter_instance_id="rq-adapter-one",
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
            )
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            assert epoch_number == 1
            await session.commit()

        async with database.session(write=True) as session:
            same = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="rq-scheduler",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 13, 1, tzinfo=UTC),
            )
            assert same.id == stream_id
            allocator = await session.get(
                ScheduleExternalEpochAllocator,
                "schedule-external-epoch",
            )
            assert allocator is not None
            assert allocator.current_epoch_number == 1
            await session.commit()

        body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner="rq-scheduler",
            source_scope=source_scope,
            adapter_instance_id="rq-adapter-one",
            schedules=[],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            activated = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="rq-scheduler",
                source_scope=source_scope,
                adapter_instance_id="rq-adapter-one",
                schedules=[],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(body),
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 13, 2, tzinfo=UTC),
            )
            assert activated.disposition == "applied"
            assert activated.inserted == 0
            assert activated.updated == 0
            assert activated.deleted == 0
            await session.commit()

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE schedule_external_epoch_allocator SET current_epoch_number = 2",
                    ),
                )
    finally:
        await async_engine.dispose()


async def test_external_epoch_allocation_binds_adapter_identity(
    boundary_d_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DB must reject an epoch row that differs from the armed authority."""

    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    sync_engine = create_engine(sync_url)
    try:
        with Session(sync_engine) as session:
            session.add(_project(project_id, "external-adapter-binding"))
            session.commit()
    finally:
        sync_engine.dispose()

    original_arm = schedule_external_repository_module.arm_external_epoch_allocation

    async def arm_with_different_adapter(*args: object, **kwargs: object) -> None:
        kwargs["adapter_instance_id"] = "descriptor-adapter"
        await original_arm(*args, **kwargs)

    monkeypatch.setattr(
        schedule_external_repository_module,
        "arm_external_epoch_allocation",
        arm_with_different_adapter,
    )
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with database.session(write=True) as session:
                await ScheduleExternalRepository(
                    session,
                ).ensure_activation_epoch(
                    project_id=project_id,
                    owner="rq-scheduler",
                    source_scope=('{"kind":"scheduler-owner","owner":"rq-scheduler","version":1}'),
                    occurred_at=datetime(2026, 7, 25, 13, 3, tzinfo=UTC),
                    adapter_instance_id="row-adapter",
                    executor_agent_id=uuid.uuid4(),
                    executor_registry_owner_id=uuid.uuid4(),
                    executor_session_generation=uuid.uuid4().hex,
                )
                await session.commit()
    finally:
        await async_engine.dispose()


def test_activation_refuses_tampered_boundary_f_state(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, _ = boundary_d_install
    command.upgrade(config, "v1_8_audit_chain_activate")

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            session.execute(
                text("DROP TRIGGER audit_chain_state_boundary_f_no_update"),
            )
            state = session.get(AuditChainState, "audit-chain")
            assert state is not None
            state.state_mac = "0" * 64
            session.flush()
            session.execute(
                text(_SQLITE_AUDIT_STATE_UPDATE_TRIGGER_SQL),
            )
            session.commit()
    finally:
        engine.dispose()

    with pytest.raises(
        CommandError,
        match="Boundary F failed authentication",
    ):
        command.upgrade(config, "head")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "v1_8_audit_chain_activate"
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type = 'table' "
                        "AND name = 'schedule_revision_state'",
                    ),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = "
                        "'schedule.control_migration_activated'",
                    ),
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()


async def test_old_sqlite_writer_fails_but_guarded_repository_succeeds(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()

    sync_engine = create_engine(sync_url)
    try:
        with Session(sync_engine) as session:
            session.add(_project(project_id, "guarded"))
            session.commit()
    finally:
        sync_engine.dispose()

    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            row = await ScheduleControlRepository(session).create_current(
                project_id=project_id,
                data={
                    "name": "guarded",
                    "task_name": "jobs.guarded",
                    "engine": "celery",
                    "scheduler": "z4j-scheduler",
                    "kind": "interval",
                    "expression": "5m",
                    "timezone": "UTC",
                    "queue": None,
                    "priority": "normal",
                    "args": [],
                    "kwargs": {},
                    "is_enabled": True,
                    "catch_up": "skip",
                    "source": "dashboard",
                },
                planning_at=datetime(2026, 7, 25, 12, 3, tzinfo=UTC),
            )
            schedule_id = row.id
            control_token = row.control_token
            await session.commit()
        async with database.session(write=True) as session:
            updated = await ScheduleControlRepository(session).update_current(
                project_id=project_id,
                schedule_id=schedule_id,
                data={"name": "guarded-updated"},
                planning_at=datetime(2026, 7, 25, 12, 4, tzinfo=UTC),
            )
            assert updated.schedule_revision == 2
            assert updated.control_token == control_token
            await session.commit()
        assert control_token is not None
        async with database.session(write=True) as session:
            quarantine = await ScheduleControlRepository(session).quarantine(
                project_id=project_id,
                schedule_id=schedule_id,
                observed_control_token=control_token,
                reason_code="definition_invalid",
                detail="migration guard oracle",
                occurred_at=datetime(2026, 7, 25, 12, 5, tzinfo=UTC),
            )
            assert quarantine.outcome == "applied"
            assert quarantine.schedule is not None
            assert quarantine.schedule.is_enabled is False
            assert quarantine.schedule.schedule_revision == 3
            definition_digest = quarantine.schedule.definition_digest
            expected_next_run_at = quarantine.schedule.next_run_at
            expected_revision = quarantine.schedule.schedule_revision
            assert definition_digest is not None
            assert expected_next_run_at is not None
            await session.commit()

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM schedule_change_log WHERE revision = 1",
                    ),
                )

        async with database.session(write=True) as session:
            pruned = await ScheduleControlRepository(
                session,
            ).prune_change_log(through_revision=2)
            assert pruned == 2
            await session.commit()
        async with database.session() as session:
            state = await session.get(
                ScheduleRevisionState,
                "schedule-revision",
            )
            assert state is not None
            assert state.current_revision == 3
            assert state.change_log_pruned_through == 2
            retained_revisions = list(
                (
                    await session.execute(
                        text(
                            "SELECT revision FROM schedule_change_log ORDER BY revision",
                        ),
                    )
                ).scalars(),
            )
            assert retained_revisions == [3]

        fire_id = uuid.uuid4()
        execution_fire_id = uuid.uuid4()
        receipt_token = uuid.uuid4()
        expires_at = datetime(2026, 7, 25, 12, 6, tzinfo=UTC)
        async with database.session(write=True) as session:
            pending, created = await PendingFiresRepository(
                session,
            ).buffer_current(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={"fire_id": str(execution_fire_id)},
                scheduled_for=expected_next_run_at,
                expires_at=expires_at,
                observed_control_token=receipt_token,
                receipt_control_token=receipt_token,
                definition_digest=definition_digest,
                expected_schedule_revision=expected_revision,
                expected_last_run_at=None,
                expected_next_run_at=expected_next_run_at,
                prepared_next_run_at=(expected_next_run_at + timedelta(minutes=5)),
                acceptance_revision=expected_revision + 1,
                execution_fire_id=execution_fire_id,
            )
            assert created is True
            pending_id = pending.id
            pending_nonce = pending.state_write_nonce
            assert pending_nonce is not None
            await session.commit()

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM pending_fires WHERE id = :pending_id",
                    ),
                    {"pending_id": pending_id.hex},
                )

        async with database.session(write=True) as session:
            expired = await PendingFiresRepository(
                session,
            ).expire_current(
                pending_id=pending_id,
                expected_state_nonce=pending_nonce,
                occurred_at=expires_at + timedelta(seconds=1),
            )
            assert expired.disposition == "expired"
            assert expired.changed is True
            await session.commit()
    finally:
        await async_engine.dispose()

    old_engine = create_engine(sync_url)
    try:
        with (
            pytest.raises(
                OperationalError,
                match="no such function: z4j_schedule_guard",
            ),
            old_engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "UPDATE schedules SET name = 'old-writer' WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id.hex},
            )
    finally:
        old_engine.dispose()


async def test_activated_legacy_scheduler_ack_is_history_only(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    fire_id = uuid.uuid4()
    fire_row_id = uuid.uuid4()
    slot = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="legacy-ack",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="legacy-ack",
            )
            _insert_pre_boundary_d_fire(
                session,
                row_id=fire_row_id,
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                scheduled_for=slot,
            )
            session.commit()
    finally:
        engine.dispose()
    await asyncio.to_thread(command.upgrade, config, "head")

    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            fire = await session.get(ScheduleFire, fire_row_id)
            assert fire is not None
            original_nonce = fire.state_write_nonce
            assert original_nonce is not None
            retained, changed = await ScheduleFireRepository(
                session,
            ).acknowledge_legacy_history(
                fire=fire,
                command_id=None,
                status="success",
                new_task_id="legacy-history",
            )
            assert changed is True
            assert retained.status == "failed"
            assert retained.acked_at is None
            assert retained.scheduler_ack_status == "success"
            assert retained.state_write_nonce != original_nonce
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            assert schedule is not None
            assert schedule.last_run_at is None
            assert schedule.total_runs == 0
            assert schedule.schedule_revision == 1
    finally:
        await async_engine.dispose()


def test_activation_failure_rolls_back_d_and_resumes_from_f(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, _ = boundary_d_install
    config.attributes["z4j_test_fail_schedule_activation_after_state"] = True
    with pytest.raises(
        RuntimeError,
        match="injected Boundary-D activation failure",
    ):
        command.upgrade(config, "head")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "v1_8_audit_chain_activate"
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type = 'table' "
                        "AND name = 'schedule_revision_state'",
                    ),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = "
                        "'schedule.control_migration_activated'",
                    ),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type = 'trigger' "
                        "AND name = 'z4j_schedule_update_guard_v1'",
                    ),
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()

    config.attributes.pop(
        "z4j_test_fail_schedule_activation_after_state",
    )
    command.upgrade(config, "head")
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == code_head()
            )
    finally:
        engine.dispose()


async def test_sqlite_self_contained_evidence_requires_write_authority(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    try:
        with pytest.raises(
            OperationalError,
            match=r"no such function|user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO schedule_terminal_holds ("
                        "id, project_id, schedule_id, fire_id, "
                        "scheduled_for, command_id, observed_control_token, "
                        "receipt_control_token, acceptance_revision, "
                        "terminal_status, state_write_nonce, created_at"
                        ") VALUES ("
                        ":id, :project_id, :schedule_id, :fire_id, "
                        ":scheduled_for, :command_id, :observed, :receipt, "
                        "1, 'failed', :nonce, :created_at)",
                    ),
                    {
                        "id": uuid.uuid4().hex,
                        "project_id": uuid.uuid4().hex,
                        "schedule_id": uuid.uuid4().hex,
                        "fire_id": uuid.uuid4().hex,
                        "scheduled_for": now,
                        "command_id": uuid.uuid4().hex,
                        "observed": uuid.uuid4().hex,
                        "receipt": uuid.uuid4().hex,
                        "nonce": uuid.uuid4().hex,
                        "created_at": now,
                    },
                )

        with pytest.raises(
            OperationalError,
            match=r"no such function|user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO schedule_occurrence_resolutions ("
                        "id, project_id, schedule_id, fire_id, "
                        "scheduled_for, source_evidence_kind, "
                        "source_evidence_id, authority_kind, "
                        "command_status, work_may_have_executed, "
                        "resolution_disposition, resolved_at, resolved_by, "
                        "resolution_source, resolution_control_token, "
                        "state_write_nonce"
                        ") VALUES ("
                        ":id, :project_id, :schedule_id, :fire_id, "
                        ":scheduled_for, 'SCHEDULE_FIRE', :source_id, "
                        "'LEGACY_NULL', 'failed', 1, 'OPERATOR_SKIPPED', "
                        ":resolved_at, :resolved_by, 'OPERATOR', "
                        ":resolution_token, :nonce)",
                    ),
                    {
                        "id": uuid.uuid4().hex,
                        "project_id": uuid.uuid4().hex,
                        "schedule_id": uuid.uuid4().hex,
                        "fire_id": uuid.uuid4().hex,
                        "scheduled_for": now,
                        "source_id": uuid.uuid4().hex,
                        "resolved_at": now,
                        "resolved_by": uuid.uuid4().hex,
                        "resolution_token": uuid.uuid4().hex,
                        "nonce": uuid.uuid4().hex,
                    },
                )
    finally:
        await async_engine.dispose()


async def test_sqlite_retention_deletes_current_and_preserves_legacy(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(
        command.upgrade,
        config,
        "v1_8_audit_chain_activate",
    )
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    legacy_fire_id = uuid.uuid4()
    fired_at = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            _insert_historical_project(
                session,
                project_id=project_id,
                slug="retention",
            )
            _insert_pre_boundary_d_schedule(
                session,
                project_id=project_id,
                schedule_id=schedule_id,
                name="retention",
            )
            _insert_pre_boundary_d_fire(
                session,
                row_id=uuid.uuid4(),
                fire_id=legacy_fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                scheduled_for=fired_at,
            )
            session.commit()
    finally:
        engine.dispose()

    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            schedule = await session.get(Schedule, schedule_id)
            assert schedule is not None
            assert schedule.control_token is not None
            assert schedule.definition_digest is not None
            assert schedule.schedule_revision is not None
            current_fire_id = uuid.uuid4()
            await ScheduleFireRepository(session).record_current(
                fire_id=current_fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="accepted",
                scheduled_for=fired_at + timedelta(minutes=5),
                fired_at=fired_at,
                observed_control_token=schedule.control_token,
                receipt_control_token=schedule.control_token,
                acceptance_revision=schedule.schedule_revision,
                definition_digest=schedule.definition_digest,
                expected_schedule_revision=schedule.schedule_revision,
                expected_last_run_at=None,
                expected_next_run_at=fired_at + timedelta(minutes=5),
                prepared_next_run_at=fired_at + timedelta(minutes=10),
            )
            await session.commit()

        async with database.session(write=True) as session:
            removed = await ScheduleFireRepository(
                session,
            ).delete_older_than(
                cutoff=fired_at + timedelta(days=1),
            )
            assert removed == 1
            await session.commit()

        async with database.session() as session:
            remaining = list(
                (
                    await session.execute(
                        select(ScheduleFire).order_by(
                            ScheduleFire.fire_id,
                        ),
                    )
                ).scalars(),
            )
            assert [row.fire_id for row in remaining] == [
                legacy_fire_id,
            ]
            assert remaining[0].receipt_control_token is None
    finally:
        await async_engine.dispose()


async def test_guarded_schedule_delete_tombstones_and_closes_pending(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            session.add(_project(project_id, "delete"))
            session.commit()
    finally:
        engine.dispose()

    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        planning_at = datetime(2026, 7, 25, 12, 3, tzinfo=UTC)
        async with database.session(write=True) as session:
            schedule = await ScheduleControlRepository(
                session,
            ).create_current(
                project_id=project_id,
                data={
                    "name": "delete",
                    "task_name": "jobs.delete",
                    "engine": "celery",
                    "scheduler": "z4j-scheduler",
                    "kind": "interval",
                    "expression": "5m",
                    "timezone": "UTC",
                    "priority": "normal",
                    "args": [],
                    "kwargs": {},
                    "is_enabled": True,
                    "catch_up": "skip",
                    "source": "dashboard",
                },
                planning_at=planning_at,
            )
            schedule_id = schedule.id
            slot = schedule.next_run_at
            token = schedule.control_token
            digest = schedule.definition_digest
            expected_revision = schedule.schedule_revision
            assert slot is not None
            assert token is not None
            assert digest is not None
            assert expected_revision is not None
            fire_id = derive_scheduler_fire_id(schedule_id, slot)
            successor = slot + timedelta(minutes=5)
            acceptance = await ScheduleControlRepository(
                session,
            ).accept_current_fire_progress(
                project_id=project_id,
                schedule_id=schedule_id,
                fire_id=fire_id,
                scheduled_for=slot,
                observed_control_token=token,
                definition_digest=digest,
                expected_revision=expected_revision,
                expected_last_run_at=None,
                expected_next_run_at=slot,
                prepared_next_run_at=successor,
                cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
                cadence_fingerprint=cadence_runtime_fingerprint(),
                occurred_at=slot + timedelta(seconds=1),
            )
            assert acceptance.acceptance_revision is not None
            assert acceptance.execution_fire_id is not None
            pending, _created = await PendingFiresRepository(
                session,
            ).buffer_current(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={
                    "fire_id": str(acceptance.execution_fire_id),
                },
                scheduled_for=slot,
                expires_at=slot + timedelta(days=1),
                observed_control_token=token,
                receipt_control_token=token,
                definition_digest=digest,
                expected_schedule_revision=expected_revision,
                expected_last_run_at=None,
                expected_next_run_at=slot,
                prepared_next_run_at=successor,
                acceptance_revision=acceptance.acceptance_revision,
                execution_fire_id=acceptance.execution_fire_id,
            )
            await ScheduleFireRepository(session).record_current(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="buffered",
                scheduled_for=slot,
                observed_control_token=token,
                receipt_control_token=token,
                acceptance_revision=acceptance.acceptance_revision,
                definition_digest=digest,
                expected_schedule_revision=expected_revision,
                expected_last_run_at=None,
                expected_next_run_at=slot,
                prepared_next_run_at=successor,
            )
            pending_id = pending.id
            await session.commit()

        with pytest.raises(
            IntegrityError,
            match="exact tombstone",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM schedules WHERE id = :schedule_id",
                    ),
                    {"schedule_id": schedule_id.hex},
                )

        async with database.session(write=True) as session:
            deleted = await ScheduleControlRepository(
                session,
            ).delete_current(
                project_id=project_id,
                schedule_id=schedule_id,
                occurred_at=slot + timedelta(seconds=2),
            )
            assert deleted.disposition == "deleted"
            assert deleted.committed_revision == 3
            assert deleted.evidence_closed == 1
            await session.commit()

        async with database.session() as session:
            assert await session.get(Schedule, schedule_id) is None
            assert await session.get(PendingFire, pending_id) is None
            retained_fire = await session.scalar(
                select(ScheduleFire).where(
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.receipt_control_token == token,
                ),
            )
            assert retained_fire is not None
            resolution = await session.scalar(
                select(ScheduleOccurrenceResolution).where(
                    ScheduleOccurrenceResolution.source_evidence_kind == "PENDING_FIRE",
                    ScheduleOccurrenceResolution.source_evidence_id == pending_id,
                ),
            )
            assert resolution is not None
            assert resolution.resolution_disposition == "SCHEDULE_DELETED"
            assert resolution.deletion_tombstone_revision == 3
            tombstone = await session.get(ScheduleChangeLog, 3)
            assert tombstone is not None
            assert tombstone.change_kind == "delete"
            assert tombstone.snapshot is None
    finally:
        await async_engine.dispose()


async def test_event_ingestor_retries_a_gap_after_raw_event_dedup(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """A sequence-gap replay must project even after its event row deduplicates."""
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "ingestor-external"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="beat-1",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="django",
                    engine_adapters=["celery"],
                    scheduler_adapters=["celery-beat"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="celery-beat",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 15, 0, tzinfo=UTC),
                adapter_instance_id="beat-instance-1",
                executor_agent_id=agent_id,
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
            )
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            await session.commit()

        def projected(name: str) -> dict[str, object]:
            return {
                "source_key": name,
                "engine": "celery",
                "scheduler": "celery-beat",
                "name": name,
                "task_name": f"jobs.{name}",
                "kind": "interval",
                "expression": "5m",
                "timezone": "UTC",
                "queue": None,
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "last_run_at": None,
                "next_run_at": None,
                "total_runs": 0,
                "external_id": None,
                "catch_up": "skip",
                "source": "agent",
                "source_hash": None,
            }

        def event(
            *,
            event_id: uuid.UUID,
            sequence: int,
            rows: list[dict[str, object]],
        ) -> dict[str, object]:
            body = external_projection_body(
                stream_id=str(stream_id),
                epoch_uuid=str(epoch_uuid),
                epoch_number=epoch_number,
                sequence=sequence,
                kind="snapshot",
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id="beat-instance-1",
                schedules=rows,
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            return {
                "id": str(event_id),
                "kind": "schedule.snapshot",
                "engine": "celery-beat",
                "task_id": "",
                "occurred_at": datetime(
                    2026,
                    7,
                    25,
                    15,
                    sequence,
                    tzinfo=UTC,
                ).isoformat(),
                "data": {
                    "external_projection": body,
                    "payload_digest": external_projection_digest(body),
                },
            }

        first = event(
            event_id=uuid.uuid4(),
            sequence=1,
            rows=[projected("alpha")],
        )
        second_id = uuid.uuid4()
        second = event(
            event_id=second_id,
            sequence=2,
            rows=[projected("alpha"), projected("beta")],
        )
        ingestor = EventIngestor(RedactionEngine(RedactionConfig()))

        async def ingest(raw: dict[str, object]):
            async with database.session(write=True) as session:
                result = await ingestor.ingest_batch(
                    events=[raw],
                    project_id=project_id,
                    agent_id=agent_id,
                    agents=AgentRepository(session),
                    event_repo=EventRepository(session),
                    task_repo=TaskRepository(session),
                    queue_repo=QueueRepository(session),
                )
                await session.commit()
                return result

        gap = await ingest(second)
        assert gap.transient_skips == 1
        assert len(gap.new_events) == 1

        accepted_first = await ingest(first)
        assert accepted_first.transient_skips == 0
        assert len(accepted_first.new_events) == 1

        replayed_gap = await ingest(second)
        assert replayed_gap.transient_skips == 0
        assert replayed_gap.new_events == []

        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            assert stream.accepted_sequence == 2
            names = set(
                (
                    await session.execute(
                        select(Schedule.name).where(
                            Schedule.external_stream_id == stream_id,
                        ),
                    )
                ).scalars(),
            )
            assert names == {"alpha", "beta"}
    finally:
        await async_engine.dispose()


async def test_framed_activation_reconciles_only_after_exact_terminal_replay(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """Partial frames stage durably but cannot mutate the schedule catalog."""

    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    adapter_instance_id = "beat-framed-instance"
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "framed-external"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="beat-framed",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="django",
                    engine_adapters=["celery"],
                    scheduler_adapters=["celery-beat"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="celery-beat",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 15, 30, tzinfo=UTC),
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=agent_id,
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
            )
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            await session.commit()

        def projected(name: str) -> dict[str, object]:
            return {
                "source_key": name,
                "engine": "celery",
                "scheduler": "celery-beat",
                "name": name,
                "task_name": f"jobs.{name}",
                "kind": "interval",
                "expression": "5m",
                "timezone": "UTC",
                "queue": None,
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "last_run_at": None,
                "next_run_at": None,
                "total_runs": 0,
                "external_id": None,
                "catch_up": "skip",
                "source": "agent",
                "source_hash": None,
            }

        rows = [projected("alpha"), projected("beta")]
        projection = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner="celery-beat",
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=rows,
            complete=True,
            stable_source=True,
        )
        snapshot_digest = external_projection_digest(projection)
        snapshot_id = uuid.uuid4()

        def frame_event(
            *,
            frame_kind: str,
            frame_index: int,
            frame_rows: list[dict[str, object]],
            event_id: uuid.UUID,
        ) -> dict[str, object]:
            body = external_snapshot_frame_body(
                stream_id=str(stream_id),
                epoch_uuid=str(epoch_uuid),
                epoch_number=epoch_number,
                sequence=1,
                owner="celery-beat",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                snapshot_id=str(snapshot_id),
                frame_kind=frame_kind,
                frame_index=frame_index,
                frame_count=2,
                row_count=2,
                snapshot_digest=snapshot_digest,
                stable_source=True,
                schedules=frame_rows,
            )
            return {
                "id": str(event_id),
                "kind": "schedule.snapshot",
                "engine": "celery-beat",
                "task_id": "",
                "occurred_at": datetime(
                    2026,
                    7,
                    25,
                    15,
                    31,
                    frame_index,
                    tzinfo=UTC,
                ).isoformat(),
                "data": {
                    "external_snapshot_frame": body,
                    "frame_digest": external_snapshot_frame_digest(body),
                },
            }

        terminal_id = uuid.uuid4()
        terminal = frame_event(
            frame_kind="terminal",
            frame_index=2,
            frame_rows=[],
            event_id=terminal_id,
        )
        row_zero = frame_event(
            frame_kind="rows",
            frame_index=0,
            frame_rows=[rows[0]],
            event_id=uuid.uuid4(),
        )
        row_one = frame_event(
            frame_kind="rows",
            frame_index=1,
            frame_rows=[rows[1]],
            event_id=uuid.uuid4(),
        )
        ingestor = EventIngestor(RedactionEngine(RedactionConfig()))

        async def ingest(raw: dict[str, object]):
            async with database.session(write=True) as session:
                result = await ingestor.ingest_batch(
                    events=[raw],
                    project_id=project_id,
                    agent_id=agent_id,
                    agents=AgentRepository(session),
                    event_repo=EventRepository(session),
                    task_repo=TaskRepository(session),
                    queue_repo=QueueRepository(session),
                )
                await session.commit()
                return result

        incomplete = await ingest(terminal)
        assert incomplete.transient_skips == 1
        await ingest(row_zero)
        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO schedule_external_snapshot_frames "
                        "SELECT * FROM schedule_external_snapshot_frames "
                        "WHERE stream_id = :stream_id",
                    ),
                    {"stream_id": stream_id.hex},
                )
        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            assert stream.phase == "ACTIVATING"
            assert stream.accepted_sequence == 0
            assert (
                await session.scalar(
                    select(Schedule).where(
                        Schedule.external_stream_id == stream_id,
                    ),
                )
                is None
            )

        await ingest(row_one)
        completed = await ingest(terminal)
        assert completed.transient_skips == 0
        assert completed.new_events == []

        async with database.session() as session:
            stream = await session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            assert stream.phase == "ACTIVE"
            assert stream.accepted_sequence == 1
            assert (
                await session.scalar(
                    select(ScheduleExternalSnapshotFrame)
                    .where(
                        ScheduleExternalSnapshotFrame.stream_id == stream_id,
                    )
                    .with_only_columns(func.count())
                )
                == 3
            )
            names = set(
                (
                    await session.execute(
                        select(Schedule.name).where(
                            Schedule.external_stream_id == stream_id,
                        ),
                    )
                ).scalars(),
            )
            assert names == {"alpha", "beta"}
    finally:
        await async_engine.dispose()


async def test_external_activation_claim_is_bound_to_exact_websocket_generation(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    adapter_instance_id = str(uuid.uuid4())
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "exact-activation"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="cron-1",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="bare",
                    engine_adapters=["arq"],
                    scheduler_adapters=["arqcron"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="arqcron",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 16, 0, tzinfo=UTC),
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=agent_id,
                executor_registry_owner_id=registry_owner_id,
                executor_session_generation=session_generation,
            )
            payload = {
                "scheduler": "arqcron",
                "owner": "arqcron",
                "source_scope": source_scope,
                "stream_id": str(stream.id),
                "epoch_uuid": str(stream.current_epoch_uuid),
                "epoch_number": stream.current_epoch_number,
                "adapter_instance_id": adapter_instance_id,
                "stable_source": True,
                "registry_owner_id": str(registry_owner_id),
                "session_generation": session_generation,
            }
            command_row, created = await CommandRepository(session).insert(
                project_id=project_id,
                agent_id=agent_id,
                issued_by=None,
                action="schedule.external.activate",
                target_type="scheduler",
                target_id="arqcron",
                payload=payload,
                idempotency_key=f"activation:{stream.current_epoch_uuid}",
                timeout_at=datetime(2026, 7, 25, 16, 5, tzinfo=UTC),
                source_ip=None,
                enforce_payload_identity=True,
            )
            assert created
            await session.commit()
            command_id = command_row.id

        async with database.session(write=True) as session:
            is_current, refused = await CommandRepository(
                session,
            ).claim_current_schedule_delivery(
                command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind="websocket",
                registry_owner_id=registry_owner_id,
                session_generation=str(uuid.uuid4()),
                timeout_seconds=60,
                occurred_at=datetime(2026, 7, 25, 16, 1, tzinfo=UTC),
            )
            assert is_current is True
            assert refused is None
            await session.rollback()

        async with database.session(write=True) as session:
            is_current, claimed = await CommandRepository(
                session,
            ).claim_current_schedule_delivery(
                command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind="websocket",
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                timeout_seconds=60,
                occurred_at=datetime(2026, 7, 25, 16, 1, tzinfo=UTC),
            )
            assert is_current is True
            assert claimed is not None
            assert claimed.delivery_transport_kind == "websocket"
            assert claimed.delivery_registry_owner_id == registry_owner_id
            assert claimed.delivery_session_generation == session_generation
            assert claimed.delivery_claim_token is not None
            await session.commit()
    finally:
        await async_engine.dispose()


async def test_activated_brain_rejects_unsequenced_schedule_event_before_insert(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "legacy-schedule-event"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="legacy-scheduler",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="1",
                    framework_adapter="bare",
                    engine_adapters=["celery"],
                    scheduler_adapters=["celery-beat"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.commit()

        event = {
            "id": str(uuid.uuid4()),
            "kind": "schedule.snapshot",
            "engine": "celery-beat",
            "task_id": "",
            "occurred_at": datetime(2026, 7, 26, 12, 0, tzinfo=UTC).isoformat(),
            "data": {
                "scheduler": "celery-beat",
                "schedules": [
                    {
                        "name": "legacy-row",
                        "task_name": "jobs.legacy",
                        "kind": "interval",
                        "expression": "5m",
                        "engine": "celery",
                        "scheduler": "celery-beat",
                        "is_enabled": True,
                        "args": [],
                        "kwargs": {},
                    },
                ],
            },
        }
        ingestor = EventIngestor(RedactionEngine(RedactionConfig()))
        async with database.session(write=True) as session:
            result = await ingestor.ingest_batch(
                events=[event],
                project_id=project_id,
                agent_id=agent_id,
                agents=AgentRepository(session),
                event_repo=EventRepository(session),
                task_repo=TaskRepository(session),
                queue_repo=QueueRepository(session),
            )
            await session.commit()

        assert result.upgrade_required is True
        assert result.fully_durable is False
        assert result.transient_skips == 0
        assert result.new_events == []
        async with database.session() as session:
            assert await session.scalar(select(func.count()).select_from(Event)) == 0
            assert await session.scalar(select(func.count()).select_from(Schedule)) == 0
    finally:
        await async_engine.dispose()


async def test_gateway_issues_activation_only_to_the_exact_stable_session(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    handle = SimpleNamespace(
        agent_id=agent_id,
        worker_id="scheduler-1",
        registry_owner_id=uuid.uuid4(),
        generation=uuid.uuid4(),
    )
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "gateway-activation"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="cron-1",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="bare",
                    engine_adapters=["arq"],
                    scheduler_adapters=["arqcron"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.commit()

        class _Audit:
            async def record(self, _repo, **_kwargs):
                return None

        class _Registry:
            async def deliver_exact(self, *, command_id, session):
                assert session is handle
                async with database.session(write=True) as db_session:
                    current, claimed = await CommandRepository(
                        db_session,
                    ).claim_current_schedule_delivery(
                        command_id,
                        project_id=project_id,
                        agent_id=agent_id,
                        transport_kind="websocket",
                        registry_owner_id=handle.registry_owner_id,
                        session_generation=str(handle.generation),
                        timeout_seconds=60,
                        occurred_at=datetime(
                            2026,
                            7,
                            25,
                            17,
                            0,
                            tzinfo=UTC,
                        ),
                    )
                    assert current is True
                    await db_session.commit()
                    return claimed is not None

        delivered = await _issue_external_schedule_activations(
            db=database,
            settings=SimpleNamespace(command_timeout_seconds=60),
            dispatcher=SimpleNamespace(audit=_Audit()),
            registry=_Registry(),
            session_handle=handle,
            project_id=project_id,
            agent_id=agent_id,
            schedulers=["arqcron"],
            capabilities={
                "arqcron": [
                    EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
                ],
            },
            runtime_features=[EXTERNAL_SCHEDULE_RUNTIME_FEATURE],
        )
        assert delivered == 1

        async with database.session() as session:
            stream = (
                await session.execute(
                    select(ScheduleExternalStream).where(
                        ScheduleExternalStream.project_id == project_id,
                    ),
                )
            ).scalar_one()
            activation_command = (
                await session.execute(
                    select(Command).where(
                        Command.action == "schedule.external.activate",
                    ),
                )
            ).scalar_one()
            assert stream.authorized_adapter_instance_id is not None
            assert (
                activation_command.payload["adapter_instance_id"]
                == stream.authorized_adapter_instance_id
            )
            assert activation_command.status.value == "dispatched"
            assert activation_command.delivery_registry_owner_id == handle.registry_owner_id
            assert activation_command.delivery_session_generation == str(handle.generation)
    finally:
        await async_engine.dispose()


async def test_gateway_reactivates_restore_hold_with_fresh_epoch(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """A proved restore hold has one bounded exit through a fresh activation."""

    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    old_agent_id = uuid.uuid4()
    handle = SimpleNamespace(
        agent_id=agent_id,
        worker_id="scheduler-1",
        registry_owner_id=uuid.uuid4(),
        generation=uuid.uuid4(),
    )
    owner = "arqcron"
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
    restored_adapter_instance_id = "restored-adapter"
    restored_projection = {
        "source_key": "restored-nightly",
        "engine": "arq",
        "scheduler": owner,
        "name": "restored-nightly",
        "task_name": "jobs.restored_nightly",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": None,
        "total_runs": 0,
        "external_id": "restored-nightly",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "gateway-restore-reactivation"))
            await session.flush()
            session.add_all(
                [
                    Agent(
                        id=agent_id,
                        project_id=project_id,
                        name="cron-new",
                        token_hash=uuid.uuid4().hex,
                        protocol_version="2",
                        framework_adapter="bare",
                        engine_adapters=["arq"],
                        scheduler_adapters=[owner],
                        capabilities={},
                        state=AgentState.ONLINE,
                    ),
                    Agent(
                        id=old_agent_id,
                        project_id=project_id,
                        name="cron-restored",
                        token_hash=uuid.uuid4().hex,
                        protocol_version="2",
                        framework_adapter="bare",
                        engine_adapters=["arq"],
                        scheduler_adapters=[owner],
                        capabilities={},
                        state=AgentState.OFFLINE,
                    ),
                ],
            )
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 17, 0, tzinfo=UTC),
                adapter_instance_id=restored_adapter_instance_id,
                executor_agent_id=old_agent_id,
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
                executor_worker_id="restored-worker",
            )
            old_epoch_uuid = stream.current_epoch_uuid
            old_epoch_number = stream.current_epoch_number
            activation = external_projection_body(
                stream_id=str(stream.id),
                epoch_uuid=str(old_epoch_uuid),
                epoch_number=old_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=restored_adapter_instance_id,
                schedules=[restored_projection],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            activation_digest = external_projection_digest(activation)
            applied = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream.id,
                epoch_uuid=old_epoch_uuid,
                epoch_number=old_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=restored_adapter_instance_id,
                schedules=[restored_projection],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=activation_digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 17, 0, 30, tzinfo=UTC),
            )
            assert applied.disposition == "applied"
            assert stream.phase == "ACTIVE"
            await arm_external_lifecycle_transition(
                session,
                transition="restore_hold",
                operation_id=uuid.uuid4(),
                stream_id=stream.id,
                epoch_uuid=old_epoch_uuid,
                epoch_number=old_epoch_number,
                accepted_sequence=stream.accepted_sequence,
                from_phase=stream.phase,
                to_phase="RESTORE_REACTIVATION_REQUIRED",
                sealed_sequence=stream.sealed_sequence,
                last_snapshot_digest=stream.last_snapshot_digest,
                mutations=[],
            )
            epoch_updated = await session.execute(
                ScheduleExternalStreamEpoch.__table__.update()
                .where(
                    ScheduleExternalStreamEpoch.epoch_uuid == old_epoch_uuid,
                    ScheduleExternalStreamEpoch.phase == "ACTIVE",
                )
                .values(phase="RESTORE_REACTIVATION_REQUIRED"),
            )
            stream_updated = await session.execute(
                ScheduleExternalStream.__table__.update()
                .where(
                    ScheduleExternalStream.id == stream.id,
                    ScheduleExternalStream.phase == "ACTIVE",
                )
                .values(phase="RESTORE_REACTIVATION_REQUIRED"),
            )
            assert epoch_updated.rowcount == 1
            assert stream_updated.rowcount == 1
            await assert_external_lifecycle_consumed(session)
            await session.commit()

        class _Audit:
            async def record(self, _repo, **_kwargs):
                return None

        class _Registry:
            async def deliver_exact(self, *, command_id, session):
                assert session is handle
                async with database.session(write=True) as db_session:
                    current, claimed = await CommandRepository(
                        db_session,
                    ).claim_current_schedule_delivery(
                        command_id,
                        project_id=project_id,
                        agent_id=agent_id,
                        transport_kind="websocket",
                        registry_owner_id=handle.registry_owner_id,
                        session_generation=str(handle.generation),
                        timeout_seconds=60,
                        occurred_at=datetime(2026, 7, 25, 17, 1, tzinfo=UTC),
                    )
                    assert current is True
                    await db_session.commit()
                    return claimed is not None

        delivered = await _issue_external_schedule_activations(
            db=database,
            settings=SimpleNamespace(command_timeout_seconds=60),
            dispatcher=SimpleNamespace(audit=_Audit()),
            registry=_Registry(),
            session_handle=handle,
            project_id=project_id,
            agent_id=agent_id,
            schedulers=[owner],
            capabilities={
                owner: [
                    EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
                ],
            },
            runtime_features=[EXTERNAL_SCHEDULE_RUNTIME_FEATURE],
        )
        assert delivered == 1

        async with database.session() as session:
            stream = (
                await session.execute(
                    select(ScheduleExternalStream).where(
                        ScheduleExternalStream.project_id == project_id,
                    ),
                )
            ).scalar_one()
            epochs = list(
                (
                    await session.execute(
                        select(ScheduleExternalStreamEpoch)
                        .where(
                            ScheduleExternalStreamEpoch.stream_id == stream.id,
                        )
                        .order_by(
                            ScheduleExternalStreamEpoch.epoch_number,
                        ),
                    )
                ).scalars(),
            )
            activation_command = (
                await session.execute(
                    select(Command).where(
                        Command.action == "schedule.external.activate",
                    ),
                )
            ).scalar_one()
            assert [epoch.phase for epoch in epochs] == [
                "RESTORE_REACTIVATION_REQUIRED",
                "ACTIVATING",
            ]
            assert epochs[0].epoch_uuid == old_epoch_uuid
            assert stream.current_epoch_uuid == epochs[1].epoch_uuid
            assert stream.current_epoch_number > old_epoch_number
            assert stream.executor_agent_id == agent_id
            assert stream.executor_registry_owner_id == handle.registry_owner_id
            assert stream.executor_session_generation == str(handle.generation)
            assert activation_command.status == CommandStatus.DISPATCHED
            assert activation_command.payload["epoch_uuid"] == str(
                stream.current_epoch_uuid,
            )
            restored_schedule = (
                await session.execute(
                    select(Schedule).where(
                        Schedule.external_stream_id == stream.id,
                    ),
                )
            ).scalar_one()
            assert restored_schedule.external_epoch_uuid == old_epoch_uuid
            assert restored_schedule.external_epoch_number == old_epoch_number
            new_epoch_uuid = stream.current_epoch_uuid
            new_epoch_number = stream.current_epoch_number
            new_adapter_instance_id = stream.authorized_adapter_instance_id

        assert new_adapter_instance_id is not None
        stable_snapshot = external_projection_body(
            stream_id=str(stream.id),
            epoch_uuid=str(new_epoch_uuid),
            epoch_number=new_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=new_adapter_instance_id,
            schedules=[restored_projection],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        stable_snapshot_digest = external_projection_digest(
            stable_snapshot,
        )
        async with database.session(write=True) as session:
            activated = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream.id,
                epoch_uuid=new_epoch_uuid,
                epoch_number=new_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=new_adapter_instance_id,
                schedules=[restored_projection],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=stable_snapshot_digest,
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 17, 2, tzinfo=UTC),
            )
            assert activated.disposition == "applied"
            await session.commit()

        async with database.session() as session:
            stream = await session.get(
                ScheduleExternalStream,
                stream.id,
            )
            restored_schedule = (
                await session.execute(
                    select(Schedule).where(
                        Schedule.external_stream_id == stream.id,
                    ),
                )
            ).scalar_one()
            assert stream is not None
            assert stream.phase == "ACTIVE"
            assert stream.accepted_sequence == 1
            assert restored_schedule.external_epoch_uuid == new_epoch_uuid
            assert restored_schedule.external_epoch_number == new_epoch_number
    finally:
        await async_engine.dispose()


async def test_gateway_activation_skips_revoked_agent_before_stream_or_command(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """Registration is a hint; the durable tombstone wins at insertion."""
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    handle = SimpleNamespace(
        agent_id=agent_id,
        worker_id="scheduler-revoked",
        registry_owner_id=uuid.uuid4(),
        generation=uuid.uuid4(),
    )
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "gateway-revoked"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="revoked-cron",
                    token_hash=f"revoked:{agent_id}",
                    protocol_version="2",
                    framework_adapter="bare",
                    engine_adapters=["arq"],
                    scheduler_adapters=["arqcron"],
                    capabilities={},
                    state=AgentState.OFFLINE,
                    revoked_at=datetime.now(UTC),
                ),
            )
            await session.commit()

        class _Audit:
            async def record(self, _repo, **_kwargs):
                pytest.fail("revoked activation must not write its allow audit")

        class _Registry:
            async def deliver_exact(self, **_kwargs):
                pytest.fail("revoked activation must not reach physical delivery")

        delivered = await _issue_external_schedule_activations(
            db=database,
            settings=SimpleNamespace(command_timeout_seconds=60),
            dispatcher=SimpleNamespace(audit=_Audit()),
            registry=_Registry(),
            session_handle=handle,
            project_id=project_id,
            agent_id=agent_id,
            schedulers=["arqcron"],
            capabilities={
                "arqcron": [
                    EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
                ],
            },
            runtime_features=[EXTERNAL_SCHEDULE_RUNTIME_FEATURE],
        )
        assert delivered == 0

        async with database.session() as session:
            assert await session.scalar(select(func.count(ScheduleExternalStream.id))) == 0
            assert (
                await session.scalar(
                    select(func.count(Command.id)).where(
                        Command.action == "schedule.external.activate",
                    ),
                )
                == 0
            )
    finally:
        await async_engine.dispose()


async def test_external_control_planning_rejects_revoked_stream_executor(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    """An ACTIVE stream cannot mint fresh work for its retired agent."""
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    database = DatabaseManager(create_async_engine(async_url))
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    adapter_instance_id = str(uuid.uuid4())
    stream_id: uuid.UUID | None = None
    try:
        occurred_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
        owner = "arqcron"
        source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
        projected = {
            "source_key": "revoked-control-source",
            "engine": "arq",
            "scheduler": owner,
            "name": "revoked-control-schedule",
            "task_name": "jobs.revoked_control",
            "kind": "interval",
            "expression": "60",
            "timezone": "UTC",
            "queue": None,
            "priority": "normal",
            "args": [],
            "kwargs": {},
            "is_enabled": True,
            "last_run_at": None,
            "next_run_at": None,
            "total_runs": 0,
            "external_id": None,
            "catch_up": "skip",
            "source": "agent",
            "source_hash": None,
        }
        async with database.session(write=True) as session:
            session.add(_project(project_id, "revoked-control"))
            await session.flush()
            agent = Agent(
                id=agent_id,
                project_id=project_id,
                name="revoked-control-agent",
                token_hash=uuid.uuid4().hex,
                protocol_version="2",
                framework_adapter="bare",
                engine_adapters=["arq"],
                scheduler_adapters=[owner],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.flush()
            external = ScheduleExternalRepository(session)
            stream = await external.ensure_activation_epoch(
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                occurred_at=occurred_at,
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=agent_id,
                executor_registry_owner_id=registry_owner_id,
                executor_session_generation=session_generation,
            )
            stream_id = stream.id
            body = external_projection_body(
                stream_id=str(stream.id),
                epoch_uuid=str(stream.current_epoch_uuid),
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            applied = await external.apply_projection(
                project_id=project_id,
                stream_id=stream.id,
                epoch_uuid=stream.current_epoch_uuid,
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(body),
                operation_id=None,
                occurred_at=occurred_at,
            )
            assert applied.disposition == "applied"
            schedule = (
                await session.execute(
                    select(Schedule).where(Schedule.external_stream_id == stream.id),
                )
            ).scalar_one()
            await AgentRepository(session).revoke(agent, at=occurred_at + timedelta(seconds=1))
            plan = await external.plan_control_operation(
                project_id=project_id,
                stream_id=stream.id,
                schedule_id=schedule.id,
                enabled=False,
                issued_by=None,
                source_ip=None,
                timeout_at=occurred_at + timedelta(minutes=5),
            )
            assert plan.disposition == "stream_not_executable"
            assert plan.operation is None
            assert plan.command is None
            await session.commit()

        async with database.session() as session:
            assert stream_id is not None
            assert await session.scalar(select(func.count(ScheduleExternalStream.id))) == 1
            assert (
                await session.scalar(
                    select(func.count(ScheduleExternalControlOperation.id)),
                )
                == 0
            )
            assert (
                await session.scalar(
                    select(func.count(Command.id)).where(
                        Command.action == "schedule.external.control",
                    ),
                )
                == 0
            )
    finally:
        await database.dispose()


@pytest.mark.parametrize("first_claimed", [False, True])
async def test_gateway_replaces_only_a_never_claimed_activation(
    boundary_d_install: tuple[Config, str, str],
    first_claimed: bool,
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    first = SimpleNamespace(
        agent_id=agent_id,
        worker_id="scheduler-1",
        registry_owner_id=uuid.uuid4(),
        generation=uuid.uuid4(),
    )
    second = SimpleNamespace(
        agent_id=agent_id,
        worker_id="scheduler-1",
        registry_owner_id=first.registry_owner_id,
        generation=uuid.uuid4(),
    )
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "gateway-activation-reconnect"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="cron-1",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="bare",
                    engine_adapters=["arq"],
                    scheduler_adapters=["arqcron"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.commit()

        class _Audit:
            async def record(self, _repo, **_kwargs):
                return None

        class _Registry:
            def __init__(self) -> None:
                self.attempt = 0

            async def deliver_exact(self, *, command_id, session):
                self.attempt += 1
                if self.attempt == 1:
                    assert session is first
                    if first_claimed:
                        async with database.session(write=True) as db_session:
                            current, claimed = await CommandRepository(
                                db_session,
                            ).claim_current_schedule_delivery(
                                command_id,
                                project_id=project_id,
                                agent_id=agent_id,
                                transport_kind="websocket",
                                registry_owner_id=first.registry_owner_id,
                                session_generation=str(first.generation),
                                timeout_seconds=60,
                                occurred_at=datetime(
                                    2026,
                                    7,
                                    25,
                                    17,
                                    0,
                                    tzinfo=UTC,
                                ),
                            )
                            assert current is True
                            assert claimed is not None
                            await db_session.commit()
                    return False
                assert session is second
                async with database.session(write=True) as db_session:
                    current, claimed = await CommandRepository(
                        db_session,
                    ).claim_current_schedule_delivery(
                        command_id,
                        project_id=project_id,
                        agent_id=agent_id,
                        transport_kind="websocket",
                        registry_owner_id=second.registry_owner_id,
                        session_generation=str(second.generation),
                        timeout_seconds=60,
                        occurred_at=datetime(2026, 7, 25, 17, 1, tzinfo=UTC),
                    )
                    assert current is True
                    await db_session.commit()
                    return claimed is not None

        registry = _Registry()
        common = {
            "db": database,
            "settings": SimpleNamespace(command_timeout_seconds=60),
            "dispatcher": SimpleNamespace(audit=_Audit()),
            "registry": registry,
            "project_id": project_id,
            "agent_id": agent_id,
            "schedulers": ["arqcron"],
            "capabilities": {
                "arqcron": [
                    EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
                ],
            },
            "runtime_features": [EXTERNAL_SCHEDULE_RUNTIME_FEATURE],
        }
        assert (
            await _issue_external_schedule_activations(
                session_handle=first,
                **common,
            )
            == 0
        )
        second_delivery = await _issue_external_schedule_activations(
            session_handle=second,
            **common,
        )
        assert second_delivery == (0 if first_claimed else 1)

        async with database.session() as session:
            stream = (
                await session.execute(
                    select(ScheduleExternalStream).where(
                        ScheduleExternalStream.project_id == project_id,
                    ),
                )
            ).scalar_one()
            commands = list(
                (
                    await session.execute(
                        select(Command)
                        .where(Command.action == "schedule.external.activate")
                        .order_by(Command.issued_at),
                    )
                ).scalars(),
            )
            epochs = list(
                (
                    await session.execute(
                        select(ScheduleExternalStreamEpoch)
                        .where(ScheduleExternalStreamEpoch.stream_id == stream.id)
                        .order_by(ScheduleExternalStreamEpoch.epoch_number),
                    )
                ).scalars(),
            )
            if first_claimed:
                assert [row.status for row in commands] == [
                    CommandStatus.DISPATCHED,
                ]
                assert [row.phase for row in epochs] == ["ACTIVATING"]
                assert stream.current_epoch_uuid == epochs[0].epoch_uuid
                assert stream.executor_session_generation == str(first.generation)
                assert commands[0].delivery_session_generation == str(first.generation)
            else:
                assert [row.status for row in commands] == [
                    CommandStatus.CANCELLED,
                    CommandStatus.DISPATCHED,
                ]
                assert [row.phase for row in epochs] == [
                    "RETIRED",
                    "ACTIVATING",
                ]
                assert stream.current_epoch_uuid == epochs[1].epoch_uuid
                assert stream.executor_session_generation == str(second.generation)
                assert commands[1].delivery_session_generation == str(
                    second.generation,
                )
    finally:
        await async_engine.dispose()


async def test_external_stream_drain_seal_retire_is_fail_closed(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    engine = create_async_engine(async_url)
    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    adapter_instance_id = str(uuid.uuid4())
    owner = "celery-beat"
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    now = datetime(2026, 7, 26, 1, 0, tzinfo=UTC)
    projected = {
        "source_key": "nightly",
        "engine": "celery",
        "scheduler": owner,
        "name": "nightly",
        "task_name": "jobs.nightly",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": None,
        "total_runs": 0,
        "external_id": "nightly",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "drain-seal"))
            await session.flush()
            repo = ScheduleExternalRepository(session)
            stream = await repo.ensure_activation_epoch(
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                occurred_at=now,
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=str(uuid.uuid4()),
                executor_worker_id="worker-a",
            )
            activation = external_projection_body(
                stream_id=str(stream.id),
                epoch_uuid=str(stream.current_epoch_uuid),
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            applied = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream.id,
                epoch_uuid=stream.current_epoch_uuid,
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(activation),
                operation_id=None,
                occurred_at=now,
            )
            assert applied.disposition == "applied"
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            await session.commit()

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            draining = await repo.begin_stream_drain(
                project_id=project_id,
                stream_id=stream_id,
                occurred_at=now + timedelta(minutes=1),
            )
            assert draining.disposition == "draining"
            await session.commit()

        final_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=2,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        final_digest = external_projection_digest(final_body)
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            final = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=2,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=final_digest,
                operation_id=None,
                occurred_at=now + timedelta(minutes=2),
            )
            assert final.disposition == "applied"
            mismatch = await repo.seal_drained_stream(
                project_id=project_id,
                stream_id=stream_id,
                expected_sequence=2,
                expected_snapshot_digest="0" * 64,
                occurred_at=now + timedelta(minutes=3),
            )
            assert mismatch.disposition == "seal_mismatch"
            sealed = await repo.seal_drained_stream(
                project_id=project_id,
                stream_id=stream_id,
                expected_sequence=2,
                expected_snapshot_digest=final_digest,
                occurred_at=now + timedelta(minutes=3),
            )
            assert sealed.disposition == "sealed"
            await session.commit()

        late_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=3,
            kind="updated",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=False,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            late = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=3,
                kind="updated",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                payload_digest=external_projection_digest(late_body),
                operation_id=None,
                occurred_at=now + timedelta(minutes=4),
            )
            assert late.disposition == "stream_not_accepting"
            retired = await repo.retire_sealed_stream(
                project_id=project_id,
                stream_id=stream_id,
                occurred_at=now + timedelta(minutes=5),
            )
            assert retired.disposition == "retired"
            await session.commit()

        async with database.session(write=True) as session:
            with pytest.raises(
                (IntegrityError, OperationalError),
            ):
                await session.execute(
                    text(
                        "UPDATE schedule_external_streams "
                        "SET phase = 'ACTIVE' WHERE id = :stream_id",
                    ),
                    {"stream_id": stream_id.hex},
                )
                await session.flush()
    finally:
        await engine.dispose()


async def test_external_to_reserved_cutover_is_manifest_bound_and_atomic(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    engine = create_async_engine(async_url)
    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    owner = "celery-beat"
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    adapter_instance_id = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 3, 0, tzinfo=UTC)
    projected = {
        "source_key": "cutover-nightly",
        "engine": "celery",
        "scheduler": owner,
        "name": "cutover-nightly",
        "task_name": "jobs.cutover_nightly",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": "2026-07-26T02:00:00+00:00",
        "next_run_at": None,
        "total_runs": 7,
        "external_id": "cutover-nightly",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "owner-cutover"))
            await session.flush()
            repo = ScheduleExternalRepository(session)
            stream = await repo.ensure_activation_epoch(
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                occurred_at=now,
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=str(uuid.uuid4()),
                executor_worker_id="worker-a",
            )
            activation_body = external_projection_body(
                stream_id=str(stream.id),
                epoch_uuid=str(stream.current_epoch_uuid),
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            activated = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream.id,
                epoch_uuid=stream.current_epoch_uuid,
                epoch_number=stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(
                    activation_body,
                ),
                operation_id=None,
                occurred_at=now,
            )
            assert activated.disposition == "applied"
            schedule = (
                await session.execute(
                    select(Schedule).where(
                        Schedule.external_stream_id == stream.id,
                    ),
                )
            ).scalar_one()
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            schedule_id = schedule.id
            await session.commit()

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            draining = await repo.begin_stream_drain(
                project_id=project_id,
                stream_id=stream_id,
                occurred_at=now + timedelta(minutes=1),
            )
            assert draining.disposition == "draining"
            stale_preview = await repo.preview_external_to_reserved_cutover(
                project_id=project_id,
                from_owner=owner,
                source_scope=source_scope,
            )
            await session.commit()

        early_attestation = {
            "all_old_and_new_scheduler_replicas_quiesced": True,
            "preview_manifest_digest": (stale_preview.manifest_digest),
            "stream_id": str(stream_id),
            "epoch_uuid": str(epoch_uuid),
            "sealed_sequence": 1,
            "final_snapshot_digest": external_projection_digest(
                activation_body,
            ),
        }
        async with database.session(write=True) as session:
            early = await ScheduleExternalRepository(
                session,
            ).finalize_external_to_reserved_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner=owner,
                source_scope=source_scope,
                preview_manifest_digest=(stale_preview.manifest_digest),
                cursor_policy="PRESERVE",
                quiescence_attestation=early_attestation,
                occurred_at=now + timedelta(minutes=2),
            )
            assert early.disposition == "stream_not_sealed"

        final_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=2,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        final_digest = external_projection_digest(final_body)
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            final = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=2,
                kind="snapshot",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=final_digest,
                operation_id=None,
                occurred_at=now + timedelta(minutes=2),
            )
            assert final.disposition == "applied"
            sealed = await repo.seal_drained_stream(
                project_id=project_id,
                stream_id=stream_id,
                expected_sequence=2,
                expected_snapshot_digest=final_digest,
                occurred_at=now + timedelta(minutes=3),
            )
            assert sealed.disposition == "sealed"
            await session.commit()

        async with database.session(write=True) as session:
            with pytest.raises(
                (IntegrityError, OperationalError),
            ):
                await session.execute(
                    text(
                        "UPDATE schedules SET scheduler = 'z4j-scheduler' WHERE id = :schedule_id",
                    ),
                    {"schedule_id": schedule_id.hex},
                )
                await session.flush()

        stale_attestation = {
            "all_old_and_new_scheduler_replicas_quiesced": True,
            "preview_manifest_digest": (stale_preview.manifest_digest),
            "stream_id": str(stream_id),
            "epoch_uuid": str(epoch_uuid),
            "sealed_sequence": 2,
            "final_snapshot_digest": final_digest,
        }
        async with database.session(write=True) as session:
            stale = await ScheduleExternalRepository(
                session,
            ).finalize_external_to_reserved_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner=owner,
                source_scope=source_scope,
                preview_manifest_digest=(stale_preview.manifest_digest),
                cursor_policy="PRESERVE",
                quiescence_attestation=stale_attestation,
                occurred_at=now + timedelta(minutes=4),
            )
            assert stale.disposition == "preview_changed"

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            preview = await repo.preview_external_to_reserved_cutover(
                project_id=project_id,
                from_owner=owner,
                source_scope=source_scope,
            )
            before = await session.get(Schedule, schedule_id)
            assert before is not None
            old_token = before.control_token
            old_revision = before.schedule_revision
            attestation = {
                "all_old_and_new_scheduler_replicas_quiesced": True,
                "preview_manifest_digest": preview.manifest_digest,
                "stream_id": str(stream_id),
                "epoch_uuid": str(epoch_uuid),
                "sealed_sequence": 2,
                "final_snapshot_digest": final_digest,
            }
            await session.commit()

        cli_result = await asyncio.to_thread(
            cli_module.main,
            [
                "projects",
                "rewrite-scheduler",
                "--slug",
                "owner-cutover",
                "--from",
                owner,
                "--to",
                "z4j-scheduler",
                "--source-scope",
                source_scope,
                "--operation-id",
                str(operation_id),
                "--preview-manifest-digest",
                preview.manifest_digest,
                "--attest-all-schedulers-quiesced",
            ],
        )
        assert cli_result == 0

        async with database.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                stream_id,
            )
            cutover = await session.get(
                ScheduleOwnerCutover,
                operation_id,
            )
            assert schedule is not None
            assert stream is not None
            assert cutover is not None
            assert schedule.scheduler == "z4j-scheduler"
            assert schedule.control_token != old_token
            assert schedule.schedule_revision > old_revision
            assert schedule.last_run_at == datetime(
                2026,
                7,
                26,
                2,
                0,
            )
            assert schedule.next_run_at is not None
            assert schedule.total_runs == 7
            assert schedule.external_stream_id is None
            assert schedule.external_epoch_uuid is None
            assert schedule.external_epoch_number is None
            assert schedule.external_source_key is None
            assert schedule.external_source_sequence is None
            assert stream.phase == "RETIRED"
            assert cutover.preview_manifest_digest == (preview.manifest_digest)
            committed_token = schedule.control_token
            committed_revision = schedule.schedule_revision

        late_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=3,
            kind="updated",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=False,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            late = await repo.apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=3,
                kind="updated",
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                payload_digest=external_projection_digest(late_body),
                operation_id=None,
                occurred_at=now + timedelta(minutes=6),
            )
            assert late.disposition == "stream_not_accepting"
            replay = await repo.finalize_external_to_reserved_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner=owner,
                source_scope=source_scope,
                preview_manifest_digest=preview.manifest_digest,
                cursor_policy="PRESERVE",
                quiescence_attestation=attestation,
                occurred_at=now + timedelta(minutes=7),
            )
            assert replay.disposition == "exact_replay"
            current = await session.get(Schedule, schedule_id)
            assert current is not None
            assert current.control_token == committed_token
            assert current.schedule_revision == committed_revision

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            return_operation_id = uuid.uuid4()
            replacement_adapter = str(uuid.uuid4())
            replacement_agent = uuid.uuid4()
            replacement_registry = uuid.uuid4()
            replacement_generation = str(uuid.uuid4())
            return_preview = await repo.preview_to_external_cutover(
                project_id=project_id,
                from_owner="z4j-scheduler",
                source_scope='{"kind":"schedule-ids","version":1}',
                to_owner=owner,
                target_source_scope=source_scope,
                schedule_ids=(schedule_id,),
                target_adapter_instance_id=replacement_adapter,
                target_executor_agent_id=replacement_agent,
                target_executor_registry_owner_id=(replacement_registry),
                target_executor_session_generation=(replacement_generation),
                target_executor_worker_id="replacement-worker",
            )
            return_attestation = {
                "all_old_and_new_scheduler_replicas_quiesced": True,
                "preview_manifest_digest": (return_preview.manifest_digest),
                "source_stream_id": None,
            }
            returned = await repo.finalize_to_external_cutover(
                operation_id=return_operation_id,
                project_id=project_id,
                from_owner="z4j-scheduler",
                source_scope='{"kind":"schedule-ids","version":1}',
                to_owner=owner,
                target_source_scope=source_scope,
                schedule_ids=(schedule_id,),
                preview_manifest_digest=(return_preview.manifest_digest),
                cursor_policy="PRESERVE",
                quiescence_attestation=return_attestation,
                target_adapter_instance_id=replacement_adapter,
                target_executor_agent_id=replacement_agent,
                target_executor_registry_owner_id=(replacement_registry),
                target_executor_session_generation=(replacement_generation),
                target_executor_worker_id="replacement-worker",
                occurred_at=now + timedelta(minutes=8),
            )
            assert returned.disposition == "completed"
            replacement = returned.cutover
            assert replacement is not None
            target = await session.get(
                ScheduleExternalStream,
                replacement.target_stream_id,
            )
            assert target is not None
            assert target.id == stream_id
            assert target.current_epoch_uuid != epoch_uuid
            assert target.current_epoch_number > epoch_number
            assert target.phase == "ACTIVATING"
            assert target.accepted_sequence == 0
            await session.commit()

        async with database.session(write=True) as session:
            session.add(
                ScheduleOwnerCutover(
                    id=uuid.uuid4(),
                    project_id=project_id,
                    from_owner=owner,
                    to_owner="z4j-scheduler",
                    source_scope=source_scope,
                    preview_manifest_digest="0" * 64,
                    preview_manifest={},
                    cursor_policy="PRESERVE",
                    quiescence_attestation={},
                    quiescence_attestation_digest="1" * 64,
                    source_stream_manifest=[],
                    target_stream_id=None,
                    result_manifest={},
                    result_manifest_digest="2" * 64,
                    completed_at=now,
                    created_at=now,
                ),
            )
            with pytest.raises(
                (IntegrityError, OperationalError),
            ):
                await session.flush()
    finally:
        await engine.dispose()


async def test_reserved_to_external_cutover_requires_exact_activation(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    engine = create_async_engine(async_url)
    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    target_owner = "apscheduler"
    target_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    selection_scope = '{"kind":"schedule-ids","version":1}'
    adapter_instance_id = str(uuid.uuid4())
    executor_agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 5, 0, tzinfo=UTC)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "reserved-cutover"))
            await session.flush()
            schedule = await ScheduleControlRepository(
                session,
            ).create_current(
                project_id=project_id,
                data={
                    "name": "reserved-cutover",
                    "task_name": "jobs.reserved_cutover",
                    "engine": "celery",
                    "scheduler": "z4j-scheduler",
                    "kind": "interval",
                    "expression": "5m",
                    "timezone": "UTC",
                    "queue": None,
                    "priority": "normal",
                    "args": [],
                    "kwargs": {},
                    "is_enabled": True,
                    "catch_up": "skip",
                    "source": "dashboard",
                },
                planning_at=now,
            )
            schedule_id = schedule.id
            original_token = schedule.control_token
            original_revision = schedule.schedule_revision
            await session.commit()

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            preview = await repo.preview_to_external_cutover(
                project_id=project_id,
                from_owner="z4j-scheduler",
                source_scope=selection_scope,
                to_owner=target_owner,
                target_source_scope=target_scope,
                schedule_ids=(schedule_id,),
                target_adapter_instance_id=adapter_instance_id,
                target_executor_agent_id=executor_agent_id,
                target_executor_registry_owner_id=(registry_owner_id),
                target_executor_session_generation=(session_generation),
                target_executor_worker_id="worker-a",
            )
            attestation = {
                "all_old_and_new_scheduler_replicas_quiesced": True,
                "preview_manifest_digest": preview.manifest_digest,
                "source_stream_id": None,
            }
            completed = await repo.finalize_to_external_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner="z4j-scheduler",
                source_scope=selection_scope,
                to_owner=target_owner,
                target_source_scope=target_scope,
                schedule_ids=(schedule_id,),
                preview_manifest_digest=preview.manifest_digest,
                cursor_policy="PRESERVE",
                quiescence_attestation=attestation,
                target_adapter_instance_id=adapter_instance_id,
                target_executor_agent_id=executor_agent_id,
                target_executor_registry_owner_id=(registry_owner_id),
                target_executor_session_generation=(session_generation),
                target_executor_worker_id="worker-a",
                occurred_at=now + timedelta(minutes=1),
            )
            assert completed.disposition == "completed"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            cutover = await session.get(
                ScheduleOwnerCutover,
                operation_id,
            )
            assert schedule is not None
            assert cutover is not None
            target_stream = await session.get(
                ScheduleExternalStream,
                cutover.target_stream_id,
            )
            assert target_stream is not None
            assert schedule.scheduler == target_owner
            assert schedule.control_token != original_token
            assert schedule.schedule_revision > original_revision
            assert schedule.next_run_at is None
            assert schedule.external_stream_id == target_stream.id
            assert schedule.external_source_sequence == 0
            assert target_stream.phase == "ACTIVATING"
            assert target_stream.accepted_sequence == 0
            assert target_stream.activation_requirement == (f"OWNER_CUTOVER:{operation_id}")
            tombstone = await session.get(
                ScheduleChangeLog,
                schedule.schedule_revision,
            )
            assert tombstone is not None
            assert tombstone.change_kind == "delete"
            cutover_token = schedule.control_token
            cutover_revision = schedule.schedule_revision
            target_stream_id = target_stream.id
            target_epoch_uuid = target_stream.current_epoch_uuid
            target_epoch_number = target_stream.current_epoch_number
            activation_rows = cutover.result_manifest["target_activation_schedules"]

        wrong_rows = [dict(activation_rows[0])]
        wrong_rows[0]["expression"] = "10m"
        wrong_body = external_projection_body(
            stream_id=str(target_stream_id),
            epoch_uuid=str(target_epoch_uuid),
            epoch_number=target_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=target_owner,
            source_scope=target_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=wrong_rows,
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            wrong = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=target_stream_id,
                epoch_uuid=target_epoch_uuid,
                epoch_number=target_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=target_owner,
                source_scope=target_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=wrong_rows,
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(
                    wrong_body,
                ),
                operation_id=None,
                occurred_at=now + timedelta(minutes=2),
            )
            assert wrong.disposition == ("activation_manifest_mismatch")

        activation_body = external_projection_body(
            stream_id=str(target_stream_id),
            epoch_uuid=str(target_epoch_uuid),
            epoch_number=target_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=target_owner,
            source_scope=target_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=activation_rows,
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            activated = await repo.apply_projection(
                project_id=project_id,
                stream_id=target_stream_id,
                epoch_uuid=target_epoch_uuid,
                epoch_number=target_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=target_owner,
                source_scope=target_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=activation_rows,
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(
                    activation_body,
                ),
                operation_id=None,
                occurred_at=now + timedelta(minutes=3),
            )
            assert activated.disposition == "applied"
            replay = await repo.finalize_to_external_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner="z4j-scheduler",
                source_scope=selection_scope,
                to_owner=target_owner,
                target_source_scope=target_scope,
                schedule_ids=(schedule_id,),
                preview_manifest_digest=preview.manifest_digest,
                cursor_policy="PRESERVE",
                quiescence_attestation=attestation,
                target_adapter_instance_id=adapter_instance_id,
                target_executor_agent_id=executor_agent_id,
                target_executor_registry_owner_id=(registry_owner_id),
                target_executor_session_generation=(session_generation),
                target_executor_worker_id="worker-a",
                occurred_at=now + timedelta(minutes=4),
            )
            assert replay.disposition == "exact_replay"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                target_stream_id,
            )
            assert schedule is not None
            assert stream is not None
            assert schedule.control_token == cutover_token
            assert schedule.schedule_revision > cutover_revision
            assert schedule.external_source_sequence == 1
            assert stream.phase == "ACTIVE"
            assert stream.accepted_sequence == 1
            assert stream.activation_requirement is None
    finally:
        await engine.dispose()


async def test_external_to_external_cutover_retires_source_epoch(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    engine = create_async_engine(async_url)
    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    from_owner = "celery-beat"
    to_owner = "apscheduler"
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    target_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    source_adapter = str(uuid.uuid4())
    target_adapter = str(uuid.uuid4())
    target_agent = uuid.uuid4()
    target_registry = uuid.uuid4()
    target_generation = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 6, 0, tzinfo=UTC)
    projected = {
        "source_key": "external-transfer",
        "engine": "celery",
        "scheduler": from_owner,
        "name": "external-transfer",
        "task_name": "jobs.external_transfer",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": "2026-07-26T05:00:00+00:00",
        "next_run_at": None,
        "total_runs": 4,
        "external_id": "external-transfer",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "external-transfer"))
            await session.flush()
            repo = ScheduleExternalRepository(session)
            source_stream = await repo.ensure_activation_epoch(
                project_id=project_id,
                owner=from_owner,
                source_scope=source_scope,
                occurred_at=now,
                adapter_instance_id=source_adapter,
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=str(uuid.uuid4()),
                executor_worker_id="source-worker",
            )
            body = external_projection_body(
                stream_id=str(source_stream.id),
                epoch_uuid=str(
                    source_stream.current_epoch_uuid,
                ),
                epoch_number=source_stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=from_owner,
                source_scope=source_scope,
                adapter_instance_id=source_adapter,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            activated = await repo.apply_projection(
                project_id=project_id,
                stream_id=source_stream.id,
                epoch_uuid=source_stream.current_epoch_uuid,
                epoch_number=source_stream.current_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=from_owner,
                source_scope=source_scope,
                adapter_instance_id=source_adapter,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(body),
                operation_id=None,
                occurred_at=now,
            )
            assert activated.disposition == "applied"
            schedule = (
                await session.execute(
                    select(Schedule).where(
                        Schedule.external_stream_id == source_stream.id,
                    ),
                )
            ).scalar_one()
            schedule_id = schedule.id
            source_stream_id = source_stream.id
            source_epoch_uuid = source_stream.current_epoch_uuid
            source_epoch_number = source_stream.current_epoch_number
            await session.commit()

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            draining = await repo.begin_stream_drain(
                project_id=project_id,
                stream_id=source_stream_id,
                occurred_at=now + timedelta(minutes=1),
            )
            assert draining.disposition == "draining"
            await session.commit()

        final_body = external_projection_body(
            stream_id=str(source_stream_id),
            epoch_uuid=str(source_epoch_uuid),
            epoch_number=source_epoch_number,
            sequence=2,
            kind="snapshot",
            owner=from_owner,
            source_scope=source_scope,
            adapter_instance_id=source_adapter,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        final_digest = external_projection_digest(final_body)
        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            final = await repo.apply_projection(
                project_id=project_id,
                stream_id=source_stream_id,
                epoch_uuid=source_epoch_uuid,
                epoch_number=source_epoch_number,
                sequence=2,
                kind="snapshot",
                owner=from_owner,
                source_scope=source_scope,
                adapter_instance_id=source_adapter,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=final_digest,
                operation_id=None,
                occurred_at=now + timedelta(minutes=2),
            )
            assert final.disposition == "applied"
            sealed = await repo.seal_drained_stream(
                project_id=project_id,
                stream_id=source_stream_id,
                expected_sequence=2,
                expected_snapshot_digest=final_digest,
                occurred_at=now + timedelta(minutes=3),
            )
            assert sealed.disposition == "sealed"
            await session.commit()

        async with database.session(write=True) as session:
            repo = ScheduleExternalRepository(session)
            preview = await repo.preview_to_external_cutover(
                project_id=project_id,
                from_owner=from_owner,
                source_scope=source_scope,
                to_owner=to_owner,
                target_source_scope=target_scope,
                target_adapter_instance_id=target_adapter,
                target_executor_agent_id=target_agent,
                target_executor_registry_owner_id=target_registry,
                target_executor_session_generation=(target_generation),
                target_executor_worker_id="target-worker",
            )
            attestation = {
                "all_old_and_new_scheduler_replicas_quiesced": True,
                "preview_manifest_digest": preview.manifest_digest,
                "source_stream_id": str(source_stream_id),
                "source_epoch_uuid": str(source_epoch_uuid),
                "source_sealed_sequence": 2,
                "source_final_snapshot_digest": final_digest,
            }
            completed = await repo.finalize_to_external_cutover(
                operation_id=operation_id,
                project_id=project_id,
                from_owner=from_owner,
                source_scope=source_scope,
                to_owner=to_owner,
                target_source_scope=target_scope,
                schedule_ids=(),
                preview_manifest_digest=preview.manifest_digest,
                cursor_policy="PRESERVE",
                quiescence_attestation=attestation,
                target_adapter_instance_id=target_adapter,
                target_executor_agent_id=target_agent,
                target_executor_registry_owner_id=target_registry,
                target_executor_session_generation=(target_generation),
                target_executor_worker_id="target-worker",
                occurred_at=now + timedelta(minutes=4),
            )
            assert completed.disposition == "completed"
            await session.commit()

        async with database.session() as session:
            source = await session.get(
                ScheduleExternalStream,
                source_stream_id,
            )
            schedule = await session.get(Schedule, schedule_id)
            cutover = await session.get(
                ScheduleOwnerCutover,
                operation_id,
            )
            assert source is not None
            assert schedule is not None
            assert cutover is not None
            target = await session.get(
                ScheduleExternalStream,
                cutover.target_stream_id,
            )
            assert target is not None
            assert source.phase == "RETIRED"
            assert target.phase == "ACTIVATING"
            assert schedule.scheduler == to_owner
            assert schedule.external_stream_id == target.id
            assert schedule.external_source_key == ("external-transfer")
            assert schedule.external_source_sequence == 0
            target_stream_id = target.id
            target_epoch_uuid = target.current_epoch_uuid
            target_epoch_number = target.current_epoch_number
            activation_rows = cutover.result_manifest["target_activation_schedules"]

        late_body = external_projection_body(
            stream_id=str(source_stream_id),
            epoch_uuid=str(source_epoch_uuid),
            epoch_number=source_epoch_number,
            sequence=3,
            kind="updated",
            owner=from_owner,
            source_scope=source_scope,
            adapter_instance_id=source_adapter,
            schedules=[projected],
            deleted_source_keys=[],
            complete=False,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            late = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=source_stream_id,
                epoch_uuid=source_epoch_uuid,
                epoch_number=source_epoch_number,
                sequence=3,
                kind="updated",
                owner=from_owner,
                source_scope=source_scope,
                adapter_instance_id=source_adapter,
                schedules=[projected],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                payload_digest=external_projection_digest(late_body),
                operation_id=None,
                occurred_at=now + timedelta(minutes=5),
            )
            assert late.disposition == "stream_not_accepting"

        activation_body = external_projection_body(
            stream_id=str(target_stream_id),
            epoch_uuid=str(target_epoch_uuid),
            epoch_number=target_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=to_owner,
            source_scope=target_scope,
            adapter_instance_id=target_adapter,
            schedules=activation_rows,
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        async with database.session(write=True) as session:
            activated = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=target_stream_id,
                epoch_uuid=target_epoch_uuid,
                epoch_number=target_epoch_number,
                sequence=1,
                kind="snapshot",
                owner=to_owner,
                source_scope=target_scope,
                adapter_instance_id=target_adapter,
                schedules=activation_rows,
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(
                    activation_body,
                ),
                operation_id=None,
                occurred_at=now + timedelta(minutes=6),
            )
            assert activated.disposition == "applied"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            target = await session.get(
                ScheduleExternalStream,
                target_stream_id,
            )
            assert schedule is not None
            assert target is not None
            assert schedule.total_runs == 4
            assert schedule.external_source_sequence == 1
            assert target.phase == "ACTIVE"
    finally:
        await engine.dispose()


async def _seed_claimed_external_control(
    database: DatabaseManager,
    *,
    slug: str,
    occurred_at: datetime,
) -> SimpleNamespace:
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    adapter_instance_id = str(uuid.uuid4())
    owner = "arqcron"
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
    projected = {
        "source_key": f"{slug}-source",
        "engine": "arq",
        "scheduler": owner,
        "name": f"{slug}-schedule",
        "task_name": f"jobs.{slug}",
        "kind": "interval",
        "expression": "60",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": None,
        "total_runs": 0,
        "external_id": None,
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    async with database.session(write=True) as session:
        session.add(_project(project_id, slug))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name=f"{slug}-agent",
                token_hash=uuid.uuid4().hex,
                protocol_version="2",
                framework_adapter="bare",
                engine_adapters=["arq"],
                scheduler_adapters=[owner],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.flush()
        stream = await ScheduleExternalRepository(
            session,
        ).ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=occurred_at,
            adapter_instance_id=adapter_instance_id,
            executor_agent_id=agent_id,
            executor_registry_owner_id=registry_owner_id,
            executor_session_generation=session_generation,
        )
        stream_id = stream.id
        epoch_uuid = stream.current_epoch_uuid
        epoch_number = stream.current_epoch_number
        activation = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        applied = await ScheduleExternalRepository(
            session,
        ).apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=external_projection_digest(activation),
            operation_id=None,
            occurred_at=occurred_at,
        )
        assert applied.disposition == "applied"
        schedule = (
            await session.execute(
                select(Schedule).where(
                    Schedule.external_stream_id == stream_id,
                ),
            )
        ).scalar_one()
        plan = await ScheduleExternalRepository(
            session,
        ).plan_control_operation(
            project_id=project_id,
            stream_id=stream_id,
            schedule_id=schedule.id,
            enabled=False,
            issued_by=None,
            source_ip=None,
            timeout_at=occurred_at + timedelta(minutes=5),
        )
        assert plan.disposition == "planned"
        assert plan.operation is not None
        assert plan.command is not None
        operation_id = plan.operation.id
        command_id = plan.command.id
        schedule_id = schedule.id
        await session.commit()

    async with database.session(write=True) as session:
        marked, claimed = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            timeout_seconds=60,
            occurred_at=occurred_at + timedelta(minutes=1),
        )
        assert marked is True
        assert claimed is not None
        claim_token = claimed.delivery_claim_token
        assert claim_token is not None
        await session.commit()
    return SimpleNamespace(
        project_id=project_id,
        agent_id=agent_id,
        registry_owner_id=registry_owner_id,
        session_generation=session_generation,
        adapter_instance_id=adapter_instance_id,
        owner=owner,
        source_scope=source_scope,
        stream_id=stream_id,
        epoch_uuid=epoch_uuid,
        epoch_number=epoch_number,
        schedule_id=schedule_id,
        operation_id=operation_id,
        command_id=command_id,
        claim_token=claim_token,
    )


async def test_external_control_timeout_is_specialized_and_fail_closed(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    base = datetime(2026, 7, 25, 19, 0, tzinfo=UTC)
    try:
        seeded = await _seed_claimed_external_control(
            database,
            slug="control-timeout",
            occurred_at=base,
        )
        async with database.session(write=True) as session:
            ack = await ScheduleExternalRepository(
                session,
            ).acknowledge_control_delivery(
                command_id=seeded.command_id,
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                transport_kind="websocket",
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                delivery_claim_token=str(seeded.claim_token),
                occurred_at=base + timedelta(minutes=1, seconds=1),
            )
            assert ack.disposition == "acknowledged"
            await session.commit()

        expired_at = base + timedelta(minutes=3)
        async with database.session(write=True) as session:
            generic = await CommandRepository(session).sweep_timeouts(
                now=expired_at,
            )
            assert generic == 0
            command_row = await session.get(Command, seeded.command_id)
            assert command_row is not None
            assert command_row.status == CommandStatus.DISPATCHED
            await session.commit()

        async with database.session(write=True) as session:
            receipt = await ScheduleExternalRepository(
                session,
            ).apply_control_result(
                command_id=seeded.command_id,
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                status="success",
                result_payload={"accepted": True},
                error=None,
                transport_kind="websocket",
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                delivery_claim_token=str(seeded.claim_token),
                occurred_at=expired_at,
            )
            assert receipt.disposition == "result_recorded"
            schedule = await session.get(Schedule, seeded.schedule_id)
            operation = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            assert schedule is not None
            assert operation is not None
            assert schedule.is_enabled is True
            assert operation.status == "CLAIMED"
            await session.commit()

        async with database.session(write=True) as session:
            terminal = await ScheduleExternalRepository(
                session,
            ).expire_claimed_control(
                command_id=seeded.command_id,
                occurred_at=expired_at + timedelta(seconds=1),
            )
            assert terminal.disposition == "ambiguous"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, seeded.schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                seeded.stream_id,
            )
            operation = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            command_row = await session.get(Command, seeded.command_id)
            assert schedule is not None
            assert stream is not None
            assert operation is not None
            assert command_row is not None
            assert schedule.is_enabled is True
            assert stream.phase == "AMBIGUOUS"
            assert operation.status == "AMBIGUOUS"
            assert command_row.status == CommandStatus.COMPLETED
    finally:
        await async_engine.dispose()


async def test_external_control_agent_timeout_status_is_rejected_without_mutation(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    base = datetime(2026, 7, 25, 19, 30, tzinfo=UTC)
    try:
        seeded = await _seed_claimed_external_control(
            database,
            slug="control-agent-timeout",
            occurred_at=base,
        )
        async with database.session(write=True) as session:
            receipt = await ScheduleExternalRepository(
                session,
            ).apply_control_result(
                command_id=seeded.command_id,
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                status="timeout",
                result_payload={"adapter_timeout": True},
                error="adapter deadline elapsed",
                transport_kind="websocket",
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                delivery_claim_token=str(seeded.claim_token),
                occurred_at=base + timedelta(minutes=1, seconds=1),
            )
            assert receipt.disposition == "invalid_status"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, seeded.schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                seeded.stream_id,
            )
            operation = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            command_row = await session.get(Command, seeded.command_id)
            assert schedule is not None
            assert stream is not None
            assert operation is not None
            assert command_row is not None
            assert schedule.is_enabled is True
            assert stream.phase == "ACTIVE"
            assert operation.status == "CLAIMED"
            assert command_row.status == CommandStatus.DISPATCHED
            assert command_row.result is None
            assert command_row.error is None
    finally:
        await async_engine.dispose()


async def test_external_control_failure_result_ambiguates_without_truth_change(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    base = datetime(2026, 7, 25, 20, 0, tzinfo=UTC)
    try:
        seeded = await _seed_claimed_external_control(
            database,
            slug="control-failure",
            occurred_at=base,
        )
        async with database.session(write=True) as session:
            receipt = await ScheduleExternalRepository(
                session,
            ).apply_control_result(
                command_id=seeded.command_id,
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                status="failed",
                result_payload=None,
                error="adapter refused",
                transport_kind="websocket",
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                delivery_claim_token=str(seeded.claim_token),
                occurred_at=base + timedelta(minutes=1, seconds=1),
            )
            assert receipt.disposition == "ambiguous"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, seeded.schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                seeded.stream_id,
            )
            operation = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            command_row = await session.get(Command, seeded.command_id)
            assert schedule is not None
            assert stream is not None
            assert operation is not None
            assert command_row is not None
            assert schedule.is_enabled is True
            assert stream.phase == "AMBIGUOUS"
            assert operation.status == "AMBIGUOUS"
            assert command_row.status == CommandStatus.FAILED
    finally:
        await async_engine.dispose()


async def test_external_control_exact_executor_loss_ambiguates(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    base = datetime(2026, 7, 25, 21, 0, tzinfo=UTC)
    try:
        seeded = await _seed_claimed_external_control(
            database,
            slug="control-disconnect",
            occurred_at=base,
        )
        async with database.session(write=True) as session:
            changed = await ScheduleExternalRepository(
                session,
            ).mark_claimed_controls_for_executor_loss(
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                occurred_at=base + timedelta(minutes=1, seconds=1),
            )
            assert changed == [seeded.operation_id]
            await session.commit()

        async with database.session(write=True) as session:
            late = await ScheduleExternalRepository(
                session,
            ).apply_control_result(
                command_id=seeded.command_id,
                project_id=seeded.project_id,
                agent_id=seeded.agent_id,
                status="success",
                result_payload={"late": True},
                error=None,
                transport_kind="websocket",
                registry_owner_id=seeded.registry_owner_id,
                session_generation=seeded.session_generation,
                delivery_claim_token=str(seeded.claim_token),
                occurred_at=base + timedelta(minutes=2),
            )
            assert late.disposition == "replay"
            await session.commit()

        async with database.session() as session:
            schedule = await session.get(Schedule, seeded.schedule_id)
            stream = await session.get(
                ScheduleExternalStream,
                seeded.stream_id,
            )
            operation = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            command_row = await session.get(Command, seeded.command_id)
            assert schedule is not None
            assert stream is not None
            assert operation is not None
            assert command_row is not None
            assert schedule.is_enabled is True
            assert stream.phase == "AMBIGUOUS"
            assert operation.status == "AMBIGUOUS"
            assert command_row.status == CommandStatus.FAILED
    finally:
        await async_engine.dispose()


async def test_external_control_api_returns_project_bound_location(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    base = datetime(2026, 7, 25, 22, 0, tzinfo=UTC)
    try:
        seeded = await _seed_claimed_external_control(
            database,
            slug="api-control",
            occurred_at=base,
        )
        async with database.session(write=True) as session:
            first = await session.get(
                ScheduleExternalControlOperation,
                seeded.operation_id,
            )
            assert first is not None
            desired = first.desired_projection
            body = external_projection_body(
                stream_id=str(seeded.stream_id),
                epoch_uuid=str(seeded.epoch_uuid),
                epoch_number=seeded.epoch_number,
                sequence=2,
                kind="control",
                owner=seeded.owner,
                source_scope=seeded.source_scope,
                adapter_instance_id=seeded.adapter_instance_id,
                schedules=[desired],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                operation_id=str(seeded.operation_id),
            )
            applied = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=seeded.project_id,
                stream_id=seeded.stream_id,
                epoch_uuid=seeded.epoch_uuid,
                epoch_number=seeded.epoch_number,
                sequence=2,
                kind="control",
                owner=seeded.owner,
                source_scope=seeded.source_scope,
                adapter_instance_id=seeded.adapter_instance_id,
                schedules=[desired],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                payload_digest=external_projection_digest(body),
                operation_id=seeded.operation_id,
                occurred_at=base + timedelta(minutes=2),
            )
            assert applied.disposition == "applied"
            await session.commit()

        user_id = uuid.uuid4()
        session_id = uuid.uuid4()
        csrf = uuid.uuid4().hex
        async with database.session(write=True) as session:
            session.add(
                User(
                    id=user_id,
                    email=f"api-{user_id.hex[:8]}@example.com",
                    password_hash="not-used-by-session-auth",
                    is_admin=True,
                    is_active=True,
                ),
            )
            session.add(
                Project(
                    id=uuid.uuid4(),
                    slug="other-control-project",
                    name="Other control project",
                ),
            )
            await session.flush()
            session.add(
                UserSession(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="boundary-d-test",
                ),
            )
            await session.commit()

        from httpx import ASGITransport, AsyncClient
        from z4j_brain.auth.csrf import csrf_cookie_name
        from z4j_brain.auth.sessions import (
            SessionCookieCodec,
            cookie_name,
        )
        from z4j_brain.main import create_app

        settings = Settings()  # type: ignore[call-arg]
        app = create_app(settings, engine=async_engine)
        client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
            headers={"X-CSRF-Token": csrf},
        )
        codec = SessionCookieCodec(settings)
        client.cookies.set(
            cookie_name(environment=settings.environment),
            codec.encode(session_id),
        )
        client.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            csrf,
        )
        async with client:
            response = await client.post(
                f"/api/v1/projects/api-control/schedules/{seeded.schedule_id}/enable",
            )
            assert response.status_code == 202, response.text
            location = response.headers.get("Location")
            assert location is not None
            assert location.startswith(
                "/api/v1/projects/api-control/schedules/external-control-operations/",
            )
            operation_response = await client.get(location)
            assert operation_response.status_code == 200
            operation_body = operation_response.json()
            assert operation_body["status"] == "PENDING"
            assert operation_body["schedule_id"] == str(
                seeded.schedule_id,
            )
            assert operation_body["desired_is_enabled"] is True

            wrong_project = await client.get(
                location.replace(
                    "/projects/api-control/",
                    "/projects/other-control-project/",
                ),
            )
            assert wrong_project.status_code == 404
    finally:
        await async_engine.dispose()


async def test_external_control_changes_truth_only_on_allowed_observed_projection(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, async_url = boundary_d_install
    await asyncio.to_thread(command.upgrade, config, "head")
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    adapter_instance_id = str(uuid.uuid4())
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
    projected = {
        "source_key": "nightly",
        "engine": "arq",
        "scheduler": "arqcron",
        "name": "nightly",
        "task_name": "jobs.nightly",
        "kind": "interval",
        "expression": "60",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": "2026-07-25T18:30:00+00:00",
        "total_runs": 0,
        "external_id": None,
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    async_engine = create_async_engine(async_url)
    database = DatabaseManager(async_engine)
    try:
        async with database.session(write=True) as session:
            session.add(_project(project_id, "external-control"))
            await session.flush()
            session.add(
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="cron-control",
                    token_hash=uuid.uuid4().hex,
                    protocol_version="2",
                    framework_adapter="bare",
                    engine_adapters=["arq"],
                    scheduler_adapters=["arqcron"],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
            )
            await session.flush()
            stream = await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="arqcron",
                source_scope=source_scope,
                occurred_at=datetime(2026, 7, 25, 18, 0, tzinfo=UTC),
                adapter_instance_id=adapter_instance_id,
                executor_agent_id=agent_id,
                executor_registry_owner_id=registry_owner_id,
                executor_session_generation=session_generation,
            )
            stream_id = stream.id
            epoch_uuid = stream.current_epoch_uuid
            epoch_number = stream.current_epoch_number
            activation = external_projection_body(
                stream_id=str(stream_id),
                epoch_uuid=str(epoch_uuid),
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="arqcron",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
            )
            applied = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                kind="snapshot",
                owner="arqcron",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[projected],
                deleted_source_keys=[],
                complete=True,
                stable_source=True,
                payload_digest=external_projection_digest(activation),
                operation_id=None,
                occurred_at=datetime(2026, 7, 25, 18, 0, tzinfo=UTC),
            )
            assert applied.disposition == "applied"
            schedule = (
                await session.execute(
                    select(Schedule).where(
                        Schedule.external_stream_id == stream_id,
                    ),
                )
            ).scalar_one()
            schedule_id = schedule.id
            original_token = schedule.control_token
            original_revision = schedule.schedule_revision
            plan = await ScheduleExternalRepository(
                session,
            ).plan_control_operation(
                project_id=project_id,
                stream_id=stream_id,
                schedule_id=schedule_id,
                enabled=False,
                issued_by=None,
                source_ip=None,
                timeout_at=datetime(2026, 7, 25, 18, 5, tzinfo=UTC),
            )
            assert plan.disposition == "planned"
            assert plan.operation is not None
            assert plan.command is not None
            operation_id = plan.operation.id
            command_id = plan.command.id
            assert schedule.is_enabled is True
            opposite = await ScheduleExternalRepository(
                session,
            ).plan_control_operation(
                project_id=project_id,
                stream_id=stream_id,
                schedule_id=schedule_id,
                enabled=True,
                issued_by=None,
                source_ip=None,
                timeout_at=datetime(2026, 7, 25, 18, 5, tzinfo=UTC),
            )
            assert opposite.disposition == "operation_conflict"
            assert opposite.operation is plan.operation
            await session.commit()

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO schedule_external_control_operations "
                        "SELECT * FROM schedule_external_control_operations "
                        "WHERE id = :operation_id",
                    ),
                    {"operation_id": operation_id.hex},
                )

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE schedule_external_control_operations "
                        "SET status = 'CLAIMED', "
                        "dispatch_lease = :dispatch_lease, "
                        "reserved_sequence = expected_accepted_sequence + 1 "
                        "WHERE id = :operation_id",
                    ),
                    {
                        "dispatch_lease": uuid.uuid4().hex,
                        "operation_id": operation_id.hex,
                    },
                )

        async with database.session(write=True) as session:
            command_row = await session.get(Command, command_id)
            assert command_row is not None
            corrupted_payload = dict(command_row.payload)
            corrupted_payload["session_generation"] = str(uuid.uuid4())
            command_row.payload = corrupted_payload
            await session.flush()
            marked, corrupted = await CommandRepository(
                session,
            ).claim_current_schedule_delivery(
                command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind="websocket",
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                timeout_seconds=60,
                occurred_at=datetime(
                    2026,
                    7,
                    25,
                    18,
                    1,
                    tzinfo=UTC,
                ),
            )
            assert marked is True
            assert corrupted is None
            await session.rollback()

        async with database.session(write=True) as session:
            marked, wrong = await CommandRepository(
                session,
            ).claim_current_schedule_delivery(
                command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind="websocket",
                registry_owner_id=registry_owner_id,
                session_generation=str(uuid.uuid4()),
                timeout_seconds=60,
                occurred_at=datetime(2026, 7, 25, 18, 1, tzinfo=UTC),
            )
            assert marked is True
            assert wrong is None
            await session.rollback()

        async with database.session(write=True) as session:
            marked, claimed = await CommandRepository(
                session,
            ).claim_current_schedule_delivery(
                command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind="websocket",
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                timeout_seconds=60,
                occurred_at=datetime(2026, 7, 25, 18, 1, tzinfo=UTC),
            )
            assert marked is True
            assert claimed is not None
            operation = await session.get(
                ScheduleExternalControlOperation,
                operation_id,
            )
            assert operation is not None
            assert operation.status == "CLAIMED"
            assert operation.dispatch_lease == claimed.delivery_claim_token
            assert operation.reserved_sequence == 2
            schedule = await session.get(Schedule, schedule_id)
            assert schedule is not None
            assert schedule.is_enabled is True
            await session.commit()

        with pytest.raises(
            OperationalError,
            match="user-defined function raised exception",
        ):
            async with async_engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE schedule_external_control_operations "
                        "SET status = 'APPLIED', "
                        "result_projection_id = :projection_id "
                        "WHERE id = :operation_id",
                    ),
                    {
                        "projection_id": uuid.uuid4().hex,
                        "operation_id": operation_id.hex,
                    },
                )

        async with database.session(write=True) as session:
            operation = await session.get(
                ScheduleExternalControlOperation,
                operation_id,
            )
            assert operation is not None
            desired = operation.desired_projection
            observed = dict(desired)
            observed["next_run_at"] = None
            control_body = external_projection_body(
                stream_id=str(stream_id),
                epoch_uuid=str(epoch_uuid),
                epoch_number=epoch_number,
                sequence=2,
                kind="control",
                owner="arqcron",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[observed],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                operation_id=str(operation_id),
            )
            result = await ScheduleExternalRepository(
                session,
            ).apply_projection(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=2,
                kind="control",
                owner="arqcron",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                schedules=[observed],
                deleted_source_keys=[],
                complete=False,
                stable_source=True,
                payload_digest=external_projection_digest(
                    control_body,
                ),
                operation_id=operation_id,
                occurred_at=datetime(2026, 7, 25, 18, 2, tzinfo=UTC),
            )
            assert result.disposition == "applied"
            await session.commit()

        async with database.session() as session:
            operation = await session.get(
                ScheduleExternalControlOperation,
                operation_id,
            )
            schedule = await session.get(Schedule, schedule_id)
            stream = await session.get(ScheduleExternalStream, stream_id)
            assert operation is not None
            assert schedule is not None
            assert stream is not None
            assert operation.status == "APPLIED"
            assert operation.result_projection_id is not None
            assert schedule.is_enabled is False
            assert schedule.next_run_at is None
            assert schedule.control_token != original_token
            assert schedule.schedule_revision > original_revision
            assert stream.accepted_sequence == 2
    finally:
        await async_engine.dispose()


def test_boundary_d_downgrade_refuses(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, _, _ = boundary_d_install
    command.upgrade(config, "head")
    with pytest.raises(Exception, match="refusing downgrade below Boundary D"):
        command.downgrade(config, "v1_8_audit_chain_activate")


def test_catalog_contains_no_mutating_cadence_foreign_keys(
    boundary_d_install: tuple[Config, str, str],
) -> None:
    config, sync_url, _ = boundary_d_install
    command.upgrade(config, "head")
    engine = create_engine(sync_url)
    try:
        inspector = inspect(engine)
        command_foreign_keys = {
            tuple(item["constrained_columns"]) for item in inspector.get_foreign_keys("commands")
        }
        fire_foreign_keys = {
            tuple(item["constrained_columns"])
            for item in inspector.get_foreign_keys("schedule_fires")
        }
        assert ("project_id",) not in command_foreign_keys
        assert ("agent_id",) not in command_foreign_keys
        assert ("schedule_id",) not in fire_foreign_keys
        assert ("project_id",) not in fire_foreign_keys
        assert ("command_id",) not in fire_foreign_keys
    finally:
        engine.dispose()
