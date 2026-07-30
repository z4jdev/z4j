"""Real-PostgreSQL Boundary-D activation and old-writer gates."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, null, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from z4j_brain import management_restore_postgres as postgres_restore_module
from z4j_brain.backup import (
    backup_postgres,
    restore_postgres,
    rollback_restore,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.management_restore import (
    DatabaseRestorePending,
    authenticated_database_snapshot,
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
    Project,
    Schedule,
    ScheduleChangeLog,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleOwnerCutover,
    ScheduleRevisionState,
)
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
)
from z4j_brain.persistence.repositories import (
    schedule_external as schedule_external_repository_module,
)
from z4j_brain.persistence.repositories.commands import CommandRepository
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
from z4j_brain.settings import Settings
from z4j_core.schedule_external import (
    external_projection_body,
    external_projection_digest,
    external_snapshot_frame_body,
    external_snapshot_frame_digest,
)

pytestmark = pytest.mark.asyncio


async def test_real_pg_restore_hold_reactivates_above_barrier(
    migrated_engine: AsyncEngine,
) -> None:
    """A restored stream retains data until a fresh stable epoch activates."""

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    owner = "arqcron"
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'
    old_adapter_instance_id = "pg-restored-adapter"
    projected = {
        "source_key": "pg-restored-nightly",
        "engine": "arq",
        "scheduler": owner,
        "name": "pg-restored-nightly",
        "task_name": "jobs.pg_restored_nightly",
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
        "external_id": "pg-restored-nightly",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    now = datetime(2026, 7, 25, 17, 0, tzinfo=UTC)
    async with database.session(write=True) as session:
        session.add(Project(id=project_id, slug="pg-restore-reactivation", name="PG Restore"))
        await session.flush()
        repo = ScheduleExternalRepository(session)
        stream = await repo.ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=now,
            adapter_instance_id=old_adapter_instance_id,
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
            executor_worker_id="pg-restored-worker",
        )
        stream_id = stream.id
        old_epoch_uuid = stream.current_epoch_uuid
        old_epoch_number = stream.current_epoch_number
        activation = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(old_epoch_uuid),
            epoch_number=old_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=old_adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
        )
        activation_digest = external_projection_digest(activation)
        applied = await repo.apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=old_epoch_uuid,
            epoch_number=old_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=old_adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=activation_digest,
            operation_id=None,
            occurred_at=now + timedelta(seconds=30),
        )
        assert applied.disposition == "applied"
        await arm_external_lifecycle_transition(
            session,
            transition="restore_hold",
            operation_id=uuid.uuid4(),
            stream_id=stream_id,
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
                ScheduleExternalStream.id == stream_id,
                ScheduleExternalStream.phase == "ACTIVE",
            )
            .values(phase="RESTORE_REACTIVATION_REQUIRED"),
        )
        assert epoch_updated.rowcount == 1
        assert stream_updated.rowcount == 1
        await assert_external_lifecycle_consumed(session)
        await session.commit()

    async with database.session(write=True) as session:
        repo = ScheduleExternalRepository(session)
        new_adapter_instance_id = "pg-reactivated-adapter"
        reactivated = await repo.ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=now + timedelta(minutes=1),
            adapter_instance_id=new_adapter_instance_id,
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
            executor_worker_id="pg-reactivated-worker",
            reactivate_restored=True,
        )
        new_epoch_uuid = reactivated.current_epoch_uuid
        new_epoch_number = reactivated.current_epoch_number
        assert new_epoch_uuid != old_epoch_uuid
        assert new_epoch_number > old_epoch_number
        retained = (
            await session.execute(
                select(Schedule).where(
                    Schedule.external_stream_id == stream_id,
                ),
            )
        ).scalar_one()
        assert retained.external_epoch_uuid == old_epoch_uuid
        await session.commit()

    stable_snapshot = external_projection_body(
        stream_id=str(stream_id),
        epoch_uuid=str(new_epoch_uuid),
        epoch_number=new_epoch_number,
        sequence=1,
        kind="snapshot",
        owner=owner,
        source_scope=source_scope,
        adapter_instance_id=new_adapter_instance_id,
        schedules=[projected],
        deleted_source_keys=[],
        complete=True,
        stable_source=True,
    )
    stable_snapshot_digest = external_projection_digest(stable_snapshot)
    async with database.session(write=True) as session:
        activated = await ScheduleExternalRepository(
            session,
        ).apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=new_epoch_uuid,
            epoch_number=new_epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=new_adapter_instance_id,
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=stable_snapshot_digest,
            operation_id=None,
            occurred_at=now + timedelta(minutes=2),
        )
        assert activated.disposition == "applied"
        await session.commit()

    async with database.session() as session:
        stream = await session.get(ScheduleExternalStream, stream_id)
        epochs = list(
            (
                await session.execute(
                    select(ScheduleExternalStreamEpoch)
                    .where(
                        ScheduleExternalStreamEpoch.stream_id == stream_id,
                    )
                    .order_by(
                        ScheduleExternalStreamEpoch.epoch_number,
                    ),
                )
            ).scalars(),
        )
        schedule = (
            await session.execute(
                select(Schedule).where(
                    Schedule.external_stream_id == stream_id,
                ),
            )
        ).scalar_one()
        assert stream is not None
        assert stream.phase == "ACTIVE"
        assert [epoch.phase for epoch in epochs] == [
            "RESTORE_REACTIVATION_REQUIRED",
            "ACTIVE",
        ]
        assert schedule.external_epoch_uuid == new_epoch_uuid
        assert schedule.external_epoch_number == new_epoch_number


async def test_never_claimed_activation_retires_before_epoch_replacement(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    first_generation = str(uuid.uuid4())
    second_generation = str(uuid.uuid4())
    owner = "arqcron"
    source_scope = '{"kind":"scheduler-owner","owner":"arqcron","version":1}'

    async with database.session(write=True) as session:
        session.add(Project(id=project_id, slug="activation-replace-pg", name="Activation"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="arqcron",
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
        stream = await ScheduleExternalRepository(session).ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=datetime.now(UTC),
            adapter_instance_id="adapter-first",
            executor_agent_id=agent_id,
            executor_registry_owner_id=registry_owner_id,
            executor_session_generation=first_generation,
            executor_worker_id="scheduler-1",
        )
        payload = {
            "scheduler": owner,
            "owner": owner,
            "source_scope": source_scope,
            "stream_id": str(stream.id),
            "epoch_uuid": str(stream.current_epoch_uuid),
            "epoch_number": stream.current_epoch_number,
            "adapter_instance_id": "adapter-first",
            "stable_source": True,
            "registry_owner_id": str(registry_owner_id),
            "session_generation": first_generation,
        }
        command_row, created = await CommandRepository(session).insert(
            project_id=project_id,
            agent_id=agent_id,
            issued_by=None,
            action="schedule.external.activate",
            target_type="scheduler",
            target_id=owner,
            payload=payload,
            idempotency_key=(f"external-activation:{stream.current_epoch_uuid}:adapter-first"),
            timeout_at=datetime.now(UTC) + timedelta(minutes=1),
            source_ip=None,
            enforce_payload_identity=True,
        )
        assert created
        old_epoch_uuid = stream.current_epoch_uuid
        command_id = command_row.id
        stream_id = stream.id
        await session.commit()

    async with database.session(write=True) as session:
        external = ScheduleExternalRepository(session)
        assert await external.abandon_undelivered_activation(
            project_id=project_id,
            stream_id=stream_id,
            occurred_at=datetime.now(UTC),
        )
        replacement = await external.ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=datetime.now(UTC),
            adapter_instance_id="adapter-second",
            executor_agent_id=agent_id,
            executor_registry_owner_id=registry_owner_id,
            executor_session_generation=second_generation,
            executor_worker_id="scheduler-1",
            replace_retired=True,
        )
        assert replacement.current_epoch_uuid != old_epoch_uuid
        await session.commit()

    async with database.session() as session:
        old_command = await session.get(Command, command_id)
        old_epoch = await session.get(ScheduleExternalStreamEpoch, old_epoch_uuid)
        stream = await session.get(ScheduleExternalStream, stream_id)
        assert old_command is not None
        assert old_epoch is not None
        assert stream is not None
        assert old_command.status == CommandStatus.CANCELLED
        assert old_epoch.phase == "RETIRED"
        assert stream.phase == "ACTIVATING"
        assert stream.executor_session_generation == second_generation


async def test_committed_restore_recovery_authenticates_marker_generation(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """A shallowly matching marker from a tampered chain cannot clear a fence."""
    operation_id = uuid.uuid4()
    source_digest = "1" * 64
    database = DatabaseManager(migrated_engine)
    async with database.session(write=True) as session:
        marker = await AuditService(integration_settings).record(
            AuditLogRepository(session),
            action="audit.database_restored",
            target_type="database",
            target_id=str(operation_id),
            result="success",
            outcome="allow",
            metadata={
                "operation_id": str(operation_id),
                "source_stage_digest": source_digest,
                "migration_head": (postgres_restore_module.RELEASE_MIGRATION_HEAD),
                "known_head_result": "current",
                "revision_rebase": {},
                "epoch_rebase": {},
                "schema_contract_digest": "2" * 64,
            },
        )
        await session.commit()
        marker_id = str(marker.id)

    async with migrated_engine.begin() as connection:
        await connection.execute(
            text("ALTER TABLE audit_log DISABLE TRIGGER USER"),
        )
        await connection.execute(
            text(
                "UPDATE audit_log SET row_hmac = :forged WHERE id = CAST(:marker_id AS uuid)",
            ),
            {
                "forged": "0" * 64,
                "marker_id": marker_id,
            },
        )
        await connection.execute(
            text("ALTER TABLE audit_log ENABLE TRIGGER USER"),
        )

    target = postgres_restore_module._parse_target(
        integration_settings.database_url,
    )
    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="audit state is not clean",
    ):
        await postgres_restore_module._recover_committed_finalization(
            target,
            marker_id=marker_id,
            operation_id=operation_id,
            source_digest=source_digest,
            settings=integration_settings,
        )


async def test_authenticated_snapshot_is_timezone_invariant(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """Catalog partition bounds digest identically across session zones."""

    async with migrated_engine.connect() as connection:
        await connection.execute(
            text("SET TIME ZONE 'America/New_York'"),
        )
        new_york = await authenticated_database_snapshot(
            integration_settings.database_url,
            integration_settings,
            connection=connection,
        )
        await connection.rollback()

    async with migrated_engine.connect() as connection:
        await connection.execute(text("SET TIME ZONE 'UTC'"))
        utc = await authenticated_database_snapshot(
            integration_settings.database_url,
            integration_settings,
            connection=connection,
        )
        await connection.rollback()

    assert new_york["manifest_digest"] == utc["manifest_digest"]
    assert new_york["schema_contract_digest"] == utc["schema_contract_digest"]


async def test_postgres_restore_process_coordinator_serializes_same_target(
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two local restore commands cannot mutate one target concurrently."""

    private_home = tmp_path / "coordinator-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    entered = 0
    maximum_entered = 0
    state_lock = threading.Lock()
    first_entered = threading.Event()
    release = threading.Event()

    async def controlled_restore(
        database_url: str,
        source: Path,
        **kwargs: object,
    ) -> dict[str, object]:
        del database_url, source, kwargs
        nonlocal entered, maximum_entered
        with state_lock:
            entered += 1
            maximum_entered = max(maximum_entered, entered)
            first_entered.set()
        await asyncio.to_thread(release.wait)
        with state_lock:
            entered -= 1
        return {"serialized": True}

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_restore",
        controlled_restore,
    )
    database_url = integration_settings.database_url
    source = tmp_path / "unused.dump"
    first = asyncio.create_task(
        asyncio.to_thread(
            postgres_restore_module.restore_postgres_database,
            database_url,
            source,
        ),
    )
    assert await asyncio.to_thread(first_entered.wait, 5)
    second = asyncio.create_task(
        asyncio.to_thread(
            postgres_restore_module.restore_postgres_database,
            database_url,
            source,
        ),
    )
    await asyncio.sleep(0.2)
    observed_maximum = maximum_entered
    release.set()
    assert await asyncio.gather(first, second) == [
        {"serialized": True},
        {"serialized": True},
    ]
    assert observed_maximum == 1
    assert maximum_entered == 1


async def test_real_pg_backup_uses_sanitized_identity_bound_runner(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-only backup inherits no ambient libpq or loader authority."""

    del migrated_engine
    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None:
        pytest.skip("PostgreSQL client tools are unavailable")
    private_home = tmp_path / "backup-runner-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv("PGOPTIONS", "-c search_path=attacker")
    monkeypatch.setenv("PGSERVICE", "attacker-service")
    monkeypatch.setenv("LD_PRELOAD", "/attacker/library.so")
    original_runner = postgres_restore_module._run_identity_bound
    observed: list[tuple[list[str], dict[str, str], str]] = []

    def observe_runner(
        tool: object,
        arguments: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[object]:
        if getattr(tool, "name", None) == "pg_dump":
            observed.append(
                (
                    list(arguments),
                    dict(kwargs["environment"]),  # type: ignore[arg-type]
                    str(tool.path),  # type: ignore[attr-defined]
                ),
            )
        return original_runner(  # type: ignore[return-value]
            tool,  # type: ignore[arg-type]
            arguments,
            **kwargs,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        observe_runner,
    )
    output = tmp_path / "sanitized.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        output,
    )
    assert output.is_file()
    assert len(observed) == 1
    arguments, environment, executable = observed[0]
    assert Path(executable).is_absolute()
    assert "--dbname" in arguments
    assert integration_settings.database_url not in arguments
    assert "PGOPTIONS" not in environment
    assert "PGSERVICE" not in environment
    assert "LD_PRELOAD" not in environment
    assert set(environment) <= {
        "LANG",
        "LC_ALL",
        "TZ",
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGDATABASE",
        "PGUSER",
        "PGSSLMODE",
        "PGCONNECT_TIMEOUT",
        "PGPASSFILE",
        "PGSSLROOTCERT",
        "PGSSLCERT",
        "PGSSLKEY",
    }


async def test_real_pg_catalog_restore_fence_blocks_service_and_alembic(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The database catalog wins even if an effective GUC is shadowed."""

    database_name = make_url(
        integration_settings.database_url,
    ).database
    assert database_name is not None
    envelope = json.dumps(
        {
            "operation_id": str(uuid.uuid4()),
            "source_digest": "1" * 64,
            "state": "TARGET_CLEARED",
            "target_identity_digest": "2" * 64,
            "toc_digest": "3" * 64,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    quoted_database = database_name.replace('"', '""')
    quoted_envelope = envelope.replace("'", "''")
    async with migrated_engine.begin() as connection:
        await connection.exec_driver_sql(
            f"ALTER DATABASE \"{quoted_database}\" SET z4j.restore_pending = '{quoted_envelope}'",
        )
    await migrated_engine.dispose()

    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
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
    monkeypatch.setenv("PGOPTIONS", "-c z4j.restore_pending=")

    service_engine = create_engine_from_settings(
        integration_settings,
    )
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240
    alembic_config = Config(str(backend_root / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    try:
        with pytest.raises(
            DatabaseRestorePending,
            match="database restore is unfinished",
        ):
            async with service_engine.connect():
                pytest.fail("fenced service connection was admitted")
        with pytest.raises(
            DatabaseRestorePending,
            match="database restore is unfinished",
        ):
            await asyncio.to_thread(
                command.upgrade,
                alembic_config,
                "head",
            )
    finally:
        await service_engine.dispose()
        cleanup_engine = create_async_engine(
            integration_settings.database_url,
        )
        try:
            async with cleanup_engine.begin() as connection:
                await connection.exec_driver_sql(
                    f'ALTER DATABASE "{quoted_database}" RESET z4j.restore_pending',
                )
        finally:
            await cleanup_engine.dispose()


async def test_real_pg_restore_rebases_above_target_and_signs_marker(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The durable PG ceremony must not resurrect an old revision namespace."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")

    private_home = tmp_path / "restore-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
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
    monkeypatch.setenv("Z4J_HOME", str(private_home))

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"restore-{project_id.hex[:12]}",
                name="PG restore",
            ),
        )
        await session.flush()
        source_schedule = await ScheduleControlRepository(
            session,
        ).create_current(
            project_id=project_id,
            data=_definition(),
            planning_at=datetime(2026, 7, 25, 12, 0, tzinfo=UTC),
        )
        schedule_id = source_schedule.id
        await session.commit()
    async with database.session() as session:
        audit_state = await session.get(AuditChainState, "audit-chain")
        assert audit_state is not None
        known_head = {
            "row_hmac": audit_state.head_row_hmac,
            "hmac_version": 2,
            "hmac_key_id": audit_state.head_hmac_key_id,
            "generation": str(audit_state.generation),
            "occurred_at": audit_state.head_occurred_at.isoformat(),
            "id": str(audit_state.head_id),
        }

    archive = tmp_path / "source.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )

    async with database.session(write=True) as session:
        changed = await ScheduleControlRepository(
            session,
        ).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"name": "target-newer-name"},
            planning_at=datetime(2026, 7, 25, 13, 0, tzinfo=UTC),
        )
        assert changed is not None
        target_revision = int(changed.schedule_revision or 0)
        await session.commit()

    await migrated_engine.dispose()
    expected_source_digest = postgres_restore_module._file_digest(archive)[1]
    result = await asyncio.to_thread(
        restore_postgres,
        integration_settings.database_url,
        archive,
        expected_sha256=expected_source_digest,
        known_head=known_head,
    )
    assert result["known_head_result"] == "CURRENT_MATCH"

    engine = create_async_engine(integration_settings.database_url)
    verify_database = DatabaseManager(engine)
    try:
        async with verify_database.session() as session:
            restored = await session.get(Schedule, schedule_id)
            state = await session.get(
                ScheduleRevisionState,
                "schedule-revision",
            )
            allocator = await session.get(
                ScheduleExternalEpochAllocator,
                "schedule-external-epoch",
            )
            assert restored is not None
            assert state is not None
            assert allocator is not None
            assert restored.name == "pg-guarded"
            assert state.change_log_pruned_through > target_revision
            assert restored.schedule_revision > (state.change_log_pruned_through)
            marker = (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.database_restored",
                    ),
                )
            ).scalar_one()
            assert (
                marker.audit_metadata["revision_rebase"]["captured_target_revision"]
                == target_revision
            )
            assert marker.audit_metadata["source_provenance"] == {
                "kind": "operator_expected_sha256",
                "expected_sha256": expected_source_digest,
                "verified_digest": expected_source_digest,
            }
            assert marker.audit_metadata["known_head"] == known_head
            assert marker.audit_metadata["known_head_result"] == "CURRENT_MATCH"
            assert (
                marker.audit_metadata["physical_target"]["database_name"]
                == make_url(integration_settings.database_url).database
            )
    finally:
        await verify_database.dispose()


async def test_real_pg_restore_refuses_altered_executable_before_fence(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-named altered function cannot pass archive preflight."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")
    private_home = tmp_path / "altered-function-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
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

    async with migrated_engine.begin() as connection:
        await connection.exec_driver_sql(
            """
            CREATE OR REPLACE FUNCTION public.z4j_schedules_notify()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
              RETURN COALESCE(NEW, OLD);
            END;
            $$
            """,
        )
    archive = tmp_path / "altered-function.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )
    await migrated_engine.dispose()

    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="executable function definitions",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    target = postgres_restore_module._parse_target(
        integration_settings.database_url,
    )
    assert await postgres_restore_module._read_fence(target) is None


async def test_real_pg_restore_refuses_altered_static_schema_before_fence(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-named altered index cannot pass archive preflight."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")
    private_home = tmp_path / "altered-schema-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
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

    async with migrated_engine.begin() as connection:
        await connection.exec_driver_sql(
            "DROP INDEX public.ix_audit_log_action_occurred",
        )
        await connection.exec_driver_sql(
            "CREATE INDEX ix_audit_log_action_occurred ON public.audit_log (action)",
        )
    archive = tmp_path / "altered-schema.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )
    async with migrated_engine.begin() as connection:
        await connection.exec_driver_sql(
            "DROP INDEX public.ix_audit_log_action_occurred",
        )
        await connection.exec_driver_sql(
            "CREATE INDEX ix_audit_log_action_occurred ON public.audit_log (action, occurred_at)",
        )
    await migrated_engine.dispose()

    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="static schema definitions",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    target = postgres_restore_module._parse_target(
        integration_settings.database_url,
    )
    assert await postgres_restore_module._read_fence(target) is None


async def test_real_pg_legacy_restore_has_bound_activation_continuation(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1.7 archive can activate only through its exact restore phase."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")
    source_database = f"z4j_legacy_restore_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{source_database}"')
    finally:
        await admin.close()
    source_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{source_database}"
    source_async_url = source_url.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    archive = tmp_path / "legacy-source.dump"
    try:
        monkeypatch.setenv("Z4J_DATABASE_URL", source_async_url)
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
        await asyncio.to_thread(
            command.upgrade,
            config,
            "v1_7_security_hardening",
        )
        await asyncio.to_thread(
            backup_postgres,
            source_async_url,
            archive,
        )
    finally:
        admin = await asyncpg.connect(postgres_admin_url)
        try:
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                source_database,
            )
            await admin.execute(
                f'DROP DATABASE IF EXISTS "{source_database}"',
            )
        finally:
            await admin.close()

    private_home = tmp_path / "legacy-restore-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
    await migrated_engine.dispose()
    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="awaiting manifest-bound audit activation",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    phase_paths = list(
        (private_home / ".z4j-restore" / "postgres").glob(
            "*/*/phase.json",
        ),
    )
    assert len(phase_paths) == 1
    phase = json.loads(phase_paths[0].read_text())
    assert phase["state"] == "AWAITING_AUDIT_ACTIVATION"
    operation = phase["operation_id"]
    manifest = await asyncio.to_thread(
        postgres_restore_module.build_restore_activation_manifest,
        integration_settings.database_url,
        operation=operation,
        settings=integration_settings,
        legacy_key_window_complete=False,
        known_head=None,
    )
    assert manifest["requires_ambiguity_attestation"] is True
    activated = await asyncio.to_thread(
        postgres_restore_module.apply_restore_activation_manifest,
        integration_settings.database_url,
        operation=operation,
        settings=integration_settings,
        manifest=manifest,
        attestation=manifest["manifest_digest"],
    )
    assert activated["state"] == "AUDIT_ACTIVATED"
    result = await asyncio.to_thread(
        restore_postgres,
        integration_settings.database_url,
        archive,
        operation=operation,
    )
    assert result["operation_id"] == operation

    verify_engine = create_engine_from_settings(integration_settings)
    verify_database = DatabaseManager(verify_engine)
    try:
        async with verify_database.session() as session:
            marker = (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.database_restored",
                    ),
                )
            ).scalar_one()
            assert marker.target_id == operation
    finally:
        await verify_database.dispose()


@pytest.mark.parametrize(
    "resolution",
    [
        "resume",
        "rollback",
        "rollback_marker_crash",
        "rollback_clear_crash",
    ],
)
async def test_real_pg_restore_failure_retains_fence_and_resolves(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolution: str,
) -> None:
    """A failed restore can resume or restore its captured target."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")

    private_home = tmp_path / "restore-failure-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        integration_settings.database_url,
    )
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
    monkeypatch.setenv("Z4J_HOME", str(private_home))

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"restore-resume-{project_id.hex[:12]}",
                name="PG restore resume",
            ),
        )
        await session.flush()
        source_schedule = await ScheduleControlRepository(
            session,
        ).create_current(
            project_id=project_id,
            data=_definition(),
            planning_at=datetime(2026, 7, 25, 12, 0, tzinfo=UTC),
        )
        schedule_id = source_schedule.id
        await session.commit()

    archive = tmp_path / "resume-source.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )
    async with database.session(write=True) as session:
        changed = await ScheduleControlRepository(
            session,
        ).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"name": "target-before-failed-restore"},
            planning_at=datetime(2026, 7, 25, 13, 0, tzinfo=UTC),
        )
        assert changed is not None
        await session.commit()
    await migrated_engine.dispose()

    original_runner = postgres_restore_module._run_identity_bound
    failed = False

    def fail_source_restore_once(
        tool: object,
        arguments: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal failed
        if not failed and getattr(tool, "name", None) == "pg_restore" and "--dbname" in arguments:
            failed = True
            return subprocess.CompletedProcess(
                ["pg_restore"],
                1,
                "",
                "injected source restore failure",
            )
        return original_runner(tool, arguments, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        fail_source_restore_once,
    )
    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="durable fence retained",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    assert failed

    phase_paths = list(
        (private_home / ".z4j-restore" / "postgres").glob(
            "*/*/phase.json",
        ),
    )
    assert len(phase_paths) == 1
    phase = json.loads(phase_paths[0].read_text())
    assert phase["state"] == "TARGET_CLEARED"
    operation_dir = phase_paths[0].parent
    assert (operation_dir / "source-staged.dump").is_file()
    assert (operation_dir / "target-recovery.dump").is_file()

    fenced_engine = create_engine_from_settings(integration_settings)
    try:
        with pytest.raises(DatabaseRestorePending):
            async with fenced_engine.connect():
                pytest.fail("failed restore did not retain its catalog fence")
    finally:
        await fenced_engine.dispose()

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        original_runner,
    )
    committed_marker_id: str | None = None
    if resolution == "resume":
        result = await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
            operation=phase["operation_id"],
        )
        expected_name = "pg-guarded"
    elif resolution == "rollback":
        result = await asyncio.to_thread(
            rollback_restore,
            integration_settings.database_url,
            operation=phase["operation_id"],
        )
        expected_name = "target-before-failed-restore"
    elif resolution == "rollback_marker_crash":
        original_set_fence = postgres_restore_module._set_fence
        marker_window_failed = False

        async def fail_after_rollback_marker(
            target: object,
            envelope: dict[str, object],
        ) -> None:
            nonlocal marker_window_failed
            if not marker_window_failed and envelope.get("state") == "TARGET_RECOVERED":
                marker_window_failed = True
                raise RuntimeError(
                    "injected crash after signed rollback marker",
                )
            await original_set_fence(target, envelope)  # type: ignore[arg-type]

        monkeypatch.setattr(
            postgres_restore_module,
            "_set_fence",
            fail_after_rollback_marker,
        )
        with pytest.raises(
            RuntimeError,
            match="after signed rollback marker",
        ):
            await asyncio.to_thread(
                rollback_restore,
                integration_settings.database_url,
                operation=phase["operation_id"],
            )
        assert marker_window_failed
        direct_url = integration_settings.database_url.replace(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        )
        direct = await asyncpg.connect(direct_url)
        try:
            committed_marker_id = await direct.fetchval(
                "SELECT id::text FROM audit_log "
                "WHERE action = 'audit.database_restore_rolled_back' "
                "AND target_id = $1",
                phase["operation_id"],
            )
        finally:
            await direct.close()
        assert committed_marker_id is not None
        monkeypatch.setattr(
            postgres_restore_module,
            "_set_fence",
            original_set_fence,
        )
        result = await asyncio.to_thread(
            rollback_restore,
            integration_settings.database_url,
            operation=phase["operation_id"],
        )
        expected_name = "target-before-failed-restore"
    else:
        original_clear_fence = postgres_restore_module._clear_fence
        clear_window_failed = False

        async def clear_then_fail(target: object) -> None:
            nonlocal clear_window_failed
            await original_clear_fence(target)  # type: ignore[arg-type]
            if not clear_window_failed:
                clear_window_failed = True
                raise RuntimeError(
                    "injected crash after rollback fence clear",
                )

        monkeypatch.setattr(
            postgres_restore_module,
            "_clear_fence",
            clear_then_fail,
        )
        with pytest.raises(
            RuntimeError,
            match="after rollback fence clear",
        ):
            await asyncio.to_thread(
                rollback_restore,
                integration_settings.database_url,
                operation=phase["operation_id"],
            )
        assert clear_window_failed
        direct_url = integration_settings.database_url.replace(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        )
        direct = await asyncpg.connect(direct_url)
        try:
            committed_marker_id = await direct.fetchval(
                "SELECT id::text FROM audit_log "
                "WHERE action = 'audit.database_restore_rolled_back' "
                "AND target_id = $1",
                phase["operation_id"],
            )
        finally:
            await direct.close()
        assert committed_marker_id is not None
        monkeypatch.setattr(
            postgres_restore_module,
            "_clear_fence",
            original_clear_fence,
        )
        result = await asyncio.to_thread(
            rollback_restore,
            integration_settings.database_url,
            operation=phase["operation_id"],
        )
        expected_name = "target-before-failed-restore"
    assert result["operation_id"] == phase["operation_id"]
    if committed_marker_id is not None:
        assert result["marker_id"] == committed_marker_id
    assert not (operation_dir / "source-staged.dump").exists()
    assert not (operation_dir / "target-recovery.dump").exists()

    verify_engine = create_engine_from_settings(integration_settings)
    verify_database = DatabaseManager(verify_engine)
    try:
        async with verify_database.session() as session:
            restored = await session.get(Schedule, schedule_id)
            assert restored is not None
            assert restored.name == expected_name
            if resolution in {
                "rollback",
                "rollback_marker_crash",
                "rollback_clear_crash",
            }:
                rollback_marker = (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.database_restore_rolled_back",
                        ),
                    )
                ).scalar_one()
                assert rollback_marker.target_id == phase["operation_id"]
                marker_count = (
                    await session.execute(
                        select(func.count())
                        .select_from(AuditLog)
                        .where(
                            AuditLog.action == "audit.database_restore_rolled_back",
                            AuditLog.target_id == phase["operation_id"],
                        ),
                    )
                ).scalar_one()
                assert marker_count == 1
    finally:
        await verify_database.dispose()


async def test_real_pg_external_epoch_allocation_binds_adapter_identity(
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The PostgreSQL trigger must consume the exact armed adapter identity."""

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"adapter-binding-{project_id.hex[:12]}",
                name="External adapter binding",
            ),
        )
        await session.commit()

    original_arm = schedule_external_repository_module.arm_external_epoch_allocation

    async def arm_with_different_adapter(*args: object, **kwargs: object) -> None:
        kwargs["adapter_instance_id"] = "descriptor-adapter"
        await original_arm(*args, **kwargs)

    monkeypatch.setattr(
        schedule_external_repository_module,
        "arm_external_epoch_allocation",
        arm_with_different_adapter,
    )
    with pytest.raises(
        DBAPIError,
        match="external allocated epoch already consumed",
    ):
        async with database.session(write=True) as session:
            await ScheduleExternalRepository(
                session,
            ).ensure_activation_epoch(
                project_id=project_id,
                owner="apscheduler",
                source_scope=('{"kind":"scheduler-owner","owner":"apscheduler","version":1}'),
                occurred_at=datetime(2026, 7, 25, 13, 59, tzinfo=UTC),
                adapter_instance_id="row-adapter",
                executor_agent_id=uuid.uuid4(),
                executor_registry_owner_id=uuid.uuid4(),
                executor_session_generation=uuid.uuid4().hex,
            )
            await session.commit()


def _definition() -> dict[str, object]:
    return {
        "name": "pg-guarded",
        "task_name": "jobs.pg_guarded",
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
    }


async def _seed_sealed_pg_external(
    database: DatabaseManager,
    *,
    project_id: uuid.UUID,
    owner: str,
    source_scope: str,
    adapter_instance_id: str,
    occurred_at: datetime,
) -> SimpleNamespace:
    projected = {
        "source_key": "pg-external-transfer",
        "engine": "celery",
        "scheduler": owner,
        "name": "pg-external-transfer",
        "task_name": "jobs.pg_external_transfer",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": "2026-07-26T07:00:00+00:00",
        "next_run_at": None,
        "total_runs": 3,
        "external_id": "pg-external-transfer",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    async with database.session(write=True) as session:
        repo = ScheduleExternalRepository(session)
        stream = await repo.ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=occurred_at,
            adapter_instance_id=adapter_instance_id,
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=str(uuid.uuid4()),
            executor_worker_id="source-worker",
        )
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
            payload_digest=external_projection_digest(body),
            operation_id=None,
            occurred_at=occurred_at,
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
        draining = await ScheduleExternalRepository(
            session,
        ).begin_stream_drain(
            project_id=project_id,
            stream_id=stream_id,
            occurred_at=occurred_at + timedelta(minutes=1),
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
            occurred_at=occurred_at + timedelta(minutes=2),
        )
        assert final.disposition == "applied"
        sealed = await repo.seal_drained_stream(
            project_id=project_id,
            stream_id=stream_id,
            expected_sequence=2,
            expected_snapshot_digest=final_digest,
            occurred_at=occurred_at + timedelta(minutes=3),
        )
        assert sealed.disposition == "sealed"
        await session.commit()
    return SimpleNamespace(
        stream_id=stream_id,
        epoch_uuid=epoch_uuid,
        epoch_number=epoch_number,
        schedule_id=schedule_id,
        final_digest=final_digest,
        projected=projected,
    )


async def test_real_pg_framed_external_activation_is_atomic(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    source_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    adapter_instance_id = "pg-framed-adapter"
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"framed-{project_id.hex[:12]}",
                name="Framed external PG",
            ),
        )
        await session.flush()
        stream = await ScheduleExternalRepository(
            session,
        ).ensure_activation_epoch(
            project_id=project_id,
            owner="apscheduler",
            source_scope=source_scope,
            occurred_at=datetime(2026, 7, 25, 13, 58, tzinfo=UTC),
            adapter_instance_id=adapter_instance_id,
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
        )
        stream_id = stream.id
        epoch_uuid = stream.current_epoch_uuid
        epoch_number = stream.current_epoch_number
        await session.commit()

    row = {
        **_definition(),
        "source_key": "pg-framed-job",
        "scheduler": "apscheduler",
        "source": "agent",
    }
    projection = external_projection_body(
        stream_id=str(stream_id),
        epoch_uuid=str(epoch_uuid),
        epoch_number=epoch_number,
        sequence=1,
        kind="snapshot",
        owner="apscheduler",
        source_scope=source_scope,
        adapter_instance_id=adapter_instance_id,
        schedules=[row],
        complete=True,
        stable_source=True,
    )
    snapshot_digest = external_projection_digest(projection)
    snapshot_id = uuid.uuid4()

    def frame(
        frame_kind: str,
        frame_index: int,
        rows: list[dict[str, object]],
    ) -> tuple[dict[str, object], str]:
        body = external_snapshot_frame_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=1,
            owner="apscheduler",
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            snapshot_id=str(snapshot_id),
            frame_kind=frame_kind,
            frame_index=frame_index,
            frame_count=1,
            row_count=1,
            snapshot_digest=snapshot_digest,
            stable_source=True,
            schedules=rows,
        )
        return body, external_snapshot_frame_digest(body)

    terminal, terminal_digest = frame("terminal", 1, [])
    row_frame, row_digest = frame("rows", 0, [row])

    async def stage(
        body: dict[str, object],
        digest: str,
    ):
        async with database.session(write=True) as session:
            transition = await ScheduleExternalRepository(
                session,
            ).stage_snapshot_frame(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=1,
                owner="apscheduler",
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                snapshot_id=snapshot_id,
                frame_kind=str(body["frame_kind"]),
                frame_index=int(body["frame_index"]),
                frame_count=int(body["frame_count"]),
                row_count=int(body["row_count"]),
                snapshot_digest=str(body["snapshot_digest"]),
                frame_digest=digest,
                stable_source=True,
                schedules=list(body["schedules"]),  # type: ignore[arg-type]
                occurred_at=datetime(2026, 7, 25, 13, 59, tzinfo=UTC),
            )
            await session.commit()
            return transition

    assert (await stage(terminal, terminal_digest)).disposition == "snapshot_incomplete"
    with pytest.raises(
        DBAPIError,
        match="external projection is not armed",
    ):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO schedule_external_snapshot_frames "
                    "SELECT * FROM schedule_external_snapshot_frames "
                    "WHERE stream_id = :stream_id",
                ),
                {"stream_id": stream_id},
            )
    async with database.session() as session:
        stream = await session.get(ScheduleExternalStream, stream_id)
        assert stream is not None
        assert stream.phase == "ACTIVATING"
        assert stream.accepted_sequence == 0

    assert (await stage(row_frame, row_digest)).disposition == "staged"
    assert (await stage(terminal, terminal_digest)).disposition == "applied"
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
            == 2
        )
        schedule = await session.scalar(
            select(Schedule).where(Schedule.external_stream_id == stream_id),
        )
        assert schedule is not None
        assert schedule.name == "pg-guarded"


async def test_real_pg_external_epoch_projection_is_guarded(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    source_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"external-{project_id.hex[:12]}",
                name="External PG",
            ),
        )
        await session.commit()

    async with database.session(write=True) as session:
        stream = await ScheduleExternalRepository(
            session,
        ).ensure_activation_epoch(
            project_id=project_id,
            owner="apscheduler",
            source_scope=source_scope,
            occurred_at=datetime(2026, 7, 25, 14, 0, tzinfo=UTC),
            adapter_instance_id="pg-adapter-one",
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
        )
        assert stream.authorized_adapter_instance_id == "pg-adapter-one"
        stream_id = stream.id
        epoch_uuid = stream.current_epoch_uuid
        epoch_number = stream.current_epoch_number
        await session.commit()

    projected = {
        "source_key": "pg-job",
        "engine": "apscheduler",
        "scheduler": "apscheduler",
        "name": "pg-job",
        "task_name": "jobs.pg_external",
        "kind": "interval",
        "expression": "60s",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": "2026-07-25T14:01:00+00:00",
        "total_runs": 0,
        "external_id": "pg-native-id",
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
        owner="apscheduler",
        source_scope=source_scope,
        adapter_instance_id="pg-adapter-one",
        schedules=[projected],
        deleted_source_keys=[],
        complete=True,
        stable_source=True,
    )
    async with database.session(write=True) as session:
        transition = await ScheduleExternalRepository(
            session,
        ).apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner="apscheduler",
            source_scope=source_scope,
            adapter_instance_id="pg-adapter-one",
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=external_projection_digest(body),
            operation_id=None,
            occurred_at=datetime(2026, 7, 25, 14, 1, tzinfo=UTC),
        )
        assert transition.disposition == "applied"
        assert transition.inserted == 1
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
        assert stream.authorized_adapter_instance_id == "pg-adapter-one"
        assert schedule.external_source_sequence == 1

    with pytest.raises(
        DBAPIError,
        match="external projection is not armed",
    ):
        async with database.session(write=True) as session:
            schedule = (
                await session.execute(
                    select(Schedule).where(Schedule.id == schedule_id).with_for_update(),
                )
            ).scalar_one()
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
                    schedule_owner="apscheduler",
                    change_kind="gap",
                    protocol_version=1,
                    snapshot=null(),
                    occurred_at=datetime(
                        2026,
                        7,
                        25,
                        14,
                        2,
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
            schedule.external_source_sequence = 2
            schedule.expression = "forged-without-projection"
            await session.flush()

    async with database.session() as session:
        stream = await session.get(ScheduleExternalStream, stream_id)
        schedule = await session.get(Schedule, schedule_id)
        assert stream is not None
        assert schedule is not None
        assert stream.accepted_sequence == 1
        assert schedule.external_source_sequence == 1
        assert schedule.expression == "60s"

    conflicting = dict(projected)
    conflicting["expression"] = "120s"
    conflicting_body = external_projection_body(
        stream_id=str(stream_id),
        epoch_uuid=str(epoch_uuid),
        epoch_number=epoch_number,
        sequence=1,
        kind="snapshot",
        owner="apscheduler",
        source_scope=source_scope,
        adapter_instance_id="pg-adapter-one",
        schedules=[conflicting],
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
            sequence=1,
            kind="snapshot",
            owner="apscheduler",
            source_scope=source_scope,
            adapter_instance_id="pg-adapter-one",
            schedules=[conflicting],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=external_projection_digest(conflicting_body),
            operation_id=None,
            occurred_at=datetime(2026, 7, 25, 14, 3, tzinfo=UTC),
        )
        assert fault.disposition == "protocol_fault"
        await session.commit()

    async with database.session() as session:
        stream = await session.get(ScheduleExternalStream, stream_id)
        schedule = await session.get(Schedule, schedule_id)
        assert stream is not None
        assert schedule is not None
        assert stream.phase == "AMBIGUOUS"
        assert stream.accepted_sequence == 1
        assert schedule.expression == "60s"


async def test_real_pg_external_stream_drain_seal_retire_is_guarded(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    owner = "huey-periodic"
    source_scope = '{"kind":"scheduler-owner","owner":"huey-periodic","version":1}'
    adapter_instance_id = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 2, 0, tzinfo=UTC)
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"lifecycle-{project_id.hex[:12]}",
                name="External lifecycle",
            ),
        )
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
            schedules=[],
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
            schedules=[],
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
        schedules=[],
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
            schedules=[],
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
        retired = await repo.retire_sealed_stream(
            project_id=project_id,
            stream_id=stream_id,
            occurred_at=now + timedelta(minutes=4),
        )
        assert retired.disposition == "retired"
        await session.commit()

    with pytest.raises(DBAPIError):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedule_external_streams SET phase = 'ACTIVE' WHERE id = :stream_id",
                ),
                {"stream_id": stream_id},
            )

    async with database.session(write=True) as session:
        replacement = await ScheduleExternalRepository(
            session,
        ).ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=now + timedelta(minutes=5),
            adapter_instance_id=str(uuid.uuid4()),
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=str(uuid.uuid4()),
            executor_worker_id="replacement-worker",
            activation_requirement=(f"OWNER_CUTOVER:{uuid.uuid4()}"),
            replace_retired=True,
        )
        assert replacement.id == stream_id
        assert replacement.current_epoch_uuid != epoch_uuid
        assert replacement.current_epoch_number > epoch_number
        assert replacement.phase == "ACTIVATING"
        await session.commit()


async def test_real_pg_external_to_reserved_cutover_is_guarded(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    owner = "celery-beat"
    source_scope = '{"kind":"scheduler-owner","owner":"celery-beat","version":1}'
    adapter_instance_id = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 4, 0, tzinfo=UTC)
    projected = {
        "source_key": "pg-cutover",
        "engine": "celery",
        "scheduler": owner,
        "name": "pg-cutover",
        "task_name": "jobs.pg_cutover",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": "2026-07-26T03:00:00+00:00",
        "next_run_at": None,
        "total_runs": 11,
        "external_id": "pg-cutover",
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"cutover-{project_id.hex[:12]}",
                name="External owner cutover",
            ),
        )
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
        old_token = schedule.control_token
        old_revision = schedule.schedule_revision
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
        sealed = await repo.seal_drained_stream(
            project_id=project_id,
            stream_id=stream_id,
            expected_sequence=2,
            expected_snapshot_digest=final_digest,
            occurred_at=now + timedelta(minutes=3),
        )
        assert sealed.disposition == "sealed"
        await session.commit()

    with pytest.raises(DBAPIError):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedules SET scheduler = 'z4j-scheduler' WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id},
            )

    async with database.session(write=True) as session:
        repo = ScheduleExternalRepository(session)
        preview = await repo.preview_external_to_reserved_cutover(
            project_id=project_id,
            from_owner=owner,
            source_scope=source_scope,
        )
        attestation = {
            "all_old_and_new_scheduler_replicas_quiesced": True,
            "preview_manifest_digest": preview.manifest_digest,
            "stream_id": str(stream_id),
            "epoch_uuid": str(epoch_uuid),
            "sealed_sequence": 2,
            "final_snapshot_digest": final_digest,
        }
        completed = await repo.finalize_external_to_reserved_cutover(
            operation_id=operation_id,
            project_id=project_id,
            from_owner=owner,
            source_scope=source_scope,
            preview_manifest_digest=preview.manifest_digest,
            cursor_policy="PRESERVE",
            quiescence_attestation=attestation,
            occurred_at=now + timedelta(minutes=4),
        )
        assert completed.disposition == "completed"
        await session.commit()

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
        assert schedule.total_runs == 11
        assert schedule.external_stream_id is None
        assert schedule.next_run_at is not None
        assert stream.phase == "RETIRED"
        committed_token = schedule.control_token
        committed_revision = schedule.schedule_revision

    async with database.session(write=True) as session:
        replay = await ScheduleExternalRepository(
            session,
        ).finalize_external_to_reserved_cutover(
            operation_id=operation_id,
            project_id=project_id,
            from_owner=owner,
            source_scope=source_scope,
            preview_manifest_digest=preview.manifest_digest,
            cursor_policy="PRESERVE",
            quiescence_attestation=attestation,
            occurred_at=now + timedelta(minutes=5),
        )
        assert replay.disposition == "exact_replay"
        current = await session.get(Schedule, schedule_id)
        assert current is not None
        assert current.control_token == committed_token
        assert current.schedule_revision == committed_revision

    with pytest.raises(DBAPIError):
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
            await session.flush()


async def test_real_pg_reserved_to_external_cutover_requires_activation(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    target_owner = "apscheduler"
    target_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    selection_scope = '{"kind":"schedule-ids","version":1}'
    adapter_instance_id = str(uuid.uuid4())
    executor_agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    now = datetime(2026, 7, 26, 7, 0, tzinfo=UTC)
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"reserved-x-{project_id.hex[:12]}",
                name="Reserved to external",
            ),
        )
        await session.flush()
        schedule = await ScheduleControlRepository(
            session,
        ).create_current(
            project_id=project_id,
            data={
                "name": "pg-reserved-cutover",
                "task_name": "jobs.pg_reserved_cutover",
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
            target_executor_registry_owner_id=registry_owner_id,
            target_executor_session_generation=session_generation,
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
            target_executor_registry_owner_id=registry_owner_id,
            target_executor_session_generation=session_generation,
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
        target = await session.get(
            ScheduleExternalStream,
            cutover.target_stream_id,
        )
        assert target is not None
        assert schedule.scheduler == target_owner
        assert schedule.next_run_at is None
        assert schedule.external_source_sequence == 0
        assert target.phase == "ACTIVATING"
        target_stream_id = target.id
        target_epoch_uuid = target.current_epoch_uuid
        target_epoch_number = target.current_epoch_number
        activation_rows = cutover.result_manifest["target_activation_schedules"]

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
        activated = await ScheduleExternalRepository(
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
            schedules=activation_rows,
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=external_projection_digest(
                activation_body,
            ),
            operation_id=None,
            occurred_at=now + timedelta(minutes=2),
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
        assert schedule.external_source_sequence == 1
        assert target.phase == "ACTIVE"


async def test_real_pg_external_to_external_cutover_retires_source(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
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
    now = datetime(2026, 7, 26, 8, 0, tzinfo=UTC)
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"external-x-{project_id.hex[:12]}",
                name="External to external",
            ),
        )
        await session.commit()
    source = await _seed_sealed_pg_external(
        database,
        project_id=project_id,
        owner=from_owner,
        source_scope=source_scope,
        adapter_instance_id=source_adapter,
        occurred_at=now,
    )
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
            target_executor_session_generation=target_generation,
            target_executor_worker_id="target-worker",
        )
        attestation = {
            "all_old_and_new_scheduler_replicas_quiesced": True,
            "preview_manifest_digest": preview.manifest_digest,
            "source_stream_id": str(source.stream_id),
            "source_epoch_uuid": str(source.epoch_uuid),
            "source_sealed_sequence": 2,
            "source_final_snapshot_digest": source.final_digest,
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
            target_executor_session_generation=target_generation,
            target_executor_worker_id="target-worker",
            occurred_at=now + timedelta(minutes=4),
        )
        assert completed.disposition == "completed"
        await session.commit()
    async with database.session() as session:
        old_stream = await session.get(
            ScheduleExternalStream,
            source.stream_id,
        )
        schedule = await session.get(
            Schedule,
            source.schedule_id,
        )
        cutover = await session.get(
            ScheduleOwnerCutover,
            operation_id,
        )
        assert old_stream is not None
        assert schedule is not None
        assert cutover is not None
        target = await session.get(
            ScheduleExternalStream,
            cutover.target_stream_id,
        )
        assert target is not None
        assert old_stream.phase == "RETIRED"
        assert target.phase == "ACTIVATING"
        assert schedule.scheduler == to_owner
        assert schedule.external_stream_id == target.id
        assert schedule.external_source_sequence == 0
    late_body = external_projection_body(
        stream_id=str(source.stream_id),
        epoch_uuid=str(source.epoch_uuid),
        epoch_number=source.epoch_number,
        sequence=3,
        kind="updated",
        owner=from_owner,
        source_scope=source_scope,
        adapter_instance_id=source_adapter,
        schedules=[source.projected],
        deleted_source_keys=[],
        complete=False,
        stable_source=True,
    )
    async with database.session(write=True) as session:
        late = await ScheduleExternalRepository(
            session,
        ).apply_projection(
            project_id=project_id,
            stream_id=source.stream_id,
            epoch_uuid=source.epoch_uuid,
            epoch_number=source.epoch_number,
            sequence=3,
            kind="updated",
            owner=from_owner,
            source_scope=source_scope,
            adapter_instance_id=source_adapter,
            schedules=[source.projected],
            deleted_source_keys=[],
            complete=False,
            stable_source=True,
            payload_digest=external_projection_digest(late_body),
            operation_id=None,
            occurred_at=now + timedelta(minutes=5),
        )
        assert late.disposition == "stream_not_accepting"


async def test_real_pg_external_control_is_guarded_end_to_end(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    registry_owner_id = uuid.uuid4()
    session_generation = str(uuid.uuid4())
    adapter_instance_id = str(uuid.uuid4())
    source_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    projected = {
        "source_key": "pg-control",
        "engine": "apscheduler",
        "scheduler": "apscheduler",
        "name": "pg-control",
        "task_name": "jobs.pg_control",
        "kind": "interval",
        "expression": "60s",
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
        session.add(
            Project(
                id=project_id,
                slug=f"control-{project_id.hex[:12]}",
                name="External control PG",
            ),
        )
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="pg-control-agent",
                token_hash=uuid.uuid4().hex,
                protocol_version="2",
                framework_adapter="bare",
                engine_adapters=["apscheduler"],
                scheduler_adapters=["apscheduler"],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.flush()
        stream = await ScheduleExternalRepository(
            session,
        ).ensure_activation_epoch(
            project_id=project_id,
            owner="apscheduler",
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
            owner="apscheduler",
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
            owner="apscheduler",
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
        await session.commit()

    with pytest.raises(
        DBAPIError,
        match="external control transition is not armed",
    ):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO schedule_external_control_operations "
                    "SELECT * FROM schedule_external_control_operations "
                    "WHERE id = :operation_id",
                ),
                {"operation_id": operation_id},
            )

    with pytest.raises(
        DBAPIError,
        match="external control transition is not armed",
    ):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedule_external_control_operations "
                    "SET status = 'CLAIMED', "
                    "dispatch_lease = :dispatch_lease, "
                    "reserved_sequence = expected_accepted_sequence + 1 "
                    "WHERE id = :operation_id",
                ),
                {
                    "dispatch_lease": uuid.uuid4(),
                    "operation_id": operation_id,
                },
            )

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
        await session.commit()

    with pytest.raises(
        DBAPIError,
        match="external control transition is not armed",
    ):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedule_external_control_operations "
                    "SET status = 'APPLIED', "
                    "result_projection_id = :projection_id "
                    "WHERE id = :operation_id",
                ),
                {
                    "projection_id": uuid.uuid4(),
                    "operation_id": operation_id,
                },
            )

    async with database.session(write=True) as session:
        operation = await session.get(
            ScheduleExternalControlOperation,
            operation_id,
        )
        assert operation is not None
        desired = operation.desired_projection
        control_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=2,
            kind="control",
            owner="apscheduler",
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[desired],
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
            owner="apscheduler",
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=[desired],
            deleted_source_keys=[],
            complete=False,
            stable_source=True,
            payload_digest=external_projection_digest(control_body),
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
        assert schedule.is_enabled is False
        assert schedule.control_token != original_token
        assert stream.accepted_sequence == 2

    async with database.session(write=True) as session:
        second = await ScheduleExternalRepository(
            session,
        ).plan_control_operation(
            project_id=project_id,
            stream_id=stream_id,
            schedule_id=schedule_id,
            enabled=True,
            issued_by=None,
            source_ip=None,
            timeout_at=datetime(2026, 7, 25, 18, 10, tzinfo=UTC),
        )
        assert second.disposition == "planned"
        assert second.operation is not None
        assert second.command is not None
        second_operation_id = second.operation.id
        second_command_id = second.command.id
        await session.commit()

    async with database.session(write=True) as session:
        marked, claimed = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            second_command_id,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            timeout_seconds=60,
            occurred_at=datetime(2026, 7, 25, 18, 3, tzinfo=UTC),
        )
        assert marked is True
        assert claimed is not None
        await session.commit()

    async with database.session(write=True) as session:
        generic = await CommandRepository(session).sweep_timeouts(
            now=datetime(2026, 7, 25, 18, 5, tzinfo=UTC),
        )
        assert generic == 0
        terminal = await ScheduleExternalRepository(
            session,
        ).expire_claimed_control(
            command_id=second_command_id,
            occurred_at=datetime(2026, 7, 25, 18, 5, tzinfo=UTC),
        )
        assert terminal.disposition == "ambiguous"
        await session.commit()

    async with database.session() as session:
        second_operation = await session.get(
            ScheduleExternalControlOperation,
            second_operation_id,
        )
        schedule = await session.get(Schedule, schedule_id)
        stream = await session.get(ScheduleExternalStream, stream_id)
        assert second_operation is not None
        assert schedule is not None
        assert stream is not None
        assert second_operation.status == "AMBIGUOUS"
        assert schedule.is_enabled is False
        assert stream.phase == "AMBIGUOUS"


async def test_guarded_repository_succeeds_and_raw_old_writes_fail(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"d-{project_id.hex[:12]}",
                name="Boundary D",
            ),
        )
        await session.commit()

    async with database.session(write=True) as session:
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data=_definition(),
            planning_at=datetime(2026, 7, 25, 12, 3, tzinfo=UTC),
        )
        schedule_id = schedule.id
        control_token = schedule.control_token
        assert control_token is not None
        assert schedule.schedule_revision == 1
        await session.commit()

    async with database.session(write=True) as session:
        updated = await ScheduleControlRepository(session).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"name": "pg-guarded-updated"},
            planning_at=datetime(2026, 7, 25, 12, 4, tzinfo=UTC),
        )
        assert updated.schedule_revision == 2
        assert updated.control_token == control_token
        await session.commit()

    with pytest.raises(
        DBAPIError,
        match=r"transition identity|change envelope|descriptor",
    ):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedules SET name = 'old-writer' WHERE id = :schedule_id",
                ),
                {"schedule_id": schedule_id},
            )

    now = datetime(2026, 7, 25, 12, 5, tzinfo=UTC)
    with pytest.raises(DBAPIError, match="transition is not armed"):
        async with migrated_engine.begin() as connection:
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
                    "id": uuid.uuid4(),
                    "project_id": project_id,
                    "schedule_id": schedule_id,
                    "fire_id": uuid.uuid4(),
                    "scheduled_for": now,
                    "command_id": uuid.uuid4(),
                    "observed": control_token,
                    "receipt": control_token,
                    "nonce": uuid.uuid4(),
                    "created_at": now,
                },
            )

    with pytest.raises(DBAPIError, match="transition is not armed"):
        async with migrated_engine.begin() as connection:
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
                    "'LEGACY_NULL', 'failed', true, 'OPERATOR_SKIPPED', "
                    ":resolved_at, :resolved_by, 'OPERATOR', "
                    ":resolution_token, :nonce)",
                ),
                {
                    "id": uuid.uuid4(),
                    "project_id": project_id,
                    "schedule_id": schedule_id,
                    "fire_id": uuid.uuid4(),
                    "scheduled_for": now,
                    "source_id": uuid.uuid4(),
                    "resolved_at": now,
                    "resolved_by": uuid.uuid4(),
                    "resolution_token": uuid.uuid4(),
                    "nonce": uuid.uuid4(),
                },
            )

    with pytest.raises(DBAPIError, match="protocol marker required"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO commands ("
                    "id, project_id, action, target_type, payload, status, "
                    "issued_at, timeout_at"
                    ") VALUES ("
                    ":id, :project_id, 'schedule.fire', 'schedule', "
                    "'{}'::jsonb, 'pending', now(), now()"
                    ")",
                ),
                {"id": uuid.uuid4(), "project_id": project_id},
            )

    with pytest.raises(DBAPIError, match="prune is not armed"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "DELETE FROM schedule_change_log WHERE revision = 1",
                ),
            )

    async with database.session(write=True) as session:
        pruned = await ScheduleControlRepository(
            session,
        ).prune_change_log(through_revision=1)
        assert pruned == 1
        await session.commit()
    async with database.session() as session:
        state = await session.get(
            ScheduleRevisionState,
            "schedule-revision",
        )
        assert state is not None
        assert state.current_revision == 2
        assert state.change_log_pruned_through == 1
        retained = list(
            (
                await session.execute(
                    text(
                        "SELECT revision FROM schedule_change_log ORDER BY revision",
                    ),
                )
            ).scalars(),
        )
        assert retained == [2]


async def test_partitioned_generation_uniqueness_and_legacy_insert_fence(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"u-{project_id.hex[:12]}",
                name="Uniqueness",
            ),
        )
        await session.commit()
    async with database.session(write=True) as session:
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data=_definition(),
            planning_at=datetime(2026, 7, 25, 12, 3, tzinfo=UTC),
        )
        schedule_id = schedule.id
        await session.commit()

    fire_id = uuid.uuid4()
    slot = datetime(2026, 7, 25, 12, 5, tzinfo=UTC)
    base = {
        "schedule_id": schedule_id,
        "project_id": project_id,
        "fire_id": fire_id,
        "slot": slot,
    }
    current_insert = text(
        "INSERT INTO schedule_fires ("
        "id, fire_id, schedule_id, project_id, status, scheduled_for, "
        "fired_at, protocol_marker, state_write_nonce, "
        "receipt_control_token, acceptance_revision, definition_digest, "
        "expected_schedule_revision, expected_next_run_at, "
        "prepared_next_run_at"
        ") VALUES ("
        ":id, :fire_id, :schedule_id, :project_id, 'accepted', :slot, "
        ":slot, 1, :nonce, :receipt, 1, :digest, 1, :slot, :slot"
        ")",
    )
    async with migrated_engine.begin() as connection:
        for _ in range(2):
            await connection.execute(
                current_insert,
                {
                    **base,
                    "id": uuid.uuid4(),
                    "nonce": uuid.uuid4(),
                    "receipt": uuid.uuid4(),
                    "digest": "a" * 64,
                },
            )

    legacy_insert = text(
        "INSERT INTO schedule_fires ("
        "id, fire_id, schedule_id, project_id, status, scheduled_for, "
        "fired_at, protocol_marker, state_write_nonce"
        ") VALUES ("
        ":id, :fire_id, :schedule_id, :project_id, 'failed', :slot, "
        ":slot, 1, :nonce"
        ")",
    )
    with pytest.raises(DBAPIError, match="receipt tuple is required"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                legacy_insert,
                {
                    **base,
                    "id": uuid.uuid4(),
                    "nonce": uuid.uuid4(),
                },
            )


async def test_activated_current_cadence_writer_lifecycle(
    migrated_engine: AsyncEngine,
) -> None:
    """The real repositories can traverse every guarded evidence boundary."""

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    planning_at = datetime(2026, 7, 25, 12, 3, 7, tzinfo=UTC)
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"l-{project_id.hex[:12]}",
                name="Lifecycle",
            ),
        )
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="lifecycle-agent",
                token_hash=uuid.uuid4().hex,
                protocol_version="1.8",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    async with database.session(write=True) as session:
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data=_definition(),
            planning_at=planning_at,
        )
        await session.commit()
        schedule_id = schedule.id

    async with database.session(write=True) as session:
        schedule = await ScheduleControlRepository(session).stable_snapshot(
            project_id=project_id,
        )
        row = schedule.rows[0]
        slot = row.next_run_at
        token = row.control_token
        digest = row.definition_digest
        expected_revision = row.schedule_revision
        assert slot is not None
        assert token is not None
        assert digest is not None
        assert expected_revision is not None
        fire_id = derive_scheduler_fire_id(schedule_id, slot)
        successor = slot + timedelta(minutes=5)
        transition = await ScheduleControlRepository(
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
        assert transition.disposition == "applied"
        execution_fire_id = transition.execution_fire_id
        acceptance_revision = transition.acceptance_revision
        assert execution_fire_id is not None
        assert acceptance_revision is not None
        initial_deadline = slot + timedelta(minutes=1)
        command, created = await CommandRepository(
            session,
        ).insert_current_schedule_fire(
            project_id=project_id,
            agent_id=agent_id,
            schedule_id=schedule_id,
            fire_id=fire_id,
            scheduled_for=slot,
            observed_control_token=token,
            receipt_control_token=token,
            execution_fire_id=execution_fire_id,
            acceptance_revision=acceptance_revision,
            definition_digest=digest,
            expected_revision=expected_revision,
            expected_last_run_at=None,
            expected_next_run_at=slot,
            prepared_next_run_at=successor,
            payload={
                "schedule_id": str(schedule_id),
                "fire_id": str(execution_fire_id),
                "schedule_fire_id": str(fire_id),
            },
            timeout_at=initial_deadline,
            initial_claim_deadline=initial_deadline,
        )
        assert created is True
        await ScheduleFireRepository(session).record_current(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=command.id,
            status="accepted",
            scheduled_for=slot,
            observed_control_token=token,
            receipt_control_token=token,
            acceptance_revision=acceptance_revision,
            definition_digest=digest,
            expected_schedule_revision=expected_revision,
            expected_last_run_at=None,
            expected_next_run_at=slot,
            prepared_next_run_at=successor,
        )
        command_id = command.id
        await session.commit()

    owner_id = uuid.uuid4()
    session_generation = uuid.uuid4().hex
    async with database.session(write=True) as session:
        is_current, command = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner_id,
            session_generation=session_generation,
            timeout_seconds=30,
            occurred_at=slot + timedelta(seconds=10),
        )
        assert is_current is True
        assert command is not None
        assert command.status == CommandStatus.DISPATCHED
        claim_token = command.delivery_claim_token
        assert claim_token is not None
        await session.commit()

    async with database.session(write=True) as session:
        acknowledged = await ScheduleControlRepository(
            session,
        ).acknowledge_current_agent_delivery(
            command_id=command_id,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner_id,
            session_generation=session_generation,
            delivery_claim_token=str(claim_token),
            occurred_at=slot + timedelta(seconds=20),
        )
        assert acknowledged.disposition == "acknowledged"
        await session.commit()

    async with database.session(write=True) as session:
        completed = await ScheduleControlRepository(
            session,
        ).apply_current_agent_result(
            command_id=command_id,
            project_id=project_id,
            agent_id=agent_id,
            status="success",
            result_payload={"task_id": "pg-lifecycle"},
            error=None,
            transport_kind="websocket",
            registry_owner_id=owner_id,
            session_generation=session_generation,
            delivery_claim_token=str(claim_token),
            occurred_at=slot + timedelta(seconds=30),
        )
        assert completed.disposition == "completed"
        assert completed.command is not None
        assert completed.command.status == CommandStatus.COMPLETED
        await session.commit()

    with pytest.raises(DBAPIError, match="invalid schedule command transition"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE commands SET delivery_claim_token = :token, "
                    "schedule_state_nonce = :nonce WHERE id = :command_id",
                ),
                {
                    "token": uuid.uuid4(),
                    "nonce": uuid.uuid4(),
                    "command_id": command_id,
                },
            )
    with pytest.raises(DBAPIError, match="invalid schedule fire transition"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE schedule_fires SET command_id = :replacement, "
                    "state_write_nonce = :nonce "
                    "WHERE fire_id = :fire_id "
                    "AND receipt_control_token = :receipt",
                ),
                {
                    "replacement": uuid.uuid4(),
                    "nonce": uuid.uuid4(),
                    "fire_id": fire_id,
                    "receipt": token,
                },
            )
    with pytest.raises(DBAPIError, match="transition is not armed"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text(
                    "DELETE FROM schedule_fires "
                    "WHERE fire_id = :fire_id "
                    "AND receipt_control_token = :receipt",
                ),
                {"fire_id": fire_id, "receipt": token},
            )

    async with database.session(write=True) as session:
        snapshot = await ScheduleControlRepository(session).stable_snapshot(
            project_id=project_id,
        )
        row = snapshot.rows[0]
        second_slot = row.next_run_at
        second_token = row.control_token
        second_digest = row.definition_digest
        second_expected_revision = row.schedule_revision
        assert second_slot is not None
        assert second_token is not None
        assert second_digest is not None
        assert second_expected_revision is not None
        second_fire_id = derive_scheduler_fire_id(schedule_id, second_slot)
        second_successor = second_slot + timedelta(minutes=5)
        second_transition = await ScheduleControlRepository(
            session,
        ).accept_current_fire_progress(
            project_id=project_id,
            schedule_id=schedule_id,
            fire_id=second_fire_id,
            scheduled_for=second_slot,
            observed_control_token=second_token,
            definition_digest=second_digest,
            expected_revision=second_expected_revision,
            expected_last_run_at=row.last_run_at,
            expected_next_run_at=second_slot,
            prepared_next_run_at=second_successor,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=second_slot + timedelta(seconds=1),
        )
        second_execution_fire_id = second_transition.execution_fire_id
        second_acceptance_revision = second_transition.acceptance_revision
        assert second_execution_fire_id is not None
        assert second_acceptance_revision is not None
        pending, created = await PendingFiresRepository(
            session,
        ).buffer_current(
            fire_id=second_fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            engine="celery",
            payload={
                "schedule_id": str(schedule_id),
                "fire_id": str(second_execution_fire_id),
                "schedule_fire_id": str(second_fire_id),
            },
            scheduled_for=second_slot,
            expires_at=second_slot + timedelta(seconds=10),
            observed_control_token=second_token,
            receipt_control_token=second_token,
            definition_digest=second_digest,
            expected_schedule_revision=second_expected_revision,
            expected_last_run_at=row.last_run_at,
            expected_next_run_at=second_slot,
            prepared_next_run_at=second_successor,
            acceptance_revision=second_acceptance_revision,
            execution_fire_id=second_execution_fire_id,
        )
        assert created is True
        await ScheduleFireRepository(session).record_current(
            fire_id=second_fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=None,
            status="buffered",
            scheduled_for=second_slot,
            observed_control_token=second_token,
            receipt_control_token=second_token,
            acceptance_revision=second_acceptance_revision,
            definition_digest=second_digest,
            expected_schedule_revision=second_expected_revision,
            expected_last_run_at=row.last_run_at,
            expected_next_run_at=second_slot,
            prepared_next_run_at=second_successor,
        )
        pending_id = pending.id
        pending_nonce = pending.state_write_nonce
        assert pending_nonce is not None
        await session.commit()

    with pytest.raises(DBAPIError, match="transition is not armed"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM pending_fires WHERE id = :pending_id"),
                {"pending_id": pending_id},
            )

    async with database.session(write=True) as session:
        expired = await PendingFiresRepository(session).expire_current(
            pending_id=pending_id,
            expected_state_nonce=pending_nonce,
            occurred_at=second_slot + timedelta(seconds=11),
        )
        assert expired.disposition == "expired"
        assert expired.changed is True
        await session.commit()

    async with database.session(write=True) as session:
        snapshot = await ScheduleControlRepository(session).stable_snapshot(
            project_id=project_id,
        )
        row = snapshot.rows[0]
        third_slot = row.next_run_at
        third_token = row.control_token
        third_digest = row.definition_digest
        third_expected_revision = row.schedule_revision
        third_expected_last = row.last_run_at
        assert third_slot is not None
        assert third_token is not None
        assert third_digest is not None
        assert third_expected_revision is not None
        third_fire_id = derive_scheduler_fire_id(schedule_id, third_slot)
        third_successor = third_slot + timedelta(minutes=5)
        third_transition = await ScheduleControlRepository(
            session,
        ).accept_current_fire_progress(
            project_id=project_id,
            schedule_id=schedule_id,
            fire_id=third_fire_id,
            scheduled_for=third_slot,
            observed_control_token=third_token,
            definition_digest=third_digest,
            expected_revision=third_expected_revision,
            expected_last_run_at=third_expected_last,
            expected_next_run_at=third_slot,
            prepared_next_run_at=third_successor,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=third_slot + timedelta(seconds=1),
        )
        third_execution_fire_id = third_transition.execution_fire_id
        third_acceptance_revision = third_transition.acceptance_revision
        assert third_execution_fire_id is not None
        assert third_acceptance_revision is not None
        third_payload = {
            "schedule_id": str(schedule_id),
            "fire_id": str(third_execution_fire_id),
            "schedule_fire_id": str(third_fire_id),
        }
        pending, created = await PendingFiresRepository(
            session,
        ).buffer_current(
            fire_id=third_fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            engine="celery",
            payload=third_payload,
            scheduled_for=third_slot,
            expires_at=third_slot + timedelta(minutes=1),
            observed_control_token=third_token,
            receipt_control_token=third_token,
            definition_digest=third_digest,
            expected_schedule_revision=third_expected_revision,
            expected_last_run_at=third_expected_last,
            expected_next_run_at=third_slot,
            prepared_next_run_at=third_successor,
            acceptance_revision=third_acceptance_revision,
            execution_fire_id=third_execution_fire_id,
        )
        assert created is True
        await ScheduleFireRepository(session).record_current(
            fire_id=third_fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=None,
            status="buffered",
            scheduled_for=third_slot,
            observed_control_token=third_token,
            receipt_control_token=third_token,
            acceptance_revision=third_acceptance_revision,
            definition_digest=third_digest,
            expected_schedule_revision=third_expected_revision,
            expected_last_run_at=third_expected_last,
            expected_next_run_at=third_slot,
            prepared_next_run_at=third_successor,
        )
        replay_pending_id = pending.id
        replay_pending_nonce = pending.state_write_nonce
        assert replay_pending_nonce is not None
        await session.commit()

    async with database.session(write=True) as session:
        replayed = await PendingFiresRepository(session).replay_current(
            pending_id=replay_pending_id,
            expected_state_nonce=replay_pending_nonce,
            agent_id=agent_id,
            command_timeout_seconds=30,
            occurred_at=third_slot + timedelta(seconds=5),
        )
        assert replayed.disposition == "replayed"
        assert replayed.changed is True
        assert replayed.command is not None
        assert replayed.fire is not None
        assert replayed.fire.command_id == replayed.command.id
        await session.commit()

    with pytest.raises(DBAPIError, match="exact tombstone"):
        async with migrated_engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM schedules WHERE id = :schedule_id"),
                {"schedule_id": schedule_id},
            )

    async with database.session(write=True) as session:
        deleted = await ScheduleControlRepository(session).delete_current(
            project_id=project_id,
            schedule_id=schedule_id,
            occurred_at=third_slot + timedelta(seconds=6),
        )
        assert deleted.disposition == "deleted"
        assert deleted.committed_revision == 5
        assert deleted.evidence_closed == 1
        await session.commit()

    async with database.session() as session:
        state = await session.execute(
            text(
                "SELECT "
                "(SELECT count(*) FROM schedules WHERE id = :schedule_id), "
                "(SELECT count(*) FROM pending_fires "
                " WHERE schedule_id = :schedule_id), "
                "(SELECT count(*) FROM schedule_change_log "
                " WHERE schedule_id = :schedule_id "
                "   AND revision = 5 "
                "   AND change_kind = 'delete' "
                "   AND snapshot IS NULL), "
                "(SELECT count(*) FROM schedule_occurrence_resolutions "
                " WHERE schedule_id = :schedule_id "
                "   AND resolution_disposition = 'SCHEDULE_DELETED')",
            ),
            {"schedule_id": schedule_id},
        )
        assert state.one() == (0, 0, 1, 1)


async def test_exhausted_one_shot_command_keeps_nullable_successor(
    migrated_engine: AsyncEngine,
) -> None:
    """Prepared-next NULL is valid evidence for an exhausted one-shot."""

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    planning_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    definition = _definition()
    definition.update(
        {
            "name": "one-shot",
            "task_name": "jobs.one_shot",
            "kind": "clocked",
            "expression": "2026-07-25T13:00:00+00:00",
        },
    )
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"o-{project_id.hex[:12]}",
                name="One Shot",
            ),
        )
        await session.commit()
    async with database.session(write=True) as session:
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data=definition,
            planning_at=planning_at,
        )
        slot = schedule.next_run_at
        token = schedule.control_token
        digest = schedule.definition_digest
        expected_revision = schedule.schedule_revision
        assert slot is not None
        assert token is not None
        assert digest is not None
        assert expected_revision is not None
        fire_id = derive_scheduler_fire_id(schedule.id, slot)
        transition = await ScheduleControlRepository(
            session,
        ).accept_current_fire_progress(
            project_id=project_id,
            schedule_id=schedule.id,
            fire_id=fire_id,
            scheduled_for=slot,
            observed_control_token=token,
            definition_digest=digest,
            expected_revision=expected_revision,
            expected_last_run_at=None,
            expected_next_run_at=slot,
            prepared_next_run_at=None,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=slot + timedelta(seconds=1),
        )
        assert transition.disposition == "applied"
        assert transition.execution_fire_id is not None
        assert transition.acceptance_revision is not None
        command, created = await CommandRepository(
            session,
        ).insert_current_schedule_fire(
            project_id=project_id,
            agent_id=agent_id,
            schedule_id=schedule.id,
            fire_id=fire_id,
            scheduled_for=slot,
            observed_control_token=token,
            receipt_control_token=token,
            execution_fire_id=transition.execution_fire_id,
            acceptance_revision=transition.acceptance_revision,
            definition_digest=digest,
            expected_revision=expected_revision,
            expected_last_run_at=None,
            expected_next_run_at=slot,
            prepared_next_run_at=None,
            payload={"fire_id": str(transition.execution_fire_id)},
            timeout_at=slot + timedelta(minutes=1),
            initial_claim_deadline=slot + timedelta(minutes=1),
        )
        assert created is True
        assert command.schedule_next_run_at is None
        await session.commit()
