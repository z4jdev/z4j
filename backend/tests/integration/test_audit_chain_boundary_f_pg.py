"""Boundary-F runtime gates that require real PostgreSQL semantics."""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from z4j_brain.audit_retention import AuditRetentionSweeper
from z4j_brain.domain.audit_chain import AuditChainIntegrityError
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.management_reset import (
    GenerationResetRefused,
    build_generation_reset_preview,
    perform_generation_reset,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    Agent,
    AuditChainState,
    AuditLog,
    Event,
    Project,
    ScheduleExternalEpochAllocator,
    ScheduleRevisionState,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.repositories.schedule_external import (
    ScheduleExternalRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.startup import verify_production_authority_at_startup

pytestmark = pytest.mark.asyncio


async def _append(
    engine: AsyncEngine,
    settings: Settings,
    *,
    action: str,
) -> AuditLog:
    service = AuditService(settings)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        row = await service.record(
            AuditLogRepository(session),
            action=action,
            target_type="boundary-f-pg",
        )
        await session.commit()
        return row


async def _verify(
    engine: AsyncEngine,
    settings: Settings,
) -> tuple[object, AuditChainState]:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        report = await verify_active_audit_generation(
            session,
            settings,
            page_size=1,
        )
        state = (await session.execute(select(AuditChainState))).scalar_one()
        return report, state


def _retention_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "audit_retention_days": 1,
            "audit_retention_sweep_batch_size": 100,
            "audit_retention_sweep_max_per_pass": 100,
        },
    )


class _FutureClock(datetime):
    @classmethod
    def now(cls, tz=None):
        future = datetime.now(UTC) + timedelta(days=30)
        return future if tz is not None else future.replace(tzinfo=None)


async def test_append_normalizes_postgres_values_and_startup_verifies(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    service = AuditService(integration_settings)
    async with AsyncSession(migrated_engine, expire_on_commit=False) as session:
        initial_head = (
            await session.execute(
                select(AuditLog).order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(1),
            )
        ).scalar_one()
        assert initial_head.action == "schedule.control_migration_activated"
        row = await service.record(
            AuditLogRepository(session),
            action="project.updated",
            target_type="project",
            target_id=str(uuid.uuid4()),
            source_ip="2001:0db8:0:0:0:0:0:1",
            metadata={
                "z-last": [3, 2, 1],
                "a-first": {"finite": 1.25, "enabled": True},
            },
        )
        await session.commit()

        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert str(row.source_ip) == "2001:db8::1"
        assert row.prev_row_hmac == initial_head.row_hmac
        assert row.chain_generation == state.generation
        assert state.active_row_count == 3
        assert state.head_id == row.id
        assert service.verify_row(row)

    report = await verify_production_authority_at_startup(
        db=DatabaseManager(migrated_engine),
        settings=integration_settings,
    )
    assert report.clean
    assert report.verified_active_rows == 3


async def test_postgres_generation_reset_signs_marker_and_advances_d_barriers(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"generation-reset-{project_id.hex[:12]}",
                name="Generation reset",
            ),
        )
        await session.flush()
        await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data={
                "name": "generation-reset",
                "task_name": "jobs.generation_reset",
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
            planning_at=datetime(2026, 7, 26, 9, 0, tzinfo=UTC),
        )
        await session.commit()

    async with database.session() as session:
        old_state = (await session.execute(select(AuditChainState))).scalar_one()
        old_generation = old_state.generation
        old_installation = old_state.installation_id
        old_revision = int(
            (await session.execute(select(ScheduleRevisionState))).scalar_one().current_revision,
        )
        old_epoch = int(
            (
                await session.execute(
                    select(ScheduleExternalEpochAllocator),
                )
            )
            .scalar_one()
            .current_epoch_number,
        )

    async with database.session(write=True) as session:
        result = await perform_generation_reset(
            session,
            integration_settings,
        )
        await session.commit()

    assert result["new_revision"] == old_revision + 1
    assert result["new_epoch"] == old_epoch + 1
    async with database.session() as session:
        assert (await session.scalar(text("SELECT COUNT(*) FROM projects"))) == 0
        assert (await session.scalar(text("SELECT COUNT(*) FROM schedules"))) == 0
        marker = (await session.execute(select(AuditLog))).scalar_one()
        assert marker.action == "audit.chain_generation_reset"
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert state.generation != old_generation
        assert state.installation_id == old_installation
        assert state.active_row_count == 1
        revision = (await session.execute(select(ScheduleRevisionState))).scalar_one()
        assert revision.current_revision == old_revision + 1
        assert revision.change_log_pruned_through == revision.current_revision
        allocator = (await session.execute(select(ScheduleExternalEpochAllocator))).scalar_one()
        assert allocator.current_epoch_number == old_epoch + 1


async def test_postgres_generation_reset_consumes_exact_external_attestation(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"reset-external-{project_id.hex[:12]}",
                name="Reset external",
            ),
        )
        await session.flush()
        await ScheduleExternalRepository(session).ensure_activation_epoch(
            project_id=project_id,
            owner="celery-beat",
            source_scope="app.beat",
            occurred_at=datetime(2026, 7, 26, 10, 0, tzinfo=UTC),
            adapter_instance_id="pg-reset-adapter",
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation="pg-reset-generation",
            executor_worker_id="pg-reset-worker",
        )
        await session.commit()

    async with database.session() as session:
        old_epoch = int(
            (
                await session.execute(
                    select(ScheduleExternalEpochAllocator),
                )
            )
            .scalar_one()
            .current_epoch_number,
        )

    async with database.session(write=True) as session:
        preview = await build_generation_reset_preview(
            session,
            integration_settings,
        )
        await session.rollback()
    assert preview["requires_stopped_executor_attestation"] is True

    async with database.session(write=True) as session:
        await perform_generation_reset(
            session,
            integration_settings,
            stopped_executor_attestation=preview["stopped_executor_attestation_challenge"],
        )
        await session.commit()

    async with database.session() as session:
        assert (
            await session.scalar(
                text("SELECT COUNT(*) FROM schedule_external_streams"),
            )
        ) == 0
        assert (
            await session.scalar(
                text(
                    "SELECT COUNT(*) FROM schedule_external_stream_epochs",
                ),
            )
        ) == 0
        allocator = (await session.execute(select(ScheduleExternalEpochAllocator))).scalar_one()
        assert allocator.current_epoch_number == old_epoch + 1


async def test_postgres_generation_reset_manifests_and_empties_physical_partition(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    event_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"reset-partition-{project_id.hex[:12]}",
                name="Reset partition",
            ),
        )
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="reset-partition-agent",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=[],
                scheduler_adapters=[],
                capabilities={},
                agent_metadata={},
            ),
        )
        await session.flush()
        session.add(
            Event(
                id=event_id,
                project_id=project_id,
                agent_id=agent_id,
                engine="celery",
                task_id="partition-reset",
                kind="task.received",
                occurred_at=datetime.now(UTC),
                payload={"partition": True},
            ),
        )
        await session.commit()

    async with database.session() as session:
        partition_name = str(
            await session.scalar(
                text(
                    "SELECT tableoid::regclass::text FROM events WHERE id = :event_id",
                ),
                {"event_id": event_id},
            ),
        )

    async with database.session(write=True) as session:
        preview = await build_generation_reset_preview(
            session,
            integration_settings,
        )
        await session.rollback()
    partition = preview["destruction_manifest"]["physical_partitions"][partition_name]
    assert partition["parent"] == "events"
    assert partition["row_count"] == 1
    assert partition["relation_oid"] > 0
    assert partition["parent_relation_oid"] > 0
    assert partition["primary_key_definition"] == ("PRIMARY KEY (project_id, occurred_at, id)")

    async with database.session(write=True) as session:
        await perform_generation_reset(session, integration_settings)
        await session.commit()

    async with database.session() as session:
        assert await session.scalar(text("SELECT COUNT(*) FROM events")) == 0
        assert (
            await session.scalar(
                text(
                    f'SELECT COUNT(*) FROM "{partition_name}"',
                ),
            )
            == 0
        )


async def test_postgres_generation_reset_refuses_schema_signature_drift(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"reset-schema-drift-{project_id.hex[:12]}",
                name="Reset schema drift",
            ),
        )
        await session.commit()
    async with migrated_engine.begin() as connection:
        await connection.execute(text("DROP INDEX ix_projects_active"))

    async with database.session(write=True) as session:
        with pytest.raises(
            GenerationResetRefused,
            match="migration-head schema signature mismatch",
        ):
            await perform_generation_reset(session, integration_settings)
        await session.rollback()

    async with database.session() as session:
        assert (
            await session.scalar(
                select(Project.id).where(Project.id == project_id),
            )
            == project_id
        )


async def test_partition_ddl_paths_share_the_reset_schema_transition_lock(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    from z4j_brain.domain.workers.partition_creator import (
        PartitionCreatorWorker,
    )
    from z4j_brain.domain.workers.schedule_fires_partition import (
        ScheduleFiresPartitionWorker,
    )
    from z4j_brain.schema_transition import (
        SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
    )

    database = DatabaseManager(migrated_engine)
    async with AsyncSession(migrated_engine) as holder:
        await holder.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )

        with pytest.raises(DBAPIError, match="lock timeout"):
            await PartitionCreatorWorker(
                db=database,
                settings=integration_settings,
            ).tick()

        async with database.session() as blocked:
            with pytest.raises(DBAPIError, match="lock timeout"):
                await ScheduleFiresPartitionWorker._prime(blocked)
            await blocked.rollback()

        await holder.rollback()

    async with database.session() as unblocked:
        await ScheduleFiresPartitionWorker._prime(unblocked)
        await unblocked.rollback()


async def test_postgres_guards_mutation_and_attribution_survives_deletes(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    async with AsyncSession(migrated_engine, expire_on_commit=False) as session:
        await session.execute(
            text(
                "INSERT INTO projects (id, slug, name) "
                "VALUES (:id, :slug, 'Boundary F attribution')",
            ),
            {"id": project_id, "slug": f"f-pg-{secrets.token_hex(4)}"},
        )
        await session.execute(
            text(
                "INSERT INTO users (id, email, password_hash) VALUES (:id, :email, 'x')",
            ),
            {
                "id": user_id,
                "email": f"f-pg-{secrets.token_hex(4)}@example.com",
            },
        )
        row = await AuditService(integration_settings).record(
            AuditLogRepository(session),
            action="attribution.preserved",
            target_type="project",
            target_id=str(project_id),
            project_id=project_id,
            user_id=user_id,
        )
        await session.commit()

    async with AsyncSession(migrated_engine) as session:
        with pytest.raises(DBAPIError, match="audit_log is append-only"):
            await session.execute(
                text("DELETE FROM audit_log WHERE id = :id"),
                {"id": row.id},
            )
            await session.commit()
        await session.rollback()

        with pytest.raises(DBAPIError, match="signer-managed"):
            await session.execute(
                text(
                    "UPDATE audit_chain_state SET active_row_count = 0 "
                    "WHERE singleton_id = 'audit-chain'",
                ),
            )
            await session.commit()
        await session.rollback()

        await session.execute(
            text("DELETE FROM projects WHERE id = :id"),
            {"id": project_id},
        )
        await session.execute(
            text("DELETE FROM users WHERE id = :id"),
            {"id": user_id},
        )
        await session.commit()

    async with AsyncSession(migrated_engine) as session:
        attribution = (
            await session.execute(
                text(
                    "SELECT project_id, user_id FROM audit_log WHERE id = :id",
                ),
                {"id": row.id},
            )
        ).one()
        assert attribution == (project_id, user_id)


async def test_startup_rejects_state_tamper_even_via_transition_guc(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("SET LOCAL z4j.audit_transition = 'append-v1'"),
        )
        await conn.execute(
            text(
                "UPDATE audit_chain_state SET state_mac = :mac WHERE singleton_id = 'audit-chain'",
            ),
            {"mac": "0" * 64},
        )

    with pytest.raises(AuditChainIntegrityError, match="state MAC mismatch"):
        await verify_production_authority_at_startup(
            db=DatabaseManager(migrated_engine),
            settings=integration_settings,
        )


async def test_startup_rejects_row_tamper_by_table_owner(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "UPDATE audit_log SET action = 'tampered' "
                "WHERE action = 'audit.chain_generation_started'",
            ),
        )
        await conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER USER"))

    with pytest.raises(
        AuditChainIntegrityError,
        match="Boundary-F startup verification failed",
    ):
        await verify_production_authority_at_startup(
            db=DatabaseManager(migrated_engine),
            settings=integration_settings,
        )


async def test_concurrent_append_and_retention_are_two_serial_orders(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _retention_settings(integration_settings)
    await _append(migrated_engine, settings, action="before.concurrent.1")
    await _append(migrated_engine, settings, action="before.concurrent.2")
    monkeypatch.setattr("z4j_brain.audit_retention.datetime", _FutureClock)

    sweeper = AuditRetentionSweeper()
    sweeper._db = DatabaseManager(migrated_engine)
    sweeper._settings = settings
    deleted, _row = await asyncio.wait_for(
        asyncio.gather(
            sweeper.sweep_once(),
            _append(migrated_engine, settings, action="concurrent.append"),
        ),
        timeout=10,
    )

    report, state = await _verify(migrated_engine, settings)
    assert report.clean
    assert deleted in {4, 5}
    assert state.active_row_count == 5 - deleted


async def test_concurrent_retention_workers_serialize_without_deadlock(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _retention_settings(integration_settings)
    await _append(migrated_engine, settings, action="before.retention.1")
    await _append(migrated_engine, settings, action="before.retention.2")
    monkeypatch.setattr("z4j_brain.audit_retention.datetime", _FutureClock)

    first = AuditRetentionSweeper()
    second = AuditRetentionSweeper()
    db = DatabaseManager(migrated_engine)
    first._db = db
    first._settings = settings
    second._db = db
    second._settings = settings

    deleted = await asyncio.wait_for(
        asyncio.gather(first.sweep_once(), second.sweep_once()),
        timeout=10,
    )

    report, state = await _verify(migrated_engine, settings)
    assert report.clean
    assert sorted(deleted) == [0, 4]
    assert state.active_row_count == 0
    assert state.prune_id == state.head_id
    assert state.prune_row_hmac == state.head_row_hmac
