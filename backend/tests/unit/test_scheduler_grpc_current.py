from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import grpc
import pytest
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.domain.workers.command_timeout import CommandTimeoutWorker
from z4j_brain.domain.workers.pending_fires import PendingFiresReplayWorker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    Command,
    PendingFire,
    Project,
    ScheduleChangeLog,
    ScheduleFire,
    ScheduleRevisionState,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_CHANGE_PROTOCOL_VERSION,
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    CommandRepository,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.protocol import current_capabilities
from z4j_brain.settings import Settings


class RpcAbortError(RuntimeError):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code


class Context:
    def __init__(self) -> None:
        self.is_cancelled = False

    def cancelled(self) -> bool:
        return self.is_cancelled

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        raise RpcAbortError(code, details)

    def auth_context(self) -> dict[str, list[bytes]]:
        return {}


@pytest.fixture
async def current_service() -> AsyncIterator[tuple[SchedulerServiceImpl, DatabaseManager, Project]]:
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    database = DatabaseManager(engine)
    project = Project(id=uuid.uuid4(), slug="current", name="Current")
    async with database.session() as session:
        session.add_all(
            [
                project,
                ScheduleRevisionState(
                    singleton_id=SCHEDULE_REVISION_SINGLETON_ID,
                    current_revision=0,
                    change_log_pruned_through=0,
                ),
            ],
        )
        await session.commit()
        await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data={
                "name": "cleanup",
                "task_name": "jobs.cleanup",
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "kind": "interval",
                "expression": "5m",
                "timezone": "UTC",
                "queue": "maintenance",
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "catch_up": "skip",
            },
            planning_at=datetime(2026, 1, 1, 12, 3, 7, tzinfo=UTC),
        )
        await session.commit()
    audit = AsyncMock()
    dispatcher = AsyncMock()
    service = SchedulerServiceImpl(
        settings=settings,
        db=database,
        command_dispatcher=dispatcher,
        audit_service=audit,
    )
    async with database.session() as session:
        session.add(
            Agent(
                id=uuid.uuid4(),
                project_id=project.id,
                name="current-agent",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()
    yield service, database, project
    await engine.dispose()


async def _only_schedule(database: DatabaseManager):
    from sqlalchemy import select
    from z4j_brain.persistence.models import Schedule

    async with database.session() as session:
        return (await session.execute(select(Schedule))).scalar_one()


def _timestamp(value: datetime) -> Timestamp:
    result = Timestamp()
    result.FromDatetime(value)
    return result


def _current_fire_request(row) -> pb.FireScheduleRequest:
    token = row.control_token
    assert token is not None
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    return pb.FireScheduleRequest(
        schedule_id=str(row.id),
        fire_id=str(derive_scheduler_fire_id(row.id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
        scheduler_protocol_epoch=1,
        observed_control_token=str(token),
        definition_digest=row.definition_digest,
        expected_schedule_revision=row.schedule_revision,
        expected_next_run_at=_timestamp(slot),
        prepared_next_run_at=_timestamp(
            datetime(2026, 1, 1, 12, 10, tzinfo=UTC),
        ),
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )


def _legacy_fire_request(row) -> pb.FireScheduleRequest:
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    return pb.FireScheduleRequest(
        schedule_id=str(row.id),
        fire_id=str(derive_scheduler_fire_id(row.id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
    )


async def test_current_control_denies_tokenless_fire_without_grant(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    row = await _only_schedule(database)

    response = await service.FireSchedule(
        _legacy_fire_request(row),
        Context(),
    )

    assert response.disposition == pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED
    assert response.error_code == "scheduler_upgrade_required"
    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        assert schedule is not None
        assert schedule.schedule_revision == 1
        assert schedule.total_runs == 0
        assert (await session.execute(select(Command))).scalars().all() == []
        assert (await session.execute(select(ScheduleFire))).scalars().all() == []


async def test_granted_tokenless_fire_is_receipt_bound_and_idempotent(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    async with database.session(write=True) as session:
        granted = await ScheduleControlRepository(
            session,
        ).set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=True,
            all_replicas_quiesced_and_resynced=True,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert granted.disposition == "granted"
        await session.commit()

    request = _legacy_fire_request(row)
    response = await service.FireSchedule(request, Context())
    assert response.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert response.command_id
    async with database.session(write=True) as session:
        schedule = await session.get(type(row), row.id)
        command = (await session.execute(select(Command))).scalar_one()
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert schedule.control_token == token
        assert schedule.legacy_fire_control_token == token
        assert schedule.schedule_revision == 3
        assert schedule.total_runs == 1
        assert schedule.last_run_at.replace(tzinfo=UTC) == datetime(
            2026,
            1,
            1,
            12,
            5,
            tzinfo=UTC,
        )
        assert schedule.next_run_at.replace(tzinfo=UTC) == datetime(
            2026,
            1,
            1,
            12,
            10,
            tzinfo=UTC,
        )
        assert command.schedule_observed_control_token is None
        assert command.schedule_receipt_control_token == token
        assert command.schedule_execution_fire_id is not None
        assert command.payload["fire_id"] == str(
            command.schedule_execution_fire_id,
        )
        assert fire.observed_control_token is None
        assert fire.receipt_control_token == token
        command.status = CommandStatus.DISPATCHED
        await session.commit()

    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    replay = await service.FireSchedule(request, Context())
    assert replay.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert replay.command_id == response.command_id
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]
    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        assert schedule is not None
        assert schedule.schedule_revision == 3
        assert schedule.total_runs == 1
        assert (
            len(
                (await session.execute(select(Command))).scalars().all(),
            )
            == 1
        )
        assert (
            len(
                (await session.execute(select(ScheduleFire))).scalars().all(),
            )
            == 1
        )


async def test_granted_tokenless_buffer_replays_without_progress_twice(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    async with database.session(write=True) as session:
        granted = await ScheduleControlRepository(
            session,
        ).set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=True,
            all_replicas_quiesced_and_resynced=True,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert granted.disposition == "granted"
        await session.execute(
            update(Agent).values(state=AgentState.OFFLINE),
        )
        await session.commit()

    response = await service.FireSchedule(
        _legacy_fire_request(row),
        Context(),
    )
    assert response.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert response.buffered is True
    async with database.session() as session:
        pending = (await session.execute(select(PendingFire))).scalar_one()
        schedule = await session.get(type(row), row.id)
        assert schedule is not None
        assert pending.observed_control_token is None
        assert pending.receipt_control_token == token
        assert schedule.schedule_revision == 3
        assert schedule.total_runs == 1

    async with database.session(write=True) as session:
        await session.execute(
            update(Agent).values(state=AgentState.ONLINE),
        )
        await session.commit()
    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    await worker.tick()

    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        command = (await session.execute(select(Command))).scalar_one()
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert schedule.schedule_revision == 3
        assert schedule.total_runs == 1
        assert command.schedule_observed_control_token is None
        assert command.schedule_receipt_control_token == token
        assert fire.command_id == command.id
        assert (await session.execute(select(PendingFire))).scalars().all() == []
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_awaited_once()  # type: ignore[union-attr]


async def test_revoked_tokenless_buffer_is_staled_without_delivery(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    async with database.session(write=True) as session:
        granted = await ScheduleControlRepository(
            session,
        ).set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=True,
            all_replicas_quiesced_and_resynced=True,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert granted.disposition == "granted"
        await session.execute(
            update(Agent).values(state=AgentState.OFFLINE),
        )
        await session.commit()

    accepted = await service.FireSchedule(
        _legacy_fire_request(row),
        Context(),
    )
    assert accepted.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert accepted.buffered is True

    async with database.session(write=True) as session:
        revoked = await ScheduleControlRepository(
            session,
        ).set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=False,
            all_replicas_quiesced_and_resynced=False,
            occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
        )
        assert revoked.disposition == "revoked"
        await session.execute(
            update(Agent).values(state=AgentState.ONLINE),
        )
        await session.commit()

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    await worker.tick()

    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert schedule.control_token == token
        assert schedule.legacy_fire_control_token is None
        assert schedule.schedule_revision == 4
        assert schedule.total_runs == 1
        assert fire.status == "buffer_stale"
        assert fire.error_code == "stale_control"
        assert (await session.execute(select(PendingFire))).scalars().all() == []
        assert (await session.execute(select(Command))).scalars().all() == []
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]


async def test_granted_tokenless_terminal_resolution_carries_grant_one_generation(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    async with database.session(write=True) as session:
        granted = await ScheduleControlRepository(
            session,
        ).set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=True,
            all_replicas_quiesced_and_resynced=True,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert granted.disposition == "granted"
        await session.commit()

    request = _legacy_fire_request(row)
    accepted = await service.FireSchedule(request, Context())
    assert accepted.disposition == pb.FireDisposition.FIRE_ACCEPTED
    async with database.session(write=True) as session:
        command = (await session.execute(select(Command))).scalar_one()
        command.status = CommandStatus.FAILED
        command.error = "legacy result may have executed"
        await session.commit()

    classified = await service._classify_current_fire_command(
        command_id=command.id,
    )
    assert classified.disposition == pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS
    assert classified.error_code == "operator_resolution_required"
    async with database.session() as session:
        assert (await session.execute(select(ScheduleTerminalHold))).scalars().all() == []

    actor = uuid.uuid4()
    async with database.session(write=True) as session:
        resolved = await ScheduleControlRepository(
            session,
        ).resolve_terminal_occurrence(
            project_id=project.id,
            schedule_id=row.id,
            fire_id=command.schedule_fire_id,
            command_id=command.id,
            expected_status=CommandStatus.FAILED,
            observed_control_token=token,
            resolved_by=actor,
            work_may_have_executed=True,
            enabled_after_resolution=False,
            occurred_at=datetime(2026, 1, 1, 12, 7, tzinfo=UTC),
        )
        assert resolved.disposition == "resolved"
        assert resolved.grant_carried is True
        new_token = resolved.schedule.control_token
        assert resolved.schedule.is_enabled is False
        assert resolved.schedule.legacy_fire_control_token == new_token
        await session.commit()

    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    consumed = await service.FireSchedule(request, Context())
    assert consumed.disposition == pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH
    assert consumed.buffered is True
    assert consumed.command_id == ""
    assert consumed.live_control_token == str(new_token)
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]
    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        assert schedule is not None
        assert schedule.total_runs == 1
        assert (
            len(
                (await session.execute(select(Command))).scalars().all(),
            )
            == 1
        )


async def test_current_fire_commits_progress_and_complete_evidence_once(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    prepared = datetime(2026, 1, 1, 12, 10, tzinfo=UTC)
    request = _current_fire_request(row)

    first = await service.FireSchedule(request, Context())
    replay = await service.FireSchedule(request, Context())

    assert first.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert first.acceptance_revision == 2
    assert first.command_id
    assert first.buffered is False
    assert replay.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert replay.acceptance_revision == first.acceptance_revision
    assert replay.command_id == first.command_id
    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        assert schedule is not None
        assert schedule.last_run_at.replace(tzinfo=UTC) == slot
        assert schedule.next_run_at.replace(tzinfo=UTC) == prepared
        assert schedule.total_runs == 1
        commands = list((await session.execute(select(Command))).scalars())
        fires = list((await session.execute(select(ScheduleFire))).scalars())
        pending = list((await session.execute(select(PendingFire))).scalars())
        assert len(commands) == 1
        assert len(fires) == 1
        assert pending == []
        command = commands[0]
        fire = fires[0]
        assert command.id == uuid.UUID(first.command_id)
        assert command.schedule_receipt_control_token == token
        assert command.schedule_acceptance_revision == 2
        assert command.schedule_execution_fire_id is not None
        assert command.payload["fire_id"] == str(command.schedule_execution_fire_id)
        assert fire.command_id == command.id
        assert fire.receipt_control_token == token
        assert fire.acceptance_revision == 2


async def test_current_fire_buffers_same_complete_acceptance_without_agent(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    row = await _only_schedule(database)
    token = row.control_token
    assert token is not None
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()

    response = await service.FireSchedule(_current_fire_request(row), Context())

    assert response.disposition == pb.FireDisposition.FIRE_ACCEPTED
    assert response.buffered is True
    assert response.command_id == ""
    assert response.acceptance_revision == 2
    async with database.session() as session:
        commands = list((await session.execute(select(Command))).scalars())
        fires = list((await session.execute(select(ScheduleFire))).scalars())
        pending = list((await session.execute(select(PendingFire))).scalars())
        schedule = await session.get(type(row), row.id)
        assert commands == []
        assert len(fires) == 1
        assert len(pending) == 1
        assert schedule is not None
        assert schedule.total_runs == 1
        assert pending[0].receipt_control_token == token
        assert pending[0].acceptance_revision == response.acceptance_revision
        assert pending[0].execution_fire_id is not None
        assert pending[0].payload["fire_id"] == str(pending[0].execution_fire_id)
        assert fires[0].receipt_control_token == token


async def test_current_pending_replay_copies_acceptance_without_progress_twice(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="z4j.brain.workers.pending_fires")
    service, database, _project = current_service
    original = await _only_schedule(database)
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()
    request = _current_fire_request(original)
    accepted = await service.FireSchedule(request, Context())
    assert accepted.buffered is True
    async with database.session() as session:
        pending = (await session.execute(select(PendingFire))).scalar_one()
        pending_id = pending.id
        pending_nonce = pending.state_write_nonce
        execution_fire_id = pending.execution_fire_id
        await session.execute(update(Agent).values(state=AgentState.ONLINE))
        await session.commit()

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    await worker.tick()

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        commands = list((await session.execute(select(Command))).scalars())
        fires = list((await session.execute(select(ScheduleFire))).scalars())
        pending_rows = list(
            (await session.execute(select(PendingFire))).scalars(),
        )
        assert schedule is not None
        assert len(commands) == 1
        assert len(fires) == 1
        assert pending_rows == []
        command = commands[0]
        fire = fires[0]
        assert command.status == CommandStatus.PENDING
        assert command.schedule_execution_fire_id == execution_fire_id
        assert command.schedule_acceptance_revision == (accepted.acceptance_revision)
        assert command.schedule_receipt_control_token == original.control_token
        assert command.payload["fire_id"] == str(execution_fire_id)
        assert command.cadence_initial_claim_deadline is not None
        assert fire.command_id == command.id
        assert fire.status == "accepted"
        assert schedule.total_runs == 1
        assert schedule.schedule_revision == accepted.acceptance_revision
        assert pending_id is not None
        assert pending_nonce is not None
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_awaited_once()  # type: ignore[union-attr]

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    await worker.tick()
    service._audit.record.assert_not_awaited()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]
    async with database.session() as session:
        assert (
            len(
                list((await session.execute(select(Command))).scalars()),
            )
            == 1
        )


async def test_current_pending_expiry_is_audited_no_execution_disposition(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()
    request = _current_fire_request(original)
    accepted = await service.FireSchedule(request, Context())
    async with database.session() as session:
        pending = (await session.execute(select(PendingFire))).scalar_one()
        expiry = pending.expires_at.replace(tzinfo=UTC)

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    await worker.tick(now=expiry + timedelta(microseconds=1))

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert (await session.execute(select(PendingFire))).scalars().all() == []
        assert (await session.execute(select(Command))).scalars().all() == []
        assert (await session.execute(select(ScheduleTerminalHold))).scalars().all() == []
        assert fire.status == "buffer_expired"
        assert fire.error_code == "buffer_expired"
        assert schedule.total_runs == 1
        assert schedule.schedule_revision == accepted.acceptance_revision
        assert schedule.last_cadence_acceptance_fire_id == fire.fire_id
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    retried = await service.FireSchedule(request, Context())
    assert retried.disposition == pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH
    assert retried.buffered is True
    assert retried.command_id == ""
    service._audit.record.assert_not_awaited()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]


async def test_current_pending_replay_resolves_stale_receipt_without_delivery(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    async with database.session(write=True) as session:
        repaired = await ScheduleControlRepository(session).update_current(
            project_id=project.id,
            schedule_id=original.id,
            data={"kwargs": {"generation": "repaired"}},
            planning_at=datetime.now(UTC),
        )
        assert repaired is not None
        assert repaired.control_token != original.control_token
        await session.execute(update(Agent).values(state=AgentState.ONLINE))
        await session.commit()

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.reset_mock()  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    await worker.tick()

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert schedule.schedule_revision == accepted.acceptance_revision + 1
        assert schedule.total_runs == 1
        assert fire.status == "buffer_stale"
        assert fire.error_code == "stale_control"
        assert (await session.execute(select(PendingFire))).scalars().all() == []
        assert (await session.execute(select(Command))).scalars().all() == []
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    service._dispatcher.deliver_persisted.assert_not_awaited()  # type: ignore[union-attr]


async def test_current_pending_expiry_audit_failure_rolls_back_disposition(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()
    await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    async with database.session() as session:
        pending = (await session.execute(select(PendingFire))).scalar_one()
        expiry = pending.expires_at.replace(tzinfo=UTC)

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._audit.record.side_effect = RuntimeError("audit unavailable")  # type: ignore[union-attr]
    worker = PendingFiresReplayWorker(
        db=database,
        dispatcher=service._dispatcher,
        audit=service._audit,
        command_timeout_seconds=60,
    )
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await worker.tick(now=expiry + timedelta(microseconds=1))

    async with database.session() as session:
        assert (
            len(
                list((await session.execute(select(PendingFire))).scalars()),
            )
            == 1
        )
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert fire.status == "buffered"
        assert fire.error_code is None
        assert (await session.execute(select(Command))).scalars().all() == []


async def test_scheduler_ack_is_history_only_for_receipt_bound_command(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    fire_id = derive_scheduler_fire_id(
        original.id,
        datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
    )

    with pytest.raises(RpcAbortError) as caught:
        await service.AcknowledgeFireResult(
            pb.AcknowledgeFireResultRequest(
                fire_id=str(fire_id),
                command_id=str(uuid.uuid4()),
                status="success",
            ),
            Context(),
        )
    assert caught.value.code is grpc.StatusCode.FAILED_PRECONDITION

    await service.AcknowledgeFireResult(
        pb.AcknowledgeFireResultRequest(
            fire_id=str(fire_id),
            command_id=accepted.command_id,
            status="success",
            new_task_id="task-from-round-trip",
        ),
        Context(),
    )
    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        command = await session.get(Command, uuid.UUID(accepted.command_id))
        assert command is not None
        fire = (
            await session.execute(
                select(ScheduleFire).where(
                    ScheduleFire.command_id == command.id,
                ),
            )
        ).scalar_one()
        change_count = len(
            list((await session.execute(select(ScheduleChangeLog))).scalars()),
        )
        assert schedule is not None
        assert schedule.last_run_at.replace(tzinfo=UTC) == datetime(
            2026,
            1,
            1,
            12,
            5,
            tzinfo=UTC,
        )
        assert schedule.next_run_at.replace(tzinfo=UTC) == datetime(
            2026,
            1,
            1,
            12,
            10,
            tzinfo=UTC,
        )
        assert schedule.total_runs == 1
        assert schedule.schedule_revision == accepted.acceptance_revision
        assert change_count == 2
        assert command.status == CommandStatus.PENDING
        assert command.completed_at is None
        assert fire.status == "accepted"
        assert fire.acked_at is None
        assert fire.scheduler_ack_status == "success"
        assert fire.scheduler_acknowledged_at is not None
        assert fire.scheduler_ack_task_id == "task-from-round-trip"
        assert (await session.execute(select(ScheduleTerminalHold))).scalars().all() == []


async def test_scheduler_ack_without_command_is_limited_to_buffered_history(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    async with database.session() as session:
        await session.execute(update(Agent).values(state=AgentState.OFFLINE))
        await session.commit()
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    assert accepted.buffered is True
    assert accepted.command_id == ""
    fire_id = derive_scheduler_fire_id(
        original.id,
        datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
    )

    await service.AcknowledgeFireResult(
        pb.AcknowledgeFireResultRequest(
            fire_id=str(fire_id),
            status="success",
        ),
        Context(),
    )

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert schedule is not None
        assert schedule.total_runs == 1
        assert schedule.schedule_revision == accepted.acceptance_revision
        assert fire.command_id is None
        assert fire.status == "buffered"
        assert fire.acked_at is None
        assert fire.scheduler_ack_status == "success"


async def test_migrated_legacy_ack_is_history_only_after_activation(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    schedule = await _only_schedule(database)
    fire_id = derive_scheduler_fire_id(
        schedule.id,
        datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
    )
    original_nonce = uuid.uuid4()
    async with database.session() as session:
        session.add(
            ScheduleFire(
                id=uuid.uuid4(),
                fire_id=fire_id,
                schedule_id=schedule.id,
                project_id=project.id,
                command_id=None,
                status="failed",
                scheduled_for=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
                fired_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
                protocol_marker=1,
                state_write_nonce=original_nonce,
            ),
        )
        await session.commit()

    await service.AcknowledgeFireResult(
        pb.AcknowledgeFireResultRequest(
            fire_id=str(fire_id),
            status="success",
            new_task_id="legacy-round-trip",
        ),
        Context(),
    )

    async with database.session() as session:
        retained_schedule = await session.get(type(schedule), schedule.id)
        fire = (await session.execute(select(ScheduleFire))).scalar_one()
        assert retained_schedule is not None
        assert retained_schedule.schedule_revision == 1
        assert retained_schedule.last_run_at is None
        assert retained_schedule.total_runs == 0
        assert fire.status == "failed"
        assert fire.acked_at is None
        assert fire.scheduler_ack_status == "success"
        assert fire.scheduler_ack_task_id == "legacy-round-trip"
        assert fire.state_write_nonce != original_nonce


@pytest.mark.parametrize(
    ("result_status", "expected_status", "expect_hold"),
    [
        ("success", CommandStatus.COMPLETED, False),
        ("failed", CommandStatus.FAILED, True),
    ],
)
async def test_agent_receipts_own_current_terminal_state(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
    result_status: str,
    expected_status: CommandStatus,
    expect_hold: bool,
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    owner = uuid.uuid4()
    generation = str(uuid.uuid4())
    dispatcher = CommandDispatcher(
        settings=service._settings,
        registry=AsyncMock(),
        audit=service._audit,
    )
    service._audit.record.reset_mock()  # type: ignore[union-attr]

    async with database.session() as session:
        candidate = await session.get(Command, command_id)
        assert candidate is not None
        assert candidate.agent_id is not None
        is_current, command = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project.id,
            agent_id=candidate.agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            timeout_seconds=60,
        )
        assert is_current is True
        assert command is not None
        assert command.agent_id is not None
        assert command.delivery_claim_token is not None
        agent_id = command.agent_id
        claim_token = str(command.delivery_claim_token)
        await dispatcher.handle_ack(
            commands=CommandRepository(session),
            command_id=command_id,
            project_id=project.id,
            agent_id=agent_id,
            # A current token may correlate a buffered ACK after reconnect.
            transport_kind="websocket",
            registry_owner_id=uuid.uuid4(),
            session_generation=str(uuid.uuid4()),
            delivery_claim_token=claim_token,
        )
        await session.commit()

    async with database.session() as session:
        acknowledged = await session.get(Command, command_id)
        assert acknowledged is not None
        assert acknowledged.status == CommandStatus.DISPATCHED
        assert acknowledged.agent_acknowledged_at is not None
        is_current, recovery_after_ack = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            timeout_seconds=60,
            occurred_at=datetime.now(UTC) + timedelta(seconds=11),
        )
        assert is_current is True
        assert recovery_after_ack is None
        await dispatcher.handle_result(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            command_id=command_id,
            status=result_status,
            result_payload={"task_id": "executed"},
            error=("engine rejected task" if expect_hold else None),
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=uuid.uuid4(),
            session_generation=str(uuid.uuid4()),
            delivery_claim_token=claim_token,
        )
        await session.commit()

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        command = await session.get(Command, command_id)
        fire = (
            await session.execute(
                select(ScheduleFire).where(
                    ScheduleFire.command_id == command_id,
                ),
            )
        ).scalar_one()
        holds = list(
            (await session.execute(select(ScheduleTerminalHold))).scalars(),
        )
        assert schedule is not None
        assert command is not None
        assert command.status == expected_status
        assert command.completed_at is not None
        assert fire.status == f"terminal_{expected_status.value}"
        assert len(holds) == (1 if expect_hold else 0)
        assert schedule.is_enabled is (not expect_hold)
        assert schedule.total_runs == 1
        assert schedule.schedule_revision == (
            accepted.acceptance_revision + (1 if expect_hold else 0)
        )
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]


async def test_current_agent_result_rejects_replacement_without_claim_token(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    owner = uuid.uuid4()
    generation = str(uuid.uuid4())
    dispatcher = CommandDispatcher(
        settings=service._settings,
        registry=AsyncMock(),
        audit=service._audit,
    )
    async with database.session() as session:
        candidate = await session.get(Command, command_id)
        assert candidate is not None
        assert candidate.agent_id is not None
        agent_id = candidate.agent_id
        is_current, claimed = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            timeout_seconds=60,
        )
        assert is_current is True
        assert claimed is not None
        assert claimed.delivery_claim_token is not None
        claim_token = str(claimed.delivery_claim_token)
        await session.commit()

    async with database.session() as session:
        await dispatcher.handle_result(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            command_id=command_id,
            status="timeout",
            result_payload=None,
            error="invalid current-cadence result status",
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            delivery_claim_token=claim_token,
        )
        await session.commit()
    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.status == CommandStatus.DISPATCHED

    async with database.session() as session:
        await dispatcher.handle_result(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            command_id=command_id,
            status="failed",
            result_payload=None,
            error="replacement tried to claim result",
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=uuid.uuid4(),
            session_generation=str(uuid.uuid4()),
            delivery_claim_token=None,
        )
        await session.commit()

    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.status == CommandStatus.DISPATCHED
        assert (await session.execute(select(ScheduleTerminalHold))).scalars().all() == []


async def test_cadence_timeout_worker_records_never_claimed_terminal_hold_once(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.cadence_initial_claim_deadline is not None
        deadline = command.cadence_initial_claim_deadline.replace(tzinfo=UTC)

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    worker = CommandTimeoutWorker(database, audit=service._audit)
    await worker.tick(now=deadline + timedelta(microseconds=1))

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        command = await session.get(Command, command_id)
        fire = (
            await session.execute(
                select(ScheduleFire).where(
                    ScheduleFire.command_id == command_id,
                ),
            )
        ).scalar_one()
        holds = list(
            (await session.execute(select(ScheduleTerminalHold))).scalars(),
        )
        assert schedule is not None
        assert command is not None
        assert command.status == CommandStatus.TIMEOUT
        assert command.first_delivery_claimed_at is None
        assert command.delivery_claim_token is None
        assert command.error is not None
        assert "before any send" in command.error
        assert fire.status == "terminal_timeout"
        assert fire.error_code == "initial_claim_timeout"
        assert len(holds) == 1
        assert holds[0].terminal_status == CommandStatus.TIMEOUT.value
        assert schedule.is_enabled is False
        hold_revision = schedule.schedule_revision
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    await worker.tick(now=deadline + timedelta(minutes=1))
    service._audit.record.assert_not_awaited()  # type: ignore[union-attr]
    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        assert schedule is not None
        assert schedule.schedule_revision == hold_revision
        assert (
            len(
                list(
                    (await session.execute(select(ScheduleTerminalHold))).scalars(),
                ),
            )
            == 1
        )


async def test_cadence_timeout_worker_terminalizes_claimed_ambiguity(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    owner = uuid.uuid4()
    generation = str(uuid.uuid4())
    async with database.session() as session:
        candidate = await session.get(Command, command_id)
        assert candidate is not None
        assert candidate.agent_id is not None
        assert candidate.cadence_initial_claim_deadline is not None
        claim_at = candidate.cadence_initial_claim_deadline.replace(
            tzinfo=UTC,
        ) - timedelta(seconds=1)
        is_current, claimed = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project.id,
            agent_id=candidate.agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            timeout_seconds=60,
            occurred_at=claim_at,
        )
        assert is_current is True
        assert claimed is not None
        assert claimed.cadence_redelivery_deadline is not None
        deadline = claimed.cadence_redelivery_deadline.replace(tzinfo=UTC)
        await session.commit()

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    worker = CommandTimeoutWorker(database, audit=service._audit)
    await worker.tick(now=deadline + timedelta(microseconds=1))

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        command = await session.get(Command, command_id)
        fire = (
            await session.execute(
                select(ScheduleFire).where(
                    ScheduleFire.command_id == command_id,
                ),
            )
        ).scalar_one()
        assert schedule is not None
        assert command is not None
        assert command.status == CommandStatus.TIMEOUT
        assert command.first_delivery_claimed_at is not None
        assert command.first_delivery_claimed_at.replace(tzinfo=UTC) == claim_at
        assert command.error is not None
        assert "without an authenticated agent result" in command.error
        assert fire.error_code == "delivery_ambiguous_timeout"
        assert schedule.is_enabled is False
        assert (
            len(
                list(
                    (await session.execute(select(ScheduleTerminalHold))).scalars(),
                ),
            )
            == 1
        )
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]


async def test_cadence_recovery_worker_targets_only_frozen_websocket_owner(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    owner = uuid.uuid4()
    generation = str(uuid.uuid4())
    async with database.session() as session:
        candidate = await session.get(Command, command_id)
        assert candidate is not None
        assert candidate.agent_id is not None
        assert candidate.cadence_initial_claim_deadline is not None
        agent_id = candidate.agent_id
        claim_at = candidate.cadence_initial_claim_deadline.replace(
            tzinfo=UTC,
        ) - timedelta(seconds=50)
        is_current, claimed = await CommandRepository(
            session,
        ).claim_current_schedule_delivery(
            command_id,
            project_id=project.id,
            agent_id=agent_id,
            transport_kind="websocket",
            registry_owner_id=owner,
            session_generation=generation,
            timeout_seconds=60,
            occurred_at=claim_at,
        )
        assert is_current is True
        assert claimed is not None
        await session.commit()

    registry = AsyncMock()
    registry.deliver_frozen.return_value = True
    service._audit.record.reset_mock()  # type: ignore[union-attr]
    worker = CommandTimeoutWorker(
        database,
        audit=service._audit,
        registry=registry,
    )
    await worker.tick(now=claim_at + timedelta(seconds=11))

    registry.deliver_frozen.assert_awaited_once_with(
        command_id=command_id,
        agent_id=agent_id,
        registry_owner_id=owner,
        session_generation=generation,
    )
    service._audit.record.assert_not_awaited()  # type: ignore[union-attr]
    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.status == CommandStatus.DISPATCHED


async def test_cadence_timeout_audit_failure_rolls_back_entire_transition(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, _project = current_service
    original = await _only_schedule(database)
    accepted = await service.FireSchedule(
        _current_fire_request(original),
        Context(),
    )
    command_id = uuid.UUID(accepted.command_id)
    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.cadence_initial_claim_deadline is not None
        deadline = command.cadence_initial_claim_deadline.replace(tzinfo=UTC)

    service._audit.record.reset_mock()  # type: ignore[union-attr]
    service._audit.record.side_effect = RuntimeError("audit unavailable")  # type: ignore[union-attr]
    worker = CommandTimeoutWorker(database, audit=service._audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await worker.tick(now=deadline + timedelta(microseconds=1))

    async with database.session() as session:
        schedule = await session.get(type(original), original.id)
        command = await session.get(Command, command_id)
        fire = (
            await session.execute(
                select(ScheduleFire).where(
                    ScheduleFire.command_id == command_id,
                ),
            )
        ).scalar_one()
        assert schedule is not None
        assert command is not None
        assert command.status == CommandStatus.PENDING
        assert command.completed_at is None
        assert schedule.is_enabled is True
        assert schedule.schedule_revision == accepted.acceptance_revision
        assert fire.status == "accepted"
        assert (await session.execute(select(ScheduleTerminalHold))).scalars().all() == []


@pytest.mark.parametrize(
    ("status", "expected_disposition", "terminal"),
    [
        (CommandStatus.PENDING, pb.FireDisposition.FIRE_ACCEPTED, False),
        (CommandStatus.DISPATCHED, pb.FireDisposition.FIRE_ACCEPTED, False),
        (CommandStatus.COMPLETED, pb.FireDisposition.FIRE_ACCEPTED, False),
        (
            CommandStatus.FAILED,
            pb.FireDisposition.FIRE_TERMINAL_QUARANTINED,
            True,
        ),
        (
            CommandStatus.CANCELLED,
            pb.FireDisposition.FIRE_TERMINAL_QUARANTINED,
            True,
        ),
        (
            CommandStatus.TIMEOUT,
            pb.FireDisposition.FIRE_TERMINAL_QUARANTINED,
            True,
        ),
    ],
)
async def test_current_fire_replay_table_is_exhaustive(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
    status: CommandStatus,
    expected_disposition: int,
    terminal: bool,
) -> None:
    service, database, _project = current_service
    row = await _only_schedule(database)
    request = _current_fire_request(row)
    accepted = await service.FireSchedule(request, Context())
    command_id = uuid.UUID(accepted.command_id)
    async with database.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        command.status = status
        if status == CommandStatus.DISPATCHED:
            command.dispatched_at = datetime.now(UTC)
        if terminal:
            command.error = f"{status.value} evidence"
        await session.commit()

    replay = await service.FireSchedule(request, Context())
    repeated = await service.FireSchedule(request, Context())

    assert replay.disposition == expected_disposition
    assert repeated.disposition == expected_disposition
    assert replay.command_id == accepted.command_id
    assert replay.acceptance_revision == accepted.acceptance_revision
    expected_delivery_attempts = 3 if status == CommandStatus.PENDING else 1
    assert service._dispatcher.deliver_persisted.await_count == expected_delivery_attempts
    async with database.session() as session:
        schedule = await session.get(type(row), row.id)
        commands = list((await session.execute(select(Command))).scalars())
        fires = list((await session.execute(select(ScheduleFire))).scalars())
        holds = list(
            (await session.execute(select(ScheduleTerminalHold))).scalars(),
        )
        assert schedule is not None
        assert len(commands) == 1
        assert len(fires) == 1
        assert len(holds) == (1 if terminal else 0)
        assert schedule.is_enabled is (not terminal)
        assert schedule.total_runs == 1
        if terminal:
            assert fires[0].status == f"terminal_{status.value}"
            assert holds[0].terminal_status == status.value


async def test_ping_and_negotiation_advertise_only_active_exact_tuple(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, _, _ = current_service
    context = Context()

    ping = await service.Ping(pb.PingRequest(), context)
    assert ping.scheduler_protocol_epoch == 1
    response = await service.NegotiateSchedulerProtocol(
        pb.NegotiateSchedulerProtocolRequest(offered=current_capabilities()),
        context,
    )
    assert response.selected == current_capabilities()

    mismatched = current_capabilities()
    mismatched.cadence_runtime_fingerprint = "wrong"
    with pytest.raises(RpcAbortError) as caught:
        await service.NegotiateSchedulerProtocol(
            pb.NegotiateSchedulerProtocolRequest(offered=mismatched),
            context,
        )
    assert caught.value.code is grpc.StatusCode.FAILED_PRECONDITION


async def test_legacy_list_never_leaks_partial_current_shape(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, _, project = current_service

    rows = [
        row
        async for row in service.ListSchedules(
            pb.ListSchedulesRequest(project_id=str(project.id)),
            Context(),
        )
    ]

    assert len(rows) == 1
    assert rows[0].control_token == ""
    assert rows[0].schedule_revision == 0
    assert rows[0].definition_digest == ""
    assert rows[0].cadence_semantics_version == 0
    assert rows[0].cadence_runtime_fingerprint == ""


async def test_stable_snapshot_is_complete_current_shape(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, _, project = current_service
    frames = [
        frame
        async for frame in service.ListScheduleSnapshot(
            pb.ListScheduleSnapshotRequest(
                project_id=str(project.id),
                page_size=100,
                snapshot_format_version=1,
            ),
            Context(),
        )
    ]

    assert [frame.WhichOneof("frame") for frame in frames] == [
        "header",
        "row",
        "complete",
    ]
    schedule = frames[1].row.schedule
    assert schedule.control_token
    assert schedule.schedule_revision == 1
    assert schedule.definition_digest
    assert schedule.cadence_semantics_version == CADENCE_SEMANTICS_VERSION
    assert schedule.cadence_runtime_fingerprint == cadence_runtime_fingerprint()
    assert frames[-1].complete.watermark == 1
    assert frames[-1].complete.row_count == 1
    assert len(frames[-1].complete.digest) == 64


async def test_all_project_snapshot_uses_blank_scope_and_current_rows(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, _, project = current_service
    frames = [
        frame
        async for frame in service.ListScheduleSnapshot(
            pb.ListScheduleSnapshotRequest(
                project_id="",
                page_size=100,
                snapshot_format_version=1,
            ),
            Context(),
        )
    ]

    assert frames[0].header.project_id == ""
    assert frames[-1].complete.project_id == ""
    assert frames[-1].complete.row_count == 1
    assert frames[1].row.schedule.project_id == str(project.id)
    assert frames[1].row.schedule.control_token
    assert frames[1].row.schedule.schedule_revision == 1

    # Decode the actual Brain bytes through the independently implemented
    # scheduler framing/digest path. This proves the production all-scope wire
    # carries current authority rather than only checking Brain-side objects.
    from z4j_scheduler.proto import scheduler_pb2 as scheduler_pb
    from z4j_scheduler.storage._snapshot_wire import SnapshotAssembler

    assembler = SnapshotAssembler(expected_project_id=None)
    for frame in frames:
        assembler.accept(
            scheduler_pb.ScheduleSnapshotFrame.FromString(
                frame.SerializeToString(),
            ),
        )
    decoded = assembler.finish()
    assert decoded.project_id is None
    assert decoded.rows[0].control_token is not None
    assert decoded.rows[0].schedule_revision == 1


async def test_all_project_current_stream_is_cn_binding_filtered(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    other = Project(id=uuid.uuid4(), slug="other", name="Other")
    async with database.session() as session:
        session.add(other)
        await session.commit()
        await ScheduleControlRepository(session).create_current(
            project_id=other.id,
            data={
                "name": "other-cleanup",
                "task_name": "jobs.cleanup",
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "kind": "interval",
                "expression": "5m",
                "timezone": "UTC",
                "queue": "maintenance",
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "catch_up": "skip",
            },
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        await session.commit()

    service._settings.scheduler_grpc_cn_project_bindings.update(
        {"bound-scheduler": [project.slug]},
    )

    class BoundContext(Context):
        def auth_context(self) -> dict[str, list[bytes]]:
            return {"x509_common_name": [b"bound-scheduler"]}

    frames = [
        frame
        async for frame in service.ListScheduleSnapshot(
            pb.ListScheduleSnapshotRequest(
                project_id="",
                snapshot_format_version=1,
            ),
            BoundContext(),
        )
    ]
    assert frames[-1].complete.row_count == 1
    assert frames[1].row.schedule.project_id == str(project.id)

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id="",
            after_revision=0,
            watch_format_version=1,
        ),
        BoundContext(),
    )
    first = await anext(stream)
    second = await anext(stream)
    await stream.aclose()
    assert first.WhichOneof("frame") == "change"
    assert first.change.project_id == str(project.id)
    assert second.WhichOneof("frame") == "scanned_through"
    assert second.scanned_through.scanned_through_revision == 2


async def test_quarantine_rpc_is_durable_token_cas_and_effectively_disables(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    assert row.control_token is not None

    response = await service.QuarantineSchedule(
        pb.QuarantineScheduleRequest(
            project_id=str(project.id),
            schedule_id=str(row.id),
            observed_control_token=str(row.control_token),
            reason_code="cadence_definition_invalid",
            detail="bad\ninterval",
            scheduler_protocol_epoch=1,
        ),
        Context(),
    )

    assert response.outcome == pb.QuarantineOutcome.QUARANTINE_APPLIED
    assert response.observed_revision == 2
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    replay = await service.QuarantineSchedule(
        pb.QuarantineScheduleRequest(
            project_id=str(project.id),
            schedule_id=str(row.id),
            observed_control_token=str(row.control_token),
            reason_code="cadence_definition_invalid",
            detail="bad\ninterval",
            scheduler_protocol_epoch=1,
        ),
        Context(),
    )
    assert replay.outcome == pb.QuarantineOutcome.QUARANTINE_ALREADY_APPLIED
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]
    frames = [
        frame
        async for frame in service.ListScheduleSnapshot(
            pb.ListScheduleSnapshotRequest(
                project_id=str(project.id),
                snapshot_format_version=1,
            ),
            Context(),
        )
    ]
    assert frames[1].row.schedule.is_enabled is False


async def test_cursor_rpc_applies_only_brain_recomputed_successor(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    assert row.control_token is not None
    assert row.definition_digest is not None
    assert row.next_run_at is not None
    expected_next = row.next_run_at.replace(tzinfo=UTC)
    skipped = expected_next + timedelta(minutes=10)
    prepared = skipped + timedelta(minutes=5)

    request = pb.AdvanceScheduleCursorRequest(
        project_id=str(project.id),
        schedule_id=str(row.id),
        observed_control_token=str(row.control_token),
        definition_digest=row.definition_digest,
        expected_schedule_revision=1,
        expected_next_run_at=_timestamp(expected_next),
        skipped_through=_timestamp(skipped),
        prepared_next_run_at=_timestamp(prepared),
        scheduler_protocol_epoch=1,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )
    response = await service.AdvanceScheduleCursor(request, Context())

    assert response.disposition == pb.CursorTransitionDisposition.CURSOR_APPLIED
    assert response.committed_revision == 2
    assert response.live_revision == 2
    assert response.committed_last_run_at == _timestamp(skipped)
    assert response.committed_next_run_at == _timestamp(prepared)
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]

    replay = await service.AdvanceScheduleCursor(request, Context())
    assert replay.disposition == pb.CursorTransitionDisposition.CURSOR_IDEMPOTENT
    assert replay.committed_revision == 2
    assert replay.live_revision == 2
    service._audit.record.assert_awaited_once()  # type: ignore[union-attr]


async def test_cursor_rpc_farther_progress_resolves_stale_slot(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    original = await _only_schedule(database)
    assert original.control_token is not None
    assert original.definition_digest is not None
    assert original.next_run_at is not None
    expected_next = original.next_run_at.replace(tzinfo=UTC)
    first_slot = expected_next + timedelta(minutes=10)
    first_next = first_slot + timedelta(minutes=5)
    first_request = pb.AdvanceScheduleCursorRequest(
        project_id=str(project.id),
        schedule_id=str(original.id),
        observed_control_token=str(original.control_token),
        definition_digest=original.definition_digest,
        expected_schedule_revision=1,
        expected_next_run_at=_timestamp(expected_next),
        skipped_through=_timestamp(first_slot),
        prepared_next_run_at=_timestamp(first_next),
        scheduler_protocol_epoch=1,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )
    first = await service.AdvanceScheduleCursor(first_request, Context())
    assert first.disposition == pb.CursorTransitionDisposition.CURSOR_APPLIED

    second_slot = first_next + timedelta(minutes=10)
    second_next = second_slot + timedelta(minutes=5)
    second = await service.AdvanceScheduleCursor(
        pb.AdvanceScheduleCursorRequest(
            project_id=str(project.id),
            schedule_id=str(original.id),
            observed_control_token=str(original.control_token),
            definition_digest=original.definition_digest,
            expected_schedule_revision=first.committed_revision,
            expected_last_run_at=_timestamp(first_slot),
            expected_next_run_at=_timestamp(first_next),
            skipped_through=_timestamp(second_slot),
            prepared_next_run_at=_timestamp(second_next),
            scheduler_protocol_epoch=1,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
        ),
        Context(),
    )
    assert second.disposition == pb.CursorTransitionDisposition.CURSOR_APPLIED

    stale = await service.AdvanceScheduleCursor(first_request, Context())
    assert stale.disposition == pb.CursorTransitionDisposition.CURSOR_SLOT_RESOLVED_REFRESH
    assert stale.committed_revision == 0
    assert stale.live_revision == second.committed_revision


async def test_per_id_state_returns_row_or_revision_bounded_absence(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)

    present = await service.GetScheduleState(
        pb.GetScheduleStateRequest(
            project_id=str(project.id),
            schedule_id=str(row.id),
            minimum_observed_revision=1,
        ),
        Context(),
    )
    assert present.WhichOneof("state") == "schedule"
    assert present.observed_revision == 1

    missing_id = uuid.uuid4()
    absent = await service.GetScheduleState(
        pb.GetScheduleStateRequest(
            project_id=str(project.id),
            schedule_id=str(missing_id),
            minimum_observed_revision=1,
        ),
        Context(),
    )
    assert absent.WhichOneof("state") == "absence"
    assert absent.observed_revision == 1
    assert absent.absence.schedule_id == str(missing_id)


async def test_watch_orders_relevant_change_then_filtered_checkpoint(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    async with database.session() as session:
        session.add(
            ScheduleChangeLog(
                revision=2,
                project_id=project.id,
                schedule_id=uuid.uuid4(),
                schedule_owner="celery-beat",
                change_kind="upsert",
                protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                snapshot={"filtered": True},
                occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
            ),
        )
        await session.execute(
            update(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            )
            .values(current_revision=2),
        )
        await session.commit()

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id=str(project.id),
            after_revision=0,
            watch_format_version=1,
        ),
        Context(),
    )
    first = await anext(stream)
    second = await anext(stream)
    await stream.aclose()

    assert first.WhichOneof("frame") == "change"
    assert first.change.revision == 1
    assert first.change.kind == pb.ScheduleChange.Kind.UPSERT
    assert second.WhichOneof("frame") == "scanned_through"
    assert second.scanned_through.scanned_through_revision == 2
    assert second.scanned_through.server_revision == 2


async def test_watch_below_pruned_boundary_is_out_of_range(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    async with database.session() as session:
        await session.execute(
            update(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            )
            .values(change_log_pruned_through=1),
        )
        await session.commit()

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id=str(project.id),
            after_revision=0,
            watch_format_version=1,
        ),
        Context(),
    )
    with pytest.raises(RpcAbortError) as caught:
        await anext(stream)
    assert caught.value.code is grpc.StatusCode.OUT_OF_RANGE


async def test_watch_malformed_relevant_envelope_is_data_loss(
    current_service: tuple[SchedulerServiceImpl, DatabaseManager, Project],
) -> None:
    service, database, project = current_service
    row = await _only_schedule(database)
    async with database.session() as session:
        session.add(
            ScheduleChangeLog(
                revision=2,
                project_id=project.id,
                schedule_id=row.id,
                schedule_owner="z4j-scheduler",
                change_kind="upsert",
                protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                snapshot={"not_schedule": True},
                occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
            ),
        )
        await session.execute(
            update(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            )
            .values(current_revision=2),
        )
        await session.commit()

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id=str(project.id),
            after_revision=1,
            watch_format_version=1,
        ),
        Context(),
    )
    with pytest.raises(RpcAbortError) as caught:
        await anext(stream)
    assert caught.value.code is grpc.StatusCode.DATA_LOSS
