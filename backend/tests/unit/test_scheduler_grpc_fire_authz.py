"""Per-cert project authority on the current-protocol ``FireSchedule``.

Runs against a MIGRATED database. Boundary D lives in the migration as
triggers and CHECK constraints, so on a ``create_all`` schema the cadence
acceptance under test here accepts sequences an operator's database refuses
and the ordering these tests are about stops meaning anything.

``Z4J_SCHEDULER_GRPC_CN_PROJECT_BINDINGS`` narrows an allow-listed scheduler
cert to a set of projects. The property is that the Brain resolves the target,
decides whether the peer may have it, and only then writes: a cadence
acceptance allocates a revision, appends a change-log envelope and moves the
cursor, so a peer that is not entitled to the project must not be able to reach
any of it, nor to collect the Brain's reasons for refusing on the way.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import grpc
import pytest
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Command, Project, Schedule
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH
from z4j_brain.settings import Settings

#: The CN on the peer cert these tests present, and the one project slug it is
#: bound to. Everything else is out of its reach.
_PEER_CN = "sched-bound"
_BOUND_SLUG = "bound"
_UNBOUND_SLUG = "unbound"


class RpcAbortError(RuntimeError):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code


class Context:
    """A servicer context carrying one bound CN.

    The default ``Context`` used elsewhere reports an empty auth context, and
    an empty one means no CN is bound, which makes every binding check a no-op.
    A test written on that context would pass whatever the handler did.
    """

    def __init__(self, *, cn: str = _PEER_CN) -> None:
        self._cn = cn

    def cancelled(self) -> bool:
        return False

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        raise RpcAbortError(code, details)

    def auth_context(self) -> dict[str, list[bytes]]:
        return {"x509_common_name": [self._cn.encode()]}


def _timestamp(value: datetime) -> Timestamp:
    stamp = Timestamp()
    stamp.FromDatetime(value)
    return stamp


async def _seed_project(
    database: DatabaseManager,
    *,
    slug: str,
) -> tuple[uuid.UUID, Schedule]:
    """Plan one reserved-owner schedule with a slot that is already due.

    ``create_current`` is the only writer an activated database accepts for a
    ``z4j-scheduler`` row, and it computes the first cursor forward from
    ``planning_at``; back-dating it is what makes the first slot acceptable
    rather than beyond the Brain's clock-skew bound.
    """

    project = Project(id=uuid.uuid4(), slug=slug, name=slug)
    async with database.session() as session:
        session.add(project)
        await session.flush()
        row = await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data={
                "name": f"{slug}-cleanup",
                "task_name": "jobs.cleanup",
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "kind": "cron",
                "expression": "0 * * * *",
                "timezone": "UTC",
                "queue": "maintenance",
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "catch_up": "skip",
            },
            planning_at=datetime.now(UTC) - timedelta(hours=3),
        )
        session.add(
            Agent(
                id=uuid.uuid4(),
                project_id=project.id,
                name=f"{slug}-agent",
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
        session.expunge(row)
    return project.id, row


@pytest.fixture
async def bound_service(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> AsyncIterator[tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule]]:
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        scheduler_grpc_cn_project_bindings={_PEER_CN: [_BOUND_SLUG]},
    )
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)
    try:
        _bound_project, bound_row = await _seed_project(database, slug=_BOUND_SLUG)
        _other_project, unbound_row = await _seed_project(
            database,
            slug=_UNBOUND_SLUG,
        )
        service = SchedulerServiceImpl(
            settings=settings,
            db=database,
            command_dispatcher=AsyncMock(),
            audit_service=AsyncMock(),
        )
        yield service, database, bound_row, unbound_row
    finally:
        await engine.dispose()


def _current_request(
    row: Schedule, *, slot: datetime, fire_id: uuid.UUID
) -> pb.FireScheduleRequest:
    """The request the shipped scheduler builds for one due slot."""

    successor = canonical_next_run_at(
        kind=row.kind.value,
        expression=row.expression,
        timezone=row.timezone,
        last_run_at=slot,
        anchor_at=slot,
    )
    assert successor is not None
    return pb.FireScheduleRequest(
        schedule_id=str(row.id),
        fire_id=str(fire_id),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
        scheduler_protocol_epoch=CURRENT_PROTOCOL_EPOCH,
        observed_control_token=str(row.control_token),
        definition_digest=row.definition_digest,
        expected_schedule_revision=row.schedule_revision,
        expected_next_run_at=_timestamp(slot),
        prepared_next_run_at=_timestamp(successor),
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )


def _slot(row: Schedule) -> datetime:
    assert row.next_run_at is not None
    return row.next_run_at.replace(tzinfo=UTC)


async def _cadence_state(
    database: DatabaseManager,
    schedule_id: uuid.UUID,
) -> tuple:
    async with database.session() as session:
        row = (
            await session.execute(select(Schedule).where(Schedule.id == schedule_id))
        ).scalar_one()
        return (
            row.schedule_revision,
            row.last_run_at,
            row.total_runs,
            row.last_fire_id,
        )


@pytest.mark.asyncio
async def test_unbound_project_is_refused_before_the_cadence_acceptance(
    bound_service: tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule],
) -> None:
    """A refusal the acceptance raises must not reach an unentitled peer.

    The fire id is deliberately not the one that identifies the slot, which is
    a mismatch the cadence acceptance detects for itself. If the binding is
    consulted only after the acceptance runs, the peer is handed that finding
    about a project it was never entitled to name, and the acceptance did its
    revision allocation and envelope append before anyone asked.
    """

    service, _database, _bound, unbound = bound_service
    slot = _slot(unbound)
    wrong_fire_id = derive_scheduler_fire_id(unbound.id, slot + timedelta(hours=1))

    with pytest.raises(RpcAbortError) as raised:
        await service.FireSchedule(
            _current_request(unbound, slot=slot, fire_id=wrong_fire_id),
            Context(),
        )

    assert raised.value.code == grpc.StatusCode.PERMISSION_DENIED


@pytest.mark.asyncio
async def test_unbound_project_keeps_its_cadence_on_a_complete_fire(
    bound_service: tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule],
) -> None:
    """Complete authority for the wrong project is still the wrong project."""

    service, database, _bound, unbound = bound_service
    before = await _cadence_state(database, unbound.id)
    slot = _slot(unbound)

    with pytest.raises(RpcAbortError) as raised:
        await service.FireSchedule(
            _current_request(
                unbound,
                slot=slot,
                fire_id=derive_scheduler_fire_id(unbound.id, slot),
            ),
            Context(),
        )

    assert raised.value.code == grpc.StatusCode.PERMISSION_DENIED
    assert await _cadence_state(database, unbound.id) == before
    async with database.session() as session:
        assert (await session.execute(select(Command))).scalars().all() == []


@pytest.mark.asyncio
async def test_bound_project_still_fires(
    bound_service: tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule],
) -> None:
    """The positive control: denial must not be the answer to everything."""

    service, database, bound, _unbound = bound_service
    slot = _slot(bound)

    response = await service.FireSchedule(
        _current_request(
            bound,
            slot=slot,
            fire_id=derive_scheduler_fire_id(bound.id, slot),
        ),
        Context(),
    )

    assert response.error_code == ""
    assert response.disposition == pb.FireDisposition.FIRE_ACCEPTED
    revision, last_run_at, total_runs, last_fire_id = await _cadence_state(
        database,
        bound.id,
    )
    assert revision > bound.schedule_revision
    assert last_run_at is not None
    assert total_runs == 1
    assert last_fire_id == derive_scheduler_fire_id(bound.id, slot)


@pytest.mark.asyncio
async def test_bound_project_still_hears_the_acceptance_refusal(
    bound_service: tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule],
) -> None:
    """The peer that IS entitled keeps the diagnosis the acceptance produced.

    Pairs with the first test: moving the binding check earlier must not turn
    every cadence conflict into a denial.
    """

    service, database, bound, _unbound = bound_service
    before = await _cadence_state(database, bound.id)
    slot = _slot(bound)
    wrong_fire_id = derive_scheduler_fire_id(bound.id, slot + timedelta(hours=1))

    response = await service.FireSchedule(
        _current_request(bound, slot=slot, fire_id=wrong_fire_id),
        Context(),
    )

    assert response.error_code == "fire_conflict"
    assert await _cadence_state(database, bound.id) == before


@pytest.mark.asyncio
async def test_unknown_schedule_is_answered_not_found(
    bound_service: tuple[SchedulerServiceImpl, DatabaseManager, Schedule, Schedule],
) -> None:
    """Resolving the owner first must not lose the not-found answer.

    A schedule id that is in no project cannot be attributed to any binding,
    so there is nothing to deny; the scheduler is told to refresh instead.
    """

    service, _database, bound, _unbound = bound_service
    missing = uuid.uuid4()
    slot = _slot(bound)
    request = _current_request(
        bound,
        slot=slot,
        fire_id=derive_scheduler_fire_id(missing, slot),
    )
    request.schedule_id = str(missing)

    response = await service.FireSchedule(request, Context())

    assert response.error_code == "schedule_not_found"
    assert response.disposition == pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH
