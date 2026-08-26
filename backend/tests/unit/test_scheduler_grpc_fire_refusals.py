"""What the Brain says when it will not fire, and why it matters.

Runs against a MIGRATED database, because both branches under test only exist
once durable schedule control is active.

An operator trigger and an out-of-date scheduler are two different problems
with two different remedies, and the ``FireSchedule`` guards used to answer
both with the code that means "upgrade the scheduler". The scheduler patched
that up on its own side before an operator saw it, which left the Brain's logs,
its audit rows and every other client holding a diagnosis that sends someone to
redeploy a component that was working. These tests hold the two apart at the
source.
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
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import Project, Schedule
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH
from z4j_brain.settings import Settings

_MANUAL_CODE = "manual_trigger_not_accepted"


class Context:
    def __init__(self) -> None:
        self.aborted: tuple[grpc.StatusCode, str] | None = None

    def cancelled(self) -> bool:
        return False

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted = (code, details)
        raise AssertionError(f"unexpected abort {code}: {details}")

    def auth_context(self) -> dict[str, list[bytes]]:
        return {}


def _timestamp(value: datetime) -> Timestamp:
    stamp = Timestamp()
    stamp.FromDatetime(value)
    return stamp


@pytest.fixture
async def service_and_row(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> AsyncIterator[tuple[SchedulerServiceImpl, Schedule]]:
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)
    try:
        project = Project(id=uuid.uuid4(), slug="refusals", name="Refusals")
        async with database.session() as session:
            session.add(project)
            await session.flush()
            row = await ScheduleControlRepository(session).create_current(
                project_id=project.id,
                data={
                    "name": "cleanup",
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
            await session.commit()
            session.expunge(row)
        yield (
            SchedulerServiceImpl(
                settings=settings,
                db=database,
                command_dispatcher=AsyncMock(),
                audit_service=AsyncMock(),
            ),
            row,
        )
    finally:
        await engine.dispose()


def _slot(row: Schedule) -> datetime:
    assert row.next_run_at is not None
    return row.next_run_at.replace(tzinfo=UTC)


def _tokenless(row: Schedule, **overrides) -> pb.FireScheduleRequest:
    """The 1.7 wire: a slot, a fire id, and no control authority at all."""

    slot = _slot(row)
    fields = {
        "schedule_id": str(row.id),
        "fire_id": str(derive_scheduler_fire_id(row.id, slot)),
        "scheduled_for": _timestamp(slot),
        "fired_at": _timestamp(slot + timedelta(seconds=1)),
    }
    fields.update(overrides)
    return pb.FireScheduleRequest(**fields)


def _current(row: Schedule, **overrides) -> pb.FireScheduleRequest:
    """The shipped wire: the slot plus the authority that governs it."""

    slot = _slot(row)
    successor = canonical_next_run_at(
        kind=row.kind.value,
        expression=row.expression,
        timezone=row.timezone,
        last_run_at=slot,
        anchor_at=slot,
    )
    assert successor is not None
    fields = {
        "schedule_id": str(row.id),
        "fire_id": str(derive_scheduler_fire_id(row.id, slot)),
        "scheduled_for": _timestamp(slot),
        "fired_at": _timestamp(slot + timedelta(seconds=1)),
        "scheduler_protocol_epoch": CURRENT_PROTOCOL_EPOCH,
        "observed_control_token": str(row.control_token),
        "definition_digest": row.definition_digest,
        "expected_schedule_revision": row.schedule_revision,
        "expected_next_run_at": _timestamp(slot),
        "prepared_next_run_at": _timestamp(successor),
        "cadence_semantics_version": CADENCE_SEMANTICS_VERSION,
        "cadence_runtime_fingerprint": cadence_runtime_fingerprint(),
    }
    fields.update(overrides)
    return pb.FireScheduleRequest(**fields)


@pytest.mark.asyncio
async def test_tokenless_cadence_fire_is_told_to_upgrade(
    service_and_row: tuple[SchedulerServiceImpl, Schedule],
) -> None:
    """The negative control for every case below.

    A slot-derived, unattributed fire with no control token is what an N-1
    scheduler sends, and "upgrade the scheduler" is the true answer to it. If
    this ever changes to the manual-trigger code, the split has been made in
    the wrong place and a real N-1 deployment is being told to edit a setting
    it does not have.
    """

    service, row = service_and_row

    response = await service.FireSchedule(_tokenless(row), Context())

    assert response.error_code == "scheduler_upgrade_required"
    assert response.disposition == pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED


@pytest.mark.asyncio
async def test_attributed_tokenless_fire_names_the_operator_trigger(
    service_and_row: tuple[SchedulerServiceImpl, Schedule],
) -> None:
    service, row = service_and_row

    response = await service.FireSchedule(
        _tokenless(row, triggered_by_user_id=str(uuid.uuid4())),
        Context(),
    )

    assert response.error_code == _MANUAL_CODE
    assert "scheduler_trigger_url" in response.error_message


@pytest.mark.asyncio
async def test_unattributed_manual_fire_id_names_the_operator_trigger(
    service_and_row: tuple[SchedulerServiceImpl, Schedule],
) -> None:
    """Dropping the attribution does not turn a trigger into a cadence fire.

    An operator trigger mints a uuid4 because it settles no slot, so the id's
    version is the tell even when nothing else is.
    """

    service, row = service_and_row

    response = await service.FireSchedule(
        _tokenless(row, fire_id=str(uuid.uuid4())),
        Context(),
    )

    assert response.error_code == _MANUAL_CODE
    assert "scheduler_trigger_url" in response.error_message


@pytest.mark.asyncio
async def test_attributed_current_fire_names_the_operator_trigger(
    service_and_row: tuple[SchedulerServiceImpl, Schedule],
) -> None:
    """Complete authority does not make an extra fire a cadence acceptance.

    This request carries every control field the current wire defines, so
    "lacks complete authority" would be plainly false; the reason it is refused
    is the attribution, and that is what it is told.
    """

    service, row = service_and_row

    response = await service.FireSchedule(
        _current(row, triggered_by_user_id=str(uuid.uuid4())),
        Context(),
    )

    assert response.error_code == _MANUAL_CODE
    assert "scheduler_trigger_url" in response.error_message


@pytest.mark.asyncio
async def test_current_fire_missing_authority_still_says_so(
    service_and_row: tuple[SchedulerServiceImpl, Schedule],
) -> None:
    """The other half of the split keeps its own answer."""

    service, row = service_and_row

    response = await service.FireSchedule(
        _current(row, definition_digest=""),
        Context(),
    )

    assert response.error_code == "invalid_current_fire"
    assert response.disposition == pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS
