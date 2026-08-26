"""PostgreSQL concurrency coverage for schedule-fire global identity."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import TypedDict

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncEngine
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import Project, ScheduleFire
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.repositories.schedule_fires import (
    ScheduleFireIdentityError,
    ScheduleFireRepository,
)

pytestmark = pytest.mark.asyncio


class _CurrentArguments(TypedDict):
    fire_id: uuid.UUID
    schedule_id: uuid.UUID
    project_id: uuid.UUID
    command_id: uuid.UUID | None
    status: str
    scheduled_for: datetime
    observed_control_token: uuid.UUID | None
    receipt_control_token: uuid.UUID
    acceptance_revision: int
    definition_digest: str
    expected_schedule_revision: int
    expected_last_run_at: datetime | None
    expected_next_run_at: datetime
    prepared_next_run_at: datetime | None


def _arguments(
    *,
    fire_id: uuid.UUID,
    schedule_id: uuid.UUID,
    project_id: uuid.UUID,
    slot: datetime,
    receipt: uuid.UUID,
) -> _CurrentArguments:
    return {
        "fire_id": fire_id,
        "schedule_id": schedule_id,
        "project_id": project_id,
        "command_id": None,
        "status": "accepted",
        "scheduled_for": slot,
        "observed_control_token": receipt,
        "receipt_control_token": receipt,
        "acceptance_revision": 1,
        "definition_digest": "d" * 64,
        "expected_schedule_revision": 1,
        "expected_last_run_at": None,
        "expected_next_run_at": slot,
        "prepared_next_run_at": slot + timedelta(minutes=5),
    }


async def _race_records(
    *,
    database: DatabaseManager,
    arguments: list[_CurrentArguments],
) -> list[tuple[str, bool | None, uuid.UUID | None]]:
    start = asyncio.Event()

    async def record_one(
        values: _CurrentArguments,
    ) -> tuple[str, bool | None, uuid.UUID | None]:
        await start.wait()
        try:
            async with database.session(write=True) as session:
                row, created = await ScheduleFireRepository(session).record_current(
                    **values,
                )
                await session.commit()
            return "accepted", created, row.id
        except ScheduleFireIdentityError:
            return "divergent", None, None

    contenders = [asyncio.create_task(record_one(values)) for values in arguments]
    await asyncio.sleep(0)
    start.set()
    return await asyncio.gather(*contenders)


async def test_postgres_advisory_authority_serializes_divergent_slots_and_retries(
    migrated_engine: AsyncEngine,
) -> None:
    database = DatabaseManager(migrated_engine)
    schedule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    slot = datetime(2026, 8, 12, 12, tzinfo=UTC)

    divergent_fire_id = uuid.uuid4()
    divergent_receipt = uuid.uuid4()
    divergent = await _race_records(
        database=database,
        arguments=[
            _arguments(
                fire_id=divergent_fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                slot=slot,
                receipt=divergent_receipt,
            ),
            _arguments(
                fire_id=divergent_fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                slot=slot + timedelta(minutes=1),
                receipt=divergent_receipt,
            ),
        ],
    )

    assert sorted(outcome for outcome, _created, _row_id in divergent) == [
        "accepted",
        "divergent",
    ]
    async with database.session() as session:
        divergent_count = await session.scalar(
            select(func.count())
            .select_from(ScheduleFire)
            .where(
                ScheduleFire.fire_id == divergent_fire_id,
            ),
        )
    assert divergent_count == 1

    retry_fire_id = uuid.uuid4()
    retry_arguments = _arguments(
        fire_id=retry_fire_id,
        schedule_id=schedule_id,
        project_id=project_id,
        slot=slot + timedelta(hours=1),
        receipt=uuid.uuid4(),
    )
    retries = await _race_records(
        database=database,
        arguments=[retry_arguments, retry_arguments.copy()],
    )

    assert [outcome for outcome, _created, _row_id in retries] == [
        "accepted",
        "accepted",
    ]
    assert {created for _outcome, created, _row_id in retries} == {False, True}
    assert len({row_id for _outcome, _created, row_id in retries}) == 1
    async with database.session() as session:
        retry_count = await session.scalar(
            select(func.count())
            .select_from(ScheduleFire)
            .where(
                ScheduleFire.fire_id == retry_fire_id,
            ),
        )
    assert retry_count == 1


async def test_ack_read_does_not_invert_caller_row_to_fire_write_order(
    migrated_engine: AsyncEngine,
) -> None:
    """A bare receipt read cannot retain Fire before a later row mutation.

    The writer deliberately holds a caller-owned row before asking for the Fire
    advisory mutex (production acceptance similarly holds Schedule).  If
    ``get_current`` also retained that mutex, the reader's later row update and
    writer's Fire acquisition would form a deterministic cycle.  The bounded
    read is therefore lock-free; only the identity-authority decision in
    ``record_current`` takes the transaction mutex.
    """

    database = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    slot = datetime(2026, 8, 12, 14, tzinfo=UTC)
    fire_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=project_id,
                slug=f"fire-order-{uuid.uuid4().hex[:8]}",
                name="Fire order",
            ),
        )
        await session.flush()
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project_id,
            data={
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "name": "fire-order",
                "task_name": "tests.fire_order",
                "kind": ScheduleKind.CRON.value,
                "expression": "0 * * * *",
                "timezone": "UTC",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
            },
            planning_at=slot,
        )
        assert schedule.control_token is not None
        assert schedule.definition_digest is not None
        receipt_token = schedule.control_token
        arguments = _arguments(
            fire_id=fire_id,
            schedule_id=schedule.id,
            project_id=project_id,
            slot=slot,
            receipt=receipt_token,
        )
        arguments["definition_digest"] = schedule.definition_digest
        await ScheduleFireRepository(session).record_current(**arguments)
        await session.commit()

    read_complete = asyncio.Event()
    caller_row_locked = asyncio.Event()

    async def read_fire_then_update_caller_row() -> None:
        async with database.session(write=True) as session:
            fire = await ScheduleFireRepository(session).get_current(
                fire_id=fire_id,
                receipt_control_token=receipt_token,
                scheduled_for=slot,
            )
            assert fire is not None
            read_complete.set()
            await caller_row_locked.wait()
            await session.execute(
                update(Project)
                .where(Project.id == project_id)
                .values(name="Fire order acknowledged"),
            )
            await session.commit()

    async def lock_caller_row_then_retry_fire() -> None:
        await read_complete.wait()
        async with database.session(write=True) as session:
            locked = await session.scalar(
                select(Project).where(Project.id == project_id).with_for_update(),
            )
            assert locked is not None
            caller_row_locked.set()
            _row, created = await ScheduleFireRepository(session).record_current(
                **arguments,
            )
            assert created is False
            await session.commit()

    await asyncio.wait_for(
        asyncio.gather(
            read_fire_then_update_caller_row(),
            lock_caller_row_then_retry_fire(),
        ),
        timeout=5,
    )
