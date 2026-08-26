"""Cross-replica authority tests for schedule-fire global identity."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence import models  # noqa: F401  register full metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import ScheduleFire
from z4j_brain.persistence.repositories.schedule_fires import (
    ScheduleFireIdentityError,
    ScheduleFireRepository,
    _postgres_fire_identity_key,
)


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


@pytest.fixture
async def sqlite_db(tmp_path: Path) -> AsyncIterator[DatabaseManager]:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'fire-identity.sqlite3'}",
        connect_args={"timeout": 10},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    database = DatabaseManager(engine)
    try:
        yield database
    finally:
        await database.dispose()


def _current_arguments(
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


@pytest.mark.asyncio
async def test_sqlite_concurrent_divergent_slots_create_exactly_one_identity(
    sqlite_db: DatabaseManager,
) -> None:
    """BEGIN IMMEDIATE closes SQLite's corresponding probe/insert window."""

    fire_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    receipt = uuid.uuid4()
    first_slot = datetime(2026, 8, 12, 12, tzinfo=UTC)
    start = asyncio.Event()

    async def record(slot: datetime) -> bool:
        await start.wait()
        try:
            async with sqlite_db.session(write=True) as session:
                await ScheduleFireRepository(session).record_current(
                    **_current_arguments(
                        fire_id=fire_id,
                        schedule_id=schedule_id,
                        project_id=project_id,
                        slot=slot,
                        receipt=receipt,
                    ),
                )
                await session.commit()
            return True
        except ScheduleFireIdentityError:
            return False

    contenders = [
        asyncio.create_task(record(first_slot)),
        asyncio.create_task(record(first_slot + timedelta(minutes=1))),
    ]
    await asyncio.sleep(0)
    start.set()
    outcomes = await asyncio.gather(*contenders)

    assert sum(outcomes) == 1
    async with sqlite_db.session() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(ScheduleFire)
            .where(
                ScheduleFire.fire_id == fire_id,
            ),
        )
    assert count == 1


@pytest.mark.asyncio
async def test_sqlite_exact_receipt_retry_is_same_slot_idempotent(
    sqlite_db: DatabaseManager,
) -> None:
    fire_id = uuid.uuid4()
    slot = datetime(2026, 8, 12, 12, tzinfo=UTC)
    arguments = _current_arguments(
        fire_id=fire_id,
        schedule_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        slot=slot,
        receipt=uuid.uuid4(),
    )

    async with sqlite_db.session(write=True) as session:
        first, first_created = await ScheduleFireRepository(session).record_current(
            **arguments,
        )
        second, second_created = await ScheduleFireRepository(session).record_current(
            **arguments,
        )
        await session.commit()

    assert first_created is True
    assert second_created is False
    assert first.id == second.id


@pytest.mark.asyncio
async def test_sqlite_same_global_slot_allows_distinct_receipt_generations(
    sqlite_db: DatabaseManager,
) -> None:
    fire_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    slot = datetime(2026, 8, 12, 12, tzinfo=UTC)

    async with sqlite_db.session(write=True) as session:
        first, first_created = await ScheduleFireRepository(session).record_current(
            **_current_arguments(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                slot=slot,
                receipt=uuid.uuid4(),
            ),
        )
        second, second_created = await ScheduleFireRepository(session).record_current(
            **_current_arguments(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                slot=slot,
                receipt=uuid.uuid4(),
            ),
        )
        await session.commit()

    assert first_created is True
    assert second_created is True
    assert first.id != second.id


@pytest.mark.asyncio
async def test_bare_ack_fails_closed_on_legacy_ambiguity_with_bounded_lookup(
    sqlite_db: DatabaseManager,
) -> None:
    fire_id = uuid.uuid4()
    slot = datetime(2026, 8, 12, 12, tzinfo=UTC)
    schedule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    async with sqlite_db.session(write=True) as session:
        session.add_all(
            [
                ScheduleFire(
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=slot,
                    fired_at=slot,
                    receipt_control_token=uuid.uuid4(),
                ),
                ScheduleFire(
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=slot + timedelta(minutes=1),
                    fired_at=slot,
                    receipt_control_token=uuid.uuid4(),
                ),
            ],
        )
        await session.commit()

    statements: list[str] = []

    def capture_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement)

    event.listen(
        sqlite_db.engine.sync_engine,
        "before_cursor_execute",
        capture_statement,
    )
    try:
        with pytest.raises(
            ScheduleFireIdentityError,
            match="ambiguous durable history",
        ):
            async with sqlite_db.session(write=True) as session:
                await ScheduleFireRepository(session).acknowledge(
                    fire_id=fire_id,
                    status="acked_success",
                )
    finally:
        event.remove(
            sqlite_db.engine.sync_engine,
            "before_cursor_execute",
            capture_statement,
        )

    fire_queries = [
        statement
        for statement in statements
        if "FROM schedule_fires" in statement and "fire_id" in statement
    ]
    assert fire_queries
    assert all("LIMIT" in statement.upper() for statement in fire_queries)


def test_postgres_authority_key_is_signed_stable_and_uses_the_full_uuid() -> None:
    low = uuid.UUID("00000000-0000-0000-0000-000000000001")
    high = uuid.UUID("80000000-0000-0000-0000-000000000001")

    assert _postgres_fire_identity_key(low) == _postgres_fire_identity_key(low)
    assert _postgres_fire_identity_key(low) != _postgres_fire_identity_key(high)
    assert -(2**63) <= _postgres_fire_identity_key(low) < 2**63
