"""Regression: keyset-pagination cursor bugs fixed in 1.7.1.

B11 -- schedules cursor split on the FIRST '|' broke on schedule names
containing '|' (UUID parse failed -> the server restarted at page 1 and
re-emitted the same cursor -> the dashboard's do/while(cursor) loop hung).

B12 -- the task list ordered by ``started_at DESC NULLS LAST`` but the
non-null cursor predicate ``started_at < sort_value`` is NULL for pending
(started_at IS NULL) rows in SQL three-valued logic, so once page 1 filled
with non-null rows the continuation never reached the NULL section and every
pending task was permanently invisible.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.api.schedules import _decode_schedules_cursor, _encode_schedules_cursor
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories.tasks import TaskRepository


class TestSchedulesCursorPipeB11:
    def test_name_with_pipe_round_trips(self) -> None:
        sid = uuid.uuid4()
        cursor = _encode_schedules_cursor("nightly|cleanup", sid)
        name, decoded_id = _decode_schedules_cursor(cursor)
        assert name == "nightly|cleanup"
        assert decoded_id == sid

    def test_plain_name_still_round_trips(self) -> None:
        sid = uuid.uuid4()
        name, decoded_id = _decode_schedules_cursor(_encode_schedules_cursor("nightly", sid))
        assert name == "nightly"
        assert decoded_id == sid

    def test_garbage_cursor_returns_none(self) -> None:
        assert _decode_schedules_cursor("no-separator-here") == (None, None)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
class TestTaskPaginationPendingB12:
    async def test_pending_tasks_are_reachable_across_pages(
        self,
        session: AsyncSession,
    ) -> None:
        project = Project(slug="p", name="P")
        session.add(project)
        await session.flush()

        base = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
        # 4 running/finished tasks (non-null started_at) + 3 pending (NULL).
        for i in range(4):
            session.add(
                Task(
                    project_id=project.id,
                    engine="celery",
                    task_id=f"done-{i}",
                    name="myapp.run",
                    state="success",
                    priority="normal",
                    received_at=base,
                    started_at=datetime(2026, 7, 17, 12, i, tzinfo=UTC),
                ),
            )
        for i in range(3):
            session.add(
                Task(
                    project_id=project.id,
                    engine="celery",
                    task_id=f"pending-{i}",
                    name="myapp.run",
                    state="pending",
                    priority="normal",
                    received_at=base,
                    started_at=None,
                ),
            )
        await session.commit()

        repo = TaskRepository(session)
        # Page size 2 forces the cursor onto a non-null row before the
        # NULL section is reached -- the exact B12 trigger.
        seen: list[str] = []
        cursor = None
        for _ in range(10):  # generous page cap
            page = await repo.list_for_project(project_id=project.id, limit=2, cursor=cursor)
            if not page:
                break
            seen.extend(t.task_id for t in page)
            last = page[-1]
            cursor = (last.started_at, last.id)

        # All 7 tasks -- including the 3 pending -- must be reachable, once each.
        assert len(seen) == len(set(seen)), f"duplicates: {seen}"
        assert set(seen) == {
            "done-0",
            "done-1",
            "done-2",
            "done-3",
            "pending-0",
            "pending-1",
            "pending-2",
        }, seen
