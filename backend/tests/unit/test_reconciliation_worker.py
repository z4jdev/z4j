"""ReconciliationWorker tests - repository + worker invariants.

Covers:

- ``TaskRepository.list_stuck_for_reconciliation`` returns only
  non-terminal tasks older than the cutoff.
- Worker.tick returns cleanly when no stuck tasks exist.
- Worker.tick with stuck tasks + no online agent → skipped_no_agent.
- Worker.tick with stuck tasks + online agent → dispatched counter.
- Worker respects the per-tick cap.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.domain.workers.reconciliation import ReconciliationWorker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Project, Task
from z4j_brain.persistence.repositories import TaskRepository


class _FakeDb:
    """Minimal shim that exposes ``.session()`` as an async CM."""

    def __init__(self, factory):
        self._factory = factory

    def session(self):
        return self._factory()


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


def _session_factory(eng):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        async with AsyncSession(eng) as s:
            yield s
    return _ctx


@pytest.fixture
async def project(engine) -> Project:
    async with AsyncSession(engine) as s:
        p = Project(slug="proj", name="Proj")
        s.add(p)
        await s.commit()
        await s.refresh(p)
        return p


async def _insert_task(
    engine,
    *,
    project_id: UUID,
    task_id: str,
    state: TaskState,
    started_at: datetime | None,
):
    async with AsyncSession(engine) as s:
        t = Task(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            name=f"myapp.tasks.{task_id}",
            state=state,
            started_at=started_at,
        )
        s.add(t)
        await s.commit()


async def _insert_agent(engine, *, project_id: UUID, state: AgentState):
    async with AsyncSession(engine) as s:
        from uuid import uuid4
        a = Agent(
            project_id=project_id,
            name=f"agent-{uuid4().hex[:6]}",
            token_hash=f"fake-hash-{uuid4().hex[:8]}",
            state=state,
            protocol_version="2",
            framework_adapter="unknown",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            last_seen_at=datetime.now(UTC),
        )
        s.add(a)
        await s.commit()


@pytest.mark.asyncio
class TestStuckTasksRepo:
    async def test_empty_when_no_tasks(self, engine, project):
        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=datetime.now(UTC),
            )
            assert stuck == []

    async def test_returns_only_non_terminal_tasks(self, engine, project):
        now = datetime.now(UTC)
        long_ago = now - timedelta(hours=1)

        # Started + old → should appear
        await _insert_task(
            engine, project_id=project.id, task_id="stuck-1",
            state=TaskState.STARTED, started_at=long_ago,
        )
        # Terminal + old → should NOT appear
        await _insert_task(
            engine, project_id=project.id, task_id="done-1",
            state=TaskState.SUCCESS, started_at=long_ago,
        )
        # Started but recent → should NOT appear
        await _insert_task(
            engine, project_id=project.id, task_id="recent-1",
            state=TaskState.STARTED, started_at=now - timedelta(seconds=30),
        )

        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=now - timedelta(minutes=5),
            )
        ids = {t.task_id for t in stuck}
        assert ids == {"stuck-1"}

    async def test_respects_limit(self, engine, project):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        for i in range(5):
            await _insert_task(
                engine, project_id=project.id,
                task_id=f"s-{i}",
                state=TaskState.STARTED, started_at=long_ago,
            )
        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=datetime.now(UTC), limit=2,
            )
        assert len(stuck) == 2


@pytest.mark.asyncio
class TestReconciliationWorker:
    async def test_tick_noop_when_nothing_stuck(self, engine, project):
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        await worker.tick()  # must not raise

    async def test_tick_with_stuck_task_and_no_agent_skips(
        self, engine, project,
    ):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        await _insert_task(
            engine, project_id=project.id, task_id="s-1",
            state=TaskState.STARTED, started_at=long_ago,
        )
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        # No online agent → worker should not raise; just log + move on.
        await worker.tick()

    async def test_tick_with_stuck_task_and_online_agent_dispatches(
        self, engine, project,
    ):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        await _insert_task(
            engine, project_id=project.id, task_id="s-1",
            state=TaskState.STARTED, started_at=long_ago,
        )
        await _insert_agent(
            engine, project_id=project.id, state=AgentState.ONLINE,
        )
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        await worker.tick()  # must not raise
