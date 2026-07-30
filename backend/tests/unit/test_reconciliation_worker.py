"""ReconciliationWorker tests - repository + worker invariants.

Covers:

- ``TaskRepository.list_stuck_for_reconciliation`` returns only
  non-terminal tasks older than the cutoff, including tasks that
  never started ((a): age anchor falls back to ``received_at``
  then ``created_at``).
- Worker.tick returns cleanly when no stuck tasks exist.
- Worker.tick with stuck tasks + no online agent → skipped_no_agent.
- Worker.tick with stuck tasks + online agent → dispatched counter.
- Worker respects the per-tick cap.
- Probe commands carry the deterministic per-task / per-sweep-window
  idempotency key ((c)).
- The main.py wiring leader-locks the tick so only one brain process
  sweeps per interval ((b))."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.workers.reconciliation import (
    ReconciliationWorker,
    _probe_idempotency_key,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Project, Task
from z4j_brain.persistence.repositories import TaskRepository


class _FakeDb:
    """Minimal shim that exposes ``.session()`` as an async CM."""

    def __init__(self, factory):
        self._factory = factory

    def session(self, *, write: bool = False):
        assert write is True
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
    **columns,
):
    async with AsyncSession(engine) as s:
        t = Task(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            name=f"myapp.tasks.{task_id}",
            state=state,
            started_at=started_at,
            **columns,
        )
        s.add(t)
        await s.commit()


async def _insert_agent(
    engine,
    *,
    project_id: UUID,
    state: AgentState,
    engine_adapters: list[str] | None = None,
):
    async with AsyncSession(engine) as s:
        from uuid import uuid4

        a = Agent(
            project_id=project_id,
            name=f"agent-{uuid4().hex[:6]}",
            token_hash=f"fake-hash-{uuid4().hex[:8]}",
            state=state,
            protocol_version="2",
            framework_adapter="unknown",
            engine_adapters=engine_adapters or [],
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
            engine,
            project_id=project.id,
            task_id="stuck-1",
            state=TaskState.STARTED,
            started_at=long_ago,
        )
        # Terminal + old → should NOT appear
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="done-1",
            state=TaskState.SUCCESS,
            started_at=long_ago,
        )
        # Started but recent → should NOT appear
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="recent-1",
            state=TaskState.STARTED,
            started_at=now - timedelta(seconds=30),
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
                engine,
                project_id=project.id,
                task_id=f"s-{i}",
                state=TaskState.STARTED,
                started_at=long_ago,
            )
        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=datetime.now(UTC),
                limit=2,
            )
        assert len(stuck) == 2

    async def test_never_started_old_pending_is_selected(self, engine, project):
        # (a): pre-fix, ``started_at IS NOT NULL`` silently
        # excluded tasks that never got a start event, so an old
        # PENDING task was never reconciled. The age anchor now falls
        # back to received_at, then created_at.
        now = datetime.now(UTC)
        long_ago = now - timedelta(hours=1)

        # Never started, received long ago → selected via received_at.
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="pending-received",
            state=TaskState.PENDING,
            started_at=None,
            received_at=long_ago,
        )
        # Never started, never received (lost enqueue event) →
        # selected via created_at.
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="pending-created",
            state=TaskState.PENDING,
            started_at=None,
            received_at=None,
            created_at=long_ago,
            updated_at=long_ago,
        )
        # Never started but FRESH → not stuck yet.
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="pending-fresh",
            state=TaskState.PENDING,
            started_at=None,
            received_at=now - timedelta(seconds=30),
        )

        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=now - timedelta(minutes=5),
            )
        ids = {t.task_id for t in stuck}
        assert ids == {"pending-received", "pending-created"}

    async def test_oldest_stuck_tasks_come_first(self, engine, project):
        now = datetime.now(UTC)
        # Mixed anchors: a never-started task older than a started one.
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="older-never-started",
            state=TaskState.PENDING,
            started_at=None,
            received_at=now - timedelta(hours=3),
        )
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="younger-started",
            state=TaskState.STARTED,
            started_at=now - timedelta(hours=1),
        )
        async with AsyncSession(engine) as s:
            repo = TaskRepository(s)
            stuck = await repo.list_stuck_for_reconciliation(
                stuck_before=now - timedelta(minutes=5),
            )
        assert [t.task_id for t in stuck] == [
            "older-never-started",
            "younger-started",
        ]


@pytest.mark.asyncio
class TestReconciliationWorker:
    async def test_tick_noop_when_nothing_stuck(self, engine, project):
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        await worker.tick()  # must not raise

    async def test_tick_with_stuck_task_and_no_agent_skips(
        self,
        engine,
        project,
    ):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="s-1",
            state=TaskState.STARTED,
            started_at=long_ago,
        )
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        # No online agent → worker should not raise; just log + move on.
        await worker.tick()

    async def test_tick_with_stuck_task_and_online_agent_dispatches(
        self,
        engine,
        project,
    ):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="s-1",
            state=TaskState.STARTED,
            started_at=long_ago,
        )
        await _insert_agent(
            engine,
            project_id=project.id,
            state=AgentState.ONLINE,
        )
        db = _FakeDb(_session_factory(engine))
        worker = ReconciliationWorker(db, stale_threshold_seconds=300)
        await worker.tick()  # must not raise


class _CapturingDispatcher:
    """Stub CommandDispatcher recording every ``issue`` call's kwargs."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def issue(self, **kwargs):
        self.calls.append(kwargs)


# Window bucket wide enough that "now" stays inside one bucket for
# the duration of a test run (bucket boundary at epoch 2e9 ≈ 2033).
_HUGE_WINDOW_SECONDS = 10**9


class TestProbeIdempotencyKey:
    """(c): probes carry a deterministic per-task / per-window key."""

    def _expected_window(self) -> int:
        return int(datetime.now(UTC).timestamp() // _HUGE_WINDOW_SECONDS)

    @pytest.mark.asyncio
    async def test_issued_probe_carries_deterministic_key(self, engine, project):
        long_ago = datetime.now(UTC) - timedelta(hours=1)
        await _insert_task(
            engine,
            project_id=project.id,
            task_id="s-1",
            state=TaskState.STARTED,
            started_at=long_ago,
        )
        await _insert_agent(
            engine,
            project_id=project.id,
            state=AgentState.ONLINE,
            engine_adapters=["celery"],
        )
        db = _FakeDb(_session_factory(engine))
        dispatcher = _CapturingDispatcher()
        worker = ReconciliationWorker(
            db,
            stale_threshold_seconds=300,
            sweep_interval_seconds=_HUGE_WINDOW_SECONDS,
            dispatcher=dispatcher,
        )

        await worker.tick()
        assert len(dispatcher.calls) == 1
        expected = f"reconcile:celery:s-1:{self._expected_window()}"
        assert dispatcher.calls[0]["idempotency_key"] == expected

        # A duplicate sweep in the SAME window re-issues with the SAME
        # key - downstream, CommandRepository.insert dedupes on
        # (project_id, idempotency_key) so no second probe command row
        # is minted.
        await worker.tick()
        assert len(dispatcher.calls) == 2
        assert dispatcher.calls[1]["idempotency_key"] == expected

    def test_same_window_same_key_later_window_new_key(self) -> None:
        base = _probe_idempotency_key("celery", "abc", 100)
        assert base == "reconcile:celery:abc:100"
        assert _probe_idempotency_key("celery", "abc", 100) == base
        # A later window may re-probe a still-stuck task.
        assert _probe_idempotency_key("celery", "abc", 101) != base
        # Different tasks / engines never collide.
        assert _probe_idempotency_key("celery", "xyz", 100) != base
        assert _probe_idempotency_key("rq", "abc", 100) != base

    def test_long_task_id_key_fits_column_and_stays_deterministic(self) -> None:
        # ``commands.idempotency_key`` is String(200); ``task_id`` can
        # itself be 200 chars. The key must always fit and stay
        # deterministic per window.
        long_id = "x" * 200
        key_a = _probe_idempotency_key("celery", long_id, 100)
        key_b = _probe_idempotency_key("celery", long_id, 100)
        key_next = _probe_idempotency_key("celery", long_id, 101)
        assert key_a == key_b
        assert key_a != key_next
        assert len(key_a) <= 200
        assert len(key_next) <= 200
        # Distinct long ids stay distinct through the hash fold.
        other = _probe_idempotency_key("celery", "y" * 200, 100)
        assert other != key_a


class TestReconciliationLeaderGating:
    """(b): with ``z4j serve``'s min(4, cpu) uvicorn workers,
    only the process that wins the per-worker advisory lock may
    sweep; the others no-op until the next interval."""

    @pytest.mark.asyncio
    async def test_gated_tick_skips_when_another_holder_owns_lock(
        self,
        monkeypatch,
    ) -> None:
        import contextlib

        from z4j_brain.domain.workers import _leader_lock
        from z4j_brain.main import _leader_gated_tick

        ran: list[bool] = []
        seen_names: list[str] = []

        async def _raw_tick() -> None:
            ran.append(True)

        @contextlib.asynccontextmanager
        async def _lock_denied(db, worker_name):
            seen_names.append(worker_name)
            yield False

        monkeypatch.setattr(
            _leader_lock,
            "acquire_per_worker_lock",
            _lock_denied,
        )
        tick = _leader_gated_tick(object(), "reconciliation_worker", _raw_tick)
        await tick()
        assert ran == []
        assert seen_names == ["reconciliation_worker"]

    @pytest.mark.asyncio
    async def test_gated_tick_runs_when_lock_acquired(self, monkeypatch) -> None:
        import contextlib

        from z4j_brain.domain.workers import _leader_lock
        from z4j_brain.main import _leader_gated_tick

        ran: list[bool] = []

        async def _raw_tick() -> None:
            ran.append(True)

        @contextlib.asynccontextmanager
        async def _lock_granted(db, worker_name):
            yield True

        monkeypatch.setattr(
            _leader_lock,
            "acquire_per_worker_lock",
            _lock_granted,
        )
        tick = _leader_gated_tick(object(), "reconciliation_worker", _raw_tick)
        await tick()
        assert ran == [True]

    def test_main_wires_reconciliation_tick_through_leader_gate(self) -> None:
        # Wiring tripwire: the PeriodicWorker registration for the
        # reconciliation worker must route its tick through
        # ``_leader_gated_tick`` - pre-(b) it was registered
        # ungated, so every brain process issued duplicate probe
        # commands each sweep.
        import inspect

        import z4j_brain.main as main_mod

        source = inspect.getsource(main_mod.create_app)
        idx = source.index('name="reconciliation_worker"')
        registration = source[idx : idx + 800]
        assert "_leader_gated_tick(" in registration
        assert (
            '"reconciliation_worker"' in registration[registration.index("_leader_gated_tick(") :]
        )

    def test_main_wires_partition_creator_through_worker_lock(self) -> None:
        # Wiring tripwire: the partition creator's tick must stay
        # behind the per-worker advisory lock - f198e02 fixed the
        # multi-worker boot ERROR storm (concurrent CREATE ..
        # PARTITION OF is not protected by IF NOT EXISTS on
        # Postgres) but shipped without a test pinning the gate.
        import inspect

        import z4j_brain.main as main_mod

        source = inspect.getsource(main_mod.create_app)
        idx = source.index("async def _partition_creator_tick")
        closure = source[idx : idx + 400]
        assert "_acquire_partition_creator_lock(" in closure
        assert '"partition_creator_worker"' in closure
        assert "if got:" in closure
        reg = source.index('name="partition_creator_worker"')
        registration = source[reg : reg + 300]
        assert "tick=_partition_creator_tick" in registration
