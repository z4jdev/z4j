"""Tests for the v1.0.15 P-1 batched-upsert refactor in
:meth:`EventIngestor.ingest_batch`.

Companion to :mod:`test_workers_repo_bulk_upsert`. This file asserts
the *integration* between EventIngestor's worker accumulator and
WorkerRepository's bulk upsert:

1. **Dedupe on (engine, worker_name)** - 200 events from the same
   worker collapse into one upsert row, with the worker's
   ``last_heartbeat`` advancing to the MAX ``occurred_at`` in the
   batch.
2. **Heartbeat-at-max** - ``Agent.last_seen_at`` after a batch
   carries the batch's max ``occurred_at``, not wall-clock now().
3. **No regression in per-event task projection** - existing
   ``task.received → task.started → task.succeeded`` lifecycle
   still lands the same TaskState.
4. **Empty / worker-less batch** - heartbeat still fires (event
   traffic counts as agent liveness even when no event carries
   a worker name).
5. **Per-row fallback** - if the bulk upsert raises
   ``OperationalError``, ``_flush_worker_upserts`` falls back to
   the per-row path and the data still lands.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState, WorkerState
from z4j_brain.persistence.models import (
    Agent,
    Project,
    Task,
    Worker,
)
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
    WorkerRepository,
)
from z4j_core.redaction import RedactionConfig, RedactionEngine


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="default", name="Default")
    session.add(p)
    await session.commit()
    return p


@pytest.fixture
async def agent(session: AsyncSession, project: Project) -> Agent:
    a = Agent(
        project_id=project.id,
        name="web-01",
        token_hash=secrets.token_hex(32),
        protocol_version="1",
        framework_adapter="django",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(a)
    await session.commit()
    return a


@pytest.fixture
def ingestor() -> EventIngestor:
    return EventIngestor(RedactionEngine(RedactionConfig()))


def _evt(
    *,
    kind: str,
    task_id: str = "t",
    engine: str = "celery",
    worker: str | None = None,
    occurred_at: datetime | None = None,
    extra_data: dict | None = None,
) -> dict:
    data: dict = dict(extra_data or {})
    if worker is not None:
        data["worker"] = worker
    return {
        "kind": kind,
        "engine": engine,
        "task_id": task_id,
        "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
        "data": data,
    }


@pytest.mark.asyncio
class TestBulkWorkerUpsert:
    async def test_200_events_one_worker_collapse_to_one_row(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """200 events from one worker → 1 worker row, heartbeat = max occurred_at.

        Events are stamped 100 ms apart in the recent past so they
        all clear the ingestor's ``_OCCURRED_AT_FUTURE_LIMIT``
        (60 s) clamp without being snapped to ``now``.
        """
        base = datetime.now(UTC) - timedelta(seconds=300)
        events = [
            _evt(
                kind="task.started",
                task_id=f"t-{i}",
                worker="celery@web-01",
                occurred_at=base + timedelta(milliseconds=i * 100),
            )
            for i in range(200)
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
            worker_repo=WorkerRepository(session),
        )
        await session.commit()

        # Exactly one worker row, with heartbeat = max occurred_at.
        workers = (await session.execute(select(Worker))).scalars().all()
        assert len(workers) == 1
        w = workers[0]
        assert w.name == "celery@web-01"
        assert w.state == WorkerState.ONLINE
        # MAX occurred_at across the batch is base + 19.9s
        # (200 events x100ms).  SQLite drops timezone, so compare
        # via .replace(tzinfo=None) when needed.
        expected = base + timedelta(milliseconds=199 * 100)
        actual = w.last_heartbeat
        if actual.tzinfo is None:
            expected = expected.replace(tzinfo=None)
        # Allow 1 second slop for serialization rounding.
        assert abs((actual - expected).total_seconds()) < 1.0

    async def test_multiple_workers_each_get_their_max(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """3 workers x50 events each → 3 rows, each carrying its own max."""
        # Push base far enough into the past that worker_2's stride
        # (i + 200) still lands well inside the past-limit window.
        base = datetime.now(UTC) - timedelta(seconds=600)
        events: list[dict] = []
        for w_idx in range(3):
            for i in range(50):
                events.append(
                    _evt(
                        kind="task.succeeded",
                        task_id=f"t-{w_idx}-{i}",
                        worker=f"celery@worker-{w_idx}",
                        occurred_at=base + timedelta(seconds=i + w_idx * 100),
                    ),
                )
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
            worker_repo=WorkerRepository(session),
        )
        await session.commit()

        workers = (
            await session.execute(
                select(Worker).order_by(Worker.name),
            )
        ).scalars().all()
        assert len(workers) == 3
        for idx, w in enumerate(workers):
            assert w.name == f"celery@worker-{idx}"
            # Worker idx's max occurred_at is base + (49 + idx*100)s.
            expected = base + timedelta(seconds=49 + idx * 100)
            actual = w.last_heartbeat
            if actual.tzinfo is None:
                expected = expected.replace(tzinfo=None)
            assert abs((actual - expected).total_seconds()) < 1.0

    async def test_agent_heartbeat_carries_batch_max(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """Agent.last_seen_at = max(occurred_at) in the batch."""
        base = datetime.now(UTC) - timedelta(minutes=10)
        events = [
            _evt(
                kind="task.received",
                task_id=f"t-{i}",
                worker="celery@web-01",
                occurred_at=base + timedelta(seconds=i),
            )
            for i in range(50)
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
            worker_repo=WorkerRepository(session),
        )
        await session.commit()

        await session.refresh(agent)
        # last_seen_at should be base + 49s (max of the batch),
        # NOT wall-clock now() (which is ~10 minutes later).
        expected_max = base + timedelta(seconds=49)
        actual = agent.last_seen_at
        if actual.tzinfo is None:
            expected_max = expected_max.replace(tzinfo=None)
        assert abs((actual - expected_max).total_seconds()) < 2.0
        # And definitively NOT now-ish.
        now = datetime.now(UTC)
        if actual.tzinfo is None:
            now = now.replace(tzinfo=None)
        # The batch's max is ~9 minutes in the past; if the heartbeat
        # accidentally used wall-clock now(), it'd be within seconds.
        assert (now - actual).total_seconds() > 60

    async def test_worker_less_batch_still_heartbeats_agent(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """Events without a worker key still heartbeat the agent."""
        base = datetime.now(UTC) - timedelta(seconds=30)
        events = [
            _evt(
                kind="task.received",
                task_id="t-1",
                # No worker key
                occurred_at=base,
                extra_data={"task_name": "myapp.tasks.f", "queue": "default"},
            ),
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
            worker_repo=WorkerRepository(session),
        )
        await session.commit()

        # No worker row created.
        workers = (await session.execute(select(Worker))).scalars().all()
        assert len(workers) == 0
        # Agent still heartbeated to ~base.
        await session.refresh(agent)
        actual = agent.last_seen_at
        expected = base
        if actual.tzinfo is None:
            expected = expected.replace(tzinfo=None)
        assert abs((actual - expected).total_seconds()) < 2.0

    async def test_lifecycle_projection_unchanged(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """Per-event task projection still works (no regression vs N+1 path)."""
        events = [
            _evt(
                kind="task.received",
                task_id="t-1",
                extra_data={"task_name": "myapp.tasks.f", "queue": "default"},
            ),
            _evt(
                kind="task.started",
                task_id="t-1",
                worker="celery@web-01",
            ),
            _evt(
                kind="task.succeeded",
                task_id="t-1",
                worker="celery@web-01",
                extra_data={"result": {"ok": True}, "runtime_ms": 7},
            ),
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
            worker_repo=WorkerRepository(session),
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.state == TaskState.SUCCESS
        assert task.worker_name == "celery@web-01"
        assert task.runtime_ms == 7
        # And the worker row is there with one heartbeat.
        workers = (await session.execute(select(Worker))).scalars().all()
        assert len(workers) == 1


@pytest.mark.asyncio
class TestBulkUpsertFallback:
    async def test_per_row_fallback_when_bulk_raises(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        """If bulk path raises OperationalError, per-row fallback still lands data."""
        base = datetime.now(UTC) - timedelta(seconds=30)
        events = [
            _evt(
                kind="task.started",
                task_id=f"t-{i}",
                worker=f"celery@w-{i}",
                occurred_at=base + timedelta(seconds=i),
            )
            for i in range(5)
        ]

        # Patch the bulk method to raise OperationalError ONCE,
        # forcing the per-row fallback path. The fallback uses
        # ``upsert_from_event`` (the original slow path) which has
        # its own savepoint scaffolding.
        call_count = {"n": 0}

        async def _exploding_bulk(self, rows):
            call_count["n"] += 1
            raise OperationalError(
                "simulated deadlock", params=None, orig=Exception("deadlock"),
            )

        with patch.object(
            WorkerRepository,
            "upsert_from_events_bulk",
            _exploding_bulk,
        ):
            await ingestor.ingest_batch(
                events=events,
                project_id=project.id,
                agent_id=agent.id,
                agents=AgentRepository(session),
                event_repo=EventRepository(session),
                task_repo=TaskRepository(session),
                queue_repo=QueueRepository(session),
                worker_repo=WorkerRepository(session),
            )
            await session.commit()

        # Bulk method was called exactly once (then raised).
        assert call_count["n"] == 1
        # Per-row fallback successfully landed all 5 worker rows.
        workers = (await session.execute(select(Worker))).scalars().all()
        assert len(workers) == 5
