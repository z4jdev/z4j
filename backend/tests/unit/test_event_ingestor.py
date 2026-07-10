"""Tests for ``z4j_brain.domain.event_ingestor.EventIngestor``."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)
from z4j_core.redaction import RedactionConfig, RedactionEngine


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
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


def _make_event(
    *,
    kind: str,
    task_id: str = "task-001",
    engine: str = "celery",
    data: dict | None = None,
    occurred_at: datetime | None = None,
) -> dict:
    return {
        "kind": kind,
        "engine": engine,
        "task_id": task_id,
        "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
        "data": data or {},
    }


@pytest.mark.asyncio
class TestIngestBasic:
    async def test_received_event_creates_task_row(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={
                    "task_name": "myapp.tasks.send_email",
                    "queue": "default",
                    "args": [],
                    "kwargs": {"to": "alice@example.com"},
                },
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
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.name == "myapp.tasks.send_email"
        assert task.state == TaskState.RECEIVED
        assert task.queue == "default"

    async def test_started_then_succeeded_lifecycle(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={"task_name": "myapp.tasks.f", "queue": "default"},
            ),
            _make_event(
                kind="task.started",
                data={"worker": "celery@web-01"},
            ),
            _make_event(
                kind="task.succeeded",
                data={"result": {"ok": True}, "runtime_ms": 42},
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
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.state == TaskState.SUCCESS
        assert task.worker_name == "celery@web-01"
        assert task.runtime_ms == 42
        assert task.result == {"ok": True}

    async def test_failure_records_exception_and_traceback(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={"task_name": "myapp.tasks.broken"},
            ),
            _make_event(
                kind="task.failed",
                data={
                    "exception": "RuntimeError",
                    "traceback": "Traceback...\nRuntimeError: kaboom",
                },
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
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.state == TaskState.FAILURE
        assert task.exception == "RuntimeError"
        assert "kaboom" in task.traceback


@pytest.mark.asyncio
class TestIdempotence:
    async def test_replayed_event_does_not_duplicate(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        # Insert one event, then try to insert it again as part of
        # a second batch. The events table dedupes by (occurred_at, id);
        # the brain mints its own ids, so two distinct ids for the
        # same logical event still create two rows. We assert that
        # the TASKS row stays consistent (one task) regardless.
        ev = _make_event(
            kind="task.received",
            data={"task_name": "x"},
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        tasks = (await session.execute(select(Task))).scalars().all()
        assert len(tasks) == 1


@pytest.mark.asyncio
class TestRedactionDefenseInDepth:
    async def test_password_in_kwargs_redacted(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        # Agent should already have redacted; brain re-applies. We
        # send an UNREDACTED kwargs to simulate a misconfigured
        # agent and verify the brain catches it.
        ev = _make_event(
            kind="task.received",
            data={
                "task_name": "myapp.tasks.login",
                "kwargs": {"password": "hunter2"},
            },
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (await session.execute(select(Task))).scalar_one()
        assert task.kwargs is not None
        # The redaction engine replaces the value with [REDACTED].
        assert "hunter2" not in str(task.kwargs)


@pytest.mark.asyncio
class TestHeartbeat:
    async def test_event_traffic_bumps_last_seen(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        ev = _make_event(kind="task.received", data={"task_name": "x"})
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        await session.refresh(agent)
        assert agent.last_seen_at is not None


@pytest.mark.asyncio
async def test_ingest_batch_returns_only_new_events(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """A re-delivered event (same content -> same content-derived
    event_id) is deduped at insert and is NOT returned, so the caller's
    automation hook fires ONCE per logical event, not once per delivery.
    This is the fix for the flaky-WS reconnect firing amplification.
    """
    ev = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
    )

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    first = await ingestor.ingest_batch(events=[ev], **_kw())
    await session.commit()
    assert len(first) == 1  # genuinely new -> returned (rule would fire)

    # Re-deliver the exact same event (agent reconnect buffer re-flush).
    second = await ingestor.ingest_batch(events=[ev], **_kw())
    await session.commit()
    assert second == []  # duplicate -> NOT returned -> rule does NOT re-fire

    # Exactly one events row exists (dedup held).
    rows = (await session.execute(select(Event))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_subsecond_divergent_redelivery_dedupes(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """Two deliveries of ONE logical task event that differ only in the
    sub-second of occurred_at (the celery-events fan-out, or two brain
    replicas) must collapse to a single events row and fire automation
    once. The content-derived event_id is second-grained, so occurred_at
    is stored at second granularity too; otherwise the (project_id,
    occurred_at, id) conflict key would miss and both would insert.
    """
    base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    ev1 = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
        occurred_at=base.replace(microsecond=100_000),
    )
    ev2 = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
        occurred_at=base.replace(microsecond=400_000),
    )

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    first = await ingestor.ingest_batch(events=[ev1], **_kw())
    await session.commit()
    assert len(first) == 1

    second = await ingestor.ingest_batch(events=[ev2], **_kw())
    await session.commit()
    # Same logical event within one second -> deduped, no second firing.
    assert second == []
    rows = (await session.execute(select(Event))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_heartbeat_touch_failure_does_not_lose_events(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deadlock/failure on the best-effort heartbeat touch (now wrapped
    in its own savepoint) must NOT abort the batch: the ingested events
    still commit and are returned. Live-test finding: an unprotected
    deadlock there lost the whole batch and automation never fired.
    """
    ev = _make_event(kind="task.received", data={"task_name": "x"})
    agents_repo = AgentRepository(session)

    async def _boom(*_a, **_k):
        raise RuntimeError("simulated heartbeat deadlock")

    monkeypatch.setattr(agents_repo, "touch_heartbeat_at", _boom)

    new = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=agents_repo,
        event_repo=EventRepository(session),
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    # Heartbeat failed, but the event survived (savepoint isolation).
    assert len(new) == 1
    task = (await session.execute(select(Task))).scalar_one()
    assert task.name == "x"
