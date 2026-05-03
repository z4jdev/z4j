"""Tests for ``z4j_brain.domain.event_ingestor.EventIngestor``."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_core.redaction import RedactionConfig, RedactionEngine

from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)


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
