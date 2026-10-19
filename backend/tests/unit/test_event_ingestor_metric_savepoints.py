"""Task metrics follow each event's savepoint, as well as the outer commit."""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from z4j_brain.api.metrics import registry
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_core.redaction import RedactionConfig, RedactionEngine
from z4j_core.transport.frames import EventBatchFrame, EventBatchPayload


def _terminal_event(task_id: str, **extra: Any) -> dict[str, Any]:
    return {
        "engine": "celery",
        "kind": "task.succeeded",
        "task_id": task_id,
        "occurred_at": datetime.now(UTC).isoformat(),
        "data": {"task_name": task_id, "runtime_ms": 250, "result": "done", **extra},
    }


def _metric(project_id: UUID, name: str, task_name: str, **labels: str) -> float:
    return (
        registry.get_sample_value(
            name,
            {"project": str(project_id), "task_name": task_name, **labels},
        )
        or 0.0
    )


def _repositories(session: AsyncSession, project: Project, agent: Agent) -> dict[str, Any]:
    return {
        "project_id": project.id,
        "agent_id": agent.id,
        "agents": AgentRepository(session),
        "event_repo": EventRepository(session),
        "task_repo": TaskRepository(session),
        "queue_repo": QueueRepository(session),
    }


@pytest.fixture
async def metric_session() -> AsyncIterator[tuple[AsyncSession, Project, Agent]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            project = Project(slug="metric-savepoints", name="Metric savepoints")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="metric-savepoint-agent",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.commit()
            yield session, project, agent
    finally:
        await engine.dispose()


@pytest.mark.parametrize(
    "invalid_envelope",
    [
        {"external_projection": {}},
        {"external_snapshot_frame": {}},
        {"external_projection": {}, "external_snapshot_frame": {}},
    ],
    ids=["invalid-projection", "invalid-snapshot", "conflicting-envelopes"],
)
async def test_late_validation_rollback_does_not_emit_task_metrics(
    metric_session: tuple[AsyncSession, Project, Agent],
    invalid_envelope: dict[str, Any],
) -> None:
    session, project, agent = metric_session
    ingestor = EventIngestor(RedactionEngine(RedactionConfig()))

    def metric(name: str, task_name: str, **labels: str) -> float:
        return _metric(project.id, name, task_name, **labels)

    kwargs = _repositories(session, project, agent)
    failed = _terminal_event("rolled-back-task", **invalid_envelope)
    accepted = _terminal_event("committed-task")
    await session.execute(text("BEGIN"))
    result = await ingestor.ingest_batch(events=[failed, accepted], **kwargs)
    assert result.inserted_count == 1
    assert result.fully_durable is True  # Invalid envelopes are permanent skips.
    assert metric("z4j_tasks_total", "committed-task", state="task.succeeded") == 0
    await session.commit()

    # The late, real protocol validation error rolled back both task and event.
    assert (await session.scalars(select(Event.task_id))).all() == ["committed-task"]
    assert (await session.scalars(select(Task.task_id))).all() == ["committed-task"]

    result.emit_metrics()
    assert metric("z4j_tasks_total", "committed-task", state="task.succeeded") == 1
    assert metric("z4j_task_duration_seconds_count", "committed-task") == 1
    assert metric("z4j_task_duration_seconds_sum", "committed-task") == 0.25
    assert metric("z4j_tasks_total", "rolled-back-task", state="task.succeeded") == 0
    assert metric("z4j_task_duration_seconds_count", "rolled-back-task") == 0
    assert metric("z4j_task_duration_seconds_sum", "rolled-back-task") == 0

    # A corrected resend should supply its one observation; its already-stored
    # sibling should not gain another observation from this delivery.
    await session.execute(text("BEGIN"))
    replay = await ingestor.ingest_batch(
        events=[_terminal_event("rolled-back-task"), accepted],
        **kwargs,
    )
    await session.commit()
    replay.emit_metrics()
    assert replay.inserted_count == 1
    for task_name in ("rolled-back-task", "committed-task"):
        assert metric("z4j_tasks_total", task_name, state="task.succeeded") == 1
        assert metric("z4j_task_duration_seconds_count", task_name) == 1
        assert metric("z4j_task_duration_seconds_sum", task_name) == 0.25


async def test_late_transient_failure_discards_metrics_from_the_failed_attempt(
    metric_session: tuple[AsyncSession, Project, Agent],
    tmp_path: Path,
) -> None:
    session, project, agent = metric_session
    database = tmp_path / "late-write.db"
    blocker = sqlite3.connect(database)
    blocker.execute("CREATE TABLE late_write (value TEXT)")
    blocker.commit()
    blocker.execute("BEGIN IMMEDIATE")
    late_engine = create_async_engine(
        f"sqlite+aiosqlite:///{database}",
        connect_args={"timeout": 0},
    )
    attempts = 0

    class _LateWriteIngestor(EventIngestor):
        async def _ingest_one(self, **kwargs: Any) -> Any:
            nonlocal attempts
            attempts += 1
            result = await super()._ingest_one(**kwargs)
            # Inject a later persistence step after the real task projection
            # has queued its metrics. The first attempt gets a real SQLite
            # lock error; the next attempt can complete its savepoint.
            try:
                async with late_engine.begin() as connection:
                    await connection.execute(text("INSERT INTO late_write VALUES ('observed')"))
            finally:
                blocker.rollback()
            return result

    try:
        ingestor = _LateWriteIngestor(RedactionEngine(RedactionConfig()))
        await session.execute(text("BEGIN"))
        result = await ingestor.ingest_batch(
            events=[_terminal_event("retry-task")],
            **_repositories(session, project, agent),
        )
        assert attempts == 2
        assert result.fully_durable is True
        assert result.inserted_count == 1
        await session.commit()
        assert (await session.scalars(select(Event.task_id))).all() == ["retry-task"]
        assert (await session.scalars(select(Task.task_id))).all() == ["retry-task"]
        result.emit_metrics()
        assert _metric(project.id, "z4j_tasks_total", "retry-task", state="task.succeeded") == 1
        assert _metric(project.id, "z4j_task_duration_seconds_count", "retry-task") == 1
        assert _metric(project.id, "z4j_task_duration_seconds_sum", "retry-task") == 0.25
    finally:
        blocker.close()
        await late_engine.dispose()


async def test_router_outer_commit_failure_does_not_emit_any_event_metrics(
    metric_session: tuple[AsyncSession, Project, Agent],
) -> None:
    session, project, agent = metric_session
    # A deferred constraint lets every per-event savepoint succeed, then causes
    # a real database error at the router's outer COMMIT.
    await session.execute(text("PRAGMA foreign_keys=ON"))
    await session.execute(text("CREATE TABLE metric_parent (id INTEGER PRIMARY KEY)"))
    await session.execute(
        text(
            "CREATE TABLE metric_child (parent_id INTEGER REFERENCES metric_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)",
        ),
    )
    await session.execute(
        text(
            "CREATE TRIGGER deferred_event_failure AFTER INSERT ON events BEGIN "
            "INSERT INTO metric_child VALUES (999); END",
        ),
    )
    await session.commit()
    sent: list[Any] = []

    async def send(frame: Any) -> None:
        sent.append(frame)

    router = FrameRouter(
        db=DatabaseManager(session.bind),  # type: ignore[arg-type]
        ingestor=EventIngestor(RedactionEngine(RedactionConfig())),
        dispatcher=object(),  # type: ignore[arg-type]
        project_id=project.id,
        agent_id=agent.id,
        send_frame=send,
    )
    result = await router.dispatch(
        EventBatchFrame(
            id="commit-failed",
            payload=EventBatchPayload(events=[_terminal_event("commit-failed-task")]),
        ),
    )
    if router._pending_ack_tasks:
        await asyncio.gather(*tuple(router._pending_ack_tasks))
    assert result is FrameOutcome.DROP
    assert len(sent) == 1
    assert (await session.scalars(select(Event.task_id))).all() == []
    assert (await session.scalars(select(Task.task_id))).all() == []
    assert _metric(project.id, "z4j_tasks_total", "commit-failed-task", state="task.succeeded") == 0
    assert _metric(project.id, "z4j_task_duration_seconds_count", "commit-failed-task") == 0
    assert _metric(project.id, "z4j_task_duration_seconds_sum", "commit-failed-task") == 0
    assert (
        registry.get_sample_value(
            "z4j_events_ingested_total",
            {"project": str(project.id), "engine": "celery", "kind": "task.succeeded"},
        )
        == 0
    )
