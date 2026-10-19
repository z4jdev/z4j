"""Driver failures must classify independently of monitored task payloads."""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncpg
import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.event_ingestor import (
    EventIngestor,
    _is_transient_db_error,
    _looks_like_deadlock,
)
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.settings import Settings
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_brain.websocket.registry import LocalRegistry
from z4j_core.redaction import RedactionConfig, RedactionEngine
from z4j_core.transport.frames import EventBatchAckFrame, EventBatchFrame, EventBatchPayload


@pytest.mark.parametrize(
    "payload",
    [
        "ordinary result",
        "no such column",
        "no such table",
        "no such function",
        "has no column",
        "syntax error",
        "too many",
        "unrecognized token",
    ],
)
def test_real_sqlite_lock_ignores_bound_payload(tmp_path: Path, payload: str) -> None:
    database = tmp_path / "contended.db"
    with closing(sqlite3.connect(database)) as setup, setup:
        setup.execute("CREATE TABLE events (payload TEXT)")
    engine = create_engine(f"sqlite:///{database}", connect_args={"timeout": 0})
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with engine.connect() as connection, pytest.raises(OperationalError) as failure:
            connection.execute(text("INSERT INTO events VALUES (:payload)"), {"payload": payload})

        error = failure.value
        assert isinstance(error.orig, sqlite3.OperationalError)
        assert error.orig.sqlite_errorcode == sqlite3.SQLITE_BUSY
        assert payload in str(error)  # SQLAlchemy includes the unrelated event content.
        assert _is_transient_db_error(error) is True
        assert _looks_like_deadlock(error) is True
    finally:
        blocker.rollback()
        blocker.close()
        engine.dispose()


@pytest.mark.parametrize("payload", ["deadlock", "could not serialize", "database is locked"])
def test_real_sqlite_syntax_error_does_not_inherit_payload_retry(
    tmp_path: Path,
    payload: str,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'syntax.db'}")
    try:
        with engine.connect() as connection, pytest.raises(OperationalError) as failure:
            connection.execute(text("INSERT INT events VALUES (:payload)"), {"payload": payload})

        error = failure.value
        assert isinstance(error.orig, sqlite3.OperationalError)
        assert error.orig.sqlite_errorcode == sqlite3.SQLITE_ERROR
        assert payload in str(error)
        assert _is_transient_db_error(error) is False
        assert _looks_like_deadlock(error) is False
    finally:
        engine.dispose()


def test_real_sqlite_busy_snapshot_uses_extended_lock_code(tmp_path: Path) -> None:
    database = tmp_path / "snapshot.db"
    writer = sqlite3.connect(database)
    engine = create_engine(f"sqlite:///{database}", connect_args={"timeout": 0})
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE events (payload TEXT)")
        writer.commit()
        with engine.connect() as reader:
            reader.exec_driver_sql("BEGIN")
            reader.execute(text("SELECT * FROM events"))
            writer.execute("INSERT INTO events VALUES ('committed writer')")
            writer.commit()
            with pytest.raises(OperationalError) as failure:
                reader.execute(
                    text("INSERT INTO events VALUES (:payload)"),
                    {"payload": "syntax error; too many"},
                )

        error = failure.value
        assert isinstance(error.orig, sqlite3.OperationalError)
        assert error.orig.sqlite_errorcode == sqlite3.SQLITE_BUSY_SNAPSHOT
        assert _is_transient_db_error(error) is True
        assert _is_transient_db_error(error.orig) is True
        assert _looks_like_deadlock(error) is True
    finally:
        writer.close()
        engine.dispose()


def test_wrapper_with_no_driver_diagnostic_does_not_use_sql_or_parameters() -> None:
    error = DBAPIError(
        "INSERT INTO events (payload) VALUES (:payload) -- deadlock",
        {"payload": "could not serialize"},
        None,
    )
    assert _is_transient_db_error(error) is False
    assert _looks_like_deadlock(error) is False


@pytest.mark.parametrize(
    ("driver_class", "message", "transient", "retry_savepoint"),
    [
        (asyncpg.exceptions.DeadlockDetectedError, "deadlock detected", True, True),
        (asyncpg.exceptions.SerializationError, "could not serialize access", True, True),
        (asyncpg.exceptions.LockNotAvailableError, "lock not available", True, False),
        (asyncpg.exceptions.UndefinedColumnError, "column does not exist", True, False),
        (asyncpg.exceptions.UniqueViolationError, "duplicate key", False, False),
        (asyncpg.exceptions.StringDataRightTruncationError, "value too long", False, False),
        (asyncpg.exceptions.InternalServerError, "unrelated backend failure", False, False),
        (
            asyncpg.exceptions.InternalServerError,
            "cache lookup failed for type 12345",
            True,
            False,
        ),
    ],
)
def test_postgres_driver_codes_ignore_sqlalchemy_parameters(
    driver_class: type[Exception],
    message: str,
    transient: bool,
    retry_savepoint: bool,
) -> None:
    error = DBAPIError(
        "INSERT INTO events (payload) VALUES (:payload)",
        {"payload": "syntax error; too many; deadlock; cache lookup failed for type 99"},
        driver_class(message),
    )
    assert _is_transient_db_error(error) is transient
    assert _looks_like_deadlock(error) is retry_savepoint


@pytest.mark.parametrize("payload", ["ordinary result", "syntax error", "too many"])
async def test_router_withholds_ack_during_real_lock_then_persists_replay(
    tmp_path: Path,
    payload: str,
    brain_settings: Settings,
) -> None:
    database = tmp_path / "router-contention.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database}",
        connect_args={"timeout": 0},
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        project = Project(slug="driver-errors", name="Driver errors")
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name="driver-error-agent",
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

    class _Database:
        @asynccontextmanager
        async def session(self, *, write: bool = False) -> AsyncIterator[AsyncSession]:
            # Exercise errors at the INSERT boundary. Production's SQLite
            # BEGIN IMMEDIATE gate may encounter contention earlier instead.
            del write
            async with factory() as session:
                yield session

    sent: list[Any] = []

    async def send(frame: Any) -> None:
        sent.append(frame)

    async def unexpected_command(*_args: Any) -> bool:
        raise AssertionError("This ingestion fixture has no rules or outbound commands")

    router = FrameRouter(
        db=_Database(),  # type: ignore[arg-type]
        ingestor=EventIngestor(RedactionEngine(RedactionConfig())),
        dispatcher=CommandDispatcher(
            settings=brain_settings,
            registry=LocalRegistry(deliver_local=unexpected_command),
            audit=AuditService(brain_settings),
        ),
        project_id=project.id,
        agent_id=agent.id,
        send_frame=send,
    )
    frame = EventBatchFrame(
        id="real-lock-replay",
        payload=EventBatchPayload(
            events=[
                {
                    "id": "real-lock-event",
                    "engine": "celery",
                    "kind": "task.succeeded",
                    "task_id": "real-lock-task",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "data": {"task_name": "jobs.contention", "result": payload},
                },
            ],
        ),
    )

    async def drain_router_tasks() -> None:
        # Successful ingestion also dispatches notifications and automation.
        # Those tasks own sessions and must finish before engine disposal.
        tasks = (
            router._pending_ack_tasks
            | router._pending_notify_tasks
            | router._pending_automation_tasks
        )
        if tasks:
            await asyncio.gather(*tasks)

    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        first = await router.dispatch(frame)
        await drain_router_tasks()
        assert first is FrameOutcome.TRANSIENT
        assert sent == []
        async with factory() as session:
            assert await session.scalar(select(func.count()).select_from(Event)) == 0

        blocker.rollback()
        assert await router.dispatch(frame) is FrameOutcome.DURABLE
        await drain_router_tasks()
        assert len(sent) == 1
        assert isinstance(sent[0], EventBatchAckFrame)
        assert sent[0].payload.acked_id == frame.id
        assert sent[0].payload.accepted == 1

        # A delivery replay after successful persistence must still dedupe.
        assert await router.dispatch(frame) is FrameOutcome.DURABLE
        await drain_router_tasks()
        async with factory() as session:
            assert await session.scalar(select(func.count()).select_from(Event)) == 1
            task = (await session.execute(select(Task))).scalar_one()
            assert task.result == payload
    finally:
        blocker.rollback()
        blocker.close()
        await drain_router_tasks()
        router.aclose()
        await engine.dispose()
