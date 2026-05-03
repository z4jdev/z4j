"""Tests for the SQLite WAL checkpoint task (1.2.2+).

Three behaviours under test:

1. SQLite engine: ``checkpoint_once`` issues the pragma and
   reports the page count.
2. Postgres-shaped engine: :meth:`start` short-circuits and
   never spawns a task.
3. Lifecycle: ``start`` → ``stop`` is clean and idempotent.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from z4j_brain.persistence import models  # noqa: F401  - register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.settings import Settings
from z4j_brain.wal_checkpoint import WalCheckpointTask


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        wal_checkpoint_interval_seconds=60,
    )


@pytest.fixture
async def db_manager() -> DatabaseManager:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


@pytest.mark.asyncio
class TestSqliteCheckpoint:
    async def test_checkpoint_once_returns_int(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        task = WalCheckpointTask()
        task._db = db_manager
        task._settings = settings
        # In-memory SQLite has no WAL file (WAL mode requires
        # filesystem-backed DB), but the pragma still returns a
        # valid response (typically all zeros). The task must not
        # crash on either WAL or non-WAL DB.
        pages = await task.checkpoint_once()
        assert isinstance(pages, int)
        assert task.last_run_at is not None
        assert task.last_error is None


@pytest.mark.asyncio
class TestPostgresShortCircuit:
    async def test_start_does_not_spawn_on_postgres(
        self, settings: Settings,
    ) -> None:
        # Build a "Postgres-shaped" engine without actually connecting.
        # SQLAlchemy will accept the URL and report ``dialect.name='postgresql'``
        # without trying to connect until first request.
        engine = create_async_engine(
            "postgresql+asyncpg://user:pass@127.0.0.1:1/x",
        )
        try:
            db = DatabaseManager(engine)
            task = WalCheckpointTask()
            task.start(db=db, settings=settings)
            assert task._task is None  # short-circuited
        finally:
            await engine.dispose()


@pytest.mark.asyncio
class TestLifecycle:
    async def test_start_then_stop(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        task = WalCheckpointTask()
        task.start(db=db_manager, settings=settings)
        assert task._task is not None
        await task.stop()
        assert task._task is None

    async def test_double_start_is_idempotent(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        task = WalCheckpointTask()
        task.start(db=db_manager, settings=settings)
        first = task._task
        task.start(db=db_manager, settings=settings)
        assert task._task is first
        await task.stop()

    async def test_stop_without_start_is_noop(self) -> None:
        task = WalCheckpointTask()
        await task.stop()
