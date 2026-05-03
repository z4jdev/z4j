"""Tests for the audit-log retention sweeper (1.2.2+).

The sweeper runs in two modes:

- SQLite (the homelab default): no triggers, plain DELETE.
- Postgres (production): trigger function permits DELETE only when
  ``z4j.audit_sweep`` GUC is on. The sweeper sets it via
  ``SET LOCAL`` so the opt-in dies at COMMIT.

These tests cover SQLite end-to-end. The Postgres trigger-bypass
path is covered by ``test_audit_retention_postgres`` in B7
integration (Postgres 18 container).
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.audit_retention import AuditRetentionSweeper
from z4j_brain.persistence import models  # noqa: F401  - register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditLog
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        audit_retention_days=30,
        audit_retention_sweep_batch_size=100,
    )


@pytest.fixture
async def db_manager() -> DatabaseManager:
    """Build a DatabaseManager backed by in-memory SQLite."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


async def _insert_audit_row(
    session: AsyncSession,
    *,
    occurred_at: datetime,
    action: str = "test.action",
) -> None:
    """Insert one audit_log row at the given timestamp."""
    row = AuditLog(
        action=action,
        target_type="test",
        target_id="x",
        result="success",
        occurred_at=occurred_at,
    )
    session.add(row)
    await session.flush()


@pytest.mark.asyncio
class TestSweepOnce:
    async def test_disabled_when_retention_zero(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        # Force-enable the field via raw assignment - Pydantic gates >=1
        # but we exercise the runtime guard explicitly.
        object.__setattr__(settings, "audit_retention_days", 0)
        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        deleted = await sweeper.sweep_once()
        assert deleted == 0

    async def test_old_rows_pruned(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        now = datetime.now(UTC)
        # Insert 3 old + 2 fresh rows
        async with db_manager.session() as session:
            for i in range(3):
                await _insert_audit_row(
                    session,
                    occurred_at=now - timedelta(days=settings.audit_retention_days + i + 1),
                )
            for i in range(2):
                await _insert_audit_row(
                    session, occurred_at=now - timedelta(hours=i),
                )
            await session.commit()

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        deleted = await sweeper.sweep_once()
        assert deleted == 3

        # Verify only fresh rows remain
        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AuditLog))
            ).scalars().all()
            assert len(remaining) == 2

    async def test_state_tracking_after_sweep(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        now = datetime.now(UTC)
        async with db_manager.session() as session:
            for _ in range(5):
                await _insert_audit_row(
                    session,
                    occurred_at=now - timedelta(
                        days=settings.audit_retention_days + 5,
                    ),
                )
            await session.commit()

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        await sweeper.sweep_once()
        assert sweeper.last_deleted == 5
        assert sweeper.total_deleted == 5
        assert sweeper.last_run_at is not None
        assert sweeper.last_error is None

        # Second pass should be a no-op (no eligible rows)
        await sweeper.sweep_once()
        assert sweeper.last_deleted == 0
        assert sweeper.total_deleted == 5  # cumulative

    async def test_batched_delete_completes(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        # 250 old rows with batch_size=100 → expect 3 batches
        # (100 + 100 + 50) and total_deleted == 250.
        object.__setattr__(settings, "audit_retention_sweep_batch_size", 100)
        now = datetime.now(UTC)
        async with db_manager.session() as session:
            for i in range(250):
                await _insert_audit_row(
                    session,
                    occurred_at=now - timedelta(
                        days=settings.audit_retention_days + 5,
                        seconds=i,
                    ),
                )
            await session.commit()

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        deleted = await sweeper.sweep_once()
        assert deleted == 250

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AuditLog))
            ).scalars().all()
            assert remaining == []

    async def test_recent_rows_preserved(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        """Rows newer than cutoff must survive even an aggressive sweep."""
        now = datetime.now(UTC)
        async with db_manager.session() as session:
            # Just inside the retention window
            await _insert_audit_row(
                session, occurred_at=now - timedelta(
                    days=settings.audit_retention_days - 1,
                ),
            )
            # Brand new
            await _insert_audit_row(session, occurred_at=now)
            # And one ancient row that should die
            await _insert_audit_row(
                session, occurred_at=now - timedelta(days=365),
            )
            await session.commit()

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        deleted = await sweeper.sweep_once()
        assert deleted == 1

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AuditLog))
            ).scalars().all()
            assert len(remaining) == 2


@pytest.mark.asyncio
class TestLifecycle:
    async def test_start_then_stop_clean(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        # Make sweep interval much shorter than the test so the loop
        # ticks at least once.
        object.__setattr__(
            settings, "audit_retention_sweep_interval_seconds", 60,
        )
        sweeper = AuditRetentionSweeper()
        sweeper.start(db=db_manager, settings=settings)
        assert sweeper._task is not None
        await sweeper.stop()
        assert sweeper._task is None

    async def test_double_start_is_idempotent(
        self, db_manager: DatabaseManager, settings: Settings,
    ) -> None:
        sweeper = AuditRetentionSweeper()
        sweeper.start(db=db_manager, settings=settings)
        first_task = sweeper._task
        sweeper.start(db=db_manager, settings=settings)
        assert sweeper._task is first_task
        await sweeper.stop()

    async def test_stop_without_start_is_noop(self) -> None:
        sweeper = AuditRetentionSweeper()
        await sweeper.stop()
