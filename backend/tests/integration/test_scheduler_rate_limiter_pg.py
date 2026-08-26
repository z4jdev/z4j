"""PostgreSQL race coverage for the persistent scheduler rate limiter."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import Table
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_brain.domain.scheduler_rate_limiter import SchedulerRateLimiter
from z4j_brain.persistence.database import DatabaseManager, create_async_engine_from_url
from z4j_brain.persistence.models import SchedulerRateBucket

pytestmark = pytest.mark.asyncio


async def test_postgres_concurrent_first_insert_consumes_one_shared_budget(
    fresh_database_async_url: str,
) -> None:
    engine = create_async_engine_from_url(fresh_database_async_url)
    async with engine.begin() as connection:
        await connection.run_sync(
            cast("Table", SchedulerRateBucket.__table__).create,
        )

    try:
        db = DatabaseManager(engine)
        settings: Any = SimpleNamespace(
            scheduler_grpc_fire_rate_limit_enabled=True,
            scheduler_grpc_fire_rate_capacity=1.0,
            scheduler_grpc_fire_rate_per_second=0.000001,
        )
        limiter = SchedulerRateLimiter(db=db, settings=settings)
        start = asyncio.Event()

        async def consume_once() -> bool:
            await start.wait()
            return await limiter.consume(cert_cn="simultaneous-new-cert")

        tasks = [asyncio.create_task(consume_once()) for _ in range(32)]
        await asyncio.sleep(0)
        start.set()
        results = await asyncio.gather(*tasks)

        assert sum(results) == 1
        async with db.session() as session:
            bucket = await session.get(
                SchedulerRateBucket,
                "simultaneous-new-cert",
            )
        assert bucket is not None
        assert 0 <= bucket.tokens < 1
    finally:
        await engine.dispose()


async def test_postgres_reordered_callers_never_regress_refill_time(
    fresh_database_async_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller queued before the row lock cannot mint a second burst."""

    engine = create_async_engine_from_url(fresh_database_async_url)
    async with engine.begin() as connection:
        await connection.run_sync(
            cast("Table", SchedulerRateBucket.__table__).create,
        )

    early_at = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    locked_at = early_at + timedelta(seconds=10)
    early_waiting = asyncio.Event()
    release_early = asyncio.Event()

    async def task_database_clock(**_kwargs: object) -> datetime:
        task = asyncio.current_task()
        if task is not None and task.get_name() == "early":
            return early_at
        return locked_at

    class DelayedDatabase:
        def __init__(self, base: DatabaseManager) -> None:
            self._base = base

        @property
        def engine(self) -> Any:
            return self._base.engine

        @asynccontextmanager
        async def session(self, *, write: bool = False) -> AsyncIterator[AsyncSession]:
            task = asyncio.current_task()
            if task is not None and task.get_name() == "early":
                early_waiting.set()
                await release_early.wait()
            async with self._base.session(write=write) as session:
                yield session

    monkeypatch.setattr(
        "z4j_brain.domain.scheduler_rate_limiter._database_now",
        task_database_clock,
    )

    try:
        base = DatabaseManager(engine)
        settings: Any = SimpleNamespace(
            scheduler_grpc_fire_rate_limit_enabled=True,
            scheduler_grpc_fire_rate_capacity=1.0,
            scheduler_grpc_fire_rate_per_second=1.0,
        )
        limiter = SchedulerRateLimiter(
            db=cast("DatabaseManager", DelayedDatabase(base)),
            settings=settings,
        )

        early = asyncio.create_task(
            limiter.consume(cert_cn="reordered-cert"),
            name="early",
        )
        await early_waiting.wait()
        late = asyncio.create_task(
            limiter.consume(cert_cn="reordered-cert"),
            name="late",
        )
        assert await late is True
        release_early.set()
        assert await early is False

        async with base.session() as session:
            after_pair = await session.get(
                SchedulerRateBucket,
                "reordered-cert",
            )
        assert after_pair is not None
        assert after_pair.last_refill == locked_at
        assert after_pair.tokens == 0.0

        # The test task observes the same process instant as the late caller.
        # No elapsed time means no replacement token may exist.
        assert await limiter.consume(cert_cn="reordered-cert") is False
    finally:
        await engine.dispose()
