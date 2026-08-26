"""Trends endpoint query shape test (SQLite path).

Verifies that the dialect-aware time-bucketing expression produces
one row per (bucket, state) group and that the counts + runtimes
roll up as expected.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.api.trends import (
    TrendBucket,
    _bucket_expr,
    _normalize_bucket_timestamp,
    get_trends,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Project, Task


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


@pytest.mark.asyncio
async def test_bucket_expr_groups_tasks_by_hour(engine):
    """Three tasks at t, t+10m, t+70m should land in two 1h buckets."""
    base = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    async with AsyncSession(engine) as s:
        p = Project(slug="proj", name="Proj")
        s.add(p)
        await s.commit()
        await s.refresh(p)
        project_id = p.id

        # Bucket A (12:00): success @ 12:00, failure @ 12:10
        # Bucket B (13:00): success @ 13:10
        for i, (offset, state, rt) in enumerate(
            [
                (timedelta(0), TaskState.SUCCESS, 100),
                (timedelta(minutes=10), TaskState.FAILURE, 200),
                (timedelta(minutes=70), TaskState.SUCCESS, 400),
            ],
        ):
            s.add(
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id=f"t-{i}",
                    name="myapp.tasks.x",
                    state=state,
                    started_at=base + offset - timedelta(seconds=rt / 1000),
                    finished_at=base + offset,
                    runtime_ms=rt,
                ),
            )
        await s.commit()

        b_expr = _bucket_expr(s, 3_600).label("b")
        rows = (
            await s.execute(
                select(
                    b_expr,
                    Task.state,
                    func.count(Task.id),
                )
                .where(Task.project_id == project_id)
                .group_by(b_expr, Task.state)
                .order_by(b_expr),
            )
        ).all()

    # Expected: 3 rows - (A, success, 1), (A, failure, 1), (B, success, 1)
    assert len(rows) == 3
    buckets = {str(r[0]) for r in rows}
    assert len(buckets) == 2  # two distinct hour buckets


@pytest.mark.asyncio
async def test_sqlite_response_uses_utc_timestamp_and_non_null_runtime_weight(engine):
    """SQLite response timestamps and exact combined averages match the contract."""
    bucket_start = (datetime.now(UTC) - timedelta(hours=2)).replace(
        minute=0,
        second=0,
        microsecond=0,
    )
    async with AsyncSession(engine) as session:
        project = Project(slug="proj", name="Proj")
        session.add(project)
        await session.commit()
        await session.refresh(project)
        project_id = project.id

        # SQLite's AVG for SUCCESS is not exactly representable as a float:
        # (1 * 6 + 55) / 7. Reconstructing the sum with AVG * COUNT can round
        # below 64 and truncate the combined average to 7 instead of 8.
        for index, (state, runtime_ms) in enumerate(
            [(TaskState.SUCCESS, 1)] * 6
            + [
                (TaskState.SUCCESS, 55),
                (TaskState.FAILURE, 3),
                (TaskState.FAILURE, None),
            ],
        ):
            session.add(
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id=f"weighted-{index}",
                    name="myapp.tasks.weighted",
                    state=state,
                    finished_at=bucket_start + timedelta(minutes=index),
                    runtime_ms=runtime_ms,
                ),
            )
        # Keep division in the integer domain too: converting this runtime to
        # binary float would silently lose one millisecond.
        large_runtime = 2**53 + 1
        session.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="large-runtime",
                name="myapp.tasks.weighted",
                state=TaskState.SUCCESS,
                finished_at=bucket_start + timedelta(hours=1),
                runtime_ms=large_runtime,
            ),
        )
        await session.commit()

        project_record = SimpleNamespace(id=project_id, is_active=True)
        projects = SimpleNamespace(get_by_slug=AsyncMock(return_value=project_record))
        response = await get_trends(
            slug="proj",
            window="24h",
            bucket="1h",
            user=SimpleNamespace(id=uuid.uuid4(), is_admin=True),
            memberships=SimpleNamespace(),
            projects=projects,
            db_session=session,
        )

    assert len(response.series) == 2
    result = response.series[0]
    assert result.t == bucket_start
    assert result.t.tzinfo is UTC
    assert response.model_dump(mode="json")["series"][0]["t"] == bucket_start.isoformat().replace(
        "+00:00",
        "Z",
    )
    assert result.success == 7
    assert result.failure == 2
    assert result.total == 9
    assert result.avg_runtime_ms == 8
    assert response.series[1].avg_runtime_ms == large_runtime


def test_postgresql_shape_timestamp_is_normalized_to_utc():
    """A PostgreSQL-shaped aware datetime is serialized in the same UTC form."""
    pg_value = datetime.fromisoformat("2026-04-15T14:00:00+02:00")

    result = _normalize_bucket_timestamp(pg_value)

    assert result == datetime(2026, 4, 15, 12, 0, tzinfo=UTC)
    assert result.tzinfo is UTC
    assert TrendBucket(t=result).model_dump(mode="json")["t"] == "2026-04-15T12:00:00Z"
