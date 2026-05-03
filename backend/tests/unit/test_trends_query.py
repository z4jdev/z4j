"""Trends endpoint query shape test (SQLite path).

Verifies that the dialect-aware time-bucketing expression produces
one row per (bucket, state) group and that the counts + runtimes
roll up as expected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.api.trends import _bucket_expr
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
