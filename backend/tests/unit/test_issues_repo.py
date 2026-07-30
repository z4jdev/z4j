"""Tests for the Issues aggregation repository."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories import IssuesRepository
from z4j_core.models.task import TaskState


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _project(session: AsyncSession) -> uuid.UUID:
    p = Project(id=uuid.uuid4(), slug=f"p{uuid.uuid4().hex[:8]}", name="P")
    session.add(p)
    await session.flush()
    return p.id


def _task(
    project_id,
    *,
    engine,
    task_id,
    state,
    fingerprint,
    name="t.t",
    exc="ValueError",
    last_failed_at=None,
    finished_at=None,
):
    return Task(
        project_id=project_id,
        engine=engine,
        task_id=task_id,
        name=name,
        state=state,
        fingerprint=fingerprint,
        exception=exc if fingerprint else None,
        last_failed_at=last_failed_at,
        finished_at=finished_at,
    )


@pytest.mark.asyncio
async def test_groups_by_fingerprint_with_open_and_recovered(session: AsyncSession) -> None:
    pid = await _project(session)
    session.add_all(
        [
            # Issue A: 2 failing + 1 recovered, across celery + rq.
            _task(pid, engine="celery", task_id="a1", state=TaskState.FAILURE, fingerprint="AAA"),
            _task(pid, engine="rq", task_id="a2", state=TaskState.FAILURE, fingerprint="AAA"),
            _task(pid, engine="celery", task_id="a3", state=TaskState.SUCCESS, fingerprint="AAA"),
            # Issue B: 1 recovered only.
            _task(pid, engine="celery", task_id="b1", state=TaskState.SUCCESS, fingerprint="BBB"),
            # A currently-successful task that never failed -> no fingerprint,
            # must NOT appear.
            _task(pid, engine="celery", task_id="c1", state=TaskState.SUCCESS, fingerprint=None),
        ],
    )
    await session.commit()

    issues, cursor = await IssuesRepository(session).list_issues(project_id=pid)
    by_fp = {i.fingerprint: i for i in issues}
    assert set(by_fp) == {"AAA", "BBB"}

    a = by_fp["AAA"]
    assert a.occurrences == 3
    assert a.open_count == 2
    assert a.recovered_count == 1
    assert a.engine_count == 2
    assert set(a.engines) == {"celery", "rq"}

    b = by_fp["BBB"]
    assert b.open_count == 0
    assert b.recovered_count == 1
    assert cursor is None


@pytest.mark.asyncio
async def test_status_filter(session: AsyncSession) -> None:
    pid = await _project(session)
    session.add_all(
        [
            _task(pid, engine="celery", task_id="o1", state=TaskState.FAILURE, fingerprint="OPEN"),
            _task(pid, engine="celery", task_id="r1", state=TaskState.SUCCESS, fingerprint="RECO"),
        ],
    )
    await session.commit()
    repo = IssuesRepository(session)

    ongoing, _ = await repo.list_issues(project_id=pid, status="ongoing")
    assert [i.fingerprint for i in ongoing] == ["OPEN"]

    recovered, _ = await repo.list_issues(project_id=pid, status="recovered")
    assert [i.fingerprint for i in recovered] == ["RECO"]


@pytest.mark.asyncio
async def test_engine_filter(session: AsyncSession) -> None:
    pid = await _project(session)
    session.add_all(
        [
            _task(pid, engine="celery", task_id="c", state=TaskState.FAILURE, fingerprint="X"),
            _task(pid, engine="rq", task_id="r", state=TaskState.FAILURE, fingerprint="Y"),
        ],
    )
    await session.commit()
    issues, _ = await IssuesRepository(session).list_issues(project_id=pid, engine="rq")
    assert [i.fingerprint for i in issues] == ["Y"]


@pytest.mark.asyncio
async def test_engine_filter_constrains_engines_list(session: AsyncSession) -> None:
    """REGRESSION: with ?engine=celery the engines list must NOT leak the
    other engines the fingerprint also spans (engine_count would say 1 but
    engines said [celery, rq])."""
    pid = await _project(session)
    session.add_all(
        [
            _task(
                pid, engine="celery", task_id="c1", state=TaskState.FAILURE, fingerprint="SHARED"
            ),
            _task(pid, engine="rq", task_id="r1", state=TaskState.FAILURE, fingerprint="SHARED"),
        ],
    )
    await session.commit()

    issues, _ = await IssuesRepository(session).list_issues(project_id=pid, engine="celery")
    assert len(issues) == 1
    row = issues[0]
    assert row.fingerprint == "SHARED"
    # engine_count (from the main aggregate) and the engines list must agree.
    assert row.engine_count == 1
    assert row.engines == ["celery"]


@pytest.mark.asyncio
async def test_pagination_cursor(session: AsyncSession) -> None:
    pid = await _project(session)
    # 3 distinct fingerprints, each one failing task.
    for i in range(3):
        session.add(
            _task(
                pid,
                engine="celery",
                task_id=f"t{i}",
                state=TaskState.FAILURE,
                fingerprint=f"FP{i}",
            ),
        )
    await session.commit()
    repo = IssuesRepository(session)

    page1, cursor = await repo.list_issues(project_id=pid, limit=2)
    assert len(page1) == 2
    assert cursor is not None
    page2, cursor2 = await repo.list_issues(project_id=pid, limit=2, cursor=cursor)
    assert len(page2) == 1
    assert cursor2 is None
    # No overlap across pages.
    seen = {i.fingerprint for i in page1} | {i.fingerprint for i in page2}
    assert seen == {"FP0", "FP1", "FP2"}


@pytest.mark.asyncio
async def test_seen_window_tracks_failure_time_not_recovery(session: AsyncSession) -> None:
    """A task that FAILED long ago but RECOVERED
    recently (finished_at overwritten) must surface by its failure time, not
    its recovery time. The ?hours window filters on last_failed_at."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    old_fail = now - timedelta(days=10)
    recent_recovery = now - timedelta(minutes=5)

    pid = await _project(session)
    # Recovered (SUCCESS) but its last failure was 10 days ago; finished_at
    # (recovery) is 5 minutes ago.
    session.add(
        _task(
            pid,
            engine="celery",
            task_id="r1",
            state=TaskState.SUCCESS,
            fingerprint="OLD",
            last_failed_at=old_fail,
            finished_at=recent_recovery,
        ),
    )
    await session.commit()

    repo = IssuesRepository(session)
    # first/last seen reflect the FAILURE (10 days ago), not the recovery.
    # (SQLite returns naive datetimes for timezone=True columns; normalize.)
    issues, _ = await repo.list_issues(project_id=pid)
    seen = issues[0].last_seen
    if seen is not None and seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    assert seen == old_fail

    # A 2-hour window excludes it (it last failed 10 days ago), even though
    # it recovered 5 minutes ago.
    windowed, _ = await repo.list_issues(project_id=pid, since=now - timedelta(hours=2))
    assert windowed == []


@pytest.mark.asyncio
async def test_project_scoped(session: AsyncSession) -> None:
    pid_a = await _project(session)
    pid_b = await _project(session)
    session.add_all(
        [
            _task(pid_a, engine="celery", task_id="x", state=TaskState.FAILURE, fingerprint="A"),
            _task(pid_b, engine="celery", task_id="y", state=TaskState.FAILURE, fingerprint="B"),
        ],
    )
    await session.commit()
    issues, _ = await IssuesRepository(session).list_issues(project_id=pid_a)
    assert [i.fingerprint for i in issues] == ["A"]
