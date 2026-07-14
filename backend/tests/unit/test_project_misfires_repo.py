"""``AuditLogRepository.list_misfires_for_project`` (project-wide misfires).

Proves the project-wide misfire query that backs the ``GET
/projects/{slug}/schedules/misfires`` endpoint + the ``z4j misfires``
CLI:

- rows span MULTIPLE schedules in the project (no per-schedule filter);
- ordering is newest-first on ``(occurred_at, id)``;
- each row's ``target_id`` is its own schedule id;
- another project's misfires are excluded (project-scoped / IDOR-safe);
- non-misfire audit rows are excluded (action filter);
- ``limit`` is honoured and hard-capped at 1000.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401  registers metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
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


async def _misfire(
    audit: AuditService,
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    when: str,
    late: float,
) -> None:
    """Write one ``scheduler.misfire_detected`` row (target_id = schedule)."""
    await audit.record(
        AuditLogRepository(session),
        action="scheduler.misfire_detected",
        target_type="schedule",
        target_id=str(schedule_id),
        result="failed",
        outcome="error",
        project_id=project_id,
        metadata={
            "name": f"sched-{str(schedule_id)[:4]}",
            "engine": "celery",
            "kind": "interval",
            "expected_fire_at": when,
            "lateness_seconds": late,
            "grace_seconds": 60,
        },
    )
    await session.commit()


@pytest.mark.asyncio
async def test_spans_schedules_newest_first_and_project_scoped(
    settings: Settings,
    session: AsyncSession,
) -> None:
    audit = AuditService(settings)
    project_id = uuid.uuid4()
    other_project_id = uuid.uuid4()
    sched_a = uuid.uuid4()
    sched_b = uuid.uuid4()

    # Two schedules in the project, plus one row under ANOTHER project.
    await _misfire(
        audit,
        session,
        project_id=project_id,
        schedule_id=sched_a,
        when="2026-06-01T00:00:00+00:00",
        late=120.0,
    )
    await _misfire(
        audit,
        session,
        project_id=project_id,
        schedule_id=sched_b,
        when="2026-06-01T01:00:00+00:00",
        late=300.0,
    )
    await _misfire(
        audit,
        session,
        project_id=project_id,
        schedule_id=sched_a,
        when="2026-06-01T02:00:00+00:00",
        late=540.0,
    )
    await _misfire(
        audit,
        session,
        project_id=other_project_id,
        schedule_id=uuid.uuid4(),
        when="2026-06-01T03:00:00+00:00",
        late=999.0,
    )

    rows = await AuditLogRepository(session).list_misfires_for_project(
        project_id=project_id,
    )

    # Only the three project rows -- the other project's misfire is gone.
    assert len(rows) == 3
    # The result spans BOTH schedules of the project.
    assert {r.target_id for r in rows} == {str(sched_a), str(sched_b)}
    # Newest-first ordering (the three insert timestamps advance).
    assert [r.audit_metadata["lateness_seconds"] for r in rows] == [540.0, 300.0, 120.0]
    # Every returned row is the misfire action, scoped to this project.
    assert all(r.action == "scheduler.misfire_detected" for r in rows)
    assert all(r.project_id == project_id for r in rows)


@pytest.mark.asyncio
async def test_excludes_non_misfire_actions(
    settings: Settings,
    session: AsyncSession,
) -> None:
    audit = AuditService(settings)
    project_id = uuid.uuid4()
    sched = uuid.uuid4()

    await _misfire(
        audit,
        session,
        project_id=project_id,
        schedule_id=sched,
        when="2026-06-01T00:00:00+00:00",
        late=120.0,
    )
    # A non-misfire audit row in the same project must NOT leak in.
    await audit.record(
        AuditLogRepository(session),
        action="schedule.create",
        target_type="schedule",
        target_id=str(sched),
        result="success",
        outcome="allow",
        project_id=project_id,
        metadata={"name": "sched"},
    )
    await session.commit()

    rows = await AuditLogRepository(session).list_misfires_for_project(
        project_id=project_id,
    )
    assert len(rows) == 1
    assert rows[0].action == "scheduler.misfire_detected"


@pytest.mark.asyncio
async def test_limit_is_honoured_and_capped(
    settings: Settings,
    session: AsyncSession,
) -> None:
    audit = AuditService(settings)
    project_id = uuid.uuid4()
    sched = uuid.uuid4()
    for i in range(5):
        await _misfire(
            audit,
            session,
            project_id=project_id,
            schedule_id=sched,
            when=f"2026-06-01T0{i}:00:00+00:00",
            late=float(i),
        )

    repo = AuditLogRepository(session)
    # A small limit returns exactly that many, newest first.
    limited = await repo.list_misfires_for_project(project_id=project_id, limit=2)
    assert len(limited) == 2
    assert limited[0].audit_metadata["lateness_seconds"] == 4.0

    # An over-cap / non-positive limit is clamped into [1, 1000]; here the
    # clamp still returns every one of the 5 seeded rows.
    for weird in (0, -3, 10_000):
        all_rows = await repo.list_misfires_for_project(
            project_id=project_id,
            limit=weird,
        )
        assert 1 <= len(all_rows) <= 5
