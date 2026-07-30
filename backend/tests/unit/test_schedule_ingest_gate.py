"""External round-8 M3 + H3: the schedule-snapshot reconcile inside
``EventIngestor`` is (a) gated on ``inserted`` so a dedup'd duplicate
snapshot does not 3-way-diff-delete a schedule a newer snapshot added, and
(b) wrapped in its own ``begin_nested()`` savepoint so a transient failure
inside the best-effort reconcile does not poison the per-event transaction
and drop-and-ack the whole event.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Event, Project, Schedule
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)
from z4j_core.redaction import RedactionConfig, RedactionEngine

pytestmark = pytest.mark.asyncio

# A valid v4 UUID literal so the ingestor honours the agent-supplied id
# (its dedupe keys on it); a non-UUID id would be rejected and a fresh one
# minted, so the two deliveries would NOT dedupe and the gate never fires.
_SNAP_ID = "12345678-1234-4234-8234-1234567890ab"
# A fixed timestamp keeps the derived event_id stable across the two
# deliveries (no sub-second jitter across a boundary).
_FIXED_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


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
        scheduler_adapters=["celery-beat"],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(a)
    await session.commit()
    return a


@pytest.fixture
def ingestor() -> EventIngestor:
    return EventIngestor(RedactionEngine(RedactionConfig()))


def _schedule(name: str) -> dict[str, object]:
    return {
        "name": name,
        "task_name": "myapp.tasks.run",
        "kind": "cron",
        "expression": "*/5 * * * *",
        "engine": "celery",
        "scheduler": "celery-beat",
        "is_enabled": True,
        "args": [],
        "kwargs": {},
    }


def _snapshot_event(schedules: list[dict[str, object]]) -> dict:
    return {
        "id": _SNAP_ID,
        "kind": "schedule.snapshot",
        "engine": "celery",
        "occurred_at": _FIXED_TS.isoformat(),
        "data": {"scheduler": "celery-beat", "schedules": schedules},
    }


async def _ingest(ingestor, session, project, agent, event):
    return await ingestor.ingest_batch(
        events=[event],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=EventRepository(session),
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )


async def test_duplicate_snapshot_does_not_reconcile_and_delete(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """M3: the SECOND delivery of the SAME snapshot event id dedups
    (inserted=False), so its reconcile is skipped. If the gate were absent, a
    stale duplicate carrying only [A] would 3-way-diff-DELETE B."""
    # First delivery: inventory [A, B] -> both inserted.
    await _ingest(
        ingestor, session, project, agent, _snapshot_event([_schedule("A"), _schedule("B")])
    )
    await session.commit()
    count = (await session.execute(select(func.count()).select_from(Schedule))).scalar_one()
    assert count == 2

    # Second delivery: SAME event id (a reconnect replay) but a STALE
    # inventory of only [A]. Dedup -> inserted=False -> reconcile skipped.
    await _ingest(ingestor, session, project, agent, _snapshot_event([_schedule("A")]))
    await session.commit()

    names = {row[0] for row in (await session.execute(select(Schedule.name))).all()}
    # B MUST survive -- the duplicate did not re-reconcile-and-prune it.
    assert names == {"A", "B"}


async def test_reconcile_failure_does_not_drop_the_event(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H3: a TRANSIENT failure inside the best-effort reconcile is caught and
    rolled back to its OWN savepoint, so the per-event insert still commits
    (the event is not lost) and ingest reports it as new/durable."""
    from z4j_brain.persistence.repositories import ScheduleRepository

    original = ScheduleRepository.reconcile_snapshot

    async def _boom(self, **kwargs):
        # Do the REAL reconcile first (inserts + flushes schedule rows inside
        # the per-op savepoint) THEN raise a transient error, so the test
        # proves the savepoint rolls the partial write back rather than
        # leaving it to poison the outer per-event transaction.
        await original(self, **kwargs)
        exc = RuntimeError("deadlock detected")
        exc.sqlstate = "40P01"  # type: ignore[attr-defined]
        raise exc

    monkeypatch.setattr(ScheduleRepository, "reconcile_snapshot", _boom)

    result = await _ingest(ingestor, session, project, agent, _snapshot_event([_schedule("A")]))
    await session.commit()

    # The event itself was inserted despite the reconcile blowing up ...
    assert len(result.new_events) == 1
    event_count = (await session.execute(select(func.count()).select_from(Event))).scalar_one()
    assert event_count == 1
    # ... and the failed reconcile left no half-written schedule rows.
    sched_count = (await session.execute(select(func.count()).select_from(Schedule))).scalar_one()
    assert sched_count == 0


async def test_reserved_outer_owner_never_reaches_schedule_projection(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    event = _snapshot_event([_schedule("forged")])
    event["engine"] = "z4j-scheduler"

    result = await _ingest(ingestor, session, project, agent, event)
    await session.commit()

    assert len(result.new_events) == 1
    sched_count = (await session.execute(select(func.count()).select_from(Schedule))).scalar_one()
    assert sched_count == 0
