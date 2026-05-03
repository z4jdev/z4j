"""External-audit Medium #5 + #6 regression tests for the event
ingestor:

- #5: canvas-link sanitisation must NOT drop legitimate links when
  another project happens to reuse the same (engine, task_id).
- #6: state projection must not regress a task row when a stale
  event arrives out of order.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_core.redaction import RedactionConfig, RedactionEngine

from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
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


async def _make_project(session: AsyncSession, slug: str) -> Project:
    p = Project(slug=slug, name=slug.title())
    session.add(p)
    await session.commit()
    return p


async def _make_agent(session: AsyncSession, project: Project) -> Agent:
    a = Agent(
        project_id=project.id,
        name=f"agent-{secrets.token_hex(4)}",
        token_hash=secrets.token_hex(32),
        protocol_version="1",
        framework_adapter="django",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(a)
    await session.commit()
    return a


@pytest.fixture
def ingestor() -> EventIngestor:
    return EventIngestor(RedactionEngine(RedactionConfig()))


def _event(
    *,
    kind: str,
    task_id: str,
    occurred_at: datetime,
    data: dict | None = None,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "kind": kind,
        "engine": "celery",
        "task_id": task_id,
        "occurred_at": occurred_at.isoformat(),
        "data": data or {"task_name": "app.x"},
    }


# ---------------------------------------------------------------------------
# #5 - canvas-link ambiguity: same task_id in two projects is OK
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCanvasAmbiguity:
    async def test_same_task_id_in_caller_project_not_dropped(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """If the referenced task_id exists in the CALLER's project
        (and also happens to exist in another project), the link
        must NOT be dropped - it is legitimately valid within the
        caller's own tree."""
        proj_a = await _make_project(session, "alpha")
        proj_b = await _make_project(session, "beta")
        agent_a = await _make_agent(session, proj_a)

        # Project-A has a parent task with this id.
        parent_a = Task(
            project_id=proj_a.id, engine="celery",
            task_id="shared-id", name="parent-in-a",
        )
        # Project-B coincidentally has a row with the same
        # (engine, task_id) - legitimate same-id reuse.
        parent_b = Task(
            project_id=proj_b.id, engine="celery",
            task_id="shared-id", name="parent-in-b",
        )
        session.add_all([parent_a, parent_b])
        await session.commit()

        # Attacker-free child event in project-A references the
        # shared id.
        ev = _event(
            kind="task.received",
            task_id="child-in-a",
            occurred_at=datetime.now(UTC),
            data={
                "task_name": "app.x",
                "parent_task_id": "shared-id",
            },
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=proj_a.id,
            agent_id=agent_a.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        child = (
            await session.execute(
                select(Task).where(
                    Task.project_id == proj_a.id,
                    Task.task_id == "child-in-a",
                ),
            )
        ).scalar_one()
        assert child.parent_task_id == "shared-id", (
            "legitimate same-id reuse in project-A must keep the link"
        )

    async def test_task_id_only_in_other_project_is_dropped(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """If the referenced task_id is UNAMBIGUOUSLY owned by a
        different project (no row in the caller's project), the
        link is still dropped - that's the original cross-project
        poisoning fix."""
        proj_a = await _make_project(session, "alpha")
        proj_b = await _make_project(session, "beta")
        agent_a = await _make_agent(session, proj_a)

        # Only project-B has this parent.
        parent_b = Task(
            project_id=proj_b.id, engine="celery",
            task_id="victim", name="parent-in-b-only",
        )
        session.add(parent_b)
        await session.commit()

        ev = _event(
            kind="task.received",
            task_id="attacker-child",
            occurred_at=datetime.now(UTC),
            data={
                "task_name": "app.x",
                "parent_task_id": "victim",
            },
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=proj_a.id,
            agent_id=agent_a.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        child = (
            await session.execute(
                select(Task).where(
                    Task.project_id == proj_a.id,
                    Task.task_id == "attacker-child",
                ),
            )
        ).scalar_one()
        assert child.parent_task_id is None, (
            "cross-project-only reference must be dropped"
        )


# ---------------------------------------------------------------------------
# #6 - state projection monotonic guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStateMonotonicGuard:
    async def test_stale_started_does_not_regress_succeeded(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """A late ``task.started`` event arriving after
        ``task.succeeded`` must NOT move the task back to STARTED."""
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)

        t_start = datetime.now(UTC) - timedelta(minutes=5)
        t_end = t_start + timedelta(minutes=1)
        late_started = t_start + timedelta(seconds=10)

        # 1) received → started → succeeded lifecycle (ordered).
        ordered = [
            _event(
                kind="task.received", task_id="t1",
                occurred_at=t_start,
                data={"task_name": "app.x"},
            ),
            _event(
                kind="task.started", task_id="t1",
                occurred_at=t_start + timedelta(seconds=1),
                data={"worker": "w1"},
            ),
            _event(
                kind="task.succeeded", task_id="t1",
                occurred_at=t_end,
                data={"runtime_ms": 59000},
            ),
        ]
        await ingestor.ingest_batch(
            events=ordered,
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (
            await session.execute(
                select(Task).where(Task.task_id == "t1"),
            )
        ).scalar_one()
        assert task.state == TaskState.SUCCESS

        # 2) Late duplicate ``task.started`` arrives (replay,
        # network reorder, buffer flush from a reconnecting agent).
        # occurred_at is BEFORE the terminal event.
        stale = [
            _event(
                kind="task.started", task_id="t1",
                occurred_at=late_started,
                data={"worker": "w1"},
            ),
        ]
        await ingestor.ingest_batch(
            events=stale,
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (
            await session.execute(
                select(Task).where(Task.task_id == "t1"),
            )
        ).scalar_one()
        assert task.state == TaskState.SUCCESS, (
            "stale task.started must not regress a finished task"
        )

    async def test_in_order_events_still_transition(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """Sanity: the monotonic guard does NOT block
        well-ordered lifecycle transitions."""
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        t = datetime.now(UTC)
        events = [
            _event(kind="task.received", task_id="ok",
                   occurred_at=t),
            _event(kind="task.started", task_id="ok",
                   occurred_at=t + timedelta(seconds=1),
                   data={"worker": "w1"}),
        ]
        await ingestor.ingest_batch(
            events=events, project_id=proj.id, agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (
            await session.execute(
                select(Task).where(Task.task_id == "ok"),
            )
        ).scalar_one()
        assert task.state == TaskState.STARTED

    async def test_near_future_stamp_cannot_lock_state(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """R5 H1 regression - a hostile agent stamping
        ``task.succeeded`` just under the clamp window cannot
        lock a task in SUCCESS against a subsequent legitimate
        lifecycle event. The clamp normalises future-dated
        incoming events AND ``_task_latest_lifecycle_at``
        applies ``min(ts, now)`` defence in depth."""
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        t_now = datetime.now(UTC)
        # Attacker sends task.succeeded with occurred_at = now + 55s.
        # The clamp (_OCCURRED_AT_FUTURE_LIMIT = 60s) allows this
        # through (under the window) - but the clamp now also
        # stamps it to now, so existing_latest after ingest is
        # ~= now.
        attacker = [
            _event(kind="task.received", task_id="x",
                   occurred_at=t_now - timedelta(seconds=10)),
            _event(kind="task.succeeded", task_id="x",
                   occurred_at=t_now + timedelta(seconds=55),
                   data={"runtime_ms": 10_000}),
        ]
        await ingestor.ingest_batch(
            events=attacker, project_id=proj.id, agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        # A legitimate task.failed arrives a few seconds later.
        # With the R5 fix, the existing row's lifecycle timestamp
        # never exceeds `now`, so the legitimate event's
        # occurred_at is NOT < existing_latest, and the state
        # transition lands.
        legit = [
            _event(kind="task.failed", task_id="x",
                   occurred_at=t_now + timedelta(seconds=30),
                   data={"exception": "oops"}),
        ]
        await ingestor.ingest_batch(
            events=legit, project_id=proj.id, agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (
            await session.execute(
                select(Task).where(Task.task_id == "x"),
            )
        ).scalar_one()
        # The task should now be FAILURE, not the attacker-locked
        # SUCCESS (the R5 H1 fix - clamp tight + min(ts, now) on
        # the existing row's timestamps).
        assert task.state == TaskState.FAILURE, (
            f"R5 H1 regression: hostile near-future stamp locked "
            f"state at {task.state}"
        )
