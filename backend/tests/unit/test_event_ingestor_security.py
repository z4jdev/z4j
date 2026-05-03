"""Security regression tests for :mod:`z4j_brain.domain.event_ingestor`.

Covers the Batch-2 / Batch-3 / Batch-4 security fixes:

- cross-project event_id namespacing (H1 R3)
- SAVEPOINT batch isolation on duplicate (C1 R3)
- ``_coerce_event_id`` rejects nil / max / non-v4-v7 UUIDs (H2 R3)
- ``_sanitize_canvas_ref`` drops cross-project parent/root refs (H4 R2)
- ``occurred_at`` clamp to [-400d, +5min] (C2 R3)
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_core.redaction import RedactionConfig, RedactionEngine

from z4j_brain.domain.event_ingestor import (
    EventIngestor,
    _coerce_event_id,
)
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Event, Project, Task
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


def _received(
    agent_event_id: str,
    *,
    task_id: str = "task-1",
    occurred_at: datetime | None = None,
) -> dict:
    return {
        "id": agent_event_id,
        "kind": "task.received",
        "engine": "celery",
        "task_id": task_id,
        "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
        "data": {"task_name": "app.x", "queue": "q"},
    }


# ---------------------------------------------------------------------------
# _coerce_event_id
# ---------------------------------------------------------------------------


class TestCoerceEventId:
    """H2 R3: only v4 / v7 accepted; nil + max rejected."""

    def test_accepts_uuid4(self) -> None:
        u = uuid.uuid4()
        assert _coerce_event_id(u) == u
        assert _coerce_event_id(str(u)) == u

    def test_rejects_none(self) -> None:
        assert _coerce_event_id(None) is None

    def test_rejects_nil_uuid(self) -> None:
        assert _coerce_event_id("00000000-0000-0000-0000-000000000000") is None
        assert _coerce_event_id(uuid.UUID(int=0)) is None

    def test_rejects_max_uuid(self) -> None:
        maxu = uuid.UUID(int=(1 << 128) - 1)
        assert _coerce_event_id(maxu) is None

    def test_rejects_uuid1(self) -> None:
        assert _coerce_event_id(uuid.uuid1()) is None

    def test_rejects_uuid3(self) -> None:
        u3 = uuid.uuid3(uuid.NAMESPACE_URL, "http://example.com")
        assert _coerce_event_id(u3) is None

    def test_rejects_uuid5(self) -> None:
        u5 = uuid.uuid5(uuid.NAMESPACE_URL, "http://example.com")
        assert _coerce_event_id(u5) is None

    def test_rejects_garbage_strings(self) -> None:
        assert _coerce_event_id("not-a-uuid") is None
        assert _coerce_event_id("") is None
        assert _coerce_event_id(123) is None


# ---------------------------------------------------------------------------
# Cross-project event_id namespacing (H1 R3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCrossProjectNamespacing:
    """Two projects supplying the same agent_event_id must NOT collide
    on the brain-side events row (structural safety + PK widening)."""

    async def test_same_agent_id_different_projects_no_collision(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj_a = await _make_project(session, "alpha")
        proj_b = await _make_project(session, "beta")
        agent_a = await _make_agent(session, proj_a)
        agent_b = await _make_agent(session, proj_b)

        shared_agent_event_id = str(uuid.uuid4())
        shared_occurred = datetime.now(UTC)
        payload = {
            "id": shared_agent_event_id,
            "kind": "task.received",
            "engine": "celery",
            "task_id": "t-1",
            "occurred_at": shared_occurred.isoformat(),
            "data": {"task_name": "app.x", "queue": "q"},
        }

        await ingestor.ingest_batch(
            events=[payload],
            project_id=proj_a.id,
            agent_id=agent_a.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        await ingestor.ingest_batch(
            events=[payload],  # same agent id, same occurred_at
            project_id=proj_b.id,
            agent_id=agent_b.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        # Both projects get their own events row; no collision.
        count = (
            await session.execute(select(func.count()).select_from(Event))
        ).scalar_one()
        assert count == 2, (
            "Project-A and Project-B should each have their own row; "
            "they must NOT collide via a shared agent-supplied event_id."
        )

    async def test_replay_same_project_dedupes(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        """Same agent_event_id inside the SAME project → dedupes."""
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        payload = _received(str(uuid.uuid4()))

        for _ in range(3):
            await ingestor.ingest_batch(
                events=[payload],
                project_id=proj.id,
                agent_id=agent.id,
                agents=AgentRepository(session),
                event_repo=EventRepository(session),
                task_repo=TaskRepository(session),
                queue_repo=QueueRepository(session),
            )
            await session.commit()

        count = (
            await session.execute(select(func.count()).select_from(Event))
        ).scalar_one()
        assert count == 1, "Replay in the same project should dedupe."


# ---------------------------------------------------------------------------
# SAVEPOINT batch isolation (C1 R3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSavepointBatchIsolation:
    """A duplicate event in a batch must NOT roll back the other events'
    projections. The fix was ``session.begin_nested()`` around the
    per-event flush so the ROLLBACK is scoped to the SAVEPOINT."""

    async def test_duplicate_event_does_not_poison_batch(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)

        good_a = _received(str(uuid.uuid4()), task_id="task-A")
        dup_id = str(uuid.uuid4())
        # Share occurred_at so the (project_id, occurred_at, id)
        # conflict key actually fires - otherwise microsecond
        # drift between datetime.now() calls makes the two rows
        # distinct.
        dup_when = datetime.now(UTC)
        dup_1 = _received(dup_id, task_id="task-B", occurred_at=dup_when)
        dup_2 = _received(dup_id, task_id="task-B", occurred_at=dup_when)
        good_c = _received(str(uuid.uuid4()), task_id="task-C")

        # Ingest a 4-event batch with a duplicate in the middle.
        new_count = await ingestor.ingest_batch(
            events=[good_a, dup_1, dup_2, good_c],
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        # Exactly 3 rows landed in events (dup_2 deduped).
        event_count = (
            await session.execute(select(func.count()).select_from(Event))
        ).scalar_one()
        assert event_count == 3
        assert new_count == 3

        # Tasks for A, B, C all projected (dup did NOT poison the batch).
        task_ids = sorted(
            t.task_id
            for t in (await session.execute(select(Task))).scalars().all()
        )
        assert task_ids == ["task-A", "task-B", "task-C"]


# ---------------------------------------------------------------------------
# Canvas-ref sanitization (H4 R2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCanvasRefSanitization:
    """``_sanitize_canvas_ref`` refuses to store a parent/root ref that
    already belongs to a different project - closes the cross-project
    canvas-linkage poisoning vector."""

    async def test_parent_in_different_project_dropped(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj_a = await _make_project(session, "alpha")
        proj_b = await _make_project(session, "beta")
        agent_a = await _make_agent(session, proj_a)
        agent_b = await _make_agent(session, proj_b)

        # Landmark task in project-B so the attacker can reference it.
        victim = Task(
            project_id=proj_b.id,
            engine="celery",
            task_id="victim-1",
            name="victim",
        )
        session.add(victim)
        await session.commit()

        # Attacker in project-A sends a received event whose
        # parent_task_id points at the Project-B task id.
        attacker_event = {
            "id": str(uuid.uuid4()),
            "kind": "task.received",
            "engine": "celery",
            "task_id": "attacker-child",
            "occurred_at": datetime.now(UTC).isoformat(),
            "data": {
                "task_name": "app.x",
                "queue": "q",
                "parent_task_id": "victim-1",  # cross-project attempt
                "root_task_id": "victim-1",
            },
        }
        await ingestor.ingest_batch(
            events=[attacker_event],
            project_id=proj_a.id,
            agent_id=agent_a.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        # Attacker's task exists in Project-A with parent/root DROPPED.
        landed = (
            await session.execute(
                select(Task).where(Task.project_id == proj_a.id),
            )
        ).scalar_one()
        assert landed.task_id == "attacker-child"
        assert landed.parent_task_id is None, (
            "cross-project parent_task_id should have been sanitized out"
        )
        assert landed.root_task_id is None

    async def test_self_loop_dropped(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        event = {
            "id": str(uuid.uuid4()),
            "kind": "task.received",
            "engine": "celery",
            "task_id": "self",
            "occurred_at": datetime.now(UTC).isoformat(),
            "data": {
                "task_name": "app.x",
                "parent_task_id": "self",  # self-loop - meaningless
            },
        }
        await ingestor.ingest_batch(
            events=[event],
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        t = (await session.execute(select(Task))).scalar_one()
        assert t.parent_task_id is None


# ---------------------------------------------------------------------------
# occurred_at clamp (C2 R3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestOccurredAtClamp:
    async def test_far_future_clamped_to_now(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        future = datetime.now(UTC) + timedelta(days=365 * 3)
        event = {
            "id": str(uuid.uuid4()),
            "kind": "task.received",
            "engine": "celery",
            "task_id": "t",
            "occurred_at": future.isoformat(),
            "data": {"task_name": "app.x"},
        }
        await ingestor.ingest_batch(
            events=[event],
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        ev = (await session.execute(select(Event))).scalar_one()
        # Clamp pulled the timestamp back to "approximately now".
        # SQLite drops tzinfo on round-trip - coerce for comparison.
        stored = ev.occurred_at
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        assert abs((stored - now).total_seconds()) < 60, (
            f"far-future occurred_at should have been clamped to now; "
            f"got {stored}"
        )

    async def test_far_past_clamped_to_now(
        self,
        session: AsyncSession,
        ingestor: EventIngestor,
    ) -> None:
        proj = await _make_project(session, "alpha")
        agent = await _make_agent(session, proj)
        past = datetime.now(UTC) - timedelta(days=401)
        event = {
            "id": str(uuid.uuid4()),
            "kind": "task.received",
            "engine": "celery",
            "task_id": "t",
            "occurred_at": past.isoformat(),
            "data": {"task_name": "app.x"},
        }
        await ingestor.ingest_batch(
            events=[event],
            project_id=proj.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        ev = (await session.execute(select(Event))).scalar_one()
        stored = ev.occurred_at
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        assert abs((stored - now).total_seconds()) < 60
