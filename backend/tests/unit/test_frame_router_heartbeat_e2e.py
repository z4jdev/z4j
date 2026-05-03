"""End-to-end test for ``FrameRouter._handle_heartbeat``.

Exercises the **full** heartbeat handling path that runs in production
on every WebSocket heartbeat from a real agent: a HEARTBEAT frame
arrives carrying ``adapter_health["celery.worker_details"]`` (a JSON
string of ``{hostname: {stats, active, active_queues, registered, conf}}``)
and ``adapter_health["celery.queue_depths"]`` (a JSON string of
``{queue_name: depth}``); the router should land worker rows + queue
rows in the DB.

This test was added in 1.3.1 after a regression escaped 1.3.0:
``Worker.worker_metadata`` is the Python attribute, but the DB column
is ``metadata``. The bulk-upsert path used the attribute name in
``stmt.excluded.<>`` lookups, which key off DB column names, every
heartbeat raised ``AttributeError: worker_metadata`` and the workers
list silently stayed empty on every dashboard. The unit-level
:mod:`test_workers_repo_bulk_upsert` tests didn't catch it because
``_row()`` never set ``worker_metadata``. This file closes that gap
by exercising the ``_handle_heartbeat`` code path the production WS
gateway actually invokes, with a payload shaped exactly like what
``z4j-celery``'s ``CeleryEngine.health()`` emits.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import Agent, Project, Worker
from z4j_brain.websocket.frame_router import FrameRouter
from z4j_core.transport.frames import HeartbeatFrame, HeartbeatPayload


@pytest.fixture
async def db_manager():
    """A real DatabaseManager backed by in-memory SQLite."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


@pytest.fixture
async def project_and_agent(db_manager: DatabaseManager):
    """Pre-seed the DB with one project + one agent so the router has
    valid foreign-key targets."""
    factory = sessionmaker(
        db_manager._engine, class_=AsyncSession, expire_on_commit=False,
    )
    project_id: uuid.UUID
    agent_id: uuid.UUID
    async with factory() as s:
        p = Project(slug="picker", name="Picker")
        s.add(p)
        await s.flush()
        project_id = p.id

        a = Agent(
            project_id=project_id,
            name="picker_django",
            token_hash="x" * 64,
            protocol_version=1,
            framework_adapter="django",
        )
        s.add(a)
        await s.flush()
        agent_id = a.id
        await s.commit()
    return project_id, agent_id


def _build_celery_worker_details_payload() -> str:
    """Mirror the shape z4j-celery's ``CeleryEngine.get_worker_details``
    emits: dict keyed by hostname, each value carrying stats / active /
    active_queues / registered / conf. Encoded as a JSON string because
    ``HeartbeatFrame.adapter_health`` is typed ``dict[str, str]`` -
    agents serialise structured values to JSON before stuffing them
    in.
    """
    return json.dumps({
        "celery@picker_django": {
            "stats": {
                "pool": {
                    "max-concurrency": 4,
                    "processes": [101, 102, 103, 104],
                },
                "rusage": {"utime": 12.3, "stime": 4.5},
                "loadavg": [0.5, 0.7, 0.8],
                "pid": 100,
            },
            "active": [
                {"id": "task-1", "name": "myapp.tasks.add"},
            ],
            "active_queues": [
                {"name": "celery"},
                {"name": "high_priority"},
            ],
            "registered": ["myapp.tasks.add", "myapp.tasks.send_email"],
            "conf": {"BROKER_URL": "redis://localhost:6379/0"},
        },
    })


@pytest.fixture
def heartbeat_frame() -> HeartbeatFrame:
    """A heartbeat frame in the exact shape a real Celery agent sends."""
    return HeartbeatFrame(
        id=str(uuid.uuid4()),
        ts=datetime.now(UTC),
        payload=HeartbeatPayload(
            buffer_size=0,
            last_flush_at=datetime.now(UTC),
            dropped_events=0,
            adapter_health={
                "celery.broker": "redis",
                "celery.broker_alive": "True",
                "celery.worker_details": _build_celery_worker_details_payload(),
                "celery.queue_depths": json.dumps({
                    "celery": 3,
                    "high_priority": 1,
                }),
            },
        ),
    )


@pytest.mark.asyncio
class TestFrameRouterHeartbeatE2E:
    """The whole heartbeat handler with a real DB and a real frame."""

    async def test_worker_details_lands_worker_row_with_metadata(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        heartbeat_frame: HeartbeatFrame,
    ) -> None:
        project_id, agent_id = project_and_agent

        router = FrameRouter(
            db=db_manager,
            ingestor=None,  # not used by _handle_heartbeat
            dispatcher=None,  # not used by _handle_heartbeat
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        # ---- THE CALL UNDER TEST ----
        # Pre-1.3.1 this raised AttributeError: worker_metadata
        # internally and the worker row never landed.
        await router._handle_heartbeat(heartbeat_frame)

        # The worker row MUST exist with metadata populated.
        factory = sessionmaker(
            db_manager._engine, class_=AsyncSession, expire_on_commit=False,
        )
        async with factory() as s:
            result = await s.execute(
                select(Worker).where(Worker.project_id == project_id),
            )
            workers = list(result.scalars().all())
            assert len(workers) == 1, (
                "expected exactly one worker row from the heartbeat; "
                "if zero, the bulk-upsert path silently swallowed the "
                "row (1.3.0 regression). if multiple, dedup is broken."
            )
            w = workers[0]
            assert w.engine == "celery"
            assert w.name == "celery@picker_django"
            assert w.hostname == "celery@picker_django"
            assert w.concurrency == 4
            # active task count came from data["active"] length (=1).
            assert w.active_tasks == 1
            # The two queues from active_queues land on the row.
            assert sorted(w.queues or []) == ["celery", "high_priority"]
            # And the metadata bundle round-trips through JSON ↔
            # the "metadata" DB column ↔ the Python attribute.
            assert isinstance(w.worker_metadata, dict)
            assert "stats" in w.worker_metadata
            assert "active" in w.worker_metadata
            assert "active_queues" in w.worker_metadata

    async def test_worker_details_idempotent_across_two_heartbeats(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        heartbeat_frame: HeartbeatFrame,
    ) -> None:
        """Two consecutive heartbeats from the same agent should
        update the existing worker row, not duplicate it."""
        project_id, _ = project_and_agent

        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=project_and_agent[1],
            dashboard_hub=None,
            worker_id=None,
        )

        await router._handle_heartbeat(heartbeat_frame)
        await router._handle_heartbeat(heartbeat_frame)

        factory = sessionmaker(
            db_manager._engine, class_=AsyncSession, expire_on_commit=False,
        )
        async with factory() as s:
            result = await s.execute(
                select(Worker).where(Worker.project_id == project_id),
            )
            workers = list(result.scalars().all())
            assert len(workers) == 1, (
                "two heartbeats produced "
                f"{len(workers)} worker rows; "
                "ON CONFLICT DO UPDATE on (project_id, engine, name) "
                "must collapse them to one"
            )
