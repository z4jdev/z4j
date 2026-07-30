"""Long-poll recovery cutoffs are recomputed on each poll.

The bug: ``agent_longpoll._pull_pending`` computed the redispatch/lease cutoffs
ONCE at request start and froze them into its closure, so a DISPATCHED
redeliverable row that became lease-eligible DURING the wait was never observed
until the NEXT request. The fix recomputes the cutoffs on every poll.

This test drives the real ``GET /agent/commands`` endpoint against an in-memory
brain with a small lease interval: a fire is DISPATCHED at request start (not yet
lease-eligible), and the endpoint must re-send it once the lease elapses DURING
the wait. On the frozen-cutoff code the row never becomes eligible within the
request and the response is empty."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import Agent, Command, Project
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import CURRENT_PROTOCOL

pytestmark = pytest.mark.asyncio

AGENT_TOKEN = "z4j_agent_h2_recompute_test"
LEASE = 1.0  # the smallest allowed min-interval (ge=1); the mid-wait boundary
#             crosses ~1s into the wait, so the test runs in ~1-1.3s.


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        registry_backend="local",
        agent_longpoll_redispatch_seconds=60.0,
        agent_longpoll_redispatch_min_interval_seconds=LEASE,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def ids(settings: Settings, brain_app) -> dict[str, uuid.UUID]:
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with brain_app.state.db.session() as s:
        s.add(Project(id=project_id, slug="h2", name="H2"))
        s.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="h2-agent",
                token_hash=hash_agent_token(
                    plaintext=AGENT_TOKEN,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.UNKNOWN,
            ),
        )
        await s.commit()
    return {"project_id": project_id, "agent_id": agent_id}


@pytest.fixture
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


async def _insert_dispatched_fire(brain_app, ids, *, dispatched_at: datetime) -> uuid.UUID:
    cmd_id = uuid.uuid4()
    async with brain_app.state.db.session() as s:
        s.add(
            Command(
                id=cmd_id,
                project_id=ids["project_id"],
                agent_id=ids["agent_id"],
                action="schedule.fire",
                target_type="schedule",
                target_id="sched-1",
                payload={"task_name": "t", "fire_id": str(uuid.uuid4()), "kwargs": {}},
                idempotency_key=None,
                status=CommandStatus.DISPATCHED,
                dispatched_at=dispatched_at,
                timeout_at=datetime.now(UTC) + timedelta(seconds=300),
            ),
        )
        await s.commit()
    return cmd_id


async def test_dispatched_fire_recovered_when_lease_elapses_mid_wait(brain_app, ids, client):
    # DISPATCHED right now: NOT yet lease-eligible (needs LEASE seconds to pass).
    await _insert_dispatched_fire(brain_app, ids, dispatched_at=datetime.now(UTC))
    # Long-poll for longer than the lease. The lease elapses DURING the wait, so
    # with recomputed cutoffs the endpoint re-sends the fire before the deadline.
    r = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 3, "max_frames": 10},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert r.status_code == 200, r.text
    frames = r.json()["frames"]
    assert len(frames) >= 1, "H2: a fire that becomes lease-eligible mid-wait must be recovered"


async def test_fresh_dispatched_fire_not_resent_within_lease(brain_app, ids, client):
    # A fire DISPATCHED now, polled with wait=0: still inside the lease window, so
    # it must NOT be re-sent (guards against re-sending on every poll).
    await _insert_dispatched_fire(brain_app, ids, dispatched_at=datetime.now(UTC))
    r = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 10},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["frames"] == []
