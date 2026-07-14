"""Long-poll identity-header contract tests (B13 fix, brain side).

The agent's long-poll transport learns its canonical signing identity
from the ``X-Z4J-Agent-Id`` / ``X-Z4J-Project-Id`` response headers on
the connect probe (``GET /api/v1/agent/commands``), the long-poll
analogue of the WebSocket ``hello_ack``. Without them a slug-configured
agent has no way to discover the project UUID the brain binds into the
frame-HMAC envelope, and every frame fails verification.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import CURRENT_PROTOCOL

AGENT_TOKEN = "z4j_agent_longpoll_identity_test"


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
async def agent_ids(settings: Settings, brain_app) -> dict[str, uuid.UUID]:
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with brain_app.state.db.session() as s:
        s.add(Project(id=project_id, slug="lp-project", name="LP"))
        s.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="lp-agent",
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
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_commands_probe_advertises_canonical_identity(
    client,
    agent_ids,
) -> None:
    """The exact request the transport's connect() probe makes."""
    r = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Z4J-Agent-Id"] == str(agent_ids["agent_id"])
    assert r.headers["X-Z4J-Project-Id"] == str(agent_ids["project_id"])


@pytest.mark.asyncio
async def test_events_route_advertises_identity_too(
    client,
    agent_ids,
) -> None:
    """Either long-poll route teaches the transport its identity."""
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": ["not-a-real-frame"]},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    # The garbage frame is dropped-and-acked (deterministic parse failure,
    # R8: accepted so the agent stops looping), but auth succeeded, so the
    # identity headers must be present on the 200.
    assert r.status_code == 200
    assert r.json()["accepted"] == 1
    assert r.headers["X-Z4J-Agent-Id"] == str(agent_ids["agent_id"])
    assert r.headers["X-Z4J-Project-Id"] == str(agent_ids["project_id"])


@pytest.mark.asyncio
async def test_bad_token_gets_no_identity_headers(client, agent_ids) -> None:
    """An unauthenticated caller must not learn any identity."""
    r = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401
    assert "X-Z4J-Agent-Id" not in r.headers
    assert "X-Z4J-Project-Id" not in r.headers
