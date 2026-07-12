"""Pinning tests for the two brain-side longpoll defects (1.7 matrix).

LP-1 (no ack channel): ``api/agent_longpoll.py:365-374`` builds its
per-request :class:`FrameRouter` WITHOUT the ``send_frame`` callback,
so the ``event_batch_ack`` emission in
``websocket/frame_router.py:489`` is silently skipped
(``_send_frame is None``). ``GET /agent/commands`` only ever signs
``CommandFrame`` rows, so there is no path by which a longpoll agent
can EVER receive an ack. The 1.5+ agent defers buffer confirmation
until the ack arrives, so it re-sends the same batch at HTTP
round-trip cadence until the rate limiter 429s it.

LP-3 (state pinned at unknown): a longpoll-only agent's row is
created with ``state=UNKNOWN`` and nothing on the longpoll path ever
calls ``mark_online`` (that only happens in the WS hello). The fix
widens ``promote_online_if_offline`` to promote from any non-online
state and calls it from the events POST on a successful ingest, so a
longpoll-only agent shows online.

These are post-fix regression guards for both defects.
"""

from __future__ import annotations

import asyncio
import contextlib
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
from z4j_brain.persistence.repositories import AgentRepository
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.frame_router import FrameRouter
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.frames import (
    EventBatchAckFrame,
    EventBatchFrame,
    EventBatchPayload,
    HeartbeatFrame,
    HeartbeatPayload,
)
from z4j_core.transport.framing import FrameSigner
from z4j_core.transport.hmac import derive_project_secret

AGENT_TOKEN = "z4j_agent_longpoll_pins_test"


# ---------------------------------------------------------------------------
# App fixtures (mirrors test_agent_longpoll_identity.py)
# ---------------------------------------------------------------------------


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
        s.add(Project(id=project_id, slug="lp-pins", name="LP Pins"))
        s.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="lp-pins-agent",
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


async def _agent_state(brain_app, agent_id: uuid.UUID) -> AgentState:
    async with brain_app.state.db.session() as s:
        agent = await s.get(Agent, agent_id)
        return agent.state


def _signed_heartbeat(
    settings: Settings,
    ids: dict[str, uuid.UUID],
    *,
    nonce: str,
    frame_id: str = "hb_pin_1",
) -> str:
    """Sign a heartbeat exactly the way LongPollTransport does.

    Same per-project derived secret, same session-nonce binding the
    brain applies in ``_get_or_create_session``.
    """
    master = settings.secret.get_secret_value().encode("utf-8")
    signer = FrameSigner(
        secret=derive_project_secret(master, ids["project_id"]),
        agent_id=ids["agent_id"],
        project_id=ids["project_id"],
        session_id=nonce,
    )
    frame = HeartbeatFrame(id=frame_id, payload=HeartbeatPayload())
    return signer.sign_and_serialize(frame).decode("utf-8")


# ---------------------------------------------------------------------------
# LP-1: FrameRouter ack-emission gate
# ---------------------------------------------------------------------------


class _FakeSession:
    async def commit(self) -> None:
        return None


class _FakeDB:
    @contextlib.asynccontextmanager
    async def session(self):
        yield _FakeSession()


class _FakeIngestor:
    async def ingest_batch(self, **_kwargs):
        return []


def _router(send_frame=None) -> FrameRouter:
    return FrameRouter(
        db=_FakeDB(),
        ingestor=_FakeIngestor(),
        dispatcher=object(),
        project_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        dashboard_hub=None,
        send_frame=send_frame,
    )


async def test_longpoll_router_has_no_ack_channel() -> None:
    """The longpoll FrameRouter deliberately emits no ack.

    ``agent_longpoll.py`` builds its FrameRouter without a
    ``send_frame`` callback, so a committed event_batch produces no
    ``event_batch_ack``. That is BY DESIGN for long-poll: there is no
    open socket to sign an ack back over, and the HTTP 200 on
    ``POST /events`` is the acknowledgement. The agent side handles
    this via ``LongPollTransport.confirm_on_send`` (it confirms
    buffered entries on the 200 rather than waiting for an ack frame
    that will never come). This test pins that the brain router stays
    ack-free in that configuration so the two sides do not drift.
    """
    router = _router(send_frame=None)
    frame = EventBatchFrame(id="evb_pin_1", payload=EventBatchPayload(events=[]))
    await router.dispatch(frame)
    for _ in range(3):
        await asyncio.sleep(0)
    assert not router._pending_ack_tasks


async def test_router_with_send_frame_emits_linked_ack() -> None:
    """The ack plumbing the fix must reuse: one ack per committed
    batch, ``payload.acked_id`` carrying the original frame id.

    Whatever delivery channel the longpoll fix chooses (acks in the
    POST /events response, acks over GET /commands, or agent-side
    confirm-on-send), this linkage is the contract the agent's
    ``_handle_event_batch_ack`` (z4j-bare runtime.py:1560-1589)
    confirms buffer entries against.
    """
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame)
    frame = EventBatchFrame(id="evb_pin_2", payload=EventBatchPayload(events=[]))
    await router.dispatch(frame)
    if router._pending_ack_tasks:
        await asyncio.gather(*router._pending_ack_tasks)
    assert len(sent) == 1
    ack = sent[0]
    assert isinstance(ack, EventBatchAckFrame)
    assert ack.payload.acked_id == "evb_pin_2"


# ---------------------------------------------------------------------------
# LP-3: longpoll-only agent liveness
# ---------------------------------------------------------------------------


async def test_longpoll_verified_events_promote_online(
    client,
    brain_app,
    settings,
    agent_ids,
) -> None:
    """LP-3 fix: verified longpoll traffic promotes a never-connected
    (UNKNOWN) agent to ONLINE.

    The signed heartbeat is dispatched through the FrameRouter and the
    events POST, on accepted > 0, calls ``promote_online_if_offline``,
    whose guard is now ``state != ONLINE``. A longpoll-only agent
    starts at UNKNOWN (never saw a WS hello / ``mark_online``) and was
    pinned there forever pre-fix; now the /agents page reflects it as
    online.
    """
    nonce = "lp-pins-nonce-1"
    raw = _signed_heartbeat(settings, agent_ids, nonce=nonce)
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": [raw]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert r.status_code == 200
    assert r.json()["accepted"] == 1

    state = await _agent_state(brain_app, agent_ids["agent_id"])
    assert state == AgentState.ONLINE


async def test_promote_online_repo_semantics(brain_app, agent_ids) -> None:
    """Repo-level guard: promotes from any non-online state.

    OFFLINE -> ONLINE (the WS heartbeat un-stick path) and
    UNKNOWN -> ONLINE (the LP-3 longpoll fix) both promote; ONLINE is
    a no-op. Only three states exist (ONLINE / OFFLINE / UNKNOWN,
    z4j_core/models/agent.py:21-34), so ``state != ONLINE`` covers
    exactly OFFLINE and UNKNOWN.
    """
    agent_id = agent_ids["agent_id"]

    # UNKNOWN is promoted (the LP-3 fix).
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).promote_online_if_offline(agent_id)
        await s.commit()
    assert await _agent_state(brain_app, agent_id) == AgentState.ONLINE

    # OFFLINE is promoted (unchanged WS behavior).
    async with brain_app.state.db.session() as s:
        agent = await s.get(Agent, agent_id)
        agent.state = AgentState.OFFLINE
        await s.commit()
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).promote_online_if_offline(agent_id)
        await s.commit()
    assert await _agent_state(brain_app, agent_id) == AgentState.ONLINE
