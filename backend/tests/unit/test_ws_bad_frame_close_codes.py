"""Close codes for unacceptable frames on an established agent WebSocket.

A mid-session frame that is not JSON, is not a JSON object, carries a
missing, mistyped or different protocol version ``v``, or names an unknown
frame type is malformed input. The frame verifier reports these as
``ProtocolError``; the gateway closes them 4400, like an empty or oversized
frame, and keeps 1011 for a genuine brain-side fault. The shipped agent
reconnects on its ordinary schedule for both codes, so the code is what an
operator reads, not a change in how the agent retries.

Driven through the real gateway on file-backed SQLite with the ORM schema.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.gateway import ws_agent
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.frames import (
    PROTOCOL_VERSION,
    HeartbeatFrame,
    HeartbeatPayload,
    HelloAckFrame,
    HelloFrame,
    HelloPayload,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import derive_project_secret

AGENT_TOKEN = "z4j_agent_bad_frame_close_codes"


@asynccontextmanager
async def _brain(tmp_path: Path) -> AsyncIterator[tuple[Any, Settings, uuid.UUID, uuid.UUID]]:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'bad-frames.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        disable_spa_fallback=True,
        registry_backend="local",
    )
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    project_id, agent_id = uuid.uuid4(), uuid.uuid4()
    async with app.state.db.session() as session:
        session.add(Project(id=project_id, slug="frames", name="Frames"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="frames-agent",
                token_hash=hash_agent_token(
                    plaintext=AGENT_TOKEN,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
                last_seen_at=datetime.now(UTC),
            ),
        )
        await session.commit()
    try:
        yield app, settings, project_id, agent_id
    finally:
        await engine.dispose()


class _AgentSocket:
    """An agent socket that completes the hello, then sends what the test queues."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.client = SimpleNamespace(host="203.0.113.7")
        self.headers = {
            "authorization": f"Bearer {AGENT_TOKEN}",
            "user-agent": "frames-agent/1",
        }
        self.close_code: int | None = None
        self.sent: list[bytes] = []
        self.waiting_for_frame = asyncio.Event()
        self._incoming: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        hello = HelloFrame(
            id=f"frames-hello-{secrets.token_hex(4)}",
            payload=HelloPayload(
                protocol_version=CURRENT_PROTOCOL,
                agent_version="0.0.0",
                framework="bare",
                engines=["celery"],
                schedulers=[],
                capabilities={},
                host={},
                runtime_features=[],
            ),
        )
        self._incoming.put_nowait({"type": "websocket.receive", "bytes": serialize_frame(hello)})

    async def accept(self) -> None:
        return None

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        del reason
        if self.close_code is None:
            self.close_code = code
            self._incoming.put_nowait({"type": "websocket.disconnect"})

    async def receive(self) -> dict[str, object]:
        if self._incoming.empty():
            self.waiting_for_frame.set()
        return await self._incoming.get()

    async def send_bytes(self, payload: bytes) -> None:
        self.sent.append(payload)

    def queue(self, payload: bytes) -> None:
        self.waiting_for_frame.clear()
        self._incoming.put_nowait({"type": "websocket.receive", "bytes": payload})


async def _session_then(app: Any, payloads: list[bytes]) -> _AgentSocket:
    """Complete the handshake, send ``payloads`` in order, return the socket."""
    websocket = _AgentSocket(app)
    task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    try:
        async with asyncio.timeout(5):
            await websocket.waiting_for_frame.wait()
            assert websocket.close_code is None, f"handshake closed {websocket.close_code}"
            assert isinstance(parse_frame(websocket.sent[0]), HelloAckFrame)
            for payload in payloads:
                websocket.queue(payload)
                while websocket.close_code is None:
                    if websocket.waiting_for_frame.is_set():
                        break
                    await asyncio.sleep(0.01)
    finally:
        await websocket.close(code=1000)
        await asyncio.wait_for(task, timeout=5)
    return websocket


def _signed_heartbeat(settings: Settings, websocket: _AgentSocket) -> bytes:
    ack = parse_frame(websocket.sent[0])
    assert isinstance(ack, HelloAckFrame)
    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            uuid.UUID(ack.payload.project_id),
        ),
        agent_id=ack.payload.agent_id,
        project_id=ack.payload.project_id,
        session_id=ack.payload.session_id,
    )
    return signer.sign_and_serialize(
        HeartbeatFrame(id=f"hb-{secrets.token_hex(4)}", payload=HeartbeatPayload()),
    )


_MALFORMED: dict[str, bytes] = {
    "not_json": b"this is not json",
    "not_an_object": b"[1, 2, 3]",
    "missing_version": json.dumps({"type": "heartbeat", "id": "hb-1", "payload": {}}).encode(),
    "mistyped_version": json.dumps(
        {"v": str(PROTOCOL_VERSION), "type": "heartbeat", "id": "hb-1", "payload": {}},
    ).encode(),
    "different_version": json.dumps(
        {"v": PROTOCOL_VERSION + 7, "type": "heartbeat", "id": "hb-1", "payload": {}},
    ).encode(),
    "unknown_type": json.dumps(
        {"v": PROTOCOL_VERSION, "type": "no_such_frame", "id": "x-1", "payload": {}},
    ).encode(),
}


@pytest.mark.parametrize("case", sorted(_MALFORMED))
async def test_malformed_mid_session_frame_closes_4400(tmp_path: Path, case: str) -> None:
    async with _brain(tmp_path) as (app, _settings, _project_id, _agent_id):
        websocket = await _session_then(app, [_MALFORMED[case]])
    assert websocket.close_code == 4400, case


async def test_valid_signed_frame_keeps_the_session_open(tmp_path: Path) -> None:
    """Positive control: a signed heartbeat is accepted and nothing closes."""
    async with _brain(tmp_path) as (app, settings, _project_id, _agent_id):
        websocket = _AgentSocket(app)
        task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
        try:
            async with asyncio.timeout(5):
                await websocket.waiting_for_frame.wait()
                websocket.queue(_signed_heartbeat(settings, websocket))
                await websocket.waiting_for_frame.wait()
            assert websocket.close_code is None
        finally:
            await websocket.close(code=1000)
            await asyncio.wait_for(task, timeout=5)
    assert websocket.close_code == 1000


async def test_brain_side_fault_still_closes_1011(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only malformed input moved to 4400; a fault in the brain stays 1011."""

    def broken(self: FrameVerifier, data: bytes | str) -> Any:
        del self, data
        raise RuntimeError("simulated brain fault")

    async with _brain(tmp_path) as (app, _settings, _project_id, _agent_id):
        monkeypatch.setattr(FrameVerifier, "parse_and_verify", broken)
        websocket = await _session_then(app, [b'{"v": 2, "type": "heartbeat"}'])
    assert websocket.close_code == 1011
