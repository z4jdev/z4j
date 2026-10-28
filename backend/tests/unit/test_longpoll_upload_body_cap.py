"""Body cap of the agent long-poll upload (``POST /api/v1/agent/events``).

Every request is read against ``Z4J_MAX_PAYLOAD_SIZE_BYTES`` (8 KiB by
default), except an upload from an admitted agent: that one may be as large
as a single frame the WebSocket gateway accepts, escaped into the
``{"frames": [...]}`` envelope. The route admits the caller (throttle,
address, bearer, project) before FastAPI reads the body, so a caller that
is not admitted is answered without a single body byte read, whatever it
declares or streams.

Driven through the real app on SQLite with the ORM schema, partly through
the raw ASGI interface so the tests can count the body bytes the app read
and send a body without ``Content-Length``.
"""

from __future__ import annotations

import json
import secrets
import uuid
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.api.agent_longpoll import upload_body_limit_bytes
from z4j_brain.main import AGENT_EVENTS_PATH, create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import CURRENT_PROTOCOL

AGENT_TOKEN = "z4j_agent_upload_body_cap"
GLOBAL_CAP = 8_192


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
        "registry_backend": "local",
        "max_payload_size_bytes": GLOBAL_CAP,
    }
    values.update(overrides)
    return Settings(**values)


async def _app(settings: Settings) -> Any:
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    project_id = uuid.uuid4()
    async with app.state.db.session() as session:
        session.add(Project(id=project_id, slug="cap", name="Cap"))
        await session.flush()
        session.add(
            Agent(
                id=uuid.uuid4(),
                project_id=project_id,
                name="cap-agent",
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
    app.state._test_engine = engine
    return app


@pytest.fixture
async def app() -> AsyncIterator[Any]:
    brain = await _app(_settings())
    yield brain
    await brain.state._test_engine.dispose()


def _envelope(frame: str) -> bytes:
    """The body the shipped agent sends: compact JSON, UTF-8, not ASCII-escaped."""
    return json.dumps({"frames": [frame]}, separators=(",", ":"), ensure_ascii=False).encode()


async def _raw_post(
    app: Any,
    chunks: Iterable[bytes],
    *,
    token: str,
    content_length: bool = True,
    path: str = AGENT_EVENTS_PATH,
) -> tuple[int | None, int]:
    """POST through ASGI; return (status, body bytes the app read)."""
    pending = list(chunks)
    total = sum(len(chunk) for chunk in pending)
    read = 0

    async def receive() -> dict[str, Any]:
        nonlocal read
        if pending:
            chunk = pending.pop(0)
            read += len(chunk)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    status: int | None = None

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]

    headers = [
        (b"host", b"testserver"),
        (b"authorization", f"Bearer {token}".encode()),
        (b"content-type", b"application/json"),
    ]
    if content_length:
        headers.append((b"content-length", str(total).encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": headers,
        "client": ("203.0.113.7", 4321),
        "server": ("testserver", 80),
    }
    await app(scope, receive, send)
    return status, read


def _chunks(body: bytes, size: int = 4096) -> list[bytes]:
    return [body[i : i + size] for i in range(0, len(body), size)]


def test_events_path_is_the_route_the_router_serves() -> None:
    app = create_app(_settings())
    assert app.url_path_for("agent_events") == AGENT_EVENTS_PATH


def test_upload_cap_admits_one_websocket_sized_frame_after_escaping() -> None:
    settings = _settings()
    frame_cap = settings.effective_ws_max_frame_bytes
    # The worst case escaping of a frame: every byte a quote.
    worst = _envelope('"' * frame_cap)
    assert len(worst) <= upload_body_limit_bytes(settings)
    # Never below the global cap, whatever the frame cap.
    raised = _settings(max_payload_size_bytes=8 * 1024 * 1024)
    assert upload_body_limit_bytes(raised) == 8 * 1024 * 1024


async def test_admitted_agent_upload_above_the_global_cap_is_processed(app: Any) -> None:
    """A 600 KiB frame (an unparseable one, so the brain drops and acks it)."""
    body = _envelope("x" * (600 * 1024))
    assert len(body) > GLOBAL_CAP
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.post(
            AGENT_EVENTS_PATH,
            content=body,
            headers={"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"},
        )
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 1


async def test_admitted_agent_upload_of_a_maximal_escaped_frame_is_processed(app: Any) -> None:
    frame_cap = app.state.settings.effective_ws_max_frame_bytes
    status, read = await _raw_post(app, _chunks(_envelope('"' * frame_cap)), token=AGENT_TOKEN)
    assert status == 200
    assert read > 2 * frame_cap


async def test_admitted_agent_upload_above_the_upload_cap_is_413(app: Any) -> None:
    limit = upload_body_limit_bytes(app.state.settings)
    status, read = await _raw_post(app, _chunks(_envelope("x" * limit)), token=AGENT_TOKEN)
    assert status == 413
    assert read == 0


async def test_admitted_agent_streamed_upload_above_the_upload_cap_is_413(app: Any) -> None:
    """No Content-Length: the cap holds on the bytes actually read."""
    limit = upload_body_limit_bytes(app.state.settings)
    status, read = await _raw_post(
        app,
        _chunks(_envelope("x" * limit), size=64 * 1024),
        token=AGENT_TOKEN,
        content_length=False,
    )
    assert status == 413
    assert read <= limit + 64 * 1024


@pytest.mark.parametrize("content_length", [True, False], ids=["declared", "streamed"])
async def test_unadmitted_upload_is_answered_before_its_body_is_read(
    app: Any,
    content_length: bool,
) -> None:
    body = _envelope("x" * (600 * 1024))
    status, read = await _raw_post(
        app,
        _chunks(body),
        token="z4j_agent_never_minted",
        content_length=content_length,
    )
    assert status == 401
    assert read == 0


async def test_other_routes_keep_the_global_cap(app: Any) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "a@example.com", "password": "x" * (2 * GLOBAL_CAP)},
        )
    assert r.status_code == 413


async def test_frame_cap_follows_the_websocket_frame_cap() -> None:
    """A frame the WebSocket gateway would refuse is refused here too (422)."""
    settings = _settings(ws_max_frame_bytes=64 * 1024)
    brain = await _app(settings)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=brain),
            base_url="http://testserver",
        ) as client:
            headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"}
            over = await client.post(
                AGENT_EVENTS_PATH, content=_envelope("x" * (64 * 1024 + 1)), headers=headers
            )
            within = await client.post(
                AGENT_EVENTS_PATH, content=_envelope("x" * (64 * 1024)), headers=headers
            )
    finally:
        await brain.state._test_engine.dispose()
    assert over.status_code == 422, over.text
    assert "cap is 65536" in over.text
    assert within.status_code == 200, within.text


async def test_streamed_body_over_the_global_cap_is_413_on_other_routes(app: Any) -> None:
    """Without Content-Length a FastAPI route used to report the overflow as a parse error (400)."""
    body = json.dumps({"email": "a@example.com", "password": "x" * (4 * GLOBAL_CAP)}).encode()
    status, read = await _raw_post(
        app,
        _chunks(body, size=1024),
        token="unused",
        content_length=False,
        path="/api/v1/auth/login",
    )
    assert status == 413
    assert read <= GLOBAL_CAP + 1024
