"""Source-address allowlists on the transports the HTTP middleware never sees.

The agent WebSocket hello, both long-poll routes and the dashboard WebSocket,
driven through the real app on file-backed SQLite with the ORM schema so the
tests do not depend on the migration chain's head. Same contract as
``test_ip_allowlist.py``: the address matched is the trusted-proxy-resolved
one, every refusal leaves a ``z4j_auth_ip_denied_total{surface}`` increment
and an ``auth.ip_denied`` row (on the agent surface one per address per
interval, shared by the hello and the long-poll routes), and an empty list
restricts nothing.

The WebSocket doubles carry only what the two gateways read up to the close
they are expected to send. A dashboard double that disconnects at the
subscribe step turns "the session was admitted" into a 4400, distinct from
the 4401 a refused address gets.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import z4j_brain.api.agent_longpoll as longpoll
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api.metrics import registry
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain import ip_allowlist as ipa
from z4j_brain.domain import refusal_audit
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, AuditLog, Project, Session, User
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.dashboard_gateway import ws_dashboard
from z4j_brain.websocket.gateway import ws_agent
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.frames import (
    HeartbeatFrame,
    HeartbeatPayload,
    HelloAckFrame,
    HelloFrame,
    HelloPayload,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner
from z4j_core.transport.hmac import derive_project_secret

ALLOWED = "203.0.113.7"
DENIED = "198.51.100.9"
DENIED_TOO = "198.51.100.10"
PROXY = "10.0.0.2"
AGENT_TOKEN = "z4j_agent_ip_allowlist_probe"
BAD_TOKEN = "z4j_agent_never_minted"
NONCE_HEADER = "X-Z4J-Session-Nonce"
FETCH_URL = "/api/v1/agent/commands"
UPLOAD_URL = "/api/v1/agent/events"
_PW = "correct horse battery staple 9"


# ---------------------------------------------------------------------------
# Harness: one project, one agent, one admin with a verified session
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Seeded:
    project_id: uuid.UUID
    agent_id: uuid.UUID
    user_id: uuid.UUID
    session_id: uuid.UUID


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'transports.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        disable_spa_fallback=True,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        registry_backend="local",
        **overrides,
    )


async def _seed(app: Any, settings: Settings) -> _Seeded:
    now = datetime.now(UTC)
    seeded = _Seeded(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4())
    async with app.state.db.session() as session:
        session.add_all(
            [
                Project(id=seeded.project_id, slug="probe", name="Probe"),
                User(
                    id=seeded.user_id,
                    email="alice@example.com",
                    password_hash=PasswordHasher(settings).hash(_PW),
                    display_name="Alice",
                    is_admin=True,
                    is_active=True,
                ),
            ],
        )
        await session.flush()
        session.add_all(
            [
                Session(
                    id=seeded.session_id,
                    user_id=seeded.user_id,
                    csrf_token=secrets.token_urlsafe(32),
                    expires_at=now + timedelta(hours=1),
                    # Aged, inside the idle window, so a touch shows as a change.
                    last_seen_at=now - timedelta(minutes=10),
                    ip_at_issue=ALLOWED,
                    user_agent_at_issue="probe-browser/1",
                    mfa_verified_at=now,
                ),
                Agent(
                    id=seeded.agent_id,
                    project_id=seeded.project_id,
                    name="probe-agent",
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
                    last_seen_at=now,
                ),
            ],
        )
        await session.commit()
    return seeded


@asynccontextmanager
async def _brain(
    tmp_path: Path,
    **overrides: Any,
) -> AsyncIterator[tuple[Any, Settings, _Seeded]]:
    settings = _settings(tmp_path, **overrides)
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    try:
        yield app, settings, await _seed(app, settings)
    finally:
        await engine.dispose()


async def _denial_rows(app: Any) -> list[AuditLog]:
    async with app.state.db.session() as session:
        rows = await session.execute(
            select(AuditLog).where(AuditLog.action == ipa.AUDIT_ACTION),
        )
        return list(rows.scalars().all())


async def _rows_for(app: Any, action: str) -> list[AuditLog]:
    async with app.state.db.session() as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars().all())


async def _last_seen(app: Any, session_id: uuid.UUID) -> datetime | None:
    async with app.state.db.session() as session:
        row = await session.get(Session, session_id)
        assert row is not None
        return row.last_seen_at


def _metric(surface: str) -> float:
    return registry.get_sample_value("z4j_auth_ip_denied_total", {"surface": surface}) or 0.0


def _assert_row(row: AuditLog, *, surface: str, ip: str, path: str) -> None:
    assert row.target_type == "auth_surface"
    assert row.target_id == surface
    assert row.result == "failed"
    assert row.outcome == "deny"
    assert row.source_ip == ip
    assert row.audit_metadata["surface"] == surface
    assert row.audit_metadata["reason"] == "global_allowlist"
    assert row.audit_metadata["ip"] == ip
    assert row.audit_metadata["path"] == path


# ---------------------------------------------------------------------------
# WebSocket doubles
# ---------------------------------------------------------------------------


class _HandshakeSocket:
    """An agent hello the gateway settles at or before the bearer step."""

    def __init__(
        self,
        app: Any,
        *,
        token: str,
        peer: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.app = app
        self.client = SimpleNamespace(host=peer)
        self.headers = {
            "authorization": f"Bearer {token}",
            "user-agent": "probe-agent/1",
            **(headers or {}),
        }
        self.accepted = False
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        del reason
        self.close_code = code


class _SessionSocket(_HandshakeSocket):
    """Carries a hello so the handshake can complete; disconnects on close."""

    def __init__(
        self,
        app: Any,
        *,
        token: str,
        peer: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(app, token=token, peer=peer, headers=headers)
        self.sent: list[bytes] = []
        self.waiting_for_frame = asyncio.Event()
        self._incoming: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self._incoming.put_nowait(
            {"type": "websocket.receive", "bytes": serialize_frame(_hello())},
        )

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


class _DashboardSocket:
    """A dashboard socket that disconnects at the subscribe step.

    Getting that far closes with 4400, which is how the tests tell an
    admitted session from the 4401 a refused address gets.
    """

    def __init__(
        self,
        app: Any,
        *,
        settings: Settings,
        session_id: uuid.UUID,
        peer: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.app = app
        self.client = SimpleNamespace(host=peer)
        self.headers = {"user-agent": "probe-browser/1", **(headers or {})}
        self.cookies = {
            cookie_name(environment=settings.environment): SessionCookieCodec(settings).encode(
                session_id,
            ),
        }
        self.accepted = False
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        del reason
        self.close_code = code

    async def receive(self) -> dict[str, object]:
        return {"type": "websocket.disconnect", "code": 1000}


def _hello() -> HelloFrame:
    return HelloFrame(
        id=f"ip-hello-{secrets.token_hex(4)}",
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


async def _settled_hello(
    app: Any,
    *,
    token: str,
    peer: str,
    headers: dict[str, str] | None = None,
) -> _HandshakeSocket:
    """Run a hello the gateway must settle at or before the bearer step."""
    websocket = _HandshakeSocket(app, token=token, peer=peer, headers=headers)
    await ws_agent(websocket)  # type: ignore[arg-type]
    assert websocket.accepted is True, "the close code must reach the agent"
    return websocket


async def _established(
    app: Any,
    seeded: _Seeded,
    *,
    peer: str,
    headers: dict[str, str] | None = None,
) -> None:
    """Positive control: a hello from ``peer`` completes the handshake, then leaves."""
    websocket = _SessionSocket(app, token=AGENT_TOKEN, peer=peer, headers=headers)
    task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    brain_registry = app.state.brain_registry
    try:
        async with asyncio.timeout(3):
            while not brain_registry.is_online(seeded.agent_id):
                assert not task.done(), f"handshake ended with close {websocket.close_code}"
                await asyncio.sleep(0)
            await websocket.waiting_for_frame.wait()
    finally:
        await websocket.close(code=1000)
        await asyncio.wait_for(task, timeout=3)
    assert isinstance(parse_frame(websocket.sent[0]), HelloAckFrame)
    assert brain_registry.is_online(seeded.agent_id) is False


async def _dashboard(
    app: Any,
    settings: Settings,
    seeded: _Seeded,
    *,
    peer: str,
    headers: dict[str, str] | None = None,
) -> int | None:
    websocket = _DashboardSocket(
        app,
        settings=settings,
        session_id=seeded.session_id,
        peer=peer,
        headers=headers,
    )
    await ws_dashboard(websocket)  # type: ignore[arg-type]
    assert websocket.accepted is True
    return websocket.close_code


# ---------------------------------------------------------------------------
# Long-poll helpers
# ---------------------------------------------------------------------------


def _client(app: Any, ip: str) -> AsyncClient:
    """A client whose socket peer the brain sees as ``ip``."""
    return AsyncClient(
        transport=ASGITransport(app=app, client=(ip, 4321)),
        base_url="http://testserver",
    )


def _agent_headers(nonce: str, token: str = AGENT_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", NONCE_HEADER: nonce}


def _upload_body(settings: Settings, seeded: _Seeded, nonce: str) -> dict[str, list[str]]:
    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            seeded.project_id,
        ),
        agent_id=seeded.agent_id,
        project_id=seeded.project_id,
        session_id=nonce,
    )
    frame = HeartbeatFrame(id=f"hb-{secrets.token_hex(4)}", payload=HeartbeatPayload())
    return {"frames": [signer.sign_and_serialize(frame).decode("utf-8")]}


async def _fetch(app: Any, ip: str, headers: dict[str, str]) -> Any:
    async with _client(app, ip) as client:
        return await client.get(FETCH_URL, params={"wait": 0, "max_frames": 0}, headers=headers)


async def _upload(app: Any, ip: str, headers: dict[str, str], body: dict[str, Any]) -> Any:
    async with _client(app, ip) as client:
        return await client.post(UPLOAD_URL, json=body, headers=headers)


def _assert_denied_body(response: Any) -> None:
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == ipa.ERROR_CODE
    assert body["message"] == ipa.DENIED_MESSAGE
    assert body["details"] == {"surface": "agent"}
    # Refused before the identity advertisement, so nothing about the agent leaks.
    assert "X-Z4J-Agent-Id" not in response.headers


# ---------------------------------------------------------------------------
# Agent WebSocket
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_hello_outside_the_list_closes_4403_before_the_bearer_is_read(
    tmp_path: Path,
) -> None:
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _, seeded):
        before = _metric("agent")
        valid = await _settled_hello(app, token=AGENT_TOKEN, peer=DENIED)
        assert valid.close_code == 4403
        assert app.state.brain_registry.is_online(seeded.agent_id) is False
        # A token that was never minted gets the very same close: the list is
        # consulted before the bearer, so the hello is no oracle for a token.
        bogus = await _settled_hello(app, token=BAD_TOKEN, peer=DENIED)
        assert bogus.close_code == 4403

        # Both refusals are counted; one row is written, the record of written
        # rows being keyed on the address and shared with the long-poll routes.
        rows = await _denial_rows(app)
        assert len(rows) == 1
        _assert_row(rows[0], surface="agent", ip=DENIED, path="/ws/agent")
        assert rows[0].user_id is None
        assert rows[0].api_key_id is None
        assert rows[0].user_agent == "probe-agent/1"
        assert await _rows_for(app, "agent.auth.bearer_failed") == []
        assert _metric("agent") == before + 2


@pytest.mark.asyncio
async def test_agent_hello_inside_the_list_proceeds_to_the_bearer(tmp_path: Path) -> None:
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _, seeded):
        before = _metric("agent")
        # The bearer step is reached: a bogus token is refused the usual way,
        # with its own audit action and the resolved address on the row.
        bogus = await _settled_hello(app, token=BAD_TOKEN, peer=ALLOWED)
        assert bogus.close_code == 4401
        await _established(app, seeded, peer=ALLOWED)

        assert await _denial_rows(app) == []
        failed = await _rows_for(app, "agent.auth.bearer_failed")
        assert [row.source_ip for row in failed] == [ALLOWED]
        assert _metric("agent") == before


@pytest.mark.asyncio
async def test_agent_hello_ignores_forwarded_for_from_an_untrusted_peer(tmp_path: Path) -> None:
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _, _seeded):
        websocket = await _settled_hello(
            app,
            token=AGENT_TOKEN,
            peer=DENIED,
            headers={"x-forwarded-for": ALLOWED},
        )
        assert websocket.close_code == 4403
        rows = await _denial_rows(app)
        assert len(rows) == 1
        # The header did not become the audited address either.
        _assert_row(rows[0], surface="agent", ip=DENIED, path="/ws/agent")


@pytest.mark.asyncio
async def test_agent_hello_honours_forwarded_for_from_a_trusted_proxy(tmp_path: Path) -> None:
    async with _brain(
        tmp_path,
        agent_ip_allowlist=[f"{ALLOWED}/32"],
        trusted_proxies=[f"{PROXY}/32"],
    ) as (app, _, seeded):
        # The proxy itself is outside the list; only the forwarded client counts.
        await _established(app, seeded, peer=PROXY, headers={"x-forwarded-for": ALLOWED})
        forwarded = await _settled_hello(
            app,
            token=AGENT_TOKEN,
            peer=PROXY,
            headers={"x-forwarded-for": DENIED},
        )
        assert forwarded.close_code == 4403
        # No header from the proxy: the proxy is the client, and it is not listed.
        bare = await _settled_hello(app, token=AGENT_TOKEN, peer=PROXY)
        assert bare.close_code == 4403

        rows = await _denial_rows(app)
        assert sorted(str(row.source_ip) for row in rows) == sorted([DENIED, PROXY])


@pytest.mark.asyncio
async def test_agent_hello_ip_denied_rows_are_one_per_address_per_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused hello is closed 4403 every time and audited once per interval.

    An unlisted peer needs no credential to be refused, so one row per hello
    let a handful of addresses inside the connect bucket fill the SQLite
    writer with denial rows. The first hello of an address writes its row,
    the ones inside the interval (the dedupe clock is driven by hand) are
    counted and closed but write nothing, a second address gets its own row,
    the interval elapsing earns a new one, and a row that could not be
    written is retried on the next hello.
    """
    clock = [10_000.0]
    monkeypatch.setattr(refusal_audit, "now", lambda: clock[0])
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _, _seeded):
        before = _metric("agent")

        async def rows_by_address() -> list[str]:
            async with app.state.db.session() as session:
                rows = await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == ipa.AUDIT_ACTION)
                    .order_by(AuditLog.occurred_at, AuditLog.id),
                )
                return [str(row.source_ip) for row in rows.scalars().all()]

        async def refused_hello(peer: str) -> None:
            websocket = await _settled_hello(app, token=AGENT_TOKEN, peer=peer)
            assert websocket.close_code == 4403

        # Two hellos of one address inside the interval: one row, the first.
        await refused_hello(DENIED)
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED]
        assert _metric("agent") == before + 2

        # A second address is a second key.
        await refused_hello(DENIED_TOO)
        assert await rows_by_address() == [DENIED, DENIED_TOO]

        # Just short of the interval: no new row. At the interval: a new one.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS - 1.0
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED, DENIED_TOO]
        clock[0] += 1.0
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED]

        # A row that cannot be written gives its claim back: the next hello
        # inside the same interval writes it instead of losing the interval.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
        # The service instance is slotted, so the method is replaced on its class.
        audit_service_class = type(app.state.audit_service)
        real_record = audit_service_class.record

        async def failing_record(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(audit_service_class, "record", failing_record)
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED]
        monkeypatch.setattr(audit_service_class, "record", real_record)
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED, DENIED]
        await refused_hello(DENIED)
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED, DENIED]
        # Every refusal was counted, whether or not it wrote a row.
        assert _metric("agent") == before + 8


@pytest.mark.asyncio
async def test_agent_hello_bearer_failed_rows_are_one_per_address_per_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad bearer is closed 4401 every time and audited once per address per interval.

    Nothing was authenticated, so the address is the only fact the row
    carries, and a hello needs no valid credential to reach the bearer step.
    The first bad bearer from an address writes the row, the ones inside the
    interval (the dedupe clock is driven by hand) are closed but write
    nothing, a second address gets its own row, the interval elapsing earns
    a new one, a row that could not be written is retried on the next hello,
    ``clear_all`` forgets every claim, and the long-poll routes, which answer
    a bad bearer 401 without a row, leave the record alone.
    """
    clock = [10_000.0]
    monkeypatch.setattr(refusal_audit, "now", lambda: clock[0])
    async with _brain(tmp_path) as (app, _, seeded):

        async def rows_by_address() -> list[str]:
            async with app.state.db.session() as session:
                rows = await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == "agent.auth.bearer_failed")
                    .order_by(AuditLog.occurred_at, AuditLog.id),
                )
                return [str(row.source_ip) for row in rows.scalars().all()]

        async def bad_bearer(peer: str) -> None:
            websocket = await _settled_hello(app, token=BAD_TOKEN, peer=peer)
            assert websocket.close_code == 4401

        # Two bad bearers from one address inside the interval: one row.
        await bad_bearer(ALLOWED)
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED]
        # The valid token from the same address is admitted throughout.
        await _established(app, seeded, peer=ALLOWED)

        # A second address is a second key.
        await bad_bearer(DENIED)
        assert await rows_by_address() == [ALLOWED, DENIED]

        # Just short of the interval: no new row. At the interval: a new one.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS - 1.0
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED]
        clock[0] += 1.0
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED]

        # A row that cannot be written gives its claim back: the next hello
        # inside the same interval writes it instead of losing the interval.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
        # The service instance is slotted, so the method is replaced on its class.
        audit_service_class = type(app.state.audit_service)
        real_record = audit_service_class.record

        async def failing_record(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(audit_service_class, "record", failing_record)
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED]
        monkeypatch.setattr(audit_service_class, "record", real_record)
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED, ALLOWED]
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED, ALLOWED]

        # The suite-wide reset forgets every claim: the next hello writes.
        refusal_audit.clear_all()
        await bad_bearer(ALLOWED)
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED, ALLOWED, ALLOWED]
        assert len(refusal_audit.BEARER_FAILED_ROWS) == 1

        # The long-poll routes answer a bad bearer 401 with no row and do not
        # touch the record of written rows.
        probe = await _fetch(app, DENIED_TOO, _agent_headers("n", token=BAD_TOKEN))
        assert probe.status_code == 401, probe.text
        assert await rows_by_address() == [ALLOWED, DENIED, ALLOWED, ALLOWED, ALLOWED]
        assert len(refusal_audit.BEARER_FAILED_ROWS) == 1


# ---------------------------------------------------------------------------
# Long-poll
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_longpoll_fetch_and_upload_outside_the_list_answer_403_ip_denied(
    tmp_path: Path,
) -> None:
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, settings, seeded):
        nonce = secrets.token_hex(8)
        headers = _agent_headers(nonce)
        before = _metric("agent")

        # Negative controls: both routes admit the listed address.
        probe = await _fetch(app, ALLOWED, headers)
        assert probe.status_code == 200, probe.text
        assert probe.headers["X-Z4J-Agent-Id"] == str(seeded.agent_id)
        upload = await _upload(app, ALLOWED, headers, _upload_body(settings, seeded, nonce))
        assert upload.status_code == 200, upload.text
        assert upload.json()["accepted"] == 1

        _assert_denied_body(await _fetch(app, DENIED, headers))
        _assert_denied_body(
            await _upload(app, DENIED, headers, _upload_body(settings, seeded, nonce)),
        )
        # The list is consulted before the bearer, as on the WebSocket: a
        # token that was never minted gets the very same 403 from outside
        # the list, so neither route is an oracle for a token. From inside
        # the list the bearer step is reached and the bogus token is 401.
        bogus = _agent_headers(nonce, token=BAD_TOKEN)
        _assert_denied_body(await _fetch(app, DENIED, bogus))
        _assert_denied_body(
            await _upload(app, DENIED, bogus, _upload_body(settings, seeded, nonce))
        )
        inside = await _fetch(app, ALLOWED, bogus)
        assert inside.status_code == 401, inside.text

        # Four refusals of one address inside the interval: the first wrote
        # the row, the rest were refused without one. The metric counts all four.
        rows = await _denial_rows(app)
        assert len(rows) == 1
        for row in rows:
            _assert_row(row, surface="agent", ip=DENIED, path=FETCH_URL)
            # Nothing was authenticated when the row was written.
            assert row.user_id is None
            assert row.api_key_id is None
            assert "agent_id" not in row.audit_metadata
            assert row.user_agent is not None
        assert _metric("agent") == before + 4


@pytest.mark.asyncio
async def test_longpoll_ip_denied_rows_are_one_per_address_per_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unlisted address is refused every time and audited once per interval.

    The row carries no identity (the check runs before the bearer), so the
    address is the key: an address that keeps calling leaves one row per
    interval, a second address leaves its own, the interval elapsing (the
    dedupe clock is driven by hand) earns a new row, and the WebSocket
    gateway shares the record, so a refused hello inside the interval of a
    long-poll row writes nothing, and the other way round.
    """
    clock = [10_000.0]
    monkeypatch.setattr(refusal_audit, "now", lambda: clock[0])
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, settings, seeded):
        headers = _agent_headers(secrets.token_hex(8))
        before = _metric("agent")

        async def rows_by_address() -> list[str]:
            async with app.state.db.session() as session:
                rows = await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == ipa.AUDIT_ACTION)
                    .order_by(AuditLog.occurred_at, AuditLog.id),
                )
                return [str(row.source_ip) for row in rows.scalars().all()]

        # Three refusals of one address inside the interval: one row.
        _assert_denied_body(await _fetch(app, DENIED, headers))
        _assert_denied_body(
            await _upload(app, DENIED, headers, _upload_body(settings, seeded, "n")),
        )
        _assert_denied_body(await _fetch(app, DENIED, _agent_headers("n", token=BAD_TOKEN)))
        assert await rows_by_address() == [DENIED]

        # A second address is a second key.
        _assert_denied_body(await _fetch(app, DENIED_TOO, headers))
        _assert_denied_body(await _fetch(app, DENIED_TOO, headers))
        assert await rows_by_address() == [DENIED, DENIED_TOO]

        # Just short of the interval: no new row. At the interval: a new one.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS - 1.0
        _assert_denied_body(await _fetch(app, DENIED, headers))
        assert await rows_by_address() == [DENIED, DENIED_TOO]
        clock[0] += 1.0
        _assert_denied_body(await _fetch(app, DENIED, headers))
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED]
        assert _metric("agent") == before + 7

        # The WebSocket gateway shares the record: inside the interval of the
        # long-poll row, refused hellos of the same address are counted and
        # closed as before but write nothing.
        for _ in range(2):
            websocket = await _settled_hello(app, token=AGENT_TOKEN, peer=DENIED)
            assert websocket.close_code == 4403
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED]
        assert _metric("agent") == before + 9
        # At the interval a hello writes the row, and the long-poll routes are
        # then inside the interval of the hello's row.
        clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
        websocket = await _settled_hello(app, token=AGENT_TOKEN, peer=DENIED)
        assert websocket.close_code == 4403
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED, DENIED]
        _assert_denied_body(await _fetch(app, DENIED, headers))
        assert await rows_by_address() == [DENIED, DENIED_TOO, DENIED, DENIED]
        assert _metric("agent") == before + 11

        # The listed address was never refused and is admitted throughout.
        probe = await _fetch(app, ALLOWED, headers)
        assert probe.status_code == 200, probe.text


@pytest.mark.asyncio
async def test_longpoll_outside_the_list_does_not_reveal_an_archived_project(
    tmp_path: Path,
) -> None:
    async with _brain(tmp_path, agent_ip_allowlist=[f"{ALLOWED}/32"]) as (app, settings, seeded):
        async with app.state.db.session(write=True) as session:
            project = await session.get(Project, seeded.project_id)
            assert project is not None
            project.is_active = False
            await session.commit()
        nonce = secrets.token_hex(8)
        headers = _agent_headers(nonce)

        # Positive control: from inside the list the archive is what answers,
        # on the probe and on the upload; the first refusal leaves the audit
        # row, the second is inside the agent's dedupe interval.
        for inside in (
            await _fetch(app, ALLOWED, headers),
            await _upload(app, ALLOWED, headers, _upload_body(settings, seeded, nonce)),
        ):
            assert inside.status_code == 403, inside.text
            assert inside.json()["error"] == "project_inactive"
        inactive_rows = await _rows_for(app, "agent.auth.project_inactive")
        assert [row.audit_metadata["path"] for row in inactive_rows] == [FETCH_URL]
        assert {str(row.source_ip) for row in inactive_rows} == {ALLOWED}

        # From outside, the address is refused before the project is looked
        # at: the body is the allowlist's, and no project_inactive row joins.
        _assert_denied_body(await _fetch(app, DENIED, headers))
        _assert_denied_body(
            await _upload(app, DENIED, headers, _upload_body(settings, seeded, nonce)),
        )
        assert len(await _rows_for(app, "agent.auth.project_inactive")) == 1
        assert len(await _denial_rows(app)) == 1


# ---------------------------------------------------------------------------
# Dashboard WebSocket
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_socket_outside_the_list_closes_4401_without_a_touch(
    tmp_path: Path,
) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=[f"{ALLOWED}/32"]) as (
        app,
        settings,
        seeded,
    ):
        before = _metric("dashboard")
        aged = await _last_seen(app, seeded.session_id)

        # Admitted: the socket gets as far as the subscribe step (4400 on the
        # disconnect the double answers with) and the session is touched.
        assert await _dashboard(app, settings, seeded, peer=ALLOWED) == 4400
        touched = await _last_seen(app, seeded.session_id)
        assert touched is not None
        assert touched != aged

        assert await _dashboard(app, settings, seeded, peer=DENIED) == 4401
        # A spoofed header from an untrusted peer changes nothing.
        spoofed = await _dashboard(
            app,
            settings,
            seeded,
            peer=DENIED,
            headers={"x-forwarded-for": ALLOWED},
        )
        assert spoofed == 4401
        assert await _last_seen(app, seeded.session_id) == touched, (
            "a refused socket is not a use of the session"
        )

        rows = await _denial_rows(app)
        assert len(rows) == 2
        for row in rows:
            _assert_row(row, surface="dashboard", ip=DENIED, path="/ws/dashboard")
            assert row.user_id == seeded.user_id
            assert row.user_agent == "probe-browser/1"
        assert _metric("dashboard") == before + 2


# ---------------------------------------------------------------------------
# No list, no restriction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_lists_leave_every_transport_open(tmp_path: Path) -> None:
    async with _brain(tmp_path) as (app, settings, seeded):
        agent_before, dashboard_before = _metric("agent"), _metric("dashboard")
        nonce = secrets.token_hex(8)

        await _established(app, seeded, peer=DENIED)
        probe = await _fetch(app, DENIED, _agent_headers(nonce))
        assert probe.status_code == 200, probe.text
        upload = await _upload(
            app,
            DENIED,
            _agent_headers(nonce),
            _upload_body(settings, seeded, nonce),
        )
        assert upload.status_code == 200, upload.text
        assert await _dashboard(app, settings, seeded, peer=DENIED) == 4400

        assert await _denial_rows(app) == []
        assert (_metric("agent"), _metric("dashboard")) == (agent_before, dashboard_before)
