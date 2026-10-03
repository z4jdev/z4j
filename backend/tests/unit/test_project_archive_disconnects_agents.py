"""Archiving a project disconnects its agents and refuses them until reactivation.

The bearer lookup resolves an agent by token hash only, and an archive leaves
every agent row and token hash intact, so before this the agents of an archived
project kept connecting, streaming events and pulling commands. Every test here
runs against the real app: the archive goes through ``DELETE /api/v1/projects``
and the agents through ``ws_agent`` or the long-poll routes.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import z4j_brain.api.agent_longpoll as longpoll
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain import refusal_audit
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, AuditLog, Project, Session, User
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.gateway import ws_agent
from z4j_brain.websocket.registry.local import LocalRegistry
from z4j_brain.websocket.registry.postgres_notify import (
    _AGENT_REVOKED_CHANNEL,
    PostgresNotifyRegistry,
)
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

ALPHA_TOKEN = "z4j_agent_archive_alpha"
BETA_TOKEN = "z4j_agent_archive_beta"
CSRF_HEADER = "X-CSRF-Token"
NONCE_HEADER = "X-Z4J-Session-Nonce"


# ---------------------------------------------------------------------------
# Fixtures: a real brain app over file-backed SQLite with two active projects
# ---------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path) -> Settings:
    # File-backed rather than the shared in-memory StaticPool connection: the
    # mid-poll test overlaps a sleeping long-poll request with the archive
    # request, and two transaction owners on one SQLite connection is not a
    # supported shape.
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'archive.sqlite3'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


def _agent_row(
    *,
    agent_id: uuid.UUID,
    project_id: uuid.UUID,
    name: str,
    token: str,
    secret: bytes,
    now: datetime,
) -> Agent:
    return Agent(
        id=agent_id,
        project_id=project_id,
        name=name,
        token_hash=hash_agent_token(plaintext=token, secret=secret),
        protocol_version=CURRENT_PROTOCOL,
        framework_adapter="bare",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.OFFLINE,
        last_seen_at=now,
    )


@pytest.fixture
async def seeded(settings: Settings, brain_app) -> dict[str, Any]:
    now = datetime.now(UTC)
    ids = {
        "alpha_project": uuid.uuid4(),
        "beta_project": uuid.uuid4(),
        "alpha_agent": uuid.uuid4(),
        "beta_agent": uuid.uuid4(),
        "user": uuid.uuid4(),
        "session": uuid.uuid4(),
    }
    csrf = secrets.token_urlsafe(32)
    secret = settings.secret.get_secret_value().encode("utf-8")
    async with brain_app.state.db.session() as session:
        session.add_all(
            [
                Project(id=ids["alpha_project"], slug="alpha", name="Alpha"),
                Project(id=ids["beta_project"], slug="beta", name="Beta"),
                User(
                    id=ids["user"],
                    email="admin@example.com",
                    password_hash=PasswordHasher(settings).hash(
                        "correct horse battery staple 9",
                    ),
                    is_admin=True,
                    is_active=True,
                ),
            ],
        )
        await session.flush()
        session.add_all(
            [
                Session(
                    id=ids["session"],
                    user_id=ids["user"],
                    csrf_token=csrf,
                    expires_at=now + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                    mfa_verified_at=now,
                ),
                _agent_row(
                    agent_id=ids["alpha_agent"],
                    project_id=ids["alpha_project"],
                    name="alpha-agent",
                    token=ALPHA_TOKEN,
                    secret=secret,
                    now=now,
                ),
                _agent_row(
                    agent_id=ids["beta_agent"],
                    project_id=ids["beta_project"],
                    name="beta-agent",
                    token=BETA_TOKEN,
                    secret=secret,
                    now=now,
                ),
            ],
        )
        await session.commit()
    return {**ids, "csrf": csrf}


@pytest.fixture
async def admin_client(brain_app, settings: Settings, seeded):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(seeded["session"]),
        )
        client.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            seeded["csrf"],
        )
        yield client


# ---------------------------------------------------------------------------
# WebSocket doubles and helpers
# ---------------------------------------------------------------------------


class _RejectedWebSocket:
    """Minimum surface for a handshake the gateway refuses before hello."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.client = SimpleNamespace(host="192.0.2.42")
        self.headers = {"authorization": f"Bearer {token}"}
        self.accepted = False
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        del reason
        self.close_code = code


class _QueuedWebSocket:
    """ASGI websocket double for an established agent session."""

    def __init__(self, app, token: str, hello: HelloFrame) -> None:
        self.app = app
        self.client = None
        self.headers = {"authorization": f"Bearer {token}"}
        self.accepted = False
        self.close_code: int | None = None
        self.sent: list[bytes] = []
        self._incoming: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.waiting_for_frame = asyncio.Event()
        self._incoming.put_nowait(
            {"type": "websocket.receive", "bytes": serialize_frame(hello)},
        )

    async def accept(self) -> None:
        self.accepted = True

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


def _hello_frame() -> HelloFrame:
    return HelloFrame(
        id=f"archive-hello-{secrets.token_hex(4)}",
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


async def _connect(
    brain_app,
    *,
    token: str,
    agent_id: uuid.UUID,
) -> tuple[_QueuedWebSocket, asyncio.Task[None]]:
    """Drive ``ws_agent`` to an established session and return the double."""
    websocket = _QueuedWebSocket(brain_app, token, _hello_frame())
    task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    registry = brain_app.state.brain_registry

    async def established() -> None:
        while not registry.is_online(agent_id):  # noqa: ASYNC110
            await asyncio.sleep(0)

    await asyncio.wait_for(established(), timeout=3)
    await asyncio.wait_for(websocket.waiting_for_frame.wait(), timeout=3)
    assert websocket.accepted is True
    assert websocket.close_code is None
    assert len(websocket.sent) == 1
    assert isinstance(parse_frame(websocket.sent[0]), HelloAckFrame)
    return websocket, task


async def _disconnect(websocket: _QueuedWebSocket, task: asyncio.Task[None]) -> None:
    await websocket.close(code=1000)
    await asyncio.wait_for(task, timeout=3)


async def _archive(admin_client, seeded, slug: str = "alpha") -> None:
    response = await admin_client.delete(
        f"/api/v1/projects/{slug}",
        headers={CSRF_HEADER: seeded["csrf"]},
    )
    assert response.status_code == 204


def _signed_heartbeat(
    settings: Settings,
    *,
    agent_id: uuid.UUID,
    project_id: uuid.UUID,
    nonce: str,
) -> str:
    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            project_id,
        ),
        agent_id=agent_id,
        project_id=project_id,
        session_id=nonce,
    )
    return signer.sign_and_serialize(
        HeartbeatFrame(id=f"hb-{secrets.token_hex(4)}", payload=HeartbeatPayload()),
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# WebSocket: live sockets close, hello is refused, reactivation re-admits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_archiving_a_project_closes_its_live_sockets_and_spares_other_projects(
    brain_app,
    admin_client,
    seeded,
) -> None:
    ws_alpha, task_alpha = await _connect(
        brain_app, token=ALPHA_TOKEN, agent_id=seeded["alpha_agent"]
    )
    ws_beta, task_beta = await _connect(brain_app, token=BETA_TOKEN, agent_id=seeded["beta_agent"])
    registry = brain_app.state.brain_registry

    await _archive(admin_client, seeded)

    await asyncio.wait_for(task_alpha, timeout=3)
    assert ws_alpha.close_code == 4003, "an archived project's socket closes like a revoked one"
    assert registry.is_online(seeded["alpha_agent"]) is False
    # The other project is untouched: still registered, never closed.
    assert ws_beta.close_code is None
    assert registry.is_online(seeded["beta_agent"]) is True
    assert not task_beta.done()

    async with brain_app.state.db.session() as session:
        alpha = await session.get(Project, seeded["alpha_project"])
        assert alpha is not None
        assert alpha.is_active is False
        alpha_agent = await session.get(Agent, seeded["alpha_agent"])
        assert alpha_agent is not None
        assert alpha_agent.state == AgentState.OFFLINE
        assert alpha_agent.revoked_at is None, "archive must not revoke the agent"
        beta_agent = await session.get(Agent, seeded["beta_agent"])
        assert beta_agent is not None
        assert beta_agent.state == AgentState.ONLINE
        archived_rows = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == "project.archived"),
                )
            )
            .scalars()
            .all()
        )
        assert [row.target_id for row in archived_rows] == [str(seeded["alpha_project"])]
        assert archived_rows[0].project_id == seeded["alpha_project"]
        assert archived_rows[0].user_id == seeded["user"]

    await _disconnect(ws_beta, task_beta)


@pytest.mark.asyncio
async def test_hello_from_an_archived_project_is_refused_like_a_revoked_token(
    brain_app,
    admin_client,
    seeded,
) -> None:
    # Positive control: the same token completes a handshake while active.
    ws_before, task_before = await _connect(
        brain_app, token=ALPHA_TOKEN, agent_id=seeded["alpha_agent"]
    )
    await _disconnect(ws_before, task_before)

    await _archive(admin_client, seeded)

    websocket = _RejectedWebSocket(brain_app, ALPHA_TOKEN)
    await ws_agent(websocket)  # type: ignore[arg-type]
    assert websocket.accepted is True
    assert websocket.close_code == 4401, "same code as a revoked token, so the agent backs off"
    assert brain_app.state.brain_registry.is_online(seeded["alpha_agent"]) is False

    # The other project's agent still connects.
    ws_beta, task_beta = await _connect(brain_app, token=BETA_TOKEN, agent_id=seeded["beta_agent"])
    await _disconnect(ws_beta, task_beta)

    async with brain_app.state.db.session() as session:
        refused = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == "agent.auth.project_inactive"),
                )
            )
            .scalars()
            .all()
        )
        assert len(refused) == 1
        assert refused[0].target_type == "agent"
        assert refused[0].target_id == str(seeded["alpha_agent"])
        assert refused[0].project_id == seeded["alpha_project"]
        assert refused[0].result == "failed"
        assert refused[0].outcome == "deny"
        assert refused[0].source_ip == "192.0.2.42"
        agent = await session.get(Agent, seeded["alpha_agent"])
        assert agent is not None
        assert agent.revoked_at is None
        assert agent.state == AgentState.OFFLINE


@pytest.mark.asyncio
async def test_reactivation_admits_the_agent_again_without_reminting(
    brain_app,
    admin_client,
    seeded,
) -> None:
    await _archive(admin_client, seeded)
    refused = _RejectedWebSocket(brain_app, ALPHA_TOKEN)
    await ws_agent(refused)  # type: ignore[arg-type]
    assert refused.close_code == 4401

    # There is no reactivation route; the flag is flipped where an operator
    # would flip it. Nothing else changes: same agent row, same token.
    async with brain_app.state.db.session(write=True) as session:
        project = await session.get(Project, seeded["alpha_project"])
        assert project is not None
        project.is_active = True
        await session.commit()

    websocket, task = await _connect(brain_app, token=ALPHA_TOKEN, agent_id=seeded["alpha_agent"])
    probe = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": f"Bearer {ALPHA_TOKEN}"},
    )
    assert probe.status_code == 200
    await _disconnect(websocket, task)


@pytest.mark.asyncio
async def test_hello_from_an_archived_project_is_audited_once_per_agent_per_interval(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused hello is closed 4401 every time and audited once per interval.

    The agent of an archived project reconnects on its backoff until the
    project is active again, and every row it would write names the same
    agent, project and address. The first hello writes the row, the ones
    inside the interval (the dedupe clock is driven by hand) are closed but
    write nothing, the interval elapsing earns a new row, a row that could
    not be written is retried on the next hello, and the long-poll routes
    share the record.
    """
    clock = [10_000.0]
    monkeypatch.setattr(refusal_audit, "now", lambda: clock[0])
    await _archive(admin_client, seeded)
    alpha_id = str(seeded["alpha_agent"])

    async def refused_hello() -> None:
        websocket = _RejectedWebSocket(brain_app, ALPHA_TOKEN)
        await ws_agent(websocket)  # type: ignore[arg-type]
        assert websocket.accepted is True
        assert websocket.close_code == 4401

    async def rows_by_agent() -> list[str]:
        return [row.target_id for row in await _project_inactive_rows(brain_app)]

    # Two hellos inside the interval: one row, the first.
    await refused_hello()
    await refused_hello()
    assert await rows_by_agent() == [alpha_id]

    # Just short of the interval: still the same row. At the interval: a new one.
    clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS - 1.0
    await refused_hello()
    assert await rows_by_agent() == [alpha_id]
    clock[0] += 1.0
    await refused_hello()
    assert await rows_by_agent() == [alpha_id, alpha_id]

    # A row that cannot be written gives its claim back: the next hello
    # inside the same interval writes it instead of losing the interval.
    clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
    # The service instance is slotted, so the method is replaced on its class.
    audit_service_class = type(brain_app.state.audit_service)
    real_record = audit_service_class.record

    async def failing_record(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_service_class, "record", failing_record)
    await refused_hello()
    assert await rows_by_agent() == [alpha_id, alpha_id]
    monkeypatch.setattr(audit_service_class, "record", real_record)
    await refused_hello()
    assert await rows_by_agent() == [alpha_id, alpha_id, alpha_id]
    await refused_hello()
    assert await rows_by_agent() == [alpha_id, alpha_id, alpha_id]

    # The long-poll routes share the record: inside the interval of the
    # hello's row they refuse the agent without a row.
    response = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": f"Bearer {ALPHA_TOKEN}", NONCE_HEADER: secrets.token_hex(8)},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "project_inactive"
    assert await rows_by_agent() == [alpha_id, alpha_id, alpha_id]


# ---------------------------------------------------------------------------
# Long-poll: 403 with a stable error on fetch and upload, including mid-wait
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_longpoll_fetch_and_upload_answer_403_project_inactive(
    brain_app,
    admin_client,
    seeded,
    settings: Settings,
) -> None:
    nonce = secrets.token_hex(8)
    alpha_headers = {"Authorization": f"Bearer {ALPHA_TOKEN}", NONCE_HEADER: nonce}

    def upload_body() -> dict[str, list[str]]:
        return {
            "frames": [
                _signed_heartbeat(
                    settings,
                    agent_id=seeded["alpha_agent"],
                    project_id=seeded["alpha_project"],
                    nonce=nonce,
                ),
            ],
        }

    # Negative controls: probe, fetch and upload all succeed while active.
    probe = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers=alpha_headers,
    )
    assert probe.status_code == 200
    fetch = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 50},
        headers=alpha_headers,
    )
    assert fetch.status_code == 200
    upload = await admin_client.post(
        "/api/v1/agent/events", json=upload_body(), headers=alpha_headers
    )
    assert upload.status_code == 200
    assert upload.json()["accepted"] == 1

    await _archive(admin_client, seeded)

    for name, response in (
        (
            "probe",
            await admin_client.get(
                "/api/v1/agent/commands",
                params={"wait": 0, "max_frames": 0},
                headers=alpha_headers,
            ),
        ),
        (
            "fetch",
            await admin_client.get(
                "/api/v1/agent/commands",
                params={"wait": 0, "max_frames": 50},
                headers=alpha_headers,
            ),
        ),
        (
            "upload",
            await admin_client.post(
                "/api/v1/agent/events", json=upload_body(), headers=alpha_headers
            ),
        ),
    ):
        assert response.status_code == 403, name
        body = response.json()
        assert body["error"] == "project_inactive", name
        assert body["details"]["project_id"] == str(seeded["alpha_project"]), name
        assert body["details"]["agent_id"] == str(seeded["alpha_agent"]), name
        assert "X-Z4J-Agent-Id" not in response.headers, name

    # The first refusal left the row the WebSocket gateway writes for a hello
    # from an archived project, so the trail shows long-poll agents too: the
    # agent, its project, the resolved address and (long-poll only) the route
    # path. The two refusals that followed inside the interval left none: one
    # row per agent per interval, however often it calls.
    refused = await _project_inactive_rows(brain_app)
    assert [row.audit_metadata["path"] for row in refused] == ["/api/v1/agent/commands"]
    for row in refused:
        assert row.target_type == "agent"
        assert row.target_id == str(seeded["alpha_agent"])
        assert row.audit_metadata["agent_id"] == str(seeded["alpha_agent"])
        assert row.project_id == seeded["alpha_project"]
        assert row.result == "failed"
        assert row.outcome == "deny"
        assert row.source_ip is not None

    # The other project's agent is untouched, and a bad token is still 401,
    # so the 403 is the archive and not a change to bearer handling.
    beta = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": f"Bearer {BETA_TOKEN}"},
    )
    assert beta.status_code == 200
    bad = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": "Bearer not-a-token"},
    )
    assert bad.status_code == 401
    # Neither an admitted agent nor a bad token is an inactive-project refusal.
    assert len(await _project_inactive_rows(brain_app)) == 1


async def _project_inactive_rows(brain_app) -> list[AuditLog]:
    async with brain_app.state.db.session() as session:
        rows = await session.execute(
            select(AuditLog)
            .where(AuditLog.action == "agent.auth.project_inactive")
            .order_by(AuditLog.occurred_at, AuditLog.id),
        )
        return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_longpoll_refusal_rows_are_one_per_agent_per_interval(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused agent is answered 403 every time and audited once per interval.

    An agent from a release that treats the 403 as transient retries every
    1 to 30 seconds; without the dedupe one such agent of an archived project
    appended about 2,880 chained rows a day. The first refusal's row is
    immediate, a second agent gets its own, the interval elapsing (the
    dedupe clock is driven by hand) earns a new row, a row that could not be
    written is retried on the next refusal, and the WebSocket gateway shares
    the record, so a refused hello inside the interval of a long-poll row
    writes nothing, and the other way round.
    """
    clock = [10_000.0]
    monkeypatch.setattr(refusal_audit, "now", lambda: clock[0])
    alpha = {"Authorization": f"Bearer {ALPHA_TOKEN}", NONCE_HEADER: secrets.token_hex(8)}
    beta = {"Authorization": f"Bearer {BETA_TOKEN}", NONCE_HEADER: secrets.token_hex(8)}

    async def refuse(headers: dict[str, str]) -> None:
        response = await admin_client.get(
            "/api/v1/agent/commands",
            params={"wait": 0, "max_frames": 0},
            headers=headers,
        )
        assert response.status_code == 403
        assert response.json()["error"] == "project_inactive"

    async def rows_by_agent() -> list[str]:
        return [row.target_id for row in await _project_inactive_rows(brain_app)]

    await _archive(admin_client, seeded, "alpha")
    # The route refuses to archive the last active project; the flag is
    # flipped where an operator would flip it, as the reactivation test does.
    async with brain_app.state.db.session(write=True) as session:
        beta_project = await session.get(Project, seeded["beta_project"])
        assert beta_project is not None
        beta_project.is_active = False
        await session.commit()
    alpha_id, beta_id = str(seeded["alpha_agent"]), str(seeded["beta_agent"])

    # Three refusals of one agent inside the interval: one row, the first one.
    for _ in range(3):
        await refuse(alpha)
    assert await rows_by_agent() == [alpha_id]

    # A second agent is a second key: its first refusal writes its own row.
    await refuse(beta)
    await refuse(beta)
    assert await rows_by_agent() == [alpha_id, beta_id]

    # Just short of the interval: still the same row. At the interval: a new one.
    clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS - 1.0
    await refuse(alpha)
    assert await rows_by_agent() == [alpha_id, beta_id]
    clock[0] += 1.0
    await refuse(alpha)
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id]

    # A row that cannot be written gives its claim back: the next refusal
    # inside the same interval writes it instead of losing the interval.
    clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
    # The service instance is slotted, so the method is replaced on its class.
    audit_service_class = type(brain_app.state.audit_service)
    real_record = audit_service_class.record

    async def failing_record(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_service_class, "record", failing_record)
    await refuse(alpha)
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id]
    monkeypatch.setattr(audit_service_class, "record", real_record)
    await refuse(alpha)
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id, alpha_id]
    await refuse(alpha)
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id, alpha_id]

    # The WebSocket gateway shares the record: inside the interval of the
    # long-poll row, refused hellos of the same agent are closed as before
    # but write nothing.
    for _ in range(2):
        websocket = _RejectedWebSocket(brain_app, ALPHA_TOKEN)
        await ws_agent(websocket)  # type: ignore[arg-type]
        assert websocket.close_code == 4401
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id, alpha_id]
    # At the interval a hello writes the row, and the long-poll routes are
    # then inside the interval of the hello's row.
    clock[0] += longpoll._REFUSAL_AUDIT_INTERVAL_SECONDS
    websocket = _RejectedWebSocket(brain_app, ALPHA_TOKEN)
    await ws_agent(websocket)  # type: ignore[arg-type]
    assert websocket.close_code == 4401
    assert await rows_by_agent() == [alpha_id, beta_id, alpha_id, alpha_id, alpha_id]
    await refuse(alpha)
    assert len(await rows_by_agent()) == 5


@pytest.mark.asyncio
async def test_longpoll_wait_detects_an_archive_committed_mid_poll(
    brain_app,
    admin_client,
    seeded,
) -> None:
    headers = {"Authorization": f"Bearer {ALPHA_TOKEN}", NONCE_HEADER: secrets.token_hex(8)}
    # Positive control for the wait path itself: an idle poll completes normally.
    idle = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 1, "max_frames": 50},
        headers=headers,
    )
    assert idle.status_code == 200
    assert idle.json()["frames"] == []

    poll = asyncio.create_task(
        admin_client.get(
            "/api/v1/agent/commands",
            params={"wait": 5, "max_frames": 50},
            headers=headers,
        ),
    )
    await asyncio.sleep(0.6)
    assert not poll.done(), "the poll must still be waiting when the archive lands"
    assert await _project_inactive_rows(brain_app) == []

    await _archive(admin_client, seeded)

    response = await asyncio.wait_for(poll, timeout=5)
    assert response.status_code == 403
    assert response.json()["error"] == "project_inactive"
    # The mid-wait refusal is recorded like the up-front one.
    (row,) = await _project_inactive_rows(brain_app)
    assert row.target_id == str(seeded["alpha_agent"])
    assert row.audit_metadata["path"] == "/api/v1/agent/commands"


# ---------------------------------------------------------------------------
# Registry backends: the project kick on both implementations
# ---------------------------------------------------------------------------


class _FakeSocket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.close_code: int | None = None

    async def close(self, code: int = 1000) -> None:
        self.close_code = code


async def _deliver(_command_id: uuid.UUID, _ws: Any) -> bool:
    return True


@pytest.mark.asyncio
async def test_local_registry_kick_project_closes_only_that_projects_sockets() -> None:
    registry = LocalRegistry(deliver_local=_deliver)
    alpha, beta = uuid.uuid4(), uuid.uuid4()
    agent_a, agent_a2, agent_b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    a_w1, a_w2, a2_legacy, b_w1 = (_FakeSocket(n) for n in ("a-w1", "a-w2", "a2", "b-w1"))
    await registry.register(project_id=alpha, agent_id=agent_a, ws=a_w1, worker_id="w1")
    await registry.register(project_id=alpha, agent_id=agent_a, ws=a_w2, worker_id="w2")
    await registry.register(project_id=alpha, agent_id=agent_a2, ws=a2_legacy)
    await registry.register(project_id=beta, agent_id=agent_b, ws=b_w1, worker_id="w1")

    closed = await registry.kick_project(alpha)

    assert closed == 3
    assert {s.close_code for s in (a_w1, a_w2, a2_legacy)} == {4003}
    assert b_w1.close_code is None
    assert registry.is_online(agent_a) is False
    assert registry.is_online(agent_a2) is False
    assert registry.is_online(agent_b) is True
    assert registry.fleet_snapshot() == {
        "agents": {str(beta): 1},
        "workers": {str(beta): 1},
    }
    assert await registry.kick_project(alpha) == 0, "idempotent"


def _postgres_registry(settings: Settings, engine) -> PostgresNotifyRegistry:
    return PostgresNotifyRegistry(
        settings=settings,
        db=DatabaseManager(engine),
        dsn_provider=lambda: "postgresql://unused",
        deliver_local=_deliver,
    )


@pytest.fixture
def registry_settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.mark.asyncio
async def test_postgres_registry_kick_project_closes_local_sockets_and_broadcasts(
    registry_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The local half of the cluster kick, plus the exact NOTIFY payload.

    SQLite has no ``pg_notify``, so the publish step is captured where the
    real one issues the NOTIFY; the real-Postgres round trip lives in the
    integration suite.
    """
    engine = create_async_engine(registry_settings.database_url)
    registry = _postgres_registry(registry_settings, engine)
    published: list[str] = []

    async def capture(payload: str) -> None:
        published.append(payload)

    monkeypatch.setattr(registry, "_publish_revoke_notify", capture)
    alpha, beta = uuid.uuid4(), uuid.uuid4()
    agent_a, agent_a2, agent_b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    a1, a2, b1 = _FakeSocket("a1"), _FakeSocket("a2"), _FakeSocket("b1")
    try:
        await registry.register(project_id=alpha, agent_id=agent_a, ws=a1, worker_id="w1")
        await registry.register(project_id=alpha, agent_id=agent_a2, ws=a2, worker_id="w1")
        await registry.register(project_id=beta, agent_id=agent_b, ws=b1, worker_id="w1")

        closed = await registry.kick_project(alpha)
        assert closed == 2
        assert a1.close_code == 4003
        assert a2.close_code == 4003
        assert b1.close_code is None
        assert registry.is_online(agent_a) is False
        assert registry.is_online(agent_b) is True
        assert published == [f"project:{alpha}"]

        # Nothing left locally, but another replica may hold sockets, so the
        # broadcast still goes out.
        assert await registry.kick_project(alpha) == 0
        assert published == [f"project:{alpha}", f"project:{alpha}"]

        # The per-agent revoke keeps its bare-uuid wire form.
        assert await registry.kick(agent_b) == 1
        assert published[-1] == str(agent_b)
        assert b1.close_code == 4003
    finally:
        await engine.dispose()


async def _settled(predicate) -> None:
    """Wait for the listener's background kick task to land."""
    async with asyncio.timeout(2.0):
        while not predicate():  # noqa: ASYNC110  polling a plain attribute set by a background task
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_postgres_registry_listener_kicks_project_payload_and_keeps_agent_payload(
    registry_settings: Settings,
) -> None:
    """A receiving replica closes its own sockets for the project form."""
    engine = create_async_engine(registry_settings.database_url)
    registry = _postgres_registry(registry_settings, engine)
    alpha, beta = uuid.uuid4(), uuid.uuid4()
    agent_a, agent_b = uuid.uuid4(), uuid.uuid4()
    a1, b1 = _FakeSocket("a1"), _FakeSocket("b1")
    try:
        await registry.register(project_id=alpha, agent_id=agent_a, ws=a1, worker_id="w1")
        await registry.register(project_id=beta, agent_id=agent_b, ws=b1, worker_id="w1")

        # Malformed and unknown payloads are ignored without raising and
        # without touching any socket: a replica that does not hold the
        # project is a no-op, and garbage is logged, not acted on.
        for payload in ("project:not-a-uuid", f"project:{uuid.uuid4()}", "garbage", ""):
            registry._on_agent_revoked(None, 0, _AGENT_REVOKED_CHANNEL, payload)  # type: ignore[arg-type]
        await asyncio.sleep(0.05)
        assert a1.close_code is None
        assert b1.close_code is None

        registry._on_agent_revoked(None, 0, _AGENT_REVOKED_CHANNEL, f"project:{alpha}")  # type: ignore[arg-type]
        await _settled(lambda: a1.close_code is not None)
        assert a1.close_code == 4003
        assert b1.close_code is None
        assert registry.is_online(agent_a) is False
        assert registry.is_online(agent_b) is True

        # The bare agent-id form a revoke publishes still works unchanged.
        registry._on_agent_revoked(None, 0, _AGENT_REVOKED_CHANNEL, str(agent_b))  # type: ignore[arg-type]
        await _settled(lambda: b1.close_code is not None)
        assert b1.close_code == 4003
        assert registry.is_online(agent_b) is False
    finally:
        await engine.dispose()
