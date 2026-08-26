"""Regression tests for durable agent revocation and stale-agent pruning."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.schedule_fire_authority import derive_execution_fire_id
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.agent_authority import local_agent_authority
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, CommandStatus, ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    AgentOfflineAlert,
    BulkRetryRequest,
    Command,
    Event,
    Membership,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.persistence.repositories import (
    AgentOfflineAlertRepository,
    AgentRepository,
    CommandRepository,
)
from z4j_brain.persistence.repositories.agents import REVOKED_AGENT_NAME_PREFIX
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.gateway import (
    deliver_command_frame_with_authority,
    ws_agent,
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

AGENT_TOKEN = "z4j_agent_soft_revoke_test"
AGENT_NAME = "event-producing-agent"


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
        login_min_duration_ms=10,
        registry_backend="local",
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        # SQLite normally hides the PostgreSQL failure mode by allowing an
        # orphan. Enabling FK enforcement makes the unit test exercise the
        # model's non-null ON DELETE RESTRICT agent/event boundary.
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded(settings: Settings, brain_app) -> dict[str, object]:
    now = datetime.now(UTC)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    event_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    token_hash = hash_agent_token(
        plaintext=AGENT_TOKEN,
        secret=settings.secret.get_secret_value().encode("utf-8"),
    )

    async with brain_app.state.db.session() as session:
        session.add_all(
            [
                Project(id=project_id, slug="default", name="Default"),
                User(
                    id=user_id,
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
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=now + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                    mfa_verified_at=now,
                ),
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name=AGENT_NAME,
                    token_hash=token_hash,
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
        await session.flush()
        session.add(
            Event(
                id=event_id,
                project_id=project_id,
                agent_id=agent_id,
                engine="celery",
                task_id="task-soft-revoke",
                kind="task.succeeded",
                occurred_at=now,
                payload={},
            ),
        )
        await session.commit()

    return {
        "agent_id": agent_id,
        "csrf": csrf,
        "event_id": event_id,
        "event_occurred_at": now,
        "project_id": project_id,
        "session_id": session_id,
        "token_hash": token_hash,
        "user_id": user_id,
    }


@pytest.fixture
async def authority_delivery_env(tmp_path) -> AsyncIterator[dict[str, object]]:
    """File-backed SQLite so two authority transactions can truly contend."""
    db_path = tmp_path / "revoke-send-authority.sqlite3"
    local_settings = Settings(
        database_url=f"sqlite+aiosqlite:///{db_path}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        command_timeout_seconds=10,
    )
    engine = create_async_engine(local_settings.database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    command_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="authority", name="Authority"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="authority-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        session.add(
            Command(
                id=command_id,
                project_id=project_id,
                agent_id=agent_id,
                issued_by=None,
                action="cancel_task",
                target_type="task",
                target_id="celery:authority",
                payload={"engine": "celery", "task_id": "authority"},
                timeout_at=datetime.now(UTC) + timedelta(minutes=1),
            ),
        )
        await session.commit()
    async with db.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
    signer = FrameSigner(
        secret=derive_project_secret(
            local_settings.secret.get_secret_value().encode("utf-8"),
            project_id,
        ),
        agent_id=agent_id,
        project_id=project_id,
        session_id=uuid.uuid4(),
    )
    yield {
        "agent_id": agent_id,
        "command": command,
        "db": db,
        "project_id": project_id,
        "settings": local_settings,
        "signer": signer,
    }
    await engine.dispose()


@pytest.fixture
async def admin_client(brain_app, settings: Settings, seeded):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(seeded["session_id"]),
        )
        from z4j_brain.auth.csrf import csrf_cookie_name

        client.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            seeded["csrf"],
        )
        yield client


class _RejectedWebSocket:
    """Minimum WebSocket surface needed by the bearer-rejection path."""

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
    """ASGI websocket double for an established-session revoke race."""

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

    def send_agent_frame(self, payload: bytes) -> None:
        self._incoming.put_nowait({"type": "websocket.receive", "bytes": payload})


class _BlockedHelloWebSocket(_QueuedWebSocket):
    """Pause after bearer auth, just before the gateway reads Hello."""

    def __init__(self, app, token: str, hello: HelloFrame) -> None:
        super().__init__(app, token, hello)
        self.receive_started = asyncio.Event()
        self.release_receive = asyncio.Event()
        self._first_receive = True

    async def receive(self) -> dict[str, object]:
        if self._first_receive:
            self._first_receive = False
            self.receive_started.set()
            await self.release_receive.wait()
        return await super().receive()


class _AuthoritySendWebSocket:
    """Socket double that can hold the physical-send authority window open."""

    def __init__(
        self,
        *,
        agent_id: uuid.UUID,
        signer: FrameSigner,
        blocked: bool = False,
    ) -> None:
        self._z4j_agent_id = agent_id
        self._z4j_signer = signer
        self.send_started = asyncio.Event()
        self.release_send = asyncio.Event()
        if not blocked:
            self.release_send.set()
        self.sent: list[bytes] = []

    async def send_bytes(self, payload: bytes) -> None:
        self.send_started.set()
        await self.release_send.wait()
        self.sent.append(payload)


@pytest.mark.asyncio
async def test_revoke_preserves_event_and_rejects_old_token_on_both_transports(
    brain_app,
    admin_client,
    seeded,
) -> None:
    """The operator route retires identity without deleting its history."""
    agent_id = seeded["agent_id"]

    # Negative controls: this exact row is visible and this exact bearer is
    # accepted before revocation. The post-revoke assertions therefore cannot
    # pass merely because the fixture started hidden or unauthenticated.
    listed_before = await admin_client.get("/api/v1/projects/default/agents")
    assert listed_before.status_code == 200
    assert str(agent_id) in {item["id"] for item in listed_before.json()}
    accepted_before = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert accepted_before.status_code == 200
    home_before = await admin_client.get("/api/v1/home/summary")
    assert home_before.status_code == 200
    home_before_body = home_before.json()
    assert home_before_body["aggregate"]["agents_total"] == 1
    assert home_before_body["projects"][0]["agents_total"] == 1
    stats_before = await admin_client.get("/api/v1/projects/default/stats")
    assert stats_before.status_code == 200
    assert stats_before.json()["agents_offline"] == 1
    duplicate = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": AGENT_NAME},
    )
    assert duplicate.status_code == 409

    # Mutation negative control: the old endpoint's hard DELETE is genuinely
    # rejected by the same FK shape PostgreSQL enforces. A test that merely
    # checked the final event row without enabling/probing this constraint
    # could pass while SQLite silently orphaned it.
    async with brain_app.state.db.session() as session:
        with pytest.raises(IntegrityError):
            await session.execute(delete(Agent).where(Agent.id == agent_id))
        await session.rollback()

    response = await admin_client.delete(
        f"/api/v1/projects/default/agents/{agent_id}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert response.status_code == 204

    async with brain_app.state.db.session() as session:
        fk_enabled = await session.scalar(text("PRAGMA foreign_keys"))
        assert fk_enabled == 1
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.revoked_at is not None
        assert agent.name == AGENT_NAME
        assert agent.agent_metadata["_z4j_revoked_original_name"] == AGENT_NAME
        assert agent.state == AgentState.OFFLINE
        assert agent.token_hash != seeded["token_hash"]
        assert agent.token_hash.startswith(f"revoked:{agent_id}:")

        event = (
            await session.execute(
                select(Event).where(
                    Event.project_id == seeded["project_id"],
                    Event.occurred_at == seeded["event_occurred_at"],
                    Event.id == seeded["event_id"],
                ),
            )
        ).scalar_one()
        assert event.agent_id == agent_id
        assert (await session.execute(text("PRAGMA foreign_key_check"))).all() == []

    listed_after = await admin_client.get("/api/v1/projects/default/agents")
    assert listed_after.status_code == 200
    assert str(agent_id) not in {item["id"] for item in listed_after.json()}
    home_after = await admin_client.get("/api/v1/home/summary")
    assert home_after.status_code == 200
    home_after_body = home_after.json()
    assert home_after_body["aggregate"]["agents_total"] == 0
    assert home_after_body["projects"][0]["agents_total"] == 0
    stats_after = await admin_client.get("/api/v1/projects/default/stats")
    assert stats_after.status_code == 200
    assert stats_after.json()["agents_offline"] == 0

    longpoll_after = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert longpoll_after.status_code == 401

    websocket = _RejectedWebSocket(brain_app, AGENT_TOKEN)
    await ws_agent(websocket)  # type: ignore[arg-type]
    assert websocket.accepted is True
    assert websocket.close_code == 4401

    replacement = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": AGENT_NAME},
    )
    assert replacement.status_code == 201
    replacement_id = uuid.UUID(replacement.json()["agent"]["id"])
    assert replacement_id != agent_id

    reserved = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": f"{REVOKED_AGENT_NAME_PREFIX}operator-choice"},
    )
    assert reserved.status_code == 422

    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        replacement_row = await session.get(Agent, replacement_id)
        event = (
            await session.execute(
                select(Event).where(
                    Event.project_id == seeded["project_id"],
                    Event.occurred_at == seeded["event_occurred_at"],
                    Event.id == seeded["event_id"],
                ),
            )
        ).scalar_one()
        assert tombstone is not None
        assert tombstone.name.startswith(f"{REVOKED_AGENT_NAME_PREFIX}{agent_id}")
        assert tombstone.agent_metadata["_z4j_revoked_original_name"] == AGENT_NAME
        assert replacement_row is not None
        assert replacement_row.name == AGENT_NAME
        assert replacement_row.revoked_at is None
        assert event is not None
        assert event.agent_id == agent_id


@pytest.mark.asyncio
async def test_sqlite_remint_revalidates_role_after_name_reservation(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SQLite path uses the same post-authority policy invariant."""
    async with brain_app.state.db.session(write=True) as session:
        actor = await session.get(User, seeded["user_id"])
        assert actor is not None
        actor.is_admin = False
        session.add(
            Membership(
                user_id=seeded["user_id"],
                project_id=seeded["project_id"],
                role=ProjectRole.ADMIN,
            ),
        )
        await session.commit()

    revoked = await admin_client.delete(
        f"/api/v1/projects/default/agents/{seeded['agent_id']}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert revoked.status_code == 204

    original_reserve_name = AgentRepository.reserve_name

    async def demote_after_reservation(
        repository: AgentRepository,
        *,
        project_id: uuid.UUID,
        name: str,
    ):
        reservation = await original_reserve_name(
            repository,
            project_id=project_id,
            name=name,
        )
        membership = await repository.session.scalar(
            select(Membership).where(
                Membership.user_id == seeded["user_id"],
                Membership.project_id == seeded["project_id"],
            ),
        )
        assert membership is not None
        membership.role = ProjectRole.VIEWER
        await repository.session.flush()
        return reservation

    monkeypatch.setattr(
        AgentRepository,
        "reserve_name",
        demote_after_reservation,
    )

    replacement = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": AGENT_NAME},
    )
    assert replacement.status_code == 403

    async with brain_app.state.db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(Agent).where(Agent.project_id == seeded["project_id"]),
                )
            ).scalars(),
        )
        assert len(rows) == 1
        assert rows[0].id == seeded["agent_id"]
        assert rows[0].name == AGENT_NAME
        assert rows[0].revoked_at is not None


@pytest.mark.asyncio
async def test_revoke_owns_original_name_metadata_across_repeated_revoke(
    brain_app,
    admin_client,
    seeded,
) -> None:
    """Agent metadata cannot spoof provenance or replace it after rename."""
    agent_id = seeded["agent_id"]
    async with brain_app.state.db.session(write=True) as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        agent.agent_metadata = {
            "_z4j_revoked_original_name": "operator-supplied-spoof",
            "legitimate": "preserved",
        }
        await session.commit()

    first = await admin_client.delete(
        f"/api/v1/projects/default/agents/{agent_id}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert first.status_code == 204
    replacement = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": AGENT_NAME},
    )
    assert replacement.status_code == 201

    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.name.startswith(f"{REVOKED_AGENT_NAME_PREFIX}{agent_id}")
        assert tombstone.agent_metadata == {
            "_z4j_revoked_original_name": AGENT_NAME,
            "legitimate": "preserved",
        }

    repeated = await admin_client.delete(
        f"/api/v1/projects/default/agents/{agent_id}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert repeated.status_code == 204
    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.agent_metadata["_z4j_revoked_original_name"] == AGENT_NAME
        assert tombstone.agent_metadata["legitimate"] == "preserved"


def _hello_frame() -> HelloFrame:
    return HelloFrame(
        id="soft-revoke-hello",
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


@pytest.mark.asyncio
async def test_websocket_revoke_between_auth_and_promotion_cannot_resurrect(
    brain_app,
    admin_client,
    seeded,
) -> None:
    websocket = _BlockedHelloWebSocket(brain_app, AGENT_TOKEN, _hello_frame())
    gateway_task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    await asyncio.wait_for(websocket.receive_started.wait(), timeout=2)

    revoked = await admin_client.delete(
        f"/api/v1/projects/default/agents/{seeded['agent_id']}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert revoked.status_code == 204
    websocket.release_receive.set()
    await asyncio.wait_for(gateway_task, timeout=3)

    assert websocket.close_code == 4401
    assert websocket.sent == []
    assert brain_app.state.brain_registry.is_online(seeded["agent_id"]) is False
    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, seeded["agent_id"])
        assert tombstone is not None
        assert tombstone.revoked_at is not None
        assert tombstone.state == AgentState.OFFLINE


@pytest.mark.asyncio
async def test_websocket_revoke_between_promotion_and_register_is_rechecked(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    websocket = _QueuedWebSocket(brain_app, AGENT_TOKEN, _hello_frame())
    registry = brain_app.state.brain_registry
    register_started = asyncio.Event()
    release_register = asyncio.Event()
    real_register = registry.register

    async def paused_register(**kwargs):
        register_started.set()
        await release_register.wait()
        return await real_register(**kwargs)

    monkeypatch.setattr(registry, "register", paused_register)
    gateway_task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    await asyncio.wait_for(register_started.wait(), timeout=2)
    assert len(websocket.sent) == 1
    assert registry.is_online(seeded["agent_id"]) is False

    revoked = await admin_client.delete(
        f"/api/v1/projects/default/agents/{seeded['agent_id']}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert revoked.status_code == 204
    release_register.set()
    await asyncio.wait_for(gateway_task, timeout=3)

    assert websocket.close_code == 4003
    assert registry.is_online(seeded["agent_id"]) is False
    assert len(websocket.sent) == 1


@pytest.mark.asyncio
async def test_established_websocket_rechecks_marker_when_registry_kick_fails(
    brain_app,
    admin_client,
    seeded,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The durable marker is authoritative even if best-effort kick crashes."""
    websocket = _QueuedWebSocket(brain_app, AGENT_TOKEN, _hello_frame())
    gateway_task = asyncio.create_task(ws_agent(websocket))  # type: ignore[arg-type]
    registry = brain_app.state.brain_registry

    async def established() -> None:
        while not registry.is_online(seeded["agent_id"]):  # noqa: ASYNC110
            await asyncio.sleep(0)

    await asyncio.wait_for(established(), timeout=2)
    # Registry registration precedes the gateway's remaining handshake DB
    # work.  Wait until it reaches the receive loop before starting a second
    # request; StaticPool intentionally has one in-memory SQLite connection
    # and cannot safely serve overlapping transaction owners.
    await asyncio.wait_for(websocket.waiting_for_frame.wait(), timeout=2)
    assert websocket.accepted is True
    assert len(websocket.sent) == 1
    hello_ack = parse_frame(websocket.sent[0])
    assert isinstance(hello_ack, HelloAckFrame)

    async with brain_app.state.db.session() as session:
        connected = await session.get(Agent, seeded["agent_id"])
        assert connected is not None
        baseline_seen = connected.last_seen_at

    async def broken_kick(_agent_id: uuid.UUID) -> int:
        raise RuntimeError("simulated registry kick failure")

    monkeypatch.setattr(registry, "kick", broken_kick)
    revoked = await admin_client.delete(
        f"/api/v1/projects/default/agents/{seeded['agent_id']}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert revoked.status_code == 204
    assert registry.is_online(seeded["agent_id"])

    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            seeded["project_id"],
        ),
        agent_id=seeded["agent_id"],
        project_id=seeded["project_id"],
        session_id=uuid.UUID(hello_ack.payload.session_id),
    )
    websocket.send_agent_frame(
        signer.sign_and_serialize(
            HeartbeatFrame(
                id="heartbeat-after-revoke",
                payload=HeartbeatPayload(),
            ),
        ),
    )
    await asyncio.wait_for(gateway_task, timeout=3)

    assert websocket.close_code == 4003
    assert registry.is_online(seeded["agent_id"]) is False
    assert len(websocket.sent) == 1
    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, seeded["agent_id"])
        assert tombstone is not None
        assert tombstone.state == AgentState.OFFLINE
        assert tombstone.last_seen_at == baseline_seen


@pytest.mark.asyncio
async def test_outbound_sender_rejects_socket_bound_to_another_agent(
    authority_delivery_env: dict[str, object],
) -> None:
    """The live target row cannot authorize an unrelated registered socket."""
    db = authority_delivery_env["db"]
    command = authority_delivery_env["command"]
    settings = authority_delivery_env["settings"]
    signer = authority_delivery_env["signer"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(command, Command)
    assert isinstance(settings, Settings)
    assert isinstance(signer, FrameSigner)

    websocket = _AuthoritySendWebSocket(
        agent_id=uuid.uuid4(),
        signer=signer,
    )
    delivered = await deliver_command_frame_with_authority(
        db=db,
        websocket=websocket,  # type: ignore[arg-type]
        settings=settings,
        command=command,
    )

    assert delivered is False
    assert websocket.sent == []


@pytest.mark.asyncio
async def test_outbound_sender_rejects_tombstone_before_physical_send(
    authority_delivery_env: dict[str, object],
) -> None:
    db = authority_delivery_env["db"]
    command = authority_delivery_env["command"]
    settings = authority_delivery_env["settings"]
    signer = authority_delivery_env["signer"]
    agent_id = authority_delivery_env["agent_id"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(command, Command)
    assert isinstance(settings, Settings)
    assert isinstance(signer, FrameSigner)
    assert isinstance(agent_id, uuid.UUID)

    async with db.session(write=True) as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
        await session.commit()

    websocket = _AuthoritySendWebSocket(agent_id=agent_id, signer=signer)
    delivered = await deliver_command_frame_with_authority(
        db=db,
        websocket=websocket,  # type: ignore[arg-type]
        settings=settings,
        command=command,
    )

    assert delivered is False
    assert websocket.sent == []


@pytest.mark.asyncio
async def test_doctor_treats_a_revoked_tombstone_as_no_minted_agent(
    authority_delivery_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    """Doctor's operational count must not mistake history for access."""
    from z4j_brain import cli as brain_cli

    db = authority_delivery_env["db"]
    settings = authority_delivery_env["settings"]
    agent_id = authority_delivery_env["agent_id"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(settings, Settings)
    assert isinstance(agent_id, uuid.UUID)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path / "doctor-home"))
    monkeypatch.setenv("Z4J_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    monkeypatch.setenv("Z4J_SECRET", settings.secret.get_secret_value())
    monkeypatch.setenv(
        "Z4J_SESSION_SECRET",
        settings.session_secret.get_secret_value(),
    )
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_METRICS_AUTH_TOKEN", secrets.token_urlsafe(32))
    monkeypatch.setattr(brain_cli, "_run_check", lambda _args: 0)

    assert await asyncio.to_thread(brain_cli._run_doctor, SimpleNamespace()) == 0
    live_output = capsys.readouterr().out
    assert "Projects exist but no agents minted" not in live_output

    async with db.session(write=True) as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
        await session.commit()

    assert await asyncio.to_thread(brain_cli._run_doctor, SimpleNamespace()) == 0
    revoked_output = capsys.readouterr().out
    assert "Projects exist but no agents minted" in revoked_output


@pytest.mark.asyncio
async def test_outbound_send_that_wins_forces_revoke_to_wait(
    authority_delivery_env: dict[str, object],
) -> None:
    db = authority_delivery_env["db"]
    command = authority_delivery_env["command"]
    settings = authority_delivery_env["settings"]
    signer = authority_delivery_env["signer"]
    agent_id = authority_delivery_env["agent_id"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(command, Command)
    assert isinstance(settings, Settings)
    assert isinstance(signer, FrameSigner)
    assert isinstance(agent_id, uuid.UUID)
    websocket = _AuthoritySendWebSocket(
        agent_id=agent_id,
        signer=signer,
        blocked=True,
    )

    send_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=websocket,  # type: ignore[arg-type]
            settings=settings,
            command=command,
        ),
    )
    await asyncio.wait_for(websocket.send_started.wait(), timeout=2)
    revoke_entered = asyncio.Event()

    async def revoke() -> None:
        revoke_entered.set()
        async with local_agent_authority(agent_id), db.session(write=True) as session:
            agent = await session.get(Agent, agent_id)
            assert agent is not None
            await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
            await session.commit()

    revoke_task = asyncio.create_task(revoke())
    await revoke_entered.wait()
    await asyncio.sleep(0.05)
    assert revoke_task.done() is False

    websocket.release_send.set()
    assert await asyncio.wait_for(send_task, timeout=2) is True
    await asyncio.wait_for(revoke_task, timeout=2)
    assert len(websocket.sent) == 1
    async with db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.revoked_at is not None


@pytest.mark.asyncio
async def test_blocked_sqlite_send_does_not_hold_global_writer_lock(
    authority_delivery_env: dict[str, object],
) -> None:
    """An unrelated SQLite mutation completes while socket I/O is blocked."""

    db = authority_delivery_env["db"]
    command = authority_delivery_env["command"]
    settings = authority_delivery_env["settings"]
    signer = authority_delivery_env["signer"]
    agent_id = authority_delivery_env["agent_id"]
    project_id = authority_delivery_env["project_id"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(command, Command)
    assert isinstance(settings, Settings)
    assert isinstance(signer, FrameSigner)
    assert isinstance(agent_id, uuid.UUID)
    assert isinstance(project_id, uuid.UUID)
    websocket = _AuthoritySendWebSocket(
        agent_id=agent_id,
        signer=signer,
        blocked=True,
    )

    send_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=websocket,  # type: ignore[arg-type]
            settings=settings,
            command=command,
        ),
    )
    await asyncio.wait_for(websocket.send_started.wait(), timeout=2)

    async def unrelated_write() -> None:
        async with db.session(write=True) as session:
            await session.execute(
                update(Project)
                .where(Project.id == project_id)
                .values(name="Unrelated writer completed"),
            )
            await session.commit()

    await asyncio.wait_for(unrelated_write(), timeout=1)
    assert send_task.done() is False

    websocket.release_send.set()
    assert await asyncio.wait_for(send_task, timeout=2) is True
    async with db.session() as session:
        assert (
            await session.scalar(select(Project.name).where(Project.id == project_id))
        ) == "Unrelated writer completed"


@pytest.mark.asyncio
async def test_sqlite_revoke_releases_request_writer_before_waiting_for_send(
    brain_app,
    admin_client,
    seeded,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real DELETE route waits per-agent without blocking other writes."""

    import z4j_brain.api.agents as agents_api

    command = Command(
        id=uuid.uuid4(),
        project_id=seeded["project_id"],
        agent_id=seeded["agent_id"],
        issued_by=None,
        action="cancel_task",
        target_type="task",
        target_id="celery:request-writer",
        payload={"engine": "celery", "task_id": "request-writer"},
        timeout_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    async with brain_app.state.db.session(write=True) as session:
        session.add(command)
        await session.commit()

    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            seeded["project_id"],
        ),
        agent_id=seeded["agent_id"],
        project_id=seeded["project_id"],
        session_id=uuid.uuid4(),
    )
    websocket = _AuthoritySendWebSocket(
        agent_id=seeded["agent_id"],
        signer=signer,
        blocked=True,
    )
    send_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=brain_app.state.db,
            websocket=websocket,  # type: ignore[arg-type]
            settings=settings,
            command=command,
        ),
    )
    await asyncio.wait_for(websocket.send_started.wait(), timeout=2)

    revoke_waiting = asyncio.Event()
    real_local_authority = agents_api.local_agent_authority

    @contextlib.asynccontextmanager
    async def observed_local_authority(agent_id: uuid.UUID) -> AsyncIterator[None]:
        revoke_waiting.set()
        async with real_local_authority(agent_id):
            yield

    monkeypatch.setattr(
        agents_api,
        "local_agent_authority",
        observed_local_authority,
    )
    revoke_task = asyncio.create_task(
        admin_client.delete(
            f"/api/v1/projects/default/agents/{seeded['agent_id']}",
            headers={"X-CSRF-Token": seeded["csrf"]},
        ),
    )
    await asyncio.wait_for(revoke_waiting.wait(), timeout=2)
    assert revoke_task.done() is False

    # The request entered get_session with BEGIN IMMEDIATE, but it must have
    # rolled that transaction back before reaching the observed mutex wait.
    async with brain_app.state.db.session(write=True) as session:
        await session.execute(
            update(Project)
            .where(Project.id == seeded["project_id"])
            .values(name="Writer passed queued revoke"),
        )
        await asyncio.wait_for(session.commit(), timeout=1)
    assert send_task.done() is False
    assert revoke_task.done() is False

    websocket.release_send.set()
    assert await asyncio.wait_for(send_task, timeout=2) is True
    response = await asyncio.wait_for(revoke_task, timeout=2)
    assert response.status_code == 204
    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, seeded["agent_id"])
        assert tombstone is not None
        assert tombstone.revoked_at is not None
        assert (
            await session.scalar(
                select(Project.name).where(Project.id == seeded["project_id"]),
            )
        ) == "Writer passed queued revoke"


@pytest.mark.asyncio
async def test_sqlite_queued_revoke_rechecks_membership_after_send(
    brain_app,
    admin_client,
    seeded,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A membership removal committed during the mutex wait denies revoke."""

    import z4j_brain.api.agents as agents_api

    command = Command(
        id=uuid.uuid4(),
        project_id=seeded["project_id"],
        agent_id=seeded["agent_id"],
        issued_by=None,
        action="cancel_task",
        target_type="task",
        target_id="celery:membership-recheck",
        payload={"engine": "celery", "task_id": "membership-recheck"},
        timeout_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    async with brain_app.state.db.session(write=True) as session:
        actor = await session.get(User, seeded["user_id"])
        assert actor is not None
        actor.is_admin = False
        session.add(
            Membership(
                user_id=seeded["user_id"],
                project_id=seeded["project_id"],
                role=ProjectRole.ADMIN,
            ),
        )
        session.add(command)
        await session.commit()

    signer = FrameSigner(
        secret=derive_project_secret(
            settings.secret.get_secret_value().encode("utf-8"),
            seeded["project_id"],
        ),
        agent_id=seeded["agent_id"],
        project_id=seeded["project_id"],
        session_id=uuid.uuid4(),
    )
    websocket = _AuthoritySendWebSocket(
        agent_id=seeded["agent_id"],
        signer=signer,
        blocked=True,
    )
    send_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=brain_app.state.db,
            websocket=websocket,  # type: ignore[arg-type]
            settings=settings,
            command=command,
        ),
    )
    await asyncio.wait_for(websocket.send_started.wait(), timeout=2)

    revoke_waiting = asyncio.Event()
    real_local_authority = agents_api.local_agent_authority

    @contextlib.asynccontextmanager
    async def observed_local_authority(agent_id: uuid.UUID) -> AsyncIterator[None]:
        revoke_waiting.set()
        async with real_local_authority(agent_id):
            yield

    monkeypatch.setattr(
        agents_api,
        "local_agent_authority",
        observed_local_authority,
    )
    revoke_task = asyncio.create_task(
        admin_client.delete(
            f"/api/v1/projects/default/agents/{seeded['agent_id']}",
            headers={"X-CSRF-Token": seeded["csrf"]},
        ),
    )
    await asyncio.wait_for(revoke_waiting.wait(), timeout=2)

    # This writer wins after the endpoint's initial authorization but before
    # the fresh authority transaction. The resumed endpoint must not rely on
    # its snapshotted role.
    async with brain_app.state.db.session(write=True) as session:
        await session.execute(
            delete(Membership).where(
                Membership.user_id == seeded["user_id"],
                Membership.project_id == seeded["project_id"],
            ),
        )
        await session.commit()

    websocket.release_send.set()
    assert await asyncio.wait_for(send_task, timeout=2) is True
    response = await asyncio.wait_for(revoke_task, timeout=2)
    assert response.status_code == 404
    async with brain_app.state.db.session() as session:
        agent = await session.get(Agent, seeded["agent_id"])
        assert agent is not None
        assert agent.revoked_at is None


@pytest.mark.asyncio
async def test_cancelled_outbound_send_releases_revocation_authority(
    authority_delivery_env: dict[str, object],
) -> None:
    db = authority_delivery_env["db"]
    command = authority_delivery_env["command"]
    settings = authority_delivery_env["settings"]
    signer = authority_delivery_env["signer"]
    agent_id = authority_delivery_env["agent_id"]
    assert isinstance(db, DatabaseManager)
    assert isinstance(command, Command)
    assert isinstance(settings, Settings)
    assert isinstance(signer, FrameSigner)
    assert isinstance(agent_id, uuid.UUID)
    websocket = _AuthoritySendWebSocket(
        agent_id=agent_id,
        signer=signer,
        blocked=True,
    )
    send_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=websocket,  # type: ignore[arg-type]
            settings=settings,
            command=command,
        ),
    )
    await asyncio.wait_for(websocket.send_started.wait(), timeout=2)
    send_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await send_task

    async def revoke() -> None:
        async with local_agent_authority(agent_id), db.session(write=True) as session:
            agent = await session.get(Agent, agent_id)
            assert agent is not None
            await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
            await session.commit()

    await asyncio.wait_for(revoke(), timeout=2)
    assert websocket.sent == []


@pytest.mark.asyncio
async def test_same_name_remint_survives_legacy_reserved_name_collision(
    brain_app,
    admin_client,
    seeded,
) -> None:
    """A legacy internal-looking name cannot turn revoke into a 500."""
    agent_id = seeded["agent_id"]
    occupied_name = f"{REVOKED_AGENT_NAME_PREFIX}{agent_id}"
    occupied_id = uuid.uuid4()
    async with brain_app.state.db.session() as session:
        session.add(
            Agent(
                id=occupied_id,
                project_id=seeded["project_id"],
                name=occupied_name,
                token_hash=f"legacy-reserved-name-{occupied_id}",
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=[],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
            ),
        )
        await session.commit()

    revoked = await admin_client.delete(
        f"/api/v1/projects/default/agents/{agent_id}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert revoked.status_code == 204

    replacement = await admin_client.post(
        "/api/v1/projects/default/agents",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={"name": AGENT_NAME},
    )
    assert replacement.status_code == 201

    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        occupied = await session.get(Agent, occupied_id)
        assert tombstone is not None
        assert tombstone.name.startswith(f"{occupied_name}:")
        assert tombstone.name != occupied_name
        assert occupied is not None
        assert occupied.name == occupied_name


@pytest.mark.asyncio
async def test_revoked_agent_cannot_be_targeted_by_command_or_bulk_request(
    brain_app,
    admin_client,
    seeded,
) -> None:
    agent_id = seeded["agent_id"]
    response = await admin_client.delete(
        f"/api/v1/projects/default/agents/{agent_id}",
        headers={"X-CSRF-Token": seeded["csrf"]},
    )
    assert response.status_code == 204

    command = await admin_client.post(
        "/api/v1/projects/default/commands/cancel-task",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={
            "agent_id": str(agent_id),
            "engine": "celery",
            "task_id": "revoked-target",
        },
    )
    assert command.status_code == 404

    bulk = await admin_client.post(
        "/api/v1/projects/default/bulk-retry-requests",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={
            "idempotency_key": "revoked-target",
            "agent_id": str(agent_id),
            "filter": {},
            "max": 1,
        },
    )
    assert bulk.status_code == 404

    async with brain_app.state.db.session() as session:
        assert await session.scalar(select(Command.id)) is None
        assert await session.scalar(select(BulkRetryRequest.id)) is None


@pytest.mark.asyncio
async def test_revoked_agent_cannot_be_resurrected_by_state_updates(
    brain_app,
    seeded,
) -> None:
    agent_id = seeded["agent_id"]
    after = datetime.now(UTC) + timedelta(minutes=5)
    async with brain_app.state.db.session() as session:
        repo = AgentRepository(session)
        agent = await repo.get(agent_id)
        assert agent is not None
        baseline_seen = agent.last_seen_at
        await repo.revoke(agent, at=datetime.now(UTC))
        await session.commit()

    async with brain_app.state.db.session() as session:
        repo = AgentRepository(session)
        assert (
            await repo.mark_online(
                agent_id,
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["rq"],
                scheduler_adapters=[],
                capabilities={"rq": ["cancel_task"]},
                runtime_features=["revived"],
            )
            is None
        )
        assert await repo.touch_heartbeat_at(agent_id, when=after) is False
        assert await repo.promote_online_if_offline(agent_id) is False
        await session.commit()

    async with brain_app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.state == AgentState.OFFLINE
        assert agent.last_seen_at == baseline_seen
        assert agent.engine_adapters == ["celery"]
        assert "runtime_features" not in (agent.agent_metadata or {})

        live = Agent(
            project_id=seeded["project_id"],
            name="live-state-control",
            token_hash=f"live-state-control-{uuid.uuid4()}",
            protocol_version="0",
            framework_adapter="unknown",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.OFFLINE,
        )
        session.add(live)
        await session.commit()
        live_id = live.id

    async with brain_app.state.db.session() as session:
        repo = AgentRepository(session)
        connected_at = await repo.mark_online(
            live_id,
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
        )
        assert connected_at is not None
        assert await repo.touch_heartbeat_at(live_id, when=after) is True
        await session.commit()

    async with brain_app.state.db.session() as session:
        live = await session.get(Agent, live_id)
        assert live is not None
        assert live.state == AgentState.ONLINE
        assert live.last_seen_at.replace(tzinfo=UTC) == after


@pytest.mark.asyncio
async def test_longpoll_rechecks_revocation_before_claim_after_authentication(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bearer authenticated before revoke has no later claim authority."""
    import z4j_brain.api.agent_longpoll as longpoll

    control = await admin_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert control.status_code == 200
    assert control.json() == {"frames": []}

    authenticated = asyncio.Event()
    release = asyncio.Event()
    real_get_session = longpoll._get_or_create_session

    async def pause_after_authentication(**kwargs):
        result = await real_get_session(**kwargs)
        authenticated.set()
        await release.wait()
        return result

    monkeypatch.setattr(longpoll, "_get_or_create_session", pause_after_authentication)
    request_task = asyncio.create_task(
        admin_client.get(
            "/api/v1/agent/commands",
            params={"wait": 2, "max_frames": 1},
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
        ),
    )
    await asyncio.wait_for(authenticated.wait(), timeout=2)

    command_id = uuid.uuid4()
    async with brain_app.state.db.session(write=True) as session:
        session.add(
            Command(
                id=command_id,
                project_id=seeded["project_id"],
                agent_id=seeded["agent_id"],
                issued_by=None,
                action="cancel_task",
                target_type="task",
                target_id="celery:longpoll-race",
                payload={"engine": "celery", "task_id": "longpoll-race"},
                timeout_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
        )
        agent = await AgentRepository(session).get(seeded["agent_id"])
        assert agent is not None
        await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
        await session.commit()

    release.set()
    response = await asyncio.wait_for(request_task, timeout=3)
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid agent token"}

    async with brain_app.state.db.session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.status.value == "pending"
        assert command.dispatched_at is None


@pytest.mark.asyncio
async def test_longpoll_current_claim_rechecks_revoke_after_selection(
    brain_app,
    admin_client,
    seeded,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Schedule→Agent→Command edge rejects a selected stale row."""
    now = datetime.now(UTC)
    schedule_id = uuid.uuid4()
    fire_id = uuid.uuid4()
    control_token = uuid.uuid4()
    execution_fire_id = derive_execution_fire_id(fire_id, control_token)
    async with brain_app.state.db.session(write=True) as session:
        session.add(
            Schedule(
                id=schedule_id,
                project_id=seeded["project_id"],
                engine="celery",
                scheduler="z4j-scheduler",
                name="revoke-current-claim",
                task_name="jobs.revoke_current",
                kind=ScheduleKind.INTERVAL,
                expression="5m",
                timezone="UTC",
                args=[],
                kwargs={},
                is_enabled=True,
            ),
        )
        command, created = await CommandRepository(
            session,
        ).insert_current_schedule_fire(
            project_id=seeded["project_id"],
            agent_id=seeded["agent_id"],
            schedule_id=schedule_id,
            fire_id=fire_id,
            scheduled_for=now,
            observed_control_token=control_token,
            receipt_control_token=control_token,
            execution_fire_id=execution_fire_id,
            acceptance_revision=2,
            definition_digest="d" * 64,
            expected_revision=1,
            expected_last_run_at=None,
            expected_next_run_at=now,
            prepared_next_run_at=now + timedelta(minutes=5),
            payload={
                "fire_id": str(execution_fire_id),
                "task_name": "jobs.revoke_current",
            },
            timeout_at=now + timedelta(minutes=5),
            initial_claim_deadline=now + timedelta(minutes=1),
        )
        assert created is True
        command_id = command.id
        await session.commit()

    async def no_bulk(**_kwargs):
        return []

    monkeypatch.setattr(
        brain_app.state.bulk_retry_coordinator,
        "claim_for_longpoll",
        no_bulk,
    )
    real_session = brain_app.state.db.session
    before_claim = asyncio.Event()
    release_claim = asyncio.Event()
    pause_next_write = True

    @contextlib.asynccontextmanager
    async def pause_before_first_write(*, write: bool = False):
        nonlocal pause_next_write
        if write and pause_next_write:
            pause_next_write = False
            before_claim.set()
            await release_claim.wait()
        async with real_session(write=write) as session:
            yield session

    monkeypatch.setattr(brain_app.state.db, "session", pause_before_first_write)
    request_task = asyncio.create_task(
        admin_client.get(
            "/api/v1/agent/commands",
            params={"wait": 0, "max_frames": 1},
            headers={
                "Authorization": f"Bearer {AGENT_TOKEN}",
                "X-Z4J-Session-Nonce": "revoke-current-claim",
            },
        ),
    )
    await asyncio.wait_for(before_claim.wait(), timeout=2)

    async with real_session(write=True) as session:
        agent = await session.get(Agent, seeded["agent_id"])
        assert agent is not None
        await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
        await session.commit()
    release_claim.set()

    response = await asyncio.wait_for(request_task, timeout=3)
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid agent token"}
    async with real_session() as session:
        command = await session.get(Command, command_id)
        assert command is not None
        assert command.status == CommandStatus.PENDING
        assert command.dispatched_at is None
        assert command.first_delivery_claimed_at is None
        assert command.delivery_transport_kind is None
        assert command.delivery_claim_token is None


@pytest.mark.asyncio
async def test_longpoll_upload_rechecks_revocation_after_authentication(
    brain_app,
    admin_client,
    seeded,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A signed frame cannot mutate state after its bearer is revoked."""
    import z4j_brain.api.agent_longpoll as longpoll

    def signed_heartbeat(*, nonce: str, frame_id: str) -> str:
        signer = FrameSigner(
            secret=derive_project_secret(
                settings.secret.get_secret_value().encode("utf-8"),
                seeded["project_id"],
            ),
            agent_id=seeded["agent_id"],
            project_id=seeded["project_id"],
            session_id=nonce,
        )
        return signer.sign_and_serialize(
            HeartbeatFrame(id=frame_id, payload=HeartbeatPayload()),
        ).decode("utf-8")

    control_nonce = "soft-revoke-control"
    control = await admin_client.post(
        "/api/v1/agent/events",
        json={
            "frames": [
                signed_heartbeat(nonce=control_nonce, frame_id="heartbeat-control"),
            ],
        },
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": control_nonce,
        },
    )
    assert control.status_code == 200
    assert control.json()["accepted"] == 1
    async with brain_app.state.db.session() as session:
        controlled = await session.get(Agent, seeded["agent_id"])
        assert controlled is not None
        baseline_seen = controlled.last_seen_at
        assert controlled.state == AgentState.ONLINE

    authenticated = asyncio.Event()
    release = asyncio.Event()
    real_get_session = longpoll._get_or_create_session

    async def pause_after_authentication(**kwargs):
        result = await real_get_session(**kwargs)
        authenticated.set()
        await release.wait()
        return result

    monkeypatch.setattr(longpoll, "_get_or_create_session", pause_after_authentication)
    race_nonce = "soft-revoke-race"
    request_task = asyncio.create_task(
        admin_client.post(
            "/api/v1/agent/events",
            json={
                "frames": [
                    signed_heartbeat(nonce=race_nonce, frame_id="heartbeat-race"),
                ],
            },
            headers={
                "Authorization": f"Bearer {AGENT_TOKEN}",
                "X-Z4J-Session-Nonce": race_nonce,
            },
        ),
    )
    await asyncio.wait_for(authenticated.wait(), timeout=2)
    async with brain_app.state.db.session(write=True) as session:
        agent = await AgentRepository(session).get(seeded["agent_id"])
        assert agent is not None
        await AgentRepository(session).revoke(agent, at=datetime.now(UTC))
        await session.commit()
    release.set()

    response = await asyncio.wait_for(request_task, timeout=3)
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid agent token"}
    async with brain_app.state.db.session() as session:
        agent = await session.get(Agent, seeded["agent_id"])
        assert agent is not None
        assert agent.state == AgentState.OFFLINE
        assert agent.last_seen_at == baseline_seen


@pytest.mark.asyncio
async def test_prune_stale_revokes_used_and_unused_agents(brain_app) -> None:
    """Hygiene retains history while killing every stale live token."""
    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    cutoff = now - timedelta(days=30)
    project_id = uuid.uuid4()
    used_id = uuid.uuid4()
    revoked_id = uuid.uuid4()
    unused_id = uuid.uuid4()
    fresh_id = uuid.uuid4()

    def agent(
        *,
        agent_id: uuid.UUID,
        name: str,
        last_seen_at: datetime,
        revoked_at: datetime | None = None,
    ) -> Agent:
        return Agent(
            id=agent_id,
            project_id=project_id,
            name=name,
            token_hash=(
                f"revoked:{agent_id}:{revoked_at.isoformat()}"
                if revoked_at is not None
                else f"test-token-hash-{agent_id}"
            ),
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.OFFLINE,
            last_seen_at=last_seen_at,
            revoked_at=revoked_at,
        )

    async with brain_app.state.db.session() as session:
        session.add(Project(id=project_id, slug="prune", name="Prune"))
        await session.flush()
        session.add_all(
            [
                agent(agent_id=used_id, name="used", last_seen_at=old),
                agent(
                    agent_id=revoked_id,
                    name="revoked",
                    last_seen_at=old,
                    revoked_at=old,
                ),
                agent(agent_id=unused_id, name="unused", last_seen_at=old),
                agent(agent_id=fresh_id, name="fresh", last_seen_at=now),
            ],
        )
        await session.flush()
        session.add(
            Event(
                project_id=project_id,
                agent_id=used_id,
                engine="celery",
                task_id="task-prune",
                kind="task.succeeded",
                occurred_at=now,
                payload={},
            ),
        )
        await session.commit()

    async with brain_app.state.db.session() as session:
        await session.execute(
            update(Agent)
            .where(Agent.id.in_([revoked_id, fresh_id]))
            .values(state=AgentState.ONLINE),
        )
        repo = AgentRepository(session)
        offline_ids = {row.id for row in await repo.list_offline_unseen_since(cutoff=cutoff)}
        assert used_id in offline_ids
        assert unused_id in offline_ids
        assert revoked_id not in offline_ids
        online_ids = {row.id for row in await repo.list_online_for_project(project_id)}
        assert fresh_id in online_ids
        assert revoked_id not in online_ids
        pruned = await repo.prune_stale(cutoff=cutoff)
        await session.commit()
    assert pruned == 2

    async with brain_app.state.db.session() as session:
        used = await session.get(Agent, used_id)
        assert used is not None
        assert used.revoked_at is not None
        assert used.state == AgentState.OFFLINE
        assert used.token_hash.startswith(f"revoked:{used_id}:")
        assert (
            await AgentRepository(session).get_by_token_hash(
                f"test-token-hash-{used_id}",
            )
            is None
        )
        assert await session.get(Agent, revoked_id) is not None
        unused = await session.get(Agent, unused_id)
        assert unused is not None
        assert unused.revoked_at is not None
        assert unused.state == AgentState.OFFLINE
        assert unused.token_hash.startswith(f"revoked:{unused_id}:")
        assert (
            await AgentRepository(session).get_by_token_hash(
                f"test-token-hash-{unused_id}",
            )
            is None
        )
        assert await session.get(Agent, fresh_id) is not None
        event_agent_id = await session.scalar(
            select(Event.agent_id).where(Event.agent_id == used_id),
        )
        assert event_agent_id == used_id
        assert (await session.execute(text("PRAGMA foreign_key_check"))).all() == []


@pytest.mark.asyncio
async def test_offline_alert_claim_and_prune_recheck_revocation(brain_app) -> None:
    """Candidate selection cannot page or retain an episode after revoke."""
    now = datetime.now(UTC).replace(microsecond=0)
    old = now - timedelta(days=90)
    project_id = uuid.uuid4()
    candidate_id = uuid.uuid4()
    revoked_claim_id = uuid.uuid4()
    active_claim_id = uuid.uuid4()

    def offline_agent(agent_id: uuid.UUID, name: str) -> Agent:
        return Agent(
            id=agent_id,
            project_id=project_id,
            name=name,
            token_hash=f"offline-alert-{agent_id}",
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.OFFLINE,
            last_seen_at=old,
        )

    async with brain_app.state.db.session() as session:
        session.add(Project(id=project_id, slug="offline-alert", name="Offline Alert"))
        await session.flush()
        session.add_all(
            [
                offline_agent(candidate_id, "candidate"),
                offline_agent(revoked_claim_id, "revoked-claim"),
                offline_agent(active_claim_id, "active-claim"),
            ],
        )
        await session.commit()

    # Prove this was a genuine health-worker candidate before the race.
    async with brain_app.state.db.session() as session:
        candidates = await AgentRepository(session).list_offline_unseen_since(
            cutoff=now,
        )
        assert candidate_id in {candidate.id for candidate in candidates}

    async with brain_app.state.db.session() as session:
        repo = AgentRepository(session)
        candidate = await repo.get(candidate_id)
        assert candidate is not None
        await repo.revoke(candidate, at=now)
        await session.commit()

    async with brain_app.state.db.session() as session:
        claimed = await AgentOfflineAlertRepository(session).claim(
            agent_id=candidate_id,
            anchor_at=old,
        )
        await session.commit()
        assert claimed is False
        assert (
            await session.scalar(
                select(AgentOfflineAlert.id).where(
                    AgentOfflineAlert.agent_id == candidate_id,
                ),
            )
            is None
        )

    # Seed two aged durable claims while both episodes are active, then revoke
    # one. Prune must release only the revoked episode; retaining it would
    # preserve misleading alert state forever because tombstones are durable.
    async with brain_app.state.db.session() as session:
        alerts = AgentOfflineAlertRepository(session)
        assert await alerts.claim(agent_id=revoked_claim_id, anchor_at=old)
        assert await alerts.claim(agent_id=active_claim_id, anchor_at=old)
        await session.commit()
        await session.execute(
            update(AgentOfflineAlert).values(created_at=old),
        )
        revoked_agent = await AgentRepository(session).get(revoked_claim_id)
        assert revoked_agent is not None
        await AgentRepository(session).revoke(revoked_agent, at=now)
        await session.commit()

    async with brain_app.state.db.session() as session:
        pruned = await AgentOfflineAlertRepository(session).prune(
            older_than=now - timedelta(days=30),
        )
        await session.commit()
        assert pruned == 1
        remaining = set(
            (
                await session.execute(
                    select(AgentOfflineAlert.agent_id),
                )
            ).scalars(),
        )
        assert active_claim_id in remaining
        assert revoked_claim_id not in remaining
        assert await session.get(Agent, revoked_claim_id) is not None


def test_event_agent_fk_is_the_postgres_restrict_contract() -> None:
    """Pin the metadata seam that PostgreSQL enforces in production."""
    agent_fk = next(
        foreign_key
        for foreign_key in Event.__table__.foreign_keys
        if foreign_key.parent.name == "agent_id"
    )
    assert agent_fk.ondelete == "RESTRICT"
    assert Event.__table__.c.agent_id.nullable is False


@pytest.mark.asyncio
async def test_hygiene_soft_revoke_preserves_references_after_sqlite_fk_tamper(
    brain_app,
    settings: Settings,
) -> None:
    """A command-only ghost becomes an inert tombstone, never an orphan."""
    from z4j_brain.domain.workers.agent_hygiene import AgentHygieneWorker
    from z4j_brain.persistence.models import AgentStatusHistory, AgentWorker
    from z4j_brain.persistence.repositories import (
        AgentStatusHistoryRepository,
        AgentWorkerRepository,
    )

    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    worker_row_id = uuid.uuid4()
    token_hash = "command-only-ghost-token"

    # Simulate an external connection disabling enforcement.  The runtime
    # checkout guard must restore it before DatabaseManager serves work; the
    # former hard DELETE would otherwise silently leave Command.agent_id
    # dangling.
    async with brain_app.state.db.engine.connect() as connection:
        await connection.execute(text("PRAGMA foreign_keys=OFF"))
        await connection.commit()
        assert (await connection.execute(text("PRAGMA foreign_keys"))).scalar() == 0

    async with brain_app.state.db.session() as session:
        session.add(Project(id=project_id, slug="prune-refs", name="Prune Refs"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="command-only",
                token_hash=token_hash,
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=[],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
                last_seen_at=old,
            ),
        )
        await session.flush()
        session.add_all(
            [
                Command(
                    project_id=project_id,
                    agent_id=agent_id,
                    action="retry_task",
                    target_type="task",
                    target_id="historical-task",
                    payload={},
                    status=CommandStatus.COMPLETED,
                    timeout_at=now + timedelta(minutes=1),
                ),
                AgentWorker(
                    id=worker_row_id,
                    agent_id=agent_id,
                    project_id=project_id,
                    worker_id="worker-1",
                    role="task",
                    framework="bare",
                    state="offline",
                    last_seen_at=old,
                ),
            ],
        )
        await AgentStatusHistoryRepository(session).insert(
            project_id=project_id,
            agent_id=agent_id,
            captured_at=old,
            payload={"state": "offline"},
        )
        await session.commit()

    async with brain_app.state.db.session() as session:
        before = await AgentWorkerRepository(session).list_for_project(project_id)
        assert [row.id for row in before] == [worker_row_id]

    await AgentHygieneWorker(db=brain_app.state.db, settings=settings).tick()

    async with brain_app.state.db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.revoked_at is not None
        assert tombstone.state == AgentState.OFFLINE
        assert tombstone.token_hash.startswith(f"revoked:{agent_id}:")
        assert await AgentRepository(session).get_by_token_hash(token_hash) is None
        assert await AgentRepository(session).list_for_project(project_id) == []

        command_agent_id = await session.scalar(
            select(Command.agent_id).where(Command.agent_id == agent_id),
        )
        assert command_agent_id == agent_id

        # Worker inventory is live state, so the retained historical row is
        # hidden once its parent is revoked. Status snapshots are an explicit
        # history lookup and intentionally remain queryable.
        assert await AgentWorkerRepository(session).list_for_project(project_id) == []
        assert await session.get(AgentWorker, worker_row_id) is not None
        history = await AgentStatusHistoryRepository(session).recent_for_agent(
            agent_id=agent_id,
        )
        assert len(history) == 1
        assert isinstance(history[0], AgentStatusHistory)
        assert (await session.execute(text("PRAGMA foreign_keys"))).scalar() == 1


@pytest.mark.asyncio
async def test_prune_revalidates_candidate_after_reconnect(brain_app) -> None:
    """A reconnect that wins after discovery keeps its row and token live."""
    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    cutoff = now - timedelta(days=30)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    token_hash = "reconnected-agent-token"

    async with brain_app.state.db.session() as session:
        session.add(Project(id=project_id, slug="prune-race", name="Prune Race"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="reconnected",
                token_hash=token_hash,
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=[],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
                last_seen_at=old,
            ),
        )
        await session.commit()

    async with brain_app.state.db.session() as session:
        candidate_ids = await AgentRepository(session).list_stale_ids(cutoff=cutoff)
        assert candidate_ids == [agent_id]

    # Deterministic interleave: reconnect commits after discovery but before
    # the hygiene mutation obtains authority and rechecks the stale predicate.
    async with brain_app.state.db.session(write=True) as session:
        await session.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(state=AgentState.ONLINE, last_seen_at=now),
        )
        await session.commit()

    async with brain_app.state.db.session(write=True) as session:
        pruned = await AgentRepository(session).prune_stale(
            cutoff=cutoff,
            candidate_ids=candidate_ids,
        )
        await session.commit()
    assert pruned == 0

    async with brain_app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.revoked_at is None
        assert agent.token_hash == token_hash
        assert agent.state == AgentState.ONLINE


@pytest.mark.asyncio
async def test_hygiene_drains_multiple_bounded_batches(
    brain_app,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fleet larger than one batch drains without a large mutation unit."""
    import z4j_brain.persistence.agent_authority as authority_module
    import z4j_brain.persistence.repositories.agents as agents_module
    from z4j_brain.domain.workers.agent_hygiene import AgentHygieneWorker

    monkeypatch.setattr(agents_module, "AGENT_STALE_PRUNE_BATCH_SIZE", 2)
    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    project_id = uuid.uuid4()
    agent_ids = [uuid.uuid4() for _ in range(5)]
    async with brain_app.state.db.session(write=True) as session:
        session.add(Project(id=project_id, slug="bounded-prune", name="Bounded prune"))
        await session.flush()
        session.add_all(
            [
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name=f"never-connected-{index}",
                    token_hash=f"bounded-prune-token-{agent_id}",
                    protocol_version="0",
                    framework_adapter="unknown",
                    engine_adapters=[],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.UNKNOWN,
                    created_at=old,
                    updated_at=old,
                )
                for index, agent_id in enumerate(agent_ids)
            ],
        )
        await session.commit()

    mutation_batches: list[tuple[uuid.UUID, ...]] = []
    original_prune = AgentRepository.prune_stale

    async def recording_prune(
        repository: AgentRepository,
        *,
        cutoff: datetime,
        candidate_ids: list[uuid.UUID] | None = None,
    ) -> int:
        assert candidate_ids is not None
        mutation_batches.append(tuple(candidate_ids))
        assert len(candidate_ids) <= agents_module.AGENT_STALE_PRUNE_BATCH_SIZE
        return await original_prune(
            repository,
            cutoff=cutoff,
            candidate_ids=candidate_ids,
        )

    monkeypatch.setattr(AgentRepository, "prune_stale", recording_prune)

    original_authority = authority_module.local_agent_authority
    active_authorities = 0
    max_active_authorities = 0

    @contextlib.asynccontextmanager
    async def recording_authority(agent_id: uuid.UUID):
        nonlocal active_authorities, max_active_authorities
        async with original_authority(agent_id):
            active_authorities += 1
            max_active_authorities = max(max_active_authorities, active_authorities)
            try:
                yield
            finally:
                active_authorities -= 1

    monkeypatch.setattr(authority_module, "local_agent_authority", recording_authority)

    await AgentHygieneWorker(db=brain_app.state.db, settings=settings).tick()

    assert [len(batch) for batch in mutation_batches] == [2, 2, 1]
    assert max_active_authorities == 2
    assert active_authorities == 0
    assert sorted(agent_id for batch in mutation_batches for agent_id in batch) == sorted(agent_ids)
    async with brain_app.state.db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(Agent).where(Agent.project_id == project_id),
                )
            ).scalars(),
        )
        assert len(rows) == len(agent_ids)
        assert all(row.revoked_at is not None for row in rows)
        assert all(row.token_hash.startswith(f"revoked:{row.id}:") for row in rows)
        assert await AgentRepository(session).list_for_project(project_id) == []
