"""End-to-end REST tests for projects/agents/tasks/events/workers/queues/commands.

These exercise the wiring from main.py all the way down: the
PolicyEngine + repositories + serialisation. Auth is handled by
seeding a session row directly into the DB and setting the cookie
on the test client.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import (
    AgentState,
    CommandStatus,
    ProjectRole,
    TaskState,
)
from z4j_brain.persistence.models import (
    Agent,
    Membership,
    Project,
    Session,
    Task,
    User,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import CURRENT_PROTOCOL


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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded(settings: Settings, brain_app):
    """Insert a project + admin user + admin session.

    Returns a dict so the tests can pluck out what they need.
    """
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        project = Project(id=project_id, slug="default", name="Default")
        user = User(
            id=user_id,
            email="admin@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            is_admin=True,
            is_active=True,
        )
        session_row = Session(
            id=session_id,
            user_id=user_id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add_all([project, user, session_row])
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


@pytest.fixture
async def client(brain_app, settings: Settings, seeded):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        # Set the session cookie so /api/v1 routes see an
        # authenticated user.
        codec = SessionCookieCodec(settings)
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            codec.encode(seeded["session_id"]),
        )
        # CSRF echo cookie + header lookup.
        from z4j_brain.auth.csrf import csrf_cookie_name

        ac.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            seeded["csrf"],
        )
        yield ac


@pytest.mark.asyncio
class TestProjects:
    async def test_list_projects(self, client) -> None:
        r = await client.get("/api/v1/projects")
        assert r.status_code == 200
        body = r.json()
        assert any(p["slug"] == "default" for p in body)

    async def test_get_project(self, client) -> None:
        r = await client.get("/api/v1/projects/default")
        assert r.status_code == 200
        assert r.json()["slug"] == "default"

    async def test_get_project_404(self, client) -> None:
        r = await client.get("/api/v1/projects/nope")
        assert r.status_code == 404


@pytest.mark.asyncio
class TestAgentsRouter:
    async def test_list_agents_empty(self, client) -> None:
        r = await client.get("/api/v1/projects/default/agents")
        assert r.status_code == 200
        assert r.json() == []

    async def test_create_agent_returns_token_once(
        self, client, seeded,
    ) -> None:
        r = await client.post(
            "/api/v1/projects/default/agents",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"name": "web-01"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["agent"]["name"] == "web-01"
        assert body["token"]  # plaintext returned once
        assert "agents" in r.url.path

    async def test_create_agent_without_csrf_403(self, client) -> None:
        r = await client.post(
            "/api/v1/projects/default/agents",
            json={"name": "web-01"},
        )
        assert r.status_code == 403

    async def test_list_agents_flags_outdated_protocol(
        self,
        brain_app,
        client,
        settings: Settings,
        seeded,
    ) -> None:
        # Three agents: (a) connected + current protocol,
        # (b) connected + old protocol, (c) never-connected with
        # placeholder "0". Only (b) should be flagged outdated -
        # (c) has not advertised a real version yet.
        now = datetime.now(UTC)
        async with brain_app.state.db.session() as s:
            for name, proto, connected in [
                ("agent-current", CURRENT_PROTOCOL, now),
                ("agent-old", "1", now),
                ("agent-never", "0", None),
            ]:
                s.add(
                    Agent(
                        project_id=seeded["project_id"],
                        name=name,
                        token_hash=hash_agent_token(
                            plaintext=f"dummy-{name}",
                            secret=settings.secret.get_secret_value().encode("utf-8"),
                        ),
                        protocol_version=proto,
                        framework_adapter="bare",
                        engine_adapters=["celery"],
                        scheduler_adapters=[],
                        capabilities={},
                        state=(
                            AgentState.OFFLINE if connected else AgentState.UNKNOWN
                        ),
                        last_connect_at=connected,
                    ),
                )
            await s.commit()

        r = await client.get("/api/v1/projects/default/agents")
        assert r.status_code == 200
        by_name = {a["name"]: a for a in r.json()}
        assert by_name["agent-current"]["is_outdated"] is False
        assert by_name["agent-old"]["is_outdated"] is True
        assert by_name["agent-never"]["is_outdated"] is False


@pytest.mark.asyncio
class TestTasksRouter:
    async def test_list_tasks_empty(self, client) -> None:
        r = await client.get("/api/v1/projects/default/tasks")
        assert r.status_code == 200
        assert r.json()["items"] == []
        assert r.json()["next_cursor"] is None

    async def test_list_tasks_with_state_filter(
        self, brain_app, client, seeded,
    ) -> None:
        # Seed two tasks in different states.
        async with brain_app.state.db.session() as s:
            for i in range(2):
                t = Task(
                    project_id=seeded["project_id"],
                    engine="celery",
                    task_id=f"task-{i}",
                    name="myapp.tasks.x",
                    state=TaskState.SUCCESS if i == 0 else TaskState.FAILURE,
                    started_at=datetime.now(UTC) - timedelta(seconds=i),
                )
                s.add(t)
            await s.commit()

        r = await client.get("/api/v1/projects/default/tasks?state=success")
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["state"] == "success"


@pytest.mark.asyncio
class TestCommandsRouter:
    async def test_list_commands_empty(self, client) -> None:
        r = await client.get("/api/v1/projects/default/commands")
        assert r.status_code == 200
        assert r.json()["items"] == []

    async def test_retry_task_offline_agent_returns_503(
        self,
        brain_app,
        client,
        settings: Settings,
        seeded,
    ) -> None:
        # Seed an agent (offline by default - never connected to
        # the test transport).
        async with brain_app.state.db.session() as s:
            agent = Agent(
                project_id=seeded["project_id"],
                name="w",
                token_hash=hash_agent_token(
                    plaintext="dummy",
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
            )
            s.add(agent)
            await s.commit()
            agent_id = agent.id

        r = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(agent_id),
                "engine": "celery",
                "task_id": "task-001",
            },
        )
        # Local registry returns delivered_locally=False +
        # notified_cluster=False + agent_was_known=False → 503.
        assert r.status_code == 503

    async def test_retry_task_with_online_agent(
        self,
        brain_app,
        client,
        settings: Settings,
        seeded,
    ) -> None:
        # Seed an agent + register it locally so the registry
        # delivers synchronously.
        async with brain_app.state.db.session() as s:
            agent = Agent(
                project_id=seeded["project_id"],
                name="w",
                token_hash=hash_agent_token(
                    plaintext="x",
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            s.add(agent)
            await s.commit()
            agent_id = agent.id

        # Register a fake WS in the local registry so the
        # deliver_local callback returns True. Protocol v2 expects
        # the gateway handshake to have stashed a FrameSigner on
        # the websocket; we attach one directly since this test
        # bypasses the real handshake.
        from z4j_core.transport.framing import FrameSigner

        registry = brain_app.state.brain_registry

        class FakeWS:
            async def send_bytes(self, _data: bytes) -> None:
                pass

            async def close(self, code: int = 1000) -> None:  # noqa: ARG002
                pass

        fake_ws = FakeWS()
        fake_ws._z4j_signer = FrameSigner(
            secret=settings.secret.get_secret_value().encode("utf-8"),
            agent_id=agent_id,
            project_id=seeded["project_id"],
        )

        await registry.register(
            project_id=seeded["project_id"],
            agent_id=agent_id,
            ws=fake_ws,
        )

        r = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(agent_id),
                "engine": "celery",
                "task_id": "task-001",
            },
        )
        assert r.status_code == 202
        body = r.json()
        assert body["action"] == "retry_task"
        assert body["status"] in ("pending", "dispatched")
