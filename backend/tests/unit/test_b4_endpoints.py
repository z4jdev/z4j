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
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import (
    AgentState,
    TaskPriority,
    TaskState,
)
from z4j_brain.persistence.models import (
    Agent,
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
        s.add_all([project, user])
        await s.flush()
        s.add(session_row)
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
        self,
        client,
        seeded,
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
        # Four agents: (a) connected + current protocol,
        # (b) connected + old protocol, (c) connected + newer
        # protocol, and (d) never-connected with placeholder "0".
        # Only (b) should be flagged outdated: newer is an explicit
        # non-outdated state, and (d) has not advertised a real version.
        now = datetime.now(UTC)
        newer_protocol = str(int(CURRENT_PROTOCOL) + 1)
        async with brain_app.state.db.session() as s:
            for name, proto, connected in [
                ("agent-current", CURRENT_PROTOCOL, now),
                ("agent-old", "1", now),
                ("agent-newer", newer_protocol, now),
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
                        state=(AgentState.OFFLINE if connected else AgentState.UNKNOWN),
                        last_connect_at=connected,
                    ),
                )
            await s.commit()

        r = await client.get("/api/v1/projects/default/agents")
        assert r.status_code == 200
        by_name = {a["name"]: a for a in r.json()}
        assert by_name["agent-current"]["is_outdated"] is False
        assert by_name["agent-old"]["is_outdated"] is True
        assert by_name["agent-newer"]["is_outdated"] is False
        assert by_name["agent-never"]["is_outdated"] is False


@pytest.mark.asyncio
class TestTasksRouter:
    @pytest.fixture
    async def counted_history(self, brain_app, seeded):
        now = datetime.now(UTC)
        async with brain_app.state.db.session() as s:
            other = Project(slug="other", name="Other")
            s.add(other)
            await s.flush()
            for project_id in [seeded["project_id"], other.id]:
                for i, (name, state, priority, queue, worker) in enumerate(
                    [
                        ("billing%refund", TaskState.FAILURE, TaskPriority.HIGH, "urgent", "one"),
                        (
                            "billingXrefund",
                            TaskState.SUCCESS,
                            TaskPriority.NORMAL,
                            "default",
                            "two",
                        ),
                        (
                            "billing_refund",
                            TaskState.FAILURE,
                            TaskPriority.CRITICAL,
                            "urgent",
                            "one",
                        ),
                        ("reporting.send", TaskState.FAILURE, TaskPriority.HIGH, "default", "two"),
                    ]
                ):
                    s.add(
                        Task(
                            project_id=project_id,
                            engine="celery",
                            task_id=f"counted-{i}",
                            name=name,
                            state=state,
                            priority=priority,
                            queue=queue,
                            worker_name=worker,
                            received_at=now - timedelta(days=i),
                            started_at=now - timedelta(days=i) if i < 2 else None,
                        )
                    )
            await s.commit()
        return now

    @pytest.mark.parametrize("limit", [1, 2, 4])
    async def test_total_is_project_scoped_and_independent_of_cursor(
        self,
        client,
        counted_history,
        limit,
    ) -> None:
        params = {"include_total": "true", "limit": limit}
        seen = []
        while True:
            r = await client.get("/api/v1/projects/default/tasks", params=params)
            assert r.status_code == 200
            body = r.json()
            assert body["total_count"] == 4
            assert len(body["items"]) == limit
            seen.extend(item["task_id"] for item in body["items"])
            if body["next_cursor"] is None:
                break
            assert len(seen) < 4  # no extra empty page on exact page boundaries
            params["cursor"] = body["next_cursor"]
        assert len(seen) == len(set(seen)) == 4

    @pytest.mark.parametrize(
        ("filters", "total"),
        [
            ({"state": "failure"}, 3),
            ({"priority": "high,critical"}, 3),
            ({"name": "billing"}, 3),
            ({"search": "BILLING"}, 3),
            ({"search": "%"}, 1),
            ({"search": "_"}, 1),
            ({"search": "URGENT"}, 2),
            ({"search": "counted-3"}, 1),
            ({"search": "ONE"}, 2),
            ({"queue": "urgent", "worker": "one", "priority": "high", "state": "failure"}, 1),
            ({"search": "not-present"}, 0),
        ],
    )
    async def test_total_uses_the_list_filters(
        self,
        client,
        counted_history,
        filters,
        total,
    ) -> None:
        r = await client.get(
            "/api/v1/projects/default/tasks",
            params={
                **filters,
                "include_total": "true",
                "limit": 1,
            },
        )
        assert r.status_code == 200
        assert r.json()["total_count"] == total
        assert len(r.json()["items"]) == min(total, 1)

    async def test_total_uses_received_time_bounds(self, client, counted_history) -> None:
        r = await client.get(
            "/api/v1/projects/default/tasks",
            params={
                "include_total": "true",
                "since": (counted_history - timedelta(days=2)).isoformat(),
                "until": (counted_history - timedelta(days=1)).isoformat(),
                "limit": 1,
            },
        )
        assert r.status_code == 200
        assert r.json()["total_count"] == 2

    async def test_count_is_opt_in_and_exports_do_not_count(
        self,
        client,
        counted_history,
        monkeypatch,
    ) -> None:
        from unittest.mock import AsyncMock

        count = AsyncMock(side_effect=AssertionError("unrequested count"))
        monkeypatch.setattr(
            "z4j_brain.persistence.repositories.TaskRepository.count_for_project",
            count,
        )
        r = await client.get("/api/v1/projects/default/tasks")
        assert r.status_code == 200
        assert r.json()["total_count"] is None
        r = await client.get("/api/v1/projects/default/tasks?format=json&include_total=true")
        assert r.status_code == 200
        count.assert_not_awaited()

    async def test_total_requires_project_access(self, client, seeded, brain_app) -> None:
        async with brain_app.state.db.session() as s:
            user = await s.get(User, seeded["user_id"])
            user.is_admin = False
            await s.commit()
        r = await client.get("/api/v1/projects/default/tasks?include_total=true")
        assert r.status_code == 404  # do not reveal another project's existence

    async def test_list_tasks_empty(self, client) -> None:
        r = await client.get("/api/v1/projects/default/tasks")
        assert r.status_code == 200
        assert r.json()["items"] == []
        assert r.json()["next_cursor"] is None

    async def test_list_tasks_with_state_filter(
        self,
        brain_app,
        client,
        seeded,
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

    async def test_list_tasks_preserves_and_filters_non_normal_priority(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        async with brain_app.state.db.session() as s:
            for task_id, priority in [
                ("task-high", TaskPriority.HIGH),
                ("task-normal", TaskPriority.NORMAL),
            ]:
                s.add(
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id=task_id,
                        name="myapp.tasks.x",
                        priority=priority,
                        started_at=datetime.now(UTC),
                    ),
                )
            await s.commit()

        r = await client.get("/api/v1/projects/default/tasks?priority=high")
        assert r.status_code == 200
        items = r.json()["items"]
        assert [item["task_id"] for item in items] == ["task-high"]
        assert items[0]["priority"] == "high"

    @pytest.mark.parametrize(
        "query",
        [
            "state=succes",
            "state=",
            "priority=urgent",
            "priority=high,urgent",
            "priority=high,",
            "priority=",
        ],
    )
    async def test_list_tasks_rejects_unknown_filter_values(
        self,
        client,
        query,
    ) -> None:
        r = await client.get(f"/api/v1/projects/default/tasks?{query}")
        assert r.status_code == 422
        assert "items" not in r.json()

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"task_ids": []},
            {"task_ids": None},
            {
                "task_ids": None,
                "filter_state": None,
                "filter_priority": None,
                "filter_search": None,
                "filter_name": None,
                "filter_queue": None,
                "filter_worker": None,
                "filter_since": None,
                "filter_until": None,
            },
            {"filter_search": "   "},
            {"filter_name": "\t"},
            {"filter_queue": " "},
            {"filter_worker": "\t "},
            {"filter_priority": []},
            {"filter_priority": ["critical", " CRITICAL "]},
            {"filter_state": "succes"},
            {"filter_priority": ["urgent"]},
            {"task_ids": [str(uuid.uuid4())], "filter_state": "failure"},
        ],
    )
    async def test_bulk_delete_rejects_empty_invalid_or_mixed_selection(
        self,
        brain_app,
        client,
        seeded,
        body,
    ) -> None:
        async with brain_app.state.db.session() as session:
            session.add(
                Task(
                    project_id=seeded["project_id"],
                    engine="celery",
                    task_id="must-survive",
                    name="app.survive",
                    state=TaskState.FAILURE,
                ),
            )
            await session.commit()

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json=body,
        )

        assert response.status_code == 422
        async with brain_app.state.db.session() as session:
            assert await session.scalar(select(func.count(Task.id))) == 1

    async def test_bulk_delete_priority_only_is_exact_and_project_scoped(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        other_project_id = uuid.uuid4()
        async with brain_app.state.db.session() as session:
            session.add(Project(id=other_project_id, slug="other", name="Other"))
            session.add_all(
                [
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id="critical-owned",
                        name="app.work",
                        state=TaskState.SUCCESS,
                        priority=TaskPriority.CRITICAL,
                    ),
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id="normal-owned",
                        name="app.work",
                        state=TaskState.SUCCESS,
                        priority=TaskPriority.NORMAL,
                    ),
                    Task(
                        project_id=other_project_id,
                        engine="celery",
                        task_id="critical-other",
                        name="app.work",
                        state=TaskState.SUCCESS,
                        priority=TaskPriority.CRITICAL,
                    ),
                ],
            )
            await session.commit()

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"filter_priority": ["critical"]},
        )

        assert response.status_code == 200
        assert response.json() == {"deleted_count": 1}
        async with brain_app.state.db.session() as session:
            remaining = set((await session.scalars(select(Task.task_id))).all())
        assert remaining == {"normal-owned", "critical-other"}

    async def test_bulk_delete_intersects_state_priority_and_literal_search(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        cases = [
            (
                "exact-percent",
                "Name%Literal",
                "queue",
                "worker",
                TaskState.FAILURE,
                TaskPriority.CRITICAL,
            ),
            (
                "percent-decoy",
                "NameXLiteral",
                "queue",
                "worker",
                TaskState.FAILURE,
                TaskPriority.CRITICAL,
            ),
            (
                "wrong-state",
                "Name%Literal",
                "queue",
                "worker",
                TaskState.SUCCESS,
                TaskPriority.CRITICAL,
            ),
            (
                "wrong-priority",
                "Name%Literal",
                "queue",
                "worker",
                TaskState.FAILURE,
                TaskPriority.NORMAL,
            ),
        ]
        async with brain_app.state.db.session() as session:
            for task_id, name, queue, worker, state, priority in cases:
                session.add(
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id=task_id,
                        name=name,
                        queue=queue,
                        worker_name=worker,
                        state=state,
                        priority=priority,
                    ),
                )
            await session.commit()

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "filter_state": "failure",
                "filter_priority": [" CRITICAL "],
                "filter_search": "%",
            },
        )

        assert response.status_code == 200
        assert response.json() == {"deleted_count": 1}
        async with brain_app.state.db.session() as session:
            remaining = set((await session.scalars(select(Task.task_id))).all())
        assert remaining == {"percent-decoy", "wrong-state", "wrong-priority"}

    @pytest.mark.parametrize(
        ("needle", "matching_field", "matching_value", "decoy_value"),
        [
            ("_", "queue", "queue_literal", "queueXliteral"),
            ("\\", "worker_name", r"worker\literal", "workerXliteral"),
            ("/", "task_id", "task/literal", "taskXliteral"),
        ],
    )
    async def test_bulk_delete_search_is_literal_across_every_list_field(
        self,
        brain_app,
        client,
        seeded,
        needle,
        matching_field,
        matching_value,
        decoy_value,
    ) -> None:
        async with brain_app.state.db.session() as session:
            for suffix, value in [("match", matching_value), ("decoy", decoy_value)]:
                values = {
                    "task_id": f"task-{suffix}",
                    "name": f"name-{suffix}",
                    "queue": f"queue-{suffix}",
                    "worker_name": f"worker-{suffix}",
                }
                values[matching_field] = value
                session.add(
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        state=TaskState.FAILURE,
                        priority=TaskPriority.CRITICAL,
                        **values,
                    ),
                )
            await session.commit()

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"filter_search": needle},
        )

        assert response.status_code == 200
        assert response.json() == {"deleted_count": 1}
        async with brain_app.state.db.session() as session:
            remaining = (await session.scalars(select(Task))).one()
        assert getattr(remaining, matching_field) == decoy_value

    async def test_bulk_delete_explicit_ids_stays_safe(self, brain_app, client, seeded) -> None:
        other_project_id = uuid.uuid4()
        async with brain_app.state.db.session() as session:
            session.add(Project(id=other_project_id, slug="foreign", name="Foreign"))
            selected = Task(
                project_id=seeded["project_id"],
                engine="celery",
                task_id="selected",
                name="app.selected",
            )
            survivor = Task(
                project_id=seeded["project_id"],
                engine="celery",
                task_id="survivor",
                name="app.survivor",
            )
            foreign = Task(
                project_id=other_project_id,
                engine="celery",
                task_id="foreign",
                name="app.foreign",
            )
            session.add_all([selected, survivor, foreign])
            await session.commit()
            selected_id = selected.id
            foreign_id = foreign.id

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"task_ids": [str(selected_id), str(foreign_id)]},
        )

        assert response.status_code == 200
        assert response.json() == {"deleted_count": 1}
        async with brain_app.state.db.session() as session:
            assert set((await session.scalars(select(Task.task_id))).all()) == {
                "survivor",
                "foreign",
            }

    async def test_bulk_delete_filtered_mode_keeps_deterministic_ten_thousand_cap(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        async with brain_app.state.db.session() as session:
            session.add_all(
                [
                    Task(
                        id=uuid.UUID(int=index + 1),
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id=f"capped-{index:05d}",
                        name="app.capped",
                        state=TaskState.FAILURE,
                    )
                    for index in range(10_001)
                ],
            )
            await session.commit()

        response = await client.post(
            "/api/v1/projects/default/tasks/bulk-delete",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"filter_state": "failure"},
        )

        assert response.status_code == 200
        assert response.json() == {"deleted_count": 10_000}
        async with brain_app.state.db.session() as session:
            remaining = (await session.scalars(select(Task))).one()
        assert remaining.id == uuid.UUID(int=10_001)
        assert remaining.task_id == "capped-10000"


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
                # Attest, so this test still exercises the OFFLINE path
                # (503) rather than being short-circuited by the retry gate.
                agent_metadata={"runtime_features": ["retry_by_reference"]},
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
        # notified_cluster=False + agent_was_known=False, and the agent is
        # offline → 503.
        assert r.status_code == 503

    async def test_retry_task_live_long_poll_agent_is_accepted_pending(
        self,
        brain_app,
        client,
        settings: Settings,
        seeded,
    ) -> None:
        # A long-poll agent stays online through its uploads but never
        # registers a WebSocket session. The local registry cannot push to it,
        # yet its next poll claims the committed command, so the request is
        # accepted as pending instead of refused as offline.
        async with brain_app.state.db.session() as s:
            agent = Agent(
                project_id=seeded["project_id"],
                name="long-poll",
                token_hash=hash_agent_token(
                    plaintext="long-poll",
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version="0",
                framework_adapter="unknown",
                engine_adapters=[],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
                agent_metadata={"runtime_features": ["retry_by_reference"]},
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
        assert r.status_code == 202
        assert r.json()["status"] == "pending"

    async def test_retry_task_refused_when_only_session_is_unattested(
        self,
        brain_app,
        client,
        settings: Settings,
        seeded,
    ) -> None:
        # Boundary A: a sticky Agent-row value is not authority. Register an
        # old session without an adapter contract; it must not receive a retry.
        async with brain_app.state.db.session() as s:
            agent = Agent(
                project_id=seeded["project_id"],
                name="old-runtime",
                token_hash=hash_agent_token(
                    plaintext="x2",
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version="1",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
                # A stale positive is deliberate: session proof must win.
                agent_metadata={"runtime_features": ["retry_by_reference"]},
            )
            s.add(agent)
            await s.commit()
            agent_id = agent.id

        class OldWS:
            async def close(self, code: int = 1000) -> None:
                pass

        await brain_app.state.brain_registry.register(
            project_id=seeded["project_id"],
            agent_id=agent_id,
            ws=OldWS(),
            worker_id="old",
            retry_contracts={},
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
                # The retry gate refuses an agent that has not attested the
                # safe retry contract, so a retry fixture must attest.
                agent_metadata={"runtime_features": ["retry_by_reference"]},
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

            async def close(self, code: int = 1000) -> None:
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
            retry_contracts={"celery": 1},
        )

        eta_before = datetime.now(UTC).timestamp() + 60
        r = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(agent_id),
                "engine": "celery",
                "task_id": "task-001",
                "eta_seconds": 60,
            },
        )
        eta_after = datetime.now(UTC).timestamp() + 60
        assert r.status_code == 202
        body = r.json()
        assert body["action"] == "retry_task"
        assert body["status"] in ("pending", "dispatched")
        assert body["payload"]["eta_seconds"] == 60
        assert eta_before <= body["payload"]["eta"] <= eta_after


class TestRequeueDeadLetter:
    """The dead-letter requeue must be reachable, and only by an operator.

    Every layer below this endpoint already existed: z4j-rq implements
    ``requeue_dead_letter``, z4j-core puts the policy Action in the operator
    tier, the agent dispatcher handles it, and the wire helper anticipates it.
    What was missing was a route that mints the command, so none of it could be
    triggered by a user.
    """

    async def test_cross_project_agent_is_refused(self, client, seeded):
        """The cross-project agent guard applies here as to its siblings."""
        r = await client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(uuid.uuid4()),
                "engine": "rq",
                "task_id": "dead-letter-1",
            },
        )
        assert r.status_code == 404

    async def test_csrf_is_required(self, client, seeded):
        """A state-changing command endpoint is not exempt from CSRF."""
        r = await client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            json={
                "agent_id": str(uuid.uuid4()),
                "engine": "rq",
                "task_id": "dead-letter-2",
            },
        )
        assert r.status_code == 403

    async def test_engine_is_validated(self, client, seeded):
        """The engine is dispatched on, so an unroutable value is refused."""
        r = await client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(uuid.uuid4()),
                "engine": "not a real engine",
                "task_id": "dead-letter-3",
            },
        )
        assert r.status_code == 422
