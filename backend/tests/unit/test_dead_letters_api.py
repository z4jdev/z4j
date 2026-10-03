"""Dead letters are listed through the agent that advertises the read side.

``GET /projects/{slug}/dead-letters`` issues one ``dlq.list`` command to an
online agent whose session advertises the engine with ``list_dead_letters``,
waits for the agent's result and returns the re-validated page. The
``requeue-dead-letter`` command follows the same rule for
``requeue_dead_letter``: any engine an agent advertises it for is accepted,
RQ is not special.

The agent here is a fake WebSocket session on the real registry. When the
brain pushes the command frame, the fake finds the dispatched ``dlq.list``
row and answers it through the dispatcher's result path, which is what the
gateway does for a real ``command_result`` frame.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api import dead_letters as dead_letters_api
from z4j_brain.api.dead_letters import cursor_error
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    ApiKey,
    AuditLog,
    Command,
    Project,
    Session,
    User,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.models.dead_letter import DLQ_LIST_ACTION
from z4j_core.transport import RETRY_BY_REFERENCE_CAPABILITY
from z4j_core.transport.framing import FrameSigner

_NOW = datetime.now(UTC)

RQ = [
    "submit_task",
    "retry_task",
    "cancel_task",
    "purge_queue",
    "bulk_retry",
    "requeue_dead_letter",
    "list_dead_letters",
    RETRY_BY_REFERENCE_CAPABILITY,
]
CELERY = ["submit_task", "retry_task", "cancel_task", "bulk_retry", "purge_queue"]
DRAMATIQ_WITH_REQUEUE = ["submit_task", "retry_task", "purge_queue", "requeue_dead_letter"]

PAGE: dict[str, Any] = {
    "entries": [
        {
            "task_id": "job-1",
            "task_name": "app.send_mail",
            "queue": "default",
            "failed_at": "2026-10-02T12:00:00Z",
            "error_excerpt": "ValueError: boom",
            "attempts": 3,
        },
        {
            "task_id": "job-2",
            "task_name": "",
            "queue": "default",
            "failed_at": None,
            "error_excerpt": "",
            "attempts": None,
        },
    ],
    "next_cursor": "2",
    "total": 7,
    "engine": "rq",
}


@pytest.fixture
def settings(tmp_path) -> Settings:
    # File-backed SQLite: the fake agent answers from a task of its own, and
    # an in-memory database's single shared connection would let the
    # handler's session teardown roll that answer back mid-flight. A file
    # gives every session its own connection, which is what production has.
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'dead-letters.sqlite3'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
    )


@pytest.fixture(autouse=True)
async def _drain_bulk_action_bucket():
    """The listing draws on the process-wide bulk-action bucket; every test
    client here shares the loopback address, so the bucket is emptied around
    each test rather than letting one test's listings throttle the next."""
    from z4j_brain.domain import ip_rate_limit as ipl

    await ipl._bulk_action_bucket.prune_idle(idle_seconds=0)
    yield
    await ipl._bulk_action_bucket.prune_idle(idle_seconds=0)


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded(settings: Settings, brain_app):
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="default", name="Default"),
                User(
                    id=user_id,
                    email="admin@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=True,
                    is_active=True,
                ),
            ]
        )
        await s.flush()
        s.add(
            Session(
                id=session_id,
                user_id=user_id,
                csrf_token=csrf,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            )
        )
        await s.commit()
    return {"project_id": project_id, "user_id": user_id, "session_id": session_id, "csrf": csrf}


@pytest.fixture
async def client(brain_app, settings: Settings, seeded):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
        headers={"X-CSRF-Token": seeded["csrf"]},
    ) as ac:
        codec = SessionCookieCodec(settings)
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            codec.encode(seeded["session_id"]),
        )
        ac.cookies.set(csrf_cookie_name(environment=settings.environment), seeded["csrf"])
        yield ac


@pytest.fixture
async def bare_client(brain_app):
    """A client with no session cookie, for Bearer calls."""
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as ac:
        yield ac


async def _seed_agent(
    brain_app,
    settings: Settings,
    seeded,
    *,
    name: str,
    engines: list[str],
    capabilities: dict[str, list[str]],
) -> uuid.UUID:
    async with brain_app.state.db.session() as s:
        agent = Agent(
            project_id=seeded["project_id"],
            name=name,
            token_hash=hash_agent_token(
                plaintext=name,
                secret=settings.secret.get_secret_value().encode("utf-8"),
            ),
            protocol_version="1",
            framework_adapter="bare",
            engine_adapters=list(engines),
            scheduler_adapters=[],
            capabilities=capabilities,
            state=AgentState.ONLINE,
            last_connect_at=_NOW,
            last_seen_at=_NOW,
        )
        s.add(agent)
        await s.commit()
        return agent.id


class _FakeAgentSession:
    """A registered WebSocket that answers ``dlq.list`` the way an agent would.

    ``answer`` is ``("success", page)`` or ``("failed", error)``; ``None``
    never answers, which is a silent agent.
    """

    def __init__(self, brain_app, seeded, agent_id: uuid.UUID, answer: tuple[str, Any] | None):
        self._app = brain_app
        self._project_id = seeded["project_id"]
        self._agent_id = agent_id
        self._answer = answer
        self.frames: list[bytes] = []
        self.tasks: list[asyncio.Task[None]] = []

    async def send_bytes(self, data: bytes) -> None:
        self.frames.append(data)
        if self._answer is not None:
            self.tasks.append(asyncio.get_running_loop().create_task(self._respond()))

    async def close(self, code: int = 1000) -> None:
        pass

    async def _respond(self) -> None:
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
        )

        assert self._answer is not None
        status, payload = self._answer
        async with self._app.state.db.session(write=True) as s:
            command = (
                (
                    await s.execute(
                        select(Command)
                        .where(
                            Command.project_id == self._project_id,
                            Command.agent_id == self._agent_id,
                            Command.action == DLQ_LIST_ACTION,
                            Command.status.in_([CommandStatus.PENDING, CommandStatus.DISPATCHED]),
                        )
                        .order_by(Command.issued_at.desc())
                    )
                )
                .scalars()
                .first()
            )
            assert command is not None
            await self._app.state.command_dispatcher.handle_result(
                commands=CommandRepository(s),
                audit_log=AuditLogRepository(s),
                command_id=command.id,
                status=status,
                result_payload=payload if status == "success" else None,
                error=payload if status == "failed" else None,
                project_id=self._project_id,
                agent_id=self._agent_id,
            )
            await s.commit()


async def _connect(
    brain_app,
    settings: Settings,
    seeded,
    agent_id: uuid.UUID,
    *,
    answer: tuple[str, Any] | None,
    retry_contracts: dict[str, int] | None = None,
) -> _FakeAgentSession:
    ws = _FakeAgentSession(brain_app, seeded, agent_id, answer)
    ws._z4j_signer = FrameSigner(  # type: ignore[attr-defined]
        secret=settings.secret.get_secret_value().encode("utf-8"),
        agent_id=agent_id,
        project_id=seeded["project_id"],
    )
    await brain_app.state.brain_registry.register(
        project_id=seeded["project_id"],
        agent_id=agent_id,
        ws=ws,
        retry_contracts=retry_contracts or {},
    )
    return ws


async def _rq_agent(brain_app, settings, seeded, *, answer: tuple[str, Any] | None):
    agent_id = await _seed_agent(
        brain_app, settings, seeded, name="rq-agent", engines=["rq"], capabilities={"rq": RQ}
    )
    ws = await _connect(brain_app, settings, seeded, agent_id, answer=answer)
    return agent_id, ws


async def _commands(brain_app, *, action: str | None = None) -> list[Command]:
    async with brain_app.state.db.session() as s:
        stmt = select(Command).order_by(Command.issued_at)
        if action is not None:
            stmt = stmt.where(Command.action == action)
        return list((await s.execute(stmt)).scalars().all())


async def _command_count(brain_app) -> int:
    async with brain_app.state.db.session() as s:
        return int(await s.scalar(select(func.count(Command.id))) or 0)


async def _audit_rows(brain_app, action: str) -> list[AuditLog]:
    async with brain_app.state.db.session() as s:
        return list(
            (await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
        )


async def _seed_api_key(brain_app, settings: Settings, seeded, *, scopes: list[str]) -> str:
    from z4j_brain.api.api_keys import _hash_api_key

    plaintext = f"z4k_{secrets.token_urlsafe(32)}"
    async with brain_app.state.db.session() as s:
        s.add(
            ApiKey(
                id=uuid.uuid4(),
                user_id=seeded["user_id"],
                name=f"key-{'-'.join(scopes)}",
                token_hash=_hash_api_key(
                    plaintext=plaintext,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                prefix=plaintext[:8],
                scopes=list(scopes),
            )
        )
        await s.commit()
    return plaintext


class TestCursorShape:
    def test_absent_and_opaque_tokens_pass(self) -> None:
        assert cursor_error(None) is None
        assert cursor_error("") is None
        assert cursor_error("2") is None
        assert cursor_error("eyJvZmZzZXQiOjIwMH0=") is None

    @pytest.mark.parametrize("cursor", ["page one", "tab\there", "x" * 201, "é", "\n"])
    def test_whitespace_control_and_overlong_tokens_are_named(self, cursor: str) -> None:
        assert cursor_error(cursor) is not None


@pytest.mark.asyncio
class TestListDeadLetters:
    async def test_the_page_the_rq_agent_returns_is_served_and_audited(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id, ws = await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))

        r = await client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq", "queue": "default", "limit": 50},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["engine"] == "rq"
        assert body["total"] == 7
        assert body["next_cursor"] == "2"
        assert [entry["task_id"] for entry in body["entries"]] == ["job-1", "job-2"]
        assert body["entries"][0]["failed_at"].startswith("2026-10-02T12:00:00")
        assert body["entries"][1]["attempts"] is None

        # One ``dlq.list`` command carried the engine, queue, limit and cursor.
        (command,) = await _commands(brain_app, action=DLQ_LIST_ACTION)
        assert command.agent_id == agent_id
        assert command.target_type == "queue" and command.target_id == "default"
        assert command.payload == {"engine": "rq", "queue": "default", "limit": 50, "cursor": None}
        assert command.status is CommandStatus.COMPLETED
        assert command.result == PAGE
        assert len(ws.frames) == 1

        # One listing audit row names the request; the issuance row is the
        # dispatcher's own.
        (row,) = await _audit_rows(brain_app, "dead_letters.list")
        assert row.user_id == seeded["user_id"]
        assert row.project_id == seeded["project_id"]
        assert row.target_type == "queue" and row.target_id == "rq:default"
        assert row.audit_metadata["engine"] == "rq"
        assert row.audit_metadata["queue"] == "default"
        assert row.audit_metadata["limit"] == 50
        assert row.audit_metadata["agent_id"] == str(agent_id)
        assert len(await _audit_rows(brain_app, f"command.issue.{DLQ_LIST_ACTION}")) == 1

    async def test_the_cursor_is_forwarded_verbatim_and_a_queue_is_optional(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        r = await client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq", "cursor": "2"},
        )
        assert r.status_code == 200, r.text
        (command,) = await _commands(brain_app, action=DLQ_LIST_ACTION)
        assert command.target_id is None
        assert command.payload == {"engine": "rq", "queue": None, "limit": 100, "cursor": "2"}
        (row,) = await _audit_rows(brain_app, "dead_letters.list")
        assert row.target_id == "rq:*"
        assert row.audit_metadata["cursor_supplied"] is True

    async def test_no_capable_agent_is_a_409_listing_who_advertises_what(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        celery_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="celery-agent",
            engines=["celery"],
            capabilities={"celery": CELERY},
        )
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": "rq"})
        assert r.status_code == 409, r.text
        detail = r.json()
        text = r.text
        assert "'rq'" in text and "list_dead_letters" in text
        detail = detail.get("detail", detail)
        agents = detail["agents"] if "agents" in detail else detail["details"]["agents"]
        assert [a["id"] for a in agents] == [str(celery_id)]
        assert agents[0]["engines"] == ["celery"]
        assert "list_dead_letters" not in agents[0]["advertises"]
        assert await _command_count(brain_app) == 0
        assert await _audit_rows(brain_app, "dead_letters.list") == []

    async def test_an_rq_agent_without_the_read_capability_is_not_chosen(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        old = [token for token in RQ if token != "list_dead_letters"]
        await _seed_agent(
            brain_app, settings, seeded, name="old-rq", engines=["rq"], capabilities={"rq": old}
        )
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": "rq"})
        assert r.status_code == 409, r.text
        assert "old-rq" in r.text
        assert await _command_count(brain_app) == 0

    async def test_the_listing_draws_on_the_bulk_action_bucket(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        """Each listing fans a command out to an agent and holds the request
        for up to the wait bound, so it is throttled like the other fan-outs:
        the per-IP bulk-action bucket admits its budget and then answers 429
        before the handler runs (no command issued, nothing audited)."""
        from z4j_brain.domain import ip_rate_limit as ipl

        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        budget = ipl._bulk_action_bucket._max_hits
        for _ in range(budget):
            served = await client.get(
                "/api/v1/projects/default/dead-letters", params={"engine": "rq"}
            )
            assert served.status_code == 200, served.text

        throttled = await client.get(
            "/api/v1/projects/default/dead-letters", params={"engine": "rq"}
        )
        assert throttled.status_code == 429, throttled.text
        assert "bulk-action" in throttled.text
        # The header names the same bounded wait the body does, in whole
        # seconds, never past the bucket's window.
        retry_after = throttled.headers["retry-after"]
        assert retry_after.isdigit()
        assert 1 <= int(retry_after) <= ipl._bulk_action_bucket._window_seconds
        assert f"retry in {retry_after} seconds" in throttled.text
        assert await _command_count(brain_app) == budget
        assert len(await _audit_rows(brain_app, "dead_letters.list")) == budget

        # The bucket is per address: another address still has its budget.
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=brain_app, client=("203.0.113.9", 4321)),
            base_url="http://testserver",
            headers={"X-CSRF-Token": seeded["csrf"]},
            cookies=client.cookies,
        ) as other:
            fresh = await other.get(
                "/api/v1/projects/default/dead-letters", params={"engine": "rq"}
            )
            assert fresh.status_code == 200, fresh.text

    async def test_a_silent_agent_is_a_504_naming_the_command(
        self, brain_app, client, settings: Settings, seeded, monkeypatch
    ) -> None:
        monkeypatch.setattr(dead_letters_api, "DEAD_LETTER_WAIT_SECONDS", 0.3)
        agent_id, _ws = await _rq_agent(brain_app, settings, seeded, answer=None)
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": "rq"})
        assert r.status_code == 504, r.text
        (command,) = await _commands(brain_app, action=DLQ_LIST_ACTION)
        assert str(command.id) in r.text and str(agent_id) in r.text
        assert command.status in {CommandStatus.PENDING, CommandStatus.DISPATCHED}

    @pytest.mark.parametrize("cursor", ["page one", "x" * 201])
    async def test_a_malformed_cursor_is_a_422_before_any_command(
        self, brain_app, client, settings: Settings, seeded, cursor: str
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        r = await client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq", "cursor": cursor},
        )
        assert r.status_code == 422, r.text
        assert await _command_count(brain_app) == 0

    @pytest.mark.parametrize("cursor", ["page one", "café"])
    async def test_a_malformed_cursor_names_a_stable_code(
        self, brain_app, client, settings: Settings, seeded, cursor: str
    ) -> None:
        """The code is what a client keys on; the sentence is the message,
        not the code itself."""
        r = await client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq", "cursor": cursor},
        )
        assert r.status_code == 422, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_cursor"
        assert detail["message"] == cursor_error(cursor)
        assert "cursor" in detail["message"]

    async def test_the_adapter_refusing_the_cursor_is_a_422(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(
            brain_app,
            settings,
            seeded,
            answer=("failed", "dlq.list: validation_error: invalid dead-letter cursor 'zz'"),
        )
        r = await client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq", "cursor": "zz"},
        )
        assert r.status_code == 422, r.text
        assert "invalid dead-letter cursor" in r.text

    async def test_any_other_adapter_failure_is_a_502(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(
            brain_app, settings, seeded, answer=("failed", "dlq.list: adapter_error: redis down")
        )
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": "rq"})
        assert r.status_code == 502, r.text
        assert "redis down" in r.text

    async def test_an_adapter_failure_that_merely_mentions_a_cursor_is_a_502(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        """Only the core's exact cursor refusal is the client's error; a
        broker failure that happens to say "cursor" is still the upstream's."""
        from z4j_core.models.dead_letter import decode_offset_cursor

        with pytest.raises(ValueError, match=dead_letters_api.CURSOR_REFUSAL_TEXT):
            decode_offset_cursor("zz")
        await _rq_agent(
            brain_app,
            settings,
            seeded,
            answer=("failed", "dlq.list: adapter_error: redis SCAN cursor timed out"),
        )
        r = await client.get(
            "/api/v1/projects/default/dead-letters", params={"engine": "rq", "cursor": "2"}
        )
        assert r.status_code == 502, r.text
        assert "SCAN cursor timed out" in r.text

    async def test_a_result_that_is_not_a_page_is_a_502(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", {"entries": "nope"}))
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": "rq"})
        assert r.status_code == 502, r.text

    @pytest.mark.parametrize("limit", [0, 201, "ten"])
    async def test_limit_bounds_are_422(
        self, brain_app, client, settings: Settings, seeded, limit: Any
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        r = await client.get(
            "/api/v1/projects/default/dead-letters", params={"engine": "rq", "limit": limit}
        )
        assert r.status_code == 422, r.text
        assert await _command_count(brain_app) == 0

    @pytest.mark.parametrize("engine", ["", "not an engine", "x" * 41])
    async def test_a_malformed_engine_is_422(
        self, brain_app, client, settings: Settings, seeded, engine: str
    ) -> None:
        r = await client.get("/api/v1/projects/default/dead-letters", params={"engine": engine})
        assert r.status_code == 422, r.text

    async def test_the_engine_is_required(self, brain_app, client, seeded) -> None:
        r = await client.get("/api/v1/projects/default/dead-letters")
        assert r.status_code == 422, r.text


@pytest.mark.asyncio
class TestApiKeyReach:
    async def test_tasks_read_reaches_the_listing(
        self, brain_app, bare_client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        key = await _seed_api_key(brain_app, settings, seeded, scopes=["tasks:read"])
        r = await bare_client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq"},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["engine"] == "rq"

    async def test_an_unrelated_scope_cannot_list(
        self, brain_app, bare_client, settings: Settings, seeded
    ) -> None:
        await _rq_agent(brain_app, settings, seeded, answer=("success", PAGE))
        key = await _seed_api_key(brain_app, settings, seeded, scopes=["workers:read"])
        r = await bare_client.get(
            "/api/v1/projects/default/dead-letters",
            params={"engine": "rq"},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r.status_code == 403, r.text
        assert await _command_count(brain_app) == 0

    async def test_tasks_write_cannot_requeue_but_commands_write_can(
        self, brain_app, bare_client, settings: Settings, seeded
    ) -> None:
        agent_id, _ws = await _rq_agent(brain_app, settings, seeded, answer=None)
        body = {"agent_id": str(agent_id), "engine": "rq", "task_id": "job-1"}

        tasks_write = await _seed_api_key(brain_app, settings, seeded, scopes=["tasks:write"])
        refused = await bare_client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            json=body,
            headers={"Authorization": f"Bearer {tasks_write}"},
        )
        assert refused.status_code == 403, refused.text
        assert await _command_count(brain_app) == 0

        commands_write = await _seed_api_key(brain_app, settings, seeded, scopes=["commands:write"])
        accepted = await bare_client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            json=body,
            headers={"Authorization": f"Bearer {commands_write}"},
        )
        assert accepted.status_code == 202, accepted.text
        assert accepted.json()["action"] == "requeue_dead_letter"


@pytest.mark.asyncio
class TestRequeueFollowsTheCapability:
    async def test_dramatiq_is_accepted_when_its_agent_advertises_requeue(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="dramatiq-agent",
            engines=["dramatiq"],
            capabilities={"dramatiq": DRAMATIQ_WITH_REQUEUE},
        )
        r = await client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            json={"agent_id": str(agent_id), "engine": "dramatiq", "task_id": "msg-1"},
        )
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["action"] == "requeue_dead_letter"
        assert body["payload"] == {"engine": "dramatiq", "task_id": "msg-1"}
        assert body["target_id"] == "dramatiq:msg-1"
        # The requeue is audited by the dispatcher's issuance row.
        (row,) = await _audit_rows(brain_app, "command.issue.requeue_dead_letter")
        assert row.user_id == seeded["user_id"]
        assert row.audit_metadata["agent_id"] == str(agent_id)

    async def test_dramatiq_is_refused_when_its_agent_does_not_advertise_requeue(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="dramatiq-agent",
            engines=["dramatiq"],
            capabilities={"dramatiq": ["submit_task", "retry_task", "purge_queue"]},
        )
        r = await client.post(
            "/api/v1/projects/default/commands/requeue-dead-letter",
            json={"agent_id": str(agent_id), "engine": "dramatiq", "task_id": "msg-1"},
        )
        assert r.status_code == 422, r.text
        assert "requeue_dead_letter" in r.text and "'dramatiq'" in r.text
        assert await _command_count(brain_app) == 0
