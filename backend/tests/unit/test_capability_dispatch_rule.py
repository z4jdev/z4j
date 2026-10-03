"""Engine commands are dispatchable by advertised capability, not by a list.

A command for engine E with action A goes to an agent whose current session
advertises E in its engine list together with A's capability token; a
retry-family action also needs the adapter's attested safe retry contract. The
engine string is validated for shape only and is never rewritten: LATENT-1 was
an unknown engine such as ``laravel`` falling back silently to ``celery`` in
two repository helpers, and the property that replaced it is that such an
engine is refused with a message naming it.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.retry_contract import (
    dispatch_refusal,
    engine_name_error,
    project_engine_authority,
    required_retry_engine,
)
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Command, Project, Session, Task, User
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import RETRY_BY_REFERENCE_CAPABILITY
from z4j_core.transport.framing import FrameSigner

_NOW = datetime.now(UTC)

#: What each shipped adapter advertises (its ``DEFAULT_CAPABILITIES`` plus the
#: marker z4j-bare adds for an adapter attesting ``safe_retry_by_reference``).
HUEY = ["submit_task", "retry_task", "cancel_task", RETRY_BY_REFERENCE_CAPABILITY]
ARQ = ["submit_task", "cancel_task"]
TASKIQ = ["submit_task"]
CELERY = [
    "submit_task",
    "retry_task",
    "cancel_task",
    "bulk_retry",
    "purge_queue",
    RETRY_BY_REFERENCE_CAPABILITY,
]


@dataclass
class _Inventory:
    """The handshake fields of an Agent row, without a database."""

    name: str = "agent"
    engine_adapters: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    last_connect_at: datetime | None = None


def _connected(name: str, engine: str, tokens: list[str]) -> _Inventory:
    return _Inventory(
        name=name,
        engine_adapters=[engine],
        capabilities={engine: list(tokens)},
        last_connect_at=_NOW,
    )


class TestDispatchRule:
    @pytest.mark.parametrize("engine", ["huey", "arq", "taskiq"])
    def test_retry_and_cancel_admitted_when_the_session_advertises_them(self, engine: str) -> None:
        agent = _connected(
            "w", engine, ["retry_task", "cancel_task", RETRY_BY_REFERENCE_CAPABILITY]
        )
        assert dispatch_refusal(agent, engine=engine, action="retry_task") is None
        assert dispatch_refusal(agent, engine=engine, action="cancel_task") is None

    def test_shipped_adapter_inventories(self) -> None:
        huey = _connected("huey-agent", "huey", HUEY)
        arq = _connected("arq-agent", "arq", ARQ)
        taskiq = _connected("taskiq-agent", "taskiq", TASKIQ)

        assert dispatch_refusal(huey, engine="huey", action="retry_task") is None
        assert dispatch_refusal(huey, engine="huey", action="cancel_task") is None
        assert dispatch_refusal(arq, engine="arq", action="cancel_task") is None
        refusal = dispatch_refusal(arq, engine="arq", action="retry_task")
        assert refusal is not None and "retry_task" in refusal and "arq" in refusal
        for action in ("retry_task", "cancel_task"):
            refusal = dispatch_refusal(taskiq, engine="taskiq", action=action)
            assert refusal is not None and action in refusal and "taskiq" in refusal

    def test_engine_the_agent_does_not_list_is_refused_naming_both(self) -> None:
        celery = _connected("celery-agent", "celery", CELERY)
        refusal = dispatch_refusal(celery, engine="huey", action="cancel_task")
        assert refusal is not None
        assert "huey" in refusal and "celery-agent" in refusal and "celery" in refusal

    def test_retry_family_needs_the_attested_safe_retry_marker(self) -> None:
        unattested = _connected("old", "huey", ["retry_task", "cancel_task", "bulk_retry"])
        for action in ("retry_task", "bulk_retry"):
            refusal = dispatch_refusal(unattested, engine="huey", action=action)
            assert refusal is not None and RETRY_BY_REFERENCE_CAPABILITY in refusal
        assert dispatch_refusal(unattested, engine="huey", action="cancel_task") is None

    def test_unreported_inventory_is_not_refused_by_the_row(self) -> None:
        """A long-poll row reports nothing; its poll states its contracts."""
        long_poll = _Inventory(name="lp")
        assert dispatch_refusal(long_poll, engine="huey", action="cancel_task") is None
        assert dispatch_refusal(long_poll, engine="huey", action="retry_task") is None
        assert dispatch_refusal(long_poll, engine="", action="cancel_task") is not None

    def test_reported_but_empty_inventory_is_refused(self) -> None:
        """A connected scheduler-only process has reported: no engines."""
        scheduler_only = _Inventory(name="beat", last_connect_at=_NOW)
        refusal = dispatch_refusal(scheduler_only, engine="celery", action="cancel_task")
        assert refusal is not None and "celery" in refusal

    @pytest.mark.parametrize(
        "engine",
        ["", "not an engine", "x" * 41, "-leading", "sp ace", None, 7, "tab\t"],
    )
    def test_malformed_engine_strings_are_refused_before_inventory(self, engine: Any) -> None:
        error = engine_name_error(engine)
        assert error is not None
        long_poll = _Inventory(name="lp")
        assert dispatch_refusal(long_poll, engine=engine, action="cancel_task") == error

    def test_latent_1_an_unknown_engine_is_never_rewritten_to_celery(self) -> None:
        """LATENT-1: ``laravel`` names ``laravel`` in the refusal, not ``celery``."""
        celery = _connected("celery-agent", "celery", CELERY)
        for action in ("retry_task", "cancel_task", "requeue_dead_letter", "bulk_retry"):
            refusal = dispatch_refusal(celery, engine="laravel", action=action)
            assert refusal is not None and "laravel" in refusal
        # The session requirement is the name that was sent, not a default.
        assert required_retry_engine("retry_task", {"engine": "laravel"}) == "laravel"
        assert required_retry_engine("bulk_retry", {"filter": {"engine": "laravel"}}) == "laravel"
        assert required_retry_engine("retry_task", {"engine": ""}) == ""
        assert required_retry_engine("retry_task", {}) == ""

    def test_project_authority_is_any_capable_agent(self) -> None:
        celery = _connected("c", "celery", CELERY)
        huey = _connected("h", "huey", [*HUEY, "bulk_retry"])
        authority = project_engine_authority([celery, huey], action="bulk_retry")
        assert authority("celery") and authority("huey")
        assert not authority("arq") and not authority("not an engine")
        assert not project_engine_authority([], action="bulk_retry")("celery")
        # An unreported inventory can be anything, so it makes every
        # well-formed engine possible and no malformed one.
        long_poll = project_engine_authority([_Inventory(name="lp")], action="bulk_retry")
        assert long_poll("arq") and not long_poll("")


# ---------------------------------------------------------------------------
# The REST surface, through the real app
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


async def _seed_agent(
    brain_app,
    settings: Settings,
    seeded,
    *,
    name: str,
    engines: list[str],
    capabilities: dict[str, list[str]],
    connected: bool = True,
) -> uuid.UUID:
    async with brain_app.state.db.session() as s:
        agent = Agent(
            project_id=seeded["project_id"],
            name=name,
            token_hash=hash_agent_token(
                plaintext=name,
                secret=settings.secret.get_secret_value().encode("utf-8"),
            ),
            protocol_version="1" if connected else "0",
            framework_adapter="bare" if connected else "unknown",
            engine_adapters=list(engines),
            scheduler_adapters=[],
            capabilities=capabilities,
            state=AgentState.ONLINE,
            last_connect_at=_NOW if connected else None,
        )
        s.add(agent)
        await s.commit()
        return agent.id


async def _register_session(
    brain_app, settings: Settings, seeded, agent_id: uuid.UUID, *, retry_contracts: dict[str, int]
) -> None:
    class FakeWS:
        async def send_bytes(self, _data: bytes) -> None:
            pass

        async def close(self, code: int = 1000) -> None:
            pass

    ws = FakeWS()
    ws._z4j_signer = FrameSigner(  # type: ignore[attr-defined]
        secret=settings.secret.get_secret_value().encode("utf-8"),
        agent_id=agent_id,
        project_id=seeded["project_id"],
    )
    await brain_app.state.brain_registry.register(
        project_id=seeded["project_id"],
        agent_id=agent_id,
        ws=ws,
        retry_contracts=retry_contracts,
    )


async def _seed_tasks(brain_app, seeded, *, engine: str, task_ids: list[str]) -> None:
    async with brain_app.state.db.session() as s:
        s.add_all(
            Task(
                project_id=seeded["project_id"],
                engine=engine,
                task_id=task_id,
                name="app.work",
                state=TaskState.FAILURE,
            )
            for task_id in task_ids
        )
        await s.commit()


async def _command_count(brain_app) -> int:
    async with brain_app.state.db.session() as s:
        return int(await s.scalar(select(func.count(Command.id))) or 0)


def _retry_body(agent_id: uuid.UUID, engine: str, *, overrides: bool) -> dict[str, Any]:
    body: dict[str, Any] = {"agent_id": str(agent_id), "engine": engine, "task_id": "task-001"}
    if overrides:
        body["override_args"] = [1]
        body["override_kwargs"] = {"k": "v"}
    return body


@pytest.mark.asyncio
class TestCapabilityDispatchOverHttp:
    async def test_huey_retry_is_dispatched_when_the_session_advertises_it(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app, settings, seeded, name="huey", engines=["huey"], capabilities={"huey": HUEY}
        )
        await _register_session(brain_app, settings, seeded, agent_id, retry_contracts={"huey": 1})

        r = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            json=_retry_body(agent_id, "huey", overrides=True),
        )
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["action"] == "retry_task"
        assert body["payload"]["engine"] == "huey"
        assert body["status"] == "dispatched"

    async def test_huey_retry_without_overrides_is_the_polyfill_409(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        """Capability admits the engine; argument safety is still engine-keyed."""
        agent_id = await _seed_agent(
            brain_app, settings, seeded, name="huey", engines=["huey"], capabilities={"huey": HUEY}
        )
        r = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            json=_retry_body(agent_id, "huey", overrides=False),
        )
        assert r.status_code == 409, r.text
        assert "no native retry" in r.text
        assert await _command_count(brain_app) == 0

    async def test_huey_cancel_is_accepted(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app, settings, seeded, name="huey", engines=["huey"], capabilities={"huey": HUEY}
        )
        r = await client.post(
            "/api/v1/projects/default/commands/cancel-task",
            json={"agent_id": str(agent_id), "engine": "huey", "task_id": "task-001"},
        )
        assert r.status_code == 202, r.text
        assert r.json()["payload"]["engine"] == "huey"

    async def test_arq_cancel_accepted_and_arq_retry_refused_by_capability(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app, settings, seeded, name="arq", engines=["arq"], capabilities={"arq": ARQ}
        )
        cancel = await client.post(
            "/api/v1/projects/default/commands/cancel-task",
            json={"agent_id": str(agent_id), "engine": "arq", "task_id": "task-001"},
        )
        assert cancel.status_code == 202, cancel.text

        retry = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            json=_retry_body(agent_id, "arq", overrides=True),
        )
        assert retry.status_code == 422, retry.text
        assert "retry_task" in retry.text and "'arq'" in retry.text
        assert await _command_count(brain_app) == 1

    async def test_taskiq_retry_and_cancel_refused_by_capability(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="taskiq",
            engines=["taskiq"],
            capabilities={"taskiq": TASKIQ},
        )
        retry = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            json=_retry_body(agent_id, "taskiq", overrides=True),
        )
        cancel = await client.post(
            "/api/v1/projects/default/commands/cancel-task",
            json={"agent_id": str(agent_id), "engine": "taskiq", "task_id": "task-001"},
        )
        assert retry.status_code == 422, retry.text
        assert cancel.status_code == 422, cancel.text
        assert "retry_task" in retry.text and "cancel_task" in cancel.text
        assert await _command_count(brain_app) == 0

    async def test_latent_1_unknown_engine_is_refused_naming_it_and_nothing_is_issued(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        """LATENT-1: a ``laravel`` command to a celery agent is a 422, not a celery command."""
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="celery",
            engines=["celery"],
            capabilities={"celery": CELERY},
        )
        for route, body in (
            ("retry-task", _retry_body(agent_id, "laravel", overrides=False)),
            ("cancel-task", {"agent_id": str(agent_id), "engine": "laravel", "task_id": "t"}),
            (
                "requeue-dead-letter",
                {"agent_id": str(agent_id), "engine": "laravel", "task_id": "t"},
            ),
        ):
            r = await client.post(f"/api/v1/projects/default/commands/{route}", json=body)
            assert r.status_code == 422, (route, r.text)
            assert "'laravel'" in r.text and "'celery'" in r.text
        assert await _command_count(brain_app) == 0

    async def test_malformed_engine_string_is_refused_at_the_request_boundary(
        self, brain_app, client, seeded
    ) -> None:
        for engine in ("not a real engine", "", "x" * 41):
            r = await client.post(
                "/api/v1/projects/default/commands/cancel-task",
                json={"agent_id": str(uuid.uuid4()), "engine": engine, "task_id": "t"},
            )
            assert r.status_code == 422, (engine, r.text)
        assert await _command_count(brain_app) == 0

    async def test_unreported_inventory_agent_is_admitted_for_a_well_formed_engine(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        """A long-poll row reports no inventory; its poll admits each command."""
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="long-poll",
            engines=[],
            capabilities={},
            connected=False,
        )
        r = await client.post(
            "/api/v1/projects/default/commands/cancel-task",
            json={"agent_id": str(agent_id), "engine": "huey", "task_id": "task-001"},
        )
        assert r.status_code == 202, r.text
        assert r.json()["status"] == "pending"

    async def test_retry_needs_the_attested_safe_retry_marker(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="old-huey",
            engines=["huey"],
            capabilities={"huey": ["submit_task", "retry_task", "cancel_task"]},
        )
        retry = await client.post(
            "/api/v1/projects/default/commands/retry-task",
            json=_retry_body(agent_id, "huey", overrides=True),
        )
        assert retry.status_code == 422, retry.text
        assert "safe retry contract" in retry.text
        cancel = await client.post(
            "/api/v1/projects/default/commands/cancel-task",
            json={"agent_id": str(agent_id), "engine": "huey", "task_id": "task-001"},
        )
        assert cancel.status_code == 202, cancel.text

    async def test_legacy_bulk_retry_filter_accepts_huey_when_advertised(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="huey",
            engines=["huey"],
            capabilities={"huey": [*HUEY, "bulk_retry"]},
        )
        await _seed_tasks(brain_app, seeded, engine="huey", task_ids=["t1", "t2"])
        r = await client.post(
            "/api/v1/projects/default/commands/bulk-retry",
            json={
                "agent_id": str(agent_id),
                "filter": {"task_ids": ["t1", "t2"], "engine": "huey"},
                "max": 10,
            },
        )
        assert r.status_code == 202, r.text
        payload = r.json()["payload"]
        assert payload["filter"]["engine"] == "huey"
        assert payload["filter"]["task_ids"] == ["t1", "t2"]

    async def test_legacy_bulk_retry_refuses_an_engine_the_agent_does_not_advertise(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        agent_id = await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="celery",
            engines=["celery"],
            capabilities={"celery": CELERY},
        )
        await _seed_tasks(brain_app, seeded, engine="huey", task_ids=["t1"])
        r = await client.post(
            "/api/v1/projects/default/commands/bulk-retry",
            json={"agent_id": str(agent_id), "filter": {"task_ids": ["t1"], "engine": "huey"}},
        )
        assert r.status_code == 422, r.text
        assert "'huey'" in r.text
        assert await _command_count(brain_app) == 0

    async def test_durable_bulk_retry_filter_follows_the_capability_rule(
        self, brain_app, client, settings: Settings, seeded
    ) -> None:
        await _seed_agent(
            brain_app,
            settings,
            seeded,
            name="huey",
            engines=["huey"],
            capabilities={"huey": [*HUEY, "bulk_retry"]},
        )
        await _seed_tasks(brain_app, seeded, engine="huey", task_ids=["t1"])
        accepted = await client.post(
            "/api/v1/projects/default/bulk-retry-requests",
            json={"idempotency_key": "huey-ok", "filter": {"engine": "huey", "state": "failure"}},
        )
        assert accepted.status_code == 202, accepted.text
        assert accepted.json()["counts"]["total"] == 1

        refused = await client.post(
            "/api/v1/projects/default/bulk-retry-requests",
            json={"idempotency_key": "arq-none", "filter": {"engine": "arq", "state": "failure"}},
        )
        assert refused.status_code == 400, refused.text
        assert "'arq'" in refused.text
