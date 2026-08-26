"""The worker-lint endpoint.

The rules themselves are covered in ``test_worker_lint.py``. What matters
here is the aggregation an operator actually reads: who is affected, how
badly, and which workers were never judged at all.
"""

from __future__ import annotations

import contextlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Session,
    User,
    Worker,
)
from z4j_brain.settings import Settings

_URL = "/api/v1/projects/default/workers/lint"
_PW = "correct-horse-battery-staple-9"


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
        metrics_public=True,
        disable_spa_fallback=True,
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
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


@contextlib.asynccontextmanager
async def _client(brain_app, settings, seeded=None):
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        if seeded is not None:
            ac.cookies.set(
                cookie_name(environment=settings.environment),
                SessionCookieCodec(settings).encode(seeded["session_id"]),
            )
        yield ac


SAFE_CONF = {
    "accept_content": ["json"],
    "task_acks_late": True,
    "task_reject_on_worker_lost": True,
    "worker_prefetch_multiplier": 1,
    "task_time_limit": 300,
}
PICKLE_CONF = {**SAFE_CONF, "accept_content": ["json", "pickle"]}
LOSSY_CONF = {**SAFE_CONF, "task_acks_late": False}


async def _seed_viewer(brain_app, settings) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        proj = (
            await s.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if proj is None:
            proj = Project(id=uuid.uuid4(), slug="default", name="default")
            s.add(proj)
            await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_active=True,
        )
        s.add(user)
        await s.flush()
        s.add(Membership(user_id=user.id, project_id=proj.id, role=ProjectRole.VIEWER))
        session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add(session_row)
        await s.commit()
    return {"session_id": session_row.id, "project_id": proj.id}


async def _add_worker(brain_app, project_id, name, engine, conf) -> None:
    db = brain_app.state.db
    async with db.session() as s:
        s.add(
            Worker(
                id=uuid.uuid4(),
                project_id=project_id,
                engine=engine,
                name=name,
                worker_metadata={"conf": conf} if conf is not None else {},
                last_heartbeat=datetime.now(UTC),
            )
        )
        await s.commit()


@pytest.mark.asyncio
async def test_requires_authentication(brain_app, settings) -> None:
    """A configuration inventory is not public."""
    async with _client(brain_app, settings) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_reports_findings_and_counts_them_by_severity(brain_app, settings) -> None:
    seeded = await _seed_viewer(brain_app, settings)
    await _add_worker(brain_app, seeded["project_id"], "w-pickle", "celery", PICKLE_CONF)
    await _add_worker(brain_app, seeded["project_id"], "w-lossy", "celery", LOSSY_CONF)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workers_evaluated"] == 2
    assert body["findings_by_severity"].get("high") == 1
    assert body["findings_by_severity"].get("medium") == 1


@pytest.mark.asyncio
async def test_worst_worker_is_listed_first(brain_app, settings) -> None:
    """An operator reads the top of the list, so the top must be the worst."""
    seeded = await _seed_viewer(brain_app, settings)
    await _add_worker(brain_app, seeded["project_id"], "a-clean", "celery", SAFE_CONF)
    await _add_worker(brain_app, seeded["project_id"], "z-pickle", "celery", PICKLE_CONF)

    async with _client(brain_app, settings, seeded) as ac:
        body = (await ac.get(_URL)).json()

    # Alphabetically "a-clean" sorts first; severity has to beat name order.
    assert body["workers"][0]["worker_name"] == "z-pickle"


@pytest.mark.asyncio
async def test_unevaluated_workers_are_not_counted_as_clean(brain_app, settings) -> None:
    """The distinction the summary exists to preserve.

    An RQ worker has no rules and a worker that reported no configuration
    has nothing to judge. Folding either into "no problems found" would
    claim knowledge the check does not have.
    """
    seeded = await _seed_viewer(brain_app, settings)
    await _add_worker(brain_app, seeded["project_id"], "w-rq", "rq", SAFE_CONF)
    await _add_worker(brain_app, seeded["project_id"], "w-silent", "celery", None)
    await _add_worker(brain_app, seeded["project_id"], "w-ok", "celery", SAFE_CONF)

    async with _client(brain_app, settings, seeded) as ac:
        body = (await ac.get(_URL)).json()

    assert body["workers_evaluated"] == 1
    assert body["workers_not_evaluated"] == 2
    assert body["findings_by_severity"] == {}
    unevaluated = {w["worker_name"] for w in body["workers"] if not w["evaluated"]}
    assert unevaluated == {"w-rq", "w-silent"}


@pytest.mark.asyncio
async def test_reported_empty_config_is_evaluated_for_absence_rules(brain_app, settings) -> None:
    """An empty report and no report are distinct domain inputs.

    Celery's time-limit rule deliberately treats missing limit keys in a
    reported mapping as proof that no limit is configured. The endpoint must
    not suppress that warning merely because the mapping has no unrelated key.
    """
    seeded = await _seed_viewer(brain_app, settings)
    await _add_worker(brain_app, seeded["project_id"], "w-empty", "celery", {})

    async with _client(brain_app, settings, seeded) as ac:
        body = (await ac.get(_URL)).json()

    assert body["workers_evaluated"] == 1
    assert body["workers_not_evaluated"] == 0
    assert body["findings_by_severity"] == {"medium": 1}
    assert body["workers"][0]["evaluated"] is True
    assert [finding["rule_id"] for finding in body["workers"][0]["findings"]] == [
        "celery.no-time-limit"
    ]


@pytest.mark.asyncio
async def test_a_project_with_no_workers_is_empty_not_an_error(brain_app, settings) -> None:
    seeded = await _seed_viewer(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        body = (await ac.get(_URL)).json()

    assert body["workers"] == []
    assert body["workers_evaluated"] == 0
    assert body["findings_by_severity"] == {}


@pytest.mark.asyncio
async def test_every_finding_reaches_the_client_with_its_remedy(brain_app, settings) -> None:
    """The remedy is the reason the panel is worth opening."""
    seeded = await _seed_viewer(brain_app, settings)
    await _add_worker(brain_app, seeded["project_id"], "w1", "celery", PICKLE_CONF)

    async with _client(brain_app, settings, seeded) as ac:
        body = (await ac.get(_URL)).json()
    finding = body["workers"][0]["findings"][0]

    assert finding["rule_id"] == "celery.pickle-accepted"
    assert finding["severity"] == "high"
    assert finding["remedy"].strip()
    assert finding["detail"].strip()
