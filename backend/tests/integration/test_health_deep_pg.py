"""The deep-health probe on the engine whose transaction semantics it fights.

PostgreSQL aborts the whole transaction on the first statement error and SQLite
does not, so probe isolation is not observable on SQLite at all: the second
probe succeeds whether or not the first one was isolated, which is a test that
cannot fail. This file is therefore the only place that claim is checked.

It lives in the integration suite because that is what runs it. The same test
sat in the unit suite behind ``skipif(Z4J_TEST_POSTGRES_URL is None)``, and
neither lane that runs the unit suite sets that variable, so it was skipped
everywhere and read as coverage of a property nothing checked. The integration
conftest either starts a PostgreSQL container or is handed one, so a test here
runs or the whole suite is skipped loudly.
"""

from __future__ import annotations

import contextlib
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.models import Project, Session, User
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio

_URL = "/api/v1/health/deep"
_PW = "correct-horse-battery-staple-9"


@pytest.fixture
async def health_app(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> AsyncIterator[tuple[object, Settings]]:
    """A brain on the migrated per-test database, ready to answer the probe."""
    engine = create_async_engine(integration_settings.database_url)
    app = create_app(integration_settings, engine=engine)
    app.state.lifespan_ready = True
    try:
        yield app, integration_settings
    finally:
        await engine.dispose()


async def _seed_user(app, settings: Settings) -> uuid.UUID:
    """One authenticated cookie session; the probe is behind auth on purpose."""
    hasher = PasswordHasher(settings)
    async with app.state.db.session() as session:
        project = (
            await session.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if project is None:
            session.add(Project(id=uuid.uuid4(), slug="default", name="default"))
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        session.add(row)
        await session.commit()
    return row.id


@contextlib.asynccontextmanager
async def _client(app, settings: Settings, session_id: uuid.UUID):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(session_id),
        )
        yield client


async def test_a_failing_probe_does_not_poison_the_next_one(health_app) -> None:
    """The pairing that makes narrowing the exception handlers safe.

    A PostgreSQL database with no ``alembic_version`` fails its migrations
    probe legitimately, and that statement error aborts the transaction the
    request's session is holding, so every later probe raises
    ``InFailedSqlTransaction``. Before the handlers were narrowed that surfaced
    as a lie -- a fully activated audit chain reported as not activated.
    Narrowing them without isolating each probe would have turned the same
    database into a 503 that blamed the wrong subsystem.

    The migrations verdict below is the one startup gives the same database:
    it refuses to boot without that table, so the probe reports failed. What
    this test is about is the check AFTER it still telling the truth.
    """
    app, settings = health_app
    session_id = await _seed_user(app, settings)

    engine = create_async_engine(settings.database_url)
    try:
        async with engine.begin() as connection:
            await connection.execute(text("DROP TABLE alembic_version"))
    finally:
        await engine.dispose()

    async with _client(app, settings, session_id) as client:
        resp = await client.get(_URL)

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["checks"]["migrations"]["status"] == "failed"
    assert "alembic_version is missing" in body["checks"]["migrations"]["detail"]
    # The half that was wrong in both directions: this chain IS activated, and
    # a poisoned session reported it as absent.
    assert body["checks"]["audit_chain"] == {
        "status": "ok",
        "activated": True,
        "scope": "state-only",
    }
    # And the probe that ran before the failing one is still reported at all.
    assert body["checks"]["database"]["status"] == "ok"
