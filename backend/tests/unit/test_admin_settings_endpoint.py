"""Tests for ``GET /api/v1/admin/settings``.

Covers the auth gate (anonymous -> 401, non-admin -> 403,
admin -> 200) and the response contract (z4j_home present, every
field has a source label, secrets are masked).

Reuses the ASGI + seeded-admin fixture pattern from
``test_b5_endpoints`` so the harness stays consistent across
admin-route tests.
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
from z4j_brain.persistence import models  # noqa: F401  - register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Session, User
from z4j_brain.settings import Settings


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
    yield app
    await engine.dispose()


async def _seed_user(
    brain_app, settings: Settings, *, is_admin: bool, email: str,
) -> dict:
    """Insert a user + active session, return cookie material."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        user = User(
            id=user_id,
            email=email,
            password_hash=hasher.hash("correct horse battery staple 9"),
            is_admin=is_admin,
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
        s.add_all([user, session_row])
        await s.commit()

    return {
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


def _client_for(brain_app, settings: Settings, seeded: dict | None):
    """Build an httpx AsyncClient pre-loaded with session cookies.

    When ``seeded`` is ``None`` the client is anonymous (no cookies).
    """
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    ac = AsyncClient(transport=transport, base_url="http://testserver")
    if seeded is not None:
        codec = SessionCookieCodec(settings)
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            codec.encode(seeded["session_id"]),
        )
    return ac


@pytest.mark.asyncio
class TestAdminSettingsEndpoint:
    async def test_anonymous_gets_401(self, brain_app, settings) -> None:
        async with _client_for(brain_app, settings, None) as ac:
            r = await ac.get("/api/v1/admin/settings")
        # No session cookie + no bearer header -> AuthenticationError
        # (mapped to 401 by the error middleware).
        assert r.status_code == 401

    async def test_non_admin_gets_403(self, brain_app, settings) -> None:
        seeded = await _seed_user(
            brain_app, settings, is_admin=False, email="user@example.com",
        )
        async with _client_for(brain_app, settings, seeded) as ac:
            r = await ac.get("/api/v1/admin/settings")
        # require_admin -> AuthorizationError -> 403.
        assert r.status_code == 403

    async def test_admin_gets_200_with_settings(
        self, brain_app, settings,
    ) -> None:
        seeded = await _seed_user(
            brain_app, settings, is_admin=True, email="admin@example.com",
        )
        async with _client_for(brain_app, settings, seeded) as ac:
            r = await ac.get("/api/v1/admin/settings")
        assert r.status_code == 200
        body = r.json()

        # Top-level shape.
        assert isinstance(body["z4j_home"], str) and body["z4j_home"]
        assert isinstance(body["settings"], list)
        assert len(body["settings"]) > 0

        # Each row has the expected shape and a known source label.
        valid_sources = {"env", "config.env", "secret.env", ".env", "default"}
        for row in body["settings"]:
            assert set(row.keys()) == {
                "name", "value", "source", "is_secret", "description",
            }
            assert row["source"] in valid_sources
            assert isinstance(row["is_secret"], bool)
            assert isinstance(row["value"], str)

        # The ``secret`` field must always be masked, regardless of
        # whether it came from env / config.env / etc.
        by_name = {row["name"]: row for row in body["settings"]}
        assert "secret" in by_name
        assert by_name["secret"]["is_secret"] is True
        assert by_name["secret"]["value"] == "***"

        # Secrets must NEVER appear in cleartext anywhere in the body,
        # even partially. This pins the "secrets never cross the wire"
        # invariant in a single grep-the-response check.
        cleartext = settings.secret.get_secret_value()
        assert cleartext not in r.text

        # Sorted alphabetically.
        names = [row["name"] for row in body["settings"]]
        assert names == sorted(names)

    async def test_settings_includes_known_field(
        self, brain_app, settings,
    ) -> None:
        """``event_retention_days`` is a stable public field; any
        rename to it should fail this test loudly so the dashboard
        doesn't silently lose its row.
        """
        seeded = await _seed_user(
            brain_app, settings, is_admin=True, email="admin2@example.com",
        )
        async with _client_for(brain_app, settings, seeded) as ac:
            r = await ac.get("/api/v1/admin/settings")
        body = r.json()
        by_name = {row["name"]: row for row in body["settings"]}
        assert "event_retention_days" in by_name
        row = by_name["event_retention_days"]
        assert row["is_secret"] is False
        # Default is 30 per Settings; test fixture doesn't override.
        assert row["value"] == "30"
        assert row["source"] == "default"
