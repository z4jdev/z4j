"""End-to-end tests for /api/v1/auth/{login,logout,me}.

These exercise the full middleware + dep + service stack against an
in-memory SQLite database. The slow path is the argon2 verify on
login - we use the smaller test cost from the conftest fixture.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.models import User
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        # Cheap argon2 for tests.
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        # Cheap login min duration so the suite is fast.
        login_min_duration_ms=10,
        login_lockout_threshold=4,
        login_backoff_base_seconds=0.0,
        login_backoff_max_seconds=0.0,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    """Build the brain on a shared in-memory engine.

    A single shared engine + StaticPool is required because we
    create the schema in one connection and need every subsequent
    handler-bound session to see it.
    """
    from sqlalchemy.pool import StaticPool

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
async def seeded_user(settings: Settings, brain_app):  # noqa: ARG001
    """Insert one active user with a known password."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    async with db.session() as s:
        user = User(
            email="alice@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            display_name="Alice",
            is_admin=False,
            is_active=True,
        )
        s.add(user)
        await s.commit()
        return user


@pytest.fixture
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
class TestLoginHappy:
    async def test_login_sets_session_cookie(
        self, client, settings: Settings, seeded_user,
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["user"]["email"] == "alice@example.com"
        assert body["user"]["is_admin"] is False
        # Sensitive fields must NOT be in the response.
        assert "password_hash" not in body["user"]
        assert "failed_login_count" not in body["user"]
        # Cookie set.
        assert cookie_name(environment=settings.environment) in [
            c.split("=", 1)[0] for c in response.headers.get_list("set-cookie")
        ]


@pytest.mark.asyncio
class TestLoginFailureShape:
    """Wrong password and unknown email return byte-identical envelopes."""

    async def test_wrong_password(self, client, seeded_user) -> None:  # noqa: ARG002
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "WRONG"},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "unauthenticated"
        assert body["message"] == "invalid_credentials"

    async def test_unknown_email(self, client, seeded_user) -> None:  # noqa: ARG002
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "WRONG"},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "unauthenticated"
        assert body["message"] == "invalid_credentials"

    async def test_failure_responses_byte_identical_modulo_request_id(
        self, client, seeded_user,  # noqa: ARG002
    ) -> None:
        r1 = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "WRONG"},
        )
        r2 = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "WRONG"},
        )
        assert r1.status_code == r2.status_code == 401
        b1 = r1.json()
        b2 = r2.json()
        b1["request_id"] = "X"
        b2["request_id"] = "X"
        assert b1 == b2


@pytest.mark.asyncio
class TestPasswordResetRequest:
    async def test_unknown_email_uses_timing_floor(
        self,
        client,
        settings: Settings,
        monkeypatch,
    ) -> None:
        from z4j_brain.api import auth as auth_api

        calls: list[int] = []

        async def fake_hold(start: float, min_duration_ms: int) -> None:
            assert start > 0
            calls.append(min_duration_ms)

        monkeypatch.setattr(
            auth_api,
            "_hold_minimum_response_time",
            fake_hold,
        )

        response = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "nobody@example.com"},
        )

        assert response.status_code == 200
        assert response.json() == {"accepted": True}
        assert calls == [settings.login_min_duration_ms]

    async def test_known_email_uses_same_timing_floor(
        self,
        client,
        settings: Settings,
        seeded_user,  # noqa: ARG002
        monkeypatch,
    ) -> None:
        from z4j_brain.api import auth as auth_api

        calls: list[int] = []

        async def fake_hold(start: float, min_duration_ms: int) -> None:
            assert start > 0
            calls.append(min_duration_ms)

        monkeypatch.setattr(
            auth_api,
            "_hold_minimum_response_time",
            fake_hold,
        )

        response = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )

        assert response.status_code == 200
        assert response.json() == {"accepted": True}
        assert calls == [settings.login_min_duration_ms]


@pytest.mark.asyncio
class TestLockout:
    async def test_lockout_triggers_after_threshold(
        self, client, settings: Settings, seeded_user,  # noqa: ARG002
    ) -> None:
        # threshold is 4 in the fixture; 4 wrong attempts → locked.
        for _ in range(settings.login_lockout_threshold):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": "alice@example.com", "password": "WRONG"},
            )
            assert r.status_code == 401
        # 5th attempt with the CORRECT password is also rejected
        # because the account is locked.
        r = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert r.status_code == 401
        # Same envelope as wrong-password - the lockout state
        # never leaks to the response.
        assert r.json()["error"] == "unauthenticated"
        assert r.json()["message"] == "invalid_credentials"


@pytest.mark.asyncio
class TestMe:
    async def test_me_unauthenticated_is_401(self, client) -> None:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_me_after_login(self, client, seeded_user) -> None:  # noqa: ARG002
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        body = me.json()
        # Field whitelist enforced. ``memberships`` was added in
        # B5 so the dashboard's project switcher can render roles.
        assert set(body.keys()) == {
            "id",
            "email",
            "display_name",
            "first_name",
            "last_name",
            "is_admin",
            "timezone",
            "created_at",
            "memberships",
        }
        assert isinstance(body["memberships"], list)


@pytest.mark.asyncio
class TestLogout:
    async def test_logout_revokes_session(
        self, client, settings: Settings, seeded_user,  # noqa: ARG002
    ) -> None:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200
        # Pull the CSRF cookie value out of the login response.
        from z4j_brain.auth.csrf import csrf_cookie_name

        csrf_name = csrf_cookie_name(environment=settings.environment)
        csrf_value = client.cookies.get(csrf_name)
        assert csrf_value is not None
        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": csrf_value},
        )
        assert logout.status_code == 204
        # /me now fails - session was revoked.
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 401

    async def test_logout_without_csrf_is_403(
        self, client, seeded_user,  # noqa: ARG002
    ) -> None:
        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        logout = await client.post("/api/v1/auth/logout")
        assert logout.status_code == 403
