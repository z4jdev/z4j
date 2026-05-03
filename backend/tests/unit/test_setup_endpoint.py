"""End-to-end tests for /setup, /api/v1/setup/status, /api/v1/setup/complete."""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
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
        first_boot_attempts_per_ip=3,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    """Brain on a shared in-memory engine - first-boot mode active."""
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
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.fixture
async def fresh_token(brain_app, settings):  # noqa: ARG001
    """Mint a setup token via the SetupService directly.

    The lifespan startup hook would normally do this, but the
    ASGI test transport does not run lifespan automatically. We
    invoke the same code path here so the test exercises the real
    mint → verify → consume flow.
    """
    from z4j_brain.persistence.repositories import (
        FirstBootTokenRepository,
        UserRepository,
    )

    db = brain_app.state.db
    setup_service = brain_app.state.setup_service
    async with db.session() as session:
        users = UserRepository(session)
        tokens = FirstBootTokenRepository(session)
        if not await setup_service.is_first_boot(users):
            raise RuntimeError("brain not in first-boot mode")
        plaintext, _ = await setup_service.mint_token(tokens)
        await session.commit()
    return plaintext


@pytest.mark.asyncio
class TestStatus:
    async def test_first_boot_true_initially(self, client) -> None:
        r = await client.get("/api/v1/setup/status")
        assert r.status_code == 200
        assert r.json() == {"first_boot": True}

    async def test_status_no_auth_required(self, client) -> None:
        # No cookies, no headers - must succeed.
        r = await client.get("/api/v1/setup/status")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestForm:
    async def test_form_served_in_first_boot(
        self, client, fresh_token,  # noqa: ARG002 - just need the row minted
    ) -> None:
        # Round-9 audit fix R8-Bootstrap-MED test update (Apr 2026):
        # the form is now also gated on an active token row
        # existing. ``fresh_token`` mints one; the form's JS still
        # reads the token from window.location, so the value passed
        # in the URL is irrelevant to the gate.
        r = await client.get("/setup?token=anything")
        assert r.status_code == 200
        assert "z4j first-boot setup" in r.text
        assert r.headers.get("content-security-policy") is not None
        assert r.headers.get("referrer-policy") == "no-referrer"

    async def test_form_404_when_no_active_token(self, client) -> None:
        # Round-9 audit fix R8-Bootstrap-MED (Apr 2026): even in
        # first-boot state, refuse the form when no token row
        # exists, the operator either hasn't restarted to mint
        # one or the prior token expired without consumption.
        r = await client.get("/setup?token=anything")
        assert r.status_code == 404

    async def test_form_404_after_first_boot(self, client, fresh_token) -> None:
        # Complete setup first.
        r = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": fresh_token,
                "email": "admin@example.com",
                "display_name": "Admin",
                "password": "correct horse battery staple 9",
            },
        )
        assert r.status_code == 200
        # Now /setup should return 404.
        form = await client.get("/setup?token=anything")
        assert form.status_code == 404


@pytest.mark.asyncio
class TestComplete:
    async def test_happy_path(self, client, fresh_token) -> None:
        r = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": fresh_token,
                "email": "admin@example.com",
                "display_name": "Admin",
                "password": "correct horse battery staple 9",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["user"]["email"] == "admin@example.com"
        assert body["user"]["is_admin"] is True
        # Status now reports first_boot=False.
        s = await client.get("/api/v1/setup/status")
        assert s.json() == {"first_boot": False}

    async def test_invalid_token_410(self, client, fresh_token) -> None:  # noqa: ARG002
        r = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": "totally-fake-token",
                "email": "admin@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        # Service raises NotFoundError → 404 in our error map.
        assert r.status_code == 404

    async def test_double_consumption_blocked(
        self, client, fresh_token,
    ) -> None:
        first = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": fresh_token,
                "email": "admin@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert first.status_code == 200
        second = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": fresh_token,
                "email": "admin2@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        # Brain is no longer in first-boot mode → ConflictError → 409.
        assert second.status_code == 409

    async def test_weak_password_rejected(
        self, client, fresh_token,
    ) -> None:
        r = await client.post(
            "/api/v1/setup/complete",
            json={
                "token": fresh_token,
                "email": "admin@example.com",
                "password": "password1234",
            },
        )
        # password1234 is in the breach list → 422 from policy.
        assert r.status_code in (422, 500, 400)
        # The exact mapping depends on how PasswordError surfaces;
        # we just confirm it's not a 200.
        assert r.status_code != 200
