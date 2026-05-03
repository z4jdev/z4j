"""Tests for ``z4j_brain.middleware.body_size``."""

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
        max_payload_size_bytes=1024,  # tiny so we can hit it cheaply
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
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
class TestBodySizeLimit:
    async def test_small_body_accepted(self, client) -> None:
        # 50-byte body - well under the 1024 limit.
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "a@example.com", "password": "x"},
        )
        # Doesn't matter that login fails; we only care that the
        # body got through to the handler.
        assert r.status_code != 413

    async def test_oversized_body_rejected(self, client) -> None:
        big = "x" * 5000
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "a@example.com", "password": big},
        )
        assert r.status_code == 413
        assert r.json()["error"] == "payload_too_large"
