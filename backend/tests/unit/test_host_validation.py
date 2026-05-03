"""Tests for ``z4j_brain.middleware.host_validation``."""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.main import create_app
from z4j_brain.middleware.host_validation import HostValidationMiddleware
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.settings import Settings


class TestStripPort:
    def test_no_port(self) -> None:
        assert HostValidationMiddleware._strip_port("z4j.example.com") == "z4j.example.com"

    def test_port(self) -> None:
        assert HostValidationMiddleware._strip_port("z4j.example.com:7700") == "z4j.example.com"

    def test_ipv6_no_port(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]") == "[::1]"

    def test_ipv6_with_port(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]:7700") == "[::1]"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
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
class TestHostValidationDev:
    async def test_localhost_allowed(self, client) -> None:
        # ASGITransport's default Host is testserver, which we
        # allow-list in dev mode automatically.
        r = await client.get("/api/v1/health")
        assert r.status_code == 200

    async def test_unknown_host_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "evil.example.com"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_known_host_with_port_accepted(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "127.0.0.1:7700"},
        )
        assert r.status_code == 200
