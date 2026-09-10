"""Tests for ``z4j_brain.middleware.security_headers``."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route
from z4j_brain.main import create_app
from z4j_brain.middleware.security_headers import SecurityHeadersMiddleware
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.settings import Settings

# The backend suite intentionally does not require a dashboard build. Prefer
# the bundled artifact when present, then the frontend build, and finally
# Vite's canonical source template in a fresh checkout.
_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_DASHBOARD_INDEX_HTML = next(
    candidate
    for candidate in (
        _PACKAGE_ROOT / "backend" / "src" / "z4j_brain" / "dashboard" / "dist" / "index.html",
        _PACKAGE_ROOT / "dashboard" / "dist" / "index.html",
        _PACKAGE_ROOT / "dashboard" / "index.html",
    )
    if candidate.is_file()
).read_text(encoding="utf-8")


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
class TestBaselineHeaders:
    async def test_no_sniff(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert r.headers["x-content-type-options"] == "nosniff"

    async def test_frame_deny(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert r.headers["x-frame-options"] == "DENY"

    async def test_permissions_policy(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert "geolocation=()" in r.headers["permissions-policy"]
        assert "camera=()" in r.headers["permissions-policy"]

    async def test_coop(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert r.headers["cross-origin-opener-policy"] == "same-origin"

    async def test_corp(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert r.headers["cross-origin-resource-policy"] == "same-origin"


@pytest.mark.asyncio
class TestReferrerPolicy:
    async def test_default_referrer_policy(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin"

    async def test_no_referrer_on_setup(self, client) -> None:
        r = await client.get("/api/v1/setup/status")
        assert r.headers["referrer-policy"] == "no-referrer"


@pytest.mark.asyncio
class TestCacheControlOnAuthPaths:
    async def test_auth_path_no_store(self, client) -> None:
        # /api/v1/auth/me 401s without a session - but the header
        # should still be set on the failure response.
        r = await client.get("/api/v1/auth/me")
        assert r.headers.get("cache-control") == "no-store"

    async def test_setup_path_no_store(self, client) -> None:
        r = await client.get("/api/v1/setup/status")
        assert r.headers.get("cache-control") == "no-store"


@pytest.mark.asyncio
class TestHsts:
    async def test_hsts_absent_in_dev(self, client) -> None:
        r = await client.get("/api/v1/health")
        assert "strict-transport-security" not in r.headers


@pytest.mark.asyncio
class TestCspOnHtml:
    async def test_dashboard_csp_allows_only_exact_first_party_inline_blocks(
        self,
        settings: Settings,
    ) -> None:
        async def html_response(_request: Request) -> HTMLResponse:
            return HTMLResponse("<!doctype html><title>CSP test</title>")

        app = Starlette(routes=[Route("/", html_response)])
        app.add_middleware(SecurityHeadersMiddleware, settings=settings)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            r = await client.get("/")

        csp = r.headers["content-security-policy"]
        directives = {
            fields[0]: fields[1:]
            for directive in csp.split(";")
            if (fields := directive.strip().split())
        }

        inline_script = re.search(
            r"<script>(.*?)</script>",
            _DASHBOARD_INDEX_HTML,
            flags=re.DOTALL,
        )
        assert inline_script is not None
        digest = base64.b64encode(hashlib.sha256(inline_script.group(1).encode()).digest()).decode()

        assert directives["script-src"] == [
            "'self'",
            f"'sha256-{digest}'",
        ]
        assert directives["style-src-elem"] == [
            "'self'",
            "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
            "'sha256-StEaX+se6YS7pqjzrzMIA0KaX9zF/8zAhvQXZAe5epY='",
        ]
        assert "'unsafe-inline'" not in directives["script-src"]
        assert "'unsafe-inline'" not in directives["style-src-elem"]

    async def test_csp_on_setup_form(self, client) -> None:
        r = await client.get("/setup?token=anything")
        assert "content-security-policy" in r.headers
        assert "default-src 'none'" in r.headers["content-security-policy"]

    async def test_csp_absent_on_json(self, client) -> None:
        r = await client.get("/api/v1/health")
        # JSON responses skip CSP - handlers may set it later but
        # the middleware does not by default.
        assert "content-security-policy" not in r.headers
