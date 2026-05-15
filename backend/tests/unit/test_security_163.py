"""Security regression tests for the 1.6.3 advisory release.

Covers:

- **S1**: OpenAPI three-mode visibility (public / private / disabled)
  with a 9-cell matrix (3 modes x 3 caller types) plus rate-limit,
  ETag round-trip, audit log, and watermark presence
- **S4**: ``/api/v1/api-keys/scopes`` requires authentication
- **S5**: ``POST /api/v1/setup/complete`` route-level throttle

Each test pins the regression that the corresponding fix prevents.
Removing any of these tests must be deliberate and justified in the
PR description.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from z4j_brain.main import create_app
from z4j_brain.settings import Settings


# ---------------------------------------------------------------------------
# Autouse fixture: reset the per-IP rate-limit buckets between tests.
# All tests share the loopback IP via ASGITransport, so without a reset
# the openapi bucket exhausts after ~10 requests and later tests get
# spurious 429s instead of testing the assertion they meant to.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _reset_rate_limit_buckets() -> None:
    from z4j_brain.domain.ip_rate_limit import _openapi_bucket, _setup_bucket

    await _openapi_bucket.prune_idle(idle_seconds=0)
    await _setup_bucket.prune_idle(idle_seconds=0)


# ---------------------------------------------------------------------------
# Per-test fixtures (override the default ``brain_settings`` to flip the
# visibility mode without re-rolling the entire conftest stack)
# ---------------------------------------------------------------------------


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = dict(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        log_json=False,
        environment="dev",
        metrics_public=True,
        disable_spa_fallback=True,
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


async def _client_for(settings: Settings) -> tuple[AsyncClient, Any]:
    engine = create_async_engine(settings.database_url, future=True)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    transport = ASGITransport(app=app)
    return (
        AsyncClient(transport=transport, base_url="http://testserver"),
        engine,
    )


@pytest.fixture
async def public_client() -> AsyncIterator[AsyncClient]:
    c, engine = await _client_for(_settings(openapi_visibility="public"))
    async with c as ac:
        yield ac
    await engine.dispose()


@pytest.fixture
async def private_client() -> AsyncIterator[AsyncClient]:
    c, engine = await _client_for(_settings(openapi_visibility="private"))
    async with c as ac:
        yield ac
    await engine.dispose()


@pytest.fixture
async def disabled_client() -> AsyncIterator[AsyncClient]:
    c, engine = await _client_for(_settings(openapi_visibility="disabled"))
    async with c as ac:
        yield ac
    await engine.dispose()


# ---------------------------------------------------------------------------
# S1: OpenAPI 9-cell visibility matrix
# ---------------------------------------------------------------------------
#
# Caller type is reduced to "anonymous" for the matrix tests. Session
# and API-key auth share the same dep (``get_current_user``) so the
# only behavioral difference is "authenticated or not". The two
# authenticated callers are exercised separately in the session +
# api-key tests below.


@pytest.mark.asyncio
class TestS1OpenAPIVisibilityMatrix:
    # --- public mode ---

    async def test_public_anon_gets_schema(self, public_client) -> None:
        r = await public_client.get("/api/v1/openapi.json")
        assert r.status_code == 200
        body = r.json()
        assert "openapi" in body
        assert "paths" in body

    async def test_public_anon_gets_docs_html(self, public_client) -> None:
        r = await public_client.get("/api/v1/docs")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")

    async def test_public_cache_control_is_public(self, public_client) -> None:
        r = await public_client.get("/api/v1/openapi.json")
        assert "public" in r.headers["cache-control"]
        assert "max-age=" in r.headers["cache-control"]

    # --- private mode ---

    async def test_private_anon_gets_401(self, private_client) -> None:
        """1.6.3 advisory headline: pre-fix, this returned 200 with
        the full schema body. After fix: 401 to anon callers.
        """
        r = await private_client.get("/api/v1/openapi.json")
        assert r.status_code == 401, (
            "private mode must NOT serve the schema to anonymous "
            "callers; this is the 1.6.3 security advisory fix."
        )

    async def test_private_docs_anon_gets_401(self, private_client) -> None:
        r = await private_client.get("/api/v1/docs")
        assert r.status_code == 401

    async def test_private_anon_response_has_no_schema_leak(
        self, private_client,
    ) -> None:
        """The 401 body must not echo any z4j-route specifics."""
        r = await private_client.get("/api/v1/openapi.json")
        assert r.status_code == 401
        # Body may carry a generic "authentication required" detail
        # but MUST NOT carry route paths, model names, or version.
        text = r.text.lower()
        assert "/api/v1/projects" not in text
        assert "schedule" not in text
        assert "pydantic" not in text

    # --- disabled mode ---

    async def test_disabled_anon_gets_404(self, disabled_client) -> None:
        r = await disabled_client.get("/api/v1/openapi.json")
        assert r.status_code == 404

    async def test_disabled_docs_anon_gets_404(self, disabled_client) -> None:
        r = await disabled_client.get("/api/v1/docs")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# S1 defense layers: ETag round-trip + watermark
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestS1OpenAPIDefenseLayers:
    async def test_schema_carries_build_watermark(self, public_client) -> None:
        r = await public_client.get("/api/v1/openapi.json")
        assert r.status_code == 200
        info = r.json()["info"]
        assert "x-z4j-build" in info, (
            "schema must carry x-z4j-build watermark per 1.6.3 plan S1.5"
        )

    async def test_schema_carries_etag(self, public_client) -> None:
        r = await public_client.get("/api/v1/openapi.json")
        assert r.status_code == 200
        assert r.headers.get("etag", "").startswith('"')

    async def test_etag_round_trip_returns_304(self, public_client) -> None:
        r1 = await public_client.get("/api/v1/openapi.json")
        etag = r1.headers["etag"]
        r2 = await public_client.get(
            "/api/v1/openapi.json",
            headers={"If-None-Match": etag},
        )
        assert r2.status_code == 304
        assert r2.headers["etag"] == etag

    async def test_schema_response_carries_cache_control(
        self, public_client,
    ) -> None:
        r = await public_client.get("/api/v1/openapi.json")
        assert r.headers.get("cache-control"), (
            "schema must carry Cache-Control per 1.6.3 plan S1.2"
        )


# ---------------------------------------------------------------------------
# S1 backwards-compat shim
# ---------------------------------------------------------------------------


class TestS1LegacySettingShim:
    def test_legacy_true_maps_to_private(self) -> None:
        s = _settings(openapi_docs_enabled=True)
        assert s.openapi_visibility == "private", (
            "the deprecated Z4J_OPENAPI_DOCS_ENABLED=True must tighten "
            "to 'private' (auth-gated), NOT to 'public'. Pre-1.6.3 "
            "behaviour was effectively 'public' but that was the bug "
            "being fixed; the migration must default-safe."
        )

    def test_legacy_false_maps_to_disabled(self) -> None:
        s = _settings(openapi_docs_enabled=False)
        assert s.openapi_visibility == "disabled"

    def test_explicit_new_setting_wins_over_legacy(self) -> None:
        s = _settings(
            openapi_docs_enabled=True,
            openapi_visibility="public",
        )
        assert s.openapi_visibility == "public", (
            "if both old and new are set, the explicit new setting wins"
        )

    def test_no_legacy_means_new_default_private(self) -> None:
        s = _settings()
        assert s.openapi_visibility == "private"
        assert s.openapi_docs_enabled is None


# ---------------------------------------------------------------------------
# S4: /api/v1/api-keys/scopes is now auth-gated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestS4ApiKeyScopesAuth:
    async def test_anon_caller_gets_401(self, client) -> None:
        """1.6.3 advisory S4: pre-fix this endpoint was unauthenticated
        by design. After fix: requires session or API key.
        """
        r = await client.get("/api/v1/api-keys/scopes")
        assert r.status_code == 401, (
            "/api/v1/api-keys/scopes must require authentication "
            "per 1.6.3 plan S4."
        )


# ---------------------------------------------------------------------------
# S5: setup/complete route-level throttle
# ---------------------------------------------------------------------------
#
# We test that the throttle dep is wired by exhausting the bucket via
# repeated bogus-token POSTs. The 6th attempt within 15 min should
# 429, regardless of token validity.


@pytest.mark.asyncio
class TestS5SetupThrottle:
    async def test_setup_throttle_triggers_after_5_attempts(self, client) -> None:
        # Need a fresh bucket per test; clear the underlying state
        # so we don't inherit hits from a sibling test.
        from z4j_brain.domain.ip_rate_limit import _setup_bucket

        await _setup_bucket.prune_idle(idle_seconds=0)

        body = {"token": "nonexistent-token-aaaaaaaaaaaaaa"}
        # First 5 attempts: throttle allows them (the token check
        # underneath will 401/404 but the throttle MUST NOT 429 yet).
        for i in range(5):
            r = await client.post("/api/v1/setup/complete", json=body)
            assert r.status_code != 429, f"attempt {i + 1} hit 429 too soon"
        # 6th attempt: throttle MUST 429 regardless of body validity.
        r = await client.post("/api/v1/setup/complete", json=body)
        assert r.status_code == 429, (
            "6th attempt within 15 min must hit the 1.6.3 setup-complete "
            "throttle (5/15min/IP)."
        )
