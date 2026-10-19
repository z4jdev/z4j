"""Tests for ``z4j_brain.middleware.host_validation``."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.main import create_app
from z4j_brain.middleware.host_validation import HostValidationMiddleware
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.settings import Settings


class TestPersistedAllowedHosts:
    def test_read_preserves_first_spelling_and_deduplicates_case_insensitively(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from z4j_brain import allowed_hosts

        path = tmp_path / "allowed-hosts"
        path.write_text("Example.COM\nexample.com\nOther.example\n", encoding="utf-8")
        monkeypatch.setattr(allowed_hosts, "get_path", lambda: path)

        assert allowed_hosts.read_persisted() == ["Example.COM", "Other.example"]

    def test_failed_replace_preserves_existing_allow_list(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from z4j_brain import allowed_hosts

        path = tmp_path / "allowed-hosts"
        original = "# retained\nexisting.example\n"
        path.write_text(original, encoding="utf-8")
        monkeypatch.setattr(allowed_hosts, "get_path", lambda: path)

        def refuse_replace(_source: Path, _destination: Path) -> Path:
            raise OSError("simulated sharing violation")

        monkeypatch.setattr(Path, "replace", refuse_replace)

        with pytest.raises(OSError, match="sharing violation"):
            allowed_hosts.write_persisted(["new.example"])

        assert path.read_text(encoding="utf-8") == original
        assert not path.with_suffix(path.suffix + ".tmp").exists()


class TestStripPort:
    def test_no_port(self) -> None:
        assert HostValidationMiddleware._strip_port("z4j.example.com") == "z4j.example.com"

    def test_port(self) -> None:
        assert HostValidationMiddleware._strip_port("z4j.example.com:7700") == "z4j.example.com"

    def test_ipv6_no_port(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]") == "[::1]"

    def test_ipv6_with_port(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]:7700") == "[::1]"


class TestStripPortMalformedR4M1:
    """1.6.5 audit defense-in-depth.

    The upstream Starlette CVE-2026-48710 (BadHost) is fixed by
    the >=1.0.1 floor in z4j's pyproject; these tests pin the
    in-app parser so a future Starlette regression cannot smuggle
    malformed hosts past the allow-list.
    """

    def test_host_with_path_separator_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil.com/admin:80") == ""

    def test_host_with_backslash_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil.com\\admin") == ""

    def test_host_with_whitespace_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil .com") == ""

    def test_host_with_tab_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil\t.com") == ""

    def test_host_with_newline_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil.com\nfoo") == ""

    def test_host_with_control_char_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil.com\x00") == ""

    def test_host_with_del_char_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("evil.com\x7f") == ""

    def test_nonnumeric_port_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("z4j.example.com:not-a-port") == ""

    def test_ipv6_with_nonnumeric_port_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]:abc") == ""

    def test_ipv6_with_garbage_after_bracket_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1]extra") == ""

    def test_unclosed_ipv6_bracket_collapses_to_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("[::1") == ""

    def test_empty_string_returns_empty(self) -> None:
        assert HostValidationMiddleware._strip_port("") == ""


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


@pytest.fixture
def prod_settings() -> Settings:
    """Production posture with a public-domain allow-list that does NOT
    include loopback -- the exact shape that made the container
    healthcheck (Host: 127.0.0.1) 400-reject before B2."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="production",
        public_url="https://z4j.example.com",
        allowed_hosts=["z4j.example.com"],
        log_json=False,
    )


@pytest.fixture
async def prod_client(prod_settings: Settings):
    engine = create_async_engine(
        prod_settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(prod_settings, engine=engine)
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://z4j.example.com") as ac:
        yield ac
    await engine.dispose()


async def _metrics_client(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, create_app(settings, engine=engine)


@pytest.mark.asyncio
class TestMetricsScrapeByAddress:
    """Prometheus scrapes a target by its address, so the Host it sends is the
    pod IP and port (Kubernetes ServiceMonitor) or the host IP, which a pinned
    allow-list never carries. Every scrape used to be a 400 ``invalid_host``.
    """

    async def _get(self, settings: Settings, host: str, token: str | None):
        from httpx import ASGITransport, AsyncClient

        engine, app = await _metrics_client(settings)
        try:
            headers = {"Host": host}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="https://z4j.example.com"
            ) as ac:
                return await ac.get("/metrics", headers=headers)
        finally:
            await engine.dispose()

    async def test_token_gated_scrape_by_pod_address_is_served(self, prod_settings) -> None:
        settings = prod_settings.model_copy(
            update={"metrics_auth_token": SecretStr("scrape-token-0123456789")}
        )
        r = await self._get(settings, "10.42.3.17:7700", "scrape-token-0123456789")
        assert r.status_code == 200, r.text
        assert "z4j_" in r.text

    async def test_token_gate_still_applies_to_the_exempt_scrape(self, prod_settings) -> None:
        settings = prod_settings.model_copy(
            update={"metrics_auth_token": SecretStr("scrape-token-0123456789")}
        )
        r = await self._get(settings, "10.42.3.17:7700", "wrong-token")
        assert r.status_code == 401

    async def test_public_metrics_keep_the_allow_list(self, prod_settings) -> None:
        # Unauthenticated /metrics stays behind Host validation, so a
        # DNS-rebinding page cannot read it through a foreign Host.
        settings = prod_settings.model_copy(update={"metrics_public": True})
        r = await self._get(settings, "10.42.3.17:7700", None)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_malformed_host_is_still_rejected_on_metrics(self, prod_settings) -> None:
        settings = prod_settings.model_copy(
            update={"metrics_auth_token": SecretStr("scrape-token-0123456789")}
        )
        r = await self._get(settings, "evil.com/admin", "scrape-token-0123456789")
        assert r.status_code == 400


@pytest.mark.asyncio
class TestHealthExemptionB2:
    """B2 regression: the container healthcheck probes
    ``http://127.0.0.1:7700/api/v1/health`` (Host: 127.0.0.1), but a
    production allow-list is pinned to the operator's public domain. The
    health subtree is exempt from the allow-list check so the probe
    succeeds and the container reports healthy (else Caddy never starts).
    Malformed hosts remain rejected on health; non-health routes remain
    fully validated.
    """

    async def test_health_allows_loopback_host_not_in_allowlist(self, prod_client) -> None:
        r = await prod_client.get("/api/v1/health", headers={"Host": "127.0.0.1"})
        assert r.status_code == 200

    async def test_health_still_rejects_malformed_host(self, prod_client) -> None:
        r = await prod_client.get("/api/v1/health", headers={"Host": "evil.com/admin"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_non_health_route_still_rejects_unknown_host(self, prod_client) -> None:
        # The exemption must NOT leak to real endpoints.
        r = await prod_client.get("/api/v1/projects", headers={"Host": "127.0.0.1"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"


@pytest.mark.asyncio
class TestHostValidationDev:
    async def test_localhost_allowed(self, client) -> None:
        # ASGITransport's default Host is testserver, which we
        # allow-list in dev mode automatically.
        r = await client.get("/api/v1/health")
        assert r.status_code == 200

    async def test_unknown_host_rejected(self, client) -> None:
        # Uses a NON-exempt path: the health subtree is exempt from the
        # allow-list check (B2), so an unknown well-formed Host must be
        # asserted against a normal route. Host validation runs before
        # routing, so the 400 fires regardless of the route's own auth.
        r = await client.get(
            "/api/v1/projects",
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


@pytest.mark.asyncio
class TestHostValidationDispatchR5M1:
    """1.6.5 round-5 audit regression.

    Hardened ``_strip_port`` to collapse malformed hosts to
    "" but the dispatcher's pre- check ``if host and host not in
    allowed`` skipped rejection on the empty side, so a present-
    but-malformed Host header reached the app. fixed this:
    a present Host header that does not survive _strip_port intact
    is now rejected with 400 ``invalid_host``.

    These are dispatch-level (full request round-trip) so a future
    contributor who tweaks the if-condition trips both layers: the
    parser tests AND the round-trip test.
    """

    async def test_host_with_path_separator_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "evil.com/admin:80"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_host_with_backslash_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "evil.com\\admin"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_host_with_nonnumeric_port_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "z4j.example.com:not-a-port"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_ipv6_with_garbage_after_bracket_rejected(
        self,
        client,
    ) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "[::1]extra"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_unclosed_ipv6_bracket_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "[::1"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_ipv6_with_nonnumeric_port_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "[::1]:abc"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_host_with_control_char_rejected(self, client) -> None:
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "evil.com\x00"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_host"

    async def test_malformed_response_does_not_leak_raw_header(
        self,
        client,
    ) -> None:
        """The 400 body must NOT echo the raw malformed Host header.

        The operator log gets the raw value (operator-only surface);
        the wire response only gets the minimal ``invalid_host`` body.
        Anything that reflects attacker-controlled bytes back to the
        wire would defeat the point of the minimal-rejection design.
        """
        r = await client.get(
            "/api/v1/health",
            headers={"Host": "evil.com/admin:80"},
        )
        assert r.status_code == 400
        body = r.text
        assert "evil.com/admin" not in body
        assert "<malformed>" not in body
