"""Tests for ``z4j_brain.middleware.host_validation``."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
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
