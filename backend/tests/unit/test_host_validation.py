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


class TestStripPortMalformedR4M1:
    """1.6.5 audit R4-M1 defense-in-depth.

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


@pytest.mark.asyncio
class TestHostValidationDispatchR5M1:
    """1.6.5 round-5 audit (R5-M1) regression.

    R4-M1 hardened ``_strip_port`` to collapse malformed hosts to
    "" but the dispatcher's pre-R5 check ``if host and host not in
    allowed`` skipped rejection on the empty side, so a present-
    but-malformed Host header reached the app. R5-M1 fixed this:
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
        self, client,
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
        self, client,
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
