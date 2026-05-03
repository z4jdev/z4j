"""Dashboard WebSocket Origin checks."""

from __future__ import annotations

import secrets

from z4j_brain.settings import Settings
from z4j_brain.websocket.dashboard_gateway import _origin_allowed


def _settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    values = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "production",
        "allowed_hosts": ["z4j.example.com"],
        "public_url": "https://z4j.example.com",
        "log_json": False,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


class TestDashboardWsOrigin:
    def test_public_url_origin_allowed(self) -> None:
        settings = _settings()
        assert _origin_allowed(
            "https://z4j.example.com",
            settings=settings,
        )

    def test_default_https_port_normalized(self) -> None:
        settings = _settings()
        assert _origin_allowed(
            "https://z4j.example.com:443",
            settings=settings,
        )

    def test_cross_site_origin_rejected(self) -> None:
        settings = _settings()
        assert not _origin_allowed(
            "https://evil.example",
            settings=settings,
        )

    def test_configured_cors_origin_allowed(self) -> None:
        settings = _settings(cors_origins=["https://ops.example.com"])
        assert _origin_allowed(
            "https://ops.example.com",
            settings=settings,
        )

    def test_missing_origin_only_allowed_in_dev(self) -> None:
        prod = _settings()
        dev = _settings(
            environment="dev",
            allowed_hosts=[],
            public_url="http://localhost:7700",
        )
        assert not _origin_allowed(None, settings=prod)
        assert _origin_allowed(None, settings=dev)
