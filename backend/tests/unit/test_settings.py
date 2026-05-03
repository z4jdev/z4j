"""Settings validation tests."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from z4j_brain.settings import Settings


def _base_kwargs() -> dict[str, str]:
    return {
        "database_url": "postgresql+asyncpg://u:p@h/d?sslmode=require",
        "secret": "x" * 48,
        "session_secret": "y" * 48,
        "environment": "dev",
    }


class TestSecretLength:
    def test_short_secret_rejected(self) -> None:
        kwargs = _base_kwargs()
        kwargs["secret"] = "tooshort"
        with pytest.raises(ValidationError) as exc_info:
            Settings(**kwargs)  # type: ignore[arg-type]
        # The error message must NOT echo the actual value.
        msg = str(exc_info.value)
        assert "tooshort" not in msg
        assert "32 bytes" in msg

    def test_short_session_secret_rejected(self) -> None:
        kwargs = _base_kwargs()
        kwargs["session_secret"] = "x" * 16
        with pytest.raises(ValidationError):
            Settings(**kwargs)  # type: ignore[arg-type]


class TestDatabaseUrl:
    def test_sync_postgres_url_rejected(self) -> None:
        kwargs = _base_kwargs()
        kwargs["database_url"] = "postgresql://u:p@h/d"
        with pytest.raises(ValidationError, match="asyncpg"):
            Settings(**kwargs)  # type: ignore[arg-type]

    def test_async_postgres_url_accepted(self) -> None:
        Settings(**_base_kwargs())  # type: ignore[arg-type]

    def test_aiosqlite_url_accepted_for_tests(self) -> None:
        kwargs = _base_kwargs()
        kwargs["database_url"] = "sqlite+aiosqlite:///:memory:"
        Settings(**kwargs)  # type: ignore[arg-type]


class TestDefaults:
    def test_defaults_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Scrub Z4J_* env overrides so this test actually measures
        # Python-level defaults. The dev container sets several
        # Z4J_* vars (log level, require_db_ssl, ...) that pydantic-
        # settings otherwise surfaces as "the default".
        for key in list(os.environ):
            if key.startswith("Z4J_"):
                monkeypatch.delenv(key, raising=False)
        s = Settings(**_base_kwargs())  # type: ignore[arg-type]
        assert s.bind_port == 7700
        assert s.environment == "dev"  # _base_kwargs sets dev for tests
        assert s.log_level == "INFO"
        assert s.metrics_enabled is True
        assert s.first_boot_token_ttl_seconds == 900
        assert s.session_idle_timeout_seconds == 1800
        assert s.login_lockout_threshold == 10
        assert s.cors_allow_credentials is True
