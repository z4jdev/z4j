"""Tests for the security invariants on Settings."""

from __future__ import annotations

import pytest
from z4j_brain.settings import ConfigError, Settings


def _kw(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "database_url": "postgresql+asyncpg://u:p@h/d?sslmode=require",
        "secret": "x" * 48,
        "session_secret": "y" * 48,
        "audit_chain_secret": "a" * 48,
        "environment": "production",
        "public_url": "https://z4j.example.com",
        "allowed_hosts": ["z4j.example.com"],
        # Explicit so the test does not pick up Z4J_REQUIRE_DB_SSL
        # from the dev-container env, which is ``false``.
        "require_db_ssl": True,
    }
    base.update(overrides)
    return base


class TestProductionGuards:
    def test_production_with_https_and_allowed_hosts_ok(self) -> None:
        Settings(**_kw())  # type: ignore[arg-type]

    def test_production_without_allowed_hosts_rejected(self) -> None:
        with pytest.raises(ConfigError, match="allowed_hosts"):
            Settings(**_kw(allowed_hosts=[]))  # type: ignore[arg-type]

    def test_production_without_https_rejected(self) -> None:
        with pytest.raises(ConfigError, match="https"):
            Settings(**_kw(public_url="http://z4j.example.com"))  # type: ignore[arg-type]

    def test_production_db_url_without_sslmode_rejected(self) -> None:
        with pytest.raises(ConfigError, match="sslmode"):
            Settings(  # type: ignore[arg-type]
                **_kw(database_url="postgresql+asyncpg://u:p@h/d"),
            )

    def test_production_db_url_with_sslmode_disable_rejected(self) -> None:
        with pytest.raises(ConfigError, match="sslmode"):
            Settings(  # type: ignore[arg-type]
                **_kw(
                    database_url="postgresql+asyncpg://u:p@h/d?sslmode=disable",
                ),
            )

    @pytest.mark.parametrize("mode", ["allow", "prefer", "disable", ""])
    def test_production_db_url_with_non_strict_sslmode_rejected(
        self,
        mode: str,
    ) -> None:
        with pytest.raises(ConfigError, match="sslmode"):
            Settings(  # type: ignore[arg-type]
                **_kw(
                    database_url=f"postgresql+asyncpg://u:p@h/d?sslmode={mode}",
                ),
            )

    @pytest.mark.parametrize(
        "tls_query",
        [
            "sslmode=require",
            "sslmode=verify-ca&sslrootcert=/run/secrets/postgres-ca.pem",
            "sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem",
        ],
    )
    def test_production_db_url_with_strict_sslmode_allowed(self, tls_query: str) -> None:
        Settings(  # type: ignore[arg-type]
            **_kw(database_url=f"postgresql+asyncpg://u:p@h/d?{tls_query}"),
        )

    @pytest.mark.parametrize("mode", ["verify-ca", "verify-full"])
    def test_verifying_db_tls_requires_explicit_root(self, mode: str) -> None:
        with pytest.raises(ConfigError, match="explicit sslrootcert"):
            Settings(  # type: ignore[arg-type]
                **_kw(database_url=f"postgresql+asyncpg://u:p@h/d?sslmode={mode}"),
            )

    def test_production_db_url_with_duplicate_sslmode_rejected(self) -> None:
        with pytest.raises(ConfigError, match="exactly one sslmode"):
            Settings(  # type: ignore[arg-type]
                **_kw(
                    database_url=("postgresql+asyncpg://u:p@h/d?sslmode=require&sslmode=prefer"),
                ),
            )

    def test_production_can_disable_db_ssl_check(self) -> None:
        Settings(  # type: ignore[arg-type]
            **_kw(
                database_url="postgresql+asyncpg://u:p@h/d?sslmode=prefer",
                require_db_ssl=False,
            ),
        )

    def test_effective_ws_frame_limit_uses_smaller_compatibility_cap(self) -> None:
        settings = Settings(  # type: ignore[arg-type]
            **_kw(
                max_ws_frame_bytes=32_768,
                ws_max_frame_bytes=65_536,
            ),
        )
        assert settings.effective_ws_max_frame_bytes == 32_768

    def test_effective_ws_frame_limit_uses_smaller_primary_cap(self) -> None:
        settings = Settings(  # type: ignore[arg-type]
            **_kw(
                max_ws_frame_bytes=131_072,
                ws_max_frame_bytes=65_536,
            ),
        )
        assert settings.effective_ws_max_frame_bytes == 65_536


class TestCorsGuards:
    def test_wildcard_with_credentials_rejected(self) -> None:
        with pytest.raises(ConfigError, match="cors_origins"):
            Settings(  # type: ignore[arg-type]
                **_kw(
                    cors_origins=["*"],
                    cors_allow_credentials=True,
                ),
            )

    def test_wildcard_without_credentials_ok(self) -> None:
        Settings(  # type: ignore[arg-type]
            **_kw(
                cors_origins=["*"],
                cors_allow_credentials=False,
            ),
        )


class TestDevGuards:
    def test_dev_relaxes_allowed_hosts(self) -> None:
        Settings(  # type: ignore[arg-type]
            database_url="sqlite+aiosqlite:///:memory:",
            secret="x" * 48,
            session_secret="y" * 48,
            environment="dev",
        )

    def test_dev_relaxes_https(self) -> None:
        Settings(  # type: ignore[arg-type]
            database_url="sqlite+aiosqlite:///:memory:",
            secret="x" * 48,
            session_secret="y" * 48,
            environment="dev",
            public_url="http://localhost:7700",
        )

    def test_dev_relaxes_db_ssl(self) -> None:
        Settings(  # type: ignore[arg-type]
            database_url="postgresql+asyncpg://u:p@h/d",  # no sslmode!
            secret="x" * 48,
            session_secret="y" * 48,
            environment="dev",
            public_url="http://localhost:7700",
        )
