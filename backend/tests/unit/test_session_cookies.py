"""Tests for ``z4j_brain.auth.sessions`` (cookie codec + helpers)."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from z4j_brain.auth.sessions import (
    SESSION_COOKIE_NAME_DEV,
    SESSION_COOKIE_NAME_PROD,
    SessionCookieCodec,
    cookie_kwargs,
    cookie_name,
    generate_csrf_token,
    is_session_live,
)
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret="x" * 48,  # type: ignore[arg-type]
        session_secret="y" * 48,  # type: ignore[arg-type]
        environment="dev",
    )


class TestCodec:
    def test_round_trip(self, settings: Settings) -> None:
        codec = SessionCookieCodec(settings)
        sid = uuid.uuid4()
        encoded = codec.encode(sid)
        decoded = codec.decode(encoded, max_age_seconds=3600)
        assert decoded == sid

    def test_tampered_signature_returns_none(self, settings: Settings) -> None:
        codec = SessionCookieCodec(settings)
        encoded = codec.encode(uuid.uuid4())
        assert codec.decode(encoded[:-3] + "AAA", max_age_seconds=3600) is None

    def test_garbage_returns_none(self, settings: Settings) -> None:
        codec = SessionCookieCodec(settings)
        assert codec.decode("not-a-cookie", max_age_seconds=3600) is None

    def test_empty_returns_none(self, settings: Settings) -> None:
        codec = SessionCookieCodec(settings)
        assert codec.decode("", max_age_seconds=3600) is None

    def test_different_secret_rejects(self) -> None:
        s1 = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret="x" * 48,  # type: ignore[arg-type]
            session_secret="a" * 48,  # type: ignore[arg-type]
            environment="dev",
        )
        s2 = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret="x" * 48,  # type: ignore[arg-type]
            session_secret="b" * 48,  # type: ignore[arg-type]
            environment="dev",
        )
        c1 = SessionCookieCodec(s1)
        c2 = SessionCookieCodec(s2)
        encoded = c1.encode(uuid.uuid4())
        assert c2.decode(encoded, max_age_seconds=3600) is None


class TestCookieName:
    def test_prod_uses_host_prefix(self) -> None:
        assert cookie_name(environment="production") == SESSION_COOKIE_NAME_PROD
        assert cookie_name(environment="production").startswith("__Host-")

    def test_dev_drops_host_prefix(self) -> None:
        assert cookie_name(environment="dev") == SESSION_COOKIE_NAME_DEV
        assert not cookie_name(environment="dev").startswith("__Host-")


class TestCookieKwargs:
    def test_dev_secure_false(self) -> None:
        kw = cookie_kwargs(environment="dev", max_age_seconds=3600)
        assert kw["secure"] is False
        assert kw["httponly"] is True

    def test_production_secure_true(self) -> None:
        kw = cookie_kwargs(environment="production", max_age_seconds=3600)
        assert kw["secure"] is True
        assert kw["httponly"] is True
        assert kw["samesite"] == "lax"
        assert kw["path"] == "/"
        assert kw["domain"] is None


class TestCsrfGen:
    def test_token_length(self) -> None:
        # token_urlsafe(32) → ~43 char base64 string.
        for _ in range(20):
            assert len(generate_csrf_token()) >= 32

    def test_tokens_are_unique(self) -> None:
        seen = {generate_csrf_token() for _ in range(100)}
        assert len(seen) == 100


class TestIsSessionLive:
    def _row(self, **overrides: object) -> MagicMock:
        now = datetime.now(UTC)
        defaults = {
            "revoked_at": None,
            "expires_at": now + timedelta(hours=1),
            "last_seen_at": now,
            "issued_at": now - timedelta(minutes=5),
        }
        defaults.update(overrides)
        return MagicMock(**defaults)

    def test_live(self) -> None:
        row = self._row()
        assert is_session_live(
            row,
            now=datetime.now(UTC),
            idle_timeout_seconds=1800,
            user_password_changed_at=None,
        )

    def test_revoked(self) -> None:
        row = self._row(revoked_at=datetime.now(UTC))
        assert not is_session_live(
            row,
            now=datetime.now(UTC),
            idle_timeout_seconds=1800,
            user_password_changed_at=None,
        )

    def test_absolute_expiry(self) -> None:
        row = self._row(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert not is_session_live(
            row,
            now=datetime.now(UTC),
            idle_timeout_seconds=1800,
            user_password_changed_at=None,
        )

    def test_idle_timeout(self) -> None:
        row = self._row(
            last_seen_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert not is_session_live(
            row,
            now=datetime.now(UTC),
            idle_timeout_seconds=1800,
            user_password_changed_at=None,
        )

    def test_password_change_after_issue(self) -> None:
        now = datetime.now(UTC)
        row = self._row(issued_at=now - timedelta(hours=2))
        assert not is_session_live(
            row,
            now=now,
            idle_timeout_seconds=86400,
            user_password_changed_at=now - timedelta(minutes=10),
        )

    def test_password_change_before_issue(self) -> None:
        now = datetime.now(UTC)
        row = self._row(issued_at=now - timedelta(minutes=5))
        assert is_session_live(
            row,
            now=now,
            idle_timeout_seconds=86400,
            user_password_changed_at=now - timedelta(hours=2),
        )
