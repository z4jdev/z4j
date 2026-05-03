"""R6 M1 regression: Bearer auth must not crash when the API key's
``expires_at`` column comes back naive (SQLite TIMESTAMP round-trip
loses tzinfo), even though we stored a tz-aware value."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


class _FakeKey:
    """Minimal stand-in for ``ApiKey`` with the only two fields the
    auth path reads during expiry check."""

    def __init__(self, *, expires_at):
        self.revoked_at = None
        self.expires_at = expires_at


def _check_expires(row: _FakeKey) -> str | None:
    """Re-implements the expiry branch of ``_resolve_bearer_user``
    (``api/deps.py``) so we can unit-test the tz-coercion without a
    full FastAPI + DB fixture. Returns ``None`` when the key is
    still valid, or the AuthenticationError reason otherwise.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    now = _dt.now(_UTC)
    if row.revoked_at is not None:
        return "revoked"
    expires_at = row.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=_UTC)
        if expires_at <= now:
            return "expired"
    return None


class TestExpiresAtTzCoercion:
    """Aware + naive future-dated ``expires_at`` must both pass."""

    def test_aware_future_accepted(self) -> None:
        row = _FakeKey(expires_at=datetime.now(UTC) + timedelta(days=30))
        assert _check_expires(row) is None

    def test_naive_future_accepted(self) -> None:
        """SQLite round-trip - naive datetime treated as UTC."""
        row = _FakeKey(
            expires_at=(datetime.now(UTC) + timedelta(days=30)).replace(
                tzinfo=None,
            ),
        )
        assert _check_expires(row) is None

    def test_naive_past_rejected(self) -> None:
        row = _FakeKey(
            expires_at=(datetime.now(UTC) - timedelta(days=1)).replace(
                tzinfo=None,
            ),
        )
        assert _check_expires(row) == "expired"

    def test_aware_past_rejected(self) -> None:
        row = _FakeKey(expires_at=datetime.now(UTC) - timedelta(days=1))
        assert _check_expires(row) == "expired"

    def test_no_expiry_accepted(self) -> None:
        row = _FakeKey(expires_at=None)
        assert _check_expires(row) is None

    def test_naive_comparison_would_crash_without_coercion(self) -> None:
        """Documents the pre-R6 M1 bug: raw aware-vs-naive compare
        raises ``TypeError``. If the coercion is ever removed from
        the real auth path, _this_ test still passes (it runs the
        new logic) but the real auth handler would regress. The
        test captures the intent so a reviewer spots the coupling."""
        naive = (datetime.now(UTC) + timedelta(days=1)).replace(tzinfo=None)
        aware = datetime.now(UTC)
        with pytest.raises(TypeError):
            # This is the raw comparison the old code did.
            _ = naive <= aware  # noqa: B015


class TestAuthDepsActualImplementationCoerces:
    """Pin the real auth path - read the module source and confirm
    the ``expires_at.replace(tzinfo=UTC)`` coercion is there."""

    def test_deps_source_has_tz_coercion(self) -> None:
        import inspect

        from z4j_brain.api import deps

        src = inspect.getsource(deps._resolve_bearer_user)
        assert "expires_at.replace(tzinfo=UTC)" in src or (
            "expires_at.replace(tzinfo=" in src
        ), (
            "R6 M1 regression: _resolve_bearer_user must coerce a naive "
            "expires_at to UTC before comparing to datetime.now(UTC)"
        )
