"""B9 regression: the dashboard WebSocket must enforce the second-factor
gate, not just the enrollment-enforcement policy.

REST 403s a password-only session (MFA enrolled, ``mfa_verified_at IS
NULL``) everywhere but the verify allowlist. The push channel
(``/ws/dashboard``) previously only checked ``evaluate_mfa_enforcement``
(the ENROLLMENT policy, which returns not-blocked for an already-enrolled
user) and discarded the SessionRow, so ``mfa_verified_at`` was invisible.
A stolen-password session could then subscribe to the live change stream
without ever presenting the second factor. ``_mfa_blocks_dashboard`` closes
that gap; these tests pin its truth table.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from types import SimpleNamespace

from z4j_brain.settings import Settings
from z4j_brain.websocket.dashboard_gateway import _mfa_blocks_dashboard


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


def _user(*, enrolled: bool) -> SimpleNamespace:
    return SimpleNamespace(
        mfa_secret_encrypted=b"ct" if enrolled else None,
        mfa_enrolled_at=datetime.now(UTC) if enrolled else None,
        mfa_enforcement_started_at=None,
    )


def _session(*, verified: bool) -> SimpleNamespace:
    return SimpleNamespace(
        mfa_verified_at=datetime.now(UTC) if verified else None,
    )


def test_password_only_session_with_mfa_enrolled_is_blocked() -> None:
    """The exact bypass: enrolled user, session never passed the second
    factor. Must be blocked (the fix)."""
    blocked = _mfa_blocks_dashboard(
        user=_user(enrolled=True),
        session_row=_session(verified=False),
        settings=_settings(),
    )
    assert blocked is True


def test_verified_session_with_mfa_enrolled_is_allowed() -> None:
    blocked = _mfa_blocks_dashboard(
        user=_user(enrolled=True),
        session_row=_session(verified=True),
        settings=_settings(),
    )
    assert blocked is False


def test_user_without_mfa_is_allowed() -> None:
    """No enrolled second factor -> the verification gate is a no-op
    (enrollment enforcement is a separate policy)."""
    blocked = _mfa_blocks_dashboard(
        user=_user(enrolled=False),
        session_row=_session(verified=False),
        settings=_settings(),
    )
    assert blocked is False
