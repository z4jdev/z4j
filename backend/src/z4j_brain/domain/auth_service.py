"""Login orchestration with timing normalisation, lockout, sessions.

The single entry point is :meth:`AuthService.login`. It runs the
constant-time path:

1. Canonicalise the email.
2. Look up the user (one indexed query).
3. Pick the verify target: real hash if user exists, dummy hash
   otherwise. Both branches go through ``hasher.verify`` so the
   wall-clock time is comparable.
4. Compute the boolean ``ok`` from password match + active +
   not-locked.
5. Hold the response time to at least ``login_min_duration_ms``
   to mask DB-query and argon2 variance.
6. On failure: increment lockout counter (if user exists), apply
   exponential backoff sleep, write audit row, raise
   :class:`AuthenticationError` with the SAME code regardless of
   reason.
7. On success: reset lockout counter, rehash if needed, mint a
   session row, write audit row, return the session.

Every branch is audited. Every branch returns the same shape on
failure. Every branch waits the same minimum time.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from z4j_brain.auth.sessions import aware_utc
from z4j_brain.errors import AuthenticationError
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.auth.sessions import SessionPayload
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        SessionRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


def canonicalize_email(raw: str) -> str:
    """Canonicalise an email address for storage / lookup.

    Hardened against three classes of homoglyph / case-folding
    bypasses that the previous ``NFC + .lower()`` implementation
    let through:

    1. **NFKC compatibility decomposition.** Maps full-width and
       compatibility-form characters to their canonical ASCII
       equivalents before any other step. ``Ｕｓｅｒ@gmail.com``
       (full-width 'User' in U+FF21..U+FF7A) used to be a
       different identifier from ``user@gmail.com``; NFKC folds
       both to the same string. NFC alone preserves the
       full-width forms.
    2. **``str.casefold()`` instead of ``str.lower()``.**
       Case-folding handles non-ASCII letters that lower-case
       cannot collapse - e.g. German ``ß`` casefolds to ``"ss"``,
       Greek lower-case sigma at end-of-word folds to its
       canonical form. ``.lower()`` leaves both alone, opening a
       collision-free registration path.
    3. **IDNA encoding on the domain.** International domains
       (``xn--`` punycode) and Unicode-form domains
       (``café.example``) used to register as different
       identities. We normalise to the punycode A-label so any
       form of the same registered domain collapses to one
       row. Falls back to ``casefold`` on IDNA failure so
       legitimately invalid domains still surface as a
       validation error rather than a 500.
    """
    import unicodedata

    if not raw:
        raise ValueError("email is required")
    cleaned = unicodedata.normalize("NFKC", raw).strip()
    if "@" not in cleaned:
        raise ValueError("invalid email")
    local, _, domain = cleaned.rpartition("@")
    if not local or not domain:
        raise ValueError("invalid email")
    if "@" in local:
        raise ValueError("invalid email")

    # IDNA-encode the domain so Unicode forms collapse to their
    # punycode A-label. ``encode("idna")`` raises
    # ``UnicodeError`` on syntactically broken domains - we
    # surface those as a validation error so the caller sees
    # the user-facing message rather than a 500.
    try:
        domain_idna = domain.casefold().encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid email domain: {exc}") from None

    # ``casefold`` instead of ``.lower()`` - see docstring.
    return f"{local.casefold()}@{domain_idna}"


class AuthService:
    """Login / logout / current-user orchestration.

    Construct once per request (or once per process - it has no
    per-request state). Hold a reference to a :class:`PasswordHasher`
    and an :class:`AuditService`; pass repositories per call so the
    audit row participates in the same transaction as the login
    bookkeeping.
    """

    __slots__ = (
        "_settings",
        "_hasher",
        "_audit",
    )

    def __init__(
        self,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
    ) -> None:
        self._settings = settings
        self._hasher = hasher
        self._audit = audit

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(
        self,
        *,
        users: UserRepository,
        sessions: SessionRepository,
        audit_log: AuditLogRepository,
        email_raw: str,
        password_raw: str,
        ip: str,
        user_agent: str | None,
    ) -> SessionRow:
        """Authenticate a user and mint a session.

        Raises:
            AuthenticationError: with code ``invalid_credentials``
                for ANY failure mode (wrong email, wrong password,
                inactive account, locked account, malformed email).
                The caller MUST NOT distinguish - the response
                shape is identical on all paths.
        """
        start = time.monotonic()
        event_id = uuid.uuid4()

        # Canonicalize. Malformed email is treated like wrong-email
        # - same audit row, same response, no leak of "this is
        # the registration form, that is the login form".
        try:
            email = canonicalize_email(email_raw)
        except ValueError:
            email = ""

        user = await users.get_by_email(email) if email else None
        target_hash = user.password_hash if user else self._hasher.dummy_hash

        # Constant-time path. ``verify`` is the expensive bit; we
        # always run it, even when we know the user is missing.
        password_ok = self._hasher.verify(target_hash, password_raw)

        is_locked = (
            user is not None
            and user.locked_until is not None
            and aware_utc(user.locked_until) > datetime.now(UTC)
        )
        ok = (
            password_ok
            and user is not None
            and user.is_active
            and not is_locked
        )

        # Hold the response duration before any branching. Mask DB
        # variance, argon2 variance, cache hit/miss.
        await self._hold_minimum_response_time(start)

        if not ok:
            await self._handle_failed_login(
                users=users,
                audit_log=audit_log,
                user=user,
                email=email,
                ip=ip,
                user_agent=user_agent,
                event_id=event_id,
            )
            raise AuthenticationError(
                "invalid_credentials",
                details={"reason": "invalid_credentials"},
            )

        # Success path.
        assert user is not None
        await users.reset_failed_login(user.id)
        if self._hasher.needs_rehash(user.password_hash):
            new_hash = self._hasher.hash(password_raw)
            await users.update_password_hash(
                user.id,
                new_hash,
                password_changed=False,
            )

        from z4j_brain.auth.sessions import generate_csrf_token

        csrf = generate_csrf_token()
        expires_at = datetime.now(UTC) + timedelta(
            seconds=self._settings.session_absolute_lifetime_seconds,
        )
        session_row = await sessions.create(
            user_id=user.id,
            csrf_token=csrf,
            expires_at=expires_at,
            ip_at_issue=ip,
            user_agent_at_issue=user_agent,
        )
        await self._audit.record(
            audit_log,
            action="auth.login",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            event_id=event_id,
            user_id=user.id,
            source_ip=ip,
            user_agent=user_agent,
            metadata={
                # Email intentionally omitted - the audit row's
                # ``user_id`` (FK to users) is enough to correlate
                # back to the account, and email is mildly sensitive
                # PII we don't want sitting in plaintext in audit
                # exports.
                "session_id": str(session_row.id),
            },
        )
        return session_row

    async def _handle_failed_login(
        self,
        *,
        users: UserRepository,
        audit_log: AuditLogRepository,
        user: User | None,
        email: str,
        ip: str,
        user_agent: str | None,
        event_id: uuid.UUID,
    ) -> None:
        """Lockout bookkeeping + backoff sleep + audit row.

        Runs after the constant-time path has finished, so it does
        NOT contribute to the timing oracle. The audit row is
        always written; the sleep happens after the audit but
        before the caller raises.
        """
        # Reason metadata used in the audit row but NEVER in the
        # response.
        reason = (
            "invalid_credentials"
            if user is None
            else (
                "inactive"
                if not user.is_active
                else (
                    "locked"
                    if user.locked_until and aware_utc(user.locked_until) > datetime.now(UTC)
                    else "invalid_credentials"
                )
            )
        )

        if user is not None:
            updated = await users.record_failed_login(
                user.id,
                ip=ip,
                lockout_threshold=self._settings.login_lockout_threshold,
                lockout_duration_seconds=self._settings.login_lockout_duration_seconds,
            )
            if updated is not None:
                await asyncio.sleep(
                    min(
                        self._settings.login_backoff_max_seconds,
                        self._settings.login_backoff_base_seconds
                        * (2 ** min(updated.failed_login_count, 16)),
                    ),
                )

        # Audit row. Email is always recorded for forensics; the
        # stdout log path respects ``log_login_email``.
        await self._audit.record(
            audit_log,
            action="auth.login",
            target_type="user",
            target_id=str(user.id) if user else None,
            result="failed",
            outcome="deny",
            event_id=event_id,
            user_id=user.id if user else None,
            source_ip=ip,
            user_agent=user_agent,
            metadata={
                "email": email,
                "reason": reason,
            },
        )

    async def _hold_minimum_response_time(self, start_monotonic: float) -> None:
        """Sleep until at least ``login_min_duration_ms`` has elapsed."""
        target_seconds = self._settings.login_min_duration_ms / 1000.0
        elapsed = time.monotonic() - start_monotonic
        wait = target_seconds - elapsed
        if wait > 0:
            await asyncio.sleep(wait)

    # ------------------------------------------------------------------
    # Session resolution (used by the request-time auth dep)
    # ------------------------------------------------------------------

    async def resolve_session(
        self,
        *,
        users: UserRepository,
        sessions: SessionRepository,
        session_id: uuid.UUID,
    ) -> tuple[SessionRow, User] | None:
        """Look up a session by id and validate every revocation rule.

        Returns ``(session_row, user)`` if the session is live and
        usable; ``None`` otherwise. ``last_seen_at`` is bumped on
        success - single indexed UPDATE per request.
        """
        from z4j_brain.auth.sessions import is_session_live

        session_row = await sessions.get(session_id)
        if session_row is None:
            return None
        user = await users.get(session_row.user_id)
        if user is None:
            await sessions.revoke(session_row.id, reason="user_missing")
            return None
        if not user.is_active:
            await sessions.revoke(session_row.id, reason="deactivated")
            return None
        if not is_session_live(
            session_row,
            now=datetime.now(UTC),
            idle_timeout_seconds=self._settings.session_idle_timeout_seconds,
            user_password_changed_at=user.password_changed_at,
        ):
            return None
        await sessions.touch(session_row.id)
        return session_row, user

    async def logout(
        self,
        *,
        sessions: SessionRepository,
        audit_log: AuditLogRepository,
        session_row: SessionRow,
        user: User,
        ip: str,
        user_agent: str | None,
    ) -> None:
        """Revoke a session and write the audit row."""
        await sessions.revoke(session_row.id, reason="logout")
        await self._audit.record(
            audit_log,
            action="auth.logout",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            user_id=user.id,
            source_ip=ip,
            user_agent=user_agent,
            metadata={"session_id": str(session_row.id)},
        )


# ProjectRole is re-exported here purely so the auth_service module
# is the single place that knows the role taxonomy. Removed when
# B5 lands and the policy engine takes over.
__all__ = ["AuthService", "ProjectRole", "canonicalize_email"]
