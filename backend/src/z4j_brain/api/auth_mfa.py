"""MFA enrollment, verification, disable, recovery-code regenerate.

The POST endpoints under ``/auth/mfa`` require an authenticated
session (``Depends(get_current_user)``). Successful verification and
enrollment completion stamp ``sessions.mfa_verified_at`` so the
sensitive-action gate treats the caller as "MFA-fresh".

In-progress enrollment is tracked directly on the user row:

  * ``mfa_secret_encrypted IS NOT NULL AND mfa_enrolled_at IS NULL``
    -> enrollment in progress (start was called, complete pending)
  * ``mfa_secret_encrypted IS NOT NULL AND mfa_enrolled_at IS NOT NULL``
    -> MFA is on
  * ``mfa_secret_encrypted IS NULL``
    -> no MFA

This avoids a separate ephemeral store and survives a brain restart
mid-flow. ``enroll-start`` conditionally replaces the exact state observed
by the request, so a concurrent start or completion cannot silently make a
returned secret stale. Re-enrollment of an already-enrolled user first
requires a fresh second-factor verification; a password-only stolen session
cannot replace the factor.

See ``docs/MFA-DESIGN.md`` for the full design + threat model.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update

from z4j_brain.api.deps import (
    enforce_fresh_mfa,
    get_audit_log_repo,
    get_client_ip,
    get_current_session,
    get_current_user,
    get_mfa_recovery_codes_repo,
    get_session,
    get_session_repo,
    get_settings,
    get_trusted_device_repo,
    get_user_repo,
    require_csrf,
    require_fresh_mfa,
)
from z4j_brain.auth.trusted_device import (
    clear_trust_cookie,
    derive_label_from_user_agent,
    hash_cookie_id,
    mint_cookie_id,
    set_trust_cookie,
)
from z4j_brain.domain.ip_rate_limit import require_mfa_verify_throttle
from z4j_brain.domain.mfa import (
    RECOVERY_CODE_PATTERN,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    provisioning_url,
    verify_recovery_code,
    verify_totp_code,
)
from z4j_brain.domain.mfa.recovery import (
    burn_one_argon2_cycle,
    normalize_recovery_code,
)
from z4j_brain.domain.mfa.totp import secret_to_base32
from z4j_brain.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitExceeded,
    ValidationError,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import TrustedDevice, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MfaRecoveryCodeRepository,
        SessionRepository,
        TrustedDeviceRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/auth/mfa", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EnrollStartResponse(BaseModel):
    secret_base32: str = Field(
        description=(
            "Raw secret, base32-encoded. Authenticator apps that "
            "cannot read the QR code's URL can be configured by "
            "typing this string."
        ),
    )
    provisioning_url: str = Field(
        description="otpauth:// URL the dashboard renders as a QR code.",
    )


class EnrollCompleteRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class EnrollCompleteResponse(BaseModel):
    recovery_codes: list[str] = Field(
        description=(
            "Single-use recovery codes, shown ONCE. Encourage the "
            "user to download and store them somewhere safe."
        ),
    )


class VerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=20)
    """Either a 6-digit TOTP code OR a normalised recovery code
    (``XXXX-XXXX-XXXX``). The body field is a single string; the
    brain detects the format and routes accordingly."""
    remember_device: bool = Field(
        default=False,
        description=(
            "If True, the brain mints a ``z4j_mfa_trust`` cookie "
            "whose hash is stored in a server-side row scoped to the "
            "user. A later login presenting that cookie skips the MFA "
            "second step until the cookie or server row "
            "expires (default 30 days; configurable via "
            "``Z4J_MFA_REMEMBER_DEVICE_DAYS``)."
        ),
    )

    @field_validator("code")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class VerifyResponse(BaseModel):
    ok: bool = True
    used_recovery_code: bool = Field(
        default=False,
        description=(
            "True when a recovery code was redeemed. The dashboard "
            "uses this to prompt the user to regenerate codes."
        ),
    )
    remaining_recovery_codes: int | None = None


class DisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=20)


class RegenerateResponse(BaseModel):
    recovery_codes: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _master_secret_bytes(settings: Settings) -> bytes:
    return settings.secret.get_secret_value().encode("utf-8")


def _previous_secrets_bytes(settings: Settings) -> list[bytes]:
    """Bytes form of every previous Z4J_SECRET still accepted for verify."""
    # ``all_secrets_for_verification`` returns the CURRENT secret first
    # plus every entry in Z4J_PREVIOUS_SECRETS. Drop the current value
    # (we already pass it as ``master_secret``) so the iterator only
    # carries rotated-out keys.
    full = settings.all_secrets_for_verification()
    current = _master_secret_bytes(settings)
    return [s for s in full if s != current]


async def _audit_verify_failure(
    *,
    audit_log: AuditLogRepository,
    settings: Settings,
    user_id: UUID,
    ip: str,
    reason: str,
    action: str = "user.mfa_verify_failed",
) -> None:
    """Record a failed MFA verify attempt in the HMAC-chained log.
    A brute-force attacker hitting the verify endpoint must leave
    a trail; without this row the per-IP throttle alone would let
    failed attempts vanish into a quiet 401.

    ``action`` distinguishes the surface: ``user.mfa_verify_failed``
    (the login step-up), ``user.mfa_disable_failed``, and
    ``user.mfa_enroll_failed`` -- failed attempts against /disable and
    /enroll-complete previously wrote NO rows at all, so those two
    brute-force surfaces were invisible in the chained log.
    """
    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action=action,
        target_type="user",
        target_id=str(user_id),
        result="failure",
        outcome="deny",
        user_id=user_id,
        source_ip=ip,
        metadata={"reason": reason},
    )


def _mfa_lockout_active(user: User) -> bool:
    """True when the account's MFA lock is set and still in the future.

    Normalises a naive SQLite timestamp to UTC before comparing, the
    same way ``enforce_fresh_mfa`` does, so the check is correct on both
    Postgres (aware) and SQLite (naive) backends.
    """
    locked_until = user.mfa_locked_until
    if locked_until is None:
        return False
    locked_until_aware = (
        locked_until if locked_until.tzinfo is not None else locked_until.replace(tzinfo=UTC)
    )
    return locked_until_aware > datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime for either database representation.

    PostgreSQL returns timezone-aware values for ``DateTime(timezone=True)``;
    SQLite returns naive values even for that declaration. Keeping this
    normalization in one helper prevents cap/list comparisons from raising
    when the backend is SQLite.
    """
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def _serialize_mfa_security_state(
    db_session: AsyncSession,
    user_id: UUID,
) -> None:
    """Acquire the cross-dialect write fence for one user's MFA state.

    PostgreSQL uses ``SELECT ... FOR UPDATE``. SQLite mutation requests already
    start with ``BEGIN IMMEDIATE`` before dependency reads; direct callers that
    lack that request marker use a no-op ``UPDATE`` to acquire the same writer
    authority. Verify and recovery-code regeneration hold the fence through
    commit/rollback, so neither can read or replace a code set while the other
    is using it.
    """
    from z4j_brain.persistence.models import User as UserRow

    dialect = db_session.get_bind().dialect.name
    if dialect == "sqlite" and not db_session.sync_session.info.get(
        "z4j_sqlite_immediate",
    ):
        update_result = cast(
            "CursorResult[Any]",
            await db_session.execute(
                update(UserRow).where(UserRow.id == user_id).values(id=UserRow.id),
            ),
        )
        found = int(update_result.rowcount or 0) == 1
    else:
        lock_result = await db_session.execute(
            select(UserRow.id).where(UserRow.id == user_id).with_for_update(of=UserRow),
        )
        found = lock_result.scalar_one_or_none() is not None
    if not found:
        raise AuthenticationError("authenticated user no longer exists")


async def _replace_mfa_with_pending(
    db_session: AsyncSession,
    *,
    user_id: UUID,
    observed_secret_encrypted: bytes | None,
    observed_enrolled_at: datetime | None,
    new_secret_encrypted: bytes,
) -> bool:
    """Start enrollment only if the exact observed MFA state is current."""
    from z4j_brain.persistence.models import User as UserRow

    secret_predicate = (
        UserRow.mfa_secret_encrypted.is_(None)
        if observed_secret_encrypted is None
        else UserRow.mfa_secret_encrypted == observed_secret_encrypted
    )
    enrolled_predicate = (
        UserRow.mfa_enrolled_at.is_(None)
        if observed_enrolled_at is None
        else UserRow.mfa_enrolled_at == observed_enrolled_at
    )
    result = cast(
        "CursorResult[Any]",
        await db_session.execute(
            update(UserRow)
            .where(
                UserRow.id == user_id,
                secret_predicate,
                enrolled_predicate,
            )
            .values(
                mfa_secret_encrypted=new_secret_encrypted,
                mfa_enrolled_at=None,
                updated_at=datetime.now(UTC),
            ),
        ),
    )
    return int(result.rowcount or 0) == 1


async def _activate_pending_enrollment(
    db_session: AsyncSession,
    *,
    user_id: UUID,
    pending_secret_encrypted: bytes,
    stored_secret_encrypted: bytes,
    enrolled_at: datetime,
) -> bool:
    """Activate one exact pending secret; only one concurrent caller wins."""
    from z4j_brain.persistence.models import User as UserRow

    result = cast(
        "CursorResult[Any]",
        await db_session.execute(
            update(UserRow)
            .where(
                UserRow.id == user_id,
                UserRow.mfa_secret_encrypted == pending_secret_encrypted,
                UserRow.mfa_enrolled_at.is_(None),
            )
            .values(
                mfa_secret_encrypted=stored_secret_encrypted,
                mfa_enrolled_at=enrolled_at,
                updated_at=datetime.now(UTC),
            ),
        ),
    )
    return int(result.rowcount or 0) == 1


def _trusted_device_is_current(
    row: TrustedDevice,
    *,
    inbound_hash: str | None,
    now: datetime,
) -> bool:
    """Match the cookie only to a currently active trusted-device row."""
    if inbound_hash is None:
        return False
    return (
        row.revoked_at is None
        and _as_utc(row.expires_at) > now
        and row.cookie_id_hash == inbound_hash
    )


async def _reject_if_mfa_locked(
    *,
    user: User,
    audit_log: AuditLogRepository,
    settings: Settings,
    db_session: AsyncSession,
    ip: str,
    action: str,
) -> None:
    """Refuse a code-verification request while the account is MFA-locked.

    Per-account failed-MFA lockout (NIST 800-63B 5.2.2): the per-IP
    verify throttle is bypassable by IP rotation and by horizontal
    replicas, so once ``settings.mfa_lockout_threshold`` wrong codes have
    been recorded the account itself is locked for
    ``settings.mfa_lockout_duration_seconds``. Writes the lockout-refused
    audit row FIRST and commits it (matching the
    ``_audit_verify_failure``-then-commit discipline used by the wrong-
    code paths) so a brute-force attempt against a locked account still
    leaves a durable trail, then raises a 429.
    """
    if not _mfa_lockout_active(user):
        return
    await _audit_verify_failure(
        audit_log=audit_log,
        settings=settings,
        user_id=user.id,
        ip=ip,
        reason="mfa_locked",
        action=action,
    )
    await db_session.commit()
    raise RateLimitExceeded(
        "too many failed MFA attempts; the account is temporarily locked",
        details={"reason": "mfa_locked"},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/enroll-start",
    response_model=EnrollStartResponse,
    dependencies=[
        Depends(require_csrf),
        Depends(require_mfa_verify_throttle),
    ],
)
async def enroll_start(
    user: User = Depends(get_current_user),
    session_row: SessionRow = Depends(get_current_session),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> EnrollStartResponse:
    """Start (or restart) an MFA enrollment.

    Generates a fresh TOTP secret, encrypts it with the brain master
    secret, persists it on the user row with ``mfa_enrolled_at=NULL``
    (pending state), and returns the base32 form + the otpauth URL.
    Any prior MFA state for the user is cleared in the same transaction.
    The state change is conditional on the exact secret/enrollment state this
    request observed, so concurrent starts and completions have one database-
    selected winner instead of returning mutually inconsistent secrets.
    """
    # Re-enrolling wipes the victim's existing TOTP secret + recovery codes
    # and rebinds MFA to whatever device completes the flow -- as sensitive
    # as /disable, which requires the second factor. Require a fresh MFA
    # verification FIRST so a password-only or hijacked session (whose
    # mfa_verified_at is NULL) cannot silently take over the second factor.
    # enforce_fresh_mfa is a no-op when the user has no ACTIVE MFA -- i.e. a
    # first enrollment (never enrolled) and a pending-enrollment restart
    # (mfa_enrolled_at IS NULL) both pass -- so the freeze-race restart and
    # recovery-code-based device replacement (which stamps mfa_verified_at)
    # are preserved; only an already-enrolled user is gated.
    enforce_fresh_mfa(user=user, session_row=session_row, settings=settings)

    # Whether or not the user already had MFA; restart_of_enrolled
    # going to True means a previously-enrolled user is wiping their
    # secret + codes. The audit row distinguishes the two so an
    # attacker who hijacks a session and resets MFA mid-flow leaves
    # a clearly different event behind. (1.6.0 audit High-2.)
    observed_secret = user.mfa_secret_encrypted
    observed_enrolled_at = user.mfa_enrolled_at
    was_enrolled = observed_secret is not None and observed_enrolled_at is not None

    secret = generate_totp_secret()
    blob = encrypt_totp_secret(
        secret,
        master_secret=_master_secret_bytes(settings),
        user_id=user.id,
    )
    # Claim the exact observed state before touching recovery codes. If a
    # concurrent start/complete/disable changed either MFA column, this stale
    # request must not overwrite it or return a secret that is already dead.
    if not await _replace_mfa_with_pending(
        db_session,
        user_id=user.id,
        observed_secret_encrypted=observed_secret,
        observed_enrolled_at=observed_enrolled_at,
        new_secret_encrypted=blob,
    ):
        raise ConflictError(
            "MFA enrollment changed concurrently; restart the enrollment flow",
            details={"reason": "enrollment_state_changed"},
        )

    # Clear recovery codes from any prior enrollment only after winning the
    # state transition; rollback restores both sides if a later write fails.
    await recovery_codes_repo.delete_all_for_user(user.id)

    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_enroll_started",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"restart_of_enrolled": was_enrolled},
    )

    await db_session.commit()

    # Build the otpauth URL with the brain's public URL as the issuer
    # context so authenticator apps render "z4j (<host>)".
    from urllib.parse import urlparse

    host = urlparse(settings.public_url).hostname or "z4j"
    issuer = f"z4j ({host})"
    url = provisioning_url(
        secret=secret,
        account_label=user.email,
        issuer=issuer,
    )
    return EnrollStartResponse(
        secret_base32=secret_to_base32(secret),
        provisioning_url=url,
    )


@router.post(
    "/enroll-complete",
    response_model=EnrollCompleteResponse,
    # Throttled like /verify: a wrong-code loop here is the same
    # 6-digit brute-force surface (audit finding, MFA test suite).
    dependencies=[
        Depends(require_csrf),
        Depends(require_mfa_verify_throttle),
    ],
)
async def enroll_complete(
    body: EnrollCompleteRequest,
    user: User = Depends(get_current_user),
    users: UserRepository = Depends(get_user_repo),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    sessions: SessionRepository = Depends(get_session_repo),
    session_row: SessionRow = Depends(get_current_session),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> EnrollCompleteResponse:
    """Confirm a pending enrollment and activate MFA.

    Verifies the supplied code against the pending secret on the user
    row, sets ``mfa_enrolled_at=NOW()``, mints + stores the recovery
    codes, stamps ``sessions.mfa_verified_at`` on the current session
    so the user is "MFA-fresh" immediately, and returns the plaintext
    recovery codes once.
    """
    if user.mfa_secret_encrypted is None:
        raise ConflictError(
            "no pending MFA enrollment; call /auth/mfa/enroll-start first",
            details={"reason": "no_pending_enrollment"},
        )
    if user.mfa_enrolled_at is not None:
        raise ConflictError(
            "MFA is already enabled; disable it first to re-enroll",
            details={"reason": "already_enrolled"},
        )
    pending_secret_encrypted = user.mfa_secret_encrypted

    # Per-account MFA lockout gate (NIST 800-63B 5.2.2). enroll-complete
    # verifies a 6-digit code against the pending secret, so it is a
    # brute-force surface just like /verify and /disable.
    await _reject_if_mfa_locked(
        user=user,
        audit_log=audit_log,
        settings=settings,
        db_session=db_session,
        ip=ip,
        action="user.mfa_enroll_failed",
    )

    plaintext_secret, needs_rewrite = decrypt_totp_secret(
        user.mfa_secret_encrypted,
        master_secret=_master_secret_bytes(settings),
        user_id=user.id,
        previous_secrets=_previous_secrets_bytes(settings),
    )
    if verify_totp_code(plaintext_secret, body.code) is None:
        await _audit_verify_failure(
            audit_log=audit_log,
            settings=settings,
            user_id=user.id,
            ip=ip,
            reason="wrong_totp",
            action="user.mfa_enroll_failed",
        )
        # Count this toward the per-account lockout (Fix 1).
        await users.record_mfa_failure(
            user.id,
            lockout_threshold=settings.mfa_lockout_threshold,
            lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
        )
        # Commit BEFORE raising: the error path rolls the request
        # session back, which would silently discard the audit row
        # (same pattern as /verify's failure audits).
        await db_session.commit()
        raise AuthenticationError(
            "invalid code",
            details={"reason": "wrong_totp"},
        )

    # Optionally re-encrypt with the current key if the prior blob
    # was wrapped under a rotated-out Z4J_SECRET.
    blob: bytes = pending_secret_encrypted
    if needs_rewrite:
        blob = encrypt_totp_secret(
            plaintext_secret,
            master_secret=_master_secret_bytes(settings),
            user_id=user.id,
        )

    now = datetime.now(UTC)
    # Atomically claim this exact pending secret. Two concurrent completes,
    # or a complete racing a restart, can never both proceed to recovery-code
    # creation. The loser has no side effects and must restart from fresh state.
    if not await _activate_pending_enrollment(
        db_session,
        user_id=user.id,
        pending_secret_encrypted=pending_secret_encrypted,
        stored_secret_encrypted=blob,
        enrolled_at=now,
    ):
        raise ConflictError(
            "MFA enrollment changed concurrently; restart the enrollment flow",
            details={"reason": "enrollment_state_changed"},
        )

    # Good code and successful state claim: clear the failed-MFA counter/lock.
    await users.reset_mfa_failures(user.id)
    # New secret => fresh TOTP counter space. Reset the anti-replay
    # high-water mark to NULL (rather than consuming this code's counter)
    # so the FIRST post-enroll code is not pre-rejected by a stale mark
    # left over from a previous enrollment. (Fix 2, RFC 6238 5.2.)
    await users.reset_totp_counter(user.id)

    plaintext_codes = generate_recovery_codes(
        settings.mfa_recovery_code_count,
    )
    hashed = [hash_recovery_code(c) for c in plaintext_codes]
    await recovery_codes_repo.bulk_insert(
        user_id=user.id,
        hashed_codes=hashed,
    )

    # User is "MFA-fresh" right now.
    await sessions.set_mfa_verified(session_row.id)

    # Audit row.
    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_enrolled",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={
            "recovery_code_count": settings.mfa_recovery_code_count,
        },
    )
    await db_session.commit()

    return EnrollCompleteResponse(recovery_codes=plaintext_codes)


@router.post(
    "/verify",
    response_model=VerifyResponse,
    dependencies=[
        Depends(require_csrf),
        Depends(require_mfa_verify_throttle),
    ],
)
async def verify(  # noqa: PLR0912, PLR0915  MFA verify branches over factor types
    request: Request,
    response: Response,
    body: VerifyRequest,
    user: User = Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repo),
    session_row: SessionRow = Depends(get_current_session),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> VerifyResponse:
    """Verify a TOTP code or a recovery code.

    On success, ``sessions.mfa_verified_at`` is stamped so the
    sensitive-action gate accepts the caller. On a recovery-code
    success the code is consumed in the same transaction.
    """
    # Per-account MFA lockout gate (NIST 800-63B 5.2.2). Refuse further
    # attempts -- TOTP or recovery code -- while the account is locked
    # after too many wrong codes; a successful verification below clears
    # the counter. (Fix 1.)
    from z4j_brain.persistence.repositories import UserRepository

    users = UserRepository(db_session)
    # Shared cross-dialect fence with recovery-code regeneration. Acquire it
    # before reading either factor's mutable state and hold it through commit,
    # so regeneration cannot replace a set underneath a verifier (and vice
    # versa). It also serializes TOTP anti-replay claims for this user.
    await _serialize_mfa_security_state(db_session, user.id)
    await db_session.refresh(user)
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )
    await _reject_if_mfa_locked(
        user=user,
        audit_log=audit_log,
        settings=settings,
        db_session=db_session,
        ip=ip,
        action="user.mfa_verify_failed",
    )

    raw = body.code
    used_recovery = False
    # Recovery code path: anything that looks like XXXX-XXXX-XXXX once
    # normalised falls in here. Otherwise treat as TOTP digits.
    import re

    from z4j_brain.domain.audit_service import AuditService

    normalized = normalize_recovery_code(raw)
    if re.match(RECOVERY_CODE_PATTERN, normalized):
        # Constant-time scan: hash EVERY candidate before returning a
        # decision, so a timing attacker cannot infer which slot
        # contained the correct code from how long the request took.
        # Without this, an attacker observing response time over many
        # rate-limited attempts can narrow down where the valid code
        # lives in the user's set of N codes. (1.6.0 audit High-1.)
        rows = await recovery_codes_repo.list_unused_for_user(user.id)
        if not rows:
            # Burn one argon2 cycle so the "no codes left" path does not
            # expose a zero-work shortcut. This removes the largest timing
            # discontinuity, but does not claim to equalize the cost of an
            # arbitrary configured set of recovery codes.
            # (1.6.0 round-2 audit High-2.)
            burn_one_argon2_cycle()
        match = None
        for r in rows:
            # Capture the first match but DO NOT break -- continue
            # hashing every remaining row to keep the scan time
            # uniform over hit / miss positions.
            if verify_recovery_code(plaintext=normalized, hashed=r.code_hash) and match is None:
                match = r
        if match is None:
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="wrong_recovery_code",
            )
            # B25: a wrong recovery code must count toward the per-account
            # MFA lockout, exactly like a wrong TOTP. Without this, recovery
            # -code brute force was bounded only by the per-IP throttle
            # (bypassable via a botnet), while ~59-bit code entropy is the
            # only remaining backstop.
            await users.record_mfa_failure(
                user.id,
                lockout_threshold=settings.mfa_lockout_threshold,
                lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code",
                details={"reason": "wrong_recovery_code"},
            )
        # Atomic consume: WHERE consumed_at IS NULL guards against the
        # double-spend race of two parallel verifies redeeming the same
        # code. consume() returns False when another verifier already
        # won; we then surface the same error the wrong-code path
        # produces, so a defeated race attempt is indistinguishable
        # from a wrong code from outside. (1.6.0 audit Critical-1.)
        if not await recovery_codes_repo.consume(match.id):
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="recovery_code_race_lost",
            )
            # B25: count toward the lockout like every other failed verify
            # (a defeated race is indistinguishable from a wrong code).
            await users.record_mfa_failure(
                user.id,
                lockout_threshold=settings.mfa_lockout_threshold,
                lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code",
                details={"reason": "wrong_recovery_code"},
            )
        used_recovery = True
    else:
        # TOTP path.
        if len(raw) != 6 or not raw.isdigit():
            raise ValidationError(
                "code must be a 6-digit TOTP or a XXXX-XXXX-XXXX recovery code",
                details={"reason": "bad_code_format"},
            )
        plaintext_secret, needs_rewrite = decrypt_totp_secret(
            user.mfa_secret_encrypted,
            master_secret=_master_secret_bytes(settings),
            user_id=user.id,
            previous_secrets=_previous_secrets_bytes(settings),
        )
        counter = verify_totp_code(plaintext_secret, raw)
        if counter is None:
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="wrong_totp",
            )
            await users.record_mfa_failure(
                user.id,
                lockout_threshold=settings.mfa_lockout_threshold,
                lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code",
                details={"reason": "wrong_totp"},
            )
        # Anti-replay single-use claim (Fix 2, RFC 6238 5.2). The +/-1
        # step window keeps a captured code valid for ~90s; consuming the
        # matched counter here means a second presentation of the SAME
        # code finds the high-water mark already advanced and is rejected
        # exactly like a wrong code (and counts toward the lockout).
        if not await users.consume_totp_counter(user.id, counter=counter):
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="wrong_totp",
            )
            await users.record_mfa_failure(
                user.id,
                lockout_threshold=settings.mfa_lockout_threshold,
                lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code",
                details={"reason": "wrong_totp"},
            )
        if needs_rewrite:
            await users.set_mfa_state(
                user.id,
                secret_encrypted=encrypt_totp_secret(
                    plaintext_secret,
                    master_secret=_master_secret_bytes(settings),
                    user_id=user.id,
                ),
                enrolled_at=user.mfa_enrolled_at,
            )

    # Good code (TOTP or recovery): clear the failed-MFA counter/lock
    # so a subsequent wrong attempt starts from zero. (Fix 1.)
    await users.reset_mfa_failures(user.id)

    await sessions.set_mfa_verified(session_row.id)

    # "Remember this device" cookie + server-side trust row.
    trust_metadata: dict[str, object] = {}
    if body.remember_device:
        # The shared user write fence above is still held. It serializes the
        # cap check and create on both PostgreSQL and SQLite, so concurrent
        # verifies cannot both pass the count and exceed the cap.
        # Enforce a per-user cap on active trust rows. If the user is
        # already at the cap, revoke the oldest active row to make
        # room. This bounds the blast radius of a stolen session that
        # tries to mint thousands of "remember-device" rows.
        # (1.6.0 audit High-7.)
        active_count = await trusted_devices.count_active_for_user(user.id)
        if active_count >= settings.mfa_trusted_devices_max_per_user:
            existing = await trusted_devices.list_for_user(user.id)
            oldest = None
            now = datetime.now(UTC)
            for row in existing:
                if row.revoked_at is not None or _as_utc(row.expires_at) <= now:
                    continue
                if oldest is None or _as_utc(row.last_seen_at) < _as_utc(
                    oldest.last_seen_at,
                ):
                    oldest = row
            if oldest is not None:
                await trusted_devices.revoke(
                    device_id=oldest.id,
                    user_id=user.id,
                )
        cookie_value = mint_cookie_id()
        cookie_hash = hash_cookie_id(cookie_value)
        max_age_seconds = settings.mfa_remember_device_days * 86400
        expires_at = datetime.now(UTC) + timedelta(
            days=settings.mfa_remember_device_days,
        )
        label = derive_label_from_user_agent(
            request.headers.get("user-agent"),
        )
        device_row = await trusted_devices.create(
            user_id=user.id,
            cookie_id_hash=cookie_hash,
            label=label,
            expires_at=expires_at,
        )
        set_trust_cookie(
            response,
            cookie_value=cookie_value,
            environment=settings.environment,
            max_age_seconds=max_age_seconds,
        )
        trust_metadata = {
            "trusted_device_id": str(device_row.id),
            "trusted_device_label": label,
            "expires_at": expires_at.isoformat(),
        }
        await AuditService(settings).record(
            audit_log,
            action="user.mfa_trusted_device_added",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            user_id=user.id,
            source_ip=ip,
            metadata=trust_metadata,
        )

    await AuditService(settings).record(
        audit_log,
        action=("user.mfa_recovery_code_used" if used_recovery else "user.mfa_verified"),
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={},
    )
    await db_session.commit()

    remaining: int | None = None
    if used_recovery:
        remaining = await recovery_codes_repo.count_unused_for_user(
            user.id,
        )

    return VerifyResponse(
        ok=True,
        used_recovery_code=used_recovery,
        remaining_recovery_codes=remaining,
    )


@router.post(
    "/disable",
    response_model=VerifyResponse,
    # Throttled like /verify: this route accepts password + TOTP, so
    # WITHOUT the throttle an attacker who knows the password could
    # brute-force the 6-digit code unthrottled and disable MFA -- a
    # full second-factor bypass (audit finding, MFA test suite).
    dependencies=[
        Depends(require_csrf),
        Depends(require_mfa_verify_throttle),
    ],
)
async def disable(
    response: Response,
    body: DisableRequest,
    user: User = Depends(get_current_user),
    users: UserRepository = Depends(get_user_repo),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> VerifyResponse:
    """Disable MFA for the current user.

    Requires BOTH current password AND a current TOTP code in the
    same request body. Not session-cached: the gate fires every time,
    regardless of ``sessions.mfa_verified_at``. On success the user's
    MFA state is cleared and recovery codes are deleted.
    """
    from z4j_brain.auth.passwords import PasswordHasher

    # Share the user-state fence with verify/regenerate, then refresh the
    # dependency-loaded row. A concurrent restart or regeneration cannot make
    # this request verify one state and disable another.
    await _serialize_mfa_security_state(db_session, user.id)
    await db_session.refresh(user)
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    # Per-account MFA lockout gate (NIST 800-63B 5.2.2). /disable accepts
    # password + a 6-digit TOTP code, so the code is a brute-force
    # surface here too; refuse while the account is locked. (Fix 1.)
    await _reject_if_mfa_locked(
        user=user,
        audit_log=audit_log,
        settings=settings,
        db_session=db_session,
        ip=ip,
        action="user.mfa_disable_failed",
    )

    hasher = PasswordHasher(settings)
    if not hasher.verify(user.password_hash, body.password):
        await _audit_verify_failure(
            audit_log=audit_log,
            settings=settings,
            user_id=user.id,
            ip=ip,
            reason="wrong_password",
            action="user.mfa_disable_failed",
        )
        # Commit BEFORE raising (see /verify): the error path rolls
        # the request session back and would discard the audit row.
        await db_session.commit()
        raise AuthenticationError(
            "current password is incorrect",
            details={"reason": "wrong_password"},
        )

    plaintext_secret, _needs_rewrite = decrypt_totp_secret(
        user.mfa_secret_encrypted,
        master_secret=_master_secret_bytes(settings),
        user_id=user.id,
        previous_secrets=_previous_secrets_bytes(settings),
    )
    counter = verify_totp_code(plaintext_secret, body.code)
    if counter is None or not await users.consume_totp_counter(user.id, counter=counter):
        # ``counter is None`` = wrong code; a non-None counter that fails
        # to consume = a replay of an already-spent code (Fix 2). Both are
        # rejected as a wrong TOTP and both count toward the per-account
        # lockout. ``or`` short-circuits so consume_totp_counter only runs
        # on a well-formed, in-window code.
        await _audit_verify_failure(
            audit_log=audit_log,
            settings=settings,
            user_id=user.id,
            ip=ip,
            reason="wrong_totp",
            action="user.mfa_disable_failed",
        )
        await users.record_mfa_failure(
            user.id,
            lockout_threshold=settings.mfa_lockout_threshold,
            lockout_duration_seconds=settings.mfa_lockout_duration_seconds,
        )
        # Commit BEFORE raising (see /verify): the error path rolls
        # the request session back and would discard the audit row.
        await db_session.commit()
        raise AuthenticationError(
            "invalid code",
            details={"reason": "wrong_totp"},
        )

    # Good password + code: clear the failed-MFA counter/lock. (Fix 1.)
    await users.reset_mfa_failures(user.id)

    # Count side effects before the writes so the audit row records
    # what was actually wiped. Forensics needs this when an attacker
    # disables MFA and we want to know how many recovery codes /
    # trust rows were lost. (1.6.0 audit High-5.)
    deleted_recovery_codes = await recovery_codes_repo.count_unused_for_user(user.id)
    deleted_trusted_devices = await trusted_devices.count_active_for_user(user.id)

    await users.set_mfa_state(
        user.id,
        secret_encrypted=None,
        enrolled_at=None,
    )
    # MFA is gone: reset the TOTP anti-replay high-water mark to NULL so a
    # later re-enrollment starts from a clean counter space. (Fix 2.)
    await users.reset_totp_counter(user.id)
    await recovery_codes_repo.delete_all_for_user(user.id)
    await trusted_devices.delete_all_for_user(user.id)
    clear_trust_cookie(response, environment=settings.environment)

    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_disabled",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={
            "reason": "user_initiated",
            "deleted_recovery_codes": deleted_recovery_codes,
            "deleted_trusted_devices": deleted_trusted_devices,
        },
    )
    await db_session.commit()

    return VerifyResponse(ok=True)


@router.post(
    "/recovery-codes/regenerate",
    response_model=RegenerateResponse,
    dependencies=[Depends(require_csrf), Depends(require_fresh_mfa)],
)
async def regenerate_recovery_codes(
    user: User = Depends(get_current_user),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> RegenerateResponse:
    """Replace every recovery code with a fresh set.

    No code is required in this request: ``require_fresh_mfa`` admits only a
    cookie session with a recent second-factor verification. Existing codes
    are deleted atomically with insertion of the new set.
    """
    # This is the same effective write fence acquired by /verify. It is a row
    # lock on PostgreSQL and a serialized-writer fence on SQLite, so a verify
    # cannot scan/consume the old set while it is being replaced and two
    # regenerations cannot interleave. Held through commit/rollback.
    await _serialize_mfa_security_state(db_session, user.id)
    await db_session.refresh(user)
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    plaintext_codes = generate_recovery_codes(
        settings.mfa_recovery_code_count,
    )
    hashed = [hash_recovery_code(c) for c in plaintext_codes]

    await recovery_codes_repo.delete_all_for_user(user.id)
    await recovery_codes_repo.bulk_insert(
        user_id=user.id,
        hashed_codes=hashed,
    )

    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_recovery_codes_regenerated",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"count": settings.mfa_recovery_code_count},
    )
    await db_session.commit()

    return RegenerateResponse(recovery_codes=plaintext_codes)


# ---------------------------------------------------------------------------
# Status (read-only): "is MFA enrolled for me?"
# ---------------------------------------------------------------------------


class MfaStatusResponse(BaseModel):
    enrolled: bool
    enrolled_at: datetime | None
    remaining_recovery_codes: int
    enrollment_required: bool = Field(
        default=False,
        description=(
            "True when the operator's MFA enrollment-enforcement "
            "policy targets this user and they have not enrolled "
            "yet. The enrollment page reads this (the endpoint stays "
            "reachable even for a session that is past its grace "
            "deadline)."
        ),
    )
    enrollment_deadline: datetime | None = Field(
        default=None,
        description=(
            "End of the enrollment grace window; None until the "
            "grace clock has been started by a login that observed "
            "the policy. After the deadline, non-exempt endpoints "
            "answer 403 with error code mfa_enrollment_required; "
            "status, whoami, logout, enroll-start, and enroll-complete "
            "remain reachable so the user can enroll or leave."
        ),
    )


@router.get("/status", response_model=MfaStatusResponse)
async def status_endpoint(
    user: User = Depends(get_current_user),
    recovery_codes_repo: MfaRecoveryCodeRepository = Depends(
        get_mfa_recovery_codes_repo,
    ),
    settings: Settings = Depends(get_settings),
) -> MfaStatusResponse:
    """Current user's MFA state. Used by the Settings, Security tab
    and by the enrollment page (which also needs the enforcement
    deadline to render the countdown / lockout panel).
    """
    from z4j_brain.domain.mfa.enforcement import evaluate_mfa_enforcement

    enrolled = user.mfa_secret_encrypted is not None and user.mfa_enrolled_at is not None
    remaining = 0
    if enrolled:
        remaining = await recovery_codes_repo.count_unused_for_user(
            user.id,
        )
    enforcement = evaluate_mfa_enforcement(user=user, settings=settings)
    return MfaStatusResponse(
        enrolled=enrolled,
        enrolled_at=user.mfa_enrolled_at,
        remaining_recovery_codes=remaining,
        enrollment_required=enforcement.required,
        enrollment_deadline=enforcement.deadline,
    )


# ---------------------------------------------------------------------------
# Trusted devices ("remember this device" management)
# ---------------------------------------------------------------------------


class TrustedDevicePublic(BaseModel):
    id: UUID
    label: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    is_current: bool = Field(
        description=(
            "True iff the inbound z4j_mfa_trust cookie matches this "
            "device row and the row is unrevoked and unexpired. Used "
            "by the dashboard to label the active row 'this device'."
        ),
    )


class TrustedDeviceRename(BaseModel):
    label: str = Field(min_length=1, max_length=200)


@router.get(
    "/trusted-devices",
    response_model=list[TrustedDevicePublic],
)
async def list_trusted_devices(
    request: Request,
    user: User = Depends(get_current_user),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    settings: Settings = Depends(get_settings),
) -> list[TrustedDevicePublic]:
    """Return every trusted-device row for the caller.

    Includes revoked + expired rows so the user can audit what's been
    used. The currently-active cookie's row is flagged ``is_current``.
    """
    from z4j_brain.auth.trusted_device import cookie_name

    inbound = request.cookies.get(
        cookie_name(environment=settings.environment),
    )
    inbound_hash = hash_cookie_id(inbound) if inbound else None

    rows = await trusted_devices.list_for_user(user.id)
    now = datetime.now(UTC)
    return [
        TrustedDevicePublic(
            id=r.id,
            label=r.label,
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            expires_at=r.expires_at,
            revoked_at=r.revoked_at,
            is_current=_trusted_device_is_current(
                r,
                inbound_hash=inbound_hash,
                now=now,
            ),
        )
        for r in rows
    ]


@router.post(
    "/trusted-devices",
    response_model=TrustedDevicePublic,
    status_code=201,
    dependencies=[
        Depends(require_csrf),
        Depends(require_fresh_mfa),
    ],
)
async def trust_current_device(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> TrustedDevicePublic:
    """Trust the caller's current browser without making them log out.
    The verify endpoint already supports ``remember_device=True``, but
    that path forces the user to sign out + back in just to flip a
    checkbox. End-users expect the action to live on the same
    Trusted devices panel they revoke from. The endpoint is gated by
    ``require_fresh_mfa`` so the second factor is still required to
    mint the trust row (matches the security posture of the verify-
    page flow, where the user has just produced a TOTP code).
    """
    from z4j_brain.auth.trusted_device import (
        cookie_name as trust_cookie_name,
    )
    from z4j_brain.domain.audit_service import AuditService

    # Serialize with verify/regenerate/disable before trusting either the
    # dependency-loaded MFA state or the active-row/cap reads below.
    await _serialize_mfa_security_state(db_session, user.id)
    await db_session.refresh(user)
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    # If the browser already presents a valid trust cookie for an
    # active row, return that row instead of creating a duplicate.
    # Keeps the per-user cap clean and matches what users mean when
    # they click "Trust this device" twice.
    inbound = request.cookies.get(
        trust_cookie_name(environment=settings.environment),
    )
    if inbound is not None:
        existing = await trusted_devices.find_active(
            user_id=user.id,
            cookie_id_hash=hash_cookie_id(inbound),
        )
        if existing is not None:
            return TrustedDevicePublic(
                id=existing.id,
                label=existing.label,
                created_at=existing.created_at,
                last_seen_at=existing.last_seen_at,
                expires_at=existing.expires_at,
                revoked_at=existing.revoked_at,
                is_current=True,
            )

    # Mirror the per-user cap logic from the verify endpoint so the two paths
    # cannot produce different shapes of state. The shared fence is still held.
    active_count = await trusted_devices.count_active_for_user(user.id)
    if active_count >= settings.mfa_trusted_devices_max_per_user:
        existing_rows = await trusted_devices.list_for_user(user.id)
        oldest = None
        now = datetime.now(UTC)
        for row in existing_rows:
            if row.revoked_at is not None or _as_utc(row.expires_at) <= now:
                continue
            if oldest is None or _as_utc(row.last_seen_at) < _as_utc(
                oldest.last_seen_at,
            ):
                oldest = row
        if oldest is not None:
            await trusted_devices.revoke(
                device_id=oldest.id,
                user_id=user.id,
            )

    cookie_value = mint_cookie_id()
    cookie_hash = hash_cookie_id(cookie_value)
    max_age_seconds = settings.mfa_remember_device_days * 86400
    expires_at = datetime.now(UTC) + timedelta(
        days=settings.mfa_remember_device_days,
    )
    label = derive_label_from_user_agent(
        request.headers.get("user-agent"),
    )
    device_row = await trusted_devices.create(
        user_id=user.id,
        cookie_id_hash=cookie_hash,
        label=label,
        expires_at=expires_at,
    )
    set_trust_cookie(
        response,
        cookie_value=cookie_value,
        environment=settings.environment,
        max_age_seconds=max_age_seconds,
    )

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_trusted_device_added",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={
            "trusted_device_id": str(device_row.id),
            "trusted_device_label": label,
            "expires_at": expires_at.isoformat(),
            "trust_via": "settings",
        },
    )
    await db_session.commit()

    return TrustedDevicePublic(
        id=device_row.id,
        label=device_row.label,
        created_at=device_row.created_at,
        last_seen_at=device_row.last_seen_at,
        expires_at=device_row.expires_at,
        revoked_at=device_row.revoked_at,
        is_current=True,
    )


@router.post(
    "/trusted-devices/{device_id}/revoke",
    status_code=204,
    dependencies=[
        Depends(require_csrf),
        Depends(require_fresh_mfa),
    ],
)
async def revoke_trusted_device(
    device_id: UUID,
    response: Response,
    request: Request,
    user: User = Depends(get_current_user),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> Response:
    """Revoke a single trusted-device row.

    Scoped to the caller's user_id so an attacker who has another
    user's device id cannot revoke it remotely. If the revoked row
    matches the inbound cookie, the cookie is also cleared on the
    response so the browser stops sending it.
    """
    from z4j_brain.auth.trusted_device import cookie_name

    ok = await trusted_devices.revoke(
        device_id=device_id,
        user_id=user.id,
    )
    if not ok:
        raise NotFoundError(
            "trusted device not found",
            details={"device_id": str(device_id)},
        )

    inbound = request.cookies.get(
        cookie_name(environment=settings.environment),
    )
    if inbound is not None:
        inbound_hash = hash_cookie_id(inbound)
        # Check whether the revoked device was the caller's current
        # cookie; clear it if so.
        rows = await trusted_devices.list_for_user(user.id)
        for r in rows:
            if r.id == device_id and r.cookie_id_hash == inbound_hash:
                clear_trust_cookie(
                    response,
                    environment=settings.environment,
                )
                break

    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_trusted_device_revoked",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"device_id": str(device_id)},
    )
    await db_session.commit()
    response.status_code = 204
    return response


@router.patch(
    "/trusted-devices/{device_id}",
    response_model=TrustedDevicePublic,
    dependencies=[
        Depends(require_csrf),
        Depends(require_fresh_mfa),
    ],
)
async def rename_trusted_device(
    device_id: UUID,
    body: TrustedDeviceRename,
    request: Request,
    user: User = Depends(get_current_user),
    trusted_devices: TrustedDeviceRepository = Depends(
        get_trusted_device_repo,
    ),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> TrustedDevicePublic:
    """Rename a trusted device for the user's own clarity."""
    from z4j_brain.auth.trusted_device import cookie_name

    ok = await trusted_devices.rename(
        device_id=device_id,
        user_id=user.id,
        label=body.label,
    )
    if not ok:
        raise NotFoundError(
            "trusted device not found",
            details={"device_id": str(device_id)},
        )

    # Audit the rename so a stolen-session attacker who relabels
    # rows to hide their tracks still leaves a chained-log trail.
    # (1.6.0 audit High-4.)
    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_trusted_device_renamed",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"device_id": str(device_id), "label": body.label},
    )
    await db_session.commit()

    rows = await trusted_devices.list_for_user(user.id)
    target = next((r for r in rows if r.id == device_id), None)
    if target is None:
        raise NotFoundError(
            "trusted device not found",
            details={"device_id": str(device_id)},
        )
    inbound = request.cookies.get(
        cookie_name(environment=settings.environment),
    )
    inbound_hash = hash_cookie_id(inbound) if inbound else None
    now = datetime.now(UTC)
    return TrustedDevicePublic(
        id=target.id,
        label=target.label,
        created_at=target.created_at,
        last_seen_at=target.last_seen_at,
        expires_at=target.expires_at,
        revoked_at=target.revoked_at,
        is_current=_trusted_device_is_current(
            target,
            inbound_hash=inbound_hash,
            now=now,
        ),
    )


__all__ = [
    "DisableRequest",
    "EnrollCompleteRequest",
    "EnrollCompleteResponse",
    "EnrollStartResponse",
    "MfaStatusResponse",
    "RegenerateResponse",
    "TrustedDevicePublic",
    "TrustedDeviceRename",
    "VerifyRequest",
    "VerifyResponse",
    "router",
]
