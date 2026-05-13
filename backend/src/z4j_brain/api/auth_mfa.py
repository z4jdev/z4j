"""MFA enrollment, verification, disable, recovery-code regenerate.

Five POST endpoints under ``/auth/mfa``. All require an authenticated
session (``Depends(get_current_user)``); the verify endpoint is the
one that flips ``sessions.mfa_verified_at`` so the sensitive-action
gate (phase 5) starts treating the caller as "MFA-fresh".

In-progress enrollment is tracked directly on the user row:

  * ``mfa_secret_encrypted IS NOT NULL AND mfa_enrolled_at IS NULL``
    -> enrollment in progress (start was called, complete pending)
  * ``mfa_secret_encrypted IS NOT NULL AND mfa_enrolled_at IS NOT NULL``
    -> MFA is on
  * ``mfa_secret_encrypted IS NULL``
    -> no MFA

This avoids a separate ephemeral store and survives a brain restart
mid-flow. The ``enroll-start`` endpoint deliberately clears any
already-enrolled state, so an attacker who steals a session cannot
race the legitimate user to "freeze" their MFA mid-enrollment.

See ``docs/MFA-DESIGN.md`` for the full design + threat model.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, field_validator

from z4j_brain.api.deps import (
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
    ValidationError,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import User
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
            "bound to the device so subsequent logins from this "
            "browser skip the MFA second step until the cookie "
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


def _master_secret_bytes(settings: "Settings") -> bytes:
    return settings.secret.get_secret_value().encode("utf-8")


def _previous_secrets_bytes(settings: "Settings") -> list[bytes]:
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
    audit_log: "AuditLogRepository",
    settings: "Settings",
    user_id: UUID,
    ip: str,
    reason: str,
) -> None:
    """Record a failed MFA verify attempt in the HMAC-chained log.
    A brute-force attacker hitting the verify endpoint must leave
    a trail; without this row the per-IP throttle alone would let
    failed attempts vanish into a quiet 401.
    """
    from z4j_brain.domain.audit_service import AuditService

    await AuditService(settings).record(
        audit_log,
        action="user.mfa_verify_failed",
        target_type="user",
        target_id=str(user_id),
        result="failure",
        outcome="deny",
        user_id=user_id,
        source_ip=ip,
        metadata={"reason": reason},
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
    user: "User" = Depends(get_current_user),
    users: "UserRepository" = Depends(get_user_repo),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> EnrollStartResponse:
    """Start (or restart) an MFA enrollment.

    Generates a fresh TOTP secret, encrypts it with the brain master
    secret, persists it on the user row with ``mfa_enrolled_at=NULL``
    (pending state), and returns the base32 form + the otpauth URL.
    Any prior MFA state for the user is cleared in the same
    transaction so a fresh start cannot be raced by a stale flow.
    """
    # Whether or not the user already had MFA; restart_of_enrolled
    # going to True means a previously-enrolled user is wiping their
    # secret + codes. The audit row distinguishes the two so an
    # attacker who hijacks a session and resets MFA mid-flow leaves
    # a clearly different event behind. (1.6.0 audit High-2.)
    was_enrolled = (
        user.mfa_secret_encrypted is not None
        and user.mfa_enrolled_at is not None
    )

    secret = generate_totp_secret()
    blob = encrypt_totp_secret(
        secret,
        master_secret=_master_secret_bytes(settings),
        user_id=user.id,
    )
    # Clear recovery codes from any prior enrollment.
    await recovery_codes_repo.delete_all_for_user(user.id)
    await users.set_mfa_state(
        user.id,
        secret_encrypted=blob,
        enrolled_at=None,
    )

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
        secret=secret, account_label=user.email, issuer=issuer,
    )
    return EnrollStartResponse(
        secret_base32=secret_to_base32(secret),
        provisioning_url=url,
    )


@router.post(
    "/enroll-complete",
    response_model=EnrollCompleteResponse,
    dependencies=[Depends(require_csrf)],
)
async def enroll_complete(
    body: EnrollCompleteRequest,
    user: "User" = Depends(get_current_user),
    users: "UserRepository" = Depends(get_user_repo),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
    sessions: "SessionRepository" = Depends(get_session_repo),
    session_row: "SessionRow" = Depends(get_current_session),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
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

    plaintext_secret, needs_rewrite = decrypt_totp_secret(
        user.mfa_secret_encrypted,
        master_secret=_master_secret_bytes(settings),
        user_id=user.id,
        previous_secrets=_previous_secrets_bytes(settings),
    )
    if not verify_totp_code(plaintext_secret, body.code):
        raise AuthenticationError(
            "invalid code", details={"reason": "wrong_totp"},
        )

    # Optionally re-encrypt with the current key if the prior blob
    # was wrapped under a rotated-out Z4J_SECRET.
    blob: bytes = user.mfa_secret_encrypted
    if needs_rewrite:
        blob = encrypt_totp_secret(
            plaintext_secret,
            master_secret=_master_secret_bytes(settings),
            user_id=user.id,
        )

    now = datetime.now(UTC)
    await users.set_mfa_state(
        user.id, secret_encrypted=blob, enrolled_at=now,
    )

    plaintext_codes = generate_recovery_codes(
        settings.mfa_recovery_code_count,
    )
    hashed = [hash_recovery_code(c) for c in plaintext_codes]
    await recovery_codes_repo.bulk_insert(
        user_id=user.id, hashed_codes=hashed,
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
async def verify(
    request: Request,
    response: Response,
    body: VerifyRequest,
    user: "User" = Depends(get_current_user),
    sessions: "SessionRepository" = Depends(get_session_repo),
    session_row: "SessionRow" = Depends(get_current_session),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> VerifyResponse:
    """Verify a TOTP code or a recovery code.

    On success, ``sessions.mfa_verified_at`` is stamped so the
    sensitive-action gate accepts the caller. On a recovery-code
    success the code is consumed in the same transaction.
    """
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    raw = body.code
    used_recovery = False
    from z4j_brain.domain.audit_service import AuditService

    # Recovery code path: anything that looks like XXXX-XXXX-XXXX once
    # normalised falls in here. Otherwise treat as TOTP digits.
    import re

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
            # Burn one argon2 cycle so the "no codes left" response
            # time matches the "codes present" path. Without this,
            # an attacker can distinguish enrolled-but-out-of-codes
            # from enrolled-with-codes via timing.
            # (1.6.0 round-2 audit High-2.)
            burn_one_argon2_cycle()
        match = None
        for r in rows:
            if verify_recovery_code(plaintext=normalized, hashed=r.code_hash):
                # Capture the first match but DO NOT break -- continue
                # hashing every remaining row to keep the scan time
                # uniform over hit / miss positions.
                if match is None:
                    match = r
        if match is None:
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="wrong_recovery_code",
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code", details={"reason": "wrong_recovery_code"},
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
            await db_session.commit()
            raise AuthenticationError(
                "invalid code", details={"reason": "wrong_recovery_code"},
            )
        used_recovery = True
    else:
        # TOTP path.
        if len(raw) != 6 or not raw.isdigit():
            raise ValidationError(
                "code must be a 6-digit TOTP or a XXXX-XXXX-XXXX "
                "recovery code",
                details={"reason": "bad_code_format"},
            )
        plaintext_secret, needs_rewrite = decrypt_totp_secret(
            user.mfa_secret_encrypted,
            master_secret=_master_secret_bytes(settings),
            user_id=user.id,
            previous_secrets=_previous_secrets_bytes(settings),
        )
        if not verify_totp_code(plaintext_secret, raw):
            await _audit_verify_failure(
                audit_log=audit_log,
                settings=settings,
                user_id=user.id,
                ip=ip,
                reason="wrong_totp",
            )
            await db_session.commit()
            raise AuthenticationError(
                "invalid code", details={"reason": "wrong_totp"},
            )
        if needs_rewrite:
            from z4j_brain.persistence.repositories import UserRepository

            await UserRepository(db_session).set_mfa_state(
                user.id,
                secret_encrypted=encrypt_totp_secret(
                    plaintext_secret,
                    master_secret=_master_secret_bytes(settings),
                    user_id=user.id,
                ),
                enrolled_at=user.mfa_enrolled_at,
            )

    await sessions.set_mfa_verified(session_row.id)

    # "Remember this device" cookie + server-side trust row.
    trust_metadata: dict[str, object] = {}
    if body.remember_device:
        # Take the user lock BEFORE the count check so two concurrent
        # verifies cannot both pass the count, both revoke (or skip),
        # and both create a fresh row, blowing past the cap. The lock
        # is held until commit / rollback; under SQLite it is a no-op
        # (per-process serialisation is sufficient there). (1.6.0
        # round-2 audit High-1.)
        from z4j_brain.persistence.repositories import UserRepository

        await UserRepository(db_session).lock_for_password_change(user.id)
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
                if row.revoked_at is not None or row.expires_at <= now:
                    continue
                if oldest is None or row.last_seen_at < oldest.last_seen_at:
                    oldest = row
            if oldest is not None:
                await trusted_devices.revoke(
                    device_id=oldest.id, user_id=user.id,
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
        action=(
            "user.mfa_recovery_code_used"
            if used_recovery
            else "user.mfa_verified"
        ),
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
    dependencies=[Depends(require_csrf)],
)
async def disable(
    response: Response,
    body: DisableRequest,
    user: "User" = Depends(get_current_user),
    users: "UserRepository" = Depends(get_user_repo),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> VerifyResponse:
    """Disable MFA for the current user.

    Requires BOTH current password AND a current TOTP code in the
    same request body. Not session-cached: the gate fires every time,
    regardless of ``sessions.mfa_verified_at``. On success the user's
    MFA state is cleared and recovery codes are deleted.
    """
    from z4j_brain.auth.passwords import PasswordHasher

    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    hasher = PasswordHasher(settings)
    if not hasher.verify(user.password_hash, body.password):
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
    if not verify_totp_code(plaintext_secret, body.code):
        raise AuthenticationError(
            "invalid code", details={"reason": "wrong_totp"},
        )

    # Count side effects before the writes so the audit row records
    # what was actually wiped. Forensics needs this when an attacker
    # disables MFA and we want to know how many recovery codes /
    # trust rows were lost. (1.6.0 audit High-5.)
    deleted_recovery_codes = (
        await recovery_codes_repo.count_unused_for_user(user.id)
    )
    deleted_trusted_devices = (
        await trusted_devices.count_active_for_user(user.id)
    )

    await users.set_mfa_state(
        user.id, secret_encrypted=None, enrolled_at=None,
    )
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
    user: "User" = Depends(get_current_user),
    users: "UserRepository" = Depends(get_user_repo),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> RegenerateResponse:
    """Replace every recovery code with a fresh set.

    No code required as input -- the act of being able to call this
    endpoint (authenticated session) plus the future sensitive-action
    gate (phase 5) is the protection. Existing codes are deleted
    atomically with the insert of the new ones.
    """
    if user.mfa_secret_encrypted is None or user.mfa_enrolled_at is None:
        raise ConflictError(
            "MFA is not enabled for this user",
            details={"reason": "mfa_not_enrolled"},
        )

    # Serialise against concurrent verify / regenerate on the same user.
    # Without the row lock, a verify reading the old code set can race
    # the regenerate's delete+insert and end up consuming a stale row,
    # or two parallel regenerates can leak code rows. (1.6.0 Critical-2.)
    await users.lock_for_password_change(user.id)

    plaintext_codes = generate_recovery_codes(
        settings.mfa_recovery_code_count,
    )
    hashed = [hash_recovery_code(c) for c in plaintext_codes]

    await recovery_codes_repo.delete_all_for_user(user.id)
    await recovery_codes_repo.bulk_insert(
        user_id=user.id, hashed_codes=hashed,
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


@router.get("/status", response_model=MfaStatusResponse)
async def status_endpoint(  # noqa: A001 - shadow fastapi.status
    user: "User" = Depends(get_current_user),
    recovery_codes_repo: "MfaRecoveryCodeRepository" = Depends(
        get_mfa_recovery_codes_repo,
    ),
) -> MfaStatusResponse:
    """Current user's MFA state. Used by the Settings, Security tab."""
    enrolled = (
        user.mfa_secret_encrypted is not None
        and user.mfa_enrolled_at is not None
    )
    remaining = 0
    if enrolled:
        remaining = await recovery_codes_repo.count_unused_for_user(
            user.id,
        )
    return MfaStatusResponse(
        enrolled=enrolled,
        enrolled_at=user.mfa_enrolled_at,
        remaining_recovery_codes=remaining,
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
            "device row. Used by the dashboard to label the row "
            "'this device' in the list."
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
    user: "User" = Depends(get_current_user),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    settings: "Settings" = Depends(get_settings),
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
    return [
        TrustedDevicePublic(
            id=r.id,
            label=r.label,
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            expires_at=r.expires_at,
            revoked_at=r.revoked_at,
            is_current=inbound_hash is not None
            and r.cookie_id_hash == inbound_hash,
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
    user: "User" = Depends(get_current_user),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
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

    # Mirror the per-user cap logic from the verify endpoint so the
    # two paths cannot produce different shapes of state.
    from z4j_brain.persistence.repositories import UserRepository

    await UserRepository(db_session).lock_for_password_change(user.id)
    active_count = await trusted_devices.count_active_for_user(user.id)
    if active_count >= settings.mfa_trusted_devices_max_per_user:
        existing_rows = await trusted_devices.list_for_user(user.id)
        oldest = None
        now = datetime.now(UTC)
        for row in existing_rows:
            if row.revoked_at is not None or row.expires_at <= now:
                continue
            if oldest is None or row.last_seen_at < oldest.last_seen_at:
                oldest = row
        if oldest is not None:
            await trusted_devices.revoke(
                device_id=oldest.id, user_id=user.id,
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
    user: "User" = Depends(get_current_user),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
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
        device_id=device_id, user_id=user.id,
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
                    response, environment=settings.environment,
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
    user: "User" = Depends(get_current_user),
    trusted_devices: "TrustedDeviceRepository" = Depends(
        get_trusted_device_repo,
    ),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> TrustedDevicePublic:
    """Rename a trusted device for the user's own clarity."""
    from z4j_brain.auth.trusted_device import cookie_name

    ok = await trusted_devices.rename(
        device_id=device_id, user_id=user.id, label=body.label,
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
    return TrustedDevicePublic(
        id=target.id,
        label=target.label,
        created_at=target.created_at,
        last_seen_at=target.last_seen_at,
        expires_at=target.expires_at,
        revoked_at=target.revoked_at,
        is_current=inbound_hash is not None
        and target.cookie_id_hash == inbound_hash,
    )


__all__ = [
    "router",
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
]
