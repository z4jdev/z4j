"""``/api/v1/projects/{slug}/invitations`` + ``/api/v1/invitations``
REST router - admin mints + invitee accepts the team-invite flow.

Endpoints:

- ``POST   /projects/{slug}/invitations``            (admin) mint
- ``GET    /projects/{slug}/invitations``            (admin) list pending
- ``DELETE /projects/{slug}/invitations/{id}``       (admin) revoke
- ``GET    /invitations/preview``                    (public) validate token
- ``POST   /invitations/accept``                     (public) accept + signup

Security mirrors ``first_boot_tokens`` + audit H5 (TOCTOU-safe
accept) and audit H4 (atomic counter on auth paths):

- Plaintext token shown once at mint, never persisted.
- Token comparison uses ``hmac.compare_digest``.
- Accept re-checks "email not already in use" inside the same
  transaction as the user insert + membership grant.
- Revoked / expired / already-accepted invitations all return a
  generic ``invalid_or_expired`` error - no oracle for token
  enumeration.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, EmailStr, Field, field_validator

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_invitation_repo,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    get_user_repo,
    require_admin,
    require_csrf,
)
from z4j_brain.domain.ip_rate_limit import require_invitation_throttle
from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        InvitationRepository,
        MembershipRepository,
        ProjectRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


# Routers - one for admin project-scoped operations, one for public
# accept flow. Both are attached to the FastAPI app in ``main.py``.
admin_router = APIRouter(
    prefix="/projects/{slug}/invitations",
    tags=["invitations"],
)
public_router = APIRouter(prefix="/invitations", tags=["invitations"])


_DEFAULT_TTL_DAYS = 7
_MIN_TTL_DAYS = 1
_MAX_TTL_DAYS = 30
_TOKEN_BYTES = 32  # 256-bit token


# ---------------------------------------------------------------------------
# Request + response schemas
# ---------------------------------------------------------------------------


class InvitationCreateRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", max_length=20)
    ttl_days: int = Field(
        default=_DEFAULT_TTL_DAYS, ge=_MIN_TTL_DAYS, le=_MAX_TTL_DAYS,
    )

    @field_validator("role")
    @classmethod
    def _role_valid(cls, v: str) -> str:
        allowed = {r.value for r in ProjectRole}
        if v not in allowed:
            raise ValueError(
                f"role must be one of {sorted(allowed)}",
            )
        return v


class InvitationPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    email: str
    role: str
    invited_by: uuid.UUID | None
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class InvitationMintPublic(BaseModel):
    """Mint response - includes the plaintext token exactly ONCE."""

    invitation: InvitationPublic
    token: str = Field(
        description=(
            "Plaintext invitation token. Shown ONCE - never again. "
            "Send this as part of the invite-accept URL "
            "(e.g. https://z4j.example.com/invite?token=<value>)."
        ),
    )
    accept_url_path: str = Field(
        description="Suggested relative accept path with the token embedded.",
    )
    email_sent: bool = Field(
        default=False,
        description=(
            "True when the invitation link was auto-emailed to the "
            "invitee via the project's email channel. False when no "
            "email channel is configured OR the send failed - in "
            "that case the admin should relay the token manually."
        ),
    )


class InvitationPreviewPublic(BaseModel):
    """Minimal safe info for the accept-page to render.

    Does NOT leak project details beyond name/slug - the invitee
    needs to see "you've been invited to the X project" but should
    not learn arbitrary metadata about projects they don't have
    membership to.
    """

    email: str
    role: str
    project_slug: str
    project_name: str
    expires_at: datetime


class InvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=10, max_length=256)
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=200)


class InvitationAcceptPublic(BaseModel):
    user_id: uuid.UUID
    project_slug: str
    role: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_token(plaintext: str, settings: "Settings") -> str:
    """HMAC-SHA256 digest of a plaintext token, keyed by the server secret."""
    secret = settings.secret.get_secret_value().encode()
    return hmac.new(secret, plaintext.encode(), sha256).hexdigest()


def _mint_token() -> str:
    """Generate a URL-safe invitation token (~43 chars of base64)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _is_pending(inv) -> bool:  # type: ignore[no-untyped-def]
    """True when an invitation is still usable (not accepted/revoked/expired)."""
    now = datetime.now(UTC)
    expires_at = inv.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return (
        inv.accepted_at is None
        and inv.revoked_at is None
        and expires_at > now
    )


def _invitation_public(inv) -> InvitationPublic:  # type: ignore[no-untyped-def]
    return InvitationPublic(
        id=inv.id,
        project_id=inv.project_id,
        email=inv.email,
        role=inv.role,
        invited_by=inv.invited_by,
        expires_at=inv.expires_at,
        accepted_at=inv.accepted_at,
        revoked_at=inv.revoked_at,
        created_at=inv.created_at,
    )


# ---------------------------------------------------------------------------
# Admin endpoints (project-scoped)
# ---------------------------------------------------------------------------


@admin_router.post(
    "",
    response_model=InvitationMintPublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def mint_invitation(
    slug: str,
    body: InvitationCreateRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    invitations: "InvitationRepository" = Depends(get_invitation_repo),
    users: "UserRepository" = Depends(get_user_repo),
    settings: "Settings" = Depends(get_settings),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> InvitationMintPublic:
    """Admin-only: mint a single-use invitation token for ``email``."""
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships, user=user, project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    # Round-9 audit fix R9-Auth-LOW (Apr 2026): canonicalize the
    # invitee email at mint time. Pre-fix ``get_by_email`` casefolded
    # but did NOT NFKC/IDNA normalize, so an admin who pasted
    # ``Ｕｓｅｒ@example.com`` (full-width) while ``user@example.com``
    # already existed got a "no existing user" response, the invite
    # was minted, and accept-time TOCTOU re-canonicalization
    # eventually 409'd, wasted invite + confusing UX. Canonicalize
    # before the dup-check AND store the canonical form on the row
    # so the accept path sees consistent state.
    from z4j_brain.domain.auth_service import canonicalize_email  # noqa: PLC0415

    canonical_email = canonicalize_email(body.email)

    # Reject inviting someone who is already a member - no value
    # in creating dangling invites. 409 Conflict with a clean
    # error body so the dashboard can show "that user is already
    # a member" directly.
    existing_user = await users.get_by_email(canonical_email)
    if existing_user is not None:
        existing = await memberships.get_for_user_project(
            user_id=existing_user.id, project_id=project.id,
        )
        if existing is not None:
            raise ConflictError(
                "user is already a member of this project",
                details={"email": canonical_email},
            )

    plaintext = _mint_token()
    token_hash = _hash_token(plaintext, settings)
    expires_at = datetime.now(UTC) + timedelta(days=body.ttl_days)

    row = await invitations.create(
        project_id=project.id,
        email=canonical_email,
        role=body.role,
        invited_by=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    await audit.record(
        audit_log,
        action="invitation.mint",
        user_id=user.id,
        project_id=project.id,
        target_type="invitation",
        target_id=str(row.id),
        source_ip=ip,
        metadata={"email": body.email, "role": body.role},
    )
    await db_session.commit()

    # Best-effort auto-email the invitee. If the project has an
    # active email channel configured, send the invite link via it.
    # If no channel is configured or the send fails, we still
    # return the token to the admin so they can relay manually -
    # the mint itself never fails because the email dispatch did.
    email_sent = await _try_send_invitation_email(
        db_session=db_session,
        settings=settings,
        project_id=project.id,
        project_name=project.name,
        invitee_email=body.email,
        role=body.role,
        token=plaintext,
    )

    return InvitationMintPublic(
        invitation=_invitation_public(row),
        token=plaintext,
        # Round-9 audit fix R9-Auth-MED (Apr 2026): URL fragment
        # not query string. See auth.py password-reset accept_url
        # for the threat model, fragment isn't sent in Referer
        # headers, isn't written to access logs, and isn't synced
        # by most browser history mechanisms.
        accept_url_path=f"/invite#token={plaintext}",
        email_sent=email_sent,
    )


async def _try_send_invitation_email(
    *,
    db_session: "AsyncSession",
    settings: "Settings",
    project_id: uuid.UUID,
    project_name: str,
    invitee_email: str,
    role: str,
    token: str,
) -> bool:
    """Find a project-level email channel and send the invitation.

    Returns ``True`` when at least one email channel was found and
    the dispatcher reported success; ``False`` when no email channel
    is configured OR when every configured channel errored. Never
    raises - the mint itself must not depend on SMTP availability.
    """
    import logging

    from z4j_brain.domain.notifications.channels import deliver_email
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    logger = logging.getLogger("z4j.brain.invitations")

    try:
        channel_repo = NotificationChannelRepository(db_session)
        channels = await channel_repo.list_for_project(
            project_id, active_only=True,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "z4j: invitation email - failed to list channels",
        )
        return False

    email_channels = [c for c in channels if c.type == "email"]
    if not email_channels:
        return False

    # Round-9 audit fix R9-Auth-MED (Apr 2026): URL fragment.
    accept_url = (
        f"{settings.public_url.rstrip('/')}/invite#token={token}"
        if getattr(settings, "public_url", None)
        else f"/invite#token={token}"
    )
    subject = f"z4j: you're invited to {project_name}"
    body = (
        f"You've been invited to join the z4j project '{project_name}' "
        f"with role: {role}.\n\n"
        f"Accept the invitation here:\n{accept_url}\n\n"
        f"This link is single-use and expires soon.\n\n"
        f"-- z4j"
    )

    # Try the first channel that succeeds; stop on first success.
    for channel in email_channels:
        try:
            result = await deliver_email(
                config=dict(channel.config or {}),
                payload={
                    "subject": subject,
                    "body": body,
                    "to_addrs": [invitee_email],
                },
            )
            if result.success:
                return True
            logger.warning(
                "z4j: invitation email channel %s failed: %s",
                channel.id, result.error,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j: invitation email channel %s crashed", channel.id,
            )
    return False


@admin_router.get("", response_model=list[InvitationPublic])
async def list_pending_invitations(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    invitations: "InvitationRepository" = Depends(get_invitation_repo),
) -> list[InvitationPublic]:
    """Admin-only: list non-accepted, non-revoked, non-expired invitations."""
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships, user=user, project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )
    rows = await invitations.list_for_project(project.id)
    return [_invitation_public(r) for r in rows]


@admin_router.delete(
    "/{invitation_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def revoke_invitation(
    slug: str,
    invitation_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    invitations: "InvitationRepository" = Depends(get_invitation_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> Response:
    """Admin-only: revoke a pending invitation."""
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships, user=user, project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )
    row = await invitations.get(invitation_id)
    if row is None or row.project_id != project.id:
        raise NotFoundError(
            "invitation not found",
            details={"invitation_id": str(invitation_id)},
        )
    if row.accepted_at is not None:
        raise ConflictError(
            "invitation has already been accepted; cannot revoke",
        )
    await invitations.revoke(invitation_id)
    await audit.record(
        audit_log,
        action="invitation.revoke",
        user_id=user.id,
        project_id=project.id,
        target_type="invitation",
        target_id=str(invitation_id),
        source_ip=ip,
    )
    await db_session.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Public endpoints (no session auth - gated by the token itself)
# ---------------------------------------------------------------------------


@public_router.get(
    "/preview",
    response_model=InvitationPreviewPublic,
    dependencies=[Depends(require_invitation_throttle)],
)
async def preview_invitation(
    token: str = Query(min_length=10, max_length=256),
    invitations: "InvitationRepository" = Depends(get_invitation_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    settings: "Settings" = Depends(get_settings),
) -> InvitationPreviewPublic:
    """Anonymous endpoint - lets the accept page render "invited to X"."""
    token_hash = _hash_token(token, settings)
    row = await invitations.get_by_hash(token_hash)
    if row is None or not _is_pending(row):
        raise NotFoundError("invalid_or_expired")
    project = await projects.get(row.project_id)
    if project is None:
        raise NotFoundError("invalid_or_expired")
    return InvitationPreviewPublic(
        email=row.email,
        role=row.role,
        project_slug=project.slug,
        project_name=project.name,
        expires_at=row.expires_at,
    )


@public_router.post(
    "/accept",
    response_model=InvitationAcceptPublic,
    status_code=201,
    dependencies=[Depends(require_invitation_throttle)],
)
async def accept_invitation(
    body: InvitationAcceptRequest,
    invitations: "InvitationRepository" = Depends(get_invitation_repo),
    users: "UserRepository" = Depends(get_user_repo),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    settings: "Settings" = Depends(get_settings),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> InvitationAcceptPublic:
    """Anonymous endpoint - consumes the token + creates user + grants membership.

    Everything runs in a single transaction so the four side-effects
    (invitation stamped, user inserted, membership granted, default
    subscriptions materialized) succeed or fail together. TOCTOU-safe
    per audit H5: email uniqueness is re-checked inside the
    transaction.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.auth_service import canonicalize_email
    from z4j_brain.persistence.models import User

    token_hash = _hash_token(body.token, settings)
    row = await invitations.get_by_hash(token_hash)
    if row is None or not _is_pending(row):
        raise NotFoundError("invalid_or_expired")

    project = await projects.get(row.project_id)
    if project is None:
        raise NotFoundError("invalid_or_expired")

    # Defense-in-depth (audit M1): re-validate the stored role
    # against the current ProjectRole enum. ``role`` is a free-text
    # column; if a future enum narrowing or a buggy code path ever
    # writes a non-enum value, accept must refuse rather than grant.
    if row.role not in {r.value for r in ProjectRole}:
        raise NotFoundError("invalid_or_expired")

    email_canonical = canonicalize_email(row.email)

    # TOCTOU-safe re-check inside the same transaction as the insert.
    existing = await users.get_by_email(email_canonical)
    if existing is not None:
        raise ConflictError(
            "a user with this email already exists; ask the admin to "
            "add you to the project directly instead of using this "
            "invitation link",
            details={"email": row.email},
        )

    # Audit fix M1 (1.4.0 pre-release pass): enforce the same
    # password policy here as every other write path (auth.py
    # password change, users.py admin create / set, cli.py
    # changepassword, setup_service first-boot). Pre-fix the
    # invitation-accept handler called ``hasher.hash`` directly,
    # bypassing the 3-of-4-character-classes + common-password
    # denylist + max-length checks. ``Field(min_length=12)`` on the
    # request schema only enforces length, not strength -- a 12-char
    # value like "Summer2025!!" or "qwertyuiop12" would pass.
    hasher = PasswordHasher(settings)
    hasher.validate_policy(body.password)
    password_hash = hasher.hash(body.password)

    new_user = User(
        email=email_canonical,
        password_hash=password_hash,
        display_name=body.display_name.strip(),
        is_admin=False,
        is_active=True,
        password_changed_at=_dt.now(_UTC),
    )
    await users.add(new_user)
    await memberships.grant(
        user_id=new_user.id,
        project_id=project.id,
        role=row.role,
    )
    await invitations.accept(
        row.id, accepted_by_user_id=new_user.id,
    )

    # Materialize the project's default subscriptions so the new
    # member starts getting bell notifications immediately - same
    # post-join hook used by the direct-membership path.
    from z4j_brain.domain.notifications import NotificationService
    await NotificationService().materialize_defaults_for_member(
        session=db_session,
        user_id=new_user.id,
        project_id=project.id,
    )

    await audit.record(
        audit_log,
        action="invitation.accept",
        user_id=new_user.id,
        project_id=project.id,
        target_type="invitation",
        target_id=str(row.id),
        source_ip=ip,
        metadata={"email": row.email, "role": row.role},
    )
    await db_session.commit()

    return InvitationAcceptPublic(
        user_id=new_user.id,
        project_slug=project.slug,
        role=row.role,
    )


__all__ = ["admin_router", "public_router"]
