"""Auth endpoints: login / logout / me / account management.

Routes:

- ``POST  /api/v1/auth/login`` - exchange (email, password) for a
  session cookie. NO csrf protection (no session yet) but tightly
  rate-limited at the brain level by the per-account lockout +
  exponential backoff in the auth service.
- ``POST  /api/v1/auth/logout`` - revoke the current session.
  Requires CSRF.
- ``GET   /api/v1/auth/me`` - return the current user.
- ``PATCH /api/v1/auth/me`` - update display_name / timezone.
  Requires CSRF.
- ``GET   /api/v1/auth/sessions`` - list active sessions for the
  current user.
- ``POST  /api/v1/auth/sessions/{session_id}/revoke`` - revoke a
  specific session belonging to the current user. Requires CSRF.

Response shape for ALL endpoints uses an explicit Pydantic model
so we never accidentally leak sensitive ORM fields like
``password_hash``, ``failed_login_count``, ``locked_until``.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_auth_service,
    get_client_ip,
    get_current_session,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_session_repo,
    get_settings,
    get_user_repo,
    require_csrf,
)
from z4j_brain.domain.ip_rate_limit import (
    require_login_throttle,
    require_password_reset_throttle,
)
from z4j_brain.auth.csrf import csrf_cookie_kwargs, csrf_cookie_name
from z4j_brain.auth.sessions import (
    SessionCookieCodec,
    cookie_kwargs,
    cookie_name,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.auth_service import AuthService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
        SessionRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas (response models - explicit field whitelist)
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class UserPublic(BaseModel):
    """The fields the dashboard is allowed to read.

    Explicit whitelist - never `from_attributes=True` directly on
    the ORM model. Adding a field here is a deliberate decision a
    reviewer can spot.
    """

    id: uuid.UUID
    email: str
    first_name: str | None
    last_name: str | None
    display_name: str | None
    is_admin: bool
    timezone: str
    created_at: datetime


class UserMembershipSummary(BaseModel):
    """One of the current user's memberships - the slim three-field
    shape the dashboard needs for the project switcher.

    Intentionally NOT called ``MembershipPublic`` - the canonical
    resource with that name lives in
    :mod:`z4j_brain.api.memberships` and carries the full
    ``(id, user_id, user_email, user_display_name, created_at,
    ...)`` shape. FastAPI would otherwise emit two schemas with
    the same title into the OpenAPI doc and force downstream
    codegen clients (ours included) onto ugly
    ``z4j_brain__api__...`` namespaced names.
    """

    project_id: uuid.UUID
    project_slug: str
    role: str


class UserMePublic(UserPublic):
    """``/auth/me`` payload - :class:`UserPublic` + memberships."""

    memberships: list[UserMembershipSummary]


class LoginResponse(BaseModel):
    user: UserPublic


class UpdateProfileRequest(BaseModel):
    """Body for ``PATCH /auth/me`` - self-service profile update.

    All fields optional; the endpoint only touches fields that
    are explicitly provided. ``first_name`` / ``last_name`` are
    structured name fields for SCIM / AD parity; ``display_name``
    remains the canonical render field (derived if absent).
    """

    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    timezone: str | None = None


class SessionPublic(BaseModel):
    """One active session as returned by ``GET /auth/sessions``."""

    id: uuid.UUID
    issued_at: datetime
    last_seen_at: datetime
    ip_at_issue: str
    user_agent_at_issue: str | None
    is_current: bool


class SessionRevokedResponse(BaseModel):
    revoked: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _derive_display_name(user: "User") -> str | None:
    """Same precedence rule as :mod:`z4j_brain.api.users`:
    explicit ``display_name`` → ``"first last"`` → email local part.
    Kept in both modules so a change to the rule is a single grep.
    """
    if user.display_name:
        return user.display_name
    first = (user.first_name or "").strip()
    last = (user.last_name or "").strip()
    combined = f"{first} {last}".strip()
    if combined:
        return combined
    return user.email.split("@", 1)[0] if user.email else None


def _user_payload(user: "User") -> UserPublic:
    return UserPublic(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        display_name=_derive_display_name(user),
        is_admin=user.is_admin,
        timezone=user.timezone,
        created_at=user.created_at,
    )


def _set_session_cookies(
    response: Response,
    *,
    settings: "Settings",
    session_id: uuid.UUID,
    csrf_token: str,
) -> None:
    """Set the session + csrf cookies on the response.

    Both cookies use the ``__Host-`` prefix in production for the
    secure-by-default cookie attributes. The csrf cookie is NOT
    HttpOnly so dashboard JS can read it and echo it as a header.
    """
    codec = SessionCookieCodec(settings)
    response.set_cookie(
        cookie_name(environment=settings.environment),
        codec.encode(session_id),
        **cookie_kwargs(
            environment=settings.environment,
            max_age_seconds=settings.session_absolute_lifetime_seconds,
            samesite=settings.session_cookie_samesite,
        ),
    )
    response.set_cookie(
        csrf_cookie_name(environment=settings.environment),
        csrf_token,
        **csrf_cookie_kwargs(
            environment=settings.environment,
            max_age_seconds=settings.session_absolute_lifetime_seconds,
        ),
    )


def _clear_session_cookies(response: Response, settings: "Settings") -> None:
    """Best-effort clear of both cookies."""
    for name in (
        cookie_name(environment=settings.environment),
        csrf_cookie_name(environment=settings.environment),
    ):
        response.delete_cookie(name, path="/")


async def _hold_minimum_response_time(
    start: float,
    min_duration_ms: int,
) -> None:
    """Sleep until a route has taken at least ``min_duration_ms``."""
    target_seconds = min_duration_ms / 1000.0
    remaining = target_seconds - (time.monotonic() - start)
    if remaining > 0:
        await asyncio.sleep(remaining)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=LoginResponse,
    dependencies=[Depends(require_login_throttle)],
)
async def login(
    request: Request,
    request_body: LoginRequest,
    response: Response,
    settings: "Settings" = Depends(get_settings),
    auth_service: "AuthService" = Depends(get_auth_service),
    users: "UserRepository" = Depends(get_user_repo),
    sessions: "SessionRepository" = Depends(get_session_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> LoginResponse:
    """Authenticate a user and mint a session.

    On any failure (wrong email, wrong password, locked, inactive)
    raises :class:`AuthenticationError` which the error middleware
    maps to 401 with the byte-identical envelope. The caller cannot
    distinguish between the failure modes.
    """
    # User-Agent is stored on the session row so the Account →
    # Security tab can show where each session was issued from.
    # The repository truncates it to 256 chars, so we pass it raw.
    user_agent = request.headers.get("user-agent")
    #
    # Both branches MUST commit. The failure branch needs to
    # persist the audit row + lockout counter bump, otherwise the
    # rollback inside ``get_session`` throws them away. We catch,
    # commit, then re-raise so the error middleware sees the same
    # 401 envelope.
    from z4j_brain.errors import AuthenticationError as _AuthErr

    try:
        session_row = await auth_service.login(
            users=users,
            sessions=sessions,
            audit_log=audit_log,
            email_raw=request_body.email,
            password_raw=request_body.password,
            ip=ip,
            user_agent=user_agent or None,
        )
    except _AuthErr:
        await db_session.commit()
        raise
    await db_session.commit()

    user = await users.get(session_row.user_id)
    assert user is not None  # auth_service guarantees the row exists

    _set_session_cookies(
        response,
        settings=settings,
        session_id=session_row.id,
        csrf_token=session_row.csrf_token,
    )
    return LoginResponse(user=_user_payload(user))


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def logout(
    response: Response,
    settings: "Settings" = Depends(get_settings),
    auth_service: "AuthService" = Depends(get_auth_service),
    sessions: "SessionRepository" = Depends(get_session_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    user: "User" = Depends(get_current_user),
    session_row: "SessionRow" = Depends(get_current_session),
    ip: str = Depends(get_client_ip),
) -> Response:
    await auth_service.logout(
        sessions=sessions,
        audit_log=audit_log,
        session_row=session_row,
        user=user,
        ip=ip,
        user_agent=None,
    )
    await db_session.commit()
    _clear_session_cookies(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserMePublic)
async def me(
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
) -> UserMePublic:
    """Return the current user with their project memberships.

    The dashboard's project switcher reads this on every page
    load to know which projects to render in the sidebar and what
    role the user holds in each.
    """
    if user.is_admin:
        # Global admins see every active project. Synthesize an
        # ADMIN membership row per project so the dashboard can
        # render them in the switcher.
        all_projects = await projects.list(limit=500, offset=0)
        membership_rows = [
            UserMembershipSummary(
                project_id=p.id,
                project_slug=p.slug,
                role="admin",
            )
            for p in all_projects
            if p.is_active
        ]
    else:
        rows = await memberships.list_for_user(user.id)
        membership_rows = []
        if rows:
            project_rows = await projects.list_by_ids(
                {m.project_id for m in rows}, only_active=True,
            )
            by_id = {p.id: p for p in project_rows}
            for m in rows:
                project = by_id.get(m.project_id)
                if project is None:
                    continue
                membership_rows.append(
                    UserMembershipSummary(
                        project_id=project.id,
                        project_slug=project.slug,
                        role=m.role.value,
                    ),
                )

    base = _user_payload(user)
    return UserMePublic(
        id=base.id,
        email=base.email,
        first_name=base.first_name,
        last_name=base.last_name,
        display_name=base.display_name,
        is_admin=base.is_admin,
        timezone=base.timezone,
        created_at=base.created_at,
        memberships=membership_rows,
    )


# ---------------------------------------------------------------------------
# Self-service password change
# ---------------------------------------------------------------------------


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


@router.post(
    "/change-password",
    response_model=LoginResponse,
    dependencies=[Depends(require_csrf)],
)
async def change_password(
    request: Request,
    response: Response,
    body: ChangePasswordRequest,
    user: "User" = Depends(get_current_user),
    session_row: "SessionRow" = Depends(get_current_session),
    settings: "Settings" = Depends(get_settings),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> LoginResponse:
    """Self-service password change for the current user.

    Verifies the current password, validates the new password
    against the policy, hashes it, and rotates the session atomic-
    ally:

    1. ``update_password_hash`` writes the new hash and bumps
       ``password_changed_at``.
    2. ``sessions.revoke_all_for_user`` explicitly revokes every
       prior session (audit H3 - the timestamp check alone leaves
       stale ``revoked_at IS NULL`` rows that still show in the
       Account → Security tab until each is next touched).
    3. A fresh session is minted + cookies reset so the caller
       keeps working without an extra login round-trip.
    """
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.auth.sessions import generate_csrf_token
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.repositories import (
        SessionRepository,
        UserRepository,
    )

    hasher = PasswordHasher(settings)
    users = UserRepository(db_session)
    sessions = SessionRepository(db_session)

    # Lock the user row so two concurrent change_password requests
    # for the same user serialise here. Without this, both can
    # pass ``verify`` and both call ``revoke_all_for_user`` +
    # ``sessions.create``, leaving TWO live post-rotation
    # sessions instead of one (R3 finding H6). SQLite ignores
    # FOR UPDATE; the test suite covers per-process serialisation
    # there. Postgres honours it strictly.
    await users.lock_for_password_change(user.id)

    if not hasher.verify(user.password_hash, body.current_password):
        from z4j_brain.errors import AuthenticationError

        raise AuthenticationError(
            "current password is incorrect",
            details={"reason": "wrong_current_password"},
        )

    hasher.validate_policy(body.new_password)
    new_hash = hasher.hash(body.new_password)

    await users.update_password_hash(
        user.id, new_hash, password_changed=True,
    )
    # Explicit revoke so every prior session row is flagged in the
    # database, not just implicitly defeated by the
    # ``password_changed_at`` timestamp check.
    await sessions.revoke_all_for_user(
        user.id, reason="password_changed",
    )

    # Mint a fresh session for the caller. ``issued_at`` is after
    # ``password_changed_at`` so the new session passes the live
    # check immediately; the old cookie's session id is already in
    # the revoked set.
    from datetime import UTC, datetime, timedelta

    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.session_absolute_lifetime_seconds,
    )
    new_csrf = generate_csrf_token()
    new_session = await sessions.create(
        user_id=user.id,
        csrf_token=new_csrf,
        expires_at=expires_at,
        ip_at_issue=ip,
        user_agent_at_issue=request.headers.get("user-agent"),
    )

    _set_session_cookies(
        response,
        settings=settings,
        session_id=new_session.id,
        csrf_token=new_csrf,
    )

    await AuditService(settings).record(
        audit_log,
        action="auth.password_changed",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"revoked_previous_session_id": str(session_row.id)},
    )
    await db_session.commit()

    return LoginResponse(user=_user_payload(user))


# ---------------------------------------------------------------------------
# Profile update (self-service)
# ---------------------------------------------------------------------------


@router.patch(
    "/me",
    response_model=UserMePublic,
    dependencies=[Depends(require_csrf)],
)
async def update_profile(
    body: UpdateProfileRequest,
    user: "User" = Depends(get_current_user),
    users: "UserRepository" = Depends(get_user_repo),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> UserMePublic:
    """Update the current user's display name and/or timezone.

    Only fields present in the request body are changed. Returns
    the full ``UserMePublic`` payload (same shape as ``GET /me``)
    so the dashboard can update its local state in one round-trip.
    """
    # Build kwargs - only pass fields that were explicitly set in
    # the request body so the repository sentinel logic works.
    kwargs: dict[str, object] = {}
    if body.first_name is not None:
        kwargs["first_name"] = body.first_name
    if body.last_name is not None:
        kwargs["last_name"] = body.last_name
    if body.display_name is not None:
        kwargs["display_name"] = body.display_name
    if body.timezone is not None:
        kwargs["timezone"] = body.timezone

    if kwargs:
        updated = await users.update_profile(user.id, **kwargs)
        assert updated is not None
        user = updated

    await db_session.commit()

    # Re-use the same membership-loading logic as GET /me.
    if user.is_admin:
        all_projects = await projects.list(limit=500, offset=0)
        membership_rows = [
            UserMembershipSummary(
                project_id=p.id,
                project_slug=p.slug,
                role="admin",
            )
            for p in all_projects
            if p.is_active
        ]
    else:
        rows = await memberships.list_for_user(user.id)
        membership_rows = []
        if rows:
            project_rows = await projects.list_by_ids(
                {m.project_id for m in rows}, only_active=True,
            )
            by_id = {p.id: p for p in project_rows}
            for m in rows:
                project = by_id.get(m.project_id)
                if project is None:
                    continue
                membership_rows.append(
                    UserMembershipSummary(
                        project_id=project.id,
                        project_slug=project.slug,
                        role=m.role.value,
                    ),
                )

    base = _user_payload(user)
    return UserMePublic(
        id=base.id,
        email=base.email,
        first_name=base.first_name,
        last_name=base.last_name,
        display_name=base.display_name,
        is_admin=base.is_admin,
        timezone=base.timezone,
        created_at=base.created_at,
        memberships=membership_rows,
    )


# ---------------------------------------------------------------------------
# Session management (self-service)
# ---------------------------------------------------------------------------


@router.get("/sessions", response_model=list[SessionPublic])
async def list_sessions(
    user: "User" = Depends(get_current_user),
    session_row: "SessionRow" = Depends(get_current_session),
    sessions: "SessionRepository" = Depends(get_session_repo),
) -> list[SessionPublic]:
    """Return every active (non-revoked, non-expired) session for the
    current user.

    The ``is_current`` flag marks which session corresponds to the
    cookie that made this request, so the dashboard can highlight
    "this device" in the sessions list.
    """
    active = await sessions.list_active_for_user(user.id)
    # SQLAlchemy maps Postgres ``inet`` to a Python
    # ``ipaddress.IPv4Address`` / ``IPv6Address``. Pydantic's
    # ``str`` field validator under ``ConfigDict(strict=True)``
    # rejects those, so we coerce here. SQLite returns a plain
    # ``str`` already - the ``str(...)`` call is a no-op there.
    return [
        SessionPublic(
            id=s.id,
            issued_at=s.issued_at,
            last_seen_at=s.last_seen_at,
            ip_at_issue=str(s.ip_at_issue) if s.ip_at_issue is not None else "",
            user_agent_at_issue=s.user_agent_at_issue,
            is_current=(s.id == session_row.id),
        )
        for s in active
    ]


@router.post(
    "/sessions/{session_id}/revoke",
    response_model=SessionRevokedResponse,
    dependencies=[Depends(require_csrf)],
)
async def revoke_session(
    session_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    sessions: "SessionRepository" = Depends(get_session_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> SessionRevokedResponse:
    """Revoke a specific session belonging to the current user.

    The session must exist and belong to the authenticated user -
    users cannot revoke other users' sessions. Returns 404 if the
    session does not exist or does not belong to the caller.
    """
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.errors import NotFoundError

    target = await sessions.get(session_id)
    if target is None or target.user_id != user.id:
        raise NotFoundError(
            "session not found",
            details={"session_id": str(session_id)},
        )

    await sessions.revoke(session_id, reason="user_revoke")

    await AuditService(settings).record(
        audit_log,
        action="auth.session_revoked",
        target_type="session",
        target_id=str(session_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
        metadata={"revoked_session_id": str(session_id)},
    )
    await db_session.commit()

    return SessionRevokedResponse(revoked=True)


# ---------------------------------------------------------------------------
# Password reset (request + confirm)
# ---------------------------------------------------------------------------


class PasswordResetRequestBody(BaseModel):
    email: EmailStr


class PasswordResetRequestResponse(BaseModel):
    # Always the same constant shape regardless of whether the
    # email exists OR whether email delivery is configured -
    # prevents email enumeration. Docs tell users to check their
    # email; if nothing arrives, contact an admin. The system
    # deliberately does not tell the caller "we tried to send"
    # vs "the project has no email channel" vs "no such user".
    accepted: bool = True


class PasswordResetConfirmBody(BaseModel):
    token: str = Field(min_length=10, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class PasswordResetConfirmResponse(BaseModel):
    success: bool = True


_PW_RESET_TTL_MINUTES = 30


def _hash_reset_token(plaintext: str, settings: "Settings") -> str:
    """HMAC-SHA256 of a plaintext reset token - same construction
    as the invitation token hash. Keyed by the server secret so a
    DB exfil alone can't forge tokens.
    """
    import hmac
    from hashlib import sha256

    secret = settings.secret.get_secret_value().encode()
    return hmac.new(secret, plaintext.encode(), sha256).hexdigest()


@router.post(
    "/password-reset/request",
    response_model=PasswordResetRequestResponse,
    dependencies=[Depends(require_password_reset_throttle)],
)
async def password_reset_request(
    request: Request,
    body: PasswordResetRequestBody,
    background_tasks: BackgroundTasks,
    settings: "Settings" = Depends(get_settings),
    users: "UserRepository" = Depends(get_user_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> PasswordResetRequestResponse:
    """Request a password-reset token.

    Response is constant-shape + constant-time (audit M2): token
    minting + email dispatch happen in a background task after
    the response is flushed, so the known-user path and the
    unknown-user path are indistinguishable to a timing attacker.
    The caller ALWAYS gets ``accepted=True``. If nothing arrives
    in the user's inbox they know to contact an admin - the
    system deliberately does not confirm or deny account
    existence.
    """
    start = time.monotonic()
    import secrets
    from datetime import UTC, datetime, timedelta

    from z4j_brain.domain.auth_service import canonicalize_email
    from z4j_brain.persistence.models import PasswordResetToken

    email_canonical = canonicalize_email(body.email)
    user = await users.get_by_email(email_canonical)

    if user is not None:
        # Mint the token + commit now so the background task has a
        # valid row to reference. The SMTP roundtrip happens AFTER
        # the response is flushed, out of the critical path.
        plaintext = secrets.token_urlsafe(32)
        token_hash = _hash_reset_token(plaintext, settings)
        expires_at = datetime.now(UTC) + timedelta(
            minutes=_PW_RESET_TTL_MINUTES,
        )
        row = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        db_session.add(row)
        await db_session.flush()

        from z4j_brain.domain.audit_service import AuditService

        audit_svc = AuditService(settings)
        await audit_svc.record(
            audit_log,
            action="auth.password_reset_requested",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            source_ip=ip,
        )
        await db_session.commit()

        user_id = user.id
        user_email = user.email
        db = request.app.state.db
        background_tasks.add_task(
            _send_password_reset_email,
            db=db,
            user_id=user_id,
            user_email=user_email,
            plaintext_token=plaintext,
            settings=settings,
        )
    # No-op for unknown users - no DB writes, no background task.
    # Hold both branches to the same floor as login so the DB/audit
    # work in the known-user branch does not become an account
    # enumeration timing oracle.
    await _hold_minimum_response_time(start, settings.login_min_duration_ms)
    return PasswordResetRequestResponse(accepted=True)


async def _send_password_reset_email(
    *,
    db: "DatabaseManager",
    user_id: "uuid.UUID",
    user_email: str,
    plaintext_token: str,
    settings: "Settings",
) -> None:
    """Background task: find a project email channel for the user
    and dispatch the reset link.

    Runs AFTER the HTTP response is flushed so the caller can't
    time the known-user branch vs. unknown-user branch. Opens its
    own DB session because the request's session is closed by
    the time this fires.
    """
    import logging

    from z4j_brain.domain.notifications.channels import deliver_email
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        NotificationChannelRepository,
    )

    logger = logging.getLogger("z4j.brain.auth.password_reset")
    # Round-9 audit fix R9-Auth-MED (Apr 2026): place the token
    # in the URL FRAGMENT rather than the query string. The
    # fragment is never sent in the Referer header to third-party
    # assets on the reset page, never written to server-side
    # access logs, and is excluded from most browser-history
    # sync mechanisms. The reset page's JS reads it via
    # ``window.location.hash`` and POSTs it with the form. Same
    # 256-bit token, same TTL, just shifted to a header / cache
    # surface that doesn't leak.
    accept_url = (
        f"{settings.public_url.rstrip('/')}/reset#token={plaintext_token}"
        if getattr(settings, "public_url", None)
        else f"/reset#token={plaintext_token}"
    )
    subject = "z4j: password reset requested"
    email_body = (
        f"A password reset was requested for {user_email}.\n\n"
        f"If this was you, follow this link to set a new password:\n"
        f"{accept_url}\n\n"
        f"This link is single-use and expires in "
        f"{_PW_RESET_TTL_MINUTES} minutes. If you did not request "
        f"a reset, you can safely ignore this message.\n\n"
        f"-- z4j"
    )

    try:
        async with db.session() as session:
            memberships_repo = MembershipRepository(session)
            user_memberships = await memberships_repo.list_for_user(user_id)
            channel_repo = NotificationChannelRepository(session)
            for m in user_memberships:
                try:
                    channels = await channel_repo.list_for_project(
                        m.project_id, active_only=True,
                    )
                except Exception:  # noqa: BLE001
                    continue
                email_channels = [c for c in channels if c.type == "email"]
                for channel in email_channels:
                    try:
                        result = await deliver_email(
                            config=dict(channel.config or {}),
                            payload={
                                "subject": subject,
                                "body": email_body,
                                "to_addrs": [user_email],
                            },
                        )
                        if result.success:
                            return
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "z4j: password-reset email channel %s crashed",
                            channel.id,
                        )
    except Exception:  # noqa: BLE001
        logger.exception("z4j: password-reset background send failed")


@router.post(
    "/password-reset/confirm",
    response_model=PasswordResetConfirmResponse,
    dependencies=[Depends(require_password_reset_throttle)],
)
async def password_reset_confirm(
    body: PasswordResetConfirmBody,
    settings: "Settings" = Depends(get_settings),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> PasswordResetConfirmResponse:
    """Consume a reset token and set a new password.

    Single-use: the token row's ``consumed_at`` is stamped in the
    same transaction as the password update. Once consumed the
    token is rejected on replay even though the row stays around
    for the audit trail.

    Revokes every existing session for the user so an attacker
    who had a session open doesn't survive the reset.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select

    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.models import PasswordResetToken
    from z4j_brain.persistence.repositories import (
        SessionRepository,
        UserRepository,
    )

    token_hash = _hash_reset_token(body.token, settings)
    stmt = select(PasswordResetToken).where(
        PasswordResetToken.token_hash == token_hash,
    )
    row = (await db_session.execute(stmt)).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.consumed_at is not None or row.expires_at < now:
        raise NotFoundError("invalid_or_expired")

    users_repo = UserRepository(db_session)
    user = await users_repo.get(row.user_id)
    if user is None:
        raise NotFoundError("invalid_or_expired")

    hasher = PasswordHasher(settings)
    # Round-9 audit fix R9-Auth-H1 (Apr 2026): enforce the password
    # policy on reset-confirm. Pre-fix this call site went straight
    # to ``hasher.hash`` while every OTHER write path
    # (``setup_service.complete``, ``change_password``,
    # ``invitations.accept``) called ``validate_policy`` first. An
    # attacker who phished a reset link could land any 8-char
    # password on the account, Pydantic enforced ``min_length=8``
    # but nothing else. Now mirrors ``change_password`` exactly.
    hasher.validate_policy(body.new_password)
    new_hash = hasher.hash(body.new_password)

    # Correct repo signatures (audit H1: earlier code used wrong
    # kwarg names and would 500 on every call, leaving the reset
    # token un-consumed and replayable until TTL).
    await users_repo.update_password_hash(
        user.id, new_hash, password_changed=True,
    )
    row.consumed_at = now
    # Revoke every existing session for this user - attacker who
    # had a live session must not survive the reset.
    sessions_repo = SessionRepository(db_session)
    await sessions_repo.revoke_all_for_user(
        user.id, reason="password_reset",
    )
    # Invalidate any OTHER unconsumed reset tokens for this user
    # so a minted-but-unused token from an earlier request can't
    # second-reset the account (audit M5).
    from sqlalchemy import update as _sa_update
    await db_session.execute(
        _sa_update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.id != row.id,
        )
        .values(consumed_at=now),
    )

    audit_svc = AuditService(settings)
    await audit_svc.record(
        audit_log,
        action="auth.password_reset_completed",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
    )
    await db_session.commit()
    return PasswordResetConfirmResponse(success=True)


__all__ = ["router"]
