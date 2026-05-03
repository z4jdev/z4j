"""``/api/v1/users`` REST router - global brain admin only.

Operator surface for managing dashboard users:

- ``GET    /``                 - list users (paginated)
- ``POST   /``                 - create a new user
- ``GET    /{user_id}``        - user detail
- ``PATCH  /{user_id}``        - update display_name / is_active /
                                  is_admin / timezone
- ``POST   /{user_id}/password`` - admin password reset

Password resets force a session revocation across all of the
target user's sessions (B3's ``revoke_all_for_user`` path) so the
old credentials cannot be used after rotation.

This router is brain-admin only via :func:`require_admin` - there
is no per-project sub-resource here. Project membership management
lives in :mod:`z4j_brain.api.memberships`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_password_hasher,
    get_session,
    get_session_repo,
    get_user_repo,
    require_admin,
    require_csrf,
)
from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.models import User

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        SessionRepository,
        UserRepository,
    )


router = APIRouter(prefix="/users", tags=["users"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UserAdminPublic(BaseModel):
    id: uuid.UUID
    email: str
    first_name: str | None
    last_name: str | None
    display_name: str | None
    is_admin: bool
    is_active: bool
    timezone: str
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _validate_user_timezone(value: str | None) -> str | None:
    """Round-8 audit fix R8-Pyd-MED (Apr 2026): IANA tz validation.

    Mirrors the schedule API's tz validator. Pre-fix any 64-char
    string was accepted, so a typo like ``"America/New York"`` (with
    a space) was persisted on the user row, breaking dashboard
    renders that fed it to ``zoneinfo.ZoneInfo`` later.
    """
    if value is None or value == "":
        return value
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415

        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"timezone {value!r} is not a valid IANA timezone "
            "(e.g. 'UTC', 'America/New_York', 'Europe/London')",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"timezone {value!r} could not be resolved: {exc}",
        ) from exc
    return value


class CreateUserRequest(BaseModel):
    email: EmailStr
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=8, max_length=256)
    is_admin: bool = False
    timezone: str = Field(default="UTC", max_length=64)

    @field_validator("timezone")
    @classmethod
    def _check_tz(cls, v: str) -> str:
        return _validate_user_timezone(v) or "UTC"


class UpdateUserRequest(BaseModel):
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=200)
    is_admin: bool | None = None
    is_active: bool | None = None
    timezone: str | None = Field(default=None, max_length=64)

    @field_validator("timezone")
    @classmethod
    def _check_tz(cls, v: str | None) -> str | None:
        return _validate_user_timezone(v)


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=256)


def _derive_display_name(user: User) -> str | None:
    """Read-only computed display name.

    Precedence: explicit ``display_name`` → ``"first last"`` →
    email local part. Used only for the public payload when no
    explicit display_name was set, so admins can populate just
    first/last and get a sensible rendering without also filling
    in display_name.
    """
    if user.display_name:
        return user.display_name
    first = (user.first_name or "").strip()
    last = (user.last_name or "").strip()
    combined = f"{first} {last}".strip()
    if combined:
        return combined
    return user.email.split("@", 1)[0] if user.email else None


def _payload(user: User) -> UserAdminPublic:
    return UserAdminPublic(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        display_name=_derive_display_name(user),
        is_admin=user.is_admin,
        is_active=user.is_active,
        timezone=user.timezone,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[UserAdminPublic])
async def list_users(
    admin: User = Depends(require_admin),  # noqa: ARG001
    db_session: "AsyncSession" = Depends(get_session),
    limit: int = 100,
    offset: int = 0,
) -> list[UserAdminPublic]:
    """List every dashboard user. Bounded by ``limit``."""
    if limit <= 0 or limit > 500:
        limit = 100
    if offset < 0:
        offset = 0
    result = await db_session.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset),
    )
    return [_payload(u) for u in result.scalars().all()]


@router.post(
    "",
    response_model=UserAdminPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_user(
    body: CreateUserRequest,
    admin: User = Depends(require_admin),
    users: "UserRepository" = Depends(get_user_repo),
    hasher: "PasswordHasher" = Depends(get_password_hasher),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> UserAdminPublic:
    from z4j_brain.domain.auth_service import canonicalize_email

    email = canonicalize_email(body.email)
    existing = await users.get_by_email(email)
    if existing is not None:
        raise ConflictError(
            "email already in use",
            details={"email": email},
        )

    hasher.validate_policy(body.password)
    password_hash = hasher.hash(body.password)

    user = User(
        email=email,
        password_hash=password_hash,
        first_name=(body.first_name.strip() or None) if body.first_name else None,
        last_name=(body.last_name.strip() or None) if body.last_name else None,
        display_name=(body.display_name.strip() if body.display_name else None),
        is_admin=body.is_admin,
        is_active=True,
        timezone=body.timezone,
    )
    await users.add(user)

    await audit.record(
        audit_log,
        action="user.created",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=admin.id,
        source_ip=ip,
        metadata={"email": email, "is_admin": body.is_admin},
    )
    await db_session.commit()
    return _payload(user)


@router.get("/{user_id}", response_model=UserAdminPublic)
async def get_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),  # noqa: ARG001
    users: "UserRepository" = Depends(get_user_repo),
) -> UserAdminPublic:
    user = await users.get(user_id)
    if user is None:
        raise NotFoundError(
            "user not found",
            details={"user_id": str(user_id)},
        )
    return _payload(user)


@router.patch(
    "/{user_id}",
    response_model=UserAdminPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    admin: User = Depends(require_admin),
    users: "UserRepository" = Depends(get_user_repo),
    sessions: "SessionRepository" = Depends(get_session_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> UserAdminPublic:
    user = await users.get(user_id)
    if user is None:
        raise NotFoundError(
            "user not found",
            details={"user_id": str(user_id)},
        )

    # Self-lockout protection. An admin toggling their own is_admin
    # flag off or deactivating themselves through this endpoint has
    # no good use case and very bad failure mode. Refuse; direct the
    # admin to either use a separate admin account or log in as a
    # different admin first.
    if user.id == admin.id:
        if body.is_admin is False:
            raise ConflictError(
                "cannot remove admin role from your own account",
                details={"reason": "self_demote"},
            )
        if body.is_active is False:
            raise ConflictError(
                "cannot deactivate your own account",
                details={"reason": "self_deactivate"},
            )

    # Last-admin protection. Refuse to demote or deactivate the only
    # remaining active admin - the instance would lose all admin
    # access and become unrecoverable from the UI.
    would_strip_admin = (
        user.is_admin
        and user.is_active
        and (body.is_admin is False or body.is_active is False)
    )
    if would_strip_admin:
        # ``count_active_admins_for_update`` row-locks every active
        # admin until the next commit so two concurrent admin-edit
        # requests can't both think there are 2 admins and each
        # demote one. See repo docstring for the TOCTOU window.
        active_admins = await users.count_active_admins_for_update()
        if active_admins <= 1:
            raise ConflictError(
                "cannot remove the last admin - promote another "
                "user to admin first",
                details={"reason": "last_admin"},
            )

    changed: dict[str, object] = {}
    if body.first_name is not None:
        user.first_name = body.first_name.strip() or None
        changed["first_name"] = user.first_name
    if body.last_name is not None:
        user.last_name = body.last_name.strip() or None
        changed["last_name"] = user.last_name
    if body.display_name is not None:
        user.display_name = body.display_name.strip() or None
        changed["display_name"] = user.display_name
    if body.is_admin is not None:
        user.is_admin = body.is_admin
        changed["is_admin"] = body.is_admin
    if body.is_active is not None and body.is_active != user.is_active:
        user.is_active = body.is_active
        changed["is_active"] = body.is_active
        if not body.is_active:
            # Deactivation revokes every active session for the user.
            await sessions.revoke_all_for_user(
                user.id, reason="deactivated",
            )
    if body.timezone is not None:
        user.timezone = body.timezone
        changed["timezone"] = body.timezone

    # Populate updated_at explicitly so the post-commit response
    # serialization doesn't trigger a lazy refresh (which breaks on
    # aiosqlite because of greenlet context handoff).
    user.updated_at = datetime.now(UTC)

    if changed:
        await audit.record(
            audit_log,
            action="user.updated",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            user_id=admin.id,
            source_ip=ip,
            metadata={"changed": list(changed.keys())},
        )
    await db_session.commit()
    return _payload(user)


@router.post(
    "/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def reset_password(
    user_id: uuid.UUID,
    body: PasswordResetRequest,
    admin: User = Depends(require_admin),
    users: "UserRepository" = Depends(get_user_repo),
    sessions: "SessionRepository" = Depends(get_session_repo),
    hasher: "PasswordHasher" = Depends(get_password_hasher),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    """Admin password reset.

    Sets a fresh password hash, marks ``password_changed_at``,
    and revokes every active session for the target user. The
    ``password_changed_at`` anchor (B3) makes any session issued
    before this point unusable even before the explicit revoke.
    """
    user = await users.get(user_id)
    if user is None:
        raise NotFoundError(
            "user not found",
            details={"user_id": str(user_id)},
        )

    hasher.validate_policy(body.new_password)
    new_hash = hasher.hash(body.new_password)
    await users.update_password_hash(
        user.id, new_hash, password_changed=True,
    )
    await sessions.revoke_all_for_user(user.id, reason="password_changed")

    await audit.record(
        audit_log,
        action="user.password.reset",
        target_type="user",
        target_id=str(user.id),
        result="success",
        outcome="allow",
        user_id=admin.id,
        source_ip=ip,
    )
    await db_session.commit()


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def delete_user(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    users: "UserRepository" = Depends(get_user_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    """Permanently delete a user.

    FK cleanup: memberships / sessions / api_keys / preferences /
    subscriptions CASCADE; audit_log.user_id and commands.issued_by
    are SET NULL so historical records survive with an anonymised
    actor.

    Refuses to delete the acting admin (would log them out of the
    operation) and the only remaining active admin (would lock the
    instance out of admin UI). Callers that want a softer operation
    should PATCH ``is_active=false`` instead - the Users page wires
    the trash icon to this hard delete and the deactivate icon to
    the soft path, so the operator picks the semantic they want.
    """
    user = await users.get(user_id)
    if user is None:
        raise NotFoundError(
            "user not found",
            details={"user_id": str(user_id)},
        )

    if user.id == admin.id:
        raise ConflictError(
            "cannot delete your own account",
            details={"reason": "self_delete"},
        )

    if user.is_admin and user.is_active:
        # Row-lock to close the TOCTOU window between concurrent
        # delete requests (same protection as the demote path).
        active_admins = await users.count_active_admins_for_update()
        if active_admins <= 1:
            raise ConflictError(
                "cannot delete the last admin - promote another "
                "user to admin first",
                details={"reason": "last_admin"},
            )

    email_snapshot = user.email
    await db_session.delete(user)

    await audit.record(
        audit_log,
        action="user.deleted",
        target_type="user",
        target_id=str(user_id),
        result="success",
        outcome="allow",
        user_id=admin.id,
        source_ip=ip,
        metadata={"email": email_snapshot},
    )
    await db_session.commit()


__all__ = [
    "CreateUserRequest",
    "PasswordResetRequest",
    "UpdateUserRequest",
    "UserAdminPublic",
    "router",
]
