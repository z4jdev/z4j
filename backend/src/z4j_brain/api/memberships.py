"""``/api/v1/projects/{slug}/memberships`` REST router.

Project-scoped membership management. Project admins (or global
brain admins) can list, grant, and revoke memberships on the
project they administer.

Endpoints:

- ``GET    /``                 - list memberships on the project
- ``POST   /``                 - grant a user a role
- ``PATCH  /{membership_id}``  - change a user's role
- ``DELETE /{membership_id}``  - revoke a membership
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import select

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_user_repo,
    require_csrf,
)
from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
        UserRepository,
    )


router = APIRouter(
    prefix="/projects/{slug}/memberships",
    tags=["memberships"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class MembershipPublic(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    project_id: uuid.UUID
    user_email: str
    user_display_name: str | None
    role: str
    created_at: datetime


class GrantMembershipRequest(BaseModel):
    user_id: uuid.UUID
    role: str  # one of "viewer" / "operator" / "admin"


class UpdateMembershipRequest(BaseModel):
    role: str


def _coerce_role(value: str) -> ProjectRole:
    try:
        return ProjectRole(value)
    except ValueError as exc:
        raise ConflictError(
            f"unknown role {value!r}",
            details={"value": value},
        ) from exc


def _payload(membership: Membership, *, email: str, display_name: str | None) -> MembershipPublic:
    return MembershipPublic(
        id=membership.id,
        user_id=membership.user_id,
        project_id=membership.project_id,
        user_email=email,
        user_display_name=display_name,
        role=membership.role.value,
        created_at=membership.created_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[MembershipPublic])
async def list_memberships(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[MembershipPublic]:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.models import User as UserModel

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    rows = (
        await db_session.execute(
            select(Membership, UserModel.email, UserModel.display_name)
            .join(UserModel, UserModel.id == Membership.user_id)
            .where(Membership.project_id == project.id)
            .order_by(Membership.created_at.asc()),
        )
    ).all()
    return [
        _payload(m, email=email, display_name=display_name)
        for (m, email, display_name) in rows
    ]


@router.post(
    "",
    response_model=MembershipPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def grant_membership(
    slug: str,
    body: GrantMembershipRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    users_repo: "UserRepository" = Depends(get_user_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> MembershipPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )
    role = _coerce_role(body.role)

    target_user = await users_repo.get(body.user_id)
    if target_user is None or not target_user.is_active:
        raise NotFoundError(
            "user not found or inactive",
            details={"user_id": str(body.user_id)},
        )

    # Duplicate check - single-row lookup with a composite index
    # hit (users.id + projects.id) instead of Python-side scan of
    # every membership the user has (POL-4).
    existing = await memberships.get_for_user_project(
        user_id=target_user.id,
        project_id=project.id,
    )
    if existing is not None:
        raise ConflictError(
            "user already has a membership on this project",
            details={"user_id": str(target_user.id)},
        )

    membership = await memberships.grant(
        user_id=target_user.id,
        project_id=project.id,
        role=role,
    )

    # Materialize the project's default subscriptions for the new
    # member so they immediately receive bell notifications for the
    # project's "out of the box" alerts (e.g. task.failed).
    from z4j_brain.domain.notifications import NotificationService

    await NotificationService().materialize_defaults_for_member(
        session=db_session,
        user_id=target_user.id,
        project_id=project.id,
    )

    await audit.record(
        audit_log,
        action="membership.granted",
        target_type="user",
        target_id=str(target_user.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
        metadata={"role": role.value},
    )
    await db_session.commit()
    return _payload(
        membership,
        email=target_user.email,
        display_name=target_user.display_name,
    )


@router.patch(
    "/{membership_id}",
    response_model=MembershipPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_membership(
    slug: str,
    membership_id: uuid.UUID,
    body: UpdateMembershipRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    users_repo: "UserRepository" = Depends(get_user_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> MembershipPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )
    role = _coerce_role(body.role)

    membership = await memberships.get(membership_id)
    if membership is None or membership.project_id != project.id:
        raise NotFoundError(
            "membership not found",
            details={"membership_id": str(membership_id)},
        )

    # Last-admin protection: refuse to demote the only remaining admin.
    # Without this check an admin can accidentally (or maliciously)
    # lock every member out of admin-scoped settings.
    if (
        membership.role == ProjectRole.ADMIN
        and role != ProjectRole.ADMIN
    ):
        admin_count = await memberships.count_admins_for_project_for_update(project.id)
        if admin_count <= 1:
            raise ConflictError(
                "cannot demote the last admin - promote another "
                "member to admin first",
                details={"project_id": str(project.id)},
            )

    membership.role = role
    await db_session.flush()

    target_user = await users_repo.get(membership.user_id)
    assert target_user is not None  # FK guarantees this

    await audit.record(
        audit_log,
        action="membership.updated",
        target_type="user",
        target_id=str(membership.user_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
        metadata={"role": role.value},
    )
    await db_session.commit()
    return _payload(
        membership,
        email=target_user.email,
        display_name=target_user.display_name,
    )


@router.delete(
    "/{membership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def revoke_membership(
    slug: str,
    membership_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    membership = await memberships.get(membership_id)
    if membership is None or membership.project_id != project.id:
        raise NotFoundError(
            "membership not found",
            details={"membership_id": str(membership_id)},
        )

    # Last-admin protection: refuse to remove the only remaining admin
    # for the same reason update_membership refuses to demote them.
    if membership.role == ProjectRole.ADMIN:
        admin_count = await memberships.count_admins_for_project_for_update(project.id)
        if admin_count <= 1:
            raise ConflictError(
                "cannot remove the last admin - promote another "
                "member to admin first",
                details={"project_id": str(project.id)},
            )

    target_user_id = membership.user_id
    await memberships.delete(membership)

    # DATA-02 / HIGH-05: drop the user's per-(project, trigger)
    # subscriptions so they do not silently re-activate if the user
    # is re-added to the project later. user_notifications rows are
    # retained intentionally (inbox history for audit); if the
    # project itself is ever deleted the FK will CASCADE.
    from z4j_brain.persistence.repositories import UserSubscriptionRepository

    await UserSubscriptionRepository(db_session).delete_for_user_in_project(
        user_id=membership.user_id,
        project_id=project.id,
    )

    await audit.record(
        audit_log,
        action="membership.revoked",
        target_type="user",
        target_id=str(target_user_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
    )
    await db_session.commit()


__all__ = [
    "GrantMembershipRequest",
    "MembershipPublic",
    "UpdateMembershipRequest",
    "router",
]
