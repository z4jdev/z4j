"""``/api/v1/projects`` REST router.

Read endpoints scope to membership; write endpoints
(create / update / archive) require global brain admin.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import update

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    require_admin,
    require_csrf,
)
from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import Project, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$")


router = APIRouter(prefix="/projects", tags=["projects"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProjectPublic(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    environment: str
    timezone: str
    retention_days: int
    is_active: bool
    # 1.2.2+: which scheduler owns newly-created schedules in this
    # project when the operator didn't pick explicitly. Free-form
    # string so future schedulers can be added without a new enum.
    default_scheduler_owner: str
    # 1.2.2+: optional allow-list. ``None`` = unrestricted (the
    # default; backwards-compat with every existing operator).
    # When set, schedule create/update/import paths reject any
    # ``scheduler`` value not in the list.
    allowed_schedulers: list[str] | None = None
    created_at: datetime
    updated_at: datetime


# 1.2.2: known scheduler owner values. Free-form strings are also
# accepted (so future schedulers can be added without a code
# change), but these four are what the dashboard renders badges
# for + what the per-project default validator suggests.
# Audit fix CRIT-4 (1.2.2 seventh-pass): tightened from 64 to 40
# chars. ``Schedule.scheduler`` is ``String(40)`` (defined long
# before 1.2.2); a 41+ char value passing the regex but failing
# the INSERT was a latent inconsistency exposed by 1.2.2's
# default-resolution path. Both columns now agree at 40.
_SCHEDULER_OWNER_PATTERN = r"^[a-z][a-z0-9_-]{0,39}$"
_SCHEDULER_OWNER_REGEX = re.compile(_SCHEDULER_OWNER_PATTERN)


# Round-8 audit fix R8-Pyd-LOW (Apr 2026): tighten environment to
# a known-good shape. We use a pattern instead of Literal so older
# rows with values outside the canonical set (e.g. ``staging-eu``,
# ``qa1``) can still be re-PATCHed without forcing the operator to
# rename. The dashboard's audit-log filter knows the canonical
# four; anything else still renders as a plain string.
_ENVIRONMENT_PATTERN = r"^[a-z][a-z0-9_-]{0,39}$"


def _validate_allowed_schedulers_elements(
    value: list[str] | None,
) -> list[str] | None:
    """Reject non-conforming entries in ``allowed_schedulers``.

    Pydantic's `list[str]` allows free-form strings; this validator
    pins each element to the same regex we apply to
    ``default_scheduler_owner`` so the allow-list can't accumulate
    junk values like ``"; DROP TABLE"`` or ``"<script>"``. (Not a
    SQLi vector, the validator does ``==`` comparison, but it
    would render unsafely in the dashboard.) Audit fix HIGH-8
    second pass.
    """
    if value is None:
        return value
    for entry in value:
        if not isinstance(entry, str) or not _SCHEDULER_OWNER_REGEX.match(entry):
            raise ValueError(
                f"allowed_schedulers entries must match "
                f"{_SCHEDULER_OWNER_PATTERN!r}; got {entry!r}",
            )
    return value


class CreateProjectRequest(BaseModel):
    slug: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    environment: str = Field(
        default="production",
        max_length=40,
        pattern=_ENVIRONMENT_PATTERN,
    )
    timezone: str = Field(default="UTC", max_length=64)
    retention_days: int = Field(default=30, ge=1, le=3650)
    default_scheduler_owner: str = Field(
        default="z4j-scheduler",
        max_length=40,
        pattern=_SCHEDULER_OWNER_PATTERN,
    )
    # 1.2.2 audit fix MED-13: optional allow-list of scheduler
    # names that may own schedules in this project. ``None`` =
    # unrestricted. Cap at 32 entries (a generous fleet count) so
    # a typo'd config can't bloat the row.
    allowed_schedulers: list[str] | None = Field(
        default=None,
        max_length=32,
    )

    @field_validator("allowed_schedulers")
    @classmethod
    def _validate_allowed_schedulers(
        cls, v: list[str] | None,
    ) -> list[str] | None:
        return _validate_allowed_schedulers_elements(v)


class UpdateProjectRequest(BaseModel):
    slug: str | None = Field(default=None, min_length=2, max_length=63)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    environment: str | None = Field(
        default=None,
        max_length=40,
        pattern=_ENVIRONMENT_PATTERN,
    )
    timezone: str | None = Field(default=None, max_length=64)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    default_scheduler_owner: str | None = Field(
        default=None,
        max_length=40,
        pattern=_SCHEDULER_OWNER_PATTERN,
    )
    allowed_schedulers: list[str] | None = Field(
        default=None,
        max_length=32,
    )

    @field_validator("allowed_schedulers")
    @classmethod
    def _validate_allowed_schedulers(
        cls, v: list[str] | None,
    ) -> list[str] | None:
        return _validate_allowed_schedulers_elements(v)


def _project_payload(project: "Project") -> ProjectPublic:
    return ProjectPublic(
        id=project.id,
        slug=project.slug,
        name=project.name,
        description=project.description,
        environment=project.environment,
        timezone=project.timezone,
        retention_days=project.retention_days,
        is_active=project.is_active,
        default_scheduler_owner=getattr(
            project, "default_scheduler_owner", "z4j-scheduler",
        ),
        allowed_schedulers=getattr(project, "allowed_schedulers", None),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


# ---------------------------------------------------------------------------
# Read routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[ProjectPublic])
async def list_projects(
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    settings: "Settings" = Depends(get_settings),
) -> list[ProjectPublic]:
    """List the projects the current user has access to.

    When the caller is authenticated via a **project-scoped Bearer
    key**, the response is further filtered to only that bound
    project - the scope layer writes
    ``request.state.api_key_project_slug`` at auth time and this
    handler respects it. Without this filter a project-A-bound
    key could enumerate every project the owner user can see
    (external audit, Critical #1).
    """
    bound_slug: str | None = getattr(
        request.state, "api_key_project_slug", None,
    )

    if user.is_admin:
        rows = await projects.list(limit=settings.admin_project_list_cap, offset=0)
        payload = [_project_payload(p) for p in rows if p.is_active]
    else:
        member_rows = await memberships.list_for_user(user.id)
        project_ids = {m.project_id for m in member_rows}
        if not project_ids:
            return []
        rows = await projects.list_by_ids(project_ids, only_active=True)
        payload = [_project_payload(p) for p in rows]

    if bound_slug is not None:
        payload = [p for p in payload if p.slug == bound_slug]
    return payload


@router.get("/{slug}", response_model=ProjectPublic)
async def get_project(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
) -> ProjectPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    return _project_payload(project)


# ---------------------------------------------------------------------------
# Write routes - global brain admin only
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ProjectPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_project(
    body: CreateProjectRequest,
    admin: "User" = Depends(require_admin),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> ProjectPublic:
    if not _SLUG_RE.match(body.slug):
        raise ConflictError(
            "slug must match ^[a-z0-9][a-z0-9-]{1,62}$",
            details={"slug": body.slug},
        )
    existing = await projects.get_by_slug(body.slug)
    if existing is not None:
        raise ConflictError(
            "project slug already in use",
            details={"slug": body.slug},
        )

    # Audit fix HIGH-9 (1.2.2 second-pass): same cross-check as
    # update_project, if both default_scheduler_owner and
    # allowed_schedulers are set, the default must be in the list.
    if (
        body.allowed_schedulers is not None
        and body.default_scheduler_owner not in body.allowed_schedulers
    ):
        raise ConflictError(
            "default_scheduler_owner must be in allowed_schedulers "
            "when both are set",
            details={
                "default_scheduler_owner": body.default_scheduler_owner,
                "allowed_schedulers": list(body.allowed_schedulers),
            },
        )

    from z4j_brain.persistence.models import Project

    project = Project(
        slug=body.slug,
        name=body.name,
        description=body.description,
        environment=body.environment,
        timezone=body.timezone,
        retention_days=body.retention_days,
        default_scheduler_owner=body.default_scheduler_owner,
        allowed_schedulers=body.allowed_schedulers,
    )
    await projects.add(project)

    await audit.record(
        audit_log,
        action="project.created",
        target_type="project",
        target_id=str(project.id),
        result="success",
        outcome="allow",
        user_id=admin.id,
        project_id=project.id,
        source_ip=ip,
        metadata={"slug": body.slug},
    )
    await db_session.commit()
    return _project_payload(project)


@router.patch(
    "/{slug}",
    response_model=ProjectPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_project(
    slug: str,
    body: UpdateProjectRequest,
    admin: "User" = Depends(require_admin),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> ProjectPublic:
    """PATCH the project's mutable settings.

    NOTE on ``default_scheduler_owner`` semantics (1.2.2 round-9):
    flipping ``default_scheduler_owner`` only affects schedules
    created AFTER the change. Existing rows keep their stored
    ``Schedule.scheduler`` value (which was resolved at creation
    time from the THEN-current default). The next reconciler
    ``:import`` for those rows will resolve to the NEW default
    and treat the OLD-default rows as absent, under
    ``replace_for_source`` mode that means they get DELETED.
    Operators who want to retroactively migrate stored values
    use the ``z4j projects rewrite-scheduler --slug X
    --from A --to B`` CLI command (audit-logged, scoped to
    declarative-source rows by default).

    Why no auto-rewrite at PATCH time? Earlier 1.2.2 builds tried
    that and it created a six-round cascade of concurrency / lock
    / staleness bugs (rounds 3-8 in the audit history). The
    explicit-CLI design has one mutable knob with predictable
    semantics, instead of two coupled mutable knobs that need a
    distributed-systems infrastructure to keep in sync.
    """
    project = await projects.get_by_slug(slug)
    if project is None:
        raise NotFoundError(
            "project not found",
            details={"slug": slug},
        )
    changed: dict[str, object] = {}
    # Slug is the project's external identifier. Renaming is allowed
    # but the new slug must match the same format and not collide
    # with an existing project. Callers that bookmark the old URL
    # will get a 404 until they refresh - that's the accepted
    # trade-off of exposing slugs in the API surface.
    if body.slug is not None and body.slug != project.slug:
        if not _SLUG_RE.match(body.slug):
            raise ConflictError(
                "slug must match ^[a-z0-9][a-z0-9-]{1,62}$",
                details={"slug": body.slug},
            )
        existing = await projects.get_by_slug(body.slug)
        if existing is not None and existing.id != project.id:
            raise ConflictError(
                "project slug already in use",
                details={"slug": body.slug},
            )
        changed["slug"] = body.slug
        project.slug = body.slug
    for field in (
        "name", "description", "environment", "timezone", "retention_days",
        "default_scheduler_owner",
    ):
        value = getattr(body, field, None)
        if value is not None:
            changed[field] = value
            setattr(project, field, value)
    # ``allowed_schedulers`` is special: ``None`` is meaningful
    # (unrestricted), so we use the body's ``model_fields_set`` to
    # tell "explicitly omitted" from "explicitly set to None /
    # explicit empty list". Pydantic v2's ``model_fields_set``
    # carries exactly that info.
    if "allowed_schedulers" in body.model_fields_set:
        # Empty list = strict-deny (no scheduler allowed), that's
        # likely a misconfig, so we reject it. ``None`` = unrestricted.
        if body.allowed_schedulers is not None and len(
            body.allowed_schedulers,
        ) == 0:
            raise ConflictError(
                "allowed_schedulers cannot be an empty list "
                "(use null to remove the restriction)",
                details={"allowed_schedulers": []},
            )
        changed["allowed_schedulers"] = body.allowed_schedulers
        project.allowed_schedulers = body.allowed_schedulers
    # Audit fix HIGH-9 (1.2.2 second-pass): cross-check that the
    # post-PATCH ``default_scheduler_owner`` is in the allow-list.
    # The "default is implicitly allowed" rule means a mismatch
    # silently widens the allow-list, surprising operators who
    # set both. Reject so the operator gets an explicit signal.
    if (
        project.allowed_schedulers is not None
        and project.default_scheduler_owner not in project.allowed_schedulers
    ):
        raise ConflictError(
            "default_scheduler_owner must be in allowed_schedulers "
            "when both are set; the implicit-default-allowed rule "
            "would otherwise silently widen the allow-list. Add "
            f"{project.default_scheduler_owner!r} to "
            "allowed_schedulers, or change the default to one of "
            f"{sorted(project.allowed_schedulers)}.",
            details={
                "default_scheduler_owner": project.default_scheduler_owner,
                "allowed_schedulers": list(project.allowed_schedulers),
            },
        )
    project.updated_at = datetime.now(UTC)

    if changed:
        await audit.record(
            audit_log,
            action="project.updated",
            target_type="project",
            target_id=str(project.id),
            result="success",
            outcome="allow",
            user_id=admin.id,
            project_id=project.id,
            source_ip=ip,
            metadata={"changed": list(changed.keys())},
        )
    await db_session.commit()
    return _project_payload(project)


@router.delete(
    "/{slug}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def archive_project(
    slug: str,
    admin: "User" = Depends(require_admin),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    """Soft-archive a project (sets ``is_active=False``).

    We never hard-delete projects - that would cascade across the
    audit log and break the historical record. The archived
    project is hidden from list views but its rows survive.
    """
    project = await projects.get_by_slug(slug)
    if project is None:
        raise NotFoundError(
            "project not found",
            details={"slug": slug},
        )
    if not project.is_active:
        return  # idempotent

    active_count = await projects.count_active()
    if active_count <= 1:
        raise ConflictError(
            "cannot archive the last remaining project",
            details={"slug": slug},
        )

    project.is_active = False
    project.updated_at = datetime.now(UTC)
    await audit.record(
        audit_log,
        action="project.archived",
        target_type="project",
        target_id=str(project.id),
        result="success",
        outcome="allow",
        user_id=admin.id,
        project_id=project.id,
        source_ip=ip,
    )
    await db_session.commit()


__all__ = [
    "CreateProjectRequest",
    "ProjectPublic",
    "UpdateProjectRequest",
    "router",
]
