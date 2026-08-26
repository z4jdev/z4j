"""``/api/v1/projects/{slug}/issues`` REST router.

An "issue" is a distinct failure fingerprint on a project -- the same
logical bug grouped across runs and engines. This endpoint aggregates the
``tasks`` table by fingerprint and returns one row per issue with its
occurrence count, open-vs-recovered split, first/last seen, engines
affected, and a representative exception + task name.

``GET /projects/{slug}/issues`` -- VIEWER role. An issue is operational
data about tasks the member can already read (no who-did-what), so unlike
the audit log it is safe for any project member. Cursor-paginated with
optional engine / status / time-window filters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
)
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )

router = APIRouter(prefix="/projects/{slug}/issues", tags=["issues"])

IssueStatus = Literal["ongoing", "recovered"]


class IssuePublic(BaseModel):
    fingerprint: str
    status: IssueStatus
    occurrences: int
    open_count: int
    recovered_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    engine_count: int
    engines: list[str]
    sample_exception: str | None
    sample_task_name: str | None


class IssueListResponse(BaseModel):
    items: list[IssuePublic]
    next_cursor: str | None


@router.get("", response_model=IssueListResponse)
async def list_issues(
    slug: str,
    engine: str | None = Query(default=None),
    status: IssueStatus | None = Query(default=None, description="ongoing | recovered"),
    hours: int | None = Query(default=None, ge=1, le=8760, description="time window"),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> IssueListResponse:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import IssuesRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )

    since = datetime.now(UTC) - timedelta(hours=hours) if hours is not None else None

    rows, next_cursor = await IssuesRepository(db_session).list_issues(
        project_id=project.id,
        engine=engine,
        since=since,
        status=status,
        cursor=cursor,
        limit=limit,
    )
    return IssueListResponse(
        items=[
            IssuePublic(
                fingerprint=r.fingerprint,
                status="recovered" if r.open_count == 0 else "ongoing",
                occurrences=r.occurrences,
                open_count=r.open_count,
                recovered_count=r.recovered_count,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                engine_count=r.engine_count,
                engines=r.engines,
                sample_exception=r.sample_exception,
                sample_task_name=r.sample_task_name,
            )
            for r in rows
        ],
        next_cursor=next_cursor,
    )
