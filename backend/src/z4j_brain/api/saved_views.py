"""Personal task filter presets. Project membership never grants another user's views."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    require_csrf,
)
from z4j_brain.domain.policy_engine import PolicyEngine
from z4j_brain.persistence.enums import ProjectRole, TaskPriority, TaskState
from z4j_brain.persistence.repositories.saved_views import SavedViewRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Project, User
    from z4j_brain.persistence.repositories import MembershipRepository, ProjectRepository

router = APIRouter(prefix="/projects/{slug}/saved-views", tags=["saved-views"])


class SavedTaskFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: TaskState | None = None
    priority: list[TaskPriority] = Field(default_factory=list, max_length=4)
    search: str = Field(default="", max_length=200)

    @field_validator("priority")
    @classmethod
    def canonical_priorities(cls, value: list[TaskPriority]) -> list[TaskPriority]:
        return [priority for priority in TaskPriority if priority in value]


class SavedViewWrite(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=80)
    filters: SavedTaskFilters


class SavedViewPublic(SavedViewWrite):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


async def view_project(
    slug: str,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
) -> Project:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships, user=user, project=project, min_role=ProjectRole.VIEWER
    )
    return project


@router.get("", response_model=list[SavedViewPublic])
async def list_saved_views(
    user: User = Depends(get_current_user),
    project: Project = Depends(view_project),
    session: AsyncSession = Depends(get_session),
) -> list[SavedViewPublic]:
    views = await SavedViewRepository(session).list_for_owner(user.id, project.id)
    return [SavedViewPublic.model_validate(view) for view in views]


@router.post(
    "", response_model=SavedViewPublic, status_code=201, dependencies=[Depends(require_csrf)]
)
async def create_saved_view(
    body: SavedViewWrite,
    user: User = Depends(get_current_user),
    project: Project = Depends(view_project),
    session: AsyncSession = Depends(get_session),
) -> SavedViewPublic:
    view = await SavedViewRepository(session).save(
        user.id,
        project.id,
        name=body.name,
        filters=body.filters.model_dump(mode="json"),
    )
    await session.commit()
    return SavedViewPublic.model_validate(view)


@router.put("/{view_id}", response_model=SavedViewPublic, dependencies=[Depends(require_csrf)])
async def update_saved_view(
    view_id: uuid.UUID,
    body: SavedViewWrite,
    user: User = Depends(get_current_user),
    project: Project = Depends(view_project),
    session: AsyncSession = Depends(get_session),
) -> SavedViewPublic:
    view = await SavedViewRepository(session).save(
        user.id,
        project.id,
        view_id=view_id,
        name=body.name,
        filters=body.filters.model_dump(mode="json"),
    )
    await session.commit()
    return SavedViewPublic.model_validate(view)


@router.delete("/{view_id}", status_code=204, dependencies=[Depends(require_csrf)])
async def delete_saved_view(
    view_id: uuid.UUID,
    user: User = Depends(get_current_user),
    project: Project = Depends(view_project),
    session: AsyncSession = Depends(get_session),
) -> Response:
    await SavedViewRepository(session).delete(user.id, project.id, view_id)
    await session.commit()
    return Response(status_code=204)
