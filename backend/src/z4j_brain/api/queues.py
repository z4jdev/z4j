"""``/api/v1/projects/{slug}/queues`` REST router."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
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

    from z4j_brain.persistence.models import Queue, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(prefix="/projects/{slug}/queues", tags=["queues"])


class QueuePublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    engine: str
    broker_type: str | None
    broker_url_hint: str | None
    last_seen_at: datetime | None
    created_at: datetime


def _queue_payload(queue: "Queue") -> QueuePublic:
    return QueuePublic(
        id=queue.id,
        project_id=queue.project_id,
        name=queue.name,
        engine=queue.engine,
        broker_type=queue.broker_type,
        broker_url_hint=queue.broker_url_hint,
        last_seen_at=queue.last_seen_at,
        created_at=queue.created_at,
    )


@router.get("", response_model=list[QueuePublic])
async def list_queues(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[QueuePublic]:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import QueueRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    rows = await QueueRepository(db_session).list_for_project(project.id)
    return [_queue_payload(q) for q in rows]


__all__ = ["QueuePublic", "router"]
