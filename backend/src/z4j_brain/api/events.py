"""``/api/v1/projects/{slug}/events`` REST router."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from z4j_brain.api._pagination import (
    clamp_limit,
    decode_cursor,
    encode_cursor,
)
from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
)
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Event, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/events", tags=["events"])


class EventPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    agent_id: uuid.UUID
    engine: str
    task_id: str
    kind: str
    occurred_at: datetime
    payload: dict[str, Any]


class EventListResponse(BaseModel):
    items: list[EventPublic]
    next_cursor: str | None


def _event_payload(event: "Event") -> EventPublic:
    return EventPublic(
        id=event.id,
        project_id=event.project_id,
        agent_id=event.agent_id,
        engine=event.engine,
        task_id=event.task_id,
        kind=event.kind,
        occurred_at=event.occurred_at,
        payload=dict(event.payload or {}),
    )


@router.get("", response_model=EventListResponse)
async def list_events_for_task(
    slug: str,
    engine: str = Query(..., min_length=1, max_length=40),
    task_id: str = Query(..., min_length=1, max_length=200),
    cursor: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=5000),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
) -> EventListResponse:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import EventRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    cursor_pair = decode_cursor(cursor)
    page_size = clamp_limit(
        limit,
        default=settings.rest_default_page_size,
        maximum=settings.rest_max_page_size,
    )

    rows = await EventRepository(db_session).list_for_task(
        project_id=project.id,
        engine=engine,
        task_id=task_id,
        cursor=cursor_pair,
        limit=page_size,
    )
    next_cursor: str | None = None
    if len(rows) == page_size:
        last = rows[-1]
        next_cursor = encode_cursor(last.occurred_at, last.id)

    return EventListResponse(
        items=[_event_payload(e) for e in rows],
        next_cursor=next_cursor,
    )


__all__ = ["EventListResponse", "EventPublic", "router"]
