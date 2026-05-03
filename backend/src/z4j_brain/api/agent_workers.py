"""``/api/v1/projects/{slug}/agent-workers`` REST router (1.2.1+).

The worker-first protocol's per-worker view. DISTINCT from the
existing ``/workers`` endpoint which serves engine-native worker
data (Celery / RQ workers known via broker heartbeat events):

- ``/workers``       - engine workers (Celery@web-01 etc.)
- ``/agent-workers`` - z4j agent processes (gunicorn worker
                       pid 12345, celery worker pid 12400, beat
                       pid 12500), tracked via the WebSocket
                       handshake protocol.

The dashboard's /workers page in 1.2.1+ joins both: every
agent_worker is shown, with optional engine-side details from
the engine workers table when there's a hostname/pid match.

Filters:

- ``state=online|offline`` (default: all)
- ``role=web|task|scheduler|beat|other`` (default: all)
- ``limit`` (default 200, hard cap 500)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

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

    from z4j_brain.persistence.models import AgentWorker, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(
    prefix="/projects/{slug}/agent-workers", tags=["agent-workers"],
)


class AgentWorkerPublic(BaseModel):
    """One row in the agent-workers list view.

    Fields mirror the ``agent_workers`` table directly with one
    addition: ``id`` is the row's UUID PK so URLs / row keys
    stay stable across the (agent_id, worker_id) reassignments
    that happen when workers cycle.
    """

    id: uuid.UUID
    agent_id: uuid.UUID
    project_id: uuid.UUID
    worker_id: str | None
    role: str | None
    framework: str | None
    pid: int | None
    started_at: datetime | None
    state: str
    last_seen_at: datetime | None
    last_connect_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _agent_worker_payload(row: "AgentWorker") -> AgentWorkerPublic:
    return AgentWorkerPublic(
        id=row.id,
        agent_id=row.agent_id,
        project_id=row.project_id,
        worker_id=row.worker_id,
        role=row.role,
        framework=row.framework,
        pid=row.pid,
        started_at=row.started_at,
        state=row.state,
        last_seen_at=row.last_seen_at,
        last_connect_at=row.last_connect_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=list[AgentWorkerPublic])
async def list_agent_workers(
    slug: str,
    state: str | None = Query(default=None, pattern="^(online|offline)$"),
    role: str | None = Query(
        default=None, pattern=r"^(web|task|scheduler|beat|other)$",
    ),
    limit: int = Query(default=200, ge=1, le=500),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[AgentWorkerPublic]:
    """List agent worker processes for a project.

    Returns rows ordered online-before-offline, then by
    last_seen_at descending. The role filter accepts only known
    values so a typo is rejected at the API layer rather than
    silently returning everything.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import AgentWorkerRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    repo = AgentWorkerRepository(db_session)
    rows = await repo.list_for_project(
        project.id, state=state, role=role, limit=limit,
    )
    return [_agent_worker_payload(r) for r in rows]


__all__ = ["AgentWorkerPublic", "router"]
