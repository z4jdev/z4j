"""``/api/v1/projects/{slug}/workers`` REST router."""

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

    from z4j_brain.persistence.models import User, Worker
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(prefix="/projects/{slug}/workers", tags=["workers"])


class WorkerPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    engine: str
    name: str
    hostname: str | None
    pid: int | None
    concurrency: int | None
    queues: list[str]
    state: str
    last_heartbeat: datetime | None
    load_average: list[float] | None = None
    active_tasks: int
    processed: int = 0
    failed: int = 0
    succeeded: int = 0
    retried: int = 0
    created_at: datetime


class WorkerDetailPublic(WorkerPublic):
    """Extended worker data from control.inspect()."""

    metadata: dict = {}


def _worker_payload(
    worker: "Worker",
    counts: dict[str, int] | None = None,
) -> WorkerPublic:
    """Build the dashboard-facing worker row.

    ``counts`` comes from
    :meth:`WorkerRepository.counts_for_project` and is the
    authoritative source for per-worker totals - we used to derive
    them from ``worker_metadata.stats.total`` (Celery's
    ``inspect`` snapshot), but that dict only counts tasks the
    worker handled while it was alive AND only counts succeeds,
    so a restarted worker resets to zero and failures vanish. The
    events-table aggregation survives worker restarts and counts
    failures + retries independently.
    """
    c = counts or {}
    return WorkerPublic(
        id=worker.id,
        project_id=worker.project_id,
        engine=worker.engine,
        name=worker.name,
        hostname=worker.hostname,
        pid=worker.pid,
        concurrency=worker.concurrency,
        queues=list(worker.queues or []),
        state=worker.state.value,
        last_heartbeat=worker.last_heartbeat,
        load_average=worker.load_average,
        active_tasks=worker.active_tasks,
        processed=c.get("processed", 0),
        succeeded=c.get("succeeded", 0),
        failed=c.get("failed", 0),
        retried=c.get("retried", 0),
        created_at=worker.created_at,
    )


def _worker_detail_payload(
    worker: "Worker",
    counts: dict[str, int] | None = None,
) -> WorkerDetailPublic:
    base = _worker_payload(worker, counts)
    return WorkerDetailPublic(
        **base.model_dump(),
        metadata=worker.worker_metadata or {},
    )


@router.get("", response_model=list[WorkerPublic])
async def list_workers(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[WorkerPublic]:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import WorkerRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    repo = WorkerRepository(db_session)
    rows = await repo.list_for_project(project.id)
    counts = await repo.counts_for_project(project.id)
    return [_worker_payload(w, counts.get(w.name)) for w in rows]


@router.get("/{worker_id}", response_model=WorkerDetailPublic)
async def get_worker_detail(
    slug: str,
    worker_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> WorkerDetailPublic:
    """Get detailed worker info including inspect() data.

    Uses the worker's UUID (not hostname) so URLs don't break on
    special characters like ``@``.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import WorkerRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    repo = WorkerRepository(db_session)
    worker = await repo.get(worker_id)
    if worker is None or worker.project_id != project.id:
        raise NotFoundError(
            "worker not found",
            details={"worker_id": str(worker_id)},
        )
    counts = await repo.counts_for_project(project.id)
    return _worker_detail_payload(worker, counts.get(worker.name))


__all__ = ["WorkerDetailPublic", "WorkerPublic", "router"]
