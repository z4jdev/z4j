"""``/api/v1/projects/{slug}/stats`` REST router.

Aggregations the dashboard's "overview" page renders as cards.
Single endpoint, single round-trip - the dashboard fetches once
on page load and refetches every N seconds via TanStack Query
``refetchInterval``.

The query set is intentionally lean: a few COUNT and one
``GROUP BY`` over the indexed paths. Every query takes its
``project_id`` as the leading filter so the partial / composite
indexes from B2 cover them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
)
from z4j_brain.persistence.enums import (
    AgentState,
    CommandStatus,
    ProjectRole,
    TaskState,
    WorkerState,
)
from z4j_brain.persistence.models import Agent, Command, Queue, Task, Worker

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(prefix="/projects/{slug}/stats", tags=["stats"])


class TaskStateCounts(BaseModel):
    pending: int = 0
    received: int = 0
    started: int = 0
    success: int = 0
    failure: int = 0
    retry: int = 0
    revoked: int = 0
    rejected: int = 0
    unknown: int = 0


class QueueHealth(BaseModel):
    """Per-queue health snapshot."""

    name: str
    engine: str
    pending_count: int
    broker_type: str | None = None
    last_seen_at: str | None = None


class SystemHealth(BaseModel):
    """Overall system health assessment."""

    status: str  # healthy / degraded / critical
    agents_all_online: bool
    queue_depth_ok: bool
    failure_rate_ok: bool
    brain_db_ok: bool = True


class StatsResponse(BaseModel):
    """The aggregated overview the dashboard's stat cards render."""

    tasks_by_state: TaskStateCounts
    tasks_total: int
    tasks_failed_24h: int
    tasks_succeeded_24h: int
    failure_rate_24h: float  # 0..1
    agents_online: int
    agents_offline: int
    workers_online: int
    workers_offline: int
    commands_pending: int
    commands_completed_24h: int
    commands_failed_24h: int
    commands_timeout_24h: int
    queue_depths: list[QueueHealth] = []
    system_health: SystemHealth | None = None


@router.get("", response_model=StatsResponse)
async def get_stats(
    slug: str,
    hours: int = 24,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> StatsResponse:
    """Return aggregated project statistics.

    ``hours`` controls the time window for rate-based metrics
    (failure rate, command counts). Accepts 1, 6, 24, 72, 168.
    Defaults to 24.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine

    # Clamp hours to allowed values.
    allowed = {1, 6, 24, 72, 168}
    if hours not in allowed:
        hours = 24

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    cutoff_24h = datetime.now(UTC) - timedelta(hours=hours)

    # tasks by state
    state_rows = (
        await db_session.execute(
            select(Task.state, func.count(Task.id))
            .where(Task.project_id == project.id)
            .group_by(Task.state),
        )
    ).all()
    counts = TaskStateCounts()
    for state, count in state_rows:
        # state is a TaskState enum value
        setattr(counts, state.value if hasattr(state, "value") else str(state), int(count))
    tasks_total = sum(
        getattr(counts, name) for name in TaskStateCounts.model_fields
    )

    # 24h failure / success counts
    tasks_failed_24h = int(
        (
            await db_session.execute(
                select(func.count(Task.id))
                .where(
                    Task.project_id == project.id,
                    Task.state == TaskState.FAILURE,
                    Task.finished_at >= cutoff_24h,
                ),
            )
        ).scalar_one(),
    )
    tasks_succeeded_24h = int(
        (
            await db_session.execute(
                select(func.count(Task.id))
                .where(
                    Task.project_id == project.id,
                    Task.state == TaskState.SUCCESS,
                    Task.finished_at >= cutoff_24h,
                ),
            )
        ).scalar_one(),
    )
    total_24h = tasks_failed_24h + tasks_succeeded_24h
    failure_rate_24h = (
        tasks_failed_24h / total_24h if total_24h > 0 else 0.0
    )

    # agents online/offline
    agents_online = int(
        (
            await db_session.execute(
                select(func.count(Agent.id))
                .where(
                    Agent.project_id == project.id,
                    Agent.state == AgentState.ONLINE,
                ),
            )
        ).scalar_one(),
    )
    agents_offline = int(
        (
            await db_session.execute(
                select(func.count(Agent.id))
                .where(
                    Agent.project_id == project.id,
                    Agent.state != AgentState.ONLINE,
                ),
            )
        ).scalar_one(),
    )

    # workers online/offline
    workers_online = int(
        (
            await db_session.execute(
                select(func.count(Worker.id))
                .where(
                    Worker.project_id == project.id,
                    Worker.state == WorkerState.ONLINE,
                ),
            )
        ).scalar_one(),
    )
    workers_offline = int(
        (
            await db_session.execute(
                select(func.count(Worker.id))
                .where(
                    Worker.project_id == project.id,
                    Worker.state != WorkerState.ONLINE,
                ),
            )
        ).scalar_one(),
    )

    # command activity
    commands_pending = int(
        (
            await db_session.execute(
                select(func.count(Command.id))
                .where(
                    Command.project_id == project.id,
                    Command.status.in_(
                        [CommandStatus.PENDING, CommandStatus.DISPATCHED],
                    ),
                ),
            )
        ).scalar_one(),
    )
    commands_completed_24h = int(
        (
            await db_session.execute(
                select(func.count(Command.id))
                .where(
                    Command.project_id == project.id,
                    Command.status == CommandStatus.COMPLETED,
                    Command.completed_at >= cutoff_24h,
                ),
            )
        ).scalar_one(),
    )
    commands_failed_24h = int(
        (
            await db_session.execute(
                select(func.count(Command.id))
                .where(
                    Command.project_id == project.id,
                    Command.status == CommandStatus.FAILED,
                    Command.completed_at >= cutoff_24h,
                ),
            )
        ).scalar_one(),
    )
    commands_timeout_24h = int(
        (
            await db_session.execute(
                select(func.count(Command.id))
                .where(
                    Command.project_id == project.id,
                    Command.status == CommandStatus.TIMEOUT,
                    Command.completed_at >= cutoff_24h,
                ),
            )
        ).scalar_one(),
    )

    # Queue depths
    queue_rows = (
        await db_session.execute(
            select(Queue).where(Queue.project_id == project.id),
        )
    ).scalars().all()
    queue_depths = [
        QueueHealth(
            name=q.name,
            engine=q.engine,
            pending_count=q.pending_count,
            broker_type=q.broker_type,
            last_seen_at=q.last_seen_at.isoformat() if q.last_seen_at else None,
        )
        for q in queue_rows
    ]

    # System health assessment
    total_queue_depth = sum(q.pending_count for q in queue_rows)
    health = SystemHealth(
        status="healthy",
        agents_all_online=agents_offline == 0 and agents_online > 0,
        queue_depth_ok=total_queue_depth < 10_000,
        failure_rate_ok=failure_rate_24h < 0.1,
        brain_db_ok=True,
    )
    if not health.agents_all_online or not health.queue_depth_ok:
        health.status = "degraded"
    if not health.failure_rate_ok:
        health.status = "degraded"
    if agents_online == 0:
        health.status = "critical"

    return StatsResponse(
        tasks_by_state=counts,
        tasks_total=tasks_total,
        tasks_failed_24h=tasks_failed_24h,
        tasks_succeeded_24h=tasks_succeeded_24h,
        failure_rate_24h=failure_rate_24h,
        agents_online=agents_online,
        agents_offline=agents_offline,
        workers_online=workers_online,
        workers_offline=workers_offline,
        commands_pending=commands_pending,
        commands_completed_24h=commands_completed_24h,
        commands_failed_24h=commands_failed_24h,
        commands_timeout_24h=commands_timeout_24h,
        queue_depths=queue_depths,
        system_health=health,
    )


__all__ = ["QueueHealth", "StatsResponse", "SystemHealth", "TaskStateCounts", "router"]
