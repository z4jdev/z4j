"""``/api/v1/projects/{slug}/workers`` REST router."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

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

    metadata: dict[str, Any] = Field(default_factory=dict)


def _worker_payload(
    worker: Worker,
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
    worker: Worker,
    counts: dict[str, int] | None = None,
) -> WorkerDetailPublic:
    base = _worker_payload(worker, counts)
    return WorkerDetailPublic(
        **base.model_dump(),
        metadata=worker.worker_metadata or {},
    )


class LintFindingPublic(BaseModel):
    """One dangerous setting on one worker."""

    rule_id: str
    severity: str
    setting: str
    title: str
    detail: str
    remedy: str


class WorkerLintPublic(BaseModel):
    """Lint results for a single worker."""

    worker_id: uuid.UUID
    worker_name: str
    engine: str
    hostname: str | None
    evaluated: bool
    findings: list[LintFindingPublic]


class ProjectLintPublic(BaseModel):
    """Project-wide lint summary.

    ``workers_not_evaluated`` is reported separately from a clean result on
    purpose. A worker whose engine has no rules, or which reported no
    configuration, has not been judged, and presenting that as "no problems
    found" would overstate what the check actually knows.
    """

    workers_evaluated: int
    workers_not_evaluated: int
    findings_by_severity: dict[str, int]
    workers: list[WorkerLintPublic]


@router.get("/lint", response_model=ProjectLintPublic)
async def lint_workers(
    slug: str,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> ProjectLintPublic:
    """Flag worker configurations that lose or leak work.

    Evaluates the configuration each worker already reports on its
    heartbeat, so this costs one query and no new collection. Read-only and
    advisory: nothing here changes a worker, and a finding is a prompt to
    look rather than a fault.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.domain.worker_lint import (
        SEVERITY_ORDER,
        Severity,
        lint_worker_conf,
        supported_engines,
    )
    from z4j_brain.persistence.repositories import WorkerRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )

    repo = WorkerRepository(db_session)
    rows = await repo.list_for_project(project.id)
    engines_with_rules = supported_engines()

    results: list[WorkerLintPublic] = []
    counts: dict[str, int] = {}
    evaluated = 0
    for worker in rows:
        conf = (worker.worker_metadata or {}).get("conf")
        # ``None`` means the worker did not report configuration. An empty
        # mapping is still a report and is meaningful to rules whose unsafe
        # state is the absence of a setting (currently the time-limit rule).
        can_evaluate = worker.engine.lower() in engines_with_rules and conf is not None
        findings = lint_worker_conf(worker.engine, conf) if can_evaluate else []
        if can_evaluate:
            evaluated += 1
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        results.append(
            WorkerLintPublic(
                worker_id=worker.id,
                worker_name=worker.name,
                engine=worker.engine,
                hostname=worker.hostname,
                evaluated=can_evaluate,
                # asdict, not vars: Finding is a slots dataclass and has no
                # __dict__ to read.
                findings=[LintFindingPublic(**dataclasses.asdict(f)) for f in findings],
            )
        )

    # Worst-affected workers first, then the unevaluated ones last: an
    # operator opening this wants the problems, not the inventory.
    results.sort(
        key=lambda w: (
            min(
                (SEVERITY_ORDER[cast(Severity, f.severity)] for f in w.findings),
                default=len(SEVERITY_ORDER),
            ),
            -len(w.findings),
            w.worker_name,
        )
    )

    return ProjectLintPublic(
        workers_evaluated=evaluated,
        workers_not_evaluated=len(rows) - evaluated,
        findings_by_severity=counts,
        workers=results,
    )


@router.get("", response_model=list[WorkerPublic])
async def list_workers(
    slug: str,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> list[WorkerPublic]:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import WorkerRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
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
        project=project,
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
