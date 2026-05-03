"""``/api/v1/projects/{slug}/commands`` REST router.

Read endpoints + the two operator-facing write endpoints
(retry-task, cancel-task) needed to demo the loop. Schedule
mutations, bulk operations, and worker control land in B5.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator

# Engines the brain knows how to dispatch commands to. This is the
# whitelist that gates ``RetryTaskRequest.engine`` /
# ``CancelTaskRequest.engine``. Adding a new engine = one line here.
# Keeping this centralized (vs a plain Enum on each request) so the
# error message at 422 time is clear + one code edit covers every
# endpoint that accepts an engine name.
#
# The brain already accepts ``Event.engine`` as a free-form string
# for *ingest* (so we don't break when an agent on a newer brain
# version reports a newly-added engine) - this list applies only
# to *dispatch*, where we have to actually have an adapter.
KNOWN_ENGINES: frozenset[str] = frozenset({"celery", "rq", "dramatiq"})

from z4j_brain.api._pagination import (
    clamp_limit,
    decode_cursor,
    encode_cursor,
)
from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_command_dispatcher,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    require_csrf,
)
from z4j_brain.domain.ip_rate_limit import require_bulk_action_throttle
from z4j_brain.errors import NotFoundError
from z4j_brain.persistence.enums import CommandStatus, ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.command_dispatcher import CommandDispatcher
    from z4j_brain.persistence.models import Command, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/commands", tags=["commands"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CommandPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    agent_id: uuid.UUID | None
    issued_by: uuid.UUID | None
    action: str
    target_type: str
    target_id: str | None
    payload: dict[str, Any]
    status: str
    result: Any | None
    error: str | None
    issued_at: datetime
    dispatched_at: datetime | None
    completed_at: datetime | None
    timeout_at: datetime


class CommandListResponse(BaseModel):
    items: list[CommandPublic]
    next_cursor: str | None


def _validate_engine_dispatch(value: str) -> str:
    """Reject dispatch requests for engines the brain cannot route to.

    Raises ``ValueError`` (→ FastAPI 422) with the known-engine list
    when the caller sends something like ``{"engine": "laravel"}``.
    Without this check, an unknown engine used to silently fall back
    to ``"celery"`` in two repository helpers (LATENT-1). See
    docs/MULTI_ENGINE_VERIFICATION_2026Q2.md §7.
    """
    if value not in KNOWN_ENGINES:
        raise ValueError(
            f"engine must be one of {sorted(KNOWN_ENGINES)}, got {value!r}",
        )
    return value


class RetryTaskRequest(BaseModel):
    agent_id: uuid.UUID
    engine: str = Field(min_length=1, max_length=40)
    task_id: str = Field(min_length=1, max_length=200)
    override_args: list[Any] | None = None
    override_kwargs: dict[str, Any] | None = None
    eta_seconds: int | None = Field(default=None, ge=0, le=86_400)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v: str) -> str:
        return _validate_engine_dispatch(v)

    @field_validator("override_args", "override_kwargs")
    @classmethod
    def _cap_overrides(cls, v: object) -> object:
        """Round-8 audit fix R8-Pyd-H3 (Apr 2026): cap override size.

        Pre-fix a 50 MB ``override_kwargs`` was parsed, persisted
        into ``commands.payload`` JSONB, HMAC-signed, and pushed
        over the wire to the agent, a single retry request could
        OOM the brain or wedge the WS frame cap downstream. The
        64 KiB ceiling matches the ``_validate_args_kwargs_size``
        cap already used on schedule create/update.
        """
        if v is None:
            return v
        import json as _json  # noqa: PLC0415

        try:
            size = len(_json.dumps(v).encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"override value is not JSON-serialisable: {exc}",
            ) from exc
        if size > 64 * 1024:
            raise ValueError(
                f"override payload {size} bytes exceeds 64 KiB cap",
            )
        return v


class CancelTaskRequest(BaseModel):
    agent_id: uuid.UUID
    engine: str = Field(min_length=1, max_length=40)
    task_id: str = Field(min_length=1, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v: str) -> str:
        return _validate_engine_dispatch(v)


class BulkRetryRequest(BaseModel):
    """Bulk retry request body.

    ``filter`` is forwarded to the agent verbatim. Common keys the
    celery adapter understands: ``state``, ``queue``, ``name``,
    ``since``, ``until``. ``max`` is hard-capped agent-side at 10000.
    """

    agent_id: uuid.UUID
    filter: dict[str, Any] = Field(default_factory=dict)
    max: int = Field(default=1000, ge=1, le=10_000)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class PurgeQueueRequest(BaseModel):
    """Purge-queue request body.

    The agent's per-engine ``purge_queue_action`` refuses to act
    unless one of the two confirmation fields is supplied:

    * ``confirm_token`` - HMAC of ``(queue_name, observed_depth)``.
      The caller (dashboard / API client) fetches the current depth
      first (from the agent's measurement, surfaced in the brain's
      queue-depth telemetry), computes the token with
      :func:`z4j_celery.actions.purge.expected_confirm_token`, and
      sends it here. The agent re-measures and re-computes; a
      mismatch means the depth moved (likely a replayed command).
    * ``force`` - bypass the token check and the depth threshold.
      Logged at CRITICAL by the agent; reserved for scripted
      emergency use.

    Audit 2026-04-24 Medium-3: these fields were missing from the
    brain request model, so every ``purge_queue`` command reached
    the agent with ``confirm_token=None`` and was rejected.
    """

    agent_id: uuid.UUID
    queue: str = Field(min_length=1, max_length=200)
    confirm_token: str | None = Field(
        default=None, min_length=1, max_length=128,
    )
    force: bool = False
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class RestartWorkerRequest(BaseModel):
    agent_id: uuid.UUID
    worker_name: str = Field(min_length=1, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class PoolResizeRequest(BaseModel):
    """Grow or shrink a worker's process pool."""

    agent_id: uuid.UUID
    worker_name: str = Field(min_length=1, max_length=200)
    delta: int = Field(ge=-100, le=100)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class ConsumerRequest(BaseModel):
    """Add or cancel a queue consumer on a worker."""

    agent_id: uuid.UUID
    worker_name: str = Field(min_length=1, max_length=200)
    queue: str = Field(min_length=1, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class RateLimitRequest(BaseModel):
    """Set or clear a per-task rate limit on one (or every) worker.

    ``rate`` follows Celery's grammar - integer optionally suffixed
    with ``/s``, ``/m``, ``/h``; ``"0"`` clears the limit. Pattern
    is enforced server-side so an obvious typo is rejected before
    we even mint a command row. ``worker_name`` is OPTIONAL: an
    omitted / empty value broadcasts the new rate to every worker
    subscribed to the broker (audit-flagged "global throttle"
    path; the agent-side action logs at CRITICAL when this fires).
    """

    agent_id: uuid.UUID
    task_name: str = Field(min_length=1, max_length=500)
    rate: str = Field(
        min_length=1,
        max_length=20,
        pattern=r"^(?:0|[1-9]\d*(?:/[smh])?)$",
    )
    worker_name: str | None = Field(default=None, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


def _command_payload(cmd: "Command") -> CommandPublic:
    return CommandPublic(
        id=cmd.id,
        project_id=cmd.project_id,
        agent_id=cmd.agent_id,
        issued_by=cmd.issued_by,
        action=cmd.action,
        target_type=cmd.target_type,
        target_id=cmd.target_id,
        payload=dict(cmd.payload or {}),
        status=cmd.status.value,
        result=cmd.result,
        error=cmd.error,
        issued_at=cmd.issued_at,
        dispatched_at=cmd.dispatched_at,
        completed_at=cmd.completed_at,
        timeout_at=cmd.timeout_at,
    )


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=CommandListResponse)
async def list_commands(
    slug: str,
    status: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=5000),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
) -> CommandListResponse:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import CommandRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    status_enum: CommandStatus | None = None
    if status:
        try:
            status_enum = CommandStatus(status)
        except ValueError:
            status_enum = None

    cursor_pair = decode_cursor(cursor)
    page_size = clamp_limit(
        limit,
        default=settings.rest_default_page_size,
        maximum=settings.rest_max_page_size,
    )

    rows = await CommandRepository(db_session).list_for_project(
        project_id=project.id,
        status=status_enum,
        cursor=cursor_pair,
        limit=page_size,
    )
    next_cursor: str | None = None
    if len(rows) == page_size:
        last = rows[-1]
        next_cursor = encode_cursor(last.issued_at, last.id)

    return CommandListResponse(
        items=[_command_payload(c) for c in rows],
        next_cursor=next_cursor,
    )


@router.get("/{command_id}", response_model=CommandPublic)
async def get_command(
    slug: str,
    command_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> CommandPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import CommandRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    cmd = await CommandRepository(db_session).get(command_id)
    if cmd is None or cmd.project_id != project.id:
        raise NotFoundError(
            "command not found",
            details={"command_id": str(command_id)},
        )
    return _command_payload(cmd)


# ---------------------------------------------------------------------------
# Write endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/retry-task",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_retry_task(
    slug: str,
    body: RetryTaskRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    # Look up the original task's priority so the agent can
    # preserve it on the re-enqueue. Without this a "high"
    # priority task silently drops to broker default on every
    # retry. ``None`` is fine - the agent skips the priority
    # kwarg when it's missing.
    #
    # Membership is checked BEFORE the priority lookup. Otherwise
    # a non-member who knows a slug could send a POST and observe
    # the latency difference between "task exists" and "task
    # missing" before the membership rejection lands - a tiny
    # enumeration oracle, but a real one.
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.enums import ProjectRole
    from z4j_brain.persistence.repositories import TaskRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.OPERATOR,
    )
    task_repo = TaskRepository(db_session)
    priority_label = await task_repo.get_priority_label(
        project_id=project.id,
        engine=body.engine,
        task_id=body.task_id,
    )
    # Polyfill payload (audit-noted as part of the unified action
    # surface): forward the original task name + args so adapters
    # without a native ``retry_task`` (huey/arq/taskiq) can lower
    # the call to ``submit_task`` agent-side. Adapters that DO
    # implement retry_task natively (celery/rq/dramatiq) ignore the
    # extra fields.
    original = await task_repo.get_by_engine_task_id(
        project_id=project.id,
        engine=body.engine,
        task_id=body.task_id,
    )
    return await _issue_task_command(
        slug=slug,
        action="retry_task",
        agent_id=body.agent_id,
        target_id=f"{body.engine}:{body.task_id}",
        payload={
            "engine": body.engine,
            "task_id": body.task_id,
            "task_name": original.name if original else None,
            "args": (
                original.args
                if (original and body.override_args is None)
                else None
            ),
            "kwargs": (
                original.kwargs
                if (original and body.override_kwargs is None)
                else None
            ),
            "override_args": body.override_args,
            "override_kwargs": body.override_kwargs,
            "eta_seconds": body.eta_seconds,
            "priority": priority_label,
        },
        idempotency_key=body.idempotency_key,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/cancel-task",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_cancel_task(
    slug: str,
    body: CancelTaskRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    return await _issue_task_command(
        slug=slug,
        action="cancel_task",
        agent_id=body.agent_id,
        target_id=f"{body.engine}:{body.task_id}",
        payload={
            "engine": body.engine,
            "task_id": body.task_id,
        },
        idempotency_key=body.idempotency_key,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/bulk-retry",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def issue_bulk_retry(
    slug: str,
    body: BulkRetryRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    # Look up per-task priorities so the bulk re-enqueue
    # preserves the original priority of each item in the batch
    # (a mixed `high` + `low` set retries onto the right priority
    # slots, not all-default).
    #
    # Membership check happens BEFORE the priority lookup (timing
    # oracle) and the task-id list is hard-clamped to ``body.max``
    # (defaulting to BulkRetryRequest's own ceiling) so a
    # caller cannot push a million-element IN-clause through this
    # endpoint by stuffing ``filter.task_ids``.
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.enums import ProjectRole
    from z4j_brain.persistence.repositories import TaskRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.OPERATOR,
    )
    raw_ids = (body.filter or {}).get("task_ids")
    enriched_filter = dict(body.filter or {})
    if isinstance(raw_ids, list) and raw_ids:
        # Hard cap matches the eventual `max` cap on the agent
        # side - querying more priorities than we'll ever retry
        # is wasted work AND a DoS amplifier.
        capped_ids = [str(t) for t in raw_ids[: body.max]]
        # The filter MUST carry an explicit engine now - silently
        # defaulting to "celery" would misroute a bulk retry of RQ
        # or Dramatiq tasks (LATENT-1). We still accept the filter
        # without an engine, but then we skip the priority lookup
        # (which needs an engine for its WHERE clause) rather than
        # guessing.
        filter_engine = (body.filter or {}).get("engine")
        if filter_engine in KNOWN_ENGINES:
            priorities = await TaskRepository(db_session).get_priorities_for_ids(
                project_id=project.id,
                engine=str(filter_engine),
                task_ids=capped_ids,
            )
            if priorities:
                enriched_filter["task_priorities"] = priorities

    return await _issue_generic_command(
        slug=slug,
        action="bulk_retry",
        target_type="bulk",
        target_id=None,
        payload={"filter": enriched_filter, "max": body.max},
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/purge-queue",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def issue_purge_queue(
    slug: str,
    body: PurgeQueueRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """DESTRUCTIVE - requires admin role.

    Removes every pending task from the named queue. The agent's
    purge action refuses the destructive ``queue_delete`` fallback
    (B3 audit fix), so this is bounded to ``queue_purge`` semantics.

    The caller must pass either ``confirm_token`` (HMAC of
    ``queue_name + observed_depth``) or ``force=True``. Without one
    of these the agent refuses to act (audit 2026-04-24 Medium-3).
    """
    return await _issue_generic_command(
        slug=slug,
        action="purge_queue",
        target_type="queue",
        target_id=body.queue,
        payload={
            "queue": body.queue,
            "confirm_token": body.confirm_token,
            "force": body.force,
        },
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
        require_role=ProjectRole.ADMIN,  # destructive → admin only
    )


@router.post(
    "/restart-worker",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_restart_worker(
    slug: str,
    body: RestartWorkerRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    return await _issue_generic_command(
        slug=slug,
        action="restart_worker",
        target_type="worker",
        target_id=body.worker_name,
        payload={"worker_name": body.worker_name},
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/pool-resize",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_pool_resize(
    slug: str,
    body: PoolResizeRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """Grow or shrink the worker pool by ``delta`` processes."""
    action = "pool_grow" if body.delta > 0 else "pool_shrink"
    return await _issue_generic_command(
        slug=slug,
        action=action,
        target_type="worker",
        target_id=body.worker_name,
        payload={
            "worker_name": body.worker_name,
            "delta": abs(body.delta),
        },
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/add-consumer",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_add_consumer(
    slug: str,
    body: ConsumerRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """Start consuming from an additional queue on a worker."""
    return await _issue_generic_command(
        slug=slug,
        action="add_consumer",
        target_type="worker",
        target_id=body.worker_name,
        payload={
            "worker_name": body.worker_name,
            "queue": body.queue,
        },
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/cancel-consumer",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_cancel_consumer(
    slug: str,
    body: ConsumerRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """Stop consuming from a queue on a worker."""
    return await _issue_generic_command(
        slug=slug,
        action="cancel_consumer",
        target_type="worker",
        target_id=body.worker_name,
        payload={
            "worker_name": body.worker_name,
            "queue": body.queue,
        },
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/rate-limit",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_rate_limit(
    slug: str,
    body: RateLimitRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """Set or clear a per-task rate limit on one (or every) worker.

    The target_id on the audit row is the task name, not the worker
    name - the rate limit is a property of the task across the
    cluster, not of the worker. Operators searching the audit log
    for a noisy task want to find every rate-limit change against
    that task in one query.
    """
    return await _issue_generic_command(
        slug=slug,
        action="rate_limit",
        target_type="task",
        target_id=body.task_name,
        payload={
            "task_name": body.task_name,
            "rate": body.rate,
            "worker_name": body.worker_name,
        },
        idempotency_key=body.idempotency_key,
        agent_id=body.agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


async def _issue_task_command(
    *,
    slug: str,
    action: str,
    agent_id: uuid.UUID,
    target_id: str,
    payload: dict[str, Any],
    idempotency_key: str | None,
    user: "User",
    memberships: "MembershipRepository",
    projects: "ProjectRepository",
    audit_log: "AuditLogRepository",
    dispatcher: "CommandDispatcher",
    db_session: "AsyncSession",
    ip: str,
) -> CommandPublic:
    """Shared body for the two task-targeting command endpoints."""
    return await _issue_generic_command(
        slug=slug,
        action=action,
        target_type="task",
        target_id=target_id,
        payload=payload,
        idempotency_key=idempotency_key,
        agent_id=agent_id,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


async def _issue_generic_command(
    *,
    slug: str,
    action: str,
    target_type: str,
    target_id: str | None,
    payload: dict[str, Any],
    idempotency_key: str | None,
    agent_id: uuid.UUID,
    user: "User",
    memberships: "MembershipRepository",
    projects: "ProjectRepository",
    audit_log: "AuditLogRepository",
    dispatcher: "CommandDispatcher",
    db_session: "AsyncSession",
    ip: str,
    require_role: ProjectRole = ProjectRole.OPERATOR,
) -> CommandPublic:
    """Shared body for every command-issuing endpoint.

    Centralises the policy check, the cross-project agent guard,
    and the dispatcher invocation. Sub-routes pass an ``action``
    and a payload; everything else is identical.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        AgentRepository,
        CommandRepository,
    )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=require_role,
    )

    # Cross-project agent guard.
    agent = await AgentRepository(db_session).get(agent_id)
    if agent is None or agent.project_id != project.id:
        raise NotFoundError(
            "agent not found in this project",
            details={"agent_id": str(agent_id)},
        )

    commands = CommandRepository(db_session)
    command = await dispatcher.issue(
        commands=commands,
        audit_log=audit_log,
        project_id=project.id,
        agent_id=agent_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        payload=payload,
        issued_by=user.id,
        ip=ip,
        user_agent=None,
        idempotency_key=idempotency_key,
    )
    await db_session.commit()

    # After commit: notify dashboards. Helper swallows hub failures.
    await dispatcher.notify_dashboard_command_change(project.id)
    return _command_payload(command)


__all__ = [
    "BulkRetryRequest",
    "CancelTaskRequest",
    "CommandListResponse",
    "CommandPublic",
    "PurgeQueueRequest",
    "RestartWorkerRequest",
    "RetryTaskRequest",
    "router",
]
