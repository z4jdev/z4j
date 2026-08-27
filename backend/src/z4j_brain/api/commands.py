"""``/api/v1/projects/{slug}/commands`` REST router.

Read endpoints plus the operator-facing command write surface:
task retry/cancel, explicit-selection bulk retry, queue purge,
and worker pool/consumer/rate controls.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator

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
from z4j_brain.domain.retry_contract import (
    RETRY_COMMAND_ENGINES,
    engine_is_native_retry,
    polyfill_retry_has_operator_overrides,
)
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
KNOWN_ENGINES: frozenset[str] = RETRY_COMMAND_ENGINES


# Every key in this frozenset is populated by the
# brain server-side from the Task table; an API client must NOT be
# able to seed any of them through ``BulkRetryRequest.filter``.
#
# Surface impact: ``filter["task_names"]`` is consumed by the RQ
# adapter's ``bulk_retry_action`` and passed straight to
# ``queue.enqueue_call(func=...)``; a client-spoofable map would
# let an authenticated operator retry a known RQ job as an
# arbitrary importable callable. ``filter["overrides"]`` and
# ``filter["task_priorities"]`` have analogous server-owned shapes
# and round through the same dispatcher pathway.
#
# The ``issue_bulk_retry`` endpoint strips these keys from the
# inbound filter before enrichment; the rejected key list is
# surfaced in the outgoing command payload as
# ``rejected_client_supplied_filter_keys`` so the audit trail
# records the attempt rather than silently dropping it.
SERVER_OWNED_FILTER_KEYS: frozenset[str] = frozenset(
    {
        "task_names",
        "task_priorities",
        "overrides",
    }
)

# 1.7.1 (CX-H5, HIGH/security): the bulk-retry filter is now locked to a
# SELECTION-ONLY allowlist. A client may only narrow WHICH tasks to retry;
# every executable field is stripped and re-populated by the brain from its
# own Task table. The prior denylist (SERVER_OWNED_FILTER_KEYS) stripped only
# three keys, so a client could smuggle filter["actors"] / ["args"] /
# ["kwargs"] / ["queues"] straight through to the Dramatiq adapter's
# ``bulk_retry_action`` and invoke an arbitrary registered actor with
# attacker-chosen arguments (a confused-deputy actor-invocation primitive).
# An allowlist closes the whole class at once: anything that is not an
# explicit, non-executable selection filter is refused (and audited).
# ``SERVER_OWNED_FILTER_KEYS`` is a strict subset kept for the audit-trail
# vocabulary and the security regression tests; the allowlist below is what
# the endpoint actually enforces.
CLIENT_ALLOWED_BULK_FILTER_KEYS: frozenset[str] = frozenset(
    {
        "task_ids",  # the selection set (hard-clamped to body.max)
        "engine",  # routing; validated against KNOWN_ENGINES
        "state",  # celery selection: task state
        "status",  # alias some clients send for state
        "queue",  # celery selection: single SOURCE queue to filter on
        # (NOT the per-id executable ``queues`` map)
        "name",  # celery selection: task-name filter
        "since",  # celery selection: time-window lower bound
        "until",  # celery selection: time-window upper bound
    }
)


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
        """Cap override size.

        Without this cap a 50 MB ``override_kwargs`` would be
        parsed, persisted into ``commands.payload`` JSONB,
        HMAC-signed, and pushed over the wire to the agent; a
        single retry request could OOM the brain or wedge the
        WS frame cap downstream. The 64 KiB ceiling matches the
        ``_validate_args_kwargs_size`` cap already used on
        schedule create/update.
        """
        if v is None:
            return v
        import json as _json

        try:
            size = len(_json.dumps(v).encode("utf-8"))
        except Exception as exc:
            raise ValueError(
                f"override value is not JSON-serialisable: {exc}",
            ) from exc
        if size > 64 * 1024:
            raise ValueError(
                f"override payload {size} bytes exceeds 64 KiB cap",
            )
        return v

    @field_validator("override_kwargs")
    @classmethod
    def _reject_reserved_control_keys(cls, v: object) -> object:
        """Refuse operator override_kwargs carrying a reserved control key.

        The brain/agent protocol injects control metadata under the ``__z4j_``
        namespace (e.g. ``__z4j_actor_name__``, ``__z4j_task_name__``,
        ``__z4j_queue_name__``) to steer a polyfill re-submit. A legitimate retry
        NEVER carries these -- they are set by the dispatcher, not the operator.
        An agent runtime that consumes such a key as control metadata (notably a
        pre-1.7.1 N-1 agent that predates the strip/attest gate) could be steered
        to enqueue a DIFFERENT registered actor/task than the one being retried.
        Reject any operator-supplied ``__z4j_`` key at the request boundary so the
        smuggle can never reach the wire, on any fleet version.
        """
        if isinstance(v, dict):
            reserved = [k for k in v if isinstance(k, str) and k.startswith("__z4j_")]
            if reserved:
                raise ValueError(
                    f"override_kwargs may not contain reserved control keys: {sorted(reserved)}",
                )
        return v

    @model_validator(mode="after")
    def _overrides_both_or_neither(self) -> RetryTaskRequest:
        """RH1 defense in depth: override_args and override_kwargs must
        be supplied TOGETHER or not at all.

        Native engines (celery/rq/dramatiq) retry BY REFERENCE and normally need
        no overrides, so a PARTIAL override -- exactly one half present -- is
        ambiguous: the operator changed one half but left the other to be
        reconstructed from a source the brain has redacted. An older (N-1) agent
        that predates the both-halves contract could substitute an empty value
        for the missing half and re-run with dropped inputs. Refusing a partial
        override closes that window statically at the request boundary, for every
        engine, with no dependence on a negotiated runtime capability. Supplying
        neither (plain by-reference retry) or both (full operator inputs) is
        always accepted.
        """
        has_args = self.override_args is not None
        has_kwargs = self.override_kwargs is not None
        if has_args != has_kwargs:
            missing = "override_kwargs" if has_args else "override_args"
            raise ValueError(
                "override_args and override_kwargs must be supplied together; "
                f"{missing} is missing. Provide both halves to retry with "
                "different inputs, or neither to retry the original by reference.",
            )
        return self


class CancelTaskRequest(BaseModel):
    agent_id: uuid.UUID
    engine: str = Field(min_length=1, max_length=40)
    task_id: str = Field(min_length=1, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v: str) -> str:
        return _validate_engine_dispatch(v)


class RequeueDeadLetterRequest(BaseModel):
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

    ``filter`` accepts only the selection keys in
    :data:`CLIENT_ALLOWED_BULK_FILTER_KEYS`; executable and server-owned
    keys are stripped and audit-recorded. This compatibility endpoint
    requires a non-empty ``task_ids`` selection plus an explicit engine,
    then deduplicates, caps, and ownership-checks those IDs before adding
    server-derived task names and priorities. All-matching requests use
    the versioned ``/bulk-retry-requests`` resource instead. ``max`` is
    capped at 10 000 at the request boundary.
    """

    agent_id: uuid.UUID
    filter: dict[str, Any] = Field(default_factory=dict)
    max: int = Field(default=1000, ge=1, le=10_000)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class PurgeQueueRequest(BaseModel):
    """Purge-queue request body.

    The agent's per-engine ``purge_queue_action`` refuses to act
    unless one of these confirmation inputs is supplied:

    * ``observed_depth`` - the queue depth the operator confirmed
      against (from the brain's queue-depth telemetry shown in the
      dashboard). The brain computes the keyed
      ``HMAC(project_secret, "purge|queue|depth")`` confirm token
      server-side (M-7) -- the operator never handles the token, and
      because it is keyed a party who can only see the depth cannot
      forge it. The agent re-measures and re-computes against its own
      per-project secret; a mismatch means the depth moved (likely a
      replayed command) and it refuses.
    * ``confirm_token`` - a pre-computed token, for non-dashboard API
      clients. Passed through as-is (a keyed token from a secret-holder,
      or a legacy unkeyed token during the grace window).
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
        default=None,
        min_length=1,
        max_length=128,
    )
    #: Operator-observed queue depth. When supplied (and no explicit
    #: confirm_token), the brain computes the keyed token server-side.
    observed_depth: int | None = Field(default=None, ge=0)
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

    @field_validator("delta")
    @classmethod
    def _require_resize(cls, value: int) -> int:
        if value == 0:
            raise ValueError("delta must be non-zero (positive to grow, negative to shrink)")
        return value


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


#: Payload keys that are SECRETS and must never appear in a read response,
#: for ANY role: the purge confirm token authorizes a destructive
#: mass-delete, so returning it to a depth observer is a forgery handoff.
_SECRET_PAYLOAD_KEYS = frozenset({"confirm_token"})


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: ("<redacted>" if k in _SECRET_PAYLOAD_KEYS else v) for k, v in payload.items()}


def _command_payload(cmd: Command, *, include_actor: bool = True) -> CommandPublic:
    """Build the public view of a command.

    ``include_actor`` gates who-did-what (``issued_by``) plus the raw
    ``payload`` and ``result`` behind OPERATOR: a VIEWER sees a command's
    action / target / status / timestamps but NOT the issuing operator, the
    payload (which can carry ``override_kwargs`` / arguments), or the
    result. The confirm-token secret is redacted for EVERY role.
    """
    payload = _redact_payload(dict(cmd.payload or {})) if include_actor else {}
    return CommandPublic(
        id=cmd.id,
        project_id=cmd.project_id,
        agent_id=cmd.agent_id,
        issued_by=cmd.issued_by if include_actor else None,
        action=cmd.action,
        target_type=cmd.target_type,
        target_id=cmd.target_id,
        payload=payload,
        status=cmd.status.value,
        result=cmd.result if include_actor else None,
        error=cmd.error,
        issued_at=cmd.issued_at,
        dispatched_at=cmd.dispatched_at,
        completed_at=cmd.completed_at,
        timeout_at=cmd.timeout_at,
    )


def _include_actor(membership: Any) -> bool:
    """Whether the caller may see who-did-what + the raw command payload
    (OPERATOR+). A VIEWER gets the operational shape only."""
    from z4j_brain.domain.policy_engine import role_rank

    return role_rank(membership.role) >= role_rank(ProjectRole.OPERATOR)


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=CommandListResponse)
async def list_commands(
    slug: str,
    status: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=5000),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> CommandListResponse:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import CommandRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    membership = await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    include_actor = _include_actor(membership)

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
        items=[_command_payload(c, include_actor=include_actor) for c in rows],
        next_cursor=next_cursor,
    )


@router.get("/{command_id}", response_model=CommandPublic)
async def get_command(
    slug: str,
    command_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> CommandPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import CommandRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    membership = await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    cmd = await CommandRepository(db_session).get(command_id)
    if cmd is None or cmd.project_id != project.id:
        raise NotFoundError(
            "command not found",
            details={"command_id": str(command_id)},
        )
    return _command_payload(cmd, include_actor=_include_actor(membership))


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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    # ``eta_seconds`` is a relative REST input, while every adapter receives
    # ``eta`` as an absolute POSIX timestamp. Resolve the wall-clock deadline
    # before any database / dispatch awaits so queueing or an offline agent
    # cannot silently restart the requested delay later.
    eta = time.time() + body.eta_seconds if body.eta_seconds is not None else None

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
        project=project,
        min_role=ProjectRole.OPERATOR,
    )
    task_repo = TaskRepository(db_session)
    priority_label = await task_repo.get_priority_label(
        project_id=project.id,
        engine=body.engine,
        task_id=body.task_id,
    )
    # Polyfill payload: forward the original task NAME (a dotted import
    # path -- routing metadata, never redacted) so adapters without a
    # native ``retry_task`` (huey/arq/taskiq) can lower the call to
    # ``submit_task`` agent-side. Adapters that DO implement retry_task
    # natively (celery/rq/dramatiq) ignore the extra fields.
    #
    # 1.7.1 (H3/M7, correctness/security): the brain stores args/kwargs
    # ALREADY REDACTED (Task model: "defence in depth before storing"),
    # so they can never faithfully reconstruct a retry. We therefore
    # NEVER forward brain-side args/kwargs -- doing so re-ran tasks with
    # scrubbed values (e.g. the literal string "[REDACTED]", or () on a
    # default-config app). A native retry re-runs the original broker job
    # by reference; only operator-owned overrides ride along. When the
    # original invocation carried arguments that are now unavailable, we
    # signal it so a polyfill adapter can fail closed rather than silently
    # re-run with no args.
    original = await task_repo.get_by_engine_task_id(
        project_id=project.id,
        engine=body.engine,
        task_id=body.task_id,
    )
    # RH1 (direction 1) -- defense in depth. The manual retry endpoint already
    # validates ``engine`` against KNOWN_ENGINES (all native today), so this
    # branch is unreachable UNLESS a future release adds a polyfill engine to
    # KNOWN_ENGINES. If that happens, a polyfill retry is refused unless BOTH
    # operator override halves are supplied: the engine has no native retry, so
    # the agent lowers it to a re-submit, and the brain's stored arguments are
    # redacted -- only real operator overrides make the re-submit safe (on ANY
    # runtime). This is a static rule on the presence of overrides, not a
    # negotiated runtime capability; the agent-side dispatcher fails closed on
    # the same criterion, and the automation runner refuses polyfill retries
    # outright (it can supply no overrides at all).
    if not engine_is_native_retry(body.engine) and not polyfill_retry_has_operator_overrides(
        body.override_args, body.override_kwargs
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "error": (
                    f"refusing to retry a {body.engine!r} task: this engine has no "
                    "native retry, so the agent lowers it to a re-submit, and the "
                    "brain stores the original arguments redacted. Use 'retry with "
                    "different inputs' to supply both override_args and "
                    "override_kwargs explicitly."
                ),
            },
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
            "args": None,
            "kwargs": None,
            "override_args": body.override_args,
            "override_kwargs": body.override_kwargs,
            "original_had_args": bool(
                original is not None and (original.args is not None or original.kwargs is not None)
            ),
            "eta": eta,
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    "/requeue-dead-letter",
    response_model=CommandPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def issue_requeue_dead_letter(
    slug: str,
    body: RequeueDeadLetterRequest,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CommandPublic:
    """Move one dead-lettered task back onto its queue.

    Deliberately not gated on engine support, and the reason is safety rather
    than convenience. Whether a requeue is safe is a property of the engine's
    own dead-letter primitive, which only the adapter knows. RQ has one:
    ``FailedJobRegistry`` IS its dead-letter concept and ``registry.requeue``
    consumes the entry and preserves its original routing. Celery does not, and
    its adapter's implementation was removed as a breaking safety correction
    after it was found to publish a plain retry without consuming the broker
    entry, which could duplicate work; it now refuses without touching the
    broker at all.

    So an unsupported engine returns a FAILED command naming the reason, which
    is honest. An engine allowlist here would encode today's adapter set into
    the brain, and would go stale in both directions: it would block an adapter
    that gains a safe primitive, and it would keep advertising one whose
    implementation was withdrawn.
    """
    return await _issue_task_command(
        slug=slug,
        action="requeue_dead_letter",
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    audit_service: AuditService = Depends(get_audit_service),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
        project=project,
        min_role=ProjectRole.OPERATOR,
    )
    raw_ids = (body.filter or {}).get("task_ids")

    # CX-H5: the inbound filter is locked to a
    # SELECTION-ONLY allowlist. Every key that is not an explicit,
    # non-executable selection filter is stripped BEFORE enrichment --
    # this refuses the server-owned keys (task_names / task_priorities /
    # overrides) AND every executable field (actors / queues / args /
    # kwargs / func) a client could otherwise smuggle to an engine
    # adapter. See CLIENT_ALLOWED_BULK_FILTER_KEYS at module top.
    raw_filter = body.filter or {}
    rejected_client_keys = sorted(k for k in raw_filter if k not in CLIENT_ALLOWED_BULK_FILTER_KEYS)
    enriched_filter = {k: v for k, v in raw_filter.items() if k in CLIENT_ALLOWED_BULK_FILTER_KEYS}

    # The act of an authenticated operator supplying
    # server-owned filter keys (the confused-deputy attempt) is
    # a security-relevant event that MUST leave a tamper-evident audit
    # row regardless of whether the request then succeeds or trips the
    # partial-resolution 400 fast-path below. The command-issuance
    # audit row (written later by dispatcher.issue) is not reached on
    # the 400 path, and it does not carry the rejected keys. Record a
    # dedicated chained audit row + commit it now so the attempt is
    # durable independent of the request's eventual outcome. Commit is
    # clean here: the only prior DB activity is reads (project,
    # membership), no pending writes to lose.
    if rejected_client_keys:
        await audit_service.record(
            audit_log,
            action="command.bulk_retry.filter_keys_rejected",
            target_type="bulk",
            target_id=None,
            result="success",
            outcome="sanitized",
            user_id=user.id,
            project_id=project.id,
            source_ip=ip,
            metadata={
                "rejected_client_supplied_filter_keys": rejected_client_keys,
                "engine": raw_filter.get("engine"),
            },
        )
        await db_session.commit()

    # H2: distinguish "task_ids omitted" (a legitimate retry-all-matching
    # request) from "task_ids present but not a non-empty list" (an explicit
    # selection that is empty [] or malformed, e.g. a bare string). The latter
    # must NOT fall through to the all-matching path below -- that would silently
    # mass-retry the WHOLE project's failed backlog when the operator/UI actually
    # selected zero (or sent a malformed value). Reject it (fail closed: a
    # malformed explicit selection must never widen a destructive action).
    if "task_ids" in raw_filter and not (isinstance(raw_ids, list) and raw_ids):
        raise HTTPException(
            status_code=400,
            detail={
                "error": (
                    "task_ids was supplied but is not a non-empty list of ids. "
                    "Omit task_ids to retry all matching, or supply at least one "
                    "id to retry a specific selection."
                ),
            },
        )

    if isinstance(raw_ids, list) and raw_ids:
        # Hard cap matches the eventual `max` cap on the agent
        # side - querying more priorities than we'll ever retry
        # is wasted work AND a DoS amplifier.
        # RL3: dedup (order-preserving) BEFORE the cap, so a client sending the
        # same id twice does not trip the ownership check below (which compares
        # len(task_names), a deduped dict, against len(capped_ids)) into a
        # false 400 with zero ids actually missing.
        capped_ids = list(dict.fromkeys(str(t) for t in raw_ids))[: body.max]
        # The filter MUST carry an explicit engine now - silently
        # defaulting to "celery" would misroute a bulk retry of RQ
        # or Dramatiq tasks (LATENT-1). We still accept the filter
        # without an engine, but then we skip the priority lookup
        # (which needs an engine for its WHERE clause) rather than
        # guessing.
        filter_engine = raw_filter.get("engine")
        # H4: a bulk retry that targets explicit task_ids MUST name a known
        # engine, and EVERY id must resolve to a Task row in THIS project for
        # THAT engine -- for ALL engines, not just RQ. Otherwise an operator
        # could label foreign ids (RQ ids as engine=celery, or omit the engine
        # entirely) to skip the project-scoped ownership lookup and have the
        # sole matching adapter requeue tasks that belong to another workload /
        # project on shared broker infrastructure.
        if filter_engine not in KNOWN_ENGINES:
            await audit_service.record(
                audit_log,
                action="command.bulk_retry.refused",
                target_type="bulk",
                target_id=None,
                result="failure",
                outcome="deny",
                user_id=user.id,
                project_id=project.id,
                source_ip=ip,
                metadata={
                    "reason": "missing_or_unknown_engine",
                    "engine": str(filter_engine),
                    "requested_ids": len(capped_ids),
                    "rejected_client_supplied_filter_keys": (rejected_client_keys),
                },
            )
            await db_session.commit()
            raise HTTPException(
                status_code=400,
                detail={
                    "error": (
                        "bulk_retry with task_ids requires an explicit engine "
                        "(celery, rq, or dramatiq) so every id can be "
                        "ownership-verified against this project."
                    ),
                    "rejected_client_supplied_keys": rejected_client_keys,
                },
            )
        task_repo = TaskRepository(db_session)
        priorities = await task_repo.get_priorities_for_ids(
            project_id=project.id,
            engine=str(filter_engine),
            task_ids=capped_ids,
        )
        if priorities:
            enriched_filter["task_priorities"] = priorities
        # RQ's bulk_retry_action requires per-task task_name so it can
        # call enqueue_call(func=task_name) without reading job.func_name
        # (which lazy-loads pickle from the broker). Look up names alongside
        # priorities so the agent gets both in one round trip. Other engines
        # ignore filter["task_names"] safely.
        task_names = await task_repo.get_names_for_ids(
            project_id=project.id,
            engine=str(filter_engine),
            task_ids=capped_ids,
        )
        if task_names:
            enriched_filter["task_names"] = task_names
        # P1-5: the command MUST carry the SAME canonical id set that ownership
        # was verified against. enriched_filter still holds the client's RAW
        # task_ids (with duplicates, and uncapped); overwrite it with capped_ids
        # (deduped + clamped to body.max) so an adapter cannot retry a duplicate
        # twice or act on an id that was never ownership-checked.
        enriched_filter["task_ids"] = capped_ids
        # H4 /: fail closed when ANY targeted id does not resolve to a
        # named Task row in this project + engine. A partial resolution means
        # the client mislabeled the engine, sent foreign ids, or is probing DB
        # coverage; the agent must never silently retry only the resolved
        # subset (an RCE-class + cross-project surface).
        if len(task_names) != len(capped_ids):
            missing = sorted(set(capped_ids) - set(task_names.keys()))
            # Record the refusal as a tamper-evident audit row +
            # commit BEFORE raising, so the 400 fast-path is not an audit
            # blind spot (an HTTPException would otherwise roll the session
            # back and leave the refusal with no trace).
            await audit_service.record(
                audit_log,
                action="command.bulk_retry.refused",
                target_type="bulk",
                target_id=None,
                result="failure",
                outcome="deny",
                user_id=user.id,
                project_id=project.id,
                source_ip=ip,
                metadata={
                    "reason": "partial_task_ownership_resolution",
                    "engine": str(filter_engine),
                    "missing_task_names": missing,
                    "requested_ids": len(capped_ids),
                    "rejected_client_supplied_filter_keys": (rejected_client_keys),
                },
            )
            await db_session.commit()
            raise HTTPException(
                status_code=400,
                detail={
                    "error": (
                        "bulk_retry refused: every targeted id must resolve to "
                        "a Task row in this project for the named engine; the "
                        f"DB has no match for {len(missing)} of "
                        f"{len(capped_ids)} ids (wrong engine label, foreign "
                        "ids, or unknown tasks). Retry only ids this project "
                        "owns, or use 'retry with different inputs' to supply "
                        "arguments explicitly."
                    ),
                    "missing_task_names": missing,
                    "rejected_client_supplied_keys": rejected_client_keys,
                },
            )
    else:
        # Boundary B: this command-shaped endpoint cannot honestly represent a
        # sealed multi-engine parent.  Keeping the all-matching branch alive
        # would also leave keyless old callers able to bypass the durable
        # ledger. Explicit-id compatibility remains above; all-matching callers
        # must move to the versioned resource.
        raise HTTPException(
            status_code=410,
            detail={
                "error": (
                    f"all-matching bulk retry moved to /api/v1/projects/{slug}/bulk-retry-requests"
                ),
                "replacement": f"/api/v1/projects/{slug}/bulk-retry-requests",
            },
        )

    # If the client smuggled server-owned keys, surface the rejection
    # as a structured warning in the command result so the audit trail
    # records the attempt. We do NOT silently strip without trace; the
    # operator's session ought to surface a "your filter was sanitized"
    # banner so a misuse pattern is observable.
    cmd_payload: dict[str, Any] = {"filter": enriched_filter, "max": body.max}
    if rejected_client_keys:
        cmd_payload["rejected_client_supplied_filter_keys"] = rejected_client_keys

    return await _issue_generic_command(
        slug=slug,
        action="bulk_retry",
        target_type="bulk",
        target_id=None,
        payload=cmd_payload,
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


def _parse_filter_datetime(value: Any) -> datetime | None:
    """Parse a bulk-filter ``since``/``until`` value (ISO-8601 string or epoch
    seconds) into an aware datetime; None if absent or unparseable (an
    unparseable bound is simply not applied rather than silently widening)."""
    import contextlib

    dt: datetime | None = None
    if isinstance(value, bool):  # bool is an int subclass; not a timestamp
        return None
    if isinstance(value, (int, float)):
        with contextlib.suppress(OverflowError, OSError, ValueError):
            dt = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, str) and value.strip():
        s = value.strip()
        if s.endswith(("Z", "z")):  # fromisoformat pre-3.11 rejects a bare Z
            s = s[:-1] + "+00:00"
        with contextlib.suppress(ValueError):
            parsed = datetime.fromisoformat(s)
            dt = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return dt


#: The command ``idempotency_key`` column is VARCHAR(200).
_IDEMPOTENCY_KEY_MAX = 200

#: Reserved pseudo-engine used to namespace the no-owned-match no-op bulk-retry
#: key so it can NEVER collide with a real per-engine key (commands:1028). Not a
#: valid engine adapter name, so ``_engine_idempotency_key(base, engine)`` for
#: any real engine can never produce this suffix.
_BULK_NOOP_KEY_ENGINE = "__noop__"

#: The single request-scoped idempotency namespace for a bulk retry. Not a
#: valid engine name, so it can never collide with a real per-engine key. The
#: FIRST command a request issues commits here, whatever the expansion turned out
#: to be, so a replay of the same request collides regardless of what the data
#: looks like the second time.
_BULK_REQUEST_KEY_ENGINE = "__request__"


def _engine_idempotency_key(base: str | None, engine: str) -> str | None:
    """Per-engine idempotency key for a multi-engine bulk-retry expansion.

    commands:1015: a client key is accepted up to 200 chars (the column width),
    so a naive ``{base}:{engine}`` can overflow VARCHAR(200). We fold the base to
    a stable SHA-256 digest so the result always fits AND a retry of the same
    request maps to the same key (idempotent). ``None`` in -> ``None`` out.

    M2: hash UNIFORMLY (always, not only when the raw key overflows). A
    two-branch encoding (direct when short, digest when long) is NOT injective:
    a 200-char base 'x'*200 folds to '<sha256hex>:engine', and a DISTINCT client
    key equal to that 64-char hex would suffix directly to the SAME
    '<sha256hex>:engine' -- two different client keys collapsing to one derived
    key silently dedups the second request against the first. Always hashing
    makes the transform injective (distinct bases collide only on a real SHA-256
    collision) and keeps it within the column. The digest is an internal dedup
    token, never surfaced to the operator, so readability is not lost.
    """
    if base is None:
        return None
    import hashlib

    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()  # 64 hex chars
    return f"{digest}:{engine}"


def _validate_narrowing_filters(raw_filter: dict[str, Any]) -> None:
    """H3: reject a present-but-malformed NARROWING filter instead of silently
    coercing it to None.

    Dropping a narrowing predicate WIDENS the resolved set (losing ``since``
    pulls in older failed tasks; a non-string queue/name/engine pulls in other
    queues/names/engines), so a malformed value would silently mass-retry far
    more than the operator scoped. Fail closed on a selection filter the server
    cannot honour. (An empty string is a no-op filter, not a dropped narrowing,
    so it is allowed; ``state`` falls back to FAILURE, the narrowest set, so it
    never widens.)
    """
    from z4j_brain.persistence.enums import TaskState

    for key in ("queue", "name", "engine"):
        if key in raw_filter and not isinstance(raw_filter[key], str):
            raise HTTPException(
                status_code=400,
                detail={"error": f"bulk-retry filter {key!r} must be a string"},
            )
    # M1: a present engine must be a KNOWN engine. An unknown engine string (e.g.
    # a "celrey" typo) otherwise resolves to zero owned rows and returns a
    # false-success no-op that masks the mistake instead of surfacing it -- and if
    # it ever DID match rows it would dispatch an unhandleable command. An empty
    # string is treated as "no engine filter" (unchanged), not an unknown engine.
    engine = raw_filter.get("engine")
    if isinstance(engine, str) and engine and engine not in KNOWN_ENGINES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": (f"bulk-retry filter 'engine' must be one of {sorted(KNOWN_ENGINES)}"),
            },
        )
    # H2: a present state/status must be a VALID task state. Silently coercing an
    # invalid value to FAILURE (the old except-branch) mass-retries every failed
    # task in the project that the operator never scoped -- e.g. a state="sucess"
    # typo or status=17 selects and re-dispatches the owned FAILED set. Absent /
    # empty falls back to FAILURE (the narrowest set), so it is allowed.
    for key in ("state", "status"):
        if key not in raw_filter:
            continue
        value = raw_filter[key]
        # ABSENT (handled above), an explicit JSON
        # ``null`` (decoded to ``None``), or an empty string all fall back to
        # FAILURE, the documented NARROWEST default. Treating ``null`` as absent
        # is deliberate and SAFE: many JSON clients serialize an unset optional as
        # ``null``, and the fallback can only ever select the owned FAILED set --
        # it can NEVER widen the selection beyond FAILURE, so there is no scope
        # escalation (this is why 's HIGH severity is an over-call). Any
        # OTHER present value -- including a non-null FALSY one such as ``false`` /
        # ``0`` / ``[]`` / ``{}`` -- must be a valid TaskState or be rejected, so a
        # ``state="sucess"`` typo or ``status=17`` cannot coerce to FAILURE and
        # mass-retry the backlog the operator never scoped.
        if value is None or value == "":
            continue
        try:
            TaskState(value)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": f"bulk-retry filter {key!r} is not a valid task state",
                },
            ) from exc
    for bound in ("since", "until"):
        if raw_filter.get(bound) is not None and _parse_filter_datetime(raw_filter[bound]) is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": (
                        f"bulk-retry filter {bound!r} is not a parseable "
                        "ISO-8601 or epoch-seconds timestamp"
                    ),
                },
            )


async def _resolve_and_issue_all_matching_bulk_retry(
    *,
    slug: str,
    body: BulkRetryRequest,
    project: Any,
    raw_filter: dict[str, Any],
    enriched_filter: dict[str, Any],
    rejected_client_keys: list[str],
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
    audit_log: AuditLogRepository,
    dispatcher: CommandDispatcher,
    db_session: AsyncSession,
    ip: str,
) -> CommandPublic:
    """RH4: bind a no-explicit-ids ("retry all matching") bulk_retry to project
    ownership.

    Resolves the tasks THIS project owns that match the selection (default:
    FAILED, plus an optional queue/engine) from the brain's own Task rows,
    groups them by engine, and issues one ownership-verified bulk_retry command
    per engine -- each carrying explicit task_ids, names, and priorities exactly
    like the explicit-ids path. Because every id comes from a project-scoped
    Task row, the agent never sweeps the broker's failed registry and foreign
    jobs on shared infrastructure can never be retried. Returns the FIRST
    command issued (the dashboard refreshes the whole command list); a no-match
    request issues a single clean no-op so the action is still audited.
    """
    from z4j_brain.persistence.enums import TaskState
    from z4j_brain.persistence.repositories import TaskRepository

    task_repo = TaskRepository(db_session)

    # Selection state: default to FAILED. An unknown state string narrows to
    # FAILURE rather than widening the set (never retry successful tasks by
    # accident). ``status`` is an accepted alias for ``state``.
    state_str = raw_filter.get("state") or raw_filter.get("status")
    try:
        state = TaskState(state_str) if state_str else TaskState.FAILURE
    except ValueError:
        state = TaskState.FAILURE

    _validate_narrowing_filters(raw_filter)

    filter_engine = raw_filter.get("engine")
    queue = raw_filter.get("queue")
    name = raw_filter.get("name")
    # P1-4: the resolution MUST honour EVERY accepted selection filter (name,
    # since, until), not just state/queue/engine -- otherwise "retry all
    # matching" with e.g. {name, since, until} dispatches out-of-window,
    # wrong-name tasks the operator never selected. The client-facing filter is
    # already allowlisted to selection-only keys (CLIENT_ALLOWED_BULK_FILTER_KEYS).
    # Freeze the whole REQUEST before expanding it.
    #
    # The expansion below derives an idempotency key per ENGINE, so the key a
    # request commits under depends on what its filter happened to match at the
    # time. A request that matched nothing committed under the reserved no-op
    # key; a lost-response replay of the SAME request, once a task had failed
    # into range, matched something, derived a DIFFERENT per-engine key, and
    # executed a retry the caller's first response had reported as "nothing
    # matched". Idempotency has to be a property of the request, not of what the
    # data looked like when it ran.
    #
    # One request-scoped key, checked BEFORE any live query, is enough: a replay
    # returns the original command and never re-expands, so it can add neither
    # engines nor tasks.
    request_key = _engine_idempotency_key(body.idempotency_key, _BULK_REQUEST_KEY_ENGINE)
    if request_key is not None:
        from z4j_brain.persistence.repositories import CommandRepository

        prior = await CommandRepository(db_session).get_by_idempotency_key(
            project_id=project.id, idempotency_key=request_key
        )
        if prior is not None:
            # ``prior`` is an ORM row. CommandPublic does not declare
            # from_attributes, so model_validate raises on it -- this path 500'd
            # on every real replay and only looked right because a test double
            # returned a CommandPublic instead of a row. Serialize the way every
            # other endpoint in this module does, which also applies the same
            # redaction rules.
            return _command_payload(prior)

    owned = await task_repo.list_for_project(
        project_id=project.id,
        state=state,
        queue=queue if isinstance(queue, str) else None,
        name_substring=name if isinstance(name, str) and name else None,
        since=_parse_filter_datetime(raw_filter.get("since")),
        until=_parse_filter_datetime(raw_filter.get("until")),
        # RH4: scope the query to the requested engine IN SQL so the row cap
        # bounds that engine's rows -- otherwise other-engine newer rows consume
        # the limit and owned target-engine rows are silently dropped. When no
        # engine is requested (multi-engine "retry all"), the cap bounds the
        # total newest across engines, which is the intended max semantics.
        engine=filter_engine if isinstance(filter_engine, str) else None,
        limit=body.max,
    )

    # Group owned ids by engine (the SQL already applied any engine filter; the
    # guard below is belt-and-braces). The list_for_project limit bounds the
    # per-engine set when filter_engine is set, else the total across engines.
    by_engine: dict[str, list[str]] = {}
    for task in owned:
        if filter_engine and task.engine != filter_engine:
            continue
        by_engine.setdefault(task.engine, []).append(task.task_id)

    if not by_engine:
        # M1: nothing this project owns matches. Record a synthetic COMPLETED
        # success no-op WITHOUT dispatching -- round-tripping a task_ids=[]
        # command makes the celery/rq adapter report FAILED (v1 requires a
        # non-empty list), so a legitimate no-match would surface as a failed
        # command in the dashboard and audit. ``synthetic_success_result`` tells
        # the dispatcher to complete the command in place instead of delivering.
        noop_filter = dict(enriched_filter)
        noop_filter["task_ids"] = []
        payload: dict[str, Any] = {"filter": noop_filter, "max": body.max}
        if rejected_client_keys:
            payload["rejected_client_supplied_filter_keys"] = rejected_client_keys
        return await _issue_generic_command(
            slug=slug,
            action="bulk_retry",
            target_type="bulk",
            target_id=None,
            payload=payload,
            # commands:1028: namespace the no-op key under a reserved pseudo-
            # engine so it can never collide with a real per-engine key.
            # The request-scoped key, NOT a no-op-specific one. Keying the
            # no-op separately is exactly what let a replay that later matched
            # something slip past it under a different key.
            idempotency_key=request_key
            or _engine_idempotency_key(body.idempotency_key, _BULK_NOOP_KEY_ENGINE),
            agent_id=body.agent_id,
            user=user,
            memberships=memberships,
            projects=projects,
            audit_log=audit_log,
            dispatcher=dispatcher,
            db_session=db_session,
            ip=ip,
            synthetic_success_result={
                "requested": 0,
                "succeeded": 0,
                "failed": 0,
                "capped": False,
                "new_task_ids": {},
                "no_owned_match": True,
            },
        )

    first: CommandPublic | None = None
    # Deterministic order, so "the first engine" is the same on a replay as
    # it was originally and the request-scoped key always lands on the same one.
    for engine, ids in sorted(by_engine.items()):
        capped = ids[: body.max]
        priorities = await task_repo.get_priorities_for_ids(
            project_id=project.id,
            engine=engine,
            task_ids=capped,
        )
        names = await task_repo.get_names_for_ids(
            project_id=project.id,
            engine=engine,
            task_ids=capped,
        )
        per_engine_filter = dict(enriched_filter)
        per_engine_filter["engine"] = engine
        per_engine_filter["task_ids"] = capped
        if priorities:
            per_engine_filter["task_priorities"] = priorities
        if names:
            per_engine_filter["task_names"] = names
        payload = {"filter": per_engine_filter, "max": body.max}
        if rejected_client_keys:
            payload["rejected_client_supplied_filter_keys"] = rejected_client_keys
        issued = await _issue_generic_command(
            slug=slug,
            action="bulk_retry",
            target_type="bulk",
            target_id=None,
            payload=payload,
            # A distinct idempotency key per engine so the several commands from
            # one request do not collide on the CommandRepository UNIQUE index
            # (and a retry of the whole request stays idempotent per engine).
            # Bounded to the VARCHAR(200) column even when the base key is at its
            # max length (commands:1015).
            # The FIRST command of the request commits under the
            # request-scoped key so a replay collides with it whatever the
            # expansion turns out to be; the rest stay per-engine.
            idempotency_key=(
                request_key
                if first is None and request_key is not None
                else _engine_idempotency_key(body.idempotency_key, engine)
            ),
            agent_id=body.agent_id,
            user=user,
            memberships=memberships,
            projects=projects,
            audit_log=audit_log,
            dispatcher=dispatcher,
            db_session=db_session,
            ip=ip,
        )
        if first is None:
            first = issued
    assert first is not None  # by_engine was non-empty
    return first


async def _resolve_purge_confirm_token(
    *,
    body: PurgeQueueRequest,
    slug: str,
    projects: ProjectRepository,
    settings: Settings,
) -> str | None:
    """Return the confirm token to attach to a purge command.

    An explicit ``body.confirm_token`` (non-dashboard API client) is
    passed through unchanged. Otherwise, when ``observed_depth`` is
    supplied and the command is not ``force``, compute the keyed
    ``HMAC(project_secret, "purge|queue|depth")`` token server-side (M-7)
    using the same per-project secret the agent holds -- so the operator
    never handles a token and a depth-observer cannot forge one. Returns
    None (agent will refuse unless force) when neither input is present
    or the project cannot be resolved.
    """
    if body.confirm_token is not None:
        return body.confirm_token
    if body.force or body.observed_depth is None:
        return None
    from z4j_core.purge_token import compute_purge_confirm_token
    from z4j_core.transport.hmac import derive_project_secret

    project = await projects.get_by_slug(slug)
    if project is None:
        return None
    master = settings.secret.get_secret_value().encode("utf-8")
    secret = derive_project_secret(master, project.id)
    return compute_purge_confirm_token(
        secret=secret,
        queue_name=body.queue,
        queue_depth=body.observed_depth,
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
) -> CommandPublic:
    """DESTRUCTIVE - requires admin role.

    Removes every pending task from the named queue. The agent's
    purge action refuses the destructive ``queue_delete``
    fallback, so this is bounded to ``queue_purge`` semantics.

    The caller passes ``observed_depth`` (the depth they confirmed
    against) and the brain computes the keyed confirm token
    server-side (M-7), or a pre-computed ``confirm_token``, or
    ``force=True``. Without one of these the agent refuses to act.
    """
    confirm_token = await _resolve_purge_confirm_token(
        body=body,
        slug=slug,
        projects=projects,
        settings=settings,
    )
    return await _issue_generic_command(
        slug=slug,
        action="purge_queue",
        target_type="queue",
        target_id=body.queue,
        payload={
            "queue": body.queue,
            "confirm_token": confirm_token,
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    db_session: AsyncSession = Depends(get_session),
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
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
    audit_log: AuditLogRepository,
    dispatcher: CommandDispatcher,
    db_session: AsyncSession,
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
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
    audit_log: AuditLogRepository,
    dispatcher: CommandDispatcher,
    db_session: AsyncSession,
    ip: str,
    require_role: ProjectRole = ProjectRole.OPERATOR,
    synthetic_success_result: dict[str, Any] | None = None,
) -> CommandPublic:
    """Shared body for every command-issuing endpoint.

    Centralises the policy check, the cross-project agent guard,
    and the dispatcher invocation. Sub-routes pass an ``action``
    and a payload; everything else is identical.

    M1: when ``synthetic_success_result`` is supplied the command is COMPLETED
    in place with that result instead of being delivered to the agent (used by
    the no-owned-match bulk-retry no-op, which must not round-trip a task_ids=[]
    command the adapter reports as failed).
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
        project=project,
        min_role=require_role,
    )

    # Cross-project agent guard.
    agent = await AgentRepository(db_session).get_live(agent_id, lock=True)
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
        pre_completed_result=synthetic_success_result,
        # Operator endpoints (retry/cancel/bulk-retry) reach the wire via
        # this helper. Reusing an idempotency key with DIFFERENT parameters (a
        # different override_kwargs, a different bulk filter) must 409, not be
        # silently swallowed and return the first command. The fire + automation
        # paths (which call dispatcher.issue directly) keep the default False.
        enforce_payload_identity=True,
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
