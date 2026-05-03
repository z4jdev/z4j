"""``/api/v1/projects/{slug}/schedules`` REST router.

Provides:

- ``GET    /``                - list schedules in the project
- ``GET    /{schedule_id}``    - schedule detail
- ``POST   /{schedule_id}/enable``  - enable (issues schedule.enable command)
- ``POST   /{schedule_id}/disable`` - disable
- ``POST   /{schedule_id}/trigger`` - fire-now (issues schedule.trigger_now)

Schedules CRUD (create / update / delete via the brain) lands in
B6 alongside the registry-delta sync - for now schedules are
created in the user's own celery-beat / APScheduler and the brain
mirrors them via the agent's signal hooks.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    resolve_api_key_id,
)
from z4j_brain.domain.ip_rate_limit import require_bulk_action_throttle
from z4j_brain.errors import NotFoundError, ValidationError
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.command_dispatcher import CommandDispatcher
    from z4j_brain.persistence.models import Agent, Schedule, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/schedules", tags=["schedules"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SchedulePublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    engine: str
    scheduler: str
    name: str
    task_name: str
    kind: str
    expression: str
    timezone: str
    queue: str | None
    priority: str
    args: Any
    kwargs: Any
    is_enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    total_runs: int
    external_id: str | None
    created_at: datetime
    updated_at: datetime
    # Phase 2 columns surfaced for the dashboard + the reverse
    # exporter. ``source`` lets the dashboard render a "managed by"
    # badge; ``catch_up`` shows the missed-fire policy.
    catch_up: str = "skip"
    source: str = "dashboard"
    source_hash: str | None = None


def _payload(schedule: "Schedule") -> SchedulePublic:
    return SchedulePublic(
        id=schedule.id,
        project_id=schedule.project_id,
        engine=schedule.engine,
        scheduler=schedule.scheduler,
        name=schedule.name,
        task_name=schedule.task_name,
        kind=schedule.kind.value,
        expression=schedule.expression,
        timezone=schedule.timezone,
        queue=schedule.queue,
        priority=schedule.priority.value if hasattr(schedule.priority, "value") else str(schedule.priority or "normal"),
        args=schedule.args,
        kwargs=schedule.kwargs,
        is_enabled=schedule.is_enabled,
        last_run_at=schedule.last_run_at,
        next_run_at=schedule.next_run_at,
        total_runs=schedule.total_runs,
        external_id=schedule.external_id,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
        catch_up=getattr(schedule, "catch_up", None) or "skip",
        source=getattr(schedule, "source", None) or "dashboard",
        source_hash=getattr(schedule, "source_hash", None),
    )


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


class SchedulesListPublic(BaseModel):
    """Paged list of schedules (v1.1.0 N+1 fix).

    Pre-1.1 ``GET /schedules`` returned a bare ``list[SchedulePublic]``
    with no LIMIT, a project with 1000+ schedules pulled every row
    on every dashboard refresh. v1.1.0 adds keyset pagination on
    ``(name, id)``; the response envelope mirrors the existing
    deliveries / audit / commands list shape.

    Back-compat: when neither ``limit`` nor ``cursor`` is supplied
    AND the result set fits inside the default page (50), the
    response is structurally compatible with anything that just
    iterates ``items``. A consumer that previously did
    ``response.json()`` and got a list now gets a dict, bumping
    the response_model is a v1.0 → v1.1 contract change documented
    in the brain CHANGELOG.
    """

    items: list[SchedulePublic]
    next_cursor: str | None


def _encode_schedules_cursor(name: str, schedule_id: uuid.UUID) -> str:
    return f"{name}|{schedule_id.hex}"


def _decode_schedules_cursor(
    raw: str | None,
) -> tuple[str | None, uuid.UUID | None]:
    if not raw or "|" not in raw:
        return None, None
    name, _, hex_id = raw.partition("|")
    try:
        sched_id = uuid.UUID(hex=hex_id)
    except ValueError:
        return None, None
    return name, sched_id


@router.get("", response_model=SchedulesListPublic)
async def list_schedules(
    slug: str,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> SchedulesListPublic:
    """List schedules in a project, paginated.

    Keyset cursor encoded as ``"<name>|<uuid_hex>"``. Pages are
    capped at 500 rows; default 50 mirrors the dashboard's typical
    table page size. Order is ``(name, id)`` so the same row never
    appears on two pages even when names collide cross-project
    (within a project ``name`` is unique by DB constraint).
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import ScheduleRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    cursor_name, cursor_id = _decode_schedules_cursor(cursor)
    # Fetch limit+1 so we can detect a next page without a second
    # COUNT() round-trip. Mirrors the deliveries / audit pattern.
    rows = await ScheduleRepository(db_session).list_for_project(
        project.id,
        limit=limit + 1,
        cursor_name=cursor_name,
        cursor_id=cursor_id,
    )
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_schedules_cursor(last.name, last.id)
    return SchedulesListPublic(
        items=[_payload(s) for s in rows],
        next_cursor=next_cursor,
    )


class ScheduleFirePublic(BaseModel):
    """One historical fire of a schedule (Phase 4 fire-history view)."""

    id: uuid.UUID
    fire_id: uuid.UUID
    schedule_id: uuid.UUID
    command_id: uuid.UUID | None
    status: str
    scheduled_for: datetime
    fired_at: datetime
    acked_at: datetime | None
    latency_ms: int | None
    error_code: str | None
    error_message: str | None


def _fire_payload(row: Any) -> ScheduleFirePublic:
    return ScheduleFirePublic(
        id=row.id,
        fire_id=row.fire_id,
        schedule_id=row.schedule_id,
        command_id=row.command_id,
        status=row.status,
        scheduled_for=row.scheduled_for,
        fired_at=row.fired_at,
        acked_at=row.acked_at,
        latency_ms=row.latency_ms,
        error_code=row.error_code,
        error_message=row.error_message,
    )


@router.get(
    "/{schedule_id}/fires",
    response_model=list[ScheduleFirePublic],
)
async def list_schedule_fires(
    slug: str,
    schedule_id: uuid.UUID,
    limit: int = 100,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[ScheduleFirePublic]:
    """Return the schedule's fire history, newest first.

    Authorization: VIEWER (read-only). The fire history exposes
    timestamps + status + latency, which any project member should
    see (matches the existing schedule list/get permissions). The
    error_message field is included verbatim - operators want the
    debug detail. Args/kwargs are NOT included since the dashboard
    has the schedule detail page for those.

    Limit is capped at 1000 to prevent runaway queries; the
    dashboard pages defaults to 50.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        ScheduleFireRepository,
        ScheduleRepository,
    )

    if limit < 1 or limit > 1000:
        limit = max(1, min(1000, limit))

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    # Verify the schedule belongs to this project (IDOR-safe).
    schedule = await ScheduleRepository(db_session).get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    if schedule is None:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )

    rows = await ScheduleFireRepository(db_session).list_recent_for_schedule(
        schedule_id=schedule.id,
        project_id=project.id,
        limit=limit,
    )
    return [_fire_payload(r) for r in rows]


@router.get("/{schedule_id}", response_model=SchedulePublic)
async def get_schedule(
    slug: str,
    schedule_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> SchedulePublic:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import ScheduleRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    schedule = await ScheduleRepository(db_session).get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    if schedule is None:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )
    return _payload(schedule)


# ---------------------------------------------------------------------------
# CRUD endpoints (Phase 3) - dashboard + declarative reconciler
# ---------------------------------------------------------------------------


# --- Audit-driven hardening (Apr 2026) ---
#
# Field caps + enum constraints applied to every operator-facing
# schedule body. The API layer was previously schema-permissive
# and relied on the repository's downstream validation, which
# meant:
#
# 1. **DoS via unbounded args/kwargs**: an admin (or compromised
#    admin token) could POST a 100MB JSON payload that OOM'd the
#    brain on parse + bloated the JSONB column. Fixed via
#    a serialised-size cap enforced at the boundary (audit H-1).
# 2. **Unconstrained kind values**: ``kind: str`` accepted any
#    string at the API; OpenAPI docs lied about allowed values
#    and the wire was looser than the underlying enum (audit H-2).
# 3. **Name corruption**: control characters in ``name`` flowed
#    into audit metadata, dashboard, and gRPC payloads. Operators
#    could break log-line parsing; the dashboard had to render
#    arbitrary unicode (audit M-3 from REST audit).
# 4. **Length cliffs**: ``expression``, ``task_name``, ``queue``,
#    ``source`` could carry MB-scale strings (audit M-4 / L-3).

_KIND_VOCAB = ("cron", "interval", "one_shot", "solar")
_CATCH_UP_VOCAB = ("skip", "fire_one_missed", "fire_all_missed")


def _validate_iana_timezone(value: str) -> str:
    """Round-8 audit fix R8-Time-H2 (Apr 2026): reject bad IANA tz at API.

    Pre-fix the only validation was ``max_length``. A typo like
    ``"America/New York"`` (space) or a junk string like ``"Foo/Bar"``
    was accepted at create time, watch-streamed to the scheduler,
    and on first tick ``cron.next_fire`` raised ``CronExpressionError``
    which the engine swallowed by disabling the schedule. Operators
    saw a created-but-never-firing schedule and no API-side error.

    Validates by attempting :class:`zoneinfo.ZoneInfo` construction.
    Empty string and ``"UTC"`` always pass. Returns the trimmed
    value.
    """
    if value is None:
        return value
    stripped = value.strip()
    if stripped == "":
        return "UTC"
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415

        ZoneInfo(stripped)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"timezone {stripped!r} is not a valid IANA timezone "
            "(e.g. 'UTC', 'America/New_York', 'Europe/London')",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Any other parser failure (malformed bytes, encoding issues)
        # is also a rejection; better an explicit 422 than silent
        # downstream tick failure.
        raise ValueError(
            f"timezone {stripped!r} could not be resolved: {exc}",
        ) from exc
    return stripped

# JSON-serialised byte cap per args/kwargs payload. 64KB is the
# operator-friendly ceiling: covers every realistic schedule
# (largest celery-beat configs in the wild are ~5KB) without
# allowing the abuse case that motivated the cap.
_ARGS_KWARGS_MAX_SERIALIZED_BYTES = 64 * 1024

# Per-field length caps. Picked to comfortably cover legitimate
# values + some padding, while bounding worst-case storage and
# log-line cost.
_NAME_MAX = 200
_EXPRESSION_MAX = 1024  # six-field cron with comma-lists is still short
_TASK_NAME_MAX = 500    # python.dotted.module.name with package depth
_TIMEZONE_MAX = 64      # IANA tz names are < 50 chars in practice
_QUEUE_MAX = 200        # broker queue name; RabbitMQ caps at 255
_SOURCE_MAX = 64        # source label vocab is short by convention
_SOURCE_HASH_MAX = 128  # SHA-256 hex = 64 chars; SHA-512 = 128

# Pattern that rejects ASCII control chars (NUL through US, plus
# DEL). Tab + newlines are explicitly disallowed because audit
# log lines + cron output are line-oriented.
_NO_CONTROL_CHARS = r"^[^\x00-\x1f\x7f]+$"


def _validate_args_kwargs_size(value: Any, field_name: str) -> Any:
    """Cap the JSON-serialised size of args/kwargs payloads.

    Pydantic does not have a native "deep size" validator; we
    serialise once here so the runtime is bounded. The check is
    cheap (json.dumps over a small payload is fast); for the
    abuse case (multi-MB payload) the serialise itself is the
    rate-limit.
    """
    import json as _json  # noqa: PLC0415

    if value is None:
        return value
    try:
        serialized = _json.dumps(value, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field_name} is not JSON-serialisable: {exc}",
        ) from exc
    if len(serialized.encode("utf-8")) > _ARGS_KWARGS_MAX_SERIALIZED_BYTES:
        raise ValueError(
            f"{field_name} exceeds {_ARGS_KWARGS_MAX_SERIALIZED_BYTES} "
            f"bytes when JSON-serialised; trim the payload",
        )
    return value


class ScheduleCreateIn(BaseModel):
    """Body for ``POST /schedules`` - operator-defined schedule."""

    name: str = Field(
        ..., min_length=1, max_length=_NAME_MAX, pattern=_NO_CONTROL_CHARS,
    )
    engine: str = Field(..., min_length=1, max_length=40)
    kind: str = Field(..., min_length=1, max_length=20)
    expression: str = Field(
        ..., min_length=1, max_length=_EXPRESSION_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    # Round-3 audit fix (Apr 2026): reject control characters in
    # ``task_name``. Pre-fix the cron exporter's DISABLED branch
    # could be coerced into emitting an active crontab line by
    # planting a newline in this field. Defense-in-depth at the
    # API boundary so any future renderer / exporter that forgets
    # to sanitize is still safe.
    task_name: str = Field(
        ..., min_length=1, max_length=_TASK_NAME_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    timezone: str = Field(default="UTC", max_length=_TIMEZONE_MAX)
    queue: str | None = Field(default=None, max_length=_QUEUE_MAX)
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    catch_up: str = Field(default="skip", min_length=1, max_length=20)
    is_enabled: bool = True
    # 1.2.2: when None, the create handler falls back to the
    # project's ``default_scheduler_owner`` (default
    # ``"z4j-scheduler"``). Operators in celery-beat-first shops
    # can flip the project default so dashboard-created schedules
    # land under celery-beat ownership instead of z4j-scheduler.
    # Pre-1.2.2 this field defaulted to ``"z4j-scheduler"``
    # unconditionally; the new None default is backward-compatible
    # because callers that explicitly pass ``"z4j-scheduler"``
    # still get z4j-scheduler-owned schedules.
    scheduler: str | None = Field(
        default=None, min_length=1, max_length=40,
    )
    source: str = Field(default="dashboard", min_length=1, max_length=_SOURCE_MAX)
    source_hash: str | None = Field(default=None, max_length=_SOURCE_HASH_MAX)

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str) -> str:
        if v not in _KIND_VOCAB:
            raise ValueError(
                f"kind must be one of {_KIND_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("catch_up")
    @classmethod
    def _validate_catch_up(cls, v: str) -> str:
        if v not in _CATCH_UP_VOCAB:
            raise ValueError(
                f"catch_up must be one of {_CATCH_UP_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str) -> str:
        return _validate_iana_timezone(v)

    @field_validator("args")
    @classmethod
    def _cap_args(cls, v: list[Any]) -> list[Any]:
        return _validate_args_kwargs_size(v, "args")

    @field_validator("kwargs")
    @classmethod
    def _cap_kwargs(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_args_kwargs_size(v, "kwargs")


class ScheduleUpdateIn(BaseModel):
    """Body for ``PATCH /schedules/{id}`` - all fields optional.

    None means "do not touch this field." This lets the dashboard
    flip a single attribute (timezone, expression, queue) without
    re-sending the rest of the row.

    NOTE (1.2.2 audit fix): ``scheduler`` is intentionally NOT in
    this model. Changing a schedule's owner mid-flight would
    create surprising side-effects (the new owner has different
    fire history, possibly different `allowed_schedulers`
    membership). Operators who need to migrate ownership delete +
    recreate via the importer or the dashboard "Promote" action.
    If this list ever gains a ``scheduler`` field, the
    ``update_schedule`` handler MUST call
    ``_validate_scheduler_in_allowlist`` before persisting it.
    """

    engine: str | None = Field(default=None, min_length=1, max_length=40)
    kind: str | None = Field(default=None, min_length=1, max_length=20)
    expression: str | None = Field(
        default=None, min_length=1, max_length=_EXPRESSION_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    # Round-3 audit fix (Apr 2026): see ScheduleCreateIn.task_name.
    task_name: str | None = Field(
        default=None, min_length=1, max_length=_TASK_NAME_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    timezone: str | None = Field(default=None, max_length=_TIMEZONE_MAX)
    queue: str | None = Field(default=None, max_length=_QUEUE_MAX)
    args: list[Any] | None = None
    kwargs: dict[str, Any] | None = None
    catch_up: str | None = Field(default=None, min_length=1, max_length=20)
    is_enabled: bool | None = None
    source_hash: str | None = Field(default=None, max_length=_SOURCE_HASH_MAX)

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in _KIND_VOCAB:
            raise ValueError(
                f"kind must be one of {_KIND_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_iana_timezone(v)

    @field_validator("catch_up")
    @classmethod
    def _validate_catch_up(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in _CATCH_UP_VOCAB:
            raise ValueError(
                f"catch_up must be one of {_CATCH_UP_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("args")
    @classmethod
    def _cap_args(cls, v: list[Any] | None) -> list[Any] | None:
        return _validate_args_kwargs_size(v, "args")

    @field_validator("kwargs")
    @classmethod
    def _cap_kwargs(
        cls, v: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        return _validate_args_kwargs_size(v, "kwargs")


@router.post(
    "",
    response_model=SchedulePublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_schedule(
    slug: str,
    body: ScheduleCreateIn,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> SchedulePublic:
    """Create a new schedule under the project.

    Authorization: ADMIN. Creating a schedule is a privileged
    operation - it can move money, send emails, etc.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import ScheduleRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    # 1.2.2: when scheduler is None (operator didn't pick), fall
    # back to the project's default_scheduler_owner. Defaults to
    # ``"z4j-scheduler"`` for fresh projects; celery-beat-first
    # shops flip it via PATCH /projects/{slug}.
    create_data = body.model_dump()
    if create_data.get("scheduler") is None:
        create_data["scheduler"] = getattr(
            project, "default_scheduler_owner", "z4j-scheduler",
        )
    # 1.2.2 audit fix MED-13: enforce per-project allow-list when
    # set. ``None`` means unrestricted (the default).
    _validate_scheduler_in_allowlist(project, create_data["scheduler"])

    repo = ScheduleRepository(db_session)
    try:
        row = await repo.create_for_project(
            project_id=project.id, data=create_data,
        )
    except ValueError as exc:
        # 422 Unprocessable Entity - the request was syntactically
        # OK but the values failed semantic validation (bad enum,
        # missing required field). Audit-Phase3-4 fix: previously
        # this raised NotFoundError → 404 which misled clients.
        raise ValidationError(
            f"invalid schedule: {exc}",
            details={"reason": str(exc)},
        ) from exc

    await audit.record(
        audit_log,
        action="schedule.create",
        target_type="schedule",
        target_id=str(row.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={"name": row.name, "engine": row.engine, "kind": row.kind.value},
    )
    await db_session.commit()
    return _payload(row)


@router.patch(
    "/{schedule_id}",
    response_model=SchedulePublic,
    dependencies=[Depends(require_csrf)],
)
async def update_schedule(
    slug: str,
    schedule_id: uuid.UUID,
    body: ScheduleUpdateIn,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> SchedulePublic:
    """Partial update. Only fields present in the body are touched.

    Authorization: ADMIN.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import ScheduleRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    # Drop None values so the repo's "only set what's present"
    # contract holds.
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    repo = ScheduleRepository(db_session)
    try:
        row = await repo.update_for_project(
            project_id=project.id,
            schedule_id=schedule_id,
            data=patch,
        )
    except ValueError as exc:
        # 422 (not 404). Bad enum / unknown field is a semantic
        # validation failure, not a "resource missing" condition.
        raise ValidationError(
            f"invalid schedule update: {exc}",
            details={"reason": str(exc)},
        ) from exc
    if row is None:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )

    await audit.record(
        audit_log,
        action="schedule.update",
        target_type="schedule",
        target_id=str(schedule_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={"fields_changed": sorted(patch.keys())},
    )
    await db_session.commit()
    return _payload(row)


@router.delete(
    "/{schedule_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_schedule(
    slug: str,
    schedule_id: uuid.UUID,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    """Hard-delete the schedule. IDOR-safe (project-scoped lookup).

    Cascades to ``pending_fires`` via FK. Authorization: ADMIN.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import ScheduleRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    repo = ScheduleRepository(db_session)
    deleted = await repo.delete_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    if not deleted:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )

    await audit.record(
        audit_log,
        action="schedule.delete",
        target_type="schedule",
        target_id=str(schedule_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={},
    )
    await db_session.commit()
    return None


# ---------------------------------------------------------------------------
# Write endpoints - issue commands to the agent
# ---------------------------------------------------------------------------


async def _pick_scheduler_agent(
    *,
    db_session: "AsyncSession",
    project_id: uuid.UUID,
    scheduler_name: str,
    schedule_id: uuid.UUID,
) -> "Agent":
    """Pick the best online agent to receive a schedule command.

    Filters the project's agents down to those that are:

    1. Currently online (``state == ONLINE``), and
    2. Registered for the schedule's specific scheduler adapter
       (``scheduler_name`` in ``agent.scheduler_adapters``).

    Returns the freshest match (``list_online_for_project`` orders
    by ``last_seen_at DESC``). Raises :class:`NotFoundError` with a
    helpful message if nothing matches so the dashboard can surface
    the root cause (offline agent vs. adapter not installed) rather
    than the old "no agent registered" generic string.

    Audit 2026-04-24 Medium-4: before this helper the caller did
    ``next(iter(list_for_project(...)), None)``, which picked ANY
    agent regardless of online state or scheduler support - so a
    Django+Celery+RQ project could send ``schedule.enable`` to the
    RQ-only agent and leave the brain's optimistic ``is_enabled``
    out of sync forever.
    """
    from z4j_brain.persistence.repositories import AgentRepository

    agents = await AgentRepository(db_session).list_online_for_project(
        project_id,
    )
    for agent in agents:
        if scheduler_name in (agent.scheduler_adapters or ()):
            return agent

    # None matched. Tell the caller WHY so the UI can help the
    # operator: is no agent online at all, or is one online but
    # without this scheduler adapter?
    if not agents:
        raise NotFoundError(
            "no online agent for this project; start the agent "
            "and retry",
            details={
                "schedule_id": str(schedule_id),
                "scheduler": scheduler_name,
                "reason": "no_online_agent",
            },
        )
    raise NotFoundError(
        f"no online agent advertises scheduler {scheduler_name!r}; "
        f"install the matching scheduler adapter on an agent and "
        f"restart it",
        details={
            "schedule_id": str(schedule_id),
            "scheduler": scheduler_name,
            "reason": "scheduler_not_installed",
        },
    )


async def _enable_or_disable(
    *,
    slug: str,
    schedule_id: uuid.UUID,
    enabled: bool,
    user: "User",
    memberships: "MembershipRepository",
    projects: "ProjectRepository",
    audit_log: "AuditLogRepository",
    dispatcher: "CommandDispatcher",
    db_session: "AsyncSession",
    ip: str,
) -> SchedulePublic:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        CommandRepository,
        ScheduleRepository,
    )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.OPERATOR,
    )

    schedules_repo = ScheduleRepository(db_session)
    schedule = await schedules_repo.get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    if schedule is None:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )

    target_agent = await _pick_scheduler_agent(
        db_session=db_session,
        project_id=project.id,
        scheduler_name=schedule.scheduler,
        schedule_id=schedule_id,
    )

    action = "schedule.enable" if enabled else "schedule.disable"
    commands = CommandRepository(db_session)
    await dispatcher.issue(
        commands=commands,
        audit_log=audit_log,
        project_id=project.id,
        agent_id=target_agent.id,
        action=action,
        target_type="schedule",
        target_id=str(schedule_id),
        payload={
            "schedule_id": schedule.name,
            "schedule_name": schedule.name,
            "external_id": schedule.external_id,
        },
        issued_by=user.id,
        ip=ip,
        user_agent=None,
    )
    # Optimistically reflect the operator's intent in the brain row.
    # The agent will sync back the authoritative state on success.
    await schedules_repo.set_enabled(
        schedule_id=schedule_id, enabled=enabled,
    )
    await db_session.commit()

    await dispatcher.notify_dashboard_command_change(project.id)

    refreshed = await schedules_repo.get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    assert refreshed is not None
    return _payload(refreshed)


@router.post(
    "/{schedule_id}/enable",
    response_model=SchedulePublic,
    dependencies=[Depends(require_csrf)],
)
async def enable_schedule(
    slug: str,
    schedule_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> SchedulePublic:
    return await _enable_or_disable(
        slug=slug,
        schedule_id=schedule_id,
        enabled=True,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/{schedule_id}/disable",
    response_model=SchedulePublic,
    dependencies=[Depends(require_csrf)],
)
async def disable_schedule(
    slug: str,
    schedule_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> SchedulePublic:
    return await _enable_or_disable(
        slug=slug,
        schedule_id=schedule_id,
        enabled=False,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_log=audit_log,
        dispatcher=dispatcher,
        db_session=db_session,
        ip=ip,
    )


@router.post(
    "/{schedule_id}/trigger",
    response_model=SchedulePublic,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def trigger_schedule_now(
    slug: str,
    schedule_id: uuid.UUID,
    request: "Request",
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    settings: "Settings" = Depends(get_settings),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> SchedulePublic:
    """Issue a one-shot ``schedule.trigger_now`` command.

    The schedule itself is unchanged - its normal cadence is
    untouched. The agent fires the underlying task once.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        CommandRepository,
        ScheduleRepository,
    )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.OPERATOR,
    )

    schedules_repo = ScheduleRepository(db_session)
    schedule = await schedules_repo.get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    if schedule is None:
        raise NotFoundError(
            "schedule not found",
            details={"schedule_id": str(schedule_id)},
        )

    # Phase 2: when the schedule is owned by z4j-scheduler AND the
    # operator has wired the trigger client, route the trigger
    # through the scheduler so its local cache last_fire_at gets
    # the update (preventing the next tick from double-firing).
    # Falls through to the v1 direct-dispatch path for any
    # combination that doesn't match.
    # Phase 2: when the schedule is owned by z4j-scheduler AND the
    # operator has wired the trigger client, route through the
    # scheduler so its local cache last_fire_at gets the update
    # (preventing the next tick from double-firing).
    use_scheduler_grpc = (
        schedule.scheduler == "z4j-scheduler"
        and bool(settings.scheduler_trigger_url)
    )
    if use_scheduler_grpc:
        client = await _get_or_build_trigger_client(request, settings)
        response = await client.trigger(
            schedule_id=schedule_id,
            user_id=user.id,
            idempotency_key=f"trigger:{schedule_id}:{user.id}",
        )
        if response.error_code:
            # Audit fix M-2 (Apr 2026): record the failed trigger
            # attempt BEFORE raising. Pre-fix the brain had no
            # record an operator attempted a trigger that the
            # scheduler refused; an attacker probing for valid
            # schedule_ids could brute-force without leaving a
            # forensic trail.
            try:
                await audit.record(
                    audit_log,
                    action="schedule.trigger_now.via_scheduler",
                    target_type="schedule",
                    target_id=str(schedule_id),
                    result="failure",
                    outcome="deny",
                    user_id=user.id,
                    project_id=project.id,
                    api_key_id=resolve_api_key_id(request),
                    source_ip=ip,
                    metadata={
                        "error_code": response.error_code,
                        "error_message": response.error_message,
                        "scheduler_url": settings.scheduler_trigger_url,
                    },
                )
                await db_session.commit()
            except Exception:  # noqa: BLE001
                # Audit failure should not mask the original
                # scheduler error from the operator. Log + continue
                # to the raise.
                import logging  # noqa: PLC0415

                logging.getLogger("z4j.brain.schedules").exception(
                    "trigger audit (failure) write crashed",
                )
            raise NotFoundError(
                f"scheduler rejected trigger: {response.error_code}",
                details={
                    "error_code": response.error_code,
                    "error_message": response.error_message,
                },
            )
        # Audit the trigger on the brain side (the scheduler audits
        # its dispatch separately). One row per click is the
        # operator-facing record.
        await audit.record(
            audit_log,
            action="schedule.trigger_now.via_scheduler",
            target_type="schedule",
            target_id=str(schedule_id),
            result="success",
            outcome="allow",
            user_id=user.id,
            project_id=project.id,
            api_key_id=resolve_api_key_id(request),
            source_ip=ip,
            metadata={
                "scheduler_command_id": response.command_id,
                "scheduler_url": settings.scheduler_trigger_url,
            },
        )
        await db_session.commit()
        refreshed = await schedules_repo.get_for_project(
            project_id=project.id, schedule_id=schedule_id,
        )
        assert refreshed is not None
        return _payload(refreshed)

    # v1 direct-dispatch path: pick a matching agent and issue the
    # schedule.trigger_now command. Used when no scheduler is
    # attached, or when the schedule is owned by celery-beat /
    # apscheduler / etc. on the agent side.
    target_agent = await _pick_scheduler_agent(
        db_session=db_session,
        project_id=project.id,
        scheduler_name=schedule.scheduler,
        schedule_id=schedule_id,
    )

    await dispatcher.issue(
        commands=CommandRepository(db_session),
        audit_log=audit_log,
        project_id=project.id,
        agent_id=target_agent.id,
        action="schedule.trigger_now",
        target_type="schedule",
        target_id=str(schedule_id),
        payload={
            "schedule_id": schedule.name,
            "schedule_name": schedule.name,
            "external_id": schedule.external_id,
        },
        issued_by=user.id,
        ip=ip,
        user_agent=None,
    )
    await db_session.commit()

    await dispatcher.notify_dashboard_command_change(project.id)

    refreshed = await schedules_repo.get_for_project(
        project_id=project.id, schedule_id=schedule_id,
    )
    assert refreshed is not None
    return _payload(refreshed)


# ---------------------------------------------------------------------------
# Trigger-client singleton helper
# ---------------------------------------------------------------------------


async def _get_or_build_trigger_client(
    request: "Request",
    settings: "Settings",
):
    """Return a process-wide :class:`TriggerScheduleClient` singleton.

    First call lazily constructs the client + opens the gRPC channel
    and caches it on ``app.state.scheduler_trigger_client``. Every
    subsequent trigger reuses the same channel - which means one TLS
    handshake per brain process, not one per click. The previous
    per-call construction was an audit-Phase2 finding (TLS cost on
    every trigger button push).

    The brain shutdown path closes the client in
    ``z4j_brain.main._lifespan`` finally-block.
    """
    cached = getattr(request.app.state, "scheduler_trigger_client", None)
    if cached is not None:
        return cached
    from z4j_brain.scheduler_grpc.trigger_client import (  # noqa: PLC0415
        TriggerScheduleClient,
    )

    client = TriggerScheduleClient(settings=settings)
    await client.connect()
    request.app.state.scheduler_trigger_client = client
    return client


# ---------------------------------------------------------------------------
# Bulk import (z4j-scheduler migration importers)
# ---------------------------------------------------------------------------


class ImportedScheduleIn(BaseModel):
    """One row of a bulk import payload.

    Mirrors :class:`z4j_scheduler.importers._core.ImportedSchedule` -
    the importers compute ``source_hash`` for re-import idempotency
    and carry through ``source`` so the dashboard can render a
    "managed by celery-beat (imported)" badge.

    ``project_slug`` is dropped on the wire because the URL already
    pins the project; we accept it if the importer still sends it
    (using ``model_config = ConfigDict(extra="ignore")``) but never
    use it.

    Field caps mirror :class:`ScheduleCreateIn` (audit fix Apr 2026).
    """

    name: str = Field(
        ..., min_length=1, max_length=_NAME_MAX, pattern=_NO_CONTROL_CHARS,
    )
    engine: str = Field(..., min_length=1, max_length=40)
    kind: str = Field(..., min_length=1, max_length=20)
    expression: str = Field(
        ..., min_length=1, max_length=_EXPRESSION_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    # Round-3 audit fix (Apr 2026): see ScheduleCreateIn.task_name.
    task_name: str = Field(
        ..., min_length=1, max_length=_TASK_NAME_MAX,
        pattern=_NO_CONTROL_CHARS,
    )
    timezone: str = Field(default="UTC", max_length=_TIMEZONE_MAX)
    queue: str | None = Field(default=None, max_length=_QUEUE_MAX)
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    catch_up: str = Field(default="skip", min_length=1, max_length=20)
    is_enabled: bool = True
    # Audit fix CRIT-2 (1.2.2 second-pass): default ``None`` so
    # the import handler resolves to the project's
    # ``default_scheduler_owner`` instead of overriding it with a
    # hardcoded ``"z4j-scheduler"``. Pre-fix, a project that had
    # flipped its default to ``celery-beat`` saw imported rows
    # silently land under ``z4j-scheduler`` ownership.
    scheduler: str | None = Field(
        default=None, min_length=1, max_length=40,
    )
    source: str = Field(
        default="imported", min_length=1, max_length=_SOURCE_MAX,
    )
    source_hash: str | None = Field(default=None, max_length=_SOURCE_HASH_MAX)

    # Pydantic v2 - allow extra keys (project_slug from importer
    # client) without erroring. We only consume the fields above.
    model_config = {"extra": "ignore"}

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str) -> str:
        if v not in _KIND_VOCAB:
            raise ValueError(
                f"kind must be one of {_KIND_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str) -> str:
        return _validate_iana_timezone(v)

    @field_validator("catch_up")
    @classmethod
    def _validate_catch_up(cls, v: str) -> str:
        if v not in _CATCH_UP_VOCAB:
            raise ValueError(
                f"catch_up must be one of {_CATCH_UP_VOCAB}; got {v!r}",
            )
        return v

    @field_validator("args")
    @classmethod
    def _cap_args(cls, v: list[Any]) -> list[Any]:
        return _validate_args_kwargs_size(v, "args")

    @field_validator("kwargs")
    @classmethod
    def _cap_kwargs(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_args_kwargs_size(v, "kwargs")


# Audit fix H-3 (Apr 2026): the ``replace_for_source`` mode deletes
# every schedule sharing the source label that's NOT in the batch.
# Without an allow-list, an admin (or compromised admin token) can
# POST ``mode=replace_for_source, source_filter="dashboard",
# schedules=[]`` and wipe every dashboard-managed schedule in one
# request. We pin the legitimate replace-mode source values to the
# declarative + importer vocabulary; "dashboard" is operator-edited
# state and must NEVER be a replace target.
_REPLACE_FOR_SOURCE_ALLOWLIST: frozenset[str] = frozenset({
    # Declarative reconcilers - the legitimate use case for replace
    # mode. Each framework adapter tags rows with this prefix.
    # Both ``:`` and ``_`` separators are accepted because both
    # forms appear in the wild (the recent docs use ``:``, the
    # earlier integration tests + some adapter releases use ``_``).
    "declarative:django",
    "declarative:flask",
    "declarative:fastapi",
    "declarative_django",
    "declarative_flask",
    "declarative_fastapi",
    "declarative",  # bare prefix used by some adapters
    # Migration importers - operators occasionally re-run a
    # celery-beat → z4j import to apply upstream changes; the
    # replace mode is the right tool for that flow.
    "imported_celerybeat",
    "imported_celery",
    "imported_django_celery_beat",
    "imported_rq",
    "imported_rqscheduler",
    "imported_apscheduler",
    "imported_cron",
    "imported",  # generic importer label
})


def _validate_scheduler_in_allowlist(
    project: "Project", scheduler_name: str,
) -> None:
    """Reject schedulers outside the project's allow-list (1.2.2+).

    When ``project.allowed_schedulers`` is ``None`` (the default
    for every existing operator) we accept any value, backwards-
    compat. When it's a list we enforce membership; the project's
    own ``default_scheduler_owner`` is implicitly allowed so
    flipping the setting never strands existing schedules.

    Audit fix MED-13 (1.2.2 deep audit). Raises ``ValueError`` so
    both the schedule-create handler (which re-raises as
    ``ValidationError`` for a 422) and the per-row import loop
    (which catches ``ValueError`` to report row-scoped errors)
    handle it uniformly.
    """
    allowed = getattr(project, "allowed_schedulers", None)
    if allowed is None:
        return  # unrestricted
    default_owner = getattr(
        project, "default_scheduler_owner", "z4j-scheduler",
    )
    if scheduler_name == default_owner or scheduler_name in allowed:
        return
    raise ValueError(
        f"allowed_schedulers: scheduler {scheduler_name!r} is not "
        f"in this project's allow-list "
        f"(allow-list: {sorted(allowed)}, "
        f"default: {default_owner!r})",
    )


def _validate_replace_for_source_label(label: str | None) -> str:
    """Reject obviously-destructive replace-mode source labels.

    The allow-list above names the legitimate sources where
    "absence == removal" is the documented contract. Any other
    label - notably ``"dashboard"``, the empty string, or an
    operator typo - is rejected with 422 to prevent the
    accidental-wipe class of incident.
    """
    if not label:
        raise ValueError(
            "replace_for_source requires a non-empty source_filter; "
            "the label must come from the migration importer / "
            "declarative reconciler vocabulary",
        )
    if label not in _REPLACE_FOR_SOURCE_ALLOWLIST:
        raise ValueError(
            f"replace_for_source source_filter {label!r} is not in "
            f"the allow-list {sorted(_REPLACE_FOR_SOURCE_ALLOWLIST)}. "
            "Dashboard-managed schedules must not be wiped via "
            "replace mode - use upsert + per-row delete instead.",
        )
    return label


class ImportSchedulesRequest(BaseModel):
    """POST body for ``/api/v1/projects/{slug}/schedules:import``.

    ``mode`` controls the delete behaviour:

    - ``"upsert"`` (default): per-row upsert. Schedules already in
      brain that are NOT in the batch stay untouched. Right for the
      one-shot importers (celery-beat, rq, apscheduler, cron).
    - ``"replace_for_source"``: same upsert semantics for present
      rows, plus delete every schedule with the same ``source``
      label that is NOT in this batch. Right for the declarative
      reconciler - the framework adapter sends the COMPLETE set of
      schedules from one source label and absence means removal.

    ``source_filter`` is required when ``mode="replace_for_source"``
    and must come from the audited replace-source allow-list.
    Defaults to the source of the first row in the batch (the
    framework adapters always tag everything with one label).

    Audit fix HIGH-8: ``schedules`` is capped at 2000 entries to
    bound the worst-case blast radius of
    ``mode=replace_for_source`` (a misconfigured CI pipeline with
    an empty list could otherwise wipe thousands of schedules in
    one POST). Operators with legitimately larger schedule sets
    should batch their reconciles by source label or contact us
    so we can raise the cap with safer semantics.
    """

    schedules: list[ImportedScheduleIn] = Field(..., max_length=2000)
    mode: str = "upsert"
    source_filter: str | None = None


class ImportSchedulesResponse(BaseModel):
    """Per-batch summary returned to the importer.

    Lets the operator see at a glance whether their re-import was a
    real diff or a no-op. ``errors`` carries human-readable messages
    keyed by index in the input list so the operator can pinpoint
    which row failed without re-correlating by name.

    ``deleted`` counts rows removed by ``mode="replace_for_source"``
    semantics; always 0 in plain upsert mode.
    """

    inserted: int
    updated: int
    unchanged: int
    failed: int
    deleted: int = 0
    errors: dict[int, str] = {}


@router.post(
    ":import",
    response_model=ImportSchedulesResponse,
    status_code=200,
    dependencies=[Depends(require_csrf)],
)
async def import_schedules(
    slug: str,
    body: ImportSchedulesRequest,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> ImportSchedulesResponse:
    """Bulk-import schedules from a migration tool.

    Called by ``z4j-scheduler import --from <tool>``. Each row is
    upserted by ``(project_id, scheduler, name)``. Re-imports with
    matching ``source_hash`` are no-ops so the operator can re-run
    the importer without flooding the audit log.

    Authorization: project ADMIN. Schedule import is a privileged
    operation - it adds new fire surfaces to a project, which can
    move money, send emails, etc. ADMIN matches the existing
    convention for membership / retention / token mutations.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        ScheduleRepository,
        upsert_imported_schedule,
    )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    if body.mode not in ("upsert", "replace_for_source"):
        # Audit fix L-4 (Apr 2026): mode is a semantic input error,
        # not a missing resource. Was raising NotFoundError → 404,
        # which misled clients. Use ValidationError → 422 to match
        # the diff endpoint's behavior + the rest of the API.
        raise ValidationError(
            f"unsupported import mode {body.mode!r}",
            details={"mode": body.mode},
        )

    # Audit fix H-3 (Apr 2026): pre-flight ``source_filter`` against
    # the replace-mode allow-list BEFORE we take the advisory lock
    # or do any per-row work. This is the check that prevents an
    # admin (or compromised admin token) from posting
    # ``mode=replace_for_source, source_filter="dashboard",
    # schedules=[]`` and wiping every dashboard-managed schedule
    # in one request. Reject early + with a clear 422.
    if body.mode == "replace_for_source":
        # Resolve the same way the actual replace pass does so the
        # validation matches the eventual delete scope.
        resolved_source = body.source_filter
        if resolved_source is None and body.schedules:
            resolved_source = body.schedules[0].source
        try:
            _validate_replace_for_source_label(resolved_source)
        except ValueError as exc:
            raise ValidationError(
                str(exc),
                details={
                    "mode": body.mode,
                    "source_filter": body.source_filter,
                    "resolved_source": resolved_source,
                },
            ) from exc

    # Replace-for-source has a TOCTOU race: two admins calling
    # reconcile() concurrently with the same source label can each
    # compute ``surviving_ids`` from a stale snapshot, then the
    # second one's ``DELETE WHERE source=X AND id NOT IN (mine)``
    # silently removes the first one's just-inserted rows.
    # Audit-Phase3-2 caught this. Mitigation: take a Postgres
    # advisory transaction lock keyed on ``hash(project_id, source)``
    # so concurrent reconciles for the same scope serialize. The
    # lock is released on commit/rollback - no manual cleanup. Only
    # applies on Postgres; SQLite has a single writer so the race
    # cannot happen there.
    # 1.2.2 round-7 audit fix CRIT: acquire the project-wide
    # advisory lock FOR EVERY import mode so a concurrent project
    # PATCH that rewrites stored ``Schedule.scheduler`` values
    # cannot race this import. ``update_project`` takes the SAME
    # ``(proj_int, 0)`` lock; both paths serialize on it.
    #
    # Round-7 second pass: the lock used to be inside the
    # ``replace_for_source`` branch (because the source-specific
    # lock only matters for replace), but the PATCH-vs-import race
    # affects EVERY import that touches declarative-source rows
    # under the OLD scheduler, including ``upsert_only``. Hoist
    # the project-wide lock outside the mode check; keep the
    # source-specific lock inside (it's finer-grained
    # reconcile-vs-reconcile serialization, only meaningful for
    # ``replace_for_source``).
    if body.mode == "replace_for_source" and (
        db_session.bind.dialect.name == "postgresql"
        if db_session.bind is not None
        else False
    ):
        from hashlib import sha256  # noqa: PLC0415

        from sqlalchemy import text  # noqa: PLC0415

        scope_key = (
            (body.source_filter
             or (body.schedules[0].source if body.schedules else "")
             or "")
        )
        # Two-int form so we can fit both project_id and source-label
        # hash in the 64-bit advisory-lock key space without collision.
        # Source-specific lock for replace_for_source serializes
        # concurrent reconciles for the SAME source label. (Audit
        # fix M-3, predates 1.2.2.)
        proj_int = int.from_bytes(project.id.bytes[:4], "big", signed=True)
        source_int = int.from_bytes(
            sha256(scope_key.encode()).digest()[:4], "big", signed=True,
        )
        await db_session.execute(
            text("SELECT pg_advisory_xact_lock(:p, :s)"),
            {"p": proj_int, "s": source_int},
        )

    summary = ImportSchedulesResponse(
        inserted=0, updated=0, unchanged=0, failed=0, deleted=0, errors={},
    )
    # Audit fix N-2 (Apr 2026 follow-up): for replace_for_source
    # mode, pre-load the entire (scheduler, name) -> id map for
    # the batch in a SINGLE query, then look up failed-row ids
    # in-memory. Pre-fix the failure-recovery path issued one
    # SELECT per failed row inside the import loop - a 5000-row
    # import with 5% failures was 250 sequential round-trips
    # serialized inside the request. Operational scale + admin-
    # driven imports made this a real tail-latency contributor.
    # Audit fix CRIT-2 (1.2.2 second-pass): resolve each row's
    # scheduler to the project's ``default_scheduler_owner`` when
    # the row didn't pick. Pre-fix the import default was a
    # hardcoded ``"z4j-scheduler"`` which silently overrode the
    # project's chosen default for every row that didn't specify.
    project_default_scheduler = getattr(
        project, "default_scheduler_owner", "z4j-scheduler",
    )

    def _resolve_scheduler(row_scheduler: str | None) -> str:
        return row_scheduler or project_default_scheduler

    existing_id_map: dict[tuple[str, str], uuid.UUID] = {}
    if body.mode == "replace_for_source" and body.schedules:
        from sqlalchemy import select, tuple_  # noqa: PLC0415

        from z4j_brain.persistence.models import Schedule  # noqa: PLC0415

        # The pre-flight existing-row lookup is keyed by the
        # resolved (scheduler, name) tuple, the same key the
        # upsert uses. Pre-1.2.2-stored rows that were saved
        # under the legacy hardcoded default ``"z4j-scheduler"``
        # in projects whose ``default_scheduler_owner`` has been
        # flipped get a one-shot data migration (alembic 0019)
        # that rewrites them to the project's current default.
        # See migration ``2026_05_01_0019_legacy_scheduler_migrate``.
        # That migration runs at upgrade time so the lookup here
        # finds them under the new key without runtime dual-key
        # logic (which had a double-firing bug, see round-4
        # audit fix CRIT).
        batch_keys = [
            (_resolve_scheduler(row.scheduler), row.name)
            for row in body.schedules
        ]
        existing_lookup = await db_session.execute(
            select(
                Schedule.scheduler,
                Schedule.name,
                Schedule.id,
            ).where(
                Schedule.project_id == project.id,
                tuple_(Schedule.scheduler, Schedule.name).in_(
                    batch_keys,
                ),
            ),
        )
        for sched_name, name, sid in existing_lookup.all():
            existing_id_map[(sched_name, name)] = sid

    # Track which schedules survived the upsert pass so the
    # replace-for-source delete can target the absent ones.
    surviving_ids: set[uuid.UUID] = set()
    for idx, row in enumerate(body.schedules):
        try:
            # 1.2.2 audit fix MED-13: enforce per-project
            # allowed_schedulers allow-list before we touch the DB.
            # When the project sets the list, a row with an
            # unauthorised ``scheduler`` value is rejected per-row
            # (so the rest of the batch still commits).
            row_scheduler = _resolve_scheduler(row.scheduler)
            _validate_scheduler_in_allowlist(project, row_scheduler)
            # Force the resolved scheduler into the upsert payload
            # so the persisted row matches the allowlist-validated
            # value (and the surviving_ids tuple, see below).
            row_data = row.model_dump()
            row_data["scheduler"] = row_scheduler
            outcome, schedule_row = await upsert_imported_schedule(
                session=db_session,
                project_id=project.id,
                data=row_data,
            )
        except ValueError as exc:
            # Per-row validation failure (bad kind, empty name, etc.)
            # - record + continue. The whole batch still commits if
            # at least one row succeeded; the operator gets the
            # error map so they can fix the source and re-import.
            summary.failed += 1
            summary.errors[idx] = str(exc)
            # Audit fix M-6 (Apr 2026): in replace_for_source mode,
            # add the EXISTING brain row's id (if any) to
            # surviving_ids when the upsert fails. Without this, a
            # row with a syntax error was excluded from
            # surviving_ids → the replace pass deleted the
            # corresponding existing schedule. Re-importing 100
            # rows where 1 has a typo would silently delete that
            # schedule.
            if body.mode == "replace_for_source":
                # M-6 fix: in replace_for_source mode, when a row's
                # upsert raises (validation error / allow-list
                # rejection), add the EXISTING brain row's id to
                # surviving_ids so the replace pass doesn't delete
                # the corresponding row that's currently live.
                key = (_resolve_scheduler(row.scheduler), row.name)
                existing_id = existing_id_map.get(key)
                if existing_id is not None:
                    surviving_ids.add(existing_id)
            continue
        surviving_ids.add(schedule_row.id)
        if outcome == "inserted":
            summary.inserted += 1
        elif outcome == "updated":
            summary.updated += 1
        else:
            summary.unchanged += 1

    # Replace-for-source: delete any schedule with the same source
    # label that is not in this batch. The framework adapter sends
    # the COMPLETE set so absence means deletion.
    if body.mode == "replace_for_source":
        # Pick the source label: explicit ``source_filter`` wins,
        # otherwise infer from the first row in the batch.
        source_label = body.source_filter
        if source_label is None and body.schedules:
            source_label = body.schedules[0].source
        if source_label:
            deleted = await ScheduleRepository(db_session).delete_by_source_except(
                project_id=project.id,
                source=source_label,
                keep_ids=surviving_ids,
            )
            summary.deleted = deleted

    # Single audit row for the whole batch. Per-row audit would
    # spam the log when the importer is run on a big celery-beat
    # config (a 50-schedule import generating 50 audit entries
    # buries everything else for that minute).
    #
    # ``source_filter`` is included unconditionally - audit-Phase3-1
    # caught the previous version omitting it, which meant an admin
    # running ``mode="replace_for_source"`` with ``source="dashboard"``
    # could wipe every dashboard-managed schedule and leave only a
    # ``deleted=N`` row in the audit log with no breadcrumb of WHICH
    # source was affected. The forensic trail must name the label.
    audit_metadata: dict[str, object] = {
        "mode": body.mode,
        "inserted": summary.inserted,
        "updated": summary.updated,
        "unchanged": summary.unchanged,
        "deleted": summary.deleted,
        "failed": summary.failed,
    }
    if body.mode == "replace_for_source":
        # The label that scoped the delete pass. Use the resolved
        # value (which may have come from the first row's source if
        # the operator didn't set source_filter explicitly).
        audit_metadata["source_filter"] = (
            body.source_filter
            or (body.schedules[0].source if body.schedules else None)
        )
    # Audit fix HIGH-11 (1.2.2): also record the API key that
    # fired this action (if the request came in via bearer auth).
    api_key_id = resolve_api_key_id(request)
    await audit.record(
        audit_log,
        action="schedules.import",
        target_type="project",
        target_id=str(project.id),
        result="success" if summary.failed == 0 else "partial",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=api_key_id,
        source_ip=ip,
        metadata=audit_metadata,
    )
    await db_session.commit()
    return summary


# ---------------------------------------------------------------------------
# :diff endpoint - dry-run preview of what :import would do
# ---------------------------------------------------------------------------


class DiffEntry(BaseModel):
    """One row in the diff output.

    The dashboard renders these as a 4-bucket panel; the CLI's
    ``import --verify`` flag also renders them on stdout. ``current``
    carries the brain's existing values for UPDATE rows so the
    operator can see exactly what's about to change before they
    re-run reconcile without ``--dry-run``.
    """

    name: str
    scheduler: str
    # Proposed shape from the incoming batch. Always populated for
    # INSERT / UPDATE / UNCHANGED. Empty dict for DELETE because the
    # source dropped the row (there is no "proposed" value).
    proposed: dict
    # Current brain shape. Populated for UPDATE / UNCHANGED / DELETE.
    # Empty dict for INSERT because there is no current row yet.
    current: dict


class DiffSchedulesResponse(BaseModel):
    """Per-bucket classification of what ``:import`` would do.

    Mirrors the CLI ``import --verify`` helper's output. Counts in
    ``summary`` match the inserted/updated/unchanged/deleted fields
    that the real import would return so the operator can see at a
    glance whether the diff is a no-op.
    """

    inserted: list[DiffEntry]
    updated: list[DiffEntry]
    unchanged: list[DiffEntry]
    deleted: list[DiffEntry]
    summary: dict[str, int]


@router.post(
    ":diff",
    response_model=DiffSchedulesResponse,
    status_code=200,
    dependencies=[Depends(require_csrf)],
)
async def diff_schedules(
    slug: str,
    body: ImportSchedulesRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> DiffSchedulesResponse:
    """Preview what ``:import`` would do without applying it.

    Same body as ``:import``. Returns four buckets:

    - ``inserted`` - rows in the batch with no matching brain row.
    - ``updated`` - rows with a matching brain row and a different
      ``source_hash``. The ``current`` field carries the brain's
      pre-update shape.
    - ``unchanged`` - rows whose ``source_hash`` matches brain.
    - ``deleted`` - only populated when ``mode="replace_for_source"``;
      rows brain has under the resolved ``source_filter`` that the
      batch dropped.

    Authorization: project ADMIN. The diff itself is read-only but
    surfaces the same data ``:import`` would mutate, so it inherits
    the same role gate. (A separate "view diff as VIEWER" path could
    be added later if operator UX demands it.)
    """
    from sqlalchemy import select

    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.models import Schedule

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    if body.mode not in ("upsert", "replace_for_source"):
        raise ValidationError(
            f"unsupported import mode {body.mode!r}",
            details={"mode": body.mode},
        )

    # Audit fix H-3 (Apr 2026): mirror the :import endpoint's
    # source-label allow-list on :diff. Otherwise an admin could
    # use the (read-only, unaudited) diff endpoint to enumerate
    # which schedules they would wipe with a follow-up :import call,
    # bypassing the audit-trail-on-destruction protection.
    if body.mode == "replace_for_source":
        resolved_source = body.source_filter
        if resolved_source is None and body.schedules:
            resolved_source = body.schedules[0].source
        try:
            _validate_replace_for_source_label(resolved_source)
        except ValueError as exc:
            raise ValidationError(
                str(exc),
                details={
                    "mode": body.mode,
                    "source_filter": body.source_filter,
                    "resolved_source": resolved_source,
                },
            ) from exc

    inserted: list[DiffEntry] = []
    updated: list[DiffEntry] = []
    unchanged: list[DiffEntry] = []

    # Track (scheduler, name) tuples in the batch so we can compute
    # the DELETE set for replace_for_source without a second pass.
    batch_keys: set[tuple[str, str]] = set()

    # Audit fix N-3 (Apr 2026 follow-up): batch the existing-row
    # lookup. Pre-fix the diff endpoint issued one SELECT per row
    # in the batch - a 5000-row reconciler dry-run was 5000
    # sequential queries. Now: one batched SELECT per request.
    # ``tuple_(...).in_(...)`` is portable across Postgres + SQLite.
    from sqlalchemy import tuple_  # noqa: PLC0415

    # Audit fix CRIT-2 (1.2.2 second-pass): same project-default
    # resolution as the :import path, so :diff previews the same
    # row identity that :import will write.
    diff_project_default = getattr(
        project, "default_scheduler_owner", "z4j-scheduler",
    )
    diff_batch_keys = [
        (row.scheduler or diff_project_default, row.name)
        for row in body.schedules
    ]
    existing_rows: dict[tuple[str, str], Schedule] = {}
    if diff_batch_keys:
        result = await db_session.execute(
            select(Schedule).where(
                Schedule.project_id == project.id,
                tuple_(Schedule.scheduler, Schedule.name).in_(
                    diff_batch_keys,
                ),
            ),
        )
        for sched_row in result.scalars().all():
            existing_rows[(sched_row.scheduler, sched_row.name)] = sched_row

    for row in body.schedules:
        scheduler = row.scheduler or diff_project_default
        batch_keys.add((scheduler, row.name))
        existing = existing_rows.get((scheduler, row.name))
        proposed = {
            "name": row.name,
            "scheduler": scheduler,
            "engine": row.engine,
            "kind": row.kind,
            "expression": row.expression,
            "task_name": row.task_name,
            "timezone": row.timezone,
            "queue": row.queue,
            "args": row.args,
            "kwargs": row.kwargs,
            "is_enabled": row.is_enabled,
            "catch_up": row.catch_up,
            "source": row.source,
            "source_hash": row.source_hash,
        }
        if existing is None:
            inserted.append(DiffEntry(
                name=row.name, scheduler=scheduler,
                proposed=proposed, current={},
            ))
            continue
        current = {
            "name": existing.name,
            "scheduler": existing.scheduler,
            "engine": existing.engine,
            "kind": existing.kind.value if hasattr(existing.kind, "value") else str(existing.kind),
            "expression": existing.expression,
            "task_name": existing.task_name,
            "timezone": existing.timezone,
            "queue": existing.queue,
            "args": existing.args,
            "kwargs": existing.kwargs,
            "is_enabled": existing.is_enabled,
            "catch_up": getattr(existing, "catch_up", "skip") or "skip",
            "source": getattr(existing, "source", "dashboard") or "dashboard",
            "source_hash": getattr(existing, "source_hash", None),
        }
        # ``unchanged`` requires the operator's row to carry a hash
        # AND brain's row to carry the same hash. Without a hash we
        # treat the row as an UPDATE - same semantics the real
        # import takes (it always rewrites when it can't compare).
        if (
            row.source_hash
            and current["source_hash"]
            and row.source_hash == current["source_hash"]
        ):
            unchanged.append(DiffEntry(
                name=row.name, scheduler=scheduler,
                proposed=proposed, current=current,
            ))
        else:
            updated.append(DiffEntry(
                name=row.name, scheduler=scheduler,
                proposed=proposed, current=current,
            ))

    deleted: list[DiffEntry] = []
    if body.mode == "replace_for_source":
        source_label = body.source_filter
        if source_label is None and body.schedules:
            source_label = body.schedules[0].source
        if source_label:
            # Pull every schedule with this source and surface the
            # ones the batch did not name. Mirrors what the real
            # import's ``delete_by_source_except`` would remove.
            result = await db_session.execute(
                select(Schedule).where(
                    Schedule.project_id == project.id,
                    Schedule.source == source_label,
                ),
            )
            for existing in result.scalars():
                if (existing.scheduler, existing.name) in batch_keys:
                    continue
                deleted.append(DiffEntry(
                    name=existing.name,
                    scheduler=existing.scheduler,
                    proposed={},
                    current={
                        "name": existing.name,
                        "scheduler": existing.scheduler,
                        "engine": existing.engine,
                        "kind": (
                            existing.kind.value
                            if hasattr(existing.kind, "value")
                            else str(existing.kind)
                        ),
                        "expression": existing.expression,
                        "task_name": existing.task_name,
                        "source": (
                            getattr(existing, "source", "") or ""
                        ),
                        "source_hash": getattr(
                            existing, "source_hash", None,
                        ),
                    },
                ))

    return DiffSchedulesResponse(
        inserted=inserted,
        updated=updated,
        unchanged=unchanged,
        deleted=deleted,
        summary={
            "insert": len(inserted),
            "update": len(updated),
            "unchanged": len(unchanged),
            "delete": len(deleted),
            "total": len(inserted) + len(updated) + len(unchanged) + len(deleted),
        },
    )


class ResyncSchedulesResponse(BaseModel):
    """Response from the project-scoped ``:resync`` action."""

    model_config = ConfigDict(extra="forbid")
    agents_dispatched: int = Field(
        description=(
            "Number of online agents the brain dispatched a "
            "``schedule.resync`` command to. Each agent will, on "
            "receipt, drain every scheduler adapter it has registered "
            "and emit one ``schedule.snapshot`` event per adapter."
        ),
    )
    schedulers_observed: list[str] = Field(
        default_factory=list,
        description=(
            "Distinct scheduler-adapter names advertised by the "
            "online agents at dispatch time (informational - the "
            "real reconciliation arrives via the snapshot events)."
        ),
    )


@router.post(
    ":resync",
    response_model=ResyncSchedulesResponse,
    status_code=202,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def resync_schedules(
    slug: str,
    request: "Request",
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    dispatcher: "CommandDispatcher" = Depends(get_command_dispatcher),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> ResyncSchedulesResponse:
    """Force every online agent in the project to re-emit a full
    schedule inventory snapshot.

    This is the dashboard's *Sync now* button. The brain dispatches a
    ``schedule.resync`` command to each online agent that advertises
    at least one scheduler adapter. On receipt, the agent calls
    ``list_schedules()`` on every registered scheduler adapter
    (celery-beat, apscheduler, rq-scheduler, arqcron, hueyperiodic,
    taskiqscheduler) and emits one
    :class:`~z4j_core.models.event.EventKind.SCHEDULE_SNAPSHOT` event
    per adapter. The brain's event ingestor reconciles each snapshot
    against the DB (insert / update / delete-missing) scoped to
    ``(project, scheduler)``.

    Use cases:

    - First-time onboarding: existing celery-beat ``PeriodicTask``
      rows that pre-date the agent install show up immediately
      instead of waiting for the operator to edit-and-save each one.
    - Recovery: schedules created via Django admin / SQL while the
      agent was offline get reconciled the moment the operator
      clicks the button (no Django reload needed).
    - Drift checks: operator suspects the dashboard is stale →
      one click re-asserts the agent's view as the source of truth.

    Note that the agent ALSO does this on a periodic timer
    (default 15 minutes) and at every reconnect, so most operators
    never need to hit this endpoint by hand. It exists for the
    *I want it now* case.

    Returns immediately with HTTP 202. The actual snapshot events
    arrive asynchronously and the dashboard's existing schedule
    list query will reflect them on the next refetch.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        AgentRepository,
        CommandRepository,
    )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    # Admin role: resync may DELETE schedule rows from the DB if the
    # agent reports that they no longer exist on its side. That's a
    # destructive write at the operator's discretion - same gate as
    # the existing import / reconcile-diff path.
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    online_agents = await AgentRepository(
        db_session,
    ).list_online_for_project(project.id)
    eligible = [
        agent for agent in online_agents
        if agent.scheduler_adapters
    ]

    if not eligible:
        # Audit the failed attempt so an operator clicking the
        # button repeatedly leaves a trail.
        await audit.record(
            audit_log,
            action="schedule.resync",
            target_type="project",
            target_id=slug,
            result="failure",
            outcome="deny",
            user_id=user.id,
            project_id=project.id,
            api_key_id=resolve_api_key_id(request),
            source_ip=ip,
            metadata={
                "reason": (
                    "no_online_agent_with_scheduler"
                    if online_agents
                    else "no_online_agent"
                ),
                "online_agent_count": len(online_agents),
            },
        )
        await db_session.commit()
        raise NotFoundError(
            (
                "no online agent advertises a scheduler adapter; "
                "start an agent that has z4j-celerybeat / "
                "z4j-apscheduler / z4j-rqscheduler / z4j-arqcron / "
                "z4j-hueyperiodic / z4j-taskiqscheduler installed"
            ),
            details={
                "online_agent_count": len(online_agents),
                "reason": (
                    "no_online_agent_with_scheduler"
                    if online_agents
                    else "no_online_agent"
                ),
            },
        )

    schedulers_seen: set[str] = set()
    commands_repo = CommandRepository(db_session)
    for agent in eligible:
        for adapter_name in agent.scheduler_adapters or ():
            schedulers_seen.add(str(adapter_name))
        await dispatcher.issue(
            commands=commands_repo,
            audit_log=audit_log,
            project_id=project.id,
            agent_id=agent.id,
            action="schedule.resync",
            target_type="project",
            target_id=slug,
            payload={
                # Empty payload: the agent drains EVERY scheduler
                # adapter it has registered. We could narrow to a
                # specific adapter via payload["scheduler"] in a
                # future patch but the V1 surface is "all of them".
            },
            issued_by=user.id,
            ip=ip,
            user_agent=None,
        )

    await audit.record(
        audit_log,
        action="schedule.resync",
        target_type="project",
        target_id=slug,
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={
            "agents_dispatched": len(eligible),
            "schedulers_observed": sorted(schedulers_seen),
        },
    )
    await db_session.commit()

    return ResyncSchedulesResponse(
        agents_dispatched=len(eligible),
        schedulers_observed=sorted(schedulers_seen),
    )


__all__ = [
    "DiffEntry",
    "DiffSchedulesResponse",
    "ImportSchedulesRequest",
    "ImportSchedulesResponse",
    "ImportedScheduleIn",
    "ResyncSchedulesResponse",
    "SchedulePublic",
    "router",
]
