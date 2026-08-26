"""Versioned durable bulk-retry request resource."""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError

from z4j_brain.api.commands import (
    CLIENT_ALLOWED_BULK_FILTER_KEYS,
    KNOWN_ENGINES,
    _parse_filter_datetime,
)
from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    require_csrf,
)
from z4j_brain.domain.bulk_retry import (
    CURRENT_CANONICALIZER_VERSION,
    CanonicalizerUnavailableError,
    PayloadTooLargeError,
    SelectionLimitExceededError,
    UnsupportedRetryEngineError,
    build_sealed_plan,
    canonicalize_request,
)
from z4j_brain.domain.ip_rate_limit import require_bulk_action_throttle
from z4j_brain.persistence.enums import ProjectRole, TaskPriority, TaskState
from z4j_brain.persistence.models import BulkRetryControlState

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.bulk_retry import CanonicalRequest, PlannedChild
    from z4j_brain.persistence.models import BulkRetryRequest, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.persistence.repositories.bulk_retry_requests import (
        BulkRetrySnapshot,
    )
    from z4j_brain.settings import Settings


router = APIRouter(
    prefix="/projects/{slug}/bulk-retry-requests",
    tags=["bulk-retry-requests"],
)

DURABLE_ALLOWED_BULK_FILTER_KEYS = CLIENT_ALLOWED_BULK_FILTER_KEYS | {
    "priority",
    "search",
}


def _validate_filter_keys(raw_filter: dict[str, Any]) -> None:
    unknown = sorted(set(raw_filter) - DURABLE_ALLOWED_BULK_FILTER_KEYS)
    if unknown:
        raise ValueError(
            "bulk-retry filter accepts selection keys only; rejected: " + ", ".join(unknown)
        )


def _validate_state_alias(raw_filter: dict[str, Any]) -> None:
    state = raw_filter.get("state")
    status = raw_filter.get("status")
    if state is not None and status is not None and state != status:
        raise ValueError("state and status aliases disagree")
    state_value = state if state is not None else status
    if state_value is None:
        return
    try:
        TaskState(str(state_value))
    except ValueError as exc:
        raise ValueError(f"unknown task state {state_value!r}") from exc


def _validate_text_filters(raw_filter: dict[str, Any]) -> None:
    for key in ("engine", "queue", "name", "search"):
        if key in raw_filter and not isinstance(raw_filter[key], str):
            raise ValueError(f"filter {key!r} must be a string")
        if isinstance(raw_filter.get(key), str) and len(raw_filter[key]) > 200:
            raise ValueError(f"filter {key!r} must be at most 200 characters")
    engine = raw_filter.get("engine")
    if engine not in (None, "") and engine not in KNOWN_ENGINES:
        raise ValueError(f"engine must be one of {sorted(KNOWN_ENGINES)}")


def _validate_priority_filter(raw_filter: dict[str, Any]) -> None:
    priority = raw_filter.get("priority")
    if priority is None:
        return
    if not isinstance(priority, list) or not priority:
        raise ValueError("filter 'priority' must be a non-empty list")
    if any(not isinstance(value, str) for value in priority):
        raise ValueError("filter 'priority' values must be strings")
    try:
        {TaskPriority(value) for value in priority}
    except ValueError as exc:
        raise ValueError("filter 'priority' contains an unknown priority") from exc
    if "task_ids" in raw_filter:
        raise ValueError("priority cannot be combined with explicit task_ids")


def _validate_explicit_ids(
    raw_filter: dict[str, Any],
    *,
    maximum: int,
) -> None:
    if "task_ids" not in raw_filter:
        return
    ids = raw_filter["task_ids"]
    if (
        not isinstance(ids, list)
        or not ids
        or any(not isinstance(task_id, str) or not task_id or len(task_id) > 200 for task_id in ids)
    ):
        raise ValueError("task_ids must be a non-empty list of strings up to 200 characters")
    if raw_filter.get("engine") not in KNOWN_ENGINES:
        raise ValueError("explicit task_ids require one known engine")
    if len(ids) > maximum:
        raise ValueError("task_ids count exceeds max")


def _validate_time_bounds(raw_filter: dict[str, Any]) -> None:
    for key in ("since", "until"):
        if key in raw_filter and _parse_filter_datetime(raw_filter[key]) is None:
            raise ValueError(f"filter {key!r} is not a valid datetime")


class BulkRetryRequestCreate(BaseModel):
    """A client-keyed destructive operation.

    ``agent_id`` is optional.  When absent, each sealed child binds at its send
    edge to a compatible session in this project.
    """

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=200)
    agent_id: uuid.UUID | None = None
    filter: dict[str, Any] = Field(default_factory=dict)
    max: int = Field(default=1000, ge=1, le=10_000)

    @field_validator("idempotency_key")
    @classmethod
    def _nonblank_raw_key(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("idempotency_key must not be blank")
        return value

    def validate_selection(self) -> None:
        """Validate selection semantics after auth so refusals are auditable."""

        _validate_filter_keys(self.filter)
        _validate_state_alias(self.filter)
        _validate_text_filters(self.filter)
        _validate_priority_filter(self.filter)
        _validate_explicit_ids(self.filter, maximum=self.max)
        _validate_time_bounds(self.filter)
        # Invoke the actual current canonicalizer during validation so accepted
        # input cannot later fail after authorization/expansion.
        canonicalize_request(
            self.model_dump(
                exclude={"idempotency_key"},
                exclude_unset=True,
                mode="json",
            )
        )


class BulkRetryCountsPublic(BaseModel):
    total: int
    pending: int
    claimed: int
    unobserved: int
    succeeded: int
    failed: int
    unknown: int


class BulkRetryRequestPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    idempotency_key: str
    status: str
    control_state: str
    canonicalizer_version: int
    canonical_digest: str
    plan_digest: str
    target_agent_id: uuid.UUID | None
    counts: BulkRetryCountsPublic
    created_at: datetime
    sealed_at: datetime
    deadline_at: datetime
    last_progress_at: datetime | None


def _public_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _public(snapshot: BulkRetrySnapshot) -> BulkRetryRequestPublic:
    parent = snapshot.parent
    counts = snapshot.counts
    return BulkRetryRequestPublic(
        id=parent.id,
        project_id=parent.project_id,
        idempotency_key=parent.idempotency_key,
        status=snapshot.status,
        control_state=parent.control_state,
        canonicalizer_version=parent.canonicalizer_version,
        canonical_digest=parent.canonical_digest,
        plan_digest=parent.plan_digest,
        target_agent_id=parent.target_agent_id,
        counts=BulkRetryCountsPublic(
            total=counts.total,
            pending=counts.pending,
            claimed=counts.claimed,
            unobserved=counts.unobserved,
            succeeded=counts.succeeded,
            failed=counts.failed,
            unknown=counts.unknown,
        ),
        created_at=_public_utc(parent.created_at),
        sealed_at=_public_utc(parent.sealed_at),
        deadline_at=_public_utc(parent.deadline_at),
        last_progress_at=(
            _public_utc(parent.last_progress_at) if parent.last_progress_at is not None else None
        ),
    )


def _location(slug: str, request_id: uuid.UUID) -> str:
    return f"/api/v1/projects/{slug}/bulk-retry-requests/{request_id}"


def _raw_identity(body: BulkRetryRequestCreate) -> dict[str, Any]:
    return body.model_dump(
        exclude={"idempotency_key"},
        exclude_unset=True,
        mode="json",
    )


def _compare_replay(
    parent: BulkRetryRequest,
    *,
    raw_identity: dict[str, Any],
) -> None:
    try:
        replay = canonicalize_request(
            raw_identity,
            version=parent.canonicalizer_version,
        )
    except CanonicalizerUnavailableError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stored canonicalizer unavailable; refusing unsafe replay",
                "canonicalizer_version": parent.canonicalizer_version,
            },
        ) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "idempotency_key already belongs to a different request",
                "idempotency_key": parent.idempotency_key,
            },
        ) from exc
    if not (
        hmac.compare_digest(replay.digest, parent.canonical_digest)
        and hmac.compare_digest(replay.exact_bytes, bytes(parent.canonical_request))
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "idempotency_key already belongs to a different request",
                "idempotency_key": parent.idempotency_key,
            },
        )


async def _authorize_project(
    *,
    slug: str,
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
) -> Any:
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.OPERATOR,
    )
    return project


async def _commit_refusal_audit(
    *,
    audit_service: AuditService,
    audit_log: AuditLogRepository,
    db_session: AsyncSession,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    ip: str,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    await audit_service.record(
        audit_log,
        action="bulk_retry_request.refused",
        target_type="bulk_retry_request",
        result="failure",
        outcome="deny",
        user_id=user_id,
        project_id=project_id,
        source_ip=ip,
        metadata={"reason": reason, **(metadata or {})},
    )
    # A refusal must survive the HTTP error just like an accepted request's
    # issuance row survives its response.
    await db_session.commit()


async def _resolve_sealed_plan(
    *,
    project_id: uuid.UUID,
    body: BulkRetryRequestCreate,
    raw_identity: dict[str, Any],
    db_session: AsyncSession,
    settings: Settings,
) -> tuple[CanonicalRequest, list[PlannedChild], str]:
    from z4j_brain.persistence.repositories import AgentRepository, TaskRepository

    if body.agent_id is not None:
        agent = await AgentRepository(db_session).get_live(body.agent_id)
        if agent is None or agent.project_id != project_id:
            raise HTTPException(status_code=404, detail="agent not found in this project")

    canonical = canonicalize_request(
        raw_identity,
        version=CURRENT_CANONICALIZER_VERSION,
    )
    effective_filter = dict(canonical.effective["filter"])
    task_repository = TaskRepository(db_session)
    explicit_ids = effective_filter.get("task_ids")
    if explicit_ids is not None:
        engine = str(effective_filter["engine"])
        tasks = await task_repository.list_by_engine_task_ids(
            project_id=project_id,
            engine=engine,
            task_ids=list(explicit_ids),
        )
        if len(tasks) != len(explicit_ids):
            resolved = {str(task.task_id) for task in tasks}
            missing = [task_id for task_id in explicit_ids if task_id not in resolved]
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "every explicit task must belong to this project and engine",
                    "missing_task_ids": missing,
                },
            )
    else:
        tasks = await task_repository.list_for_project(
            project_id=project_id,
            state=TaskState(effective_filter["state"]),
            priority=[TaskPriority(value) for value in effective_filter.get("priority", [])]
            or None,
            queue=effective_filter.get("queue"),
            name_substring=effective_filter.get("name"),
            search_query=effective_filter.get("search"),
            since=_parse_filter_datetime(effective_filter.get("since")),
            until=_parse_filter_datetime(effective_filter.get("until")),
            engine=effective_filter.get("engine"),
            # Read one extra row so ``max`` is an acceptance ceiling, never a
            # silent truncation boundary.  A durable request advertised as
            # "all matching" is either exact or refused.
            limit=body.max + 1,
        )
    try:
        children, plan_digest = build_sealed_plan(
            tasks,
            effective_filter=effective_filter,
            maximum=body.max,
            max_frame_bytes=settings.effective_ws_max_frame_bytes,
        )
    except SelectionLimitExceededError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "matching task count exceeds max",
                "max": body.max,
                "matched_at_least": len(tasks),
            },
        ) from exc
    except PayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except UnsupportedRetryEngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return canonical, children, plan_digest


@router.post(
    "",
    response_model=BulkRetryRequestPublic,
    status_code=202,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def create_bulk_retry_request(
    slug: str,
    body: BulkRetryRequestCreate,
    response: Response,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> BulkRetryRequestPublic:
    """Create or exactly replay one sealed durable request."""

    from z4j_brain.persistence.repositories import (
        BulkRetryRequestRepository,
    )

    project = await _authorize_project(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    project_id = project.id
    user_id = user.id
    raw_identity = _raw_identity(body)
    repository = BulkRetryRequestRepository(db_session)

    # Raw-key lookup precedes current-version validation. An exact replay is
    # interpreted by the historical canonicalizer stored on its parent, so a
    # future normalization/default change cannot reject a formerly valid body.
    existing = await repository.get_by_key(
        project_id=project_id,
        idempotency_key=body.idempotency_key,
    )
    if existing is not None:
        _compare_replay(existing, raw_identity=raw_identity)
        snapshot = await repository.snapshot(existing)
        response.headers["Location"] = _location(slug, existing.id)
        if snapshot.status != "in_progress":
            response.status_code = 200
        return _public(snapshot)

    try:
        body.validate_selection()
    except (TypeError, ValueError) as exc:
        rejected_keys = sorted(set(body.filter) - DURABLE_ALLOWED_BULK_FILTER_KEYS)
        await _commit_refusal_audit(
            audit_service=audit_service,
            audit_log=audit_log,
            db_session=db_session,
            user_id=user_id,
            project_id=project_id,
            ip=ip,
            reason=str(exc),
            metadata={
                "rejected_client_supplied_filter_keys": rejected_keys,
            },
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        canonical, planned_children, plan_digest = await _resolve_sealed_plan(
            project_id=project_id,
            body=body,
            raw_identity=raw_identity,
            db_session=db_session,
            settings=settings,
        )
    except HTTPException as exc:
        if exc.status_code in {400, 413}:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            await _commit_refusal_audit(
                audit_service=audit_service,
                audit_log=audit_log,
                db_session=db_session,
                user_id=user_id,
                project_id=project_id,
                ip=ip,
                reason=str(exc.detail),
                metadata={
                    "missing_task_ids": detail.get("missing_task_ids", []),
                },
            )
        raise

    # End the read transaction before SQLite's BEGIN IMMEDIATE.  IDs and plain
    # canonical data above are detached from ORM liveness.
    await db_session.rollback()
    repository = BulkRetryRequestRepository(db_session)
    await repository.begin_immediate_if_sqlite()
    parent_timeout = int(settings.bulk_retry_parent_timeout_seconds)
    try:
        parent = await repository.insert_sealed(
            project_id=project_id,
            issued_by=user_id,
            idempotency_key=body.idempotency_key,
            canonical=canonical,
            target_agent_id=body.agent_id,
            planned_children=planned_children,
            plan_digest=plan_digest,
            max_in_flight=int(settings.bulk_retry_max_in_flight),
            deadline_at=datetime.now(UTC) + timedelta(seconds=parent_timeout),
            source_ip=ip,
        )
        await audit_service.record(
            audit_log,
            action="bulk_retry_request.sealed",
            target_type="bulk_retry_request",
            target_id=str(parent.id),
            result="success",
            outcome="allow",
            user_id=user_id,
            project_id=project_id,
            source_ip=ip,
            metadata={
                "idempotency_key": body.idempotency_key,
                "canonical_digest": canonical.digest,
                "plan_digest": plan_digest,
                "children": len(planned_children),
            },
        )
        await db_session.commit()
    except IntegrityError:
        await db_session.rollback()
        repository = BulkRetryRequestRepository(db_session)
        winner = await repository.get_by_key(
            project_id=project_id,
            idempotency_key=body.idempotency_key,
        )
        if winner is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": (
                        "idempotency_key conflicts with a legacy command or "
                        "an incomplete reservation"
                    )
                },
            ) from None
        _compare_replay(winner, raw_identity=raw_identity)
        parent = winner

    snapshot = await BulkRetryRequestRepository(db_session).snapshot(parent)
    response.headers["Location"] = _location(slug, parent.id)
    if snapshot.status != "in_progress":
        response.status_code = 200
    return _public(snapshot)


async def _get_authorized_snapshot(
    *,
    slug: str,
    request_id: uuid.UUID,
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
    db_session: AsyncSession,
) -> tuple[Any, BulkRetrySnapshot]:
    from z4j_brain.persistence.repositories import BulkRetryRequestRepository

    project = await _authorize_project(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    repository = BulkRetryRequestRepository(db_session)
    parent = await repository.get_for_project(
        project_id=project.id,
        request_id=request_id,
    )
    if parent is None:
        raise HTTPException(status_code=404, detail="bulk retry request not found")
    return project, await repository.snapshot(parent)


@router.get("/{request_id}", response_model=BulkRetryRequestPublic)
async def get_bulk_retry_request(
    slug: str,
    request_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> BulkRetryRequestPublic:
    _, snapshot = await _get_authorized_snapshot(
        slug=slug,
        request_id=request_id,
        user=user,
        memberships=memberships,
        projects=projects,
        db_session=db_session,
    )
    return _public(snapshot)


async def _change_control(
    *,
    slug: str,
    request_id: uuid.UUID,
    state: BulkRetryControlState,
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
    audit_service: AuditService,
    db_session: AsyncSession,
    settings: Settings,
    ip: str,
) -> BulkRetryRequestPublic:
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        BulkRetryRequestRepository,
    )

    project = await _authorize_project(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    repository = BulkRetryRequestRepository(db_session)
    parent = await repository.set_control_state(
        project_id=project.id,
        request_id=request_id,
        control_state=state,
        resume_window_seconds=(
            int(settings.bulk_retry_parent_timeout_seconds)
            if state == BulkRetryControlState.RUNNING
            else None
        ),
    )
    if parent is None:
        raise HTTPException(status_code=404, detail="bulk retry request not found")
    await audit_service.record(
        AuditLogRepository(db_session),
        action=(
            "bulk_retry_request.resumed"
            if state == BulkRetryControlState.RUNNING
            else "bulk_retry_request.paused"
        ),
        target_type="bulk_retry_request",
        target_id=str(request_id),
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
        metadata={},
    )
    await db_session.commit()
    return _public(await repository.snapshot(parent))


@router.post(
    "/{request_id}/pause",
    response_model=BulkRetryRequestPublic,
    dependencies=[Depends(require_csrf)],
)
async def pause_bulk_retry_request(
    slug: str,
    request_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> BulkRetryRequestPublic:
    return await _change_control(
        slug=slug,
        request_id=request_id,
        state=BulkRetryControlState.PAUSED,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_service=audit_service,
        db_session=db_session,
        settings=settings,
        ip=ip,
    )


@router.post(
    "/{request_id}/resume",
    response_model=BulkRetryRequestPublic,
    dependencies=[Depends(require_csrf)],
)
async def resume_bulk_retry_request(
    slug: str,
    request_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> BulkRetryRequestPublic:
    return await _change_control(
        slug=slug,
        request_id=request_id,
        state=BulkRetryControlState.RUNNING,
        user=user,
        memberships=memberships,
        projects=projects,
        audit_service=audit_service,
        db_session=db_session,
        settings=settings,
        ip=ip,
    )


__all__ = [
    "BulkRetryCountsPublic",
    "BulkRetryRequestCreate",
    "BulkRetryRequestPublic",
    "create_bulk_retry_request",
    "router",
]
