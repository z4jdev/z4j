"""``/api/v1/projects/{slug}/automation/rules`` REST router.

CRUD for the cross-engine automation rule engine, with the governance
gates that make destructive automation safe to hand an operator:

- **Grammar validation at write time**: the trigger must be known, the
  conditions must pass the FIXED evaluator grammar, and every action must
  be a currently-executable type. A bad rule is a 422, never a
  create-then-silently-no-op.
- **RBAC**: reads need VIEWER; a rule whose actions only notify needs
  OPERATOR; a rule carrying any DESTRUCTIVE action (retry / cancel / ...)
  needs ADMIN.
- **Fresh MFA step-up**: creating / updating / enabling a destructive
  rule from a browser session additionally requires a recent MFA verify
  (bearer API keys are their own factor and are exempt, matching
  ``require_fresh_mfa``).
- **Every mutation is audited** through the one HMAC-chained audit log.

The project-level ``/automation/settings`` endpoint exposes a kill switch
that disables all rule execution for the project independently of each
rule's own ``is_enabled`` state."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.exc import IntegrityError

from z4j_brain.api.deps import (
    enforce_fresh_mfa,
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_optional_session,
    get_project_repo,
    get_session,
    get_settings,
    require_csrf,
    resolve_api_key_id,
)
from z4j_brain.domain.automation import (
    DISPATCHED_TRIGGERS,
    TRIGGER_TYPES,
    actions_are_destructive,
    validate_actions,
    validate_conditions,
)
from z4j_brain.domain.policy_engine import PolicyEngine
from z4j_brain.errors import ConflictError, NotFoundError, ValidationError
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import AutomationRule
from z4j_brain.persistence.repositories.automation_rule import (
    AutomationRuleRepository,
)

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings

router = APIRouter(prefix="/projects/{slug}/automation/rules", tags=["automation"])
#: Project-level automation settings (the kill switch) live one level up
#: from the per-rule CRUD so the path is ``/automation/settings``.
settings_router = APIRouter(prefix="/projects/{slug}/automation", tags=["automation"])

#: Ceiling on the serialised conditions+actions blob so a rule can't be
#: used to stuff megabytes of JSON into the row (and into every audit
#: metadata copy). The grammar validators already bound individual value
#: shapes; this bounds the aggregate.
_MAX_SPEC_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RulePublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    is_enabled: bool
    dry_run: bool
    trigger: str
    conditions: dict[str, Any]
    actions: list[Any]
    max_executions_per_window: int
    window_seconds: int
    cb_tripped: bool
    cb_execution_count: int
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class RuleListResponse(BaseModel):
    items: list[RulePublic]


class AutomationSettings(BaseModel):
    #: Per-project kill switch. When False, the rule engine loads no
    #: rules for the project so nothing fires, regardless of each rule's
    #: own ``is_enabled`` state.
    automation_enabled: bool


class RuleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    trigger: str = Field(min_length=1, max_length=64)
    conditions: dict[str, Any] = Field(default_factory=dict)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    #: New rules default to dry-run: the rule evaluates + audits what it
    #: WOULD do but executes nothing until an operator flips it live.
    dry_run: bool = True
    is_enabled: bool = True
    max_executions_per_window: int = Field(default=100, ge=1, le=100_000)
    window_seconds: int = Field(default=3600, ge=1, le=604_800)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


class RuleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    trigger: str | None = Field(default=None, min_length=1, max_length=64)
    conditions: dict[str, Any] | None = None
    actions: list[dict[str, Any]] | None = None
    dry_run: bool | None = None
    is_enabled: bool | None = None
    max_executions_per_window: int | None = Field(
        default=None,
        ge=1,
        le=100_000,
    )
    window_seconds: int | None = Field(default=None, ge=1, le=604_800)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @model_validator(mode="after")
    def _reject_explicit_null(self) -> RuleUpdateRequest:
        # Every updatable field maps to a NOT NULL column, so an explicit
        # JSON null is never valid; reject it as a 422 here instead of
        # letting it reach the DB as an IntegrityError -> 500.
        for field_name in self.model_fields_set:
            if getattr(self, field_name) is None:
                raise ValueError(f"field '{field_name}' may not be null")
        return self


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _payload(rule: AutomationRule) -> RulePublic:
    return RulePublic(
        id=rule.id,
        project_id=rule.project_id,
        name=rule.name,
        is_enabled=rule.is_enabled,
        dry_run=rule.dry_run,
        trigger=rule.trigger,
        conditions=dict(rule.conditions or {}),
        actions=list(rule.actions or []),
        max_executions_per_window=rule.max_executions_per_window,
        window_seconds=rule.window_seconds,
        cb_tripped=rule.cb_tripped,
        cb_execution_count=rule.cb_execution_count,
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def _action_types(actions: Any) -> list[str | None]:
    if not isinstance(actions, list):
        return []
    return [a.get("type") for a in actions if isinstance(a, dict)]


def _assert_spec_size(conditions: Any, actions: Any) -> None:
    try:
        size = len(json.dumps({"c": conditions, "a": actions}).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "conditions/actions are not JSON-serialisable",
            details={"reason": str(exc)},
        ) from exc
    if size > _MAX_SPEC_BYTES:
        raise ValidationError(
            f"rule spec {size} bytes exceeds {_MAX_SPEC_BYTES // 1024} KiB cap",
            details={"bytes": size},
        )


def _validate_rule_spec(trigger: str, conditions: Any, actions: Any) -> None:
    """422 if the trigger / conditions / actions violate the grammar."""
    errors: list[str] = []
    if trigger not in TRIGGER_TYPES:
        errors.append(
            f"unknown trigger {trigger!r} (known: {sorted(TRIGGER_TYPES)})",
        )
    elif trigger not in DISPATCHED_TRIGGERS:
        errors.append(
            f"trigger {trigger!r} is grammar-valid but not yet dispatched by "
            f"any emit site, so a rule on it would never fire "
            f"(dispatched: {sorted(DISPATCHED_TRIGGERS)})",
        )
    errors.extend(validate_conditions(conditions))
    errors.extend(validate_actions(actions))
    if errors:
        raise ValidationError(
            "invalid automation rule",
            details={"errors": errors},
        )
    _assert_spec_size(conditions, actions)


async def _authorize_write(
    policy: PolicyEngine,
    memberships: MembershipRepository,
    *,
    user: User,
    project: Any,
    resolved: tuple[SessionRow, User] | None,
    settings: Settings,
    destructive: bool,
    require_mfa: bool = True,
) -> None:
    """RBAC + (conditional) fresh-MFA gate for a rule mutation.

    A destructive rule needs ADMIN; anything else needs OPERATOR. For a
    destructive mutation from a browser session we additionally require a
    recent MFA verify; bearer callers (``resolved is None``) are exempt,
    matching ``require_fresh_mfa``.
    """
    min_role = ProjectRole.ADMIN if destructive else ProjectRole.OPERATOR
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=min_role,
    )
    if destructive and require_mfa and resolved is not None:
        enforce_fresh_mfa(
            user=user,
            session_row=resolved[0],
            settings=settings,
        )


async def _load_rule(
    repo: AutomationRuleRepository,
    *,
    rule_id: uuid.UUID,
    project_id: uuid.UUID,
) -> AutomationRule:
    rule = await repo.get(rule_id)
    if rule is None or rule.project_id != project_id:
        raise NotFoundError(
            "automation rule not found",
            details={"rule_id": str(rule_id)},
        )
    return rule


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=RuleListResponse)
async def list_rules(
    slug: str,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: Any = Depends(get_session),
) -> RuleListResponse:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    rows = await AutomationRuleRepository(db_session).list_for_project(
        project_id=project.id,
    )
    return RuleListResponse(items=[_payload(r) for r in rows])


@router.get("/{rule_id}", response_model=RulePublic)
async def get_rule(
    slug: str,
    rule_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: Any = Depends(get_session),
) -> RulePublic:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    repo = AutomationRuleRepository(db_session)
    rule = await _load_rule(repo, rule_id=rule_id, project_id=project.id)
    return _payload(rule)


# ---------------------------------------------------------------------------
# Write endpoints
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=RulePublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_rule(
    slug: str,
    body: RuleCreateRequest,
    request: Request,
    user: User = Depends(get_current_user),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit: AuditService = Depends(get_audit_service),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    db_session: Any = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> RulePublic:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    # Prove membership BEFORE any grammar validation so a non-member can
    # never use a 422 as a cross-tenant project-existence oracle (they get
    # the same 404 as any unknown slug).
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    _validate_rule_spec(body.trigger, body.conditions, body.actions)
    destructive = actions_are_destructive(body.actions)
    await _authorize_write(
        policy,
        memberships,
        user=user,
        project=project,
        resolved=resolved,
        settings=settings,
        destructive=destructive,
    )

    repo = AutomationRuleRepository(db_session)
    if await repo.get_by_project_and_name(project_id=project.id, name=body.name):
        raise ConflictError(
            "an automation rule with this name already exists",
            details={"name": body.name},
        )
    rule = AutomationRule(
        project_id=project.id,
        name=body.name,
        trigger=body.trigger,
        conditions=body.conditions,
        actions=body.actions,
        dry_run=body.dry_run,
        is_enabled=body.is_enabled,
        max_executions_per_window=body.max_executions_per_window,
        window_seconds=body.window_seconds,
        created_by=user.id,
    )
    try:
        await repo.add(rule)
    except IntegrityError as exc:
        # Lost the unique-(project, name) race between the pre-check and
        # the INSERT: 409, not the DB's 500.
        await db_session.rollback()
        raise ConflictError(
            "an automation rule with this name already exists",
            details={"name": body.name},
        ) from exc
    await audit.record(
        audit_log,
        action="automation.rule.created",
        target_type="automation_rule",
        target_id=str(rule.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={
            "name": rule.name,
            "trigger": rule.trigger,
            "destructive": destructive,
            "dry_run": rule.dry_run,
            "actions": _action_types(body.actions),
        },
    )
    await db_session.commit()
    return _payload(rule)


@router.patch(
    "/{rule_id}",
    response_model=RulePublic,
    dependencies=[Depends(require_csrf)],
)
async def update_rule(
    slug: str,
    rule_id: uuid.UUID,
    body: RuleUpdateRequest,
    request: Request,
    user: User = Depends(get_current_user),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit: AuditService = Depends(get_audit_service),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    db_session: Any = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> RulePublic:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    # Prove membership before loading the rule so a non-member cannot
    # probe rule_ids as an existence oracle (same 404 as an unknown slug).
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    repo = AutomationRuleRepository(db_session)
    # Lock the authoritative configuration before deriving the old/new RBAC
    # union. The same lock is retained through the DB-side revision increment,
    # so a concurrent edit cannot change the action class after authorization.
    rule = await repo.get_for_update(rule_id, project_id=project.id)
    if rule is None:
        raise NotFoundError(
            "automation rule not found",
            details={"rule_id": str(rule_id)},
        )

    data = body.model_dump(exclude_unset=True)
    eff_trigger = data.get("trigger", rule.trigger)
    eff_conditions = data.get("conditions", rule.conditions)
    eff_actions = data.get("actions", rule.actions)
    _validate_rule_spec(eff_trigger, eff_conditions, eff_actions)

    # Gate on the union of old + new: escalating a notify rule into a
    # destructive one, OR touching an already-destructive rule, both
    # require the stricter ADMIN + fresh-MFA gate.
    destructive = actions_are_destructive(eff_actions) or actions_are_destructive(
        rule.actions,
    )
    await _authorize_write(
        policy,
        memberships,
        user=user,
        project=project,
        resolved=resolved,
        settings=settings,
        destructive=destructive,
    )

    if "name" in data and data["name"] != rule.name:
        clash = await repo.get_by_project_and_name(
            project_id=project.id,
            name=data["name"],
        )
        if clash is not None and clash.id != rule.id:
            raise ConflictError(
                "an automation rule with this name already exists",
                details={"name": data["name"]},
            )

    try:
        await repo.update_configuration(rule, data)
    except IntegrityError as exc:
        # Lost the unique-(project, name) rename race: 409, not 500.
        await db_session.rollback()
        raise ConflictError(
            "an automation rule with this name already exists",
            details={"name": data.get("name")},
        ) from exc

    await audit.record(
        audit_log,
        action="automation.rule.updated",
        target_type="automation_rule",
        target_id=str(rule.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={
            "name": rule.name,
            "destructive": destructive,
            "changed": sorted(data.keys()),
        },
    )
    await db_session.commit()
    # ``updated_at`` is server-recomputed (onupdate=now()) so it is
    # expired after the UPDATE; reload it under an awaited call before
    # serialising (a bare attribute access would trigger implicit IO
    # outside the async greenlet).
    await db_session.refresh(rule)
    return _payload(rule)


@router.delete(
    "/{rule_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_rule(
    slug: str,
    rule_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit: AuditService = Depends(get_audit_service),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    db_session: Any = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    repo = AutomationRuleRepository(db_session)
    # Lock the exact configuration whose action class controls authorization.
    # Without this, an OPERATOR could read a notify-only rule while an ADMIN
    # concurrently turns it destructive, then delete the committed
    # destructive rule using the stale lower privilege decision.
    rule = await repo.get_for_update(rule_id, project_id=project.id)
    if rule is None:
        raise NotFoundError(
            "automation rule not found",
            details={"rule_id": str(rule_id)},
        )

    # Deleting a destructive rule needs ADMIN; removal reduces blast
    # radius, so no MFA step-up here.
    min_role = ProjectRole.ADMIN if actions_are_destructive(rule.actions) else ProjectRole.OPERATOR
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=min_role,
    )

    await repo.delete(rule)
    await audit.record(
        audit_log,
        action="automation.rule.deleted",
        target_type="automation_rule",
        target_id=str(rule_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={"name": rule.name, "trigger": rule.trigger},
    )
    await db_session.commit()


@router.post(
    "/{rule_id}/reset-circuit",
    response_model=RulePublic,
    dependencies=[Depends(require_csrf)],
)
async def reset_circuit(
    slug: str,
    rule_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit: AuditService = Depends(get_audit_service),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    db_session: Any = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> RulePublic:
    """Clear a tripped circuit breaker so the rule can fire again.

    Re-arming a destructive rule is itself a destructive-grade action
    (it restores the rule's ability to issue commands), so it carries the
    same ADMIN + fresh-MFA gate as creating one.
    """
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    repo = AutomationRuleRepository(db_session)
    # Lock before inspecting the action set: reset re-arms the rule, so a
    # concurrent edit must not turn a notify-only rule destructive after the
    # authorization decision but before its breaker history is cleared.
    rule = await repo.get_for_update(rule_id, project_id=project.id)
    if rule is None:
        raise NotFoundError(
            "automation rule not found",
            details={"rule_id": str(rule_id)},
        )

    await _authorize_write(
        policy,
        memberships,
        user=user,
        project=project,
        resolved=resolved,
        settings=settings,
        destructive=actions_are_destructive(rule.actions),
    )

    await repo.reset_circuit(rule)

    await audit.record(
        audit_log,
        action="automation.rule.circuit_reset",
        target_type="automation_rule",
        target_id=str(rule.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={"name": rule.name},
    )
    await db_session.commit()
    # See update_rule: reload the server-recomputed ``updated_at`` under
    # an awaited call before serialising.
    await db_session.refresh(rule)
    return _payload(rule)


# ---------------------------------------------------------------------------
# Project-level automation kill switch
# ---------------------------------------------------------------------------


@settings_router.get("/settings", response_model=AutomationSettings)
async def get_automation_settings(
    slug: str,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
) -> AutomationSettings:
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )
    return AutomationSettings(automation_enabled=project.automation_enabled)


@settings_router.put(
    "/settings",
    response_model=AutomationSettings,
    dependencies=[Depends(require_csrf)],
)
async def set_automation_settings(
    slug: str,
    body: AutomationSettings,
    request: Request,
    user: User = Depends(get_current_user),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit: AuditService = Depends(get_audit_service),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    db_session: Any = Depends(get_session),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> AutomationSettings:
    """Flip the whole-project automation kill switch (ADMIN only).

    Disabling stops ALL rules for the project from firing at the single
    executor choke point; individual rule ``is_enabled`` state is left
    untouched, so re-enabling restores the prior configuration exactly.
    """
    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.ADMIN,
    )
    # Re-enabling automation re-arms every destructive rule in the project
    # at once, so it carries the same fresh-MFA step-up as arming a single
    # destructive rule (from a browser session; bearer callers exempt).
    # Turning the switch OFF reduces blast radius and stays MFA-free.
    if body.automation_enabled and resolved is not None:
        enforce_fresh_mfa(user=user, session_row=resolved[0], settings=settings)

    # The SQL statement owns both the boolean transition and its monotonic
    # authority epoch. In particular, off/on racing requests cannot return the
    # epoch to an earlier value and resurrect a pre-toggle dispatch token.
    await AutomationRuleRepository(db_session).set_project_automation_enabled(
        project,
        enabled=body.automation_enabled,
    )
    await audit.record(
        audit_log,
        action="automation.kill_switch.updated",
        target_type="project",
        target_id=str(project.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        metadata={"automation_enabled": body.automation_enabled},
    )
    await db_session.commit()
    return AutomationSettings(automation_enabled=project.automation_enabled)


__all__ = ["router", "settings_router"]
