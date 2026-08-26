"""``automation_rules`` repository: trigger lookup + circuit-breaker claim.

The circuit breaker is a per-rule exact rolling window: at most
``max_executions_per_window`` normal-mode firings in any
``window_seconds`` interval; over the limit the rule trips into notify-only
"failsafe mode". Retained admissions live in a bounded child table, and the
rule row is the transactional arbiter so concurrent event ingest cannot race
the prune/count/insert decision.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import structlog
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AutomationRule, AutomationRuleAdmission, Project
from z4j_brain.persistence.repositories._base import BaseRepository

logger = structlog.get_logger("z4j.brain.automation.repository")

#: Ceiling on rules loaded per (project, trigger) on the hot path. Bounds
#: the per-event cost; rules beyond it are truncated (and the truncation
#: is logged, never silent).
_MAX_RULES_PER_TRIGGER = 500
_PROJECT_REVISION_ATTR = "_z4j_automation_project_revision"
_CONFIGURATION_FIELDS = frozenset(
    {
        "name",
        "is_enabled",
        "dry_run",
        "trigger",
        "conditions",
        "actions",
        "max_executions_per_window",
        "window_seconds",
        "created_by",
        "source_hash",
    },
)


class CircuitDecision(enum.StrEnum):
    """Outcome of claiming one execution slot on a rule's circuit breaker."""

    EXECUTE = "execute"  # within budget; run actions normally
    TRIPPED_NOW = "tripped_now"  # this call pushed it over the limit
    TRIPPED = "tripped"  # already tripped; failsafe (notify-only)
    STALE = "stale"  # rule/project changed since matching; run nothing


@dataclass(frozen=True, slots=True)
class AutomationRuleDispatchCandidate:
    """Immutable rule configuration matched by the evaluator.

    ``run_matching`` evaluates conditions before it starts the per-rule write
    unit.  Carrying only the rule id across that boundary lets a disable,
    kill-switch flip, or edit race with execution: the later row reload would
    run the *new* actions even though the *old* conditions matched.  This
    token binds every execution-relevant field without retaining an ORM
    object that a sibling rollback can expire.
    """

    rule_id: UUID
    project_id: UUID
    trigger: str
    rule_revision: int
    project_revision: int
    config_digest: str


def _dispatch_revision(rule: Any) -> str:
    """Canonical, exact token for fields that define one rule execution.

    Circuit-breaker and notify-coalesce state are deliberately excluded:
    claims mutate those fields themselves.  ``updated_at`` is excluded for
    the same reason (SQLAlchemy advances it on the state UPDATE).  Comparing
    the configuration itself also catches writers that bypass the ORM's
    timestamp hook.
    """
    payload = {
        "project_id": str(rule.project_id),
        "name": getattr(rule, "name", None),
        "is_enabled": getattr(rule, "is_enabled", None),
        "dry_run": getattr(rule, "dry_run", None),
        "trigger": getattr(rule, "trigger", None),
        "conditions": getattr(rule, "conditions", None),
        "actions": getattr(rule, "actions", None),
        "max_executions_per_window": getattr(rule, "max_executions_per_window", None),
        "window_seconds": getattr(rule, "window_seconds", None),
        "created_by": str(rule.created_by) if getattr(rule, "created_by", None) else None,
        "source_hash": getattr(rule, "source_hash", None),
        # Make the breaker epoch monotonic too: edit-away/edit-back must not
        # resurrect admission history from an earlier identical payload.
        "config_revision": getattr(rule, "config_revision", None),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def dispatch_candidate(
    rule: Any,
    *,
    project_revision: int | None = None,
) -> AutomationRuleDispatchCandidate:
    """Freeze a matched ORM row into a rollback-safe dispatch token.

    Production callers receive ``project_revision`` on rows returned by
    :meth:`list_enabled_for_trigger`. Tests or maintenance callers that load a
    rule directly must pass it explicitly; silently assuming an epoch would
    re-open the project kill-switch ABA race.
    """
    if project_revision is None:
        project_revision = getattr(rule, _PROJECT_REVISION_ATTR, None)
    if project_revision is None:
        raise ValueError("project automation revision is required for dispatch")
    return AutomationRuleDispatchCandidate(
        rule_id=rule.id,
        project_id=rule.project_id,
        trigger=rule.trigger,
        rule_revision=int(rule.config_revision),
        project_revision=int(project_revision),
        config_digest=_dispatch_revision(rule),
    )


def _aware(dt: Any) -> datetime:
    """Normalise a possibly-naive/string SQLite datetime to UTC."""

    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    if not isinstance(dt, datetime):
        raise TypeError("database returned an invalid automation clock")
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _database_wall_clock(dialect_name: str) -> Any:
    """Database wall clock used after the claim's authority lock.

    SQLite ``CURRENT_TIMESTAMP`` has only whole-second precision, which can
    expire an admission almost one second before a real W-second interval has
    elapsed. Its ``strftime('%f')`` clock retains millisecond precision; the
    production PostgreSQL path retains full ``clock_timestamp`` precision.
    """

    if dialect_name == "postgresql":
        return func.clock_timestamp()
    if dialect_name == "sqlite":
        return func.strftime("%Y-%m-%d %H:%M:%f", "now")
    return func.current_timestamp()


class AutomationRuleRepository(BaseRepository[AutomationRule]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AutomationRule)

    async def list_enabled_for_trigger(
        self,
        *,
        project_id: UUID,
        trigger: str,
    ) -> list[AutomationRule]:
        """Enabled rules for one project + trigger (uses the
        ``(project_id, trigger, is_enabled)`` index). Bounded.

        Honours the per-project kill switch: the join to ``projects``
        with ``automation_enabled`` short-circuits to zero rows when a
        project's automation is switched off, so the executor's single
        rule-loading choke point is also the single kill-switch check.
        """
        result = await self.session.execute(
            select(AutomationRule, Project.automation_revision)
            .join(Project, AutomationRule.project_id == Project.id)
            .where(
                AutomationRule.project_id == project_id,
                AutomationRule.trigger == trigger,
                AutomationRule.is_enabled.is_(True),
                Project.automation_enabled.is_(True),
            )
            # Deterministic order so which rules survive the cap is stable
            # (creation order), not arbitrary.
            .order_by(AutomationRule.created_at, AutomationRule.id)
            # Fetch one past the cap so we can distinguish "exactly at the
            # cap, nothing dropped" from "over the cap, tail truncated" and
            # only warn in the latter case.
            .limit(_MAX_RULES_PER_TRIGGER + 1),
        )
        rows = list(result.all())
        if len(rows) > _MAX_RULES_PER_TRIGGER:
            logger.warning(
                "z4j automation: (project, trigger) hit the rule-load cap; "
                "rules beyond the cap will not fire",
                project_id=str(project_id),
                trigger=trigger,
                cap=_MAX_RULES_PER_TRIGGER,
            )
            rows = rows[:_MAX_RULES_PER_TRIGGER]
        rules: list[AutomationRule] = []
        for rule, project_revision in rows:
            # This is deliberately plain snapshot data, not a relationship:
            # evaluator access remains synchronous and cannot lazy-load.
            setattr(rule, _PROJECT_REVISION_ATTR, int(project_revision))
            rules.append(rule)
        return rules

    async def has_enabled_rule_for_trigger(
        self,
        *,
        project_id: UUID,
        trigger: str,
    ) -> bool:
        """Cheap EXISTS: does the project have any enabled rule for this
        trigger (honouring the kill switch)? Used to skip persisting a
        firing to the durable outbox when there is nothing to fire, so a
        busy project with no automation cannot bloat the outbox under an
        event flood."""
        result = await self.session.execute(
            select(AutomationRule.id)
            .join(Project, AutomationRule.project_id == Project.id)
            .where(
                AutomationRule.project_id == project_id,
                AutomationRule.trigger == trigger,
                AutomationRule.is_enabled.is_(True),
                Project.automation_enabled.is_(True),
            )
            .limit(1),
        )
        return result.scalar_one_or_none() is not None

    async def list_for_project(
        self,
        *,
        project_id: UUID,
        limit: int = 200,
        offset: int = 0,
    ) -> list[AutomationRule]:
        """All rules for a project (enabled or not), newest first. Bounded."""
        capped = min(max(1, limit), 500)
        result = await self.session.execute(
            select(AutomationRule)
            .where(AutomationRule.project_id == project_id)
            .order_by(AutomationRule.created_at.desc())
            .limit(capped)
            .offset(max(0, offset)),
        )
        return list(result.scalars().all())

    async def get_by_project_and_name(
        self,
        *,
        project_id: UUID,
        name: str,
    ) -> AutomationRule | None:
        """Look up a rule by its project-unique name (409 pre-check)."""
        result = await self.session.execute(
            select(AutomationRule).where(
                AutomationRule.project_id == project_id,
                AutomationRule.name == name,
            ),
        )
        return result.scalar_one_or_none()

    async def get_for_update(
        self,
        rule_id: UUID,
        *,
        project_id: UUID | None = None,
    ) -> AutomationRule | None:
        """Load one authoritative rule and hold its mutation lock.

        Used by update, delete, and circuit reset so authorization and the
        corresponding mutation refer to one locked configuration revision.
        """
        statement = select(AutomationRule).where(AutomationRule.id == rule_id)
        if project_id is not None:
            statement = statement.where(AutomationRule.project_id == project_id)
        return (
            await self.session.execute(
                statement.with_for_update().execution_options(populate_existing=True),
            )
        ).scalar_one_or_none()

    async def reset_circuit(self, rule: AutomationRule) -> None:
        """Clear one locked rule's breaker state and admission evidence."""
        await self.session.execute(
            delete(AutomationRuleAdmission).where(
                AutomationRuleAdmission.rule_id == rule.id,
            ),
        )
        rule.cb_tripped = False
        rule.cb_execution_count = 0
        rule.cb_window_start = None
        rule.cb_config_digest = _dispatch_revision(rule)
        await self.session.flush()

    async def update_configuration(
        self,
        rule: AutomationRule,
        values: dict[str, Any],
    ) -> AutomationRule:
        """Apply one already-authorized, already-locked config mutation.

        The epoch increment is a SQL expression evaluated against the locked
        database row, rather than ``rule.config_revision += 1`` calculated in
        Python. That makes the mutation boundary explicit and prevents two
        writers from publishing the same epoch. Callers must acquire the row
        through :meth:`get_for_update` before their authorization decision.
        """
        unexpected = values.keys() - _CONFIGURATION_FIELDS
        if unexpected:
            raise ValueError(f"unsupported automation rule fields: {sorted(unexpected)}")
        if not values:
            return rule
        await self.session.execute(
            update(AutomationRule)
            .where(AutomationRule.id == rule.id)
            .values(
                **values,
                config_revision=AutomationRule.config_revision + 1,
            )
            .execution_options(synchronize_session=False),
        )
        await self.session.refresh(rule)
        return rule

    async def set_project_automation_enabled(
        self,
        project: Project,
        *,
        enabled: bool,
    ) -> bool:
        """Atomically transition the kill switch and advance its ABA epoch.

        The value predicate is part of the UPDATE. PostgreSQL re-evaluates it
        after waiting for a concurrent row writer, while SQLite's request
        ``BEGIN IMMEDIATE`` serializes it before this statement. Thus two
        racing off/on requests cannot collapse into one revision.
        """
        result = await self.session.execute(
            update(Project)
            .where(
                Project.id == project.id,
                Project.automation_enabled != enabled,
            )
            .values(
                automation_enabled=enabled,
                automation_revision=Project.automation_revision + 1,
            )
            .execution_options(synchronize_session=False),
        )
        changed = bool(getattr(result, "rowcount", 0))
        await self.session.refresh(project)
        return changed

    async def revalidate_execution(
        self,
        candidate: AutomationRuleDispatchCandidate,
    ) -> AutomationRule | None:
        """Lock and return the exact still-authorized candidate revision.

        This is both the claim's initial authority check and the checkpoint
        between actions. A command action durably commits its command before
        delivery, releasing transaction locks; the next action must therefore
        reacquire the rule/project authority instead of trusting the earlier
        ORM row.
        """
        locked = (
            await self.session.execute(
                select(AutomationRule, Project.automation_revision)
                .join(Project, AutomationRule.project_id == Project.id)
                .where(
                    AutomationRule.id == candidate.rule_id,
                    AutomationRule.project_id == candidate.project_id,
                    AutomationRule.trigger == candidate.trigger,
                    AutomationRule.is_enabled.is_(True),
                    AutomationRule.config_revision == candidate.rule_revision,
                    Project.automation_enabled.is_(True),
                    Project.automation_revision == candidate.project_revision,
                )
                # With no ``OF`` restriction Postgres locks every joined row:
                # both the rule and its project kill-switch authority.
                .with_for_update()
                .execution_options(populate_existing=True),
            )
        ).one_or_none()
        if locked is None:
            return None
        row, project_revision = cast(tuple[AutomationRule, int], locked)
        if (
            int(row.config_revision) != candidate.rule_revision
            or int(project_revision) != candidate.project_revision
            or _dispatch_revision(row) != candidate.config_digest
        ):
            return None
        return row

    async def disable_rules_created_by(
        self,
        *,
        user_id: UUID,
        project_id: UUID,
    ) -> int:
        """Disable every still-enabled rule a user created in a project.

        Called when the user is deprovisioned (membership revoked) so their
        automation stops firing ENTIRELY. The fire-time re-check only gates
        destructive commands, so without this a revoked creator's notify
        rules would keep firing to the remaining members. Returns the count
        disabled. Does NOT commit -- the caller owns the transaction.
        """
        result = await self.session.execute(
            update(AutomationRule)
            .where(
                AutomationRule.created_by == user_id,
                AutomationRule.project_id == project_id,
                AutomationRule.is_enabled.is_(True),
            )
            .values(
                is_enabled=False,
                config_revision=AutomationRule.config_revision + 1,
            ),
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def disable_all_rules_created_by_user(self, *, user_id: UUID) -> int:
        """Disable every still-enabled rule a user created, in ALL projects.

        Called on hard user-deletion. The ``created_by`` FK is
        ``ON DELETE SET NULL``, so a deleted creator's rules would
        otherwise become ``created_by IS NULL`` -- indistinguishable from a
        system rule -- and the fire-time authz check treats NULL as system
        authority, leaving orphaned destructive automation firing with no
        owner. Disabling first stops them entirely before the FK nulls the
        owner. Does NOT commit -- the caller owns the transaction.
        """
        result = await self.session.execute(
            update(AutomationRule)
            .where(
                AutomationRule.created_by == user_id,
                AutomationRule.is_enabled.is_(True),
            )
            .values(
                is_enabled=False,
                config_revision=AutomationRule.config_revision + 1,
            ),
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def claim_execution(
        self,
        *,
        candidate: AutomationRuleDispatchCandidate,
        now: datetime | None = None,
    ) -> tuple[CircuitDecision, AutomationRule | None]:
        """Revalidate one matched candidate and claim it under row locks.

        Returns ``(decision, row)`` where ``row`` is the freshly-locked
        rule (or ``None`` if it no longer qualifies). The caller runs its
        actions against THIS returned row rather than a pre-fetched copy:
        after a sibling rule's per-rule rollback the caller's earlier
        objects are expired, and touching them would trigger an implicit
        lazy load outside the async greenlet. The row handed back here is
        loaded fresh in the current transaction, so it is always safe.

        The locked query repeats the authoritative project kill-switch,
        rule-enabled, project, and trigger predicates.  It then compares
        the complete execution configuration with the immutable token made
        when conditions matched.  Any disable/edit/kill-switch race returns
        ``STALE`` without advancing the breaker or running an action.  The
        rule and project rows remain locked until the caller commits, so a
        mutation cannot slip between this revalidation and dispatch.

        On Postgres the ``FOR UPDATE`` lock serialises concurrent claims
        from parallel detached dispatch tasks and locks the joined project
        row as well. ``populate_existing`` forces the locked row to be
        re-read from the database even when an older copy is already in this
        session's identity map, so the read-modify-write sees DB-current
        state. On SQLite ``FOR UPDATE`` is a no-op; callers must use the
        ``BEGIN IMMEDIATE`` write unit that ``run_matching`` reserves before
        reaching this method, which serialises the SQLite path. Production
        claims use a database wall clock sampled *after* the authority lock;
        PostgreSQL's transaction-start ``CURRENT_TIMESTAMP`` is deliberately
        avoided because a lock wait could otherwise backdate an admission and
        age it out early. Replica process-clock skew is therefore irrelevant. ``now`` is an
        explicit deterministic-clock seam for boundary tests. The window and
        limit come from the rule's own config columns. Does NOT commit -- the
        caller owns the transaction.
        """
        row = await self.revalidate_execution(candidate)
        if row is None:
            return CircuitDecision.STALE, None
        current_digest = _dispatch_revision(row)

        # A config digest identifies the epoch whose admission timestamps are
        # meaningful. Any execution-relevant edit (including a changed limit
        # or window) starts empty: otherwise widening a window could require
        # timestamps already pruned under the prior configuration. This reset
        # is inside the same rule lock and transaction as admission.
        if row.cb_config_digest != current_digest:
            await self.session.execute(
                delete(AutomationRuleAdmission).where(
                    AutomationRuleAdmission.rule_id == row.id,
                ),
            )
            row.cb_config_digest = current_digest
            row.cb_window_start = None
            row.cb_execution_count = 0
            row.cb_tripped = False

        if now is not None:
            claim_now = _aware(now)
        else:
            dialect_name = self.session.bind.dialect.name if self.session.bind is not None else ""
            database_clock = _database_wall_clock(dialect_name)
            claim_now = _aware(
                (await self.session.execute(select(database_clock))).scalar_one(),
            )
        window = timedelta(seconds=max(1, row.window_seconds))
        cutoff = claim_now - window
        # Half-open window ``(now-W, now]``: an admission exactly W seconds
        # old is expired, so the boundary behaviour is deterministic.
        await self.session.execute(
            delete(AutomationRuleAdmission).where(
                AutomationRuleAdmission.rule_id == row.id,
                AutomationRuleAdmission.admitted_at <= cutoff,
            ),
        )
        retained_count, oldest = (
            await self.session.execute(
                select(
                    func.coalesce(func.sum(AutomationRuleAdmission.weight), 0),
                    func.min(AutomationRuleAdmission.admitted_at),
                ).where(AutomationRuleAdmission.rule_id == row.id),
            )
        ).one()
        retained = int(retained_count)
        limit = max(1, row.max_executions_per_window)
        row.cb_window_start = oldest
        row.cb_execution_count = retained

        if retained >= limit:
            was_tripped = row.cb_tripped
            row.cb_tripped = True
            return (CircuitDecision.TRIPPED if was_tripped else CircuitDecision.TRIPPED_NOW), row

        self.session.add(
            AutomationRuleAdmission(
                rule_id=row.id,
                admitted_at=claim_now,
                weight=1,
            ),
        )
        row.cb_window_start = oldest or claim_now
        row.cb_execution_count = retained + 1
        row.cb_tripped = False
        return CircuitDecision.EXECUTE, row


__all__ = [
    "AutomationRuleDispatchCandidate",
    "AutomationRuleRepository",
    "CircuitDecision",
    "dispatch_candidate",
]
