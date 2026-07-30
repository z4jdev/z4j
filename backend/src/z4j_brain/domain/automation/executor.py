"""Automation action executor + governance.

Given the rules that matched an event, this decides -- per action --
whether to EXECUTE, DRY-RUN, or SKIP (circuit-breaker failsafe), runs the
real action via an injected :class:`ActionRunner`, and writes an
HMAC-chained audit row for every rule firing (and one on a circuit trip).

The ``ActionRunner`` boundary keeps this orchestration unit-testable with
a fake; the real runner -- wired to ``NotificationService`` (notify /
webhook) and ``CommandDispatcher`` (retry / cancel / revoke / purge /
pause_schedule, gated by the target adapter's capabilities) -- lands with
the frame-router integration.

Governance rules enforced here:

- **dry-run**: a dry-run rule audits what it WOULD do and runs nothing.
- **failsafe**: a tripped circuit runs NOTIFY actions but skips
  DESTRUCTIVE ones (notify-only), so a runaway rule can still alert while
  its destructive blast radius is contained.
- **fault isolation**: an action that raises is logged, audited as
  ``failed``, and does not abort the rest of the rule; a DB-level failure
  that poisons the session rolls back only the offending rule (each rule
  commits in its own transaction) so the rest of the event's fan-out
  still fires -- and the drop is surfaced as a swallowed-error metric."""

from __future__ import annotations

from datetime import UTC
from typing import Any, Protocol

import structlog

from z4j_brain.domain.automation.evaluator import (
    DESTRUCTIVE_ACTIONS,
    KNOWN_ACTIONS,
    NOTIFY_ACTIONS,
    matching_rules,
)
from z4j_brain.persistence.repositories.automation_rule import CircuitDecision

logger = structlog.get_logger("z4j.brain.automation.executor")


def _record_swallowed_automation() -> None:
    """Surface a rolled-back rule firing as a swallowed-error metric so a
    per-rule rollback is observable to operators, never silent."""
    try:
        from z4j_brain.api.metrics import record_swallowed

        record_swallowed("automation_executor", "run_matching")
    except Exception:
        logger.debug("z4j automation: record_swallowed unavailable")


def _within_coalesce_window(last_notify_at: Any, now: Any, window_seconds: int) -> bool:
    """True if ``last_notify_at`` is within ``window_seconds`` before ``now``.

    Normalises a possibly-naive (SQLite) ``last_notify_at`` to UTC so the
    subtraction never raises on a mixed-awareness comparison.
    """
    if last_notify_at is None:
        return False
    if last_notify_at.tzinfo is None:
        last_notify_at = last_notify_at.replace(tzinfo=UTC)
    return (now - last_notify_at).total_seconds() < window_seconds


def _record_notify_coalesced(project_id: Any) -> None:
    """Best-effort metric bump for a coalesced (suppressed) notify."""
    try:
        from z4j_brain.api.metrics import (
            z4j_automation_notify_coalesced_total,
        )

        z4j_automation_notify_coalesced_total.labels(project=str(project_id)).inc()
    except Exception:
        logger.debug("z4j automation: notify-coalesce metric unavailable")


class ActionRunner(Protocol):
    """Executes one action for a firing rule and returns an outcome
    string (e.g. ``"delivered"``, ``"issued"``, ``"unsupported"``)."""

    async def run(
        self,
        *,
        session: Any,
        rule: Any,
        action_spec: dict[str, Any],
        fields: dict[str, Any],
    ) -> str: ...


class AutomationExecutor:
    def __init__(self, *, audit: Any, runner: ActionRunner) -> None:
        self._audit = audit
        self._runner = runner

    async def run_matching(
        self,
        *,
        session: Any,
        rules_repo: Any,
        audit_log: Any,
        project_id: Any,
        trigger: str,
        fields: dict[str, Any],
        now: Any,
        notify_coalesce_seconds: int = 0,
    ) -> None:
        """Load enabled rules for ``(project, trigger)``, match, and run
        EACH matching rule in its OWN committed transaction.

        Per-rule commit is load-bearing for three properties:

        - **fault isolation**: a transient DB error (deadlock / lock
          timeout / a poisoned session) on one rule rolls back only that
          rule; the rest of the event's fan-out still fires.
        - **lock hygiene**: the audit-chain advisory lock and the circuit
          breaker's ``FOR UPDATE`` row lock are released after each rule
          instead of being held across the whole batch -- which would
          serialize the brain's audit subsystem cross-tenant under an
          event flood.
        - **firing durability**: a rule's ``fired`` audit rows commit
          together with the rule's own side effects.

        A rolled-back rule is surfaced as a swallowed-error metric so the
        drop is observable, never silent.
        """
        rules = await rules_repo.list_enabled_for_trigger(
            project_id=project_id,
            trigger=trigger,
        )
        # Snapshot the matching rules' ids while the ORM objects are still
        # fresh. A per-rule rollback below EXPIRES every persistent object
        # in the session (SQLAlchemy 2.0 rollback semantics), so reading
        # ``rule.id`` off a pre-fetched object on a LATER iteration would
        # trigger an implicit lazy-load outside the async greenlet
        # (MissingGreenlet) and cascade-fail the rest of the batch. We
        # instead carry plain ids and operate only on the fresh row that
        # ``claim_execution`` re-loads under its FOR UPDATE lock.
        matched_ids = [rule.id for rule in matching_rules(rules, trigger, fields)]
        for rule_id in matched_ids:
            try:
                decision, rule = await rules_repo.claim_execution(
                    rule_id=rule_id,
                    now=now,
                )
                if rule is None:
                    continue  # rule was deleted between load and claim
                await self._run_one(
                    audit_log,
                    session,
                    rule,
                    fields,
                    decision,
                    now=now,
                    notify_coalesce_seconds=notify_coalesce_seconds,
                )
                await session.commit()
            except Exception:
                logger.exception(
                    "z4j automation: rule dispatch failed; rolled back",
                    rule_id=str(rule_id),
                )
                await session.rollback()
                _record_swallowed_automation()

    async def _run_one(
        self,
        audit_log: Any,
        session: Any,
        rule: Any,
        fields: dict[str, Any],
        decision: CircuitDecision,
        *,
        now: Any = None,
        notify_coalesce_seconds: int = 0,
    ) -> None:
        if decision == CircuitDecision.TRIPPED_NOW:
            await self._audit.record(
                audit_log,
                action="automation.rule.circuit_tripped",
                target_type="automation_rule",
                target_id=str(rule.id),
                result="failed",
                outcome="failure",
                project_id=rule.project_id,
                metadata={"rule_name": rule.name, "trigger": rule.trigger},
            )
            # Operators alert on metrics, not the audit log; mirror the
            # trip. Best-effort: a metrics failure must never affect the
            # firing path.
            try:
                from z4j_brain.api.metrics import (
                    z4j_automation_circuit_trips_total,
                )

                z4j_automation_circuit_trips_total.labels(
                    project=str(rule.project_id),
                ).inc()
            except Exception:  # noqa: S110  best-effort metrics mirror
                pass

        failsafe = decision in (
            CircuitDecision.TRIPPED,
            CircuitDecision.TRIPPED_NOW,
        )
        # Durability of the firing record (audit finding, accepted with
        # mitigation): notify firings commit atomically with their
        # UserNotification rows via run_matching's per-rule commit. A
        # command firing's CommandDispatcher.issue self-commits the command
        # AND a ``command.issue.<action>`` audit row that already carries
        # full automation attribution (rule id + action + task via the
        # idempotency_key, rule name via user_agent), so the firing is
        # durably recorded and reconstructable even if this higher-level
        # ``automation.rule.fired`` row is lost in the small post-issue
        # window. Fully-atomic command+fired auditing would require
        # issue() to defer its commit (delivery depends on the committed
        # row) -- deferred rather than restructure the shared dispatcher.
        for action_spec in rule.actions or []:
            action_type = action_spec.get("type") if isinstance(action_spec, dict) else None
            outcome = await self._decide_and_run(
                session,
                rule,
                action_spec,
                action_type,
                fields,
                failsafe,
                now=now,
                notify_coalesce_seconds=notify_coalesce_seconds,
            )
            # Metrics mirror of the ``automation.rule.fired`` audit row
            # below. Labelled by action + outcome (NOT rule id -- that is
            # unbounded cardinality; per-rule detail lives in the audit
            # rows). Best-effort: never affects the firing path.
            try:
                from z4j_brain.api.metrics import (
                    z4j_automation_rule_fires_total,
                )

                z4j_automation_rule_fires_total.labels(
                    project=str(rule.project_id),
                    action=str(action_type),
                    outcome=str(outcome),
                ).inc()
            except Exception:  # noqa: S110  best-effort metrics mirror
                pass
            await self._audit.record(
                audit_log,
                action="automation.rule.fired",
                target_type="automation_rule",
                target_id=str(rule.id),
                result="failed" if outcome == "failed" else "success",
                outcome="allow",
                project_id=rule.project_id,
                metadata={
                    "rule_name": rule.name,
                    "trigger": rule.trigger,
                    "action": action_type,
                    "outcome": outcome,
                    "dry_run": bool(rule.dry_run),
                    "task_id": fields.get("task_id"),
                    # engine + agent_id make every firing uniquely
                    # traceable to a task, matching the (engine, task_id)
                    # key the command path uses -- not just notify rules.
                    "engine": fields.get("engine"),
                    "agent_id": (
                        str(fields["agent_id"]) if fields.get("agent_id") is not None else None
                    ),
                },
            )

    async def _decide_and_run(
        self,
        session: Any,
        rule: Any,
        action_spec: Any,
        action_type: Any,
        fields: dict[str, Any],
        failsafe: bool,
        *,
        now: Any = None,
        notify_coalesce_seconds: int = 0,
    ) -> str:
        if action_type not in KNOWN_ACTIONS:
            return "unknown_action"
        if failsafe and action_type in DESTRUCTIVE_ACTIONS:
            return "skipped_failsafe"
        if rule.dry_run:
            return "dry_run"
        # Notify-flood coalesce: if this rule already emitted a notify
        # inside the window, fold this one into it. The check runs under the
        # rule's FOR UPDATE lock (claim_execution), so concurrent dispatch
        # tasks cannot both slip past. last_notify_at is only advanced on an
        # actual emission below, so the first alert per window always fires.
        if (
            action_type == "notify"
            and notify_coalesce_seconds > 0
            and now is not None
            and _within_coalesce_window(rule.last_notify_at, now, notify_coalesce_seconds)
        ):
            _record_notify_coalesced(getattr(rule, "project_id", None))
            return "coalesced"
        try:
            outcome = await self._runner.run(
                session=session,
                rule=rule,
                action_spec=action_spec,
                fields=fields,
            )
        except Exception:
            # One bad action must not abort the batch or crash the event
            # path; audit it as failed and move on.
            logger.exception(
                "z4j automation: action execution failed",
                rule_id=str(rule.id),
                action=action_type,
            )
            return "failed"
        if action_type == "notify" and now is not None:
            # Record the emission so the next notify inside the window
            # coalesces. Advanced only on a real emission (not dry_run /
            # coalesced), so it commits with this rule's per-rule commit.
            rule.last_notify_at = now
        return outcome


__all__ = [
    "DESTRUCTIVE_ACTIONS",
    "NOTIFY_ACTIONS",
    "ActionRunner",
    "AutomationExecutor",
]
