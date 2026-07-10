"""``automation_rules`` repository: trigger lookup + circuit-breaker claim.

The circuit breaker is a per-rule rolling-window counter (copied from
Kanchi): at most ``max_executions_per_window`` firings per
``window_seconds``; over the limit the rule trips into notify-only
"failsafe mode" until the window rolls. State lives on the rule row and
is advanced atomically under a row lock so concurrent event ingest can't
race the counter.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AutomationRule, Project
from z4j_brain.persistence.repositories._base import BaseRepository

logger = structlog.get_logger("z4j.brain.automation.repository")

#: Ceiling on rules loaded per (project, trigger) on the hot path. Bounds
#: the per-event cost; rules beyond it are truncated (and the truncation
#: is logged, never silent).
_MAX_RULES_PER_TRIGGER = 500


class CircuitDecision(enum.StrEnum):
    """Outcome of claiming one execution slot on a rule's circuit breaker."""

    EXECUTE = "execute"  # within budget; run actions normally
    TRIPPED_NOW = "tripped_now"  # this call pushed it over the limit
    TRIPPED = "tripped"  # already tripped; failsafe (notify-only)


def _aware(dt: datetime) -> datetime:
    """Normalise a possibly-naive (SQLite) datetime to UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


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
            select(AutomationRule)
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
        rules = list(result.scalars().all())
        if len(rules) > _MAX_RULES_PER_TRIGGER:
            logger.warning(
                "z4j automation: (project, trigger) hit the rule-load cap; "
                "rules beyond the cap will not fire",
                project_id=str(project_id),
                trigger=trigger,
                cap=_MAX_RULES_PER_TRIGGER,
            )
            rules = rules[:_MAX_RULES_PER_TRIGGER]
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
            .values(is_enabled=False),
        )
        return result.rowcount or 0

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
            .values(is_enabled=False),
        )
        return result.rowcount or 0

    async def claim_execution(
        self,
        *,
        rule_id: UUID,
        now: datetime,
    ) -> tuple[CircuitDecision, AutomationRule | None]:
        """Advance the rolling-window circuit breaker under a row lock.

        Returns ``(decision, row)`` where ``row`` is the freshly-locked
        rule (or ``None`` if the rule vanished). The caller runs its
        actions against THIS returned row rather than a pre-fetched copy:
        after a sibling rule's per-rule rollback the caller's earlier
        objects are expired, and touching them would trigger an implicit
        lazy load outside the async greenlet. The row handed back here is
        loaded fresh in the current transaction, so it is always safe.

        On Postgres the ``FOR UPDATE`` lock serialises concurrent claims
        from parallel detached dispatch tasks, and ``populate_existing``
        forces the locked row to be re-read from the database even when an
        older copy is already in this session's identity map, so the
        read-modify-write sees the DB-current counter and the per-window
        cap is EXACT. On SQLite ``FOR UPDATE`` is a no-op, so concurrent
        detached tasks can interleave the read-increment-write and
        under-count -- the cap is only APPROXIMATE there. SQLite is the
        dev/test backend; production runs Postgres, where the cap is
        exact. The window and limit come from the rule's own config
        columns. Does NOT commit -- the caller owns the transaction.
        """
        row = (
            await self.session.execute(
                select(AutomationRule)
                .where(AutomationRule.id == rule_id)
                .with_for_update()
                .execution_options(populate_existing=True),
            )
        ).scalar_one_or_none()
        if row is None:
            return CircuitDecision.TRIPPED, None  # rule vanished; do nothing

        window = timedelta(seconds=max(1, row.window_seconds))
        window_expired = row.cb_window_start is None or now >= _aware(row.cb_window_start) + window
        if window_expired:
            row.cb_window_start = now
            row.cb_execution_count = 1
            row.cb_tripped = False
            return CircuitDecision.EXECUTE, row

        row.cb_execution_count += 1
        if row.cb_execution_count > row.max_executions_per_window:
            was_tripped = row.cb_tripped
            row.cb_tripped = True
            return (CircuitDecision.TRIPPED if was_tripped else CircuitDecision.TRIPPED_NOW), row
        return CircuitDecision.EXECUTE, row


__all__ = ["AutomationRuleRepository", "CircuitDecision"]
