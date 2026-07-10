"""Real automation ``ActionRunner`` (Cluster R2 wiring).

Executes a firing rule's actions against the live brain:

- ``notify`` -> an in-app ``UserNotification`` for every active project
  member. External-channel delivery (slack / webhook) is a follow-up.
- ``retry`` / ``cancel`` -> a governed command issued to the agent that
  REPORTED the triggering event, via ``CommandDispatcher.issue``. The
  retry payload carries only the brain-known ``task_name`` (never a
  broker re-read, never redacted args), so the RQ pickle-safe retry path
  is preserved: adapters that need explicit overrides (rq/huey/arq/
  taskiq) fail closed agent-side, celery/dramatiq retry natively.
- anything else -> ``"unsupported"`` (webhook / purge / pause_schedule
  land next).

Capability enforcement is agent-side: the agent's dispatcher fails closed
on an action its engine adapter does not advertise, and the failed
``command_result`` is audited by the command dispatcher. Brain-side
pre-gating is a follow-up.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from z4j_brain.domain.policy_engine import role_rank
from z4j_brain.errors import AgentOfflineError
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models.notification import (
    NotificationReason,
    UserNotification,
)
from z4j_brain.persistence.repositories.audit_log import AuditLogRepository
from z4j_brain.persistence.repositories.commands import CommandRepository
from z4j_brain.persistence.repositories.memberships import MembershipRepository
from z4j_brain.persistence.repositories.tasks import TaskRepository

logger = structlog.get_logger("z4j.brain.automation.runner")

_COMMAND_FOR_ACTION: dict[str, str] = {
    "retry": "retry_task",
    "cancel": "cancel_task",
}


class AutomationActionRunner:
    """The production :class:`ActionRunner`. Injected with the
    ``CommandDispatcher``; opens no sessions of its own (the executor's
    caller owns the transaction)."""

    def __init__(self, *, dispatcher: Any) -> None:
        self._dispatcher = dispatcher
        # Per-dispatch cache of active member ids by project so N notify
        # rules matching one event don't re-run the same membership query.
        # The runner is constructed fresh per event dispatch, so the cache
        # lifetime is exactly one event's fan-out.
        self._member_ids_cache: dict[Any, set[Any]] = {}

    async def run(
        self,
        *,
        session: Any,
        rule: Any,
        action_spec: dict[str, Any],
        fields: dict[str, Any],
    ) -> str:
        action_type = action_spec.get("type") if isinstance(action_spec, dict) else None
        if action_type == "notify":
            return await self._notify(session, rule, fields)
        command_action = _COMMAND_FOR_ACTION.get(action_type or "")
        if command_action is not None:
            return await self._command(session, rule, command_action, fields)
        return "unsupported"

    async def _notify(self, session: Any, rule: Any, fields: dict[str, Any]) -> str:
        member_ids = self._member_ids_cache.get(rule.project_id)
        if member_ids is None:
            member_ids = await MembershipRepository(
                session,
            ).list_active_user_ids_for_project(rule.project_id)
            self._member_ids_cache[rule.project_id] = member_ids
        if not member_ids:
            return "no_recipients"

        title = f"Automation rule '{rule.name}' fired"
        body = _notify_body(rule, fields)
        data = {
            "task_id": fields.get("task_id"),
            "task_name": fields.get("task_name"),
            "engine": fields.get("engine"),
            "rule_id": str(rule.id),
        }
        for uid in member_ids:
            session.add(
                UserNotification(
                    user_id=uid,
                    project_id=rule.project_id,
                    subscription_id=None,
                    trigger=rule.trigger,
                    reason=NotificationReason.AUTOMATION,
                    title=title,
                    body=body,
                    data=data,
                ),
            )
        return "notified"

    async def _command(
        self,
        session: Any,
        rule: Any,
        command_action: str,
        fields: dict[str, Any],
    ) -> str:
        agent_id = fields.get("agent_id")
        engine = fields.get("engine")
        task_id = fields.get("task_id")
        if not agent_id or not engine or not task_id:
            return "no_target"

        # Fire-time authorization: the create-time RBAC gate can go stale
        # (the creator was removed or demoted). Re-check before issuing a
        # DESTRUCTIVE command so a deprovisioned creator's automation stops
        # acting; the executor audits the "denied_stale_authz" outcome.
        if not await self._creator_may_act(session, rule):
            logger.warning(
                "z4j automation: destructive command skipped -- creator no longer authorized",
                rule_id=str(rule.id),
                action=command_action,
            )
            return "denied_stale_authz"

        payload: dict[str, Any] = {"engine": engine, "task_id": task_id}
        if command_action == "retry_task":
            # Brain-supplied task_name only (RQ pickle-safe: no broker
            # re-read, no redacted args passed as real args). Native
            # engines retry from the broker; polyfill engines that need
            # explicit overrides fail closed agent-side.
            task = await TaskRepository(session).get_by_engine_task_id(
                project_id=rule.project_id,
                engine=engine,
                task_id=task_id,
            )
            if task is not None:
                payload["task_name"] = task.name

        try:
            await self._dispatcher.issue(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=rule.project_id,
                agent_id=agent_id if isinstance(agent_id, UUID) else UUID(str(agent_id)),
                action=command_action,
                target_type="task",
                target_id=f"{engine}:{task_id}",
                payload=payload,
                issued_by=rule.created_by,
                ip=None,
                user_agent=f"automation-rule:{rule.name}"[:1024],
                idempotency_key=f"automation:{rule.id}:{command_action}:{task_id}",
            )
        except AgentOfflineError:
            return "agent_offline"
        return "issued"

    async def _creator_may_act(self, session: Any, rule: Any) -> bool:
        """Is the rule's creator still authorized to fire this DESTRUCTIVE
        command on the project?

        Only called from :meth:`_command` (retry / cancel), which are
        destructive actions, so the floor is ADMIN -- the SAME floor
        ``api.automation_rules._authorize_write`` demands to create or
        re-arm a destructive rule. Requiring only OPERATOR here would let a
        creator demoted from ADMIN to OPERATOR keep firing a destructive
        rule they can no longer edit or re-arm.

        FAILS CLOSED on ``created_by IS NULL``: every automation rule is
        user-created (there is no system/declarative rule path), so a NULL
        owner means the creator was hard-deleted (the FK is ON DELETE SET
        NULL). Such an orphaned rule must NOT fire destructive commands
        with standing system authority. User-deletion also disables the
        rules up front (see ``disable_all_rules_created_by_user``); this is
        the defence-in-depth for the delete/fire race and any other path
        that could null the owner.
        """
        created_by = getattr(rule, "created_by", None)
        if created_by is None:
            return False
        membership = await MembershipRepository(session).get_for_user_project(
            user_id=created_by,
            project_id=rule.project_id,
        )
        if membership is None:
            return False
        return role_rank(membership.role) >= role_rank(ProjectRole.ADMIN)


def _notify_body(rule: Any, fields: dict[str, Any]) -> str:
    parts = [f"trigger={rule.trigger}"]
    if fields.get("task_name"):
        parts.append(f"task={fields['task_name']}")
    if fields.get("exception"):
        parts.append(f"exception={str(fields['exception'])[:200]}")
    return "; ".join(parts)


__all__ = ["AutomationActionRunner"]
