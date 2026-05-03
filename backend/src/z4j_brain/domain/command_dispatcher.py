"""Brain-side command dispatcher.

Different from the agent's :class:`z4j_bare.dispatcher.CommandDispatcher`
(which routes inbound commands to engine adapters). The brain-side
dispatcher does the OPPOSITE direction: an operator clicks "retry"
in the dashboard → this class persists the command, signs it, and
asks the registry to deliver it to whichever worker holds the
agent's WebSocket.

Public surface:

- :meth:`issue` - operator-initiated. Inserts the row, asks the
  registry to deliver, audits, returns the command.
- :meth:`handle_ack` - called from the frame router when an agent
  ACKs a command frame. Updates ``commands.dispatched_at``.
- :meth:`handle_result` - called when an agent returns a result.
  Updates ``status`` + ``result`` + ``error``.

Atomicity rules:

- The ``commands`` row INSERT and the NOTIFY publish happen in the
  same transaction. NOTIFY only fires on COMMIT, so if the INSERT
  rolls back the NOTIFY never fires.
- The ``mark_dispatched`` UPDATE has a ``WHERE status='pending'``
  guard so two workers racing to dispatch the same command cannot
  double-mark.
- ``CommandTimeoutWorker`` is the safety net: any command stuck in
  ``pending`` past ``timeout_at`` flips to ``timeout``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

from z4j_brain.errors import AgentOfflineError

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import Command
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        CommandRepository,
    )
    from z4j_brain.settings import Settings
    from z4j_brain.websocket.dashboard_hub import DashboardHub
    from z4j_brain.websocket.registry import BrainRegistry


logger = structlog.get_logger("z4j.brain.command_dispatcher")


class CommandDispatcher:
    """Operator → agent command issuance + result handling."""

    __slots__ = ("_settings", "_registry", "_audit", "_dashboard_hub")

    def __init__(
        self,
        *,
        settings: Settings,
        registry: BrainRegistry,
        audit: AuditService,
        dashboard_hub: "DashboardHub | None" = None,
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._audit = audit
        self._dashboard_hub = dashboard_hub

    # ------------------------------------------------------------------
    # Dashboard fan-out
    # ------------------------------------------------------------------

    async def notify_dashboard_command_change(
        self,
        project_id: UUID,
    ) -> None:
        """Publish a ``command.changed`` topic for one project.

        Called by command-issuing route handlers AFTER they commit
        the inserted row. Routes call this rather than the hub
        directly so they don't have to depend on the hub abstraction.
        Failures are swallowed - a missed dashboard ping is never
        worth turning into a 500.
        """
        if self._dashboard_hub is None:
            return
        try:
            await self._dashboard_hub.publish_command_change(project_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j command_dispatcher: dashboard publish failed",
                project_id=str(project_id),
            )

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    async def issue(
        self,
        *,
        commands: CommandRepository,
        audit_log: AuditLogRepository,
        project_id: UUID,
        agent_id: UUID,
        action: str,
        target_type: str,
        target_id: str | None,
        payload: dict[str, Any],
        issued_by: UUID | None,
        ip: str | None,
        user_agent: str | None,
        idempotency_key: str | None = None,
    ) -> Command:
        """Persist a command and ask the registry to deliver it.

        Returns the freshly inserted command row. Status will be
        ``pending`` (no worker has the agent) or ``dispatched``
        (the registry pushed it locally - already updated by the
        ``deliver_local`` callback).

        The command + audit rows are committed before delivery so
        the ``deliver_local`` callback (which opens its own session)
        can read the command row.
        """
        timeout_at = datetime.now(UTC) + timedelta(
            seconds=self._settings.command_timeout_seconds,
        )
        command = await commands.insert(
            project_id=project_id,
            agent_id=agent_id,
            issued_by=issued_by,
            action=action,
            target_type=target_type,
            target_id=target_id,
            payload=payload,
            idempotency_key=idempotency_key,
            timeout_at=timeout_at,
            source_ip=ip,
        )

        # Audit BEFORE deliver - the audit row is the durable
        # record. Even if the deliver crashes, the issuance is
        # logged.
        await self._audit.record(
            audit_log,
            action=f"command.issue.{action}",
            target_type=target_type,
            target_id=target_id,
            result="success",
            outcome="allow",
            user_id=issued_by,
            project_id=project_id,
            source_ip=ip,
            user_agent=user_agent,
            metadata={
                "command_id": str(command.id),
                "agent_id": str(agent_id),
                "idempotency_key": idempotency_key,
            },
        )

        # Commit the command + audit rows so that the deliver
        # callback (which opens its own session) can read the row.
        # Without this, the command is only flush()ed and invisible
        # to other transactions.
        await commands.session.commit()

        # Ask the registry to deliver. The local fast path
        # (synchronous push + UPDATE status='dispatched') happens
        # inside ``deliver`` via the ``deliver_local`` callback the
        # gateway gave the registry at startup. The slow path is
        # NOTIFY → some other worker picks it up.
        try:
            result = await self._registry.deliver(
                command_id=command.id,
                agent_id=agent_id,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j command_dispatcher: registry deliver crashed",
                command_id=str(command.id),
                agent_id=str(agent_id),
            )
            result = None

        if result is not None and not result.delivered_locally and not result.notified_cluster:
            # Edge case: deliver returned but neither path fired.
            # The registry treats unknown agents this way. Surface
            # a clean error to the caller - the row stays pending,
            # the timeout sweeper handles cleanup.
            raise AgentOfflineError(
                "agent is not connected",
                details={"agent_id": str(agent_id)},
            )

        # Refresh the row from the session - the deliver_local
        # callback may have UPDATEd it to dispatched while the
        # row object was still in the session identity map.
        await commands.session.refresh(command)

        # Prometheus counter. Best-effort: must not block the
        # dispatch pipeline. ``record_swallowed`` keeps a meta-
        # metric on any registry hiccup.
        try:
            from z4j_brain.api.metrics import z4j_commands_total

            z4j_commands_total.labels(
                project=str(project_id),
                action=action,
                status="dispatched" if result and result.delivered_locally else "pending",
            ).inc()
        except Exception:  # noqa: BLE001
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("command_dispatcher", "counter_inc")

        return command

    # ------------------------------------------------------------------
    # Inbound frame handling
    # ------------------------------------------------------------------

    async def handle_ack(
        self,
        *,
        commands: CommandRepository,
        command_id: UUID,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> None:
        """Mark a command as dispatched.

        Idempotent: a duplicate ACK is a no-op (the
        ``mark_dispatched`` SQL has a ``WHERE status='pending'``
        guard).
        """
        await commands.mark_dispatched(
            command_id,
            project_id=project_id,
            agent_id=agent_id,
        )

    async def handle_result(
        self,
        *,
        commands: CommandRepository,
        audit_log: AuditLogRepository,
        command_id: UUID,
        status: str,
        result_payload: dict[str, Any] | None,
        error: str | None,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> None:
        """Mark a command completed or failed based on the agent's reply.

        Audits the outcome regardless. ``status`` from the agent
        is one of ``"success"`` / ``"failed"`` / ``"timeout"`` -
        we map to the brain enum.
        """
        if status == "success":
            transitioned = await commands.mark_completed(
                command_id,
                result_payload=result_payload,
                project_id=project_id,
                agent_id=agent_id,
            )
            outcome = "allow"
            audit_action = "command.completed"
        else:
            transitioned = await commands.mark_failed(
                command_id,
                error=(error or "agent reported failure"),
                result_payload=result_payload,
                project_id=project_id,
                agent_id=agent_id,
            )
            # v1.1.0: was ``outcome="deny"`` pre-1.1, which conflated
            # real authorization-denied audit rows with mere
            # execution failures. ``deny`` is now reserved for
            # actual policy rejections; ``failure`` flags an
            # authorised-but-failed command so security dashboards
            # don't flag routine task crashes as access denials.
            outcome = "failure"
            audit_action = "command.failed"

        if not transitioned:
            # Race or replay: the command was already terminal,
            # almost always because the timeout sweeper transitioned
            # it to TIMEOUT before the agent's late result arrived
            # (R3 finding M7 - operator-visible "X seems to have
            # timed out but actually finished" signal). We log + bump
            # a metric so operators can see how often this happens
            # and tune ``command_timeout_seconds`` if needed.
            logger.info(
                "z4j command_dispatcher: result for non-pending command, ignoring",
                command_id=str(command_id),
                status=status,
            )
            try:
                from z4j_brain.api.metrics import (
                    z4j_command_late_results_total,
                )

                z4j_command_late_results_total.labels(status=status).inc()
            except Exception:  # noqa: BLE001
                from z4j_brain.api.metrics import record_swallowed

                record_swallowed("command_dispatcher", "late_result_metric")
            return

        # Look up the command for the audit row context.
        command = await commands.get_for_dispatch(command_id)
        if command is None:
            return

        await self._audit.record(
            audit_log,
            action=audit_action,
            target_type=command.target_type,
            target_id=command.target_id,
            result=("success" if status == "success" else "failed"),
            outcome=outcome,
            project_id=command.project_id,
            metadata={
                "command_id": str(command_id),
                "agent_id": (
                    str(command.agent_id) if command.agent_id else None
                ),
                "error": error,
            },
        )

        # Reconciliation post-processing: when a ``reconcile_task``
        # command comes back successful, the result dict carries the
        # adapter's view of the engine's authoritative state. Apply
        # that back to the ``tasks`` row so a stuck "started forever"
        # task gets corrected. The normal command path does NOT do
        # this - for retry/cancel/etc. the adapter emits a separate
        # lifecycle event that the EventIngestor handles.
        if (
            status == "success"
            and command.action == "reconcile_task"
            and result_payload is not None
        ):
            await self._apply_reconciliation_result(
                commands=commands,
                audit_log=audit_log,
                command=command,
                result_payload=result_payload,
            )

    async def _apply_reconciliation_result(
        self,
        *,
        commands: CommandRepository,
        audit_log: AuditLogRepository,
        command: Command,
        result_payload: dict[str, Any],
    ) -> None:
        """Project a ``reconcile_task`` CommandResult onto ``tasks``.

        Security note (audit H3): the ``engine`` and ``task_id`` are
        sourced *only* from the brain-issued command, never from the
        agent-supplied result payload. A compromised agent that
        replied with a different ``(engine, task_id)`` pair could
        otherwise corrupt the state of any task in its project that
        it knew the id of. ``engine_state`` (the only field we
        actually trust the agent on) is bounded by the canonical
        enum mapping in ``apply_reconciled_state``.
        """
        from datetime import datetime as _dt

        from z4j_brain.persistence.repositories import TaskRepository

        engine_state = result_payload.get("engine_state")
        if engine_state in (None, "unknown"):
            return

        # Anchored to command, NOT result_payload - see audit H3.
        engine = (command.payload or {}).get("engine")
        task_id = command.target_id
        if not engine or not task_id:
            return

        finished_raw = result_payload.get("finished_at")
        finished_at: _dt | None = None
        if isinstance(finished_raw, str):
            try:
                finished_at = _dt.fromisoformat(
                    finished_raw.replace("Z", "+00:00"),
                )
            except ValueError:
                finished_at = None

        tasks = TaskRepository(commands.session)
        changed = await tasks.apply_reconciled_state(
            project_id=command.project_id,
            engine=engine,
            task_id=task_id,
            engine_state=engine_state,
            finished_at=finished_at,
            exception_text=result_payload.get("exception"),
        )
        if changed:
            await self._audit.record(
                audit_log,
                action="task.reconciled",
                target_type="task",
                target_id=task_id,
                result="success",
                outcome="allow",
                project_id=command.project_id,
                metadata={
                    "command_id": str(command.id),
                    "engine_state": engine_state,
                    "engine": engine,
                },
            )
            await commands.session.commit()
            logger.info(
                "z4j reconciliation: task state corrected",
                task_id=task_id,
                engine_state=engine_state,
                project_id=str(command.project_id),
            )


__all__ = ["CommandDispatcher"]
