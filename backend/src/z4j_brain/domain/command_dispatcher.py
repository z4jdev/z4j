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

- The ``commands`` row INSERT and its issuance audit commit together.
  Registry delivery happens only after that commit.  A PostgreSQL
  ``NOTIFY`` is therefore a best-effort wake-up in a separate
  transaction, not part of the command write.  The durable
  ``status='pending'`` row is the recovery queue: a healthy
  PostgreSQL registry polls it every
  ``registry_reconcile_interval_seconds`` (validated to 1..600
  seconds), and reconnect/long-poll drains read it too.  A crash or
  failed wake-up can delay delivery until the next successful drain,
  but cannot erase the command.
- The ``mark_dispatched`` UPDATE has a ``WHERE status='pending'``
  guard so two workers racing to dispatch the same command cannot
  double-mark.
- ``CommandTimeoutWorker`` is the safety net: any command stuck in
  ``pending`` past ``timeout_at`` flips to ``timeout``.
- :meth:`CommandDispatcher.issue` COMMITS the caller's session, so it
  is the point at which a command becomes work an agent will run,
  and the end of the caller's write unit. A caller that decided the
  command was permitted by reading state (a hold, an enabled flag, a
  quota) must hold that read and this call inside ONE transaction,
  with whatever lock makes the read authoritative: a decision taken
  in an earlier transaction can be contradicted by a commit that
  lands in between, and this commit then makes the contradicted
  command durable anyway. Nothing here can check that for the caller,
  because only the caller knows what it decided on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

from z4j_brain.domain.retry_contract import required_retry_engine
from z4j_brain.errors import AgentOfflineError
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.repositories.commands import action_is_redeliverable

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


def _dispatch_is_fresh(dispatched_at: datetime | None, window_seconds: float) -> bool:
    """True if a DISPATCHED command was claimed within ``window_seconds``.

    A re-issue of a FRESHLY-dispatched command treats it as in-flight / delivered
    (do not re-send); an older one is orphaned and gets re-driven.
    """
    if dispatched_at is None:
        return False
    # SQLite returns naive timestamps; normalise to aware UTC before subtracting.
    aware = dispatched_at if dispatched_at.tzinfo else dispatched_at.replace(tzinfo=UTC)
    return (datetime.now(UTC) - aware).total_seconds() < window_seconds


class CommandDispatcher:
    """Operator → agent command issuance + result handling."""

    __slots__ = ("_audit", "_dashboard_hub", "_registry", "_settings")

    def __init__(
        self,
        *,
        settings: Settings,
        registry: BrainRegistry,
        audit: AuditService,
        dashboard_hub: DashboardHub | None = None,
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._audit = audit
        self._dashboard_hub = dashboard_hub

    @property
    def audit(self) -> AuditService:
        """The audit service backing this dispatcher.

        Exposed so the automation executor wired on the same connection
        can reuse it (rather than re-reading settings + secrets per
        event) while still writing audit rows through the one HMAC chain.
        """
        return self._audit

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
        except Exception:
            logger.exception(
                "z4j command_dispatcher: dashboard publish failed",
                project_id=str(project_id),
            )

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    async def deliver_persisted(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        """Publish a command that another transaction already persisted.

        Boundary D uses this only after its schedule, command, fire, change
        envelope, and audit evidence have committed atomically.
        """

        try:
            await self._registry.deliver(
                command_id=command_id,
                agent_id=agent_id,
                required_retry_engine=required_retry_engine(action, payload),
            )
        except Exception:
            logger.exception(
                "z4j command_dispatcher: persisted command delivery crashed",
                command_id=str(command_id),
                agent_id=str(agent_id),
            )

    async def deliver_frozen(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
        registry_owner_id: UUID,
        session_generation: str,
    ) -> bool:
        """Deliver only through one persisted WebSocket generation."""

        try:
            return await self._registry.deliver_frozen(
                command_id=command_id,
                agent_id=agent_id,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
            )
        except Exception:
            logger.exception(
                "z4j command_dispatcher: frozen command delivery crashed",
                command_id=str(command_id),
                agent_id=str(agent_id),
            )
            return False

    @property
    def command_timeout_seconds(self) -> int:
        """Configured command response bound used by preplanned operations."""

        return self._settings.command_timeout_seconds

    async def issue(  # noqa: PLR0911, PLR0912  status+freshness+at-most-once re-issue branches
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
        pre_completed_result: dict[str, Any] | None = None,
        enforce_payload_identity: bool = False,
    ) -> Command:
        """Persist a command and ask the registry to deliver it.

        Returns the freshly inserted command row. Status will be
        ``pending`` (no worker has the agent) or ``dispatched``
        (the registry pushed it locally - already updated by the
        ``deliver_local`` callback).

        The command + audit rows are committed before delivery so
        the ``deliver_local`` callback (which opens its own session)
        can read the command row.  Registry delivery and its optional
        PostgreSQL ``NOTIFY`` are post-commit wake-ups.  If that step
        crashes, the durable PENDING row remains eligible for registry
        reconciliation, reconnect drain, and long polling.  The commit
        ends the caller's write unit and releases every lock it was
        holding, so any invariant the caller checked has to have been
        checked in this same transaction, and nothing the caller does
        afterwards is still protected by it. See the module docstring's
        atomicity rules.

        M1: when ``pre_completed_result`` is supplied the command is COMPLETED
        in place with that result and NOT delivered to any agent (a brain-side
        synthetic success, e.g. the no-owned-match bulk-retry no-op). Still
        inserted + audited + committed so it is a durable, queryable record.
        """
        from z4j_brain.persistence.repositories import AgentRepository

        # This is the final authority edge shared by every generic issue()
        # caller. Selecting an online agent earlier is only a routing hint:
        # revocation may commit after that selection, and a failed best-effort
        # registry kick may leave the old socket available for delivery. Lock
        # the durable live row in the SAME transaction as command insert +
        # commit so either the command wins first or revoke wins and no new
        # work is made executable. Specialized cadence/external writers enforce
        # the same invariant inside CommandRepository and their planning edge.
        agent = await AgentRepository(commands.session).get_live(agent_id, lock=True)
        if agent is None or agent.project_id != project_id:
            raise AgentOfflineError(
                "agent is revoked or unavailable",
                details={"agent_id": str(agent_id)},
            )
        # Read under the same lock. A live agent with no WebSocket session on
        # this registry still receives the command (see the delivery below).
        agent_online = agent.state == AgentState.ONLINE

        timeout_at = datetime.now(UTC) + timedelta(
            seconds=self._settings.command_timeout_seconds,
        )
        command, created = await commands.insert(
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
            enforce_payload_identity=enforce_payload_identity,
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

        # M1 +: a synthetic success completes IN PLACE and is NOT
        # delivered. Do the completion in the SAME transaction as the insert and
        # commit ONCE, so no committed status=PENDING window is ever visible to a
        # concurrent long-poll/reconnect drain (H1: the no-op payload carries
        # task_ids=[], which an older RQ adapter reads as registry-sweep mode).
        # And complete ONLY a row WE created: on an idempotency-key collision the
        # existing row belongs to some OTHER request (possibly an in-flight
        # PENDING retry_task); marking it completed with our no-op result would
        # hijack it (H3). A genuine repeat no-op is already COMPLETED, so
        # returning it unchanged preserves idempotency.
        if pre_completed_result is not None:
            if created:
                await commands.mark_completed(command.id, result_payload=pre_completed_result)
            await commands.session.commit()
            await commands.session.refresh(command)
            return command

        # Commit the command + audit rows so that the deliver callback (which
        # opens its own session) can read the row.  This deliberately publishes
        # durable recovery authority BEFORE the best-effort registry wake-up:
        # PostgreSQL NOTIFY is not an outbox and uses another transaction.
        # Without this commit, the command is only flush()ed and invisible to
        # delivery and reconciliation readers.
        await commands.session.commit()

        # 4: an idempotent re-issue (same key) that returned an
        # EXISTING command is resolved by a STATUS + FRESHNESS decision, not the
        # blanket "any non-PENDING -> success" (which reported a FAILED/TIMEOUT
        # collision as delivered, and silently LOST a pushed-but-never-received
        # fire on replay). deliver_local claims via ``mark_dispatched WHERE
        # status=PENDING`` (0 rows for a non-PENDING row), so re-driving a
        # genuinely-delivered row would wedge -- hence we re-drive ONLY the
        # orphaned cases and short-circuit the rest.
        if not created:
            status = command.status
            if status in (
                CommandStatus.COMPLETED,
                CommandStatus.FAILED,
                CommandStatus.CANCELLED,
            ):
                # Terminal: the task already ran (or was cancelled). Returning it
                # is idempotent (preserves the catch-up drain); re-delivery
                # would risk a double-execution.
                return command
            if status == CommandStatus.DISPATCHED and _dispatch_is_fresh(
                command.dispatched_at,
                getattr(self._settings, "agent_longpoll_redispatch_seconds", 60.0),
            ):
                # DISPATCHED == physically delivered while FRESH: either
                # genuinely delivered, or a concurrent deliver is mid-push (the
                # P2-1 claim-race winner). Return without re-sending.
                return command
            if status in (CommandStatus.DISPATCHED, CommandStatus.TIMEOUT):
                # ORPHANED: a stale-DISPATCHED (pushed but no result came back) or
                # a TIMEOUT.
                #
                # (At-most-once for destructive): re-driving here is only
                # safe when re-EXECUTION is safe. "No result observed" does NOT
                # prove "the action did not execute" -- the agent may have run it
                # and only the result frame was lost. For a NON-idempotent action
                # (purge_queue / restart_worker / retry_task / bulk_retry /
                # requeue_dead_letter) a re-drive would double-execute a
                # side-effecting operation, so we DO NOT re-drive: return the row
                # as-is (ambiguous outcome; the CommandTimeoutWorker retires it).
                # Cadence fires (deduped on fire_id) and idempotent actions
                # (cancel / reconcile) remain re-drivable so a genuinely-lost
                # delivery still recovers.
                if not action_is_redeliverable(command.action):
                    return command
                # Re-drive ONCE: revert to PENDING with a fresh timeout and
                # re-deliver.: the revert is a compare-and-swap on the
                # OBSERVED dispatched_at so a concurrent rearm+redispatch is not
                # clobbered (ABA).: transfer ownership to the (possibly
                # re-picked) target agent so an agent-scoped ack can terminalize
                # the row instead of it wedging under the offline original owner.
                reverted = await commands.revert_dispatch(
                    command.id,
                    timeout_seconds=self._settings.command_timeout_seconds,
                    expected_dispatched_at=command.dispatched_at,
                    new_agent_id=agent_id,
                )
                await commands.session.commit()
                await commands.session.refresh(command)
                if not reverted:
                    # Concurrently advanced to terminal, or the CAS lost to a
                    # concurrent rearm+redispatch; treat as done / in-flight.
                    return command
            # PENDING (fresh, or just reverted) falls through to delivery.
            # A PENDING fire returned from an idempotency-collision may
            # still be owned by an agent that went offline before it was ever
            # dispatched, while a DIFFERENT agent was re-picked for this delivery.
            # Transfer ownership to the target so the target's agent-scoped ack can
            # terminalize it (mirrors the DISPATCHED/TIMEOUT transfer).
            # Status-guarded to PENDING; a no-op when the owner already matches
            # (every operator command, which conflicts on an agent mismatch at
            # insert). Only reached on the re-issue path (not created).
            elif command.agent_id != agent_id:
                await commands.reassign_pending_owner(command.id, new_agent_id=agent_id)
                await commands.session.commit()
                await commands.session.refresh(command)

        # Ask the registry to deliver. The local fast path
        # (synchronous push + UPDATE status='dispatched') happens
        # inside ``deliver`` via the ``deliver_local`` callback the
        # gateway gave the registry at startup. The slow path is
        # NOTIFY → some other worker picks it up.
        try:
            result = await self._registry.deliver(
                command_id=command.id,
                agent_id=agent_id,
                # An idempotency collision returns the immutable existing row.
                # Gate the session against the exact command the delivery
                # callback will reload and sign, never the re-issuer's input.
                required_retry_engine=required_retry_engine(
                    command.action,
                    command.payload,
                ),
            )
        except Exception:
            logger.exception(
                "z4j command_dispatcher: registry wake-up failed; "
                "durable pending-command reconciliation will retry",
                command_id=str(command.id),
                agent_id=str(agent_id),
            )
            result = None

        if result is not None and not result.delivered_locally and not result.notified_cluster:
            # Edge case: deliver returned but neither path fired.
            # Before surfacing agent-offline, re-read the row. A
            # CONCURRENT deliver (another worker / a long-poll redispatch) may have
            # WON the ``mark_dispatched WHERE status=PENDING`` claim and already
            # pushed the command -- in which case this caller's local claim simply
            # lost the race and the command IS on its way. Reporting AgentOffline
            # here would write a spurious failed-fire record for a delivered
            # command. If the row is now DISPATCHED/terminal, return it as success
            # WITHOUT re-delivering. Only a still-PENDING row is genuinely offline.
            await commands.session.refresh(command)
            if command.status != CommandStatus.PENDING:
                return command
            # No WebSocket session holds the agent here, yet the agent is live:
            # it polls (the long-poll transport claims committed PENDING rows)
            # or is reconnecting (the reconnect drain delivers them). The
            # command will run, so it stays pending, as behind a cluster
            # NOTIFY. Reporting it offline would invite a second attempt.
            if result.agent_was_known or not agent_online:
                # Offline, or connected only through sessions that cannot take
                # this command: surface a clean error to the caller. The row
                # stays pending; the timeout sweeper cleans up.
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
        except Exception:
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
        transport_kind: str | None = None,
        registry_owner_id: UUID | None = None,
        session_generation: str | None = None,
        delivery_claim_token: str | None = None,
    ) -> None:
        """Mark a command as dispatched.

        Idempotent: a duplicate ACK is a no-op (the
        ``mark_dispatched`` SQL has a ``WHERE status='pending'``
        guard).
        """
        from z4j_brain.domain.schedule_fire_authority import (
            SCHEDULE_FIRE_PROTOCOL_MARKER,
        )

        candidate = await commands.get_for_dispatch(command_id)
        if candidate is not None and candidate.action == "schedule.external.control":
            if project_id is None or agent_id is None:
                return
            from z4j_brain.persistence.repositories.schedule_external import (
                ScheduleExternalRepository,
            )

            await ScheduleExternalRepository(
                commands.session,
            ).acknowledge_control_delivery(
                command_id=command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                delivery_claim_token=delivery_claim_token,
                occurred_at=datetime.now(UTC),
            )
            return
        if (
            candidate is not None
            and candidate.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        ):
            if project_id is None or agent_id is None:
                return
            from z4j_brain.persistence.repositories.schedule_control import (
                ScheduleControlRepository,
            )

            await ScheduleControlRepository(
                commands.session,
            ).acknowledge_current_agent_delivery(
                command_id=command_id,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                delivery_claim_token=delivery_claim_token,
                occurred_at=datetime.now(UTC),
            )
            return
        await commands.mark_dispatched(
            command_id,
            timeout_seconds=self._settings.command_timeout_seconds,
            project_id=project_id,
            agent_id=agent_id,
        )

    async def handle_result(  # noqa: PLR0911, PLR0912 - protocol routing
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
        transport_kind: str | None = None,
        registry_owner_id: UUID | None = None,
        session_generation: str | None = None,
        delivery_claim_token: str | None = None,
    ) -> None:
        """Apply one authenticated terminal result from an agent.

        A first accepted transition is audited exactly once.  Replays, late
        results, authority mismatches, non-pending commands, and unknown command
        ids append no audit rows: the existing command state and any original
        terminal audit are the durable evidence for known commands, while
        attacker-controlled rejected frames must not amplify the append-only
        audit chain.  Terminal replays increment only the fixed-cardinality
        late-result metric.

        ``status`` is one of ``"success"`` / ``"failed"``. ``TIMEOUT`` is
        deliberately distinct from ``FAILED``, but it is brain-owned state:
        :class:`CommandTimeoutWorker` applies it only when no result arrived by
        the durable deadline. An agent cannot report it directly.
        """
        from z4j_brain.domain.schedule_fire_authority import (
            SCHEDULE_FIRE_PROTOCOL_MARKER,
        )

        if status not in ("success", "failed"):
            # The wire schema rejects this before dispatch.  Keep the domain
            # boundary fail-closed for direct/internal callers too, without
            # copying attacker-controlled status strings into an audit or
            # metric label.
            return

        candidate = await commands.get_for_dispatch(command_id)
        if candidate is not None and candidate.action == "schedule.external.control":
            if project_id is None or agent_id is None:
                return
            from z4j_brain.persistence.repositories.schedule_external import (
                ScheduleExternalRepository,
            )

            external_transition = await ScheduleExternalRepository(
                commands.session,
            ).apply_control_result(
                command_id=command_id,
                project_id=project_id,
                agent_id=agent_id,
                status=status,
                result_payload=result_payload,
                error=error,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                delivery_claim_token=delivery_claim_token,
                occurred_at=datetime.now(UTC),
            )
            if external_transition.disposition in {
                "result_recorded",
                "ambiguous",
            }:
                operation = external_transition.operation
                command = external_transition.command
                await self._audit.record(
                    audit_log,
                    action=(
                        "schedule.external_control.result"
                        if external_transition.disposition == "result_recorded"
                        else "schedule.external_control.ambiguous"
                    ),
                    target_type="schedule",
                    target_id=(
                        str(operation.schedule_id) if operation is not None else candidate.target_id
                    ),
                    result=status,
                    outcome=(
                        "allow"
                        if external_transition.disposition == "result_recorded"
                        else "failure"
                    ),
                    project_id=project_id,
                    metadata={
                        "command_id": str(command_id),
                        "operation_id": (str(operation.id) if operation is not None else None),
                        "agent_id": (
                            str(command.agent_id)
                            if command is not None and command.agent_id is not None
                            else str(agent_id)
                        ),
                        "projection_authoritative": False,
                        "error": error,
                    },
                )
            return
        if (
            candidate is not None
            and candidate.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        ):
            if project_id is None or agent_id is None:
                return
            from z4j_brain.persistence.repositories.schedule_control import (
                ScheduleControlRepository,
            )

            cadence_transition = await ScheduleControlRepository(
                commands.session,
            ).apply_current_agent_result(
                command_id=command_id,
                project_id=project_id,
                agent_id=agent_id,
                status=status,
                result_payload=result_payload,
                error=error,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                delivery_claim_token=delivery_claim_token,
                occurred_at=datetime.now(UTC),
            )
            command = cadence_transition.command
            if cadence_transition.command_transitioned and command is not None:
                succeeded = status == "success"
                await self._audit.record(
                    audit_log,
                    action=("command.completed" if succeeded else "command.failed"),
                    target_type=command.target_type,
                    target_id=command.target_id,
                    result="success" if succeeded else "failed",
                    outcome="allow" if succeeded else "failure",
                    project_id=command.project_id,
                    metadata={
                        "command_id": str(command_id),
                        "agent_id": str(command.agent_id),
                        "error": error,
                        "cadence_hold_created": cadence_transition.hold_created,
                    },
                )
            return

        if candidate is None:
            # There is no trusted project/target context for an audit row.
            return
        if (project_id is not None and candidate.project_id != project_id) or (
            agent_id is not None and candidate.agent_id != agent_id
        ):
            # An authenticated agent can still guess another command id.  The
            # guarded UPDATE below would reject it too, but rejecting before a
            # write attempt makes the no-audit/no-amplification policy explicit.
            return

        if status == "success":
            transitioned = await commands.mark_completed(
                command_id,
                result_payload=result_payload,
                project_id=project_id,
                agent_id=agent_id,
            )
            outcome = "allow"
            audit_action = "command.completed"
            audit_result = "success"
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
            audit_result = "failed"
        if not transitioned:
            # Race or replay. Refresh so a concurrent winner is classified from
            # durable state.  Do not append an audit row or emit one log record
            # per rejected frame: a compromised agent could otherwise amplify
            # append-only/operator storage.  Only a bounded-label metric tracks
            # results that arrived after a terminal transition.
            await commands.session.refresh(candidate)
            if candidate.status in {
                CommandStatus.COMPLETED,
                CommandStatus.FAILED,
                CommandStatus.TIMEOUT,
                CommandStatus.CANCELLED,
            }:
                try:
                    from z4j_brain.api.metrics import (
                        z4j_command_late_results_total,
                    )

                    z4j_command_late_results_total.labels(status=status).inc()
                except Exception:
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
            result=audit_result,
            outcome=outcome,
            project_id=command.project_id,
            metadata={
                "command_id": str(command_id),
                "agent_id": (str(command.agent_id) if command.agent_id else None),
                "error": error,
            },
        )

        if command.bulk_retry_child_id is not None:
            # Project the authenticated result in this same transaction.  This
            # also refines a prior UNKNOWN child after a late result; delivery
            # state remains irreversibly claimed.
            from z4j_brain.persistence.repositories import (
                BulkRetryRequestRepository,
            )

            await BulkRetryRequestRepository(commands.session).reconcile_command_outcomes(
                limit=1, command_id=command_id
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
        if not isinstance(engine_state, str) or engine_state == "unknown":
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
            # Staleness anchor: the probe cannot have observed
            # anything newer than its own issuance, so a task row
            # written after ``issued_at`` outranks a non-terminal
            # probe response.
            probe_issued_at=command.issued_at,
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
            # ``task.orphaned`` emit site: the task was stuck non-terminal
            # (started-but-never-finished; the terminal event was lost) and
            # reconciliation just confirmed + applied the engine's terminal
            # truth. ``apply_reconciled_state`` returns True exactly once
            # per correction (a replayed probe result is a no-op), so this
            # fires once per orphan episode with no extra dedup ledger.
            # Only TERMINAL outcomes count as an orphan: a probe that finds
            # the task legitimately still pending/started is not one. The
            # ``task.reconciled`` audit row above is the durable detection
            # record; rule firing is a best-effort side effect of it, same
            # isolation the misfire detector uses.
            if engine_state in ("success", "failure"):
                try:
                    await self._fire_orphaned_automation(
                        commands=commands,
                        command=command,
                        engine=engine,
                        task_id=task_id,
                        engine_state=engine_state,
                    )
                except Exception:
                    await commands.session.rollback()
                    logger.exception(
                        "z4j reconciliation: task.orphaned automation failed "
                        "(reconciliation audited; not re-run)",
                        task_id=task_id,
                        project_id=str(command.project_id),
                    )

    async def _fire_orphaned_automation(
        self,
        *,
        commands: CommandRepository,
        command: Command,
        engine: str,
        task_id: str,
        engine_state: str,
    ) -> None:
        """Run ``task.orphaned`` automation rules for one corrected task.

        Reuses the caller's session AFTER the reconciliation commit.

        "Clean at this point" is true of the ORM and false of Boundary F. The
        commit ended the audited write unit, so on SQLite the first rule to
        fire raised when it wrote its ``automation.rule.fired`` audit row, and
        the caller swallows that exception: the correction was audited, the
        rule never fired, and no notification went out. Re-arm the unit before
        reading, exactly as the write paths do.

        ``run_matching`` owns its own per-rule transaction boundary and the
        per-project kill-switch check, exactly as on the task-event path.
        """
        from sqlalchemy import text as _text

        if commands.session.get_bind().dialect.name == "sqlite":
            if commands.session.in_transaction():
                await commands.session.rollback()
            await commands.session.execute(_text("BEGIN IMMEDIATE"))
            commands.session.sync_session.info["z4j_sqlite_immediate"] = True
        from z4j_brain.domain.automation import (
            AutomationActionRunner,
            AutomationExecutor,
        )
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            AutomationRuleRepository,
            TaskRepository,
        )

        task_repo = TaskRepository(commands.session)
        # Identity-map hit: apply_reconciled_state just loaded this row.
        task = await task_repo.get_by_engine_task_id(
            project_id=command.project_id,
            engine=engine,
            task_id=task_id,
        )
        priority = await task_repo.get_priority_label(
            project_id=command.project_id,
            engine=engine,
            task_id=task_id,
        )
        fields: dict[str, Any] = {
            "task_id": task_id,
            "task_name": task.name if task is not None else None,
            "engine": engine,
            "queue": task.queue if task is not None else None,
            "priority": priority,
            "exception": task.exception if task is not None else None,
            "runtime_ms": None,
            # The agent that answered the probe is the command target for
            # retry / cancel actions.
            "agent_id": command.agent_id,
            # Extra context for notify templates: what the engine said.
            "engine_state": engine_state,
        }
        executor = AutomationExecutor(
            audit=self._audit,
            runner=AutomationActionRunner(dispatcher=self),
        )
        await executor.run_matching(
            session=commands.session,
            rules_repo=AutomationRuleRepository(commands.session),
            audit_log=AuditLogRepository(commands.session),
            project_id=command.project_id,
            trigger="task.orphaned",
            fields=fields,
            now=datetime.now(UTC),
            notify_coalesce_seconds=self._settings.automation_notify_coalesce_seconds,
        )


__all__ = ["CommandDispatcher"]
