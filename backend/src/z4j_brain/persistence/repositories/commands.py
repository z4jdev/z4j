"""``commands`` repository."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import DateTime, and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_core.errors import AgentOfflineError, ConflictError

from z4j_brain.domain.schedule_fire_authority import (
    SCHEDULE_FIRE_PROTOCOL_MARKER,
)
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    Command,
    Schedule,
    ScheduleExternalControlOperation,
    ScheduleExternalStream,
)
from z4j_brain.persistence.repositories._base import BaseRepository
from z4j_brain.persistence.schedule_external_guard import (
    arm_external_control_transition,
    assert_external_control_consumed,
)

#: The scheduler-fire command action (mirror of ``handlers._FIRE_ACTION``).
#: A fire's idempotency key is ``schedule:{schedule_id}:fire:{fire_id}`` and
#: already fully identifies the fire, so its collision check excludes agent_id
#: (a legit HA/timeout re-fire may re-pick a different online agent) and payload
#: (a re-fire carries a different ``fired_at``). See ``insert``.
_FIRE_ACTION = "schedule.fire"
_EXTERNAL_ACTIVATION_ACTION = "schedule.external.activate"
_EXTERNAL_CONTROL_ACTION = "schedule.external.control"

#: Payload keys that legitimately differ between two otherwise-identical
#: idempotent re-issues and so are excluded from the payload-identity check.
_VOLATILE_PAYLOAD_KEYS: frozenset[str] = frozenset({"fired_at"})

#: (At-most-once for destructive): a DISPATCHED/TIMEOUT command whose
#: delivery outcome is UNKNOWN (no result came back) is re-driven / re-delivered
#: ONLY when re-execution is safe. These actions are NON-idempotent: re-running
#: one after it silently succeeded (its result frame lost) double-executes a
#: side-effecting operation (a second queue purge, a second worker restart, a
#: second task submission). For them the recovery path must NOT blind-redrive --
#: it surfaces the ambiguous outcome instead (the row stays as-is and the
#: CommandTimeoutWorker retires it). Everything ELSE (cadence fires -- deduped on
#: fire_id -- and idempotent actions such as cancel/reconcile) stays redeliverable
#: so a genuinely-lost delivery still recovers. New actions default to
#: redeliverable; add a non-idempotent verb here explicitly.
#: An ALLOWLIST, not a denylist -- redeliverability now FAILS CLOSED.
#: Only actions PROVEN safe to re-drive when their outcome is unknown are listed;
#: everything else (including any new / unknown verb, and the config / consumer
#: ops) is treated as non-idempotent and NOT re-driven, so a mistake defaults to
#: at-most-once rather than to double-executing a side effect. The denylist
#: failed OPEN -- it omitted schedule.trigger_now, pool resizes, add_consumer, and
#: schedule config ops, which are non-idempotent but were silently re-drivable.
#:
#: The two safe classes are: (1) cadence + manual FIRES (deduped on fire_id, and
#: -- on command_id in the agent's DURABLE dedup, so a re-drive across an
#: agent restart is a no-op, not a second run); (2) genuinely IDEMPOTENT verbs
#: (cancel a task, reconcile its state, resync the schedule snapshot, enable /
#: disable a schedule) whose repeat is a no-op. Anything not proven to belong here
#: stays at-most-once.
#: schedule.enable / schedule.disable are DESIRED-STATE ops -- the agent
#: sets the schedule enabled/disabled and a repeat is a no-op -- but they were
#: issued with idempotency_key=None and were NOT allowlisted, so a dropped
#: (delivered-but-unacked) disable was never re-driven while the brain
#: optimistically showed it disabled: the schedule kept firing. They are safe to
#: re-drive, so they belong in class (2).
_REDELIVERABLE_ACTIONS: frozenset[str] = frozenset(
    {
        "schedule.fire",
        "schedule.trigger_now",
        "schedule.trigger_now.via_scheduler",
        "cancel_task",
        "reconcile_task",
        "schedule.resync",
        "schedule.enable",
        "schedule.disable",
    }
)


def action_is_redeliverable(action: str) -> bool:
    """True ONLY for an explicitly-allowlisted action that is safe
    to re-deliver / re-drive when its delivery outcome is unknown. Fails CLOSED --
    an unknown or non-idempotent verb is NOT re-driven (at-most-once), so the
    ambiguous outcome is surfaced instead of a possible double side effect."""
    return action in _REDELIVERABLE_ACTIONS


async def _database_now(session: AsyncSession) -> datetime:
    """Read a wall-clock generation from the database, never this process.

    PostgreSQL ``CURRENT_TIMESTAMP`` is fixed at transaction start, which is
    unsuitable for leases in a long-running transaction. ``clock_timestamp``
    advances in real time. SQLite's fractional ``strftime`` is the equivalent
    connection-local database clock and avoids its one-second
    ``CURRENT_TIMESTAMP`` resolution. Other supported/test dialects fall back
    to their typed ``CURRENT_TIMESTAMP``.
    """
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        expression = func.clock_timestamp(type_=DateTime(timezone=True))
    elif dialect == "sqlite":
        expression = func.strftime(
            "%Y-%m-%d %H:%M:%f",
            "now",
            type_=DateTime(timezone=True),
        )
    else:
        expression = func.current_timestamp(type_=DateTime(timezone=True))
    observed = cast("datetime | None", await session.scalar(select(expression)))
    if observed is None:
        raise RuntimeError("database did not return a timestamp for command lease")
    return observed if observed.tzinfo is not None else observed.replace(tzinfo=UTC)


def _canonical_payload(payload: dict[str, Any] | None) -> str:
    """A stable string identity for a command payload, minus volatile keys."""
    stable = {k: v for k, v in (payload or {}).items() if k not in _VOLATILE_PAYLOAD_KEYS}
    # Retry's public identity is its relative ``eta_seconds`` request. ``eta``
    # is the absolute wire deadline derived from the request clock, so it will
    # differ when the same idempotency key is replayed. Ignore only that
    # derivative when its stable source field is present; a different
    # ``eta_seconds`` still conflicts, and a caller that supplies only an
    # absolute ``eta`` still has that value included in identity.
    if stable.get("eta_seconds") is not None:
        stable.pop("eta", None)
    return json.dumps(stable, sort_keys=True, default=str)


def _same_datetime(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return left is right
    left_utc = left.replace(tzinfo=UTC) if left.tzinfo is None else left.astimezone(UTC)
    right_utc = right.replace(tzinfo=UTC) if right.tzinfo is None else right.astimezone(UTC)
    return left_utc == right_utc


class CommandRepository(BaseRepository[Command]):
    """Command CRUD + state transitions."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Command)

    async def _lock_live_agent(self, *, project_id: UUID, agent_id: UUID) -> bool:
        """Lock the durable command target in the caller's established order."""
        live = (
            await self.session.execute(
                select(Agent.id)
                .where(
                    Agent.id == agent_id,
                    Agent.project_id == project_id,
                    Agent.revoked_at.is_(None),
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        return live is not None

    async def _require_live_agent(self, *, project_id: UUID, agent_id: UUID) -> None:
        """Lock the durable command target or fail before inserting work."""
        if not await self._lock_live_agent(project_id=project_id, agent_id=agent_id):
            raise AgentOfflineError(
                "agent is revoked or unavailable",
                details={"agent_id": str(agent_id)},
            )

    # ------------------------------------------------------------------
    # Inserts
    # ------------------------------------------------------------------

    async def insert_current_schedule_fire(
        self,
        *,
        project_id: UUID,
        agent_id: UUID,
        schedule_id: UUID,
        fire_id: UUID,
        scheduled_for: datetime,
        observed_control_token: UUID | None,
        receipt_control_token: UUID,
        execution_fire_id: UUID,
        acceptance_revision: int,
        definition_digest: str,
        expected_revision: int,
        expected_last_run_at: datetime | None,
        expected_next_run_at: datetime,
        prepared_next_run_at: datetime | None,
        payload: dict[str, Any],
        timeout_at: datetime,
        initial_claim_deadline: datetime,
    ) -> tuple[Command, bool]:
        """Insert/reuse one complete receipt-bound cadence command."""

        await self._require_live_agent(project_id=project_id, agent_id=agent_id)
        if payload.get("fire_id") != str(execution_fire_id):
            raise ValueError("cadence command payload lacks its execution fire identity")
        idempotency_key = f"schedule:{schedule_id}:fire:{fire_id}:receipt:{receipt_control_token}"
        row = Command(
            project_id=project_id,
            agent_id=agent_id,
            issued_by=None,
            action=_FIRE_ACTION,
            target_type="schedule",
            target_id=str(schedule_id),
            payload=payload,
            idempotency_key=idempotency_key,
            status=CommandStatus.PENDING,
            timeout_at=timeout_at,
            source_ip=None,
            schedule_protocol_marker=SCHEDULE_FIRE_PROTOCOL_MARKER,
            schedule_state_nonce=uuid4(),
            schedule_id=schedule_id,
            schedule_fire_id=fire_id,
            schedule_scheduled_for=scheduled_for,
            schedule_observed_control_token=observed_control_token,
            schedule_receipt_control_token=receipt_control_token,
            schedule_execution_fire_id=execution_fire_id,
            schedule_acceptance_revision=acceptance_revision,
            schedule_definition_digest=definition_digest,
            schedule_expected_revision=expected_revision,
            schedule_expected_last_run_at=expected_last_run_at,
            schedule_expected_next_run_at=expected_next_run_at,
            schedule_next_run_at=prepared_next_run_at,
            cadence_initial_claim_deadline=initial_claim_deadline,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            result = await self.session.execute(
                select(Command).where(
                    Command.project_id == project_id,
                    Command.idempotency_key == idempotency_key,
                ),
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                raise
            exact = (
                existing.action == _FIRE_ACTION
                and existing.target_type == "schedule"
                and existing.target_id == str(schedule_id)
                and existing.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
                and existing.schedule_id == schedule_id
                and existing.schedule_fire_id == fire_id
                and _same_datetime(existing.schedule_scheduled_for, scheduled_for)
                and existing.schedule_observed_control_token == observed_control_token
                and existing.schedule_receipt_control_token == receipt_control_token
                and existing.schedule_execution_fire_id == execution_fire_id
                and existing.schedule_acceptance_revision == acceptance_revision
                and existing.schedule_definition_digest == definition_digest
                and existing.schedule_expected_revision == expected_revision
                and _same_datetime(
                    existing.schedule_expected_last_run_at,
                    expected_last_run_at,
                )
                and _same_datetime(
                    existing.schedule_expected_next_run_at,
                    expected_next_run_at,
                )
                and _same_datetime(
                    existing.schedule_next_run_at,
                    prepared_next_run_at,
                )
                and _canonical_payload(existing.payload) == _canonical_payload(payload)
            )
            if not exact:
                raise ConflictError(
                    "cadence command idempotency identity is divergent",
                    details={"idempotency_key": idempotency_key},
                ) from None
            return existing, False
        return row, True

    async def insert(
        self,
        *,
        project_id: UUID,
        agent_id: UUID | None,
        issued_by: UUID | None,
        action: str,
        target_type: str,
        target_id: str | None,
        payload: dict[str, Any],
        idempotency_key: str | None,
        timeout_at: datetime,
        source_ip: str | None,
        enforce_payload_identity: bool = False,
    ) -> tuple[Command, bool]:
        """Insert a Command row. Idempotent on (project_id, idempotency_key).

        Returns ``(command, created)`` where ``created`` is True iff a NEW row
        was inserted, and False when an existing row was returned because the
        ``(project_id, idempotency_key)`` already existed. Callers that complete
        a command in place (the synthetic no-op path) MUST gate that on
        ``created`` so an idempotency-key collision with an UNRELATED command
        never marks that command completed.

        When ``idempotency_key`` is set and a row with the same
        ``(project_id, idempotency_key)`` already exists, returns
        the existing row instead of raising ``IntegrityError``.
        Without this, two scheduler instances ticking the same
        schedule (HA failover, retry-after-timeout, or two brain
        replicas behind a load balancer both serving a retried
        FireSchedule) would both mint the same deterministic
        ``fire_id = uuid5(NAMESPACE, schedule_id +
        scheduled_for)``; the second insert raises
        IntegrityError; the FireSchedule handler reports
        ``brain_error`` to the scheduler; the scheduler retries;
        the schedule wedges per-fire until something else breaks
        the cycle.

        With idempotent insert, the second caller gets the same
        Command back as if it had won the race, the dispatcher's
        callers idempotency contract holds, and the wedge cycle is
        broken. The same fix also closes the pending-fires replay
        worker bug where a re-issue after a transient failure stuck
        the buffer row forever.

        Idempotency is opt-in: when ``idempotency_key`` is None we
        always insert (callers without an idempotency contract -
        e.g. the dashboard's ad-hoc command path - keep the original
        no-dedup behavior).
        """
        row = Command(
            project_id=project_id,
            agent_id=agent_id,
            issued_by=issued_by,
            action=action,
            target_type=target_type,
            target_id=target_id,
            payload=payload,
            idempotency_key=idempotency_key,
            status=CommandStatus.PENDING,
            timeout_at=timeout_at,
            source_ip=source_ip,
        )
        # Use a SAVEPOINT (``begin_nested``) so a UNIQUE collision
        # on (project_id, idempotency_key) only rolls the INSERT
        # back - not the caller's outer transaction (which holds
        # SELECT FOR UPDATE locks + audit writes that must survive).
        # ``session.rollback()`` would wipe the entire session
        # state, releasing locks and discarding queued-up writes;
        # SAVEPOINT is the targeted rollback we want.
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
                # Preserve idempotency-collision classification: a conflicting
                # existing row must still raise ConflictError even when the
                # re-issuer supplied an unknown agent. For a genuinely new row,
                # validate the durable target inside the same SAVEPOINT so a
                # revoked target rolls the insert back before it can escape.
                if agent_id is not None:
                    await self._require_live_agent(
                        project_id=project_id,
                        agent_id=agent_id,
                    )
        except IntegrityError:
            if idempotency_key is None:
                # No idempotency contract → caller did not opt into
                # dedup; surface the error.
                raise
            result = await self.session.execute(
                select(Command).where(
                    Command.project_id == project_id,
                    Command.idempotency_key == idempotency_key,
                ),
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                # Constraint fired but the row vanished - very
                # unusual; surface so the caller knows something
                # is wrong.
                raise
            # 2: the idempotency key maps to ONE logical
            # command, but the identity comparison differs by command CLASS:
            #
            # - A scheduler FIRE (key ``schedule:{id}:fire:{fire_id}``) is already
            #   fully identified by the embedded fire_id. A legitimate HA/timeout
            #   re-fire may re-pick a DIFFERENT online agent (agent selection is
            #   not pinned) and carries a different ``fired_at``, so comparing
            #   agent_id or payload here would false-conflict and re-open the
            #   per-fire wedge the idempotent insert exists to prevent (P1-1).
            #   Dedup on the stable fire identity (target) ONLY.
            # - An OPERATOR command (free-form key) must CONFLICT when the key is
            #   reused for a DIFFERENT command -- a different action/target/agent,
            #   OR, when the caller opts in (``enforce_payload_identity``), a
            #   different MEANINGFUL payload (a retry with different
            #   override_kwargs, a different bulk filter). Otherwise the second
            #   request is silently swallowed and the first is returned as if it
            #   were the caller's (P1-2). ``fired_at`` is excluded as volatile.
            if existing.action == _FIRE_ACTION and action == _FIRE_ACTION:
                conflict = existing.target_type != target_type or existing.target_id != target_id
            else:
                conflict = (
                    existing.action != action
                    or existing.target_type != target_type
                    or existing.agent_id != agent_id
                    or existing.target_id != target_id
                    or (
                        enforce_payload_identity
                        and _canonical_payload(existing.payload) != _canonical_payload(payload)
                    )
                )
            if conflict:
                raise ConflictError(
                    "idempotency_key already in use for a different command",
                    details={"idempotency_key": idempotency_key},
                ) from None
            return existing, False
        return row, True

    async def get_by_idempotency_key(
        self, *, project_id: UUID, idempotency_key: str
    ) -> Command | None:
        """The command previously issued under this key in this project, if any.

        Lets a multi-command request freeze its PLAN. Bulk retry expands a
        filter into one command per engine and derived a key per engine, so a
        request that first matched nothing committed under one key and a later
        replay of the SAME request, once tasks existed, expanded afresh under a
        DIFFERENT key and executed work the first response said did not exist.
        Checking a single request-scoped key up front makes a replay return the
        original outcome instead of re-expanding against live data.
        """
        row = await self.session.execute(
            select(Command).where(
                Command.project_id == project_id,
                Command.idempotency_key == idempotency_key,
            ),
        )
        return row.scalar_one_or_none()

    async def get_current_schedule_fire(
        self,
        *,
        schedule_id: UUID,
        fire_id: UUID,
        receipt_control_token: UUID,
    ) -> Command | None:
        result = await self.session.execute(
            select(Command).where(
                Command.action == _FIRE_ACTION,
                Command.schedule_id == schedule_id,
                Command.schedule_fire_id == fire_id,
                Command.schedule_receipt_control_token == receipt_control_token,
            ),
        )
        return result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # State transitions (single UPDATE, guarded by current status)
    # ------------------------------------------------------------------

    async def claim_current_schedule_delivery(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        command_id: UUID,
        *,
        project_id: UUID,
        agent_id: UUID,
        transport_kind: str,
        registry_owner_id: UUID,
        session_generation: str,
        timeout_seconds: int,
        recovery_min_interval_seconds: float = 10.0,
        occurred_at: datetime | None = None,
    ) -> tuple[bool, Command | None]:
        """Claim one current cadence command for one exact execution owner.

        The boolean identifies whether ``command_id`` is a marked Boundary-D
        cadence command.  A marked command returns ``None`` when it cannot take
        its first claim, and must never fall through to generic delivery.
        """

        candidate = await self.session.get(Command, command_id)
        if candidate is not None and candidate.action == _EXTERNAL_CONTROL_ACTION:
            return True, await self._claim_external_control_delivery(
                command_id=command_id,
                candidate=candidate,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                timeout_seconds=timeout_seconds,
                occurred_at=occurred_at,
            )
        if candidate is not None and candidate.action == _EXTERNAL_ACTIVATION_ACTION:
            return True, await self._claim_external_activation_delivery(
                command_id=command_id,
                candidate=candidate,
                project_id=project_id,
                agent_id=agent_id,
                transport_kind=transport_kind,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                timeout_seconds=timeout_seconds,
                occurred_at=occurred_at,
            )
        if candidate is None or candidate.schedule_protocol_marker != SCHEDULE_FIRE_PROTOCOL_MARKER:
            return False, candidate
        if candidate.action != _FIRE_ACTION or candidate.schedule_id is None:
            return True, None
        if transport_kind not in {"websocket", "longpoll"}:
            return True, None
        now = occurred_at or datetime.now(UTC)
        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        if not await self._lock_live_agent(
            project_id=project_id,
            agent_id=agent_id,
        ):
            return True, None
        # The candidate may predate another delivery claim. Locking the row
        # does not refresh SQLAlchemy's identity map unless explicitly requested.
        command_result = await self.session.execute(
            select(Command)
            .where(Command.id == command_id)
            .with_for_update()
            .execution_options(populate_existing=True),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            return True, None
        complete = (
            command.action == _FIRE_ACTION
            and command.project_id == project_id
            and command.agent_id == agent_id
            and command.schedule_state_nonce is not None
            and command.schedule_id == candidate.schedule_id
            and command.schedule_fire_id is not None
            and command.schedule_scheduled_for is not None
            and command.schedule_receipt_control_token is not None
            and command.schedule_execution_fire_id is not None
            and command.schedule_acceptance_revision is not None
            and command.schedule_definition_digest is not None
            and command.schedule_expected_revision is not None
            and command.schedule_expected_next_run_at is not None
            and command.cadence_initial_claim_deadline is not None
        )
        if not complete:
            return True, None
        if schedule is not None and schedule.project_id != command.project_id:
            return True, None
        initial_deadline = command.cadence_initial_claim_deadline
        assert initial_deadline is not None
        if initial_deadline.tzinfo is None:
            initial_deadline = initial_deadline.replace(tzinfo=UTC)
        if command.status == CommandStatus.DISPATCHED:
            deadline = command.cadence_redelivery_deadline
            if deadline is None:
                return True, None
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            timeout_at = command.timeout_at
            if timeout_at.tzinfo is None:
                timeout_at = timeout_at.replace(tzinfo=UTC)
            dispatched_at = command.dispatched_at
            if dispatched_at is None:
                return True, None
            if dispatched_at.tzinfo is None:
                dispatched_at = dispatched_at.replace(tzinfo=UTC)
            recovery_cutoff = now - timedelta(
                seconds=max(recovery_min_interval_seconds, 0.1),
            )
            exact_owner = (
                command.agent_acknowledged_at is None
                and command.first_delivery_claimed_at is not None
                and command.delivery_claim_token is not None
                and command.delivery_transport_kind == transport_kind
                and command.delivery_registry_owner_id == registry_owner_id
                and command.delivery_session_generation == session_generation[:128]
            )
            if (
                not exact_owner
                or now >= deadline
                or now >= timeout_at
                or dispatched_at > recovery_cutoff
            ):
                return True, None
            # The row lock makes this a single-winner recovery lease.  Rotating
            # the nonce and send timestamp suppresses every concurrent or
            # too-soon scanner without moving either immutable deadline.
            command.dispatched_at = now
            command.schedule_state_nonce = uuid4()
            await self.session.flush()
            return True, command
        if command.status != CommandStatus.PENDING or now > initial_deadline:
            return True, None
        if any(
            value is not None
            for value in (
                command.first_delivery_claimed_at,
                command.cadence_redelivery_deadline,
                command.delivery_transport_kind,
                command.delivery_registry_owner_id,
                command.delivery_session_generation,
                command.delivery_claim_token,
                command.agent_acknowledged_at,
            )
        ):
            return True, None

        # The current compatibility window is hard-capped at 240 seconds,
        # below the N-1 agent's known 300-second durable dedup retention.
        redelivery_window = min(max(timeout_seconds, 1), 240)
        deadline = now + timedelta(seconds=redelivery_window)
        command.status = CommandStatus.DISPATCHED
        command.dispatched_at = now
        command.timeout_at = deadline
        command.first_delivery_claimed_at = now
        command.cadence_redelivery_deadline = deadline
        command.delivery_transport_kind = transport_kind
        command.delivery_registry_owner_id = registry_owner_id
        command.delivery_session_generation = session_generation[:128]
        command.delivery_claim_token = uuid4()
        command.schedule_state_nonce = uuid4()
        await self.session.flush()
        return True, command

    async def _claim_external_activation_delivery(  # noqa: PLR0911 - fail-closed authority gates
        self,
        *,
        command_id: UUID,
        candidate: Command,
        project_id: UUID,
        agent_id: UUID,
        transport_kind: str,
        registry_owner_id: UUID,
        session_generation: str,
        timeout_seconds: int,
        occurred_at: datetime | None,
    ) -> Command | None:
        """Bind external activation to one immutable WebSocket generation."""
        if (
            transport_kind != "websocket"
            or candidate.project_id != project_id
            or candidate.agent_id != agent_id
            or candidate.status != CommandStatus.PENDING
        ):
            return None
        payload = candidate.payload
        if not isinstance(payload, dict):
            return None
        try:
            stream_id = UUID(str(payload["stream_id"]))
            epoch_uuid = UUID(str(payload["epoch_uuid"]))
            epoch_number = int(payload["epoch_number"])
        except (KeyError, TypeError, ValueError):
            return None
        owner = str(payload.get("owner") or "")
        adapter_instance_id = str(payload.get("adapter_instance_id") or "")
        source_scope = str(payload.get("source_scope") or "")
        if (
            not owner
            or not adapter_instance_id
            or not source_scope
            or payload.get("stable_source") is not True
            or candidate.target_id != owner
            or str(payload.get("registry_owner_id") or "") != str(registry_owner_id)
            or str(payload.get("session_generation") or "") != session_generation
        ):
            return None

        stream_result = await self.session.execute(
            select(ScheduleExternalStream)
            .where(
                ScheduleExternalStream.id == stream_id,
                ScheduleExternalStream.project_id == project_id,
            )
            .with_for_update(),
        )
        stream = stream_result.scalar_one_or_none()
        if (
            stream is None
            or stream.owner != owner
            or stream.source_scope != source_scope
            or stream.current_epoch_uuid != epoch_uuid
            or stream.current_epoch_number != epoch_number
            or stream.phase != "ACTIVATING"
            or stream.accepted_sequence != 0
            or stream.authorized_adapter_instance_id != adapter_instance_id
            or stream.executor_agent_id != agent_id
            or stream.executor_registry_owner_id != registry_owner_id
            or stream.executor_session_generation != session_generation
        ):
            return None

        if not await self._lock_live_agent(
            project_id=project_id,
            agent_id=agent_id,
        ):
            return None

        command_result = await self.session.execute(
            select(Command)
            .where(Command.id == command_id)
            .with_for_update()
            .execution_options(populate_existing=True),
        )
        command = command_result.scalar_one_or_none()
        if (
            command is None
            or command.status != CommandStatus.PENDING
            or any(
                value is not None
                for value in (
                    command.first_delivery_claimed_at,
                    command.delivery_transport_kind,
                    command.delivery_registry_owner_id,
                    command.delivery_session_generation,
                    command.delivery_claim_token,
                    command.agent_acknowledged_at,
                )
            )
        ):
            return None
        now = occurred_at or datetime.now(UTC)
        deadline = now + timedelta(seconds=min(max(timeout_seconds, 1), 240))
        command.status = CommandStatus.DISPATCHED
        command.dispatched_at = now
        command.timeout_at = deadline
        command.first_delivery_claimed_at = now
        command.delivery_transport_kind = "websocket"
        command.delivery_registry_owner_id = registry_owner_id
        command.delivery_session_generation = session_generation[:128]
        command.delivery_claim_token = uuid4()
        await self.session.flush()
        return command

    async def _claim_external_control_delivery(  # noqa: PLR0911
        self,
        *,
        command_id: UUID,
        candidate: Command,
        project_id: UUID,
        agent_id: UUID,
        transport_kind: str,
        registry_owner_id: UUID,
        session_generation: str,
        timeout_seconds: int,
        occurred_at: datetime | None,
    ) -> Command | None:
        """Claim one external control for its frozen WebSocket executor."""

        if (
            transport_kind != "websocket"
            or candidate.project_id != project_id
            or candidate.agent_id != agent_id
            or candidate.status != CommandStatus.PENDING
        ):
            return None
        payload = candidate.payload
        required_fields = {
            "operation_id",
            "scheduler",
            "schedule_id",
            "source_key",
            "z4j_schedule_id",
            "stream_id",
            "epoch_uuid",
            "epoch_number",
            "adapter_instance_id",
            "expected_accepted_sequence",
            "expected_projection_digest",
            "desired_projection",
            "desired_projection_digest",
            "registry_owner_id",
            "session_generation",
        }
        if not isinstance(payload, dict) or set(payload) != required_fields:
            return None
        try:
            operation_id = UUID(str(payload["operation_id"]))
            stream_id = UUID(str(payload["stream_id"]))
            epoch_uuid = UUID(str(payload["epoch_uuid"]))
            schedule_id = UUID(str(payload["z4j_schedule_id"]))
            payload_registry_owner_id = UUID(
                str(payload["registry_owner_id"]),
            )
            epoch_number = int(payload["epoch_number"])
            expected_sequence = int(
                payload["expected_accepted_sequence"],
            )
        except (TypeError, ValueError):
            return None
        if (
            isinstance(payload["epoch_number"], bool)
            or isinstance(payload["expected_accepted_sequence"], bool)
            or epoch_number <= 0
            or expected_sequence < 0
            or payload_registry_owner_id != registry_owner_id
            or str(payload["session_generation"]) != session_generation
        ):
            return None

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if (
            stream is None
            or stream.phase != "ACTIVE"
            or stream.current_epoch_uuid != epoch_uuid
            or stream.current_epoch_number != epoch_number
            or stream.accepted_sequence != expected_sequence
            or stream.owner != str(payload["scheduler"])
            or stream.authorized_adapter_instance_id != str(payload["adapter_instance_id"])
            or stream.executor_agent_id != agent_id
            or stream.executor_registry_owner_id != registry_owner_id
            or stream.executor_session_generation != session_generation
        ):
            return None

        operation = (
            await self.session.execute(
                select(ScheduleExternalControlOperation)
                .where(
                    ScheduleExternalControlOperation.id == operation_id,
                    ScheduleExternalControlOperation.stream_id == stream.id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if (
            operation is None
            or operation.status != "PENDING"
            or operation.command_id != command_id
            or operation.schedule_id != schedule_id
            or operation.agent_id != agent_id
            or operation.epoch_uuid != epoch_uuid
            or operation.epoch_number != epoch_number
            or operation.expected_accepted_sequence != expected_sequence
            or operation.source_key != str(payload["source_key"])
            or operation.source_key != str(payload["schedule_id"])
            or operation.adapter_instance_id != str(payload["adapter_instance_id"])
            or operation.registry_owner_id != registry_owner_id
            or operation.session_generation != session_generation
            or operation.prior_projection_digest != str(payload["expected_projection_digest"])
            or operation.desired_projection_digest != str(payload["desired_projection_digest"])
            or operation.desired_projection != payload["desired_projection"]
            or operation.dispatch_lease is not None
            or operation.reserved_sequence is not None
        ):
            return None

        schedule = (
            await self.session.execute(
                select(Schedule)
                .where(
                    Schedule.id == schedule_id,
                    Schedule.project_id == project_id,
                    Schedule.external_stream_id == stream.id,
                    Schedule.external_epoch_uuid == epoch_uuid,
                    Schedule.external_epoch_number == epoch_number,
                    Schedule.external_source_key == operation.source_key,
                    Schedule.schedule_revision == operation.expected_schedule_revision,
                    Schedule.control_token == operation.expected_control_token,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if schedule is None:
            return None

        if not await self._lock_live_agent(
            project_id=project_id,
            agent_id=agent_id,
        ):
            return None

        command = (
            await self.session.execute(
                select(Command)
                .where(Command.id == command_id)
                .with_for_update()
                .execution_options(populate_existing=True),
            )
        ).scalar_one_or_none()
        if (
            command is None
            or command.status != CommandStatus.PENDING
            or command.action != _EXTERNAL_CONTROL_ACTION
            or command.project_id != project_id
            or command.agent_id != agent_id
            or command.payload != payload
            or any(
                value is not None
                for value in (
                    command.first_delivery_claimed_at,
                    command.delivery_transport_kind,
                    command.delivery_registry_owner_id,
                    command.delivery_session_generation,
                    command.delivery_claim_token,
                    command.agent_acknowledged_at,
                )
            )
        ):
            return None

        now = occurred_at or datetime.now(UTC)
        deadline = now + timedelta(
            seconds=min(max(timeout_seconds, 1), 240),
        )
        delivery_claim_token = uuid4()
        await arm_external_control_transition(
            self.session,
            transition="claim",
            operation_id=operation.id,
            stream_id=operation.stream_id,
            epoch_number=operation.epoch_number,
            reserved_sequence=expected_sequence + 1,
            state_nonce=operation.state_nonce,
            dispatch_lease=delivery_claim_token,
            terminal_id=command.id,
        )
        command.status = CommandStatus.DISPATCHED
        command.dispatched_at = now
        command.timeout_at = deadline
        command.first_delivery_claimed_at = now
        command.delivery_transport_kind = "websocket"
        command.delivery_registry_owner_id = registry_owner_id
        command.delivery_session_generation = session_generation
        command.delivery_claim_token = delivery_claim_token
        operation.status = "CLAIMED"
        operation.dispatch_lease = delivery_claim_token
        operation.reserved_sequence = expected_sequence + 1
        operation.updated_at = now
        await self.session.flush()
        await assert_external_control_consumed(self.session)
        return command

    async def list_recoverable_current_websocket_deliveries(
        self,
        *,
        now: datetime,
        minimum_interval_seconds: float,
        limit: int = 200,
    ) -> list[tuple[UUID, UUID, UUID, str]]:
        """Select due, unacknowledged recovery sends for frozen WS owners."""

        cutoff = now - timedelta(
            seconds=max(minimum_interval_seconds, 0.1),
        )
        result = await self.session.execute(
            select(
                Command.id,
                Command.agent_id,
                Command.delivery_registry_owner_id,
                Command.delivery_session_generation,
            )
            .where(
                Command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                Command.status == CommandStatus.DISPATCHED,
                Command.delivery_transport_kind == "websocket",
                Command.agent_acknowledged_at.is_(None),
                Command.agent_id.is_not(None),
                Command.delivery_registry_owner_id.is_not(None),
                Command.delivery_session_generation.is_not(None),
                Command.cadence_redelivery_deadline > now,
                Command.timeout_at > now,
                Command.dispatched_at <= cutoff,
            )
            .order_by(Command.dispatched_at.asc(), Command.id.asc())
            .limit(max(1, min(limit, 1000))),
        )
        candidates: list[tuple[UUID, UUID, UUID, str]] = []
        for command_id, agent_id, owner_id, generation in result.all():
            if agent_id is None or owner_id is None or generation is None:
                continue
            candidates.append(
                (command_id, agent_id, owner_id, generation),
            )
        return candidates

    async def list_expired_current_schedule_deliveries(
        self,
        *,
        now: datetime,
        limit: int = 200,
    ) -> list[UUID]:
        """Return marked cadence commands whose immutable delivery bound elapsed.

        This is selection only.  The schedule-first terminal service re-locks
        and revalidates every candidate before changing state, so concurrent
        agent results, operator edits, and other timeout workers collapse to one
        durable outcome.
        """

        result = await self.session.execute(
            select(Command.id)
            .where(
                Command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                or_(
                    and_(
                        Command.status == CommandStatus.PENDING,
                        Command.first_delivery_claimed_at.is_(None),
                        Command.cadence_initial_claim_deadline <= now,
                    ),
                    and_(
                        Command.status == CommandStatus.DISPATCHED,
                        or_(
                            Command.cadence_redelivery_deadline <= now,
                            Command.timeout_at <= now,
                        ),
                    ),
                ),
            )
            .order_by(Command.timeout_at.asc(), Command.id.asc())
            .limit(max(1, min(limit, 1000))),
        )
        return list(result.scalars().all())

    async def mark_dispatched(
        self,
        command_id: UUID,
        *,
        timeout_seconds: int,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> datetime | None:
        """Pending → dispatched. Returns the GENERATION (the ``dispatched_at`` it
        stamped) on a successful claim, or None if the row did not transition.

        The command timeout is a response window, so its deadline starts at the
        successful initial delivery claim rather than at issuance. Stamping
        ``dispatched_at`` and ``timeout_at`` in the same guarded UPDATE prevents a
        late first delivery from timing out before it is redispatch-eligible.

        The returned generation is the claim's identity. A claim-then-push
        caller threads it into ``revert_dispatch(expected_dispatched_at=...)`` so a
        failed-send revert can only ever undo ITS OWN claim -- a delayed sender
        whose claim was already superseded by a newer redispatch reverts nothing.
        The generation comes from the database wall clock, so replica clock skew
        cannot make a fresh delivery immediately lease-eligible (or postpone it
        indefinitely). The datetime is truthy, None is falsy, so existing ``if
        claimed`` / ``if not claimed`` callers are unaffected."""
        generation = await _database_now(self.session)
        predicates = [
            Command.id == command_id,
            Command.status == CommandStatus.PENDING,
            Command.schedule_protocol_marker.is_(None),
            Command.action != _EXTERNAL_CONTROL_ACTION,
        ]
        if project_id is not None:
            predicates.append(Command.project_id == project_id)
        if agent_id is not None:
            predicates.append(Command.agent_id == agent_id)
        result = await self.session.execute(
            update(Command)
            .where(*predicates)
            .values(
                status=CommandStatus.DISPATCHED,
                dispatched_at=generation,
                timeout_at=generation + timedelta(seconds=timeout_seconds),
            ),
        )
        return generation if (getattr(result, "rowcount", 0) or 0) > 0 else None

    async def revert_dispatch(
        self,
        command_id: UUID,
        *,
        timeout_seconds: int | None = None,
        expected_dispatched_at: datetime | None = None,
        new_agent_id: UUID | None = None,
    ) -> bool:
        """Dispatched/timeout → pending, re-deliverable. Returns True if it moved.

        ``deliver_local`` claims a row DISPATCHED *before* the WebSocket
        push. If the push then fails, the row is durably DISPATCHED but the agent
        never received it -- yet a catch-up re-issue sees a non-PENDING row and
        (via the idempotent-success guard) treats it as already delivered,
        silently dropping the fire. Reverting the claim on a failed push keeps the
        invariant DISPATCHED == physically delivered, so the re-issue finds a
        PENDING row and re-delivers.

        The re-issue path also RE-DRIVES an ORPHANED command -- a
        stale-DISPATCHED (pushed but no result ever came back) or a TIMEOUT row.
        So the guard matches ``status IN (DISPATCHED, TIMEOUT)``; and when
        ``timeout_seconds`` is given the row's ``timeout_at`` is refreshed
        (otherwise a re-delivered TIMEOUT row would instantly re-expire on its
        stale deadline). Never clobbers a row an ack has advanced to a terminal
        SUCCESS/FAILURE/CANCELLED state.

        (ABA guard): when ``expected_dispatched_at`` is given, the revert is
        a compare-and-swap -- it fires ONLY if the row's ``dispatched_at`` still
        equals the value the caller observed. A caller that read a STALE
        generation (dispatched_at ``d0``) will not clobber a row that a concurrent
        rearm+redispatch has already advanced to ``d1`` (every redispatch stamps a
        strictly-later ``now()``, so ``d1 != d0``), preventing the double-drive an
        unguarded revert allowed.

        (Ownership transfer): when ``new_agent_id`` is given, the row's
        ``agent_id`` is reassigned to the re-driving target in the SAME UPDATE.
        A fire whose original online agent went offline is re-picked to a
        different agent; without this the row stays owned by the offline agent and
        the new agent's ack/result/long-poll (all agent-scoped) can never
        terminalize it (spurious TIMEOUT + a possible undelivered redrive).

        Rearming a TIMEOUT row (which the CommandTimeoutWorker stamped with
        ``completed_at`` + a timeout ``error``) also CLEARS those terminal fields,
        so the re-armed PENDING/DISPATCHED row is not simultaneously marked
        completed-and-failed.
        """
        values: dict[str, Any] = {
            "status": CommandStatus.PENDING,
            "dispatched_at": None,
            "completed_at": None,
            "error": None,
            "result": None,
        }
        if timeout_seconds is not None:
            values["timeout_at"] = datetime.now(UTC) + timedelta(seconds=timeout_seconds)
        if new_agent_id is not None:
            values["agent_id"] = new_agent_id
        predicates = [
            Command.id == command_id,
            Command.status.in_((CommandStatus.DISPATCHED, CommandStatus.TIMEOUT)),
            Command.schedule_protocol_marker.is_(None),
            Command.action != _EXTERNAL_CONTROL_ACTION,
        ]
        if expected_dispatched_at is not None:
            predicates.append(Command.dispatched_at == expected_dispatched_at)
        result = await self.session.execute(
            update(Command)
            .where(*predicates)
            .values(**values)
            # The datetime CAS WHERE must run in SQL, not the ORM's in-memory
            # evaluator (which trips on a naive/aware mix under SQLite).
            .execution_options(synchronize_session=False),
        )
        return (result.rowcount or 0) > 0

    async def reassign_pending_owner(
        self,
        command_id: UUID,
        *,
        new_agent_id: UUID,
    ) -> bool:
        """Transfer a still-PENDING command to a new target agent. Returns
        True if it moved.

        A fire returned from an idempotency-collision may still be owned by an
        agent that went offline before it was ever dispatched, while a DIFFERENT
        agent is re-picked for this delivery. Without transferring ownership the
        target receives it but its agent-scoped ack/result is rejected (the row
        still belongs to the offline agent), so the fire wedges under a spurious
        TIMEOUT. Status-guarded to PENDING so a concurrent claim (mark_dispatched
        WHERE status=PENDING) is never clobbered -- if the row was claimed between
        our read and this UPDATE, rowcount is 0 and we leave the claim intact."""
        result = await self.session.execute(
            update(Command)
            .where(
                Command.id == command_id,
                Command.status == CommandStatus.PENDING,
                Command.schedule_protocol_marker.is_(None),
                Command.action != _EXTERNAL_CONTROL_ACTION,
            )
            .values(agent_id=new_agent_id)
            .execution_options(synchronize_session=False),
        )
        return (result.rowcount or 0) > 0

    async def claim_redispatch(
        self,
        command_id: UUID,
        *,
        min_interval_seconds: float,
        expected_dispatched_at: datetime | None = None,
    ) -> bool:
        """Single-winner lease for a DISPATCHED-recovery redispatch (/
        ). Returns True for the poller that should re-send the frame.

        The long-poll transport re-sends a still-DISPATCHED command whose HTTP
        response may have been lost (a network drop -- the agent never got it).
        The prior implementation gated on the CALLER's freshly-read
        ``dispatched_at``, so every SEQUENTIAL poll re-read the just-bumped value
        and re-won -- re-sending on every poll (a flood to concurrent workers / a
        restarted agent that lacks in-memory dedup), and re-stamping ``now()`` kept
        the row inside the selection window indefinitely.

        This is a real database-clock lease with a strict generation CAS. The
        repository first observes ``dispatched_at`` and the database wall clock,
        then updates only if that exact generation is still current and is at
        least ``min_interval_seconds`` old. A concurrent replica that advanced
        the generation wins; a stale claimant cannot overwrite it (including an
        ABA-shaped delayed claim). The winner stamps a strictly-newer generation
        derived from database time. Process clock skew is irrelevant.

        ``timeout_at`` is left untouched so the CommandTimeoutWorker still
        retires a truly-stuck row on its original deadline. Cross-restart dedup
        still relies on agent-side idempotency (a larger design item).
        """
        observed = expected_dispatched_at
        if observed is None:
            # Compatibility for internal callers that did not select the row.
            # Delivery paths should pass their observed generation so a delayed
            # snapshot cannot become authoritative after the lease elapses.
            observed = await self.session.scalar(
                select(Command.dispatched_at).where(
                    Command.id == command_id,
                    Command.status == CommandStatus.DISPATCHED,
                    Command.schedule_protocol_marker.is_(None),
                    Command.action != _EXTERNAL_CONTROL_ACTION,
                ),
            )
        if observed is None:
            return False
        database_now = await _database_now(self.session)
        observed_utc = observed if observed.tzinfo else observed.replace(tzinfo=UTC)
        cutoff = database_now - timedelta(seconds=max(min_interval_seconds, 0.0))
        if observed_utc > cutoff:
            return False
        # Fractional SQLite database time has millisecond resolution.  A zero
        # lease can therefore observe the same timestamp twice; advance one
        # microsecond from the durable generation so every successful CAS has a
        # distinct token even then.  No process clock participates.
        generation = max(database_now, observed_utc + timedelta(microseconds=1))
        result = await self.session.execute(
            update(Command)
            .where(
                Command.id == command_id,
                Command.status == CommandStatus.DISPATCHED,
                Command.dispatched_at == observed,
                Command.dispatched_at <= cutoff,
                Command.schedule_protocol_marker.is_(None),
                Command.action != _EXTERNAL_CONTROL_ACTION,
            )
            .values(dispatched_at=generation)
            # The datetime WHERE must run in SQL, not the ORM's in-memory
            # evaluator (which trips on a naive/aware mix under SQLite).
            .execution_options(synchronize_session=False),
        )
        return (getattr(result, "rowcount", 0) or 0) > 0

    async def mark_completed(
        self,
        command_id: UUID,
        *,
        result_payload: dict[str, Any] | None,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> bool:
        predicates = [
            Command.id == command_id,
            Command.schedule_protocol_marker.is_(None),
            Command.action != _EXTERNAL_CONTROL_ACTION,
            or_(
                Command.status.in_(
                    [CommandStatus.PENDING, CommandStatus.DISPATCHED],
                ),
                # Boundary B: UNKNOWN is an observed outcome, not an
                # execution fence. A command linked to an irreversible child
                # may receive a late authenticated result after the generic
                # timeout sweeper ran; only that managed class may refine
                # TIMEOUT to the real terminal result.
                and_(
                    Command.bulk_retry_child_id.is_not(None),
                    Command.status == CommandStatus.TIMEOUT,
                ),
            ),
        ]
        if project_id is not None:
            predicates.append(Command.project_id == project_id)
        if agent_id is not None:
            predicates.append(Command.agent_id == agent_id)
        result = await self.session.execute(
            update(Command)
            .where(*predicates)
            .values(
                status=CommandStatus.COMPLETED,
                completed_at=datetime.now(UTC),
                result=result_payload,
                error=None,
            ),
        )
        return (result.rowcount or 0) > 0

    async def mark_failed(
        self,
        command_id: UUID,
        *,
        error: str,
        result_payload: dict[str, Any] | None = None,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> bool:
        predicates = [
            Command.id == command_id,
            Command.schedule_protocol_marker.is_(None),
            Command.action != _EXTERNAL_CONTROL_ACTION,
            or_(
                Command.status.in_(
                    [CommandStatus.PENDING, CommandStatus.DISPATCHED],
                ),
                and_(
                    Command.bulk_retry_child_id.is_not(None),
                    Command.status == CommandStatus.TIMEOUT,
                ),
            ),
        ]
        if project_id is not None:
            predicates.append(Command.project_id == project_id)
        if agent_id is not None:
            predicates.append(Command.agent_id == agent_id)
        result = await self.session.execute(
            update(Command)
            .where(*predicates)
            .values(
                status=CommandStatus.FAILED,
                completed_at=datetime.now(UTC),
                error=error[:1024],
                result=result_payload,
            ),
        )
        return (result.rowcount or 0) > 0

    async def sweep_timeouts(self, *, now: datetime) -> int:
        """Mark every pending/dispatched command past its ``timeout_at``.

        Used by :class:`CommandTimeoutWorker`. Single bulk UPDATE.
        Returns the number of rows transitioned.
        """
        result = await self.session.execute(
            # Evaluate deadlines in the database. SQLite reloads timestamps
            # without tzinfo; Python-side ORM synchronization can otherwise
            # compare them with this aware UTC cutoff, even on excluded rows.
            update(Command)
            .execution_options(synchronize_session="fetch")
            .where(
                Command.status.in_(
                    [CommandStatus.PENDING, CommandStatus.DISPATCHED],
                ),
                Command.timeout_at < now,
                Command.schedule_protocol_marker.is_(None),
                Command.action != _EXTERNAL_CONTROL_ACTION,
            )
            .values(
                status=CommandStatus.TIMEOUT,
                completed_at=now,
                error="command timed out before agent responded",
            ),
        )
        return int(result.rowcount or 0)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def list_for_project(
        self,
        *,
        project_id: UUID,
        status: CommandStatus | None = None,
        cursor: tuple[Any, UUID] | None = None,
        limit: int = 50,
    ) -> list[Command]:
        stmt = select(Command).where(Command.project_id == project_id)
        if status is not None:
            stmt = stmt.where(Command.status == status)
        if cursor is not None:
            sort_value, tiebreaker = cursor
            stmt = stmt.where(
                or_(
                    Command.issued_at < sort_value,
                    and_(
                        Command.issued_at == sort_value,
                        Command.id < tiebreaker,
                    ),
                ),
            )
        stmt = stmt.order_by(Command.issued_at.desc(), Command.id.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_dispatch(
        self,
        command_id: UUID,
    ) -> Command | None:
        """Fetch a command row for the dispatch path.

        Used by the registry's ``deliver_local`` callback. The
        caller has already received the NOTIFY (or has it locally)
        and needs the row to sign + push the frame.
        """
        result = await self.session.execute(
            select(Command).where(Command.id == command_id),
        )
        return result.scalar_one_or_none()


__all__ = ["CommandRepository"]
