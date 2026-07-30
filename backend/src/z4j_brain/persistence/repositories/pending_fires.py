"""``pending_fires`` repository.

Wraps the small set of operations the FireSchedule handler and the
replay worker need:

- :meth:`buffer` - insert a new pending fire (called by FireSchedule
  when no agent is online and the schedule's catch_up policy buffers)
- :meth:`list_for_replay` - oldest-first by ``scheduled_for`` for one
  ``(project_id, engine)`` pair (called by the replay worker once an
  agent comes online)
- :meth:`delete_by_fire_id` - clean up after a successful replay
- :meth:`delete_expired` - sweep expired buffers (the catch-up window
  passed without an agent ever coming online)
- :meth:`count_for_schedule` - observability surface for dashboard

Implementation notes:

- Inserts are idempotent on ``fire_id`` (UNIQUE). A re-insert of the
  same fire_id is treated as "the buffer already has it" and the
  existing row is returned rather than raising.
- The repository never commits - the caller owns the transaction
  boundary. Matches the convention used by every other brain
  repository.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.schedule_fire_authority import (
    SCHEDULE_FIRE_PROTOCOL_MARKER,
)
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import (
    Agent,
    Command,
    PendingFire,
    Schedule,
    ScheduleFire,
)
from z4j_brain.persistence.schedule_guard import (
    arm_evidence_delete,
    assert_evidence_delete_consumed,
)


@dataclass(frozen=True, slots=True)
class CurrentPendingFireTransition:
    """One locked current-protocol buffer disposition."""

    disposition: str
    pending: PendingFire | None
    command: Command | None = None
    fire: ScheduleFire | None = None
    changed: bool = False


class PendingFiresRepository:
    """``pending_fires`` table CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def buffer_current(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        engine: str,
        payload: dict[str, Any],
        scheduled_for: datetime,
        expires_at: datetime,
        observed_control_token: UUID | None,
        receipt_control_token: UUID,
        definition_digest: str,
        expected_schedule_revision: int,
        expected_last_run_at: datetime | None,
        expected_next_run_at: datetime,
        prepared_next_run_at: datetime | None,
        acceptance_revision: int,
        execution_fire_id: UUID,
    ) -> tuple[PendingFire, bool]:
        """Insert/reuse a complete current-protocol pending occurrence."""

        if payload.get("fire_id") != str(execution_fire_id):
            raise ValueError("pending fire payload lacks its execution fire identity")
        row = PendingFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            engine=engine,
            payload=payload,
            scheduled_for=scheduled_for,
            enqueued_at=datetime.now(UTC),
            expires_at=expires_at,
            protocol_marker=SCHEDULE_FIRE_PROTOCOL_MARKER,
            state_write_nonce=uuid4(),
            observed_control_token=observed_control_token,
            receipt_control_token=receipt_control_token,
            definition_digest=definition_digest,
            expected_schedule_revision=expected_schedule_revision,
            expected_last_run_at=expected_last_run_at,
            expected_next_run_at=expected_next_run_at,
            prepared_next_run_at=prepared_next_run_at,
            acceptance_revision=acceptance_revision,
            execution_fire_id=execution_fire_id,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            existing = await self._get_by_identity(
                fire_id,
                receipt_control_token,
            )
            if existing is None:
                raise
            exact = (
                existing.schedule_id == schedule_id
                and existing.project_id == project_id
                and existing.engine == engine
                and existing.payload == payload
                and _same_datetime(existing.scheduled_for, scheduled_for)
                and existing.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
                and existing.observed_control_token == observed_control_token
                and existing.receipt_control_token == receipt_control_token
                and existing.definition_digest == definition_digest
                and existing.expected_schedule_revision == expected_schedule_revision
                and _same_datetime(
                    existing.expected_last_run_at,
                    expected_last_run_at,
                )
                and _same_datetime(
                    existing.expected_next_run_at,
                    expected_next_run_at,
                )
                and _same_datetime(
                    existing.prepared_next_run_at,
                    prepared_next_run_at,
                )
                and existing.acceptance_revision == acceptance_revision
                and existing.execution_fire_id == execution_fire_id
            )
            if not exact:
                raise ValueError(
                    "pending fire receipt identity is divergent",
                ) from None
            return existing, False
        return row, True

    async def buffer(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        engine: str,
        payload: dict[str, Any],
        scheduled_for: datetime,
        expires_at: datetime,
    ) -> PendingFire:
        """Insert a buffered fire. Idempotent on ``fire_id``.

        Uses a SAVEPOINT (``begin_nested``) on IntegrityError so
        the failed INSERT rolls back without wiping the caller's
        outer transaction. A bare ``session.rollback()`` would
        release the FOR UPDATE locks the FireSchedule handler
        holds on the schedule row.
        """
        row = PendingFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            engine=engine,
            payload=payload,
            scheduled_for=scheduled_for,
            enqueued_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            existing = await self._get_by_fire_id(fire_id)
            if existing is None:
                raise  # the IntegrityError came from somewhere else
            return existing
        return row

    async def list_for_replay(
        self,
        *,
        project_id: UUID,
        engine: str,
        limit: int = 1000,
    ) -> list[PendingFire]:
        """Return buffered fires for one (project, engine), oldest first.

        On Postgres we use ``SELECT ... FOR UPDATE SKIP LOCKED``
        so multi-replica brain workers cannot pick the same row.
        Otherwise two replay workers running in parallel would
        both fetch the same fire_id, both call
        ``dispatcher.issue`` (deduped via
        commands.idempotency_key but still a wasted round-trip),
        and one of them would leave the buffer row stuck if
        ``IntegrityError`` were ever swallowed.

        SQLite doesn't support ``SKIP LOCKED`` and only one writer
        runs at a time anyway, so the lock falls through harmlessly.

        ``limit`` caps the batch so the replay worker doesn't
        materialise an unbounded list when an agent comes online
        after a long outage. The worker calls again on the next
        tick to drain the rest.
        """
        stmt = (
            select(PendingFire)
            .where(
                PendingFire.project_id == project_id,
                PendingFire.engine == engine,
                PendingFire.protocol_marker.is_(None),
            )
            .order_by(PendingFire.scheduled_for)
            .limit(limit)
        )
        # Postgres-only: row-level lock + skip rows already locked
        # by a sibling worker. No-op on SQLite (driver ignores).
        if self.session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_by_fire_id(self, fire_id: UUID) -> bool:
        """Remove one buffered fire after successful replay.

        Returns True if a row was actually deleted (False = nothing
        to delete, e.g. the operator manually cleared the row).
        """
        result = await self.session.execute(
            delete(PendingFire).where(
                PendingFire.fire_id == fire_id,
                PendingFire.protocol_marker.is_(None),
            ),
        )
        return (result.rowcount or 0) > 0

    async def delete_expired(self, *, now: datetime | None = None) -> int:
        """Sweep buffers past their expiry window.

        Called by the periodic sweep worker. Returns the number of
        rows removed so the worker can emit a metric.
        """
        cutoff = now or datetime.now(UTC)
        result = await self.session.execute(
            delete(PendingFire).where(
                PendingFire.expires_at < cutoff,
                PendingFire.protocol_marker.is_(None),
            ),
        )
        return result.rowcount or 0

    async def list_expired_current(
        self,
        *,
        now: datetime,
        limit: int = 200,
    ) -> list[tuple[UUID, UUID]]:
        """Enumerate current buffers without granting mutation authority."""

        result = await self.session.execute(
            select(PendingFire.id, PendingFire.state_write_nonce)
            .where(
                PendingFire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                PendingFire.receipt_control_token.is_not(None),
                PendingFire.state_write_nonce.is_not(None),
                PendingFire.expires_at <= now,
            )
            .order_by(PendingFire.expires_at.asc(), PendingFire.id.asc())
            .limit(max(1, min(limit, 1000))),
        )
        return [(pending_id, nonce) for pending_id, nonce in result.all() if nonce is not None]

    async def list_current_for_replay(
        self,
        *,
        now: datetime,
        limit: int = 200,
    ) -> list[PendingFire]:
        """Enumerate unexpired receipt-bound buffers oldest first."""

        result = await self.session.execute(
            select(PendingFire)
            .where(
                PendingFire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                PendingFire.receipt_control_token.is_not(None),
                PendingFire.state_write_nonce.is_not(None),
                PendingFire.expires_at > now,
            )
            .order_by(PendingFire.scheduled_for.asc(), PendingFire.id.asc())
            .limit(max(1, min(limit, 1000))),
        )
        return list(result.scalars().all())

    async def expire_current(  # noqa: PLR0911
        self,
        *,
        pending_id: UUID,
        expected_state_nonce: UUID,
        occurred_at: datetime,
    ) -> CurrentPendingFireTransition:
        """Apply one audited-current expiry predecessor under schedule lock."""

        candidate = await self.session.get(PendingFire, pending_id)
        if candidate is None:
            return CurrentPendingFireTransition("not_found", None)
        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        pending_result = await self.session.execute(
            select(PendingFire).where(PendingFire.id == pending_id).with_for_update(),
        )
        pending = pending_result.scalar_one_or_none()
        if pending is None:
            return CurrentPendingFireTransition("not_found", None)
        if (
            pending.protocol_marker != SCHEDULE_FIRE_PROTOCOL_MARKER
            or pending.state_write_nonce != expected_state_nonce
        ):
            return CurrentPendingFireTransition("stale_candidate", pending)
        if pending.receipt_control_token is None:
            return CurrentPendingFireTransition(
                "legacy_operator_resolution_required",
                pending,
            )
        if not _complete_current_pending(pending):
            return CurrentPendingFireTransition("incomplete", pending)
        if _utc(pending.expires_at) > _utc(occurred_at):
            return CurrentPendingFireTransition("not_due", pending)

        fire = await self._lock_matching_current_fire(pending)
        if fire is not None:
            _require_fire_matches_pending(fire, pending)
            fire.status = "buffer_expired"
            fire.error_code = "buffer_expired"
            fire.error_message = "accepted cadence fire expired before an agent became available"
            fire.state_write_nonce = uuid.uuid4()
        guard_active = await arm_evidence_delete(
            self.session,
            table_name="pending_fires",
            row_id=pending.id,
            old_nonce=pending.state_write_nonce,
            reason="pending_expiry",
        )
        await self.session.delete(pending)
        await self.session.flush()
        await assert_evidence_delete_consumed(
            self.session,
            active=guard_active,
        )
        return CurrentPendingFireTransition(
            ("expired" if schedule is not None else "expired_schedule_absent"),
            pending,
            fire=fire,
            changed=True,
        )

    async def replay_current(  # noqa: PLR0911, PLR0912
        self,
        *,
        pending_id: UUID,
        expected_state_nonce: UUID,
        agent_id: UUID,
        command_timeout_seconds: int,
        occurred_at: datetime,
    ) -> CurrentPendingFireTransition:
        """Bind one current buffer to a command without re-advancing cadence."""

        from z4j_brain.persistence.repositories.commands import (
            CommandRepository,
        )

        candidate = await self.session.get(PendingFire, pending_id)
        if candidate is None:
            return CurrentPendingFireTransition("not_found", None)
        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        pending_result = await self.session.execute(
            select(PendingFire).where(PendingFire.id == pending_id).with_for_update(),
        )
        pending = pending_result.scalar_one_or_none()
        if pending is None:
            return CurrentPendingFireTransition("not_found", None)
        if (
            pending.protocol_marker != SCHEDULE_FIRE_PROTOCOL_MARKER
            or pending.state_write_nonce != expected_state_nonce
        ):
            return CurrentPendingFireTransition("stale_candidate", pending)
        if pending.receipt_control_token is None:
            return CurrentPendingFireTransition(
                "legacy_operator_resolution_required",
                pending,
            )
        if not _complete_current_pending(pending):
            return CurrentPendingFireTransition("incomplete", pending)
        if _utc(pending.expires_at) <= _utc(occurred_at):
            return CurrentPendingFireTransition("expired", pending)

        fire = await self._lock_matching_current_fire(pending)
        if fire is not None:
            _require_fire_matches_pending(fire, pending)
        if (
            schedule is None
            or schedule.project_id != pending.project_id
            or schedule.control_token != pending.receipt_control_token
            or schedule.definition_digest != pending.definition_digest
            or (
                pending.observed_control_token is not None
                and schedule.control_token != pending.observed_control_token
            )
            or (
                pending.observed_control_token is None
                and schedule.legacy_fire_control_token != pending.receipt_control_token
            )
        ):
            if fire is not None:
                fire.status = "buffer_stale"
                fire.error_code = "stale_control"
                fire.error_message = "buffer receipt no longer matches schedule control"
                fire.state_write_nonce = uuid.uuid4()
            guard_active = await arm_evidence_delete(
                self.session,
                table_name="pending_fires",
                row_id=pending.id,
                old_nonce=pending.state_write_nonce,
                reason="pending_stale",
            )
            await self.session.delete(pending)
            await self.session.flush()
            await assert_evidence_delete_consumed(
                self.session,
                active=guard_active,
            )
            return CurrentPendingFireTransition(
                "stale_resolved",
                pending,
                fire=fire,
                changed=True,
            )
        if not schedule.is_enabled:
            return CurrentPendingFireTransition(
                "schedule_disabled",
                pending,
                fire=fire,
            )

        agent_result = await self.session.execute(
            select(Agent)
            .where(
                Agent.id == agent_id,
                Agent.project_id == pending.project_id,
            )
            .with_for_update(),
        )
        agent = agent_result.scalar_one_or_none()
        if (
            agent is None
            or agent.state != AgentState.ONLINE
            or pending.engine not in (agent.engine_adapters or ())
        ):
            return CurrentPendingFireTransition(
                "agent_unavailable",
                pending,
                fire=fire,
            )

        assert pending.execution_fire_id is not None
        assert pending.receipt_control_token is not None
        assert pending.definition_digest is not None
        assert pending.expected_schedule_revision is not None
        assert pending.expected_next_run_at is not None
        assert pending.acceptance_revision is not None
        timeout_at = _utc(occurred_at) + timedelta(
            seconds=max(command_timeout_seconds, 1),
        )
        command, _created = await CommandRepository(
            self.session,
        ).insert_current_schedule_fire(
            project_id=pending.project_id,
            agent_id=agent.id,
            schedule_id=pending.schedule_id,
            fire_id=pending.fire_id,
            scheduled_for=pending.scheduled_for,
            observed_control_token=pending.observed_control_token,
            receipt_control_token=pending.receipt_control_token,
            execution_fire_id=pending.execution_fire_id,
            acceptance_revision=pending.acceptance_revision,
            definition_digest=pending.definition_digest,
            expected_revision=pending.expected_schedule_revision,
            expected_last_run_at=pending.expected_last_run_at,
            expected_next_run_at=pending.expected_next_run_at,
            prepared_next_run_at=pending.prepared_next_run_at,
            payload=dict(pending.payload),
            timeout_at=timeout_at,
            initial_claim_deadline=timeout_at,
        )
        if fire is not None:
            if fire.command_id not in {None, command.id}:
                raise ValueError(
                    "current buffered fire is bound to a divergent command",
                )
            fire.command_id = command.id
            fire.status = "accepted"
            fire.error_code = None
            fire.error_message = None
            fire.state_write_nonce = uuid.uuid4()
        guard_active = await arm_evidence_delete(
            self.session,
            table_name="pending_fires",
            row_id=pending.id,
            old_nonce=pending.state_write_nonce,
            reason="pending_replay",
        )
        await self.session.delete(pending)
        await self.session.flush()
        await assert_evidence_delete_consumed(
            self.session,
            active=guard_active,
        )
        return CurrentPendingFireTransition(
            "replayed",
            pending,
            command=command,
            fire=fire,
            changed=True,
        )

    async def _lock_matching_current_fire(
        self,
        pending: PendingFire,
    ) -> ScheduleFire | None:
        result = await self.session.execute(
            select(ScheduleFire)
            .where(
                ScheduleFire.fire_id == pending.fire_id,
                ScheduleFire.receipt_control_token == pending.receipt_control_token,
            )
            .with_for_update(),
        )
        return result.scalar_one_or_none()

    async def count_for_schedule(self, schedule_id: UUID) -> int:
        """How many buffered fires exist for one schedule.

        Used by the dashboard to render a "N fires waiting" badge so
        the operator notices long agent outages before they bite.
        """
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count(PendingFire.id)).where(
                PendingFire.schedule_id == schedule_id,
            ),
        )
        return int(result.scalar_one() or 0)

    async def _get_by_fire_id(self, fire_id: UUID) -> PendingFire | None:
        result = await self.session.execute(
            select(PendingFire).where(PendingFire.fire_id == fire_id),
        )
        return result.scalar_one_or_none()

    async def _get_by_identity(
        self,
        fire_id: UUID,
        receipt_control_token: UUID,
    ) -> PendingFire | None:
        result = await self.session.execute(
            select(PendingFire).where(
                PendingFire.fire_id == fire_id,
                PendingFire.receipt_control_token == receipt_control_token,
            ),
        )
        return result.scalar_one_or_none()

    async def get_current(
        self,
        *,
        fire_id: UUID,
        receipt_control_token: UUID,
    ) -> PendingFire | None:
        return await self._get_by_identity(
            fire_id,
            receipt_control_token,
        )


def _same_datetime(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return left is right
    left_utc = left.replace(tzinfo=UTC) if left.tzinfo is None else left.astimezone(UTC)
    right_utc = right.replace(tzinfo=UTC) if right.tzinfo is None else right.astimezone(UTC)
    return left_utc == right_utc


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _complete_current_pending(pending: PendingFire) -> bool:
    return (
        pending.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and pending.state_write_nonce is not None
        and pending.receipt_control_token is not None
        and pending.definition_digest is not None
        and pending.expected_schedule_revision is not None
        and pending.expected_next_run_at is not None
        and pending.acceptance_revision is not None
        and pending.execution_fire_id is not None
        and isinstance(pending.payload, dict)
        and pending.payload.get("fire_id") == str(pending.execution_fire_id)
    )


def _require_fire_matches_pending(
    fire: ScheduleFire,
    pending: PendingFire,
) -> None:
    exact = (
        fire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and fire.state_write_nonce is not None
        and fire.schedule_id == pending.schedule_id
        and fire.project_id == pending.project_id
        and fire.fire_id == pending.fire_id
        and _same_datetime(fire.scheduled_for, pending.scheduled_for)
        and fire.observed_control_token == pending.observed_control_token
        and fire.receipt_control_token == pending.receipt_control_token
        and fire.acceptance_revision == pending.acceptance_revision
        and fire.definition_digest == pending.definition_digest
        and fire.expected_schedule_revision == pending.expected_schedule_revision
        and _same_datetime(
            fire.expected_last_run_at,
            pending.expected_last_run_at,
        )
        and _same_datetime(
            fire.expected_next_run_at,
            pending.expected_next_run_at,
        )
        and _same_datetime(
            fire.prepared_next_run_at,
            pending.prepared_next_run_at,
        )
    )
    if not exact:
        raise ValueError(
            "retained fire history diverges from current pending fire",
        )


__all__ = [
    "CurrentPendingFireTransition",
    "PendingFiresRepository",
]
