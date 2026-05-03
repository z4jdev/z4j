"""``commands`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import Command
from z4j_brain.persistence.repositories._base import BaseRepository


class CommandRepository(BaseRepository[Command]):
    """Command CRUD + state transitions."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Command)

    # ------------------------------------------------------------------
    # Inserts
    # ------------------------------------------------------------------

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
    ) -> Command:
        """Insert a Command row. Idempotent on (project_id, idempotency_key).

        Round-4 audit fix (Apr 2026): when ``idempotency_key`` is set
        and a row with the same ``(project_id, idempotency_key)``
        already exists, return the existing row instead of raising
        ``IntegrityError``. Pre-fix, two scheduler instances ticking
        the same schedule (HA failover, retry-after-timeout, or two
        brain replicas behind a load balancer both serving a
        retried FireSchedule) both minted the same deterministic
        ``fire_id = uuid5(NAMESPACE, schedule_id + scheduled_for)``;
        the second insert raised IntegrityError; the FireSchedule
        handler reported ``brain_error`` to the scheduler; the
        scheduler retried; the schedule wedged per-fire until
        something else broke the cycle.

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
            return existing
        return row

    # ------------------------------------------------------------------
    # State transitions (single UPDATE, guarded by current status)
    # ------------------------------------------------------------------

    async def mark_dispatched(
        self,
        command_id: UUID,
        *,
        project_id: UUID | None = None,
        agent_id: UUID | None = None,
    ) -> bool:
        """Pending → dispatched. Returns True if the row transitioned."""
        predicates = [
            Command.id == command_id,
            Command.status == CommandStatus.PENDING,
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
                dispatched_at=datetime.now(UTC),
            ),
        )
        return (result.rowcount or 0) > 0

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
            Command.status.in_(
                [CommandStatus.PENDING, CommandStatus.DISPATCHED],
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
            Command.status.in_(
                [CommandStatus.PENDING, CommandStatus.DISPATCHED],
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
            update(Command)
            .where(
                Command.status.in_(
                    [CommandStatus.PENDING, CommandStatus.DISPATCHED],
                ),
                Command.timeout_at < now,
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
