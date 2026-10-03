"""Repository for :class:`AuditForwardState`, the forwarder's cursor.

Every write that moves the cursor is a compare-and-set on the row the
caller loaded: the UPDATE carries the ``last_forwarded_id`` the caller
believes is current and reports whether it matched. Under the leader
lock there is only one forwarder, so the comparison is expected to
hold; when it does not, the lock-holding connection died mid-pass and a
second replica took over, and the caller must stop rather than rewind
the cursor behind a row the other replica already delivered.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, func, literal, or_, select, tuple_, update
from sqlalchemy.exc import IntegrityError

from z4j_brain.persistence.models.audit_forward_state import AuditForwardState
from z4j_brain.persistence.models.audit_log import AuditLog
from z4j_brain.persistence.repositories._base import BaseRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def after_cursor_clause(
    dialect_name: str,
    occurred_at: datetime,
    row_id: uuid.UUID,
) -> Any:
    """Rows strictly after ``(occurred_at, row_id)`` in chain order.

    Same predicate ``AuditLogRepository.stream_for_verify`` uses, so the
    forwarder's count of what is pending and its page of what to send
    agree on the boundary. PostgreSQL gets the row comparison because it
    seeks into the ``occurred_at`` index; SQLite keeps the expanded form.
    """
    if dialect_name == "postgresql":
        return tuple_(AuditLog.occurred_at, AuditLog.id) > tuple_(
            literal(occurred_at, AuditLog.occurred_at.type),
            literal(row_id, AuditLog.id.type),
        )
    return or_(
        AuditLog.occurred_at > occurred_at,
        and_(AuditLog.occurred_at == occurred_at, AuditLog.id > row_id),
    )


class AuditForwardStateRepository(BaseRepository[AuditForwardState]):
    """Cursor reads and compare-and-set writes for one sink."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AuditForwardState)

    def _dialect(self) -> str:
        return self.session.get_bind().dialect.name

    async def get_for_sink(self, sink_id: str) -> AuditForwardState | None:
        return await self.session.get(AuditForwardState, sink_id)

    async def latest_audit_key(self) -> tuple[datetime, uuid.UUID] | None:
        """The chain-order key of the newest audit row, or None when empty."""
        stmt = (
            select(AuditLog.occurred_at, AuditLog.id)
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(1)
        )
        row = (await self.session.execute(stmt)).first()
        if row is None:
            return None
        return row[0], row[1]

    async def get_or_initialise(
        self,
        sink_id: str,
        *,
        start_at_head: bool = True,
    ) -> AuditForwardState:
        """Return the sink's row, creating it on first use.

        A new row starts at the current audit head when ``start_at_head``
        is set, so enabling the forwarder mirrors rows written from then
        on rather than replaying the whole retained history into the
        receiver. Starting from nothing (``start_at_head=False``) is the
        backfill case.

        Creation races only with another replica that lost the leader
        lock, which is why the INSERT is a savepoint: the loser re-reads
        the winner's row instead of failing the pass.
        """
        existing = await self.get_for_sink(sink_id)
        if existing is not None:
            return existing
        occurred_at: datetime | None = None
        row_id: uuid.UUID | None = None
        if start_at_head:
            head = await self.latest_audit_key()
            if head is not None:
                occurred_at, row_id = head
        row = AuditForwardState(
            sink_id=sink_id,
            last_forwarded_occurred_at=occurred_at,
            last_forwarded_id=row_id,
            consecutive_failures=0,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            self.session.expunge(row)
            raced = await self.get_for_sink(sink_id)
            if raced is None:  # pragma: no cover - the race winner's row exists by definition
                raise
            return raced
        return row

    async def count_pending(
        self,
        *,
        after_occurred_at: datetime | None,
        after_id: uuid.UUID | None,
    ) -> int:
        """Audit rows strictly after the cursor: the forwarder's lag."""
        stmt = select(func.count()).select_from(AuditLog)
        if after_occurred_at is not None and after_id is not None:
            stmt = stmt.where(after_cursor_clause(self._dialect(), after_occurred_at, after_id))
        return int((await self.session.execute(stmt)).scalar_one())

    def _expected(self, expected_last_id: uuid.UUID | None) -> Any:
        if expected_last_id is None:
            return AuditForwardState.last_forwarded_id.is_(None)
        return AuditForwardState.last_forwarded_id == expected_last_id

    async def advance(
        self,
        sink_id: str,
        *,
        expected_last_id: uuid.UUID | None,
        occurred_at: datetime,
        row_id: uuid.UUID,
        at: datetime,
    ) -> bool:
        """Move the cursor to ``(occurred_at, row_id)`` after a 2xx.

        Returns False, changing nothing, when the row's current cursor is
        not ``expected_last_id``: someone else moved it.
        """
        stmt = (
            update(AuditForwardState)
            .where(AuditForwardState.sink_id == sink_id, self._expected(expected_last_id))
            .values(
                last_forwarded_occurred_at=occurred_at,
                last_forwarded_id=row_id,
                last_attempt_at=at,
                last_success_at=at,
                consecutive_failures=0,
                updated_at=at,
            )
        )
        result = await self.session.execute(stmt)
        return int(getattr(result, "rowcount", 0) or 0) == 1

    async def record_failure(
        self,
        sink_id: str,
        *,
        expected_last_id: uuid.UUID | None,
        at: datetime,
    ) -> bool:
        """Count one failed attempt without moving the cursor."""
        stmt = (
            update(AuditForwardState)
            .where(AuditForwardState.sink_id == sink_id, self._expected(expected_last_id))
            .values(
                last_attempt_at=at,
                consecutive_failures=AuditForwardState.consecutive_failures + 1,
                updated_at=at,
            )
        )
        result = await self.session.execute(stmt)
        return int(getattr(result, "rowcount", 0) or 0) == 1


__all__ = ["AuditForwardStateRepository", "after_cursor_clause"]
