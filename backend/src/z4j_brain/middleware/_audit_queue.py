"""Bounded async queue for denial-audit writes.

Round-4 audit fix (Apr 2026). The error middleware writes a
tamper-evident audit row for every denial / validation failure on
schedule-endpoint mutations (round-2 audit-on-denial fix). Pre-fix
the write opened a NEW DB session synchronously inside the request
scope, under attack (IDOR enumeration), every 4xx doubled the
per-request connection demand and starved the connection pool,
turning the audit safety net into a self-DoS amplifier.

This module gives the middleware a fire-and-forget enqueue path.
A single background drain task owns its own session and processes
denial events one at a time. The queue is bounded; on overflow we
drop the oldest event and increment a counter (operator's
"audit_queue_dropped_total" metric). Better to drop a denial-audit
row than to block the request handler.

Lifecycle:
    queue = AuditQueue()
    queue.start(db, settings)   # spawns the drain task
    queue.enqueue(event)        # called by middleware
    await queue.stop()          # called on lifespan shutdown
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.middleware._audit_queue")

#: Max events buffered before we start dropping the oldest. Sized
#: for a ~10s spike of 100 RPS sustained denials before we drop.
_QUEUE_MAX = 1024


@dataclass(slots=True, frozen=True)
class DenialAuditEvent:
    """One queued denial-audit event."""

    action: str
    target_type: str
    target_id: str
    outcome: str
    user_id: UUID | None
    project_slug: str
    source_ip: str | None
    user_agent: str | None
    method: str
    error_class: str
    message: str
    occurred_at: datetime


class AuditQueue:
    """Bounded queue + single drain task for denial-audit writes."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[DenialAuditEvent] = asyncio.Queue(
            maxsize=_QUEUE_MAX,
        )
        self._drain_task: asyncio.Task | None = None
        self._db: DatabaseManager | None = None
        self._settings: Settings | None = None
        self._dropped: int = 0
        self._stop_event = asyncio.Event()

    @property
    def dropped_count(self) -> int:
        """Cumulative count of events dropped due to queue overflow."""
        return self._dropped

    def start(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """Spawn the drain task. Idempotent."""
        if self._drain_task is not None:
            return
        self._db = db
        self._settings = settings
        self._stop_event.clear()
        self._drain_task = asyncio.create_task(
            self._drain_loop(),
            name="z4j.brain.audit_queue.drain",
        )

    async def stop(self) -> None:
        """Signal the drain task to exit + drain remaining events.

        Waits up to 5s for the drain task to clear the queue. If
        the task hasn't exited by then we cancel and move on (the
        remaining events are lost; we don't block the lifespan
        shutdown indefinitely on audit-write latency).
        """
        if self._drain_task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._drain_task, timeout=5.0)
        except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            self._drain_task.cancel()
            try:
                await self._drain_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._drain_task = None

    def enqueue(self, event: DenialAuditEvent) -> None:
        """Non-blocking enqueue. Drops oldest on overflow.

        Synchronous so the calling request handler doesn't await
        on the queue. Drop-on-overflow keeps the queue bounded
        even under attack.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest, then enqueue. Best effort - if both
            # operations race the queue may briefly grow past
            # max, that's fine (the next put will balance it).
            try:
                _ = self._queue.get_nowait()
                self._dropped += 1
                self._queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                self._dropped += 1

    async def _drain_loop(self) -> None:
        """Pull events from the queue and persist them one at a time."""
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                event = await asyncio.wait_for(
                    self._queue.get(), timeout=0.5,
                )
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                return
            # Round-8 audit fix R8-Async-H2 (Apr 2026): if the drain
            # is cancelled BETWEEN ``queue.get()`` and ``_write_one``
            # the event we just pulled is lost. Wrap the write in
            # ``shield`` so a cancel doesn't interrupt mid-INSERT,
            # and on cancel re-enqueue the event before re-raising
            # so the next start (or a stop's wait_for) still picks
            # it up. Combined with the ``stop()`` re-loop until
            # queue.empty() this preserves at-most-once-loss
            # semantics under graceful shutdown.
            try:
                await asyncio.shield(self._write_one(event))
            except asyncio.CancelledError:
                try:
                    self._queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._dropped += 1
                raise
            except Exception:  # noqa: BLE001
                logger.warning(
                    "z4j.brain.audit_queue: drain write failed for "
                    "action=%r path=%r (event dropped)",
                    event.action, event.target_id,
                    exc_info=True,
                )

    async def _write_one(self, event: DenialAuditEvent) -> None:
        """Persist one denial-audit event to ``audit_log``."""
        if self._db is None or self._settings is None:
            return
        from sqlalchemy import select  # noqa: PLC0415

        from z4j_brain.domain.audit_service import (  # noqa: PLC0415
            AuditService,
        )
        from z4j_brain.persistence.models import Project  # noqa: PLC0415
        from z4j_brain.persistence.repositories import (  # noqa: PLC0415
            AuditLogRepository,
        )

        async with self._db.session() as session:
            project_lookup = await session.execute(
                select(Project.id).where(
                    Project.slug == event.project_slug,
                ),
            )
            project_id: UUID | None = project_lookup.scalar_one_or_none()

            audit_repo = AuditLogRepository(session)
            await AuditService(self._settings).record(
                audit_repo,
                action=event.action,
                target_type=event.target_type,
                target_id=event.target_id,
                result="failed",
                outcome=event.outcome,
                user_id=event.user_id,
                project_id=project_id,
                source_ip=event.source_ip,
                user_agent=event.user_agent,
                metadata={
                    "method": event.method,
                    "error_class": event.error_class,
                    "message": event.message[:500],
                },
            )
            await session.commit()


__all__ = ["AuditQueue", "DenialAuditEvent"]
