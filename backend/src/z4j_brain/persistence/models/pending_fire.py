"""``pending_fires`` table - z4j-scheduler buffered-fire support.

Holds schedule fires that arrived from z4j-scheduler while no agent
was online for the schedule's engine. A background worker
(``PendingFiresReplayWorker``) replays these the moment a matching
agent comes online, honouring the schedule's ``catch_up`` policy.

Identified by the scheduler-generated ``fire_id`` (the same
idempotency key the dispatcher uses on its retries) so brain treats
duplicate FireSchedule attempts during the buffering window as
no-ops.

Per ``docs/SCHEDULER.md §11`` Phase 2.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import jsonb

#: Default TTL for buffered fires when the application path forgets
#: to set ``expires_at`` explicitly. Matches the operator-tunable
#: ``pending_fires_replay_buffer_ttl_seconds`` setting default
#: (7 days). Migration 2026_04_27_0010 mirrors this on the DB
#: side via ``server_default``; the Python default below is the
#: client-side belt-and-suspenders. Per ``docs/MIGRATIONS.md`` rule
#: #1: every NOT NULL column needs a ``server_default``.
_DEFAULT_EXPIRES_DELTA = timedelta(days=7)


def _default_expires_at() -> datetime:
    return datetime.now(UTC) + _DEFAULT_EXPIRES_DELTA


class PendingFire(Base):
    """One schedule fire awaiting replay when an agent comes online.

    Attributes:
        id: Surrogate primary key.
        fire_id: Scheduler's idempotency key
            (``uuid5(NAMESPACE, schedule_id + scheduled_for_iso)``).
            Unique - duplicate FireSchedule retries collapse here.
        schedule_id: The schedule this fire belongs to.
            ``ON DELETE CASCADE`` so deleting a schedule clears any
            buffered fires for it.
        project_id: Owning project.
        engine: Engine adapter the agent must advertise to receive
            this fire (e.g. ``celery``, ``rq``).
        payload: The same dict ``CommandDispatcher.issue`` would
            receive at fire time. Kept verbatim so replay
            reproduces the exact original intent rather than
            re-deriving from the schedule (which the operator may
            have edited during the outage).
        scheduled_for: When the fire was originally meant to run.
            Used by the replay worker to order ``fire_all_missed``
            replays.
        enqueued_at: Wall-clock when brain buffered the fire.
        expires_at: After this time the sweep worker drops the
            row. Operators tune via
            ``Z4J_PENDING_FIRES_RETENTION_DAYS`` (default 7d).
    """

    __tablename__ = "pending_fires"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    fire_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), nullable=False,
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("schedules.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[Any] = mapped_column(jsonb(), nullable=False)
    scheduled_for: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    enqueued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_default_expires_at,
    )

    __table_args__ = (
        UniqueConstraint("fire_id", name="uq_pending_fires_fire_id"),
        Index(
            "ix_pending_fires_replay",
            "project_id", "engine", "scheduled_for",
        ),
        Index("ix_pending_fires_expires", "expires_at"),
    )


__all__ = ["PendingFire"]
