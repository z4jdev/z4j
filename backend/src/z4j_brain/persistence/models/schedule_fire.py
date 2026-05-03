"""``schedule_fires`` table - per-fire history.

Records every fire dispatched by the z4j-scheduler. The schedules
row carries last_run_at + total_runs for "what's going on right
now"; this table carries the historical detail operators need to
debug "did the 3am cron actually fire?"

One row per fire_id. The scheduler's idempotency-keyed retries
collapse here via the unique constraint on fire_id.

Per ``docs/SCHEDULER.md §11`` Phase 4.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base


#: Possible ``status`` values. The scheduler progresses one row
#: through these states. Stored as TEXT so future statuses don't
#: need a migration; validated at the API layer.
#:
#: - ``pending``: row created, FireSchedule arrived but
#:   ``CommandDispatcher.issue`` hasn't returned yet.
#: - ``delivered``: brain dispatched the command to an online
#:   agent successfully.
#: - ``buffered``: no agent online; row landed in ``pending_fires``
#:   for replay.
#: - ``acked_success``: agent ran the task; AcknowledgeFireResult
#:   reported success.
#: - ``acked_failed``: agent reported a failure result.
#: - ``failed``: brain or transport error - never reached an agent.
SCHEDULE_FIRE_STATUS_VALUES = (
    "pending",
    "delivered",
    "buffered",
    "acked_success",
    "acked_failed",
    "failed",
)


class ScheduleFire(Base):
    """One historical fire of a schedule.

    Attributes:
        id: Surrogate primary key.
        fire_id: Scheduler's idempotency key
            (``uuid5(NAMESPACE, schedule_id + scheduled_for_iso)``).
            UNIQUE - retries collapse here.
        schedule_id: The schedule that fired.
            ``ON DELETE CASCADE`` so deleting a schedule clears its
            history.
        project_id: Owning project (denormalised from schedule for
            simple per-project listing queries).
        command_id: Brain-assigned Command UUID created by
            ``CommandDispatcher.issue``. ``NULL`` when the fire was
            buffered or rejected before reaching the dispatcher
            (status: ``buffered`` / ``failed``).
        status: One of :data:`SCHEDULE_FIRE_STATUS_VALUES`.
        scheduled_for: When the schedule was supposed to fire
            (the tick boundary the scheduler computed).
        fired_at: Wall-clock when brain wrote this row.
        acked_at: When AcknowledgeFireResult landed; ``NULL`` until
            the agent reports back.
        latency_ms: ``acked_at - fired_at`` in milliseconds. Lets
            the dashboard render a per-schedule latency chart
            without a join. ``NULL`` until the ack arrives.
        error_code / error_message: Failure detail when
            ``status in ('acked_failed', 'failed')``.
    """

    __tablename__ = "schedule_fires"
    __table_args__ = (
        UniqueConstraint("fire_id", name="uq_schedule_fires_fire_id"),
        Index(
            "ix_schedule_fires_schedule_recent",
            "schedule_id", "fired_at",
        ),
        Index(
            "ix_schedule_fires_circuit_breaker",
            "schedule_id", "status", "fired_at",
        ),
    )

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
    command_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("commands.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    scheduled_for: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    fired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    acked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(
        String(2000), nullable=True,
    )


__all__ = ["SCHEDULE_FIRE_STATUS_VALUES", "ScheduleFire"]
