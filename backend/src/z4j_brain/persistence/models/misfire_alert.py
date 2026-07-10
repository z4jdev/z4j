"""``misfire_alerts`` -- durable cross-replica misfire dedup ledger."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class MisfireAlert(PKMixin, TimestampsMixin, Base):
    """One misfire episode already alerted for a schedule.

    The MisfireDetector runs on whichever brain replica wins a given
    sweep's per-tick advisory lock (leadership rotates tick to tick), each
    with its own in-memory state, so a purely in-memory dedup duplicates
    audit rows / notifications / firings across replicas. This table is the
    shared, durable claim: a replica INSERTs a ``(schedule_id, anchor_at)``
    row and alerts only if the insert won the UNIQUE, so a persistent
    misfire episode is alerted exactly once fleet-wide.

    ``anchor_at`` is the episode key -- ``last_run_at`` if the schedule has
    fired, else ``created_at``. It is stable while the schedule stays down
    and advances (a new episode) only when the scheduler fires it again. It
    is NON-nullable so the UNIQUE actually dedups: a NULL ``last_run_at``
    would make every sweep a distinct row on Postgres.
    """

    __tablename__ = "misfire_alerts"

    schedule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("schedules.id", ondelete="CASCADE"),
        nullable=False,
    )
    anchor_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "schedule_id",
            "anchor_at",
            name="uq_misfire_alerts_schedule_anchor",
        ),
        # Retention prune sweeps by age.
        Index("ix_misfire_alerts_created", "created_at"),
    )


__all__ = ["MisfireAlert"]
