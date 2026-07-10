"""``automation_firing_outbox`` -- durable buffer for dropped firings.

When the frame router cannot dispatch an automation firing inline (its
per-connection pending set is full under an event flood), the firing is
persisted here instead of being lost. A leader-only drain worker replays
each row through the executor and deletes it on success. Mirrors the
``pending_fires`` buffer + replay pattern used for scheduler fires.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class AutomationFiringOutbox(PKMixin, TimestampsMixin, Base):
    """One deferred automation firing awaiting replay."""

    __tablename__ = "automation_firing_outbox"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: The trigger to re-evaluate (e.g. ``task.failed``).
    trigger: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The event fields the executor matches rules against + passes to
    #: actions (task_id, task_name, engine, queue, exception, agent_id as a
    #: string, ...). JSON-safe; the drain hands this straight to
    #: ``run_matching``.
    fields: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    #: Replay attempts so far. A row that keeps failing is dropped after a
    #: cap so a poison row does not loop forever.
    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    #: Earliest time this row may be replayed again. NULL = eligible now.
    #: A FAILED replay sets this to a backoff in the future so a poison /
    #: transiently-failing row at the FIFO head does not block fresh rows
    #: behind it (head-of-line): the drain query skips not-yet-due rows.
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        # FIFO drain: oldest firings first.
        Index("ix_automation_firing_outbox_created", "created_at"),
        # Per-project cap COUNT(*) + per-tenant fairness exclusion.
        Index("ix_automation_firing_outbox_project", "project_id"),
    )


__all__ = ["AutomationFiringOutbox"]
