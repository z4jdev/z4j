"""``task_annotations`` table - operator notes on tasks.

When an operator investigates a failing task, they need to leave
notes for the team: "known issue, deploying fix", "customer
contacted", "retry scheduled for 6am", etc.

This is enterprise gold - incident responders collaborate through
annotations without leaving the dashboard.

Phase 2 feature. Table created in initial schema.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class TaskAnnotation(PKMixin, TimestampsMixin, Base):
    """An operator-authored note attached to a task."""

    __tablename__ = "task_annotations"

    task_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    annotation_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="note", server_default="note",
    )  # note, status_change, escalation, resolution


__all__ = ["TaskAnnotation"]
