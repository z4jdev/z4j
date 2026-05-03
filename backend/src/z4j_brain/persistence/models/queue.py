"""``queues`` table - known queues per project / engine."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class Queue(PKMixin, TimestampsMixin, Base):
    """A task queue observed by an agent.

    The brain learns about queues from event stream + adapter
    discovery; users do not create rows here directly. The
    ``broker_url_hint`` is *not* the live broker URL - it's a
    redacted hint string the agent supplies for diagnostic display.

    Attributes:
        project_id: Owning project.
        name: Engine-native queue name.
        engine: Engine adapter that owns this queue (``celery``,
            ``rq``, ``dramatiq``, ...).
        broker_type: ``redis`` / ``rabbitmq`` / ``sqs`` / ... if known.
        broker_url_hint: Redacted display string. Never the full URL
            with credentials.
        last_seen_at: Most recent observation timestamp.
    """

    __tablename__ = "queues"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    broker_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    broker_url_hint: Mapped[str | None] = mapped_column(String, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    pending_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    consumer_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    queue_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id", "engine", "name", name="uq_queues_project_engine_name",
        ),
        Index("ix_queues_project_id", "project_id"),
    )


__all__ = ["Queue"]
