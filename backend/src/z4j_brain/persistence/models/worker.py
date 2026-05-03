"""``workers`` table - known worker processes per project / engine."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import big_integer, jsonb, text_array


class Worker(PKMixin, TimestampsMixin, Base):
    """A worker process observed by an agent.

    Workers come and go - the AgentHealthWorker marks them
    ``offline`` when their heartbeat is stale. Old offline workers
    are pruned after seven days; the FK from ``commands.target_id``
    is by string, not by row, so deletion is safe.

    Attributes:
        project_id: Owning project.
        engine: Engine adapter that owns this worker.
        name: Engine-native worker name (``celery@web-01``, ...).
        hostname: Operator-visible host name from the heartbeat
            payload.
        pid: Worker process id, if reported.
        concurrency: Worker concurrency setting, if reported.
        queues: Queues this worker drains.
        state: ``online`` / ``offline`` / ``draining`` / ``unknown``.
        last_heartbeat: Most recent heartbeat timestamp from this
            specific worker.
        load_average: Reported [1m, 5m, 15m] loads as a JSON list
            (Postgres uses ``REAL[]``; SQLite uses JSON).
        memory_bytes: Worker RSS in bytes, if reported.
        active_tasks: Number of tasks the worker is currently
            processing.
    """

    __tablename__ = "workers"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    queues: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list, server_default="{}",
    )
    state: Mapped[WorkerState] = mapped_column(
        Enum(
            WorkerState,
            name="worker_state",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=WorkerState.UNKNOWN,
        server_default=WorkerState.UNKNOWN.value,
    )
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    load_average: Mapped[list[float] | None] = mapped_column(
        # Stored as JSON to keep cross-dialect simple. Postgres
        # production uses REAL[] but the dashboard reads it as JSON
        # via SQLAlchemy's serialiser anyway.
        jsonb(),
        nullable=True,
    )
    memory_bytes: Mapped[int | None] = mapped_column(big_integer(), nullable=True)
    active_tasks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    worker_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id", "engine", "name", name="uq_workers_project_engine_name",
        ),
        Index("ix_workers_project_state", "project_id", "state"),
    )


__all__ = ["Worker"]
