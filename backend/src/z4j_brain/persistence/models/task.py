"""``tasks`` table - latest-known state per task instance."""

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
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskPriority, TaskState
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import big_integer, jsonb, text_array, tsvector


class Task(PKMixin, TimestampsMixin, Base):
    """Latest-known state of a single task instance.

    Updated as events arrive - the EventIngestor projects raw events
    onto this row. Args, kwargs, and result are *already redacted*
    by the agent before they reach the brain; the brain re-applies
    redaction as defence in depth before storing.

    The ``search_vector`` column holds a Postgres ``TSVECTOR`` for
    full-text search; on SQLite it is a plain ``TEXT`` column kept
    null. The trigger that maintains it is created in B5 when search
    lands.

    Attributes:
        project_id: Owning project. ``ON DELETE CASCADE``.
        engine: Engine adapter that produced this task.
        task_id: Engine-native task id (Celery's UUIDv4 string,
            RQ's job id, ...).
        name: Fully-qualified task name (``myapp.tasks.send_email``).
        queue: Queue the task ran on, if known.
        state: Current task state - see :class:`TaskState`.
        args / kwargs: Redacted positional + keyword args as JSONB.
        result: Redacted return value, when ``state == 'success'``.
        exception: Exception class name on failure.
        traceback: Truncated, redacted traceback on failure.
        retry_count: Number of times the engine has retried this
            task.
        eta: Scheduled execution time, if delayed.
        received_at / started_at / finished_at: Lifecycle timestamps.
        runtime_ms: Wall-clock execution time in milliseconds.
        worker_name: Worker that executed the task.
        parent_task_id / root_task_id: For chains/groups/chords.
        tags: Free-form per-task tags from the engine adapter.
        search_vector: Postgres tsvector for full-text search.
    """

    __tablename__ = "tasks"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    task_id: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    queue: Mapped[str | None] = mapped_column(String(200), nullable=True)
    state: Mapped[TaskState] = mapped_column(
        Enum(
            TaskState,
            name="task_state",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=TaskState.PENDING,
        server_default=TaskState.PENDING.value,
    )
    priority: Mapped[TaskPriority] = mapped_column(
        Enum(
            TaskPriority,
            name="task_priority",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=TaskPriority.NORMAL,
        server_default=TaskPriority.NORMAL.value,
    )
    args: Mapped[Any | None] = mapped_column(jsonb(), nullable=True)
    kwargs: Mapped[Any | None] = mapped_column(jsonb(), nullable=True)
    result: Mapped[Any | None] = mapped_column(jsonb(), nullable=True)
    exception: Mapped[str | None] = mapped_column(Text, nullable=True)
    traceback: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    eta: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    runtime_ms: Mapped[int | None] = mapped_column(big_integer(), nullable=True)
    worker_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    parent_task_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    root_task_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tags: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list, server_default="{}",
    )
    task_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    search_vector: Mapped[str | None] = mapped_column(
        tsvector(), nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id", "engine", "task_id",
            name="uq_tasks_project_engine_task_id",
        ),
        Index(
            "ix_tasks_project_state_started",
            "project_id", "state", "started_at",
        ),
        Index("ix_tasks_project_name", "project_id", "name"),
        Index("ix_tasks_project_queue", "project_id", "queue"),
        Index("ix_tasks_project_finished", "project_id", "finished_at"),
        # Postgres-only indexes (GIN on jsonb_path_ops, GIN on tsvector,
        # partial idx on parent/root) are added in the migration as
        # raw SQL with a dialect check - SQLite cannot represent them.
    )


__all__ = ["Task"]
