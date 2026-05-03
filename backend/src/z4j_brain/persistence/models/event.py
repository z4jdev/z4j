"""``events`` table - raw lifecycle events, partitioned by day.

This table is the hot path. It is range-partitioned on
``occurred_at`` so retention is O(1) - the RetentionWorker simply
drops yesterday's partition once it ages out. The composite primary
key ``(occurred_at, id)`` is required because Postgres demands the
partition column be part of the PK.

Production runs Postgres 18+ and benefits from ``uuidv7()``
time-ordered ids on the ``id`` column; the migration installs that
default if the running Postgres is v18 or newer, falling back to
``gen_random_uuid()`` on v17. The Python-side default is always
``uuid.uuid4`` so SQLite tests work too.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    PrimaryKeyConstraint,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import jsonb


class Event(Base):
    """A raw lifecycle event reported by an agent.

    Composite PK on ``(occurred_at, id)`` so the partitioning column
    is part of the key - Postgres requirement for partitioned tables.
    The migration creates the table ``WITH (postgresql_partition_by =
    'RANGE (occurred_at)')`` and pre-creates 7 days of partitions.

    Attributes:
        id: Per-row UUID. Defaults to ``uuid.uuid4`` Python-side; the
            migration installs ``uuidv7()`` (PG18+) or
            ``gen_random_uuid()`` (PG17) as the server default.
        project_id: Owning project. ``ON DELETE CASCADE``.
        agent_id: Agent that reported this event.
            ``ON DELETE CASCADE``.
        engine: Engine adapter that produced the event.
        task_id: Engine-native task id this event refers to. May be
            an empty string for non-task events (worker.online, ...).
        kind: Event taxonomy tag (``task.received``, ``task.failed``,
            ``schedule.created``, ``worker.online``, ...).
        occurred_at: When the event happened on the source side.
            Used as the partitioning key.
        payload: Redacted event payload as JSONB.
    """

    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        # RESTRICT (not CASCADE) because the events table is
        # typically the largest in the schema - a CASCADE from a
        # 50M-row project would lock every daily partition in one
        # transaction and take hours. Operators purge events via
        # the retention worker (or an explicit DELETE) FIRST,
        # then the project delete / archive succeeds. R4 follow-up.
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        # Same rationale - retain events after an agent's row is
        # archived. Agent revoke uses a soft delete anyway.
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    task_id: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default="",
    )
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )

    __table_args__ = (
        # PK includes ``project_id`` so a Project-A agent cannot
        # collide its event_id with a Project-B row and silently
        # censor the legitimate write via ON CONFLICT DO NOTHING.
        # Defence in depth: the brain ALSO derives the per-row
        # ``id`` via uuid5(namespace, project_id || agent_event_id)
        # in EventIngestor, so two projects cannot generate the
        # same id by construction - but the wider PK guarantees
        # safety even if a future refactor drops that namespacing.
        # ``occurred_at`` must remain in the PK because Postgres
        # partitioned tables require the partition column.
        PrimaryKeyConstraint(
            "project_id", "occurred_at", "id", name="pk_events",
        ),
        Index(
            "ix_events_project_task",
            "project_id", "task_id", "occurred_at",
        ),
        Index(
            "ix_events_project_kind",
            "project_id", "kind", "occurred_at",
        ),
        # The PARTITION BY RANGE (occurred_at) is added in the
        # alembic migration via raw SQL - SQLAlchemy's
        # ``postgresql_partition_by`` option is supplied there too,
        # but the model itself stays portable for SQLite tests.
    )


__all__ = ["Event"]
