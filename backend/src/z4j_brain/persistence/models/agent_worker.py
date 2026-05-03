"""``agent_workers`` table - one row per worker process per agent (1.2.1+).

This is DISTINCT from the pre-existing ``workers`` table. The
``workers`` table tracks engine-native workers (Celery / RQ /
Dramatiq processes registered with their broker). This table
tracks **z4j agent processes** - any process running our agent
code that connects to the brain via WebSocket. Concepts:

- A gunicorn web worker is an ``agent_worker`` (it runs Django
  with z4j-django installed) but NOT a ``worker`` (it doesn't
  consume from a Celery queue).
- A Celery worker process is BOTH: an ``agent_worker`` (it
  loaded z4j-celery's signal hooks) and a ``worker`` (the
  broker knows it).
- celery-beat is an ``agent_worker`` (z4j-celerybeat hooks),
  not a ``worker`` (beat doesn't consume tasks).

The dashboard's /workers page in 1.2.1+ joins both: every
``agent_worker`` is shown, with optional engine-side details
from ``workers`` when there's a hostname/pid match.

Lifecycle:

- **register**: gateway upserts on each ``hello`` frame with
  state='online', refreshes last_seen_at + last_connect_at.
  Composite key (agent_id, worker_id) prevents duplicates.
- **heartbeat**: each heartbeat refreshes last_seen_at; state
  stays 'online'.
- **unregister**: WebSocket close flips state='offline'. Row
  stays for history (the operator can answer "what workers ran
  on this host yesterday").
- **garbage collection**: 1.3.0 will add a periodic sweep to
  delete offline rows older than ``Z4J_WORKER_RETENTION_DAYS``.
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
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class AgentWorker(PKMixin, TimestampsMixin, Base):
    """One discrete worker process under an agent_id.

    Attributes:
        agent_id: FK to ``agents.id``.
        project_id: FK to ``projects.id``. Denormalized for fast
            project-scoped queries.
        worker_id: Wire-level identifier the agent generated
            (``<framework>-<pid>-<unix_ms>``). NULL for legacy
            1.1.x clients (one such NULL slot per agent_id).
        role: Worker role hint: ``web``, ``task``, ``scheduler``,
            ``beat``, ``other``, or NULL.
        framework: Framework adapter that loaded this worker
            (``django``, ``flask``, ``fastapi``, ``bare``, ...).
        pid: OS pid the agent reported.
        started_at: When the worker process started.
        state: ``online`` while WebSocket is connected;
            ``offline`` after disconnect.
        last_seen_at: Refreshed on every heartbeat frame.
        last_connect_at: Most recent ``register`` timestamp.
    """

    __tablename__ = "agent_workers"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    worker_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True,
    )
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    framework: Mapped[str | None] = mapped_column(String(40), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    state: Mapped[str] = mapped_column(
        String(20), nullable=False, default="online",
        server_default="online",
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    last_connect_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    __table_args__ = (
        # (agent_id, worker_id) is the natural composite key.
        # NULL worker_id (legacy 1.1.x slot) is treated as
        # distinct by Postgres' default UNIQUE semantics, so
        # multiple NULL worker_ids could in theory coexist - but
        # the gateway gates this: at most one NULL slot per
        # agent_id can register at a time (in-memory registry
        # enforces). Acceptable: the write here is idempotent
        # via ON CONFLICT DO UPDATE in the upsert path.
        UniqueConstraint(
            "agent_id", "worker_id", name="uq_agent_workers_agent_worker",
        ),
        Index("ix_agent_workers_project_state", "project_id", "state"),
        Index("ix_agent_workers_agent_state", "agent_id", "state"),
    )


__all__ = ["AgentWorker"]
