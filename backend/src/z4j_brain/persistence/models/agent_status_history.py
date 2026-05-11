"""``agent_status_history`` table - per-agent self-reported status snapshots.

Phase H (1.5.0+): every connected agent emits one ``agent_status`` frame
per heartbeat tick (default 10s). The frame carries per-error-class
consecutive failure streaks, last-success / session-age timestamps,
local-buffer depth + oldest-entry age, and adapter inventory. The
brain persists each frame here so the dashboard can render a per-agent
flap timeline without parsing logs.

Why a dedicated table rather than folding the data into ``events``:

- Events are partitioned by ``occurred_at`` and have a hot-path
  ingest contract (composite PK, FOR UPDATE SKIP LOCKED purge).
  Stuffing 10s heartbeats into that partition stream inflates
  per-day partition size and competes with the real lifecycle
  events for vacuum + query budget.
- agent_status is observability data: append-only, not load-bearing
  for control-plane decisions. The retention sweeper purges rows
  older than ``Z4J_EVENT_RETENTION_DAYS`` (same retention as
  events, since it's similar high-frequency observability).
- A clean schema lets the dashboard render flap timelines without
  having to filter ``events`` by kind first.

Rows are append-only by application convention; there is no
update path. The repository's purge method is the only legitimate
DELETE caller (driven by the retention sweeper).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import jsonb


class AgentStatusHistory(Base):
    """A single agent_status frame snapshot.

    Attributes:
        id: Auto-incrementing 64-bit row id. Not a UUID because this
            table only holds machine-generated rows; the BIGINT keeps
            insert cost minimal on the heartbeat hot path.
        project_id: Owning project. ``ON DELETE CASCADE`` so deleting
            a project drops its accumulated status history with it.
        agent_id: Reporting agent. ``ON DELETE CASCADE`` for the
            same reason.
        captured_at: The frame's ``ts`` field, i.e. when the agent
            built the snapshot. Indexed alongside agent_id and
            project_id for the dashboard's "show last 100 statuses
            for agent X" / "purge older than cutoff" queries.
        payload: The full :class:`AgentStatusPayload` rendered as a
            JSON dict. Stored as JSONB on Postgres / JSON on SQLite.
            Schema is versioned via the embedded ``protocol_version``
            field; the dashboard renders unknown future fields as
            "(new)" without crashing.
    """

    __tablename__ = "agent_status_history"

    # On Postgres we want ``BIGSERIAL`` so 50 agents over 90 days
    # of 10s heartbeats (~38M rows) doesn't risk an int32 overflow.
    # On SQLite we want plain ``INTEGER`` because SQLite makes
    # ``INTEGER PRIMARY KEY`` an alias for ROWID (auto-incrementing
    # 64-bit), and using ``BIGINT PRIMARY KEY`` on SQLite breaks
    # that alias - the column then requires an explicit value on
    # insert. ``with_variant`` keeps the right type per dialect.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )

    __table_args__ = (
        # Per-agent timeline lookup: "show me the last N status rows
        # for this agent." DESC index so the dashboard's most-recent-
        # first ORDER BY is index-only.
        Index(
            "agent_status_history_agent_time_idx",
            "agent_id",
            "captured_at",
        ),
        # Per-project timeline lookup: "show me the most recent status
        # snapshots across the whole project." Used by the project-
        # level fleet view and by the retention sweeper's range scan.
        Index(
            "agent_status_history_project_time_idx",
            "project_id",
            "captured_at",
        ),
    )


__all__ = ["AgentStatusHistory"]
