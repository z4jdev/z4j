"""z4j 1.5.0 add ``agent_status_history`` table.

Revision ID: v1_5_agent_status_history
Revises: v1_3_0_initial
Create Date: 2026-05-20

Phase H of the 1.5.0 foundation release adds an ``AgentStatusFrame``
that agents emit alongside the heartbeat (default 10s cadence). The
brain persists each frame to ``agent_status_history`` so the
dashboard can render a per-agent flap timeline without parsing logs.

Schema (mirrors the ORM model in
``z4j_brain.persistence.models.agent_status_history``):

- ``id`` BIGSERIAL on Postgres, BIGINT on SQLite (autoincrement
  rowid alias). 64-bit because every connected agent emits one row
  every 10s; a single homelab brain doing 50 agents over 90 days
  hits ~38M rows, comfortably under the int64 ceiling.
- ``project_id`` UUID NOT NULL, FK ``projects.id`` ON DELETE
  CASCADE.
- ``agent_id`` UUID NOT NULL, FK ``agents.id`` ON DELETE CASCADE.
- ``captured_at`` TIMESTAMPTZ NOT NULL (the frame's ``ts`` field).
- ``payload`` JSONB on Postgres, JSON on SQLite. The full
  :class:`AgentStatusPayload` rendered as a dict.
- Two indexes: ``agent_status_history_agent_time_idx`` on
  ``(agent_id, captured_at)`` and
  ``agent_status_history_project_time_idx`` on
  ``(project_id, captured_at)``. Both are non-unique because the
  table accumulates many rows per (agent, time) tuple at sub-second
  resolution.

DOWNGRADE COMPATIBILITY: ``downgrade()`` drops the table and its
indexes. Any agent_status data captured during 1.5+ is lost on
downgrade; the agent will re-emit the next status snapshot on the
next heartbeat once the brain is rolled back forward, so the loss
is bounded by the time spent on the older release.

The migration works on both Postgres and SQLite; SQLAlchemy emits
the right CREATE TABLE per dialect via ``Base.metadata.create_all``
on a single-table subset.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.agent_status_history import (
    AgentStatusHistory,
)


# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_5_agent_status_history"
down_revision: str | Sequence[str] | None = "v1_3_0_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# ---------------------------------------------------------------------------
# Compatibility metadata (1.3.x convention, extended for 1.5)
# ---------------------------------------------------------------------------
#
# Read by ``z4j_brain.main.create_app`` at startup AND by the
# ``z4j migrate check`` CLI. The brain refuses to start if its own
# version is below ``min_z4j_version`` for ANY migration in the
# chain, so an operator on z4j-brain 1.3.x cannot accidentally
# apply this 1.5 migration. Pinning at 1.5.0 enforces the floor.

compat = {
    "min_z4j_version": "1.5.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_3_0_initial",
    "downgrade_to": "v1_3_0_initial",
}


# ---------------------------------------------------------------------------
# upgrade() / downgrade()
# ---------------------------------------------------------------------------


def upgrade() -> None:
    """Create the ``agent_status_history`` table + its two indexes.

    Uses :meth:`Base.metadata.create_all` with an explicit ``tables=``
    subset so SQLAlchemy emits the right CREATE TABLE for whichever
    dialect we're running on (BIGSERIAL on Postgres, INTEGER rowid
    alias on SQLite). The indexes declared on the model's
    ``__table_args__`` are created in the same call.
    """
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind,
        tables=[AgentStatusHistory.__table__],
    )


def downgrade() -> None:
    """Drop the ``agent_status_history`` table.

    Indexes are dropped automatically with the table (Postgres CASCADE
    is implicit; SQLite drops indexes on table drop). Data captured
    during 1.5+ is lost; the agent re-emits on the next heartbeat
    once the brain rolls back forward, so the loss is bounded by the
    time spent on the older release.
    """
    bind = op.get_bind()
    AgentStatusHistory.__table__.drop(bind=bind, checkfirst=True)
