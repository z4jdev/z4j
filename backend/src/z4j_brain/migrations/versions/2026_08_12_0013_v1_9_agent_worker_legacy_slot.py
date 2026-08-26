"""Enforce one legacy NULL worker slot per agent.

``agent_workers`` originally relied on ``UNIQUE (agent_id, worker_id)`` for
both worker-aware rows and the legacy ``worker_id IS NULL`` slot. PostgreSQL
and SQLite both treat NULL values as distinct for an ordinary UNIQUE
constraint, so every reconnect could insert another legacy row. In-memory
registry ownership cannot arbitrate reconnects across brain replicas or
process restarts.

The upgrade first keeps the newest legacy observation for each agent and
removes older duplicates, then installs a partial UNIQUE index on ``agent_id``
for rows whose ``worker_id`` is NULL. The existing composite constraint remains
the arbiter for non-NULL worker IDs. PostgreSQL excludes concurrent writers for
the dedupe/index window; the migration environment already gives SQLite an
exclusive migration transaction.

Revision ID: v1_9_agent_worker_legacy_slot
Revises: v1_9_schedule_control_columns
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_9_agent_worker_legacy_slot"
down_revision: str | Sequence[str] | None = "v1_9_schedule_control_columns"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "agent_workers"
_INDEX = "ux_agent_workers_legacy_agent"


def _index_exists(bind: sa.engine.Connection) -> bool:
    """Whether a fresh metadata-driven baseline already created the index."""

    return any(index["name"] == _INDEX for index in sa.inspect(bind).get_indexes(_TABLE))


def _deduplicate_legacy_slots(bind: sa.engine.Connection) -> None:
    """Keep the newest legacy observation for each agent.

    Explicit NULL ranks make the survivor identical on PostgreSQL and SQLite.
    UUID ``id`` is the final deterministic tiebreaker when all timestamps are
    equal.
    """

    bind.execute(
        sa.text(
            """
            WITH ranked AS (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY agent_id
                        ORDER BY
                            CASE WHEN last_connect_at IS NULL THEN 1 ELSE 0 END,
                            last_connect_at DESC,
                            CASE WHEN last_seen_at IS NULL THEN 1 ELSE 0 END,
                            last_seen_at DESC,
                            updated_at DESC,
                            created_at DESC,
                            id DESC
                    ) AS duplicate_rank
                FROM agent_workers
                WHERE worker_id IS NULL
            )
            DELETE FROM agent_workers
            WHERE id IN (
                SELECT id
                FROM ranked
                WHERE duplicate_rank > 1
            )
            """,
        ),
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Held until the migration transaction commits. Without this, a legacy
        # reconnect could insert a new duplicate between cleanup and index
        # creation and make CREATE UNIQUE INDEX fail nondeterministically.
        op.execute(f"LOCK TABLE {_TABLE} IN SHARE ROW EXCLUSIVE MODE")

    _deduplicate_legacy_slots(bind)
    # The consolidated initial migration creates tables from current model
    # metadata. A fresh installation therefore already has this index, while a
    # database upgraded from an older release does not. Keep both paths valid.
    if not _index_exists(bind):
        op.create_index(
            _INDEX,
            _TABLE,
            ["agent_id"],
            unique=True,
            postgresql_where=sa.text("worker_id IS NULL"),
            sqlite_where=sa.text("worker_id IS NULL"),
        )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name=_TABLE)


__all__ = ["_deduplicate_legacy_slots", "_index_exists", "downgrade", "upgrade"]
