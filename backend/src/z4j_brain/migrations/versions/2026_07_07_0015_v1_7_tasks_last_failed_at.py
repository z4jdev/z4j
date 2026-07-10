"""z4j 1.7 add ``tasks.last_failed_at`` (Issues failure-time windows).

Revision ID: v1_7_tasks_last_failed_at
Revises: v1_7_outbox_backoff
Create Date: 2026-07-07

The Issues view's first/last-seen windows used ``coalesce(finished_at,
created_at)``, but ``finished_at`` is overwritten when a task recovers
(TASK_SUCCEEDED), so a long-ago failure that recovered recently surfaced as
recent activity. This column records when a task LAST failed and, like
``fingerprint``, is not cleared on recovery, so the aggregation can key its
failure windows on failure time.

One nullable timestamptz column, additive + backfilled NULL, so running N-1
brains are unaffected and existing failed rows fall back to the old
coalesce until they next fail. Bidirectional per the 1.4 compat floor; a
guarded no-op on a fresh install (the initial migration already builds the
column from current model metadata).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_7_tasks_last_failed_at"
down_revision: str | Sequence[str] | None = "v1_7_outbox_backoff"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_outbox_backoff",
    "downgrade_to": "v1_7_outbox_backoff",
}

_TABLE = "tasks"
_COLUMN = "last_failed_at"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        op.add_column(
            _TABLE,
            sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_TABLE, _COLUMN)
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)
