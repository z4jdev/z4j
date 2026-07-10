"""z4j 1.7 add outbox ``next_attempt_at`` backoff + project index.

Revision ID: v1_7_outbox_backoff
Revises: v1_7_misfire_alerts
Create Date: 2026-07-07

Two additive changes to ``automation_firing_outbox`` for drain fairness:

* ``next_attempt_at`` (nullable timestamptz): a FAILED replay sets this to a
  future backoff so a poison / transiently-failing row at the FIFO head no
  longer blocks fresh rows behind it -- the drain query skips not-yet-due
  rows. NULL = eligible now (all existing rows backfill NULL, so they stay
  immediately drainable).
* ``ix_automation_firing_outbox_project`` on ``project_id``: the per-project
  cap ``COUNT(*)`` and the per-tenant fairness exclusion filtered
  ``project_id`` unindexed (a seq scan on the awaited WS receive path).

Both additive + backfilled, so running N-1 brains are unaffected (a
pre-column brain never reads or writes them). Bidirectional per the 1.4
compat floor; a guarded no-op on a fresh install (the initial migration
builds the column + index from current model metadata).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_7_outbox_backoff"
down_revision: str | Sequence[str] | None = "v1_7_misfire_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_misfire_alerts",
    "downgrade_to": "v1_7_misfire_alerts",
}

_TABLE = "automation_firing_outbox"
_COLUMN = "next_attempt_at"
_INDEX = "ix_automation_firing_outbox_project"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        op.add_column(
            _TABLE,
            sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True),
        )
    if not _index_exists(bind, _TABLE, _INDEX):
        op.create_index(_INDEX, _TABLE, ["project_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if _index_exists(bind, _TABLE, _INDEX):
        op.drop_index(_INDEX, table_name=_TABLE)
    if not _column_exists(bind, _TABLE, _COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_TABLE, _COLUMN)
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)
