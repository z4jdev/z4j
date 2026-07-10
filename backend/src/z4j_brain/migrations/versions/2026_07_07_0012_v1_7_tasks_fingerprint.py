"""z4j 1.7 add ``tasks.fingerprint`` (R4 Issues).

Revision ID: v1_7_tasks_fingerprint
Revises: v1_7_schedule_fires_partition
Create Date: 2026-07-07

Adds the stable failure fingerprint computed at ingestion when a task
transitions to FAILURE (see ``z4j_brain.domain.fingerprint``), plus the
``(project_id, fingerprint)`` index the Issues aggregation groups on.

One nullable String(32) column + one index, both additive and backfilled
NULL, so existing rows and running N-1 brains are unaffected (a pre-column
brain never reads or writes it). Bidirectional per the 1.4 compat floor.
Because the initial migration builds the schema from current model
metadata, a fresh install already has the column + index, so ``upgrade()``
is a guarded no-op there and a real ADD on a DB created before it existed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_7_tasks_fingerprint"
down_revision: str | Sequence[str] | None = "v1_7_schedule_fires_partition"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_schedule_fires_partition",
    "downgrade_to": "v1_7_schedule_fires_partition",
}

_TABLE = "tasks"
_COLUMN = "fingerprint"
_INDEX = "ix_tasks_project_fingerprint"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(length=32), nullable=True))
    if not _index_exists(bind, _TABLE, _INDEX):
        op.create_index(_INDEX, _TABLE, ["project_id", _COLUMN])


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
