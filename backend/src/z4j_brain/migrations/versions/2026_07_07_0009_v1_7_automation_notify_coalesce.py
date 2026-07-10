"""z4j 1.7 add ``automation_rules.last_notify_at`` (notify-coalesce state).

Revision ID: v1_7_automation_notify_coalesce
Revises: v1_7_schedule_fire_triggered_by
Create Date: 2026-07-07

Adds the per-rule notify-coalesce timestamp. When
``automation_notify_coalesce_seconds`` > 0, a rule's notify actions inside
that rolling window are suppressed so a distinct-event flood cannot fan out
one notification per event per member. The column is advanced under the
same FOR UPDATE row lock as the circuit breaker, so the check is race-free.

One nullable timestamp column. Additive + backfilled NULL, so existing
rows and running N-1 brains are unaffected (a pre-column brain never reads
or writes it, which just means no coalescing on that brain). Bidirectional
per the 1.4 compat floor. Because the initial migration builds the schema
from current model metadata, a fresh install already has this column, so
``upgrade()`` is a guarded no-op there and a real ADD COLUMN on a DB created
before the column existed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_automation_notify_coalesce"
down_revision: str | Sequence[str] | None = "v1_7_schedule_fire_triggered_by"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_schedule_fire_triggered_by",
    "downgrade_to": "v1_7_schedule_fire_triggered_by",
}

_TABLE = "automation_rules"
_COLUMN = "last_notify_at"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    """Add ``automation_rules.last_notify_at`` (nullable), idempotently."""
    bind = op.get_bind()
    if _column_exists(bind, _TABLE, _COLUMN):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Drop ``automation_rules.last_notify_at``, idempotently."""
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_TABLE, _COLUMN)
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)
