"""z4j 1.7 drop the dead ``projects.retention_days`` column.

Revision ID: v1_7_drop_project_retention_days
Revises: v1_7_agent_offline_alerts
Create Date: 2026-07-10

``projects.retention_days`` was created in the 1.3.0 initial schema as a
per-project override of the events retention window, but the override was
never wired: the only retention code path is ``PartitionCreatorWorker``,
which reads the global ``settings.event_retention_days`` and never
consults the project row. The column was stored and API-editable yet
enforced by nothing (the model docstring referenced a "RetentionWorker"
that does not exist). Same vapor-kill treatment as the ``alert_events``
drop in 0007: the column goes and the model field, API schema fields, and
docs go with it.

Because the model field is deleted in the same change, the initial
migration's ``Base.metadata.create_all`` no longer creates the column on
fresh installs. ``upgrade()`` is therefore a guarded drop -- a no-op on a
post-removal fresh DB, a real drop on a DB created while the field still
existed. Existing rows' values are dead data (nothing ever read them), so
the drop is acceptable data loss by design.

``downgrade()`` re-adds the column NULLABLE with its old server default
(``30``). Nullable rather than the original NOT NULL because the drop is
not value-preserving and no code at the downgraded revision requires the
constraint: the ORM always supplies the Python-side default on INSERT,
and the server default backfills every existing row anyway. This keeps
the downgrade a cheap metadata-only ALTER on any Postgres and lets the
migration round-trip cleanly on SQLite too.

Bidirectional per the 1.4 compat floor: ``alembic upgrade``/``downgrade``
round-trip on Postgres and SQLite. No data migration and no dependent
index/constraint, so N-1 running brains are unaffected (nothing reads the
column either way).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_7_drop_project_retention_days"
down_revision: str | Sequence[str] | None = "v1_7_agent_offline_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_agent_offline_alerts",
    "downgrade_to": "v1_7_agent_offline_alerts",
}

_TABLE = "projects"
_COLUMN = "retention_days"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    """Drop ``projects.retention_days`` if present (idempotent)."""
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_TABLE, _COLUMN)
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)


def downgrade() -> None:
    """Re-add ``projects.retention_days`` (nullable, old default 30)."""
    bind = op.get_bind()
    if _column_exists(bind, _TABLE, _COLUMN):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, sa.Integer(), nullable=True, server_default="30"),
    )
