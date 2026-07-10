"""z4j 1.7 add ``schedule_fires.triggered_by_user_id``.

Revision ID: v1_7_schedule_fire_triggered_by
Revises: v1_7_drop_alert_events
Create Date: 2026-07-06

Attributes a schedule fire to the operator who manually triggered it
("fire now" / TriggerSchedule); NULL for scheduler-driven cadence fires.
The scheduler now carries the user id across the FireSchedule gRPC field
of the same name, and the brain's FireSchedule handler records it here.
Required by H1 (personal-activity attribution) and RC3 (recovery
lineage).

One nullable UUID column with a ``users.id`` FK (``ON DELETE SET NULL``
so removing a user preserves the fire history). Additive + backfilled
NULL, so existing rows and running N-1 brains are unaffected -- a
pre-column brain simply never reads or writes it.

Because the initial migration builds the schema from the current model
metadata via ``create_all``, a fresh install already has this column, so
``upgrade()`` is a guarded no-op there and a real ADD COLUMN on a DB
created before the column existed. ``downgrade()`` drops it (Postgres
drops the dependent FK with the column; SQLite rebuilds the table via a
batch op). Bidirectional per the 1.4 compat floor.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.types import Uuid

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_schedule_fire_triggered_by"
down_revision: str | Sequence[str] | None = "v1_7_drop_alert_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_drop_alert_events",
    "downgrade_to": "v1_7_drop_alert_events",
}

# Must equal the name Base.metadata's naming_convention derives on the
# fresh-install (create_all) path -- fk_%(table)s_%(column)s_%(referred)s --
# so an upgraded DB and a fresh install carry an identically-named FK and
# schema-diff / autogenerate tooling sees no phantom drift.
_TABLE = "schedule_fires"
_COLUMN = "triggered_by_user_id"
_FK = "fk_schedule_fires_triggered_by_user_id_users"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    """Add ``schedule_fires.triggered_by_user_id`` (nullable), idempotently."""
    bind = op.get_bind()
    if _column_exists(bind, _TABLE, _COLUMN):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, Uuid(as_uuid=True), nullable=True),
    )
    # SQLite cannot ADD a FK to an existing table via ALTER; its FK
    # enforcement is off by default anyway and the app-level model still
    # declares the relationship. On Postgres we add the real constraint.
    if bind.dialect.name == "postgresql":
        op.create_foreign_key(
            _FK,
            _TABLE,
            "users",
            [_COLUMN],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    """Drop ``schedule_fires.triggered_by_user_id``, idempotently."""
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        return
    if bind.dialect.name == "postgresql":
        # Postgres drops the dependent FK constraint together with the
        # column, so no explicit drop_constraint is needed (and the FK
        # name differs between the create_all path and this migration's
        # path, which would make a named drop fragile).
        op.drop_column(_TABLE, _COLUMN)
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)
