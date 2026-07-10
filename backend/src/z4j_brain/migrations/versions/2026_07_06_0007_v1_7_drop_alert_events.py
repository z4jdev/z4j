"""z4j 1.7 drop the dead ``alert_events`` table.

Revision ID: v1_7_drop_alert_events
Revises: v1_7_automation_kill_switch
Create Date: 2026-07-06

``alert_events`` (an alert-lifecycle tracker: fired -> acknowledged ->
resolved -> snoozed/expired) was created in the 1.3.0 initial schema as a
planned Phase-1.1 feature but was never wired: no repository, service,
API, or query ever read or wrote it, and the model was never
instantiated. It is dead schema; this migration removes it and the model
goes with it.

Because the model is deleted in the same change, the initial migration's
``Base.metadata.create_all`` no longer creates the table on fresh
installs. ``upgrade()`` is therefore a guarded ``DROP TABLE`` -- a no-op
on a post-removal fresh DB, a real drop on a DB that was created while
the model still existed.

``downgrade()`` recreates the table with its exact original shape via
hand-written DDL (the model no longer exists to reference, so the 0005
``Model.__table__`` pattern is unavailable). It comes back EMPTY: the
drop is not data-preserving, which is acceptable for a table no code path
ever populated. Downgrading only this revision (to
``v1_7_automation_kill_switch``) restores the table so a brain pinned to
that revision sees the schema it expects; downgrading further to base
drops it again via the initial migration's own drop list -- the
round-trip in ``tests/integration/test_migration_pg.py`` covers both.

Bidirectional per the 1.4 compat floor: ``alembic upgrade``/``downgrade``
round-trip on Postgres and SQLite. No data migration and no cross-table
dependency (alert_events is a leaf -- it references
``notification_deliveries`` and ``users`` but nothing references it), so
N-1 running brains are unaffected (nothing reads the table either way).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.types import Uuid

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_drop_alert_events"
down_revision: str | Sequence[str] | None = "v1_7_automation_kill_switch"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_automation_kill_switch",
    "downgrade_to": "v1_7_automation_kill_switch",
}

_TABLE = "alert_events"


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    """Drop ``alert_events`` if present (idempotent)."""
    bind = op.get_bind()
    if _table_exists(bind, _TABLE):
        # No CASCADE needed: alert_events is a leaf table (nothing
        # references it); its own outbound FKs drop with it.
        op.drop_table(_TABLE)


def downgrade() -> None:
    """Recreate ``alert_events`` with its original shape (empty)."""
    bind = op.get_bind()
    if _table_exists(bind, _TABLE):
        return
    is_postgres = bind.dialect.name == "postgresql"
    # Match the original: the initial migration set a server-side
    # gen_random_uuid() default on every UUID id column (Postgres only).
    id_server_default = sa.text("gen_random_uuid()") if is_postgres else None
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            Uuid(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=id_server_default,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("delivery_id", Uuid(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(20), nullable=False),
        sa.Column("user_id", Uuid(as_uuid=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("snooze_until", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["delivery_id"],
            ["notification_deliveries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
    )
