"""z4j 1.7 add ``projects.automation_enabled`` (per-project kill switch).

Revision ID: v1_7_automation_kill_switch
Revises: v1_7_automation_rules
Create Date: 2026-07-06

A single ADMIN-flippable off switch for a whole project's automation. When
``automation_enabled`` is false the rule engine loads NO rules for the
project, so nothing fires regardless of individual rule ``is_enabled``
state. Adds one ``BOOLEAN NOT NULL DEFAULT true`` column, so existing
projects keep automation on after the upgrade.

DOWNGRADE COMPATIBILITY: ``downgrade()`` drops the column. A pre-switch
brain has no notion of a per-project kill switch, so any project that had
automation DISABLED will have it implicitly re-enabled on downgrade; that
is the only safe interpretation for a brain that cannot honour the flag.
Idempotent via inspector guards; works on Postgres and SQLite (both
support ``ALTER TABLE ... ADD/DROP COLUMN`` for this shape).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_automation_kill_switch"
down_revision: str | Sequence[str] | None = "v1_7_automation_rules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_automation_rules",
    "downgrade_to": "v1_7_automation_rules",
}

_TABLE = "projects"
_COLUMN = "automation_enabled"


def _column_exists(bind, table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(bind)
    return any(c["name"] == column_name for c in inspector.get_columns(table_name))


def upgrade() -> None:
    """Add ``projects.automation_enabled`` (default on), idempotently."""
    bind = op.get_bind()
    if not _column_exists(bind, _TABLE, _COLUMN):
        op.add_column(
            _TABLE,
            sa.Column(
                _COLUMN,
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )


def downgrade() -> None:
    """Drop ``projects.automation_enabled``, idempotently."""
    bind = op.get_bind()
    if _column_exists(bind, _TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
