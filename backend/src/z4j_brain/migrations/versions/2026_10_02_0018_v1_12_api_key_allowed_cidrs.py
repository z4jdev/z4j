"""Per-key source-address allowlist on ``api_keys``.

Adds ``api_keys.allowed_cidrs``, a nullable JSON list of canonical CIDR
strings (``JSONB`` on PostgreSQL, ``JSON`` on SQLite, the same portable type
the models use). NULL and an empty list both mean "no per-key restriction";
the global ``Z4J_API_IP_ALLOWLIST`` still applies either way. The column is
additive and bidirectional: downgrade drops it and loses only the per-key
restrictions, never a key. The drop is ``ALTER TABLE DROP COLUMN``, which
SQLite learned in 3.35.0, so on an older SQLite library the downgrade refuses
up front (declared as ``DOWNGRADE_PREFLIGHT``, evaluated by ``env.py`` over
the whole plan) instead of failing after the revisions stacked above it have
already committed their drops.

Revision ID: v1_12_api_key_allowed_cidrs
Revises: v1_11_audit_append_tally
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from z4j_brain.persistence.types import jsonb

revision: str = "v1_12_api_key_allowed_cidrs"
down_revision: str | Sequence[str] | None = "v1_11_audit_append_tally"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "api_keys"
_COLUMN = "allowed_cidrs"

#: SQLite learned ``ALTER TABLE ... DROP COLUMN`` in 3.35.0. Older
#: libraries would need a table rebuild, which this migration refuses to
#: improvise on the table every API credential lives in.
_SQLITE_DROP_COLUMN_MIN = (3, 35, 0)


def _column_present(bind: sa.engine.Connection) -> bool:
    return any(column["name"] == _COLUMN for column in sa.inspect(bind).get_columns(_TABLE))


def upgrade() -> None:
    bind = op.get_bind()
    if _column_present(bind):
        # A restore into an existing installation can leave the column in
        # place; adding it twice would fail the whole upgrade.
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, jsonb(), nullable=True),
    )


def _sqlite_supports_drop_column(bind: sa.engine.Connection) -> bool:
    raw = str(bind.exec_driver_sql("SELECT sqlite_version()").scalar_one())
    parts = tuple(int(piece) for piece in raw.split(".")[:3])
    return parts >= _SQLITE_DROP_COLUMN_MIN


_SQLITE_DROP_COLUMN_REFUSAL = (
    "refusing downgrade: this SQLite library predates ALTER TABLE "
    "DROP COLUMN (3.35.0); upgrade SQLite or restore a backup "
    "taken before v1_12_api_key_allowed_cidrs"
)


def _assert_downgrade_can_drop_column(bind: sa.engine.Connection) -> None:
    """Refuse the complete downgrade plan on an SQLite library that cannot drop a column.

    PostgreSQL always can, so nothing is read there. On SQLite this reads
    ``sqlite_version()`` once; ``env.py`` evaluates it over the whole
    resolved plan before its first step runs, so a library too old to finish
    this step refuses before a revision stacked above this one drops
    anything. ``downgrade()`` asks again immediately before its own drop.
    """
    if bind.dialect.name != "sqlite":
        return
    if not _column_present(bind):
        return
    if not _sqlite_supports_drop_column(bind):
        raise CommandError(_SQLITE_DROP_COLUMN_REFUSAL)


# Read by migrations/env.py from every revision in the resolved downgrade
# plan, ahead of its first migration body.
DOWNGRADE_PREFLIGHT = _assert_downgrade_can_drop_column


def downgrade() -> None:
    bind = op.get_bind()
    _assert_downgrade_can_drop_column(bind)
    if not _column_present(bind):
        return
    op.drop_column(_TABLE, _COLUMN)
