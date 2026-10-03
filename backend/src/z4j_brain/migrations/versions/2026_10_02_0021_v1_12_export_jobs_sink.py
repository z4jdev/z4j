"""Record the sink, the object size and the claim time on export jobs.

``export_jobs`` was reserved in the initial schema with the request columns
(type, format, filters) and the outcome columns (status, row count, path,
error, completion time). The export-jobs worker needs three more facts that
the reserved shape has no home for: which sink kind the job was queued for,
so a listing stays meaningful after the operator switches sinks; the length
of the written object, which the dashboard shows and an auditor checks
against the object they received; and when a worker claimed the job, which
is how an abandoned ``running`` row is told apart from a slow one.

All three are nullable and carry no default, so the upgrade touches no
existing row and the downgrade drops them without data loss beyond the
three values themselves. No index, no constraint, no backfill.

Revision ID: v1_12_export_jobs_sink
Revises: v1_12_channel_config_encrypted
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_12_export_jobs_sink"
down_revision: str | Sequence[str] | None = "v1_12_channel_config_encrypted"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "export_jobs"

#: Column name -> SQLAlchemy type, in the order they are added.
_COLUMNS: tuple[tuple[str, sa.types.TypeEngine[Any]], ...] = (
    ("sink", sa.String(length=20)),
    ("size_bytes", sa.BigInteger()),
    ("started_at", sa.DateTime(timezone=True)),
)

#: SQLite learned ``ALTER TABLE ... DROP COLUMN`` in 3.35.0. Older
#: libraries would need a table rebuild, which this migration refuses to
#: improvise on a table whose only consumers are the worker and the API.
_SQLITE_DROP_COLUMN_MIN = (3, 35, 0)


def _present(bind: sa.engine.Connection) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns(_TABLE)}


def upgrade() -> None:
    """Add the three nullable columns that are not already there."""

    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE):
        raise CommandError(f"refusing upgrade: table {_TABLE} is missing")
    present = _present(bind)
    for name, column_type in _COLUMNS:
        if name in present:
            continue
        op.add_column(_TABLE, sa.Column(name, column_type, nullable=True))


def _sqlite_supports_drop_column(bind: sa.engine.Connection) -> bool:
    raw = str(bind.exec_driver_sql("SELECT sqlite_version()").scalar_one())
    parts = tuple(int(piece) for piece in raw.split(".")[:3])
    return parts >= _SQLITE_DROP_COLUMN_MIN


_SQLITE_DROP_COLUMN_REFUSAL = (
    "refusing downgrade: this SQLite library predates ALTER TABLE "
    "DROP COLUMN (3.35.0); upgrade SQLite or restore a backup "
    "taken before v1_12_export_jobs_sink"
)


def _columns_to_drop(bind: sa.engine.Connection) -> list[str]:
    """The columns this revision owns that are present, in drop order."""
    if not sa.inspect(bind).has_table(_TABLE):
        return []
    present = _present(bind)
    return [name for name, _ in reversed(_COLUMNS) if name in present]


def _assert_downgrade_can_drop_columns(bind: sa.engine.Connection) -> None:
    """Refuse the complete downgrade plan on an SQLite library that cannot drop a column.

    PostgreSQL always can, so nothing is read there. On SQLite this reads
    ``sqlite_version()`` once; ``env.py`` evaluates it over the whole
    resolved plan before its first step runs, so a library too old to finish
    this step refuses before a revision stacked above this one drops
    anything. ``downgrade()`` asks again immediately before its own drops.
    """
    if bind.dialect.name != "sqlite":
        return
    if not _columns_to_drop(bind):
        return
    if not _sqlite_supports_drop_column(bind):
        raise CommandError(_SQLITE_DROP_COLUMN_REFUSAL)


# Read by migrations/env.py from every revision in the resolved downgrade
# plan, ahead of its first migration body.
DOWNGRADE_PREFLIGHT = _assert_downgrade_can_drop_columns


def downgrade() -> None:
    """Drop the three columns, in reverse order, where they exist."""

    bind = op.get_bind()
    _assert_downgrade_can_drop_columns(bind)
    to_drop = _columns_to_drop(bind)
    if not to_drop:
        return
    if bind.dialect.name == "sqlite":
        for name in to_drop:
            bind.exec_driver_sql(f"ALTER TABLE {_TABLE} DROP COLUMN {name}")
        return
    for name in to_drop:
        op.drop_column(_TABLE, name)


__all__ = ["downgrade", "upgrade"]
