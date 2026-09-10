"""Install the setup audit-prefix rate-limit index.

Setup-token attempts are deliberately audited before the durable per-IP and
global brute-force budgets are evaluated.  Both counters query
``action LIKE 'setup.%'`` over a recent time window.  PostgreSQL cannot use a
normal varchar B-tree for that predicate under a non-C collation, so the
production index binds ``varchar_pattern_ops`` explicitly and covers the
optional source-IP filter.  SQLite uses the same physical column order; the
repository supplies its equivalent binary prefix range.

Revision ID: v1_9_audit_action_pattern
Revises: v1_9_delivery_recipient
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_9_audit_action_pattern"
down_revision: str | Sequence[str] | None = "v1_9_delivery_recipient"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "audit_log"
_INDEX = "ix_audit_log_action_pattern"
_COLUMNS = ("action", "occurred_at", "source_ip")


def _normalise_definition(definition: str) -> str:
    return " ".join(
        definition.replace('"', "").replace("`", "").lower().split(),
    )


def _index_state(bind: sa.engine.Connection) -> str:  # noqa: PLR0911 - dialect audit
    """Return ``expected``, ``absent``, or ``conflict`` for the index."""

    if bind.dialect.name == "sqlite":
        rows = bind.exec_driver_sql(
            "SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?",
            (_INDEX,),
        ).all()
        if not rows:
            return "absent"
        if len(rows) != 1:
            return "conflict"
        object_type, owner, definition = rows[0]
        if str(object_type) != "index" or str(owner) != _TABLE or definition is None:
            return "conflict"
        normalised = _normalise_definition(str(definition))
        expected = f"create index {_INDEX} on {_TABLE} (action, occurred_at desc, source_ip)"
        return "expected" if normalised == expected else "conflict"

    if bind.dialect.name == "postgresql":
        rows = bind.execute(
            sa.text(
                "SELECT CAST(named_object.relkind AS text), table_class.relname, "
                "pg_get_indexdef(index_class.oid), idx.indisunique, "
                "idx.indnullsnotdistinct, idx.indisprimary, idx.indisexclusion, "
                "idx.indimmediate, idx.indisvalid, idx.indcheckxmin, "
                "idx.indisready, idx.indislive, constraint_row.contype "
                "FROM pg_class AS named_object "
                "JOIN pg_namespace AS namespace "
                "  ON namespace.oid = named_object.relnamespace "
                "LEFT JOIN pg_index AS idx ON idx.indexrelid = named_object.oid "
                "LEFT JOIN pg_class AS index_class ON index_class.oid = idx.indexrelid "
                "LEFT JOIN pg_class AS table_class ON table_class.oid = idx.indrelid "
                "LEFT JOIN pg_constraint AS constraint_row "
                "  ON constraint_row.conindid = named_object.oid "
                "WHERE namespace.nspname = current_schema() "
                "  AND named_object.relname = :index",
            ),
            {"index": _INDEX},
        ).all()
        if not rows:
            return "absent"
        if len(rows) != 1:
            return "conflict"
        (
            object_kind,
            owner,
            definition,
            unique,
            nulls_not_distinct,
            primary,
            exclusion,
            immediate,
            valid,
            check_xmin,
            ready,
            live,
            constraint_type,
        ) = rows[0]
        if object_kind != "i" or owner != _TABLE or definition is None:
            return "conflict"
        normalised = _normalise_definition(str(definition))
        expected_suffix = "using btree (action varchar_pattern_ops, occurred_at desc, source_ip)"
        if (
            not bool(unique)
            and not bool(nulls_not_distinct)
            and not bool(primary)
            and not bool(exclusion)
            and bool(immediate)
            and bool(valid)
            and not bool(check_xmin)
            and bool(ready)
            and bool(live)
            and constraint_type is None
            and normalised.endswith(expected_suffix)
        ):
            return "expected"
        return "conflict"

    for index in sa.inspect(bind).get_indexes(_TABLE):
        if index.get("name") != _INDEX:
            continue
        if tuple(index.get("column_names") or ()) == _COLUMNS and not bool(index.get("unique")):
            return "expected"
        return "conflict"
    return "absent"


def upgrade() -> None:
    """Create the exact dialect-aware prefix index when it is absent."""

    bind = op.get_bind()
    state = _index_state(bind)
    if state == "conflict":
        raise CommandError(
            f"refusing upgrade: index {_INDEX} exists with an unexpected definition",
        )
    if state == "absent":
        op.create_index(
            _INDEX,
            _TABLE,
            ["action", sa.text("occurred_at DESC"), "source_ip"],
            unique=False,
            postgresql_ops={"action": "varchar_pattern_ops"},
        )


def _assert_downgrade_index_is_safe(bind: sa.engine.Connection) -> None:
    """Refuse the complete downgrade plan before a newer step can commit."""
    state = _index_state(bind)
    if state == "conflict":
        raise CommandError(
            f"refusing downgrade: index {_INDEX} has an unexpected definition",
        )


DOWNGRADE_PREFLIGHT = _assert_downgrade_index_is_safe


def downgrade() -> None:
    """Remove only the exact index owned by this revision."""

    _assert_downgrade_index_is_safe(op.get_bind())
    state = _index_state(op.get_bind())
    if state == "expected":
        op.drop_index(_INDEX, table_name=_TABLE)


__all__ = ["_index_state", "downgrade", "upgrade"]
