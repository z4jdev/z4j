"""Preserve personal delivery history after subscription deletion.

``notification_deliveries.subscription_id`` deliberately uses ``ON DELETE
SET NULL`` so deleting a subscription cannot delete the project audit log.
The personal-history query nevertheless derived its owner by joining that
live subscription. Deletion therefore erased the same rows from the user's
history even though the API contract says historical deliveries survive.

``recipient_user_id`` snapshots the subscription owner at delivery time. The
foreign key also uses ``ON DELETE SET NULL``: subscription deletion preserves
historical ownership, while account deletion removes the user association for
privacy without deleting the project-scoped delivery audit row.

Existing rows are backfilled only when their subscription still exists. Rows
whose subscription was deleted before this migration have no trustworthy
owner left to recover and remain NULL. A covering-order index supports the
personal keyset feed.

Revision ID: v1_9_delivery_recipient
Revises: v1_9_automation_rolling_window
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_9_delivery_recipient"
down_revision: str | Sequence[str] | None = "v1_9_automation_rolling_window"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "notification_deliveries"
_SUBSCRIPTIONS = "user_subscriptions"
_COLUMN = "recipient_user_id"
_FK = "fk_notification_deliveries_recipient_user_id_users"
_INDEX = "ix_notification_deliveries_recipient_sent"
_PROJECT_SENT_INDEX = "ix_notification_deliveries_project_sent"
_TRIGGERED_INDEX = "ix_notification_deliveries_triggered_by_user"
_PRIOR_COLUMNS = (
    "subscription_id",
    "channel_id",
    "user_channel_id",
    "project_id",
    "trigger",
    "task_id",
    "task_name",
    "status",
    "response_code",
    "response_body",
    "error",
    "channel_name",
    "channel_type",
    "sent_at",
    "triggered_by_user_id",
    "id",
)
_CURRENT_COLUMNS = (*_PRIOR_COLUMNS, _COLUMN)
_SQLITE_TEMP_TABLE = "_alembic_tmp_notification_deliveries"


def _delivery_tables() -> tuple[sa.TableClause, sa.TableClause]:
    """Minimal table clauses shared by portable data-migration statements."""

    deliveries = sa.table(
        _TABLE,
        sa.column("subscription_id", sa.Uuid()),
        sa.column(_COLUMN, sa.Uuid()),
    )
    subscriptions = sa.table(
        _SUBSCRIPTIONS,
        sa.column("id", sa.Uuid()),
        sa.column("user_id", sa.Uuid()),
    )
    return deliveries, subscriptions


def _column_exists(bind: sa.engine.Connection) -> bool:
    return any(column["name"] == _COLUMN for column in sa.inspect(bind).get_columns(_TABLE))


def _column_state(bind: sa.engine.Connection) -> str:
    """Return ``expected``, ``absent``, or ``conflict`` for the snapshot column."""

    columns = list(sa.inspect(bind).get_columns(_TABLE))
    matches = [column for column in columns if column.get("name") == _COLUMN]
    if not matches:
        return "absent"
    if len(matches) != 1:
        return "conflict"
    column = matches[0]
    column_type = column.get("type")
    if bind.dialect.name == "sqlite":
        type_matches = isinstance(column_type, sa.CHAR) and column_type.length == 32
    else:
        type_matches = isinstance(column_type, sa.Uuid)
    if (
        not type_matches
        or not bool(column.get("nullable"))
        or column.get("default") is not None
        or columns[-1].get("name") != _COLUMN
    ):
        return "conflict"
    return "expected"


def _foreign_key_state(bind: sa.engine.Connection) -> str:  # noqa: PLR0911 exact shape classifier
    """Return ``expected``, ``absent``, or ``conflict`` for the owner FK."""

    sqlite_has_physical_candidate = False
    if bind.dialect.name == "sqlite":
        # SQLAlchemy derives SQLite constraint names by pairing parsed CREATE
        # TABLE SQL with PRAGMA rows.  Duplicate constraints on the same
        # column make that pairing ambiguous and historically collapsed into
        # one reflected entry.  Count the physical PRAGMA groups directly so
        # a canonical FK plus a conflicting twin cannot pass as canonical.
        raw_rows = bind.exec_driver_sql(f"PRAGMA foreign_key_list('{_TABLE}')").all()
        grouped: dict[int, list[Any]] = {}
        for row in raw_rows:
            if str(row[3]) == _COLUMN:
                grouped.setdefault(int(row[0]), []).append(row)
        if len(grouped) > 1:
            return "conflict"
        if grouped:
            sqlite_has_physical_candidate = True
            rows = next(iter(grouped.values()))
            if len(rows) != 1:
                return "conflict"
            foreign_key_row = rows[0]
            if (
                int(foreign_key_row[1]) != 0
                or str(foreign_key_row[2]) != "users"
                or str(foreign_key_row[3]) != _COLUMN
                or str(foreign_key_row[4]) != "id"
                or str(foreign_key_row[5]).upper() != "NO ACTION"
                or str(foreign_key_row[6]).upper() != "SET NULL"
                or str(foreign_key_row[7]).upper() != "NONE"
            ):
                return "conflict"
    foreign_keys = list(sa.inspect(bind).get_foreign_keys(_TABLE))
    candidates = [
        foreign_key
        for foreign_key in foreign_keys
        if foreign_key.get("name") == _FK
        or _COLUMN in (foreign_key.get("constrained_columns") or ())
    ]
    if bind.dialect.name == "sqlite" and not sqlite_has_physical_candidate and candidates:
        return "conflict"
    if not candidates:
        return "absent"
    if len(candidates) != 1:
        return "conflict"
    foreign_key = candidates[0]
    options = dict(foreign_key.get("options") or {})
    extra_options = {
        key: value
        for key, value in options.items()
        if key != "ondelete" and value not in (None, False, "NO ACTION")
    }
    if (
        foreign_key.get("name") != _FK
        or list(foreign_key.get("constrained_columns") or ()) != [_COLUMN]
        or foreign_key.get("referred_table") != "users"
        or list(foreign_key.get("referred_columns") or ()) != ["id"]
        or str(options.get("ondelete", "")).upper() != "SET NULL"
        or extra_options
    ):
        return "conflict"
    return "expected"


def _sqlite_index_matches(
    bind: sa.engine.Connection,
    *,
    name: str,
    first_column: str,
) -> bool:
    """Verify exact SQLite key order, direction, uniqueness, and predicate."""

    index_rows = bind.exec_driver_sql(f"PRAGMA index_list('{_TABLE}')").all()
    matches = [row for row in index_rows if str(row[1]) == name]
    if len(matches) != 1:
        return False
    index_row = matches[0]
    if bool(index_row[2]) or bool(index_row[4]):
        return False
    key_rows = [
        row for row in bind.exec_driver_sql(f"PRAGMA index_xinfo('{name}')").all() if bool(row[5])
    ]
    return [(str(row[2]), bool(row[3]), str(row[4]).upper()) for row in key_rows] == [
        (first_column, False, "BINARY"),
        ("sent_at", True, "BINARY"),
    ]


def _postgres_index_matches(
    bind: sa.engine.Connection,
    *,
    name: str,
    first_column: str,
) -> bool:
    """Verify PostgreSQL's physical btree definition, not reflection hints."""

    rows = bind.execute(
        sa.text(
            "SELECT idx.indisunique, idx.indisvalid, idx.indisready, "
            "idx.indpred IS NULL AS unfiltered, pg_get_indexdef(idx.indexrelid) "
            "FROM pg_catalog.pg_index AS idx "
            "JOIN pg_catalog.pg_class AS index_rel ON index_rel.oid = idx.indexrelid "
            "JOIN pg_catalog.pg_class AS table_rel ON table_rel.oid = idx.indrelid "
            "JOIN pg_catalog.pg_namespace AS ns ON ns.oid = table_rel.relnamespace "
            "WHERE table_rel.relname = :table_name "
            "AND index_rel.relname = :index_name "
            "AND ns.nspname = ANY (current_schemas(false))",
        ),
        {"table_name": _TABLE, "index_name": name},
    ).all()
    if len(rows) != 1:
        return False
    unique, valid, ready, unfiltered, definition = rows[0]
    normalized = " ".join(str(definition).lower().split())
    expected_suffix = f" using btree ({first_column}, sent_at desc)"
    return (
        not bool(unique)
        and bool(valid)
        and bool(ready)
        and bool(unfiltered)
        and normalized.endswith(expected_suffix)
    )


def _named_feed_index_state(
    bind: sa.engine.Connection,
    *,
    name: str,
    first_column: str,
) -> str:
    """Classify one exact two-column descending feed index."""

    if bind.dialect.name == "sqlite":
        named_rows = bind.exec_driver_sql(
            "SELECT type, tbl_name FROM sqlite_master WHERE name = ?",
            (name,),
        ).all()
        if len(named_rows) > 1 or (
            named_rows and (str(named_rows[0][0]) != "index" or str(named_rows[0][1]) != _TABLE)
        ):
            return "conflict"
    matches = [index for index in sa.inspect(bind).get_indexes(_TABLE) if index.get("name") == name]
    if not matches:
        return "absent"
    if len(matches) != 1:
        return "conflict"
    index = matches[0]
    if list(index.get("column_names") or ()) != [first_column, "sent_at"] or bool(
        index.get("unique")
    ):
        return "conflict"
    if bind.dialect.name == "sqlite":
        exact = _sqlite_index_matches(bind, name=name, first_column=first_column)
    elif bind.dialect.name == "postgresql":
        exact = _postgres_index_matches(bind, name=name, first_column=first_column)
    else:
        sorting = dict(index.get("column_sorting") or {})
        exact = "desc" in tuple(sorting.get("sent_at") or ())
    return "expected" if exact else "conflict"


def _index_state(bind: sa.engine.Connection) -> str:
    """Return ``expected``, ``absent``, or ``conflict`` for the feed index."""

    return _named_feed_index_state(
        bind,
        name=_INDEX,
        first_column=_COLUMN,
    )


def _project_feed_index_state(bind: sa.engine.Connection) -> str:
    return _named_feed_index_state(
        bind,
        name=_PROJECT_SENT_INDEX,
        first_column="project_id",
    )


def _triggered_index_state(bind: sa.engine.Connection) -> str:
    """Classify the immutable pre-1.9 triggered-user lookup index."""

    matches = [
        index
        for index in sa.inspect(bind).get_indexes(_TABLE)
        if index.get("name") == _TRIGGERED_INDEX
    ]
    if len(matches) != 1:
        return "absent" if not matches else "conflict"
    index = matches[0]
    if list(index.get("column_names") or ()) != ["triggered_by_user_id"] or bool(
        index.get("unique")
    ):
        return "conflict"
    if bind.dialect.name != "sqlite":
        return "expected"
    rows = bind.exec_driver_sql(f"PRAGMA index_list('{_TABLE}')").all()
    named = [row for row in rows if str(row[1]) == _TRIGGERED_INDEX]
    if len(named) != 1 or bool(named[0][2]) or bool(named[0][4]):
        return "conflict"
    key_rows = [
        row
        for row in bind.exec_driver_sql(
            f"PRAGMA index_xinfo('{_TRIGGERED_INDEX}')",
        ).all()
        if bool(row[5])
    ]
    exact = [(str(row[2]), bool(row[3]), str(row[4]).upper()) for row in key_rows] == [
        ("triggered_by_user_id", False, "BINARY")
    ]
    return "expected" if exact else "conflict"


def _lock_owner_snapshot_tables(bind: sa.engine.Connection) -> None:
    """Exclude delivery/subscription writers during snapshot transitions."""

    if bind.dialect.name == "postgresql":
        # One deterministic acquisition point. It closes both races that
        # matter: a subscription disappearing during backfill and a delivery
        # being inserted by an old replica before the new application field is
        # universally populated.
        bind.exec_driver_sql(
            f"LOCK TABLE {_TABLE}, {_SUBSCRIPTIONS} IN ACCESS EXCLUSIVE MODE",
        )


def _assert_transition_schema_compatible(
    bind: sa.engine.Connection,
    *,
    direction: str,
) -> None:
    """Reject partial or same-name schema conflicts before any DDL."""

    column_state = _column_state(bind)
    foreign_key_state = _foreign_key_state(bind)
    index_state = _index_state(bind)
    project_index_state = _project_feed_index_state(bind)
    triggered_index_state = _triggered_index_state(bind)
    if column_state == "conflict":
        raise CommandError(
            f"refusing {direction}: {_TABLE}.{_COLUMN} exists with an "
            "unexpected type, nullability, default, or physical position",
        )
    if foreign_key_state == "conflict":
        raise CommandError(
            f"refusing {direction}: {_TABLE}.{_COLUMN} has duplicate or "
            f"conflicting foreign keys; expected only {_FK} -> users.id "
            "ON DELETE SET NULL",
        )
    if index_state == "conflict":
        raise CommandError(
            f"refusing {direction}: index {_INDEX} exists with an unexpected "
            "definition; expected (recipient_user_id, sent_at DESC), "
            "non-unique and non-partial",
        )
    if project_index_state == "conflict":
        raise CommandError(
            f"refusing {direction}: index {_PROJECT_SENT_INDEX} exists with an "
            "unexpected definition",
        )
    if triggered_index_state != "expected":
        raise CommandError(
            f"refusing {direction}: index {_TRIGGERED_INDEX} is absent or has "
            "an unexpected definition",
        )
    if column_state == "absent" and (foreign_key_state != "absent" or index_state != "absent"):
        raise CommandError(
            f"refusing {direction}: {_COLUMN} is absent but recipient schema objects remain",
        )


def _sqlite_rebuild_delivery_table(
    bind: sa.engine.Connection,
    *,
    include_recipient: bool,
) -> None:
    """Rebuild the table from frozen DDL, independent of reflection order."""

    source_columns = tuple(column["name"] for column in sa.inspect(bind).get_columns(_TABLE))
    expected_source = _CURRENT_COLUMNS if _COLUMN in source_columns else _PRIOR_COLUMNS
    if source_columns != expected_source:
        raise CommandError(
            f"refusing SQLite {_TABLE} rebuild: unexpected source columns "
            f"{source_columns}; expected {expected_source}",
        )
    if sa.inspect(bind).has_table(_SQLITE_TEMP_TABLE):
        raise CommandError(
            f"refusing SQLite {_TABLE} rebuild: reserved temporary table "
            f"{_SQLITE_TEMP_TABLE} already exists",
        )
    triggers = bind.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
        (_TABLE,),
    ).all()
    if triggers:
        raise CommandError(
            f"refusing SQLite {_TABLE} rebuild: unexpected table trigger(s) "
            f"{[str(row[0]) for row in triggers]}",
        )
    indexes = {
        str(row[1])
        for row in bind.exec_driver_sql(f"PRAGMA index_list('{_TABLE}')").all()
        if str(row[3]).lower() == "c"
    }
    unexpected_indexes = indexes - {
        _PROJECT_SENT_INDEX,
        _TRIGGERED_INDEX,
        _INDEX,
    }
    if unexpected_indexes:
        raise CommandError(
            f"refusing SQLite {_TABLE} rebuild: unexpected index(es) {sorted(unexpected_indexes)}",
        )
    if int(bind.exec_driver_sql("PRAGMA foreign_keys").scalar_one()) != 0:
        # Dropping a parent table while SQLite FK actions are enabled performs
        # an implicit DELETE and can cascade into alert_events.  Alembic's
        # SQLite migration connection is intentionally FK-off; refuse a
        # programmatic caller that supplied an incompatible connection rather
        # than risk deleting child audit history.
        raise CommandError(
            f"refusing SQLite {_TABLE} rebuild while PRAGMA foreign_keys is ON; "
            "run Alembic through the supported migration environment",
        )

    recipient_column = ",\n recipient_user_id CHAR(32)" if include_recipient else ""
    recipient_constraint = (
        ",\n CONSTRAINT fk_notification_deliveries_recipient_user_id_users "
        "FOREIGN KEY(recipient_user_id) REFERENCES users (id) ON DELETE SET NULL"
        if include_recipient
        else ""
    )
    bind.exec_driver_sql(
        f"""CREATE TABLE {_SQLITE_TEMP_TABLE} (
 subscription_id CHAR(32),
 channel_id CHAR(32),
 user_channel_id CHAR(32),
 project_id CHAR(32) NOT NULL,
 "trigger" VARCHAR(40) NOT NULL,
 task_id VARCHAR(200),
 task_name VARCHAR(500),
 status VARCHAR(20) NOT NULL,
 response_code INTEGER,
 response_body TEXT,
 error TEXT,
 channel_name VARCHAR(200),
 channel_type VARCHAR(20),
 sent_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
 triggered_by_user_id CHAR(32),
 id CHAR(32) NOT NULL{recipient_column},
 CONSTRAINT pk_notification_deliveries PRIMARY KEY (id),
 CONSTRAINT fk_notification_deliveries_subscription_id_user_subscriptions FOREIGN KEY(subscription_id) REFERENCES user_subscriptions (id) ON DELETE SET NULL,
 CONSTRAINT fk_notification_deliveries_channel_id_notification_channels FOREIGN KEY(channel_id) REFERENCES notification_channels (id) ON DELETE SET NULL,
 CONSTRAINT fk_notification_deliveries_user_channel_id_user_channels FOREIGN KEY(user_channel_id) REFERENCES user_channels (id) ON DELETE SET NULL,
 CONSTRAINT fk_notification_deliveries_project_id_projects FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE,
 CONSTRAINT fk_notification_deliveries_triggered_by_user_id_users FOREIGN KEY(triggered_by_user_id) REFERENCES users (id) ON DELETE SET NULL{recipient_constraint}
)""",
    )
    target_columns = _CURRENT_COLUMNS if include_recipient else _PRIOR_COLUMNS
    target_projection = ", ".join(
        f'"{column}"' if column == "trigger" else column for column in target_columns
    )
    source_projection = ", ".join(
        (
            "NULL"
            if column == _COLUMN and column not in source_columns
            else f'"{column}"'
            if column == "trigger"
            else column
        )
        for column in target_columns
    )
    bind.exec_driver_sql(
        f"INSERT INTO {_SQLITE_TEMP_TABLE} ({target_projection}) "  # noqa: S608 fixed identifiers
        f"SELECT {source_projection} FROM {_TABLE}",
    )
    bind.exec_driver_sql(f"DROP TABLE {_TABLE}")
    bind.exec_driver_sql(
        f"ALTER TABLE {_SQLITE_TEMP_TABLE} RENAME TO {_TABLE}",
    )
    bind.exec_driver_sql(
        f"CREATE INDEX {_PROJECT_SENT_INDEX} ON {_TABLE} (project_id, sent_at DESC)",
    )
    bind.exec_driver_sql(
        f"CREATE INDEX {_TRIGGERED_INDEX} ON {_TABLE} (triggered_by_user_id)",
    )


def _add_column_and_foreign_key(bind: sa.engine.Connection) -> None:
    """Add the nullable owner snapshot with one cross-dialect FK identity."""

    has_column = _column_state(bind) == "expected"
    foreign_key_state = _foreign_key_state(bind) if has_column else "absent"

    if bind.dialect.name == "sqlite":
        if not has_column or foreign_key_state == "absent":
            # SQLite cannot add a named FK with ALTER TABLE.  A frozen rebuild
            # makes fresh and split upgrades emit the same physical schema;
            # reflected BatchOperations constraint order is process-dependent.
            _sqlite_rebuild_delivery_table(bind, include_recipient=True)
        return

    if not has_column:
        op.add_column(
            _TABLE,
            sa.Column(
                _COLUMN,
                sa.Uuid(),
                sa.ForeignKey(
                    "users.id",
                    name=_FK,
                    ondelete="SET NULL",
                ),
                nullable=True,
            ),
        )
    elif foreign_key_state == "absent":
        op.create_foreign_key(
            _FK,
            _TABLE,
            "users",
            [_COLUMN],
            ["id"],
            ondelete="SET NULL",
        )


def _backfill_recipient_owners(bind: sa.engine.Connection) -> int:
    """Backfill recoverable owners and reject pre-existing contradictions."""

    deliveries, subscriptions = _delivery_tables()
    mismatch = bind.execute(
        sa.select(sa.func.count())
        .select_from(
            deliveries.join(
                subscriptions,
                subscriptions.c.id == deliveries.c.subscription_id,
            ),
        )
        .where(
            deliveries.c[_COLUMN].is_not(None),
            deliveries.c[_COLUMN] != subscriptions.c.user_id,
        ),
    ).scalar_one()
    if mismatch:
        raise CommandError(
            f"refusing upgrade: {mismatch} {_TABLE} row(s) attribute a "
            "recipient different from the live subscription owner",
        )

    owner = (
        sa.select(subscriptions.c.user_id)
        .where(subscriptions.c.id == deliveries.c.subscription_id)
        .scalar_subquery()
    )
    recoverable = sa.exists(
        sa.select(1).where(subscriptions.c.id == deliveries.c.subscription_id),
    )
    result = bind.execute(
        sa.update(deliveries)
        .where(
            deliveries.c[_COLUMN].is_(None),
            deliveries.c.subscription_id.is_not(None),
            recoverable,
        )
        .values({_COLUMN: owner}),
    )
    return int(result.rowcount or 0)


def _create_index(bind: sa.engine.Connection) -> None:
    state = _index_state(bind)
    if state == "conflict":
        raise CommandError(
            f"refusing upgrade: index {_INDEX} exists with an unexpected definition",
        )
    if state == "absent":
        op.create_index(
            _INDEX,
            _TABLE,
            [_COLUMN, sa.text("sent_at DESC")],
            unique=False,
        )


def _restore_sqlite_project_feed_index(bind: sa.engine.Connection) -> None:
    """Restore the DESC expression lost by SQLite batch reflection."""

    if bind.dialect.name != "sqlite":
        return
    state = _project_feed_index_state(bind)
    if state == "conflict":
        raise CommandError(
            f"refusing schema transition: index {_PROJECT_SENT_INDEX} has an unexpected definition",
        )
    if state == "absent":
        bind.exec_driver_sql(
            f"CREATE INDEX {_PROJECT_SENT_INDEX} ON {_TABLE} (project_id, sent_at DESC)",
        )


def upgrade() -> None:
    """Install and backfill the historical recipient snapshot."""

    bind = op.get_bind()
    _lock_owner_snapshot_tables(bind)
    _assert_transition_schema_compatible(bind, direction="upgrade")
    _add_column_and_foreign_key(bind)
    _backfill_recipient_owners(bind)
    _create_index(bind)


def _irreconstructable_owner_count(bind: sa.engine.Connection) -> int:
    """Owners that an old schema cannot recover from a live subscription."""

    deliveries, subscriptions = _delivery_tables()
    reconstructable = sa.exists(
        sa.select(1).where(
            subscriptions.c.id == deliveries.c.subscription_id,
            subscriptions.c.user_id == deliveries.c[_COLUMN],
        ),
    )
    return int(
        bind.execute(
            sa.select(sa.func.count())
            .select_from(deliveries)
            .where(
                deliveries.c[_COLUMN].is_not(None),
                ~reconstructable,
            ),
        ).scalar_one(),
    )


def _assert_downgrade_state_is_safe(bind: sa.engine.Connection) -> None:
    """Refuse to discard owner snapshots the prior schema cannot rebuild."""

    _assert_transition_schema_compatible(bind, direction="downgrade")
    if _column_state(bind) == "absent":
        return
    _lock_owner_snapshot_tables(bind)
    endangered = _irreconstructable_owner_count(bind)
    if endangered:
        raise CommandError(
            f"refusing downgrade: {endangered} delivery row(s) retain personal "
            "history only through recipient_user_id after their subscription "
            "was deleted; export or clear those delivery rows before using an "
            "older schema, or restore a backup from before subscription deletion",
        )


# env.py invokes callbacks for the complete downgrade plan before applying its
# first revision, so a future revision above 0015 cannot commit partial schema
# loss before this state-dependent refusal is evaluated.
DOWNGRADE_PREFLIGHT = _assert_downgrade_state_is_safe


def downgrade() -> None:
    """Remove the snapshot only when every non-NULL owner is reconstructable."""

    bind = op.get_bind()
    _assert_downgrade_state_is_safe(bind)
    if _column_state(bind) == "absent":
        return

    if bind.dialect.name != "sqlite" and _index_state(bind) == "expected":
        op.drop_index(_INDEX, table_name=_TABLE)

    foreign_key_state = _foreign_key_state(bind)
    if bind.dialect.name == "sqlite":
        _sqlite_rebuild_delivery_table(bind, include_recipient=False)
    else:
        if foreign_key_state == "expected":
            op.drop_constraint(_FK, _TABLE, type_="foreignkey")
        op.drop_column(_TABLE, _COLUMN)


__all__ = [
    "DOWNGRADE_PREFLIGHT",
    "_assert_downgrade_state_is_safe",
    "_backfill_recipient_owners",
    "_column_exists",
    "_foreign_key_state",
    "_index_state",
    "_restore_sqlite_project_feed_index",
    "downgrade",
    "upgrade",
]
