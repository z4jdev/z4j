"""Install exact rolling-window automation breaker admissions.

The former breaker stored only a window start and aggregate count. That is a
fixed window: a burst immediately before its boundary and another immediately
after could admit twice the configured maximum in less than one window. Exact
N-in-any-W enforcement needs the retained admission timestamps themselves.

The automation-rule row is the transactional arbiter. Claims lock it, prune
expired child rows, count the retained half-open window, and insert at most one
new admission before commit. The child history therefore remains bounded by
the configured maximum for the current configuration epoch.

Revision ID: v1_9_automation_rolling_window
Revises: v1_9_agent_worker_legacy_slot
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_9_automation_rolling_window"
down_revision: str | Sequence[str] | None = "v1_9_agent_worker_legacy_slot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RULES = "automation_rules"
_PROJECTS = "projects"
_ADMISSIONS = "automation_rule_admissions"
_RULE_REVISION = "config_revision"
_PROJECT_REVISION = "automation_revision"
_DIGEST = "cb_config_digest"
_INDEX = "ix_automation_rule_admissions_rule_time"
_PK = "pk_automation_rule_admissions"
_FK = "fk_automation_rule_admissions_rule_id_automation_rules"
_CHECK = "ck_automation_rule_admissions_positive_weight"


def _normalise_sql(value: Any) -> str:
    """Canonicalise reflected SQL fragments for exact structural checks."""

    return " ".join(
        str(value).replace('"', "").replace("`", "").lower().split(),
    )


def _strip_outer_parentheses(value: str) -> str:
    """Remove only parentheses that enclose an entire SQL fragment."""

    result = value.strip()
    while result.startswith("(") and result.endswith(")"):
        depth = 0
        encloses_all = True
        for position, character in enumerate(result):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and position != len(result) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth != 0:
            break
        result = result[1:-1].strip()
    return result


def _normalise_default(value: Any) -> str | None:
    """Normalise dialect spellings of the literal integer default one."""

    if value is None:
        return None
    result = _strip_outer_parentheses(_normalise_sql(value))
    # PostgreSQL reflects ``'1'::integer`` while SQLite reflects ``'1'``.
    result = re.sub(r"::(?:pg_catalog\.)?(?:int4|integer)$", "", result).strip()
    return _strip_outer_parentheses(result).strip("'")


def _compiled_type(bind: sa.engine.Connection, type_: Any) -> str:
    return _normalise_sql(bind.dialect.type_compiler.process(type_))


def _column_contract(
    bind: sa.engine.Connection,
    *,
    table: str,
    column: str,
    type_: sa.types.TypeEngine[Any],
    nullable: bool,
    default: str | None,
) -> str:
    """Return ``expected``, ``absent``, or ``conflict`` for one column."""

    reflected = next(
        (item for item in sa.inspect(bind).get_columns(table) if item.get("name") == column),
        None,
    )
    if reflected is None:
        return "absent"
    actual_type = _compiled_type(bind, reflected["type"])
    expected_type = _compiled_type(bind, type_)
    if (
        actual_type == expected_type
        and bool(reflected.get("nullable")) is nullable
        and _normalise_default(reflected.get("default")) == default
        and not bool(reflected.get("primary_key"))
        and reflected.get("computed") is None
        and reflected.get("identity") is None
    ):
        return "expected"
    return "conflict"


def _check_contract(bind: sa.engine.Connection) -> bool:
    checks = sa.inspect(bind).get_check_constraints(_ADMISSIONS)
    if len(checks) != 1:
        return False
    check = checks[0]
    # Check constraints are the one naming-convention category that can wrap
    # an explicitly supplied name. Accept only the two deterministic names
    # emitted by Alembic with and without that wrapping, never an unnamed or
    # unrelated constraint.
    wrapped_name = f"ck_{_ADMISSIONS}_{_CHECK}"
    rendered_wrapped_name = bind.dialect.identifier_preparer._truncate_and_render_maxlen_name(
        sa.sql.elements.conv(wrapped_name),
        bind.dialect.max_identifier_length,
        _alembic_quote=False,
    )
    if check.get("name") not in {
        _CHECK,
        wrapped_name,
        rendered_wrapped_name,
    }:
        return False
    sql = _strip_outer_parentheses(_normalise_sql(check.get("sqltext", "")))
    return sql == "weight > 0"


def _index_contract(  # noqa: PLR0911 - exact dialect catalog audit
    bind: sa.engine.Connection,
) -> bool:
    indexes = sa.inspect(bind).get_indexes(_ADMISSIONS)
    if len(indexes) != 1:
        return False
    index = indexes[0]
    if (
        index.get("name") != _INDEX
        or list(index.get("column_names") or ()) != ["rule_id", "admitted_at"]
        or bool(index.get("unique"))
    ):
        return False

    if bind.dialect.name == "sqlite":
        definition = bind.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND name = ?",
            (_ADMISSIONS, _INDEX),
        ).scalar_one_or_none()
        if _normalise_sql(definition) != (
            f"create index {_INDEX} on {_ADMISSIONS} (rule_id, admitted_at)"
        ):
            return False
        key_rows = [
            tuple(row)
            for row in bind.exec_driver_sql(
                f"PRAGMA index_xinfo('{_INDEX}')",
            ).all()
            if bool(row[5])
        ]
        return [(row[2], bool(row[3]), str(row[4]).upper()) for row in key_rows] == [
            ("rule_id", False, "BINARY"),
            ("admitted_at", False, "BINARY"),
        ]
    if bind.dialect.name == "postgresql":
        row = bind.execute(
            sa.text(
                "SELECT pg_get_indexdef(index_class.oid), idx.indisunique, "
                "idx.indisvalid, idx.indisready "
                "FROM pg_class AS table_class "
                "JOIN pg_namespace AS namespace "
                "  ON namespace.oid = table_class.relnamespace "
                "JOIN pg_index AS idx ON idx.indrelid = table_class.oid "
                "JOIN pg_class AS index_class ON index_class.oid = idx.indexrelid "
                "WHERE namespace.nspname = current_schema() "
                "  AND table_class.relname = :table "
                "  AND index_class.relname = :index",
            ),
            {"table": _ADMISSIONS, "index": _INDEX},
        ).one_or_none()
        if row is None:
            return False
        definition, unique, valid, ready = row
        return (
            not bool(unique)
            and bool(valid)
            and bool(ready)
            and _normalise_sql(definition).endswith(
                "using btree (rule_id, admitted_at)",
            )
        )
    return True


def _reserved_index_owner(bind: sa.engine.Connection) -> str:
    """Return ``expected``, ``absent``, or ``conflict`` for index ownership."""

    if bind.dialect.name == "sqlite":
        owner = bind.exec_driver_sql(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?",
            (_INDEX,),
        ).scalar_one_or_none()
    elif bind.dialect.name == "postgresql":
        owner = bind.execute(
            sa.text(
                "SELECT table_class.relname "
                "FROM pg_class AS index_class "
                "JOIN pg_namespace AS namespace "
                "  ON namespace.oid = index_class.relnamespace "
                "JOIN pg_index AS idx ON idx.indexrelid = index_class.oid "
                "JOIN pg_class AS table_class ON table_class.oid = idx.indrelid "
                "WHERE namespace.nspname = current_schema() "
                "  AND index_class.relname = :index",
            ),
            {"index": _INDEX},
        ).scalar_one_or_none()
    else:
        owners = [
            table
            for table in sa.inspect(bind).get_table_names()
            if any(index.get("name") == _INDEX for index in sa.inspect(bind).get_indexes(table))
        ]
        owner = owners[0] if len(owners) == 1 else (None if not owners else "conflict")
    if owner is None:
        return "absent"
    return "expected" if owner == _ADMISSIONS else "conflict"


def _admissions_table_contract(  # noqa: PLR0911 - exact fail-closed audit
    bind: sa.engine.Connection,
) -> str:
    """Return exact compatibility state for a same-name admissions table."""

    inspector = sa.inspect(bind)
    if _ADMISSIONS in inspector.get_view_names():
        return "conflict"
    if not _table_exists(bind, _ADMISSIONS):
        return "conflict" if _reserved_index_owner(bind) != "absent" else "absent"
    if _reserved_index_owner(bind) != "expected":
        return "conflict"
    columns = inspector.get_columns(_ADMISSIONS)
    expected_columns = (
        ("rule_id", sa.Uuid(), False, None),
        ("admitted_at", sa.DateTime(timezone=True), False, None),
        ("weight", sa.Integer(), False, "1"),
        ("id", sa.Uuid(), False, None),
    )
    if [column.get("name") for column in columns] != [
        name for name, _type, _nullable, _default in expected_columns
    ]:
        return "conflict"
    for reflected, (_name, type_, nullable, default) in zip(
        columns,
        expected_columns,
        strict=True,
    ):
        if (
            _compiled_type(bind, reflected["type"]) != _compiled_type(bind, type_)
            or bool(reflected.get("nullable")) is not nullable
            or _normalise_default(reflected.get("default")) != default
            or reflected.get("computed") is not None
            or reflected.get("identity") is not None
        ):
            return "conflict"

    primary_key = inspector.get_pk_constraint(_ADMISSIONS)
    if primary_key.get("name") != _PK or list(
        primary_key.get("constrained_columns") or (),
    ) != ["id"]:
        return "conflict"
    foreign_keys = inspector.get_foreign_keys(_ADMISSIONS)
    if len(foreign_keys) != 1:
        return "conflict"
    foreign_key = foreign_keys[0]
    current_schema = (
        bind.execute(sa.text("SELECT current_schema()")).scalar_one()
        if bind.dialect.name == "postgresql"
        else None
    )
    options = foreign_key.get("options") or {}
    if not (
        foreign_key.get("name") == _FK
        and list(foreign_key.get("constrained_columns") or ()) == ["rule_id"]
        and foreign_key.get("referred_table") == _RULES
        and list(foreign_key.get("referred_columns") or ()) == ["id"]
        and foreign_key.get("referred_schema") in {None, current_schema}
        and str(options.get("ondelete", "")).upper() == "CASCADE"
        and set(options) <= {"ondelete"}
    ):
        return "conflict"
    if inspector.get_unique_constraints(_ADMISSIONS):
        return "conflict"
    if not _check_contract(bind) or not _index_contract(bind):
        return "conflict"
    return "expected"


def _schema_contracts(bind: sa.engine.Connection) -> dict[str, str]:
    contracts = {
        f"{_RULES}.{_RULE_REVISION}": _column_contract(
            bind,
            table=_RULES,
            column=_RULE_REVISION,
            type_=sa.Integer(),
            nullable=False,
            default="1",
        ),
        f"{_RULES}.{_DIGEST}": _column_contract(
            bind,
            table=_RULES,
            column=_DIGEST,
            type_=sa.String(length=64),
            nullable=True,
            default=None,
        ),
        f"{_PROJECTS}.{_PROJECT_REVISION}": _column_contract(
            bind,
            table=_PROJECTS,
            column=_PROJECT_REVISION,
            type_=sa.Integer(),
            nullable=False,
            default="1",
        ),
        _ADMISSIONS: _admissions_table_contract(bind),
    }
    rule_columns = [column["name"] for column in sa.inspect(bind).get_columns(_RULES)]
    if all(column in rule_columns for column in (_RULE_REVISION, _DIGEST)) and rule_columns[
        -2:
    ] != [_RULE_REVISION, _DIGEST]:
        contracts[f"{_RULES}.{_RULE_REVISION}"] = "conflict"
        contracts[f"{_RULES}.{_DIGEST}"] = "conflict"
    project_columns = [column["name"] for column in sa.inspect(bind).get_columns(_PROJECTS)]
    if _PROJECT_REVISION in project_columns and project_columns[-1] != _PROJECT_REVISION:
        contracts[f"{_PROJECTS}.{_PROJECT_REVISION}"] = "conflict"
    return contracts


def _assert_no_schema_conflicts(bind: sa.engine.Connection) -> dict[str, str]:
    """Fail before the first mutation when a reserved name is incompatible."""

    contracts = _schema_contracts(bind)
    conflicts = [name for name, state in contracts.items() if state == "conflict"]
    if conflicts:
        raise CommandError(
            "refusing automation rolling-window migration: incompatible "
            f"same-name schema object(s): {', '.join(conflicts)}",
        )
    return contracts


def _lock_upgrade_writers(bind: sa.engine.Connection) -> None:
    """Exclude application and out-of-band schema writers during install."""

    if bind.dialect.name != "postgresql":
        return
    bind.exec_driver_sql(
        f"LOCK TABLE {_PROJECTS}, {_RULES} IN ACCESS EXCLUSIVE MODE",
    )
    if _table_exists(bind, _ADMISSIONS):
        bind.exec_driver_sql(f"LOCK TABLE {_ADMISSIONS} IN ACCESS EXCLUSIVE MODE")


def _assert_upgrade_schema_state(bind: sa.engine.Connection) -> dict[str, str]:
    """Accept only the frozen prior schema with every 0014 object absent."""

    contracts = _assert_no_schema_conflicts(bind)
    states = list(contracts.values())
    if all(state == "absent" for state in states):
        return contracts
    raise CommandError(
        "refusing automation rolling-window migration: revision-owned schema "
        "objects are already or only partially present while the Alembic "
        "revision is not stamped",
    )


def _assert_downgrade_schema_state(bind: sa.engine.Connection) -> None:
    contracts = _assert_no_schema_conflicts(bind)
    if any(state != "expected" for state in contracts.values()):
        raise CommandError(
            "refusing automation rolling-window downgrade: revision-owned "
            "schema objects are not all present with their exact definitions",
        )


def _database_clock(bind: sa.engine.Connection) -> Any:
    """Database wall clock with the best portable SQLite precision."""

    if bind.dialect.name == "postgresql":
        return sa.func.clock_timestamp()
    if bind.dialect.name == "sqlite":
        return sa.func.strftime("%Y-%m-%d %H:%M:%f", "now")
    return sa.func.current_timestamp()


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(item["name"] == column for item in sa.inspect(bind).get_columns(table))


def _json_value(value: Any) -> Any:
    """Decode raw DBAPI JSON text while preserving valid JSON ``null``."""

    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError) as exc:
            raise CommandError(
                "refusing automation rolling-window migration: legacy rule "
                "contains invalid JSON configuration",
            ) from exc
    return value


def _boolean_value(value: Any) -> bool:
    """Interpret historical SQLite text defaults without truthy-string drift."""

    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"0", "false", "f", "no", "off"}:
            return False
        if normalised in {"1", "true", "t", "yes", "on"}:
            return True
        raise CommandError(f"invalid historical automation boolean {value!r}")
    return bool(value)


def _canonical_uuid(value: Any) -> str:
    """Render DBAPI UUID values identically on SQLite and PostgreSQL."""

    try:
        return str(uuid.UUID(str(value)))
    except (AttributeError, TypeError, ValueError):
        return str(value)


def _automation_tables() -> tuple[sa.TableClause, sa.TableClause]:
    """Typed clauses keep UUID/JSON binds portable in data migrations."""

    rules = sa.table(
        _RULES,
        sa.column("id", sa.Uuid()),
        sa.column("project_id", sa.Uuid()),
        sa.column("name", sa.String()),
        # Historical SQLite databases can store quoted boolean defaults as
        # text. Read them raw and canonicalise explicitly before hashing.
        sa.column("is_enabled"),
        sa.column("dry_run"),
        sa.column("trigger", sa.String()),
        sa.column("conditions", sa.JSON()),
        sa.column("actions", sa.JSON()),
        sa.column("max_executions_per_window", sa.Integer()),
        sa.column("window_seconds", sa.Integer()),
        sa.column("created_by", sa.Uuid()),
        sa.column("source_hash", sa.String()),
        sa.column("cb_tripped"),
        sa.column("cb_window_start", sa.DateTime(timezone=True)),
        sa.column("cb_execution_count", sa.Integer()),
        sa.column(_RULE_REVISION, sa.Integer()),
        sa.column(_DIGEST, sa.String(length=64)),
    )
    admissions = sa.table(
        _ADMISSIONS,
        sa.column("id", sa.Uuid()),
        sa.column("rule_id", sa.Uuid()),
        sa.column("admitted_at", sa.DateTime(timezone=True)),
        sa.column("weight", sa.Integer()),
    )
    return rules, admissions


def _config_digest(row: Any) -> str:
    """Frozen copy of the 0014 execution-configuration canonicalizer."""
    payload = {
        "project_id": _canonical_uuid(row.project_id),
        "name": row.name,
        "is_enabled": _boolean_value(row.is_enabled),
        "dry_run": _boolean_value(row.dry_run),
        "trigger": row.trigger,
        "conditions": _json_value(row.conditions),
        "actions": _json_value(row.actions),
        "max_executions_per_window": int(row.max_executions_per_window),
        "window_seconds": int(row.window_seconds),
        "created_by": _canonical_uuid(row.created_by) if row.created_by else None,
        "source_hash": row.source_hash,
        "config_revision": int(row.config_revision),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _aware(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _backfill_legacy_state(bind: sa.engine.Connection) -> None:
    """Bind existing fixed-window state to an exact-history epoch.

    The old schema knew the aggregate count but not each timestamp. One
    weighted admission at migration time is conservative: it can hold legacy
    debt slightly longer, but never grants fresh budget early. A weighted row
    avoids generating up to 100,000 child rows for one configured rule.
    """
    now = _aware(bind.execute(sa.select(_database_clock(bind))).scalar_one())
    if now is None:
        raise RuntimeError("database returned an invalid automation migration clock")
    rules, admissions = _automation_tables()
    rows = bind.execute(
        sa.select(
            rules.c.id,
            rules.c.project_id,
            rules.c.name,
            rules.c.is_enabled,
            rules.c.dry_run,
            rules.c.trigger,
            rules.c.conditions,
            rules.c.actions,
            rules.c.max_executions_per_window,
            rules.c.window_seconds,
            rules.c.created_by,
            rules.c.source_hash,
            rules.c.cb_tripped,
            rules.c.cb_window_start,
            rules.c.cb_execution_count,
            rules.c.config_revision,
        ),
    ).mappings()
    for row in rows:
        digest = _config_digest(row)
        is_enabled = _boolean_value(row.is_enabled)
        dry_run = _boolean_value(row.dry_run)
        was_tripped = _boolean_value(row.cb_tripped)
        limit = max(1, int(row.max_executions_per_window))
        old_count = max(0, int(row.cb_execution_count or 0))
        old_start = _aware(row.cb_window_start)
        window = timedelta(seconds=max(1, int(row.window_seconds)))
        active = old_count > 0 and (old_start is None or now < old_start + window)
        weight = min(old_count, limit) if active else 0
        anchor = max(now, old_start) if weight and old_start is not None else now
        if weight:
            bind.execute(
                sa.insert(admissions).values(
                    id=uuid.uuid4(),
                    rule_id=row.id,
                    admitted_at=anchor,
                    weight=weight,
                ),
            )
        bind.execute(
            sa.update(rules)
            .where(rules.c.id == row.id)
            .values(
                cb_config_digest=digest,
                is_enabled=is_enabled,
                dry_run=dry_run,
                cb_window_start=anchor if weight else None,
                cb_execution_count=weight,
                cb_tripped=was_tripped if weight else False,
            ),
        )


def upgrade() -> None:
    """Add monotonic authority epochs and bounded admission history."""

    bind = op.get_bind()
    # Inspect every reserved object before changing any of them. In
    # particular, existence is not compatibility: accepting a wrong-typed
    # column or an unconstrained same-name table and stamping this revision
    # would leave runtime arbitration fail-open.
    _lock_upgrade_writers(bind)
    contracts = _assert_upgrade_schema_state(bind)
    # The frozen initial revision deliberately stops at the historical schema.
    # 0014 alone owns all three appended columns and the admissions table.
    rules_absent = contracts[f"{_RULES}.{_RULE_REVISION}"] == "absent"
    projects_absent = contracts[f"{_PROJECTS}.{_PROJECT_REVISION}"] == "absent"
    if bind.dialect.name == "sqlite" and rules_absent:
        # Recreate instead of emitting raw ALTER ADD COLUMN. Both a fresh
        # chain and a restored prior-release database then converge on one
        # canonical CREATE TABLE definition rather than retaining whichever
        # whitespace/quoting the source database happened to use.
        with op.batch_alter_table(_RULES, recreate="always") as batch:
            batch.add_column(
                sa.Column(
                    _RULE_REVISION,
                    sa.Integer(),
                    nullable=False,
                    server_default="1",
                ),
            )
            batch.add_column(
                sa.Column(_DIGEST, sa.String(length=64), nullable=True),
            )
    elif rules_absent:
        op.add_column(
            _RULES,
            sa.Column(
                _RULE_REVISION,
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
        )
        op.add_column(
            _RULES,
            sa.Column(_DIGEST, sa.String(length=64), nullable=True),
        )
    if bind.dialect.name == "sqlite" and projects_absent:
        with op.batch_alter_table(_PROJECTS, recreate="always") as batch:
            batch.add_column(
                sa.Column(
                    _PROJECT_REVISION,
                    sa.Integer(),
                    nullable=False,
                    server_default="1",
                ),
            )
    elif projects_absent:
        op.add_column(
            _PROJECTS,
            sa.Column(
                _PROJECT_REVISION,
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
        )

    if contracts[_ADMISSIONS] == "absent":
        op.create_table(
            _ADMISSIONS,
            sa.Column("rule_id", sa.Uuid(), nullable=False),
            sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("weight", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.CheckConstraint(
                "weight > 0",
                name="ck_automation_rule_admissions_positive_weight",
            ),
            sa.ForeignKeyConstraint(
                ["rule_id"],
                ["automation_rules.id"],
                name="fk_automation_rule_admissions_rule_id_automation_rules",
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", name="pk_automation_rule_admissions"),
        )
        op.create_index(
            _INDEX,
            _ADMISSIONS,
            ["rule_id", "admitted_at"],
            unique=False,
        )

    # DDL reflection must now match the runtime contract exactly. This catches
    # dialect-specific surprises before any legacy state is transformed.
    _assert_downgrade_schema_state(bind)
    _backfill_legacy_state(bind)


def _lock_downgrade_writers(bind: sa.engine.Connection) -> None:
    """Freeze both the rolling history and its legacy projection."""

    if bind.dialect.name == "postgresql":
        bind.exec_driver_sql(
            f"LOCK TABLE {_RULES}, {_ADMISSIONS} IN ACCESS EXCLUSIVE MODE",
        )


def _collapse_rolling_state_for_downgrade(bind: sa.engine.Connection) -> None:
    """Conservatively translate live exact history to fixed-window debt.

    The legacy schema has only one window anchor and one count. Re-anchoring
    every non-zero retained debt at the downgrade's database wall clock can
    deny slightly longer than the exact timestamps would, but it can never
    grant budget while an admission was still live in the rolling window.
    """

    _lock_downgrade_writers(bind)
    now = _aware(bind.execute(sa.select(_database_clock(bind))).scalar_one())
    if now is None:
        raise RuntimeError("database returned an invalid automation downgrade clock")

    rules, admissions = _automation_tables()
    rows = bind.execute(
        sa.select(
            rules.c.id,
            rules.c.max_executions_per_window,
            rules.c.window_seconds,
            rules.c.cb_tripped,
        ),
    ).mappings()
    for rule in rows:
        window = timedelta(seconds=max(1, int(rule.window_seconds)))
        cutoff = now - window
        retained_value, newest_value = bind.execute(
            sa.select(
                sa.func.coalesce(sa.func.sum(admissions.c.weight), 0),
                sa.func.max(admissions.c.admitted_at),
            ).where(
                admissions.c.rule_id == rule.id,
                admissions.c.admitted_at > cutoff,
            ),
        ).one()
        retained = int(retained_value)
        limit = max(1, int(rule.max_executions_per_window))
        debt = min(max(0, retained), limit)
        newest = _aware(newest_value)
        if debt and newest is None:
            raise CommandError(
                "refusing automation rolling-window downgrade: retained "
                f"admission history for rule {rule.id} has no valid timestamp",
            )
        anchor = max(now, newest) if debt and newest is not None else None
        bind.execute(
            sa.update(rules)
            .where(rules.c.id == rule.id)
            .values(
                cb_window_start=anchor,
                cb_execution_count=debt,
                cb_tripped=_boolean_value(rule.cb_tripped) and debt >= limit,
            ),
        )


def downgrade() -> None:
    """Conservatively collapse exact history, then return to aggregates."""

    bind = op.get_bind()
    _assert_downgrade_schema_state(bind)
    _collapse_rolling_state_for_downgrade(bind)
    op.drop_table(_ADMISSIONS)
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(_RULES, recreate="always") as batch:
            if _column_exists(bind, _RULES, _DIGEST):
                batch.drop_column(_DIGEST)
            if _column_exists(bind, _RULES, _RULE_REVISION):
                batch.drop_column(_RULE_REVISION)
    else:
        if _column_exists(bind, _RULES, _DIGEST):
            op.drop_column(_RULES, _DIGEST)
        if _column_exists(bind, _RULES, _RULE_REVISION):
            op.drop_column(_RULES, _RULE_REVISION)
    if _column_exists(bind, _PROJECTS, _PROJECT_REVISION):
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(_PROJECTS, recreate="always") as batch:
                batch.drop_column(_PROJECT_REVISION)
        else:
            op.drop_column(_PROJECTS, _PROJECT_REVISION)


__all__ = [
    "_admissions_table_contract",
    "_assert_no_schema_conflicts",
    "_collapse_rolling_state_for_downgrade",
    "_config_digest",
    "_schema_contracts",
    "downgrade",
    "upgrade",
]


DOWNGRADE_PREFLIGHT = _assert_downgrade_schema_state
