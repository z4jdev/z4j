"""Maintain an exact audit tally and index receipt-bound command lookup.

The signed expected audit count remains unchanged. PostgreSQL ALWAYS triggers
maintain a separate observed count transactionally, including rollback and
replica-mode DML. Full verification still counts and authenticates the actual
rows; the append path compares the observed count with the signed expectation
under its existing locks. SQLite keeps the physical recount path.

Revision ID: v1_11_audit_append_tally
Revises: v1_9_audit_action_pattern
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_11_audit_append_tally"
down_revision: str | Sequence[str] | None = "v1_9_audit_action_pattern"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNT = "observed_active_row_count"
_TABLE = "commands"
_INDEX = "ix_commands_schedule_fire_receipt"
_COLUMNS = ("schedule_id", "schedule_fire_id", "schedule_receipt_control_token")


def _normalise_definition(definition: str) -> str:
    return " ".join(
        definition.replace('"', "").replace("`", "").lower().split(),
    )


def _command_index_state(bind: sa.engine.Connection) -> str:  # noqa: PLR0911 - dialect audit
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
        expected = f"create index {_INDEX} on {_TABLE} (schedule_id, schedule_fire_id, schedule_receipt_control_token)"
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
        expected_suffix = (
            "using btree (schedule_id, schedule_fire_id, schedule_receipt_control_token)"
        )
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
    bind = op.get_bind()
    index_state = _command_index_state(bind)
    if index_state == "conflict":
        raise CommandError(f"refusing upgrade: {_INDEX} has an unexpected definition")
    if bind.dialect.name == "postgresql":
        # Use the same lock as every signer/retention transaction. Preserve
        # the old signed state; only initialize the new observed count.
        bind.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x7A_34_6A_DA})
        bind.execute(sa.text("LOCK TABLE audit_log, audit_chain_state IN EXCLUSIVE MODE"))
    op.add_column(
        "audit_chain_state",
        sa.Column(
            _COUNT,
            sa.BigInteger(),
            sa.CheckConstraint(
                f"{_COUNT} >= 0",
                name=op.f("ck_audit_chain_state_observed_active_row_count_nonnegative"),
            ),
            nullable=False,
            server_default="0",
        ),
    )
    if index_state == "absent":
        op.create_index(_INDEX, "commands", list(_COLUMNS), unique=False)
    if bind.dialect.name != "postgresql":
        return
    old_transition = bind.scalar(sa.text("SELECT current_setting('z4j.audit_transition', true)"))
    bind.execute(sa.text("SELECT set_config('z4j.audit_transition', 'append-v1', true)"))
    bind.execute(
        sa.text(
            "UPDATE audit_chain_state SET observed_active_row_count = "
            "(SELECT count(*) FROM audit_log WHERE legacy_frozen IS FALSE)",
        ),
    )
    bind.execute(
        sa.text("SELECT set_config('z4j.audit_transition', :old, true)"),
        {"old": old_transition or ""},
    )
    _install_function(bind, "z4j_audit_protect_tally_v1", _PROTECT_TALLY)
    _install_function(bind, "z4j_audit_tally_rows_v1", _MAINTAIN_TALLY)
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_chain_state_protect_tally "
            "BEFORE INSERT OR UPDATE ON audit_chain_state FOR EACH ROW "
            "EXECUTE FUNCTION z4j_audit_protect_tally_v1()",
        ),
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_log_tally_rows "
            "AFTER INSERT OR UPDATE OR DELETE ON audit_log FOR EACH ROW "
            "EXECUTE FUNCTION z4j_audit_tally_rows_v1()",
        ),
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_log_tally_truncate AFTER TRUNCATE ON audit_log "
            "FOR EACH STATEMENT EXECUTE FUNCTION z4j_audit_tally_rows_v1()",
        ),
    )
    op.execute(
        sa.text(
            "ALTER TABLE audit_chain_state ENABLE ALWAYS TRIGGER audit_chain_state_protect_tally",
        ),
    )
    op.execute(sa.text("ALTER TABLE audit_log ENABLE ALWAYS TRIGGER audit_log_tally_rows"))
    op.execute(sa.text("ALTER TABLE audit_log ENABLE ALWAYS TRIGGER audit_log_tally_truncate"))


_PROTECT_TALLY = """
CREATE FUNCTION z4j_audit_protect_tally_v1() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT count(*) INTO NEW.observed_active_row_count
      FROM audit_log WHERE legacy_frozen IS FALSE;
  ELSIF NEW.observed_active_row_count IS DISTINCT FROM OLD.observed_active_row_count
        AND pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'audit row tally is maintained by audit row triggers';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
"""

_MAINTAIN_TALLY = """
CREATE FUNCTION z4j_audit_tally_rows_v1() RETURNS trigger AS $$
DECLARE
  delta bigint := 0;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.legacy_frozen IS FALSE AND NEW.legacy_frozen IS FALSE
       AND OLD.chain_generation IS DISTINCT FROM NEW.chain_generation THEN
      RAISE EXCEPTION 'active audit rows cannot change generation';
    END IF;
  END IF;
  IF TG_OP = 'TRUNCATE' THEN
    UPDATE audit_chain_state SET observed_active_row_count = 0
      WHERE singleton_id = 'audit-chain';
    RETURN NULL;
  END IF;
  IF TG_OP IN ('DELETE', 'UPDATE') THEN
    IF OLD.legacy_frozen IS FALSE THEN delta := delta - 1; END IF;
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    IF NEW.legacy_frozen IS FALSE THEN delta := delta + 1; END IF;
  END IF;
  IF delta <> 0 THEN
    UPDATE audit_chain_state
       SET observed_active_row_count = observed_active_row_count + delta
     WHERE singleton_id = 'audit-chain';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'audit row tally state is missing';
    END IF;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
"""


def _install_function(bind: sa.engine.Connection, name: str, definition: str) -> None:
    # A restore into an existing installation removes tables but can retain
    # these functions. Admit only this migration's exact leftover definition;
    # an unrelated reserved-name collision must not be overwritten.
    existing = (
        bind.execute(
            sa.text(
                "SELECT p.prosrc, p.prorettype = 'trigger'::regtype AS returns_trigger, "
                "p.prosecdef, p.proconfig, p.provolatile, p.proisstrict, p.proretset, "
                "p.proleakproof, l.lanname FROM pg_proc p "
                "JOIN pg_language l ON l.oid = p.prolang "
                "WHERE p.oid = to_regprocedure(:signature)",
            ),
            {"signature": f"{name}()"},
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None and (
        existing["prosrc"].strip() != definition.split("$$")[1].strip()
        or not existing["returns_trigger"]
        or existing["prosecdef"]
        or existing["proconfig"] is not None
        or existing["provolatile"] != "v"
        or existing["proisstrict"]
        or existing["proretset"]
        or existing["proleakproof"]
        or existing["lanname"] != "plpgsql"
    ):
        raise CommandError(f"refusing upgrade: {name} has an unexpected definition")
    op.execute(sa.text(definition.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)))


def _assert_downgrade_index_is_safe(bind: sa.engine.Connection) -> None:
    if _command_index_state(bind) == "conflict":
        raise CommandError(f"refusing downgrade: {_INDEX} has an unexpected definition")


DOWNGRADE_PREFLIGHT = _assert_downgrade_index_is_safe


def downgrade() -> None:
    # This removes only derived accounting/indexes. Signed authority and audit
    # rows remain intact; the previous writer resumes physical recounts. The
    # release-head startup fence refuses a new writer against this older schema.
    bind = op.get_bind()
    _assert_downgrade_index_is_safe(bind)
    state = _command_index_state(bind)
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x7A_34_6A_DA})
        bind.execute(sa.text("LOCK TABLE audit_log, audit_chain_state IN EXCLUSIVE MODE"))
        op.execute(sa.text("DROP TRIGGER audit_log_tally_rows ON audit_log"))
        op.execute(sa.text("DROP TRIGGER audit_log_tally_truncate ON audit_log"))
        op.execute(sa.text("DROP TRIGGER audit_chain_state_protect_tally ON audit_chain_state"))
        op.execute(sa.text("DROP FUNCTION z4j_audit_tally_rows_v1()"))
        op.execute(sa.text("DROP FUNCTION z4j_audit_protect_tally_v1()"))
    if state == "expected":
        op.drop_index(_INDEX, table_name=_TABLE)
    op.drop_column("audit_chain_state", _COUNT)
