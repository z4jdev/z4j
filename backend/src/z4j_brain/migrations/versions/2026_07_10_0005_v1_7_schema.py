"""z4j 1.7 consolidated schema delta over the v1_6_6 floor.

Revision ID: v1_7_schema
Revises: v1_6_6_scrub_worker_conf
Create Date: 2026-07-10

This single migration is the whole 1.7 schema delta applied on top of the
1.6.x compatibility floor (``v1_6_6_scrub_worker_conf``). It replaces the
thirteen development-time migrations 0005..0017 that were authored one per
change during the 1.7 cycle, folding them into one file for the release
while preserving their EXACT DDL, guards, and idempotency checks. The
in-place 1.6.x -> 1.7 upgrade path is unchanged: ``down_revision`` stays
``v1_6_6_scrub_worker_conf``, so an operator on any 1.6.x head upgrades
straight to this revision, and downgrading this revision returns the
database to the 1.6.x floor.

``upgrade()`` runs the thirteen original upgrades in their authored order
(0005 -> 0017); ``downgrade()`` runs the thirteen original downgrades in
the exact reverse order (0017 -> 0005), so the sequencing an operator
would have seen stepping the old chain one revision at a time is preserved
byte-for-byte.

What it does, in order:

1. automation_rules (0005): add the cross-engine rule-engine table
   (+ indexes) via a single-table ``create_all`` subset.
2. automation_kill_switch (0006): add ``projects.automation_enabled``
   (BOOLEAN NOT NULL DEFAULT true), the per-project off switch.
3. drop_alert_events (0007): drop the dead ``alert_events`` table (the
   model was removed); downgrade recreates it empty with its original
   shape.
4. schedule_fire_triggered_by (0008): add
   ``schedule_fires.triggered_by_user_id`` (nullable UUID + ON DELETE SET
   NULL FK on Postgres) for manual-trigger attribution.
5. automation_notify_coalesce (0009): add
   ``automation_rules.last_notify_at`` (nullable timestamptz) for the
   notify-coalesce window.
6. automation_firing_outbox (0010): add the durable firing-buffer table
   (+ Postgres ``gen_random_uuid()`` id default).
7. schedule_fires_partition (0011): on Postgres, recreate
   ``schedule_fires`` as a RANGE-partitioned table keyed on
   ``scheduled_for`` (recreate-and-copy). No-op on SQLite (no native
   partitioning), guarded on ``dialect.name``.
8. tasks_fingerprint (0012): add ``tasks.fingerprint`` (nullable
   String(32)) + the ``(project_id, fingerprint)`` Issues index.
9. misfire_alerts (0013): add the durable cross-replica misfire dedup
   table (+ Postgres id default).
10. outbox_backoff (0014): add ``automation_firing_outbox.next_attempt_at``
    (nullable timestamptz) + the ``(project_id)`` drain index.
11. tasks_last_failed_at (0015): add ``tasks.last_failed_at`` (nullable
    timestamptz) for Issues failure-time windows.
12. agent_offline_alerts (0016): add the durable cross-replica
    agent-offline dedup table (+ Postgres id default).
13. drop_project_retention_days (0017): drop the dead
    ``projects.retention_days`` column; downgrade re-adds it nullable with
    the old server default 30.

Idempotency and fresh installs. A fresh install builds the whole schema
from the current model metadata in the 0001 initial migration, so every
table and column added here already exists on a fresh DB. Each step is
therefore guarded to be a no-op when already applied: table adds use
``create_all(checkfirst=True)``, column and index adds check the inspector
first, and the Postgres-only partition recreate is skipped on SQLite. That
keeps this revision safe to run against both a real 1.6.x upgrade (where
the objects do not yet exist) and a fresh install (where they do).

Cross-dialect and compat. Every additive column is nullable or
server-defaulted and every new table is ignorable by an N-1 brain, so a
running pre-1.7 brain is unaffected. The migration round-trips on Postgres
and SQLite per the 1.4 compatibility floor. The only non-no-op on the
fresh path is the Postgres partition recreate (step 7), which has no
"already partitioned" guard and must not be re-run once at head; alembic's
version stamping ensures it is applied exactly once.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.types import Uuid
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.agent_offline_alert import AgentOfflineAlert
from z4j_brain.persistence.models.automation_firing_outbox import (
    AutomationFiringOutbox,
)
from z4j_brain.persistence.models.automation_rule import AutomationRule
from z4j_brain.persistence.models.misfire_alert import MisfireAlert

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_schema"
down_revision: str | Sequence[str] | None = "v1_6_6_scrub_worker_conf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_6_6_scrub_worker_conf",
    "downgrade_to": "v1_6_6_scrub_worker_conf",
}


# ===========================================================================
# 0005 v1_7_automation_rules -- add the automation_rules table (rule engine).
# ===========================================================================


def _up_automation_rules(bind) -> None:
    """Create the ``automation_rules`` table + its indexes.

    Idempotent: ``create_all`` with ``checkfirst`` (the default) skips
    the table if it already exists, so a re-run is a no-op.
    """
    Base.metadata.create_all(
        bind=bind,
        tables=[AutomationRule.__table__],
        checkfirst=True,
    )


def _down_automation_rules(bind) -> None:
    """Drop the ``automation_rules`` table (indexes drop with it)."""
    AutomationRule.__table__.drop(bind=bind, checkfirst=True)


# ===========================================================================
# 0006 v1_7_automation_kill_switch -- projects.automation_enabled kill switch.
# ===========================================================================

_KILL_SWITCH_TABLE = "projects"
_KILL_SWITCH_COLUMN = "automation_enabled"


def _kill_switch_column_exists(bind, table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(bind)
    return any(c["name"] == column_name for c in inspector.get_columns(table_name))


def _up_automation_kill_switch(bind) -> None:
    """Add ``projects.automation_enabled`` (default on), idempotently."""
    if not _kill_switch_column_exists(bind, _KILL_SWITCH_TABLE, _KILL_SWITCH_COLUMN):
        op.add_column(
            _KILL_SWITCH_TABLE,
            sa.Column(
                _KILL_SWITCH_COLUMN,
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )


def _down_automation_kill_switch(bind) -> None:
    """Drop ``projects.automation_enabled``, idempotently."""
    if not _kill_switch_column_exists(bind, _KILL_SWITCH_TABLE, _KILL_SWITCH_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_KILL_SWITCH_TABLE, _KILL_SWITCH_COLUMN)
    else:
        with op.batch_alter_table(_KILL_SWITCH_TABLE) as batch:
            batch.drop_column(_KILL_SWITCH_COLUMN)


# ===========================================================================
# 0007 v1_7_drop_alert_events -- drop the dead alert_events table.
# ===========================================================================

_DROP_ALERT_EVENTS_TABLE = "alert_events"


def _drop_alert_events_table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return sa.inspect(bind).has_table(name)


def _up_drop_alert_events(bind) -> None:
    """Drop ``alert_events`` if present (idempotent)."""
    if _drop_alert_events_table_exists(bind, _DROP_ALERT_EVENTS_TABLE):
        # No CASCADE needed: alert_events is a leaf table (nothing
        # references it); its own outbound FKs drop with it.
        op.drop_table(_DROP_ALERT_EVENTS_TABLE)


def _down_drop_alert_events(bind) -> None:
    """Recreate ``alert_events`` with its original shape (empty)."""
    if _drop_alert_events_table_exists(bind, _DROP_ALERT_EVENTS_TABLE):
        return
    is_postgres = bind.dialect.name == "postgresql"
    # Match the original: the initial migration set a server-side
    # gen_random_uuid() default on every UUID id column (Postgres only).
    id_server_default = sa.text("gen_random_uuid()") if is_postgres else None
    op.create_table(
        _DROP_ALERT_EVENTS_TABLE,
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


# ===========================================================================
# 0008 v1_7_schedule_fire_triggered_by -- schedule_fires.triggered_by_user_id.
# ===========================================================================

# Must equal the name Base.metadata's naming_convention derives on the
# fresh-install (create_all) path -- fk_%(table)s_%(column)s_%(referred)s --
# so an upgraded DB and a fresh install carry an identically-named FK and
# schema-diff / autogenerate tooling sees no phantom drift.
_TRIGGERED_BY_TABLE = "schedule_fires"
_TRIGGERED_BY_COLUMN = "triggered_by_user_id"
_TRIGGERED_BY_FK = "fk_schedule_fires_triggered_by_user_id_users"


def _triggered_by_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _up_schedule_fire_triggered_by(bind) -> None:
    """Add ``schedule_fires.triggered_by_user_id`` (nullable), idempotently."""
    if _triggered_by_column_exists(bind, _TRIGGERED_BY_TABLE, _TRIGGERED_BY_COLUMN):
        return
    op.add_column(
        _TRIGGERED_BY_TABLE,
        sa.Column(_TRIGGERED_BY_COLUMN, Uuid(as_uuid=True), nullable=True),
    )
    # SQLite cannot ADD a FK to an existing table via ALTER; its FK
    # enforcement is off by default anyway and the app-level model still
    # declares the relationship. On Postgres we add the real constraint.
    if bind.dialect.name == "postgresql":
        op.create_foreign_key(
            _TRIGGERED_BY_FK,
            _TRIGGERED_BY_TABLE,
            "users",
            [_TRIGGERED_BY_COLUMN],
            ["id"],
            ondelete="SET NULL",
        )


def _down_schedule_fire_triggered_by(bind) -> None:
    """Drop ``schedule_fires.triggered_by_user_id``, idempotently."""
    if not _triggered_by_column_exists(bind, _TRIGGERED_BY_TABLE, _TRIGGERED_BY_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        # Postgres drops the dependent FK constraint together with the
        # column, so no explicit drop_constraint is needed (and the FK
        # name differs between the create_all path and this migration's
        # path, which would make a named drop fragile).
        op.drop_column(_TRIGGERED_BY_TABLE, _TRIGGERED_BY_COLUMN)
    else:
        with op.batch_alter_table(_TRIGGERED_BY_TABLE) as batch:
            batch.drop_column(_TRIGGERED_BY_COLUMN)


# ===========================================================================
# 0009 v1_7_automation_notify_coalesce -- automation_rules.last_notify_at.
# ===========================================================================

_NOTIFY_COALESCE_TABLE = "automation_rules"
_NOTIFY_COALESCE_COLUMN = "last_notify_at"


def _notify_coalesce_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _up_automation_notify_coalesce(bind) -> None:
    """Add ``automation_rules.last_notify_at`` (nullable), idempotently."""
    if _notify_coalesce_column_exists(bind, _NOTIFY_COALESCE_TABLE, _NOTIFY_COALESCE_COLUMN):
        return
    op.add_column(
        _NOTIFY_COALESCE_TABLE,
        sa.Column(_NOTIFY_COALESCE_COLUMN, sa.DateTime(timezone=True), nullable=True),
    )


def _down_automation_notify_coalesce(bind) -> None:
    """Drop ``automation_rules.last_notify_at``, idempotently."""
    if not _notify_coalesce_column_exists(bind, _NOTIFY_COALESCE_TABLE, _NOTIFY_COALESCE_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_NOTIFY_COALESCE_TABLE, _NOTIFY_COALESCE_COLUMN)
    else:
        with op.batch_alter_table(_NOTIFY_COALESCE_TABLE) as batch:
            batch.drop_column(_NOTIFY_COALESCE_COLUMN)


# ===========================================================================
# 0010 v1_7_automation_firing_outbox -- durable firing-buffer table.
# ===========================================================================


def _up_automation_firing_outbox(bind) -> None:
    """Create ``automation_firing_outbox`` (+ index), idempotently."""
    Base.metadata.create_all(
        bind=bind,
        tables=[AutomationFiringOutbox.__table__],
        checkfirst=True,
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "ALTER TABLE IF EXISTS automation_firing_outbox "
                "ALTER COLUMN id SET DEFAULT gen_random_uuid()",
            ),
        )


def _down_automation_firing_outbox(bind) -> None:
    """Drop the ``automation_firing_outbox`` table (index drops with it)."""
    AutomationFiringOutbox.__table__.drop(bind=bind, checkfirst=True)


# ===========================================================================
# 0011 v1_7_schedule_fires_partition -- RANGE-partition schedule_fires (PG).
# ===========================================================================

# Columns in a fixed, explicit order so INSERT ... SELECT is position-safe
# regardless of the source table's physical column order.
_PARTITION_COLUMNS = (
    "id",
    "fire_id",
    "schedule_id",
    "project_id",
    "command_id",
    "triggered_by_user_id",
    "status",
    "scheduled_for",
    "fired_at",
    "acked_at",
    "latency_ms",
    "error_code",
    "error_message",
)
_PARTITION_COL_LIST = ", ".join(_PARTITION_COLUMNS)

# Days of daily partitions to pre-create on each side of today. 31 back
# covers the default 30-day retention so recent data lands in droppable
# daily partitions rather than DEFAULT; older data goes to DEFAULT and is
# handled by the DELETE-based prune fallback.
_PARTITION_PRECREATE_BACK = 31
_PARTITION_PRECREATE_FWD = 7


def _partition_create_partitioned_table_sql() -> str:
    return (
        "CREATE TABLE schedule_fires ("
        "  id UUID NOT NULL DEFAULT gen_random_uuid(),"
        "  fire_id UUID NOT NULL,"
        "  schedule_id UUID NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,"
        "  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,"
        "  command_id UUID REFERENCES commands(id) ON DELETE SET NULL,"
        "  triggered_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,"
        "  status VARCHAR(32) NOT NULL,"
        "  scheduled_for TIMESTAMPTZ NOT NULL,"
        "  fired_at TIMESTAMPTZ NOT NULL,"
        "  acked_at TIMESTAMPTZ,"
        "  latency_ms INTEGER,"
        "  error_code VARCHAR(64),"
        "  error_message VARCHAR(2000),"
        "  CONSTRAINT pk_schedule_fires PRIMARY KEY (id, scheduled_for),"
        "  CONSTRAINT uq_schedule_fires_fire_id UNIQUE (fire_id, scheduled_for)"
        ") PARTITION BY RANGE (scheduled_for)"
    )


def _partition_create_plain_table_sql() -> str:
    """The original (pre-partition) plain table shape, for downgrade."""
    return (
        "CREATE TABLE schedule_fires ("
        "  id UUID NOT NULL DEFAULT gen_random_uuid(),"
        "  fire_id UUID NOT NULL,"
        "  schedule_id UUID NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,"
        "  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,"
        "  command_id UUID REFERENCES commands(id) ON DELETE SET NULL,"
        "  triggered_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,"
        "  status VARCHAR(32) NOT NULL,"
        "  scheduled_for TIMESTAMPTZ NOT NULL,"
        "  fired_at TIMESTAMPTZ NOT NULL,"
        "  acked_at TIMESTAMPTZ,"
        "  latency_ms INTEGER,"
        "  error_code VARCHAR(64),"
        "  error_message VARCHAR(2000),"
        "  CONSTRAINT pk_schedule_fires PRIMARY KEY (id),"
        "  CONSTRAINT uq_schedule_fires_fire_id UNIQUE (fire_id)"
        ")"
    )


_PARTITION_INDEXES_SQL = (
    "CREATE INDEX ix_schedule_fires_schedule_recent ON schedule_fires (schedule_id, fired_at)",
    "CREATE INDEX ix_schedule_fires_circuit_breaker "
    "ON schedule_fires (schedule_id, status, fired_at)",
)

_PARTITION_PRECREATE_DAILIES_SQL = (
    "DO $$ "
    "DECLARE d DATE; "
    "BEGIN "
    f"FOR i IN -{_PARTITION_PRECREATE_BACK}..{_PARTITION_PRECREATE_FWD} LOOP "
    "  d := (CURRENT_DATE + i)::DATE; "
    "  EXECUTE format("
    "    'CREATE TABLE IF NOT EXISTS schedule_fires_%s "
    "     PARTITION OF schedule_fires "
    "     FOR VALUES FROM (%L) TO (%L)',"
    "    to_char(d, 'YYYY_MM_DD'), d, d + 1"
    "  ); "
    "END LOOP; "
    "END $$"
)


def _up_schedule_fires_partition(bind) -> None:
    """Convert schedule_fires into a scheduled_for RANGE-partitioned table."""
    if bind.dialect.name != "postgresql":
        return  # SQLite: no native partitioning; plain table stays as-is.

    # 1. Move the existing table + its clashing index/constraint names aside.
    #    Index/constraint names are schema-global, so the new table cannot
    #    reuse pk_schedule_fires / uq_schedule_fires_fire_id / ix_* while the
    #    old ones still exist (the metadata naming_convention names the PK
    #    pk_schedule_fires, NOT the Postgres default schedule_fires_pkey).
    op.execute("ALTER TABLE schedule_fires RENAME TO schedule_fires_legacy")
    op.execute(
        "ALTER TABLE schedule_fires_legacy "
        "RENAME CONSTRAINT pk_schedule_fires TO pk_schedule_fires_legacy",
    )
    op.execute(
        "ALTER TABLE schedule_fires_legacy "
        "RENAME CONSTRAINT uq_schedule_fires_fire_id "
        "TO uq_schedule_fires_fire_id_legacy",
    )
    op.execute(
        "ALTER INDEX ix_schedule_fires_schedule_recent "
        "RENAME TO ix_schedule_fires_schedule_recent_legacy",
    )
    op.execute(
        "ALTER INDEX ix_schedule_fires_circuit_breaker "
        "RENAME TO ix_schedule_fires_circuit_breaker_legacy",
    )

    # 2. Create the partitioned parent + indexes (Postgres propagates the
    #    indexes to every partition).
    op.execute(_partition_create_partitioned_table_sql())
    for stmt in _PARTITION_INDEXES_SQL:
        op.execute(stmt)

    # 3. DEFAULT partition (the copy can never fail with "no partition
    #    found") + a window of daily partitions around today so recent rows
    #    land in droppable dailies rather than DEFAULT.
    op.execute(
        "CREATE TABLE IF NOT EXISTS schedule_fires_default PARTITION OF schedule_fires DEFAULT"
    )
    op.execute(_PARTITION_PRECREATE_DAILIES_SQL)

    # 4. Copy the data with an explicit column list (physical column order
    #    differs between a fresh install and a 1.6->1.7 upgrade).
    op.execute(
        f"INSERT INTO schedule_fires ({_PARTITION_COL_LIST}) SELECT {_PARTITION_COL_LIST} FROM schedule_fires_legacy",  # noqa: S608 -- column list is a hardcoded module constant, not user input
    )

    # 5. Drop the old table.
    op.execute("DROP TABLE schedule_fires_legacy")


def _down_schedule_fires_partition(bind) -> None:
    """Reverse the partitioning: back to the plain (id)-PK table."""
    if bind.dialect.name != "postgresql":
        return

    op.execute("ALTER TABLE schedule_fires RENAME TO schedule_fires_part")
    op.execute(
        "ALTER TABLE schedule_fires_part "
        "RENAME CONSTRAINT pk_schedule_fires TO pk_schedule_fires_part",
    )
    op.execute(
        "ALTER TABLE schedule_fires_part "
        "RENAME CONSTRAINT uq_schedule_fires_fire_id "
        "TO uq_schedule_fires_fire_id_part",
    )
    op.execute(
        "ALTER INDEX ix_schedule_fires_schedule_recent "
        "RENAME TO ix_schedule_fires_schedule_recent_part",
    )
    op.execute(
        "ALTER INDEX ix_schedule_fires_circuit_breaker "
        "RENAME TO ix_schedule_fires_circuit_breaker_part",
    )

    op.execute(_partition_create_plain_table_sql())
    for stmt in _PARTITION_INDEXES_SQL:
        op.execute(stmt)

    op.execute(
        f"INSERT INTO schedule_fires ({_PARTITION_COL_LIST}) SELECT {_PARTITION_COL_LIST} FROM schedule_fires_part",  # noqa: S608 -- column list is a hardcoded module constant, not user input
    )

    # Dropping the partitioned parent drops all its partitions.
    op.execute("DROP TABLE schedule_fires_part")


# ===========================================================================
# 0012 v1_7_tasks_fingerprint -- tasks.fingerprint + Issues index.
# ===========================================================================

_TASKS_FINGERPRINT_TABLE = "tasks"
_TASKS_FINGERPRINT_COLUMN = "fingerprint"
_TASKS_FINGERPRINT_INDEX = "ix_tasks_project_fingerprint"


def _tasks_fingerprint_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _tasks_fingerprint_index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def _up_tasks_fingerprint(bind) -> None:
    if not _tasks_fingerprint_column_exists(
        bind, _TASKS_FINGERPRINT_TABLE, _TASKS_FINGERPRINT_COLUMN
    ):
        op.add_column(
            _TASKS_FINGERPRINT_TABLE,
            sa.Column(_TASKS_FINGERPRINT_COLUMN, sa.String(length=32), nullable=True),
        )
    if not _tasks_fingerprint_index_exists(
        bind, _TASKS_FINGERPRINT_TABLE, _TASKS_FINGERPRINT_INDEX
    ):
        op.create_index(
            _TASKS_FINGERPRINT_INDEX,
            _TASKS_FINGERPRINT_TABLE,
            ["project_id", _TASKS_FINGERPRINT_COLUMN],
        )


def _down_tasks_fingerprint(bind) -> None:
    if _tasks_fingerprint_index_exists(bind, _TASKS_FINGERPRINT_TABLE, _TASKS_FINGERPRINT_INDEX):
        op.drop_index(_TASKS_FINGERPRINT_INDEX, table_name=_TASKS_FINGERPRINT_TABLE)
    if not _tasks_fingerprint_column_exists(
        bind, _TASKS_FINGERPRINT_TABLE, _TASKS_FINGERPRINT_COLUMN
    ):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_TASKS_FINGERPRINT_TABLE, _TASKS_FINGERPRINT_COLUMN)
    else:
        with op.batch_alter_table(_TASKS_FINGERPRINT_TABLE) as batch:
            batch.drop_column(_TASKS_FINGERPRINT_COLUMN)


# ===========================================================================
# 0013 v1_7_misfire_alerts -- durable cross-replica misfire dedup table.
# ===========================================================================


def _up_misfire_alerts(bind) -> None:
    """Create ``misfire_alerts`` (+ constraints/index), idempotently."""
    Base.metadata.create_all(
        bind=bind,
        tables=[MisfireAlert.__table__],
        checkfirst=True,
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "ALTER TABLE IF EXISTS misfire_alerts "
                "ALTER COLUMN id SET DEFAULT gen_random_uuid()",
            ),
        )


def _down_misfire_alerts(bind) -> None:
    """Drop the ``misfire_alerts`` table (constraints/index drop with it)."""
    MisfireAlert.__table__.drop(bind=bind, checkfirst=True)


# ===========================================================================
# 0014 v1_7_outbox_backoff -- automation_firing_outbox.next_attempt_at + index.
# ===========================================================================

_OUTBOX_BACKOFF_TABLE = "automation_firing_outbox"
_OUTBOX_BACKOFF_COLUMN = "next_attempt_at"
_OUTBOX_BACKOFF_INDEX = "ix_automation_firing_outbox_project"


def _outbox_backoff_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _outbox_backoff_index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def _up_outbox_backoff(bind) -> None:
    if not _outbox_backoff_column_exists(bind, _OUTBOX_BACKOFF_TABLE, _OUTBOX_BACKOFF_COLUMN):
        op.add_column(
            _OUTBOX_BACKOFF_TABLE,
            sa.Column(_OUTBOX_BACKOFF_COLUMN, sa.DateTime(timezone=True), nullable=True),
        )
    if not _outbox_backoff_index_exists(bind, _OUTBOX_BACKOFF_TABLE, _OUTBOX_BACKOFF_INDEX):
        op.create_index(_OUTBOX_BACKOFF_INDEX, _OUTBOX_BACKOFF_TABLE, ["project_id"])


def _down_outbox_backoff(bind) -> None:
    if _outbox_backoff_index_exists(bind, _OUTBOX_BACKOFF_TABLE, _OUTBOX_BACKOFF_INDEX):
        op.drop_index(_OUTBOX_BACKOFF_INDEX, table_name=_OUTBOX_BACKOFF_TABLE)
    if not _outbox_backoff_column_exists(bind, _OUTBOX_BACKOFF_TABLE, _OUTBOX_BACKOFF_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_OUTBOX_BACKOFF_TABLE, _OUTBOX_BACKOFF_COLUMN)
    else:
        with op.batch_alter_table(_OUTBOX_BACKOFF_TABLE) as batch:
            batch.drop_column(_OUTBOX_BACKOFF_COLUMN)


# ===========================================================================
# 0015 v1_7_tasks_last_failed_at -- tasks.last_failed_at.
# ===========================================================================

_LAST_FAILED_AT_TABLE = "tasks"
_LAST_FAILED_AT_COLUMN = "last_failed_at"


def _last_failed_at_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _up_tasks_last_failed_at(bind) -> None:
    if not _last_failed_at_column_exists(bind, _LAST_FAILED_AT_TABLE, _LAST_FAILED_AT_COLUMN):
        op.add_column(
            _LAST_FAILED_AT_TABLE,
            sa.Column(_LAST_FAILED_AT_COLUMN, sa.DateTime(timezone=True), nullable=True),
        )


def _down_tasks_last_failed_at(bind) -> None:
    if not _last_failed_at_column_exists(bind, _LAST_FAILED_AT_TABLE, _LAST_FAILED_AT_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_LAST_FAILED_AT_TABLE, _LAST_FAILED_AT_COLUMN)
    else:
        with op.batch_alter_table(_LAST_FAILED_AT_TABLE) as batch:
            batch.drop_column(_LAST_FAILED_AT_COLUMN)


# ===========================================================================
# 0016 v1_7_agent_offline_alerts -- durable cross-replica offline dedup table.
# ===========================================================================


def _up_agent_offline_alerts(bind) -> None:
    """Create ``agent_offline_alerts`` (+ constraints/index), idempotently."""
    Base.metadata.create_all(
        bind=bind,
        tables=[AgentOfflineAlert.__table__],
        checkfirst=True,
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "ALTER TABLE IF EXISTS agent_offline_alerts "
                "ALTER COLUMN id SET DEFAULT gen_random_uuid()",
            ),
        )


def _down_agent_offline_alerts(bind) -> None:
    """Drop the ``agent_offline_alerts`` table (constraints/index drop with it)."""
    AgentOfflineAlert.__table__.drop(bind=bind, checkfirst=True)


# ===========================================================================
# 0017 v1_7_drop_project_retention_days -- drop the dead retention_days column.
# ===========================================================================

_RETENTION_DAYS_TABLE = "projects"
_RETENTION_DAYS_COLUMN = "retention_days"


def _retention_days_column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _up_drop_project_retention_days(bind) -> None:
    """Drop ``projects.retention_days`` if present (idempotent)."""
    if not _retention_days_column_exists(bind, _RETENTION_DAYS_TABLE, _RETENTION_DAYS_COLUMN):
        return
    if bind.dialect.name == "postgresql":
        op.drop_column(_RETENTION_DAYS_TABLE, _RETENTION_DAYS_COLUMN)
    else:
        with op.batch_alter_table(_RETENTION_DAYS_TABLE) as batch:
            batch.drop_column(_RETENTION_DAYS_COLUMN)


def _down_drop_project_retention_days(bind) -> None:
    """Re-add ``projects.retention_days`` (nullable, old default 30)."""
    if _retention_days_column_exists(bind, _RETENTION_DAYS_TABLE, _RETENTION_DAYS_COLUMN):
        return
    op.add_column(
        _RETENTION_DAYS_TABLE,
        sa.Column(_RETENTION_DAYS_COLUMN, sa.Integer(), nullable=True, server_default="30"),
    )


# ===========================================================================
# Consolidated upgrade / downgrade entry points.
# ===========================================================================


def upgrade() -> None:
    """Apply the full 1.7 schema delta over the v1_6_6 floor, 0005 -> 0017."""
    bind = op.get_bind()
    _up_automation_rules(bind)
    _up_automation_kill_switch(bind)
    _up_drop_alert_events(bind)
    _up_schedule_fire_triggered_by(bind)
    _up_automation_notify_coalesce(bind)
    _up_automation_firing_outbox(bind)
    _up_schedule_fires_partition(bind)
    _up_tasks_fingerprint(bind)
    _up_misfire_alerts(bind)
    _up_outbox_backoff(bind)
    _up_tasks_last_failed_at(bind)
    _up_agent_offline_alerts(bind)
    _up_drop_project_retention_days(bind)


def downgrade() -> None:
    """Reverse the full 1.7 schema delta, 0017 -> 0005, back to v1_6_6."""
    bind = op.get_bind()
    _down_drop_project_retention_days(bind)
    _down_agent_offline_alerts(bind)
    _down_tasks_last_failed_at(bind)
    _down_outbox_backoff(bind)
    _down_misfire_alerts(bind)
    _down_tasks_fingerprint(bind)
    _down_schedule_fires_partition(bind)
    _down_automation_firing_outbox(bind)
    _down_automation_notify_coalesce(bind)
    _down_schedule_fire_triggered_by(bind)
    _down_drop_alert_events(bind)
    _down_automation_kill_switch(bind)
    _down_automation_rules(bind)
