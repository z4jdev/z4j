"""z4j 1.7 partition ``schedule_fires`` by RANGE(scheduled_for) on Postgres.

Revision ID: v1_7_schedule_fires_partition
Revises: v1_7_automation_firing_outbox
Create Date: 2026-07-07

Turns the ``schedule_fires`` history table into a Postgres RANGE-partitioned
table keyed on ``scheduled_for``, so retention becomes a fast DROP PARTITION
(handled by the new schedule-fires partition worker) instead of a big DELETE
sweep, and range queries prune to the relevant days.

WHY scheduled_for AND NOT fired_at: Postgres requires the partition key to
be a member of the primary key and of every unique constraint. The table's
idempotency dedup collapses a scheduler retry (and the buffered -> delivered
upgrade) on ``fire_id``. ``fired_at`` is wall-clock and DIFFERS between the
buffered write and its delivered upgrade of the SAME fire, so a
``(fire_id, fired_at)`` unique would NOT collapse them and would duplicate
the row. ``scheduled_for`` is the tick boundary the ``fire_id`` is derived
from (``uuid5(schedule_id + scheduled_for)``), so it is STABLE per fire_id:
``(fire_id, scheduled_for)`` collapses exactly the rows ``(fire_id)`` did.
The repository's record() upsert is a try-insert / catch-IntegrityError /
select-and-upgrade pattern (not a SQL ON CONFLICT clause), so it works
unchanged against either unique.

POSTGRES ONLY. SQLite has no native partitioning, so on SQLite this migration
is a no-op and the table stays the plain ``(id)``-PK / ``(fire_id)``-unique
table the ORM model defines. The Postgres table therefore carries a
composite PK ``(id, scheduled_for)`` and unique ``(fire_id, scheduled_for)``
that the model does not declare; this is intentional (the partition
requirement) and invisible at runtime -- nothing reads schedule_fires by a
bare id and nothing foreign-keys to it.

MECHANICS (recreate-and-copy, the standard "make an existing table
partitioned" path since Postgres cannot ALTER a plain table into a
partitioned one): rename the old table aside, create the partitioned table
with a DEFAULT partition (so the copy can never fail with "no partition
found") plus a window of daily partitions around today, copy the rows with
an EXPLICIT column list (the column ORDER differs between a fresh install
and a 1.6->1.7 upgrade because triggered_by_user_id was ADD COLUMN'd by
0008), then drop the old table. Run during an upgrade maintenance window;
on a large table the copy holds locks for its duration. downgrade() reverses
it back to the plain table. The existing DELETE-based prune worker stays as
the retention fallback for any rows that land in the DEFAULT partition.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_schedule_fires_partition"
down_revision: str | Sequence[str] | None = "v1_7_automation_firing_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_automation_firing_outbox",
    "downgrade_to": "v1_7_automation_firing_outbox",
}

# Columns in a fixed, explicit order so INSERT ... SELECT is position-safe
# regardless of the source table's physical column order.
_COLUMNS = (
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
_COL_LIST = ", ".join(_COLUMNS)

# Days of daily partitions to pre-create on each side of today. 31 back
# covers the default 30-day retention so recent data lands in droppable
# daily partitions rather than DEFAULT; older data goes to DEFAULT and is
# handled by the DELETE-based prune fallback.
_PRECREATE_BACK = 31
_PRECREATE_FWD = 7


def _create_partitioned_table_sql() -> str:
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


def _create_plain_table_sql() -> str:
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


_INDEXES_SQL = (
    "CREATE INDEX ix_schedule_fires_schedule_recent ON schedule_fires (schedule_id, fired_at)",
    "CREATE INDEX ix_schedule_fires_circuit_breaker "
    "ON schedule_fires (schedule_id, status, fired_at)",
)

_PRECREATE_DAILIES_SQL = (
    "DO $$ "
    "DECLARE d DATE; "
    "BEGIN "
    f"FOR i IN -{_PRECREATE_BACK}..{_PRECREATE_FWD} LOOP "
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


def upgrade() -> None:
    """Convert schedule_fires into a scheduled_for RANGE-partitioned table."""
    bind = op.get_bind()
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
    op.execute(_create_partitioned_table_sql())
    for stmt in _INDEXES_SQL:
        op.execute(stmt)

    # 3. DEFAULT partition (the copy can never fail with "no partition
    #    found") + a window of daily partitions around today so recent rows
    #    land in droppable dailies rather than DEFAULT.
    op.execute(
        "CREATE TABLE IF NOT EXISTS schedule_fires_default PARTITION OF schedule_fires DEFAULT"
    )
    op.execute(_PRECREATE_DAILIES_SQL)

    # 4. Copy the data with an explicit column list (physical column order
    #    differs between a fresh install and a 1.6->1.7 upgrade).
    op.execute(
        f"INSERT INTO schedule_fires ({_COL_LIST}) SELECT {_COL_LIST} FROM schedule_fires_legacy",
    )

    # 5. Drop the old table.
    op.execute("DROP TABLE schedule_fires_legacy")


def downgrade() -> None:
    """Reverse the partitioning: back to the plain (id)-PK table."""
    bind = op.get_bind()
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

    op.execute(_create_plain_table_sql())
    for stmt in _INDEXES_SQL:
        op.execute(stmt)

    op.execute(
        f"INSERT INTO schedule_fires ({_COL_LIST}) SELECT {_COL_LIST} FROM schedule_fires_part",
    )

    # Dropping the partitioned parent drops all its partitions.
    op.execute("DROP TABLE schedule_fires_part")
