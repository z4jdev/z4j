"""``PartitionCreatorWorker`` - pre-creates daily events partitions.

The ``events`` table is PARTITION BY RANGE (occurred_at) with one
child table per day (e.g. ``events_2026_04_12``). The initial
migration pre-creates 7 days of partitions. After that this worker
takes over: once per hour it ensures partitions exist for today
and the next ``_LOOKAHEAD_DAYS`` days. If a partition already
exists the CREATE is a no-op (guarded by IF NOT EXISTS).

Without this worker, every INSERT into ``events`` after the
pre-created range expires fails with "no partition of relation
events found for row" - a production-fatal condition that was
flagged by the B7 audit.

The worker also handles retention: partitions older than
``settings.event_retention_days`` are dropped. This is the only
code path that deletes event data.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import text

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.workers.partition_creator")

_LOOKAHEAD_DAYS: int = 7


class PartitionCreatorWorker:
    """Periodic events-partition manager.

    Creates future partitions and drops expired ones. Designed to
    run hourly - fast enough that a missed tick doesn't leave a gap,
    infrequent enough that the DDL overhead is negligible.
    """

    def __init__(
        self,
        *,
        db: "DatabaseManager",
        settings: "Settings",
    ) -> None:
        self._db = db
        self._retention_days = settings.event_retention_days

    async def tick(self) -> None:
        """One sweep: create future partitions + drop expired ones.

        Round-9 audit fixes (Apr 2026):

        - **R9-Stor-H1**: emit a WARN when the ``events_default``
          partition contains rows. The default partition is the
          catch-all for any ``occurred_at`` outside the daily
          windows; a row landing there means either the
          pre-creator missed a tick or an agent supplied a wildly
          out-of-range timestamp. Either way it requires operator
          attention, non-empty default partition silently blocks
          ``ATTACH PARTITION`` for that range later.
        - **R9-Stor-H2**: refuse to ``DROP`` a partition whose
          MAX(occurred_at) is past the cutoff. Pre-fix the worker
          parsed the partition NAME for the date and dropped on
          name alone, clock skew between worker and DB hosts, or
          a manually re-attached partition with rows from a
          different range, would silently destroy live data.
        - **R9-Stor-H3**: set ``lock_timeout='2s'`` before each
          ``CREATE PARTITION OF`` DDL. Pre-fix the DDL took
          ACCESS EXCLUSIVE on the parent for the duration; under
          heavy ingest a tick competing with INSERT statements
          would pile up waiters and the DDL would self-cancel
          mid-mutation against the catalog. Bounded
          ``lock_timeout`` lets the DDL fail fast and retry on
          the next tick, leaving the catalog clean.
        """
        today = date.today()

        async with self._db.session() as session:
            bind = await session.connection()
            dialect = bind.dialect.name

            if dialect != "postgresql":
                return

            # R9-Stor-H3: bound lock acquisition for THIS tick's
            # session. Postgres ``lock_timeout`` is per-session;
            # the setting clears at session close.
            await session.execute(text("SET LOCAL lock_timeout = '2s'"))

            # Create partitions for today + lookahead.
            created = 0
            for offset in range(_LOOKAHEAD_DAYS + 1):
                day = today + timedelta(days=offset)
                partition_name = f"events_{day.strftime('%Y_%m_%d')}"
                range_start = day.isoformat()
                range_end = (day + timedelta(days=1)).isoformat()

                try:
                    await session.execute(
                        text(
                            f"CREATE TABLE IF NOT EXISTS {partition_name} "
                            f"PARTITION OF events "
                            f"FOR VALUES FROM ('{range_start}') "
                            f"TO ('{range_end}')"
                        ),
                    )
                    created += 1
                except Exception as exc:  # noqa: BLE001
                    # Log + skip a single partition rather than
                    # poison the whole tick. Most common cause is
                    # the lock_timeout above firing under ingest
                    # contention; the next tick will retry.
                    logger.warning(
                        "z4j partition creator: ensure failed",
                        partition=partition_name,
                        error=str(exc)[:300],
                    )

            # R9-Stor-H1: alarm on non-empty default partition.
            try:
                default_count = (
                    await session.execute(
                        text(
                            "SELECT count(*) FROM events_default",
                        ),
                    )
                ).scalar()
                if default_count and default_count > 0:
                    logger.warning(
                        "z4j partition creator: events_default has rows; "
                        "investigate clock skew, missed pre-create ticks, "
                        "or agent-supplied out-of-range occurred_at "
                        "timestamps, a non-empty default blocks ATTACH "
                        "PARTITION for that range",
                        rows=int(default_count),
                    )
            except Exception:  # noqa: BLE001
                # Default partition may not exist on a brand-new
                # install where the migration hasn't run. Best-effort.
                logger.debug(
                    "z4j partition creator: default-partition probe failed",
                    exc_info=True,
                )

            # Drop expired partitions.
            dropped = 0
            if self._retention_days > 0:
                cutoff = today - timedelta(days=self._retention_days)
                # Find all partition children of `events` that are
                # older than the cutoff. We query pg_inherits to get
                # the list, then drop each one.
                result = await session.execute(
                    text(
                        "SELECT c.relname FROM pg_inherits i "
                        "JOIN pg_class c ON i.inhrelid = c.oid "
                        "JOIN pg_class p ON i.inhparent = p.oid "
                        "WHERE p.relname = 'events' "
                        "AND c.relname LIKE 'events_20%' "
                        "ORDER BY c.relname"
                    ),
                )
                for (partition_name,) in result.all():
                    # Parse date from partition name: events_YYYY_MM_DD
                    try:
                        parts = partition_name.replace("events_", "").split("_")
                        partition_date = date(
                            int(parts[0]), int(parts[1]), int(parts[2]),
                        )
                    except (ValueError, IndexError):
                        continue
                    if partition_date >= cutoff:
                        continue
                    # R9-Stor-H2: probe MAX(occurred_at) before drop.
                    # Refuse if any row in the partition is newer
                    # than the cutoff, name-based parsing alone
                    # can't catch clock skew or manually re-attached
                    # partitions covering a different range.
                    try:
                        max_occurred = (
                            await session.execute(
                                text(
                                    f"SELECT max(occurred_at) "
                                    f"FROM {partition_name}"
                                ),
                            )
                        ).scalar()
                    except Exception:  # noqa: BLE001
                        logger.warning(
                            "z4j partition creator: probe failed; "
                            "skipping drop",
                            partition=partition_name,
                            exc_info=True,
                        )
                        continue
                    if max_occurred is not None:
                        # Coerce both sides to date for the compare;
                        # cutoff is a date and max_occurred is a
                        # timestamptz. A row whose timestamp is on
                        # cutoff-day or later must NOT be dropped.
                        if max_occurred.date() >= cutoff:
                            logger.warning(
                                "z4j partition creator: refusing drop "
                                "of %s, max(occurred_at)=%s exceeds "
                                "cutoff %s; investigate name vs "
                                "content drift",
                                partition_name,
                                max_occurred.isoformat(),
                                cutoff.isoformat(),
                            )
                            continue
                    await session.execute(
                        text(f"DROP TABLE IF EXISTS {partition_name}"),
                    )
                    dropped += 1

            await session.commit()

        if created or dropped:
            logger.info(
                "z4j partition creator tick",
                partitions_ensured=created,
                partitions_dropped=dropped,
                retention_days=self._retention_days,
            )


__all__ = ["PartitionCreatorWorker"]
