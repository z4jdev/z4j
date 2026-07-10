"""``ScheduleFiresPartitionWorker`` -- daily partition manager for
``schedule_fires`` (Postgres only).

After migration ``v1_7_schedule_fires_partition`` makes ``schedule_fires``
PARTITION BY RANGE (scheduled_for), this worker owns the going-forward
lifecycle:

- ensure a daily partition exists for today + the next ``_LOOKAHEAD_DAYS``
  (so an INSERT never fails with "no partition of relation found");
- drop daily partitions older than ``schedule_fires_retention_days`` --
  the fast, lock-cheap retention path (whole-partition DROP), guarded by a
  MAX(scheduled_for) probe so name-vs-content drift or clock skew cannot
  silently destroy live rows;
- alert (distinct metric) when the DEFAULT partition holds rows, because a
  non-empty DEFAULT permanently blocks creating an overlapping daily.

CRUCIAL: every CREATE and DROP runs in its OWN autonomous transaction
(a fresh session each). On Postgres a failed statement aborts the WHOLE
transaction it runs in ("current transaction is aborted, commands ignored
until end of transaction block"), so a single default-blocked CREATE or a
lock-timed-out DROP would otherwise poison the entire tick and roll back
every other CREATE/DROP. Per-DDL isolation means one bad day (or one
contended DROP) is logged + metriced and skipped without touching the rest.
Each session is pinned to UTC + a 2s lock_timeout.

Postgres only; a no-op on SQLite. Runs alongside the DELETE-based
``ScheduleFiresPruneWorker``, which on Postgres now only sweeps the DEFAULT
partition (the daily partitions are reclaimed here by DROP).
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import text

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.workers.schedule_fires_partition")

#: Two-week lookahead so a worker outage / leader gap shorter than this
#: cannot exhaust the pre-created window and route fires into DEFAULT.
_LOOKAHEAD_DAYS: int = 14


class ScheduleFiresPartitionWorker:
    """Periodic ``schedule_fires`` partition manager (Postgres only)."""

    def __init__(self, *, db: DatabaseManager, settings: Settings) -> None:
        self._db = db
        self._retention_days = settings.schedule_fires_retention_days

    async def tick(self) -> None:
        if not await self._is_postgres():
            return
        today = date.today()
        created = await self._ensure_future_partitions(today)
        await self._alarm_nonempty_default()
        dropped = await self._drop_expired(today) if self._retention_days > 0 else 0
        if created or dropped:
            logger.info(
                "z4j schedule_fires partition tick",
                partitions_ensured=created,
                partitions_dropped=dropped,
                retention_days=self._retention_days,
            )

    async def _is_postgres(self) -> bool:
        async with self._db.session() as session:
            bind = await session.connection()
            return bind.dialect.name == "postgresql"

    async def _ensure_future_partitions(self, today: date) -> int:
        created = 0
        for offset in range(_LOOKAHEAD_DAYS + 1):
            day = today + timedelta(days=offset)
            name = f"schedule_fires_{day.strftime('%Y_%m_%d')}"
            start = day.isoformat()
            end = (day + timedelta(days=1)).isoformat()
            try:
                # Own transaction: a failure here (default-blocked, lock
                # timeout) rolls back ONLY this CREATE, never the others.
                async with self._db.session() as session:
                    await self._prime(session)
                    await session.execute(
                        text(
                            f"CREATE TABLE IF NOT EXISTS {name} "
                            f"PARTITION OF schedule_fires "
                            f"FOR VALUES FROM ('{start}') TO ('{end}')",
                        ),
                    )
                    await session.commit()
                created += 1
            except Exception as exc:
                self._record_op_failure("create", name, exc)
        return created

    async def _drop_expired(self, today: date) -> int:
        cutoff = today - timedelta(days=self._retention_days)
        try:
            async with self._db.session() as session:
                result = await session.execute(
                    text(
                        "SELECT c.relname FROM pg_inherits i "
                        "JOIN pg_class c ON i.inhrelid = c.oid "
                        "JOIN pg_class p ON i.inhparent = p.oid "
                        "WHERE p.relname = 'schedule_fires' "
                        "AND c.relname LIKE 'schedule_fires_20%' "
                        "ORDER BY c.relname",
                    ),
                )
                names = [row[0] for row in result.all()]
        except Exception:
            logger.warning(
                "z4j schedule_fires partition: listing partitions failed",
                exc_info=True,
            )
            return 0

        dropped = 0
        for name in names:
            try:
                parts = name.replace("schedule_fires_", "").split("_")
                partition_date = date(int(parts[0]), int(parts[1]), int(parts[2]))
            except (ValueError, IndexError):
                continue
            if partition_date >= cutoff:
                continue
            # Own transaction per partition: probe MAX then DROP.
            try:
                async with self._db.session() as session:
                    await self._prime(session)
                    max_scheduled = (
                        await session.execute(
                            text(f"SELECT max(scheduled_for) FROM {name}"),  # noqa: S608  internal partition name, not user input
                        )
                    ).scalar()
                    if max_scheduled is not None and max_scheduled.date() >= cutoff:
                        logger.warning(
                            "z4j schedule_fires partition: refusing drop of %s, "
                            "max(scheduled_for)=%s exceeds cutoff %s",
                            name,
                            max_scheduled.isoformat(),
                            cutoff.isoformat(),
                        )
                        await session.commit()
                        continue
                    await session.execute(text(f"DROP TABLE IF EXISTS {name}"))
                    await session.commit()
                dropped += 1
            except Exception as exc:
                self._record_op_failure("drop", name, exc)
        return dropped

    async def _alarm_nonempty_default(self) -> None:
        try:
            async with self._db.session() as session:
                await self._prime(session)
                default_count = (
                    await session.execute(
                        text("SELECT count(*) FROM schedule_fires_default"),
                    )
                ).scalar()
                await session.commit()
            if default_count and default_count > 0:
                logger.warning(
                    "z4j schedule_fires partition: schedule_fires_default has "
                    "%d row(s); the DELETE prune worker handles them, but a "
                    "non-empty default blocks creating an overlapping daily "
                    "(retention-by-DROP cannot reclaim those days)",
                    int(default_count),
                )
        except Exception:
            logger.debug(
                "z4j schedule_fires partition: default-probe failed",
                exc_info=True,
            )

    @staticmethod
    async def _prime(session) -> None:
        # Bound lock acquisition + pin the session to UTC so the daily
        # boundary literals and the retention comparison agree with the
        # UTC ``scheduled_for`` timestamptz on a non-UTC server.
        await session.execute(text("SET LOCAL lock_timeout = '2s'"))
        await session.execute(text("SET LOCAL TIME ZONE 'UTC'"))

    @staticmethod
    def _record_op_failure(op: str, name: str, exc: Exception) -> None:
        msg = str(exc).lower()
        default_blocked = "default partition" in msg or (
            "default" in msg and "would be violated" in msg
        )
        reason = "default_blocked" if default_blocked else "error"
        if default_blocked:
            logger.error(
                "z4j schedule_fires partition: cannot create %s -- rows for "
                "that day are stuck in schedule_fires_default, so it can never "
                "be partitioned and retention-by-DROP is blocked for it until "
                "DEFAULT is cleared",
                name,
            )
        else:
            logger.warning(
                "z4j schedule_fires partition: %s failed for %s: %s",
                op,
                name,
                str(exc)[:300],
            )
        try:
            from z4j_brain.api.metrics import (
                z4j_schedule_fires_partition_failures_total,
            )

            z4j_schedule_fires_partition_failures_total.labels(
                op=op,
                reason=reason,
            ).inc()
        except Exception:
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("schedule_fires_partition", "failure_metric")


__all__ = ["ScheduleFiresPartitionWorker"]
