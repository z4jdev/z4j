"""Per-cert token-bucket rate limiter for ``SchedulerService.FireSchedule``.

Audit fix (Apr 2026 security audit follow-up). mTLS bounds *who*
can call the gRPC surface; this bounds *how much* a single cert can
fire per unit time. The defended-against scenario is a scheduler
agent compromised at the cert layer (or simply a buggy scheduler
in a tight loop) DoS-ing the worker fleet by hammering FireSchedule.

State lives in the ``scheduler_rate_buckets`` table - one row per
cert CN. The ``consume()`` operation:

1. Opens a write transaction. SQLite uses ``BEGIN IMMEDIATE`` so
   competing writers serialize before reading bucket state.
2. Executes an ``INSERT ... ON CONFLICT DO NOTHING`` seed, then locks
   the resulting row with ``SELECT ... FOR UPDATE`` on Postgres.
3. Lazily refills from the shared database clock based on elapsed time
   since ``last_refill``.
4. If at least ``tokens_to_consume`` are available, deducts them and
   commits → returns ``True``
5. Otherwise commits the refill (so the next call sees up-to-date
   ``last_refill``) → returns ``False``

Postgres provides row locks; SQLite ignores ``FOR UPDATE`` and relies
on the earlier database write lock. The conflict-tolerant seed closes
the concurrent first-observation race on both dialects. Cross-replica
brain deployments share the table, so the limit is global per-cert
across the fleet.

The limiter is a no-op when
``Settings.scheduler_grpc_fire_rate_limit_enabled`` is False - lets
operators disable in-brain rate limiting when an upstream proxy
(Envoy, NGINX) already covers the surface.
"""

from __future__ import annotations

import contextlib
import math
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.sql.dml import Insert

from z4j_brain.persistence.models import SchedulerRateBucket

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


def _validated_token_amount(tokens: float) -> float:
    """Return ``tokens`` as a float, rejecting unsafe bucket arithmetic."""

    if isinstance(tokens, bool) or not math.isfinite(tokens) or tokens <= 0:
        raise ValueError("tokens must be a finite positive number")
    return float(tokens)


def _seed_bucket_statement(
    *,
    dialect_name: str,
    cert_cn: str,
    capacity: float,
    refill_rate: float,
    now: datetime,
) -> Insert:
    """Build a conflict-tolerant first-observation seed statement."""

    values = {
        "cert_cn": cert_cn,
        "tokens": capacity,
        "last_refill": now,
        "capacity": capacity,
        "refill_per_second": refill_rate,
    }
    if dialect_name == "postgresql":
        return (
            postgresql_insert(SchedulerRateBucket)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulerRateBucket.cert_cn])
        )
    if dialect_name == "sqlite":
        return (
            sqlite_insert(SchedulerRateBucket)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulerRateBucket.cert_cn])
        )
    raise RuntimeError(
        "scheduler rate limiter supports only PostgreSQL and SQLite",
    )


async def _database_now(
    *,
    session: AsyncSession,
    dialect_name: str,
) -> datetime:
    """Read a post-wait clock from the database serving the bucket row."""

    if dialect_name == "postgresql":
        # ``CURRENT_TIMESTAMP`` is fixed at transaction start on Postgres and
        # can therefore predate a long INSERT/row-lock wait.  clock_timestamp
        # is the server's actual statement-time clock.
        expression = func.clock_timestamp(type_=DateTime(timezone=True))
    elif dialect_name == "sqlite":
        # SQLite has no transaction-start timestamp distinction.  Reading its
        # statement clock after BEGIN IMMEDIATE keeps the time observation on
        # the serialized side of the writer gate.
        expression = func.current_timestamp(type_=DateTime(timezone=True))
    else:
        raise RuntimeError(
            "scheduler rate limiter supports only PostgreSQL and SQLite",
        )
    observed = await session.scalar(select(expression))
    if observed is None:
        raise RuntimeError("scheduler rate limiter database clock was unavailable")
    if not isinstance(observed, datetime):
        raise TypeError("scheduler rate limiter database clock returned a non-datetime value")
    if observed.tzinfo is None:
        return observed.replace(tzinfo=UTC)
    return observed.astimezone(UTC)


class SchedulerRateLimiter:
    """Token-bucket rate limiter for FireSchedule, keyed by cert CN."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        self._db = db
        self._settings = settings

    async def consume(
        self,
        *,
        cert_cn: str,
        tokens: float = 1.0,
    ) -> bool:
        """Try to consume ``tokens`` from ``cert_cn``'s bucket.

        Returns ``True`` if the request is within budget (tokens
        available after refill), ``False`` if it exceeds the cap.

        No-op (always allows) when
        ``scheduler_grpc_fire_rate_limit_enabled`` is False.

        Empty / falsy ``cert_cn`` is allowed - covers the case where
        the allow-list interceptor has been disabled and we can't
        identify the peer. Operators running without mTLS get no
        rate-limit protection (consistent with the wider "trust the
        CA" deployment model).
        """
        tokens = _validated_token_amount(tokens)
        if not self._settings.scheduler_grpc_fire_rate_limit_enabled:
            return True
        if not cert_cn:
            return True

        capacity = float(self._settings.scheduler_grpc_fire_rate_capacity)
        refill_rate = float(self._settings.scheduler_grpc_fire_rate_per_second)
        async with self._db.session(write=True) as session:
            dialect_name = self._db.engine.dialect.name
            # Use the shared database clock rather than a replica's process
            # clock.  This makes cross-replica skew unable to mint an early
            # refill.  The second observation below is still required because
            # a conflicting seed or row lock can wait after this statement.
            seed_at = await _database_now(
                session=session,
                dialect_name=dialect_name,
            )
            # Seed at full capacity and consume through the common locked-row
            # path below. ON CONFLICT is important: on Postgres, two replicas
            # can both observe a new CN before either INSERT commits. The
            # losing INSERT waits, becomes a no-op, and then locks/consumes
            # the winner's row instead of surfacing a uniqueness error.
            await session.execute(
                _seed_bucket_statement(
                    dialect_name=dialect_name,
                    cert_cn=cert_cn,
                    capacity=capacity,
                    refill_rate=refill_rate,
                    now=seed_at,
                ),
            )
            stmt = (
                select(SchedulerRateBucket)
                .where(SchedulerRateBucket.cert_cn == cert_cn)
                .with_for_update()
            )
            result = await session.execute(stmt)
            bucket = result.scalar_one()

            # Observe the database clock again only after the authoritative
            # row is locked.  Clamp the write stamp below as defense in depth
            # for database clock correction or a manually future-dated row:
            # the durable refill frontier must never move backwards.  A clock
            # behind that frontier earns no refill until it catches up.
            observed_at = await _database_now(
                session=session,
                dialect_name=dialect_name,
            )

            # Lazy refill. The bucket carries its OWN capacity +
            # refill_rate (loaded on first observation) so a future
            # per-cert override survives without reading settings on
            # every call. Settings changes affect newly observed CNs;
            # existing rows retain their stored values until an operator
            # deliberately updates or deletes them in the database. There
            # is currently no scheduler-rate-bucket reset CLI.
            #
            # SQLite strips the timezone tag from DateTime(timezone=True)
            # values on round-trip; Postgres preserves it. Coerce to
            # tz-aware UTC if naive so the subtraction works on both
            # backends.
            last_refill = bucket.last_refill
            if last_refill.tzinfo is None:
                last_refill = last_refill.replace(tzinfo=UTC)
            refill_at = max(observed_at, last_refill)
            elapsed_seconds = (refill_at - last_refill).total_seconds()
            refilled = min(
                bucket.capacity,
                bucket.tokens + elapsed_seconds * bucket.refill_per_second,
            )

            if refilled < tokens:
                # Out of budget. Persist the refill so the NEXT call
                # sees an accurate last_refill timestamp without
                # double-counting elapsed time.
                bucket.tokens = refilled
                bucket.last_refill = refill_at
                await session.commit()
                return False

            bucket.tokens = refilled - tokens
            bucket.last_refill = refill_at
            await session.commit()
            return True

    async def refund(
        self,
        *,
        cert_cn: str,
        tokens: float = 1.0,
        session: AsyncSession | None = None,
    ) -> None:
        """Add ``tokens`` back to ``cert_cn``'s bucket (capped at capacity).

        The FireSchedule path consumes a token BEFORE validating
        the schedule (row lock, is_enabled check, agent-pick).
        When the post-consume validation fails the schedule is
        NOT actually fired, but the bucket charge persists. At
        enterprise scale (1000s of schedules being mass-disabled
        by an operator) the chatty scheduler can transiently
        exhaust its bucket and 429 legitimate fires. ``refund``
        returns the unspent token to the bucket so accounting
        stays accurate.

        Invalid token amounts are caller errors and raise ``ValueError``.
        Persistence failures are best-effort and are NOT propagated. The
        fire already failed for an upstream reason; double-failure because
        of bucket bookkeeping would be operationally worse than slightly
        conservative limiting.

        ``FireSchedule`` refusals already hold a write transaction while they
        validate the schedule.  Those callers must pass that ``session`` so
        SQLite reuses its existing ``BEGIN IMMEDIATE`` writer reservation
        instead of deadlocking on a second connection.  On success this method
        commits the caller-owned transaction together with the refund.  The
        supported caller paths are terminal, read-only refusals, so there is no
        unrelated mutation to commit.  Other callers omit ``session`` and get
        an isolated best-effort transaction as before.
        """
        tokens = _validated_token_amount(tokens)
        if not self._settings.scheduler_grpc_fire_rate_limit_enabled:
            return
        if not cert_cn:
            return
        try:
            if session is not None:
                await self._refund_in_session(
                    session=session,
                    cert_cn=cert_cn,
                    tokens=tokens,
                )
                await session.commit()
                return
            async with self._db.session(write=True) as owned_session:
                await self._refund_in_session(
                    session=owned_session,
                    cert_cn=cert_cn,
                    tokens=tokens,
                )
                await owned_session.commit()
        except Exception:
            if session is not None:
                # The exception is intentionally non-fatal to the refusal
                # response, but leave its caller-owned session usable and
                # release any lock it acquired before the failure.
                with contextlib.suppress(Exception):
                    await session.rollback()
            import logging

            logging.getLogger(__name__).warning(
                "SchedulerRateLimiter.refund failed for cert_cn=%r (non-fatal)",
                cert_cn,
                exc_info=True,
            )

    @staticmethod
    async def _refund_in_session(
        *,
        session: AsyncSession,
        cert_cn: str,
        tokens: float,
    ) -> None:
        """Apply one capped refund in an existing write transaction."""

        stmt = (
            select(SchedulerRateBucket)
            .where(SchedulerRateBucket.cert_cn == cert_cn)
            .with_for_update()
        )
        result = await session.execute(stmt)
        bucket = result.scalar_one_or_none()
        if bucket is None:
            # Refund without prior consume - nothing to do.
            return
        bucket.tokens = min(
            bucket.capacity,
            bucket.tokens + tokens,
        )


__all__ = ["SchedulerRateLimiter"]
