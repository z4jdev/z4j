"""Per-cert token-bucket rate limiter for ``SchedulerService.FireSchedule``.

Audit fix (Apr 2026 security audit follow-up). mTLS bounds *who*
can call the gRPC surface; this bounds *how much* a single cert can
fire per unit time. The defended-against scenario is a scheduler
agent compromised at the cert layer (or simply a buggy scheduler
in a tight loop) DoS-ing the worker fleet by hammering FireSchedule.

State lives in the ``scheduler_rate_buckets`` table - one row per
cert CN. The ``consume()`` operation:

1. Opens a transaction
2. ``SELECT ... FOR UPDATE`` on the bucket row (skipped on first
   observation - see the INSERT path)
3. Lazily refills tokens based on elapsed time since ``last_refill``
4. If at least ``tokens_to_consume`` are available, deducts them and
   commits → returns ``True``
5. Otherwise commits the refill (so the next call sees up-to-date
   ``last_refill``) → returns ``False``

Postgres + SQLite both support the ``SELECT ... FOR UPDATE`` pattern
(SQLite serializes writes, so the lock is implicit but the same
code path works). Cross-replica brain deployments share the table,
so the limit is global per-cert across the fleet.

The limiter is a no-op when
``Settings.scheduler_grpc_fire_rate_limit_enabled`` is False - lets
operators disable in-brain rate limiting when an upstream proxy
(Envoy, NGINX) already covers the surface.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from z4j_brain.persistence.models import SchedulerRateBucket

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


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
        if not self._settings.scheduler_grpc_fire_rate_limit_enabled:
            return True
        if not cert_cn:
            return True

        capacity = float(self._settings.scheduler_grpc_fire_rate_capacity)
        refill_rate = float(self._settings.scheduler_grpc_fire_rate_per_second)
        now = datetime.now(UTC)

        async with self._db.session() as session:
            stmt = (
                select(SchedulerRateBucket)
                .where(SchedulerRateBucket.cert_cn == cert_cn)
                .with_for_update()
            )
            result = await session.execute(stmt)
            bucket = result.scalar_one_or_none()

            if bucket is None:
                # First observation of this cert. Seed at full
                # capacity so a freshly-deployed scheduler doesn't
                # see spurious 429s on its first burst, then deduct.
                # SQLAlchemy ORM .add() handles INSERT inside the
                # same transaction.
                if tokens > capacity:
                    # Asking for more than the bucket can ever hold;
                    # deny rather than seed at negative.
                    await session.commit()
                    return False
                bucket = SchedulerRateBucket(
                    cert_cn=cert_cn,
                    tokens=capacity - tokens,
                    last_refill=now,
                    capacity=capacity,
                    refill_per_second=refill_rate,
                )
                session.add(bucket)
                await session.commit()
                return True

            # Lazy refill. The bucket carries its OWN capacity +
            # refill_rate (loaded on first observation) so a future
            # per-cert override survives without reading settings on
            # every call. Settings changes still reach existing
            # buckets via the operator running an explicit
            # "reset bucket" CLI; v1 just uses what's on the row.
            #
            # SQLite strips the timezone tag from DateTime(timezone=True)
            # values on round-trip; Postgres preserves it. Coerce to
            # tz-aware UTC if naive so the subtraction works on both
            # backends.
            last_refill = bucket.last_refill
            if last_refill.tzinfo is None:
                last_refill = last_refill.replace(tzinfo=UTC)
            elapsed_seconds = max(
                0.0, (now - last_refill).total_seconds(),
            )
            refilled = min(
                bucket.capacity,
                bucket.tokens + elapsed_seconds * bucket.refill_per_second,
            )

            if refilled < tokens:
                # Out of budget. Persist the refill so the NEXT call
                # sees an accurate last_refill timestamp without
                # double-counting elapsed time.
                bucket.tokens = refilled
                bucket.last_refill = now
                await session.commit()
                return False

            bucket.tokens = refilled - tokens
            bucket.last_refill = now
            await session.commit()
            return True

    async def refund(
        self,
        *,
        cert_cn: str,
        tokens: float = 1.0,
    ) -> None:
        """Add ``tokens`` back to ``cert_cn``'s bucket (capped at capacity).

        Round-4 audit fix (Apr 2026): the FireSchedule path
        consumes a token BEFORE validating the schedule (row lock,
        is_enabled check, agent-pick). When the post-consume
        validation fails the schedule is NOT actually fired, but
        the bucket charge persists. At enterprise scale (1000s of
        schedules being mass-disabled by an operator) the chatty
        scheduler can transiently exhaust its bucket and 429
        legitimate fires. ``refund`` returns the unspent token to
        the bucket so accounting stays accurate.

        Best-effort: refund failures are NOT propagated. The fire
        already failed for an upstream reason; double-failure
        because of bucket bookkeeping would be operationally worse
        than slightly conservative limiting.
        """
        if not self._settings.scheduler_grpc_fire_rate_limit_enabled:
            return
        if not cert_cn or tokens <= 0:
            return
        try:
            async with self._db.session() as session:
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
                    bucket.capacity, bucket.tokens + tokens,
                )
                await session.commit()
        except Exception:  # noqa: BLE001
            import logging  # noqa: PLC0415

            logging.getLogger(__name__).warning(
                "SchedulerRateLimiter.refund failed for cert_cn=%r "
                "(non-fatal)", cert_cn, exc_info=True,
            )


__all__ = ["SchedulerRateLimiter"]
