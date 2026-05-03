"""``scheduler_rate_buckets`` table - per-cert rate limit state.

Audit fix (Apr 2026 security audit) for the FireSchedule DoS surface.
A scheduler agent compromised at the cert layer (or simply a buggy
scheduler in a tight loop) can call ``FireSchedule`` faster than the
worker fleet can drain. mTLS bounds *who* can call the RPC; this
table backs the token-bucket that bounds *how much*.

One row per cert CN. The application path
(:class:`SchedulerRateLimiter`) implements lazy-refill: on each
consume, it computes the elapsed time since ``last_refill`` and adds
``elapsed * refill_per_second`` tokens (capped at ``capacity``).

Schema rationale:

- ``cert_cn`` is the primary key. Per-CN buckets isolate one
  misbehaving scheduler from the rest of the fleet.
- ``capacity`` + ``refill_per_second`` live on the row (not in
  settings) so a future operator UI can override per-cert limits
  without a brain restart. v1 always writes the settings defaults
  on first observation.
- ``tokens`` is ``DOUBLE PRECISION`` because lazy refill needs
  fractional accumulation (10 tokens/sec × 0.1 second = 1.0 token).

Backwards compatible: brains without z4j-scheduler attached never
write rows to this table.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base


class SchedulerRateBucket(Base):
    """One token bucket per scheduler cert CN.

    Attributes:
        cert_cn: Peer cert CN. Primary key - one row per cert.
        tokens: Current available tokens. Float so the lazy-refill
            arithmetic doesn't accumulate rounding error.
        last_refill: Wall-clock when ``tokens`` was last computed.
            On consume, the service refills based on the delta and
            updates this stamp atomically.
        capacity: Burst size (tokens). Loaded from
            ``Settings.scheduler_grpc_fire_rate_capacity`` on first
            observation; persisted so per-cert overrides become
            possible without changing global settings.
        refill_per_second: Sustained rate (tokens/sec). Same loading
            rule as ``capacity``.
        updated_at: Bookkeeping. Bumped by SQLAlchemy on every UPDATE
            so operators can see the most recent activity per cert
            via the dashboard / a SQL probe.
    """

    __tablename__ = "scheduler_rate_buckets"

    cert_cn: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
    )
    tokens: Mapped[float] = mapped_column(
        Float, nullable=False,
    )
    last_refill: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    capacity: Mapped[float] = mapped_column(
        Float, nullable=False,
    )
    refill_per_second: Mapped[float] = mapped_column(
        Float, nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


__all__ = ["SchedulerRateBucket"]
