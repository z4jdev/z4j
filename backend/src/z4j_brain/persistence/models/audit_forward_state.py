"""``audit_forward_state`` table - the audit forwarder's durable cursor.

One row per sink. The audit log is append-only and its rows carry a
strictly monotonic chain-order key ``(occurred_at, id)`` (see
``audit_chain.strictly_later_audit_key``), so "everything the receiver
has acknowledged" is one position on that key rather than a queue of
rows. The forwarder reads rows strictly after the position, POSTs them
in order, and moves the position only after a 2xx. A brain restart, a
receiver outage, or a leadership change therefore resumes from the last
acknowledged row instead of losing whatever was in memory.

The two cursor columns are the chain-order key, not an integer
sequence: the audit log has none, and adding one would not change the
ordering the verifier already relies on.

Bookkeeping columns carry what an operator needs to see from outside:
when delivery was last attempted, when it last succeeded, and how many
consecutive attempts have failed, which is also what the exponential
backoff is computed from so a restart does not reset it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base

#: The one sink this release forwards to. Keyed so a multi-sink release
#: can add rows without a schema change.
DEFAULT_AUDIT_FORWARD_SINK_ID: str = "default"


class AuditForwardState(Base):
    """Durable per-sink delivery cursor for the audit forwarder."""

    __tablename__ = "audit_forward_state"

    sink_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Chain-order key of the newest row the receiver acknowledged.
    #: Both NULL means nothing has been acknowledged yet.
    last_forwarded_occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_forwarded_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


__all__ = ["DEFAULT_AUDIT_FORWARD_SINK_ID", "AuditForwardState"]
