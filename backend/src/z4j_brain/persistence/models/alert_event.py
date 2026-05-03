"""``alert_events`` table - alert lifecycle tracking.

Tracks the lifecycle of notification deliveries:
fired -> acknowledged -> resolved (or snoozed/expired).

This is the table that makes the notification bell useful for
on-call operators. Without it, alerts fire and nobody knows
if someone is handling them.

Phase 1.1 feature. Table created in initial schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class AlertEvent(PKMixin, TimestampsMixin, Base):
    """A lifecycle event on a notification delivery.

    Events:
    - ``fired``: alert was delivered (auto-created by NotificationService)
    - ``acknowledged``: operator saw it and is handling it
    - ``resolved``: operator marked it fixed
    - ``snoozed``: operator silenced it until snooze_until
    - ``expired``: snooze period ended, alert re-surfaced
    """

    __tablename__ = "alert_events"

    delivery_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("notification_deliveries.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(20), nullable=False,
    )  # fired, acknowledged, resolved, snoozed, expired
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    snooze_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )


__all__ = ["AlertEvent"]
