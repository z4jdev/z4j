"""``agent_offline_alerts`` -- durable cross-replica offline-alert dedup ledger."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class AgentOfflineAlert(PKMixin, TimestampsMixin, Base):
    """One offline episode already alerted for an agent.

    The :class:`AgentHealthWorker` runs on every brain replica, each with
    its own in-memory state, so a purely in-memory dedup would alert a
    persistent offline episode once per replica (duplicate audit rows /
    notifications / rule firings under HA) and re-alert after every brain
    restart. This table is the shared, durable claim, mirroring
    :class:`MisfireAlert`: a replica INSERTs an ``(agent_id, anchor_at)``
    row and alerts only if the insert won the UNIQUE, so an offline
    episode is alerted exactly once fleet-wide.

    ``anchor_at`` is the episode key -- the agent's ``last_seen_at``,
    which is frozen while the agent is down (only live heartbeats advance
    it) and moves to a fresh value once the agent recovers, so the next
    outage is a new episode. Agents that have never connected
    (``last_seen_at IS NULL``) are never alerted on, so the column is
    NON-nullable and the UNIQUE actually dedups.
    """

    __tablename__ = "agent_offline_alerts"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    anchor_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "anchor_at",
            name="uq_agent_offline_alerts_agent_anchor",
        ),
        # Retention prune sweeps by age.
        Index("ix_agent_offline_alerts_created", "created_at"),
    )


__all__ = ["AgentOfflineAlert"]
