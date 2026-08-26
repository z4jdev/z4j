"""Durable bulk-retry parent and sealed-plan outbox children."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin
from z4j_brain.persistence.types import jsonb


class BulkRetryControlState(StrEnum):
    """Durable coordinator authority for a parent."""

    RUNNING = "running"
    PAUSED = "paused"
    BLOCKED = "blocked"


class BulkRetryDeliveryState(StrEnum):
    """Irreversible delivery axis for one sealed child."""

    PENDING = "pending"
    DELIVERY_CLAIMED = "delivery_claimed"


class BulkRetryOutcome(StrEnum):
    """What the brain has observed about a claimed child."""

    UNOBSERVED = "unobserved"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class BulkRetryRequest(PKMixin, Base):
    """One idempotent request and its sealed-plan identity."""

    __tablename__ = "bulk_retry_requests"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    issued_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    canonicalizer_version: Mapped[int] = mapped_column(Integer, nullable=False)
    canonical_request: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    canonical_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_request: Mapped[dict[str, Any]] = mapped_column(jsonb(), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    control_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=BulkRetryControlState.RUNNING.value,
        server_default=BulkRetryControlState.RUNNING.value,
    )
    target_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    child_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_in_flight: Mapped[int] = mapped_column(Integer, nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sealed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    last_progress_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "idempotency_key",
            name="uq_bulk_retry_requests_project_key",
        ),
        Index(
            "ix_bulk_retry_requests_control_progress",
            "control_state",
            "last_progress_at",
            "created_at",
        ),
        Index("ix_bulk_retry_requests_deadline", "deadline_at"),
    )


class BulkRetryRequestChild(PKMixin, Base):
    """One child payload in a durable outbox, written once by convention.

    Nothing in the application revises a child after the parent request is
    expanded. That is a convention this code keeps, not a database guard:
    unlike the schedule-control and audit tables, no trigger refuses UPDATE
    or DELETE here.
    """

    __tablename__ = "bulk_retry_request_children"

    parent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("bulk_retry_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    target_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(jsonb(), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_size: Mapped[int] = mapped_column(Integer, nullable=False)
    required_contract_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    delivery_state: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=BulkRetryDeliveryState.PENDING.value,
        server_default=BulkRetryDeliveryState.PENDING.value,
    )
    outcome: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=BulkRetryOutcome.UNOBSERVED.value,
        server_default=BulkRetryOutcome.UNOBSERVED.value,
    )
    claimed_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    claimed_generation: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    claim_deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "parent_id",
            "ordinal",
            name="uq_bulk_retry_request_children_parent_ordinal",
        ),
        Index(
            "ix_bulk_retry_children_parent_delivery",
            "parent_id",
            "delivery_state",
            "ordinal",
        ),
        Index(
            "ix_bulk_retry_children_project_delivery",
            "project_id",
            "delivery_state",
            "engine",
        ),
        Index(
            "ix_bulk_retry_children_claim_deadline",
            "claim_deadline_at",
        ),
    )


__all__ = [
    "BulkRetryControlState",
    "BulkRetryDeliveryState",
    "BulkRetryOutcome",
    "BulkRetryRequest",
    "BulkRetryRequestChild",
]
