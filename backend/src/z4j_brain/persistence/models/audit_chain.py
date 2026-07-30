"""Authenticated authority for the Boundary-F audit chain.

The singleton state is deliberately separate from ``audit_log``.  Retention
may remove every active row, but it must never erase the authenticated head or
the exact prefix boundary that the next append has to continue from.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import jsonb

AUDIT_CHAIN_SINGLETON_ID = "audit-chain"


class AuditChainPreparation(Base):
    """Authenticated bridge between the preparation and activation revisions."""

    __tablename__ = "audit_chain_preparation"

    singleton_id: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
        default=AUDIT_CHAIN_SINGLETON_ID,
    )
    format_version: Mapped[int] = mapped_column(Integer, nullable=False)
    preparation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        unique=True,
    )
    audit_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    preparation_revision: Mapped[str] = mapped_column(String(80), nullable=False)
    target_activation_revision: Mapped[str] = mapped_column(String(80), nullable=False)
    preparation_mac: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        CheckConstraint(
            f"singleton_id = '{AUDIT_CHAIN_SINGLETON_ID}'",
            name="singleton_id",
        ),
        CheckConstraint("format_version = 1", name="format_version"),
    )


class AuditChainState(Base):
    """The one authenticated state machine for the active audit generation."""

    __tablename__ = "audit_chain_state"

    singleton_id: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
        default=AUDIT_CHAIN_SINGLETON_ID,
    )
    format_version: Mapped[int] = mapped_column(Integer, nullable=False)
    generation: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    installation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    state_key_id: Mapped[str] = mapped_column(String(64), nullable=False)

    head_row_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_hmac_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    head_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )

    prune_row_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prune_hmac_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prune_occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    prune_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )

    active_row_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    active_key_counts: Mapped[dict[str, int]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    frozen_row_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    frozen_snapshot_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    retired_recovery_binding: Mapped[dict[str, Any] | None] = mapped_column(
        jsonb(),
        nullable=True,
    )
    state_mac: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(
            f"singleton_id = '{AUDIT_CHAIN_SINGLETON_ID}'",
            name="singleton_id",
        ),
        CheckConstraint("format_version = 1", name="format_version"),
        CheckConstraint("active_row_count >= 0", name="active_row_count_nonnegative"),
        CheckConstraint("frozen_row_count >= 0", name="frozen_row_count_nonnegative"),
    )


__all__ = [
    "AUDIT_CHAIN_SINGLETON_ID",
    "AuditChainPreparation",
    "AuditChainState",
]
