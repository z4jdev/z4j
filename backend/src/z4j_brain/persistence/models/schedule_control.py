"""Boundary-D transactional revision state and immutable visibility log."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import big_integer, jsonb

SCHEDULE_REVISION_SINGLETON_ID = "schedule-revision"
SCHEDULE_CHANGE_PROTOCOL_VERSION = 1


class ScheduleRevisionState(Base):
    """One transactional global schedule-revision allocator."""

    __tablename__ = "schedule_revision_state"

    singleton_id: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
    )
    current_revision: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    change_log_pruned_through: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    # These fields are nullable only in direct Base.metadata test schemas.
    # Boundary-D activation backfills them and installs NOT NULL constraints.
    guard_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    activation_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    activation_manifest_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    activation_audit_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            f"singleton_id = '{SCHEDULE_REVISION_SINGLETON_ID}'",
            name="ck_schedule_revision_state_singleton",
        ),
        CheckConstraint(
            "current_revision >= 0",
            name="ck_schedule_revision_state_current_nonnegative",
        ),
        CheckConstraint(
            "change_log_pruned_through >= 0 AND change_log_pruned_through <= current_revision",
            name="ck_schedule_revision_state_pruned_boundary",
        ),
        CheckConstraint(
            "(guard_version IS NULL "
            "AND activation_id IS NULL "
            "AND activation_manifest_digest IS NULL "
            "AND activation_audit_id IS NULL) "
            "OR (guard_version = 1 "
            "AND activation_id IS NOT NULL "
            "AND activation_manifest_digest IS NOT NULL "
            "AND activation_audit_id IS NOT NULL)",
            name="ck_schedule_revision_state_activation",
        ),
    )


class ScheduleChangeLog(Base):
    """One immutable upsert, delete tombstone, or filtered global gap."""

    __tablename__ = "schedule_change_log"

    revision: Mapped[int] = mapped_column(
        big_integer(),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    schedule_owner: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        index=True,
    )
    change_kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    protocol_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        jsonb(),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "revision > 0",
            name="ck_schedule_change_log_revision_positive",
        ),
        CheckConstraint(
            "change_kind IN ('upsert', 'delete', 'gap')",
            name="ck_schedule_change_log_kind",
        ),
        CheckConstraint(
            "(change_kind = 'upsert' AND snapshot IS NOT NULL) "
            "OR (change_kind IN ('delete', 'gap') AND snapshot IS NULL)",
            name="ck_schedule_change_log_payload",
        ),
        CheckConstraint(
            f"protocol_version = {SCHEDULE_CHANGE_PROTOCOL_VERSION}",
            name="ck_schedule_change_log_protocol",
        ),
    )


__all__ = [
    "SCHEDULE_CHANGE_PROTOCOL_VERSION",
    "SCHEDULE_REVISION_SINGLETON_ID",
    "ScheduleChangeLog",
    "ScheduleRevisionState",
]
