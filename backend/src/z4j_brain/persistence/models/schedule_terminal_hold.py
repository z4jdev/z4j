"""Self-contained terminal cadence holds for Boundary D."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import big_integer


class ScheduleTerminalHold(Base):
    """One unresolved or resolved generation-scoped cadence stop."""

    __tablename__ = "schedule_terminal_holds"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    fire_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    scheduled_for: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    command_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    observed_control_token: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    receipt_control_token: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    acceptance_revision: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    terminal_status: Mapped[str] = mapped_column(String(32), nullable=False)
    terminal_detail: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )
    state_write_nonce: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    resolution_disposition: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    resolution_source: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    work_may_have_executed: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )
    resolution_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    deletion_tombstone_revision: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "fire_id",
            "scheduled_for",
            "receipt_control_token",
            name="uq_schedule_terminal_hold_identity",
        ),
        Index(
            "uq_schedule_terminal_hold_unresolved_schedule",
            "schedule_id",
            unique=True,
            sqlite_where=text("resolved_at IS NULL"),
            postgresql_where=text("resolved_at IS NULL"),
        ),
        Index(
            "ix_schedule_terminal_holds_project",
            "project_id",
            "created_at",
        ),
        CheckConstraint(
            "(resolved_at IS NULL "
            "AND resolved_by IS NULL "
            "AND resolution_disposition IS NULL "
            "AND resolution_source IS NULL "
            "AND work_may_have_executed IS NULL "
            "AND resolution_control_token IS NULL "
            "AND deletion_tombstone_revision IS NULL) "
            "OR (resolved_at IS NOT NULL "
            "AND resolution_disposition = 'OPERATOR_SKIPPED' "
            "AND resolved_by IS NOT NULL "
            "AND resolution_source = 'OPERATOR' "
            "AND work_may_have_executed = TRUE "
            "AND resolution_control_token IS NOT NULL "
            "AND deletion_tombstone_revision IS NULL) "
            "OR (resolved_at IS NOT NULL "
            "AND resolution_disposition = 'SCHEDULE_DELETED' "
            "AND resolution_source = 'SCHEDULE_DELETE' "
            "AND resolution_control_token IS NULL "
            "AND deletion_tombstone_revision IS NOT NULL)",
            name="ck_schedule_terminal_hold_resolution",
        ),
    )


__all__ = ["ScheduleTerminalHold"]
