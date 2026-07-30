"""Self-contained resolutions for hold-less cadence occurrences."""

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


class ScheduleOccurrenceResolution(Base):
    """One immutable operator/deletion exit for cadence evidence without a hold.

    The row intentionally has no foreign keys.  It is historical authority that
    must survive command, schedule, project, and retained-fire cleanup.
    """

    __tablename__ = "schedule_occurrence_resolutions"

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
    command_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    source_evidence_kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    source_evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    authority_kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    observed_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    receipt_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    command_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    work_may_have_executed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    resolution_disposition: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    resolved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    resolution_source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    resolution_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    deletion_tombstone_revision: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    state_write_nonce: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
    )

    __table_args__ = (
        UniqueConstraint(
            "source_evidence_kind",
            "source_evidence_id",
            name="uq_schedule_occurrence_resolution_source",
        ),
        UniqueConstraint(
            "schedule_id",
            "fire_id",
            "scheduled_for",
            "authority_kind",
            "command_id",
            name="uq_schedule_occurrence_resolution_identity",
        ),
        CheckConstraint(
            "source_evidence_kind IN ('COMMAND', 'PENDING_FIRE', 'SCHEDULE_FIRE')",
            name="ck_schedule_occurrence_resolution_source_kind",
        ),
        CheckConstraint(
            "authority_kind IN ('LEGACY_NULL', 'TOKEN')",
            name="ck_schedule_occurrence_resolution_authority_kind",
        ),
        CheckConstraint(
            "resolution_disposition IN ('OPERATOR_SKIPPED', 'SCHEDULE_DELETED')",
            name="ck_schedule_occurrence_resolution_disposition",
        ),
        CheckConstraint(
            "(resolution_disposition = 'OPERATOR_SKIPPED' "
            "AND resolved_by IS NOT NULL "
            "AND resolution_source = 'OPERATOR' "
            "AND resolution_control_token IS NOT NULL "
            "AND deletion_tombstone_revision IS NULL) "
            "OR (resolution_disposition = 'SCHEDULE_DELETED' "
            "AND resolution_source = 'SCHEDULE_DELETE' "
            "AND resolution_control_token IS NULL "
            "AND deletion_tombstone_revision IS NOT NULL)",
            name="ck_schedule_occurrence_resolution_exit",
        ),
        CheckConstraint(
            "(authority_kind = 'LEGACY_NULL' "
            "AND receipt_control_token IS NULL) "
            "OR (authority_kind = 'TOKEN' "
            "AND receipt_control_token IS NOT NULL)",
            name="ck_schedule_occurrence_resolution_authority",
        ),
        Index(
            "ix_schedule_occurrence_resolution_schedule",
            "schedule_id",
            "resolved_at",
        ),
        Index(
            "ix_schedule_occurrence_resolution_fire",
            "fire_id",
            "scheduled_for",
        ),
        Index(
            "uq_schedule_occurrence_resolution_legacy_commandless",
            "schedule_id",
            "fire_id",
            "scheduled_for",
            "authority_kind",
            unique=True,
            sqlite_where=text(
                "command_id IS NULL AND authority_kind = 'LEGACY_NULL'",
            ),
            postgresql_where=text(
                "command_id IS NULL AND authority_kind = 'LEGACY_NULL'",
            ),
        ),
        Index(
            "uq_schedule_occurrence_resolution_token_commandless",
            "schedule_id",
            "fire_id",
            "scheduled_for",
            "receipt_control_token",
            unique=True,
            sqlite_where=text(
                "command_id IS NULL AND authority_kind = 'TOKEN'",
            ),
            postgresql_where=text(
                "command_id IS NULL AND authority_kind = 'TOKEN'",
            ),
        ),
    )


__all__ = ["ScheduleOccurrenceResolution"]
