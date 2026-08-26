"""Boundary-D causal authority for external scheduler adapters.

The tables in this module deliberately do not cascade from projects,
schedules, agents, or sessions.  Stream epochs and accepted projections are
the durable evidence that makes a delayed adapter event distinguishable from
current truth; deleting the projected schedule must not delete that evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import big_integer, jsonb

SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID = "schedule-external-epoch"
SCHEDULE_EXTERNAL_PROTOCOL_VERSION = 1

EXTERNAL_EPOCH_PHASES = (
    "ACTIVATING",
    "ACTIVE",
    "DRAINING",
    "SEALED",
    "RETIRED",
    "AMBIGUOUS",
    "RESTORE_REACTIVATION_REQUIRED",
)
EXTERNAL_CONTROL_STATUSES = (
    "PENDING",
    "CLAIMED",
    "APPLIED",
    "FAILED",
    "AMBIGUOUS",
    "CANCELLED",
)


class ScheduleExternalEpochAllocator(Base):
    """Installation-wide, never-reset external epoch allocator."""

    __tablename__ = "schedule_external_epoch_allocator"

    singleton_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    current_epoch_number: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    guard_version: Mapped[int] = mapped_column(Integer, nullable=False)
    activation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    activation_manifest_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    activation_audit_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            f"singleton_id = '{SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID}'",
            name="ck_schedule_external_epoch_allocator_singleton",
        ),
        CheckConstraint(
            "current_epoch_number >= 0",
            name="ck_schedule_external_epoch_allocator_nonnegative",
        ),
        CheckConstraint(
            "guard_version = 1",
            name="ck_schedule_external_epoch_allocator_guard",
        ),
    )


class ScheduleExternalStream(Base):
    """Non-cascading identity for one external owner/source scope."""

    __tablename__ = "schedule_external_streams"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    owner: Mapped[str] = mapped_column(String(40), nullable=False)
    source_scope: Mapped[str] = mapped_column(String(500), nullable=False)
    source_scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    current_epoch_uuid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    current_epoch_number: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    phase: Mapped[str] = mapped_column(String(40), nullable=False)
    authorized_adapter_instance_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    executor_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    executor_registry_owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    executor_session_generation: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    executor_worker_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    accepted_sequence: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
        default=0,
        server_default="0",
    )
    sealed_sequence: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    last_snapshot_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    last_projection_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    activation_requirement: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
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

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "owner",
            "source_scope",
            name="uq_schedule_external_stream_scope",
        ),
        UniqueConstraint(
            "id",
            "current_epoch_uuid",
            name="uq_schedule_external_stream_current_epoch",
        ),
        CheckConstraint(
            "owner <> 'z4j-scheduler'",
            name="ck_schedule_external_stream_owner",
        ),
        CheckConstraint(
            "current_epoch_number > 0",
            name="ck_schedule_external_stream_epoch_positive",
        ),
        CheckConstraint(
            "accepted_sequence >= 0",
            name="ck_schedule_external_stream_sequence_nonnegative",
        ),
        CheckConstraint(
            "sealed_sequence IS NULL OR sealed_sequence >= accepted_sequence",
            name="ck_schedule_external_stream_sealed_sequence",
        ),
        CheckConstraint(
            "phase IN (" + ", ".join(f"'{value}'" for value in EXTERNAL_EPOCH_PHASES) + ")",
            name="ck_schedule_external_stream_phase",
        ),
        CheckConstraint(
            "("
            "authorized_adapter_instance_id IS NULL "
            "AND executor_agent_id IS NULL "
            "AND executor_registry_owner_id IS NULL "
            "AND executor_session_generation IS NULL"
            ") OR ("
            "authorized_adapter_instance_id IS NOT NULL "
            "AND executor_agent_id IS NOT NULL "
            "AND executor_registry_owner_id IS NOT NULL "
            "AND executor_session_generation IS NOT NULL"
            ")",
            name="ck_schedule_external_stream_executor_authority",
        ),
        Index(
            "ix_schedule_external_stream_owner_scope",
            "project_id",
            "owner",
            "source_scope_digest",
        ),
    )


class ScheduleExternalStreamEpoch(Base):
    """Retained history for one Brain-issued external stream epoch."""

    __tablename__ = "schedule_external_stream_epochs"

    epoch_uuid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    epoch_number: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
        unique=True,
    )
    stream_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    phase: Mapped[str] = mapped_column(String(40), nullable=False)
    authorized_adapter_instance_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    executor_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    executor_registry_owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    executor_session_generation: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    executor_worker_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    accepted_sequence: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
        default=0,
        server_default="0",
    )
    sealed_sequence: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    last_snapshot_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    last_projection_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    activation_requirement: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    sealed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "epoch_number",
            name="uq_schedule_external_stream_epoch_number",
        ),
        CheckConstraint(
            "epoch_number > 0",
            name="ck_schedule_external_epoch_positive",
        ),
        CheckConstraint(
            "accepted_sequence >= 0",
            name="ck_schedule_external_epoch_sequence_nonnegative",
        ),
        CheckConstraint(
            "sealed_sequence IS NULL OR sealed_sequence >= accepted_sequence",
            name="ck_schedule_external_epoch_sealed_sequence",
        ),
        CheckConstraint(
            "phase IN (" + ", ".join(f"'{value}'" for value in EXTERNAL_EPOCH_PHASES) + ")",
            name="ck_schedule_external_epoch_phase",
        ),
        CheckConstraint(
            "("
            "authorized_adapter_instance_id IS NULL "
            "AND executor_agent_id IS NULL "
            "AND executor_registry_owner_id IS NULL "
            "AND executor_session_generation IS NULL"
            ") OR ("
            "authorized_adapter_instance_id IS NOT NULL "
            "AND executor_agent_id IS NOT NULL "
            "AND executor_registry_owner_id IS NOT NULL "
            "AND executor_session_generation IS NOT NULL"
            ")",
            name="ck_schedule_external_epoch_executor_authority",
        ),
    )


class ScheduleExternalProjection(Base):
    """Exact-replay ledger for accepted external projections.

    A trigger refuses UPDATE and DELETE, so no application path revises a
    row once accepted. Like every guard in this schema that holds against
    code rather than against credentials, a role writing the table directly
    is outside its reach.
    """

    __tablename__ = "schedule_external_projections"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    stream_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    epoch_uuid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    epoch_number: Mapped[int] = mapped_column(big_integer(), nullable=False)
    sequence: Mapped[int] = mapped_column(big_integer(), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_keys: Mapped[list[str]] = mapped_column(jsonb(), nullable=False)
    mutation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    operation_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "epoch_uuid",
            "sequence",
            name="uq_schedule_external_projection_sequence",
        ),
        CheckConstraint(
            "epoch_number > 0 AND sequence > 0",
            name="ck_schedule_external_projection_positive",
        ),
    )


class ScheduleExternalSnapshotFrame(Base):
    """Durable staging for one framed stable snapshot.

    Write-once through the application: a trigger refuses UPDATE and
    DELETE, which is what stops a partially reframed snapshot, not what
    stops a role holding direct write access to the table.
    """

    __tablename__ = "schedule_external_snapshot_frames"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    stream_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    epoch_uuid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    epoch_number: Mapped[int] = mapped_column(big_integer(), nullable=False)
    sequence: Mapped[int] = mapped_column(big_integer(), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    frame_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    frame_index: Mapped[int] = mapped_column(Integer, nullable=False)
    frame_count: Mapped[int] = mapped_column(Integer, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False)
    owner: Mapped[str] = mapped_column(String(40), nullable=False)
    source_scope: Mapped[str] = mapped_column(String(500), nullable=False)
    adapter_instance_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    snapshot_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    frame_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    stable_source: Mapped[bool] = mapped_column(Boolean, nullable=False)
    schedules: Mapped[list[dict[str, Any]]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "epoch_uuid",
            "sequence",
            "frame_index",
            name="uq_schedule_external_snapshot_frame_index",
        ),
        CheckConstraint(
            "epoch_number > 0 AND sequence > 0",
            name="ck_schedule_external_snapshot_frame_positive",
        ),
        CheckConstraint(
            "frame_count >= 0 AND row_count >= 0 "
            "AND frame_index >= 0 AND frame_index <= frame_count",
            name="ck_schedule_external_snapshot_frame_bounds",
        ),
        CheckConstraint(
            "frame_kind IN ('rows', 'terminal')",
            name="ck_schedule_external_snapshot_frame_kind",
        ),
        Index(
            "ix_schedule_external_snapshot_assembly",
            "stream_id",
            "epoch_uuid",
            "sequence",
            "snapshot_id",
        ),
    )


class ScheduleExternalControlOperation(Base):
    """Durable external set-to-state operation awaiting source projection."""

    __tablename__ = "schedule_external_control_operations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    request_idempotency_key: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    command_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        unique=True,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    stream_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    epoch_uuid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    epoch_number: Mapped[int] = mapped_column(big_integer(), nullable=False)
    source_key: Mapped[str] = mapped_column(String(500), nullable=False)
    expected_accepted_sequence: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    expected_schedule_revision: Mapped[int] = mapped_column(
        big_integer(),
        nullable=False,
    )
    expected_control_token: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    prior_projection: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    prior_projection_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    desired_projection: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    desired_projection_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDING",
        server_default="PENDING",
    )
    adapter_instance_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    session_generation: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    registry_owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    dispatch_lease: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    reserved_sequence: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    result_projection_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    state_nonce: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
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

    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "request_idempotency_key",
            name="uq_schedule_external_control_request",
        ),
        CheckConstraint(
            "epoch_number > 0 AND expected_accepted_sequence >= 0",
            name="ck_schedule_external_control_epoch_sequence",
        ),
        CheckConstraint(
            "expected_schedule_revision > 0",
            name="ck_schedule_external_control_revision",
        ),
        CheckConstraint(
            "reserved_sequence IS NULL OR reserved_sequence > 0",
            name="ck_schedule_external_control_reserved_sequence",
        ),
        CheckConstraint(
            "status IN (" + ", ".join(f"'{value}'" for value in EXTERNAL_CONTROL_STATUSES) + ")",
            name="ck_schedule_external_control_status",
        ),
    )


class ScheduleOwnerCutover(Base):
    """Retained idempotency and attestation authority for one owner cutover."""

    __tablename__ = "schedule_owner_cutovers"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    from_owner: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    to_owner: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    source_scope: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    preview_manifest_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    preview_manifest: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    cursor_policy: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    quiescence_attestation: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    quiescence_attestation_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    source_stream_manifest: Mapped[list[dict[str, Any]]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    target_stream_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    result_manifest: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
    )
    result_manifest_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "from_owner <> to_owner",
            name="ck_schedule_owner_cutover_distinct_owners",
        ),
        CheckConstraint(
            "cursor_policy IN ('PRESERVE', 'PRESERVE_FUTURE', 'RESET_CURSOR')",
            name="ck_schedule_owner_cutover_cursor_policy",
        ),
    )


__all__ = [
    "EXTERNAL_CONTROL_STATUSES",
    "EXTERNAL_EPOCH_PHASES",
    "SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID",
    "SCHEDULE_EXTERNAL_PROTOCOL_VERSION",
    "ScheduleExternalControlOperation",
    "ScheduleExternalEpochAllocator",
    "ScheduleExternalProjection",
    "ScheduleExternalSnapshotFrame",
    "ScheduleExternalStream",
    "ScheduleExternalStreamEpoch",
    "ScheduleOwnerCutover",
]
