"""``commands`` table - issued commands and their results."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models._mixins import PKMixin
from z4j_brain.persistence.types import big_integer, inet, jsonb


class Command(PKMixin, Base):
    """A command issued by an operator (or worker) against an agent.

    Commands are signed with the project's HMAC secret before being
    pushed to the agent over the WebSocket; the agent verifies and
    executes, then returns a result frame which updates this row.

    Attributes:
        project_id: Historical owning project id. Boundary D deliberately
            keeps this factual attribution after project deletion.
        issued_by: User who issued the command. ``ON DELETE SET NULL``
            so command history survives user deletion (audit_log
            references the user_id by id, not foreign key cascade).
        agent_id: Historical target agent id. Boundary D deliberately keeps
            this factual attribution after agent deletion.
        action: Command action verb (``retry_task``, ``cancel_task``,
            ``schedule.enable``, ...). Matches the agent dispatcher's
            recognized actions.
        target_type: Generic target identifier (``task``, ``queue``,
            ``schedule``, ``worker``).
        target_id: Engine-native identifier of the target.
        payload: Command-specific parameters (eta, override_args, ...).
        idempotency_key: Optional client-supplied dedupe key. Unique
            per project so retries from a flaky dashboard don't
            queue duplicate retries.
        status: ``pending`` → ``dispatched`` → ``completed`` /
            ``failed`` / ``timeout`` / ``cancelled``.
        result: Agent-supplied success result.
        error: Agent-supplied error message on failure.
        timeout_at: When this command should be marked timed-out by
            the CommandTimeoutWorker.
        source_ip: IP address of the dashboard caller, if known.
    """

    __tablename__ = "commands"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    issued_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[CommandStatus] = mapped_column(
        Enum(
            CommandStatus,
            name="command_status",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=CommandStatus.PENDING,
        server_default=CommandStatus.PENDING.value,
    )
    result: Mapped[Any | None] = mapped_column(jsonb(), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    timeout_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    source_ip: Mapped[str | None] = mapped_column(inet(), nullable=True)
    bulk_retry_child_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("bulk_retry_request_children.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Boundary-D cadence acceptance evidence.  These columns are nullable only
    # for rows predating activation or for non-cadence commands.  A current
    # schedule.fire command is deliverable only when the entire tuple is
    # present and internally consistent.
    schedule_protocol_marker: Mapped[int | None] = mapped_column(nullable=True)
    schedule_state_nonce: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_fire_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_scheduled_for: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    schedule_observed_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_receipt_control_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_execution_fire_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    schedule_acceptance_revision: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    schedule_definition_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    schedule_expected_revision: Mapped[int | None] = mapped_column(
        big_integer(),
        nullable=True,
    )
    schedule_expected_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    schedule_expected_next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    schedule_next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cadence_initial_claim_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    first_delivery_claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cadence_redelivery_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    delivery_transport_kind: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    delivery_registry_owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    delivery_session_generation: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    delivery_claim_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    agent_acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "idempotency_key",
            name="uq_commands_project_idempotency_key",
        ),
        Index(
            "ix_commands_project_status_issued",
            "project_id",
            "status",
            "issued_at",
        ),
        Index("ix_commands_timeout_at", "timeout_at"),
        Index("ix_commands_issued_by_at", "issued_by", "issued_at"),
        Index(
            "ix_commands_schedule_fire_receipt",
            "schedule_id",
            "schedule_fire_id",
            "schedule_receipt_control_token",
        ),
        Index(
            "ux_commands_bulk_retry_child",
            "bulk_retry_child_id",
            unique=True,
        ),
    )


__all__ = ["Command"]
