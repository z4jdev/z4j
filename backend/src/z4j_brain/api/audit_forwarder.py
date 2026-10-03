"""Read-only ``/api/v1/admin/audit-forwarder`` status endpoint.

The audit webhook forwarder is a leader-gated background worker, and the
deep health probe reports subsystems rather than workers, so an operator
asking "is the mirror keeping up" needs somewhere to look. This answers
from the durable cursor in ``audit_forward_state`` plus a count of the
rows past it, which is the brain-wide truth whichever replica happens to
hold the lock. The process-local counters (rows this process delivered)
are included when this process has the forwarder constructed; they are
one process's view and say nothing about the others.

Read-only on purpose. Moving the cursor is a delivery decision the
worker owns; an operator who needs a backfill or a skip does it against
the table with the audit trail that implies.

Auth: :func:`require_admin`, the same dep ``/admin/settings`` uses.
Non-admins get 403, anonymous gets 401.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from z4j_brain.api.deps import get_session, get_settings, require_admin
from z4j_brain.domain.audit_forwarder import (
    AuditForwarder,
    state_backoff_remaining,
)
from z4j_brain.persistence.models.audit_forward_state import (
    DEFAULT_AUDIT_FORWARD_SINK_ID,
)
from z4j_brain.persistence.repositories.audit_forward_state import (
    AuditForwardStateRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/admin/audit-forwarder", tags=["admin-audit-forwarder"])


class AuditForwarderStatus(BaseModel):
    """What the forwarder has acknowledged, and what is still waiting."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(description="Whether Z4J_AUDIT_WEBHOOK_URL is set on this brain.")
    sink_id: str = Field(description="The sink the cursor belongs to.")
    worker: str = Field(description="The supervisor and leader-lock name of the worker.")
    cursor_initialised: bool = Field(
        description=(
            "Whether the state row exists yet. It is created on the worker's "
            "first pass, starting at the audit head at that moment."
        ),
    )
    cursor_occurred_at: datetime | None = Field(
        default=None,
        description="occurred_at of the newest audit row the receiver acknowledged.",
    )
    cursor_id: str | None = Field(
        default=None,
        description="id of the newest audit row the receiver acknowledged.",
    )
    lag_rows: int | None = Field(
        default=None,
        description=(
            "Audit rows written past the cursor and not yet acknowledged. Null "
            "until the cursor exists."
        ),
    )
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    consecutive_failures: int = Field(
        default=0,
        description="Attempts in a row that did not get a 2xx; zero after a success.",
    )
    backoff_seconds_remaining: float = Field(
        default=0.0,
        description="Seconds until the next attempt is due; zero when it is due now.",
    )
    batch_size: int
    poll_interval_seconds: float
    max_backoff_seconds: float
    updated_at: datetime | None = None
    process_sent_count: int | None = Field(
        default=None,
        description=(
            "Rows this process delivered since it started. Null when this "
            "process has no forwarder constructed. One process's view only."
        ),
    )
    process_failed_count: int | None = Field(
        default=None,
        description="Failed attempts by this process since it started, or null.",
    )


@router.get("", response_model=AuditForwarderStatus)
async def get_audit_forwarder_status(
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _admin: User = Depends(require_admin),
) -> AuditForwarderStatus:
    """The forwarder's durable cursor and backlog, for admins."""
    forwarder: AuditForwarder | None = getattr(request.app.state, "audit_forwarder", None)
    sink_id = forwarder.sink_id if forwarder is not None else DEFAULT_AUDIT_FORWARD_SINK_ID
    status = AuditForwarderStatus(
        enabled=settings.audit_forwarder_enabled(),
        sink_id=sink_id,
        worker=AuditForwarder.LEADER_LOCK_NAME,
        cursor_initialised=False,
        batch_size=settings.audit_webhook_batch_size,
        poll_interval_seconds=settings.audit_webhook_poll_interval_seconds,
        max_backoff_seconds=settings.audit_webhook_max_backoff_seconds,
    )
    if forwarder is not None:
        status.process_sent_count = forwarder.sent_count
        status.process_failed_count = forwarder.failed_count

    repo = AuditForwardStateRepository(session)
    state = await repo.get_for_sink(sink_id)
    if state is None:
        return status
    status.cursor_initialised = True
    status.cursor_occurred_at = state.last_forwarded_occurred_at
    status.cursor_id = None if state.last_forwarded_id is None else str(state.last_forwarded_id)
    status.last_attempt_at = state.last_attempt_at
    status.last_success_at = state.last_success_at
    status.consecutive_failures = state.consecutive_failures
    status.updated_at = state.updated_at
    status.backoff_seconds_remaining = state_backoff_remaining(
        state,
        now=datetime.now(UTC),
        max_backoff_seconds=settings.audit_webhook_max_backoff_seconds,
    )
    status.lag_rows = await repo.count_pending(
        after_occurred_at=state.last_forwarded_occurred_at,
        after_id=state.last_forwarded_id,
    )
    return status


__all__ = ["AuditForwarderStatus", "router"]
