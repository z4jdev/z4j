"""Deterministic Boundary-D schedule-fire identities."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import NAMESPACE_DNS, UUID, uuid5

SCHEDULE_FIRE_PROTOCOL_MARKER = 1

_SCHEDULER_FIRE_ID_NAMESPACE = uuid5(
    NAMESPACE_DNS,
    "z4j-scheduler.fire-id.v1",
)
_EXECUTION_FIRE_ID_NAMESPACE = uuid5(
    NAMESPACE_DNS,
    "z4j-brain.schedule-execution-fire-id.v1",
)


def normalized_schedule_slot(value: datetime) -> datetime:
    """Return the scheduler-visible whole-second UTC slot."""

    if value.tzinfo is None:
        raise ValueError("schedule fire slot must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


def derive_scheduler_fire_id(
    schedule_id: UUID,
    scheduled_for: datetime,
) -> UUID:
    """Mirror the deployed scheduler's deterministic wire identity."""

    slot = normalized_schedule_slot(scheduled_for)
    return uuid5(
        _SCHEDULER_FIRE_ID_NAMESPACE,
        f"{schedule_id}:{slot.isoformat()}",
    )


def derive_execution_fire_id(
    fire_id: UUID,
    receipt_control_token: UUID,
) -> UUID:
    """Derive the generation-scoped identity consumed by agent dedup."""

    return uuid5(
        _EXECUTION_FIRE_ID_NAMESPACE,
        f"{fire_id}:{receipt_control_token}",
    )


__all__ = [
    "SCHEDULE_FIRE_PROTOCOL_MARKER",
    "derive_execution_fire_id",
    "derive_scheduler_fire_id",
    "normalized_schedule_slot",
]
