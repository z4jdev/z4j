"""Schedule-owner authority shared by ingestion and persistence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

RESERVED_SCHEDULE_OWNER = "z4j-scheduler"


class ReservedScheduleOwnerError(ValueError):
    """An agent projection attempted to claim Brain-owned schedule authority."""


def validate_external_schedule_projection(
    *,
    outer_owner: str | None,
    rows: Iterable[Mapping[str, Any]] = (),
) -> None:
    """Reject reserved ownership before an external projection performs I/O."""

    if outer_owner == RESERVED_SCHEDULE_OWNER:
        raise ReservedScheduleOwnerError(
            "agent schedule projection cannot claim reserved z4j-scheduler ownership",
        )
    for row in rows:
        inner_owner = row.get("scheduler", row.get("owner"))
        if inner_owner == RESERVED_SCHEDULE_OWNER:
            raise ReservedScheduleOwnerError(
                "agent schedule payload cannot claim reserved z4j-scheduler ownership",
            )


__all__ = [
    "RESERVED_SCHEDULE_OWNER",
    "ReservedScheduleOwnerError",
    "validate_external_schedule_projection",
]
