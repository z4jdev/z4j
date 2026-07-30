from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_scheduler.dispatch.fire import derive_fire_id


@pytest.mark.parametrize(
    "scheduled_for",
    [
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 3, 8, 1, 59, 59, 999999, tzinfo=timezone(timedelta(hours=-5))),
        datetime(2026, 11, 1, 1, 30, tzinfo=timezone(timedelta(hours=-4))),
    ],
)
def test_brain_and_scheduler_derive_identical_wire_fire_ids(
    scheduled_for: datetime,
) -> None:
    schedule_id = uuid.UUID("bb0637b9-465a-4cf0-b397-f54da0ac85dc")
    assert derive_scheduler_fire_id(schedule_id, scheduled_for) == derive_fire_id(
        schedule_id,
        scheduled_for,
    )
