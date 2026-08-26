"""The rollback cursor plan must survive a naive stored timestamp.

SQLite has no timezone type. A column declared ``DateTime(timezone=True)``
round-trips through it NAIVE, so the same row that comes back aware on
PostgreSQL comes back without tzinfo on SQLite. ``canonical_next_run_at``
refuses a naive input by design.

The two cursor paths disagreed about this. The change-log path normalized its
anchor; the ``last_run_at`` path passed the stored value straight through. The
consequence was narrow and severe: on SQLite, ``prepare-runtime-rollback``
raised ``ScheduleCadenceError`` for every schedule that had ever fired, which
is nearly every real schedule, and took the whole ceremony down with it. It
would have surfaced first as a failed SQLite lane in the release rollback
proof, or worse, in front of an operator trying to roll back.

These tests drive ``_cursor_plan`` directly with both shapes, because the
difference only exists at the boundary between what the database returns and
what the cadence functions accept.
"""

from __future__ import annotations

import datetime
import types

import pytest
from z4j_brain.persistence.repositories import schedule_runtime_rollback as rollback

_NAIVE = datetime.datetime(2026, 3, 8, 1, 0, 0)
_AWARE = _NAIVE.replace(tzinfo=datetime.UTC)
# A 30m interval anchored on _AWARE lands here. An enabled schedule must carry a
# cursor, so every row below supplies one; a null cursor is refused separately.
_EXPECTED_NEXT = _AWARE + datetime.timedelta(minutes=30)
_STALE_CURSOR = _AWARE + datetime.timedelta(hours=4)


def _row(*, last_run_at: datetime.datetime | None, next_run_at: datetime.datetime | None):
    """A minimal stand-in carrying only what _cursor_plan reads."""

    return types.SimpleNamespace(
        id="11111111-1111-4111-8111-111111111111",
        is_enabled=True,
        kind="interval",
        expression="30m",
        timezone="UTC",
        last_run_at=last_run_at,
        next_run_at=next_run_at,
    )


def test_utc_aware_normalizes_both_shapes() -> None:
    assert rollback._utc_aware(_NAIVE) == _AWARE
    assert rollback._utc_aware(_AWARE) == _AWARE
    assert rollback._utc_aware(_NAIVE).tzinfo is not None


@pytest.mark.parametrize("stored", [_NAIVE, _AWARE], ids=["sqlite-naive", "postgres-aware"])
def test_cursor_plan_accepts_the_timestamp_either_backend_returns(
    stored: datetime.datetime,
) -> None:
    """The plan must not depend on which backend produced the row."""

    policy, anchor_kind, anchor_at, target_next = rollback._cursor_plan(
        row=_row(last_run_at=stored, next_run_at=_STALE_CURSOR),
        history=[],
        pruned_through=0,
        inflight=False,
    )

    assert anchor_kind == "last_run_at"
    assert policy == "recomputed_from_last_run"
    assert target_next == _EXPECTED_NEXT
    assert anchor_at is not None and anchor_at.tzinfo is not None


def test_both_backends_produce_the_identical_plan() -> None:
    """Same instant, same plan. A stored tzinfo is a storage detail."""

    naive = rollback._cursor_plan(
        row=_row(last_run_at=_NAIVE, next_run_at=_STALE_CURSOR.replace(tzinfo=None)),
        history=[],
        pruned_through=0,
        inflight=False,
    )
    aware = rollback._cursor_plan(
        row=_row(last_run_at=_AWARE, next_run_at=_STALE_CURSOR),
        history=[],
        pruned_through=0,
        inflight=False,
    )
    assert naive == aware


def test_a_naive_stored_cursor_still_validates_rather_than_recomputing() -> None:
    """_same_time already normalized, so an unchanged cursor stays unchanged.

    This pins the policy label as well as the time. Getting the normalization
    wrong in the other direction would silently reclassify a row that needed no
    change as one that did, and the ceremony's receipt records that label.
    """

    policy, anchor_kind, _anchor_at, target_next = rollback._cursor_plan(
        row=_row(last_run_at=_NAIVE, next_run_at=_EXPECTED_NEXT.replace(tzinfo=None)),
        history=[],
        pruned_through=0,
        inflight=False,
    )
    assert anchor_kind == "last_run_at"
    assert policy == "validated_from_last_run"
    assert target_next == _EXPECTED_NEXT
