from __future__ import annotations

from datetime import UTC, datetime

import pytest
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    ScheduleCadenceError,
    cadence_behavior_vector_digest,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_definition import (
    CONTROL_FIELDS,
    schedule_definition_digest,
)


def _definition() -> dict[str, object]:
    return {
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "task_name": "jobs.cleanup",
        "kind": "cron",
        "expression": "0 3 * * *",
        "timezone": "America/New_York",
        "queue": "maintenance",
        "priority": "normal",
        "args": ["old"],
        "kwargs": {"dry_run": False},
        "is_enabled": True,
        "catch_up": "skip",
        "name": "metadata-only",
        "source": "dashboard",
        "source_hash": "old",
        "external_id": None,
    }


EXPECTED_CONTROL_FIELDS = (
    "engine",
    "scheduler",
    "task_name",
    "kind",
    "expression",
    "timezone",
    "queue",
    "priority",
    "args",
    "kwargs",
    "is_enabled",
    "catch_up",
)


def test_definition_control_field_set_is_exhaustive() -> None:
    assert CONTROL_FIELDS == EXPECTED_CONTROL_FIELDS


@pytest.mark.parametrize("field", EXPECTED_CONTROL_FIELDS)
def test_definition_digest_covers_every_control_field(field: str) -> None:
    before = _definition()
    after = _definition()
    replacements: dict[str, object] = {
        "engine": "rq",
        "scheduler": "other",
        "task_name": "jobs.repair",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "high",
        "args": ["new"],
        "kwargs": {"dry_run": True},
        "is_enabled": False,
        "catch_up": "fire_one_missed",
    }
    after[field] = replacements[field]
    assert schedule_definition_digest(before) != schedule_definition_digest(after)


@pytest.mark.parametrize("field", ["name", "source", "source_hash", "external_id"])
def test_definition_digest_excludes_management_metadata(field: str) -> None:
    before = _definition()
    after = _definition()
    after[field] = "changed"
    assert schedule_definition_digest(before) == schedule_definition_digest(after)


def test_cadence_runtime_identity_is_complete_and_stable() -> None:
    assert CADENCE_SEMANTICS_VERSION == 1
    assert (
        cadence_behavior_vector_digest()
        == "8e2ec76becf6ca6263805221e930c98962713ba0419c2a7e320e1dc928014a15"
    )
    assert len(cadence_runtime_fingerprint()) == 64
    assert cadence_runtime_fingerprint() == cadence_runtime_fingerprint()


def test_canonical_successor_is_utc_and_one_shot_exhaustion_is_explicit() -> None:
    anchor = datetime(2026, 1, 1, 12, 3, 7, tzinfo=UTC)
    assert canonical_next_run_at(
        kind="interval",
        expression="5m",
        timezone="UTC",
        last_run_at=None,
        anchor_at=anchor,
    ) == datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    assert (
        canonical_next_run_at(
            kind="one_shot",
            expression="2026-01-02T12:00:00Z",
            timezone="UTC",
            last_run_at=anchor,
            anchor_at=anchor,
        )
        is None
    )


@pytest.mark.parametrize(
    ("kind", "expression", "timezone"),
    [
        ("cron", "not a cron", "UTC"),
        ("cron", "* * * * *", "../UTC"),
        ("interval", "0s", "UTC"),
        ("one_shot", "2026-01-01", "UTC"),
        ("solar", "sunrise:91:0", "UTC"),
        ("unknown", "*", "UTC"),
    ],
)
def test_invalid_definition_fails_closed(
    kind: str,
    expression: str,
    timezone: str,
) -> None:
    with pytest.raises(ScheduleCadenceError):
        canonical_next_run_at(
            kind=kind,
            expression=expression,
            timezone=timezone,
            last_run_at=None,
            anchor_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
