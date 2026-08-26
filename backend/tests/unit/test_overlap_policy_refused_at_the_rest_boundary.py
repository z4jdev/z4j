"""An ordinary REST request must not have overlap_policy silently dropped.

This is the original defect, and five rounds of reviewing the z4j-core guard
walked past it because everyone, me included, checked whether the request
schemas DECLARED the field and never whether they REJECT undeclared ones.

They did not. ``ScheduleCreateIn``, ``ScheduleUpdateIn`` and
``ImportedScheduleIn`` are plain ``BaseModel`` subclasses, so they inherit
pydantic's default ``extra="ignore"``. A POST, PATCH or bulk-import body
carrying ``overlap_policy: "skip"`` was accepted, dropped before the write,
and answered 200 with ``"allow"``. The caller asked for collision prevention,
was told it was applied, and got concurrent runs -- through an ORDINARY
request, not a deliberate validation bypass.

The fix declares the field on each request schema and refuses anything but
``allow``, rather than switching the models to ``extra="forbid"``, which would
also start rejecting every unknown key these endpoints have always tolerated.
Refuse the one field that lies; leave the rest of the contract alone.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from z4j_brain.api.schedules import (
    ImportedScheduleIn,
    ScheduleCreateIn,
    ScheduleUpdateIn,
)

_FULL = {
    "name": "cleanup",
    "task_name": "jobs.cleanup",
    "engine": "celery",
    "kind": "interval",
    "expression": "5m",
    "timezone": "UTC",
}

# ScheduleUpdateIn is all-optional by design: None means "do not touch".
_BODIES = {
    "ScheduleCreateIn": (ScheduleCreateIn, _FULL),
    "ScheduleUpdateIn": (ScheduleUpdateIn, {}),
    "ImportedScheduleIn": (ImportedScheduleIn, _FULL),
}


@pytest.mark.parametrize("schema_name", sorted(_BODIES))
@pytest.mark.parametrize("policy", ["skip", "queue"])
def test_an_unimplemented_policy_is_refused_not_dropped(
    schema_name: str,
    policy: str,
) -> None:
    model, base = _BODIES[schema_name]
    with pytest.raises(ValidationError) as caught:
        model(**{**base, "overlap_policy": policy})
    message = str(caught.value)
    assert "not implemented" in message, (
        f"{schema_name} rejected {policy!r} for the wrong reason: {message}"
    )
    assert policy in message
    assert "lock inside the task" in message, "the refusal must say what to do instead"


@pytest.mark.parametrize("schema_name", sorted(_BODIES))
def test_allow_and_omitted_are_both_still_accepted(schema_name: str) -> None:
    """The refusal must not cost the supported request.

    Omitting the field is what every existing client does, and ``allow`` is
    what a client that read the docs would send. Both have to keep working or
    the fix is a different outage.
    """
    model, base = _BODIES[schema_name]
    assert model(**base) is not None
    assert model(**{**base, "overlap_policy": "allow"}) is not None


@pytest.mark.parametrize("schema_name", sorted(_BODIES))
def test_the_field_is_declared_so_extra_ignore_cannot_swallow_it(
    schema_name: str,
) -> None:
    """The mechanism, asserted directly.

    These models deliberately keep ``extra="ignore"``. That is only safe while
    every field a caller might set is declared, because an undeclared one is
    dropped in silence. If the declaration is ever removed, the refusal above
    stops running and nothing else notices.
    """
    model, _ = _BODIES[schema_name]
    assert "overlap_policy" in model.model_fields, (
        f"{schema_name} no longer declares overlap_policy, so pydantic's "
        "extra='ignore' will silently drop it again"
    )
