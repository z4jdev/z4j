"""Canonical Boundary-D execution/cadence definition identity."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

CONTROL_FIELDS = (
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


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def canonical_definition_payload(source: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Return the exhaustive versioned definition payload."""

    def read(field: str) -> Any:
        if isinstance(source, Mapping):
            return source.get(field)
        return getattr(source, field)

    payload = {field: _value(read(field)) for field in CONTROL_FIELDS}
    return {
        "format": "z4j-schedule-definition-v1",
        "definition": payload,
    }


def schedule_definition_digest(source: Mapping[str, Any] | Any) -> str:
    canonical = json.dumps(
        canonical_definition_payload(source),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "CONTROL_FIELDS",
    "canonical_definition_payload",
    "schedule_definition_digest",
]
