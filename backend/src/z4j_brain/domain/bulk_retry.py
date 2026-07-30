"""Boundary B: canonical identity and sealed child payload construction."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from z4j_brain.domain.retry_contract import required_retry_engine
from z4j_brain.persistence.enums import TaskPriority, TaskState

CURRENT_CANONICALIZER_VERSION = 2
RETRY_CONTRACT_VERSION = 1
# The exact signer metadata is unavailable while sealing.  Reserve a deliberately
# generous fixed envelope budget and size the canonical unsigned payload.
WORST_CASE_SIGNED_ENVELOPE_BYTES = 16 * 1024
_V1_ALLOWED_FILTER_KEYS = frozenset(
    {
        "task_ids",
        "engine",
        "state",
        "status",
        "queue",
        "name",
        "since",
        "until",
    }
)
_V1_ENGINES = frozenset({"celery", "rq", "dramatiq"})
_V2_ALLOWED_FILTER_KEYS = _V1_ALLOWED_FILTER_KEYS | {"priority", "search"}


class CanonicalizerUnavailableError(ValueError):
    """The stored replay version has aged out of the registry."""


class PayloadTooLargeError(ValueError):
    """A sealed child cannot fit the configured transport frame."""


class SelectionLimitExceededError(ValueError):
    """The exact matching selection is larger than the declared maximum."""


class UnsupportedRetryEngineError(ValueError):
    """A selected task cannot be authorized by the retry command domain."""


@dataclass(frozen=True, slots=True)
class CanonicalRequest:
    version: int
    effective: dict[str, Any]
    exact_bytes: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class PlannedChild:
    ordinal: int
    engine: str
    payload: dict[str, Any]
    canonical_payload: bytes
    payload_digest: str
    payload_size: int


def _parse_datetime(value: Any) -> str | None:
    """Return a stable UTC ISO string for one accepted time bound."""

    if value is None or value == "":
        return None
    parsed: datetime
    if isinstance(value, bool):
        raise TypeError("boolean is not a datetime")
    if isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith(("Z", "z")):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
    else:
        raise TypeError("datetime bound must be a string or epoch number")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _v1_filter_object(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_filter = raw.get("filter")
    if raw_filter is None:
        raw_filter = {}
    if not isinstance(raw_filter, Mapping):
        raise TypeError("filter must be an object")
    unknown = sorted(set(raw_filter) - _V1_ALLOWED_FILTER_KEYS)
    if unknown:
        raise ValueError(
            "bulk-retry filter accepts selection keys only; rejected: " + ", ".join(unknown)
        )
    return raw_filter


def _v1_maximum(raw: Mapping[str, Any]) -> int:
    maximum = raw.get("max", 1000)
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise TypeError("max must be an integer")
    if not 1 <= maximum <= 10_000:
        raise ValueError("max must be between 1 and 10000")
    return maximum


def _v1_state(raw_filter: Mapping[str, Any]) -> str:
    state = raw_filter.get("state")
    status = raw_filter.get("status")
    if state is not None and status is not None and state != status:
        raise ValueError("state and status aliases disagree")
    state_value = state if state is not None else status
    if state_value is None:
        state_value = TaskState.FAILURE.value
    if not isinstance(state_value, str):
        raise TypeError("state/status must be a string")
    try:
        return TaskState(state_value).value
    except ValueError as exc:
        raise ValueError(f"unknown task state {state_value!r}") from exc


def _v1_selection_filter(
    raw_filter: Mapping[str, Any],
    *,
    maximum: int,
) -> dict[str, Any]:
    normalized_filter: dict[str, Any] = {"state": _v1_state(raw_filter)}
    for key in ("engine", "queue", "name"):
        value = raw_filter.get(key)
        if value not in (None, ""):
            if not isinstance(value, str):
                raise TypeError(f"filter {key!r} must be a string")
            normalized_filter[key] = value
    engine = normalized_filter.get("engine")
    if engine is not None and engine not in _V1_ENGINES:
        raise ValueError(f"engine must be one of {sorted(_V1_ENGINES)}")

    for key in ("since", "until"):
        value = _parse_datetime(raw_filter.get(key))
        if value is not None:
            normalized_filter[key] = value
    if "task_ids" in raw_filter:
        ids = raw_filter["task_ids"]
        if (
            not isinstance(ids, list)
            or not ids
            or any(
                not isinstance(task_id, str) or not task_id or len(task_id) > 200 for task_id in ids
            )
        ):
            raise ValueError("task_ids must be a non-empty list of strings up to 200 characters")
        if engine not in _V1_ENGINES:
            raise ValueError("explicit task_ids require one known engine")
        if len(ids) > maximum:
            raise ValueError("task_ids count exceeds max")
        normalized_filter["task_ids"] = list(dict.fromkeys(ids))
    return normalized_filter


def _v1_target(raw: Mapping[str, Any]) -> dict[str, str]:
    agent_id = raw.get("agent_id")
    if agent_id not in (None, ""):
        try:
            normalized_agent_id = str(uuid.UUID(str(agent_id)))
        except ValueError as exc:
            raise ValueError("agent_id must be a UUID") from exc
        target = {"agent_id": normalized_agent_id}
    else:
        target = {"routing_policy": "project_compatible_session_v1"}
    return target


def _canonicalize_v1(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Historical v1 canonicalizer; retain for the full replay horizon."""

    raw_filter = _v1_filter_object(raw)
    maximum = _v1_maximum(raw)
    return {
        "action": "bulk_retry",
        "filter": _v1_selection_filter(raw_filter, maximum=maximum),
        "max": maximum,
        "target": _v1_target(raw),
        "version": 1,
    }


def _v2_filter_object(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_filter = raw.get("filter")
    if raw_filter is None:
        raw_filter = {}
    if not isinstance(raw_filter, Mapping):
        raise TypeError("filter must be an object")
    unknown = sorted(set(raw_filter) - _V2_ALLOWED_FILTER_KEYS)
    if unknown:
        raise ValueError(
            "bulk-retry filter accepts selection keys only; rejected: " + ", ".join(unknown)
        )
    return raw_filter


def _v2_selection_filter(
    raw_filter: Mapping[str, Any],
    *,
    maximum: int,
) -> dict[str, Any]:
    normalized_filter = _v1_selection_filter(raw_filter, maximum=maximum)

    search = raw_filter.get("search")
    if search not in (None, ""):
        if not isinstance(search, str):
            raise TypeError("filter 'search' must be a string")
        if len(search) > 200:
            raise ValueError("filter 'search' must be at most 200 characters")
        normalized_filter["search"] = search

    priority = raw_filter.get("priority")
    if priority is not None:
        if not isinstance(priority, list) or not priority:
            raise ValueError("filter 'priority' must be a non-empty list")
        if any(not isinstance(value, str) for value in priority):
            raise TypeError("filter 'priority' values must be strings")
        try:
            requested = {TaskPriority(value) for value in priority}
        except ValueError as exc:
            raise ValueError("filter 'priority' contains an unknown priority") from exc
        normalized_filter["priority"] = [
            value.value for value in TaskPriority if value in requested
        ]

    if "task_ids" in normalized_filter and "priority" in normalized_filter:
        raise ValueError("priority cannot be combined with explicit task_ids")
    return normalized_filter


def _canonicalize_v2(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Current canonicalizer: v1 plus exact priority and search scope."""

    raw_filter = _v2_filter_object(raw)
    maximum = _v1_maximum(raw)
    return {
        "action": "bulk_retry",
        "filter": _v2_selection_filter(raw_filter, maximum=maximum),
        "max": maximum,
        "target": _v1_target(raw),
        "version": 2,
    }


_Canonicalizer = Callable[[Mapping[str, Any]], dict[str, Any]]
_CANONICALIZERS: dict[int, _Canonicalizer] = {
    1: _canonicalize_v1,
    2: _canonicalize_v2,
}


def canonicalize_request(
    raw: Mapping[str, Any],
    *,
    version: int = CURRENT_CANONICALIZER_VERSION,
) -> CanonicalRequest:
    """Canonicalize with the requested (possibly historical) version."""

    canonicalizer = _CANONICALIZERS.get(version)
    if canonicalizer is None:
        raise CanonicalizerUnavailableError(f"bulk-retry canonicalizer v{version} is unavailable")
    effective = canonicalizer(raw)
    exact = json.dumps(
        effective,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return CanonicalRequest(
        version=version,
        effective=effective,
        exact_bytes=exact,
        digest=hashlib.sha256(exact).hexdigest(),
    )


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def build_sealed_plan(
    tasks: list[Any],
    *,
    effective_filter: Mapping[str, Any],
    maximum: int,
    max_frame_bytes: int,
) -> tuple[list[PlannedChild], str]:
    """Build deterministic per-task children from production Task rows."""

    if len(tasks) > maximum:
        raise SelectionLimitExceededError(
            f"selection exceeds max ({len(tasks)} > {maximum})",
        )
    children: list[PlannedChild] = []
    selection_filter = {
        key: value for key, value in effective_filter.items() if key not in {"task_ids", "engine"}
    }
    ordered = sorted(tasks, key=lambda task: (str(task.engine), str(task.task_id)))
    for ordinal, task in enumerate(ordered):
        priority = getattr(task, "priority", None)
        priority_value = getattr(priority, "value", priority)
        task_id = str(task.task_id)
        engine = str(task.engine)
        requirement = required_retry_engine(
            "bulk_retry",
            {"filter": {"engine": engine}},
        )
        if requirement != engine:
            raise UnsupportedRetryEngineError(
                f"task {engine}:{task_id} uses an engine that cannot receive retry commands"
            )
        child_filter: dict[str, Any] = {
            **selection_filter,
            "engine": engine,
            "task_ids": [task_id],
            "task_names": {task_id: str(task.name)},
        }
        if priority_value is not None:
            child_filter["task_priorities"] = {task_id: priority_value}
        payload = {"filter": child_filter, "max": 1}
        unsigned = canonical_payload_bytes(payload)
        projected_size = len(unsigned) + WORST_CASE_SIGNED_ENVELOPE_BYTES
        if projected_size > max_frame_bytes:
            raise PayloadTooLargeError(
                f"task {engine}:{task_id} requires {projected_size} bytes "
                f"including the worst-case envelope; frame cap is {max_frame_bytes}"
            )
        children.append(
            PlannedChild(
                ordinal=ordinal,
                engine=engine,
                payload=payload,
                canonical_payload=unsigned,
                payload_digest=hashlib.sha256(unsigned).hexdigest(),
                payload_size=len(unsigned),
            )
        )
    plan_identity = [
        {
            "ordinal": child.ordinal,
            "engine": child.engine,
            "payload_digest": child.payload_digest,
        }
        for child in children
    ]
    plan_bytes = canonical_payload_bytes({"children": plan_identity})
    return children, hashlib.sha256(plan_bytes).hexdigest()


__all__ = [
    "CURRENT_CANONICALIZER_VERSION",
    "RETRY_CONTRACT_VERSION",
    "WORST_CASE_SIGNED_ENVELOPE_BYTES",
    "CanonicalRequest",
    "CanonicalizerUnavailableError",
    "PayloadTooLargeError",
    "PlannedChild",
    "SelectionLimitExceededError",
    "UnsupportedRetryEngineError",
    "build_sealed_plan",
    "canonical_payload_bytes",
    "canonicalize_request",
]
