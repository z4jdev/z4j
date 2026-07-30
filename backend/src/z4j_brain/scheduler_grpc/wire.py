"""Canonical Brain encoding for Boundary-D schedule rows and snapshots."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from google.protobuf.timestamp_pb2 import Timestamp

from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

SNAPSHOT_FORMAT_VERSION = 1
_DEFAULT_ANCHOR = datetime(2000, 1, 1, tzinfo=UTC)


def _read(source: Mapping[str, Any] | Any, field: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(field, default)
    return getattr(source, field, default)


def _enum(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value)


def _datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def _timestamp(value: Any) -> Timestamp:
    result = Timestamp()
    parsed = _datetime(value)
    if parsed is not None:
        result.FromDatetime(parsed)
    return result


def schedule_to_pb(
    source: Mapping[str, Any] | Any,
    *,
    include_current: bool = True,
) -> pb.Schedule:
    """Translate an ORM row or immutable log snapshot to protobuf."""

    args = _read(source, "args", []) or []
    kwargs = _read(source, "kwargs", {}) or {}
    control_token = _read(source, "control_token")
    quarantine_token = _read(source, "quarantine_control_token")
    desired_enabled = bool(_read(source, "is_enabled", False))
    effectively_enabled = desired_enabled and not (
        control_token is not None and quarantine_token == control_token
    )
    return pb.Schedule(
        id=str(_read(source, "id")),
        project_id=str(_read(source, "project_id")),
        engine=str(_read(source, "engine", "")),
        name=str(_read(source, "name", "")),
        task_name=str(_read(source, "task_name", "")),
        kind=_enum(_read(source, "kind", "")),
        expression=str(_read(source, "expression", "")),
        timezone=str(_read(source, "timezone", "UTC") or "UTC"),
        queue=str(_read(source, "queue", "") or ""),
        args_json=json.dumps(args, separators=(",", ":"), sort_keys=True).encode(),
        kwargs_json=json.dumps(kwargs, separators=(",", ":"), sort_keys=True).encode(),
        is_enabled=effectively_enabled,
        catch_up=str(_read(source, "catch_up", "skip") or "skip"),
        source=str(_read(source, "source", "dashboard") or "dashboard"),
        last_run_at=_timestamp(_read(source, "last_run_at")),
        next_run_at=_timestamp(_read(source, "next_run_at")),
        total_runs=int(_read(source, "total_runs", 0) or 0),
        source_hash=str(_read(source, "source_hash", "") or ""),
        control_token=str(control_token or "") if include_current else "",
        schedule_revision=(
            int(_read(source, "schedule_revision", 0) or 0) if include_current else 0
        ),
        definition_digest=(
            str(_read(source, "definition_digest", "") or "") if include_current else ""
        ),
        cadence_semantics_version=int(
            _read(source, "cadence_semantics_version", 0) or 0,
        )
        if include_current
        else 0,
        cadence_runtime_fingerprint=str(
            _read(source, "cadence_runtime_fingerprint", "") or "",
        )
        if include_current
        else "",
    )


def _pb_datetime(value: Timestamp) -> datetime | None:
    if value.seconds == 0 and value.nanos == 0:
        return None
    return datetime.fromtimestamp(
        value.seconds + value.nanos / 1_000_000_000,
        tz=UTC,
    )


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat(timespec="microseconds") if value else None


def _row_digest_payload(row: pb.Schedule) -> dict[str, Any]:
    last_run_at = _pb_datetime(row.last_run_at)
    next_run_at = _pb_datetime(row.next_run_at)
    return {
        "id": str(UUID(row.id)),
        "project_id": str(UUID(row.project_id)),
        "kind": "clocked" if row.kind == "one_shot" else row.kind,
        "expression": row.expression,
        "timezone": row.timezone or "UTC",
        "is_enabled": row.is_enabled,
        "catch_up": row.catch_up or "skip",
        "anchor_at": _iso(last_run_at or next_run_at or _DEFAULT_ANCHOR),
        "last_fire_at": _iso(last_run_at),
        "next_fire_at": _iso(next_run_at),
        "name": row.name or "",
        "engine": row.engine or "",
        "control_token": row.control_token or None,
        "schedule_revision": int(row.schedule_revision),
        "definition_digest": row.definition_digest,
        "cadence_semantics_version": int(row.cadence_semantics_version),
        "cadence_runtime_fingerprint": row.cadence_runtime_fingerprint,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _frame(digest: Any, payload: bytes) -> None:
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def stable_snapshot_digest(
    *,
    snapshot_id: UUID,
    project_id: UUID | None,
    watermark: int,
    rows: Sequence[pb.Schedule],
) -> str:
    """Match the scheduler's independently implemented snapshot digest."""

    ordered = sorted(rows, key=lambda row: UUID(row.id).bytes)
    header = _canonical_bytes(
        {
            "format_version": SNAPSHOT_FORMAT_VERSION,
            "snapshot_id": str(snapshot_id),
            "project_id": str(project_id) if project_id is not None else "",
            "watermark": watermark,
            "row_count": len(ordered),
        },
    )
    digest = hashlib.sha256()
    _frame(digest, header)
    for row in ordered:
        _frame(digest, _canonical_bytes(_row_digest_payload(row)))
    return digest.hexdigest()


__all__ = [
    "SNAPSHOT_FORMAT_VERSION",
    "schedule_to_pb",
    "stable_snapshot_digest",
]
