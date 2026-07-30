"""Brain-native canonical cadence computation for Boundary D."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Literal
from zoneinfo import ZoneInfoNotFoundError

from astral import Observer
from astral.sun import (
    dawn,
    dusk,
    midnight,
    noon,
    sunrise,
    sunset,
)
from croniter import CroniterBadCronError, croniter

from z4j_brain.domain.schedule_runtime import (
    CADENCE_SEMANTICS_VERSION,
    packaged_zoneinfo,
)
from z4j_brain.domain.schedule_runtime import (
    cadence_runtime_fingerprint as _runtime_fingerprint,
)

ScheduleCadenceKind = Literal["cron", "interval", "clocked", "one_shot", "solar"]

_INTERVAL_PATTERN = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_INTERVAL_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}
_SOLAR_EVENTS = {
    "dawn": dawn,
    "sunrise": sunrise,
    "noon": noon,
    "solar_noon": noon,
    "sunset": sunset,
    "dusk": dusk,
    "midnight": midnight,
    "solar_midnight": midnight,
}


class ScheduleCadenceError(ValueError):
    """A schedule definition cannot produce a canonical successor."""


def _aware(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ScheduleCadenceError(f"{field} must be timezone-aware")
    return value


def _interval_delta(expression: str) -> timedelta:
    match = _INTERVAL_PATTERN.match(expression)
    if match is None:
        raise ScheduleCadenceError(
            f"interval expression must match '<int>[s|m|h|d]'; got {expression!r}",
        )
    count = int(match.group(1))
    if count <= 0:
        raise ScheduleCadenceError("interval must be greater than zero")
    return timedelta(seconds=count * _INTERVAL_SECONDS[match.group(2) or "s"])


def _next_interval(
    expression: str,
    *,
    last_run_at: datetime | None,
    anchor_at: datetime,
) -> datetime:
    delta = _interval_delta(expression)
    if last_run_at is not None:
        return _aware(last_run_at, field="last_run_at") + delta
    anchor = _aware(anchor_at, field="anchor_at")
    seconds = int(delta.total_seconds())
    anchor_seconds = int(anchor.timestamp())
    next_seconds = ((anchor_seconds // seconds) + 1) * seconds
    return datetime.fromtimestamp(next_seconds, tz=anchor.tzinfo)


def _next_cron(expression: str, timezone: str, after: datetime) -> datetime:
    try:
        zone = packaged_zoneinfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ScheduleCadenceError(f"unknown timezone: {timezone!r}") from exc
    try:
        return croniter(expression, _aware(after, field="after").astimezone(zone)).get_next(
            datetime,
        )
    except (CroniterBadCronError, ValueError) as exc:
        raise ScheduleCadenceError(
            f"invalid cron expression: {expression!r}",
        ) from exc


def _next_one_shot(
    expression: str,
    *,
    last_run_at: datetime | None,
) -> datetime | None:
    if last_run_at is not None:
        return None
    try:
        moment = datetime.fromisoformat(expression)
    except ValueError as exc:
        raise ScheduleCadenceError(
            f"one-shot expression must be ISO-8601; got {expression!r}",
        ) from exc
    return _aware(moment, field="one-shot expression")


def _parse_solar(expression: str) -> tuple[str, float, float]:
    if not expression or expression.count(":") != 2:
        raise ScheduleCadenceError(
            f"solar expression must be 'event:lat:lon'; got {expression!r}",
        )
    event, latitude_raw, longitude_raw = expression.split(":", 2)
    event = event.strip().lower()
    if event not in _SOLAR_EVENTS:
        raise ScheduleCadenceError(f"unknown solar event: {event!r}")
    try:
        latitude = float(latitude_raw)
        longitude = float(longitude_raw)
    except ValueError as exc:
        raise ScheduleCadenceError("solar coordinates must be finite numbers") from exc
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ScheduleCadenceError("solar coordinates are out of range")
    return event, latitude, longitude


def _next_solar(
    expression: str,
    *,
    after: datetime,
    max_days_ahead: int = 365,
) -> datetime | None:
    event, latitude, longitude = _parse_solar(expression)
    event_function = _SOLAR_EVENTS[event]
    observer = Observer(latitude=latitude, longitude=longitude)
    lower_bound = _aware(after, field="after").astimezone(UTC)
    cursor = lower_bound.date()
    for _ in range(max_days_ahead):
        try:
            candidate = event_function(observer, date=cursor, tzinfo=UTC)
        except Exception:
            cursor += timedelta(days=1)
            continue
        if candidate > lower_bound:
            return candidate
        cursor += timedelta(days=1)
    return None


def canonical_next_run_at(
    *,
    kind: str,
    expression: str,
    timezone: str,
    last_run_at: datetime | None,
    anchor_at: datetime,
) -> datetime | None:
    """Return the exact canonical UTC successor for one definition."""

    if kind == "cron":
        result = _next_cron(
            expression,
            timezone,
            last_run_at if last_run_at is not None else anchor_at,
        )
    elif kind == "interval":
        result = _next_interval(
            expression,
            last_run_at=last_run_at,
            anchor_at=anchor_at,
        )
    elif kind in {"clocked", "one_shot"}:
        result = _next_one_shot(expression, last_run_at=last_run_at)
    elif kind == "solar":
        result = _next_solar(
            expression,
            after=last_run_at if last_run_at is not None else anchor_at,
        )
    else:
        raise ScheduleCadenceError(f"unknown schedule kind: {kind!r}")
    return result.astimezone(UTC) if result is not None else None


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat(timespec="microseconds") if value else None


@lru_cache(maxsize=1)
def cadence_behavior_vector_digest() -> str:
    """Digest fixed edge vectors so semantic drift changes negotiation."""

    anchors = {
        "winter": datetime(2026, 1, 15, 5, 59, 59, tzinfo=UTC),
        "spring": datetime(2026, 3, 8, 6, 59, 59, tzinfo=UTC),
        "interval": datetime(2026, 1, 1, 12, 3, 7, tzinfo=UTC),
        "solar": datetime(2026, 1, 1, tzinfo=UTC),
    }
    vector = [
        _iso(
            canonical_next_run_at(
                kind="cron",
                expression="0 1 * * *",
                timezone="America/New_York",
                last_run_at=anchors["winter"],
                anchor_at=anchors["winter"],
            ),
        ),
        _iso(
            canonical_next_run_at(
                kind="cron",
                expression="30 2 * * *",
                timezone="America/New_York",
                last_run_at=anchors["spring"],
                anchor_at=anchors["spring"],
            ),
        ),
        _iso(
            canonical_next_run_at(
                kind="interval",
                expression="5m",
                timezone="UTC",
                last_run_at=None,
                anchor_at=anchors["interval"],
            ),
        ),
        _iso(
            canonical_next_run_at(
                kind="one_shot",
                expression="2026-02-03T04:05:06+05:30",
                timezone="UTC",
                last_run_at=None,
                anchor_at=anchors["winter"],
            ),
        ),
        _iso(
            canonical_next_run_at(
                kind="one_shot",
                expression="2026-02-03T04:05:06Z",
                timezone="UTC",
                last_run_at=anchors["winter"],
                anchor_at=anchors["winter"],
            ),
        ),
        _iso(
            canonical_next_run_at(
                kind="solar",
                expression="sunrise:0:0",
                timezone="UTC",
                last_run_at=None,
                anchor_at=anchors["solar"],
            ),
        ),
    ]
    payload = json.dumps(vector, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


@lru_cache(maxsize=1)
def cadence_runtime_fingerprint() -> str:
    return _runtime_fingerprint(cadence_behavior_vector_digest())


__all__ = [
    "CADENCE_SEMANTICS_VERSION",
    "ScheduleCadenceError",
    "cadence_behavior_vector_digest",
    "cadence_runtime_fingerprint",
    "canonical_next_run_at",
]
