"""Cursor-based pagination helper.

We deliberately avoid OFFSET pagination - it gets slower the deeper
you page and is unsafe under concurrent inserts (rows shift). Cursor
pagination is O(1) per page and stable under writes.

The cursor is a base64url-encoded payload of
``{primary_sort_value, tiebreaker_id}``. For event-style tables that
sort by ``occurred_at DESC, id DESC`` the cursor is
``(occurred_at, id)``. For task-style tables that sort by
``started_at DESC, id DESC`` it is ``(started_at, id)``.

Two helpers below:

- :func:`encode_cursor` - bundle the sort key + tiebreaker into a
  url-safe opaque string.
- :func:`decode_cursor` - parse it back into a typed pair, or
  return ``None`` for any malformed input.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any


def encode_cursor(sort_value: Any, tiebreaker: uuid.UUID) -> str:
    """Encode a (sort_value, tiebreaker) pair as a url-safe cursor.

    ``sort_value`` may be a datetime (the common case), a string, an
    int, or None. We round-trip via JSON so the consumer reads the
    same type the producer wrote.
    """
    if isinstance(sort_value, datetime):
        sort_repr: Any = ["dt", sort_value.astimezone(UTC).isoformat()]
    elif sort_value is None:
        sort_repr = ["null", None]
    else:
        sort_repr = ["raw", sort_value]
    payload = json.dumps([sort_repr, str(tiebreaker)], separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str | None) -> tuple[Any, uuid.UUID] | None:
    """Decode a cursor previously produced by :func:`encode_cursor`.

    Returns ``None`` for empty input or any malformed cursor - the
    caller treats that as "start at the top". Never raises.
    """
    if not cursor:
        return None
    try:
        # Restore base64 padding.
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw)
        if not isinstance(payload, list) or len(payload) != 2:
            return None
        sort_repr, tiebreaker_str = payload
        if not isinstance(sort_repr, list) or len(sort_repr) != 2:
            return None
        kind, value = sort_repr
        if kind == "dt" and isinstance(value, str):
            sort_value: Any = datetime.fromisoformat(value)
        elif kind == "null":
            sort_value = None
        elif kind == "raw":
            sort_value = value
        else:
            return None
        return sort_value, uuid.UUID(tiebreaker_str)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def clamp_limit(requested: int | None, *, default: int, maximum: int) -> int:
    """Clamp a user-supplied ``limit`` to the configured bounds.

    A negative value or ``None`` falls back to ``default``. Anything
    above ``maximum`` is silently capped - we never error on a too-
    large limit because that would be a poor caller experience for
    a legitimate operator who just wants "as much as you'll give me".
    """
    if requested is None or requested <= 0:
        return default
    return min(requested, maximum)


__all__ = ["clamp_limit", "decode_cursor", "encode_cursor"]
