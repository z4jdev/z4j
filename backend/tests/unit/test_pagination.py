"""Tests for ``z4j_brain.api._pagination``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from z4j_brain.api._pagination import (
    clamp_limit,
    decode_cursor,
    encode_cursor,
)


class TestRoundTrip:
    def test_datetime_round_trip(self) -> None:
        ts = datetime(2026, 4, 11, 12, 30, 0, tzinfo=UTC)
        tb = uuid.uuid4()
        cursor = encode_cursor(ts, tb)
        sort_value, parsed_tb = decode_cursor(cursor)  # type: ignore[misc]
        assert sort_value == ts
        assert parsed_tb == tb

    def test_none_round_trip(self) -> None:
        tb = uuid.uuid4()
        cursor = encode_cursor(None, tb)
        sort_value, parsed_tb = decode_cursor(cursor)  # type: ignore[misc]
        assert sort_value is None
        assert parsed_tb == tb

    def test_string_round_trip(self) -> None:
        tb = uuid.uuid4()
        cursor = encode_cursor("hello", tb)
        sort_value, parsed_tb = decode_cursor(cursor)  # type: ignore[misc]
        assert sort_value == "hello"
        assert parsed_tb == tb


class TestDecode:
    def test_empty_returns_none(self) -> None:
        assert decode_cursor(None) is None
        assert decode_cursor("") is None

    def test_garbage_returns_none(self) -> None:
        assert decode_cursor("not a cursor") is None
        assert decode_cursor("AAAA") is None

    def test_truncated_payload_returns_none(self) -> None:
        valid = encode_cursor(datetime.now(UTC), uuid.uuid4())
        assert decode_cursor(valid[:5]) is None


class TestClampLimit:
    def test_none_uses_default(self) -> None:
        assert clamp_limit(None, default=50, maximum=500) == 50

    def test_zero_uses_default(self) -> None:
        assert clamp_limit(0, default=50, maximum=500) == 50

    def test_negative_uses_default(self) -> None:
        assert clamp_limit(-1, default=50, maximum=500) == 50

    def test_within_range(self) -> None:
        assert clamp_limit(100, default=50, maximum=500) == 100

    def test_caps_at_maximum(self) -> None:
        assert clamp_limit(10_000, default=50, maximum=500) == 500
