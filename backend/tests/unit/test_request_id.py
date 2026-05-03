"""Tests for the RequestIdMiddleware."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
class TestRequestId:
    async def test_response_carries_request_id_header(self, client) -> None:
        response = await client.get("/api/v1/health")
        assert response.headers.get("x-request-id")

    async def test_caller_supplied_id_is_preserved(self, client) -> None:
        response = await client.get(
            "/api/v1/health",
            headers={"X-Request-Id": "client-supplied-id-1234"},
        )
        assert response.headers["x-request-id"] == "client-supplied-id-1234"

    async def test_caller_supplied_id_with_spaces_is_replaced(
        self, client,
    ) -> None:
        response = await client.get(
            "/api/v1/health",
            headers={"X-Request-Id": "has spaces"},
        )
        # Should fall back to a server-generated id, not echo the
        # malformed input.
        echoed = response.headers["x-request-id"]
        assert " " not in echoed
        assert echoed.startswith("req_")

    async def test_oversized_id_is_replaced(self, client) -> None:
        response = await client.get(
            "/api/v1/health",
            headers={"X-Request-Id": "x" * 200},
        )
        echoed = response.headers["x-request-id"]
        assert len(echoed) < 100
        assert echoed.startswith("req_")

    async def test_control_chars_are_rejected(self, client) -> None:
        response = await client.get(
            "/api/v1/health",
            headers={"X-Request-Id": "abc\x01def"},
        )
        echoed = response.headers["x-request-id"]
        assert "\x01" not in echoed
        assert echoed.startswith("req_")
