"""Tests for the /health and /health/ready endpoints."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
class TestHealth:
    async def test_liveness_returns_200(self, client) -> None:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert "version" in body

    async def test_readiness_returns_200_on_sqlite(self, client) -> None:
        # SQLite is reachable in our test fixture, so /ready is happy.
        response = await client.get("/api/v1/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"

    async def test_readiness_includes_version(self, client) -> None:
        response = await client.get("/api/v1/health/ready")
        assert "version" in response.json()
