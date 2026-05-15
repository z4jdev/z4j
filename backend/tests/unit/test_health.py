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

    async def test_liveness_does_not_leak_version(self, client) -> None:
        """1.6.3 security advisory: /health is publicly reachable
        (by design for liveness probes) so leaking the brain version
        lets attackers pin specific CVEs. Version disclosure moved
        to /health/system (auth-gated).
        """
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert "version" not in body

    async def test_readiness_returns_200_on_sqlite(self, client) -> None:
        # SQLite is reachable in our test fixture, so /ready is happy.
        response = await client.get("/api/v1/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"

    async def test_readiness_does_not_leak_version(self, client) -> None:
        """1.6.3 security advisory: /health/ready is publicly reachable
        (k8s readiness probe) so leaking the brain version invites
        the same CVE-pin attacks as /health. Same fix.
        """
        response = await client.get("/api/v1/health/ready")
        assert response.status_code == 200
        body = response.json()
        assert "version" not in body
