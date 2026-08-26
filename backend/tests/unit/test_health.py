"""Tests for the /health and /health/ready endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_SHIPPED_BRAIN_HEALTHCHECK_CARRIERS = (
    _REPOSITORY_ROOT / "packages/z4j/Dockerfile",
    _REPOSITORY_ROOT / "packages/z4j/backend/Dockerfile",
    _REPOSITORY_ROOT / "docker-compose.yml",
    _REPOSITORY_ROOT / "docker-compose.postgres.yml",
    _REPOSITORY_ROOT / "packages/z4j/docker-compose.yml",
    _REPOSITORY_ROOT / "packages/z4j/docker-compose.postgres.yml",
)


def test_shipped_container_healthchecks_use_liveness_not_readiness() -> None:
    """Pin the deployment carriers named by ``health.py`` documentation."""
    for carrier in _SHIPPED_BRAIN_HEALTHCHECK_CARRIERS:
        text = carrier.read_text(encoding="utf-8")
        assert "/api/v1/health" in text, carrier
        assert "/api/v1/health/ready" not in text, carrier


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
