"""``_probe_scheduler`` must honour its "Never raises" docstring.

The fleet listing probes every URL in ``Z4J_SCHEDULER_INFO_URLS`` and reports
one ``FleetEntry`` per entry. A bad entry is meant to come back marked bad, not
to take the endpoint down, so a single operator typo cannot hide the health of
every other scheduler behind a 500.

Python 3.14 made ``urlparse`` raise ``ValueError: Invalid IPv6 URL`` on
malformed IPv6 authorities, which the scheme check parsed before validating.
On 3.11 to 3.13 those same inputs parse to an empty scheme and are rejected by
the existing branch, so this file pins the contract on every supported runtime
rather than the behaviour of one.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from z4j_brain.api.schedulers_fleet import _info_schema_error, _probe_scheduler

# Malformed IPv6 authorities. urlparse raises on these from 3.14 onward.
_UNPARSEABLE = [
    "http://[::1]extra/info",
    "http://[::1",
    "https://[not-an-address]junk",
]

# Wrong-scheme entries the probe has always rejected before issuing a GET.
_REFUSED_SCHEMES = [
    "file:///etc/passwd",
    "ftp://example.com",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _UNPARSEABLE)
async def test_unparseable_url_is_reported_not_raised(url: str) -> None:
    # A client that would explode if touched: a rejected URL must never be
    # fetched, so reaching the transport at all is a failure.
    entry = await _probe_scheduler(_ExplodingClient(), url)

    assert entry.ok is False
    assert entry.url == url
    assert entry.error


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _REFUSED_SCHEMES)
async def test_non_http_scheme_is_still_refused_before_any_request(
    url: str,
) -> None:
    entry = await _probe_scheduler(_ExplodingClient(), url)

    assert entry.ok is False
    assert "http" in (entry.error or "")


def _valid_info_payload() -> dict[str, Any]:
    return {
        "version": "1.9.0",
        "instance_id": "scheduler-a",
        "uptime_seconds": 12.5,
        "started_at": "2026-08-12T12:00:00+00:00",
        "ready": True,
        "subsystems": {
            "brain_client_connected": True,
            "cache_initial_sync_complete": True,
            "leader_gate_initialised": True,
            "compatible_extension": {"state": "ready"},
        },
        "schedules_loaded": 3,
        "compatible_extension": "preserved",
    }


@pytest.mark.asyncio
async def test_valid_info_schema_is_healthy_and_preserves_extensions() -> None:
    payload = _valid_info_payload()

    entry = await _probe_scheduler(_ResponseClient(payload), "https://scheduler.example")

    assert entry.ok is True
    assert entry.info == payload
    assert entry.error is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "error_fragment"),
    [
        (lambda payload: payload.pop("version"), "version"),
        (lambda payload: payload.update(ready="yes"), "ready"),
        (lambda payload: payload.update(schedules_loaded=True), "schedules_loaded"),
        (lambda payload: payload.update(subsystems={}), "subsystems"),
    ],
)
async def test_invalid_info_schema_is_not_counted_healthy(
    mutation,
    error_fragment: str,
) -> None:
    payload = _valid_info_payload()
    mutation(payload)

    entry = await _probe_scheduler(_ResponseClient(payload), "https://scheduler.example")

    assert entry.ok is False
    assert entry.info is None
    assert "invalid /info schema" in (entry.error or "")
    assert error_fragment in (entry.error or "")


@pytest.mark.parametrize("uptime", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_uptime_is_rejected_before_model_validation(uptime: float) -> None:
    payload = _valid_info_payload()
    payload["uptime_seconds"] = uptime

    assert _info_schema_error(payload) == "uptime_seconds must be a non-negative number"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        httpx.TimeoutException(
            "timed out",
            request=httpx.Request("GET", "https://scheduler.example/info"),
        ),
        httpx.ConnectError(
            "connection refused",
            request=httpx.Request("GET", "https://scheduler.example/info"),
        ),
    ],
)
async def test_transport_failure_means_no_response(exc: httpx.HTTPError) -> None:
    entry = await _probe_scheduler(_RaisingClient(exc), "https://scheduler.example")

    assert entry.ok is None
    assert entry.info is None
    assert entry.error


class _ResponseClient:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def get(self, *args: object, **kwargs: object) -> httpx.Response:
        return httpx.Response(200, json=self._payload)


class _RaisingClient:
    def __init__(self, exc: httpx.HTTPError) -> None:
        self._exc = exc

    async def get(self, *args: object, **kwargs: object) -> object:
        raise self._exc


class _ExplodingClient:
    """Stands in for httpx.AsyncClient and fails loudly if used."""

    async def get(self, *args: object, **kwargs: object) -> object:
        raise AssertionError(
            "probe issued a request for a URL it should have rejected",
        )
