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

import pytest
from z4j_brain.api.schedulers_fleet import _probe_scheduler

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


class _ExplodingClient:
    """Stands in for httpx.AsyncClient and fails loudly if used."""

    async def get(self, *args: object, **kwargs: object) -> object:
        raise AssertionError(
            "probe issued a request for a URL it should have rejected",
        )
