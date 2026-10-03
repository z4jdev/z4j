"""One refusal row per key per interval, shared by both agent transports.

A refused agent request is answered every time, with the same close code or
status it always got, but the HMAC-chained audit row that describes the
refusal is appended once per key per interval, across the WebSocket hello
and both long-poll routes alike. Without this every refusal opened a write
session of its own: the shipped agent treats these refusals as
authentication failures and parks on its authentication backoff (10 seconds
to 10 minutes), so it writes at most one row per retry anyway, but an agent
from a release that treats them as transient retries every 1 to 30 seconds
and appends about 2,880 rows a day for as long as it runs, and an unlisted
peer needs no credential at all to be refused, so twenty addresses inside
the connect bucket's allowance could hold the single SQLite writer busy with
denial rows while legitimate audit writes and logins queued behind them.

Three records, one per refusal kind:

- :data:`IP_DENIED_ROWS`, ``auth.ip_denied`` rows of the agent surface,
  keyed on the resolved address (the check runs before the bearer, so the
  address is the only fact the row carries);
- :data:`PROJECT_INACTIVE_ROWS`, ``agent.auth.project_inactive`` rows,
  keyed on the agent id;
- :data:`BEARER_FAILED_ROWS`, ``agent.auth.bearer_failed`` rows of the
  WebSocket hello, keyed on the resolved address (nothing was
  authenticated, so again the address is the key).

The first two are shared by the WebSocket gateway and the long-poll routes:
one row per address or per agent per interval whichever transport the agent
uses, and a refusal on one transport inside the interval of the other's row
writes nothing. The exact count of refusals stays in the metrics
(``z4j_auth_ip_denied_total{surface="agent"}``) and in the gateway's log
line, which are recorded whether or not a row is written.

Process-local, like the session registry and the rate-limit buckets: in a
multi-worker deployment each worker records its own first refusal, which
bounds the rate at one row per worker per interval rather than one per
request. The clock is :func:`now`, ``time.monotonic`` based, factored so a
test can drive it by hand on this module and move both transports at once.
"""

from __future__ import annotations

import time
from collections import OrderedDict

#: Matches the longest step of the agent's authentication backoff.
REFUSAL_AUDIT_INTERVAL_SECONDS = 600.0
#: Keys remembered per refusal kind. Enough for every agent of a large
#: installation to be refused at once without one evicting another; a flood
#: of distinct keys evicts the oldest first and costs the flooder its own
#: dedupe, nothing else. Beyond it the behaviour is the old one, one row per
#: refusal, never a withheld refusal.
REFUSAL_AUDIT_CAPACITY = 4096


def now() -> float:
    """Monotonic dedupe clock, factored for deterministic tests."""
    return time.monotonic()


class RefusalAuditDedupe:
    """Bounded, TTL-evicted record of which key's row was written when.

    ``claim`` says whether the row for ``key`` is due and, when it is,
    marks it as written before the caller writes it, so two in-flight
    requests of one agent produce one row; ``release`` gives a claim back
    when the write failed, so the next refusal retries rather than losing
    the interval. Entries are kept in claim order, so the expired ones sit
    at the front and are dropped before the capacity bound is applied.
    Single event loop, no await between the lookup and the update, so no
    lock is needed.
    """

    __slots__ = ("_capacity", "_claimed", "_interval")

    def __init__(self, *, interval: float, capacity: int) -> None:
        self._interval = interval
        self._capacity = capacity
        self._claimed: OrderedDict[str, float] = OrderedDict()

    def claim(self, key: str, *, now: float) -> bool:
        """``True`` when no row was claimed under ``key`` within the interval."""
        while self._claimed:
            oldest_key, claimed_at = next(iter(self._claimed.items()))
            if now - claimed_at < self._interval:
                break
            del self._claimed[oldest_key]
        previous = self._claimed.get(key)
        if previous is not None and now - previous < self._interval:
            return False
        self._claimed[key] = now
        self._claimed.move_to_end(key)
        while len(self._claimed) > self._capacity:
            self._claimed.popitem(last=False)
        return True

    def release(self, key: str) -> None:
        """Forget a claim whose row was not written."""
        self._claimed.pop(key, None)

    def clear(self) -> None:
        """Forget every claim; tests reset the process-local state with this."""
        self._claimed.clear()

    def __len__(self) -> int:
        return len(self._claimed)


#: ``auth.ip_denied`` rows of the agent surface, keyed on the resolved
#: address; shared by the WebSocket hello and both long-poll routes.
IP_DENIED_ROWS = RefusalAuditDedupe(
    interval=REFUSAL_AUDIT_INTERVAL_SECONDS,
    capacity=REFUSAL_AUDIT_CAPACITY,
)
#: ``agent.auth.project_inactive`` rows, keyed on the agent id; shared by
#: the WebSocket hello and both long-poll routes.
PROJECT_INACTIVE_ROWS = RefusalAuditDedupe(
    interval=REFUSAL_AUDIT_INTERVAL_SECONDS,
    capacity=REFUSAL_AUDIT_CAPACITY,
)
#: ``agent.auth.bearer_failed`` rows of the WebSocket hello, keyed on the
#: resolved address. The long-poll routes answer a bad bearer with a plain
#: 401 and no row, so this one has a single writer.
BEARER_FAILED_ROWS = RefusalAuditDedupe(
    interval=REFUSAL_AUDIT_INTERVAL_SECONDS,
    capacity=REFUSAL_AUDIT_CAPACITY,
)

_ALL_ROWS = (IP_DENIED_ROWS, PROJECT_INACTIVE_ROWS, BEARER_FAILED_ROWS)


def clear_all() -> None:
    """Forget every claim of every kind; the test suite resets with this."""
    for rows in _ALL_ROWS:
        rows.clear()
