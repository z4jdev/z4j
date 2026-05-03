"""In-process per-IP token bucket rate limiter.

Use as a FastAPI ``Depends(...)`` on individual endpoints that
need IP-level throttling but aren't worth the operational cost
of an external rate-limit store. v1 scope: a single brain
process; if the brain ever scales horizontally each replica gets
its own bucket and a determined attacker can multiply N×.

Memory bound: one ``deque`` per IP per bucket name. ``_BUCKET_TTL``
prunes entries idle for >5 min so a botnet hitting random IPs
can't grow the dict unbounded.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from z4j_brain.api.deps import get_client_ip


_IP_KEY_MAX_LEN = 120
"""Audit M1: cap the length of IP-bucket keys. ``get_client_ip``
returns whatever the X-Forwarded-For middleware produced; a 10KB
forged XFF would otherwise become a 10KB dict key."""


class _IPBucket:
    """Sliding-window counter keyed by IP."""

    __slots__ = ("_window_seconds", "_max_hits", "_hits", "_lock", "_hits_since_prune")

    def __init__(self, window_seconds: int, max_hits: int) -> None:
        self._window_seconds = window_seconds
        self._max_hits = max_hits
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        # Audit M1: inline-prune counter. Without this a spoofed-
        # XFF botnet with 1M distinct IPs would grow ``_hits``
        # until OOM.
        self._hits_since_prune = 0

    async def hit(self, key: str) -> bool:
        """Record a hit for ``key``; return True if within budget."""
        # Audit M1: clamp the key so an attacker can't burn memory
        # by submitting arbitrarily long ``X-Forwarded-For`` values.
        if len(key) > _IP_KEY_MAX_LEN:
            key = key[:_IP_KEY_MAX_LEN]

        now = time.monotonic()
        cutoff = now - self._window_seconds
        async with self._lock:
            # Inline prune every 500 hits - amortized O(1) per hit,
            # linear in len(_hits) per prune pass. Guarantees
            # bounded memory without needing a background task.
            self._hits_since_prune += 1
            if self._hits_since_prune >= 500:
                self._prune_idle_locked(cutoff)
                self._hits_since_prune = 0

            dq = self._hits[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._max_hits:
                return False
            dq.append(now)
            return True

    def _prune_idle_locked(self, cutoff: float) -> None:
        """Drop keys whose newest hit is older than ``cutoff``.

        Must be called with ``_lock`` held.
        """
        stale = [
            k for k, dq in self._hits.items()
            if not dq or dq[-1] < cutoff
        ]
        for k in stale:
            del self._hits[k]

    async def prune_idle(self, idle_seconds: int = 300) -> None:
        """External prune - kept for tests / manual triggers.

        Inline pruning in ``hit()`` covers the bounded-growth
        guarantee on the hot path; this just lets tests force a
        clean state.
        """
        now = time.monotonic()
        cutoff = now - idle_seconds
        async with self._lock:
            self._prune_idle_locked(cutoff)
            self._hits_since_prune = 0


_invitation_bucket = _IPBucket(window_seconds=60, max_hits=30)
"""Throttle for ``/invitations/preview`` and ``/invitations/accept``.

30 hits per minute per IP. Generous enough that a real user
clicking around won't trip it; tight enough that token-brute-force
attempts are bottlenecked on rate even before the 256-bit token
entropy bottlenecks the attempt itself.
"""

_login_bucket = _IPBucket(window_seconds=60, max_hits=20)
"""Throttle for ``/auth/login``.

20 attempts per minute per IP. Complements (not replaces) the
per-account lockout: account-lockout prevents brute-forcing one
specific account's password, this bucket prevents credential-
stuffing across MANY accounts from one IP (where per-account
lockout wouldn't trigger for any individual account). A real
user's worst case (typo + second try) is well under 20; a
botnet hitting the same IP past 20 req/min gets shut out.
"""

_password_reset_bucket = _IPBucket(window_seconds=60, max_hits=10)
"""Throttle for ``/auth/password-reset/{request,confirm}``.

10/min/IP. Tighter than login because a legit user only needs 1-2
hits (one to request, one to confirm). Higher numbers indicate
enumeration (testing which emails have accounts) or token brute-
force attempts.
"""

_channel_test_bucket = _IPBucket(window_seconds=60, max_hits=20)
"""Throttle for the ``/channels/test`` and ``/channels/{id}/test``
preflight endpoints (audit P-3, added v1.0.14).

20/min/IP across both project + user variants. Each test fires an
external HTTP/SMTP request through validated config; the SSRF
guards block private IPs but a determined admin can still use the
endpoint as a webhook traffic generator against their own real
destinations (Slack/PagerDuty), risking provider rate-limit bans
on legitimate accounts.
"""

_channel_import_bucket = _IPBucket(window_seconds=60, max_hits=30)
"""Throttle for the ``import_from_user`` / ``import_from_project``
endpoints (audit L-3 + P-3, added v1.0.14).

30/min/IP. The frontend "Select all + Import" loop can fire N
requests in quick succession; this lets a 30-channel batch
through but stops a runaway script. Each import does config
validation including a SSRF DNS resolve.
"""

# Round-6 audit fix WS-HIGH-3 (Apr 2026): per-IP throttle on the
# agent-facing endpoints. Pre-fix the WS handshake + long-poll
# event-batch endpoints had no rate limit. A leaked or guessed
# bearer could:
#   - open thousands of WS connections (the "second connection
#     wins" only kicks the OTHER active session; doesn't prevent
#     a flood of new connections),
#   - POST 500-frame batches to /agent/events continuously, each
#     causing 500 frame parses + Pydantic validations + DB writes.
# 600/min/IP allows a fleet of ~10 agents per IP doing 1 connect
# per second of churn (well above any realistic operation) and
# blocks credential-flood attempts.
_agent_connect_bucket = _IPBucket(window_seconds=60, max_hits=600)
"""Throttle for ``/ws/agent`` connect handshake + ``/api/v1/agent/*``
HTTP endpoints (long-poll + event ingest).

600/min/IP. A real fleet on one NAT will burst higher than for
human-facing endpoints; we size for that headroom."""

_bulk_action_bucket = _IPBucket(window_seconds=60, max_hits=10)
"""Throttle for bulk-write operations (audit P-9, added v1.0.14).

10/min/IP across bulk-delete tasks, bulk-retry, purge-queue,
schedule trigger-now, and similar admin actions that perform
expensive write work or fan out commands to agents. Each bulk
op can touch up to 10000 rows; rate-limiting prevents a buggy
script from amplifying DB load + replica lag.
"""


def _make_dependency(bucket: _IPBucket, name: str) -> Callable[..., Coroutine[Any, Any, None]]:
    async def _check(
        request: Request,  # noqa: ARG001
        ip: str = Depends(get_client_ip),
    ) -> None:
        ok = await bucket.hit(ip)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"too many requests; please try again in a minute ({name})",
            )

    return _check


require_invitation_throttle = _make_dependency(
    _invitation_bucket, "invitation",
)
require_login_throttle = _make_dependency(_login_bucket, "login")
require_password_reset_throttle = _make_dependency(
    _password_reset_bucket, "password-reset",
)
require_channel_test_throttle = _make_dependency(
    _channel_test_bucket, "channel-test",
)
require_channel_import_throttle = _make_dependency(
    _channel_import_bucket, "channel-import",
)
require_bulk_action_throttle = _make_dependency(
    _bulk_action_bucket, "bulk-action",
)
require_agent_connect_throttle = _make_dependency(
    _agent_connect_bucket, "agent-connect",
)


__all__ = [
    "_IPBucket",
    "_agent_connect_bucket",
    "_bulk_action_bucket",
    "_channel_import_bucket",
    "_channel_test_bucket",
    "_invitation_bucket",
    "_login_bucket",
    "_password_reset_bucket",
    "require_agent_connect_throttle",
    "require_bulk_action_throttle",
    "require_channel_import_throttle",
    "require_channel_test_throttle",
    "require_invitation_throttle",
    "require_login_throttle",
    "require_password_reset_throttle",
]
