"""In-process per-IP sliding-window rate limiter.

Use as a FastAPI ``Depends(...)`` on individual endpoints that
need IP-level throttling but aren't worth the operational cost
of an external rate-limit store. v1 scope: a single brain
process; if the brain ever scales horizontally each replica gets
its own window and a determined attacker can multiply Nx.

Memory bound: each limiter holds at most ``_IP_BUCKET_MAX_KEYS`` IP
keys. Stale keys are pruned periodically and whenever a new key
arrives at the cap. If every retained key is still active, the
limiter preserves their history and deterministically denies the
unseen key; it never evicts an active bucket and thereby grants an
attacker a fresh budget. The cap is per process and per limiter
object, matching this module's intentionally process-local scope.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from z4j_brain.api.deps import get_client_ip

_IP_KEY_MAX_LEN = 120
"""Audit M1: cap the length of IP-bucket keys. ``get_client_ip``
returns whatever the X-Forwarded-For middleware produced; a 10KB
forged XFF would otherwise become a 10KB dict key."""

_IP_BUCKET_MAX_KEYS = 10_000
"""Hard per-limiter cardinality cap.

Once all slots contain hits inside the rolling window, unseen IPs fail
closed until a slot becomes stale. Existing IPs retain their histories.
"""


class _IPBucket:
    """Sliding-window counter keyed by IP."""

    __slots__ = (
        "_hits",
        "_hits_since_prune",
        "_lock",
        "_max_hits",
        "_max_keys",
        "_window_seconds",
    )

    def __init__(
        self,
        window_seconds: int,
        max_hits: int,
        *,
        max_keys: int = _IP_BUCKET_MAX_KEYS,
    ) -> None:
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
            or window_seconds < 1
        ):
            raise ValueError("window_seconds must be a positive integer")
        if isinstance(max_hits, bool) or not isinstance(max_hits, int) or max_hits < 1:
            raise ValueError("max_hits must be a positive integer")
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys < 1:
            raise ValueError("max_keys must be a positive integer")
        self._window_seconds = window_seconds
        self._max_hits = max_hits
        self._max_keys = max_keys
        # Oldest most-recently-allowed hit first. This lets capacity and
        # periodic pruning remove only the stale prefix rather than scanning
        # every active IP for every unseen-IP request at saturation.
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = asyncio.Lock()
        # Inline-prune counter. Without this a spoofed-
        # XFF botnet with 1M distinct IPs would grow ``_hits``
        # until OOM.
        self._hits_since_prune = 0

    async def hit(self, key: str, *, max_hits: int | None = None) -> bool:
        """Record a hit for ``key``; return True if within budget.

        ``max_hits`` overrides the constructed cap for THIS call.
        Settings-driven throttles (the MFA verify family) read their
        cap from operator configuration at request time, while the
        bucket object itself stays import-time constructible.
        """
        allowed, _retry_after_seconds = await self.hit_with_retry_after(
            key,
            max_hits=max_hits,
        )
        return allowed

    async def hit_with_retry_after(
        self,
        key: str,
        *,
        max_hits: int | None = None,
    ) -> tuple[bool, int | None]:
        """Record a hit and return its decision plus a bounded retry delay.

        Allowed hits return ``(True, None)``. Denied hits return a retry delay
        between one second and the configured rolling-window length. The
        decision and delay are computed under the same lock so callers never
        have to inspect mutable bucket state after a rejection.
        """
        # Clamp the key so an attacker can't burn memory
        # by submitting arbitrarily long ``X-Forwarded-For`` values.
        if len(key) > _IP_KEY_MAX_LEN:
            key = key[:_IP_KEY_MAX_LEN]

        cap = self._max_hits if max_hits is None else max_hits
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
            raise ValueError("max_hits must be a positive integer")
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_seconds
            # Inline prune every 500 hits. The OrderedDict is sorted by each
            # key's newest allowed hit, so pruning stops at the first active
            # key instead of scanning the whole cardinality cap.
            self._hits_since_prune += 1
            if self._hits_since_prune >= 500:
                self._prune_idle_locked(cutoff)
                self._hits_since_prune = 0

            dq = self._hits.get(key)
            if dq is None:
                # A unique-IP flood can fill the table entirely inside one
                # rolling window, before periodic TTL pruning can help. At
                # the hard cap, give stale slots one immediate prune pass.
                # If all keys remain active, deny this unseen key without
                # allocating it. Evicting an active key would reset that
                # attacker's history and weaken the limiter.
                if len(self._hits) >= self._max_keys:
                    self._prune_idle_locked(cutoff)
                if len(self._hits) >= self._max_keys:
                    _oldest_key, oldest_dq = next(iter(self._hits.items()))
                    return (
                        False,
                        self._bounded_retry_after_seconds(
                            eligible_at=oldest_dq[-1] + self._window_seconds,
                            now=now,
                        ),
                    )
                dq = deque()
                self._hits[key] = dq
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= cap:
                # A runtime cap can be lower than the number of hits already
                # retained (the MFA cap is settings-driven). The request can
                # proceed only after enough of the oldest hits have expired to
                # leave at most ``cap - 1`` in the window.
                limiting_hit = dq[len(dq) - cap]
                return (
                    False,
                    self._bounded_retry_after_seconds(
                        eligible_at=limiting_hit + self._window_seconds,
                        now=now,
                    ),
                )
            dq.append(now)
            self._hits.move_to_end(key)
            return True, None

    def _bounded_retry_after_seconds(self, *, eligible_at: float, now: float) -> int:
        """Round a retry delay up and keep it inside this bucket's window."""
        return min(
            self._window_seconds,
            max(1, math.ceil(eligible_at - now)),
        )

    def _prune_idle_locked(self, cutoff: float) -> None:
        """Drop keys whose newest hit is at or before ``cutoff``.

        Must be called with ``_lock`` held.
        """
        while self._hits:
            _key, dq = next(iter(self._hits.items()))
            if dq and dq[-1] > cutoff:
                return
            self._hits.popitem(last=False)

    async def prune_idle(self, idle_seconds: int = 300) -> None:
        """External prune - kept for tests / manual triggers.

        The hard cardinality cap in ``hit()`` provides the bounded-growth
        guarantee. This method lets tests and maintenance hooks eagerly
        discard entries no newer than a caller-selected idle interval.
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

# Per-IP throttle on the agent-facing endpoints. Without this,
# a leaked or guessed bearer could:
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

_openapi_bucket = _IPBucket(window_seconds=60, max_hits=10)
"""Throttle for ``/api/v1/openapi.json`` and ``/api/v1/docs``
(added in 1.6.3 alongside the three-mode visibility setting).

10/min/IP. The schema is assembled lazily by FastAPI and is
expensive (~50ms+) even when cached at the application layer; this
caps CPU burn from a polling loop even when the caller is
authenticated. Cheap enough that legitimate SDK codegen tooling
will never trip it (codegen reads the schema once per generation,
not in a loop).
"""

_setup_bucket = _IPBucket(window_seconds=900, max_hits=5)
"""Throttle for ``POST /api/v1/setup/complete``
(added in 1.6.3 alongside the security advisory).

5 attempts per 15 minutes per IP. The setup token is 256-bit so
brute-force success odds are vanishing even without this throttle;
the value here is breaking the coupling between rate-limiting and
audit-log queries: pre-1.6.3 the only attempt budget was a
``SetupService._check_attempt_budget`` that queried the audit log
on every attempt, which would amplify load under a sustained
attack. This per-IP bucket short-circuits attempts before they
ever reach the audit-log query path.
"""

_mfa_verify_bucket = _IPBucket(window_seconds=60, max_hits=10)
"""Shared throttle for the MFA verification family.

The same per-IP, per-process bucket covers ``/auth/mfa/enroll-start``,
``/enroll-complete``, ``/verify``, and ``/disable``. It therefore limits
both code guessing and repeated sensitive MFA state changes; it is not a
distributed or per-account budget.

The TOTP verifier accepts the current 6-digit code plus the adjacent time
steps, so one random guess can match at most three of ``10^6`` values. If
all ten requests from a fresh default bucket were independent TOTP guesses
in one validity interval, the success bound is
``1 - (1 - 3 / 10^6)^10``, approximately ``0.003%``. Account lockout and
single-use counters add separate defenses. Operators can change the shared
cap via ``Z4J_MFA_VERIFICATION_RATE_PER_MIN``; every covered route consumes
from that configured budget.
"""


def _make_dependency(bucket: _IPBucket, name: str) -> Callable[..., Coroutine[Any, Any, None]]:
    async def _check(
        request: Request,
        ip: str = Depends(get_client_ip),
    ) -> None:
        ok, retry_after_seconds = await bucket.hit_with_retry_after(ip)
        if not ok:
            assert retry_after_seconds is not None
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(f"too many requests; retry in {retry_after_seconds} seconds ({name})"),
            )

    return _check


require_invitation_throttle = _make_dependency(
    _invitation_bucket,
    "invitation",
)
require_login_throttle = _make_dependency(_login_bucket, "login")
require_password_reset_throttle = _make_dependency(
    _password_reset_bucket,
    "password-reset",
)
require_channel_test_throttle = _make_dependency(
    _channel_test_bucket,
    "channel-test",
)
require_channel_import_throttle = _make_dependency(
    _channel_import_bucket,
    "channel-import",
)
require_bulk_action_throttle = _make_dependency(
    _bulk_action_bucket,
    "bulk-action",
)
require_agent_connect_throttle = _make_dependency(
    _agent_connect_bucket,
    "agent-connect",
)


async def require_mfa_verify_throttle(
    request: Request,
    ip: str = Depends(get_client_ip),
) -> None:
    """Settings-driven throttle for the MFA verify family.

    Unlike the fixed-cap dependencies below, the cap comes from
    ``Z4J_MFA_VERIFICATION_RATE_PER_MIN`` at request time -- the
    setting was documented as configurable but the bucket was
    constructed with a hardcoded 10/min, so operator configuration
    was silently ignored (round-4 LOW). Settings are read off
    ``app.state`` rather than via ``api.deps.get_settings`` to keep
    this domain module free of an api-layer import cycle; the
    default (10) is preserved when state carries no settings (unit
    tests that hit the bucket directly).
    """
    settings = getattr(request.app.state, "settings", None)
    cap = getattr(settings, "mfa_verification_rate_per_min", None)
    ok, retry_after_seconds = await _mfa_verify_bucket.hit_with_retry_after(
        ip,
        max_hits=cap if isinstance(cap, int) and cap >= 1 else None,
    )
    if not ok:
        assert retry_after_seconds is not None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(f"too many requests; retry in {retry_after_seconds} seconds (mfa-verify)"),
        )


require_openapi_throttle = _make_dependency(
    _openapi_bucket,
    "openapi",
)
require_setup_throttle = _make_dependency(
    _setup_bucket,
    "setup-complete",
)


__all__ = [
    "_IPBucket",
    "_agent_connect_bucket",
    "_bulk_action_bucket",
    "_channel_import_bucket",
    "_channel_test_bucket",
    "_invitation_bucket",
    "_login_bucket",
    "_mfa_verify_bucket",
    "_openapi_bucket",
    "_password_reset_bucket",
    "_setup_bucket",
    "require_agent_connect_throttle",
    "require_bulk_action_throttle",
    "require_channel_import_throttle",
    "require_channel_test_throttle",
    "require_invitation_throttle",
    "require_login_throttle",
    "require_mfa_verify_throttle",
    "require_openapi_throttle",
    "require_password_reset_throttle",
    "require_setup_throttle",
]
