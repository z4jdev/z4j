"""Host header validation middleware.

Rejects requests whose ``Host`` header is not in
``settings.allowed_hosts``. Defends against:

- **Cache poisoning** - an attacker who can hit the brain with a
  spoofed ``Host: evil.example.com`` could otherwise cause the
  brain to bake links pointing at ``evil.example.com`` into
  responses (the dashboard reads ``settings.public_url``, but
  password-reset emails or webhooks built from request URL would
  be vulnerable).
- **Routing leakage** - same threat for any future feature that
  uses ``request.url`` to build absolute URLs.

In ``environment="dev"`` we add ``localhost`` and ``127.0.0.1``
automatically so contributors do not have to set the env var to
run the test suite.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.host_validation")

#: Always-allowed hosts in dev mode (in addition to the configured
#: list). Tests do not have to set ``allowed_hosts``.
_DEV_DEFAULTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "[::1]", "testserver"},
)


class HostValidationMiddleware(BaseHTTPMiddleware):
    """Reject requests with an unrecognised Host header.

    Strips the optional port suffix before comparing - operators
    configure ``allowed_hosts=["z4j.example.com"]``, NOT
    ``["z4j.example.com:7700"]``.
    """

    def __init__(self, app, *, settings: Settings) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        import os as _os

        is_dev = settings.environment == "dev"
        configured = {h.lower() for h in settings.allowed_hosts}
        if is_dev:
            configured |= _DEV_DEFAULTS
        self._allowed: frozenset[str] = frozenset(configured)
        self._dev = is_dev
        # Frozen public list (preserve original case + order from settings)
        # used in the rejection payload so operators see exactly what's
        # whitelisted, not a lowercased+reordered version.
        self._allowed_display: tuple[str, ...] = tuple(settings.allowed_hosts)
        # Opt-in debug mode. Off by default. Only honored when dev mode
        # is also active - a `Z4J_DEBUG_HOST_ERRORS=1` in a production
        # env does nothing (the startup check in cli.py refuses it too,
        # but belt + suspenders).
        self._debug_errors = (
            is_dev
            and _os.environ.get("Z4J_DEBUG_HOST_ERRORS", "").lower()
            in ("1", "true", "yes", "on")
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        host_header = request.headers.get("host", "")
        host = self._strip_port(host_header).lower()
        if host and host not in self._allowed:
            # Operator-facing log: ALWAYS verbose. The operator runs
            # `z4j serve` (and watches stderr / journalctl / docker
            # logs); leaking detail to that surface is fine because it
            # is operator-only. The HTTP response below is ALWAYS
            # minimal because the operator does not control who can
            # reach the brain - reverse proxies, Cloudflare Tunnels,
            # public DNS pointed at a homelab, scanners probing port
            # 7700 - all of those make the HTTP response a public
            # surface no matter what `environment` we're in.
            logger.info(
                "z4j: rejected request - Host header %r is not in the "
                "allow-list. Persist it via `z4j allowed-hosts add %s` "
                "or restart with `z4j serve --allowed-host %s`. Current "
                "allow-list: %s",
                host_header,
                host,
                host,
                list(self._allowed_display),
            )
            return self._build_rejection(request, host)
        return await call_next(request)

    def _build_rejection(self, request: Request, host: str) -> JSONResponse:
        """Build the 400 response body.

        Default: minimal - no rejected host, no allow-list, no fix
        command. Internal hostnames, LAN IPs, Tailscale node names,
        and ready-to-paste env-var values must never leak through the
        wire to anyone who can hit the brain.

        Operators correlate this 400 with the verbose INFO log line
        emitted above, via the ``request_id`` field. The log surface
        is operator-only (terminal stderr / ``journalctl`` / container
        logs); no scanner, crawler, or attacker has read access to it.

        Verbose behavior can be opted into for local development via
        ``z4j serve --debug-host-errors`` (sets
        ``Z4J_DEBUG_HOST_ERRORS=1``). This is refused outside dev mode
        by the CLI, and even in dev mode it prints a loud warning at
        startup so the operator knows they've lowered their guard.
        Recommended for ``z4j serve`` bound to ``127.0.0.1`` only.

        Earlier 1.0.6/1.0.7 included the verbose ``details`` block
        unconditionally. That was a real information-disclosure bug
        because a "dev mode" gate cannot distinguish a local-laptop
        developer from a homelab-with-a-public-reverse-proxy operator
        (both run the SQLite/dev path; the latter is publicly
        reachable). Post-1.0.8 default is minimal; the opt-in is
        reserved for operators who know they're hitting the brain
        directly.
        """
        request_id = getattr(request.state, "request_id", None)
        if self._debug_errors:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_host",
                    "message": (
                        f"Host header {host!r} is not in the configured "
                        f"allow-list."
                    ),
                    "request_id": request_id,
                    "details": {
                        "rejected_host": host,
                        "allowed_hosts": list(self._allowed_display),
                        "fix": (
                            f"Persist the host: run "
                            f"`z4j allowed-hosts add {host}` and restart "
                            f"`z4j serve`."
                        ),
                    },
                },
            )
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_host",
                "message": "Bad Request: invalid Host header.",
                "request_id": request_id,
            },
        )

    @staticmethod
    def _strip_port(host: str) -> str:
        """Strip the optional port suffix.

        Handles IPv6 forms (``[::1]:7700`` → ``[::1]``) and the
        plain ``host:port`` form. Returns the host unchanged if no
        port is present.
        """
        if host.startswith("["):
            end = host.find("]")
            if end == -1:
                return host
            return host[: end + 1]
        if ":" in host:
            return host.rsplit(":", 1)[0]
        return host


__all__ = ["HostValidationMiddleware"]
