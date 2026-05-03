"""HTTP security headers middleware.

Sets the standard hardening headers on every response. The header
set + values are static enough that this is a thin wrapper around
``starlette.middleware.base.BaseHTTPMiddleware`` - there is no
per-request configuration.

Headers set on EVERY response:
- ``X-Content-Type-Options: nosniff``
- ``X-Frame-Options: DENY``
- ``Referrer-Policy: strict-origin-when-cross-origin`` (default;
  ``no-referrer`` for /setup paths)
- ``Permissions-Policy: <restrictive>``
- ``Cross-Origin-Opener-Policy: same-origin``
- ``Cross-Origin-Resource-Policy: same-origin``

Conditional:
- ``Strict-Transport-Security`` only when ``environment="production"``
  AND ``public_url`` starts with ``https://``.
- ``Content-Security-Policy`` only on HTML responses (those whose
  ``Content-Type`` starts with ``text/html``).
- ``Cache-Control: no-store`` only on responses to authenticated
  paths (anything matching ``/api/v1/auth`` or ``/api/v1/setup``).

Why a separate middleware: this layer has no business logic and is
the kind of thing security teams will explicitly look for in a
review. Keeping it tiny + obvious means a reviewer can audit it in
30 seconds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    from z4j_brain.settings import Settings


_PERMISSIONS_POLICY: str = (
    "geolocation=(), microphone=(), camera=(), payment=(), "
    "usb=(), accelerometer=(), gyroscope=(), magnetometer=()"
)

_BASE_CSP: str = (
    "default-src 'self'; "
    "script-src 'self'; "
    # CSP3 split: ``style-src-elem`` governs ``<style>`` blocks
    # and ``<link rel=stylesheet>`` (the high-impact CSS-
    # injection vector for data exfiltration via attribute
    # selectors). ``style-src-attr`` governs ``style="..."``
    # attributes which Radix portals, the TanStack Router head
    # injection, and a handful of our own React ``style={}``
    # props all require.
    #
    # We keep ``'self'`` ONLY on elem so an attacker can no
    # longer inject ``<style>body{background:url(attacker/?x=)}``
    # blocks, but our own Radix dropdowns / tooltips continue
    # to work via attr. The legacy ``style-src`` fallback stays
    # permissive so older browsers (that don't understand the
    # -elem / -attr split) keep functioning.
    "style-src 'self' 'unsafe-inline'; "
    "style-src-elem 'self'; "
    "style-src-attr 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    # frame-src 'none' explicitly closes the iframe-injection
    # vector even though no current page embeds iframes
    # (R3 finding M-4 / Round-3 dashboard pass).
    "frame-src 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

_SETUP_CSP: str = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

_AUTH_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/auth",
    "/api/v1/setup",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject the brain's security header set on every response.

    Holds a reference to ``Settings`` so it can decide whether to
    emit HSTS based on environment + public_url. The decision is
    made once per request - there is no startup-time short-circuit
    because that would prevent the brain from picking up a
    setting change without a restart (good in production, bad in
    tests).
    """

    def __init__(self, app, *, settings: Settings) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)

        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Permissions-Policy", _PERMISSIONS_POLICY)
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        path = request.url.path
        if path.startswith("/setup") or path.startswith("/api/v1/setup"):
            headers["Referrer-Policy"] = "no-referrer"
        else:
            headers.setdefault(
                "Referrer-Policy",
                "strict-origin-when-cross-origin",
            )

        # Cache-Control for any auth-touching path. Defence in
        # depth - handlers can also set this directly.
        for prefix in _AUTH_PATH_PREFIXES:
            if path.startswith(prefix):
                headers["Cache-Control"] = "no-store"
                break

        # CSP for HTML responses only.
        content_type = headers.get("content-type", "")
        if content_type.startswith("text/html"):
            csp = _SETUP_CSP if path.startswith("/setup") else _BASE_CSP
            headers.setdefault("Content-Security-Policy", csp)

        # HSTS only in production HTTPS deployments.
        if (
            self._settings.environment == "production"
            and self._settings.public_url.startswith("https://")
        ):
            hsts_value = f"max-age={self._settings.hsts_max_age_seconds}"
            if self._settings.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            headers.setdefault(
                "Strict-Transport-Security",
                hsts_value,
            )

        return response


__all__ = ["SecurityHeadersMiddleware"]
