"""Request-id middleware.

Reads the inbound ``X-Request-Id`` header (or generates a fresh
ULID-style id if absent), binds it to the structlog context for the
duration of the request, echoes it on the response, and stashes it on
``request.state.request_id`` for handlers that want to log it
themselves.

The id is exposed in error responses so users can include it in bug
reports - operators then grep their structured logs by ``request_id``
to find the matching server-side trace.
"""

from __future__ import annotations

import secrets

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_HEADER = "x-request-id"
_STATE_KEY = "request_id"
_MAX_LEN = 64


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Inject ``X-Request-Id`` into request scope, structlog, and response.

    A caller-supplied id is preserved if it is well-formed
    (printable ASCII, ≤ 64 characters). Anything else is replaced
    with a fresh server-generated id - we never echo arbitrary
    untrusted bytes back into log records or response headers.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        incoming = request.headers.get(_HEADER)
        request_id = _normalize(incoming) or _generate()

        request.state.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()

        response.headers[_HEADER] = request_id
        return response


def _generate() -> str:
    """Return a fresh request id (16 hex chars from ``secrets``)."""
    return f"req_{secrets.token_hex(8)}"


def _normalize(value: str | None) -> str | None:
    """Validate a caller-supplied request id, or return None.

    Accepts only printable ASCII (no spaces or control characters)
    up to 64 characters. The point is to keep log records and
    response headers safe from header-injection / log-poisoning.
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped or len(stripped) > _MAX_LEN:
        return None
    if not all(0x21 <= ord(c) <= 0x7E for c in stripped):
        return None
    return stripped


__all__ = ["RequestIdMiddleware"]
