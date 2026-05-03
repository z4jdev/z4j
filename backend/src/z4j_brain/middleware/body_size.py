"""Body-size enforcement middleware.

Rejects requests whose body exceeds ``settings.max_payload_size_bytes``
BEFORE the handler reads it. This stops a single oversized POST
from consuming worker memory or CPU.

Two checks:

1. **Content-Length pre-check** - fast path. If the header is
   present and exceeds the limit, return 413 immediately.
2. **Streaming check** - defence against chunked uploads or a
   missing Content-Length. We wrap ``request.receive`` to count
   bytes as they arrive and abort the read past the limit.

The streaming check is what catches a malicious client that
omits Content-Length and streams forever. uvicorn has its own
``--limit-max-requests`` and ``--limit-concurrency`` knobs but
those are not body-size aware.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Pure-ASGI middleware so we can wrap ``receive``.

    BaseHTTPMiddleware would buffer the whole body before our code
    sees it - defeating the point. We implement the ASGI protocol
    directly here.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        # Fast path - Content-Length header.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                cl = int(content_length)
            except ValueError:
                await _too_large(send, reason="invalid_content_length")
                return
            if cl > self.max_bytes:
                await _too_large(send, reason="content_length_exceeded")
                return

        # Streaming path - wrap receive to count incoming bytes.
        received = 0
        max_bytes = self.max_bytes

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)
                if received > max_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, counting_receive, send)
        except _BodyTooLarge:
            await _too_large(send, reason="streamed_body_exceeded")


class _BodyTooLarge(Exception):
    """Raised by ``counting_receive`` when the cap is exceeded."""


async def _too_large(send: Send, *, reason: str) -> None:
    """Send a 413 response."""
    response = JSONResponse(
        status_code=413,
        content={
            "error": "payload_too_large",
            "message": "request body exceeds the configured maximum",
            "request_id": None,
            "details": {"reason": reason},
        },
    )
    await response(
        {"type": "http", "method": "POST", "headers": [], "path": ""},
        # Best-effort no-op receive - we never read the body.
        _noop_receive,
        send,
    )


async def _noop_receive() -> Message:
    return {"type": "http.disconnect"}


# Allow direct re-export of the underlying response builder for tests.
def make_too_large_response() -> Response:
    return JSONResponse(
        status_code=413,
        content={
            "error": "payload_too_large",
            "message": "request body exceeds the configured maximum",
            "request_id": None,
            "details": {},
        },
    )


__all__ = ["BodySizeLimitMiddleware", "make_too_large_response"]
