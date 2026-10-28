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
those are not body-size aware. A body that outgrows the cap while the
app reads it is answered 413 with the same body as the fast path. The
app cannot be trusted to pass the error through: FastAPI reports
anything raised while it reads a body as a body it could not parse
(400), so the middleware discards whatever the app answers once the cap
has been crossed and sends the 413 itself.

``route_max_bytes`` gives an exact route path its own cap. The agent
long-poll upload uses it for frames the size the WebSocket gateway
accepts. This middleware admits the larger body for anyone, so a route
listed there must answer an unauthenticated caller before it reads its
body (``agent_longpoll._AuthenticatedUploadRoute`` does).
"""

from __future__ import annotations

from collections.abc import Mapping

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Pure-ASGI middleware so we can wrap ``receive``.

    BaseHTTPMiddleware would buffer the whole body before our code
    sees it - defeating the point. We implement the ASGI protocol
    directly here.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        route_max_bytes: Mapping[str, int] | None = None,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.route_max_bytes = dict(route_max_bytes or {})

    def _max_bytes_for(self, scope: Scope) -> int:
        """The cap for this request: its route path's own, else the global one."""
        if not self.route_max_bytes:
            return self.max_bytes
        return self.route_max_bytes.get(_route_path(scope), self.max_bytes)

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
        max_bytes = self._max_bytes_for(scope)

        # Fast path - Content-Length header.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                cl = int(content_length)
            except ValueError:
                await _too_large(send, reason="invalid_content_length")
                return
            if cl > max_bytes:
                await _too_large(send, reason="content_length_exceeded")
                return

        # Streaming path - wrap receive to count incoming bytes.
        received = 0
        # Set when the cap is crossed before the app started its response;
        # from then on the answer is this middleware's 413, not the app's.
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)
                if received > max_bytes:
                    exceeded = not started
                    raise _BodyTooLargeError()
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded:
            await _too_large(send, reason="streamed_body_exceeded")


class _BodyTooLargeError(Exception):
    """Raised by ``counting_receive`` when the cap is exceeded."""


def _route_path(scope: Scope) -> str:
    """The request path without the ASGI ``root_path`` prefix.

    The same reduction Starlette's router applies before matching, so a
    ``route_max_bytes`` key matches what the router matches whether or not
    the app is mounted under a prefix.
    """
    path: str = scope.get("path", "")
    root_path: str = scope.get("root_path", "")
    if not root_path or not path.startswith(root_path):
        return path
    if path == root_path:
        return ""
    if path[len(root_path)] == "/":
        return path[len(root_path) :]
    return path


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
