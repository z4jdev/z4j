"""Real client IP middleware.

Resolves the real client IP using the trusted-proxy resolver and
attaches it to ``request.state.client_ip``. Subsequent middleware
and handlers read it from there - they never look at
``request.client.host`` directly.

Runs BEFORE :class:`RequestIdMiddleware` so the request id binding
context already has the resolved IP available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    from z4j_brain.auth.ip import TrustedProxyResolver


class RealClientIPMiddleware(BaseHTTPMiddleware):
    """Attach the resolved client IP to ``request.state.client_ip``.

    Holds a reference to the :class:`TrustedProxyResolver` so it
    can apply the operator-configured trusted-proxy CIDRs. The
    resolver is constructed once at app startup.
    """

    def __init__(self, app, *, resolver: TrustedProxyResolver) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._resolver = resolver

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        peer_ip = request.client.host if request.client else None
        xff = request.headers.get("x-forwarded-for")
        request.state.client_ip = self._resolver.resolve(
            peer_ip=peer_ip, xff_header=xff,
        )
        return await call_next(request)


__all__ = ["RealClientIPMiddleware"]
