"""ASGI middleware for the brain.

The middleware order matters - see :func:`z4j_brain.main.create_app`.
This package only defines the components; the order is the app
factory's responsibility.
"""

from __future__ import annotations

from z4j_brain.middleware.body_size import BodySizeLimitMiddleware
from z4j_brain.middleware.errors import ErrorMiddleware
from z4j_brain.middleware.host_validation import HostValidationMiddleware
from z4j_brain.middleware.real_client_ip import RealClientIPMiddleware
from z4j_brain.middleware.request_id import RequestIdMiddleware
from z4j_brain.middleware.security_headers import SecurityHeadersMiddleware

__all__ = [
    "BodySizeLimitMiddleware",
    "ErrorMiddleware",
    "HostValidationMiddleware",
    "RealClientIPMiddleware",
    "RequestIdMiddleware",
    "SecurityHeadersMiddleware",
]
