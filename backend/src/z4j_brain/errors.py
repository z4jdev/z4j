"""Brain-side error mapping.

Every brain exception is a :class:`z4j_core.errors.Z4JError` subclass -
the agent and brain share one exception language. The brain does not
define its own duplicate hierarchy; it imports the canonical types
from ``z4j_core.errors`` and adds an HTTP status mapping for the
``ErrorMiddleware``.

Add a new mapping here whenever a new brain-relevant exception is
introduced upstream.
"""

from __future__ import annotations

from http import HTTPStatus

from z4j_core.errors import (
    AdapterError,
    AgentOfflineError,
    AuthenticationError,
    AuthorizationError,
    CommandTimeoutError,
    ConfigError,
    ConflictError,
    InvalidFrameError,
    NotFoundError,
    ProtocolError,
    RateLimitExceeded,
    RedactionConfigError,
    SignatureError,
    ValidationError,
    Z4JError,
)


_STATUS_MAP: dict[type[Z4JError], HTTPStatus] = {
    ValidationError: HTTPStatus.UNPROCESSABLE_ENTITY,
    InvalidFrameError: HTTPStatus.UNPROCESSABLE_ENTITY,
    AuthenticationError: HTTPStatus.UNAUTHORIZED,
    SignatureError: HTTPStatus.UNAUTHORIZED,
    AuthorizationError: HTTPStatus.FORBIDDEN,
    NotFoundError: HTTPStatus.NOT_FOUND,
    ConflictError: HTTPStatus.CONFLICT,
    RateLimitExceeded: HTTPStatus.TOO_MANY_REQUESTS,
    AgentOfflineError: HTTPStatus.SERVICE_UNAVAILABLE,
    CommandTimeoutError: HTTPStatus.GATEWAY_TIMEOUT,
    ProtocolError: HTTPStatus.UPGRADE_REQUIRED,
    AdapterError: HTTPStatus.BAD_GATEWAY,
    ConfigError: HTTPStatus.INTERNAL_SERVER_ERROR,
    RedactionConfigError: HTTPStatus.INTERNAL_SERVER_ERROR,
}


def http_status_for(exc: Z4JError) -> HTTPStatus:
    """Return the HTTP status code for a Z4JError instance.

    Walks the MRO so subclasses inherit their parent's mapping. Falls
    back to ``500 Internal Server Error`` for anything unmapped, which
    is also the safest default for unknown subclasses.
    """
    for cls in type(exc).__mro__:
        if cls in _STATUS_MAP:
            return _STATUS_MAP[cls]
    return HTTPStatus.INTERNAL_SERVER_ERROR


__all__ = [
    "AdapterError",
    "AgentOfflineError",
    "AuthenticationError",
    "AuthorizationError",
    "CommandTimeoutError",
    "ConfigError",
    "ConflictError",
    "InvalidFrameError",
    "NotFoundError",
    "ProtocolError",
    "RateLimitExceeded",
    "RedactionConfigError",
    "SignatureError",
    "ValidationError",
    "Z4JError",
    "http_status_for",
]
