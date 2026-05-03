"""Top-level error middleware.

Catches every exception that escapes a route handler, maps the known
:class:`z4j_core.errors.Z4JError` subclasses to HTTP status codes via
:func:`z4j_brain.errors.http_status_for`, and renders a stable JSON
shape. Pydantic ``ValidationError`` is mapped to 422 with a redacted
summary that does NOT echo the offending input value.

In production this middleware NEVER includes a stack trace in the
response body. The full traceback is logged with the request id so
operators can correlate.

Audit fix AU-1/AU-2 (Apr 2026 follow-up): denials and validation
failures on schedule endpoints leave an audit-log breadcrumb so
brute-force IDOR enumeration attempts have a forensic trail. Pre-fix
a 403/422 left zero evidence behind beyond a structured log line
(non-tamper-evident, easily filtered out of an attacker-prepared
log aggregator). Post-fix the row lands in the tamper-evident
``audit_log`` table that is HMAC-chained.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

import structlog
from pydantic import ValidationError as PydanticValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from z4j_brain.errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    Z4JError,
    http_status_for,
)

logger = structlog.get_logger("z4j.brain.errors")


# Audit fix AU-1/AU-2 (Apr 2026 follow-up): match the path prefixes
# we want to record denials for. Currently scheduler-adjacent
# endpoints (the IDOR enumeration target identified by the audit).
# Add additional prefixes here as new sensitive surfaces ship.
_AUDITED_PATH_RE = re.compile(
    r"^/api/v\d+/projects/(?P<slug>[a-z0-9_\-]+)/schedules",
    re.IGNORECASE,
)

# Methods we audit denials/validation failures for. Read paths
# (GET / HEAD) leave too much noise in the audit log without
# operational value.
_AUDITED_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH", "DELETE",
})


class ErrorMiddleware(BaseHTTPMiddleware):
    """Catch unhandled exceptions and return a structured JSON response."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            return await call_next(request)
        except Z4JError as exc:
            await _record_denial_if_relevant(request, exc=exc)
            return _z4j_error_response(request, exc)
        except PydanticValidationError as exc:
            await _record_denial_if_relevant(request, exc=exc)
            return _pydantic_validation_response(request, exc)
        except Exception as exc:  # noqa: BLE001
            return _unexpected_error_response(request, exc)


async def _record_denial_if_relevant(
    request: Request,
    *,
    exc: BaseException,
) -> None:
    """Best-effort denial-audit enqueue.

    Audit fix AU-1/AU-2 (Apr 2026 follow-up). Catches:

    - ``AuthorizationError`` (403)  → ``schedules.access.denied``
    - ``AuthenticationError`` (401) → ``schedules.access.unauth``
    - ``NotFoundError`` (404)       → ``schedules.access.not_found``
    - ``ValidationError`` / Pydantic ValidationError (422)
                                    → ``schedules.access.invalid``

    Round-4 audit fix (Apr 2026): the previous implementation
    opened a NEW DB session synchronously inside the request scope
    to write the audit row. Under attack (IDOR enumeration), every
    4xx doubled the per-request connection demand and could
    starve the connection pool, turning the audit safety net into
    a self-DoS amplifier. Now: enqueue a fire-and-forget event
    on a bounded async queue; a single background drain task
    persists the row using its own session at its own pace. The
    queue drops the oldest event on overflow rather than blocking
    the request handler.

    Skipped silently when:

    - The path doesn't match the audited prefix
    - The method is GET/HEAD (read-only - no mutation intent)
    - The audit queue isn't on app.state (unit-test harness,
      embedded tooling)
    """
    if request.method not in _AUDITED_METHODS:
        return
    match = _AUDITED_PATH_RE.match(request.url.path)
    if not match:
        return

    audit_queue = getattr(request.app.state, "audit_queue", None)
    if audit_queue is None:
        return

    if isinstance(exc, AuthorizationError):
        action = "schedules.access.denied"
        outcome = "deny"
    elif isinstance(exc, AuthenticationError):
        action = "schedules.access.unauth"
        outcome = "deny"
    elif isinstance(exc, NotFoundError):
        action = "schedules.access.not_found"
        outcome = "deny"
    elif isinstance(exc, (ValidationError, PydanticValidationError)):
        action = "schedules.access.invalid"
        outcome = "error"
    else:
        return

    from datetime import UTC, datetime  # noqa: PLC0415

    from z4j_brain.middleware._audit_queue import (  # noqa: PLC0415
        DenialAuditEvent,
    )

    user = getattr(request.state, "current_user", None)
    user_id: UUID | None = getattr(user, "id", None) if user else None

    audit_queue.enqueue(
        DenialAuditEvent(
            action=action,
            target_type="schedule_endpoint",
            target_id=request.url.path[:200],
            outcome=outcome,
            user_id=user_id,
            project_slug=match.group("slug"),
            source_ip=getattr(request.state, "real_client_ip", None),
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            error_class=type(exc).__name__,
            message=str(exc),
            occurred_at=datetime.now(UTC),
        ),
    )


def _z4j_error_response(request: Request, exc: Z4JError) -> JSONResponse:
    status = http_status_for(exc)
    request_id = getattr(request.state, "request_id", None)

    logger.warning(
        "z4j request failed",
        error_code=exc.code,
        error_class=type(exc).__name__,
        status=int(status),
        path=request.url.path,
    )

    body: dict[str, Any] = {
        "error": exc.code,
        "message": exc.message,
        "request_id": request_id,
        "details": _safe_details(exc.details),
    }
    return JSONResponse(content=body, status_code=int(status))


def _pydantic_validation_response(
    request: Request,
    exc: PydanticValidationError,
) -> JSONResponse:
    """Map a Pydantic ValidationError to a redacted 422.

    The summary lists each error's location and type but NOT its
    input value - the input may contain caller-supplied secrets and
    we don't want them in our error responses or our log lines.
    """
    request_id = getattr(request.state, "request_id", None)
    summary = [
        {
            "loc": ".".join(str(p) for p in err["loc"]),
            "type": err["type"],
        }
        for err in exc.errors()
    ]
    logger.info(
        "z4j request validation failed",
        error_count=len(summary),
        path=request.url.path,
    )
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_failed",
            "message": f"request body failed validation ({len(summary)} field(s))",
            "request_id": request_id,
            "details": {"errors": summary},
        },
    )


def _unexpected_error_response(
    request: Request,
    exc: BaseException,
) -> JSONResponse:
    """Map any unhandled exception to a generic 500.

    The exception type is logged with the full traceback for the
    operator. The HTTP response intentionally exposes nothing about
    the cause beyond a request id - even the exception class name
    is withheld, since some libraries put secrets in their class
    names (RuntimeError("missing token sk_live_...")).
    """
    request_id = getattr(request.state, "request_id", None)
    logger.error(
        "z4j unhandled exception",
        error_class=type(exc).__name__,
        path=request.url.path,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": "the brain encountered an unexpected error",
            "request_id": request_id,
            "details": {},
        },
    )


def _safe_details(details: Any) -> dict[str, Any]:
    """Coerce ``Z4JError.details`` to a JSON-safe dict.

    The dict is shallow-copied so the caller's mutable details
    object cannot be observed by a malicious response interceptor.
    """
    if not isinstance(details, dict):
        return {}
    return {str(k): v for k, v in details.items()}


__all__ = ["ErrorMiddleware"]
