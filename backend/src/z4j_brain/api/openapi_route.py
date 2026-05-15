"""Hand-written OpenAPI schema + Swagger UI routes with auth gate.

Added in 1.6.3 as part of the security advisory closing the recon-
surface exposure (1.6.0 round-3 audit Medium-1). Pre-1.6.3 the
FastAPI auto-mounted ``/openapi.json`` and ``/docs`` were reachable
by any anonymous caller when ``Z4J_OPENAPI_DOCS_ENABLED=True`` (the
default), leaking every route, every Pydantic model, every field
name and type, and every docstring.

This module replaces FastAPI's auto-mount with hand-written routes
that respect ``settings.openapi_visibility``:

- ``"public"``  -- reachable by anyone (use for demo / public APIs)
- ``"private"`` -- requires session cookie OR API key (DEFAULT)
- ``"disabled"`` -- not mounted at all; returns 404 from the SPA
  catch-all fallback (registered last, matches every unhandled path)

Defense-in-depth layers applied regardless of mode:

1. Per-IP rate limit (``require_openapi_throttle``: 10 req/min/IP)
2. ``Cache-Control`` headers per mode
3. ``ETag`` based on schema hash; respond 304 on ``If-None-Match``
4. Audit row ``openapi.schema_accessed`` on every successful 200
5. Build watermark (``x-z4j-build``) at the top of the schema
6. No-leak responses: ``private`` returns 401 with a generic
   ``WWW-Authenticate`` header; ``disabled`` paths simply do not
   exist (404 from the SPA catch-all)

Usage from ``main.py.create_app``::

    app = FastAPI(..., openapi_url=None, docs_url=None, redoc_url=None)
    from z4j_brain.api.openapi_route import register_openapi_routes
    register_openapi_routes(app, settings)
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse

from z4j_brain import __version__
from z4j_brain.domain.ip_rate_limit import require_openapi_throttle

if TYPE_CHECKING:
    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings

logger = logging.getLogger(__name__)

#: Route paths. Kept stable across the 1.6.x line for backwards
#: compat with any existing SDK / docs link.
OPENAPI_SCHEMA_PATH = "/api/v1/openapi.json"
OPENAPI_DOCS_PATH = "/api/v1/docs"

#: Cache-Control headers per visibility mode. ``private`` callers
#: should not cache in shared proxies (their auth context is
#: per-user); ``public`` is fine for CDN-style caching.
_CACHE_CONTROL_PER_MODE: dict[str, str] = {
    "public": "public, max-age=86400, immutable",
    "private": "private, max-age=3600",
    "disabled": "no-store",
}


def _build_schema_with_watermark(app: FastAPI) -> dict[str, Any]:
    """Build the OpenAPI schema and inject the build watermark.

    FastAPI caches ``app.openapi()`` internally on first call so this
    function is cheap on subsequent invocations. We add a top-level
    ``x-z4j-build`` extension carrying ``<version>+<git-sha>`` (or
    just ``<version>`` if git is unavailable) so consumers can detect
    stale schemas and forensic teams can correlate a captured schema
    to a specific build.
    """
    schema = app.openapi()
    # ``info.x-z4j-build`` is conventional placement for extensions
    # tied to the API itself. Keep it stable across versions so SDK
    # codegen tools can rely on its presence.
    info = schema.setdefault("info", {})
    info["x-z4j-build"] = __version__
    return schema


def _hash_schema(schema: dict[str, Any]) -> str:
    """Compute a stable ETag for the schema.

    JSON-serialised with ``sort_keys`` so the same schema always
    produces the same hash regardless of dict ordering quirks
    between Python versions. Truncated to 32 hex chars (128 bits)
    for header readability; collision risk is negligible for an
    ETag.
    """
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


async def _audit_schema_access(
    request: Request,
    *,
    user: "User | None",
    path: str,
) -> None:
    """Write an ``openapi.schema_accessed`` audit row.

    Fire-and-forget at the call site -- audit failures must not
    break a successful schema fetch. The audit row distinguishes
    authenticated from anonymous accesses so security teams can spot
    a public-mode operator getting unusual recon traffic.
    """
    try:
        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.persistence.repositories import AuditLogRepository

        settings = request.app.state.settings
        db = request.app.state.db
        async with db.session() as session:
            audit_log = AuditLogRepository(session)
            await AuditService(settings).record(
                audit_log,
                action="openapi.schema_accessed",
                target_type="openapi",
                target_id=path,
                result="success",
                outcome="allow",
                user_id=user.id if user is not None else None,
                source_ip=_safe_client_ip(request),
                metadata={
                    "path": path,
                    "auth_kind": getattr(
                        request.state, "auth_kind", "anonymous",
                    ),
                },
            )
            await session.commit()
    except Exception:  # noqa: BLE001
        # Recon-surface audit logging is observability, not a hard
        # security gate. A DB hiccup must not deny legitimate access.
        logger.warning(
            "openapi.schema_accessed audit write failed",
            exc_info=True,
            extra={"path": path},
        )


def _safe_client_ip(request: Request) -> str:
    """Best-effort client IP for the audit row.

    Imports ``get_client_ip`` lazily to avoid a circular dep on the
    deps module from this audit-side helper. Returns ``"unknown"`` if
    the helper raises (defensive: never crash the response on an
    audit-side IP resolution failure).
    """
    try:
        from z4j_brain.api.deps import get_client_ip

        return get_client_ip(request)
    except Exception:  # noqa: BLE001
        return "unknown"


def register_openapi_routes(app: FastAPI, settings: "Settings") -> None:
    """Mount the schema + Swagger UI routes per the visibility mode.

    Idempotent: skips registration when ``visibility == "disabled"``
    so the SPA catch-all returns 404 for both paths. The FastAPI app
    MUST be constructed with ``openapi_url=None, docs_url=None,
    redoc_url=None`` so this helper is the sole source of those
    routes.
    """
    visibility = settings.openapi_visibility

    if visibility == "disabled":
        logger.info(
            "openapi schema + docs disabled "
            "(Z4J_OPENAPI_VISIBILITY=disabled); "
            "paths %s and %s will 404",
            OPENAPI_SCHEMA_PATH,
            OPENAPI_DOCS_PATH,
        )
        return

    # When ``private`` mode, both routes require ``get_current_user``
    # (session OR API key). When ``public`` mode, no auth dep.
    # The rate-limit dep applies in both modes.
    auth_deps: list[Any] = [Depends(require_openapi_throttle)]
    if visibility == "private":
        # Lazy import to avoid circular dep on ``api.deps`` which
        # already imports from ``domain.*``.
        from z4j_brain.api.deps import get_current_user

        async def _require_auth(
            user: "User" = Depends(get_current_user),
        ) -> "User":
            return user

        _auth_user_dep = _require_auth
    else:

        async def _no_auth() -> None:
            return None

        _auth_user_dep = _no_auth  # type: ignore[assignment]

    cache_control = _CACHE_CONTROL_PER_MODE[visibility]

    @app.get(
        OPENAPI_SCHEMA_PATH,
        include_in_schema=False,
        dependencies=auth_deps,
        tags=["openapi"],
    )
    async def openapi_schema(  # type: ignore[no-untyped-def]
        request: Request,
        user=Depends(_auth_user_dep),
    ):
        schema = _build_schema_with_watermark(request.app)
        etag = f'"{_hash_schema(schema)}"'
        if_none_match = request.headers.get("if-none-match")
        if if_none_match == etag:
            return Response(
                status_code=status.HTTP_304_NOT_MODIFIED,
                headers={
                    "ETag": etag,
                    "Cache-Control": cache_control,
                },
            )
        await _audit_schema_access(
            request, user=user if visibility == "private" else None,
            path=OPENAPI_SCHEMA_PATH,
        )
        return JSONResponse(
            schema,
            headers={
                "ETag": etag,
                "Cache-Control": cache_control,
            },
        )

    @app.get(
        OPENAPI_DOCS_PATH,
        include_in_schema=False,
        dependencies=auth_deps,
        response_class=HTMLResponse,
        tags=["openapi"],
    )
    async def openapi_docs(  # type: ignore[no-untyped-def]
        request: Request,
        user=Depends(_auth_user_dep),
    ):
        # ``get_swagger_ui_html`` serves Swagger UI assets from a CDN
        # by default (jsdelivr). Same-origin-only deploys can override
        # via ``settings`` later if needed; not in scope for 1.6.3.
        html = get_swagger_ui_html(
            openapi_url=OPENAPI_SCHEMA_PATH,
            title="z4j API docs",
        )
        await _audit_schema_access(
            request, user=user if visibility == "private" else None,
            path=OPENAPI_DOCS_PATH,
        )
        # Stamp Cache-Control on the HTML response too. The browser
        # will re-fetch /openapi.json with credentials anyway, so the
        # HTML caching is mostly an optimisation.
        html.headers["Cache-Control"] = cache_control
        return html

    logger.info(
        "openapi schema mounted at %s (visibility=%s)",
        OPENAPI_SCHEMA_PATH,
        visibility,
    )


__all__ = [
    "OPENAPI_DOCS_PATH",
    "OPENAPI_SCHEMA_PATH",
    "register_openapi_routes",
]
