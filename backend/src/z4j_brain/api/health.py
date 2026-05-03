"""Health and readiness endpoints.

Two endpoints:

- ``/api/v1/health`` - liveness probe. Returns ``200 OK`` as long as
  the process is up. No I/O. Used by ``docker healthcheck``.
- ``/api/v1/health/ready`` - readiness probe. Runs ``SELECT 1``
  against the database with a short timeout. Returns ``200`` only
  when the brain can serve traffic. Used by orchestrators (k8s,
  Nomad, Compose) before sending real requests.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import text

from z4j_brain import __version__
from z4j_brain.api.deps import get_current_user, get_db
from z4j_brain.persistence.database import DatabaseManager

router = APIRouter(tags=["health"])

#: Hard timeout (seconds) on the readiness DB ping.
_READINESS_DB_TIMEOUT_S: float = 2.0


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe. No I/O.

    Returns ``200 OK`` with the build version. The point is to give
    container runtimes something cheap and reliable to poll: a
    process that can answer this endpoint is process-alive.
    """
    return {"status": "ok", "version": __version__}


@router.get("/health/ready")
async def health_ready(
    request: Request,
    response: Response,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, str]:
    """Readiness probe. Issues ``SELECT 1`` with a hard timeout.

    Returns ``200 OK`` if the database is reachable, ``503`` if it
    is not. Never raises - the response object is mutated in place.

    Round-8 audit fix R8-Bootstrap-MED (Apr 2026): also gate on
    ``app.state.lifespan_ready``. Pre-fix the brain returned 200
    the moment uvicorn bound the port, but lifespan startup
    (run_first_boot_check, registry.start, supervisor.start)
    runs AFTER the routes are mounted, so a k8s readiness probe
    flipped "ready" while the brain was still pre-bootstrap. The
    flag is set at the END of the lifespan startup phase in
    main.py.
    """
    if not getattr(request.app.state, "lifespan_ready", False):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unready", "reason": "starting"}
    try:
        async with db.session() as session:
            await asyncio.wait_for(
                session.execute(text("SELECT 1")),
                timeout=_READINESS_DB_TIMEOUT_S,
            )
    except (TimeoutError, Exception):  # noqa: BLE001
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unready", "reason": "database"}

    return {"status": "ready", "version": __version__}


@router.get("/health/system")
async def health_system(
    db: DatabaseManager = Depends(get_db),
    _user: object = Depends(get_current_user),
) -> dict[str, object]:
    """System information for the dashboard settings page.

    Requires authentication - exposes database version, Python
    version, and package details that should not be public.
    """
    import os
    import platform
    import sys

    info: dict[str, object] = {
        "z4j_version": __version__,
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "pid": os.getpid(),
    }

    # Database info.
    try:
        async with db.session() as session:
            bind = session.get_bind()
            dialect = bind.dialect.name
            info["database_type"] = dialect

            if dialect == "postgresql":
                result = await session.execute(text("SELECT version()"))
                row = result.scalar_one_or_none()
                if row:
                    info["database_version"] = str(row).split(",")[0]

                result = await session.execute(
                    text("SELECT pg_database_size(current_database())"),
                )
                db_size = result.scalar_one_or_none()
                if db_size:
                    info["database_size_mb"] = round(int(db_size) / 1_048_576, 1)

                result = await session.execute(
                    text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"),
                )
                info["database_connections"] = result.scalar_one_or_none()
            elif dialect == "sqlite":
                info["database_version"] = "SQLite"
    except Exception:  # noqa: BLE001
        info["database_type"] = "unknown"
        info["database_error"] = "failed to query database info"

    # Package versions.
    try:
        import importlib.metadata as im

        packages = {}
        for pkg in ["fastapi", "uvicorn", "sqlalchemy", "pydantic", "celery"]:
            try:
                packages[pkg] = im.version(pkg)
            except im.PackageNotFoundError:
                pass
        info["packages"] = packages
    except Exception:  # noqa: BLE001
        pass

    return info


__all__ = ["router"]
