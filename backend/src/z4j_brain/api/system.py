"""Admin-scoped *system* endpoints.

1.3.4 introduces this router to host the operator-initiated *Check
for updates* button. The endpoint is intentionally narrow: it
reaches out to ``Settings.version_check_url`` (default GitHub raw
URL of the umbrella ``z4jdev/z4j`` repo's bundled ``versions.json``)
exactly once when called and replaces the brain's in-memory snapshot
with the result. There is no background polling. There is no
telemetry. The button can be hidden entirely by setting
``Z4J_VERSION_CHECK_URL`` to an empty string.

See ``z4j_brain.domain.version_check`` for the privacy posture
discussion and the parser/validator implementation.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from z4j_brain.api.auth import require_csrf
from z4j_brain.api.deps import get_settings, require_admin
from z4j_brain.errors import ConflictError, NotFoundError

if TYPE_CHECKING:
    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.api.system")

router = APIRouter(prefix="/admin/system", tags=["system"])


class VersionsSnapshotPublic(BaseModel):
    """Slim DTO of the brain's currently-cached versions snapshot."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int
    generated_at: str = Field(
        description=(
            "When the snapshot was minted (ISO-8601 UTC). For the "
            "bundled snapshot, this is the brain release date."
        ),
    )
    generated_by: str = Field(
        description=(
            "Which release minted the snapshot, "
            "e.g. ``z4j@1.4.0``."
        ),
    )
    canonical_url: str = Field(
        description=(
            "Self-reported source URL written into the snapshot at "
            "generation time. Operators can verify by visiting this "
            "URL in a browser."
        ),
    )
    packages: dict[str, str] = Field(
        description=(
            "Map of package name to latest known SemVer string."
        ),
    )
    source: str = Field(
        description=(
            "Where the brain got the snapshot from: ``bundled`` "
            "(file shipped with the brain wheel) or ``remote`` "
            "(operator-initiated *Check for updates* fetched it "
            "from ``Z4J_VERSION_CHECK_URL``)."
        ),
    )
    fetched_at: str | None = Field(
        default=None,
        description=(
            "When the operator-initiated remote refresh ran (UTC "
            "ISO-8601). Null if the brain is still on the bundled "
            "snapshot."
        ),
    )
    fetched_from: str | None = Field(
        default=None,
        description=(
            "URL the brain fetched the remote snapshot from. Null "
            "for the bundled snapshot."
        ),
    )
    check_for_updates_url: str = Field(
        description=(
            "Configured ``Z4J_VERSION_CHECK_URL``. Empty string when "
            "the operator has disabled the check; the dashboard "
            "hides the *Check for updates* button in that case."
        ),
    )


@router.get(
    "/versions",
    response_model=VersionsSnapshotPublic,
)
async def get_versions_snapshot(
    request: Request,
    admin: "User" = Depends(require_admin),  # noqa: ARG001
    settings: "Settings" = Depends(get_settings),
) -> VersionsSnapshotPublic:
    """Return the brain's currently-cached versions snapshot.

    Read-only. Used by the dashboard's Settings -> System card to
    display the snapshot's age, source, and the configured
    ``check_for_updates_url``. No network call.
    """
    return _to_public(request, settings)


@router.post(
    "/versions/check",
    response_model=VersionsSnapshotPublic,
    dependencies=[Depends(require_csrf)],
)
async def check_for_updates(
    request: Request,
    admin: "User" = Depends(require_admin),  # noqa: ARG001
    settings: "Settings" = Depends(get_settings),
) -> VersionsSnapshotPublic:
    """Operator-initiated remote refresh of the versions snapshot.

    Fetches ``Settings.version_check_url`` (default
    ``https://raw.githubusercontent.com/z4jdev/z4j/main/versions.json``)
    once, validates the response, and replaces the brain's in-memory
    snapshot with the result. Returns the new snapshot for the
    dashboard to render.

    Failure modes (kept clean so the dashboard can show a useful
    toast):

    - ``Z4J_VERSION_CHECK_URL`` empty → 404 with reason
      ``check_disabled``.
    - URL is not ``https://`` → 409 (operator misconfig).
    - Remote returns non-200, non-JSON, oversized, or fails
      validation → 409 with the underlying error message.

    On any failure the previously cached snapshot is unchanged.

    See :mod:`z4j_brain.domain.version_check` for the validator +
    fetch implementation.
    """
    if not settings.version_check_url:
        raise NotFoundError(
            (
                "remote version check is disabled "
                "(Z4J_VERSION_CHECK_URL is empty); the dashboard "
                "is using the bundled snapshot only"
            ),
            details={"reason": "check_disabled"},
        )

    from z4j_brain.domain.version_check import fetch_remote

    # We use the same shared httpx.AsyncClient the rest of the brain
    # uses for outbound HTTP, so request timeouts and DNS resolver
    # config are uniform. Fetch is one-shot; no caching layer.
    http_client = getattr(
        request.app.state, "notification_http_client", None,
    )
    if http_client is None:
        # Defensive fallback: build an ephemeral client. The
        # notification_http_client fixture is normally set during
        # create_app; if a slim test app skipped it we don't want
        # the version-check button to crash.
        import httpx  # noqa: PLC0415

        async with httpx.AsyncClient() as client:
            try:
                result = await fetch_remote(
                    settings.version_check_url, http_client=client,
                )
            except (ValueError, RuntimeError) as exc:
                raise ConflictError(
                    f"version check failed: {exc}",
                    details={"url": settings.version_check_url},
                ) from None
    else:
        try:
            result = await fetch_remote(
                settings.version_check_url, http_client=http_client,
            )
        except (ValueError, RuntimeError) as exc:
            raise ConflictError(
                f"version check failed: {exc}",
                details={"url": settings.version_check_url},
            ) from None

    # Atomic swap on app.state. There's only one brain process per
    # uvicorn worker; no lock needed.
    request.app.state.versions_snapshot = result.snapshot
    request.app.state.versions_snapshot_source = "remote"
    request.app.state.versions_snapshot_fetched_at = result.fetched_at
    request.app.state.versions_snapshot_fetched_from = result.fetched_from

    logger.info(
        "z4j: versions snapshot refreshed via Check for updates",
        url=result.fetched_from,
        package_count=len(result.snapshot.packages),
        generated_at=result.snapshot.generated_at,
    )

    return _to_public(request, settings)


def _to_public(
    request: Request,
    settings: "Settings",
) -> VersionsSnapshotPublic:
    """Map the in-memory snapshot to the public DTO."""
    snapshot = getattr(request.app.state, "versions_snapshot", None)
    source = getattr(
        request.app.state, "versions_snapshot_source", "bundled",
    )
    fetched_at: datetime | None = getattr(
        request.app.state, "versions_snapshot_fetched_at", None,
    )
    fetched_from: str | None = getattr(
        request.app.state, "versions_snapshot_fetched_from", None,
    )

    if snapshot is None:
        # Should never happen post-startup, but keep the endpoint
        # well-defined.
        from z4j_brain.domain.version_check import _empty_snapshot  # noqa: PLC0415

        snapshot = _empty_snapshot()
        source = "bundled"

    return VersionsSnapshotPublic(
        schema_version=snapshot.schema_version,
        generated_at=snapshot.generated_at,
        generated_by=snapshot.generated_by,
        canonical_url=snapshot.canonical_url,
        packages=dict(snapshot.packages),
        source=str(source),
        fetched_at=fetched_at.isoformat() if fetched_at else None,
        fetched_from=fetched_from,
        check_for_updates_url=settings.version_check_url,
    )


__all__ = ["VersionsSnapshotPublic", "router"]
