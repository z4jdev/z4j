"""``GET /api/v1/schedulers`` - fleet overview for the dashboard.

docs/SCHEDULER.md §13.1: *"the dashboard's Schedulers page, which
can poll across all enrolled scheduler instances to render a
per-instance status grid."*

The endpoint fans out to every URL in
``Settings.scheduler_info_urls``, calls each scheduler's ``/info``
endpoint over HTTP, and returns the aggregated payload. The
dashboard renders the result; brain stays a thin proxy.

Why fan-out from brain rather than dashboard-direct:

- Most production deployments don't expose scheduler ``/info``
  externally (it's a sidecar / cluster-internal Service). The
  dashboard browser can't reach it directly. Brain CAN.
- One auth surface to manage. The dashboard already has session
  + CSRF on every brain call; tunneling through brain reuses it
  without giving the browser a separate scheduler API token.
- Brain returns a stable ``FleetEntry`` shape per scheduler URL,
  including failure cases - the dashboard renders "scheduler
  unreachable" rows the same way as healthy ones, no per-URL
  exception handling on the client.

Auth: ADMIN. Operator-fleet visibility is privileged - the
``/info`` payload includes brain endpoint URLs and scheduler
versions that aid reconnaissance.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from z4j_brain.api.deps import (
    get_current_user,
    get_settings,
)

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings

router = APIRouter(prefix="/schedulers", tags=["schedulers"])


class FleetEntry(BaseModel):
    """One scheduler instance's reported status.

    ``ok`` distinguishes the three observable states:

    - ``True``: scheduler responded with a parseable /info payload.
      ``info`` carries the full payload.
    - ``False``: scheduler responded but the response was bad
      (non-200, non-JSON, schema mismatch). ``error`` describes.
    - ``None``: scheduler did not respond within the timeout.
      ``error`` carries the connection error text.
    """

    url: str
    ok: bool | None
    info: dict[str, Any] | None = None
    error: str | None = None


class FleetResponse(BaseModel):
    schedulers: list[FleetEntry]
    total: int
    healthy: int


@router.get("", response_model=FleetResponse)
async def list_fleet(
    user: "User" = Depends(get_current_user),
    settings: "Settings" = Depends(get_settings),
) -> FleetResponse:
    """Return one entry per configured scheduler URL.

    Authorization is global ADMIN (not project-scoped). The fleet
    is operator-level concern - any project admin sees the same
    fleet, but only global admins (``user.is_admin``) can view it.
    """
    if not user.is_admin:
        # Audit fix M-1 (Apr 2026): pre-fix this returned an empty
        # FleetResponse to render gracefully on the dashboard, but
        # silently masking a denied request as "no schedulers
        # configured" obscures both the audit trail (no failed-auth
        # row) and the operator UX (the page implies there's
        # nothing here when actually they're forbidden). Raise an
        # explicit 403 so the dashboard knows to render a "you
        # don't have access" state.
        from z4j_brain.errors import AuthorizationError  # noqa: PLC0415

        raise AuthorizationError(
            "scheduler-fleet visibility requires global admin",
            details={"action": "list_scheduler_fleet"},
        )

    urls: list[str] = list(settings.scheduler_info_urls)
    # Auto-include the embedded sidecar's well-known address when
    # ``embedded_scheduler`` is on AND no explicit URL list was
    # configured. This makes the homelab single-container deploy
    # show up in the dashboard out of the box.
    if (
        not urls
        and getattr(settings, "embedded_scheduler", False)
    ):
        urls = ["http://127.0.0.1:7800"]

    if not urls:
        return FleetResponse(schedulers=[], total=0, healthy=0)

    # Audit fix L-5 (Apr 2026): explicit ``follow_redirects=False``.
    # httpx defaults to following redirects; a compromised scheduler
    # could redirect the brain's probe to internal-metadata services
    # (cloud-instance metadata at 169.254.169.254 etc). Pin to false
    # so a "redirect to a sensitive URL" attack is impossible.
    # Fan out in parallel with a short timeout - dashboard polls
    # this on a refresh interval, can't hold up rendering on a
    # dead scheduler.
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(3.0, connect=2.0),
        follow_redirects=False,
    ) as client:
        results = await asyncio.gather(
            *[_probe_scheduler(client, url) for url in urls],
            return_exceptions=False,
        )

    healthy = sum(1 for r in results if r.ok is True)
    return FleetResponse(
        schedulers=results,
        total=len(results),
        healthy=healthy,
    )


async def _probe_scheduler(
    client: httpx.AsyncClient, url: str,
) -> FleetEntry:
    """Hit one scheduler's /info endpoint. Never raises.

    Audit fix L-5 (Apr 2026): defend against an operator listing a
    non-http scheme in ``scheduler_info_urls``. ``file://`` would
    let httpx (via the FileTransport adapter, if installed) read
    arbitrary files; ``http://localhost:22`` would probe internal
    services. We reject anything that isn't ``http``/``https``
    BEFORE the GET.
    """
    from urllib.parse import urlparse  # noqa: PLC0415

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return FleetEntry(
            url=url, ok=False,
            error=(
                f"refused to probe non-http(s) scheme {parsed.scheme!r}; "
                "Z4J_SCHEDULER_INFO_URLS entries must use http or https"
            ),
        )
    info_url = url.rstrip("/") + "/info"
    try:
        response = await client.get(info_url)
    except httpx.TimeoutException:
        return FleetEntry(
            url=url, ok=None, error="timeout (no response within 3s)",
        )
    except httpx.HTTPError as exc:
        return FleetEntry(
            url=url, ok=None, error=f"connection error: {exc}",
        )
    if response.status_code != 200:
        return FleetEntry(
            url=url, ok=False,
            error=f"HTTP {response.status_code}: {response.text[:200]}",
        )
    try:
        payload = response.json()
    except ValueError as exc:
        return FleetEntry(
            url=url, ok=False, error=f"invalid JSON: {exc}",
        )
    if not isinstance(payload, dict):
        return FleetEntry(
            url=url, ok=False,
            error=f"expected JSON object, got {type(payload).__name__}",
        )
    return FleetEntry(url=url, ok=True, info=payload)


__all__ = ["FleetEntry", "FleetResponse", "router"]
