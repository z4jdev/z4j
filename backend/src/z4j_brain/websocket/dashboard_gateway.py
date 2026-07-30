"""``/ws/dashboard`` WebSocket endpoint.

The brain's push channel for the React dashboard. Per-connection
state machine:

1. Accept the upgrade.
2. Read the session cookie. Decode → session id → resolve to
   ``(SessionRow, User)``. Failure → close 4401.
3. Receive the first frame; require ``{type: "subscribe",
   project_id: "<uuid>"}``. Anything else → close 4400.
4. Verify the user has a membership on that project (admins
   bypass). Failure → close 4403.
5. Register with the dashboard hub. Reply ``{type: "ready"}``.
6. Receive loop: handle ping (reply pong), ignore everything else,
   exit on disconnect.
7. On disconnect: unregister from the hub.

Close codes (mirrors the agent gateway scheme so operators only
have to learn one set):

- 4401  invalid / missing session cookie
- 4400  malformed first frame
- 4403  user is not a member of the requested project
- 4402  hub is stopped (server is shutting down)
- 1000  clean shutdown
- 1011  internal server error

The wire protocol is intentionally tiny - see the
``DashboardHub._protocol`` module docstring. The brain only tells
the dashboard *what changed* (topic + project), the dashboard
refetches the relevant REST endpoint to get the new data.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from uuid import UUID

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import SessionRow, User
    from z4j_brain.settings import Settings
    from z4j_brain.websocket.dashboard_hub import DashboardHub

logger = structlog.get_logger("z4j.brain.dashboard_gateway")

router = APIRouter(tags=["dashboard"])


@router.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket) -> None:  # noqa: PLR0911, PLR0912  websocket lifecycle handler
    """The dashboard push endpoint. See module docstring."""
    settings = _settings_from(websocket)
    db = _db_from(websocket)
    hub = _hub_from(websocket)

    await websocket.accept()

    if not _origin_allowed(websocket.headers.get("origin"), settings=settings):
        await _safe_close(websocket, code=4403)
        return

    # ------------------------------------------------------------------
    # 1) Authenticate (session cookie)
    # ------------------------------------------------------------------
    resolved = await _resolve_user(websocket=websocket, settings=settings, db=db)
    if resolved is None:
        await _safe_close(websocket, code=4401)
        return
    session_row, user = resolved

    # MFA gates (enrollment enforcement + second-factor verification),
    # mirroring the REST ``enforce_mfa_enrollment`` / ``enforce_mfa_verified``
    # dependencies. The push channel is product surface too, so a session
    # that REST would 403 must not open the live change stream here either.
    if _mfa_blocks_dashboard(user=user, session_row=session_row, settings=settings):
        await _safe_close(websocket, code=4403)
        return

    # ------------------------------------------------------------------
    # 2) First frame: subscribe
    # ------------------------------------------------------------------
    try:
        first = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
    except (TimeoutError, WebSocketDisconnect):
        await _safe_close(websocket, code=4400)
        return

    project_id = _parse_subscribe(first)
    if project_id is None:
        await _safe_close(websocket, code=4400)
        return

    # ------------------------------------------------------------------
    # 3) Authorize project membership
    # ------------------------------------------------------------------
    if not await _user_can_see_project(db=db, user=user, project_id=project_id):
        await _safe_close(websocket, code=4403)
        return

    # ------------------------------------------------------------------
    # 4) Register with the hub + ready handshake
    # ------------------------------------------------------------------
    async def send(frame: dict[str, Any]) -> None:
        await websocket.send_json(frame)

    try:
        sub = await hub.add_subscriber(
            project_id=project_id,
            send=send,
            user_id=user.id,
        )
    except RuntimeError:
        # Hub stopped between accept and register, OR per-user
        # subscription cap reached. Tell the
        # client to reconnect later / close existing tabs.
        await _safe_close(websocket, code=4402)
        return

    try:
        await websocket.send_json({"type": "ready"})
    except (WebSocketDisconnect, ConnectionError):
        await hub.remove_subscriber(sub)
        return

    logger.info(
        "z4j dashboard_gateway: subscriber connected",
        user_id=str(user.id),
        project_id=str(project_id),
    )

    # ------------------------------------------------------------------
    # 5) Receive loop - ping/pong + drain client messages
    # ------------------------------------------------------------------
    # Per-connection idle timeout. The dashboard client pings every
    # 25 s as a keepalive; ``ws_idle_timeout_seconds`` (default 90s)
    # tolerates ~3 missed pings before we close the socket and free
    # the file descriptor. Without this, a backgrounded tab whose
    # WS got NAT-dropped silently would hold a server-side fd
    # forever.
    idle_timeout = float(settings.ws_idle_timeout_seconds)
    try:
        while True:
            try:
                msg = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=idle_timeout,
                )
            except TimeoutError:
                logger.info(
                    "z4j dashboard_gateway: idle timeout, closing",
                    user_id=str(user.id),
                    project_id=str(project_id),
                    idle_seconds=idle_timeout,
                )
                await _safe_close(websocket, code=4408)
                return
            except WebSocketDisconnect:
                return
            await _handle_client_message(websocket, msg)
    except Exception:
        logger.exception("z4j dashboard_gateway: receive loop crashed")
        await _safe_close(websocket, code=1011)
    finally:
        await hub.remove_subscriber(sub)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mfa_blocks_dashboard(
    *,
    user: User,
    session_row: SessionRow,
    settings: Settings,
) -> bool:
    """True when MFA policy forbids this session from the push channel.

    Two gates, matching REST:

    1. Enrollment enforcement: a session past its enrollment grace
       deadline is restricted to the enrollment endpoints
       (``enforce_mfa_enrollment``).
    2. Second-factor verification: login mints the session cookie at
       the PASSWORD step and only returns ``mfa_required`` as a hint, so
       a password-only session (stolen password, victim has TOTP
       enrolled) is authenticated-but-not-verified. REST 403s it
       everywhere but the verify allowlist; without the same gate here
       that session could open the live change stream on the password
       alone -- a second-factor bypass on an authenticated channel
       (``enforce_mfa_verified``).
    """
    from z4j_brain.domain.mfa.enforcement import evaluate_mfa_enforcement

    if evaluate_mfa_enforcement(user=user, settings=settings).blocked:
        return True
    has_mfa = user.mfa_secret_encrypted is not None and user.mfa_enrolled_at is not None
    return has_mfa and session_row.mfa_verified_at is None


async def _resolve_user(
    *,
    websocket: WebSocket,
    settings: Settings,
    db: DatabaseManager,
) -> tuple[SessionRow, User] | None:
    """Resolve the session cookie → ``(SessionRow, User)``, or None.

    Mirrors the REST ``get_optional_session`` dependency. We can't
    actually use it because Depends doesn't apply to WebSocket
    handlers - but we call the same underlying functions so a
    cookie that works on REST also works here. Returns the SessionRow
    too so the caller can enforce the second-factor gate
    (``session_row.mfa_verified_at``) exactly as REST does.
    """
    cookie_value = websocket.cookies.get(
        cookie_name(environment=settings.environment),
    )
    if not cookie_value:
        return None

    codec = SessionCookieCodec(settings)
    sid = codec.decode(
        cookie_value,
        max_age_seconds=settings.session_absolute_lifetime_seconds,
    )
    if sid is None:
        return None

    # Reuse the brain-wide AuthService singleton from app.state.
    # Constructing a fresh one per WebSocket would pay the
    # PasswordHasher dummy-hash cost on every connect - argon2 is
    # ~50 ms which adds up under reconnect storms.
    auth_service = websocket.app.state.auth_service
    from z4j_brain.persistence.repositories import (
        SessionRepository,
        UserRepository,
    )

    async with db.session() as session:
        users = UserRepository(session)
        sessions = SessionRepository(session)
        resolved = await auth_service.resolve_session(
            users=users,
            sessions=sessions,
            session_id=sid,
        )
    return resolved if resolved else None


def _parse_subscribe(raw: str) -> UUID | None:
    """Parse the first client frame. Returns the project_id or None."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("type") != "subscribe":
        return None
    pid_raw = data.get("project_id")
    if not isinstance(pid_raw, str):
        return None
    try:
        return UUID(pid_raw)
    except ValueError:
        return None


def _origin_allowed(origin: str | None, *, settings: Settings) -> bool:
    """Return True when a browser WebSocket Origin is trusted.

    ``/ws/dashboard`` is cookie-authenticated, so Origin is the WS
    equivalent of the CSRF check used by REST mutations. Browsers set
    this header on WebSocket handshakes; missing Origin is tolerated
    only in dev/test for local tooling.
    """
    if not origin:
        return settings.environment == "dev"
    normalized = _normalise_origin(origin)
    if normalized is None:
        return False
    return normalized in _allowed_origins(settings)


def _allowed_origins(settings: Settings) -> set[str]:
    allowed: set[str] = set()
    public_origin = _normalise_origin(settings.public_url)
    if public_origin is not None:
        allowed.add(public_origin)
    for raw in settings.cors_origins:
        if raw == "*":
            continue
        parsed = _normalise_origin(raw)
        if parsed is not None:
            allowed.add(parsed)
    if settings.environment == "dev":
        port = settings.bind_port
        allowed.update(
            {
                f"http://localhost:{port}",
                f"http://127.0.0.1:{port}",
                f"http://testserver:{port}",
                "http://testserver",
            }
        )
    return allowed


def _normalise_origin(raw: str) -> str | None:
    try:
        parsed = urlsplit(raw.strip())
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    default_port = (parsed.scheme == "http" and port == 80) or (
        parsed.scheme == "https" and port == 443
    )
    if port is not None and not default_port:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}"


async def _user_can_see_project(
    *,
    db: DatabaseManager,
    user: User,
    project_id: UUID,
) -> bool:
    """Admins see every project; everyone else needs a membership row."""
    if getattr(user, "is_admin", False):
        return True
    from z4j_brain.persistence.repositories import MembershipRepository

    async with db.session() as session:
        memberships = await MembershipRepository(session).list_for_user(user.id)
    return any(m.project_id == project_id for m in memberships)


async def _handle_client_message(
    websocket: WebSocket,
    raw: str,
) -> None:
    """Handle a client → server message after subscribe.

    The dashboard only sends pings for keepalive in V1. Anything
    else is ignored - we don't want unknown frames to be a
    connection-fatal error because the dashboard may be on a
    newer version that learned to send something we haven't
    implemented yet.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return
    if isinstance(data, dict) and data.get("type") == "ping":
        try:
            await websocket.send_json({"type": "pong"})
        except (WebSocketDisconnect, ConnectionError):
            return


async def _safe_close(websocket: WebSocket, *, code: int) -> None:
    with contextlib.suppress(Exception):
        await websocket.close(code=code)


def _settings_from(ws: WebSocket) -> Settings:
    return ws.app.state.settings  # type: ignore[no-any-return]


def _db_from(ws: WebSocket) -> DatabaseManager:
    return ws.app.state.db  # type: ignore[no-any-return]


def _hub_from(ws: WebSocket) -> DashboardHub:
    return ws.app.state.dashboard_hub  # type: ignore[no-any-return]


__all__ = ["router"]
