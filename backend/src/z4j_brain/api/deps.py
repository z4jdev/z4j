"""Shared FastAPI dependencies.

Most of the dep surface is auth-shaped:

- :func:`get_session` - yields a per-request DB session.
- :func:`get_current_user` - resolves the session cookie, looks up
  the row, validates expiry/revocation, returns the User. 401 if
  any check fails.
- :func:`get_optional_user` - same but returns ``None`` instead of
  raising. Used by ``/api/v1/health`` and ``/api/v1/setup/status``.
- :func:`require_admin` - current user must have ``is_admin``.
- :func:`require_csrf` - checks the ``X-CSRF-Token`` header against
  the session's CSRF token. State-changing endpoints depend on this.

The deps live next to the routers because they are FastAPI-bound.
The actual logic lives in :mod:`z4j_brain.domain.auth_service` and
:mod:`z4j_brain.auth.*`.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.auth.csrf import (
    CSRF_HEADER_NAME,
    is_safe_method,
    tokens_match,
)
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.errors import (
    AuthenticationError,
    AuthorizationError,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    FirstBootTokenRepository,
    InvitationRepository,
    MembershipRepository,
    ProjectRepository,
    SessionRepository,
    UserRepository,
)
from z4j_brain.settings import Settings

if TYPE_CHECKING:
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.auth_service import AuthService
    from z4j_brain.domain.setup_service import SetupService
    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.persistence.models import User


# ---------------------------------------------------------------------------
# api_keys.last_used_at sampling
# ---------------------------------------------------------------------------
#
# Process-local throttle for the bearer-auth ``last_used_at``
# write. See the call-site in ``bearer_auth`` below for the
# full motivation. Tunables:
#
# - ``_TOUCH_LAST_USED_INTERVAL_SECONDS``: skip the DB write if
#   we've already written for this key within the window. 60s is
#   chosen so the UI's "last used N min ago" stays accurate to
#   the minute - the operational unit operators care about.
# - ``_TOUCH_LAST_USED_MAX_KEYS``: cap on the throttle dict to
#   prevent unbounded memory growth from a long-running brain
#   that has seen millions of distinct API keys (paranoia; in
#   practice an instance has tens to hundreds of active keys).

_TOUCH_LAST_USED_INTERVAL_SECONDS: float = 60.0
_TOUCH_LAST_USED_MAX_KEYS: int = 10_000

#: INVARIANT: ``_touch_lock`` is acquired ONLY around pure
#: dict operations (no ``await``, no DB call, no network I/O).
#: This is why a ``threading.Lock`` is acceptable from inside an
#: async handler - the critical section is microseconds, never
#: yields the event loop, and never deadlocks. If a future edit
#: introduces an ``await`` inside the ``with _touch_lock:`` block
#: this invariant breaks and the lock MUST migrate to
#: ``asyncio.Lock`` (R3 finding M5).
_touch_lock = threading.Lock()
#: ``key_id -> monotonic timestamp of last successful claim``.
#: Monotonic (not wall-clock) so an NTP step backwards cannot
#: wedge the throttle for minutes; the only thing that matters
#: here is "elapsed since last write", which is exactly what
#: time.monotonic measures. We separately stamp `last_used_at`
#: on the row using `now: datetime`.
_touch_last_committed: "OrderedDict[UUID, float]" = OrderedDict()


def _claim_touch_slot(key_id: UUID) -> bool:
    """Atomically check + reserve a touch slot for ``key_id``.

    Returns True if the caller now owns the right to commit a
    fresh ``last_used_at`` write. The reservation is recorded
    optimistically so concurrent requests cannot both decide to
    write - but the caller MUST call :func:`_release_touch_slot`
    if the subsequent DB write fails, so the next request can
    retry rather than waiting out the full cooldown window with
    a stale (failed) reservation.
    """
    monotonic_now = time.monotonic()
    with _touch_lock:
        last = _touch_last_committed.get(key_id)
        if last is not None and (
            monotonic_now - last
        ) < _TOUCH_LAST_USED_INTERVAL_SECONDS:
            # Touch MRU so the eviction loop doesn't kill a hot key.
            _touch_last_committed.move_to_end(key_id)
            return False
        _touch_last_committed[key_id] = monotonic_now
        # Eviction: bounded memory regardless of how many distinct
        # API keys the brain has ever served.
        while len(_touch_last_committed) > _TOUCH_LAST_USED_MAX_KEYS:
            _touch_last_committed.popitem(last=False)
        return True


def _release_touch_slot(key_id: UUID) -> None:
    """Undo a slot reservation when the DB write fails.

    Without this, a transient DB outage would suppress every
    ``last_used_at`` update for every hot key for a full
    cooldown window, masking the security signal we want.
    """
    with _touch_lock:
        _touch_last_committed.pop(key_id, None)


# ---------------------------------------------------------------------------
# Settings + DB
# ---------------------------------------------------------------------------


def get_settings(request: Request) -> Settings:
    """Return the :class:`Settings` instance bound to the running app."""
    return request.app.state.settings  # type: ignore[no-any-return]


def get_db(request: Request) -> DatabaseManager:
    """Return the app-scoped :class:`DatabaseManager`."""
    return request.app.state.db  # type: ignore[no-any-return]


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a per-request ``AsyncSession``.

    Tied to the FastAPI request scope. Rolls back on any unhandled
    exception. Handlers commit explicitly when they intend to
    persist their changes.
    """
    db = get_db(request)
    async with db.session() as session:
        yield session


# ---------------------------------------------------------------------------
# Service singletons (resolved from app state)
# ---------------------------------------------------------------------------


def get_password_hasher(request: Request) -> PasswordHasher:
    """The process-wide :class:`PasswordHasher`."""
    return request.app.state.password_hasher  # type: ignore[no-any-return]


def get_audit_service(request: Request) -> AuditService:
    """The process-wide :class:`AuditService`."""
    return request.app.state.audit_service  # type: ignore[no-any-return]


def get_auth_service(request: Request) -> AuthService:
    """The process-wide :class:`AuthService`."""
    return request.app.state.auth_service  # type: ignore[no-any-return]


def get_setup_service(request: Request) -> SetupService:
    """The process-wide :class:`SetupService`.

    Singleton because the per-IP attempt-budget cache lives on the
    instance - a new instance per request would reset the budget.
    """
    return request.app.state.setup_service  # type: ignore[no-any-return]


def get_command_dispatcher(request: Request):  # type: ignore[no-untyped-def]
    """The process-wide brain-side :class:`CommandDispatcher`."""
    return request.app.state.command_dispatcher  # type: ignore[no-any-return]


def get_event_ingestor(request: Request):  # type: ignore[no-untyped-def]
    """The process-wide :class:`EventIngestor`."""
    return request.app.state.event_ingestor  # type: ignore[no-any-return]


def get_brain_registry(request: Request):  # type: ignore[no-untyped-def]
    """The process-wide :class:`BrainRegistry`."""
    return request.app.state.brain_registry  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Repositories - built per request from the session
# ---------------------------------------------------------------------------


def get_user_repo(
    session: AsyncSession = Depends(get_session),
) -> UserRepository:
    return UserRepository(session)


def get_session_repo(
    session: AsyncSession = Depends(get_session),
) -> SessionRepository:
    return SessionRepository(session)


def get_project_repo(
    session: AsyncSession = Depends(get_session),
) -> ProjectRepository:
    return ProjectRepository(session)


def get_membership_repo(
    session: AsyncSession = Depends(get_session),
) -> MembershipRepository:
    return MembershipRepository(session)


def get_first_boot_token_repo(
    session: AsyncSession = Depends(get_session),
) -> FirstBootTokenRepository:
    return FirstBootTokenRepository(session)


def get_invitation_repo(
    session: AsyncSession = Depends(get_session),
) -> InvitationRepository:
    return InvitationRepository(session)


def get_audit_log_repo(
    session: AsyncSession = Depends(get_session),
) -> AuditLogRepository:
    return AuditLogRepository(session)


# ---------------------------------------------------------------------------
# Real client IP
# ---------------------------------------------------------------------------


def get_client_ip(request: Request) -> str:
    """Return the resolved real client IP for the current request.

    Set by :class:`RealClientIPMiddleware`. Falls back to the raw
    socket peer if the middleware was not installed (test paths).
    """
    return getattr(
        request.state,
        "client_ip",
        request.client.host if request.client else "",
    )


# ---------------------------------------------------------------------------
# Current user resolution
# ---------------------------------------------------------------------------


async def get_optional_session(
    request: Request,
    settings: Settings = Depends(get_settings),
    auth_service: "AuthService" = Depends(get_auth_service),
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
) -> tuple["SessionRow", "User"] | None:
    """Resolve the session cookie OR return None.

    Used by :func:`get_optional_user` (which never raises) and by
    :func:`get_current_user` (which raises 401 on None).
    """
    cookie_value = request.cookies.get(cookie_name(environment=settings.environment))
    if not cookie_value:
        return None
    codec = SessionCookieCodec(settings)
    sid = codec.decode(
        cookie_value,
        max_age_seconds=settings.session_absolute_lifetime_seconds,
    )
    if sid is None:
        return None
    resolved = await auth_service.resolve_session(
        users=users, sessions=sessions, session_id=sid,
    )
    # Audit fix HIGH (1.2.2 fourth-pass): mark the auth winner as
    # "session" so ``resolve_api_key_id`` can correctly distinguish
    # cookie-authenticated calls from bearer-authenticated calls.
    # Without this, a request that authenticates via cookie but
    # ALSO carries a (possibly stale) bearer header would have
    # ``auth_kind`` left unset and the bearer-set
    # ``request.state.api_key`` could leak into audit attribution.
    # The cross-check at ``resolve_api_key_id`` only succeeds when
    # ``auth_kind == "api_key"``; setting ``"session"`` here makes
    # the contract explicit.
    if resolved is not None:
        request.state.auth_kind = "session"
    return resolved


async def _resolve_bearer_user(
    request: Request,
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
) -> "User | None":
    """Resolve ``Authorization: Bearer z4k_...`` to a User.

    Returns ``None`` if the header is missing / malformed / the
    token is unknown / revoked / expired / the owner is inactive.
    Also enforces scope + per-project authorization against the
    matched FastAPI route on the current request. Attaches the
    successful :class:`ApiKey` row to ``request.state.api_key``.
    """
    # Lazy imports to keep the module-level dep graph small.
    from datetime import UTC, datetime

    from z4j_brain.auth.scopes import (
        PROJECT_SCOPED_NONSLUG_ALLOWLIST,
        is_bearer_denied_tag,
        required_scope,
        scope_satisfies,
    )
    from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository

    auth_header = request.headers.get("authorization") or ""
    if not auth_header.lower().startswith("bearer "):
        return None
    plaintext = auth_header.split(" ", 1)[1].strip()
    if not plaintext.startswith("z4k_"):
        return None

    # Delegate to the exact same hash function the create endpoint
    # used - any divergence means the lookup silently misses every
    # valid token. Single source of truth lives in api/api_keys.py.
    from z4j_brain.api.api_keys import _hash_api_key as _hash
    secret = settings.secret.get_secret_value().encode("utf-8")
    digest = _hash(plaintext=plaintext, secret=secret)

    repo = ApiKeyRepository(db_session)
    key_row = await repo.get_by_hash(digest)
    if key_row is None:
        return None

    now = datetime.now(UTC)
    if key_row.revoked_at is not None:
        raise AuthenticationError(
            "api key has been revoked",
            details={"reason": "revoked"},
        )
    # SQLite strips tzinfo on round-trip for TIMESTAMP columns
    # (the dialect's stored form is naive). ``key_row.expires_at``
    # comes back as a naive ``datetime`` even though we stored it
    # as ``datetime.now(UTC) + ttl``. Comparing naive vs aware
    # raises ``TypeError`` and crashes the auth path with a 500
    # instead of a clean 401/403 (R6 M1). Coerce here so the path
    # is identical across Postgres (tz-aware round-trip) and
    # SQLite (naive round-trip we treat as UTC).
    expires_at = key_row.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            raise AuthenticationError(
                "api key has expired",
                details={"reason": "expired"},
            )

    users = UserRepository(db_session)
    user = await users.get(key_row.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError(
            "api key owner is inactive",
            details={"reason": "owner_inactive"},
        )

    # Scope check against the matched route. FastAPI populates
    # ``request.scope["route"]`` before the endpoint's deps run.
    route = request.scope.get("route")
    tags = getattr(route, "tags", None) if route else None
    first_tag = tags[0] if tags else None

    # Identity-level routes are denied outright for Bearer auth.
    # See :data:`BEARER_DENY_TAGS`. The comment in the scope module
    # has the full rationale; the short version is that a stolen
    # narrow-scope token must never be an account-takeover vector.
    if is_bearer_denied_tag(first_tag):
        raise AuthorizationError(
            "api keys cannot access identity endpoints - use a "
            "session cookie for /auth/*",
            details={"reason": "bearer_denied_for_tag", "tag": first_tag},
        )

    need = required_scope(tags=tags, method=request.method)
    if need is not None and not scope_satisfies(
        granted=list(key_row.scopes or []), required=need,
    ):
        raise AuthorizationError(
            "api key lacks required scope",
            details={"required_scope": need, "reason": "scope_missing"},
        )

    # Per-project scope check. If the token was minted for a single
    # project, the URL must address that project.
    if key_row.project_id is not None:
        path_params = request.path_params or {}
        slug = path_params.get("slug")
        projects_repo = ProjectRepository(db_session)
        bound_project = await projects_repo.get(key_row.project_id)
        if bound_project is None:
            raise AuthenticationError(
                "api key bound to a missing project",
                details={"reason": "project_missing"},
            )
        if slug is None:
            # No slug in the URL. Only a narrow allowlist of cross-
            # project endpoints (home, projects list) is legal - and
            # even then only if the token has the corresponding
            # ``:read`` scope, which the scope check above already
            # verified. Anything else is a 403.
            if first_tag not in PROJECT_SCOPED_NONSLUG_ALLOWLIST:
                raise AuthorizationError(
                    "project-scoped api keys cannot call this endpoint",
                    details={
                        "reason": "project_scope_nonslug_denied",
                        "tag": first_tag,
                        "bound_project": bound_project.slug,
                    },
                )
            request.state.api_key_project_slug = bound_project.slug
        else:
            # Resolve the URL's slug to a project row and compare by
            # id so case / canonicalization differences in the slug
            # column can never create a bypass.
            url_project = await projects_repo.get_by_slug(slug)
            if url_project is None or url_project.id != bound_project.id:
                raise AuthorizationError(
                    "api key not authorized for this project",
                    details={
                        "reason": "project_scope_mismatch",
                        "expected": bound_project.slug,
                        "got": slug,
                    },
                )

    # Bump ``last_used_at`` for the UI - sampled to once-per-60s
    # per key.
    #
    # Why sampled: under high Bearer traffic (>1k rps observed in
    # the founder's stress test) every request was committing a
    # row update in a dedicated savepoint, which dominated the
    # per-request DB time. Sampling drops 99% of those commits
    # while keeping ``last_used_at`` accurate to the minute -
    # which is the operational granularity anyone reading the
    # API-keys table actually cares about.
    #
    # The throttle is a process-local in-memory dict (no Redis,
    # no shared state). On a multi-worker deployment each
    # uvicorn worker maintains its own throttle, so the worst
    # case is N-workers commits per key per 60s instead of
    # rps-many. That's still 99.9%+ reduction on a 4-worker
    # 1k-rps cluster.
    #
    # Use a **dedicated session** so the bookkeeping write commits
    # without tying it to the caller's transaction lifetime
    # (audit C4/H2 fix: handler's partial writes could otherwise
    # leak past a handler rollback). Best-effort: a touch
    # failure must never block auth.
    if _claim_touch_slot(key_row.id):
        committed = False
        try:
            from z4j_brain.persistence.repositories.api_keys import (
                ApiKeyRepository as _ApiKeyRepo,
            )

            ip_hint = request.client.host if request.client else None
            db_mgr = getattr(request.app.state, "db", None)
            if db_mgr is not None:
                async with db_mgr.session() as touch_session:
                    await _ApiKeyRepo(touch_session).touch_used(
                        key_id=key_row.id, ip=ip_hint, when=now,
                    )
                    await touch_session.commit()
                    committed = True
        except Exception:  # noqa: BLE001
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("deps.bearer_auth", "touch_used")
        if not committed:
            # DB write didn't land - release the slot so the next
            # request retries instead of waiting out the full cooldown.
            _release_touch_slot(key_row.id)

    request.state.api_key = key_row
    # Audit fix HIGH-3 (1.2.2 fifth-pass): cookie wins over bearer
    # for auth attribution. If ``get_optional_session`` already
    # resolved a cookie session and set ``auth_kind = "session"``,
    # don't overwrite it, the audit trail should show the cookie
    # user as the actor, with the bearer header as a defense-in-
    # depth sidecar (used by ``require_csrf`` to allow stricter
    # paths). This matches ``require_csrf``'s C4 precedence: a
    # request with BOTH cookie + bearer is treated as cookie-
    # authenticated for CSRF + audit, even though the bearer can
    # still grant elevated scope checks.
    if getattr(request.state, "auth_kind", None) != "session":
        request.state.auth_kind = "api_key"
    return user


async def get_optional_api_key_user(
    user: "User | None" = Depends(_resolve_bearer_user),
) -> "User | None":
    return user


def resolve_api_key_id(request: Request) -> UUID | None:
    """Read the acting API key id off the request scope, if any.

    Returns the UUID of the bearer-token API key that authenticated
    this request, or None if the call came in via cookie session
    (or another non-bearer path).

    1.2.2 audit fix HIGH-11 (second pass): every privileged write
    endpoint that records an audit row should pass the result of
    this helper into ``AuditService.record(api_key_id=...)`` so
    the audit trail can distinguish a CI-triggered action from a
    dashboard-session admin who happens to share the same human
    user_id.

    1.2.2 audit fix HIGH-2 (third pass): only return the key when
    ``request.state.auth_kind == "api_key"``. Without this
    cross-check, a request that authenticated via cookie but ALSO
    carried a valid bearer header would attribute the audit row
    to the bearer key, even though cookie was the auth winner.
    Misattribution. We want the key id only when bearer auth was
    the path that produced the current ``user_id``.
    """
    auth_kind = getattr(request.state, "auth_kind", None)
    if auth_kind != "api_key":
        return None
    bearer_key = getattr(request.state, "api_key", None)
    if bearer_key is None:
        return None
    try:
        return getattr(bearer_key, "id", None)
    except Exception:  # noqa: BLE001
        # Defensive: a detached ORM row could raise on attribute
        # access. Silent attribution loss is preferable to a
        # request crash on the audit-write path.
        return None


async def get_optional_user(
    resolved: tuple["SessionRow", "User"] | None = Depends(get_optional_session),
    api_key_user: "User | None" = Depends(get_optional_api_key_user),
) -> "User | None":
    if resolved is not None:
        return resolved[1]
    return api_key_user


async def get_current_user(
    resolved: tuple["SessionRow", "User"] | None = Depends(get_optional_session),
    api_key_user: "User | None" = Depends(get_optional_api_key_user),
) -> "User":
    """Return the authenticated user, or raise 401.

    Session cookies win when both are present - this matches the
    behaviour most operators expect when sharing a browser.
    """
    if resolved is not None:
        return resolved[1]
    if api_key_user is not None:
        return api_key_user
    raise AuthenticationError("authentication required")


async def get_current_session(
    resolved: tuple["SessionRow", "User"] | None = Depends(get_optional_session),
) -> "SessionRow":
    """Return the active session row, or raise 401.

    Used by ``/auth/logout`` so the handler has the session row to
    revoke without re-querying.
    """
    if resolved is None:
        raise AuthenticationError("authentication required")
    return resolved[0]


async def require_admin(
    user: "User" = Depends(get_current_user),
) -> "User":
    """The current user must be a global brain admin."""
    if not user.is_admin:
        raise AuthorizationError("admin role required")
    return user


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


async def require_csrf(
    request: Request,
    settings: Settings = Depends(get_settings),
    resolved: tuple["SessionRow", "User"] | None = Depends(get_optional_session),
    # Force Bearer resolution before the CSRF check so the exemption
    # below can read ``request.state.auth_kind`` reliably regardless
    # of the order FastAPI walks the dep DAG for a given endpoint.
    _api_key_user: "User | None" = Depends(get_optional_api_key_user),
) -> None:
    """Enforce the double-submit CSRF check on state-changing requests.

    GET / HEAD / OPTIONS are exempt. The login + setup endpoints
    are NOT marked exempt here - they are exempt because they
    declare no ``Depends(require_csrf)``. The dep is opt-in per
    route.

    Bearer-authenticated requests (API keys) are exempt. CSRF
    defends against a malicious third-party site riding on the
    browser's ambient session cookie; an ``Authorization`` header
    can only be set by code that already has the token in hand,
    so the same attacker model doesn't apply.
    """
    if is_safe_method(request.method):
        return

    # Security (audit C4 / confused-deputy):
    # CSRF is ONLY skipped when the request is authenticated SOLELY
    # via Bearer auth. If a session cookie is ALSO present, the
    # handler might be attributed to the cookie user even though
    # the Bearer path cleared ``auth_kind`` - and then an attacker
    # with any valid low-scope Bearer (e.g. ``home:read``) could
    # coerce a victim's browser into making a state-changing call
    # as the cookie owner with CSRF bypassed.
    #
    # The fix: require BOTH "valid Bearer" AND "no session cookie"
    # before skipping. This matches how GitHub / Stripe / etc.
    # scope CSRF exemption to pure-API traffic.
    auth_kind = getattr(request.state, "auth_kind", None)
    has_session_cookie = bool(
        request.cookies.get(cookie_name(environment=settings.environment)),
    )
    if auth_kind == "api_key" and not has_session_cookie:
        return
    if resolved is None:
        raise AuthenticationError("authentication required for csrf check")
    expected = resolved[0].csrf_token
    supplied = request.headers.get(CSRF_HEADER_NAME)
    if not tokens_match(expected, supplied):
        raise AuthorizationError(
            "csrf token mismatch",
            details={"reason": "csrf_mismatch"},
        )


__all__ = [
    "get_audit_log_repo",
    "get_audit_service",
    "get_auth_service",
    "get_client_ip",
    "get_current_session",
    "get_current_user",
    "get_db",
    "get_first_boot_token_repo",
    "get_invitation_repo",
    "get_membership_repo",
    "get_optional_user",
    "get_password_hasher",
    "get_project_repo",
    "get_session",
    "get_session_repo",
    "get_settings",
    "get_setup_service",
    "get_user_repo",
    "require_admin",
    "require_csrf",
]
