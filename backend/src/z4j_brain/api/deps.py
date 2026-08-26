"""Shared FastAPI dependencies.

Most of the dep surface is auth-shaped:

- :func:`get_session` - yields a per-request DB session.
- :func:`get_current_user` - resolves a valid session cookie first,
  otherwise a Bearer API key, and returns the User. Invalid credentials
  are refused.
- :func:`get_optional_user` - uses the same cookie-first precedence but
  returns ``None`` for missing, unknown, revoked, expired, or inactive-owner
  credentials. Used by ``/api/v1/health`` and ``/api/v1/setup/status``.
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
    MfaEnrollmentRequiredError,
    MfaReverifyRequiredError,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    FirstBootTokenRepository,
    InvitationRepository,
    MembershipRepository,
    MfaRecoveryCodeRepository,
    ProjectRepository,
    SessionRepository,
    TrustedDeviceRepository,
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
#: ``asyncio.Lock``.
_touch_lock = threading.Lock()
#: ``key_id -> monotonic timestamp of last successful claim``.
#: Monotonic (not wall-clock) so an NTP step backwards cannot
#: wedge the throttle for minutes; the only thing that matters
#: here is "elapsed since last write", which is exactly what
#: time.monotonic measures. We separately stamp `last_used_at`
#: on the row using `now: datetime`.
_touch_last_committed: OrderedDict[UUID, float] = OrderedDict()


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
        if last is not None and (monotonic_now - last) < _TOUCH_LAST_USED_INTERVAL_SECONDS:
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


#: ``request.state`` key under which bearer auth parks the
#: ``last_used_at`` bookkeeping for :func:`_drain_api_key_touch` to run once
#: the request's own session has been closed.
_TOUCH_STATE_ATTR = "z4j_api_key_touch"

# Session activity uses the same post-request shape as API-key activity:
# authentication runs in the handler's request transaction, but the activity
# stamp must survive read-only requests and handler rollback without ever
# committing the handler's business writes. A small process-local throttle
# avoids turning every dashboard asset/API read into a database UPDATE.
_SESSION_TOUCH_MAX_INTERVAL_SECONDS: float = 60.0
_SESSION_TOUCH_MAX_SESSIONS: int = 10_000
_SESSION_TOUCH_STATE_ATTR = "z4j_session_touch"
_SESSION_REVOKE_STATE_ATTR = "z4j_session_revoke"
_session_touch_lock = threading.Lock()
_session_touch_last_committed: OrderedDict[UUID, float] = OrderedDict()


def _session_touch_interval_seconds(idle_timeout_seconds: int) -> float:
    """Return a cadence safely inside the configured idle window."""
    return min(
        _SESSION_TOUCH_MAX_INTERVAL_SECONDS,
        max(1.0, idle_timeout_seconds / 2.0),
    )


def _claim_session_touch_slot(
    session_id: UUID,
    *,
    interval_seconds: float,
) -> bool:
    """Reserve a throttled durable activity write for ``session_id``."""
    monotonic_now = time.monotonic()
    with _session_touch_lock:
        last = _session_touch_last_committed.get(session_id)
        if last is not None and (monotonic_now - last) < interval_seconds:
            _session_touch_last_committed.move_to_end(session_id)
            return False
        _session_touch_last_committed[session_id] = monotonic_now
        while len(_session_touch_last_committed) > _SESSION_TOUCH_MAX_SESSIONS:
            _session_touch_last_committed.popitem(last=False)
        return True


def _release_session_touch_slot(session_id: UUID) -> None:
    """Release a failed activity-write reservation so the next request retries."""
    with _session_touch_lock:
        _session_touch_last_committed.pop(session_id, None)


async def _drain_session_touch(request: Request) -> None:
    """Persist validated session activity in its own transaction.

    This runs after the request-scoped session has closed. Therefore a read-only
    request advances the sliding idle clock, while a failing mutation still
    rolls back all handler writes before this isolated primary-key UPDATE is
    committed.
    """
    session_id = getattr(request.state, _SESSION_TOUCH_STATE_ATTR, None)
    if session_id is None:
        return
    setattr(request.state, _SESSION_TOUCH_STATE_ATTR, None)
    settings = getattr(request.app.state, "settings", None)
    idle_timeout_seconds = int(
        getattr(settings, "session_idle_timeout_seconds", 1_800),
    )
    if not _claim_session_touch_slot(
        session_id,
        interval_seconds=_session_touch_interval_seconds(idle_timeout_seconds),
    ):
        return
    committed = False
    try:
        db_mgr = getattr(request.app.state, "db", None)
        if db_mgr is not None:
            async with db_mgr.session(write=True) as touch_session:
                touched = await SessionRepository(touch_session).touch(session_id)
                await touch_session.commit()
                committed = touched
    except Exception:
        from z4j_brain.api.metrics import record_swallowed

        record_swallowed("deps.session_auth", "touch")
    if not committed:
        _release_session_touch_slot(session_id)


async def _drain_session_revoke(request: Request) -> None:
    """Persist a request-time session invalidation in isolation."""
    pending = getattr(request.state, _SESSION_REVOKE_STATE_ATTR, None)
    if pending is None:
        return
    setattr(request.state, _SESSION_REVOKE_STATE_ATTR, None)
    session_id, reason = pending
    try:
        db_mgr = getattr(request.app.state, "db", None)
        if db_mgr is not None:
            async with db_mgr.session(write=True) as revoke_session:
                await SessionRepository(revoke_session).revoke(session_id, reason=reason)
                await revoke_session.commit()
    except Exception:
        from z4j_brain.api.metrics import record_swallowed

        record_swallowed("deps.session_auth", "revoke")


async def _drain_api_key_touch(request: Request) -> None:
    """Stamp ``last_used_at`` for the key that authenticated this request.

    Called from :func:`get_session` AFTER the request's session is closed,
    which is the whole point of the split. The write needs a session of its
    own -- on the request's session it would ride the handler's transaction,
    so a handler rollback would erase the fact that the key was used and the
    bookkeeping's commit would carry the handler's partial writes -- and a
    second session means a second connection. Taken during the request, that
    checkout waits behind the connection the request itself is holding, which
    on the ``pool_size=1, max_overflow=0`` pool this brain permits is a
    connection that is never coming: every bearer request paid the full pool
    timeout and then dropped the stamp anyway. Taken here, the request's
    connection is already back in the pool.

    Sampling (see :func:`_claim_touch_slot`) is decided here rather than at
    auth time so a request that ends in an error path, where no stamp is
    written, does not hold the sample window against the next one.

    Best-effort: the reservation is handed back on failure so the next
    request retries rather than waiting out the cooldown with a stale one.
    """
    pending = getattr(request.state, _TOUCH_STATE_ATTR, None)
    if pending is None:
        return
    setattr(request.state, _TOUCH_STATE_ATTR, None)
    key_id, ip, when = pending
    if not _claim_touch_slot(key_id):
        return
    committed = False
    try:
        from z4j_brain.persistence.repositories.api_keys import (
            ApiKeyRepository as _ApiKeyRepo,
        )

        db_mgr = getattr(request.app.state, "db", None)
        if db_mgr is not None:
            async with db_mgr.session() as touch_session:
                await _ApiKeyRepo(touch_session).touch_used(
                    key_id=key_id,
                    ip=ip,
                    when=when,
                )
                await touch_session.commit()
                committed = True
    except Exception:
        from z4j_brain.api.metrics import record_swallowed

        record_swallowed("deps.bearer_auth", "touch_used")
    if not committed:
        _release_touch_slot(key_id)


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
    persist their changes. SQLite mutation requests reserve the writer
    before dependency resolution can perform the first authentication or
    domain read; this is the request-owned Boundary-F write unit.

    Work that needs a connection of its own runs in the ``finally``, not
    during the request: this dependency's teardown is the one moment where
    the request's connection is provably back in the pool, and a pool of one
    is a supported size. The ``finally`` rather than a plain trailing
    statement because an error path throws into this generator at the
    ``yield``, and the bookkeeping is not conditional on the handler
    succeeding.
    """
    db = get_db(request)
    write = not is_safe_method(request.method)
    try:
        async with db.session(write=write) as session:
            yield session
    finally:
        await _drain_session_revoke(request)
        await _drain_session_touch(request)
        await _drain_api_key_touch(request)


async def begin_sqlite_immediate_write_unit(
    session: AsyncSession = Depends(get_session),
) -> None:
    """Reserve SQLite writer authority before a route's first DB read.

    Only routes whose audited transition requires pre-read serialization
    declare this dependency.  It must be the first item in the route's
    ``dependencies`` list so authentication, authorization, mutation, and
    audit all use the same already-reserved request session.
    """
    from z4j_brain.persistence.repositories.audit_log import (
        AuditLogRepository,
    )

    await AuditLogRepository(session).require_sqlite_immediate_write_unit()


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
    """The process-wide :class:`SetupService` bound during app startup."""
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


def get_mfa_recovery_codes_repo(
    session: AsyncSession = Depends(get_session),
) -> MfaRecoveryCodeRepository:
    return MfaRecoveryCodeRepository(session)


def get_trusted_device_repo(
    session: AsyncSession = Depends(get_session),
) -> TrustedDeviceRepository:
    return TrustedDeviceRepository(session)


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
    auth_service: AuthService = Depends(get_auth_service),
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
) -> tuple[SessionRow, User] | None:
    """Resolve the session cookie OR return None.

    Used by :func:`get_optional_user` (which treats credential-authentication
    failures as anonymous) and by :func:`get_current_user` (which raises 401
    when neither a valid cookie nor a valid Bearer credential resolves).
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
        users=users,
        sessions=sessions,
        session_id=sid,
    )
    if resolved is not None and settings.session_pin_user_agent:
        issued_user_agent = resolved[0].user_agent_at_issue
        current_user_agent = request.headers.get("user-agent")
        current_user_agent = current_user_agent[:256] if current_user_agent else None
        if issued_user_agent != current_user_agent:
            setattr(
                request.state,
                _SESSION_REVOKE_STATE_ATTR,
                (resolved[0].id, "user_agent_changed"),
            )
            return None
    # Mark the auth winner as "session" so ``resolve_api_key_id`` can
    # correctly distinguish
    # cookie-authenticated calls from bearer-authenticated calls.
    # Without this, a request that authenticates via cookie but ALSO carries
    # a Bearer header could leave ambiguous audit attribution. The wrapper
    # dependencies below make the precedence stronger still: once this
    # function resolves a valid cookie session, they do not evaluate the
    # Bearer header at all.
    # The cross-check at ``resolve_api_key_id`` only succeeds when
    # ``auth_kind == "api_key"``; setting ``"session"`` here makes
    # the contract explicit.
    if resolved is not None:
        request.state.auth_kind = "session"
        setattr(request.state, _SESSION_TOUCH_STATE_ATTR, resolved[0].id)
    return resolved


async def _resolve_bearer_user(  # noqa: PLR0912, PLR0915  bearer auth resolution branches
    request: Request,
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
) -> User | None:
    """Resolve ``Authorization: Bearer z4k_...`` to a User.

    Returns ``None`` if the header is missing, malformed, or the token is
    unknown. A known-but-revoked, expired, stale-bound, or inactive-owner key
    raises :class:`AuthenticationError`; the strict/optional wrapper selects
    whether that error is propagated or treated as anonymous. Scope and
    per-project authorization failures always raise
    :class:`AuthorizationError`. Attaches a successful :class:`ApiKey` row to
    ``request.state.api_key``.
    """
    # Lazy imports to keep the module-level dep graph small.
    from datetime import UTC

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
    # instead of a clean 401/403. Coerce here so the path
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
            "api keys cannot access identity endpoints - use a session cookie for /auth/*",
            details={"reason": "bearer_denied_for_tag", "tag": first_tag},
        )

    need = required_scope(tags=tags, method=request.method)
    if need is not None and not scope_satisfies(
        granted=list(key_row.scopes or []),
        required=need,
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
    # Park it rather than write it here: the write wants a dedicated
    # session, so it wants a second connection, and this request is
    # holding the first one for the rest of its life. ``get_session``
    # runs it once that connection is back in the pool. See
    # :func:`_drain_api_key_touch`.
    #
    # ``now`` is deliberately the moment this key AUTHENTICATED and not the
    # moment the parked write runs, so the stamp describes the use rather
    # than the drain. That is also why requests reach the write out of
    # order, and why ``touch_used`` refuses to move the row backwards.
    setattr(
        request.state,
        _TOUCH_STATE_ATTR,
        (
            key_row.id,
            request.client.host if request.client else None,
            now,
        ),
    )

    request.state.api_key = key_row
    # The public wrappers skip this resolver entirely after a valid cookie
    # session wins. Keep this state guard as defense in depth for direct
    # internal callers: a Bearer lookup must never overwrite an already-set
    # session attribution.
    if getattr(request.state, "auth_kind", None) != "session":
        request.state.auth_kind = "api_key"
    return user


async def get_optional_api_key_user(
    request: Request,
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
) -> User | None:
    """Resolve a Bearer user for an optional-auth endpoint.

    A valid cookie session has absolute precedence, so a coincident Bearer
    header is not looked up, scope-checked, touched, or attributed. Without a
    valid cookie, missing/unknown Bearer credentials already resolve to
    ``None`` in :func:`_resolve_bearer_user`; known but revoked, expired,
    stale-bound, or inactive-owner credentials raise
    :class:`AuthenticationError`, which optional auth deliberately converts
    to ``None`` as well. Authorization failures for an otherwise valid key
    still propagate -- "optional" does not mean "ignore a forbidden action".
    """
    if resolved is not None:
        return None
    try:
        return await _resolve_bearer_user(request, settings, db_session)
    except AuthenticationError:
        return None


async def _get_strict_api_key_user(
    request: Request,
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
) -> User | None:
    """Resolve Bearer auth for required-auth and CSRF dependencies.

    A valid cookie still wins and suppresses Bearer evaluation. When no valid
    cookie resolves, however, credential failures from
    :func:`_resolve_bearer_user` remain strict and propagate as 401 responses.
    """
    if resolved is not None:
        return None
    return await _resolve_bearer_user(request, settings, db_session)


def resolve_api_key_id(request: Request) -> UUID | None:
    """Read the acting API key id off the request scope, if any.

    Returns the UUID of the bearer-token API key that authenticated
    this request, or None if the call came in via cookie session
    (or another non-bearer path).

    Every privileged write endpoint that records an audit row
    should pass the result of this helper into
    ``AuditService.record(api_key_id=...)`` so the audit trail
    can distinguish a CI-triggered action from a dashboard-session
    admin who happens to share the same human user_id.

    Returns the key only when ``request.state.auth_kind ==
    "api_key"``. Without this cross-check, a request that
    authenticated via cookie but ALSO carried a valid bearer
    header would attribute the audit row to the bearer key, even
    though cookie was the auth winner. We want the key id only
    when bearer auth was the path that produced the current
    ``user_id``.
    """
    auth_kind = getattr(request.state, "auth_kind", None)
    if auth_kind != "api_key":
        return None
    bearer_key = getattr(request.state, "api_key", None)
    if bearer_key is None:
        return None
    try:
        return getattr(bearer_key, "id", None)
    except Exception:
        # Defensive: a detached ORM row could raise on attribute
        # access. Silent attribution loss is preferable to a
        # request crash on the audit-write path.
        return None


async def get_optional_user(
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    api_key_user: User | None = Depends(get_optional_api_key_user),
) -> User | None:
    """Return the cookie-first principal, or ``None`` when unauthenticated.

    A valid session cookie wins over any Authorization header. If no cookie
    session resolves, optional Bearer authentication treats missing, unknown,
    revoked, expired, stale, and inactive-owner credentials as anonymous.
    Valid credentials that fail route authorization still raise 403.
    """
    if resolved is not None:
        return resolved[1]
    return api_key_user


# ---------------------------------------------------------------------------
# MFA enrollment enforcement gate
# ---------------------------------------------------------------------------


def _matches_exempt_route(
    request: Request,
    allowlist: frozenset[tuple[str, str]],
) -> bool:
    """Return True when the request targets an allowlisted exempt route.

    Both MFA gates carry an allowlist of ``(METHOD, "/api/v1/...")``
    pairs -- the routes a gated session may still reach. The path in
    each pair is the FULL, mount-prefixed path.

    History: an earlier version matched only ``request.scope["route"].path``.
    That attribute is NOT reliably the mount-prefixed path -- with
    ``app.include_router(router, prefix="/api/v1")`` the ``APIRoute``
    object left in ``scope["route"]`` reports its router-local path
    (``/auth/me``), NOT ``/api/v1/auth/me``. So every prefixed allowlist
    entry missed, the gate refused even its own escape routes, and a user
    who enabled MFA could never present the second factor -- a permanent
    lockout recoverable only via the ``reset-mfa`` shell command.

    ``request.url.path`` is the actual app-relative path the client hit
    (``/api/v1/auth/me``), already stripped of any ASGI ``root_path``, so
    it matches the prefixed allowlist directly. We also accept a match on
    ``route.path`` so a future FastAPI that DOES bake the prefix keeps
    working. Both forms are exact-match against a static, parameter-free
    allowlist, so neither can widen the exemption beyond the intended
    routes. Every exempt route is parameter-free by construction; if a
    path-parameter route ever needs exempting, match it on
    ``route.path`` rather than the value-substituted ``url.path``.
    """
    method = request.method.upper()
    if (method, request.url.path) in allowlist:
        return True
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    return route_path is not None and (method, route_path) in allowlist


#: ``(METHOD, route-path-template)`` pairs a session that is PAST its
#: MFA-enrollment grace deadline may still call: everything a blocked
#: user needs to become enrolled, and nothing else. Whoami stays
#: reachable so the dashboard can render the enrollment page; logout
#: so the user can leave. Paths are the full ``/api/v1``-prefixed form
#: and matched via :func:`_matches_exempt_route`.
_MFA_ENROLLMENT_EXEMPT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/auth/mfa/status"),
        ("POST", "/api/v1/auth/mfa/enroll-start"),
        ("POST", "/api/v1/auth/mfa/enroll-complete"),
    },
)


def enforce_mfa_enrollment(
    *,
    request: Request,
    user: User,
    settings: Settings,
) -> None:
    """Raise 403 ``mfa_enrollment_required`` for blocked sessions.

    The request-time half of the MFA enrollment-enforcement policy
    (the login-time half stamps the grace anchor and surfaces the
    deadline -- see ``api/auth.py::login``). Evaluated on EVERY
    cookie-session request via :func:`get_current_user` /
    :func:`get_current_session`, so the policy is live: it engages
    mid-session when the deadline passes, and lifts on the very next
    request after the user enrolls (or the operator relaxes the
    policy). Deliberately a hard 403 rather than a login refusal --
    enrollment itself needs an authenticated session, so the session
    survives but only the allowlisted enrollment routes accept it.

    Bearer-only (API-key) requests never reach this gate by design:
    programmatic accounts are exempt from MFA enforcement
    (docs/MFA-DESIGN.md, open question 5).

    Cheap: pure computation over the already-loaded user row; no
    additional queries. Not audited per-request (that would flood the
    chained log); the enforcement decision is audited once at login
    (``auth.mfa_enforcement_blocked``).
    """
    from z4j_brain.domain.mfa.enforcement import evaluate_mfa_enforcement

    enforcement = evaluate_mfa_enforcement(user=user, settings=settings)
    if not enforcement.blocked:
        return
    if _matches_exempt_route(request, _MFA_ENROLLMENT_EXEMPT_ROUTES):
        return
    raise MfaEnrollmentRequiredError(
        "MFA enrollment required before this account can be used",
        details={
            "reason": "mfa_enrollment_required",
            "deadline": (
                enforcement.deadline.isoformat() if enforcement.deadline is not None else None
            ),
        },
    )


#: Routes a cookie session may reach when its owner HAS MFA enrolled but the
#: session has not yet passed the second factor (``mfa_verified_at`` is NULL):
#: exactly the routes needed to COMPLETE verification (submit a TOTP or
#: recovery code at ``/auth/mfa/verify``), plus whoami / mfa-status so the
#: dashboard can render the prompt, plus logout. Everything else is refused
#: until the second factor is presented. Paths are the full ``/api/v1``-
#: prefixed form and matched via :func:`_matches_exempt_route`.
_MFA_VERIFICATION_EXEMPT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/auth/mfa/verify"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/auth/mfa/status"),
    },
)


def enforce_mfa_verified(
    *,
    request: Request,
    user: User,
    session_row: SessionRow,
    settings: Settings,
) -> None:
    """Raise 403 ``mfa_reverify_required`` for a password-only session.

    Request-time enforcement of the second factor. A user with MFA
    ENROLLED whose current cookie session has never passed the second
    factor (``session.mfa_verified_at`` is NULL) is holding a
    password-only session: login issues the session cookie at the
    password step and only RETURNS ``mfa_required`` as a hint, so without
    this gate that session could reach the whole control plane on the
    password alone -- defeating the advertised "a stolen password is
    useless without the TOTP code" guarantee (docs/MFA-DESIGN.md). This
    gate refuses every route except the small allowlist a session needs to
    COMPLETE verification, so an attacker who ignores the client-side
    prompt gains nothing beyond whoami/logout.

    Reuses the ``mfa_reverify_required`` code (the same one the per-action
    step-up gate raises) so the dashboard's existing "prompt for a TOTP
    code and retry" handler resolves it: the user submits the code to
    ``/auth/mfa/verify`` (allowlisted), which stamps ``mfa_verified_at``,
    and the retried request passes. Any non-allowlisted route that trips
    this therefore self-heals through the same prompt.

    No-op for a user with no ACTIVE MFA (never enrolled, or mid-first-
    enrollment with ``mfa_enrolled_at`` NULL) -- those are the enrollment
    policy's concern, not this gate. The trust-cookie login branch stamps
    ``mfa_verified_at`` at login, so a remembered device passes. Cheap:
    pure computation over the already-loaded user + session rows.

    Bearer-only (API-key) requests never reach this gate -- they carry no
    cookie session, so ``get_optional_session`` returns None and the
    caller resolves via the API-key path, which does not call this.
    """
    has_mfa = user.mfa_secret_encrypted is not None and user.mfa_enrolled_at is not None
    if not has_mfa:
        return
    if session_row.mfa_verified_at is not None:
        return
    if _matches_exempt_route(request, _MFA_VERIFICATION_EXEMPT_ROUTES):
        return
    raise MfaReverifyRequiredError(
        "second-factor verification required before this account can be used",
        details={"reason": "mfa_verification_required"},
    )


async def get_current_user(
    request: Request,
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    api_key_user: User | None = Depends(_get_strict_api_key_user),
    settings: Settings = Depends(get_settings),
) -> User:
    """Return the authenticated user, or raise 401.

    A valid session cookie wins when both cookie and Bearer credentials are
    present. The Bearer header is not evaluated, scope-checked, touched, or
    used for audit attribution in that case. When no valid cookie resolves,
    Bearer authentication is strict: revoked, expired, stale-bound, and
    inactive-owner keys are refused rather than treated as anonymous.

    Cookie sessions additionally pass through
    :func:`enforce_mfa_enrollment`: a user targeted by the MFA
    enrollment-enforcement policy who is past the grace deadline gets
    403 ``mfa_enrollment_required`` everywhere except the enrollment
    allowlist. Bearer callers skip that gate (see its docstring).
    """
    if resolved is not None:
        enforce_mfa_enrollment(
            request=request,
            user=resolved[1],
            settings=settings,
        )
        enforce_mfa_verified(
            request=request,
            user=resolved[1],
            session_row=resolved[0],
            settings=settings,
        )
        # Stash the resolved user so the ErrorMiddleware denial-audit can
        # attribute a later 403 to it. get_current_user returns the User
        # as a dependency value and previously never recorded it on
        # request.state, so every denial-audit row persisted user_id=NULL
        # (B17). Set AFTER the MFA gates so a gated request that never
        # reaches its handler isn't audited as an authenticated actor.
        request.state.current_user = resolved[1]
        # Also stash the PK as a plain UUID, while the instance is still
        # attached. ErrorMiddleware reads this long after the request session
        # has closed, and reading ``.id`` off the detached ORM instance there
        # raises DetachedInstanceError instead of yielding the id.
        request.state.current_user_id = resolved[1].id
        return resolved[1]
    if api_key_user is not None:
        request.state.current_user = api_key_user
        request.state.current_user_id = api_key_user.id
        return api_key_user
    raise AuthenticationError("authentication required")


async def get_current_session(
    request: Request,
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    settings: Settings = Depends(get_settings),
) -> SessionRow:
    """Return the active session row, or raise 401.

    Used by ``/auth/logout`` so the handler has the session row to
    revoke without re-querying. Carries the same
    :func:`enforce_mfa_enrollment` gate as :func:`get_current_user`
    so no session-consuming route can dodge the enrollment policy by
    depending on the session row alone.
    """
    if resolved is None:
        raise AuthenticationError("authentication required")
    enforce_mfa_enrollment(
        request=request,
        user=resolved[1],
        settings=settings,
    )
    enforce_mfa_verified(
        request=request,
        user=resolved[1],
        session_row=resolved[0],
        settings=settings,
    )
    return resolved[0]


async def require_admin(
    user: User = Depends(get_current_user),
) -> User:
    """The current user must be a global brain admin."""
    if not user.is_admin:
        raise AuthorizationError("admin role required")
    return user


def enforce_fresh_mfa(
    *,
    user: User,
    session_row: SessionRow,
    settings: Settings,
) -> None:
    """Raise ``MfaReverifyRequiredError`` unless MFA was verified recently.

    The reusable core shared by :func:`require_fresh_mfa` (the route
    dependency) and by handlers that must gate a step-up CONDITIONALLY on
    the request body -- e.g. creating an automation rule that carries a
    DESTRUCTIVE action. A user with no MFA enrolled passes this gate --
    whether such a user is required to ENROLL is the separate
    enrollment-enforcement policy (:func:`enforce_mfa_enrollment`), not
    this per-action step-up gate.
    """
    from datetime import UTC, timedelta

    has_mfa = user.mfa_secret_encrypted is not None and user.mfa_enrolled_at is not None
    if not has_mfa:
        return
    verified_at = session_row.mfa_verified_at
    if verified_at is None:
        raise MfaReverifyRequiredError(
            "fresh MFA verification required",
            details={"ttl_seconds": settings.mfa_verification_ttl_seconds},
        )
    cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.mfa_verification_ttl_seconds,
    )
    # Normalise naive datetimes from SQLite to UTC for comparison.
    verified_at_aware = (
        verified_at if verified_at.tzinfo is not None else verified_at.replace(tzinfo=UTC)
    )
    if verified_at_aware < cutoff:
        raise MfaReverifyRequiredError(
            "fresh MFA verification required",
            details={"ttl_seconds": settings.mfa_verification_ttl_seconds},
        )


async def require_fresh_mfa(
    user: User = Depends(get_current_user),
    session_row: SessionRow = Depends(get_current_session),
    settings: Settings = Depends(get_settings),
) -> None:
    """Sensitive-action gate: caller must have verified MFA recently.

    Three branches:

    * User has no MFA enrolled. The gate is a no-op; the action
      proceeds. (NOTE: whether an un-enrolled user is REQUIRED to
      enroll is governed separately by ``Z4J_MFA_ENFORCE_FOR_ALL`` /
      ``Z4J_MFA_ENFORCE_FOR_ADMINS`` + the
      ``users.mfa_enforcement_started_at`` grace anchor: login stamps
      the anchor and surfaces the deadline, and past the deadline
      :func:`enforce_mfa_enrollment` restricts the session to the
      enrollment endpoints. This step-up gate stays orthogonal to
      that policy.)
    * User has MFA and the current session has ``mfa_verified_at``
      within the last ``Z4J_MFA_VERIFICATION_TTL_SECONDS``. Pass.
    * User has MFA but no recent verify. Raise ``403`` with
      ``error="mfa_reverify_required"``. The dashboard catches this
      response and prompts for a fresh TOTP code, then retries.

    Bearer / API-key callers: this dependency resolves the current
    session via ``get_current_session``, which raises 401 when there is
    no cookie session. So a bearer-only request to a route gated by this
    dependency is 401'd BEFORE this body runs -- i.e. these routes are
    cookie-session-only in practice (fail closed), NOT bearer-exempt. The
    ``session_row is None`` guard below is a defensive fallback for any
    caller that resolves an optional session; it is not the path a pure
    Bearer request takes here. (Automation's write gate uses the optional
    ``enforce_fresh_mfa(resolved is not None)`` pattern instead when it
    genuinely wants to let a scoped API key through.)
    """
    # Defensive: if a session row was resolved as optional (not the
    # 401-raising get_current_session path), a missing row means no
    # cookie session -> nothing to step up.
    if session_row is None:
        return
    enforce_fresh_mfa(user=user, session_row=session_row, settings=settings)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


async def require_csrf(
    request: Request,
    settings: Settings = Depends(get_settings),
    resolved: tuple[SessionRow, User] | None = Depends(get_optional_session),
    # Force Bearer resolution before the CSRF check so the exemption
    # below can read ``request.state.auth_kind`` reliably regardless
    # of the order FastAPI walks the dep DAG for a given endpoint.
    _api_key_user: User | None = Depends(_get_strict_api_key_user),
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
    "begin_sqlite_immediate_write_unit",
    "enforce_fresh_mfa",
    "enforce_mfa_enrollment",
    "enforce_mfa_verified",
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
    "get_mfa_recovery_codes_repo",
    "get_optional_user",
    "get_password_hasher",
    "get_project_repo",
    "get_session",
    "get_session_repo",
    "get_settings",
    "get_setup_service",
    "get_trusted_device_repo",
    "get_user_repo",
    "require_admin",
    "require_csrf",
    "require_fresh_mfa",
]
