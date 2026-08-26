"""HTTPS long-poll fallback for the agent transport.

Two endpoints, both bearer-authenticated, both speaking the v2
envelope-HMAC framing:

- ``POST /api/v1/agent/events`` - agent uploads a batch of signed
  outbound frames (event_batch, heartbeat, command_ack,
  command_result, registry_delta, error). The brain verifies each
  frame with the per-session :class:`FrameVerifier`. Eligible
  post-handshake frames use the same :class:`FrameRouter` as the
  WebSocket gateway, sharing its projection, audit, and notification
  behavior.
- ``GET /api/v1/agent/commands?wait=N`` - long-poll for pending
  commands. Returns immediately with any already-pending commands
  for this agent; otherwise blocks up to ``wait`` seconds (capped
  at 60) waiting for the dashboard / API to issue one. Each
  response frame is freshly v2-signed by the per-session
  :class:`FrameSigner` so the agent can verify it through the
  same code path it uses on the WebSocket.

The endpoints preserve the WebSocket transport's authentication,
signed-frame, command, and audit semantics, but are not a byte-for-byte
functional twin. Long-poll drops and acknowledges ``hello`` / ``hello_ack``
frames instead of routing the WebSocket handshake, so it does not register
``agent_workers`` rows or persist the full hello-derived worker metadata.
WebSocket records a successful ``hello`` as a connection; long-poll instead
refreshes database liveness when it authenticates at least one signed,
non-handshake upload. That authentication is the presence proof even if
downstream dispatch returns a transient outcome or crashes. Conversely, an
idle or command-only long-poll agent can age to ``offline`` in the dashboard
while it is still polling successfully. Long-poll uses repeated HTTP requests
rather than an open bidirectional socket, so its command-delivery latency and
connection visibility differ.

Deployments behind corporate proxies that strip Upgrade headers
can disable the WebSocket transport entirely and run on long-poll for core
event upload and command delivery. Deployments that require
WebSocket connection-presence semantics or the ``agent_workers`` process
inventory must retain the WebSocket transport.

**Session lifecycle.** The agent generates a fresh
``X-Z4J-Session-Nonce`` value on every ``connect()`` and sends it
on every request. The brain keys its per-session signer/verifier
state by ``(agent_id, session_nonce)`` so:

- A benign agent reconnect (process restart, network flap) gets a
  new nonce, the brain rebuilds state to match. The seq counter
  on the previous session can never block the new one.
- An attacker who lands a forged frame (e.g. ``seq=2**63-1``) can
  only poison the *attacker's* session_nonce. The legitimate
  agent's session is unaffected.
- ``SignatureError`` replaces the cached state with an invalidation
  marker. During its bounded five-minute retention, the failed nonce receives
  HTTP 409 until the agent performs the non-claiming
  ``GET /commands?max_frames=0`` connect probe with a fresh nonce. Agents must
  generate a fresh nonce after every signature failure; abandoned tombstones
  eventually expire with other idle registry state.

The registry has a hard 4096-entry admission cap. Requests pin their session
entry until the response is complete, so admission never evicts state used by
an in-flight request. At capacity an agent may replace only one of its own
idle nonces. Idle entries (including invalidation markers) expire after five
minutes, allowing a new agent to reclaim abandoned capacity without evicting
another agent's live state. Before that expiry, a new agent with no self-owned
victim receives HTTP 503.

Multi-worker deployments still need a shared ``ReplayGuard``
state in Redis or Postgres for true HA - tracked in
``docs/ENTERPRISE_READINESS.md`` under "Phase 3 HA brain". For
single-worker deployments today, the ``X-Z4J-LongPoll-Worker``
response header carries the worker pid so operators can pin
agents to one worker via their load balancer.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from z4j_core.errors import ProtocolVersionError, SignatureError
from z4j_core.transport.frames import (
    CommandFrame,
    CommandPayload,
    Frame,
    HelloAckFrame,
    HelloFrame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import derive_project_secret

from z4j_brain.domain.command_wire import wire_target
from z4j_brain.domain.ip_rate_limit import require_agent_connect_throttle
from z4j_brain.domain.retry_contract import (
    RETRY_FAMILY_ACTIONS,
    required_retry_engine,
    session_supports_retry_engine,
)
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.websocket.auth import resolve_agent_by_bearer
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Agent, Command


logger = structlog.get_logger("z4j.brain.agent_longpoll")

router = APIRouter(prefix="/agent", tags=["agent-longpoll"])


# ---------------------------------------------------------------------------
# Per-session signer / verifier registry
# ---------------------------------------------------------------------------
#
# Single-worker scope. Multi-worker deployments need a shared
# ``ReplayGuard`` state - see module docstring.
#
# Keyed by ``(agent_id, session_nonce)`` rather than just
# ``agent_id`` so that:
#   * a benign agent reconnect (new nonce) gets fresh seq state
#     instead of inheriting the previous session's ``_last_seq``,
#   * an attacker who lands a forged max-seq frame can only
#     poison their own session_nonce (which the legitimate agent
#     will never use), and
#   * a brain restart self-heals on the next reconnect cycle.
#
# Bounded at 4 096 sessions so a flood of distinct nonces cannot exhaust
# memory. A global-cap admission may evict only another idle session belonging
# to the same agent. Expired idle entries are garbage-collected across agents,
# but request leases ensure no admission evicts somebody else's in-flight
# state. ``SignatureError`` leaves a bounded invalidation marker, so a
# desynced peer must immediately handshake with a fresh nonce.

_SESSION_REGISTRY_MAX = 4096
#: Abandoned signer/verifier state and invalidation markers cannot consume the
#: bounded registry forever. This is deliberately longer than the maximum
#: 60-second long-poll request; request leases are the authoritative protection
#: against eviction and remain effective even if a request itself runs longer.
_SESSION_IDLE_TTL_SECONDS = 5 * 60.0
_SESSION_HEADER = "X-Z4J-Session-Nonce"
#: Long-poll analogue of WebSocket runtime-feature observability. This sticky
#: metadata is never retry authority; ``_RETRY_CONTRACTS_HEADER`` below is
#: checked on the exact request that claims a command.
_RUNTIME_FEATURES_HEADER = "X-Z4J-Runtime-Features"
_RETRY_CONTRACTS_HEADER = "X-Z4J-Retry-Contracts"
#: Bound so a malformed or hostile header cannot bloat the stored metadata.
_MAX_RUNTIME_FEATURES = 64
_MAX_RUNTIME_FEATURE_LEN = 64


def _longpoll_delivery_authority(
    agent_id: uuid.UUID,
    session_nonce: str | None,
) -> tuple[uuid.UUID, str] | None:
    """Derive credential-free authority from one verified long-poll nonce."""

    if not session_nonce:
        return None
    owner = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"z4j-longpoll-owner:{agent_id}:{session_nonce}",
    )
    generation = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"z4j-longpoll-generation:{agent_id}:{session_nonce}",
    )
    return owner, str(generation)


def _parse_runtime_features(raw: str | None) -> list[str] | None:
    """Parse the comma-separated feature header, or None when absent.

    None means "the agent said nothing", which is NOT the same as "the agent
    said it has no features": the first must leave any previously recorded set
    alone, the second must clear it.
    """
    if raw is None:
        return None
    out: list[str] = []
    for part in raw.split(","):
        name = part.strip()
        if name and len(name) <= _MAX_RUNTIME_FEATURE_LEN and name not in out:
            out.append(name)
        if len(out) >= _MAX_RUNTIME_FEATURES:
            break
    return out


def _parse_retry_contracts(raw: str | None) -> dict[str, int]:
    """Parse ``engine=version`` pairs for this exact polling request.

    Missing or malformed input fails closed to an empty set. Nothing is read
    from or written to sticky Agent metadata.
    """
    if not raw:
        return {}
    contracts: dict[str, int] = {}
    for part in raw.split(","):
        engine, separator, version = part.strip().partition("=")
        if (
            separator != "="
            or version != "1"
            or not engine
            or len(engine) > _MAX_RUNTIME_FEATURE_LEN
        ):
            return {}
        contracts[engine] = 1
        if len(contracts) > _MAX_RUNTIME_FEATURES:
            return {}
    return contracts


#: Per-agent session cap. Without this, one valid bearer can flood
#: 4 096 distinct nonces and LRU-evict every legitimate agent's
#: Session across the whole brain. Capping per-
#: agent means at worst the malicious agent evicts ITSELF, never
#: another agent. 16 simultaneous sessions per agent is generous
#: - a healthy agent has 1 active session at a time.
_SESSION_PER_AGENT_MAX = 16

#: Sentinel for "agent did not send the session-nonce header"
#: (legacy / out-of-tree client). A unique object instance -
#: not a string - so a malicious agent cannot forge it by sending
#: A literal string header value. Module-private
#: identity-equality is the safety property here.
_LEGACY_NONCE_SENTINEL = object()


class _InvalidatedSession:
    """Registry marker for a nonce that failed frame verification."""

    __slots__ = ()


class _SessionInvalidatedError(RuntimeError):
    """The caller reused a nonce whose session failed verification."""


class _SessionCapacityError(RuntimeError):
    """A session cannot be admitted without evicting another agent."""


_SESSION_INVALIDATED = _InvalidatedSession()
_SessionPair = tuple[FrameSigner, FrameVerifier]
_SessionKey = tuple[uuid.UUID, object]


@dataclass(slots=True)
class _SessionEntry:
    """One bounded registry slot.

    ``leases`` counts HTTP requests that may still use ``state``. Such an entry
    is never an eviction candidate, even after its idle TTL elapses. A retired
    entry is removed when its final request lease is released.
    """

    state: _SessionPair | _InvalidatedSession
    last_used: float
    leases: int = 0
    retire_on_release: bool = False


@dataclass(frozen=True, slots=True)
class _SessionLease:
    """Identity-stable lease used by the response-finalizer dependency."""

    key: _SessionKey
    entry: _SessionEntry


_sessions: OrderedDict[_SessionKey, _SessionEntry] = OrderedDict()
#: Per-agent session counter - used for the per-agent eviction cap.
#: Maintained in lockstep with ``_sessions``; cleaned on drop.
_sessions_per_agent: dict[uuid.UUID, int] = {}
_registry_lock = asyncio.Lock()


def _registry_now() -> float:
    """Monotonic registry clock, factored for deterministic lifecycle tests."""
    return time.monotonic()


def _longpoll_session_count() -> int:
    """Used by the metrics endpoint to surface in-memory state size."""
    return len(_sessions)


# Register at import time so /metrics scrapes pick this up. Safe
# in tests because the registry is brain-private (one per app).
try:
    from z4j_brain.api.metrics import register_inmemory_subsystem

    register_inmemory_subsystem("longpoll_sessions", _longpoll_session_count)
except Exception:  # noqa: S110  best-effort metrics registration, retried on next import
    # metrics module not importable yet (very early in test bootstrap);
    # the next import of this module will retry.
    pass


def _session_key(
    agent_id: uuid.UUID,
    session_nonce: str | None,
) -> tuple[uuid.UUID, object]:
    """Compute the registry key. Empty/missing nonce maps to a sentinel
    object so legacy agents that don't send the header still get a single
    shared session - they remain susceptible to the H1/H2 issues, but a
    header-aware agent gets the new safety guarantees automatically AND
    no string value can collide with the legacy bucket."""
    return (agent_id, session_nonce if session_nonce else _LEGACY_NONCE_SENTINEL)


def _remove_session_unlocked(key: _SessionKey) -> bool:
    """Remove one idle registry entry and maintain exact accounting.

    The caller must hold ``_registry_lock``. Leased entries are never removed;
    callers that need to revoke one mark it ``retire_on_release`` instead.
    """
    entry = _sessions.get(key)
    if entry is None or entry.leases:
        return False
    agent_id = key[0]
    current = _sessions_per_agent.get(agent_id)
    if current is None or current <= 0:
        raise RuntimeError("long-poll session registry accounting is inconsistent")
    _sessions.pop(key)
    if current == 1:
        _sessions_per_agent.pop(agent_id)
    else:
        _sessions_per_agent[agent_id] = current - 1
    return True


def _prune_expired_idle_sessions_unlocked(now: float) -> None:
    """Retire expired, unleased entries across agents in LRU order."""
    for key, entry in list(_sessions.items()):
        if entry.leases == 0 and now - entry.last_used >= _SESSION_IDLE_TTL_SECONDS:
            _remove_session_unlocked(key)


def _evict_oldest_idle_session_unlocked(
    agent_id: uuid.UUID,
    *,
    preserve: _SessionKey,
) -> bool:
    """Evict this agent's oldest idle valid session, never another agent's.

    Invalidation markers are not nonce-churn victims: they are retired only by
    their TTL or an explicit fresh connect probe. Request-leased entries are
    never victims, irrespective of their age.
    """
    victim = next(
        (
            candidate
            for candidate, entry in _sessions.items()
            if candidate != preserve
            and candidate[0] == agent_id
            and entry.leases == 0
            and not isinstance(entry.state, _InvalidatedSession)
        ),
        None,
    )
    return victim is not None and _remove_session_unlocked(victim)


def _invalidated_keys_unlocked(agent_id: uuid.UUID) -> list[_SessionKey]:
    """Return this agent's invalidated registry keys in LRU order."""
    return [
        candidate
        for candidate, entry in _sessions.items()
        if candidate[0] == agent_id and isinstance(entry.state, _InvalidatedSession)
    ]


def _ensure_admission_capacity_unlocked(
    agent_id: uuid.UUID,
    *,
    preserve: _SessionKey,
) -> None:
    """Make exactly one slot available without crossing an agent boundary."""
    while (
        _sessions_per_agent.get(agent_id, 0) >= _SESSION_PER_AGENT_MAX
        or len(_sessions) >= _SESSION_REGISTRY_MAX
    ):
        if not _evict_oldest_idle_session_unlocked(agent_id, preserve=preserve):
            if _sessions_per_agent.get(agent_id, 0) >= _SESSION_PER_AGENT_MAX:
                raise _SessionCapacityError(
                    "long-poll per-agent session capacity reached",
                )
            raise _SessionCapacityError(
                "long-poll session registry is at capacity; retry later",
            )


def _bind_request_session_lease(request: Request, lease: _SessionLease) -> None:
    """Attach one lease to the request's guaranteed-finalizer dependency."""
    if getattr(request.state, "_z4j_longpoll_session_lease", None) is not None:
        raise RuntimeError("long-poll request acquired more than one session lease")
    request.state._z4j_longpoll_session_lease = lease


async def _get_or_create_session(
    *,
    agent: Agent,
    master_secret: bytes,
    session_nonce: str | None,
    establishes_session: bool = False,
    request: Request | None = None,
) -> tuple[FrameSigner, FrameVerifier]:
    """Return the per-session signer/verifier pair, creating it on first use.

    The signing material is the per-project derived secret
    (:func:`derive_project_secret`), not the brain master, so a
    leaked agent host secret cannot forge frames against other
    projects.
    """
    key = _session_key(agent.id, session_nonce)
    async with _registry_lock:
        now = _registry_now()
        existing = _sessions.get(key)
        if (
            existing is not None
            and existing.leases == 0
            and now - existing.last_used >= _SESSION_IDLE_TTL_SECONDS
        ):
            _remove_session_unlocked(key)
            existing = None
        if existing is not None and isinstance(existing.state, _InvalidatedSession):
            raise _SessionInvalidatedError(
                "long-poll session invalidated; reconnect with a fresh session nonce",
            )
        if existing is not None:
            existing.last_used = now
            _sessions.move_to_end(key)  # MRU
            if request is not None:
                _bind_request_session_lease(request, _SessionLease(key, existing))
                existing.leases += 1
            state = existing.state
            if isinstance(state, _InvalidatedSession):  # pragma: no cover - narrowed above
                raise RuntimeError("invalidated session escaped registry guard")
            return state

        # Full-registry scanning is restricted to admission, not the hot path
        # for an existing polling session.
        _prune_expired_idle_sessions_unlocked(now)
        invalidated = _invalidated_keys_unlocked(agent.id)
        if invalidated and not establishes_session:
            raise _SessionInvalidatedError(
                "long-poll session invalidated; perform the connect probe "
                "with a fresh session nonce",
            )
        # A non-claiming GET /commands connect probe under a different nonce
        # is the long-poll handshake. Once it succeeds, the obsolete failed
        # nonce markers have done their job and can be retired atomically. A
        # marker still leased by its failing request is not yet session-safe;
        # the probe retries after that response completes.
        if any(_sessions[invalidated_key].leases for invalidated_key in invalidated):
            raise _SessionInvalidatedError(
                "long-poll invalidation is still completing; retry the fresh connect probe",
            )
        for invalidated_key in invalidated:
            _remove_session_unlocked(invalidated_key)

        # Enforce both bounds once, under the same lock used for accounting.
        # A single self-owned idle victim can satisfy both a per-agent and a
        # global bound; the old two-step path could evict twice, and a failed
        # invalidation eviction could increment past both caps.
        _ensure_admission_capacity_unlocked(agent.id, preserve=key)

        project_secret = derive_project_secret(master_secret, agent.project_id)
        # Bind the caller-supplied session nonce into the HMAC envelope.
        # For long-poll the nonce IS the session identity (the
        # registry is keyed on it). Without binding, a captured
        # frame from session-nonce A could be replayed inside
        # session-nonce B since both sessions reset seq=0 + have
        # independent nonce windows. Binding makes the HMAC fail.
        # The legacy sentinel (no-nonce client) gets an empty
        # binding string, those clients are documented as
        # "remain susceptible to H1/H2".
        binding = session_nonce if isinstance(session_nonce, str) else ""
        signer = FrameSigner(
            secret=project_secret,
            agent_id=agent.id,
            project_id=agent.project_id,
            session_id=binding,
        )
        verifier = FrameVerifier(
            secret=project_secret,
            agent_id=agent.id,
            project_id=agent.project_id,
            session_id=binding,
            direction="agent->brain",
        )
        pair = (signer, verifier)
        entry = _SessionEntry(
            state=pair,
            last_used=now,
            leases=1 if request is not None else 0,
        )
        if request is not None:
            _bind_request_session_lease(request, _SessionLease(key, entry))
        _sessions[key] = entry
        _sessions_per_agent[agent.id] = _sessions_per_agent.get(agent.id, 0) + 1
        return pair


async def _record_longpoll_liveness(
    db: DatabaseManager,
    agent_id: uuid.UUID,
    *,
    authenticated: bool,
) -> None:
    """Reflect a long-poll cycle as agent liveness on ``/agents``.

    Liveness (both the ``last_seen_at`` bump AND the promote) is gated
    on ``authenticated`` -- at least one signed, non-handshake frame in
    the upload passed HMAC verification. Its downstream dispatch outcome
    deliberately does not matter: a transient database failure or router
    crash does not erase the cryptographic proof that the agent is alive.
    A wholly unauthenticated upload does NOT refresh liveness, otherwise a
    bearer holder who cannot produce a valid frame HMAC could keep a dead
    agent pinned ONLINE by POSTing garbage, suppressing the offline sweep
    and its alerts. The sweep keys off a stale ``last_seen_at``, so
    refreshing it on unverified traffic would defeat it.

    When there IS verified traffic, promote the agent to online:
    long-poll has no hello handshake, so nothing else calls
    ``mark_online``, and an agent with heartbeats disabled would
    otherwise stay pinned at ``unknown`` even while verifiably
    delivering events.
    """
    if not authenticated:
        return
    from z4j_brain.persistence.repositories import AgentRepository

    async with db.session() as session:
        agents_repo = AgentRepository(session)
        await agents_repo.touch_heartbeat(agent_id)
        await agents_repo.promote_online_if_offline(agent_id)
        await session.commit()


async def _drop_session(agent_id: uuid.UUID, session_nonce: str | None) -> None:
    """Retire one active or invalidated session without breaking a lease."""
    key = _session_key(agent_id, session_nonce)
    async with _registry_lock:
        entry = _sessions.get(key)
        if entry is None:
            return
        if entry.leases:
            entry.state = _SESSION_INVALIDATED
            entry.retire_on_release = True
            entry.last_used = _registry_now()
            _sessions.move_to_end(key)
        else:
            _remove_session_unlocked(key)


async def _invalidate_session(agent_id: uuid.UUID, session_nonce: str | None) -> None:
    """Replace a failed session with a same-size invalidation marker."""
    key = _session_key(agent_id, session_nonce)
    async with _registry_lock:
        now = _registry_now()
        entry = _sessions.get(key)
        if entry is None:
            # Request paths lease their entry, so this branch is only a
            # defensive guard for internal/unleased callers. It must obey the
            # same exact bounds as ordinary admission. In particular, never
            # increment after a failed self-eviction: that historical race
            # grew a 2/2 registry to 4/4 with missing-key invalidations.
            _prune_expired_idle_sessions_unlocked(now)
            _ensure_admission_capacity_unlocked(agent_id, preserve=key)
            _sessions[key] = _SessionEntry(
                state=_SESSION_INVALIDATED,
                last_used=now,
            )
            _sessions_per_agent[agent_id] = _sessions_per_agent.get(agent_id, 0) + 1
        else:
            entry.state = _SESSION_INVALIDATED
            entry.last_used = now
        _sessions.move_to_end(key)


async def _release_session_lease(lease: _SessionLease) -> None:
    """Release exactly the entry acquired by one HTTP request."""
    async with _registry_lock:
        entry = _sessions.get(lease.key)
        if entry is not lease.entry:
            # Identity matching prevents a delayed finalizer from touching a
            # later generation under the same nonce.
            return
        if entry.leases <= 0:
            raise RuntimeError("long-poll session lease accounting underflow")
        entry.leases -= 1
        entry.last_used = _registry_now()
        if entry.retire_on_release and entry.leases == 0:
            _remove_session_unlocked(lease.key)
        else:
            _sessions.move_to_end(lease.key)


async def _release_longpoll_session_after_request(
    request: Request,
) -> AsyncIterator[None]:
    """FastAPI finalizer that makes request leases cancellation-safe."""
    try:
        yield
    finally:
        lease = getattr(request.state, "_z4j_longpoll_session_lease", None)
        if lease is not None:
            request.state._z4j_longpoll_session_lease = None
            release_task = asyncio.create_task(_release_session_lease(lease))
            try:
                await asyncio.shield(release_task)
            except asyncio.CancelledError:
                # ``shield`` leaves the release task running; keep a strong
                # reference and wait for its bounded critical section before
                # propagating cancellation so the lease cannot pin capacity.
                await asyncio.shield(release_task)
                raise


def _session_http_error(exc: _SessionInvalidatedError | _SessionCapacityError) -> HTTPException:
    """Translate registry state into a reconnect-safe HTTP response."""
    if isinstance(exc, _SessionInvalidatedError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(
        status_code=503,
        detail=str(exc),
        headers={"Retry-After": "1"},
    )


# ---------------------------------------------------------------------------
# Long-poll request/response bodies
# ---------------------------------------------------------------------------


class FrameUploadBody(BaseModel):
    """Payload of ``POST /agent/events``.

    ``frames`` is a list of pre-serialised v2 frames (each is a
    JSON object stringified). Sending a list rather than one frame
    per request keeps round-trip count down on chatty workloads.
    """

    frames: list[str] = Field(min_length=1, max_length=500)

    @field_validator("frames")
    @classmethod
    def _cap_per_frame_size(cls, v: list[str]) -> list[str]:
        """Per-frame size cap.

        Without this, the 500-element list cap is the only
        bound and each string is unlimited, so a single request
        could carry 500 x 100 MB and OOM the brain before any
        downstream validator ran. Per-frame ceiling matches the
        wire frame cap (default 1 MiB).
        """
        max_per_frame = 1 * 1024 * 1024  # 1 MiB
        for idx, frame in enumerate(v):
            try:
                encoded_size = len(frame.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ValueError(f"frames[{idx}] is not valid UTF-8") from exc
            if encoded_size > max_per_frame:
                raise ValueError(
                    f"frames[{idx}] is {encoded_size} bytes; cap is {max_per_frame}",
                )
        return v


class FrameUploadResponse(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)
    error_code: str | None = None


class CommandPullResponse(BaseModel):
    """Payload of ``GET /agent/commands``.

    ``frames`` is a list of stringified v2 ``command`` frames -
    each already signed by the brain's :class:`FrameSigner` and
    ready for the agent's :class:`FrameVerifier`. An empty list means
    no command was delivered in this response. That includes an explicit
    non-claiming ``max_frames=0`` connect probe, a timeout/no-pending result,
    and a concurrent-claim race in which another poll wins the selected row.
    The agent should treat all of those cases identically and re-poll.
    """

    frames: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/events", response_model=FrameUploadResponse)
async def agent_events(  # noqa: PLR0912, PLR0915  long-poll event-upload handler
    body: FrameUploadBody,
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
    session_nonce: str | None = Header(default=None, alias=_SESSION_HEADER),
    _throttle: None = Depends(require_agent_connect_throttle),
    _session_finalizer: None = Depends(_release_longpoll_session_after_request),
) -> FrameUploadResponse:
    """Accept a batch of signed agent->brain frames over HTTPS."""
    settings = request.app.state.settings
    db = request.app.state.db
    response.headers["X-Z4J-LongPoll-Worker"] = str(os.getpid())

    async with db.session() as session:
        from z4j_brain.persistence.repositories import AgentRepository

        agent = await resolve_agent_by_bearer(
            bearer=authorization,
            settings=settings,
            agents=AgentRepository(session),
        )
    if agent is None:
        raise HTTPException(status_code=401, detail="invalid agent token")

    # Same identity advertisement as GET /commands (the connect
    # probe), so either route teaches the transport its canonical
    # signing identity.
    response.headers["X-Z4J-Agent-Id"] = str(agent.id)
    response.headers["X-Z4J-Project-Id"] = str(agent.project_id)

    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    try:
        _, verifier = await _get_or_create_session(
            agent=agent,
            master_secret=master_bytes,
            session_nonce=session_nonce,
            request=request,
        )
    except (_SessionInvalidatedError, _SessionCapacityError) as exc:
        raise _session_http_error(exc) from exc

    ingestor = request.app.state.event_ingestor
    dispatcher = request.app.state.command_dispatcher
    dashboard_hub = getattr(request.app.state, "dashboard_hub", None)
    delivery_authority = _longpoll_delivery_authority(
        agent.id,
        session_nonce,
    )

    frame_router = FrameRouter(
        db=db,
        ingestor=ingestor,
        dispatcher=dispatcher,
        project_id=agent.project_id,
        agent_id=agent.id,
        dashboard_hub=dashboard_hub,
        transport_kind=("longpoll" if delivery_authority is not None else None),
        registry_owner_id=(delivery_authority[0] if delivery_authority is not None else None),
        session_generation=(delivery_authority[1] if delivery_authority is not None else None),
        automation_notify_coalesce_seconds=settings.automation_notify_coalesce_seconds,
        automation_outbox_max_rows_per_project=settings.automation_outbox_max_rows_per_project,
    )

    # Per-frame accounting, keyed to the brain's dispatch verdict:
    #   ``accepted``      -- frames the agent should CONFIRM+DELETE: a
    #     DURABLE store, a permanent DROP (deterministic; re-sending fails
    #     identically), or an unparseable frame dropped at the source.
    #   ``rejected``      -- frames the agent should RE-SEND: a TRANSIENT
    #     failure (deadlock / pool timeout / transient skip) or a version-
    #     skew frame that will land on an upgraded replica.
    #   ``authenticated`` -- frames that passed parse + HMAC (reached
    #     dispatch). This is the ONLY liveness signal: an unauthenticated
    #     frame (parse fail before HMAC, version skew before HMAC, or a
    #     signature failure) must never refresh ``last_seen_at``.
    # The RESPONSE accepted-count = ``accepted`` (DURABLE + DROP + parse-
    # drop); the agent confirms iff it equals the frames it sent.
    accepted = 0
    rejected = 0
    authenticated = 0
    errors: list[str] = []
    error_code: str | None = None
    session_invalidated = False
    total = len(body.frames)
    for idx, raw in enumerate(body.frames):
        try:
            frame: Frame = verifier.parse_and_verify(raw)
        except SignatureError as exc:
            # Invalidate the cached session state on signature failure.
            # On the WebSocket path this is a connection-fatal
            # 4403 close. Here we have no persistent connection,
            # but we MUST invalidate the per-session signer/
            # verifier so a forged max-seq frame cannot
            # permanently DoS the legitimate agent's session
            # (the agent will reconnect with a fresh nonce; we'd
            # otherwise still be holding the poisoned _last_seq
            # under the old key). The marker also prevents the next
            # request under that same nonce from silently creating a fresh
            # verifier. The remaining frames in this
            # batch are all rejected - we cannot trust ordering
            # once any verification failed.
            errors.append(f"verify failed: {exc}")
            logger.warning(
                "z4j longpoll: frame verification failed - invalidating session",
                agent_id=str(agent.id),
                session_nonce=session_nonce,
                reason=str(exc),
            )
            await _invalidate_session(agent.id, session_nonce)
            session_invalidated = True
            rejected += total - idx
            break
        except ProtocolVersionError as exc:
            # A version-skew frame is AUTHENTIC and RECOVERABLE: the same
            # bytes parse against a peer built with the matching
            # PROTOCOL_VERSION. During a rolling protocol upgrade it must be
            # RE-SENT (it will land on an already-upgraded replica), not
            # dropped -- so count it rejected (retry), not accepted. It is
            # NOT authenticated (the version gate is before HMAC), so it
            # does not refresh liveness.
            rejected += 1
            errors.append(f"version skew (retry): {exc}")
            logger.warning(
                "z4j longpoll: protocol-version skew; asking agent to retry",
                agent_id=str(agent.id),
                error_class=type(exc).__name__,
            )
            continue
        except Exception as exc:
            # A frame that PARSE-fails (unknown type / malformed JSON -- not
            # a signature or version error, handled above) is
            # DETERMINISTICALLY undeliverable: the agent signed and sent
            # these exact bytes, so re-sending them fails to parse
            # identically forever. Drop-and-ack it at the source (count it
            # accepted below) so the agent's confirm_on_send deletes it
            # instead of looping on it and starving every frame behind it
            # It does NOT count toward liveness: the parse failure is
            # raised BEFORE HMAC verification, so an unauthenticated garbage
            # frame must never refresh last_seen_at.
            accepted += 1
            logger.warning(
                "z4j longpoll: dropping unparseable agent frame "
                "(deterministic; acked so the agent does not loop)",
                agent_id=str(agent.id),
                error_class=type(exc).__name__,
            )
            continue

        # Unsigned handshake frames (hello / hello_ack) pass parse_and_verify
        # WITHOUT HMAC (they precede the shared session secret), so they must
        # NOT count toward the authenticated-liveness signal: a bearer-token
        # holder without the project HMAC could otherwise keep a dead agent
        # marked ONLINE by POSTing hello frames, defeating the offline sweep
        # Drop-and-ack it (accepted, matching the deterministic-drop
        # pattern so a sender never loops) and skip the liveness counter.
        if isinstance(frame, (HelloFrame, HelloAckFrame)):
            accepted += 1
            logger.warning(
                "z4j longpoll: dropping unsigned handshake frame on /events "
                "(no HMAC; excluded from liveness)",
                agent_id=str(agent.id),
                frame_type=getattr(frame, "type", None),
            )
            continue

        # The frame passed parse + HMAC -> it proves an authenticated,
        # live agent regardless of whether it stores.
        authenticated += 1

        # Over long-poll the HTTP 200 accepted-count is the acknowledgement.
        # CONFIRMED outcomes (DURABLE store or permanent DROP) count
        # accepted. TRANSIENT counts rejected so the agent re-sends;
        # UPGRADE_REQUIRED also stays unconfirmed but carries a typed,
        # operator-actionable failure.
        try:
            outcome = await frame_router.dispatch(frame)
        except Exception:  # defensive: dispatch is contracted not to raise
            rejected += 1
            errors.append("dispatch crashed (retry)")
            logger.exception(
                "z4j longpoll: dispatch crashed",
                agent_id=str(agent.id),
            )
            continue
        if outcome is FrameOutcome.REVOKED:
            rejected += total - idx
            error_code = "agent_revoked"
            errors.append("agent token revoked")
            break
        if outcome is FrameOutcome.UPGRADE_REQUIRED:
            rejected += 1
            error_code = "scheduler_upgrade_required"
            errors.append("scheduler adapter upgrade required")
        elif outcome.confirmed:
            accepted += 1
        else:
            rejected += 1
            errors.append("transient; agent re-sends")

    if error_code == "agent_revoked":
        await _drop_session(agent.id, session_nonce)
        raise HTTPException(status_code=401, detail="invalid agent token")

    # Liveness refreshes ONLY on an authenticated frame (passed parse +
    # HMAC), never on garbage / version-skew / bad-signature traffic.
    # Best-effort: the frame outcomes above are already RESOLVED, so a
    # deterministic liveness-write failure (schema/permission) must NOT turn
    # the resolved 200 into a 500 -- that would make the agent re-POST
    # already-stored (or intentionally dropped) frames forever, since the
    # fault re-fires on every request (round-8 external M-liveness).
    try:
        await _record_longpoll_liveness(db, agent.id, authenticated=authenticated > 0)
    except Exception:
        logger.exception(
            "z4j longpoll: liveness write failed; not failing the resolved delivery response",
            agent_id=str(agent.id),
        )

    if session_invalidated:
        raise HTTPException(
            status_code=409,
            detail="long-poll session invalidated; reconnect with a fresh session nonce",
        )

    return FrameUploadResponse(
        accepted=accepted,
        rejected=rejected,
        errors=errors[:10],
        error_code=error_code,
    )


@router.get("/commands", response_model=CommandPullResponse)
async def agent_commands(  # noqa: PLR0915, PLR0912  long-poll command handler
    request: Request,
    response: Response,
    wait: int = Query(default=30, ge=0, le=60),
    # Ge=0 -- max_frames=0 is a non-claiming liveness/identity probe.
    max_frames: int = Query(default=50, ge=0, le=500),
    authorization: str | None = Header(default=None),
    session_nonce: str | None = Header(default=None, alias=_SESSION_HEADER),
    runtime_features: str | None = Header(default=None, alias=_RUNTIME_FEATURES_HEADER),
    retry_contracts: str | None = Header(default=None, alias=_RETRY_CONTRACTS_HEADER),
    _throttle: None = Depends(require_agent_connect_throttle),
    _session_finalizer: None = Depends(_release_longpoll_session_after_request),
) -> CommandPullResponse:
    """Long-poll for pending commands targeting this agent."""
    settings = request.app.state.settings
    db = request.app.state.db
    response.headers["X-Z4J-LongPoll-Worker"] = str(os.getpid())

    async with db.session() as session:
        from z4j_brain.persistence.repositories import AgentRepository

        agent = await resolve_agent_by_bearer(
            bearer=authorization,
            settings=settings,
            agents=AgentRepository(session),
        )
    if agent is None:
        raise HTTPException(status_code=401, detail="invalid agent token")

    # Advertise the canonical agent/project UUIDs, the long-poll
    # analogue of the WebSocket hello_ack. The agent's config holds
    # the project SLUG, but the frame HMAC envelope binds the
    # project UUID on the brain side, so without these headers the
    # transport has no way to learn the UUIDs it must sign with
    # (pre-1.7 it minted a random uuid4 and every frame failed
    # verification in both directions).
    response.headers["X-Z4J-Agent-Id"] = str(agent.id)
    response.headers["X-Z4J-Project-Id"] = str(agent.project_id)

    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    try:
        signer, _ = await _get_or_create_session(
            agent=agent,
            master_secret=master_bytes,
            session_nonce=session_nonce,
            establishes_session=max_frames == 0,
            request=request,
        )
    except (_SessionInvalidatedError, _SessionCapacityError) as exc:
        raise _session_http_error(exc) from exc

    # max_frames=0 is a NON-CLAIMING liveness/identity probe. connect()
    # uses it to learn the canonical agent/project UUIDs (the headers above) and
    # confirm reachability WITHOUT claiming any command. The old probe used
    # max_frames>=1 and DISCARDED the body, so it marked a pending DESTRUCTIVE
    # command DISPATCHED; being non-redeliverable it was then never re-sent and
    # stranded until timeout. Returning before the claim loop preserves the
    # claim==delivery invariant: only receive_frames (which actually delivers the
    # body to the runtime) may claim a command.
    if max_frames == 0:
        # Record runtime-wide feature flags for operator observability. Retry
        # authority is not read from this sticky row; the adapter-derived
        # contract header is checked on each claiming request below.
        features = _parse_runtime_features(runtime_features)
        if features is not None:
            async with db.session() as session:
                from z4j_brain.persistence.repositories import AgentRepository

                await AgentRepository(session).record_runtime_features(
                    agent_id=agent.id, runtime_features=features
                )
                await session.commit()
        return CommandPullResponse(frames=[])

    session_retry_contracts = _parse_retry_contracts(retry_contracts)
    current_authority = _longpoll_delivery_authority(
        agent.id,
        session_nonce,
    )

    async def _require_live_agent() -> None:
        """Revalidate authority after a long-poll wait."""
        from z4j_brain.persistence.repositories import AgentRepository

        async with db.session() as live_session:
            live = await AgentRepository(live_session).get_live(agent.id)
            if live is None:
                await _drop_session(agent.id, session_nonce)
                raise HTTPException(status_code=401, detail="invalid agent token")

    # Inner helper that does ONE pass over the commands table for
    # this agent. Returns the list of pending Command rows or [].
    #
    # Also include recently-DISPATCHED commands within
    # ``Z4J_AGENT_LONGPOLL_REDISPATCH_SECONDS`` (default 60s) so
    # a quickly-reconnecting agent gets the same command re-sent.
    # If the HTTP response never reached the agent (network drop
    # after the brain committed mark_dispatched), the command
    # would otherwise sit in DISPATCHED state with no agent ever
    # seeing it - recoverable only via CommandTimeoutWorker
    # minutes later, surfaced as a generic timeout to the user.
    # The agent's in-memory ``_seen_commands`` dedup (300s TTL)
    # silently absorbs duplicates that reach a still-running
    # process. The redispatch only re-fires for commands the
    # agent never processed because the network dropped before
    # delivery completed.
    from datetime import UTC, datetime, timedelta

    async def _pull_pending(limit: int) -> list[Command]:
        if limit <= 0:
            return []
        from sqlalchemy import and_, or_

        from z4j_brain.persistence.models import Command
        from z4j_brain.persistence.repositories.commands import (
            _REDELIVERABLE_ACTIONS,
        )

        # Recompute the cutoffs on EACH poll, not once at request start
        # frozen into this closure. A DISPATCHED row that becomes lease-eligible
        # (its last send ages past ``min_interval``) DURING the wait must be seen
        # on the next poll; with frozen cutoffs the eligibility boundary never
        # advanced with wall-clock time, so such a row was only picked up on the
        # NEXT long-poll request -- delaying recovery by up to a full wait cycle.
        _now = datetime.now(UTC)
        redispatch_cutoff = _now - timedelta(
            seconds=getattr(
                settings,
                "agent_longpoll_redispatch_seconds",
                60.0,
            ),
        )
        # The lease cutoff -- a DISPATCHED row is re-send-eligible only
        # if its last send was at least min_interval ago (matches
        # claim_redispatch's server-side lease).
        lease_cutoff = _now - timedelta(
            seconds=getattr(
                settings,
                "agent_longpoll_redispatch_min_interval_seconds",
                10.0,
            ),
        )
        retry_engines = tuple(session_retry_contracts)
        session_eligible = or_(
            ~Command.action.in_(RETRY_FAMILY_ACTIONS),
            and_(
                Command.action == "retry_task",
                Command.payload["engine"].as_string().in_(retry_engines),
            ),
            and_(
                Command.action == "bulk_retry",
                Command.payload["filter"]["engine"].as_string().in_(retry_engines),
            ),
        )
        delivery_states = [
            Command.status == CommandStatus.PENDING,
            and_(
                Command.status == CommandStatus.DISPATCHED,
                Command.schedule_protocol_marker.is_(None),
                Command.dispatched_at >= redispatch_cutoff,
                Command.dispatched_at <= lease_cutoff,
                Command.action.in_(_REDELIVERABLE_ACTIONS),
            ),
        ]
        if current_authority is not None:
            delivery_states.append(
                and_(
                    Command.status == CommandStatus.DISPATCHED,
                    Command.schedule_protocol_marker.is_not(None),
                    Command.agent_acknowledged_at.is_(None),
                    Command.delivery_transport_kind == "longpoll",
                    Command.delivery_registry_owner_id == current_authority[0],
                    Command.delivery_session_generation == current_authority[1],
                    Command.delivery_claim_token.is_not(None),
                    Command.cadence_redelivery_deadline > _now,
                    Command.timeout_at > _now,
                    Command.dispatched_at <= lease_cutoff,
                ),
            )
        async with db.session() as session:
            result = await session.execute(
                select(Command)
                .where(
                    Command.agent_id == agent.id,
                    session_eligible,
                    # Every selected DISPATCHED row is already
                    # deliverable.  Generic recovery uses its action allowlist;
                    # marked cadence recovery instead requires this exact
                    # verified nonce-derived owner and immutable deadline.
                    or_(*delivery_states),
                )
                .order_by(Command.issued_at.asc())
                .limit(limit),
            )
            return list(result.scalars().all())

    # Boundary B: a long-poll request is itself the exact immutable send edge.
    # The generation binds this agent + nonce without persisting the raw nonce.
    generation = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"z4j-longpoll:{agent.id}:{session_nonce or '<legacy>'}",
    )

    async def _claim_bulk(limit: int) -> list[Command]:
        if limit <= 0:
            return []
        coordinator = request.app.state.bulk_retry_coordinator
        return await coordinator.claim_for_longpoll(
            project_id=agent.project_id,
            agent_id=agent.id,
            retry_contracts=dict(session_retry_contracts),
            generation=generation,
            maximum=limit,
        )

    async def _poll_once(limit: int) -> tuple[list[Command], list[Command]]:
        await _require_live_agent()
        bulk = await _claim_bulk(limit)
        ordinary = await _pull_pending(limit - len(bulk))
        return bulk, ordinary

    # Fast path: claim durable children first, then fill the response with
    # ordinary commands. Both paths remain bounded by max_frames.
    bulk_claimed, pending = await _poll_once(max_frames)
    if not bulk_claimed and not pending and wait > 0:
        # Slow path: poll the table at 250 ms intervals up to
        # ``wait`` seconds. A future improvement is to wake on a
        # Postgres NOTIFY (the registry already publishes one);
        # the polling fallback works even without a Postgres
        # backend (SQLite dev mode).
        deadline = asyncio.get_running_loop().time() + wait
        while not bulk_claimed and not pending:
            await asyncio.sleep(0.25)
            if asyncio.get_running_loop().time() >= deadline:
                break
            bulk_claimed, pending = await _poll_once(max_frames)

    if not bulk_claimed and not pending:
        # A revoke can commit while this request sleeps. Do not report a normal
        # empty poll after the bearer has lost authority.
        await _require_live_agent()
        return CommandPullResponse(frames=[])

    # Claim → sign → respond, in that order. Each step is critical:
    #
    # 1. Claim FIRST via ``mark_dispatched``. The UPDATE is
    #    ``WHERE id=? AND status=PENDING`` so Postgres serialises
    #    concurrent pollers - only one wins; the loser sees
    #    ``rowcount=0`` and skips the command. Without this
    #    ordering, two pollers can both ``SELECT`` the same row,
    #    both sign, both append to ``out_frames``, then both call
    #    ``mark_dispatched`` (one wins) - but the agent has
    #    already received the duplicate frame from both
    #    responses. The fix is to honour the boolean return.
    #
    # 2. Sign AFTER the claim. If signing throws, the row is now
    #    in ``DISPATCHED`` state without ever being delivered, so
    #    we transition it to ``FAILED`` to surface the problem
    #    to the user instead of silently waiting for it to time
    #    out. Reverting to ``PENDING`` would re-open the race.
    #
    # 3. Append to ``out_frames`` only after both succeed.
    out_frames: list[str] = []
    # These rows were inserted DISPATCHED in the irreversible child-claim
    # transaction. Sign them directly; never pass them through the generic
    # DISPATCHED redispatch branch (bulk_retry is intentionally non-redeliverable).
    if bulk_claimed:
        async with db.session() as bulk_session:
            from z4j_brain.persistence.repositories import (
                BulkRetryRequestRepository,
                CommandRepository,
            )

            bulk_commands = CommandRepository(bulk_session)
            for cmd in bulk_claimed:
                try:
                    payload = CommandPayload(
                        action=cmd.action,
                        target=wire_target(
                            cmd.target_type,
                            cmd.target_id,
                            cmd.payload,
                        ),
                        parameters=cmd.payload,
                        timeout_seconds=settings.command_timeout_seconds,
                        issued_by=str(cmd.issued_by) if cmd.issued_by else None,
                    )
                    frame = CommandFrame(id=str(cmd.id), payload=payload)
                    out_frames.append(signer.sign_and_serialize(frame).decode("utf-8"))
                except Exception as exc:
                    logger.exception(
                        "z4j longpoll: failed to sign durable bulk child after claim",
                        command_id=str(cmd.id),
                    )
                    await bulk_commands.mark_failed(
                        cmd.id,
                        error=f"longpoll sign failed: {type(exc).__name__}",
                    )
            await BulkRetryRequestRepository(bulk_session).reconcile_command_outcomes(
                limit=len(bulk_claimed)
            )
            await bulk_session.commit()

    def _encode_command(command: Command) -> str:
        payload = CommandPayload(
            action=command.action,
            target=wire_target(
                command.target_type,
                command.target_id,
                command.payload,
            ),
            parameters=command.payload,
            timeout_seconds=settings.command_timeout_seconds,
            issued_by=str(command.issued_by) if command.issued_by else None,
            delivery_claim_token=(
                str(command.delivery_claim_token)
                if command.delivery_claim_token is not None
                else None
            ),
        )
        return signer.sign_and_serialize(
            CommandFrame(id=str(command.id), payload=payload),
        ).decode("utf-8")

    from z4j_brain.persistence.repositories import AgentRepository, CommandRepository
    from z4j_brain.persistence.repositories.commands import action_is_redeliverable

    # Preserve the SELECT's global issued_at order while giving EVERY row its
    # own write unit. Boundary-D claims lock Schedule/stream → Agent → Command;
    # accumulating two schedules around one Agent lets concurrent polls form a
    # cycle. Generic claims are Agent → Command. One row per transaction keeps
    # both orders acyclic and gives revoke a check between every claim.
    for cmd in pending:
        if not session_supports_retry_engine(
            session_retry_contracts,
            required_retry_engine(cmd.action, cmd.payload),
        ):
            continue
        async with db.session(write=True) as claim_session:
            commands_repo = CommandRepository(claim_session)
            if cmd.schedule_protocol_marker is not None:
                if current_authority is None:
                    continue
                try:
                    (
                        is_current,
                        claimed_command,
                    ) = await commands_repo.claim_current_schedule_delivery(
                        cmd.id,
                        project_id=agent.project_id,
                        agent_id=agent.id,
                        transport_kind="longpoll",
                        registry_owner_id=current_authority[0],
                        session_generation=current_authority[1],
                        timeout_seconds=settings.command_timeout_seconds,
                        recovery_min_interval_seconds=getattr(
                            settings,
                            "agent_longpoll_redispatch_min_interval_seconds",
                            10.0,
                        ),
                    )
                    if not is_current or claimed_command is None:
                        continue
                    out_frames.append(_encode_command(claimed_command))
                except Exception:
                    # A current claim is immutable. Signing failure after it
                    # advances is ambiguous and must not be generically reverted.
                    logger.exception(
                        "z4j longpoll: failed to sign current command after claim",
                        command_id=str(cmd.id),
                    )
                await claim_session.commit()
                continue

            if await AgentRepository(claim_session).get_live(agent.id, lock=True) is None:
                await _drop_session(agent.id, session_nonce)
                # Earlier rows crossed their own locked authority edge. Return
                # those frames rather than stranding already-claimed work.
                if out_frames:
                    return CommandPullResponse(frames=out_frames)
                raise HTTPException(status_code=401, detail="invalid agent token")
            claimed = False
            try:
                if cmd.status == CommandStatus.DISPATCHED:
                    if not action_is_redeliverable(cmd.action):
                        continue
                    if cmd.dispatched_at is None:
                        # A redispatch lease is authority-bound to the exact
                        # generation selected by this poll. Never let a
                        # malformed/stale row fall back to a repository reread
                        # that could claim a newer generation.
                        continue
                    claimed = await commands_repo.claim_redispatch(
                        cmd.id,
                        min_interval_seconds=getattr(
                            settings,
                            "agent_longpoll_redispatch_min_interval_seconds",
                            10.0,
                        ),
                        expected_dispatched_at=cmd.dispatched_at,
                    )
                    if not claimed:
                        continue
                else:
                    dispatch_generation = await commands_repo.mark_dispatched(
                        cmd.id,
                        timeout_seconds=settings.command_timeout_seconds,
                    )
                    if not dispatch_generation:
                        continue
                    claimed = True
                out_frames.append(_encode_command(cmd))
            except Exception as exc:
                logger.exception(
                    "z4j longpoll: failed to sign command after claim",
                    command_id=str(cmd.id),
                )
                if claimed:
                    try:
                        await commands_repo.mark_failed(
                            cmd.id,
                            error=f"longpoll sign failed: {type(exc).__name__}",
                        )
                    except Exception:
                        logger.exception(
                            "z4j longpoll: also failed to mark command failed",
                            command_id=str(cmd.id),
                        )
            await claim_session.commit()

    if not out_frames:
        # All selected rows may have lost a concurrent claim. Distinguish that
        # normal empty result from a bearer revoked after the initial lookup.
        await _require_live_agent()

    return CommandPullResponse(frames=out_frames)


__all__ = ["router"]
