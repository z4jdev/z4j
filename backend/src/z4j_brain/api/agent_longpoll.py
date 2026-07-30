"""HTTPS long-poll fallback for the agent transport.

Two endpoints, both bearer-authenticated, both speaking the v2
envelope-HMAC framing:

- ``POST /api/v1/agent/events`` - agent uploads a batch of signed
  outbound frames (event_batch, heartbeat, command_ack,
  command_result, registry_delta, error). The brain verifies each
  frame with the per-session :class:`FrameVerifier` and feeds them
  into the same :class:`FrameRouter` the WebSocket gateway uses,
  so the projection / audit / notification side-effects are
  byte-identical between transports.
- ``GET /api/v1/agent/commands?wait=N`` - long-poll for pending
  commands. Returns immediately with any already-pending commands
  for this agent; otherwise blocks up to ``wait`` seconds (capped
  at 60) waiting for the dashboard / API to issue one. Each
  response frame is freshly v2-signed by the per-session
  :class:`FrameSigner` so the agent can verify it through the
  same code path it uses on the WebSocket.

The endpoints are intentionally a 1:1 functional fallback for the
WebSocket - same auth, same framing, same routing, same audit
trail. The only loss vs WebSocket is latency: a long-poll round
trip is ~50-200 ms vs single-digit ms over an open socket.

Deployments behind corporate proxies that strip Upgrade headers
(observed in healthcare and finance environments in 2025) can
disable the WebSocket transport entirely and run on long-poll
without losing any control-plane functionality.

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
- ``SignatureError`` always drops the cached state for that
  session, forcing whoever is on the other end to handshake fresh
  before any further frames are accepted.

The cache is bounded (LRU eviction at 4096 sessions) so a flood
of distinct nonces from any one agent cannot exhaust memory.

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
import uuid
from collections import OrderedDict
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
# LRU-evicted at 4 096 sessions so a flood of distinct nonces
# cannot exhaust memory. ``SignatureError`` always drops the
# entry, so a desynced peer must handshake fresh.

_SESSION_REGISTRY_MAX = 4096
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

_sessions: OrderedDict[tuple[uuid.UUID, object], tuple[FrameSigner, FrameVerifier]] = OrderedDict()
#: Per-agent session counter - used for the per-agent eviction cap.
#: Maintained in lockstep with ``_sessions``; cleaned on drop.
_sessions_per_agent: dict[uuid.UUID, int] = {}
_registry_lock = asyncio.Lock()


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


async def _get_or_create_session(
    *,
    agent: Agent,
    master_secret: bytes,
    session_nonce: str | None,
) -> tuple[FrameSigner, FrameVerifier]:
    """Return the per-session signer/verifier pair, creating it on first use.

    The signing material is the per-project derived secret
    (:func:`derive_project_secret`), not the brain master, so a
    leaked agent host secret cannot forge frames against other
    projects.
    """
    key = _session_key(agent.id, session_nonce)
    # Lock-free fast path: concurrent dict reads on CPython are
    # safe under the GIL, and ``OrderedDict.get`` is atomic. The
    # vast majority of long-poll requests hit this path (the
    # session was created on a previous request) so we skip the
    # ``asyncio.Lock`` contention entirely. The ``move_to_end``
    # MRU touch is racy with concurrent inserts
    # but a missed re-order can at worst cause an extra eviction
    # - never corruption - so we accept the race for the perf win.
    cached = _sessions.get(key)
    if cached is not None:
        _sessions.move_to_end(key)
        return cached
    async with _registry_lock:
        # Re-check inside the lock to handle the race where two
        # concurrent requests both saw ``cached is None`` outside.
        existing = _sessions.get(key)
        if existing is not None:
            _sessions.move_to_end(key)  # MRU
            return existing
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
        _sessions[key] = (signer, verifier)
        _sessions_per_agent[agent.id] = _sessions_per_agent.get(agent.id, 0) + 1
        # Per-agent cap: a malicious agent flooding nonces can only
        # evict ITS OWN previous sessions, never another agent's.
        # Walk the LRU order popping entries belonging to this
        # agent until the agent is back under the cap.
        if _sessions_per_agent[agent.id] > _SESSION_PER_AGENT_MAX:
            for victim_key in list(_sessions):
                if victim_key == key:
                    continue
                if victim_key[0] == agent.id:
                    _sessions.pop(victim_key, None)
                    _sessions_per_agent[agent.id] -= 1
                    if _sessions_per_agent[agent.id] <= _SESSION_PER_AGENT_MAX:
                        break
        # Global cap: catches the case where many agents each
        # have a healthy 1-2 sessions but the brain has been up
        # long enough to accumulate millions of distinct agents.
        while len(_sessions) > _SESSION_REGISTRY_MAX:
            evicted_key, _ = _sessions.popitem(last=False)
            evicted_agent = evicted_key[0]
            if evicted_agent in _sessions_per_agent:
                _sessions_per_agent[evicted_agent] -= 1
                if _sessions_per_agent[evicted_agent] <= 0:
                    _sessions_per_agent.pop(evicted_agent, None)
        return signer, verifier


async def _record_longpoll_liveness(
    db: DatabaseManager,
    agent_id: uuid.UUID,
    *,
    ingested: bool,
) -> None:
    """Reflect a long-poll cycle as agent liveness on ``/agents``.

    Liveness (both the ``last_seen_at`` bump AND the promote) is gated
    on ``ingested`` -- at least one frame in the upload was verified
    (its HMAC passed) AND durably handled. A fully-rejected upload does
    NOT refresh liveness, otherwise a bearer holder who cannot produce a
    valid frame HMAC could keep a dead agent pinned ONLINE by POSTing
    garbage, suppressing the offline sweep and its alerts. The
    offline sweep keys off a stale ``last_seen_at``, so refreshing it on
    unverified traffic would defeat it.

    When there IS verified traffic, promote the agent to online:
    long-poll has no hello handshake, so nothing else calls
    ``mark_online``, and an agent with heartbeats disabled would
    otherwise stay pinned at ``unknown`` even while verifiably
    delivering events.
    """
    if not ingested:
        return
    from z4j_brain.persistence.repositories import AgentRepository

    async with db.session() as session:
        agents_repo = AgentRepository(session)
        await agents_repo.touch_heartbeat(agent_id)
        await agents_repo.promote_online_if_offline(agent_id)
        await session.commit()


async def _drop_session(agent_id: uuid.UUID, session_nonce: str | None) -> None:
    """Drop a session's signer/verifier. Called on signature failure so a
    desynced or malicious peer must handshake fresh before being trusted.
    Decrements the per-agent session counter so the eviction cap stays
    consistent."""
    key = _session_key(agent_id, session_nonce)
    async with _registry_lock:
        if _sessions.pop(key, None) is not None and agent_id in _sessions_per_agent:
            _sessions_per_agent[agent_id] -= 1
            if _sessions_per_agent[agent_id] <= 0:
                _sessions_per_agent.pop(agent_id, None)


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
            if len(frame) > max_per_frame:
                raise ValueError(
                    f"frames[{idx}] is {len(frame)} bytes; cap is {max_per_frame}",
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
    ready for the agent's :class:`FrameVerifier`. Empty list means
    "long-poll timed out without a command"; the agent should
    immediately re-poll.
    """

    frames: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/events", response_model=FrameUploadResponse)
async def agent_events(  # noqa: PLR0915  long-poll event-upload handler
    body: FrameUploadBody,
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
    session_nonce: str | None = Header(default=None, alias=_SESSION_HEADER),
    _throttle: None = Depends(require_agent_connect_throttle),
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
    _, verifier = await _get_or_create_session(
        agent=agent,
        master_secret=master_bytes,
        session_nonce=session_nonce,
    )

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
            # Drop the cached session state on signature failure.
            # On the WebSocket path this is a connection-fatal
            # 4403 close. Here we have no persistent connection,
            # but we MUST invalidate the per-session signer/
            # verifier so a forged max-seq frame cannot
            # permanently DoS the legitimate agent's session
            # (the agent will reconnect with a fresh nonce; we'd
            # otherwise still be holding the poisoned _last_seq
            # under the old key). The remaining frames in this
            # batch are all rejected - we cannot trust ordering
            # once any verification failed.
            errors.append(f"verify failed: {exc}")
            logger.warning(
                "z4j longpoll: frame verification failed - dropping session",
                agent_id=str(agent.id),
                session_nonce=session_nonce,
                reason=str(exc),
            )
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
        if outcome is FrameOutcome.UPGRADE_REQUIRED:
            rejected += 1
            error_code = "scheduler_upgrade_required"
            errors.append("scheduler adapter upgrade required")
        elif outcome.confirmed:
            accepted += 1
        else:
            rejected += 1
            errors.append("transient; agent re-sends")

    # Liveness refreshes ONLY on an authenticated frame (passed parse +
    # HMAC), never on garbage / version-skew / bad-signature traffic.
    # Best-effort: the frame outcomes above are already RESOLVED, so a
    # deterministic liveness-write failure (schema/permission) must NOT turn
    # the resolved 200 into a 500 -- that would make the agent re-POST
    # already-stored (or intentionally dropped) frames forever, since the
    # fault re-fires on every request (round-8 external M-liveness).
    try:
        await _record_longpoll_liveness(db, agent.id, ingested=authenticated > 0)
    except Exception:
        logger.exception(
            "z4j longpoll: liveness write failed; not failing the resolved delivery response",
            agent_id=str(agent.id),
        )

    if session_invalidated:
        await _drop_session(agent.id, session_nonce)

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

    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    session_retry_contracts = _parse_retry_contracts(retry_contracts)
    signer, _ = await _get_or_create_session(
        agent=agent,
        master_secret=master_bytes,
        session_nonce=session_nonce,
    )
    current_authority = _longpoll_delivery_authority(
        agent.id,
        session_nonce,
    )

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

    # Fast path: claim durable children first, then fill the response with
    # ordinary commands. Both paths remain bounded by max_frames.
    bulk_claimed = await _claim_bulk(max_frames)
    pending = await _pull_pending(max_frames - len(bulk_claimed))
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
            bulk_claimed = await _claim_bulk(max_frames)
            pending = await _pull_pending(max_frames - len(bulk_claimed))

    if not bulk_claimed and not pending:
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

    async with db.session() as session:
        from z4j_brain.persistence.repositories import CommandRepository
        from z4j_brain.persistence.repositories.commands import (
            action_is_redeliverable,
        )

        commands_repo = CommandRepository(session)
        for cmd in pending:
            # Defense in depth against dialect/JSON-expression drift: the same
            # adapter-derived request contract is checked again immediately
            # before the claim.
            if not session_supports_retry_engine(
                session_retry_contracts,
                required_retry_engine(cmd.action, cmd.payload),
            ):
                continue
            claimed = False
            current_claim = False
            command_to_send = cmd
            try:
                # Two paths now feed this loop:
                #
                # 1. PENDING command → standard claim-then-sign.
                # 2. DISPATCHED command in the recovery window
                #    (network-drop redelivery) → skip the claim
                #    (it's already claimed) and sign + include
                #    so the agent gets it. Agent-side dedup
                #    silently absorbs duplicates that reached a
                #    still-running process.
                if cmd.schedule_protocol_marker is not None:
                    if current_authority is None:
                        continue
                    (
                        current_claim,
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
                    if not current_claim or claimed_command is None:
                        continue
                    claimed = True
                    command_to_send = claimed_command
                elif cmd.status == CommandStatus.DISPATCHED:
                    # Never RE-DELIVER a non-idempotent command whose
                    # outcome is unknown -- it may have already executed and only
                    # the result frame was lost, so a re-send would double-execute
                    # a destructive op (purge/restart/retry/bulk). At-most-once:
                    # skip it and let the CommandTimeoutWorker retire it. Fires
                    # (fire_id-deduped) and idempotent actions still recover.
                    if not action_is_redeliverable(cmd.action):
                        continue
                    # Single-winner recovery redispatch as a real
                    # LEASE. claim_redispatch wins only if the last send was >=
                    # min_interval ago (a SERVER-side cutoff), so a re-send happens
                    # at most once per lease interval -- NOT once per poll, which
                    # the old caller-supplied not_after=dispatched_at allowed
                    # (every sequential poll re-read the bumped value and re-won,
                    # flooding concurrent workers / a restarted agent).
                    claimed = await commands_repo.claim_redispatch(
                        cmd.id,
                        min_interval_seconds=getattr(
                            settings,
                            "agent_longpoll_redispatch_min_interval_seconds",
                            10.0,
                        ),
                    )
                    if not claimed:
                        continue
                else:
                    dispatch_generation = await commands_repo.mark_dispatched(
                        cmd.id,
                        timeout_seconds=settings.command_timeout_seconds,
                    )
                    if not dispatch_generation:
                        # Another poller (or the WebSocket gateway) won the
                        # race for this command. Skip silently.
                        continue
                payload = CommandPayload(
                    action=command_to_send.action,
                    target=wire_target(
                        command_to_send.target_type,
                        command_to_send.target_id,
                        command_to_send.payload,
                    ),
                    parameters=command_to_send.payload,
                    timeout_seconds=settings.command_timeout_seconds,
                    issued_by=(
                        str(command_to_send.issued_by) if command_to_send.issued_by else None
                    ),
                    delivery_claim_token=(
                        str(command_to_send.delivery_claim_token)
                        if command_to_send.delivery_claim_token is not None
                        else None
                    ),
                )
                frame = CommandFrame(
                    id=str(command_to_send.id),
                    payload=payload,
                )
                signed_bytes = signer.sign_and_serialize(frame)
                out_frames.append(signed_bytes.decode("utf-8"))
            except Exception as exc:
                logger.exception(
                    "z4j longpoll: failed to sign command after claim",
                    command_id=str(cmd.id),
                )
                if claimed and not current_claim:
                    # Already DISPATCHED - surface as failed so the
                    # user / dashboard sees something instead of
                    # a silent timeout. mark_failed accepts both
                    # PENDING and DISPATCHED as legal predecessors.
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
        await session.commit()

    return CommandPullResponse(frames=out_frames)


__all__ = ["router"]
