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
import json
import os
import uuid
from collections import OrderedDict
from typing import TYPE_CHECKING

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from z4j_brain.domain.ip_rate_limit import require_agent_connect_throttle
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from z4j_core.errors import SignatureError
from z4j_core.transport.frames import (
    CommandFrame,
    CommandPayload,
    Frame,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import derive_project_secret

from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.websocket.auth import resolve_agent_by_bearer
from z4j_brain.websocket.frame_router import FrameRouter

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

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

#: Per-agent session cap. Without this, one valid bearer can flood
#: 4 096 distinct nonces and LRU-evict every legitimate agent's
#: session across the whole brain (R3 finding M2). Capping per-
#: agent means at worst the malicious agent evicts ITSELF, never
#: another agent. 16 simultaneous sessions per agent is generous
#: - a healthy agent has 1 active session at a time.
_SESSION_PER_AGENT_MAX = 16

#: Sentinel for "agent did not send the session-nonce header"
#: (legacy / out-of-tree client). A unique object instance -
#: not a string - so a malicious agent cannot forge it by sending
#: a literal string header value (R3 finding M1). Module-private
#: identity-equality is the safety property here.
_LEGACY_NONCE_SENTINEL = object()

_sessions: "OrderedDict[tuple[uuid.UUID, object], tuple[FrameSigner, FrameVerifier]]" = (
    OrderedDict()
)
#: Per-agent session counter - used for the per-agent eviction cap.
#: Maintained in lockstep with ``_sessions``; cleaned on drop.
_sessions_per_agent: "dict[uuid.UUID, int]" = {}
_registry_lock = asyncio.Lock()


def _longpoll_session_count() -> int:
    """Used by the metrics endpoint to surface in-memory state size."""
    return len(_sessions)


# Register at import time so /metrics scrapes pick this up. Safe
# in tests because the registry is brain-private (one per app).
try:
    from z4j_brain.api.metrics import register_inmemory_subsystem

    register_inmemory_subsystem("longpoll_sessions", _longpoll_session_count)
except Exception:  # noqa: BLE001  pragma: no cover
    # metrics module not importable yet (very early in test bootstrap);
    # the next import of this module will retry.
    pass


def _session_key(
    agent_id: uuid.UUID, session_nonce: str | None,
) -> tuple[uuid.UUID, object]:
    """Compute the registry key. Empty/missing nonce maps to a sentinel
    object so legacy agents that don't send the header still get a single
    shared session - they remain susceptible to the H1/H2 issues, but a
    header-aware agent gets the new safety guarantees automatically AND
    no string value can collide with the legacy bucket."""
    return (agent_id, session_nonce if session_nonce else _LEGACY_NONCE_SENTINEL)


async def _get_or_create_session(
    *,
    agent: "Agent",
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
    # asyncio.Lock contention entirely (R3 finding M6). The
    # ``move_to_end`` MRU touch is racy with concurrent inserts
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
        # Round-9 audit fix R9-Wire-H1+H2 (Apr 2026): bind the
        # caller-supplied session nonce into the HMAC envelope.
        # For long-poll the nonce IS the session identity (the
        # registry is keyed on it). Without binding, a captured
        # frame from session-nonce A could be replayed inside
        # session-nonce B since both sessions reset seq=0 + have
        # independent nonce windows. Binding makes the HMAC fail.
        # The legacy sentinel (no-nonce client) gets an empty
        # binding string, those clients are documented as
        # "remain susceptible to H1/H2".
        binding = (
            session_nonce if isinstance(session_nonce, str)
            else ""
        )
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
        # evict ITS OWN previous sessions, never another agent's
        # (R3 finding M2). Walk the LRU order popping entries
        # belonging to this agent until the agent is back under
        # the cap.
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


async def _drop_session(agent_id: uuid.UUID, session_nonce: str | None) -> None:
    """Drop a session's signer/verifier. Called on signature failure so a
    desynced or malicious peer must handshake fresh before being trusted.
    Decrements the per-agent session counter so the eviction cap stays
    consistent."""
    key = _session_key(agent_id, session_nonce)
    async with _registry_lock:
        if _sessions.pop(key, None) is not None:
            if agent_id in _sessions_per_agent:
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
        """Round-8 audit fix R8-Pyd-MED (Apr 2026): per-frame size cap.

        Pre-fix the 500-element list cap was the only bound, each
        string was unlimited, so a single request could carry
        500 × 100 MB and OOM the brain before any downstream
        validator ran. Per-frame ceiling matches the wire frame
        cap (default 1 MiB).
        """
        max_per_frame = 1 * 1024 * 1024  # 1 MiB
        for idx, frame in enumerate(v):
            if len(frame) > max_per_frame:
                raise ValueError(
                    f"frames[{idx}] is {len(frame)} bytes; cap is "
                    f"{max_per_frame}",
                )
        return v


class FrameUploadResponse(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)


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
async def agent_events(
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

    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    _, verifier = await _get_or_create_session(
        agent=agent, master_secret=master_bytes, session_nonce=session_nonce,
    )

    ingestor = request.app.state.event_ingestor
    dispatcher = request.app.state.command_dispatcher
    dashboard_hub = getattr(request.app.state, "dashboard_hub", None)

    frame_router = FrameRouter(
        db=db,
        ingestor=ingestor,
        dispatcher=dispatcher,
        project_id=agent.project_id,
        agent_id=agent.id,
        dashboard_hub=dashboard_hub,
    )

    accepted = 0
    rejected = 0
    errors: list[str] = []
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
        except Exception as exc:  # noqa: BLE001
            rejected += 1
            errors.append(f"parse failed: {type(exc).__name__}")
            continue

        try:
            await frame_router.dispatch(frame)
            accepted += 1
        except Exception as exc:  # noqa: BLE001
            rejected += 1
            errors.append(f"dispatch failed: {type(exc).__name__}")
            logger.exception(
                "z4j longpoll: dispatch crashed",
                agent_id=str(agent.id),
            )

    # Touch agent.last_seen_at so /agents reflects the long-poll
    # cycle as liveness, the same way a heartbeat frame would over
    # a WebSocket.
    async with db.session() as session:
        from z4j_brain.persistence.repositories import AgentRepository

        await AgentRepository(session).touch_heartbeat(agent.id)
        await session.commit()

    if session_invalidated:
        await _drop_session(agent.id, session_nonce)

    return FrameUploadResponse(
        accepted=accepted, rejected=rejected, errors=errors[:10],
    )


@router.get("/commands", response_model=CommandPullResponse)
async def agent_commands(
    request: Request,
    response: Response,
    wait: int = Query(default=30, ge=0, le=60),
    max_frames: int = Query(default=50, ge=1, le=500),
    authorization: str | None = Header(default=None),
    session_nonce: str | None = Header(default=None, alias=_SESSION_HEADER),
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

    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    signer, _ = await _get_or_create_session(
        agent=agent, master_secret=master_bytes, session_nonce=session_nonce,
    )

    # Inner helper that does ONE pass over the commands table for
    # this agent. Returns the list of pending Command rows or [].
    #
    # Round-6 audit fix WS-HIGH-2 (Apr 2026): also include
    # recently-DISPATCHED commands. Pre-fix, if the HTTP response
    # never reached the agent (network drop after the brain
    # committed mark_dispatched), the command sat in DISPATCHED
    # state with no agent ever seeing it - recoverable only via
    # CommandTimeoutWorker (minutes later, surfaced as a generic
    # timeout to the user).
    #
    # Now: include commands dispatched within
    # ``Z4J_AGENT_LONGPOLL_REDISPATCH_SECONDS`` (default 60s) so a
    # quickly-reconnecting agent gets the same command re-sent.
    # The agent's in-memory ``_seen_commands`` dedup (300s TTL)
    # silently absorbs duplicates that reach a still-running
    # process. The redispatch only re-fires for commands the
    # agent never processed because the network dropped before
    # delivery completed.
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    redispatch_cutoff = datetime.now(UTC) - timedelta(
        seconds=getattr(
            settings, "agent_longpoll_redispatch_seconds", 60.0,
        ),
    )

    async def _pull_pending() -> list["Command"]:
        from sqlalchemy import or_

        from z4j_brain.persistence.models import Command

        async with db.session() as session:
            result = await session.execute(
                select(Command)
                .where(
                    Command.agent_id == agent.id,
                    or_(
                        Command.status == CommandStatus.PENDING,
                        # Recently dispatched but possibly never
                        # delivered (network drop). Re-send;
                        # agent dedups by id.
                        (
                            (Command.status == CommandStatus.DISPATCHED)
                            & (Command.dispatched_at >= redispatch_cutoff)
                        ),
                    ),
                )
                .order_by(Command.issued_at.asc())
                .limit(max_frames),
            )
            return list(result.scalars().all())

    # Fast path: any pending commands right now? Skip the wait loop
    # entirely if so - typical long-poll will return empty most
    # times but immediately on a real command issuance.
    pending = await _pull_pending()
    if not pending and wait > 0:
        # Slow path: poll the table at 250 ms intervals up to
        # ``wait`` seconds. A future improvement is to wake on a
        # Postgres NOTIFY (the registry already publishes one);
        # the polling fallback works even without a Postgres
        # backend (SQLite dev mode).
        deadline = asyncio.get_running_loop().time() + wait
        while not pending:
            await asyncio.sleep(0.25)
            if asyncio.get_running_loop().time() >= deadline:
                break
            pending = await _pull_pending()

    if not pending:
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
    async with db.session() as session:
        from z4j_brain.persistence.repositories import CommandRepository

        commands_repo = CommandRepository(session)
        for cmd in pending:
            claimed = False
            try:
                # Round-6 audit fix WS-HIGH-2 (Apr 2026): two
                # paths now feed this loop:
                #
                # 1. PENDING command → standard claim-then-sign.
                # 2. DISPATCHED command in the recovery window
                #    (network-drop redelivery) → skip the claim
                #    (it's already claimed) and sign + include
                #    so the agent gets it. Agent-side dedup
                #    silently absorbs duplicates that reached a
                #    still-running process.
                if cmd.status == CommandStatus.DISPATCHED:
                    # Recovery path - skip the claim (idempotent
                    # re-send).
                    claimed = True
                else:
                    claimed = await commands_repo.mark_dispatched(cmd.id)
                    if not claimed:
                        # Another poller (or the WebSocket gateway) won the
                        # race for this command. Skip silently.
                        continue
                payload = CommandPayload(
                    action=cmd.action,
                    target={"type": cmd.target_type, "id": cmd.target_id},
                    parameters=cmd.payload,
                    timeout_seconds=settings.command_timeout_seconds,
                    issued_by=str(cmd.issued_by) if cmd.issued_by else None,
                )
                frame = CommandFrame(id=str(cmd.id), payload=payload)
                signed_bytes = signer.sign_and_serialize(frame)
                out_frames.append(signed_bytes.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "z4j longpoll: failed to sign command after claim",
                    command_id=str(cmd.id),
                )
                if claimed:
                    # Already DISPATCHED - surface as failed so the
                    # user / dashboard sees something instead of
                    # a silent timeout. mark_failed accepts both
                    # PENDING and DISPATCHED as legal predecessors.
                    try:
                        await commands_repo.mark_failed(
                            cmd.id, error=f"longpoll sign failed: {type(exc).__name__}",
                        )
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "z4j longpoll: also failed to mark command failed",
                            command_id=str(cmd.id),
                        )
        await session.commit()

    return CommandPullResponse(frames=out_frames)


__all__ = ["router"]
