"""Pinning tests for the two brain-side longpoll defects (1.7 matrix).

LP-1 (no ack channel): ``api/agent_longpoll.py:365-374`` builds its
per-request :class:`FrameRouter` WITHOUT the ``send_frame`` callback,
so the ``event_batch_ack`` emission in
``websocket/frame_router.py:489`` is silently skipped
(``_send_frame is None``). ``GET /agent/commands`` only ever signs
``CommandFrame`` rows, so there is no path by which a longpoll agent
can EVER receive an ack. The 1.5+ agent defers buffer confirmation
until the ack arrives, so it re-sends the same batch at HTTP
round-trip cadence until the rate limiter 429s it.

LP-3 (state pinned at unknown): a longpoll-only agent's row is
created with ``state=UNKNOWN`` and nothing on the longpoll path ever
calls ``mark_online`` (that only happens in the WS hello). The fix
widens ``promote_online_if_offline`` to promote from any non-online
state and calls it from the events POST on a successful ingest, so a
longpoll-only agent shows online.

These are post-fix regression guards for both defects.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import uuid

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.event_ingestor import BatchIngestResult
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.persistence.repositories import AgentRepository
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.frames import (
    CommandResultFrame,
    CommandResultPayload,
    ErrorFrame,
    EventBatchAckFrame,
    EventBatchFrame,
    EventBatchPayload,
    HeartbeatFrame,
    HeartbeatPayload,
)
from z4j_core.transport.framing import FrameSigner
from z4j_core.transport.hmac import derive_project_secret

AGENT_TOKEN = "z4j_agent_longpoll_pins_test"


# ---------------------------------------------------------------------------
# App fixtures (mirrors test_agent_longpoll_identity.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        registry_backend="local",
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def agent_ids(settings: Settings, brain_app) -> dict[str, uuid.UUID]:
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with brain_app.state.db.session() as s:
        s.add(Project(id=project_id, slug="lp-pins", name="LP Pins"))
        await s.flush()
        s.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="lp-pins-agent",
                token_hash=hash_agent_token(
                    plaintext=AGENT_TOKEN,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.UNKNOWN,
            ),
        )
        await s.commit()
    return {"project_id": project_id, "agent_id": agent_id}


@pytest.fixture
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


async def _agent_state(brain_app, agent_id: uuid.UUID) -> AgentState:
    async with brain_app.state.db.session() as s:
        agent = await s.get(Agent, agent_id)
        return agent.state


def _signed_heartbeat(
    settings: Settings,
    ids: dict[str, uuid.UUID],
    *,
    nonce: str,
    frame_id: str = "hb_pin_1",
) -> str:
    """Sign a heartbeat exactly the way LongPollTransport does.

    Same per-project derived secret, same session-nonce binding the
    brain applies in ``_get_or_create_session``.
    """
    master = settings.secret.get_secret_value().encode("utf-8")
    signer = FrameSigner(
        secret=derive_project_secret(master, ids["project_id"]),
        agent_id=ids["agent_id"],
        project_id=ids["project_id"],
        session_id=nonce,
    )
    frame = HeartbeatFrame(id=frame_id, payload=HeartbeatPayload())
    return signer.sign_and_serialize(frame).decode("utf-8")


# ---------------------------------------------------------------------------
# LP-1: FrameRouter ack-emission gate
# ---------------------------------------------------------------------------


class _FakeSession:
    bind = type("_FakeBind", (), {"dialect": type("_FakeDialect", (), {"name": "sqlite"})()})()

    async def execute(self, _statement):
        class _LiveResult:
            @staticmethod
            def scalar_one_or_none():
                return object()

        return _LiveResult()

    async def commit(self) -> None:
        return None


class _FakeDB:
    @contextlib.asynccontextmanager
    async def session(self, *, write: bool = False):
        assert write is True
        yield _FakeSession()


class _FakeIngestor:
    async def ingest_batch(self, **_kwargs):
        return BatchIngestResult(new_events=[], transient_skips=0)


class _RaisingIngestor:
    """Fails DETERMINISTICALLY during ingest (a non-DB / permanent error).

    A RuntimeError from the whole ingest is a code/content bug that recurs
    on every replay, so the brain classifies it PERMANENT -> DROP.
    """

    async def ingest_batch(self, **_kwargs):
        raise RuntimeError("simulated deterministic ingest failure")


class _TransientRaisingIngestor:
    """Fails TRANSIENTLY during ingest (a Postgres lock-timeout cancel).

    Boxed as a bare DBAPIError-shaped exception carrying SQLSTATE 57014, so
    the brain classifies it TRANSIENT -> the batch is not confirmed and the
    agent re-sends (the exact asyncpg lock/pool case round-8 fixed)."""

    async def ingest_batch(self, **_kwargs):
        exc = RuntimeError("canceling statement due to lock timeout")
        exc.sqlstate = "57014"  # type: ignore[attr-defined]
        raise exc


class _TransientSkipIngestor:
    """Commits the batch but reports a transiently-skipped event, so the
    batch is committed-but-not-fully-durable (-panel-HIGH)."""

    async def ingest_batch(self, **_kwargs):
        return BatchIngestResult(new_events=[], transient_skips=1)


class _UpgradeRequiredIngestor:
    async def ingest_batch(self, **_kwargs):
        return BatchIngestResult(
            new_events=[],
            transient_skips=0,
            upgrade_required=True,
        )


def _router(send_frame=None, ingestor=None) -> FrameRouter:
    return FrameRouter(
        db=_FakeDB(),
        ingestor=ingestor or _FakeIngestor(),
        dispatcher=object(),
        project_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        dashboard_hub=None,
        send_frame=send_frame,
    )


async def test_dispatch_returns_durable_on_success() -> None:
    """dispatch() reports DURABLE to the long-poll caller on a clean store
    (which the caller counts accepted / the agent confirms)."""
    router = _router()
    frame = EventBatchFrame(id="evb_ok", payload=EventBatchPayload(events=[]))
    assert await router.dispatch(frame) is FrameOutcome.DURABLE


async def test_dispatch_drops_on_deterministic_ingest_failure() -> None:
    """A DETERMINISTIC (permanent) ingest failure returns DROP, so the
    long-poll caller counts it accepted and the agent CONFIRMS+DELETES it
    instead of re-sending it forever.

    Re-sending the identical batch fails identically, so looping would pin
    the agent's buffer head and overflow-lose later events. The batch's
    events are lost -- the bounded cost of not wedging the send loop -- and
    it is logged loudly. (DROP is 'confirmed', like DURABLE, on the wire.)
    """
    router = _router(ingestor=_RaisingIngestor())
    frame = EventBatchFrame(
        id="evb_fail",
        payload=EventBatchPayload(events=[{"engine": "celery", "kind": "task.succeeded"}]),
    )
    outcome = await router.dispatch(frame)
    assert outcome is FrameOutcome.DROP
    assert outcome.confirmed is True


async def test_dispatch_transient_on_transient_ingest_failure() -> None:
    """A TRANSIENT ingest failure (a lock-timeout cancel, SQLSTATE
    57014) returns TRANSIENT, so the long-poll caller counts it rejected and
    the agent RE-SENDS -- the deliverable event is never evicted before it
    stored. This is the asyncpg lock/pool case the SQLSTATE classifier fixes.
    """
    router = _router(ingestor=_TransientRaisingIngestor())
    frame = EventBatchFrame(
        id="evb_transient",
        payload=EventBatchPayload(events=[{"engine": "celery", "kind": "task.succeeded"}]),
    )
    outcome = await router.dispatch(frame)
    assert outcome is FrameOutcome.TRANSIENT
    assert outcome.confirmed is False


async def test_transient_skip_reports_not_durable_and_withholds_ack() -> None:
    """Panel-HIGH: a batch that COMMITTED but transiently skipped an
    event is NOT fully durable.

    dispatch() must return TRANSIENT (so the long-poll handler counts it
    rejected and the agent re-sends) AND no event_batch_ack is emitted
    (so a WS agent re-sends too). Pre-fix the batch committed the rest,
    dispatch reported durable, the ack fired, and the agent evicted the
    only copy of the skipped event -- permanent data loss.
    """
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame, ingestor=_TransientSkipIngestor())
    frame = EventBatchFrame(
        id="evb_skip",
        payload=EventBatchPayload(events=[{"engine": "celery", "kind": "task.failed"}]),
    )
    assert await router.dispatch(frame) is FrameOutcome.TRANSIENT
    # give any (wrongly) spawned ack task a chance to run
    for _ in range(3):
        await asyncio.sleep(0)
    assert sent == []  # no ack was emitted (TRANSIENT withholds it)


async def test_schedule_upgrade_rejection_is_typed_and_never_acked() -> None:
    sent: list = []

    async def send_frame(frame) -> None:
        sent.append(frame)

    router = _router(
        send_frame=send_frame,
        ingestor=_UpgradeRequiredIngestor(),
    )
    frame = EventBatchFrame(
        id="evb_upgrade",
        payload=EventBatchPayload(
            events=[{"engine": "celery-beat", "kind": "schedule.snapshot"}],
        ),
    )
    outcome = await router.dispatch(frame)
    assert outcome is FrameOutcome.UPGRADE_REQUIRED
    assert outcome.confirmed is False
    assert len(sent) == 1
    assert isinstance(sent[0], ErrorFrame)
    assert sent[0].payload.code == "scheduler_upgrade_required"
    assert sent[0].payload.fatal is True


async def test_dispatch_stays_durable_when_post_commit_hook_fails() -> None:
    """A post-commit hook failure must NOT flip dispatch off DURABLE.

    The events are already durably committed before the publish /
    notification / automation hooks run. If a hook exception propagated,
    dispatch would report not-durable, the long-poll handler would count
    the batch as not-stored, and the agent would re-send a batch that IS
    stored -- re-running these same hooks. Each hook is isolated so its
    failure is logged but does not affect the durability signal.
    """
    router = _router()  # _FakeIngestor commits fine (returns [])

    async def _boom() -> None:
        raise RuntimeError("post-commit publish failed")

    router._publish_task_change = _boom  # type: ignore[method-assign]
    frame = EventBatchFrame(
        id="evb_hook",
        payload=EventBatchPayload(events=[{"engine": "celery", "kind": "task.succeeded"}]),
    )
    assert await router.dispatch(frame) is FrameOutcome.DURABLE


async def test_post_commit_hooks_receive_only_new_events() -> None:
    """Notifications AND automation fire on new_events only.

    A re-delivered event was already notified/fired on first delivery;
    firing on the full delivered list re-pages subscribers on every
    reconnect re-flush. Both hooks must receive the ingestor's
    new-events subset, not the full batch.
    """
    new_subset = [{"engine": "celery", "kind": "task.failed", "task_id": "t-new"}]

    class _SubsetIngestor:
        async def ingest_batch(self, **_kwargs):
            # only 1 of the 2 delivered events is new; fully durable
            return BatchIngestResult(new_events=new_subset, transient_skips=0)

    router = _router(ingestor=_SubsetIngestor())
    notified: list = []
    automated: list = []

    async def _cap_notify(events):
        notified.append(events)

    async def _cap_auto(events):
        automated.append(events)

    router._evaluate_notifications = _cap_notify  # type: ignore[method-assign]
    router._evaluate_automation = _cap_auto  # type: ignore[method-assign]

    frame = EventBatchFrame(
        id="evb_replay",
        payload=EventBatchPayload(
            events=[
                {"engine": "celery", "kind": "task.failed", "task_id": "t-new"},
                {"engine": "celery", "kind": "task.failed", "task_id": "t-old"},
            ],
        ),
    )
    assert await router.dispatch(frame) is FrameOutcome.DURABLE
    assert notified == [new_subset]
    assert automated == [new_subset]


# ---------------------------------------------------------------------------
# /C3: a CONTROL-frame handler that raises is CLASSIFIED, so a permanent
# failure (e.g. a NUL byte in a command_result -> SQLSTATE 22xxx) is DROP
# (agent confirms, no loop) while a transient one (deadlock) is TRANSIENT
# (agent re-sends). This completes the "brain resolves every deterministic
# failure at source" invariant for the control-frame surfaces the round-8
# review found were left looping.
# ---------------------------------------------------------------------------


def _command_result_frame() -> CommandResultFrame:
    return CommandResultFrame(
        id="cr_1",
        payload=CommandResultPayload(status="success", result={"ok": True}),
    )


async def test_dispatch_drops_permanent_control_frame_error() -> None:
    router = _router()

    async def _boom_permanent(_frame) -> None:
        # A NUL byte in an agent-supplied result -> Postgres 22021
        # (character_not_in_repertoire): a deterministic content error.
        exc = RuntimeError("invalid byte sequence")
        exc.sqlstate = "22021"  # type: ignore[attr-defined]
        raise exc

    router._handle_command_result = _boom_permanent  # type: ignore[method-assign]
    outcome = await router.dispatch(_command_result_frame())
    assert outcome is FrameOutcome.DROP
    assert outcome.confirmed is True  # agent deletes it -> no unbounded loop


async def test_dispatch_transient_on_transient_control_frame_error() -> None:
    router = _router()

    async def _boom_transient(_frame) -> None:
        exc = RuntimeError("deadlock detected")
        exc.sqlstate = "40P01"  # type: ignore[attr-defined]
        raise exc

    router._handle_command_result = _boom_transient  # type: ignore[method-assign]
    outcome = await router.dispatch(_command_result_frame())
    assert outcome is FrameOutcome.TRANSIENT
    assert outcome.confirmed is False  # agent re-sends


async def test_dispatch_never_raises_on_oversized_frame_id() -> None:
    """Dispatch() must NEVER raise -- the WS ingest worker has no
    per-frame except and relies on that contract, so a raise would crash it
    and wedge the connection.

    A WS fast-path frame is built via model_construct (HMAC verified,
    Pydantic constraints bypassed), so an agent's >64-char envelope ``id``
    reaches _handle_event_batch. Building the event_batch_ack with
    ``acked_id=frame.id`` would violate the strict max_length=64 and raise
    inside the finally; the ack now truncates and dispatch is fully wrapped,
    so dispatch returns cleanly and the ack goes out with a 64-char acked_id.
    """
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame)  # _FakeIngestor commits -> DURABLE
    long_id = "evb_" + "x" * 200
    # model_construct bypasses the max_length=64 constraint, mimicking the
    # WS signed fast path.
    frame = EventBatchFrame.model_construct(id=long_id, payload=EventBatchPayload(events=[]))

    outcome = await router.dispatch(frame)  # must NOT raise
    assert outcome is FrameOutcome.DURABLE
    for _ in range(3):
        await asyncio.sleep(0)  # let the ack task run
    assert len(sent) == 1
    assert len(sent[0].payload.acked_id) <= 64


async def test_dispatch_handles_missing_frame_id_without_crashing() -> None:
    """Round-9 LOW: a WS fast-path frame is model_construct'd, so a
    buggy/compromised agent's frame can carry a None / non-str ``id``.
    dispatch() must not raise, and the ack must carry an EMPTY acked_id (which
    the agent ignores -> clean re-send + brain dedup) rather than a misleading
    "None"."""
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame)  # _FakeIngestor commits -> DURABLE
    # id=None bypasses the min_length=1 constraint via model_construct.
    frame = EventBatchFrame.model_construct(id=None, payload=EventBatchPayload(events=[]))

    outcome = await router.dispatch(frame)  # must NOT raise
    assert outcome is FrameOutcome.DURABLE
    for _ in range(3):
        await asyncio.sleep(0)
    assert len(sent) == 1
    # Normalised to "" (not "None"); the ack envelope id falls back to "eba_".
    assert sent[0].payload.acked_id == ""
    assert sent[0].id == "eba_"


async def test_dispatch_drops_and_acks_malformed_events_payload() -> None:
    """External round-8 M: a WS fast-path frame is built via model_construct
    (HMAC verified, Pydantic bypassed), so ``payload.events`` can be a
    non-list. Extracting it (``list(frame.payload.events or [])``) then raises
    a TypeError.

    That extraction now lives INSIDE the try, so the failure classifies to a
    resolved outcome (DROP) and the finally STILL emits the ack -- the agent
    confirms+deletes the malformed frame instead of the WS ingest worker
    silently withholding it forever (and dispatch, which the WS worker relies
    on, must never raise).
    """
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame)
    # events is a non-list, non-empty value -> list(123) raises TypeError.
    payload = EventBatchPayload.model_construct(events=123)
    frame = EventBatchFrame.model_construct(id="evb_malformed", payload=payload)

    outcome = await router.dispatch(frame)  # must NOT raise
    assert outcome is FrameOutcome.DROP
    assert outcome.confirmed is True  # agent deletes it -> no unbounded loop
    for _ in range(3):
        await asyncio.sleep(0)  # let the ack task run
    # The ack still went out despite the malformed extraction.
    assert len(sent) == 1
    assert sent[0].payload.acked_id == "evb_malformed"


async def test_event_batch_cap_matches_protocol_max_5000() -> None:
    """External round-8 M: the frame-router per-frame event cap was 1_000 --
    BELOW the 5000-element protocol max on ``EventBatchPayload.events``. A
    protocol-legal 5000-event frame was silently trimmed to 1000, yet its ack
    confirmed the WHOLE frame by id, so the agent deleted the trimmed tail:
    silent loss of up to 4000 events. The cap now equals the protocol max, so
    a legal frame passes untouched; a frame ABOVE the max (only reachable via
    a bypassed validator) still trims.
    """
    seen: dict[str, int] = {}

    class _Recording:
        async def ingest_batch(self, *, events, **_kwargs):
            seen["n"] = len(events)
            return BatchIngestResult(new_events=[], transient_skips=0)

    router = _router(ingestor=_Recording())

    # A protocol-legal 5000-event frame passes UNTRIMMED.
    payload = EventBatchPayload.model_construct(events=[{} for _ in range(5000)])
    frame = EventBatchFrame.model_construct(id="evb_5000", payload=payload)
    await router.dispatch(frame)
    assert seen["n"] == 5000

    # An over-max frame (only reachable with a bypassed validator) is trimmed
    # to the cap rather than processed unbounded.
    payload_over = EventBatchPayload.model_construct(events=[{} for _ in range(5001)])
    frame_over = EventBatchFrame.model_construct(id="evb_5001", payload=payload_over)
    await router.dispatch(frame_over)
    assert seen["n"] == 5000


async def test_dispatch_handles_null_events_as_empty_batch() -> None:
    """A null ``events`` (``None``) is coerced to an empty batch (``or []``),
    ingests cleanly, and returns DURABLE -- no crash, no withhold."""
    router = _router()
    payload = EventBatchPayload.model_construct(events=None)
    frame = EventBatchFrame.model_construct(id="evb_null", payload=payload)
    assert await router.dispatch(frame) is FrameOutcome.DURABLE


async def test_longpoll_router_has_no_ack_channel() -> None:
    """The longpoll FrameRouter deliberately emits no ack.

    ``agent_longpoll.py`` builds its FrameRouter without a
    ``send_frame`` callback, so a committed event_batch produces no
    ``event_batch_ack``. That is BY DESIGN for long-poll: there is no
    open socket to sign an ack back over, and the HTTP 200 on
    ``POST /events`` is the acknowledgement. The agent side handles
    this via ``LongPollTransport.confirm_on_send`` (it confirms
    buffered entries on the 200 rather than waiting for an ack frame
    that will never come). This test pins that the brain router stays
    ack-free in that configuration so the two sides do not drift.
    """
    router = _router(send_frame=None)
    frame = EventBatchFrame(id="evb_pin_1", payload=EventBatchPayload(events=[]))
    await router.dispatch(frame)
    for _ in range(3):
        await asyncio.sleep(0)
    assert not router._pending_ack_tasks


async def test_router_with_send_frame_emits_linked_ack() -> None:
    """The ack plumbing the fix must reuse: one ack per committed
    batch, ``payload.acked_id`` carrying the original frame id.

    Whatever delivery channel the longpoll fix chooses (acks in the
    POST /events response, acks over GET /commands, or agent-side
    confirm-on-send), this linkage is the contract the agent's
    ``_handle_event_batch_ack`` (z4j-bare runtime.py:1560-1589)
    confirms buffer entries against.
    """
    sent: list = []

    async def send_frame(f) -> None:
        sent.append(f)

    router = _router(send_frame=send_frame)
    frame = EventBatchFrame(id="evb_pin_2", payload=EventBatchPayload(events=[]))
    await router.dispatch(frame)
    if router._pending_ack_tasks:
        await asyncio.gather(*router._pending_ack_tasks)
    assert len(sent) == 1
    ack = sent[0]
    assert isinstance(ack, EventBatchAckFrame)
    assert ack.payload.acked_id == "evb_pin_2"


# ---------------------------------------------------------------------------
# LP-3: longpoll-only agent liveness
# ---------------------------------------------------------------------------


async def test_longpoll_verified_events_promote_online(
    client,
    brain_app,
    settings,
    agent_ids,
) -> None:
    """LP-3 fix: verified longpoll traffic promotes a never-connected
    (UNKNOWN) agent to ONLINE.

    The signed heartbeat is dispatched through the FrameRouter and the
    events POST, on accepted > 0, calls ``promote_online_if_offline``,
    whose guard is now ``state != ONLINE``. A longpoll-only agent
    starts at UNKNOWN (never saw a WS hello / ``mark_online``) and was
    pinned there forever pre-fix; now the /agents page reflects it as
    online.
    """
    nonce = "lp-pins-nonce-1"
    raw = _signed_heartbeat(settings, agent_ids, nonce=nonce)
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": [raw]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert r.status_code == 200
    assert r.json()["accepted"] == 1

    state = await _agent_state(brain_app, agent_ids["agent_id"])
    assert state == AgentState.ONLINE


async def _agent_last_seen(brain_app, agent_id: uuid.UUID):
    async with brain_app.state.db.session() as s:
        agent = await s.get(Agent, agent_id)
        return agent.last_seen_at


async def test_agent_last_seen_is_monotonic_never_rewinds(
    brain_app,
    agent_ids,
) -> None:
    """Round-9 external MED: ``touch_heartbeat_at`` carries the batch
    ``max(occurred_at)``; a reconnect that re-flushes an OLD buffered batch
    (all duplicates, stale occurred_at) must NOT rewind a live agent's
    ``last_seen_at`` and trip a false offline sweep / alert."""
    from datetime import UTC, datetime, timedelta

    agent_id = agent_ids["agent_id"]
    t_new = datetime.now(UTC).replace(microsecond=0)
    t_old = t_new - timedelta(minutes=10)
    t_newer = t_new + timedelta(minutes=5)

    # Compare readback-to-readback (SQLite returns naive datetimes, so an
    # exact == against the aware inputs would spuriously fail).
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).touch_heartbeat_at(agent_id, when=t_new)
        await s.commit()
    pinned = await _agent_last_seen(brain_app, agent_id)
    assert pinned is not None

    # An OLD replay must NOT rewind it.
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).touch_heartbeat_at(agent_id, when=t_old)
        await s.commit()
    assert await _agent_last_seen(brain_app, agent_id) == pinned

    # A genuinely-newer batch DOES advance it.
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).touch_heartbeat_at(agent_id, when=t_newer)
        await s.commit()
    assert await _agent_last_seen(brain_app, agent_id) > pinned


async def test_rejected_upload_does_not_refresh_liveness(
    client,
    brain_app,
    agent_ids,
) -> None:
    """(Preserved through): an upload with no HMAC-authenticated,
    signed frame must NOT bump last_seen_at.

    Otherwise a bearer holder who cannot produce a valid frame HMAC could
    keep a dead agent pinned ONLINE by POSTing garbage, defeating the
    offline sweep (which keys off a stale last_seen_at) and its alerts.

    The frame here is a garbage string that fails to PARSE. Under an
    unparseable frame is dropped-and-acked so the agent does not loop on
    it, which folds it into the RESPONSE accepted-count (== 1). But a
    parse failure is raised BEFORE HMAC verification, so it must NOT count
    toward liveness -- ``last_seen_at`` stays put. This decoupling is the
    security-critical property: the response accepted-count is an agent
    delivery-bookkeeping signal, NOT proof of an authenticated live agent.
    """
    before = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": ["not-a-signed-frame"]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": "lp-pins-nonce-reject",
        },
    )
    assert r.status_code == 200
    # Dropped-and-acked so the agent stops re-sending...
    assert r.json()["accepted"] == 1
    # but liveness is UNTOUCHED by unauthenticated garbage.
    after = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    assert after == before


async def test_authenticated_transient_dispatch_still_refreshes_liveness(
    client,
    brain_app,
    settings,
    agent_ids,
    monkeypatch,
) -> None:
    """Presence is proven by HMAC, independently of downstream durability."""

    async def transient_dispatch(_router, _frame):
        return FrameOutcome.TRANSIENT

    monkeypatch.setattr(FrameRouter, "dispatch", transient_dispatch)
    nonce = f"transient-liveness-{uuid.uuid4()}"
    before = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    response = await client.post(
        "/api/v1/agent/events",
        json={
            "frames": [
                _signed_heartbeat(
                    settings,
                    agent_ids,
                    nonce=nonce,
                    frame_id="transient-liveness",
                ),
            ],
        },
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 0
    assert response.json()["rejected"] == 1
    after = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    assert after is not None
    assert after != before


async def test_version_skew_frame_is_retried_not_dropped(
    client,
    brain_app,
    agent_ids,
) -> None:
    """C5: a protocol-version-skew frame is RECOVERABLE, so it must be
    RETRIED (counted rejected), NOT dropped-and-acked like garbage.

    During a rolling protocol bump an agent's frame can hit a not-yet-
    upgraded replica; the identical bytes parse fine against an upgraded
    one. So the response must count it rejected (accepted != total ->
    agent keeps + re-sends), and -- since the version gate is BEFORE HMAC
    it must NOT refresh liveness.
    """
    before = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    # A syntactically-valid, signed-type frame claiming a wrong version.
    # The version check fires before HMAC, so no valid signature is needed.
    skew = json.dumps({"v": 999, "type": "event_batch", "id": "vskew", "payload": {"events": []}})
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": [skew]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": "lp-pins-nonce-vskew",
        },
    )
    assert r.status_code == 200
    # RETRY, not confirm: accepted stays 0 (agent will re-send) ...
    assert r.json()["accepted"] == 0
    assert r.json()["rejected"] == 1
    # and liveness is untouched (version gate is pre-HMAC).
    after = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    assert after == before


async def test_unsigned_hello_frame_does_not_refresh_liveness(
    client,
    brain_app,
    agent_ids,
) -> None:
    """External round-8 L: an unsigned handshake frame (hello / hello_ack)
    parses fine on the long-poll ``/events`` route but carries NO HMAC, so it
    must NOT count toward the authenticated-liveness signal.

    A bearer-token holder who cannot forge a frame HMAC could otherwise keep a
    dead agent pinned ONLINE by POSTing a well-formed hello, defeating the
    offline sweep. The frame is still drop-and-acked (accepted, so the
    agent's confirm_on_send purges it -- a hello does not belong on /events),
    but liveness stays put.
    """
    from z4j_core.transport.frames import HelloFrame, HelloPayload, serialize_frame

    before = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    hello = HelloFrame(
        id="hello_pin_1",
        payload=HelloPayload(
            protocol_version=str(CURRENT_PROTOCOL),
            agent_version="1.7.0",
            framework="celery",
        ),
    )
    raw = serialize_frame(hello).decode("utf-8")
    r = await client.post(
        "/api/v1/agent/events",
        json={"frames": [raw]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": "lp-pins-nonce-hello",
        },
    )
    assert r.status_code == 200
    # Drop-and-acked so the agent stops re-sending a misrouted hello ...
    assert r.json()["accepted"] == 1
    # but an UNSIGNED handshake frame never refreshes liveness.
    after = await _agent_last_seen(brain_app, agent_ids["agent_id"])
    assert after == before


async def test_promote_online_repo_semantics(brain_app, agent_ids) -> None:
    """Repo-level guard: promotes from any non-online state.

    OFFLINE -> ONLINE (the WS heartbeat un-stick path) and
    UNKNOWN -> ONLINE (the LP-3 longpoll fix) both promote; ONLINE is
    a no-op. Only three states exist (ONLINE / OFFLINE / UNKNOWN,
    z4j_core/models/agent.py:21-34), so ``state != ONLINE`` covers
    exactly OFFLINE and UNKNOWN.
    """
    agent_id = agent_ids["agent_id"]

    # UNKNOWN is promoted (the LP-3 fix).
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).promote_online_if_offline(agent_id)
        await s.commit()
    assert await _agent_state(brain_app, agent_id) == AgentState.ONLINE

    # OFFLINE is promoted (unchanged WS behavior).
    async with brain_app.state.db.session() as s:
        agent = await s.get(Agent, agent_id)
        agent.state = AgentState.OFFLINE
        await s.commit()
    async with brain_app.state.db.session() as s:
        await AgentRepository(s).promote_online_if_offline(agent_id)
        await s.commit()
    assert await _agent_state(brain_app, agent_id) == AgentState.ONLINE


def test_frame_upload_cap_counts_encoded_utf8_bytes() -> None:
    """The 1 MiB wire ceiling is bytes, not Python code points."""
    from pydantic import ValidationError
    from z4j_brain.api.agent_longpoll import FrameUploadBody

    FrameUploadBody(frames=["é" * (512 * 1024)])
    with pytest.raises(ValidationError, match=r"1048578 bytes; cap is 1048576"):
        FrameUploadBody(frames=["é" * ((512 * 1024) + 1)])


async def test_signature_failure_requires_fresh_nonce_connect_probe(
    client,
    settings,
    agent_ids,
) -> None:
    """A failed nonce stays invalid instead of silently gaining seq=0 state."""
    nonce = f"invalidated-{uuid.uuid4()}"
    raw = _signed_heartbeat(settings, agent_ids, nonce=nonce, frame_id="first")
    first = await client.post(
        "/api/v1/agent/events",
        json={"frames": [raw]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert first.status_code == 200

    # Replaying seq=1 raises SignatureError and invalidates the registry slot.
    failed = await client.post(
        "/api/v1/agent/events",
        json={"frames": [raw]},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert failed.status_code == 409

    same_nonce_probe = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": nonce,
        },
    )
    assert same_nonce_probe.status_code == 409

    fresh_nonce = f"fresh-{uuid.uuid4()}"
    fresh_claim = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": fresh_nonce,
        },
    )
    assert fresh_claim.status_code == 409

    fresh_probe = await client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 0},
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": fresh_nonce,
        },
    )
    assert fresh_probe.status_code == 200
    fresh_upload = await client.post(
        "/api/v1/agent/events",
        json={
            "frames": [
                _signed_heartbeat(
                    settings,
                    agent_ids,
                    nonce=fresh_nonce,
                    frame_id="fresh",
                ),
            ],
        },
        headers={
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "X-Z4J-Session-Nonce": fresh_nonce,
        },
    )
    assert fresh_upload.status_code == 200


async def test_global_session_cap_never_evicts_another_agent(monkeypatch) -> None:
    """At capacity, nonce churn self-evicts or fails; it never crosses agents."""
    from types import SimpleNamespace

    import z4j_brain.api.agent_longpoll as longpoll

    monkeypatch.setattr(longpoll, "_SESSION_REGISTRY_MAX", 2)
    monkeypatch.setattr(longpoll, "_SESSION_PER_AGENT_MAX", 3)
    project_id = uuid.uuid4()
    agent_a = SimpleNamespace(id=uuid.uuid4(), project_id=project_id)
    agent_b = SimpleNamespace(id=uuid.uuid4(), project_id=project_id)
    agent_c = SimpleNamespace(id=uuid.uuid4(), project_id=project_id)
    secret = b"registry-fairness-test-secret-32b"

    async with longpoll._registry_lock:
        longpoll._sessions.clear()
        longpoll._sessions_per_agent.clear()
    try:
        await longpoll._get_or_create_session(
            agent=agent_a,
            master_secret=secret,
            session_nonce="a-1",
        )
        pair_b = await longpoll._get_or_create_session(
            agent=agent_b,
            master_secret=secret,
            session_nonce="b-1",
        )
        key_b = longpoll._session_key(agent_b.id, "b-1")
        stored_b = longpoll._sessions[key_b]
        assert stored_b.state == pair_b

        # A is below its per-agent limit, but the global registry is full.
        # Its new nonce may replace only A's old nonce; B survives unchanged.
        await longpoll._get_or_create_session(
            agent=agent_a,
            master_secret=secret,
            session_nonce="a-2",
        )
        assert longpoll._sessions[key_b] is stored_b
        assert longpoll._session_key(agent_a.id, "a-1") not in longpoll._sessions

        # A brand-new agent has no self-owned victim, so admission fails closed.
        with pytest.raises(longpoll._SessionCapacityError):
            await longpoll._get_or_create_session(
                agent=agent_c,
                master_secret=secret,
                session_nonce="c-1",
            )
        assert longpoll._sessions[key_b] is stored_b
    finally:
        async with longpoll._registry_lock:
            longpoll._sessions.clear()
            longpoll._sessions_per_agent.clear()


async def test_global_session_cap_recovers_after_idle_ttl(monkeypatch) -> None:
    """Abandoned distinct-agent entries cannot make HTTP 503 permanent."""
    from types import SimpleNamespace

    import z4j_brain.api.agent_longpoll as longpoll

    monkeypatch.setattr(longpoll, "_SESSION_REGISTRY_MAX", 2)
    monkeypatch.setattr(longpoll, "_SESSION_PER_AGENT_MAX", 3)
    monkeypatch.setattr(longpoll, "_SESSION_IDLE_TTL_SECONDS", 10.0)
    clock = [100.0]
    monkeypatch.setattr(longpoll, "_registry_now", lambda: clock[0])
    project_id = uuid.uuid4()
    agents = [SimpleNamespace(id=uuid.uuid4(), project_id=project_id) for _ in range(3)]
    secret = b"registry-idle-ttl-test-secret-32b"

    async with longpoll._registry_lock:
        longpoll._sessions.clear()
        longpoll._sessions_per_agent.clear()
    try:
        for index, agent in enumerate(agents[:2]):
            await longpoll._get_or_create_session(
                agent=agent,
                master_secret=secret,
                session_nonce=f"resident-{index}",
            )

        clock[0] = 109.999
        with pytest.raises(longpoll._SessionCapacityError):
            await longpoll._get_or_create_session(
                agent=agents[2],
                master_secret=secret,
                session_nonce="new-agent",
            )
        assert len(longpoll._sessions) == 2

        clock[0] = 110.0
        pair = await longpoll._get_or_create_session(
            agent=agents[2],
            master_secret=secret,
            session_nonce="new-agent",
        )
        new_key = longpoll._session_key(agents[2].id, "new-agent")
        assert longpoll._sessions[new_key].state == pair
        assert len(longpoll._sessions) == 1
        assert longpoll._sessions_per_agent == {agents[2].id: 1}
    finally:
        async with longpoll._registry_lock:
            longpoll._sessions.clear()
            longpoll._sessions_per_agent.clear()


async def test_missing_invalidation_never_exceeds_both_caps(monkeypatch) -> None:
    """A failed self-eviction cannot be followed by an unchecked insert."""
    from types import SimpleNamespace

    import z4j_brain.api.agent_longpoll as longpoll

    monkeypatch.setattr(longpoll, "_SESSION_REGISTRY_MAX", 2)
    monkeypatch.setattr(longpoll, "_SESSION_PER_AGENT_MAX", 2)
    agent = SimpleNamespace(id=uuid.uuid4(), project_id=uuid.uuid4())
    secret = b"registry-invalidation-cap-secret-32b"

    async with longpoll._registry_lock:
        longpoll._sessions.clear()
        longpoll._sessions_per_agent.clear()
    try:
        for nonce in ("failed-1", "failed-2"):
            await longpoll._get_or_create_session(
                agent=agent,
                master_secret=secret,
                session_nonce=nonce,
            )
        for nonce in ("failed-1", "failed-2"):
            await longpoll._invalidate_session(agent.id, nonce)

        for missing_nonce in ("missing-3", "missing-4"):
            with pytest.raises(longpoll._SessionCapacityError):
                await longpoll._invalidate_session(agent.id, missing_nonce)

        assert len(longpoll._sessions) == 2
        assert longpoll._sessions_per_agent == {agent.id: 2}
        assert all(
            isinstance(entry.state, longpoll._InvalidatedSession)
            for entry in longpoll._sessions.values()
        )
    finally:
        async with longpoll._registry_lock:
            longpoll._sessions.clear()
            longpoll._sessions_per_agent.clear()


async def test_concurrent_invalidation_pins_state_until_safe_recovery(monkeypatch) -> None:
    """Concurrent cap pressure cannot evict or overcount in-flight state."""
    from types import SimpleNamespace

    import z4j_brain.api.agent_longpoll as longpoll

    monkeypatch.setattr(longpoll, "_registry_lock", asyncio.Lock())
    monkeypatch.setattr(longpoll, "_SESSION_REGISTRY_MAX", 2)
    monkeypatch.setattr(longpoll, "_SESSION_PER_AGENT_MAX", 2)
    monkeypatch.setattr(longpoll, "_SESSION_IDLE_TTL_SECONDS", 1.0)
    clock = [200.0]
    monkeypatch.setattr(longpoll, "_registry_now", lambda: clock[0])
    agent = SimpleNamespace(id=uuid.uuid4(), project_id=uuid.uuid4())
    secret = b"registry-concurrency-test-secret-32b"
    requests = [SimpleNamespace(state=SimpleNamespace()) for _ in range(2)]

    async with longpoll._registry_lock:
        longpoll._sessions.clear()
        longpoll._sessions_per_agent.clear()
    try:
        for nonce, request in zip(("leased-1", "leased-2"), requests, strict=True):
            await longpoll._get_or_create_session(
                agent=agent,
                master_secret=secret,
                session_nonce=nonce,
                request=request,
            )

        # Both entries are far beyond the TTL but request leases make them
        # ineligible for cleanup. Queue invalidation before admission on the
        # fair registry lock so the interleaving is deterministic.
        clock[0] = 300.0
        async with longpoll._registry_lock:
            invalidate_task = asyncio.create_task(
                longpoll._invalidate_session(agent.id, "leased-1"),
            )
            admission_task = asyncio.create_task(
                longpoll._get_or_create_session(
                    agent=agent,
                    master_secret=secret,
                    session_nonce="fresh",
                    establishes_session=True,
                ),
            )
            await asyncio.sleep(0)
        await invalidate_task
        with pytest.raises(longpoll._SessionInvalidatedError):
            await admission_task

        key_one = longpoll._session_key(agent.id, "leased-1")
        key_two = longpoll._session_key(agent.id, "leased-2")
        assert isinstance(
            longpoll._sessions[key_one].state,
            longpoll._InvalidatedSession,
        )
        assert longpoll._sessions[key_one].leases == 1
        assert longpoll._sessions[key_two].leases == 1
        assert len(longpoll._sessions) == 2
        assert longpoll._sessions_per_agent == {agent.id: 2}

        await longpoll._release_session_lease(
            requests[0].state._z4j_longpoll_session_lease,
        )
        fresh_pair = await longpoll._get_or_create_session(
            agent=agent,
            master_secret=secret,
            session_nonce="fresh",
            establishes_session=True,
        )
        fresh_key = longpoll._session_key(agent.id, "fresh")
        assert longpoll._sessions[fresh_key].state == fresh_pair
        assert key_one not in longpoll._sessions
        assert longpoll._sessions[key_two].leases == 1
        assert len(longpoll._sessions) == 2
        assert longpoll._sessions_per_agent == {agent.id: 2}
    finally:
        lease = getattr(requests[1].state, "_z4j_longpoll_session_lease", None)
        if lease is not None:
            await longpoll._release_session_lease(lease)
        async with longpoll._registry_lock:
            longpoll._sessions.clear()
            longpoll._sessions_per_agent.clear()


async def test_cancelled_response_finalizer_still_releases_session_lease(monkeypatch) -> None:
    """Cancellation cannot leave an otherwise idle entry permanently pinned."""
    from types import SimpleNamespace

    import z4j_brain.api.agent_longpoll as longpoll

    monkeypatch.setattr(longpoll, "_registry_lock", asyncio.Lock())
    agent = SimpleNamespace(id=uuid.uuid4(), project_id=uuid.uuid4())
    request = SimpleNamespace(state=SimpleNamespace())
    secret = b"registry-finalizer-cancel-secret-32b"

    async with longpoll._registry_lock:
        longpoll._sessions.clear()
        longpoll._sessions_per_agent.clear()
    try:
        await longpoll._get_or_create_session(
            agent=agent,
            master_secret=secret,
            session_nonce="cancelled-response",
            request=request,
        )
        finalizer = longpoll._release_longpoll_session_after_request(request)
        await anext(finalizer)

        # Hold the registry lock so cancellation lands while the shielded
        # release is genuinely pending, then let the finalizer drain it.
        async with longpoll._registry_lock:
            close_task = asyncio.create_task(finalizer.aclose())
            await asyncio.sleep(0)
            close_task.cancel()
            await asyncio.sleep(0)
        with pytest.raises(asyncio.CancelledError):
            await close_task

        key = longpoll._session_key(agent.id, "cancelled-response")
        assert longpoll._sessions[key].leases == 0
        assert request.state._z4j_longpoll_session_lease is None
        assert longpoll._sessions_per_agent == {agent.id: 1}
    finally:
        async with longpoll._registry_lock:
            longpoll._sessions.clear()
            longpoll._sessions_per_agent.clear()
