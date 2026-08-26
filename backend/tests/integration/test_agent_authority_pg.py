"""Real-PostgreSQL lock-order regressions for durable agent revocation."""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from z4j_brain.api.agents import (
    CreateAgentRequest,
    create_agent,
    revoke_agent,
)
from z4j_brain.domain.event_ingestor import BatchIngestResult
from z4j_brain.errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
)
from z4j_brain.persistence.agent_authority import acquire_agent_authority_xact_lock
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, ProjectRole
from z4j_brain.persistence.models import Agent, Event, Membership, Project, User
from z4j_brain.persistence.repositories import (
    AgentRepository,
    MembershipRepository,
    ProjectRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_brain.websocket.gateway import deliver_command_frame_with_authority
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.frames import EventBatchFrame, EventBatchPayload

pytestmark = pytest.mark.asyncio


async def _wait_for_pg_blocker(
    db: DatabaseManager,
    *,
    waiter_pid: int,
    blocker_pid: int,
) -> None:
    """Wait until PostgreSQL itself reports the expected blocking edge."""

    async def _poll() -> None:
        async with db.session() as observer:
            while True:
                blockers = await observer.scalar(
                    text("SELECT pg_blocking_pids(:waiter_pid)"),
                    {"waiter_pid": waiter_pid},
                )
                if blockers is not None and blocker_pid in blockers:
                    return

    await asyncio.wait_for(_poll(), timeout=3)


async def test_explicit_revoke_precedes_actual_inbound_frame(
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A revoke holding durable authority makes FrameRouter reject the frame."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="inbound-revoke", name="Inbound revoke"))
        session.add(
            User(
                id=user_id,
                email=f"inbound-revoke-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="inbound-revoke-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    ingest_calls = 0

    class RecordingIngestor:
        async def ingest_batch(self, **_kwargs):
            nonlocal ingest_calls
            ingest_calls += 1
            return BatchIngestResult(new_events=[], transient_skips=0)

    router = FrameRouter(
        db=db,
        ingestor=RecordingIngestor(),  # type: ignore[arg-type]
        dispatcher=None,  # type: ignore[arg-type]
        project_id=project_id,
        agent_id=agent_id,
    )

    revoke_holds_authority = asyncio.Event()
    release_revoke = asyncio.Event()
    real_revoke = AgentRepository.revoke

    async def paused_revoke(self, agent, *, at):
        revoke_holds_authority.set()
        await asyncio.wait_for(release_revoke.wait(), timeout=3)
        await real_revoke(self, agent, at=at)

    monkeypatch.setattr(AgentRepository, "revoke", paused_revoke)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    class NoopRegistry:
        async def kick(self, _agent_id: uuid.UUID) -> int:
            return 0

    loop = asyncio.get_running_loop()
    revoke_pid: asyncio.Future[int] = loop.create_future()
    inbound_pid: asyncio.Future[int] = loop.create_future()

    async def revoke_through_endpoint() -> None:
        async with db.session(write=True) as session:
            pid = await session.scalar(text("SELECT pg_backend_pid()"))
            assert pid is not None
            revoke_pid.set_result(int(pid))
            user = await session.get(User, user_id)
            assert user is not None
            await revoke_agent(
                "inbound-revoke",
                agent_id,
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                audit=NoopAudit(),  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
                registry=NoopRegistry(),
            )

    async def observed_inbound_authority(
        session: AsyncSession,
        selected_agent_id: uuid.UUID,
    ) -> None:
        assert selected_agent_id == agent_id
        pid = await session.scalar(text("SELECT pg_backend_pid()"))
        assert pid is not None
        inbound_pid.set_result(int(pid))
        await acquire_agent_authority_xact_lock(session, selected_agent_id)

    monkeypatch.setattr(
        "z4j_brain.websocket.frame_router.acquire_agent_authority_xact_lock",
        observed_inbound_authority,
    )

    revoke_task = asyncio.create_task(revoke_through_endpoint())
    await asyncio.wait_for(revoke_holds_authority.wait(), timeout=3)
    inbound_task = asyncio.create_task(
        router.dispatch(
            EventBatchFrame(
                id="inbound-versus-revoke",
                payload=EventBatchPayload(events=[]),
            ),
        ),
    )
    try:
        await _wait_for_pg_blocker(
            db,
            waiter_pid=await asyncio.wait_for(inbound_pid, timeout=3),
            blocker_pid=await asyncio.wait_for(revoke_pid, timeout=3),
        )
    finally:
        release_revoke.set()

    await asyncio.wait_for(revoke_task, timeout=3)
    assert await asyncio.wait_for(inbound_task, timeout=3) is FrameOutcome.REVOKED
    assert ingest_calls == 0
    async with db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.revoked_at is not None


async def test_control_persist_does_not_invert_domain_to_agent_lock_order(
    migrated_engine: AsyncEngine,
) -> None:
    """ACK/result authority must not hold Agent before a domain lock.

    The ``claim`` transaction models the canonical Schedule/Stream -> Agent
    order with a transaction-scoped advisory lock standing in for the already-
    held domain row. The real FrameRouter path then reaches its persist callback,
    which waits for that domain lock. If FrameRouter first takes ``Agent FOR
    UPDATE`` (the regressed implementation), PostgreSQL detects the exact cycle;
    depending on the victim, either ``claim`` raises or FrameRouter consumes a
    retry. The fixed advisory-authority path completes in one attempt.
    """

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="agent-authority", name="Authority"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="authority-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
                last_seen_at=datetime.now(UTC),
            ),
        )
        await session.commit()

    router = FrameRouter(
        db=db,
        ingestor=None,  # type: ignore[arg-type]
        dispatcher=None,  # type: ignore[arg-type]
        project_id=project_id,
        agent_id=agent_id,
    )
    # Dedicated test namespace, distinct from the agent-authority hash.
    domain_lock_key = 0x5A344A5F444F4D41
    claim_has_domain_lock = asyncio.Event()
    inbound_reached_domain_lock = asyncio.Event()
    persist_calls = 0

    async def claim_in_canonical_order() -> None:
        async with db.session(write=True) as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": domain_lock_key},
            )
            claim_has_domain_lock.set()
            await asyncio.wait_for(inbound_reached_domain_lock.wait(), timeout=3)
            await session.execute(
                select(Agent).where(Agent.id == agent_id).with_for_update(),
            )
            await session.commit()

    async def persist_after_authority(session: AsyncSession) -> None:
        nonlocal persist_calls
        persist_calls += 1
        inbound_reached_domain_lock.set()
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": domain_lock_key},
        )

    claim_task = asyncio.create_task(claim_in_canonical_order())
    await asyncio.wait_for(claim_has_domain_lock.wait(), timeout=3)
    inbound_task = asyncio.create_task(
        router._run_control_persist(
            "command_result",
            uuid.uuid4(),
            persist_after_authority,
        ),
    )
    await asyncio.wait_for(
        asyncio.gather(claim_task, inbound_task),
        timeout=8,
    )
    assert persist_calls == 1


async def test_event_projection_does_not_invert_domain_to_agent_lock_order(
    migrated_engine: AsyncEngine,
) -> None:
    """Event ingest uses the same advisory authority, not Agent FOR UPDATE."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="event-authority", name="Events"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="event-authority-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    domain_lock_key = 0x5A344A5F45564E54
    claim_has_domain_lock = asyncio.Event()
    ingest_reached_domain_lock = asyncio.Event()

    class DomainLockIngestor:
        async def ingest_batch(self, *, event_repo, **_kwargs):
            ingest_reached_domain_lock.set()
            await event_repo.session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": domain_lock_key},
            )
            return BatchIngestResult(new_events=[], transient_skips=0)

    router = FrameRouter(
        db=db,
        ingestor=DomainLockIngestor(),  # type: ignore[arg-type]
        dispatcher=None,  # type: ignore[arg-type]
        project_id=project_id,
        agent_id=agent_id,
    )

    async def claim_in_canonical_order() -> None:
        async with db.session(write=True) as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": domain_lock_key},
            )
            claim_has_domain_lock.set()
            await asyncio.wait_for(ingest_reached_domain_lock.wait(), timeout=3)
            await session.execute(
                select(Agent).where(Agent.id == agent_id).with_for_update(),
            )
            await session.commit()

    claim_task = asyncio.create_task(claim_in_canonical_order())
    await asyncio.wait_for(claim_has_domain_lock.wait(), timeout=3)
    ingest_task = asyncio.create_task(
        router.dispatch(
            EventBatchFrame(
                id="event-authority-cycle",
                payload=EventBatchPayload(events=[]),
            ),
        ),
    )
    _, outcome = await asyncio.wait_for(
        asyncio.gather(claim_task, ingest_task),
        timeout=8,
    )
    assert outcome is FrameOutcome.DURABLE


async def test_prune_waits_for_reconnect_row_lock_and_rechecks_staleness(
    migrated_engine: AsyncEngine,
) -> None:
    """A reconnect that wins the Agent row cannot be tombstoned by prune."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=30)
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="prune-authority", name="Prune"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="reconnecting-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
                last_seen_at=now - timedelta(days=60),
            ),
        )
        await session.commit()

    reconnect_holds_row = asyncio.Event()
    release_reconnect = asyncio.Event()

    async def reconnect() -> None:
        async with db.session(write=True) as session:
            connected_at = await AgentRepository(session).mark_online(
                agent_id,
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
            )
            assert connected_at is not None
            reconnect_holds_row.set()
            await asyncio.wait_for(release_reconnect.wait(), timeout=3)
            await session.commit()

    async def prune_selected_candidate() -> int:
        async with db.session(write=True) as session:
            count = await AgentRepository(session).prune_stale(
                cutoff=cutoff,
                candidate_ids=[agent_id],
            )
            await session.commit()
            return count

    reconnect_task = asyncio.create_task(reconnect())
    await asyncio.wait_for(reconnect_holds_row.wait(), timeout=3)
    prune_task = asyncio.create_task(prune_selected_candidate())
    await asyncio.sleep(0.1)
    assert prune_task.done() is False

    release_reconnect.set()
    await asyncio.wait_for(reconnect_task, timeout=3)
    assert await asyncio.wait_for(prune_task, timeout=3) == 0
    async with db.session() as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.state == AgentState.ONLINE
        assert agent.revoked_at is None


async def test_prune_soft_revokes_event_bearing_agent_without_fk_delete(
    migrated_engine: AsyncEngine,
) -> None:
    """The normal PostgreSQL FK case is retained and its token is killed."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=30)
    token_hash = secrets.token_hex(32)
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="prune-event", name="Prune event"))
        await session.flush()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="event-bearing-agent",
                token_hash=token_hash,
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.OFFLINE,
                last_seen_at=now - timedelta(days=60),
            ),
        )
        await session.flush()
        session.add(
            Event(
                project_id=project_id,
                agent_id=agent_id,
                engine="celery",
                task_id="task-prune-event",
                kind="task.succeeded",
                occurred_at=now,
                payload={},
            ),
        )
        await session.commit()

    async with db.session(write=True) as session:
        count = await AgentRepository(session).prune_stale(cutoff=cutoff)
        await session.commit()
    assert count == 1

    async with db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.revoked_at is not None
        assert tombstone.token_hash != token_hash
        assert await AgentRepository(session).get_by_token_hash(token_hash) is None
        assert (
            await session.scalar(
                select(Event.agent_id).where(Event.task_id == "task-prune-event"),
            )
            == agent_id
        )


async def test_hygiene_drains_postgres_in_bounded_authority_batches(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """More than one batch drains without an oversized IN or lock set."""
    import z4j_brain.persistence.repositories.agents as agents_module
    from z4j_brain.domain.workers.agent_hygiene import AgentHygieneWorker

    monkeypatch.setattr(agents_module, "AGENT_STALE_PRUNE_BATCH_SIZE", 2)
    db = DatabaseManager(migrated_engine)
    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    project_id = uuid.uuid4()
    agent_ids = [uuid.uuid4() for _ in range(5)]
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="bounded-pg-prune", name="Bounded PG"))
        await session.flush()
        session.add_all(
            [
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name=f"never-connected-{index}",
                    token_hash=secrets.token_hex(32),
                    protocol_version="0",
                    framework_adapter="unknown",
                    engine_adapters=[],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.UNKNOWN,
                    created_at=old,
                    updated_at=old,
                )
                for index, agent_id in enumerate(agent_ids)
            ],
        )
        await session.commit()

    mutation_batches: list[tuple[uuid.UUID, ...]] = []
    authority_batches: list[list[uuid.UUID]] = []
    original_prune = AgentRepository.prune_stale
    original_authority = agents_module.acquire_agent_authority_xact_lock

    async def recording_authority(
        session: AsyncSession,
        agent_id: uuid.UUID,
    ) -> None:
        assert authority_batches
        authority_batches[-1].append(agent_id)
        await original_authority(session, agent_id)

    async def recording_prune(
        repository: AgentRepository,
        *,
        cutoff: datetime,
        candidate_ids: list[uuid.UUID] | None = None,
    ) -> int:
        assert candidate_ids is not None
        mutation_batches.append(tuple(candidate_ids))
        authority_batches.append([])
        assert len(candidate_ids) <= agents_module.AGENT_STALE_PRUNE_BATCH_SIZE
        return await original_prune(
            repository,
            cutoff=cutoff,
            candidate_ids=candidate_ids,
        )

    monkeypatch.setattr(AgentRepository, "prune_stale", recording_prune)
    monkeypatch.setattr(
        agents_module,
        "acquire_agent_authority_xact_lock",
        recording_authority,
    )
    await AgentHygieneWorker(db=db, settings=integration_settings).tick()

    assert [len(batch) for batch in mutation_batches] == [2, 2, 1]
    assert [len(batch) for batch in authority_batches] == [2, 2, 1]
    assert [tuple(batch) for batch in authority_batches] == [
        tuple(sorted(set(batch), key=str)) for batch in mutation_batches
    ]
    assert sorted(agent_id for batch in mutation_batches for agent_id in batch) == sorted(agent_ids)
    async with db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(Agent).where(Agent.project_id == project_id),
                )
            ).scalars(),
        )
        assert len(rows) == len(agent_ids)
        assert all(row.revoked_at is not None for row in rows)


async def test_explicit_revoke_row_lock_precedes_outbound_authority_check(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A revoke that wins first suppresses a later physical command send.

    The endpoint is paused inside ``AgentRepository.revoke``, after its raw
    Agent lookup but before the token-killing flush. Its lookup must already
    hold ``FOR UPDATE``: otherwise the outbound live-row check overtakes the
    paused revoke and physically sends. This exercises the real endpoint call
    and the real PostgreSQL sender authority path together.
    """

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="revoke-first", name="Revoke first"))
        session.add(
            User(
                id=user_id,
                email=f"revoke-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="revoke-first-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    revoke_reached_pre_flush = asyncio.Event()
    release_revoke = asyncio.Event()
    real_revoke = AgentRepository.revoke

    async def paused_revoke(self, agent, *, at):
        revoke_reached_pre_flush.set()
        await asyncio.wait_for(release_revoke.wait(), timeout=3)
        await real_revoke(self, agent, at=at)

    monkeypatch.setattr(AgentRepository, "revoke", paused_revoke)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    class NoopRegistry:
        async def kick(self, _agent_id: uuid.UUID) -> int:
            return 0

    async def revoke_through_endpoint() -> None:
        async with db.session(write=True) as session:
            user = await session.get(User, user_id)
            assert user is not None
            await revoke_agent(
                "revoke-first",
                agent_id,
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                audit=NoopAudit(),  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
                registry=NoopRegistry(),
            )

    class RecordingSocket:
        def __init__(self) -> None:
            self._z4j_agent_id = agent_id
            self._z4j_signer = SimpleNamespace(
                sign_and_serialize=lambda _frame: b"physically-sent",
            )
            self.sent: list[bytes] = []

        async def send_bytes(self, payload: bytes) -> None:
            self.sent.append(payload)

    socket = RecordingSocket()
    command = SimpleNamespace(
        id=uuid.uuid4(),
        project_id=project_id,
        agent_id=agent_id,
        issued_by=None,
        action="cancel_task",
        target_type="task",
        target_id="celery:revoke-first",
        payload={"engine": "celery", "task_id": "revoke-first"},
        delivery_claim_token=None,
    )

    revoke_task = asyncio.create_task(revoke_through_endpoint())
    await asyncio.wait_for(revoke_reached_pre_flush.wait(), timeout=3)
    outbound_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=socket,  # type: ignore[arg-type]
            settings=integration_settings,
            command=command,  # type: ignore[arg-type]
        ),
    )
    await asyncio.sleep(0.1)
    outbound_was_blocked = not outbound_task.done()
    release_revoke.set()
    await asyncio.wait_for(revoke_task, timeout=3)
    delivered = await asyncio.wait_for(outbound_task, timeout=3)

    assert outbound_was_blocked
    assert delivered is False
    assert socket.sent == []


async def test_outbound_row_lock_precedes_explicit_revoke(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A physical send that wins first completes before revoke tombstones it."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="send-first", name="Send first"))
        session.add(
            User(
                id=user_id,
                email=f"send-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="send-first-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    send_started = asyncio.Event()
    release_send = asyncio.Event()

    class BlockingSocket:
        def __init__(self) -> None:
            self._z4j_agent_id = agent_id
            self._z4j_signer = SimpleNamespace(
                sign_and_serialize=lambda _frame: b"physically-sent",
            )
            self.sent: list[bytes] = []

        async def send_bytes(self, payload: bytes) -> None:
            send_started.set()
            await asyncio.wait_for(release_send.wait(), timeout=3)
            self.sent.append(payload)

    command = SimpleNamespace(
        id=uuid.uuid4(),
        project_id=project_id,
        agent_id=agent_id,
        issued_by=None,
        action="cancel_task",
        target_type="task",
        target_id="celery:send-first",
        payload={"engine": "celery", "task_id": "send-first"},
        delivery_claim_token=None,
    )
    socket = BlockingSocket()
    outbound_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=socket,  # type: ignore[arg-type]
            settings=integration_settings,
            command=command,  # type: ignore[arg-type]
        ),
    )
    await asyncio.wait_for(send_started.wait(), timeout=3)

    revoke_mutation_started = asyncio.Event()
    real_revoke = AgentRepository.revoke

    async def observed_revoke(self, agent, *, at):
        revoke_mutation_started.set()
        await real_revoke(self, agent, at=at)

    monkeypatch.setattr(AgentRepository, "revoke", observed_revoke)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    class NoopRegistry:
        async def kick(self, _agent_id: uuid.UUID) -> int:
            return 0

    async def revoke_through_endpoint() -> None:
        async with db.session(write=True) as session:
            user = await session.get(User, user_id)
            assert user is not None
            await revoke_agent(
                "send-first",
                agent_id,
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                audit=NoopAudit(),  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
                registry=NoopRegistry(),
            )

    revoke_task = asyncio.create_task(revoke_through_endpoint())
    await asyncio.sleep(0.1)
    assert revoke_task.done() is False
    assert revoke_mutation_started.is_set() is False

    release_send.set()
    assert await asyncio.wait_for(outbound_task, timeout=3) is True
    await asyncio.wait_for(revoke_task, timeout=3)
    assert revoke_mutation_started.is_set()
    assert socket.sent == [b"physically-sent"]
    async with db.session() as session:
        tombstone = await session.get(Agent, agent_id)
        assert tombstone is not None
        assert tombstone.revoked_at is not None


async def test_revoke_revalidates_role_after_outbound_row_lock_wait(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A role downgrade committed during the send wait denies revocation.

    The request's initial policy check populates Membership in its identity
    map. The physical sender then makes the revoke wait on Agent FOR UPDATE.
    Once the wait ends, the endpoint must both place its policy recheck after
    that row-lock edge and expire the cached membership before querying it.
    """

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="revalidate-role", name="Revalidate role"))
        session.add(
            User(
                id=user_id,
                email=f"revalidate-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="revalidate-role-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            ),
        )
        await session.commit()

    send_started = asyncio.Event()
    release_send = asyncio.Event()

    class BlockingSocket:
        def __init__(self) -> None:
            self._z4j_agent_id = agent_id
            self._z4j_signer = SimpleNamespace(
                sign_and_serialize=lambda _frame: b"physically-sent",
            )
            self.sent: list[bytes] = []

        async def send_bytes(self, payload: bytes) -> None:
            send_started.set()
            await asyncio.wait_for(release_send.wait(), timeout=3)
            self.sent.append(payload)

    command = SimpleNamespace(
        id=uuid.uuid4(),
        project_id=project_id,
        agent_id=agent_id,
        issued_by=None,
        action="cancel_task",
        target_type="task",
        target_id="celery:revalidate-role",
        payload={"engine": "celery", "task_id": "revalidate-role"},
        delivery_claim_token=None,
    )
    socket = BlockingSocket()
    outbound_task = asyncio.create_task(
        deliver_command_frame_with_authority(
            db=db,
            websocket=socket,  # type: ignore[arg-type]
            settings=integration_settings,
            command=command,  # type: ignore[arg-type]
        ),
    )
    await asyncio.wait_for(send_started.wait(), timeout=3)

    revoke_reached_agent_lock = asyncio.Event()
    real_get_locked = AgentRepository.get_locked

    async def observed_get_locked(self, selected_agent_id):
        revoke_reached_agent_lock.set()
        return await real_get_locked(self, selected_agent_id)

    monkeypatch.setattr(AgentRepository, "get_locked", observed_get_locked)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    class NoopRegistry:
        async def kick(self, _agent_id: uuid.UUID) -> int:
            return 0

    async def revoke_through_endpoint() -> None:
        async with db.session(write=True) as session:
            user = await session.get(User, user_id)
            assert user is not None
            await revoke_agent(
                "revalidate-role",
                agent_id,
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                audit=NoopAudit(),  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
                registry=NoopRegistry(),
            )

    revoke_task = asyncio.create_task(revoke_through_endpoint())
    await asyncio.wait_for(revoke_reached_agent_lock.wait(), timeout=3)
    assert revoke_task.done() is False

    async with db.session(write=True) as session:
        membership = await MembershipRepository(session).get_for_user_project(
            user_id=user_id,
            project_id=project_id,
        )
        assert membership is not None
        membership.role = ProjectRole.VIEWER
        await session.commit()

    release_send.set()
    assert await asyncio.wait_for(outbound_task, timeout=3) is True
    with pytest.raises(AuthorizationError):
        await asyncio.wait_for(revoke_task, timeout=3)

    assert socket.sent == [b"physically-sent"]
    async with db.session() as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.revoked_at is None
        membership = await MembershipRepository(session).get_for_user_project(
            user_id=user_id,
            project_id=project_id,
        )
        assert membership is not None
        assert membership.role == ProjectRole.VIEWER


@pytest.mark.parametrize(
    ("authorization_change", "expected_error"),
    [
        pytest.param("demote", AuthorizationError, id="admin-demoted"),
        pytest.param("remove", NotFoundError, id="membership-removed"),
        pytest.param("deactivate", AuthenticationError, id="user-deactivated"),
    ],
)
async def test_same_name_remint_revalidates_authorization_after_name_lock(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    authorization_change: str,
    expected_error: type[Exception],
) -> None:
    """A policy change after name authority prevents credential issuance."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    tombstone_id = uuid.uuid4()
    slug = f"remint-auth-{authorization_change}"
    reusable_name = "authorization-remint"
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug=slug, name="Remint authority"))
        session.add(
            User(
                id=user_id,
                email=f"remint-auth-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        tombstone = Agent(
            id=tombstone_id,
            project_id=project_id,
            name=reusable_name,
            token_hash=secrets.token_hex(32),
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.OFFLINE,
        )
        session.add(tombstone)
        await session.flush()
        await AgentRepository(session).revoke(tombstone, at=datetime.now(UTC))
        await session.commit()

    name_authority_acquired = asyncio.Event()
    release_reservation = asyncio.Event()
    original_reserve_name = AgentRepository.reserve_name

    async def paused_reserve_name(
        repository: AgentRepository,
        *,
        project_id: uuid.UUID,
        name: str,
    ):
        reservation = await original_reserve_name(
            repository,
            project_id=project_id,
            name=name,
        )
        assert reservation.owner is not None
        assert reservation.owner.id == tombstone_id
        name_authority_acquired.set()
        await asyncio.wait_for(release_reservation.wait(), timeout=3)
        return reservation

    monkeypatch.setattr(AgentRepository, "reserve_name", paused_reserve_name)
    plaintext_mints = 0

    def recording_token_urlsafe(_bytes: int) -> str:
        nonlocal plaintext_mints
        plaintext_mints += 1
        return "credential-must-not-be-created"

    import z4j_brain.api.agents as agents_api

    monkeypatch.setattr(agents_api.secrets, "token_urlsafe", recording_token_urlsafe)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    async def remint():
        async with db.session(write=True) as session:
            user = await session.get(User, user_id)
            assert user is not None
            return await create_agent(
                slug,
                CreateAgentRequest(name=reusable_name),
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                settings=integration_settings,
                audit=NoopAudit(),  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
            )

    remint_task = asyncio.create_task(remint())
    await asyncio.wait_for(name_authority_acquired.wait(), timeout=3)
    async with db.session(write=True) as session:
        if authorization_change == "demote":
            membership = await MembershipRepository(session).get_for_user_project(
                user_id=user_id,
                project_id=project_id,
            )
            assert membership is not None
            membership.role = ProjectRole.VIEWER
        elif authorization_change == "remove":
            await session.execute(
                delete(Membership).where(
                    Membership.user_id == user_id,
                    Membership.project_id == project_id,
                ),
            )
        else:
            assert authorization_change == "deactivate"
            user = await session.get(User, user_id)
            assert user is not None
            user.is_active = False
        await session.commit()

    release_reservation.set()
    with pytest.raises(expected_error):
        await asyncio.wait_for(remint_task, timeout=3)

    assert plaintext_mints == 0
    async with db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(Agent).where(Agent.project_id == project_id),
                )
            ).scalars(),
        )
        assert len(rows) == 1
        assert rows[0].id == tombstone_id
        assert rows[0].name == reusable_name
        assert rows[0].revoked_at is not None


async def test_concurrent_same_name_remint_releases_one_tombstone_once(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """Two remints racing a tombstone produce one live replacement."""

    db = DatabaseManager(migrated_engine)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    tombstone_id = uuid.uuid4()
    reusable_name = "concurrent-remint"
    async with db.session(write=True) as session:
        session.add(Project(id=project_id, slug="concurrent-remint", name="Remint"))
        session.add(
            User(
                id=user_id,
                email=f"concurrent-remint-{uuid.uuid4().hex}@example.com",
                password_hash="not-used-by-this-test",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            ),
        )
        tombstone = Agent(
            id=tombstone_id,
            project_id=project_id,
            name=reusable_name,
            token_hash=secrets.token_hex(32),
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.OFFLINE,
        )
        session.add(tombstone)
        await session.flush()
        await AgentRepository(session).revoke(tombstone, at=datetime.now(UTC))
        await session.commit()

    first_insert_flushed = asyncio.Event()
    release_first_commit = asyncio.Event()

    class PausingAudit:
        async def record(self, *_args, **_kwargs) -> None:
            first_insert_flushed.set()
            await asyncio.wait_for(release_first_commit.wait(), timeout=3)

    class NoopAudit:
        async def record(self, *_args, **_kwargs) -> None:
            return None

    loop = asyncio.get_running_loop()
    first_pid: asyncio.Future[int] = loop.create_future()
    second_pid: asyncio.Future[int] = loop.create_future()

    async def remint(
        *,
        pid_result: asyncio.Future[int],
        audit: PausingAudit | NoopAudit,
    ):
        async with db.session(write=True) as session:
            pid = await session.scalar(text("SELECT pg_backend_pid()"))
            assert pid is not None
            pid_result.set_result(int(pid))
            user = await session.get(User, user_id)
            assert user is not None
            return await create_agent(
                "concurrent-remint",
                CreateAgentRequest(name=reusable_name),
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                settings=integration_settings,
                audit=audit,  # type: ignore[arg-type]
                audit_log=object(),  # type: ignore[arg-type]
                db_session=session,
                ip="127.0.0.1",
            )

    first_task = asyncio.create_task(
        remint(pid_result=first_pid, audit=PausingAudit()),
    )
    await asyncio.wait_for(first_insert_flushed.wait(), timeout=3)
    second_task = asyncio.create_task(
        remint(pid_result=second_pid, audit=NoopAudit()),
    )
    try:
        await _wait_for_pg_blocker(
            db,
            waiter_pid=await asyncio.wait_for(second_pid, timeout=3),
            blocker_pid=await asyncio.wait_for(first_pid, timeout=3),
        )
    finally:
        release_first_commit.set()

    first = await asyncio.wait_for(first_task, timeout=3)
    with pytest.raises(ConflictError):
        await asyncio.wait_for(second_task, timeout=3)

    assert first.agent.name == reusable_name
    assert first.agent.id != tombstone_id
    async with db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(Agent).where(Agent.project_id == project_id),
                )
            ).scalars(),
        )
        live = [row for row in rows if row.revoked_at is None]
        tombstones = [row for row in rows if row.revoked_at is not None]
        assert len(live) == 1
        assert live[0].id == first.agent.id
        assert live[0].name == reusable_name
        assert len(tombstones) == 1
        assert tombstones[0].id == tombstone_id
        assert tombstones[0].name.startswith(f"__z4j_revoked__:{tombstone_id}")
        assert tombstones[0].agent_metadata["_z4j_revoked_original_name"] == reusable_name


__all__ = []
