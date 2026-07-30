"""Boundary B durable request, outbox and ambiguity invariants."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from fastapi import HTTPException, Response
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from z4j_brain.api import commands as commands_mod
from z4j_brain.api.bulk_retry_requests import (
    BulkRetryRequestCreate,
    _compare_replay,
    create_bulk_retry_request,
)
from z4j_brain.api.commands import BulkRetryRequest, issue_bulk_retry
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.bulk_retry import (
    CURRENT_CANONICALIZER_VERSION,
    WORST_CASE_SIGNED_ENVELOPE_BYTES,
    PayloadTooLargeError,
    PlannedChild,
    UnsupportedRetryEngineError,
    build_sealed_plan,
    canonicalize_request,
)
from z4j_brain.domain.workers.bulk_retry import BulkRetryCoordinator
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import CommandStatus, TaskPriority, TaskState
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    BulkRetryControlState,
    BulkRetryDeliveryState,
    BulkRetryOutcome,
    BulkRetryRequestChild,
    Command,
    Project,
    Task,
    User,
)
from z4j_brain.persistence.models import (
    BulkRetryRequest as BulkRetryRequestRow,
)
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    BulkRetryRequestRepository,
    CommandRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry import SessionHandle
from z4j_brain.websocket.registry.local import LocalRegistry
from z4j_brain.websocket.registry.postgres_notify import PostgresNotifyRegistry


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret="s" * 64,  # type: ignore[arg-type]
        session_secret="t" * 64,  # type: ignore[arg-type]
        environment="dev",
    )


class _AllowProjectPolicy:
    async def get_project_or_404(self, projects: Any, _slug: str) -> Any:
        return projects

    async def require_member(
        self,
        _memberships: Any,
        **_kwargs: Any,
    ) -> None:
        return None


class _SessionDb:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    @asynccontextmanager
    async def session(self) -> Any:
        async with self._sessions() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise


class _FixedRegistry:
    def __init__(self, handle: SessionHandle | None) -> None:
        self.handle = handle
        self.requested_engines: list[str] = []

    async def select_project_session(
        self,
        *,
        project_id: uuid.UUID,
        required_retry_engine: str,
    ) -> SessionHandle | None:
        del project_id
        self.requested_engines.append(required_retry_engine)
        if self.handle and self.handle.supports_retry_engine(required_retry_engine):
            return self.handle
        return None

    async def select_session(
        self,
        *,
        agent_id: uuid.UUID,
        required_retry_engine: str | None = None,
    ) -> SessionHandle | None:
        if (
            self.handle
            and self.handle.agent_id == agent_id
            and self.handle.supports_retry_engine(required_retry_engine)
        ):
            return self.handle
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["local", "postgres"])
async def test_production_registry_selects_exact_project_session_for_coordinator(
    backend: str,
) -> None:
    """The coordinator contract must exist on both production registry types."""

    async def _deliver(_command_id: uuid.UUID, _websocket: Any) -> bool:
        return True

    if backend == "local":
        registry: Any = LocalRegistry(deliver_local=_deliver)
    else:
        registry = PostgresNotifyRegistry(
            settings=_settings(),
            db=object(),  # selection is entirely local and does not touch the DB
            dsn_provider=lambda: "postgresql://unused",
            deliver_local=_deliver,
        )

    target_project = uuid.uuid4()
    wrong_project = uuid.uuid4()
    wrong_project_handle = await registry.register(
        project_id=wrong_project,
        agent_id=uuid.uuid4(),
        ws=object(),
        worker_id="wrong-project",
        retry_contracts={"celery": 1},
    )
    wrong_contract_handle = await registry.register(
        project_id=target_project,
        agent_id=uuid.uuid4(),
        ws=object(),
        worker_id="wrong-contract",
        retry_contracts={"rq": 1},
    )
    expected = await registry.register(
        project_id=target_project,
        agent_id=uuid.uuid4(),
        ws=object(),
        worker_id="compatible",
        retry_contracts={"celery": 1},
    )

    selected = await registry.select_project_session(
        project_id=target_project,
        required_retry_engine="celery",
    )
    assert selected is expected
    assert selected.generation == expected.generation
    assert selected is not wrong_project_handle
    assert selected is not wrong_contract_handle
    assert (
        await registry.select_project_session(
            project_id=target_project,
            required_retry_engine="dramatiq",
        )
        is None
    )


@pytest_asyncio.fixture
async def boundary_db(
    tmp_path: Any,
) -> tuple[
    async_sessionmaker[AsyncSession],
    uuid.UUID,
    uuid.UUID,
    uuid.UUID,
]:
    """File-backed real SQLite with FK enforcement and production metadata."""

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'boundary-b.sqlite'}",
        connect_args={"timeout": 10},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with sessions() as session:
        session.add(
            Project(
                id=project_id,
                slug="boundary-b",
                name="Boundary B",
            )
        )
        session.add(
            User(
                id=user_id,
                email="boundary-b@example.com",
                password_hash="not-used",
            )
        )
        await session.commit()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="boundary-b-agent",
                token_hash="boundary-b-token",
                protocol_version="2",
                framework_adapter="bare",
                engine_adapters=["celery", "rq"],
                scheduler_adapters=[],
                capabilities={},
            )
        )
        await session.commit()
    yield sessions, project_id, user_id, agent_id
    await engine.dispose()


def _child(ordinal: int, engine: str = "celery") -> PlannedChild:
    payload = {
        "filter": {
            "engine": engine,
            "task_ids": [f"task-{ordinal}"],
            "task_names": {f"task-{ordinal}": "tasks.work"},
        },
        "max": 1,
    }
    exact = (
        '{"filter":{"engine":"'
        + engine
        + '","task_ids":["task-'
        + str(ordinal)
        + '"],"task_names":{"task-'
        + str(ordinal)
        + '":"tasks.work"}},"max":1}'
    ).encode()
    return PlannedChild(
        ordinal=ordinal,
        engine=engine,
        payload=payload,
        canonical_payload=exact,
        payload_digest=hashlib.sha256(exact).hexdigest(),
        payload_size=len(exact),
    )


async def _seal(
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    key: str,
    children: list[PlannedChild],
    max_in_flight: int = 8,
) -> BulkRetryRequestRow:
    canonical = canonicalize_request({"filter": {"state": "failure"}, "max": 100})
    repository = BulkRetryRequestRepository(session)
    await repository.begin_immediate_if_sqlite()
    return await repository.insert_sealed(
        project_id=project_id,
        issued_by=user_id,
        idempotency_key=key,
        canonical=canonical,
        target_agent_id=None,
        planned_children=children,
        plan_digest=hashlib.sha256(key.encode()).hexdigest(),
        max_in_flight=max_in_flight,
        deadline_at=datetime.now(UTC) + timedelta(minutes=15),
        source_ip="127.0.0.1",
    )


@pytest.mark.asyncio
async def test_fault_before_seal_commit_leaves_no_visible_prefix(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    """Parent, reservation and all engines roll back as one unit."""

    sessions, project_id, user_id, _agent_id = boundary_db
    async with sessions() as session:
        with pytest.raises(RuntimeError, match="fault injected"):
            parent = await _seal(
                session,
                project_id=project_id,
                user_id=user_id,
                key="atomic-crash",
                children=[_child(0, "celery"), _child(1, "rq")],
            )
            await AuditService(_settings()).record(
                AuditLogRepository(session),
                action="bulk_retry_request.sealed",
                target_type="bulk_retry_request",
                target_id=str(parent.id),
                result="success",
                outcome="allow",
                user_id=user_id,
                project_id=project_id,
                source_ip="127.0.0.1",
                metadata={"children": 2},
            )
            raise RuntimeError("fault injected after plan/audit staging")
        await session.rollback()

    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequestRow.id)).where(
                    BulkRetryRequestRow.idempotency_key == "atomic-crash"
                )
            )
            == 0
        )
        assert await session.scalar(select(func.count(BulkRetryRequestChild.id))) == 0
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(Command.idempotency_key == "atomic-crash")
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "bulk_retry_request.sealed"
                )
            )
            == 0
        )


def test_replay_uses_stored_canonicalizer_and_exact_bytes() -> None:
    """A key collision compares request meaning, not only the digest."""

    original = canonicalize_request(
        {"filter": {"state": "failure"}, "max": 100},
        version=1,
    )
    parent = BulkRetryRequestRow(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        issued_by=uuid.uuid4(),
        idempotency_key="same-key",
        canonicalizer_version=1,
        canonical_request=original.exact_bytes,
        canonical_digest=original.digest,
        effective_request=original.effective,
        plan_digest="0" * 64,
        child_count=0,
        max_in_flight=8,
        deadline_at=datetime.now(UTC) + timedelta(minutes=15),
    )
    # Exact replay succeeds using stored v1.
    _compare_replay(
        parent,
        raw_identity={"filter": {"state": "failure"}, "max": 100},
    )
    # Different accepted meaning under the same raw key is a 409.
    with pytest.raises(HTTPException) as exc:
        _compare_replay(
            parent,
            raw_identity={"filter": {"state": "revoked"}, "max": 100},
        )
    assert exc.value.status_code == 409

    # A digest-only implementation would accept this forged byte payload.
    parent.canonical_request = b'{"different":"request"}'
    with pytest.raises(HTTPException) as exact_exc:
        _compare_replay(
            parent,
            raw_identity={"filter": {"state": "failure"}, "max": 100},
        )
    assert exact_exc.value.status_code == 409

    parent.canonical_request = original.exact_bytes
    with pytest.raises(HTTPException) as smuggled:
        _compare_replay(
            parent,
            raw_identity={
                "filter": {
                    "state": "failure",
                    "task_names": {"x": "os.system"},
                },
                "max": 100,
            },
        )
    assert smuggled.value.status_code == 409


def test_v1_canonical_bytes_have_an_independent_fixed_oracle() -> None:
    canonical = canonicalize_request(
        {
            "filter": {
                "status": "failure",
                "engine": "rq",
                "task_ids": ["b", "a", "b"],
            },
            "max": 9,
        },
        version=1,
    )
    expected = (
        b'{"action":"bulk_retry","filter":{"engine":"rq","state":"failure",'
        b'"task_ids":["b","a"]},"max":9,"target":{"routing_policy":'
        b'"project_compatible_session_v1"},"version":1}'
    )
    assert canonical.exact_bytes == expected
    assert canonical.digest == hashlib.sha256(expected).hexdigest()


def test_current_canonicalizer_seals_priority_and_search_scope() -> None:
    canonical = canonicalize_request(
        {
            "filter": {
                "state": "failure",
                "priority": ["low", "critical", "critical"],
                "search": "needle",
            },
            "max": 1000,
        }
    )
    expected = (
        b'{"action":"bulk_retry","filter":{"priority":["critical","low"],'
        b'"search":"needle","state":"failure"},"max":1000,"target":'
        b'{"routing_policy":"project_compatible_session_v1"},"version":2}'
    )
    assert CURRENT_CANONICALIZER_VERSION == 2
    assert canonical.version == 2
    assert canonical.exact_bytes == expected
    assert canonical.digest == hashlib.sha256(expected).hexdigest()

    with pytest.raises(ValueError, match="priority cannot be combined"):
        canonicalize_request(
            {
                "filter": {
                    "engine": "celery",
                    "task_ids": ["task-1"],
                    "priority": ["critical"],
                }
            }
        )


def test_sealed_child_reserves_worst_case_signed_envelope() -> None:
    task = Task(
        project_id=uuid.uuid4(),
        engine="celery",
        task_id="sized-task",
        name="tasks.work",
        state=TaskState.FAILURE,
    )
    expected_unsigned = (
        b'{"filter":{"engine":"celery","state":"failure","task_ids":'
        b'["sized-task"],"task_names":{"sized-task":"tasks.work"}},'
        b'"max":1}'
    )
    exact_cap = len(expected_unsigned) + WORST_CASE_SIGNED_ENVELOPE_BYTES
    with pytest.raises(PayloadTooLargeError):
        build_sealed_plan(
            [task],
            effective_filter={"state": "failure"},
            maximum=1,
            max_frame_bytes=exact_cap - 1,
        )
    children, _digest = build_sealed_plan(
        [task],
        effective_filter={"state": "failure"},
        maximum=1,
        max_frame_bytes=exact_cap,
    )
    assert children[0].canonical_payload == expected_unsigned
    assert children[0].payload_size == len(expected_unsigned)


def test_sealed_plan_refuses_to_truncate_matching_selection() -> None:
    tasks = [
        Task(
            project_id=uuid.uuid4(),
            engine="celery",
            task_id=f"matching-{index}",
            name="tasks.work",
            state=TaskState.FAILURE,
        )
        for index in range(2)
    ]

    with pytest.raises(ValueError, match="selection exceeds max"):
        build_sealed_plan(
            tasks,
            effective_filter={"state": "failure"},
            maximum=1,
            max_frame_bytes=64 * 1024,
        )


def test_engine_less_plan_rejects_selected_unknown_engine() -> None:
    """Forward-compatible ingest names never become retry authority."""
    task = Task(
        project_id=uuid.uuid4(),
        engine="futurequeue",
        task_id="unknown-engine-task",
        name="tasks.future",
        state=TaskState.FAILURE,
    )
    with pytest.raises(
        UnsupportedRetryEngineError,
        match="futurequeue:unknown-engine-task",
    ):
        build_sealed_plan(
            [task],
            effective_filter={"state": "failure"},
            maximum=1,
            max_frame_bytes=256 * 1024,
        )


@pytest.mark.asyncio
async def test_engine_less_api_refuses_unknown_selected_task_before_seal(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, _agent_id = boundary_db
    async with sessions() as session:
        session.add(
            Task(
                project_id=project_id,
                engine="futurequeue",
                task_id="unknown-api-task",
                name="tasks.future",
                state=TaskState.FAILURE,
            )
        )
        await session.commit()

    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        with pytest.raises(HTTPException) as refused:
            await create_bulk_retry_request(
                slug="boundary-b",
                body=BulkRetryRequestCreate(
                    idempotency_key="unknown-engine-api",
                    filter={"state": "failure"},
                    max=10,
                ),
                response=Response(),
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=AuditService(settings),
                db_session=session,
                settings=settings,
                ip="127.0.0.1",
            )
        assert refused.value.status_code == 400
        assert "futurequeue:unknown-api-task" in str(refused.value.detail)

    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequestRow.id)).where(
                    BulkRetryRequestRow.idempotency_key == "unknown-engine-api"
                )
            )
            == 0
        )
        assert await session.scalar(select(func.count(BulkRetryRequestChild.id))) == 0
        assert (
            await session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "bulk_retry_request.refused"
                )
            )
            == 1
        )


@pytest.mark.asyncio
async def test_stored_unknown_engine_cannot_select_or_claim(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every issuer and the irreversible repository edge fail closed."""
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="unknown-engine-stored-child",
            children=[_child(0, "futurequeue")],
        )
        await session.commit()
        child_id = await session.scalar(
            select(BulkRetryRequestChild.id).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child_id is not None

    handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="futurequeue-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts={"futurequeue": 1},
    )
    registry = _FixedRegistry(handle)
    delivered: list[Command] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered.append(kwargs["command"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings(),
        registry=registry,  # type: ignore[arg-type]
    )
    await coordinator.tick()
    assert delivered == []
    assert registry.requested_engines == []
    claim_calls = 0
    real_claim = BulkRetryRequestRepository.claim_child

    async def _forbidden_longpoll_claim(self: Any, **kwargs: Any) -> Command | None:
        nonlocal claim_calls
        claim_calls += 1
        return await real_claim(self, **kwargs)

    with monkeypatch.context() as longpoll_patch:
        longpoll_patch.setattr(
            BulkRetryRequestRepository,
            "claim_child",
            _forbidden_longpoll_claim,
        )
        assert (
            await coordinator.claim_for_longpoll(
                project_id=project_id,
                agent_id=agent_id,
                retry_contracts={"futurequeue": 1},
                generation=uuid.uuid4(),
                maximum=1,
            )
            == []
        )
    assert claim_calls == 0

    async with sessions() as session:
        assert (
            await BulkRetryRequestRepository(session).claim_child(
                child_id=child_id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=30,
            )
            is None
        )
        child = await session.get(BulkRetryRequestChild, child_id)
        assert child is not None
        assert child.delivery_state == BulkRetryDeliveryState.PENDING.value
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(Command.bulk_retry_child_id == child_id)
            )
            == 0
        )


@pytest.mark.asyncio
async def test_no_match_parent_is_terminal_and_never_needs_reexpansion(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, _agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="empty",
            children=[],
        )
        await session.commit()

    async with sessions() as session:
        repository = BulkRetryRequestRepository(session)
        replay = await repository.get_by_key(
            project_id=project_id,
            idempotency_key="empty",
        )
        assert replay is not None
        snapshot = await repository.snapshot(replay)
        assert snapshot.status == "no_match"
        assert snapshot.counts.total == 0
        assert replay.id == parent.id


@pytest.mark.asyncio
async def test_atomic_claim_is_single_winner_and_command_never_pending(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="one-winner",
            children=[_child(0)],
        )
        await session.commit()
        child = (
            await session.execute(
                select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
            )
        ).scalar_one()

    generation = uuid.uuid4()
    async with sessions() as first:
        command = await BulkRetryRequestRepository(first).claim_child(
            child_id=child.id,
            agent_id=agent_id,
            generation=generation,
            command_timeout_seconds=60,
        )
        await first.commit()
    async with sessions() as second:
        loser = await BulkRetryRequestRepository(second).claim_child(
            child_id=child.id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=60,
        )
        await second.commit()

    assert command is not None
    assert loser is None
    assert command.status == CommandStatus.DISPATCHED
    assert command.bulk_retry_child_id == child.id
    async with sessions() as session:
        claimed_child = await session.get(BulkRetryRequestChild, child.id)
        assert claimed_child is not None
        assert claimed_child.delivery_state == BulkRetryDeliveryState.DELIVERY_CLAIMED.value
        assert claimed_child.claimed_generation == generation
        assert claimed_child.claimed_agent_id == agent_id
        pending_managed = await session.scalar(
            select(func.count(Command.id)).where(
                Command.bulk_retry_child_id.is_not(None),
                Command.status == CommandStatus.PENDING,
            )
        )
        assert pending_managed == 0


@pytest.mark.asyncio
async def test_unknown_never_requeues_and_late_authenticated_result_refines_it(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="late-result",
            children=[_child(0)],
        )
        await session.commit()
        child = (
            await session.execute(
                select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
            )
        ).scalar_one()
    async with sessions() as session:
        command = await BulkRetryRequestRepository(session).claim_child(
            child_id=child.id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=60,
        )
        assert command is not None
        await session.commit()
        command_id = command.id

    async with sessions() as session:
        commands = CommandRepository(session)
        row = await session.get(Command, command_id)
        assert row is not None
        row.timeout_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.flush()
        await commands.sweep_timeouts(now=datetime.now(UTC))
        repository = BulkRetryRequestRepository(session)
        await repository.reconcile_command_outcomes()
        await session.commit()

    async with sessions() as session:
        child_after_timeout = await session.get(BulkRetryRequestChild, child.id)
        assert child_after_timeout is not None
        assert child_after_timeout.outcome == BulkRetryOutcome.UNKNOWN.value
        assert child_after_timeout.delivery_state == BulkRetryDeliveryState.DELIVERY_CLAIMED.value
        # No transition back to PENDING means no automatic replay authority.
        assert (
            await BulkRetryRequestRepository(session).claim_child(
                child_id=child.id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=60,
            )
            is None
        )
        await session.rollback()

    async with sessions() as session:
        commands = CommandRepository(session)
        assert await commands.mark_completed(
            command_id,
            result_payload={"retried": 1},
            project_id=project_id,
            agent_id=agent_id,
        )
        await BulkRetryRequestRepository(session).reconcile_command_outcomes()
        await session.commit()
    async with sessions() as session:
        refined = await session.get(BulkRetryRequestChild, child.id)
        assert refined is not None
        assert refined.outcome == BulkRetryOutcome.SUCCEEDED.value
        assert refined.delivery_state == BulkRetryDeliveryState.DELIVERY_CLAIMED.value


@pytest.mark.asyncio
async def test_late_result_reconciliation_targets_its_exact_command(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="competing-late-results",
            children=[_child(0), _child(1)],
            max_in_flight=2,
        )
        await session.commit()
        children = list(
            (
                await session.execute(
                    select(BulkRetryRequestChild)
                    .where(BulkRetryRequestChild.parent_id == parent.id)
                    .order_by(BulkRetryRequestChild.ordinal)
                )
            ).scalars()
        )

    command_ids: list[uuid.UUID] = []
    for child in children:
        async with sessions() as session:
            repository = BulkRetryRequestRepository(session)
            command = await repository.claim_child(
                child_id=child.id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=60,
            )
            assert command is not None
            command.timeout_at = datetime.now(UTC) - timedelta(seconds=1)
            command_ids.append(command.id)
            await session.commit()

    async with sessions() as session:
        commands = CommandRepository(session)
        assert await commands.mark_completed(
            command_ids[0],
            result_payload={"retried": 1},
            project_id=project_id,
            agent_id=agent_id,
        )
        await commands.sweep_timeouts(now=datetime.now(UTC))
        await session.commit()
    async with sessions() as session:
        commands = CommandRepository(session)
        assert await commands.mark_completed(
            command_ids[1],
            result_payload={"retried": 1},
            project_id=project_id,
            agent_id=agent_id,
        )
        assert (
            await BulkRetryRequestRepository(session).reconcile_command_outcomes(
                limit=1,
                command_id=command_ids[1],
            )
            == 1
        )
        await session.commit()

    async with sessions() as session:
        outcomes = list(
            (
                await session.execute(
                    select(BulkRetryRequestChild.outcome)
                    .where(BulkRetryRequestChild.parent_id == parent.id)
                    .order_by(BulkRetryRequestChild.ordinal)
                )
            ).scalars()
        )
    assert outcomes == [
        BulkRetryOutcome.UNOBSERVED.value,
        BulkRetryOutcome.SUCCEEDED.value,
    ]


@pytest.mark.asyncio
async def test_parent_in_flight_bound_applies_across_children(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="bounded",
            children=[_child(0), _child(1)],
            max_in_flight=1,
        )
        await session.commit()
        children = (
            (
                await session.execute(
                    select(BulkRetryRequestChild)
                    .where(BulkRetryRequestChild.parent_id == parent.id)
                    .order_by(BulkRetryRequestChild.ordinal)
                )
            )
            .scalars()
            .all()
        )

    async with sessions() as session:
        first = await BulkRetryRequestRepository(session).claim_child(
            child_id=children[0].id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=60,
        )
        await session.commit()
    async with sessions() as session:
        second = await BulkRetryRequestRepository(session).claim_child(
            child_id=children[1].id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=60,
        )
        await session.commit()
    assert first is not None
    assert second is None


@pytest.mark.asyncio
async def test_parent_deadline_blocks_pending_work_until_explicit_resume(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="expired-parent",
            children=[_child(0)],
        )
        parent.deadline_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    async with sessions() as session:
        repository = BulkRetryRequestRepository(session)
        assert await repository.block_expired_parents(now=datetime.now(UTC)) == 1
        await session.commit()
    async with sessions() as session:
        blocked = await session.get(BulkRetryRequestRow, parent.id)
        assert blocked is not None
        assert blocked.control_state == BulkRetryControlState.BLOCKED.value
        child_id = await session.scalar(
            select(BulkRetryRequestChild.id).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child_id is not None
        assert (
            await BulkRetryRequestRepository(session).claim_child(
                child_id=child_id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=3600,
            )
            is None
        )
        await session.rollback()

    async with sessions() as session:
        resumed = await BulkRetryRequestRepository(session).set_control_state(
            project_id=project_id,
            request_id=parent.id,
            control_state=BulkRetryControlState.RUNNING,
            resume_window_seconds=30,
        )
        await session.commit()
    assert resumed is not None
    async with sessions() as session:
        command = await BulkRetryRequestRepository(session).claim_child(
            child_id=child_id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=3600,
        )
        await session.commit()
    assert command is not None
    command_timeout = (
        command.timeout_at
        if command.timeout_at.tzinfo is not None
        else command.timeout_at.replace(tzinfo=UTC)
    )
    resumed_deadline = (
        resumed.deadline_at
        if resumed.deadline_at.tzinfo is not None
        else resumed.deadline_at.replace(tzinfo=UTC)
    )
    assert command_timeout <= resumed_deadline


@pytest.mark.asyncio
async def test_concurrent_sqlite_scanners_have_one_irreversible_claim_winner(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="concurrent-scanners",
            children=[_child(0)],
        )
        await session.commit()
        child_id = await session.scalar(
            select(BulkRetryRequestChild.id).where(BulkRetryRequestChild.parent_id == parent.id)
        )
    assert child_id is not None

    release_winner = asyncio.Event()

    async def _claim(generation: uuid.UUID) -> Command | None:
        async with sessions() as session:
            command = await BulkRetryRequestRepository(session).claim_child(
                child_id=child_id,
                agent_id=agent_id,
                generation=generation,
                command_timeout_seconds=60,
            )
            if command is not None:
                release_winner.set()
            else:
                await release_winner.wait()
            await session.commit()
            return command

    first_generation = uuid.uuid4()
    second_generation = uuid.uuid4()
    winners = await asyncio.gather(
        _claim(first_generation),
        _claim(second_generation),
    )
    commands = [command for command in winners if command is not None]
    assert len(commands) == 1
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(Command.bulk_retry_child_id == child_id)
            )
            == 1
        )


@pytest.mark.asyncio
async def test_coordinator_startup_scan_is_fair_bounded_and_generation_bound(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        first_parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="fair-first",
            children=[_child(0), _child(1), _child(2)],
            max_in_flight=3,
        )
        await session.commit()
        second_parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="fair-second",
            children=[_child(3), _child(4), _child(5)],
            max_in_flight=3,
        )
        await session.commit()

    generation = uuid.uuid4()
    handle = SessionHandle(
        agent_id=agent_id,
        worker_id="celery-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts=frozenset({("celery", 1)}),
        generation=generation,
    )
    registry = _FixedRegistry(handle)
    delivered: list[Command] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered.append(kwargs["command"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    settings = _settings().model_copy(
        update={
            "bulk_retry_scan_batch": 4,
            "bulk_retry_max_in_flight": 3,
        }
    )
    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=settings,
        registry=registry,  # type: ignore[arg-type]
    )
    await coordinator.tick()

    assert len(delivered) == 4
    assert all(command.status == CommandStatus.DISPATCHED for command in delivered)
    async with sessions() as session:
        parent_by_child = dict(
            (
                await session.execute(
                    select(
                        BulkRetryRequestChild.id,
                        BulkRetryRequestChild.parent_id,
                    )
                )
            ).all()
        )
        first_round_parents = {
            parent_by_child[delivered[0].bulk_retry_child_id],
            parent_by_child[delivered[1].bulk_retry_child_id],
        }
        assert first_round_parents == {first_parent.id, second_parent.id}
        claimed = (
            (
                await session.execute(
                    select(BulkRetryRequestChild).where(
                        BulkRetryRequestChild.delivery_state
                        == BulkRetryDeliveryState.DELIVERY_CLAIMED.value
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(claimed) == 4
        assert all(child.claimed_generation == generation for child in claimed)
        assert all(child.claimed_agent_id == agent_id for child in claimed)


@pytest.mark.asyncio
async def test_unavailable_oldest_parent_rotates_out_of_bounded_scan_window(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        unavailable = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="unavailable-oldest",
            children=[_child(0, "celery")],
        )
        await session.commit()
        reachable = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="reachable-newer",
            children=[_child(1, "rq")],
        )
        await session.commit()

    handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="rq-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts={"rq": 1},
    )
    delivered: list[Command] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered.append(kwargs["command"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings().model_copy(update={"bulk_retry_scan_batch": 1}),
        registry=_FixedRegistry(handle),  # type: ignore[arg-type]
    )
    await coordinator.tick()
    assert delivered == []
    await coordinator.tick()
    assert len(delivered) == 1

    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(
                BulkRetryRequestChild.id == delivered[0].bulk_retry_child_id
            )
        )
        assert child is not None
        assert child.parent_id == reachable.id
        assert child.parent_id != unavailable.id


@pytest.mark.asyncio
async def test_compatible_engine_is_not_hidden_behind_ordinal_prefix(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="mixed-engine-prefix",
            children=[
                *[_child(ordinal, "celery") for ordinal in range(40)],
                _child(40, "rq"),
            ],
        )
        await session.commit()

    handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="rq-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts={"rq": 1},
    )
    delivered: list[Command] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered.append(kwargs["command"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    await BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings().model_copy(update={"bulk_retry_scan_batch": 1}),
        registry=_FixedRegistry(handle),  # type: ignore[arg-type]
    ).tick()

    assert len(delivered) == 1
    assert delivered[0].payload["filter"]["engine"] == "rq"
    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(
                BulkRetryRequestChild.id == delivered[0].bulk_retry_child_id
            )
        )
        assert child is not None
        assert child.parent_id == parent.id
        assert child.ordinal == 40


@pytest.mark.asyncio
async def test_coordinator_respects_pause_contract_and_explicit_resume(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="paused",
            children=[_child(0)],
        )
        await BulkRetryRequestRepository(session).set_control_state(
            project_id=project_id,
            request_id=parent.id,
            control_state=BulkRetryControlState.PAUSED,
        )
        await session.commit()

    handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="celery-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts={"celery": 1},
    )
    delivered: list[Command] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered.append(kwargs["command"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings(),
        registry=_FixedRegistry(handle),  # type: ignore[arg-type]
    )
    await coordinator.tick()
    assert delivered == []

    async with sessions() as session:
        resumed = await BulkRetryRequestRepository(session).set_control_state(
            project_id=project_id,
            request_id=parent.id,
            control_state=BulkRetryControlState.RUNNING,
            resume_window_seconds=60,
        )
        await session.commit()
    assert resumed is not None
    await coordinator.tick()
    assert len(delivered) == 1


@pytest.mark.asyncio
async def test_send_failure_never_requeues_or_retargets_claimed_child(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="ambiguous-send",
            children=[_child(0)],
        )
        await session.commit()

    handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="celery-worker",
        websocket=object(),  # type: ignore[arg-type]
        retry_contracts={"celery": 1},
    )
    attempts = 0

    async def _ambiguous_send(**_kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("socket closed during write")

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _ambiguous_send,
    )
    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings(),
        registry=_FixedRegistry(handle),  # type: ignore[arg-type]
    )
    await coordinator.tick()
    await coordinator.tick()
    assert attempts == 1

    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child is not None
        assert child.delivery_state == BulkRetryDeliveryState.DELIVERY_CLAIMED.value
        assert child.outcome == BulkRetryOutcome.UNOBSERVED.value
        assert (
            await BulkRetryRequestRepository(session).expire_claims(
                now=datetime.now(UTC) + timedelta(days=1)
            )
            == 1
        )
        await session.commit()
    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child is not None
        assert child.outcome == BulkRetryOutcome.UNKNOWN.value
        assert child.delivery_state == BulkRetryDeliveryState.DELIVERY_CLAIMED.value


@pytest.mark.asyncio
async def test_coordinator_retains_selected_session_generation_across_send(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="generation-replacement",
            children=[_child(0)],
        )
        await session.commit()

    old_websocket = object()
    new_websocket = object()
    old_handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="celery-worker",
        websocket=old_websocket,  # type: ignore[arg-type]
        retry_contracts={"celery": 1},
    )
    new_handle = SessionHandle.create(
        agent_id=agent_id,
        worker_id="celery-worker",
        websocket=new_websocket,  # type: ignore[arg-type]
        retry_contracts={"celery": 1},
    )

    class _ReplacingRegistry(_FixedRegistry):
        async def select_project_session(
            self,
            *,
            project_id: uuid.UUID,
            required_retry_engine: str,
        ) -> SessionHandle | None:
            selected = await super().select_project_session(
                project_id=project_id,
                required_retry_engine=required_retry_engine,
            )
            self.handle = new_handle
            return selected

    delivered_websockets: list[object] = []

    async def _capture_delivery(**kwargs: Any) -> None:
        delivered_websockets.append(kwargs["websocket"])

    monkeypatch.setattr(
        "z4j_brain.websocket.gateway.deliver_command_frame",
        _capture_delivery,
    )
    await BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings(),
        registry=_ReplacingRegistry(old_handle),  # type: ignore[arg-type]
    ).tick()
    assert delivered_websockets == [old_websocket]
    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child is not None
        assert child.claimed_generation == old_handle.generation
        assert child.claimed_generation != new_handle.generation


@pytest.mark.asyncio
async def test_longpoll_claim_uses_request_generation_and_contract(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
) -> None:
    sessions, project_id, user_id, agent_id = boundary_db
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="longpoll-generation",
            children=[_child(0, "rq")],
        )
        await session.commit()

    coordinator = BulkRetryCoordinator(
        db=_SessionDb(sessions),  # type: ignore[arg-type]
        settings=_settings(),
        registry=_FixedRegistry(None),  # type: ignore[arg-type]
    )
    generation = uuid.uuid4()
    assert (
        await coordinator.claim_for_longpoll(
            project_id=project_id,
            agent_id=agent_id,
            retry_contracts={"celery": 1},
            generation=generation,
            maximum=1,
        )
        == []
    )
    claimed = await coordinator.claim_for_longpoll(
        project_id=project_id,
        agent_id=agent_id,
        retry_contracts={"rq": 1},
        generation=generation,
        maximum=1,
    )
    assert len(claimed) == 1
    assert claimed[0].status == CommandStatus.DISPATCHED
    async with sessions() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == parent.id)
        )
        assert child is not None
        assert child.claimed_generation == generation
        assert child.claimed_agent_id == agent_id


@pytest.mark.asyncio
async def test_new_resource_exact_replay_never_reexpands_live_tasks(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Behavioral API proof: no-match stays no-match after a task appears."""

    sessions, project_id, user_id, _agent_id = boundary_db

    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()
    audit = AuditService(settings)
    body = BulkRetryRequestCreate(
        idempotency_key="api-no-match",
        filter={"state": "failure"},
        max=100,
    )

    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        first_response = Response()
        first = await create_bulk_retry_request(
            slug="boundary-b",
            body=body,
            response=first_response,
            user=user,
            memberships=object(),
            projects=project,
            audit_log=AuditLogRepository(session),
            audit_service=audit,
            db_session=session,
            settings=settings,
            ip="127.0.0.1",
        )
    assert first.status == "no_match"
    assert first_response.headers["Location"].endswith(str(first.id))

    async with sessions() as session:
        session.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="appeared-later",
                name="tasks.work",
                state=TaskState.FAILURE,
            )
        )
        await session.commit()

    def _current_validator_must_not_run(_body: BulkRetryRequestCreate) -> None:
        raise AssertionError("exact replay used current-version validation")

    monkeypatch.setattr(
        BulkRetryRequestCreate,
        "validate_selection",
        _current_validator_must_not_run,
    )
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        replay_response = Response()
        replay = await create_bulk_retry_request(
            slug="boundary-b",
            body=body,
            response=replay_response,
            user=user,
            memberships=object(),
            projects=project,
            audit_log=AuditLogRepository(session),
            audit_service=audit,
            db_session=session,
            settings=settings,
            ip="127.0.0.1",
        )
        reservation = await CommandRepository(session).get_by_idempotency_key(
            project_id=project_id,
            idempotency_key="api-no-match",
        )
    assert replay.id == first.id
    assert replay.status == "no_match"
    assert replay.counts.total == 0
    assert replay_response.headers["Location"] == first_response.headers["Location"]
    assert reservation is not None
    assert reservation.action == "bulk_retry_request.reservation"
    assert reservation.status == CommandStatus.COMPLETED

    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        with pytest.raises(HTTPException) as conflict:
            await create_bulk_retry_request(
                slug="boundary-b",
                body=BulkRetryRequestCreate(
                    idempotency_key="api-no-match",
                    filter={"state": "revoked"},
                    max=100,
                ),
                response=Response(),
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=audit,
                db_session=session,
                settings=settings,
                ip="127.0.0.1",
            )
    assert conflict.value.status_code == 409


@pytest.mark.asyncio
async def test_new_resource_seals_only_owned_filtered_tasks_per_engine(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expansion is project-scoped, filter-scoped, and per-task sealed."""

    sessions, project_id, user_id, _agent_id = boundary_db
    other_project_id = uuid.uuid4()
    async with sessions() as session:
        session.add(Project(id=other_project_id, slug="other", name="Other"))
        session.add_all(
            [
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="celery-wanted",
                    name="app.wanted",
                    queue="cap",
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="rq",
                    task_id="rq-wanted",
                    name="app.wanted",
                    queue="cap",
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="rq",
                    task_id="rq-wanted-2",
                    name="app.wanted",
                    queue="other",
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="celery-other-name",
                    name="app.other",
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="celery-success",
                    name="app.wanted",
                    state=TaskState.SUCCESS,
                ),
                Task(
                    project_id=other_project_id,
                    engine="rq",
                    task_id="foreign-wanted",
                    name="app.wanted",
                    state=TaskState.FAILURE,
                ),
            ]
        )
        await session.commit()

    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        created = await create_bulk_retry_request(
            slug=project.slug,
            body=BulkRetryRequestCreate(
                idempotency_key="owned-filtered",
                filter={"state": "failure", "name": "wanted"},
                max=100,
            ),
            response=Response(),
            user=user,
            memberships=object(),
            projects=project,
            audit_log=AuditLogRepository(session),
            audit_service=AuditService(settings),
            db_session=session,
            settings=settings,
            ip="127.0.0.1",
        )

    assert created.counts.total == 3
    async with sessions() as session:
        children = (
            (
                await session.execute(
                    select(BulkRetryRequestChild)
                    .where(BulkRetryRequestChild.parent_id == created.id)
                    .order_by(BulkRetryRequestChild.ordinal)
                )
            )
            .scalars()
            .all()
        )
        sealed_targets = {
            (child.engine, child.payload["filter"]["task_ids"][0]) for child in children
        }
        assert sealed_targets == {
            ("celery", "celery-wanted"),
            ("rq", "rq-wanted"),
            ("rq", "rq-wanted-2"),
        }
        assert all(child.payload["max"] == 1 for child in children)
        assert all(
            child.payload["filter"]["task_names"]
            == {child.payload["filter"]["task_ids"][0]: "app.wanted"}
            for child in children
        )
        audit_actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.project_id == project_id,
                    )
                )
            )
            .scalars()
            .all()
        )
        assert audit_actions == ["bulk_retry_request.sealed"]

    # The cap is applied after the engine predicate in SQL. Celery rows cannot
    # consume an RQ-scoped request's only slot.
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        rq_only = await create_bulk_retry_request(
            slug=project.slug,
            body=BulkRetryRequestCreate(
                idempotency_key="rq-cap",
                filter={
                    "state": "failure",
                    "engine": "rq",
                    "queue": "cap",
                },
                max=1,
            ),
            response=Response(),
            user=user,
            memberships=object(),
            projects=project,
            audit_log=AuditLogRepository(session),
            audit_service=AuditService(settings),
            db_session=session,
            settings=settings,
            ip="127.0.0.1",
        )
    async with sessions() as session:
        rq_child = await session.scalar(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.parent_id == rq_only.id)
        )
        assert rq_only.counts.total == 1
        assert rq_child is not None
        assert rq_child.engine == "rq"


@pytest.mark.asyncio
async def test_new_resource_seals_exact_priority_and_search_scope(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The durable plan must match every active dashboard selection filter."""

    sessions, project_id, user_id, _agent_id = boundary_db
    async with sessions() as session:
        session.add_all(
            [
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="critical-needle",
                    name="app.worker",
                    queue="needle-queue",
                    priority=TaskPriority.CRITICAL,
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="low-needle",
                    name="app.worker",
                    queue="needle-queue",
                    priority=TaskPriority.LOW,
                    state=TaskState.FAILURE,
                ),
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="critical-other",
                    name="app.worker",
                    queue="other-queue",
                    priority=TaskPriority.CRITICAL,
                    state=TaskState.FAILURE,
                ),
            ]
        )
        await session.commit()

    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        created = await create_bulk_retry_request(
            slug=project.slug,
            body=BulkRetryRequestCreate(
                idempotency_key="priority-search-scope",
                filter={
                    "state": "failure",
                    "priority": ["critical"],
                    "search": "needle",
                },
                max=100,
            ),
            response=Response(),
            user=user,
            memberships=object(),
            projects=project,
            audit_log=AuditLogRepository(session),
            audit_service=AuditService(settings),
            db_session=session,
            settings=settings,
            ip="127.0.0.1",
        )

    assert created.canonicalizer_version == 2
    assert created.counts.total == 1
    async with sessions() as session:
        parent = await session.get(BulkRetryRequestRow, created.id)
        child = await session.scalar(
            select(BulkRetryRequestChild).where(
                BulkRetryRequestChild.parent_id == created.id,
            )
        )
        assert parent is not None
        assert parent.effective_request["filter"]["priority"] == ["critical"]
        assert parent.effective_request["filter"]["search"] == "needle"
        assert child is not None
        assert child.payload["filter"]["task_ids"] == ["critical-needle"]
        assert child.payload["filter"]["task_priorities"] == {"critical-needle": "critical"}


@pytest.mark.asyncio
async def test_new_resource_refuses_instead_of_truncating_all_matching_scope(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, project_id, user_id, _agent_id = boundary_db
    async with sessions() as session:
        session.add_all(
            [
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id=f"matching-{index}",
                    name="app.worker",
                    priority=TaskPriority.CRITICAL,
                    state=TaskState.FAILURE,
                )
                for index in range(2)
            ]
        )
        await session.commit()

    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()
    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        with pytest.raises(HTTPException) as exc_info:
            await create_bulk_retry_request(
                slug=project.slug,
                body=BulkRetryRequestCreate(
                    idempotency_key="over-limit-visible-scope",
                    filter={
                        "state": "failure",
                        "priority": ["critical"],
                    },
                    max=1,
                ),
                response=Response(),
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=AuditService(settings),
                db_session=session,
                settings=settings,
                ip="127.0.0.1",
            )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == {
        "error": "matching task count exceeds max",
        "max": 1,
        "matched_at_least": 2,
    }
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequestRow.id)).where(
                    BulkRetryRequestRow.idempotency_key == "over-limit-visible-scope",
                )
            )
            == 0
        )
        refusal = await session.scalar(
            select(AuditLog).where(
                AuditLog.action == "bulk_retry_request.refused",
                AuditLog.project_id == project_id,
            )
        )
        assert refusal is not None
        assert refusal.audit_metadata["reason"] == str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_refused_filter_and_partial_explicit_resolution_are_audited(
    boundary_db: tuple[
        async_sessionmaker[AsyncSession],
        uuid.UUID,
        uuid.UUID,
        uuid.UUID,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confused-deputy keys and unowned ids fail closed with durable audits."""

    sessions, project_id, user_id, _agent_id = boundary_db
    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    settings = _settings()

    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        with pytest.raises(HTTPException) as smuggled:
            await create_bulk_retry_request(
                slug=project.slug,
                body=BulkRetryRequestCreate(
                    idempotency_key="smuggled-key",
                    filter={"task_names": {"x": "os.system"}},
                ),
                response=Response(),
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=AuditService(settings),
                db_session=session,
                settings=settings,
                ip="127.0.0.1",
            )
    assert smuggled.value.status_code == 400

    async with sessions() as session:
        project = await session.get(Project, project_id)
        user = await session.get(User, user_id)
        assert project is not None and user is not None
        with pytest.raises(HTTPException) as missing:
            await create_bulk_retry_request(
                slug=project.slug,
                body=BulkRetryRequestCreate(
                    idempotency_key="missing-id",
                    filter={
                        "engine": "rq",
                        "task_ids": ["not-owned"],
                    },
                ),
                response=Response(),
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=AuditService(settings),
                db_session=session,
                settings=settings,
                ip="127.0.0.1",
            )
    assert missing.value.status_code == 400

    async with sessions() as session:
        refusals = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == "bulk_retry_request.refused")
                    .order_by(AuditLog.occurred_at)
                )
            )
            .scalars()
            .all()
        )
        assert len(refusals) == 2
        assert refusals[0].outcome == "deny"
        assert refusals[0].audit_metadata["rejected_client_supplied_filter_keys"] == ["task_names"]
        assert refusals[1].audit_metadata["missing_task_ids"] == ["not-owned"]
        assert await session.scalar(select(func.count(BulkRetryRequestRow.id))) == 0
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(
                    Command.idempotency_key.in_(["smuggled-key", "missing-id"])
                )
            )
            == 0
        )


@pytest.mark.parametrize(
    "bad_filter",
    [
        {"task_ids": []},
        {"queue": 123},
        {"name": {}},
        {"engine": 7},
        {"since": "not-a-date"},
        {"until": ["x"]},
        {"search": 7},
        {"search": "x" * 201},
        {"priority": []},
        {"priority": "critical"},
        {"priority": ["urgent"]},
        {
            "engine": "celery",
            "task_ids": ["task-1"],
            "priority": ["critical"],
        },
        {"state": "sucess"},
        {"state": False},
        {"status": 0},
        {"engine": "celrey"},
    ],
)
def test_selection_validation_never_silently_widens(
    bad_filter: dict[str, Any],
) -> None:
    body = BulkRetryRequestCreate(
        idempotency_key="invalid-selection",
        filter=bad_filter,
    )
    with pytest.raises(ValueError):
        body.validate_selection()


@pytest.mark.asyncio
async def test_legacy_endpoint_fences_all_matching_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The old command-shaped endpoint cannot create a durable parent."""

    project = SimpleNamespace(id=uuid.uuid4())

    class _Policy:
        async def get_project_or_404(self, _projects: object, _slug: str) -> object:
            return project

        async def require_member(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            return None

    class _Session:
        async def commit(self) -> None:
            return None

    monkeypatch.setattr("z4j_brain.domain.policy_engine.PolicyEngine", _Policy)

    async def _must_not_resolve(**_kwargs: Any) -> object:
        raise AssertionError("legacy endpoint reached all-matching expansion")

    monkeypatch.setattr(
        commands_mod,
        "_resolve_and_issue_all_matching_bulk_retry",
        _must_not_resolve,
    )

    with pytest.raises(HTTPException) as exc:
        await issue_bulk_retry(
            slug="project",
            body=BulkRetryRequest(
                agent_id=uuid.uuid4(),
                filter={"state": "failure"},
                max=100,
                idempotency_key="legacy",
            ),
            user=SimpleNamespace(id=uuid.uuid4()),
            memberships=object(),
            projects=object(),
            audit_log=object(),
            audit_service=object(),
            dispatcher=object(),
            db_session=_Session(),  # type: ignore[arg-type]
            ip="127.0.0.1",
        )

    assert exc.value.status_code == 410
    assert "bulk-retry-requests" in str(exc.value.detail)
