"""Production invariants for event ingestion and task projection."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskPriority, TaskState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    ScheduleRepository,
    TaskRepository,
)
from z4j_brain.persistence.repositories.tasks import _event_projection_guard
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_core.redaction import REDACTED, RedactionConfig, RedactionEngine
from z4j_core.transport.frames import EventBatchAckFrame, EventBatchFrame, EventBatchPayload


@pytest.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as db_session:
        yield db_session
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    row = Project(slug="production-contracts", name="Production contracts")
    session.add(row)
    await session.commit()
    return row


@pytest.fixture
async def agent(session: AsyncSession, project: Project) -> Agent:
    row = Agent(
        project_id=project.id,
        name="event-contract-agent",
        token_hash=secrets.token_hex(32),
        protocol_version="1",
        framework_adapter="bare",
        engine_adapters=["celery", "rq"],
        scheduler_adapters=["celery-beat"],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(row)
    await session.commit()
    return row


@pytest.fixture
def ingestor() -> EventIngestor:
    return EventIngestor(RedactionEngine(RedactionConfig()))


def _repos(
    session: AsyncSession,
    project: Project,
    agent: Agent,
) -> dict[str, Any]:
    return {
        "project_id": project.id,
        "agent_id": agent.id,
        "agents": AgentRepository(session),
        "event_repo": EventRepository(session),
        "task_repo": TaskRepository(session),
        "queue_repo": QueueRepository(session),
    }


def _task_event(
    *,
    engine: str,
    kind: str,
    task_id: str,
    occurred_at: datetime,
    data: dict[str, Any],
) -> dict[str, Any]:
    return {
        "engine": engine,
        "kind": kind,
        "task_id": task_id,
        "occurred_at": occurred_at.isoformat(),
        "data": data,
    }


@pytest.mark.asyncio
async def test_new_event_hooks_receive_only_the_scrubbed_copy(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    secret = "Bearer secret-material-that-must-not-egress"
    raw_event = _task_event(
        engine="celery",
        kind="task.failed",
        task_id="secret-task",
        occurred_at=datetime.now(UTC) - timedelta(seconds=2),
        data={
            "task_name": "jobs.secret",
            "exception": secret,
            "traceback": f"failure carried {secret}",
            "password": "raw-password",
        },
    )

    result = await ingestor.ingest_batch(events=[raw_event], **_repos(session, project, agent))
    await session.commit()

    # The caller's object is untouched, but it is never returned to the
    # notification/automation hooks.
    assert raw_event["data"]["exception"] == secret
    assert raw_event["data"]["password"] == "raw-password"
    assert len(result.new_events) == 1
    safe_event = result.new_events[0]
    assert safe_event is not raw_event
    assert safe_event["data"]["exception"] == REDACTED
    assert safe_event["data"]["traceback"] == REDACTED
    assert safe_event["data"]["password"] == REDACTED
    assert secret not in repr(result.new_events)
    assert "raw-password" not in repr(result.new_events)

    stored_event = (await session.execute(select(Event))).scalar_one()
    stored_task = (await session.execute(select(Task))).scalar_one()
    assert secret not in repr(stored_event.payload)
    assert stored_task.exception == REDACTED
    assert stored_task.traceback == REDACTED


@pytest.mark.asyncio
async def test_task_event_dedupe_identity_includes_engine(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    occurred_at = datetime.now(UTC) - timedelta(seconds=2)
    events = [
        _task_event(
            engine=engine,
            kind="task.failed",
            task_id="shared-native-id",
            occurred_at=occurred_at,
            data={"task_name": f"jobs.{engine}", "exception": engine},
        )
        for engine in ("celery", "rq")
    ]

    result = await ingestor.ingest_batch(events=events, **_repos(session, project, agent))
    await session.commit()

    assert len(result.new_events) == 2
    assert (await session.scalar(select(func.count()).select_from(Event))) == 2
    task_rows = (await session.execute(select(Task.engine, Task.name).order_by(Task.engine))).all()
    assert task_rows == [("celery", "jobs.celery"), ("rq", "jobs.rq")]


@pytest.mark.asyncio
async def test_stale_terminal_event_cannot_overwrite_terminal_details(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    fresh_at = datetime.now(UTC) - timedelta(seconds=2)
    stale_at = fresh_at - timedelta(seconds=5)
    fresh = _task_event(
        engine="celery",
        kind="task.failed",
        task_id="terminal-detail-task",
        occurred_at=fresh_at,
        data={
            "task_name": "jobs.fail",
            "exception": "FreshError",
            "traceback": "fresh traceback",
        },
    )
    stale = _task_event(
        engine="celery",
        kind="task.failed",
        task_id="terminal-detail-task",
        occurred_at=stale_at,
        data={
            "task_name": "jobs.fail",
            "exception": "StaleError",
            "traceback": "stale traceback",
        },
    )

    fresh_result = await ingestor.ingest_batch(
        events=[fresh],
        **_repos(session, project, agent),
    )
    await session.commit()
    stale_result = await ingestor.ingest_batch(
        events=[stale],
        **_repos(session, project, agent),
    )
    await session.commit()

    row = (await session.execute(select(Task))).scalar_one()
    assert row.state == TaskState.FAILURE
    assert row.exception == "FreshError"
    assert row.traceback == "fresh traceback"
    expected_finished = fresh_at if row.finished_at.tzinfo else fresh_at.replace(tzinfo=None)
    assert row.finished_at == expected_finished
    assert fresh_result.inserted_count == 1
    assert len(fresh_result.new_events) == 1
    # The stale raw event remains durable for audit/forensics, but it is not
    # actionable truth and therefore cannot page or run automation.
    assert stale_result.inserted_count == 1
    assert stale_result.new_events == []
    assert (await session.scalar(select(func.count()).select_from(Event))) == 2

    replay_result = await ingestor.ingest_batch(
        events=[stale],
        **_repos(session, project, agent),
    )
    await session.commit()
    assert replay_result.inserted_count == 0
    assert replay_result.new_events == []


@pytest.mark.asyncio
async def test_stale_terminal_audit_row_is_acked_but_never_reaches_hooks(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    fresh_at = datetime.now(UTC) - timedelta(seconds=2)
    stale_at = fresh_at - timedelta(seconds=5)
    fresh_success = _task_event(
        engine="celery",
        kind="task.succeeded",
        task_id="stale-hook-task",
        occurred_at=fresh_at,
        data={"task_name": "jobs.hook", "result": "fresh-result"},
    )
    await ingestor.ingest_batch(
        events=[fresh_success],
        **_repos(session, project, agent),
    )
    await session.commit()

    stale_failure = _task_event(
        engine="celery",
        kind="task.failed",
        task_id="stale-hook-task",
        occurred_at=stale_at,
        data={
            "task_name": "jobs.hook",
            "exception": "StaleFailure",
            "traceback": "stale traceback",
        },
    )
    assert session.bind is not None
    factory = sessionmaker(session.bind, class_=AsyncSession, expire_on_commit=False)

    class _DB:
        @contextlib.asynccontextmanager
        async def session(self, *, write: bool = False):
            del write
            async with factory() as db_session:
                yield db_session

    sent: list[Any] = []
    notified: list[list[dict[str, Any]]] = []
    automated: list[list[dict[str, Any]]] = []

    async def _send(frame: Any) -> None:
        sent.append(frame)

    async def _capture_notifications(events: list[dict[str, Any]]) -> None:
        notified.append(events)

    async def _capture_automation(events: list[dict[str, Any]]) -> None:
        automated.append(events)

    router = FrameRouter(
        db=_DB(),  # type: ignore[arg-type]
        ingestor=ingestor,
        dispatcher=object(),  # type: ignore[arg-type]
        project_id=project.id,
        agent_id=agent.id,
        send_frame=_send,
    )
    router._evaluate_notifications = _capture_notifications  # type: ignore[method-assign]
    router._evaluate_automation = _capture_automation  # type: ignore[method-assign]

    outcome = await router.dispatch(
        EventBatchFrame(
            id="stale-hook-frame",
            payload=EventBatchPayload(events=[stale_failure]),
        ),
    )
    for _ in range(3):
        await asyncio.sleep(0)

    assert outcome is FrameOutcome.DURABLE
    assert notified == [[]]
    assert automated == [[]]
    assert len(sent) == 1
    assert isinstance(sent[0], EventBatchAckFrame)
    assert sent[0].payload.accepted == 1
    assert sent[0].payload.rejected == 0

    session.expire_all()
    row = (await session.execute(select(Task))).scalar_one()
    assert row.state == TaskState.SUCCESS
    assert row.result == "fresh-result"
    assert row.exception is None
    assert (await session.scalar(select(func.count()).select_from(Event))) == 2


@pytest.mark.asyncio
async def test_future_skew_cannot_create_irreversible_terminal_watermark(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    repo_kwargs = _repos(session, project, agent)
    before_attack = datetime.now(UTC)
    future_source_at = before_attack + timedelta(seconds=55)
    attacker = _task_event(
        engine="celery",
        kind="task.succeeded",
        task_id="future-watermark-task",
        occurred_at=future_source_at,
        data={"task_name": "jobs.future", "result": "attacker"},
    )

    first = await ingestor.ingest_batch(
        events=[attacker],
        **repo_kwargs,
    )
    after_attack = datetime.now(UTC)
    await session.commit()
    session.expire_all()
    attack_row = (await session.execute(select(Task))).scalar_one()
    attack_finished_at = attack_row.finished_at

    # A real later observation uses its actual source time -- it is not made
    # artificially future-dated to satisfy the guard.
    legitimate = _task_event(
        engine="celery",
        kind="task.failed",
        task_id="future-watermark-task",
        occurred_at=datetime.now(UTC),
        data={
            "task_name": "jobs.future",
            "exception": "LegitimateFailure",
            "traceback": "legitimate traceback",
        },
    )
    recovery = await ingestor.ingest_batch(
        events=[legitimate],
        **repo_kwargs,
    )
    await session.commit()
    session.expire_all()

    row = (await session.execute(select(Task))).scalar_one()
    assert row.state == TaskState.FAILURE
    assert row.exception == "LegitimateFailure"
    assert row.result is None
    assert first.inserted_count == 1
    assert recovery.inserted_count == 1
    assert len(recovery.new_events) == 1

    # The admitted future source timestamp remains stable in the raw event's
    # dedupe identity, while task lifecycle watermarks use processing authority.
    success_row = (
        await session.execute(
            select(Event).where(Event.kind == "task.succeeded"),
        )
    ).scalar_one()
    expected_source = future_source_at.replace(microsecond=0)
    expected_source = (
        expected_source if success_row.occurred_at.tzinfo else expected_source.replace(tzinfo=None)
    )
    assert success_row.occurred_at == expected_source
    assert attack_finished_at is not None
    normalized_attack_finish = (
        attack_finished_at if attack_finished_at.tzinfo else attack_finished_at.replace(tzinfo=UTC)
    )
    assert before_attack <= normalized_attack_finish <= after_attack
    assert after_attack < future_source_at

    # Replaying either source event cannot re-fire hooks or re-poison the row.
    attack_replay = await ingestor.ingest_batch(
        events=[attacker],
        **repo_kwargs,
    )
    recovery_replay = await ingestor.ingest_batch(
        events=[legitimate],
        **repo_kwargs,
    )
    await session.commit()
    session.expire_all()
    replayed_row = (await session.execute(select(Task))).scalar_one()
    assert attack_replay.inserted_count == 0
    assert attack_replay.new_events == []
    assert recovery_replay.inserted_count == 0
    assert recovery_replay.new_events == []
    assert replayed_row.state == TaskState.FAILURE
    assert replayed_row.exception == "LegitimateFailure"


@pytest.mark.asyncio
async def test_terminal_transition_detail_matrix_is_atomic(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    repo_kwargs = _repos(session, project, agent)
    base = datetime.now(UTC) - timedelta(minutes=1)

    def event(
        task_id: str,
        kind: str,
        offset: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        return _task_event(
            engine="celery",
            kind=kind,
            task_id=task_id,
            occurred_at=base + timedelta(seconds=offset),
            data={"task_name": f"jobs.{task_id}", **data},
        )

    failure_then_success = [
        event(
            "recover",
            "task.failed",
            1,
            {"exception": "OldFailure", "traceback": "old traceback"},
        ),
        event(
            "recover",
            "task.succeeded",
            2,
            {"result": "recovered", "runtime_ms": 2000},
        ),
    ]
    success_then_failure = [
        event(
            "regress",
            "task.succeeded",
            1,
            {"result": "obsolete", "runtime_ms": 1000},
        ),
        event(
            "regress",
            "task.failed",
            2,
            {"exception": "NewFailure", "traceback": "new traceback"},
        ),
    ]
    failure_success_revoke = [
        event(
            "revoked",
            "task.failed",
            1,
            {"exception": "HistoricalFailure", "traceback": "historical traceback"},
        ),
        event(
            "revoked",
            "task.succeeded",
            2,
            {"result": "obsolete", "runtime_ms": 3000},
        ),
        event("revoked", "task.revoked", 3, {}),
    ]
    accepted = await ingestor.ingest_batch(
        events=[
            *failure_then_success,
            *success_then_failure,
            *failure_success_revoke,
        ],
        **repo_kwargs,
    )
    await session.commit()
    session.expire_all()

    rows = {row.task_id: row for row in (await session.execute(select(Task))).scalars().all()}
    recovered = rows["recover"]
    recovered_fingerprint = recovered.fingerprint
    recovered_last_failed_at = recovered.last_failed_at
    assert recovered.state == TaskState.SUCCESS
    assert recovered.result == "recovered"
    assert recovered.runtime_ms == 2000
    assert recovered.exception is None
    assert recovered.traceback is None
    assert recovered_fingerprint is not None
    assert recovered_last_failed_at is not None

    failed = rows["regress"]
    assert failed.state == TaskState.FAILURE
    assert failed.result is None
    assert failed.runtime_ms is None
    assert failed.exception == "NewFailure"
    assert failed.traceback == "new traceback"

    revoked = rows["revoked"]
    assert revoked.state == TaskState.REVOKED
    assert revoked.result is None
    assert revoked.runtime_ms is None
    assert revoked.exception is None
    assert revoked.traceback is None
    assert revoked.fingerprint is not None
    assert revoked.last_failed_at is not None
    assert accepted.inserted_count == 7
    assert len(accepted.new_events) == 7

    # A rejected stale failure performs no partial field clearing or historical
    # mutation, even though its raw audit row is independently durable.
    stale = event(
        "recover",
        "task.failed",
        0,
        {"exception": "StaleFailure", "traceback": "stale traceback"},
    )
    rejected = await ingestor.ingest_batch(
        events=[stale],
        **repo_kwargs,
    )
    await session.commit()
    session.expire_all()
    unchanged = (await session.execute(select(Task).where(Task.task_id == "recover"))).scalar_one()
    assert rejected.inserted_count == 1
    assert rejected.new_events == []
    assert unchanged.state == TaskState.SUCCESS
    assert unchanged.result == "recovered"
    assert unchanged.runtime_ms == 2000
    assert unchanged.exception is None
    assert unchanged.traceback is None
    assert unchanged.fingerprint == recovered_fingerprint
    assert unchanged.last_failed_at == recovered_last_failed_at


@pytest.mark.asyncio
@pytest.mark.parametrize("projection", ["snapshot", "upsert"])
async def test_legacy_schedule_projection_db_failure_withholds_ack(
    projection: str,
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fail(*_args: Any, **_kwargs: Any) -> None:
        raise OperationalError(
            "legacy schedule projection",
            {},
            RuntimeError("simulated transient database outage"),
        )

    schedule = {
        "name": "nightly",
        "task_name": "jobs.nightly",
        "kind": "interval",
        "expression": "5m",
        "engine": "celery",
        "scheduler": "celery-beat",
        "is_enabled": True,
        "args": [],
        "kwargs": {},
    }
    if projection == "snapshot":
        monkeypatch.setattr(ScheduleRepository, "reconcile_snapshot", _fail)
        kind = "schedule.snapshot"
        data = {"scheduler": "celery-beat", "schedules": [schedule]}
    else:
        monkeypatch.setattr(ScheduleRepository, "upsert_from_event", _fail)
        kind = "schedule.created"
        data = {"schedule": schedule}
    event = _task_event(
        engine="celery-beat",
        kind=kind,
        task_id="",
        occurred_at=datetime.now(UTC) - timedelta(seconds=2),
        data=data,
    )

    result = await ingestor.ingest_batch(events=[event], **_repos(session, project, agent))
    await session.commit()

    assert result.fully_durable is False
    assert result.transient_skips == 1
    assert result.new_events == []
    assert (await session.scalar(select(func.count()).select_from(Event))) == 0


def test_event_projection_guard_compiles_for_supported_dialects() -> None:
    now = datetime.now(UTC)
    statement = select(Task.id).where(
        _event_projection_guard(
            incoming_state=TaskState.FAILURE,
            occurred_at=now,
            guard_now=now,
        ),
    )
    for dialect in (sqlite.dialect(), postgresql.dialect()):
        compiled = str(statement.compile(dialect=dialect))
        assert "tasks.state" in compiled
        assert "tasks.updated_at" in compiled
        assert "CASE WHEN" in compiled


@pytest.mark.asyncio
async def test_concurrent_terminal_writers_converge_on_newest_details(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "task-projection-race.sqlite3"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        connect_args={"timeout": 15},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    start_at = datetime.now(UTC) - timedelta(minutes=1)
    fresh_at = start_at + timedelta(seconds=20)
    stale_at = start_at + timedelta(seconds=10)
    async with factory() as seed_session:
        project = Project(slug="projection-race", name="Projection race")
        seed_session.add(project)
        await seed_session.flush()
        project_id = project.id
        seed_session.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="race-task",
                name="jobs.race",
                state=TaskState.STARTED,
                started_at=start_at,
            ),
        )
        await seed_session.commit()

    ready = (asyncio.Event(), asyncio.Event())
    release = asyncio.Event()

    async def _writer(
        index: int,
        *,
        occurred_at: datetime,
        exception: str,
        fingerprint: str,
    ) -> bool:
        async with factory() as writer_session:
            ready[index].set()
            await release.wait()
            applied = await TaskRepository(writer_session).upsert_from_event(
                project_id=project_id,
                engine="celery",
                task_id="race-task",
                incoming_state=TaskState.FAILURE,
                occurred_at=occurred_at,
                defaults={
                    "name": "jobs.race",
                    "queue": None,
                    "priority": TaskPriority.NORMAL,
                },
                updates={
                    "finished_at": occurred_at,
                    "last_failed_at": occurred_at,
                    "exception": exception,
                    "traceback": f"traceback: {exception}",
                    "fingerprint": fingerprint,
                },
            )
            await writer_session.commit()
            return applied

    stale_writer = asyncio.create_task(
        _writer(
            0,
            occurred_at=stale_at,
            exception="StaleError",
            fingerprint="stale-fingerprint",
        ),
    )
    fresh_writer = asyncio.create_task(
        _writer(
            1,
            occurred_at=fresh_at,
            exception="FreshError",
            fingerprint="fresh-fingerprint",
        ),
    )
    await asyncio.gather(*(event.wait() for event in ready))
    release.set()
    await asyncio.gather(stale_writer, fresh_writer)

    async with factory() as check_session:
        row = (await check_session.execute(select(Task))).scalar_one()
        assert row.state == TaskState.FAILURE
        assert row.exception == "FreshError"
        assert row.traceback == "traceback: FreshError"
        assert row.fingerprint == "fresh-fingerprint"
        expected_finished = fresh_at if row.finished_at.tzinfo else fresh_at.replace(tzinfo=None)
        assert row.finished_at == expected_finished
    await engine.dispose()


@pytest.mark.asyncio
async def test_older_writer_cannot_reinterpret_newer_processing_as_future_skew(
    tmp_path: Path,
) -> None:
    """A call paused before SQL cannot overwrite a later completed call.

    The older call carries a future-skewed SUCCESS. While it is paused after
    binding its processing authority, a newer real-time FAILURE commits. The
    older call must reject rather than treating the newer lifecycle watermark
    as legacy source-clock poison.
    """
    database_path = tmp_path / "task-processing-order-race.sqlite3"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        connect_args={"timeout": 15},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as seed_session:
        project = Project(slug="processing-order-race", name="Processing order race")
        seed_session.add(project)
        await seed_session.flush()
        project_id = project.id
        seed_session.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="processing-order-task",
                name="jobs.processing_order",
                state=TaskState.STARTED,
                started_at=datetime.now(UTC) - timedelta(minutes=1),
            ),
        )
        await seed_session.commit()

    first_execute_reached = asyncio.Event()
    release_older = asyncio.Event()

    class _PausedFirstExecute:
        def __init__(self, wrapped: AsyncSession) -> None:
            self._wrapped = wrapped
            self._first = True

        async def execute(self, *args: Any, **kwargs: Any) -> Any:
            if self._first:
                self._first = False
                first_execute_reached.set()
                await release_older.wait()
            return await self._wrapped.execute(*args, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._wrapped, name)

    async with factory() as older_session:
        paused = _PausedFirstExecute(older_session)
        older_call = asyncio.create_task(
            TaskRepository(paused).upsert_from_event(  # type: ignore[arg-type]
                project_id=project_id,
                engine="celery",
                task_id="processing-order-task",
                incoming_state=TaskState.SUCCESS,
                occurred_at=datetime.now(UTC) + timedelta(seconds=55),
                defaults={
                    "name": "jobs.processing_order",
                    "queue": None,
                    "priority": TaskPriority.NORMAL,
                },
                updates={
                    "finished_at": datetime.now(UTC) + timedelta(seconds=55),
                    "result": "future-skewed result",
                    "exception": None,
                    "traceback": None,
                },
            ),
        )
        await first_execute_reached.wait()

        async with factory() as newer_session:
            real_at = datetime.now(UTC)
            newer_applied = await TaskRepository(newer_session).upsert_from_event(
                project_id=project_id,
                engine="celery",
                task_id="processing-order-task",
                incoming_state=TaskState.FAILURE,
                occurred_at=real_at,
                defaults={
                    "name": "jobs.processing_order",
                    "queue": None,
                    "priority": TaskPriority.NORMAL,
                },
                updates={
                    "finished_at": real_at,
                    "last_failed_at": real_at,
                    "result": None,
                    "runtime_ms": None,
                    "exception": "NewerFailure",
                    "traceback": "newer traceback",
                    "fingerprint": "newer-fingerprint",
                },
            )
            await newer_session.commit()

        release_older.set()
        older_applied = await older_call
        await older_session.commit()

    async with factory() as check_session:
        row = (await check_session.execute(select(Task))).scalar_one()
        assert newer_applied is True
        assert older_applied is False
        assert row.state == TaskState.FAILURE
        assert row.result is None
        assert row.exception == "NewerFailure"
        assert row.traceback == "newer traceback"
        assert row.fingerprint == "newer-fingerprint"
    await engine.dispose()
