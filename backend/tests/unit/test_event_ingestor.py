"""Tests for ``z4j_brain.domain.event_ingestor.EventIngestor``."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, TaskState
from z4j_brain.persistence.models import Agent, Event, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
    WorkerRepository,
)
from z4j_core.redaction import RedactionConfig, RedactionEngine


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="default", name="Default")
    session.add(p)
    await session.commit()
    return p


@pytest.fixture
async def agent(session: AsyncSession, project: Project) -> Agent:
    a = Agent(
        project_id=project.id,
        name="web-01",
        token_hash=secrets.token_hex(32),
        protocol_version="1",
        framework_adapter="django",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(a)
    await session.commit()
    return a


@pytest.fixture
def ingestor() -> EventIngestor:
    return EventIngestor(RedactionEngine(RedactionConfig()))


def _make_event(
    *,
    kind: str,
    task_id: str = "task-001",
    engine: str = "celery",
    data: dict | None = None,
    occurred_at: datetime | None = None,
) -> dict:
    return {
        "kind": kind,
        "engine": engine,
        "task_id": task_id,
        "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
        "data": data or {},
    }


@pytest.mark.asyncio
class TestIngestBasic:
    async def test_received_event_creates_task_row(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={
                    "task_name": "myapp.tasks.send_email",
                    "queue": "default",
                    "args": [],
                    "kwargs": {"to": "alice@example.com"},
                },
            ),
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.name == "myapp.tasks.send_email"
        assert task.state == TaskState.RECEIVED
        assert task.queue == "default"

    async def test_started_then_succeeded_lifecycle(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={"task_name": "myapp.tasks.f", "queue": "default"},
            ),
            _make_event(
                kind="task.started",
                data={"worker": "celery@web-01"},
            ),
            _make_event(
                kind="task.succeeded",
                data={"result": {"ok": True}, "runtime_ms": 42},
            ),
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.state == TaskState.SUCCESS
        assert task.worker_name == "celery@web-01"
        assert task.runtime_ms == 42
        assert task.result == {"ok": True}

    async def test_failure_records_exception_and_traceback(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        events = [
            _make_event(
                kind="task.received",
                data={"task_name": "myapp.tasks.broken"},
            ),
            _make_event(
                kind="task.failed",
                data={
                    "exception": "RuntimeError",
                    "traceback": "Traceback...\nRuntimeError: kaboom",
                },
            ),
        ]
        await ingestor.ingest_batch(
            events=events,
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()

        task = (await session.execute(select(Task))).scalar_one()
        assert task.state == TaskState.FAILURE
        assert task.exception == "RuntimeError"
        assert "kaboom" in task.traceback


@pytest.mark.asyncio
class TestIdempotence:
    async def test_replayed_event_does_not_duplicate(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        # Insert one event, then try to insert it again as part of
        # a second batch. The events table dedupes by (occurred_at, id);
        # the brain mints its own ids, so two distinct ids for the
        # same logical event still create two rows. We assert that
        # the TASKS row stays consistent (one task) regardless.
        ev = _make_event(
            kind="task.received",
            data={"task_name": "x"},
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        tasks = (await session.execute(select(Task))).scalars().all()
        assert len(tasks) == 1


@pytest.mark.asyncio
class TestRedactionDefenseInDepth:
    async def test_password_in_kwargs_redacted(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        # Agent should already have redacted; brain re-applies. We
        # send an UNREDACTED kwargs to simulate a misconfigured
        # agent and verify the brain catches it.
        ev = _make_event(
            kind="task.received",
            data={
                "task_name": "myapp.tasks.login",
                "kwargs": {"password": "hunter2"},
            },
        )
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        task = (await session.execute(select(Task))).scalar_one()
        assert task.kwargs is not None
        # The redaction engine replaces the value with [REDACTED].
        assert "hunter2" not in str(task.kwargs)


@pytest.mark.asyncio
class TestHeartbeat:
    async def test_event_traffic_bumps_last_seen(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        ingestor: EventIngestor,
    ) -> None:
        ev = _make_event(kind="task.received", data={"task_name": "x"})
        await ingestor.ingest_batch(
            events=[ev],
            project_id=project.id,
            agent_id=agent.id,
            agents=AgentRepository(session),
            event_repo=EventRepository(session),
            task_repo=TaskRepository(session),
            queue_repo=QueueRepository(session),
        )
        await session.commit()
        await session.refresh(agent)
        assert agent.last_seen_at is not None


@pytest.mark.asyncio
async def test_ingest_batch_returns_only_new_events(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """A re-delivered event (same content -> same content-derived
    event_id) is deduped at insert and is NOT returned, so the caller's
    automation hook fires ONCE per logical event, not once per delivery.
    This is the fix for the flaky-WS reconnect firing amplification.
    """
    ev = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
    )

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    first = await ingestor.ingest_batch(events=[ev], **_kw())
    await session.commit()
    assert len(first.new_events) == 1  # genuinely new -> returned (rule would fire)

    # Re-deliver the exact same event (agent reconnect buffer re-flush).
    second = await ingestor.ingest_batch(events=[ev], **_kw())
    await session.commit()
    assert second.new_events == []  # duplicate -> NOT returned -> rule does NOT re-fire

    # Exactly one events row exists (dedup held).
    rows = (await session.execute(select(Event))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_subsecond_divergent_redelivery_dedupes(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """Two deliveries of ONE logical task event that differ only in the
    sub-second of occurred_at (the celery-events fan-out, or two brain
    replicas) must collapse to a single events row and fire automation
    once. The content-derived event_id is second-grained, so occurred_at
    is stored at second granularity too; otherwise the (project_id,
    occurred_at, id) conflict key would miss and both would insert.
    """
    base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    ev1 = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
        occurred_at=base.replace(microsecond=100_000),
    )
    ev2 = _make_event(
        kind="task.failed",
        data={"task_name": "myapp.t", "exception": "boom"},
        occurred_at=base.replace(microsecond=400_000),
    )

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    first = await ingestor.ingest_batch(events=[ev1], **_kw())
    await session.commit()
    assert len(first.new_events) == 1

    second = await ingestor.ingest_batch(events=[ev2], **_kw())
    await session.commit()
    # Same logical event within one second -> deduped, no second firing.
    assert second.new_events == []
    rows = (await session.execute(select(Event))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_heartbeat_touch_failure_does_not_lose_events(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deadlock/failure on the best-effort heartbeat touch (now wrapped
    in its own savepoint) must NOT abort the batch: the ingested events
    still commit and are returned. Live-test finding: an unprotected
    deadlock there lost the whole batch and automation never fired.
    """
    ev = _make_event(kind="task.received", data={"task_name": "x"})
    agents_repo = AgentRepository(session)

    async def _boom(*_a, **_k):
        raise RuntimeError("simulated heartbeat deadlock")

    monkeypatch.setattr(agents_repo, "touch_heartbeat_at", _boom)

    new = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=agents_repo,
        event_repo=EventRepository(session),
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    # Heartbeat failed, but the event survived (savepoint isolation).
    assert len(new.new_events) == 1
    task = (await session.execute(select(Task))).scalar_one()
    assert task.name == "x"


# ---------------------------------------------------------------------------
# R7-HIGH3 / R8: precise transient/permanent classification. The batch
# withholds its ack (agent re-sends) ONLY for a TRANSIENT infrastructure
# error; a PERMANENT content/schema error OR any non-DB deterministic bug is
# dropped and acked (re-sending would loop forever). TRANSIENT is a strict
# ALLOWLIST -- unknown defaults to PERMANENT, because the agent's transient-
# retry path carries no drop budget, so "unknown = transient" pinned the
# buffer head and overflow-lost innocent events (R8 adversarial finding).
# ---------------------------------------------------------------------------


class TestIsTransientDbError:
    """Direct unit tests for the classifier that decides ack-withholding."""

    def test_permanent_content_errors_are_not_transient(self) -> None:
        """IntegrityError / DataError ARE the event's content (constraint /
        bad value), so PERMANENT. ProgrammingError is NOT: it is a brain-side
        schema/SQL/privilege problem, so TRANSIENT (R8-H2).
        """
        from sqlalchemy.exc import (
            DataError,
            IntegrityError,
            ProgrammingError,
        )
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        for exc_cls in (IntegrityError, DataError):
            exc = exc_cls("INSERT ...", {}, Exception("boom"))
            assert _is_transient_db_error(exc) is False, exc_cls.__name__
        # ProgrammingError (missing column / bad SQL / privilege) is a
        # brain-side problem, not malformed event content -> TRANSIENT so a
        # schema-skew rollout does not silently drop-and-ack every event.
        assert _is_transient_db_error(ProgrammingError("SELECT ...", {}, Exception("x"))) is True

    def test_pool_timeout_is_transient(self) -> None:
        """sqlalchemy.exc.TimeoutError (pool exhaustion) is TRANSIENT.

        It is NOT a DBAPIError subclass; an earlier version dropped-and-
        acked it as permanent -- silent data loss the instant the pool
        saturated. A fresh attempt (once the pool drains) succeeds, so it
        must withhold the ack.
        """
        from sqlalchemy.exc import TimeoutError as SATimeoutError
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        assert _is_transient_db_error(SATimeoutError("QueuePool limit")) is True

    def test_db_infra_errors_are_transient(self) -> None:
        """OperationalError / InterfaceError / connection + OS errors are
        TRANSIENT infrastructure failures that clear on their own."""
        from sqlalchemy.exc import InterfaceError, OperationalError
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        assert _is_transient_db_error(OperationalError("x", {}, Exception("deadlock"))) is True
        assert _is_transient_db_error(InterfaceError("x", {}, Exception("conn"))) is True
        assert _is_transient_db_error(ConnectionError("socket gone")) is True
        assert _is_transient_db_error(OSError("broken pipe")) is True
        # asyncio.TimeoutError is the builtin TimeoutError (a subclass of
        # OSError) on 3.11+, exercised here as a plain TimeoutError.
        assert _is_transient_db_error(TimeoutError()) is True

    def test_deadlock_by_message_is_transient(self) -> None:
        """A serialization/deadlock recognised by MESSAGE is TRANSIENT even
        when the exception class is not on the allowlist."""
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        # A bare exception whose text matches a _looks_like_deadlock token
        # must be treated transient via the message fallback (covers
        # backends whose driver boxes the deadlock in an odd class).
        assert _is_transient_db_error(Exception("could not serialize access")) is True
        assert _is_transient_db_error(Exception("database is locked")) is True

    def test_asyncpg_boxed_sqlstates_classified_by_class(self) -> None:
        """R8/C1: the asyncpg dialect boxes most server errors as a BARE
        DBAPIError (no OperationalError subclass), so classification must
        key on the driver SQLSTATE. Transient classes 08/40/53/55/57/58;
        permanent classes 22/23/42/25.

        This is the exact silent-loss the isinstance-only allowlist caused:
        a lock_timeout cancel (57014) under contention was mis-dropped.
        """
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class _Orig:
            def __init__(self, sqlstate: str) -> None:
                self.sqlstate = sqlstate

        class _BoxedDBAPIError(Exception):
            """Stands in for a bare sqlalchemy.exc.DBAPIError whose .orig is
            the raw asyncpg PostgresError carrying a .sqlstate."""

            def __init__(self, sqlstate: str) -> None:
                super().__init__(f"boxed pg error {sqlstate}")
                self.orig = _Orig(sqlstate)

        # TRANSIENT: lock timeout cancel, lock-not-available, resource
        # exhaustion, connection exceptions, deadlock, serialization, class 42
        # schema/SQL (42P01 undefined_table, 42703 undefined_column -- a
        # rolling-migration gap, R8-H2), and the specific 25006
        # read_only_sql_transaction (failover window, R9).
        for code in (
            "57014",
            "55P03",
            "53300",
            "53200",
            "08006",
            "40P01",
            "40001",
            "58030",
            "42P01",
            "42703",
            "25006",
        ):
            assert _is_transient_db_error(_BoxedDBAPIError(code)) is True, code

        # PERMANENT: data (22) + integrity (23) ARE the event's content; and
        # class-25 EXCEPT the 25006 carve-out (25P02 in_failed_sql_transaction
        # stays permanent).
        for code in ("22001", "23505", "25P02", "25001"):
            assert _is_transient_db_error(_BoxedDBAPIError(code)) is False, code

    def test_self_healing_idle_txn_sqlstates_are_transient(self) -> None:
        """External round-8 H1 (narrowed round-9 H1): the idle-in-transaction
        timeout codes 25P03 / 25P04 self-heal on a fresh transaction and are
        allowlisted by EXACT code. The failover read_only code 25006 too.
        """
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class _Orig:
            def __init__(self, sqlstate: str) -> None:
                self.sqlstate = sqlstate

        class _BoxedDBAPIError(Exception):
            def __init__(self, sqlstate: str) -> None:
                super().__init__(f"boxed pg error {sqlstate}")
                self.orig = _Orig(sqlstate)

        # TRANSIENT: the specific self-healing class-25 codes.
        for code in ("25006", "25P03", "25P04"):
            assert _is_transient_db_error(_BoxedDBAPIError(code)) is True, code

    def test_bare_0a000_xx000_codes_are_permanent(self) -> None:
        """External round-9 H1: 0A000 (feature_not_supported) and XX000
        (internal_error) are NOT reliable transient signals -- an ordinary
        unsupported SQL feature is 0A000 and a corrupt index / real backend
        fault is XX000, both DETERMINISTIC. Keying transient on the bare code
        would withhold-confirm them forever, so they must classify PERMANENT.
        (The genuinely self-healing stale-plan case is caught by the asyncpg
        CLASS name instead -- see the next test.)
        """
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class _Orig:
            def __init__(self, sqlstate: str) -> None:
                self.sqlstate = sqlstate

        class _BoxedDBAPIError(Exception):
            def __init__(self, sqlstate: str) -> None:
                super().__init__(f"boxed pg error {sqlstate}")
                self.orig = _Orig(sqlstate)

        # PERMANENT: the bare codes (and other codes in their classes) whose
        # message carries NO stale-type-cache signature.
        for code in ("0A000", "0A001", "XX000", "XX001", "XX002"):
            assert _is_transient_db_error(_BoxedDBAPIError(code)) is False, code

    def test_xx000_stale_type_cache_message_is_transient(self) -> None:
        """External round-9 re-review: asyncpg raises the SERVER-side stale-
        type-cache invalidation (a rolling ALTER TYPE / DROP+CREATE TYPE
        migration) as a bare InternalServerError (XX000) with message
        ``cache lookup failed for type <oid>``. It self-heals once connections
        re-introspect, so it is TRANSIENT -- matched by MESSAGE signature so a
        GENERIC (never-healing) XX000 stays permanent.
        """
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class InternalServerError(Exception):
            """Stands in for asyncpg's XX000 class (name preserved through the
            SQLAlchemy wrapper); NOT one of the cache CLASS names."""

            def __init__(self, msg: str) -> None:
                super().__init__(msg)
                self.sqlstate = "XX000"

        class _BoxedInternalError(Exception):
            def __init__(self, orig: Exception) -> None:
                super().__init__(str(orig))
                self.orig = orig

        # TRANSIENT: the stale-type-cache signature, on the raw orig ...
        stale = InternalServerError("cache lookup failed for type 90123")
        assert _is_transient_db_error(_BoxedInternalError(stale)) is True
        # ... and directly on the exception.
        assert _is_transient_db_error(stale) is True

        # PERMANENT: a GENERIC XX000 (corrupt index / real backend fault) that
        # does NOT self-heal must NOT loop the agent forever.
        generic = InternalServerError("could not read block 3 in file base/1")
        assert _is_transient_db_error(_BoxedInternalError(generic)) is False

    def test_xx000_signature_ignores_bound_parameters(self) -> None:
        """External round-9 re-review: the signature must match the RAW driver
        message (exc.orig) ONLY, never the SQLAlchemy wrapper str -- which
        embeds the failing INSERT's bound ``[parameters: ...]``. A monitored
        task that itself hit a Postgres ``cache lookup failed for type`` error
        reports that text in its event payload; if that INSERT then hits a
        GENERIC never-healing XX000, matching the wrapper would mis-classify it
        TRANSIENT and loop forever."""
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class InternalServerError(Exception):
            def __init__(self, msg: str) -> None:
                super().__init__(msg)
                self.sqlstate = "XX000"

        class _WrapperWithParamsError(Exception):
            """str() embeds the bound params (as SQLAlchemy's DBAPIError does),
            here quoting the signature via an event payload value; .orig is the
            GENERIC (never-healing) driver error with NO signature."""

            def __init__(self, orig: Exception) -> None:
                super().__init__(
                    "(InternalServerError) corrupt index [SQL: INSERT INTO events ...] "
                    "[parameters: {'payload': 'cache lookup failed for type 90123'}]"
                )
                self.orig = orig

        wrapper = _WrapperWithParamsError(InternalServerError("corrupt index at block 3"))
        # The wrapper str CONTAINS the signature (via params) but orig does NOT
        # -> must classify PERMANENT (no infinite loop on a poison payload).
        assert _is_transient_db_error(wrapper) is False

    def test_parse_datetime_normalises_aware_offset_to_utc(self) -> None:
        """External round-9 re-review: a non-UTC ``occurred_at`` must be
        CONVERTED to UTC (not accepted with its wire offset), so a naive-offset
        dialect (SQLite drops the offset, storing local wall-clock) does not
        mis-represent the instant and mislead the monotonic liveness guards."""
        from datetime import UTC, datetime, timedelta, timezone

        from z4j_brain.domain.event_ingestor import _parse_datetime

        plus5 = timezone(timedelta(hours=5))
        aware = datetime(2026, 7, 12, 15, 0, 0, tzinfo=plus5)  # 10:00Z
        out = _parse_datetime(aware)
        assert out.tzinfo == UTC
        assert out == datetime(2026, 7, 12, 10, 0, 0, tzinfo=UTC)  # same instant, UTC

        # A string with an offset normalises the same way.
        out_str = _parse_datetime("2026-07-12T15:00:00+05:00")
        assert out_str == datetime(2026, 7, 12, 10, 0, 0, tzinfo=UTC)

        # A naive value keeps the wire contract "naive == UTC".
        out_naive = _parse_datetime(datetime(2026, 7, 12, 10, 0, 0))
        assert out_naive == datetime(2026, 7, 12, 10, 0, 0, tzinfo=UTC)

    def test_parse_datetime_boundary_year_offset_does_not_raise(self) -> None:
        """External round-9 re-review: a boundary-year aware value whose offset
        shift crosses datetime.min/max (e.g. a broken RTC / min-datetime
        sentinel with a non-UTC offset) makes ``astimezone(UTC)`` raise
        OverflowError -- which is NOT a ValueError. It must be caught so the
        garbage value falls back to now() (letting _clamp_occurred_at do its
        job) rather than escaping and drop-acking a recoverable event."""
        from datetime import UTC, datetime, timedelta, timezone

        from z4j_brain.domain.event_ingestor import _parse_datetime

        before = datetime.now(UTC) - timedelta(seconds=5)

        # Year-0001 with a positive offset overflows on the UTC shift; as a
        # string ...
        out_str = _parse_datetime("0001-01-01T00:00:00+05:00")
        assert out_str.tzinfo == UTC
        assert out_str >= before  # fell back to now()

        # ... and as a datetime object (the unguarded branch pre-fix).
        boundary = datetime(1, 1, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=5)))
        out_obj = _parse_datetime(boundary)
        assert out_obj.tzinfo == UTC
        assert out_obj >= before

        # Year-9999 with a negative offset overflows the other direction.
        out_max = _parse_datetime("9999-12-31T23:59:59-14:00")
        assert out_max.tzinfo == UTC
        assert out_max >= before

    def test_asyncpg_driver_cache_errors_by_class_name(self) -> None:
        """External round-8 H1: asyncpg raises InvalidCachedStatementError /
        OutdatedSchemaCacheError with NO SQLSTATE (boxed as
        NotSupportedError/InternalError, not OperationalError), so they escape
        both the SQLSTATE and the isinstance checks. They self-heal on a fresh
        transaction and must be matched by class name -- on either the wrapped
        ``.orig`` or the exception itself.
        """
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        class InvalidCachedStatementError(Exception):
            """Stands in for asyncpg's real class of the same name."""

        class OutdatedSchemaCacheError(Exception):
            pass

        # Matched directly on the raised exception.
        assert _is_transient_db_error(InvalidCachedStatementError("stale plan")) is True
        assert _is_transient_db_error(OutdatedSchemaCacheError("stale schema")) is True

        # Matched on the SQLAlchemy-wrapped ``.orig`` (the common shape).
        class _BoxedError(Exception):
            def __init__(self, orig: Exception) -> None:
                super().__init__("boxed")
                self.orig = orig

        assert _is_transient_db_error(_BoxedError(InvalidCachedStatementError("x"))) is True
        assert _is_transient_db_error(_BoxedError(OutdatedSchemaCacheError("x"))) is True

        # CRITICAL (round-9 H1): the real asyncpg InvalidCachedStatementError
        # carries SQLSTATE 0A000, and 0A000 is now PERMANENT-by-code. The class
        # match MUST run BEFORE the SQLSTATE gate so the genuine cache error is
        # still transient even though its code alone would classify permanent.
        cache_orig = InvalidCachedStatementError("cached plan must not change result type")
        cache_orig.sqlstate = "0A000"  # type: ignore[attr-defined]
        assert _is_transient_db_error(_BoxedError(cache_orig)) is True

        # A similarly-named-but-not-allowlisted cache error stays permanent.
        class SomeOtherCacheError(Exception):
            pass

        assert _is_transient_db_error(SomeOtherCacheError("x")) is False

    def test_pending_rollback_is_transient_but_generic_invalidrequest_is_not(self) -> None:
        """External round-8 H2: a PendingRollbackError means the connection was
        invalidated mid-transaction (under a live connection every permanent
        error rolls its savepoint back cleanly and the outer commit succeeds),
        which self-heals on a fresh session -> TRANSIENT. Its GENERIC parent
        InvalidRequestError (real API misuse) stays PERMANENT: only the
        PendingRollbackError subtype is carved out.
        """
        from sqlalchemy.exc import InvalidRequestError, PendingRollbackError
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        assert _is_transient_db_error(PendingRollbackError("conn invalidated")) is True
        # Parent class is NOT transient -- guards against widening the carve-out.
        assert _is_transient_db_error(InvalidRequestError("api misuse")) is False

    def test_sqlite_operational_error_deterministic_vs_lock(self) -> None:
        """R9: a no-SQLSTATE SQLite OperationalError is TRANSIENT for a lock
        or connection reset, but PERMANENT for a deterministic schema/syntax
        signature (else a bad-migration 'no such column' would loop forever).
        """
        from sqlalchemy.exc import OperationalError
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        def _op(msg: str) -> OperationalError:
            return OperationalError("SELECT ...", {}, Exception(msg))

        # Transient (lock / connection):
        assert _is_transient_db_error(_op("database is locked")) is True
        assert _is_transient_db_error(_op("server closed the connection")) is True
        # Permanent (deterministic schema / syntax drift):
        assert _is_transient_db_error(_op("no such column: tasks.foo")) is False
        assert _is_transient_db_error(_op("no such table: events")) is False
        assert _is_transient_db_error(_op('near "SELCT": syntax error')) is False

    def test_sqlstate_read_directly_off_exception(self) -> None:
        """Some drivers expose the code on the exception itself (no .orig
        wrapper) -- that path is also honoured."""
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        e_transient = Exception("statement timeout")
        e_transient.sqlstate = "57014"  # type: ignore[attr-defined]
        assert _is_transient_db_error(e_transient) is True

        e_permanent = Exception("value too long")
        e_permanent.sqlstate = "22001"  # type: ignore[attr-defined]
        assert _is_transient_db_error(e_permanent) is False

    def test_non_db_deterministic_errors_are_permanent(self) -> None:
        """R8: a non-DB deterministic bug (RuntimeError / TypeError /
        ValueError / SQLAlchemy StatementError / InvalidRequestError) is
        PERMANENT.

        An earlier denylist defaulted these to TRANSIENT ("unknown =
        transient"), so a deterministic projection bug for one payload
        shape withheld the ack forever: the agent re-sent it every backoff
        cycle with no drop budget, pinning its buffer head and overflow-
        losing every later event. They must drop-and-ack (bounded single-
        event loss, logged) instead.
        """
        from sqlalchemy.exc import InvalidRequestError, StatementError
        from z4j_brain.domain.event_ingestor import _is_transient_db_error

        assert _is_transient_db_error(RuntimeError("projection bug")) is False
        assert _is_transient_db_error(TypeError("bad type")) is False
        assert _is_transient_db_error(ValueError("bad value")) is False
        assert _is_transient_db_error(KeyError("missing")) is False
        assert _is_transient_db_error(InvalidRequestError("bad request")) is False
        assert (
            _is_transient_db_error(StatementError("boom", "SELECT 1", {}, Exception("x"))) is False
        )


async def test_transient_insert_error_withholds_ack(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7-HIGH3 wiring: a TRANSIENT per-event insert error marks the
    batch not-fully-durable (transient_skips >= 1) so the caller
    withholds the ack and the agent re-sends."""
    from sqlalchemy.exc import OperationalError

    ev = _make_event(kind="task.received", data={"task_name": "x"})
    event_repo = EventRepository(session)

    async def _boom(*_a, **_k):
        raise OperationalError("INSERT ...", {}, Exception("connection reset"))

    monkeypatch.setattr(event_repo, "insert", _boom)

    result = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=event_repo,
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    assert result.transient_skips == 1
    assert result.fully_durable is False
    assert result.new_events == []


async def test_schema_skew_programmingerror_withholds_ack_not_dropped(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8-H2: a ProgrammingError (missing column during a rolling migration)
    is a BRAIN-side schema problem, not malformed event content, so it is
    TRANSIENT -> the ack is WITHHELD and the agent re-sends (heals once the
    migration completes). It must NOT be dropped-and-acked, which would
    silently lose EVERY event during the schema-skew window.
    """
    from sqlalchemy.exc import ProgrammingError

    ev = _make_event(kind="task.received", data={"task_name": "x"})
    event_repo = EventRepository(session)

    async def _boom(*_a, **_k):
        raise ProgrammingError("INSERT ...", {}, Exception('column "foo" does not exist'))

    monkeypatch.setattr(event_repo, "insert", _boom)

    result = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=event_repo,
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    # Withheld (transient), NOT dropped-and-acked:
    assert result.transient_skips == 1
    assert result.fully_durable is False
    assert result.new_events == []


async def test_permanent_insert_error_is_dropped_and_acked(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7-HIGH3 wiring: a PERMANENT per-event insert error is dropped
    (not counted as a transient skip) so the batch STILL acks -- re-
    sending a malformed event would loop forever."""
    from sqlalchemy.exc import IntegrityError

    ev = _make_event(kind="task.received", data={"task_name": "x"})
    event_repo = EventRepository(session)

    async def _boom(*_a, **_k):
        raise IntegrityError("INSERT ...", {}, Exception("constraint violation"))

    monkeypatch.setattr(event_repo, "insert", _boom)

    result = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=event_repo,
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    # Dropped, not withheld: the batch is fully durable so it acks.
    assert result.transient_skips == 0
    assert result.fully_durable is True
    assert result.new_events == []


async def test_non_db_deterministic_insert_error_is_dropped_and_acked(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8: a non-DB deterministic per-event error (e.g. a RuntimeError /
    TypeError bug in the ingest/projection path for one payload shape) is
    PERMANENT -> dropped-and-acked, NOT withheld.

    Pre-R8 the classifier defaulted every non-DBAPI exception to
    transient, so the batch withheld its ack forever: the agent re-sent
    it every backoff cycle with no drop budget, pinning its buffer head
    and overflow-losing every later event. It must instead drop the one
    bad event and let the batch ack (bounded single-event loss, logged).
    """
    ev = _make_event(kind="task.received", data={"task_name": "x"})
    event_repo = EventRepository(session)

    async def _boom(*_a, **_k):
        raise RuntimeError("deterministic projection bug for this payload")

    monkeypatch.setattr(event_repo, "insert", _boom)

    result = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=event_repo,
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()

    # Dropped and acked (fully durable), NOT a withheld transient skip:
    # re-sending the identical event would fail identically forever.
    assert result.transient_skips == 0
    assert result.fully_durable is True
    assert result.new_events == []


async def test_worker_upsert_failure_never_fails_the_batch(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9: worker liveness is observability, not event data. If BOTH the
    bulk worker upsert AND the per-row fallback fail (e.g. a deadlock on an
    existing worker's UPDATE), the per-row savepoint must confine the error
    so the ingested events still commit -- otherwise a swallowed worker
    error would poison the outer transaction, the commit would roll the
    events back, and the batch would be acked as durable (silent loss).
    """
    ev = _make_event(kind="task.started", data={"task_name": "x", "worker": "w-host-1"})
    worker_repo = WorkerRepository(session)

    async def _boom_bulk(*_a, **_k):
        raise RuntimeError("simulated bulk worker deadlock")

    async def _boom_row(*_a, **_k):
        raise RuntimeError("simulated per-row worker deadlock")

    monkeypatch.setattr(worker_repo, "upsert_from_events_bulk", _boom_bulk)
    monkeypatch.setattr(worker_repo, "upsert_from_event", _boom_row)

    result = await ingestor.ingest_batch(
        events=[ev],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=EventRepository(session),
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
        worker_repo=worker_repo,
    )
    await session.commit()

    # The worker write failed twice, but the event survived and committed.
    assert len(result.new_events) == 1
    assert result.fully_durable is True
    task = (await session.execute(select(Task))).scalar_one()
    assert task.name == "x"


async def test_replayed_terminal_event_does_not_double_count_metric(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7-LOW + round-9 LOW: a re-delivered terminal event (dedup'd on replay)
    must NOT re-increment the task throughput counter, AND the increment is
    DEFERRED until the caller emits it post-commit.

    The round-7 withheld-ack re-send path re-delivers a batch's already-
    committed events after a transient skip; those dedup at the events
    table (inserted=False) but still project the task state. The
    Prometheus ``z4j_tasks_total`` counter is gated on ``inserted`` so a
    replay does not over-report completions. Round-9: the ``.inc()`` is now
    deferred into ``result.pending_metrics`` and fired only by
    ``result.emit_metrics()`` after a successful commit, so a transient
    rollback + re-send cannot double-count a never-persisted row.
    """
    import z4j_brain.api.metrics as metrics_mod

    class _CounterSpy:
        def __init__(self) -> None:
            self.inc_calls = 0

        def labels(self, **_kw):
            return self

        def inc(self, amount: float = 1) -> None:
            self.inc_calls += 1

        def observe(self, _v: float) -> None:
            pass

    spy = _CounterSpy()
    monkeypatch.setattr(metrics_mod, "z4j_tasks_total", spy)
    monkeypatch.setattr(metrics_mod, "z4j_task_duration_seconds", _CounterSpy())

    # Identical content (same task_id + kind + occurred_at second) => the
    # content-derived event_id collides, so the second ingest dedups.
    ts = datetime(2026, 7, 11, 12, 0, 0, tzinfo=UTC)
    ev = _make_event(kind="task.succeeded", data={"task_name": "x"}, occurred_at=ts)

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    first = await ingestor.ingest_batch(events=[dict(ev)], **_kw())
    # DEFERRAL: the task counter is NOT incremented during ingest -- only
    # after commit, when the caller emits result.pending_metrics.
    assert spy.inc_calls == 0
    assert first.pending_metrics  # at least the terminal-task counter is queued
    await session.commit()
    first.emit_metrics()  # caller emits post-commit
    second = await ingestor.ingest_batch(events=[dict(ev)], **_kw())
    await session.commit()
    second.emit_metrics()

    # First delivery inserted + counted; the replay dedup'd and did NOT.
    assert len(first.new_events) == 1
    assert len(second.new_events) == 0
    assert not second.pending_metrics  # dedup -> nothing to emit
    assert spy.inc_calls == 1


async def test_duplicate_failure_replay_does_not_rewind_task_fields(
    session: AsyncSession,
    project: Project,
    agent: Agent,
    ingestor: EventIngestor,
) -> None:
    """R8-M3: replaying an OLD failure after a NEWER one must NOT rewind the
    task's kind-specific fields (finished_at / exception / traceback).

    Those fields are written UNCONDITIONALLY while only the state column is
    monotonic-guarded, so re-projecting a dedup'd duplicate would overwrite
    the newer failure with the stale one. Skipping re-projection for
    inserted=False fixes it.
    """
    t1 = datetime(2026, 7, 12, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 7, 12, 10, 0, 5, tzinfo=UTC)  # 5s later: distinct id
    fail_a = _make_event(
        kind="task.failed",
        data={"task_name": "x", "exception": "ErrorA", "traceback": "tbA"},
        occurred_at=t1,
    )
    fail_b = _make_event(
        kind="task.failed",
        data={"task_name": "x", "exception": "ErrorB", "traceback": "tbB"},
        occurred_at=t2,
    )

    def _kw():
        return {
            "project_id": project.id,
            "agent_id": agent.id,
            "agents": AgentRepository(session),
            "event_repo": EventRepository(session),
            "task_repo": TaskRepository(session),
            "queue_repo": QueueRepository(session),
        }

    await ingestor.ingest_batch(events=[dict(fail_a)], **_kw())
    await session.commit()
    await ingestor.ingest_batch(events=[dict(fail_b)], **_kw())
    await session.commit()
    # Re-deliver the OLD failure A (same occurred_at second -> dedup):
    replay = await ingestor.ingest_batch(events=[dict(fail_a)], **_kw())
    await session.commit()

    assert replay.new_events == []  # dedup'd, not re-inserted
    task = (await session.execute(select(Task))).scalar_one()
    # Still the NEWER failure B -- the replay did not rewind the fields.
    assert task.exception == "ErrorB"
    assert "tbB" in (task.traceback or "")
