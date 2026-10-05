"""A brain that has begun shutting down admits no new scheduler fire.

The ASGI server reacts to a stop signal by draining its HTTP and WebSocket
connections, and only afterwards runs the lifespan teardown that stops the
scheduler gRPC listener. For those seconds the listener used to accept
``FireSchedule`` while the agents' connections were already closing: the fire
was committed, never delivered, timed out by the next brain, and (when nothing
had superseded it) left as a terminal hold that disabled the schedule until an
operator resolved it.

Three layers are held here. The handler refuses a fire once admission is
closed and writes nothing. The server closes the admission its servicer reads,
over a real channel. The signal chain closes it at the signal, in front of the
handler that was already installed, which still runs.
"""

from __future__ import annotations

import secrets
import signal
import socket
import threading
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import grpc
import pytest
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain import shutdown_signals
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import Project, Schedule
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.admission import FireAdmission
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.proto import scheduler_pb2_grpc as pb_grpc
from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH
from z4j_brain.scheduler_grpc.server import SchedulerGrpcServer
from z4j_brain.settings import Settings
from z4j_brain.shutdown_signals import notify_on_shutdown_signals

#: Every table a fire, accepted or refused in the ordinary way, can write to.
_FIRE_TABLES = (
    "commands",
    "schedule_fires",
    "pending_fires",
    "audit_log",
    "schedule_change_log",
    "schedule_terminal_holds",
    "scheduler_rate_buckets",
)


class _AbortedError(Exception):
    """What ``grpc.aio`` raises out of ``context.abort``, for a fake context."""


class _Context:
    def __init__(self) -> None:
        self.aborted: tuple[grpc.StatusCode, str] | None = None

    def cancelled(self) -> bool:
        return False

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted = (code, details)
        raise _AbortedError(details)

    def auth_context(self) -> dict[str, list[bytes]]:
        return {}


def _timestamp(value: datetime) -> Timestamp:
    stamp = Timestamp()
    stamp.FromDatetime(value)
    return stamp


def _settings(migrated_db_url: str, chain_secret: str, **overrides: Any) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        **overrides,
    )


async def _seed_schedule(database: DatabaseManager) -> Schedule:
    project = Project(id=uuid.uuid4(), slug="admission", name="Admission")
    async with database.session() as session:
        session.add(project)
        await session.flush()
        row = await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data={
                "name": "cleanup",
                "task_name": "jobs.cleanup",
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "kind": "cron",
                "expression": "0 * * * *",
                "timezone": "UTC",
                "queue": "maintenance",
                "priority": "normal",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "catch_up": "skip",
            },
            planning_at=datetime.now(UTC) - timedelta(hours=3),
        )
        await session.commit()
        session.expunge(row)
    return row


def _current_fire(row: Schedule) -> pb.FireScheduleRequest:
    """The shipped wire: the slot plus the authority that governs it."""

    assert row.next_run_at is not None
    slot = row.next_run_at.replace(tzinfo=UTC)
    successor = canonical_next_run_at(
        kind=row.kind.value,
        expression=row.expression,
        timezone=row.timezone,
        last_run_at=slot,
        anchor_at=slot,
    )
    assert successor is not None
    return pb.FireScheduleRequest(
        schedule_id=str(row.id),
        fire_id=str(derive_scheduler_fire_id(row.id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
        scheduler_protocol_epoch=CURRENT_PROTOCOL_EPOCH,
        observed_control_token=str(row.control_token),
        definition_digest=row.definition_digest,
        expected_schedule_revision=row.schedule_revision,
        expected_next_run_at=_timestamp(slot),
        prepared_next_run_at=_timestamp(successor),
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )


async def _durable_state(database: DatabaseManager, schedule_id: uuid.UUID) -> dict[str, object]:
    """Row counts of every fire table plus the schedule's own cursor."""

    state: dict[str, object] = {}
    async with database.session() as session:
        for table in _FIRE_TABLES:
            result = await session.execute(text(f"SELECT count(*) FROM {table}"))
            state[table] = result.scalar_one()
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        state["schedule"] = (
            row.is_enabled,
            row.schedule_revision,
            row.total_runs,
            row.last_run_at,
            row.next_run_at,
        )
    return state


@pytest.fixture
async def database_and_row(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> AsyncIterator[tuple[Settings, DatabaseManager, Schedule]]:
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)
    try:
        yield settings, database, await _seed_schedule(database)
    finally:
        await engine.dispose()


def _service(
    settings: Settings,
    database: DatabaseManager,
    admission: FireAdmission,
) -> tuple[SchedulerServiceImpl, AsyncMock, AsyncMock]:
    dispatcher, audit = AsyncMock(), AsyncMock()
    service = SchedulerServiceImpl(
        settings=settings,
        db=database,
        command_dispatcher=dispatcher,
        audit_service=audit,
        fire_admission=admission,
    )
    return service, dispatcher, audit


# ---------------------------------------------------------------------------
# The handler
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_closed_admission_refuses_the_fire_as_unavailable_and_writes_nothing(
    database_and_row: tuple[Settings, DatabaseManager, Schedule],
) -> None:
    settings, database, row = database_and_row
    admission = FireAdmission()
    service, dispatcher, audit = _service(settings, database, admission)
    before = await _durable_state(database, row.id)

    admission.close()
    context = _Context()
    with pytest.raises(_AbortedError):
        await service.FireSchedule(_current_fire(row), context)

    assert context.aborted is not None
    code, details = context.aborted
    # The one status the scheduler treats as "try this slot again": not a
    # disposition, so nothing is latched, quarantined or acknowledged.
    assert code is grpc.StatusCode.UNAVAILABLE
    assert "shutting down" in details
    assert await _durable_state(database, row.id) == before
    assert dispatcher.mock_calls == []
    assert audit.mock_calls == []
    assert admission.refused == 1


@pytest.mark.asyncio
async def test_the_same_fire_is_handled_while_admission_is_open(
    database_and_row: tuple[Settings, DatabaseManager, Schedule],
) -> None:
    """The control: the gate is what refused above, not the request."""

    settings, database, row = database_and_row
    admission = FireAdmission()
    service, _dispatcher, _audit = _service(settings, database, admission)
    before = await _durable_state(database, row.id)

    context = _Context()
    response = await service.FireSchedule(_current_fire(row), context)

    assert context.aborted is None
    assert response.disposition == pb.FireDisposition.FIRE_ACCEPTED
    after = await _durable_state(database, row.id)
    # No agent is online here, so the accepted fire is buffered: one history
    # row, one pending fire and one cursor transition, where the refusal
    # above left every one of them untouched.
    changed = {name for name in before if after[name] != before[name]}
    assert changed == {"schedule_fires", "pending_fires", "schedule_change_log", "schedule"}
    assert admission.refused == 0


@pytest.mark.asyncio
async def test_malformed_and_manual_fires_are_refused_the_same_way(
    database_and_row: tuple[Settings, DatabaseManager, Schedule],
) -> None:
    """The gate is ahead of parsing, so no request shape gets past it."""

    settings, database, row = database_and_row
    admission = FireAdmission()
    service, _dispatcher, _audit = _service(settings, database, admission)
    admission.close()

    requests = (
        pb.FireScheduleRequest(schedule_id="not-a-uuid", fire_id="neither"),
        pb.FireScheduleRequest(
            schedule_id=str(row.id),
            fire_id=str(uuid.uuid4()),
            triggered_by_user_id=str(uuid.uuid4()),
        ),
    )
    for request in requests:
        context = _Context()
        with pytest.raises(_AbortedError):
            await service.FireSchedule(request, context)
        assert context.aborted is not None
        assert context.aborted[0] is grpc.StatusCode.UNAVAILABLE
    assert admission.refused == len(requests)


def test_a_servicer_built_alone_admits_fires() -> None:
    """Existing callers that pass no admission keep an open one."""

    admission = FireAdmission()
    assert admission.closed is False
    admission.close()
    admission.close()
    assert admission.closed is True


# ---------------------------------------------------------------------------
# The server, over a real channel
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.asyncio
async def test_begin_shutdown_refuses_fires_on_the_wire_and_keeps_serving_the_rest(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    settings = _settings(
        migrated_db_url,
        migrated_audit_chain_secret,
        scheduler_grpc_enabled=True,
        scheduler_grpc_insecure=True,
        scheduler_grpc_bind_host="127.0.0.1",
        scheduler_grpc_bind_port=0,
        scheduler_grpc_grace_seconds=0.2,
    )
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)
    server = SchedulerGrpcServer(
        settings=settings,
        db=database,
        command_dispatcher=AsyncMock(),
        audit_service=AsyncMock(),
    )
    try:
        row = await _seed_schedule(database)
        await server.start()
        assert server.admitting_fires is True
        async with grpc.aio.insecure_channel(f"127.0.0.1:{server.bound_port}") as channel:
            stub = pb_grpc.SchedulerServiceStub(channel)
            before = await _durable_state(database, row.id)

            server.begin_shutdown()

            assert server.admitting_fires is False
            with pytest.raises(grpc.aio.AioRpcError) as refused:
                await stub.FireSchedule(_current_fire(row), timeout=10)
            assert refused.value.code() is grpc.StatusCode.UNAVAILABLE
            assert "shutting down" in (refused.value.details() or "")
            assert await _durable_state(database, row.id) == before
            # Read-only surface is untouched: the scheduler can still tell
            # that this brain is alive and what it negotiated.
            ping = await stub.Ping(pb.PingRequest(), timeout=10)
            assert ping.brain_version
    finally:
        await server.stop()
        await engine.dispose()


@pytest.mark.asyncio
async def test_stop_closes_admission_for_a_caller_that_never_signalled(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(settings.database_url)
    try:
        server = SchedulerGrpcServer(
            settings=settings,
            db=DatabaseManager(engine),
            command_dispatcher=AsyncMock(),
            audit_service=AsyncMock(),
        )
        assert server.admitting_fires is True
        await server.stop()
        assert server.admitting_fires is False
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# The signal chain
# ---------------------------------------------------------------------------


@pytest.fixture
def recorded_signals() -> Iterator[list[str]]:
    """SIGTERM and SIGINT handled by recorders, originals put back after."""

    events: list[str] = []
    originals = {
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        signal.SIGINT: signal.getsignal(signal.SIGINT),
    }

    def _previous_term(signum: int, frame: object) -> None:
        events.append(f"previous:{signal.Signals(signum).name}")

    def _previous_int(signum: int, frame: object) -> None:
        events.append(f"previous:{signal.Signals(signum).name}")

    signal.signal(signal.SIGTERM, _previous_term)
    signal.signal(signal.SIGINT, _previous_int)
    try:
        yield events
    finally:
        for signum, handler in originals.items():
            signal.signal(signum, handler)


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT"])
def test_chained_handler_closes_admission_then_runs_the_previous_handler(
    recorded_signals: list[str],
    signame: str,
) -> None:
    signum = getattr(signal, signame)
    previous = signal.getsignal(signum)
    admission = FireAdmission()

    def _close() -> None:
        recorded_signals.append("callback")
        admission.close()

    restore = notify_on_shutdown_signals(_close)
    try:
        assert signal.getsignal(signum) is not previous

        signal.raise_signal(signum)

        assert admission.closed is True
        assert recorded_signals == ["callback", f"previous:{signame}"]
    finally:
        restore()
    assert signal.getsignal(signum) is previous


def test_a_failing_callback_does_not_keep_the_previous_handler_from_running(
    recorded_signals: list[str],
) -> None:
    def _boom() -> None:
        raise RuntimeError("callback failed")

    restore = notify_on_shutdown_signals(_boom)
    try:
        signal.raise_signal(signal.SIGTERM)
        assert recorded_signals == ["previous:SIGTERM"]
    finally:
        restore()


def test_installation_is_skipped_off_the_main_thread(
    recorded_signals: list[str],
) -> None:
    before = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    outcome: dict[str, object] = {}

    def _install() -> None:
        outcome["restore"] = notify_on_shutdown_signals(lambda: recorded_signals.append("callback"))

    worker = threading.Thread(target=_install)
    worker.start()
    worker.join()

    assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == before
    restore = outcome["restore"]
    assert callable(restore)
    restore()
    signal.raise_signal(signal.SIGTERM)
    assert recorded_signals == ["previous:SIGTERM"]


def test_a_default_disposition_is_put_back_and_the_signal_delivered_again(
    recorded_signals: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    redelivered: list[int] = []
    monkeypatch.setattr(shutdown_signals.signal, "raise_signal", redelivered.append)

    restore = notify_on_shutdown_signals(lambda: recorded_signals.append("callback"))
    try:
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)

        assert recorded_signals == ["callback"]
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        assert redelivered == [signal.SIGTERM]
    finally:
        restore()


def test_an_ignored_signal_stays_ignored(recorded_signals: list[str]) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    restore = notify_on_shutdown_signals(lambda: recorded_signals.append("callback"))
    try:
        signal.raise_signal(signal.SIGTERM)
        assert recorded_signals == ["callback"]
    finally:
        restore()
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN


def test_restore_leaves_a_handler_someone_else_installed_since(
    recorded_signals: list[str],
) -> None:
    def _later(signum: int, frame: object) -> None:
        recorded_signals.append("later")

    restore = notify_on_shutdown_signals(lambda: recorded_signals.append("callback"))
    signal.signal(signal.SIGTERM, _later)

    restore()

    assert signal.getsignal(signal.SIGTERM) is _later


def test_a_handler_that_python_cannot_call_back_is_left_alone(
    recorded_signals: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(shutdown_signals.signal, "getsignal", lambda signum: None)

    restore = notify_on_shutdown_signals(lambda: recorded_signals.append("callback"))
    monkeypatch.undo()

    assert signal.getsignal(signal.SIGTERM) is before
    restore()
    assert signal.getsignal(signal.SIGTERM) is before


# ---------------------------------------------------------------------------
# The lifespan wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifespan_closes_admission_at_the_signal_while_the_listener_is_still_up(
    recorded_signals: list[str],
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """The whole chain in one process: signal, gate, refusal, previous handler.

    The lifespan runs on the main thread here, as it does under the ASGI
    server, so the chain is really installed. The recorder stands in for the
    handler the server installs: it must still run, and the listener must
    still be serving when the fire is refused, because that is the window
    the gate exists for.
    """

    from z4j_brain.main import create_app

    port = _free_port()
    settings = _settings(
        migrated_db_url,
        migrated_audit_chain_secret,
        scheduler_grpc_enabled=True,
        scheduler_grpc_insecure=True,
        scheduler_grpc_bind_host="127.0.0.1",
        scheduler_grpc_bind_port=port,
        scheduler_grpc_grace_seconds=0.2,
    )
    previous = signal.getsignal(signal.SIGTERM)
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        assert signal.getsignal(signal.SIGTERM) is not previous
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            stub = pb_grpc.SchedulerServiceStub(channel)
            await stub.Ping(pb.PingRequest(), timeout=10)

            signal.raise_signal(signal.SIGTERM)

            assert recorded_signals == ["previous:SIGTERM"]
            with pytest.raises(grpc.aio.AioRpcError) as refused:
                await stub.FireSchedule(
                    pb.FireScheduleRequest(
                        schedule_id=str(uuid.uuid4()),
                        fire_id=str(uuid.uuid4()),
                    ),
                    timeout=10,
                )
            assert refused.value.code() is grpc.StatusCode.UNAVAILABLE
            assert "shutting down" in (refused.value.details() or "")
            # Still inside the lifespan: the listener has not been stopped.
            await stub.Ping(pb.PingRequest(), timeout=10)

    assert signal.getsignal(signal.SIGTERM) is previous
