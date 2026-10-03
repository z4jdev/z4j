"""The audit forwarder's durable cursor.

What these tests hold the forwarder to, in the order an operator would
ask: a receiver that is down for an hour and comes back gets every row,
in order, with no gaps; a 500 backs the forwarder off without moving
the cursor; a restart resumes at the cursor; two forwarders under the
leader lease never both send the same row; and the request on the wire
is byte for byte what the previous forwarder sent, so receivers written
against it keep verifying.

The receiver is a fake installed over ``_post``; the database is a real
SQLite file so the cursor survives constructing a second forwarder over
it, which is what a restart is.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain import audit_forwarder as af_mod
from z4j_brain.domain.audit_forwarder import (
    AUDIT_SCHEMA_HEADER,
    AUDIT_SIGNATURE_HEADER,
    AUDIT_TIMESTAMP_HEADER,
    AuditForwarder,
    backoff_seconds,
    row_to_payload,
)
from z4j_brain.domain.workers import _leader_lock
from z4j_brain.persistence import models  # noqa: F401  - register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditForwardState, AuditLog
from z4j_brain.persistence.repositories.audit_forward_state import (
    AuditForwardStateRepository,
)
from z4j_brain.settings import Settings

SECRET = b"s" * 32
URL = "https://siem.example.test/ingest"
T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: Path) -> Any:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'forwarder.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    manager = DatabaseManager(engine)
    yield manager
    await engine.dispose()


class _Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class _Receiver:
    """A webhook receiver the test can take down, break, or slow."""

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, dict[str, str]]] = []
        self.attempts = 0
        self.down = False
        self.status = 200
        self.fail_after: int | None = None
        self.hang: asyncio.Event | None = None
        self.on_post: Any = None

    async def post(
        self,
        url: str,
        *,
        content: bytes,
        headers: dict[str, str],
        pin_ip: str | None = None,
        timeout: float | None = None,  # noqa: ASYNC109  mirrors the _post helper kwarg
    ) -> httpx.Response:
        self.attempts += 1
        if self.on_post is not None:
            await self.on_post()
        if self.hang is not None:
            self.hang.set()
            await asyncio.Event().wait()
        if self.down:
            raise httpx.ConnectError("receiver down")
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            return httpx.Response(503, content=b"overloaded")
        if self.status != 200:
            return httpx.Response(self.status, content=b"err")
        await asyncio.sleep(0)
        self.calls.append((content, dict(headers)))
        return httpx.Response(200, content=b"ok")

    def received_ids(self) -> list[str]:
        return [json.loads(body)["id"] for body, _ in self.calls]


@pytest.fixture
def receiver(monkeypatch: pytest.MonkeyPatch) -> _Receiver:
    r = _Receiver()
    monkeypatch.setattr(af_mod, "_post", r.post)

    async def _pin(_url: str) -> tuple[str | None, str | None]:
        return None, "203.0.113.1"

    monkeypatch.setattr(af_mod, "resolve_and_pin", _pin)
    return r


def _forwarder(
    db: DatabaseManager,
    clock: _Clock,
    *,
    batch_size: int = 10,
    max_backoff: float = 300.0,
) -> AuditForwarder:
    return AuditForwarder(
        db=db,
        webhook_url=URL,
        hmac_secret=SECRET,
        batch_size=batch_size,
        max_backoff_seconds=max_backoff,
        clock=clock,
    )


async def _seed(db: DatabaseManager, n: int, *, start: datetime = T0) -> list[str]:
    """Append ``n`` audit rows one second apart; return their ids in chain order."""
    ids: list[str] = []
    async with db.session(write=True) as session:
        for i in range(n):
            row = AuditLog(
                id=uuid.uuid4(),
                action="test.event",
                target_type="thing",
                target_id=str(i),
                result="success",
                outcome="allow",
                audit_metadata={"i": i, "note": "café"},
                occurred_at=start + timedelta(seconds=i),
                row_hmac=f"{i:064x}",
            )
            session.add(row)
            ids.append(str(row.id))
        await session.commit()
    return ids


async def _state(db: DatabaseManager) -> AuditForwardState:
    async with db.session() as session:
        state = await AuditForwardStateRepository(session).get_for_sink("default")
        assert state is not None
        return state


async def _initialise_empty_cursor(db: DatabaseManager, clock: _Clock) -> None:
    """Create the state row while the log is empty, so every later row counts."""
    outcome = await _forwarder(db, clock).forward_once()
    assert outcome.status == "idle"
    state = await _state(db)
    assert state.last_forwarded_id is None


# ---------------------------------------------------------------------------
# Delivery contract
# ---------------------------------------------------------------------------


async def test_first_pass_starts_at_the_head_and_mirrors_rows_written_after(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    """Enabling the forwarder does not replay the retained history."""
    before = await _seed(db, 3)
    clock = _Clock()
    fwd = _forwarder(db, clock)

    first = await fwd.forward_once()

    assert first.status == "idle"
    assert receiver.calls == []
    state = await _state(db)
    assert str(state.last_forwarded_id) == before[-1]

    after = await _seed(db, 2, start=T0 + timedelta(minutes=1))
    second = await fwd.forward_once()

    assert second.status == "sent" and second.sent == 2
    assert receiver.received_ids() == after


async def test_receiver_down_for_an_hour_then_recovering_gets_every_row_in_order(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    seeded = await _seed(db, 250)
    fwd = _forwarder(db, clock, batch_size=40)

    receiver.down = True
    for _ in range(720):  # one simulated hour at the five-second poll
        clock.advance(5)
        await fwd.tick()
    outage_attempts = receiver.attempts

    assert receiver.calls == []
    # Backoff did real work: far fewer attempts than polls, but still retrying.
    assert 5 <= outage_attempts <= 40, outage_attempts
    state = await _state(db)
    assert state.last_forwarded_id is None
    assert state.consecutive_failures == outage_attempts
    assert fwd.last_pass is not None and fwd.last_pass.status in {"backoff", "failed"}

    receiver.down = False
    for _ in range(100):
        clock.advance(5)
        delay = await fwd.tick()
        if delay is None and fwd.last_pass is not None and fwd.last_pass.status == "idle":
            break

    assert receiver.received_ids() == seeded
    state = await _state(db)
    assert str(state.last_forwarded_id) == seeded[-1]
    assert state.consecutive_failures == 0
    assert state.last_success_at is not None
    assert fwd.sent_count == 250


async def test_a_500_backs_off_without_moving_the_cursor(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    await _seed(db, 3)
    fwd = _forwarder(db, clock)
    receiver.status = 500

    first = await fwd.forward_once()
    assert first.status == "failed" and first.sent == 0
    assert receiver.attempts == 1
    state = await _state(db)
    assert state.last_forwarded_id is None
    assert state.consecutive_failures == 1
    assert state.last_success_at is None

    # Inside the one-second wait after the first failure: no attempt.
    again = await fwd.forward_once()
    assert again.status == "backoff"
    assert receiver.attempts == 1

    clock.advance(1)
    assert (await fwd.forward_once()).status == "failed"
    assert receiver.attempts == 2
    assert (await _state(db)).consecutive_failures == 2

    # The wait has doubled: one second in is still too soon, two is due.
    clock.advance(1)
    assert (await fwd.forward_once()).status == "backoff"
    clock.advance(1)
    assert (await fwd.forward_once()).status == "failed"
    assert receiver.attempts == 3

    receiver.status = 200
    clock.advance(4)
    recovered = await fwd.forward_once()

    assert recovered.status == "sent" and recovered.sent == 3
    state = await _state(db)
    assert state.consecutive_failures == 0
    assert state.last_forwarded_id is not None


def test_backoff_doubles_from_one_second_and_is_capped() -> None:
    assert backoff_seconds(0, 300.0) == 0.0
    assert [backoff_seconds(n, 300.0) for n in range(1, 6)] == [1.0, 2.0, 4.0, 8.0, 16.0]
    assert backoff_seconds(9, 300.0) == 256.0
    assert backoff_seconds(10, 300.0) == 300.0
    assert backoff_seconds(10_000, 300.0) == 300.0


async def test_a_restart_mid_stream_resumes_at_the_cursor(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    seeded = await _seed(db, 5)
    receiver.fail_after = 2

    first_process = _forwarder(db, clock)
    outcome = await first_process.forward_once()
    assert outcome.status == "failed" and outcome.sent == 2
    assert str((await _state(db)).last_forwarded_id) == seeded[1]
    del first_process

    receiver.fail_after = None
    clock.advance(60)
    second_process = _forwarder(db, clock)
    resumed = await second_process.forward_once()

    assert resumed.status == "sent" and resumed.sent == 3
    assert receiver.received_ids() == seeded
    assert str((await _state(db)).last_forwarded_id) == seeded[-1]


async def test_cancellation_during_a_post_leaves_the_row_at_the_cursor(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    """A brain stopping mid-request re-sends that row after the restart."""
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    seeded = await _seed(db, 2)
    receiver.hang = asyncio.Event()

    task = asyncio.create_task(_forwarder(db, clock).tick())
    await asyncio.wait_for(receiver.hang.wait(), timeout=5.0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert (await _state(db)).last_forwarded_id is None
    receiver.hang = None
    assert (await _forwarder(db, clock).forward_once()).sent == 2
    assert receiver.received_ids() == seeded


async def test_two_forwarders_under_the_lease_do_not_double_send(
    db: DatabaseManager, receiver: _Receiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two replicas, one lock: every row reaches the receiver exactly once."""
    held: set[str] = set()

    class _Lease:
        def __init__(self, name: str) -> None:
            self.name = name

        async def release(self) -> bool:
            held.discard(self.name)
            return True

    async def _fake_lock(_db: Any, name: str, *, announce: bool = True) -> _Lease | None:
        if name in held:
            return None
        held.add(name)
        return _Lease(name)

    monkeypatch.setattr(_leader_lock, "try_acquire_singleton_lock", _fake_lock)

    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    seeded = await _seed(db, 30)
    replica_a = _forwarder(db, clock, batch_size=7)
    replica_b = _forwarder(db, clock, batch_size=7)

    lost_the_race = 0
    for _ in range(12):
        await asyncio.gather(replica_a.tick(), replica_b.tick())
        lost_the_race += sum(
            1
            for replica in (replica_a, replica_b)
            if replica.last_pass is not None and replica.last_pass.status == "not_leader"
        )

    assert lost_the_race > 0, "the lease never serialised the two replicas"
    assert receiver.received_ids() == seeded
    assert replica_a.sent_count + replica_b.sent_count == 30
    assert str((await _state(db)).last_forwarded_id) == seeded[-1]


async def test_a_cursor_moved_by_another_writer_stops_the_pass_without_rewinding(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    """The compare-and-set is the second line behind the lease."""
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    seeded = await _seed(db, 3)
    foreign_cursor = uuid.UUID(seeded[2])

    async def _someone_else_advances() -> None:
        async with db.session(write=True) as session:
            await session.execute(
                update(AuditForwardState)
                .where(AuditForwardState.sink_id == "default")
                .values(last_forwarded_id=foreign_cursor, last_forwarded_occurred_at=T0)
            )
            await session.commit()

    receiver.on_post = _someone_else_advances
    outcome = await _forwarder(db, clock).forward_once()

    assert outcome.status == "failed" and outcome.sent == 0
    assert (await _state(db)).last_forwarded_id == foreign_cursor


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------


def _legacy_body(payload: dict[str, Any]) -> bytes:
    """The encoding the in-memory forwarder used, frozen here on purpose."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


async def test_body_and_headers_are_byte_identical_to_the_previous_format(
    db: DatabaseManager, receiver: _Receiver
) -> None:
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    (row_id,) = await _seed(db, 1)
    async with db.session() as session:
        row = (
            await session.execute(select(AuditLog).where(AuditLog.id == uuid.UUID(row_id)))
        ).scalar_one()
    expected_body = _legacy_body(row_to_payload(row))

    assert (await _forwarder(db, clock).forward_once()).sent == 1
    ((body, headers),) = receiver.calls

    assert body == expected_body
    assert list(headers) == [
        "Content-Type",
        "X-Z4J-Audit-Signature",
        "X-Z4J-Audit-Timestamp",
        "X-Z4J-Audit-Schema",
    ]
    assert headers["Content-Type"] == "application/json"
    assert headers[AUDIT_SCHEMA_HEADER] == "1"
    timestamp = headers[AUDIT_TIMESTAMP_HEADER]
    assert timestamp.isdigit() and len(timestamp) >= 10
    expected_signature = (
        "sha256="
        + hmac.new(SECRET, timestamp.encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
    )
    assert headers[AUDIT_SIGNATURE_HEADER] == expected_signature
    assert json.loads(body)["metadata"]["note"] == "café"
    assert "\\u00e9" not in body.decode("utf-8")


# ---------------------------------------------------------------------------
# Metrics and settings
# ---------------------------------------------------------------------------


async def test_lag_gauge_and_failure_counter_follow_the_pass(
    db: DatabaseManager, receiver: _Receiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    lag_values: list[int] = []
    reasons: list[str] = []

    class _Gauge:
        def set(self, value: int) -> None:
            lag_values.append(value)

    class _Counter:
        def labels(self, *, reason: str) -> Any:
            reasons.append(reason)
            return SimpleNamespace(inc=lambda: None)

    monkeypatch.setattr(
        af_mod,
        "_metrics",
        SimpleNamespace(
            z4j_audit_forward_lag_rows=_Gauge(),
            z4j_audit_forward_failures_total=_Counter(),
        ),
    )
    clock = _Clock()
    await _initialise_empty_cursor(db, clock)
    await _seed(db, 4)
    fwd = _forwarder(db, clock)

    receiver.status = 503
    assert (await fwd.forward_once()).status == "failed"
    assert lag_values[-1] == 4
    assert reasons == ["non_2xx"]

    receiver.status = 200
    clock.advance(5)
    assert (await fwd.forward_once()).sent == 4
    assert lag_values[-1] == 0


def test_leader_gated_worker_names_include_the_forwarder_only_when_configured() -> None:
    base = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
    }
    off = Settings(**base)  # type: ignore[arg-type]
    on = Settings(  # type: ignore[arg-type]
        **base,
        audit_webhook_url=URL,
        audit_webhook_hmac_secret=secrets.token_urlsafe(48),
    )

    assert "audit_forwarder_worker" not in off.leader_gated_worker_names()
    assert "audit_forwarder_worker" in on.leader_gated_worker_names()
    assert on.audit_webhook_batch_size == 100
    assert on.audit_webhook_poll_interval_seconds == 5.0
    assert on.audit_webhook_max_backoff_seconds == 300.0


def test_forwarder_rejects_degenerate_bounds() -> None:
    with pytest.raises(ValueError, match="batch_size"):
        AuditForwarder(db=SimpleNamespace(), webhook_url=URL, hmac_secret=SECRET, batch_size=0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_backoff_seconds"):
        AuditForwarder(
            db=SimpleNamespace(),  # type: ignore[arg-type]
            webhook_url=URL,
            hmac_secret=SECRET,
            max_backoff_seconds=0.5,
        )


# ---------------------------------------------------------------------------
# Admin status endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def app_settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
        audit_webhook_url=URL,  # type: ignore[arg-type]
        audit_webhook_hmac_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
    )


@pytest.fixture
async def brain_app(app_settings: Settings) -> Any:
    from z4j_brain.main import create_app

    engine = create_async_engine(
        app_settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(app_settings, engine=engine)
    yield app
    await engine.dispose()


async def _seed_user(brain_app: Any, settings: Settings, *, is_admin: bool) -> uuid.UUID:
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.persistence.models import Session, User

    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    async with brain_app.state.db.session() as s:
        s.add(
            User(
                id=user_id,
                email=f"{'admin' if is_admin else 'user'}-{user_id.hex[:6]}@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=is_admin,
                is_active=True,
            )
        )
        await s.flush()
        s.add(
            Session(
                id=session_id,
                user_id=user_id,
                csrf_token=secrets.token_urlsafe(32),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            )
        )
        await s.commit()
    return session_id


def _client(brain_app: Any, settings: Settings, session_id: uuid.UUID | None) -> httpx.AsyncClient:
    from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=brain_app), base_url="http://testserver"
    )
    if session_id is not None:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(session_id),
        )
    return client


async def test_status_endpoint_is_admin_only(brain_app: Any, app_settings: Settings) -> None:
    async with _client(brain_app, app_settings, None) as anonymous:
        assert (await anonymous.get("/api/v1/admin/audit-forwarder")).status_code == 401
    member = await _seed_user(brain_app, app_settings, is_admin=False)
    async with _client(brain_app, app_settings, member) as non_admin:
        assert (await non_admin.get("/api/v1/admin/audit-forwarder")).status_code == 403


async def test_status_endpoint_reports_the_cursor_and_the_backlog(
    brain_app: Any, app_settings: Settings, receiver: _Receiver
) -> None:
    admin = await _seed_user(brain_app, app_settings, is_admin=True)
    forwarder = brain_app.state.audit_forwarder
    assert isinstance(forwarder, AuditForwarder)
    assert "audit_forwarder_worker" in {w.name for w in brain_app.state.worker_supervisor._workers}

    async with _client(brain_app, app_settings, admin) as client:
        before = (await client.get("/api/v1/admin/audit-forwarder")).json()
    assert before["enabled"] is True
    assert before["cursor_initialised"] is False
    assert before["lag_rows"] is None
    assert before["worker"] == "audit_forwarder_worker"

    await forwarder.forward_once()
    await _seed(brain_app.state.db, 2)
    receiver.status = 500
    await forwarder.forward_once()

    async with _client(brain_app, app_settings, admin) as client:
        response = await client.get("/api/v1/admin/audit-forwarder")
    assert response.status_code == 200
    body = response.json()
    assert body["cursor_initialised"] is True
    assert body["lag_rows"] == 2
    assert body["consecutive_failures"] == 1
    assert body["backoff_seconds_remaining"] >= 0.0
    assert body["process_failed_count"] == 1
    assert body["batch_size"] == 100
