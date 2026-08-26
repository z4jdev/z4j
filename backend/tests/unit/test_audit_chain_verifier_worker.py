"""The scheduled audit-chain verifier.

The distinction this worker has to keep straight is "the chain did not
verify" versus "the verification did not run". Conflating them either lets a
database blip read as evidence of tampering, or lets tampering read as a
blip. Both are worse than reporting nothing.

The second property is that it never raises. A verifier that can take the
brain down turns a detection mechanism into an outage mechanism, and the
operator who gets burned by that switches it off, which leaves the chain
unwatched.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
from types import SimpleNamespace

import pytest
import structlog.testing
from z4j_brain.domain.workers import audit_verifier as worker_mod
from z4j_brain.domain.workers.audit_verifier import AuditChainVerifierWorker
from z4j_brain.persistence.database import DatabaseManager, create_engine_from_settings
from z4j_brain.persistence.statement_timeout import install_statement_timeouts
from z4j_brain.settings import Settings


class _Report:
    """Stands in for AuditVerificationReport.

    Every field the worker logs has to exist here. Both log calls sit outside
    the try, so a field this stand-in is missing raises out of ``tick`` and
    breaks the never-raises contract without any test naming that field.
    """

    def __init__(
        self,
        *,
        mismatches=(),
        head="VALID",
        active=10,
        frozen=5,
        truncated=0,
        unattributed=0,
    ) -> None:
        self.verified_active_rows = active
        self.verified_frozen_rows = frozen
        self.mismatches = tuple(mismatches)
        self.known_head_result = head
        self.mismatches_truncated = truncated
        self.unattributed_rows = unattributed

    @property
    def clean(self) -> bool:
        return not self.mismatches and self.known_head_result not in {
            "INVALID",
            "UNPROVABLE",
        }


class _FakeDb:
    """Minimal DatabaseManager stand-in.

    The worker opens a session and asks the engine's dialect whether the
    backend has advisory locks. SQLite does not, which is a real deployment
    of this product and the one these tests describe: the leader gate is a
    no-op there because a single-writer database cannot have two writers.
    """

    engine = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def session(self):
        import contextlib

        @contextlib.asynccontextmanager
        async def _cm():
            yield object()

        return _cm()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


def _patch_verifier(monkeypatch, result) -> list[dict]:
    """Replace the verifier; return a list that records each call."""
    calls: list[dict] = []

    async def _fake(session, settings, *, page_size, known_head=None):
        calls.append({"page_size": page_size})
        if isinstance(result, Exception):
            raise result
        return result

    import z4j_brain.domain.audit_verifier as verifier_mod

    monkeypatch.setattr(verifier_mod, "verify_active_audit_generation", _fake)
    return calls


@pytest.mark.asyncio
async def test_a_clean_chain_is_recorded_as_clean(monkeypatch, settings, caplog) -> None:
    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod, "_observe", lambda m, *, outcome, rows=0: outcomes.append(outcome)
    )
    _patch_verifier(monkeypatch, _Report())

    await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert outcomes == ["clean"]


@pytest.mark.asyncio
async def test_a_chain_that_does_not_verify_is_failed_not_error(monkeypatch, settings) -> None:
    """Tampering found is a different outcome from a run that broke."""
    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod, "_observe", lambda m, *, outcome, rows=0: outcomes.append(outcome)
    )
    _patch_verifier(monkeypatch, _Report(mismatches=("row 41 hmac mismatch",)))

    await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert outcomes == ["failed"]


@pytest.mark.asyncio
async def test_a_run_that_cannot_complete_is_error_not_failed(monkeypatch, settings) -> None:
    """The inverse, and the more dangerous confusion of the two.

    Reporting a database outage as "chain did not verify" would send an
    operator hunting for tampering that never happened.
    """
    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod, "_observe", lambda m, *, outcome, rows=0: outcomes.append(outcome)
    )
    _patch_verifier(monkeypatch, RuntimeError("database went away"))

    await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert outcomes == ["error"]


@pytest.mark.asyncio
async def test_an_unprovable_head_counts_as_failed(monkeypatch, settings) -> None:
    """No mismatched rows, but the head cannot be proven, so not clean."""
    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod, "_observe", lambda m, *, outcome, rows=0: outcomes.append(outcome)
    )
    _patch_verifier(monkeypatch, _Report(head="UNPROVABLE"))

    await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert outcomes == ["failed"]


@pytest.mark.asyncio
async def test_the_worker_never_raises(monkeypatch, settings) -> None:
    """A detection mechanism must not become an outage mechanism."""
    _patch_verifier(monkeypatch, RuntimeError("boom"))

    # It returns rather than raising, and what it returns is a short retry.
    # Returning None here would hand the supervisor the whole configured
    # interval -- a day by default, and up to a week at the accepted bound --
    # so a single transient error would suppress verification for that long.
    delay = await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert delay is not None
    assert 0 < delay < settings.audit_chain_verify_interval_seconds


@pytest.mark.asyncio
async def test_a_persistent_error_backs_off_and_stops_at_the_interval() -> None:
    """Short retries are for a blip, not a way to hammer a broken database.

    The walk takes the same lock every audit write queues behind, so retrying
    a chain that is genuinely unreachable at the shortest delay forever would
    cost an operator more than the answer is worth.
    """
    import z4j_brain.domain.audit_verifier as verifier_mod

    tight = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        audit_chain_verify_interval_seconds=900,
    )

    async def _broken(session, settings, *, page_size, known_head=None):
        raise RuntimeError("database is still gone")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(verifier_mod, "verify_active_audit_generation", _broken)
        worker = AuditChainVerifierWorker(db=_FakeDb(), settings=tight)
        delays = [await worker.tick() for _ in range(8)]

    assert delays[0] < delays[1] < delays[2], "consecutive errors must back off"
    assert max(delays) <= tight.audit_chain_verify_interval_seconds
    assert delays[-1] == tight.audit_chain_verify_interval_seconds


@pytest.mark.asyncio
async def test_a_completed_run_returns_to_the_configured_cadence(monkeypatch, settings) -> None:
    """The short retry is for the error, and only for as long as it lasts."""
    worker = AuditChainVerifierWorker(db=_FakeDb(), settings=settings)

    _patch_verifier(monkeypatch, RuntimeError("blip"))
    first = await worker.tick()
    assert first is not None

    _patch_verifier(monkeypatch, _Report())
    assert await worker.tick() is None, "a completed run takes the operator's interval"

    # And the next error starts over from the shortest retry rather than
    # carrying the old failure count forward.
    _patch_verifier(monkeypatch, RuntimeError("later blip"))
    assert await worker.tick() == first


@pytest.mark.asyncio
async def test_the_startup_walk_is_not_immediately_repeated(monkeypatch, settings) -> None:
    """Startup verifies the whole chain, then the supervisor ticks at once.

    Two full walks seconds apart answer the same question twice and take the
    blocking chain lock twice, which on a large log is the difference between
    a brain that serves promptly after boot and one that does not.
    """
    calls = _patch_verifier(monkeypatch, _Report())
    worker = AuditChainVerifierWorker(db=_FakeDb(), settings=settings)
    worker.note_already_verified()

    await worker.tick()
    assert calls == [], "the walk startup already did must not be repeated"

    await worker.tick()
    assert len(calls) == 1, "only the tick startup paid for is skipped"


@pytest.mark.asyncio
async def test_broken_metrics_do_not_lose_the_result(monkeypatch, settings) -> None:
    """The log is the record; metrics are decoration.

    A counter that raises must cost the counter and nothing else. Calling
    ``tick`` and asserting nothing only re-checks that it returned, which
    ``test_the_worker_never_raises`` already owns; the property this one is
    named for is that the verification result is IN the log afterwards, and
    that a broken counter is not mistaken for a run that could not complete.
    """

    class _AngryCounter:
        def labels(self, **_kw):
            raise RuntimeError("registry is unhappy")

    import z4j_brain.api.metrics as metrics_mod

    monkeypatch.setattr(
        metrics_mod, "z4j_audit_chain_verifications_total", _AngryCounter(), raising=False
    )
    _patch_verifier(monkeypatch, _Report(active=10, frozen=5))

    with structlog.testing.capture_logs() as logged:
        delay = await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    recorded = [entry for entry in logged if "chain verified" in entry.get("event", "")]
    assert len(recorded) == 1, (
        "the counter raised and took the verification result with it; the "
        "chain verified and nothing says so"
    )
    assert recorded[0]["log_level"] == "info"
    assert recorded[0]["rows_verified"] == 15
    # A metrics failure is not a run that could not complete. Reported as one
    # it would put the worker on the short retry and send an operator looking
    # for a database problem that is not there.
    assert delay is None
    assert [entry for entry in logged if entry.get("log_level") == "error"] == []


@pytest.mark.asyncio
async def test_page_size_is_within_the_verifier_bounds(monkeypatch, settings) -> None:
    """The verifier rejects anything outside 1..5000."""
    calls = _patch_verifier(monkeypatch, _Report())

    await AuditChainVerifierWorker(db=_FakeDb(), settings=settings).tick()

    assert 1 <= calls[0]["page_size"] <= 5000


def test_scheduled_verification_is_opt_in(settings) -> None:
    """Off by default.

    Verification takes a share lock and walks every retained row. An
    operator who has not asked for that should not discover it as a new
    recurring load after an upgrade.
    """
    assert settings.audit_chain_verify_enabled is False


def test_the_interval_floor_prevents_self_inflicted_load(settings) -> None:
    """A tight interval on a large chain is a denial of service, not a
    stronger guarantee."""
    field = Settings.model_fields["audit_chain_verify_interval_seconds"]
    constraints = {type(m).__name__: m for m in field.metadata}

    assert settings.audit_chain_verify_interval_seconds == 86_400
    assert constraints["Ge"].ge == 900


# ---------------------------------------------------------------------------
# Leadership
#
# One replica walks the chain per interval. The walk takes the same blocking
# lock every audit write queues behind, so a second replica walking at the
# same time is not merely wasted work, it is the write path stalled twice
# over for one answer.
#
# The two ways leadership can fail need different responses and the worker is
# the only place that can tell them apart. Losing the race means the answer
# is being produced elsewhere, so there is nothing to retry. Being unable to
# ask means nobody is producing it, and this worker's interval reaches a
# week, so waiting one out is not an acceptable response to a blip.
#
# Only PostgreSQL has advisory locks, so a SQLite version of the race would be
# a test that cannot fail. Point ``Z4J_TEST_POSTGRES_URL`` at a PostgreSQL to
# run those. No schema is needed: the walk itself is not what is under test
# here and is replaced by one of known duration.
# ---------------------------------------------------------------------------

_POSTGRES_URL = os.environ.get("Z4J_TEST_POSTGRES_URL")

requires_postgres = pytest.mark.skipif(
    _POSTGRES_URL is None,
    reason="leader election between replicas is PostgreSQL behaviour",
)

#: Long enough to outlive the idle-in-transaction budget below, which is what
#: a real multi-page walk of a large chain does on a real deployment.
_WALK_SECONDS: float = 2.0


def _postgres_settings(url: str) -> Settings:
    scheme, _, rest = url.partition("://")
    asyncpg_url = f"postgresql+asyncpg://{rest}" if scheme.startswith("postgresql") else url
    return Settings(  # type: ignore[arg-type]
        database_url=asyncpg_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=secrets.token_urlsafe(48),
        environment="dev",
        log_json=False,
        audit_chain_verify_enabled=True,
        # Shorter than the walk, so a leader lock that depends on an open
        # transaction has definitely lost it before the walk ends.
        db_idle_in_tx_timeout_ms=500,
    )


def _replica(settings: Settings) -> DatabaseManager:
    """One brain replica's database access, wired as the app factory wires it."""
    engine = create_engine_from_settings(settings)
    install_statement_timeouts(engine, settings=settings)
    return DatabaseManager(engine)


def _walk_taking(seconds: float, log: list[str], label: str):
    """A chain walk of known duration that records who ran it.

    The walk is not what these tests are about; how long it takes is. A real
    one over a chain big enough to matter runs for minutes, which is not
    something to build in a unit test, and its duration is exactly the
    variable the leadership guarantee has to survive.
    """

    async def _walk(session, settings, *, page_size, known_head=None):
        log.append(label)
        await asyncio.sleep(seconds)
        return _Report()

    return _walk


@requires_postgres
@pytest.mark.asyncio
async def test_a_second_replica_does_not_walk_while_the_first_is_walking() -> None:
    """The guarantee, over a walk longer than any session budget."""
    import z4j_brain.domain.audit_verifier as verifier_mod

    settings = _postgres_settings(_POSTGRES_URL or "")
    first = _replica(settings)
    second = _replica(settings)
    walked: list[str] = []
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                verifier_mod,
                "verify_active_audit_generation",
                _walk_taking(_WALK_SECONDS, walked, "first"),
            )
            leader = asyncio.create_task(
                AuditChainVerifierWorker(db=first, settings=settings).tick(),
            )
            # Let the leader claim the lock and get into its walk.
            await asyncio.sleep(0.5)
            patch.setattr(
                verifier_mod,
                "verify_active_audit_generation",
                _walk_taking(0.0, walked, "second"),
            )
            follower_delay = await AuditChainVerifierWorker(
                db=second,
                settings=settings,
            ).tick()
            await leader

        assert walked == ["first"], (
            "both replicas walked the chain at once, each holding the lock "
            "every audit write waits on"
        )
        assert follower_delay is None, (
            "the replica that lost the race asked to be run again sooner; the "
            "walk it skipped was not skipped, it was done by someone else"
        )
    finally:
        await first.engine.dispose()
        await second.engine.dispose()


def test_the_app_registers_this_worker_ungated() -> None:
    """Wiring tripwire: nothing may wrap this tick in a second leader gate.

    A wrapper cannot see the difference between losing the race and being
    unable to ask, and its own errors reach the supervisor rather than the
    bounded retry this worker owns. Re-adding one puts both back.
    """
    from z4j_brain.main import create_app

    app = create_app(
        Settings(  # type: ignore[arg-type]
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),
            session_secret=secrets.token_urlsafe(48),
            audit_chain_secret=secrets.token_urlsafe(48),
            environment="dev",
            log_json=False,
            audit_chain_verify_enabled=True,
        ),
    )
    registered = [
        w
        for w in app.state.worker_supervisor._workers
        if w.name == AuditChainVerifierWorker.LEADER_LOCK_NAME
    ]

    assert len(registered) == 1, "scheduled verification was enabled but not registered"
    tick = registered[0].tick
    assert isinstance(getattr(tick, "__self__", None), AuditChainVerifierWorker), (
        "the registered tick is not the worker's own, so something is "
        "standing between the supervisor and the worker's retry policy"
    )


@pytest.mark.asyncio
async def test_an_unreachable_database_is_a_short_retry_not_a_raise(monkeypatch) -> None:
    """Being unable to claim leadership is a run that did not happen.

    Raising would hand it to the supervisor, which retries on its own
    schedule rather than this worker's, so a blip would turn a daily
    verification into one running every few seconds. Returning None would be
    worse in the other direction: a whole interval, up to a week, with
    nothing watching the chain.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = int(probe.getsockname()[1])

    settings = _postgres_settings(f"postgresql://z4j:z4j@127.0.0.1:{dead_port}/z4j")
    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod, "_observe", lambda m, *, outcome, rows=0: outcomes.append(outcome)
    )
    db = _replica(settings)
    try:
        delay = await AuditChainVerifierWorker(db=db, settings=settings).tick()
    finally:
        await db.engine.dispose()

    assert delay is not None, "an interval of up to a week was taken for a blip"
    assert 0 < delay < settings.audit_chain_verify_interval_seconds
    assert outcomes == ["error"], (
        "a run that never started was not recorded, so the gap in the "
        "continuous record has no explanation in it"
    )
