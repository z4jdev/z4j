"""Pool sizing must be operator-configurable, and its defaults must not move.

Until 1.8.0 ``pool_size`` and ``max_overflow`` were hardcoded in
``create_engine_from_settings``. That made the brain's connection demand
impossible to fit to a server the operator does not control, which is a hard
stop for anyone on managed PostgreSQL with a low connection cap, sharing a
server, or running more than one brain.

The arithmetic is what makes it matter. Each uvicorn worker builds its own
engine and ``z4j serve`` defaults to ``max(1, min(4, cpu_count))`` workers, so
worst-case backend demand is::

    workers * (database_pool_size + database_max_overflow)

At the defaults on a 4-core host that is ``4 * (20 + 10) = 120``, which exceeds
a stock PostgreSQL ``max_connections`` of 100 by itself, leaving nothing for a
second brain, a standalone scheduler, or a superuser slot to debug with.

Two things are pinned here:

1. the settings actually reach the engine, so the knob is real rather than
   decorative; and
2. the defaults are exactly what shipped before, so no existing deployment
   silently changes its connection demand on upgrade.
"""

from __future__ import annotations

import os
import secrets
from typing import ClassVar

import pytest
from z4j_brain.settings import Settings

# What was hardcoded before 1.8.0. Changing these changes the connection
# demand of every existing deployment on upgrade, so they are asserted
# literally rather than read back from the model.
_SHIPPED_POOL_SIZE = 20
_SHIPPED_MAX_OVERFLOW = 10

# `z4j serve` default, from cli.py: max(1, min(4, cpu_count)).
_MAX_DEFAULT_WORKERS = 4


def _settings(**overrides: object) -> Settings:
    fields: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
    }
    fields.update(overrides)
    return Settings(**fields)  # type: ignore[arg-type]


def test_defaults_match_what_shipped_before_they_were_configurable() -> None:
    settings = _settings()

    assert settings.database_pool_size == _SHIPPED_POOL_SIZE
    assert settings.database_max_overflow == _SHIPPED_MAX_OVERFLOW


def test_worst_case_demand_at_defaults_is_documented_as_120() -> None:
    """The number that makes this setting necessary, pinned so it stays true.

    If a future change alters the defaults or the worker cap, this fails and
    whoever made the change has to look at the sizing guidance in
    docs/DATABASE.md rather than discovering it in production.
    """
    settings = _settings()
    per_worker = settings.database_pool_size + settings.database_max_overflow

    assert per_worker == 30
    assert per_worker * _MAX_DEFAULT_WORKERS == 120
    # The point of the whole exercise: the default exceeds a stock server.
    assert per_worker * _MAX_DEFAULT_WORKERS > 100


@pytest.mark.parametrize(
    ("pool_size", "max_overflow"),
    [
        # The smallest a PostgreSQL brain may be, which is not a small
        # number: every leader-gated worker this configuration starts holds
        # an advisory-lock connection while working on a second one, and they
        # all start at once. Settings refuses anything below that.
        (2, 2),
        (5, 2),  # a managed instance with a tight cap
        (40, 20),  # scaled up deliberately
    ],
)
def test_settings_reach_the_engine(pool_size: int, max_overflow: int) -> None:
    """The knob must be wired, not merely present on the model.

    Uses a PostgreSQL URL, which is both the faithful case (pool sizing exists
    for a server with a connection cap) and the only one that can be asserted:
    ``sqlite+aiosqlite:///:memory:`` resolves to ``StaticPool``, which rejects
    ``pool_size``/``max_overflow`` outright. ``create_async_engine`` is lazy, so
    no server is contacted.
    """
    from z4j_brain.persistence.database import create_engine_from_settings

    settings = _settings(
        database_url="postgresql+asyncpg://z4j:pw@127.0.0.1:5432/z4j",
        database_pool_size=pool_size,
        database_max_overflow=max_overflow,
    )
    engine = create_engine_from_settings(settings)
    try:
        pool = engine.pool
        assert pool.size() == pool_size
        # SQLAlchemy exposes the configured overflow as a private attribute;
        # there is no public accessor, and asserting it is the only way to
        # prove the value was not silently dropped.
        assert pool._max_overflow == max_overflow
    finally:
        engine.sync_engine.dispose()


def test_environment_variables_drive_the_settings() -> None:
    """Operators set these via Z4J_*, not by editing code."""
    import os
    from unittest.mock import patch

    with patch.dict(
        os.environ,
        {"Z4J_DATABASE_POOL_SIZE": "7", "Z4J_DATABASE_MAX_OVERFLOW": "3"},
        clear=False,
    ):
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
        )

    assert settings.database_pool_size == 7
    assert settings.database_max_overflow == 3


def test_bounds_reject_nonsense() -> None:
    with pytest.raises(ValueError, match="database_pool_size"):
        _settings(database_pool_size=0)
    with pytest.raises(ValueError, match="database_max_overflow"):
        _settings(database_max_overflow=-1)


def test_in_memory_sqlite_builds_an_engine() -> None:
    """The regression a 1.8 feature introduced.

    Pool sizing was passed to create_engine unconditionally. SQLAlchemy gives
    an in-memory SQLite database a StaticPool, which has no size and rejects
    those arguments, so engine construction died with an opaque
    "Invalid argument(s) 'pool_size','max_overflow'".

    It went unnoticed because both deployment-shaped URLs work: PostgreSQL and
    file-backed SQLite each get a real queue pool.
    """
    import secrets as _secrets

    from z4j_brain.persistence.database import create_engine_from_settings
    from z4j_brain.settings import Settings

    engine = create_engine_from_settings(
        Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            audit_chain_secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
        ),
    )

    assert engine.pool.__class__.__name__ == "StaticPool"


@pytest.mark.asyncio
async def test_runtime_sqlite_factory_enables_foreign_keys() -> None:
    """Every factory-created SQLite connection enforces declared FK actions."""

    from sqlalchemy import text
    from z4j_brain.persistence.database import create_engine_from_settings

    engine = create_engine_from_settings(_settings())
    try:
        async with engine.connect() as connection:
            assert await connection.scalar(text("PRAGMA foreign_keys")) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_database_manager_repairs_preused_and_tampered_sqlite_connection() -> None:
    """Injected engines and pooled connections cannot retain FK-off state."""

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool
    from z4j_brain.persistence.database import DatabaseManager

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        # The caller used StaticPool before handing the engine to the app.
        async with engine.connect() as connection:
            assert await connection.scalar(text("PRAGMA foreign_keys")) == 0

        db = DatabaseManager(engine)
        async with db.session() as session:
            assert await session.scalar(text("PRAGMA foreign_keys")) == 1
            await session.execute(text("PRAGMA foreign_keys = OFF"))
            assert await session.scalar(text("PRAGMA foreign_keys")) == 0

        # Checkout enforcement repairs even deliberate connection-local
        # tampering before the next request/background worker receives it.
        async with db.session() as session:
            assert await session.scalar(text("PRAGMA foreign_keys")) == 1
    finally:
        await engine.dispose()


def test_file_backed_sqlite_still_gets_a_sized_pool() -> None:
    """Negative control: the fix must not disable sizing where it applies."""
    import secrets as _secrets
    import tempfile

    from z4j_brain.persistence.database import create_engine_from_settings
    from z4j_brain.settings import Settings

    directory = tempfile.mkdtemp()
    engine = create_engine_from_settings(
        Settings(
            database_url=f"sqlite+aiosqlite:///{directory}/pool.db",
            secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            audit_chain_secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            database_pool_size=7,
        ),
    )

    assert engine.pool.__class__.__name__ == "AsyncAdaptedQueuePool"
    assert engine.pool.size() == 7


class TestPostgresConnectionFloor:
    """The floor has to cover every connection held at the same moment.

    Every leader-gated background worker takes a SESSION-scoped advisory lock
    on a connection of its own and keeps that connection checked out for the
    whole tick (a session lock belongs to its physical connection, so handing
    it back releases the lock), then does its work on a second one.

    The count is what makes this a floor rather than a pair. The lock ids are
    per worker, so two gated workers do not serialise each other, and the
    supervisor spawns all of them together with every first tick running
    immediately. A configuration that starts N of them can therefore have N
    lock connections checked out with none of the work started, and a pool
    that small deadlocks on itself: every worker is waiting for a connection
    that only another worker can release, and releasing it is what they are
    all waiting to do.
    """

    def _settings(self, **over):
        import secrets

        from z4j_brain.settings import Settings

        base = {
            "database_url": "postgresql+asyncpg://z4j:pw@127.0.0.1:5432/z4j",
            "secret": secrets.token_urlsafe(48),
            "session_secret": secrets.token_urlsafe(48),
            "audit_chain_secret": secrets.token_urlsafe(48),
            "environment": "dev",
            "log_json": False,
            "database_pool_size": 40,
            "database_max_overflow": 20,
        }
        base.update(over)
        return Settings(**base)

    #: Configurations whose worker sets differ, so the floor cannot be a
    #: constant that happens to fit one of them.
    _SHAPES: ClassVar[list] = [
        pytest.param({}, id="standalone-defaults"),
        pytest.param({"scheduler_grpc_enabled": True}, id="with-the-scheduler"),
        pytest.param({"embedded_scheduler": True}, id="embedded"),
        pytest.param(
            {"embedded_scheduler": True, "audit_chain_verify_enabled": True},
            id="embedded-plus-scheduled-verification",
        ),
        pytest.param(
            {"scheduler_grpc_enabled": True, "scheduler_misfire_sweep_seconds": 0},
            id="scheduler-with-misfire-detection-off",
        ),
    ]

    @pytest.mark.parametrize("shape", _SHAPES)
    def test_the_floor_is_a_connection_per_holder_plus_one(self, shape) -> None:
        """The arithmetic, stated against the set it is derived from.

        Not a number written down twice: the left side counts the workers this
        configuration starts and the right side is what the product refuses
        below, so a worker added to one without the other fails here.
        """
        settings = self._settings(**shape)
        expected = len(settings.leader_gated_worker_names()) + 1
        if settings.embedded_scheduler:
            expected += 1

        assert settings.minimum_postgres_pool_total() == expected

    @pytest.mark.parametrize("shape", _SHAPES)
    def test_one_below_the_floor_is_refused_and_the_floor_is_accepted(self, shape) -> None:
        """Both controls, because either alone proves nothing.

        A check that only refuses would pass if it refused everything, and a
        check that only accepts would pass if it were not there at all.
        """
        floor = self._settings(**shape).minimum_postgres_pool_total()

        with pytest.raises(Exception) as excinfo:
            self._settings(
                **shape,
                database_pool_size=floor - 1,
                database_max_overflow=0,
            )
        assert f"at least {floor}" in str(excinfo.value)

        accepted = self._settings(
            **shape,
            database_pool_size=floor,
            database_max_overflow=0,
        )
        assert accepted.database_pool_size + accepted.database_max_overflow == floor

    def test_the_floor_counts_the_scheduler_workers_embedded_mode_turns_on(self) -> None:
        """``embedded_scheduler`` does not merely add a lease.

        ``create_app`` forces ``scheduler_grpc_enabled`` on a COPY of these
        settings, and a copy does not re-run validation, so a floor derived
        without applying that implication is derived from a smaller set of
        workers than the process actually starts.
        """
        standalone = self._settings()
        embedded = self._settings(embedded_scheduler=True)

        assert set(standalone.leader_gated_worker_names()) < set(
            embedded.leader_gated_worker_names(),
        ), "embedded mode did not pick up the scheduler's leader-gated workers"
        assert "pending_fires_replay_worker" in embedded.leader_gated_worker_names()

    def test_sqlite_is_unaffected(self) -> None:
        """The lock no-ops on SQLite, which is single-writer, so it can be 1."""
        s = self._settings(
            database_url="sqlite+aiosqlite:///./z4j.db",
            database_pool_size=1,
            database_max_overflow=0,
        )
        assert s.database_pool_size == 1


@pytest.mark.asyncio
async def test_the_gated_worker_set_is_the_one_the_app_actually_starts(
    tmp_path,
    monkeypatch,
) -> None:
    """The floor's input, read off the assembled app rather than believed.

    ``Settings`` cannot import ``create_app`` to count the workers it starts,
    so it names them. A name list is a copy, and a copy drifts: a worker added
    to the app behind a leader lock, or one removed from it, changes the number
    of connections held at boot and would leave the floor describing a process
    that no longer exists.

    Measured by running each registered worker's first tick with the lock
    acquisition instrumented, which is how the workers themselves decide
    whether they lead. A gated worker asks; an ungated one does not. Both
    directions are asserted, so a new gated worker missing from the list fails
    here and so does a name in the list that nothing takes.
    """
    import contextlib
    import secrets

    from z4j_brain.domain.workers import _leader_lock
    from z4j_brain.main import create_app
    from z4j_brain.settings import Settings

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'floor.db'}",
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=secrets.token_urlsafe(48),
        environment="dev",
        log_json=False,
        registry_backend="local",
        disable_spa_fallback=True,
        # Every optional worker on, so the measurement covers the whole set
        # rather than the subset a default configuration happens to start.
        scheduler_grpc_enabled=True,
        audit_chain_verify_enabled=True,
    )
    app = create_app(settings)
    asked: list[str] = []

    async def _record(db, name, *, announce=True):
        asked.append(name)
        # None is "another replica holds it", so the tick no-ops and this
        # measures which workers ASK rather than what their work does.
        return

    monkeypatch.setattr(_leader_lock, "try_acquire_singleton_lock", _record)

    try:
        for worker in app.state.worker_supervisor._workers:
            # An ungated worker runs its real tick here against an empty
            # database. Whether that tick succeeds is another test's subject;
            # what this one reads is whether it asked to lead.
            with contextlib.suppress(Exception):
                await worker.tick()
    finally:
        # The app was assembled without its lifespan, so nothing else will
        # give this engine's connections back.
        await app.state.db.engine.dispose()

    declared = set(settings.leader_gated_worker_names())
    assert set(asked) == declared, (
        "the workers that take a leader lock are not the ones the pool floor "
        "is derived from; taking a lock but not counted: "
        f"{sorted(set(asked) - declared)}; counted but taking no lock: "
        f"{sorted(declared - set(asked))}"
    )


# ---------------------------------------------------------------------------
# Composed demand, against a real server
#
# The arithmetic above is a claim about how many connections this process holds
# at once. Only PostgreSQL can settle it: on SQLite the singleton lease holds
# no connection and the per-worker lock opens no session, so the composition
# being asserted does not exist there and a SQLite version of this test would
# be a test that cannot fail. Point ``Z4J_TEST_POSTGRES_URL`` at a PostgreSQL
# to run it. No schema is needed; this is about the pool, not the data.
# ---------------------------------------------------------------------------

_POSTGRES_URL = os.environ.get("Z4J_TEST_POSTGRES_URL")

requires_postgres = pytest.mark.skipif(
    _POSTGRES_URL is None,
    reason="advisory-lock connection holding is PostgreSQL behaviour",
)

#: How long the work session may wait for a connection before the tick is, for
#: every practical purpose, stopped. Far below SQLAlchemy's 30s default
#: checkout timeout so an exhausted pool fails here instead of passing slowly.
_CHECKOUT_BUDGET_S: float = 5.0


def _asyncpg_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"postgresql+asyncpg://{rest}" if scheme.startswith("postgresql") else url


async def _every_gated_worker_can_still_work(settings, *, pool_total: int) -> bool:
    """Compose this configuration's whole boot and report whether work happens.

    Not one gate. Every leader-gated worker this configuration starts takes
    its own lock, all of them before any of them works, because that is what
    the supervisor produces: one task per worker, each running its first tick
    immediately, and the lock ids are per worker so none of them waits for
    another to finish. The lease the embedded scheduler holds for the life of
    the process is taken first, for the same reason the lifespan takes it
    first.

    Built from the product's own helpers and the product's own worker names,
    so it composes what the process composes rather than a description of it.
    Returns False when the work session cannot get a connection inside the
    budget, which is what a permanently stalled tick looks like from outside.
    """
    import asyncio
    import contextlib

    from sqlalchemy import text
    from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
    from z4j_brain.domain.workers._leader_lock import (
        acquire_per_worker_lock,
        try_acquire_singleton_lock,
    )
    from z4j_brain.persistence.database import DatabaseManager, create_engine_from_settings

    # The size is applied through a model copy, which is the one way to get a
    # pool BELOW what Settings will construct: the copy skips validation, and
    # the negative control needs a size the product would refuse. The engine
    # is still built by the product's own factory.
    sized = settings.model_copy(
        update={"database_pool_size": pool_total, "database_max_overflow": 0},
    )
    engine = create_engine_from_settings(sized)
    db = DatabaseManager(engine)
    try:
        async with contextlib.AsyncExitStack() as stack:
            if settings.embedded_scheduler:
                lease = await try_acquire_singleton_lock(
                    db,
                    "embedded_scheduler_supervisor",
                )
                assert lease is not None, "nothing else should hold this lock in a test"
                stack.push_async_callback(lease.release)

            for name in settings.leader_gated_worker_names():
                got = await stack.enter_async_context(acquire_per_worker_lock(db, name))
                if not got:
                    # Nothing else holds these locks here, so the only way to
                    # fail to take one is to fail to get a connection to take
                    # it on. That worker's tick did not run either, which is
                    # the same answer as the work session stalling below.
                    return False

            try:
                async with db.session() as work:
                    await asyncio.wait_for(
                        work.execute(text("SELECT 1")),
                        timeout=_CHECKOUT_BUDGET_S,
                    )
            except (TimeoutError, SQLAlchemyTimeoutError):
                # Either the budget ran out or SQLAlchemy gave up on the
                # checkout first. Both are the same stall.
                return False
        return True
    finally:
        await engine.dispose()


def _postgres_base(**over: object) -> dict[str, object]:
    import secrets as _secrets

    base: dict[str, object] = {
        "database_url": _asyncpg_url(_POSTGRES_URL or ""),
        "secret": _secrets.token_urlsafe(48),
        "session_secret": _secrets.token_urlsafe(48),
        "audit_chain_secret": _secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
        "embedded_scheduler": True,
    }
    base.update(over)
    return base


def _smallest_accepted_total(base: dict[str, object]) -> int:
    """The smallest pool total Settings will construct for this configuration.

    Asked of the product rather than written down here, so this test measures
    the floor that ships instead of a copy of it that can drift.
    """
    for total in range(1, 40):
        try:
            Settings(**{**base, "database_pool_size": total, "database_max_overflow": 0})  # type: ignore[arg-type]
        except Exception:
            # Refused at this size; keep walking up to the boundary.
            continue
        return total
    msg = "Settings accepted no pool total at all"
    raise AssertionError(msg)


@requires_postgres
@pytest.mark.parametrize(
    "shape",
    [
        pytest.param({"embedded_scheduler": False}, id="standalone"),
        pytest.param({"embedded_scheduler": True}, id="embedded"),
        pytest.param(
            {"embedded_scheduler": True, "audit_chain_verify_enabled": True},
            id="embedded-plus-scheduled-verification",
        ),
    ],
)
@pytest.mark.asyncio
async def test_the_smallest_accepted_pool_still_lets_a_gated_tick_run(shape) -> None:
    """The composed demand, measured rather than reasoned about.

    Driven at whatever minimum Settings currently accepts, so it states the
    invariant (nothing Settings accepts may be unrunnable) rather than a
    number that has to be kept in step by hand. Both controls are here: one
    connection below that minimum has to stall, or the assertion above would
    hold for a floor of any size at all, including one that is simply too
    large to fail.
    """
    base = _postgres_base(**shape)
    minimum = _smallest_accepted_total(base)
    settings = Settings(  # type: ignore[arg-type]
        **{**base, "database_pool_size": minimum, "database_max_overflow": 0},
    )
    holders = len(settings.leader_gated_worker_names()) + (1 if settings.embedded_scheduler else 0)

    assert await _every_gated_worker_can_still_work(settings, pool_total=minimum), (
        f"Settings accepts a pool total of {minimum} and a leader-gated tick "
        f"cannot run on it: this configuration holds {holders} connections "
        "for locks alone before any work starts"
    )

    assert not await _every_gated_worker_can_still_work(
        settings,
        pool_total=minimum - 1,
    ), (
        f"a pool of {minimum - 1} was expected to stall with {holders} lock "
        "holders on it; if work still happens at that size the floor is "
        "higher than the demand and this test proves nothing about it"
    )
