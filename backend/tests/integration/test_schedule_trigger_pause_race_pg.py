"""Trigger Now against a hold that commits while the click is in flight.

Real Postgres, because this is a question about two transactions and SQLite
cannot be asked it: every mutating request there reserves the single writer
before its first read, so two clicks are serialised whether or not anything in
the handler asks for it, and a test on SQLite would report a pass it did not
earn.

The window is between "may this schedule fire" and "this command is committed".
Between those two points the handler looks up an agent, writes an audit row and
inserts a command, and a hold that commits anywhere in there is honoured by the
check that already happened and then overtaken by the insert that has not. What
the operator is left with is a schedule reading held and a fire dispatched under
the hold, which is the one outcome a hold exists to prevent.

Three orderings, and they answer different questions:

- the hold takes the row first and the click arrives second. The click must
  see the hold rather than the state it was placed on.
- the hold commits INSIDE the window, after the click has decided it may fire
  and before its command exists. This is the harmful one, and it is the only
  ordering that separates a lock held across both steps from a lock taken for
  the eligibility read and released before the enqueue. A trigger that did the
  latter still answers before the hold commits in the first ordering, and is
  still refused there, so that test alone does not see the difference.
- the click gets there first. Its fire is legitimate and must survive, because
  a hold placed afterwards governs what comes after it.

Nothing here sleeps and hopes. Each test establishes which side of the window
a request is on, from a connection of its own, before it releases anything.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine
from z4j_brain.auth.csrf import CSRF_HEADER_NAME
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.enums import AgentState, ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    Command,
    Membership,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio

_PW = "correct-horse-battery-staple-9"

#: Share of the brain's own ``lock_timeout`` the barrier below is allowed to
#: spend. Postgres cancels a lock wait that outlives that timeout, so a barrier
#: budget anywhere near it would time the cancellation instead of the race. The
#: state it waits for is normally reached in a few milliseconds.
_BARRIER_BUDGET_FRACTION = 0.5


@pytest.fixture(autouse=True)
def _reset_bulk_action_throttle():
    """The trigger route shares a process-wide 10/min bucket."""
    from z4j_brain.domain.ip_rate_limit import _bulk_action_bucket

    _bulk_action_bucket._hits.clear()
    yield
    _bulk_action_bucket._hits.clear()


class _StandInSocket:
    """Enough of a socket for the registry to treat the agent as connected.

    The physical push over this fails, which is not what this file is about:
    the assertion is on the command row the brain committed, which is the thing
    that outlives the request and eventually reaches an agent.
    """


@pytest.fixture
def race_settings(integration_settings: Settings) -> Settings:
    """The brain under test, on the migrated per-test database.

    Reuses the audit-chain key the migration activated with: Boundary F binds
    the activated state to the key that signed it, so a fresh key would fail
    every audit write and the trigger would never reach its command insert.
    """
    assert integration_settings.audit_chain_secret is not None
    return Settings(
        database_url=integration_settings.database_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=(integration_settings.audit_chain_secret.get_secret_value()),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        require_db_ssl=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        db_statement_timeout_ms=60_000,
        db_lock_timeout_ms=60_000,
        db_idle_in_tx_timeout_ms=60_000,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(race_settings: Settings, migrated_engine: AsyncEngine):
    app = create_app(race_settings, engine=migrated_engine)
    app.state.lifespan_ready = True
    return app


async def _seed(brain_app, settings: Settings) -> dict:
    """One project, one operator, one online celery agent, one live schedule.

    Two logins for that operator, not one. Every authenticated request bumps
    ``last_seen_at`` on the session row it arrived with, inside its own
    transaction, so two requests presenting the same cookie serialise on that
    row in the auth layer and never reach the schedule at the same time. That
    is a property of the session, not of the schedule, and it would quietly
    turn a race test into two requests running one after the other. A second
    click during an incident comes from another login anyway.
    """
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    csrf = secrets.token_urlsafe(32)
    hold_csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        project = Project(id=uuid.uuid4(), slug="default", name="default")
        s.add(project)
        await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_active=True,
        )
        s.add(user)
        await s.flush()
        s.add(
            Membership(
                user_id=user.id,
                project_id=project.id,
                role=ProjectRole.OPERATOR,
            ),
        )
        agent = Agent(
            id=uuid.uuid4(),
            project_id=project.id,
            name=f"agent-{uuid.uuid4().hex[:8]}",
            token_hash=uuid.uuid4().hex,
            protocol_version="2",
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=["celery-beat"],
            state=AgentState.ONLINE,
            last_seen_at=datetime.now(UTC),
        )
        s.add(agent)
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules.
        schedule = await ScheduleControlRepository(s).create_current(
            project_id=project.id,
            data={
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "name": "nightly",
                "task_name": "app.tasks.nightly",
                "kind": ScheduleKind.CRON.value,
                "expression": "0 3 * * *",
                "timezone": "UTC",
                "is_enabled": True,
                "queue": "periodic",
            },
            planning_at=datetime.now(UTC),
        )
        session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add(session_row)
        hold_session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=hold_csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add(hold_session_row)
        await s.commit()
    await brain_app.state.brain_registry.register(
        project_id=project.id,
        agent_id=agent.id,
        ws=_StandInSocket(),
    )
    return {
        "session_id": session_row.id,
        "csrf": csrf,
        "hold_session_id": hold_session_row.id,
        "hold_csrf": hold_csrf,
        "schedule_id": schedule.id,
        "project_id": project.id,
        "agent_id": agent.id,
    }


@contextlib.asynccontextmanager
async def _operator(brain_app, settings: Settings, session_id):
    """A logged-in client for one of the seeded operator's logins."""
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(session_id),
        )
        yield client


async def _trigger(brain_app, settings: Settings, ctx: dict):
    async with _operator(brain_app, settings, ctx["session_id"]) as client:
        return await client.post(
            f"/api/v1/projects/default/schedules/{ctx['schedule_id']}/trigger",
            headers={CSRF_HEADER_NAME: ctx["csrf"]},
        )


async def _pause(brain_app, settings: Settings, ctx: dict):
    """The pause endpoint itself, over HTTP, as the operator's other click."""
    async with _operator(brain_app, settings, ctx["hold_session_id"]) as client:
        return await client.post(
            f"/api/v1/projects/default/schedules/{ctx['schedule_id']}/pause",
            headers={CSRF_HEADER_NAME: ctx["hold_csrf"]},
        )


async def _count_commands(brain_app, project_id) -> int:
    async with brain_app.state.db.session() as s:
        return (
            await s.execute(
                select(func.count()).select_from(Command).where(Command.project_id == project_id),
            )
        ).scalar_one()


async def _waiting_on_the_schedule_row(observer: asyncpg.Connection) -> bool:
    """True while some other backend is blocked taking the schedules row.

    Read from a connection of its own, so it reports on the request without
    participating in what it is reporting on. Narrowed to a lock wait under a
    read of ``schedules`` rather than any wait at all, so the barrier cannot be
    satisfied by unrelated contention and quietly stop testing anything.

    Matched on the front of the statement because ``pg_stat_activity.query`` is
    truncated at ``track_activity_query_size`` (1kB by default) and the
    schedules row is wider than that, so the locking clause at the end of the
    statement is not there to match on.
    """
    waiting = await observer.fetchval(
        """
        SELECT count(*)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND wait_event_type = 'Lock'
          AND query LIKE 'SELECT schedules.%'
        """,
    )
    return bool(waiting)


async def _waiting_for_the_agents_table(observer: asyncpg.Connection) -> bool:
    """True while some backend is blocked reading ``agents``.

    Asked of ``pg_locks`` rather than of statement text, because what places a
    request inside the window is the relation it is waiting for, not how the
    query that waits happens to be spelled.
    """
    waiting = await observer.fetchval(
        """
        SELECT count(*)
        FROM pg_locks
        WHERE relation = 'agents'::regclass
          AND NOT granted
          AND pid <> pg_backend_pid()
        """,
    )
    return bool(waiting)


async def _hold_is_committed(observer: asyncpg.Connection, schedule_id) -> bool:
    """True once a hold is visible to everyone, not only to the click placing it.

    A plain read, so it cannot be answered by an uncommitted change and cannot
    be blocked by the row lock either: this has to report on the window from
    outside it without altering what the window does.
    """
    return bool(
        await observer.fetchval(
            "SELECT paused_at IS NOT NULL FROM schedules WHERE id = $1",
            schedule_id,
        ),
    )


async def test_a_hold_committing_mid_click_is_not_overtaken_by_the_fire(
    brain_app,
    race_settings: Settings,
    fresh_database: str,
) -> None:
    """The hold gets the row first, so the click that follows must see it.

    The hold is taken and left uncommitted, which is what a pause click looks
    like from the outside for as long as it runs. The trigger then arrives. It
    must not be able to decide it may fire from state that a transaction it can
    see nothing of is already changing.

    What this ordering does NOT settle: the click here never gets between its
    own two steps, so a handler that read the row under a lock and dropped that
    lock before enqueuing would be refused here too, for having lost the row
    rather than for holding it. The test below is the one that tells those
    apart.
    """
    ctx = await _seed(brain_app, race_settings)
    observer = await asyncpg.connect(dsn=fresh_database)
    try:
        async with brain_app.state.db.session() as pausing:
            # The pause endpoint's own repository call, stopped short of its
            # commit. Everything a real concurrent click holds at this instant
            # is held here.
            transition = await ScheduleControlRepository(pausing).set_paused(
                project_id=ctx["project_id"],
                schedule_id=ctx["schedule_id"],
                paused=True,
                occurred_at=datetime.now(UTC),
            )
            assert transition.outcome == "applied"

            click = asyncio.create_task(_trigger(brain_app, race_settings, ctx))

            # Establish which side of the window the click is on before
            # releasing the hold. Either it is waiting for the row (the check
            # and the enqueue are one step) or it has already finished (they
            # are not, and the hold arrived between them). Both are decisive;
            # a timeout is not, and fails.
            budget = (race_settings.db_lock_timeout_ms / 1000.0) * _BARRIER_BUDGET_FRACTION
            deadline = asyncio.get_running_loop().time() + budget
            while True:
                if click.done() or await _waiting_on_the_schedule_row(observer):
                    break
                if asyncio.get_running_loop().time() > deadline:
                    click.cancel()
                    pytest.fail(
                        "the trigger neither blocked on the hold nor completed; "
                        "the barrier proved nothing about the race",
                    )
                await asyncio.sleep(0.02)

            await pausing.commit()

        response = await click
    finally:
        await observer.close()

    # The durable harm first: whatever the caller was told, a command row here
    # is work an agent will run under a hold that was in force before it
    # existed, and it outlives the request that wrote it.
    assert await _count_commands(brain_app, ctx["project_id"]) == 0, (
        "a fire was durably enqueued for a schedule that was held before the "
        "command existed, so the hold reads as in force over work it did not stop"
    )
    assert response.status_code == 409, response.text
    assert response.json()["details"]["reason"] == "schedule_paused"


async def test_no_hold_can_commit_between_the_eligibility_read_and_the_enqueue(
    brain_app,
    race_settings: Settings,
    fresh_database: str,
) -> None:
    """The interleaving the row lock exists to make impossible.

    A hold that commits after the click has decided it may fire and before the
    click's command exists is the harmful one. The verdict that already
    happened honours it; the insert that has not yet happened overtakes it; the
    operator is left reading a hold that is in force over a fire it did not
    stop. It is also the only interleaving that a lock taken for the
    eligibility read and released before the enqueue would allow, which is why
    it is the one worth building.

    The click is stopped between its two steps from outside the brain, by an
    ``agents`` lock nothing in the product asks for. Choosing a target agent is
    the first thing the handler does once it has decided it may fire, so that
    lock parks the request with its verdict reached, no audit row written and
    no command inserted, and it does so without changing a line of what runs:
    every statement the handler makes is its own, and every assertion below is
    on rows it wrote.

    Which request wins is not the subject. Both answers are legitimate for the
    operator, and which one they get is a matter of microseconds. What is never
    legitimate is a hold reaching everyone else's eyes inside the window, so
    that is what is asserted, and the durable outcomes are checked against it.
    """
    ctx = await _seed(brain_app, race_settings)
    budget = (race_settings.db_lock_timeout_ms / 1000.0) * _BARRIER_BUDGET_FRACTION
    loop = asyncio.get_running_loop()

    blocker = await asyncpg.connect(dsn=fresh_database)
    observer = await asyncpg.connect(dsn=fresh_database)
    click: asyncio.Task | None = None
    hold: asyncio.Task | None = None
    hold_committed_inside_the_window = False
    try:
        async with blocker.transaction():
            await blocker.execute("LOCK TABLE agents IN ACCESS EXCLUSIVE MODE")

            click = asyncio.create_task(_trigger(brain_app, race_settings, ctx))

            # Wait for the click to be demonstrably inside the window instead
            # of assuming it got there. A click that answers first never
            # entered it, which means the step this parks on has moved and
            # this test is watching a window that is no longer there.
            deadline = loop.time() + budget
            while not await _waiting_for_the_agents_table(observer):
                if click.done():
                    pytest.fail(
                        "the trigger answered without stopping at its target "
                        f"lookup ({click.result().status_code}), so nothing was "
                        "ever parked inside the window under test",
                    )
                if loop.time() > deadline:
                    pytest.fail(
                        "the trigger never reached its target lookup; nothing "
                        "was parked inside the window under test",
                    )
                await asyncio.sleep(0.02)

            # Verdict reached, nothing enqueued. The hold arrives here, which
            # is the whole of the interleaving.
            hold = asyncio.create_task(_pause(brain_app, race_settings, ctx))

            deadline = loop.time() + budget
            while True:
                if await _hold_is_committed(observer, ctx["schedule_id"]):
                    hold_committed_inside_the_window = True
                    break
                if await _waiting_on_the_schedule_row(observer):
                    # Waiting for the row the click still holds: the verdict
                    # and the enqueue are one step, which is the claim.
                    break
                if hold.done():
                    answered = hold.result()
                    pytest.fail(
                        "the pause neither committed nor waited for the row, "
                        f"it just answered {answered.status_code}: "
                        f"{answered.text}",
                    )
                if loop.time() > deadline:
                    pytest.fail(
                        "the hold neither committed nor blocked on the row; "
                        "the barrier proved nothing about the interleaving",
                    )
                await asyncio.sleep(0.02)

        # Released, so both requests run to completion and are judged on what
        # they left behind rather than on where they were stopped.
        response = await click
        pause_response = await hold
    finally:
        pending = [task for task in (click, hold) if task is not None]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        with contextlib.suppress(Exception):
            await blocker.close()
        await observer.close()

    assert not hold_committed_inside_the_window, (
        "a hold committed between the trigger's eligibility read and its "
        "enqueue, so the command that followed was dispatched under a hold "
        "already in force, and the operator's hold reads as covering work it "
        "did not stop"
    )
    # The other half of the same claim, on the durable rows: the fire the
    # operator asked for survived, and the hold that arrived while it was
    # being decided applies from after it.
    assert response.status_code == 200, response.text
    assert await _count_commands(brain_app, ctx["project_id"]) == 1
    assert pause_response.status_code == 200, pause_response.text
    assert pause_response.json()["paused_at"] is not None


async def test_a_hold_that_loses_the_race_does_not_swallow_the_fire(
    brain_app,
    race_settings: Settings,
    fresh_database: str,
) -> None:
    """The positive control, and the reason this is a lock and not a refusal.

    Serialising the two clicks has to leave BOTH answers reachable. If the
    trigger gets to the row first, the operator's fire is legitimate: it was
    permitted by the state that was live when it was decided, it is committed
    before the hold is, and the hold then applies to everything after it. A
    change that made the trigger lose to a pause it beat would be just as wrong
    as the interleaving above, and would pass a test that only ever checks the
    refusal.
    """
    ctx = await _seed(brain_app, race_settings)
    observer = await asyncpg.connect(dsn=fresh_database)
    try:
        response = await _trigger(brain_app, race_settings, ctx)
        assert response.status_code == 200, response.text
        assert not await _waiting_on_the_schedule_row(observer), (
            "the trigger left the schedules row locked after answering"
        )
    finally:
        await observer.close()

    assert await _count_commands(brain_app, ctx["project_id"]) == 1

    async with brain_app.state.db.session() as pausing:
        transition = await ScheduleControlRepository(pausing).set_paused(
            project_id=ctx["project_id"],
            schedule_id=ctx["schedule_id"],
            paused=True,
            occurred_at=datetime.now(UTC),
        )
        assert transition.outcome == "applied"
        await pausing.commit()

    async with brain_app.state.db.session() as reader:
        held = (
            await reader.execute(
                select(Schedule).where(Schedule.id == ctx["schedule_id"]),
            )
        ).scalar_one()
    assert held.paused_at is not None

    assert (await _trigger(brain_app, race_settings, ctx)).status_code == 409
    assert await _count_commands(brain_app, ctx["project_id"]) == 1
