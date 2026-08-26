"""Trigger Now: it reaches an agent, it stops at a hold, a retirement is not a hold.

All three have to be true at once, and no one of them is worth asserting alone.
A route that refuses every held schedule while returning 404 to everybody else
passes a refusal test and is still broken. A route that fires reliably and
ignores the hold passes a dispatch test and quietly overrides the operator who
paused during an incident. And a route that refuses everything a cadence fire
would refuse passes both of those and has taken away the workflow this button
exists for, which is running a schedule by hand precisely BECAUSE its cadence
is off.

That third one is why every refusal test here is written against
``operator_hold_in_force`` and never against the cadence's own fire authority.
A pause holds the cadence during an incident, and a quarantine says the stored
definition is not the accepted one, so both are unresolved states that stop any
run until somebody clears them. Disabling retires the cadence, and an operator
who retired it and then asks for one run is not in an unresolved state, they
are using the product as it is offered: the Run button appears on disabled rows
and the public API reference promises the one-shot on every schedule.

Equating the two authorities is therefore not a safe conservatism, it is a
capability being removed, and a test asserting the equality would pin it there.

So every endpoint test here runs twice, once with ``scheduler_trigger_url``
unset and once with it configured, because the configuration used to decide
which of the two halves you got: unset ignored the hold, set routed the fire
out to z4j-scheduler and back into a brain that refuses an attributed fire
carrying no cadence authority. The parametrisation is the assertion that the
setting no longer changes the answer.

These run against a MIGRATED database rather than a create_all() one. Every
Boundary-D guard lives in a migration, so a create_all() schema refuses
nothing and cannot observe what an operator's database does.
"""

from __future__ import annotations

import contextlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api.schedules import _manual_fire_command, _manual_fire_refusal
from z4j_brain.auth.csrf import CSRF_HEADER_NAME
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.command_wire import wire_target
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState, ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    Command,
    Membership,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
    operator_hold_in_force,
)
from z4j_brain.settings import Settings

_PW = "correct-horse-battery-staple-9"


@pytest.fixture(autouse=True)
def _reset_bulk_action_throttle():
    """Give each test the full trigger budget.

    The bulk-action bucket is a module global with a 10/min cap, so a file
    that fires several triggers would otherwise start seeing 429s that have
    nothing to do with what is under test, and which test happened to run
    first would decide it.
    """
    from z4j_brain.domain.ip_rate_limit import _bulk_action_bucket

    _bulk_action_bucket._hits.clear()
    yield
    _bulk_action_bucket._hits.clear()


@pytest.fixture(
    params=[None, "127.0.0.1:7802"],
    ids=["no-scheduler-url", "scheduler-url-configured"],
)
def settings(request, migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    """The same brain, under both trigger configurations.

    Nothing listens on the configured port. That is the point: if the route
    ever routes an operator trigger back out over gRPC again, these tests fail
    with a connection error instead of passing quietly.
    """
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        scheduler_trigger_url=request.param,
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


class _StandInSocket:
    """Enough of a socket for the registry to treat the agent as connected.

    An agent row marked online is not the same thing as a connected agent, and
    the dispatcher refuses to issue to one it has no session for. The physical
    push over this object fails, which is fine and is not what this file is
    about: the assertions are on the command row the brain wrote, which is what
    the agent would be handed.
    """


async def _seed(
    brain_app,
    settings,
    *,
    scheduler: str = "z4j-scheduler",
    engine_adapters: tuple[str, ...] = ("celery",),
    scheduler_adapters: tuple[str, ...] = ("celery-beat",),
    agent_online: bool = True,
) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        proj = (
            await s.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if proj is None:
            proj = Project(id=uuid.uuid4(), slug="default", name="default")
            s.add(proj)
            await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_active=True,
        )
        s.add(user)
        await s.flush()
        s.add(Membership(user_id=user.id, project_id=proj.id, role=ProjectRole.OPERATOR))
        agent = Agent(
            id=uuid.uuid4(),
            project_id=proj.id,
            name=f"agent-{uuid.uuid4().hex[:8]}",
            token_hash=uuid.uuid4().hex,
            protocol_version="2",
            framework_adapter="bare",
            engine_adapters=list(engine_adapters),
            scheduler_adapters=list(scheduler_adapters),
            state=(AgentState.ONLINE if agent_online else AgentState.OFFLINE),
            last_seen_at=datetime.now(UTC),
        )
        s.add(agent)
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules.
        sched = await ScheduleControlRepository(s).create_current(
            project_id=proj.id,
            data={
                "engine": "celery",
                "scheduler": scheduler,
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
        await s.commit()
    if agent_online:
        await brain_app.state.brain_registry.register(
            project_id=proj.id,
            agent_id=agent.id,
            ws=_StandInSocket(),
        )
    return {
        "session_id": session_row.id,
        "csrf": csrf,
        "schedule_id": sched.id,
        "project_id": proj.id,
        "agent_id": agent.id,
    }


@contextlib.asynccontextmanager
async def _client(brain_app, settings, ctx):
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as ac:
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(ctx["session_id"]),
        )
        yield ac


def _url(ctx, action: str) -> str:
    return f"/api/v1/projects/default/schedules/{ctx['schedule_id']}/{action}"


async def _post(brain_app, settings, ctx, action: str):
    async with _client(brain_app, settings, ctx) as ac:
        return await ac.post(_url(ctx, action), headers={CSRF_HEADER_NAME: ctx["csrf"]})


async def _commands(brain_app, project_id) -> list[Command]:
    async with brain_app.state.db.session() as s:
        return list(
            (
                await s.execute(
                    select(Command)
                    .where(Command.project_id == project_id)
                    .order_by(Command.issued_at),
                )
            )
            .scalars()
            .all()
        )


async def _read(brain_app, schedule_id) -> Schedule:
    async with brain_app.state.db.session() as s:
        return (await s.execute(select(Schedule).where(Schedule.id == schedule_id))).scalar_one()


async def _count_commands(brain_app, project_id) -> int:
    async with brain_app.state.db.session() as s:
        return (
            await s.execute(
                select(func.count()).select_from(Command).where(Command.project_id == project_id),
            )
        ).scalar_one()


# =====================================================================
# The button has to work
# =====================================================================


@pytest.mark.asyncio
async def test_the_trigger_reaches_an_agent(brain_app, settings) -> None:
    """The positive control, and it is not a formality.

    A brain-fired schedule belongs to no scheduler any agent installs, so the
    route used to look for an agent advertising a ``z4j-scheduler`` scheduler
    adapter: something no adapter has ever been named, so the answer was 404
    for every schedule a hold can even be placed on. The refusal tests below
    would all have passed against that.
    """
    ctx = await _seed(brain_app, settings)

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 200, resp.text
    commands = await _commands(brain_app, ctx["project_id"])
    assert len(commands) == 1, "the click did not become a command for the agent"
    issued = commands[0]
    assert issued.agent_id == ctx["agent_id"]
    # The agent is handed the resolved task. A schedule this brain fires does
    # not exist in any scheduler on the agent, so a name to look up would be a
    # name for nothing.
    assert issued.action == "submit_task"
    assert issued.payload["name"] == "app.tasks.nightly"
    assert issued.payload["queue"] == "periodic"
    # The engine has to survive into the wire target, which is the only place
    # a multi-engine agent looks when binding an adapter.
    assert wire_target(issued.target_type, issued.target_id, issued.payload)["engine"] == "celery"


@pytest.mark.asyncio
async def test_the_trigger_is_not_a_cadence_fire(brain_app, settings) -> None:
    """An extra fire must not claim a cadence receipt.

    ``schedule.fire`` is receipt-bound on an activated database: the command
    row has to carry the acceptance revision and receipt token of a real
    cadence transition, and the INSERT is refused without them. There is no
    such transition behind a button click, so issuing this as a cadence fire
    either fails at the database or requires manufacturing a transition that
    would move the cursor and swallow the next scheduled occurrence.

    Asserted at the command row rather than at the response, because a 200 is
    what both shapes return right up to the point where one of them is refused.
    """
    ctx = await _seed(brain_app, settings)
    before = (await _read(brain_app, ctx["schedule_id"])).next_run_at

    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 200

    issued = (await _commands(brain_app, ctx["project_id"]))[0]
    assert issued.action != "schedule.fire"
    assert issued.schedule_protocol_marker is None
    assert issued.schedule_receipt_control_token is None
    assert (await _read(brain_app, ctx["schedule_id"])).next_run_at == before, (
        "the extra fire moved the cadence cursor, so a scheduled occurrence "
        "was consumed by a button"
    )


@pytest.mark.asyncio
async def test_two_clicks_are_two_commands(brain_app, settings) -> None:
    """The agent dedups a re-delivered command by its id.

    Collapsing two clicks onto one command would make the second a silent
    no-op on the agent while the brain reported success.
    """
    ctx = await _seed(brain_app, settings)

    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 200
    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 200

    commands = await _commands(brain_app, ctx["project_id"])
    assert len({c.id for c in commands}) == 2, "the second click was swallowed"


@pytest.mark.asyncio
async def test_an_agent_that_cannot_run_the_engine_is_not_used(brain_app, settings) -> None:
    """Never hand a celery task to an agent that only runs RQ.

    The remaining agent is online and healthy, which is what makes the wrong
    answer tempting: dispatching to it would look like success and enqueue
    nothing, or enqueue onto the wrong engine.
    """
    ctx = await _seed(brain_app, settings, engine_adapters=("rq",))

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 404, resp.text
    assert resp.json()["details"]["reason"] == "engine_not_installed"
    assert await _count_commands(brain_app, ctx["project_id"]) == 0


@pytest.mark.asyncio
async def test_no_online_agent_says_to_start_one(brain_app, settings) -> None:
    """The two ways to have nowhere to send it are different problems.

    "Start the agent" and "install the adapter" are different actions, and an
    operator reading one when the other is true loses the afternoon.
    """
    ctx = await _seed(brain_app, settings, agent_online=False)

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 404, resp.text
    assert resp.json()["details"]["reason"] == "no_online_agent"
    assert "start the agent" in resp.json()["message"]
    assert await _count_commands(brain_app, ctx["project_id"]) == 0


# =====================================================================
# The hold has to stop it
# =====================================================================


@pytest.mark.asyncio
async def test_a_held_schedule_refuses_the_trigger(brain_app, settings) -> None:
    """The finding: 200, dispatched, still paused.

    A hold that the button walks past is not a hold. The operator who placed
    it during an incident has no way to see it was overridden, and the fire
    they were preventing happens anyway.
    """
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "pause")).status_code == 200
    before = await _count_commands(brain_app, ctx["project_id"])

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert body["details"]["reason"] == "schedule_paused"
    # The operator is told what to do about it, not just that it failed.
    assert "resume" in body["message"].lower()
    assert await _count_commands(brain_app, ctx["project_id"]) == before, (
        "the hold was reported to the caller and the fire was dispatched anyway"
    )


@pytest.mark.asyncio
async def test_resume_makes_the_trigger_work_again(brain_app, settings) -> None:
    """The refusal is a hold, not a retirement: it lifts."""
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "pause")).status_code == 200
    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 409
    assert (await _post(brain_app, settings, ctx, "resume")).status_code == 200

    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 200
    assert await _count_commands(brain_app, ctx["project_id"]) == 1


@pytest.mark.asyncio
async def test_a_disabled_schedule_still_triggers(brain_app, settings) -> None:
    """Retired off the timer is exactly when the button matters most.

    "Stop running this automatically, I will run it by hand when I need it" is
    a supported workflow and not a broken state: the Run button is offered on
    disabled rows and the API reference promises the one-shot without
    qualifying it. Refusing here does not close a hole, it deletes that
    workflow, and the operator's only route back is to re-enable the cadence
    they deliberately retired, arm it, fire, and retire it again.
    """
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "disable")).status_code == 200

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 200, resp.text
    commands = await _commands(brain_app, ctx["project_id"])
    assert len(commands) == 1, "the retired schedule's click became no work"
    assert commands[0].payload["name"] == "app.tasks.nightly"


@pytest.mark.asyncio
async def test_triggering_a_retired_schedule_leaves_it_retired(brain_app, settings) -> None:
    """One run by hand is not a decision to start running it again.

    A fire that quietly re-armed the cadence would be worse than the refusal it
    replaced: the operator asked for one occurrence and would get every
    occurrence from then on, without being told.
    """
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "disable")).status_code == 200
    retired = await _read(brain_app, ctx["schedule_id"])
    assert retired.is_enabled is False

    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 200

    after = await _read(brain_app, ctx["schedule_id"])
    assert after.is_enabled is False, "a single manual run switched the cadence back on"
    assert after.next_run_at == retired.next_run_at, (
        "the manual run moved the retired schedule's cursor"
    )


@pytest.mark.asyncio
async def test_a_hold_outlives_a_disable(brain_app, settings) -> None:
    """Retiring a held schedule must not be a way to shake the hold off.

    The refusal is the hold, not the enabled flag, so the one state that could
    lift it by accident is the one that no longer participates in the verdict.
    An operator who disables during an incident has retired the cadence and has
    not resolved anything.
    """
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "pause")).status_code == 200
    assert (await _post(brain_app, settings, ctx, "disable")).status_code == 200
    before = await _count_commands(brain_app, ctx["project_id"])

    resp = await _post(brain_app, settings, ctx, "trigger")

    assert resp.status_code == 409, resp.text
    assert resp.json()["details"]["reason"] == "schedule_paused"
    assert await _count_commands(brain_app, ctx["project_id"]) == before


@pytest.mark.asyncio
async def test_the_refusal_leaves_an_audit_row(brain_app, settings) -> None:
    """A refused trigger during an incident is what gets reconstructed later.

    Nothing else records it: the denial-audit middleware classifies 401, 403,
    404 and 422, and lets a conflict through unrecorded.
    """
    ctx = await _seed(brain_app, settings)
    assert (await _post(brain_app, settings, ctx, "pause")).status_code == 200

    assert (await _post(brain_app, settings, ctx, "trigger")).status_code == 409

    async with brain_app.state.db.session() as s:
        rows = list(
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedule.trigger_now",
                        AuditLog.target_id == str(ctx["schedule_id"]),
                    ),
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1, "the refused trigger left no trace"
    assert rows[0].outcome == "deny"
    assert rows[0].audit_metadata["reason"] == "schedule_paused"


# =====================================================================
# The refusal predicate itself
# =====================================================================


def _row(**kwargs) -> Schedule:
    """A schedule row in one control state, not persisted.

    Built as the real mapped class so the predicate under test reads the same
    attributes it reads in production; a dictionary or a stub would prove only
    that the function reads keys it was handed.
    """
    row = Schedule(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        engine="celery",
        scheduler="z4j-scheduler",
        name="nightly",
        task_name="app.tasks.nightly",
        kind=ScheduleKind.CRON,
        expression="0 3 * * *",
        timezone="UTC",
    )
    row.is_enabled = kwargs.get("is_enabled", True)
    row.paused_at = kwargs.get("paused_at")
    row.control_token = kwargs.get("control_token")
    row.quarantine_control_token = kwargs.get("quarantine_control_token")
    return row


_TOKEN = uuid.uuid4()
_OTHER_TOKEN = uuid.uuid4()
_HELD_AT = datetime.now(UTC)

#: Every combination of the three control states, over a row that carries a
#: control token. Expected reason is None when an operator may fire it by hand,
#: which is not the same question as whether its cadence may fire it.
_STATES = [
    pytest.param({}, None, id="running"),
    pytest.param({"is_enabled": False}, None, id="retired"),
    pytest.param({"paused_at": _HELD_AT}, "schedule_paused", id="held"),
    pytest.param(
        {"quarantine_control_token": _TOKEN},
        "schedule_quarantined",
        id="quarantined",
    ),
    pytest.param(
        {"quarantine_control_token": _OTHER_TOKEN},
        None,
        id="quarantine-of-a-superseded-definition",
    ),
    pytest.param(
        {"is_enabled": False, "paused_at": _HELD_AT},
        "schedule_paused",
        id="retired-and-held",
    ),
    pytest.param(
        {"is_enabled": False, "quarantine_control_token": _TOKEN},
        "schedule_quarantined",
        id="retired-and-quarantined",
    ),
    pytest.param(
        {"paused_at": _HELD_AT, "quarantine_control_token": _TOKEN},
        "schedule_paused",
        id="held-and-quarantined",
    ),
    pytest.param(
        {"is_enabled": False, "paused_at": _HELD_AT, "quarantine_control_token": _TOKEN},
        "schedule_paused",
        id="all-three",
    ),
]


@pytest.mark.parametrize(("state", "expected_reason"), _STATES)
def test_each_held_state_is_refused_and_named(state, expected_reason) -> None:
    """Table over the whole state space, so a new rule inherits the coverage.

    Naming the reason matters as much as refusing: the way out of a hold and
    the way out of a quarantine are different actions. The rows where a
    retirement is present and the expectation is still ``None`` are the ones
    that carry the point, and each is paired here with the same retirement over
    a real hold, so "retirement is not a refusal" cannot pass by the predicate
    having stopped refusing anything at all.
    """
    refusal = _manual_fire_refusal(_row(control_token=_TOKEN, **state))

    if expected_reason is None:
        assert refusal is None
    else:
        assert refusal is not None
        assert refusal[0] == expected_reason
        assert refusal[1], "a refusal with no message tells the operator nothing"


@pytest.mark.parametrize(("state", "expected_reason"), _STATES)
def test_the_trigger_is_gated_by_the_holds_and_not_by_the_cadence(
    state,
    expected_reason,
) -> None:
    """Manual-fire authority is the operator holds, exactly, and nothing else.

    Not the cadence's fire authority. Those two are deliberately different
    predicates: the cadence one also refuses a retired schedule, because a
    retired schedule has no turn to take, while an operator asking for one run
    right now is not claiming a turn. Binding this route to the cadence
    authority is what silently withdrew Trigger from every disabled schedule.

    Written as an equality against ``operator_hold_in_force`` rather than as a
    list of allowed states, so a fourth hold added to the authority is refused
    here without anyone editing this route, and is caught here if it is not.
    """
    row = _row(control_token=_TOKEN, **state)

    assert (_manual_fire_refusal(row) is None) == (not operator_hold_in_force(row))


@pytest.mark.parametrize(("state", "expected_reason"), _STATES)
def test_retirement_never_moves_the_verdict(state, expected_reason) -> None:
    """Flipping ``is_enabled`` alone changes nothing about this route's answer.

    The stronger form of the rule above, and the one that fails loudly if
    ``is_enabled`` is ever read here again for any reason: whatever the other
    control state is, the retired row and the live row get the same verdict and
    the same reason. The table covers both flag values for every hold
    combination, so this runs the comparison over the whole space.
    """
    live = dict(state, is_enabled=True)
    retired = dict(state, is_enabled=False)

    assert _manual_fire_refusal(_row(control_token=_TOKEN, **live)) == _manual_fire_refusal(
        _row(control_token=_TOKEN, **retired),
    )


def test_a_retired_external_schedule_still_fires_its_adapter() -> None:
    """The regression as an operator of celery-beat or APScheduler meets it.

    An external scheduler owns its own cadence, and the adapter implements this
    verb as an out-of-band one-shot that does not disturb it, so "retired here,
    run it by hand" is if anything more clearly correct for a schedule this
    brain does not fire. Asserted at the predicate and the command rather than
    the endpoint, because an activated database has no writer that creates an
    externally owned schedule on demand.
    """
    retired = _row(control_token=_TOKEN, is_enabled=False)
    retired.scheduler = "celery-beat"
    retired.external_id = "beat-42"

    assert _manual_fire_refusal(retired) is None
    fire = _manual_fire_command(retired)
    assert fire.action == "schedule.trigger_now"
    assert fire.payload["external_id"] == "beat-42"


def test_the_refusal_fails_closed_on_a_hold_it_cannot_name(monkeypatch) -> None:
    """A hold this route has not learned about must still stop it.

    The point of delegating the verdict is that the authority can grow a third
    hold without anyone editing this route. That only helps if the unnamed case
    refuses, so the authority is forced to say yes here and the answer is
    checked, rather than assumed from reading the ``if`` chain.
    """
    from z4j_brain.persistence.repositories import schedule_control

    monkeypatch.setattr(schedule_control, "operator_hold_in_force", lambda _row: True)
    running = _row(control_token=_TOKEN)

    refusal = _manual_fire_refusal(running)

    assert refusal is not None, "an unrecognised hold was fired through anyway"
    assert refusal[0] == "schedule_not_runnable"


def test_a_tokenless_schedule_may_still_be_triggered() -> None:
    """A schedule with no control token is not a quarantined schedule.

    The quarantine test is ``quarantine_control_token == control_token``, which
    is true when both are NULL. The acceptance transitions only ever see rows
    that carry a token, so it never mattered there. This route sees every
    schedule in the project, including the ones a database upgraded from before
    schedule control was activated still carries, and calling those quarantined
    would refuse a button that has nothing wrong with it.
    """
    tokenless = _row()

    assert tokenless.control_token is None
    assert operator_hold_in_force(tokenless) is False
    assert _manual_fire_refusal(tokenless) is None


# =====================================================================
# Which command a click becomes
# =====================================================================


def test_a_brain_fired_schedule_is_handed_the_resolved_task() -> None:
    """There is no adapter to ask, so the task itself has to travel.

    ``z4j-scheduler`` is a service beside the brain, not something an agent
    installs, so no agent advertises it and no agent can look a schedule up by
    name in it. The engine is carried where the agent actually reads it from,
    which is the wire target, not the parameters.
    """
    row = _row(control_token=_TOKEN)
    row.queue = "periodic"
    row.args = [1]
    row.kwargs = {"deep": True}

    fire = _manual_fire_command(row)

    assert fire.by_engine is True
    assert fire.action == "submit_task"
    assert fire.payload["name"] == "app.tasks.nightly"
    assert fire.payload["args"] == [1]
    assert fire.payload["kwargs"] == {"deep": True}
    assert fire.payload["queue"] == "periodic"
    assert wire_target("schedule", str(row.id), fire.payload)["engine"] == "celery"


def test_a_brain_fired_schedule_does_not_borrow_the_cadence_verb() -> None:
    """``schedule.fire`` is receipt-bound, and a click has no receipt.

    An activated database refuses a ``schedule.fire`` command that carries no
    acceptance revision and receipt token, and the only way to get those is a
    cadence transition, which moves the cursor. Borrowing the verb therefore
    either fails at the INSERT or silently consumes a scheduled occurrence.
    """
    fire = _manual_fire_command(_row(control_token=_TOKEN))

    assert fire.action != "schedule.fire"


def test_an_externally_owned_schedule_is_addressed_to_its_own_adapter() -> None:
    """celery-beat owns its schedules, so its adapter is what fires them.

    Asserted here rather than through the endpoint because an activated
    database has no writer that will create an externally owned schedule on
    demand: they arrive only through the sequenced external projection path.
    """
    row = _row(control_token=_TOKEN)
    row.scheduler = "celery-beat"
    row.external_id = "beat-42"

    fire = _manual_fire_command(row)

    assert fire.by_engine is False, "an agent's own scheduler adapter is the target"
    assert fire.action == "schedule.trigger_now"
    assert fire.payload["schedule_id"] == "nightly"
    assert fire.payload["external_id"] == "beat-42"
