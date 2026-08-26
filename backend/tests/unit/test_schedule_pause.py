"""Pause and resume a schedule.

Pausing is deliberately not disabling, and the tests that matter are the
ones pinning that difference. Disabling retires a schedule and is propagated
to the owning scheduler adapter. Pausing is a brain-side hold enforced by the
fire authority, so it works against a scheduler that has not noticed yet.

It is offered only for schedules this brain fires. An externally owned
schedule keeps its own cadence and there is no channel to tell it to stop, so
a hold recorded for one would be a promise nothing keeps.

These run against a MIGRATED database rather than a create_all() one. Every
Boundary-D guard lives in a migration, so a create_all() schema refuses
nothing: the first version of this file passed completely while the endpoint
raised on first use in production.
"""

from __future__ import annotations

import contextlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import CSRF_HEADER_NAME
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
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

_PW = "correct-horse-battery-staple-9"


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an audit
        # row that carries no chain authentication. Production always has this
        # configured; a test that omits it is not testing production.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
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
    # A migrated database, not a create_all() one. Every Boundary-D guard
    # lives in a migration, so create_all() produces a database that refuses
    # nothing and cannot observe what an operator's database does.
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


async def _seed(
    brain_app,
    settings,
    *,
    role=ProjectRole.OPERATOR,
    scheduler: str = "z4j-scheduler",
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
        s.add(Membership(user_id=user.id, project_id=proj.id, role=role))
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules. Seeding the way the product does is the whole
        # point of running against a migrated schema.
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
    return {
        "session_id": session_row.id,
        "csrf": csrf,
        "schedule_id": sched.id,
        "project_id": proj.id,
    }


@contextlib.asynccontextmanager
async def _client(brain_app, settings, ctx=None):
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as ac:
        if ctx is not None:
            ac.cookies.set(
                cookie_name(environment=settings.environment),
                SessionCookieCodec(settings).encode(ctx["session_id"]),
            )
        yield ac


def _url(ctx, action: str) -> str:
    return f"/api/v1/projects/default/schedules/{ctx['schedule_id']}/{action}"


async def _read(brain_app, schedule_id) -> Schedule:
    async with brain_app.state.db.session() as s:
        return (await s.execute(select(Schedule).where(Schedule.id == schedule_id))).scalar_one()


@pytest.mark.asyncio
async def test_pause_sets_the_timestamp_without_disabling(brain_app, settings) -> None:
    """The core distinction: held, not retired."""
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["paused_at"] is not None
    # Still enabled: pausing must not look like a retirement.
    assert body["is_enabled"] is True

    row = await _read(brain_app, ctx["schedule_id"])
    assert row.paused_at is not None
    assert row.is_enabled is True


@pytest.mark.asyncio
async def test_resume_clears_the_timestamp(brain_app, settings) -> None:
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})
        resp = await ac.post(_url(ctx, "resume"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 200, resp.text
    assert resp.json()["paused_at"] is None
    assert (await _read(brain_app, ctx["schedule_id"])).paused_at is None


@pytest.mark.asyncio
async def test_pausing_twice_keeps_the_original_timestamp(brain_app, settings) -> None:
    """How long has this been held is the question during an incident.

    Refreshing the timestamp on a second click would erase the answer, and
    the second click is exactly what a worried operator does.
    """
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        first = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})
        second = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert second.status_code == 200
    assert second.json()["paused_at"] == first.json()["paused_at"]


@pytest.mark.asyncio
async def test_resuming_a_running_schedule_is_not_an_error(brain_app, settings) -> None:
    """Idempotent in both directions, so a retry never needs a guard."""
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "resume"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 200
    assert resp.json()["paused_at"] is None


@pytest.mark.asyncio
async def test_pause_requires_authentication(brain_app, settings) -> None:
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings) as ac:
        resp = await ac.post(_url(ctx, "pause"))

    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_a_viewer_cannot_pause(brain_app, settings) -> None:
    """Holding a schedule is an operator action, not a read."""
    ctx = await _seed(brain_app, settings, role=ProjectRole.VIEWER)

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_pause_writes_an_audit_row(brain_app, settings) -> None:
    """Every hold is attributable. An unexplained pause is an incident of
    its own."""
    from z4j_brain.persistence.models import AuditLog

    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    async with brain_app.state.db.session() as s:
        actions = [row.action for row in (await s.execute(select(AuditLog))).scalars().all()]

    assert "schedule.pause" in actions


@pytest.mark.asyncio
async def test_a_missing_schedule_is_404(brain_app, settings) -> None:
    ctx = await _seed(brain_app, settings)
    ctx = {**ctx, "schedule_id": uuid.uuid4()}

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_overlap_policy_is_reported_and_defaults_to_allow(brain_app, settings) -> None:
    """The field is inert, which is exactly why it needs a test.

    ``overlap_policy`` is public API with no behaviour behind it yet: nothing
    reads it and nothing writes it. That combination is invisible to every
    other test in the suite, so a rename, a dropped serialiser line, or a
    default flipped to something that is not today's behaviour would all pass
    silently. Pin the two things a client can actually depend on now: the key
    is present, and it says ``allow``.
    """
    ctx = await _seed(brain_app, settings)

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "overlap_policy" in body
    assert body["overlap_policy"] == "allow"
    assert (await _read(brain_app, ctx["schedule_id"])).overlap_policy == "allow"


@pytest.mark.asyncio
async def test_a_schedule_owned_by_another_scheduler_is_refused(
    brain_app,
    settings,
    monkeypatch,
) -> None:
    """A hold we cannot enforce is a lie, so it is refused rather than recorded.

    celery-beat, APScheduler and the rest keep their own cadence, and this
    brain has no channel to tell them to stop. Recording ``paused_at`` for one
    of those would show an operator a hold while the schedule kept firing.

    The owner check lives in the repository and returns before any write, so
    this drives it through the endpoint to pin the status code and the message
    an operator actually sees.
    """
    from z4j_brain.persistence.repositories import schedule_control as control_mod

    ctx = await _seed(brain_app, settings)

    async def _foreign(self, **kwargs):
        row = await _read(brain_app, ctx["schedule_id"])
        row.scheduler = "celery-beat"
        return control_mod.PauseTransition("foreign_owner", row)

    monkeypatch.setattr(control_mod.ScheduleControlRepository, "set_paused", _foreign)

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert "celery-beat" in body["message"]
    # The operator is told what to do instead, not just that it failed.
    assert "Disable it" in body["message"]


@pytest.mark.asyncio
async def test_pause_bumps_the_schedule_revision(brain_app, settings) -> None:
    """The hold is a real Boundary-D transition, not a direct column write.

    A direct write is what the first implementation did, and an activated
    database refuses it outright. Asserting the revision moved is the cheapest
    proof that this went through the change-log envelope rather than around it.
    """
    ctx = await _seed(brain_app, settings)
    before = (await _read(brain_app, ctx["schedule_id"])).schedule_revision

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})

    assert resp.status_code == 200, resp.text
    after = await _read(brain_app, ctx["schedule_id"])
    assert after.schedule_revision > before
    assert after.paused_at is not None


@pytest.mark.asyncio
async def test_a_paused_schedule_cannot_be_accepted_for_a_fire(brain_app, settings) -> None:
    """The hold has to be enforced by the authority, on every path.

    This is the half that mattered and was missing. The gRPC handler had a
    paused check, but it sat 179 lines below an early return taken by every
    current-protocol scheduler, so it was unreachable for the modern path. The
    acceptance transitions themselves checked ``is_enabled`` and quarantine and
    nothing else, so a held schedule kept firing and kept advancing its cursor.

    Asserting at the repository is deliberate: that is the one place all four
    paths (current fire, cursor advance, legacy fire, buffered replay) funnel
    through, so a test here covers the paths a handler-level test would miss.
    """
    from z4j_brain.persistence.repositories.schedule_control import (
        _effectively_enabled,
    )

    ctx = await _seed(brain_app, settings)

    row = await _read(brain_app, ctx["schedule_id"])
    assert _effectively_enabled(row) is True, "a fresh schedule should be runnable"

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})
    assert resp.status_code == 200, resp.text

    held = await _read(brain_app, ctx["schedule_id"])
    assert held.is_enabled is True, "pausing must not look like a retirement"
    assert _effectively_enabled(held) is False, (
        "a held schedule must be refused by the fire authority"
    )

    async with _client(brain_app, settings, ctx) as ac:
        await ac.post(_url(ctx, "resume"), headers={CSRF_HEADER_NAME: ctx["csrf"]})
    assert _effectively_enabled(await _read(brain_app, ctx["schedule_id"])) is True


@pytest.mark.asyncio
async def test_every_acceptance_site_uses_the_shared_predicate(brain_app, settings) -> None:
    """No acceptance site may hand-roll the enabled test.

    Three states stop a schedule and they were being checked two at a time.
    A path that spells the condition out itself is a path that will forget the
    next state added, which is precisely how the hold came to be recorded,
    reported to the operator, and ignored by every fire path.
    """
    import inspect

    from z4j_brain.persistence.repositories import schedule_control

    source = inspect.getsource(schedule_control)
    hand_rolled = source.count("row.is_enabled or row.quarantine_control_token")
    assert hand_rolled <= 1, (
        "an acceptance site is spelling the enabled test out instead of using "
        "_effectively_enabled(); it will not see paused_at"
    )


async def _latest_change_log(brain_app, schedule_id):
    """The newest change-log envelope for one schedule, as stored.

    This is the exact object the Watch stream reads: it re-projects
    ``snapshot["schedule"]`` rather than the live row, so a field the snapshot
    writer omits is a field no watching scheduler will ever see.
    """
    from z4j_brain.persistence.models import ScheduleChangeLog

    async with brain_app.state.db.session() as s:
        return (
            await s.execute(
                select(ScheduleChangeLog)
                .where(ScheduleChangeLog.schedule_id == schedule_id)
                .order_by(ScheduleChangeLog.revision.desc())
                .limit(1),
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_a_held_schedule_is_projected_to_the_scheduler_as_not_enabled(
    brain_app,
    settings,
) -> None:
    """The scheduler must not ask, rather than be told no.

    Refusing the fire brain-side is the backstop, not the mechanism. A refusal
    comes back as FIRE_RETRYABLE_OR_AMBIGUOUS, which means retry, so refusing
    alone would have turned "fires while held" into "retries under back-off
    until resume". Every scheduler already skips an entry that is not enabled,
    including builds that predate both quarantine and pause, so folding the
    hold into that flag is what actually stops the tick, and it covers the
    installed base without a wire-format change.

    Driven through the two sources the product actually projects from, because
    they are not the same object. The live row is what a point lookup answers
    with; the stored change-log snapshot is what the Watch stream replays, and
    a snapshot is written once and read forever. Handing ``schedule_to_pb`` a
    dictionary assembled here would prove only that the function reads a key it
    was given, which is never the question.
    """
    from z4j_brain.scheduler_grpc.wire import schedule_to_pb

    ctx = await _seed(brain_app, settings)

    running_row = await _read(brain_app, ctx["schedule_id"])
    running_envelope = await _latest_change_log(brain_app, ctx["schedule_id"])
    assert schedule_to_pb(running_row).is_enabled is True
    assert schedule_to_pb(running_envelope.snapshot["schedule"]).is_enabled is True

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(_url(ctx, "pause"), headers={CSRF_HEADER_NAME: ctx["csrf"]})
    assert resp.status_code == 200, resp.text

    held_row = await _read(brain_app, ctx["schedule_id"])
    assert schedule_to_pb(held_row).is_enabled is False, (
        "a held schedule projected as enabled means the scheduler keeps ticking "
        "it and the brain keeps refusing, which is a retry loop until resume"
    )

    held_envelope = await _latest_change_log(brain_app, ctx["schedule_id"])
    assert held_envelope.revision > running_envelope.revision, (
        "the hold did not append a change-log envelope, so no watching "
        "scheduler is told anything at all"
    )
    assert schedule_to_pb(held_envelope.snapshot["schedule"]).is_enabled is False, (
        "the stored snapshot the Watch stream replays still projects the hold "
        "as enabled, so every scheduler that learns about schedules by watching "
        "keeps ticking one an operator has held"
    )


async def _audit_rows(brain_app, schedule_id, action: str | None = None):
    """Audit rows for one schedule, oldest first."""
    from z4j_brain.persistence.models import AuditLog

    async with brain_app.state.db.session() as s:
        stmt = select(AuditLog).where(AuditLog.target_id == str(schedule_id))
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        return list((await s.execute(stmt.order_by(AuditLog.occurred_at))).scalars())


@pytest.mark.asyncio
async def test_already_in_state_is_not_inverted_on_resume(brain_app, settings) -> None:
    """The audit log is meant to be evidence, so its metadata has to be true.

    ``already_applied`` means the requested state was already in force, and
    that reads the same way for pause and for resume. The resume branch
    negated it, so a no-op resume was recorded as a change and a real resume
    as a no-op: exactly backwards, in the record an incident review reads.
    """
    ctx = await _seed(brain_app, settings)
    url_pause = _url(ctx, "pause")
    url_resume = _url(ctx, "resume")
    headers = {CSRF_HEADER_NAME: ctx["csrf"]}

    async with _client(brain_app, settings, ctx) as ac:
        assert (await ac.post(url_pause, headers=headers)).status_code == 200
        assert (await ac.post(url_pause, headers=headers)).status_code == 200
        assert (await ac.post(url_resume, headers=headers)).status_code == 200
        assert (await ac.post(url_resume, headers=headers)).status_code == 200

    pauses = await _audit_rows(brain_app, ctx["schedule_id"], "schedule.pause")
    resumes = await _audit_rows(brain_app, ctx["schedule_id"], "schedule.resume")
    assert len(pauses) == 2 and len(resumes) == 2

    assert pauses[0].audit_metadata["already_in_state"] is False, "first pause changed something"
    assert pauses[1].audit_metadata["already_in_state"] is True, "second pause was a no-op"
    assert resumes[0].audit_metadata["already_in_state"] is False, "first resume changed something"
    assert resumes[1].audit_metadata["already_in_state"] is True, "second resume was a no-op"


@pytest.mark.asyncio
async def test_a_refused_hold_still_leaves_a_trail(brain_app, settings) -> None:
    """A refusal an operator repeats is exactly what a reviewer needs to see.

    The resync path in the same module already audits its denial for that
    reason. These two did not, so an attempt to hold a schedule that does not
    exist left nothing behind at all.
    """
    ctx = await _seed(brain_app, settings)
    missing = uuid.uuid4()
    url = _url({**ctx, "schedule_id": missing}, "pause")

    async with _client(brain_app, settings, ctx) as ac:
        resp = await ac.post(url, headers={CSRF_HEADER_NAME: ctx["csrf"]})
    assert resp.status_code == 404, resp.text

    rows = await _audit_rows(brain_app, missing)
    assert len(rows) == 1, "the refusal wrote no audit row"
    assert rows[0].action == "schedule.pause"
    assert rows[0].result == "failure"
    assert rows[0].outcome == "deny"
    assert rows[0].audit_metadata["reason"] == "schedule_not_found"


def test_the_current_fire_path_names_every_refusal_state() -> None:
    """Every outcome the mapper's CALLER can produce has an entry.

    The first version of this derived its expectations from every
    ``FireProgressTransition`` in the repository module, which is the wrong
    set: most of them come from ``accept_legacy_fire_progress`` and reach a
    different handler with its own dedicated branches. Believing that list, I
    added four entries to the current path's mapper that its only caller can
    never produce, and this test then certified the dead code.

    Derived from the one function that feeds it, so the set is the reachable
    one.
    """
    import ast
    import inspect

    from z4j_brain.persistence.repositories import schedule_control
    from z4j_brain.scheduler_grpc import handlers

    tree = ast.parse(inspect.getsource(schedule_control))
    produced: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if node.name != "accept_current_fire_progress":
            continue
        produced = {
            call.args[0].value
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
            and getattr(call.func, "id", "") == "FireProgressTransition"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
        }
        break

    assert produced, "accept_current_fire_progress was not found, so this is vacuous"

    mapper = inspect.getsource(handlers._current_fire_refresh_response)
    # Handled before the mapping table, or not a refusal at all.
    handled_elsewhere = {"idempotent", "not_found", "applied"}
    unmapped = sorted(d for d in produced - handled_elsewhere if f'"{d}"' not in mapper)

    assert unmapped == [], (
        "these acceptance outcomes reach the mapper's fallback and are reported "
        f"as unclassifiable, so an operator cannot tell why the fire was "
        f"refused: {unmapped}"
    )


def test_the_mapper_carries_no_entry_its_caller_cannot_produce() -> None:
    """Dead entries look like a fix and are worse than no fix.

    Four were added on the belief that a hold reaches this mapper. It does not:
    the current path refuses a hold by raising ScheduleControlConflictError,
    which the handler reports separately. The entries were unreachable, and the
    commit message claimed they fixed the operator-facing diagnosis.
    """
    import ast
    import inspect

    from z4j_brain.persistence.repositories import schedule_control
    from z4j_brain.scheduler_grpc import handlers

    produced: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(schedule_control))):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "accept_current_fire_progress":
            produced = {
                call.args[0].value
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and getattr(call.func, "id", "") == "FireProgressTransition"
                and call.args
                and isinstance(call.args[0], ast.Constant)
            }
            break
    assert produced, "accept_current_fire_progress was not found, so this is vacuous"

    mapper = inspect.getsource(handlers._current_fire_refresh_response)
    # Outcomes that exist in the repository but come from the LEGACY acceptance
    # path, which has its own handler branches. If one appears in this mapper it
    # is unreachable from here.
    legacy_only = {
        "schedule_paused",
        "schedule_disabled",
        "terminal_quarantined",
        "legacy_operator_resolution_required",
        "legacy_upgrade_required",
    }
    unreachable = sorted(d for d in legacy_only - produced if f'"{d}"' in mapper)

    assert unreachable == [], (
        "the current path's refusal mapper has entries its only caller cannot "
        f"produce, so they are dead code dressed as a fix: {unreachable}"
    )
