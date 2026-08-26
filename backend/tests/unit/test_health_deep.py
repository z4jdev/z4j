"""The per-subsystem health probe.

The property that matters most is negative: a check that cannot complete
must be reported as failed. An omitted check reads as healthy, and a health
endpoint that reads healthy while a subsystem is down is worse than having
no endpoint at all.

These run against a MIGRATED database. On a ``create_all()`` schema there is
no ``alembic_version`` and no activated audit chain, so every probe was pinned
in its fallback branch: the file asserted things about the fallbacks and could
not see the difference between a healthy subsystem and a broken one, which is
the entire question this endpoint exists to answer.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api import health as health_mod
from z4j_brain.api.health import _DEEP_CHECKS
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.models import Project, Session, User
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
from z4j_brain.settings import Settings

_URL = "/api/v1/health/deep"
_PW = "correct-horse-battery-staple-9"


def _settings_for(database_url: str, audit_chain_secret: str, **overrides: object) -> Settings:
    fields: dict[str, object] = {
        "database_url": database_url,
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        # A migrated database has Boundary F activated, so it refuses an audit
        # row that carries no chain authentication. Production always has this
        # configured; a test that omits it is not testing production.
        "audit_chain_secret": audit_chain_secret,
        "environment": "dev",
        "log_json": False,
        "argon2_time_cost": 1,
        "argon2_memory_cost": 8192,
        "login_min_duration_ms": 10,
        "registry_backend": "local",
        "metrics_public": True,
        "disable_spa_fallback": True,
    }
    fields.update(overrides)
    return Settings(**fields)  # type: ignore[arg-type]


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return _settings_for(migrated_db_url, migrated_audit_chain_secret)


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


def _sqlite_file(database_url: str) -> Path:
    return Path(database_url.removeprefix("sqlite+aiosqlite:///"))


def _alter_schema(database_url: str, *statements: str) -> None:
    """Run DDL against the migrated file the app is pointed at.

    Straight through ``sqlite3`` rather than the app's engine: the point is to
    produce a schema the product cannot produce, which is exactly what the
    Boundary-D and Boundary-F guards on that engine are there to prevent.
    """
    with sqlite3.connect(_sqlite_file(database_url)) as connection:
        for statement in statements:
            connection.execute(statement)


async def _seed_user(brain_app, settings) -> dict:
    """One user with both ways in: a cookie session and a bearer API key.

    The token is hashed with the endpoint's own hasher rather than a copy of
    it, so a change to the hashing scheme breaks this the same way it would
    break a real client instead of quietly minting a token nothing accepts.
    """
    from z4j_brain.api.api_keys import _hash_api_key
    from z4j_brain.persistence.models import ApiKey

    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    plaintext = f"z4k_{secrets.token_urlsafe(32)}"
    async with db.session() as s:
        proj = (
            await s.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if proj is None:
            s.add(Project(id=uuid.uuid4(), slug="default", name="default"))
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_active=True,
        )
        s.add(user)
        await s.flush()
        session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add(session_row)
        s.add(
            ApiKey(
                id=uuid.uuid4(),
                user_id=user.id,
                name="probe",
                token_hash=_hash_api_key(
                    plaintext=plaintext,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                prefix=plaintext[:8],
                scopes=["home:read"],
            ),
        )
        await s.commit()
    return {"session_id": session_row.id, "bearer": plaintext}


@contextlib.asynccontextmanager
async def _client(brain_app, settings, seeded=None):
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as ac:
        if seeded is not None:
            ac.cookies.set(
                cookie_name(environment=settings.environment),
                SessionCookieCodec(settings).encode(seeded["session_id"]),
            )
        yield ac


@pytest.mark.asyncio
async def test_deep_probe_requires_authentication(brain_app, settings) -> None:
    """The security decision this endpoint exists to respect.

    /health is deliberately public, and 1.6.3 removed even the version
    string from it so an unauthenticated caller could not pin CVEs.
    Subsystem topology is a bigger disclosure than a version, so it must
    not be reachable the same way.
    """
    async with _client(brain_app, settings) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_public_health_is_still_thin(brain_app, settings) -> None:
    """Guard against the deep payload leaking onto the public endpoint."""
    async with _client(brain_app, settings) as ac:
        resp = await ac.get("/api/v1/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_a_migrated_database_reports_every_subsystem_healthy(brain_app, settings) -> None:
    """The baseline every other claim in this file is measured against.

    A database built the way an operator's is must come back clean on all
    three probes. Without this the file could assert only that the fallback
    branches are reachable, and a probe wired to report degraded forever
    would pass every test here.
    """
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert set(body["checks"]) == {"database", "migrations", "audit_chain"}
    assert body["checks"]["database"]["status"] == "ok"
    assert "latency_ms" in body["checks"]["database"]
    assert body["checks"]["migrations"]["status"] == "ok"
    assert body["checks"]["migrations"]["revision"]
    assert body["checks"]["audit_chain"] == {
        "status": "ok",
        "activated": True,
        # Named rather than implied: the probe authenticates the state
        # row and does not walk the chain, and a reader of a green
        # answer should not have to guess which of the two it got.
        "scope": "state-only",
    }
    # A database with nothing wrong with it is where a green answer is most
    # likely to be over-read, so this is where the response has to be clearest
    # that it is not the boot path's verdict.
    assert body["coverage"]["startup_equivalent"] is False, body["coverage"]


@pytest.mark.asyncio
async def test_a_double_stamped_alembic_version_is_failed_not_degraded(brain_app, settings) -> None:
    """The state startup calls fatal cannot be reported as a warning.

    Two rows in ``alembic_version`` made ``scalar_one_or_none`` raise, and the
    handler read every exception as "no alembic_version table", so a database
    the brain will refuse to boot on was reported as an unmanaged schema with
    a 200. An operator watching this endpoint had no signal at all until the
    next restart failed.
    """
    seeded = await _seed_user(brain_app, settings)
    _alter_schema(
        settings.database_url,
        "INSERT INTO alembic_version (version_num) VALUES ('a_second_head')",
    )

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["status"] == "failed"
    assert body["checks"]["migrations"]["status"] == "failed"
    assert "2 rows" in body["checks"]["migrations"]["detail"]
    # The other probes still ran and still told the truth: one broken
    # subsystem must not erase the report on the rest.
    assert body["checks"]["database"]["status"] == "ok"
    assert body["checks"]["audit_chain"]["status"] == "ok"


@pytest.mark.asyncio
async def test_an_unreadable_alembic_version_is_failed(brain_app, settings) -> None:
    """Missing table and unreadable table are not the same finding.

    SQLite raises the same ``OperationalError`` for "no such table" and for
    "no such column", so a handler that narrows by exception class alone still
    reports a schema it could not read as a schema that was never migrated.
    """
    seeded = await _seed_user(brain_app, settings)
    _alter_schema(
        settings.database_url,
        "ALTER TABLE alembic_version RENAME COLUMN version_num TO stale_version_num",
    )

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["checks"]["migrations"]["status"] == "failed"
    # The class name, not the message: an operator learns which subsystem is
    # unhappy without the endpoint becoming a place internals leak.
    assert body["checks"]["migrations"]["detail"] == "OperationalError"
    assert "stale_version_num" not in resp.text


# ---------------------------------------------------------------------------
# Alignment with startup
#
# The endpoint's rule is stated in terms of what the boot path does, so these
# assert against the real boot path rather than against a second copy of a
# belief about it. Every case below is driven twice: once through the probe and
# once through ``verify_production_authority_at_startup``, on the same database.
# A future change that relaxes either one on its own breaks the pair.
# ---------------------------------------------------------------------------


async def _startup_verdict(brain_app, settings) -> Exception | None:
    """What the boot path does with this database: the exception, or None."""
    from z4j_brain.startup import verify_production_authority_at_startup

    try:
        await verify_production_authority_at_startup(
            db=brain_app.state.db,
            settings=settings,
        )
    except Exception as exc:
        # The verdict IS the exception; the caller decides what it means.
        return exc
    return None


#: Every schema state startup refuses, with the DDL that produces it and the
#: probe whose report has to agree. Driven as one table so a state added to the
#: boot check has an obvious place to be added here too.
_REFUSED_BY_STARTUP = [
    pytest.param(
        ("DROP TABLE alembic_version",),
        "migrations",
        "alembic_version is missing",
        id="alembic-version-table-missing",
    ),
    pytest.param(
        ("DELETE FROM alembic_version",),
        "migrations",
        "holds no row",
        id="alembic-version-empty",
    ),
    pytest.param(
        ("UPDATE alembic_version SET version_num = 'v1_8_bulk_retry_requests'",),
        "migrations",
        "run z4j migrate upgrade head",
        id="alembic-version-behind",
    ),
    pytest.param(
        ("UPDATE alembic_version SET version_num = 'v9_9_from_a_later_build'",),
        "migrations",
        "cannot reach by upgrading",
        id="alembic-version-not-upgradable",
    ),
    pytest.param(
        ("INSERT INTO alembic_version (version_num) VALUES ('v1_8_bulk_retry_requests')",),
        "migrations",
        "stamped more than once",
        id="alembic-version-double-stamped",
    ),
    pytest.param(
        ("DROP TABLE audit_chain_state",),
        "audit_chain",
        "audit_chain_state is missing",
        id="audit-chain-state-table-missing",
    ),
    pytest.param(
        ("DROP TABLE audit_chain_preparation",),
        "audit_chain",
        "audit_chain_preparation is missing",
        id="audit-chain-preparation-table-missing",
    ),
    pytest.param(
        (
            "INSERT INTO audit_chain_preparation (singleton_id, format_version, "
            "preparation_id, audit_key_id, preparation_revision, "
            "target_activation_revision, preparation_mac) VALUES "
            "('audit-chain', 1, x'0102030405060708090a0b0c0d0e0f10', "
            f"'{'a' * 64}', 'v1_8_audit_chain_prepare', "
            f"'v1_8_audit_chain_activate', '{'b' * 64}')",
        ),
        "audit_chain",
        "preparation is still pending",
        id="audit-chain-preparation-still-pending",
    ),
    pytest.param(
        (
            # The signer's own triggers are what stop this happening through
            # the product, so they go first. What is left is a state row whose
            # contents no longer match the MAC that authenticates them, which
            # is the state a probe that counts rows calls healthy.
            "DROP TRIGGER audit_chain_state_boundary_f_no_update",
            "UPDATE audit_chain_state SET active_row_count = active_row_count + 1",
        ),
        "audit_chain",
        "does not authenticate",
        id="audit-chain-state-does-not-authenticate",
    ),
]


@pytest.mark.parametrize(("statements", "check", "detail"), _REFUSED_BY_STARTUP)
@pytest.mark.asyncio
async def test_a_state_startup_refuses_is_not_reported_as_serving(
    brain_app,
    settings,
    statements,
    check,
    detail,
) -> None:
    """The lie this endpoint exists to be immune to.

    Each of these is a database the brain is serving on right now and cannot
    come back on. Reported degraded, it is a 200 with a warning field an
    operator has every reason to defer; reported failed, it is the 503 that
    says the next restart is a one-way door.
    """
    seeded = await _seed_user(brain_app, settings)
    _alter_schema(settings.database_url, *statements)

    verdict = await _startup_verdict(brain_app, settings)
    assert verdict is not None, (
        "this database was supposed to be one startup refuses; if the boot "
        "check now accepts it, the probe's classification below is the thing "
        "that has to change, not this assertion"
    )

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["status"] == "failed"
    assert body["checks"][check]["status"] == "failed"
    assert detail in body["checks"][check]["detail"], body["checks"][check]


# ---------------------------------------------------------------------------
# Where alignment with startup stops
#
# The table above is every refused state the probes can see, and in that
# direction the pairing holds. It does not hold in either of the other two, and
# the endpoint's wording has to survive both:
#
# - The boot path reads ``audit_log`` row by row and this endpoint does not, so
#   there is a database the boot path refuses and this endpoint answers 200 for.
# - This endpoint reports failed for a check that outlived its own deadline or
#   raised, and the boot path has no deadline at all, so there is a database
#   this endpoint answers 503 for and the boot path starts on.
#
# The endpoint states both in its response instead of implying otherwise. The
# two tests below are the demonstrations those statements rest on.
# ---------------------------------------------------------------------------


async def _append_signed_audit_row(brain_app, settings, *, action: str) -> None:
    """Append one audit row through the product's own signer.

    A hand-built row is what the chain is built to reject, and it would be
    caught by counts the probe could afford. Only a row that was signed the way
    an operator's rows are signed, and then altered, isolates the reading of
    the rows themselves as the thing that makes the difference.
    """
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.repositories import AuditLogRepository

    async with brain_app.state.db.session(write=True) as session:
        await AuditService(settings).record(
            AuditLogRepository(session),
            action=action,
            target_type="test",
        )
        await session.commit()


@pytest.mark.asyncio
async def test_a_tampered_audit_row_is_refused_at_boot_and_still_answers_200(
    brain_app,
    settings,
) -> None:
    """The limit of a green answer, demonstrated rather than described.

    Altering an ``audit_log`` row leaves the authenticated state row exactly as
    it was, so every check this endpoint runs passes on a database the boot
    path refuses to start on. That gap is real and it is not closable here: the
    boot path's walk locks ``audit_log`` against writers, costs the size of the
    table, and wants a write unit this read-only request does not have, on an
    endpoint every project member can poll. What the endpoint owes an operator
    instead is a response that cannot be mistaken for the boot path's verdict.

    Driven as a pair, so the claim cannot drift away from the behaviour in
    either direction. Narrow the probes and the boot verdict below stops
    matching; widen them to the boot path and the 200 becomes a 503; assert
    equivalence again and ``startup_equivalent`` is wrong. Each of the three
    breaks this test.
    """
    seeded = await _seed_user(brain_app, settings)
    await _append_signed_audit_row(brain_app, settings, action="probe.signed")
    _alter_schema(
        settings.database_url,
        # The append-only trigger is what stops this happening through the
        # product, so it goes first. What is left is one row whose contents no
        # longer match the signature over them, with the chain state row and
        # every count it authenticates untouched.
        "DROP TRIGGER audit_log_boundary_f_no_update",
        "UPDATE audit_log SET action = 'probe.tampered' WHERE action = 'probe.signed'",
    )

    verdict = await _startup_verdict(brain_app, settings)
    assert verdict is not None, (
        "the tampered row was supposed to be one the boot path refuses; if it "
        "now boots, this test is measuring nothing"
    )
    # Named, not merely non-None. The boot path authenticates the state row
    # before it reads any audit row, so this particular finding is the proof
    # that the state row still authenticates and that reading the rows is the
    # only thing that objected -- which is exactly the work the probe skips.
    assert "active row HMAC mismatch" in str(verdict), verdict

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 200, resp.text
    assert body["status"] == "ok"
    assert body["checks"]["audit_chain"] == {
        "status": "ok",
        "activated": True,
        "scope": "state-only",
    }
    # And the response says, in the payload rather than in a docstring nobody
    # polling an endpoint reads, that this 200 is not the answer the boot path
    # would give for the same database.
    assert body["coverage"]["startup_equivalent"] is False, body["coverage"]
    assert "audit_log" in body["coverage"]["detail"], body["coverage"]


#: The two ways a check ends up failed without having decided anything about
#: the schema: it outlives its own deadline, or it raises. Both are limits this
#: endpoint imposes on itself, and the boot path imposes neither.
_FAILED_WITHOUT_A_SCHEMA_VERDICT = [
    pytest.param("deadline", "exceeded", id="check-outlives-its-deadline"),
    pytest.param("raises", "RuntimeError", id="check-raises"),
]


@pytest.mark.parametrize(("mode", "detail"), _FAILED_WITHOUT_A_SCHEMA_VERDICT)
@pytest.mark.asyncio
async def test_a_failed_check_is_not_proof_that_startup_would_refuse(
    brain_app,
    settings,
    monkeypatch,
    mode,
    detail,
) -> None:
    """The other limit of the verdict, and the reason it is stated in both directions.

    A check that runs out of :data:`_DEEP_CHECK_TIMEOUT_S` or blows up is
    reported failed, which is right: a subsystem this brain cannot answer for
    belongs in a 503 rather than being quietly omitted. What it is not is a
    statement about the next restart. ``verify_production_authority_at_startup``
    runs its queries with no deadline, so a database slow enough to miss a
    three second budget is a 503 here and a clean start there.

    Driven as a pair for the same reason the tampered-row test above is: the
    database is asserted to be one the boot path ACCEPTS, so the 503 and the
    successful boot are two answers about one database rather than two
    descriptions of two situations.
    """
    seeded = await _seed_user(brain_app, settings)

    async def _too_slow(_session, _settings):
        await asyncio.sleep(30)

    async def _raises(_session, _settings):
        raise RuntimeError("the connection went away mid-probe")

    if mode == "deadline":
        monkeypatch.setattr(health_mod, "_DEEP_CHECK_TIMEOUT_S", 0.05)
        monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _too_slow)
    else:
        monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _raises)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["status"] == "failed"
    assert body["checks"]["database"]["status"] == "failed"
    assert detail in body["checks"]["database"]["detail"], body["checks"]["database"]

    # The same database, put to the authority that actually decides whether the
    # brain comes back. Nothing was done to the schema, so this has to be None;
    # if it is not, the 503 above has a second explanation and the test is
    # measuring nothing.
    assert await _startup_verdict(brain_app, settings) is None, (
        "the database under test was supposed to be one the boot path accepts"
    )
    # And the response says so where an operator holding the 503 will see it,
    # rather than only in a docstring nobody polling an endpoint reads.
    assert body["coverage"]["startup_equivalent"] is False, body["coverage"]


@pytest.mark.asyncio
async def test_an_unreachable_revision_is_not_sent_to_upgrade_head(
    brain_app,
    settings,
) -> None:
    """The remedy has to be one that can work.

    A database stamped by a build this one has never heard of is a wrong-binary
    or wrong-direction problem. ``upgrade head`` cannot resolve it, so naming
    it as the fix costs the operator the outage it takes to find that out.
    """
    seeded = await _seed_user(brain_app, settings)
    _alter_schema(
        settings.database_url,
        "UPDATE alembic_version SET version_num = 'v9_9_from_a_later_build'",
    )

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    migrations = resp.json()["checks"]["migrations"]
    assert migrations["status"] == "failed"
    assert "upgrade head" not in migrations["detail"], migrations
    assert migrations["revision"] == "v9_9_from_a_later_build"
    assert migrations["expected"] == RELEASE_MIGRATION_HEAD


@pytest.mark.asyncio
async def test_the_expected_revision_is_the_one_startup_boots_on(
    brain_app,
    settings,
    monkeypatch,
) -> None:
    """Which head the probe compares against, and how you can tell.

    The release constant and the shipped scripts' head are the same revision in
    a released build, so a probe that resolved the head from the scripts would
    pass every other test in this file. It is only separable when the two
    disagree, which is what a build carrying an unreleased migration looks
    like: the database sits at the script head, startup refuses it, and a
    script-derived probe calls it healthy.

    Moving the constant out from under both is the only way to produce that
    disagreement without a second set of migration scripts. The database is
    untouched throughout -- what changes is which head the two authorities are
    asked to require.
    """
    seeded = await _seed_user(brain_app, settings)

    # Unpatched: the boot path and the probe both accept this database.
    async with _client(brain_app, settings, seeded) as ac:
        healthy = (await ac.get(_URL)).json()["checks"]["migrations"]
    assert healthy["status"] == "ok"
    assert healthy["revision"] == RELEASE_MIGRATION_HEAD
    assert await _startup_verdict(brain_app, settings) is None

    from z4j_brain import startup as startup_mod

    other_head = "v9_9_a_head_this_build_does_not_ship"
    monkeypatch.setattr(health_mod, "RELEASE_MIGRATION_HEAD", other_head)
    monkeypatch.setattr(startup_mod, "RELEASE_MIGRATION_HEAD", other_head)

    verdict = await _startup_verdict(brain_app, settings)
    assert verdict is not None, "the boot path was supposed to move with the constant"

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    migrations = resp.json()["checks"]["migrations"]
    assert resp.status_code == 503, resp.text
    assert migrations["status"] == "failed", (
        "the probe kept reporting healthy after the head the brain boots on "
        "moved, which means it is comparing against something other than the "
        "revision startup requires"
    )
    assert migrations["expected"] == other_head
    assert migrations["revision"] == RELEASE_MIGRATION_HEAD


@pytest.mark.asyncio
async def test_each_probe_is_rolled_back_before_the_next_one_runs(
    brain_app, settings, monkeypatch
) -> None:
    """The isolation the shared session makes mandatory, and its exact form.

    Every probe runs on the request's session. PostgreSQL aborts the whole
    transaction on the first statement error, so an un-migrated database, whose
    migrations probe legitimately fails, would report every later subsystem as
    broken too. A savepoint alone is not the fix: a probe answers a missing
    table with a report rather than an exception, so it returns normally and
    the savepoint gets RELEASED, and a release does not clear an aborted
    PostgreSQL transaction. It has to be rolled back.

    Driven with a probe that writes because that is the only way the release
    and the rollback look different on SQLite, which never aborts a transaction
    and so cannot show the poisoning itself (see the ``Z4J_TEST_POSTGRES_URL``
    test below). Real probes only read.
    """
    observed: dict[str, object] = {}

    async def _scribble(session, _settings):
        observed["nested"] = session.in_nested_transaction()
        await session.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('probe_scratch')"),
        )
        return {"status": "ok"}

    async def _count(session, _settings):
        observed["rows"] = (
            await session.execute(text("SELECT count(*) FROM alembic_version"))
        ).scalar_one()
        return {"status": "ok"}

    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _scribble)
    monkeypatch.setitem(health_mod._DEEP_CHECKS, "migrations", _count)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 200, resp.text
    assert observed["nested"] is True, (
        "a probe running outside a savepoint cannot fail without taking every "
        "later probe down with it"
    )
    assert observed["rows"] == 1, (
        "the previous probe's savepoint was released rather than rolled back, "
        "which on PostgreSQL leaves an aborted transaction aborted"
    )


@pytest.mark.asyncio
async def test_a_raising_check_is_failed_not_omitted(brain_app, settings, monkeypatch) -> None:
    """The failure mode that would make this endpoint dangerous.

    If a check that blows up were dropped from the response, the payload
    would look like a clean bill of health for a subsystem nobody managed
    to probe.
    """

    async def _boom(_session, _settings):
        raise RuntimeError("subsystem is on fire")

    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _boom)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    body = resp.json()
    assert resp.status_code == 503
    assert body["status"] == "failed"
    assert body["checks"]["database"]["status"] == "failed"
    # The class name, not the message: an operator learns which subsystem
    # is unhappy without the endpoint becoming a place internals leak.
    assert body["checks"]["database"]["detail"] == "RuntimeError"
    assert "on fire" not in resp.text


@pytest.mark.asyncio
async def test_a_hanging_check_times_out_rather_than_hanging_the_probe(
    brain_app, settings, monkeypatch
) -> None:
    """A probe that hangs takes down the thing it was meant to watch."""

    async def _hang(_session, _settings):
        await asyncio.sleep(30)

    monkeypatch.setattr(health_mod, "_DEEP_CHECK_TIMEOUT_S", 0.05)
    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _hang)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 503
    assert resp.json()["checks"]["database"]["status"] == "failed"
    assert "exceeded" in resp.json()["checks"]["database"]["detail"]


@pytest.mark.asyncio
async def test_degraded_does_not_return_503(brain_app, settings, monkeypatch) -> None:
    """Degraded is a warning, not an outage.

    Returning 503 for a degraded subsystem would have an orchestrator
    restart a brain that is serving traffic perfectly well.
    """

    async def _degraded(_session, _settings):
        return {"status": "degraded", "detail": "behind but working"}

    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _degraded)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


@pytest.mark.asyncio
async def test_failed_outranks_degraded(brain_app, settings, monkeypatch) -> None:
    """The overall status must be the worst one, not the last one."""

    async def _degraded(_session, _settings):
        return {"status": "degraded"}

    async def _failed(_session, _settings):
        return {"status": "failed"}

    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _failed)
    monkeypatch.setitem(health_mod._DEEP_CHECKS, "migrations", _degraded)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.json()["status"] == "failed"


#: How long a health probe on a one-connection pool may take before the answer
#: stops being useful. Generous by two orders of magnitude against the work the
#: request does, and far below SQLAlchemy's 30s default pool-checkout timeout,
#: so a request that waits for a connection it will never get fails here rather
#: than passing slowly.
_ONE_CONNECTION_BUDGET_S: float = 5.0


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", ["cookie", "bearer"])
async def test_deep_health_works_on_a_one_connection_pool(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
    credential: str,
) -> None:
    """A pool of exactly one is a supported configuration, so it must work.

    ``pool_size=1, max_overflow=0`` is explicitly permitted by settings.
    Authentication holds the request's session for the whole request, so a
    probe that opened its own session needed two connections at once. On this
    pool every probe blocked until its own 3s timeout and the endpoint reported
    a perfectly reachable database as failed: a false alarm that an operator
    would page on.

    Driven through the endpoint, over both credentials, on an engine built by
    the product's own factory from the operator's own setting. Calling the
    probes directly on a hand-held session skips the entire dependency stack,
    and the dependency stack is where the second connection gets taken: one
    credential resolves entirely on the request's session and the other does
    not, which is a difference no probe-level test can see.

    The migrated fixture is file-backed, which this test needs: in-memory
    SQLite gets a StaticPool, which has no size and therefore cannot exhibit
    the bug. The savepoint each probe now runs in costs no extra connection,
    which is the other half of what this pins.
    """
    from z4j_brain.persistence.database import create_engine_from_settings

    settings = _settings_for(
        migrated_db_url,
        migrated_audit_chain_secret,
        database_pool_size=1,
        database_max_overflow=0,
    )
    engine = create_engine_from_settings(settings)
    try:
        assert engine.pool.size() == 1, "the pool under test is not the pool configured"
        app = create_app(settings, engine=engine)
        app.state.lifespan_ready = True
        seeded = await _seed_user(app, settings)

        if credential == "cookie":
            client_seed, headers = seeded, {}
        else:
            client_seed = None
            headers = {"Authorization": f"Bearer {seeded['bearer']}"}

        async with _client(app, settings, client_seed) as ac:
            try:
                resp = await asyncio.wait_for(
                    ac.get(_URL, headers=headers),
                    timeout=_ONE_CONNECTION_BUDGET_S,
                )
            except TimeoutError:
                pytest.fail(
                    f"/health/deep did not answer within {_ONE_CONNECTION_BUDGET_S}s on "
                    f"{credential} auth with pool_size=1, max_overflow=0: something on "
                    "the request path is waiting for a second connection that this "
                    "pool will never hand out",
                )
    finally:
        await engine.dispose()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body["checks"]) == set(_DEEP_CHECKS)
    assert body["checks"]["database"]["status"] == "ok"
    assert body["checks"]["migrations"]["status"] == "ok"


# ---------------------------------------------------------------------------
# The deadline has to cover the whole probe, including its transaction plumbing
# ---------------------------------------------------------------------------

#: How long the endpoint may take once every probe's own budget is 50ms. Three
#: probes plus request overhead is milliseconds; anything approaching this is
#: not slowness, it is a wait with no bound on it.
_ANSWER_BUDGET_S: float = 10.0


async def _get_within_budget(brain_app, settings, seeded, what: str):
    """Fetch the endpoint, failing the test if it does not answer at all."""
    async with _client(brain_app, settings, seeded) as ac:
        try:
            return await asyncio.wait_for(ac.get(_URL), timeout=_ANSWER_BUDGET_S)
        except TimeoutError:
            pytest.fail(
                f"the endpoint never answered with {what} stalled; the probe "
                f"deadline does not cover it, so the request has no bound"
            )


@pytest.mark.asyncio
async def test_a_stalled_savepoint_does_not_hang_the_endpoint(
    brain_app,
    settings,
    monkeypatch,
) -> None:
    """Opening the savepoint is a round trip to the database being probed.

    A database that has stopped answering stalls on ``SAVEPOINT`` before any
    probe body is entered. A deadline that starts after that call bounds the
    part of the work that was never going to be the problem, and the endpoint
    an operator polls to find out whether the database is answering is itself
    held open by the database not answering.
    """
    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

    seeded = await _seed_user(brain_app, settings)
    monkeypatch.setattr(health_mod, "_DEEP_CHECK_TIMEOUT_S", 0.05)
    forever = asyncio.Event()

    async def _stall(self, *args, **kwargs):
        await forever.wait()

    monkeypatch.setattr(_AsyncSession, "begin_nested", _stall)

    resp = await _get_within_budget(brain_app, settings, seeded, "SAVEPOINT")

    body = resp.json()
    assert resp.status_code == 503, resp.text
    for name in ("database", "migrations", "audit_chain"):
        assert body["checks"][name]["status"] == "failed", body
        assert "exceeded" in body["checks"][name]["detail"], body


@pytest.mark.asyncio
async def test_a_stalled_rollback_does_not_hang_the_endpoint(
    brain_app,
    settings,
    monkeypatch,
) -> None:
    """And so is releasing it again.

    The probe's own deadline cannot cover the cleanup that runs after it
    expires, because a deadline that has fired does not fire twice. Left
    unbounded, a rollback that never returns holds the request exactly as long
    as an unbounded probe would have, which is the failure the deadline was
    put there to prevent.
    """
    from sqlalchemy.ext.asyncio import AsyncSessionTransaction

    seeded = await _seed_user(brain_app, settings)
    monkeypatch.setattr(health_mod, "_DEEP_CHECK_TIMEOUT_S", 0.05)
    forever = asyncio.Event()

    async def _stall(self, *args, **kwargs):
        await forever.wait()

    monkeypatch.setattr(AsyncSessionTransaction, "rollback", _stall)

    resp = await _get_within_budget(brain_app, settings, seeded, "the rollback")

    body = resp.json()
    assert resp.status_code == 503, resp.text
    assert body["checks"]["database"]["status"] == "failed", body


# ---------------------------------------------------------------------------
# The published contract
#
# The dashboard's TypeScript types are generated from a snapshot of this
# document, so what the document omits is a shape no client can read. Left to
# the route's ``dict[str, object]`` return annotation, the generator published
# an untyped object and a 200 with no failure case beside it, on the one
# endpoint whose reason to exist is the failure case.
# ---------------------------------------------------------------------------


def _resolve(spec: dict, node: dict) -> dict:
    """Follow one schema reference, in whichever shape the generator emitted it."""
    if "$ref" not in node and "allOf" in node:
        node = node["allOf"][0]
    return spec["components"]["schemas"][node["$ref"].rsplit("/", 1)[-1]]


@pytest.mark.asyncio
async def test_the_published_contract_describes_the_body_the_endpoint_returns(
    brain_app,
    settings,
) -> None:
    """Checked against real responses, not against a second copy of a belief.

    A spec asserted on its own passes as long as it is self-consistent, which
    is how a wildcard came to be published in the first place: the document and
    anything checking it agreed with each other and neither agreed with the
    brain. So every key asserted below is a key an actual response carried, and
    both status codes are fetched, because the fields that only appear on a
    failure are exactly the ones a wrong contract would leave undeclared.
    """
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        healthy = await ac.get(_URL)
        # A real failure rather than a stubbed one, so the failed check carries
        # the fields the shipped probe puts on it (``detail``, ``expected``)
        # instead of whatever a stub happened to invent.
        _alter_schema(
            settings.database_url,
            "UPDATE alembic_version SET version_num = 'v9_9_from_a_later_build'",
        )
        unhealthy = await ac.get(_URL)

    assert healthy.status_code == 200, healthy.text
    assert unhealthy.status_code == 503, unhealthy.text
    live = {"200": healthy.json(), "503": unhealthy.json()}

    spec = brain_app.openapi()
    operation = spec["paths"][_URL]["get"]

    # A 503 is half of what this endpoint answers. Documented as 200-only, a
    # generated client is typed as though a failing subsystem cannot happen.
    assert {"200", "503"} <= set(operation["responses"]), operation["responses"]

    observed_check_keys: set[str] = set()
    for code, payload in live.items():
        body = _resolve(
            spec,
            operation["responses"][code]["content"]["application/json"]["schema"],
        )
        assert set(body["properties"]) == set(payload), (
            f"the {code} schema names {sorted(body['properties'])} where a real "
            f"response carried {sorted(payload)}"
        )

        coverage = _resolve(spec, body["properties"]["coverage"])
        assert set(coverage["properties"]) == set(payload["coverage"]), (
            f"the {code} coverage schema and the response disagree on its keys"
        )

        result = _resolve(spec, body["properties"]["checks"]["additionalProperties"])
        declared = set(result["properties"])
        for name, check in payload["checks"].items():
            assert set(check) <= declared, (
                f"the {name} check returned {sorted(set(check) - declared)} on a "
                f"{code}, which the published schema does not name"
            )
            observed_check_keys |= set(check)
        assert result["properties"]["status"]["enum"] == ["ok", "degraded", "failed"]

    # The failing response is what widens this beyond ``status``; asserting the
    # union pins that the 503 was worth fetching.
    assert {"detail", "expected", "revision", "latency_ms"} <= observed_check_keys, (
        f"the two responses only exercised {sorted(observed_check_keys)}, so most "
        f"of the published check schema was never compared against anything"
    )


@pytest.mark.asyncio
async def test_a_field_a_probe_invents_is_not_dropped_from_the_response(
    brain_app,
    settings,
    monkeypatch,
) -> None:
    """The cost a declared response model must not impose on this endpoint.

    A closed model silently discards a key it was not told about. Everywhere
    else that is tidiness; here it means a probe reports a detail and the
    operator reading the response never sees it, which is the same class of
    harm as omitting the check. ``DeepCheckResult`` is open for that reason,
    and this is what says so.
    """

    async def _extra(_session, _settings):
        return {"status": "failed", "detail": "gone", "replica_lag_s": 41.0}

    monkeypatch.setitem(health_mod._DEEP_CHECKS, "database", _extra)
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 503, resp.text
    assert resp.json()["checks"]["database"]["replica_lag_s"] == 41.0


@pytest.mark.asyncio
async def test_a_field_a_probe_did_not_answer_is_absent_rather_than_null(
    brain_app,
    settings,
) -> None:
    """Declaring the contract must not change the body an operator reads.

    The probes report by omission: a field a probe had no answer for is not in
    its result. Serialising the declared fields unconditionally would put
    ``"revision": null`` in front of an operator on a check that never looks at
    a revision, which reads as asked-and-empty rather than as not asked.
    """
    seeded = await _seed_user(brain_app, settings)

    async with _client(brain_app, settings, seeded) as ac:
        resp = await ac.get(_URL)

    assert resp.status_code == 200, resp.text
    checks = resp.json()["checks"]
    assert checks["audit_chain"] == {"status": "ok", "activated": True, "scope": "state-only"}
    assert set(checks["database"]) == {"status", "latency_ms"}
    assert set(checks["migrations"]) == {"status", "revision"}
