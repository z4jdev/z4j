"""Health and readiness endpoints.

- ``/api/v1/health`` - liveness probe. Returns ``200 OK`` as long as
  the process is up. No I/O. This is the endpoint used by the shipped
  Dockerfiles and Compose container healthchecks; container "healthy"
  therefore means process-alive, not database-ready.
- ``/api/v1/health/ready`` - readiness probe. Runs ``SELECT 1``
  against the database with a short timeout. Returns ``200`` only
  after lifespan startup completes and the database is reachable.
  External orchestrators and load balancers can use it to gate traffic,
  but the shipped Dockerfiles and Compose healthchecks do not use it.
- ``/api/v1/health/system`` - authenticated build, platform, and
  database detail for the dashboard.
- ``/api/v1/health/deep`` - authenticated per-subsystem report, for
  naming which subsystem is unhappy. Carries a statement of what its
  own verdict covers, in both directions: the checks it runs are
  narrower than the boot path, and they can also fail on a deadline
  the boot path does not have.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain import __version__
from z4j_brain.api.deps import get_current_user, get_db, get_session, get_settings
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
from z4j_brain.settings import Settings

router = APIRouter(tags=["health"])

#: Hard timeout (seconds) on the readiness DB ping.
_READINESS_DB_TIMEOUT_S: float = 2.0


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe. No I/O.

    Returns ``200 OK``. The point is to give container runtimes
    something cheap and reliable to poll: a process that can answer
    this endpoint is process-alive.

    .. note::
       1.6.3 security advisory: removed the ``version`` field from
       this response. The endpoint is publicly reachable (by design,
       for liveness probes) so leaking the brain version let
       attackers pin specific CVEs to a target. Version disclosure
       moved to :func:`health_system` (auth-gated).
    """
    return {"status": "ok"}


@router.get("/health/ready")
async def health_ready(
    request: Request,
    response: Response,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, str]:
    """Readiness probe. Issues ``SELECT 1`` with a hard timeout.

    Returns ``200 OK`` if the database is reachable, ``503`` if it
    is not. Never raises - the response object is mutated in place.

    Also gates on ``app.state.lifespan_ready``. Without this gate
    the brain would return 200 the moment uvicorn bound the
    port, but lifespan startup (run_first_boot_check,
    registry.start, supervisor.start) runs AFTER the routes are
    mounted, so a k8s readiness probe would flip "ready" while
    the brain was still pre-bootstrap. The flag is set at the
    END of the lifespan startup phase in main.py.
    """
    if not getattr(request.app.state, "lifespan_ready", False):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unready", "reason": "starting"}
    try:
        async with db.session() as session:
            await asyncio.wait_for(
                session.execute(text("SELECT 1")),
                timeout=_READINESS_DB_TIMEOUT_S,
            )
    except (TimeoutError, Exception):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unready", "reason": "database"}

    # 1.6.3: no version field -- this endpoint is also publicly
    # reachable (k8s readiness probe) so leaking version invites
    # CVE-pin attacks. Version disclosure moved to /health/system
    # (auth-gated).
    return {"status": "ready"}


@router.get("/health/system")
async def health_system(
    db: DatabaseManager = Depends(get_db),
    _user: object = Depends(get_current_user),
) -> dict[str, object]:
    """System information for the dashboard settings page.

    Requires authentication - exposes database version, Python
    version, and package details that should not be public.
    """
    import os
    import platform
    import sys

    info: dict[str, object] = {
        "z4j_version": __version__,
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "pid": os.getpid(),
    }

    # Database info.
    try:
        async with db.session() as session:
            bind = session.get_bind()
            dialect = bind.dialect.name
            info["database_type"] = dialect

            if dialect == "postgresql":
                result = await session.execute(text("SELECT version()"))
                row = result.scalar_one_or_none()
                if row:
                    info["database_version"] = str(row).split(",")[0]

                result = await session.execute(
                    text("SELECT pg_database_size(current_database())"),
                )
                db_size = result.scalar_one_or_none()
                if db_size:
                    info["database_size_mb"] = round(int(db_size) / 1_048_576, 1)

                result = await session.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    ),
                )
                info["database_connections"] = result.scalar_one_or_none()
            elif dialect == "sqlite":
                info["database_version"] = "SQLite"
    except Exception:
        info["database_type"] = "unknown"
        info["database_error"] = "failed to query database info"

    # Package versions.
    try:
        import importlib.metadata as im

        packages = {}
        for pkg in ["fastapi", "uvicorn", "sqlalchemy", "pydantic", "celery"]:
            with contextlib.suppress(im.PackageNotFoundError):
                packages[pkg] = im.version(pkg)
        info["packages"] = packages
    except Exception:  # noqa: S110  best-effort package version probe
        pass

    return info


#: Hard timeout on any single deep check. A probe that hangs is a probe that
#: takes the endpoint down with it, which is the opposite of the job.
_DEEP_CHECK_TIMEOUT_S: float = 3.0

#: SQLSTATE ``undefined_table``.
_UNDEFINED_TABLE_SQLSTATE = "42P01"


def _is_missing_relation(exc: BaseException) -> bool:
    """Is this "that table does not exist" specifically, or some other fault?

    The probes below read a missing bookkeeping table as an un-migrated
    database, which is a fair thing to call degraded. Reading EVERY database
    error that way was not. A second row in ``alembic_version`` was reported as
    "schema is not Alembic-managed" with a 200 while startup refuses to boot on
    exactly that state, so an operator polling this endpoint saw a benign
    warning about a brain that cannot restart.

    PostgreSQL is identified by SQLSTATE. SQLite has no SQLSTATE and folds
    every schema fault into one ``OperationalError``, so it is identified by
    message -- on the raw driver exception rather than the SQLAlchemy wrapper,
    whose ``str`` embeds the failing statement and its bound parameters.
    """
    if not isinstance(exc, (ProgrammingError, OperationalError)):
        return False
    original = getattr(exc, "orig", None) or exc
    for attribute in ("sqlstate", "pgcode"):
        code = getattr(original, attribute, None)
        if isinstance(code, str):
            return code == _UNDEFINED_TABLE_SQLSTATE
    return "no such table" in str(original).lower()


async def _check_database(
    session: AsyncSession,
    settings: Settings,
) -> dict[str, object]:
    """Round-trip the database and report how long it took."""
    started = asyncio.get_running_loop().time()
    await session.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "latency_ms": round((asyncio.get_running_loop().time() - started) * 1000, 1),
    }


def _is_reachable_by_upgrade(revision: str) -> bool | None:
    """Can this build move a database at ``revision`` up to the head it boots on?

    ``True`` for an ancestor of the release head, ``False`` for anything else
    the shipped scripts do not place below it (a newer revision, a revision
    from a different lineage), and ``None`` when the scripts cannot be read at
    all and the question has no answer.
    """
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        # Reuse the CLI's resolver so the probe and `z4j migrate` can never
        # disagree about which alembic.ini is authoritative.
        from z4j_brain.cli import _find_alembic_config_path

        config_path = _find_alembic_config_path()
        if config_path is None:
            return None
        script = ScriptDirectory.from_config(Config(str(config_path)))
        ancestors = script.iterate_revisions(RELEASE_MIGRATION_HEAD, "base")
        return any(entry.revision == revision for entry in ancestors)
    except Exception:
        # An unreadable or inconsistent script directory says nothing about the
        # database, and the caller has already decided this is a failure. The
        # only thing lost is the ability to name the remedy precisely.
        return None


def _revision_mismatch_detail(revision: str) -> str:
    """Say what is actually wrong with a revision that is not the boot head.

    Only a database this build can move FORWARD onto its head has "upgrade" as
    its answer. A database stamped by a newer build, or by a different lineage,
    is a wrong-binary or wrong-direction problem, and sending that operator to
    ``upgrade head`` sends them to a command that cannot succeed and away from
    the thing that is broken.
    """
    reachable = _is_reachable_by_upgrade(revision)
    if reachable is True:
        return (
            f"database is stamped {revision}, behind the head this build boots "
            "on; run z4j migrate upgrade head"
        )
    if reachable is False:
        return (
            f"database is stamped {revision}, which this build cannot reach by "
            "upgrading; it was migrated by a different z4j build, so the fix "
            "is the running binary or a downgrade, not an upgrade"
        )
    return (
        f"database is stamped {revision}, not the head this build boots on; "
        "the shipped migration scripts could not be read, so which of the two "
        "is ahead cannot be determined here"
    )


async def _check_migrations(
    session: AsyncSession,
    settings: Settings,
) -> dict[str, object]:
    """Compare the database's Alembic revision against the head this build boots on.

    The expectation is :data:`RELEASE_MIGRATION_HEAD`, the same constant
    startup refuses to boot without, rather than whatever revision the shipped
    scripts happen to end at. Those two are the same in a released build and
    diverge in a build carrying an unreleased migration, and taking the second
    would report a database as healthy that the next restart rejects.

    Every state startup rejects is reported failed rather than degraded.
    Degraded is for a subsystem that is working less well than it should; a
    brain that is serving now and cannot come back is not that, and an operator
    polling this endpoint gets no warning that a restart is a one-way door.
    """
    expected = RELEASE_MIGRATION_HEAD
    try:
        result = await session.execute(
            text("SELECT version_num FROM alembic_version"),
        )
        revisions = list(result.scalars())
    except (ProgrammingError, OperationalError) as exc:
        if not _is_missing_relation(exc):
            raise
        # No alembic_version table at all. Startup checks for this table by
        # name and refuses the database before anything else runs, so the
        # schema having been created some other way is not a benign local
        # convenience here; it is a brain that cannot restart.
        return {
            "status": "failed",
            "expected": expected,
            "detail": (
                "alembic_version is missing; this schema was not built by the "
                "migration chain and this brain will refuse to start"
            ),
        }

    if len(revisions) > 1:
        return {
            "status": "failed",
            "expected": expected,
            "detail": (
                f"alembic_version holds {len(revisions)} rows; the schema was "
                "stamped more than once and this brain will refuse to start"
            ),
        }
    if not revisions:
        # An empty table is not "no revision to compare". Startup compares the
        # rows it reads against exactly one expected head, and no rows fails
        # that comparison the same way two rows do.
        return {
            "status": "failed",
            "expected": expected,
            "detail": (
                "alembic_version holds no row; the schema is not stamped and "
                "this brain will refuse to start"
            ),
        }

    db_head = revisions[0]
    if db_head == expected:
        return {"status": "ok", "revision": db_head}
    return {
        "status": "failed",
        "revision": db_head,
        "expected": expected,
        "detail": _revision_mismatch_detail(db_head),
    }


async def _check_audit_chain(  # noqa: PLR0911  one exit per rejected state, each named
    session: AsyncSession,
    settings: Settings,
) -> dict[str, object]:
    """Report whether the authenticated chain STATE startup demands is intact.

    Not "is there a row". The boot path authenticates the state row's MAC
    against the configured keyring and refuses to serve when that fails, so a
    row counted and not authenticated is precisely the database this endpoint
    exists to stop calling healthy: present, non-empty, and rejected by the
    next restart. The same goes for the rest of the bounded conditions boot
    checks -- an unconfigured key, a preparation record still pending, a state
    row that is duplicated instead of singular.

    What this probe does not do is anything the boot check asks of ``audit_log``
    itself. That is not only the per-row HMAC walk: it is also the row counts
    the authenticated state is compared against, the frozen-manifest digest,
    the per-key tallies, and the comparison of the retained tail against the
    authenticated head, none of which can be answered without reading the
    table. All of it costs the size of the table on an endpoint that is polled,
    and the unqualified row count alone is a full scan on PostgreSQL. The
    scheduled verifier owns that work. ``scope`` is reported on every answer,
    ok or not, so a green one cannot be read as having covered it, and
    :func:`health_deep` states the same limit at the top of the response.
    """
    from z4j_brain.domain.audit_chain import (
        AUDIT_CHAIN_SINGLETON_ID,
        AuditChainIntegrityError,
        authenticate_state,
        canonical_audit_key_id,
    )
    from z4j_brain.persistence.models import AuditChainState

    unverified: dict[str, object] = {"activated": False, "scope": "state-only"}
    if settings.audit_chain_secret is None:
        return {
            "status": "failed",
            **unverified,
            "detail": (
                "no audit-chain key is configured, so the authenticated state "
                "cannot be checked and this brain will refuse to start"
            ),
        }

    # Same rule the migrations probe follows for a table it cannot find.
    # Startup looks for these tables by name and refuses the database without
    # them, so an absence is not a subsystem waiting to be switched on; it is
    # a brain that cannot restart, and reporting that as a warning is the lie
    # this endpoint is supposed to be immune to. Asked in two statements so
    # each absence can be named: on PostgreSQL the first missing table aborts
    # the transaction, and this returns before the second is attempted.
    try:
        pending = (
            await session.execute(
                text("SELECT count(*) FROM audit_chain_preparation"),
            )
        ).scalar_one_or_none() or 0
    except (ProgrammingError, OperationalError) as exc:
        if not _is_missing_relation(exc):
            raise
        return {
            "status": "failed",
            **unverified,
            "detail": ("audit_chain_preparation is missing; this brain will refuse to start"),
        }

    try:
        rows = list(
            (
                await session.execute(
                    select(AuditChainState).where(
                        AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                    ),
                )
            ).scalars(),
        )
    except (ProgrammingError, OperationalError) as exc:
        if not _is_missing_relation(exc):
            raise
        return {
            "status": "failed",
            **unverified,
            "detail": "audit_chain_state is missing; this brain will refuse to start",
        }

    if pending:
        return {
            "status": "failed",
            **unverified,
            "detail": (
                "audit-chain preparation is still pending; startup refuses a "
                "database that has not been through the activation ceremony"
            ),
        }
    if len(rows) != 1:
        return {
            "status": "failed",
            **unverified,
            "detail": (
                f"audit_chain_state holds {len(rows)} rows where exactly one is "
                "required; this brain will refuse to start"
            ),
        }

    keyring = {
        canonical_audit_key_id(secret): secret
        for secret in settings.all_audit_chain_secrets_for_verification()
    }
    try:
        authenticate_state(rows[0], keyring)
    except AuditChainIntegrityError:
        # The reason is deliberately not echoed. It is decided by the state
        # row's own contents against the configured keys, and this endpoint is
        # reachable by every project member.
        return {
            "status": "failed",
            **unverified,
            "detail": (
                "the audit chain state does not authenticate against the "
                "configured keys; startup verifies it before serving and this "
                "brain will refuse to start"
            ),
        }
    return {"status": "ok", "activated": True, "scope": "state-only"}


# ---------------------------------------------------------------------------
# The published shape of the deep report
#
# Declared rather than inferred from the ``dict`` return annotation. Inferred,
# the generated document was one wildcard object with a 200 beside it and
# nothing else, which tells a client that the failure case does not exist -- on
# the one endpoint whose entire purpose is the failure case, and from which the
# dashboard's TypeScript types are generated.
# ---------------------------------------------------------------------------


class DeepCheckResult(BaseModel):
    """One subsystem's answer. Which fields accompany ``status`` is the probe's.

    Open rather than closed (``extra="allow"``) because a response model that
    silently dropped a key it had not been told about would let a probe report
    a detail the operator never sees, which is the failure this endpoint is
    built not to have. The fields below are the ones the shipped probes emit,
    so a generated client has them by name instead of by guess.
    """

    model_config = ConfigDict(extra="allow")

    status: Literal["ok", "degraded", "failed"]
    detail: str | None = Field(
        default=None,
        description=(
            "Why this subsystem is not ok, and for a failed check which kind "
            "of failure it was: a named schema state, or the check exceeding "
            "its deadline or raising."
        ),
    )
    latency_ms: float | None = Field(
        default=None,
        description="Round-trip time of the probe's query, where it ran one.",
    )
    revision: str | None = Field(
        default=None,
        description="The Alembic revision the database is stamped with.",
    )
    expected: str | None = Field(
        default=None,
        description="The revision this build refuses to boot without.",
    )
    activated: bool | None = Field(
        default=None,
        description="Whether the audit chain's authenticated state was verified.",
    )
    scope: str | None = Field(
        default=None,
        description=(
            "How much of a subsystem the check covered. ``state-only`` means "
            "the audit chain's state row was authenticated and ``audit_log`` "
            "was not read."
        ),
    )


class DeepHealthCoverage(BaseModel):
    """What the verdict does and does not answer, carried in the response.

    In the payload rather than in a docstring, because the reader who most
    needs it is polling the endpoint and is not reading this file.
    """

    startup_equivalent: bool = Field(
        description=(
            "Whether this verdict is the one the boot path would give the same "
            "database. It is not, in either direction; ``detail`` says how."
        ),
    )
    detail: str


class DeepHealthResponse(BaseModel):
    """The deep report. Returned with both ``200`` and ``503``."""

    status: Literal["ok", "degraded", "failed"] = Field(
        description=(
            "The worst status among the checks. ``failed`` is the 503; "
            "``degraded`` is a warning and still a 200."
        ),
    )
    coverage: DeepHealthCoverage
    checks: dict[str, DeepCheckResult] = Field(
        description=(
            "One entry per registered probe, keyed by subsystem name. A check "
            "that could not complete appears as failed rather than being "
            "omitted, because an omission reads as healthy."
        ),
    )


#: What this endpoint's verdict covers, carried in the response rather than
#: left in this module for a reader to go and find. Neither direction is the
#: boot path's answer, and the two miss it for different reasons: an "ok" is
#: only the checks named beside it, while a "failed" is either one of those
#: checks reporting a state the boot path refuses OR a check that could not
#: complete at all. An operator holding a response cannot tell which they were
#: given unless the payload says so.
_DEEP_COVERAGE: dict[str, object] = {
    "startup_equivalent": False,
    "detail": (
        "neither result is the verdict the boot path would give this database. "
        "A green result reports only the checks named beside it: audit_chain "
        "authenticates the chain state row and does not read audit_log, so a "
        "tampered audit row passes here and is refused at boot, and the "
        "scheduled audit verifier is what covers those rows. A red result "
        "names a state the boot path refuses only where the check completed; a "
        "check that exceeded its deadline or raised is reported failed too, "
        "and the boot path puts no deadline on the equivalent work, so read the "
        "check's own detail before concluding that a restart would fail."
    ),
}

#: Name to probe. Adding an entry here adds it to the response.
_DEEP_CHECKS = {
    "database": _check_database,
    "migrations": _check_migrations,
    "audit_chain": _check_audit_chain,
}


async def _run_probe(
    session: AsyncSession,
    probe: Callable[[AsyncSession, Settings], Awaitable[dict[str, object]]],
    settings: Settings,
) -> dict[str, object]:
    """Run one probe on the shared session without letting it reach the next.

    The savepoint is always rolled back, never released. That is not tidiness:
    a probe answers a missing table with a report rather than an exception, so
    it RETURNS after the statement that aborted the PostgreSQL transaction, and
    ``RELEASE SAVEPOINT`` does not clear an aborted transaction -- only
    ``ROLLBACK TO SAVEPOINT`` does. Releasing left the abort in place and every
    later probe then died on its own ``SAVEPOINT`` statement. Unconditional
    rollback is safe here because these probes only read.

    The deadline covers the savepoint and its rollback, not just the probe
    between them. Both are round trips to the same database the probe is
    asking about, so a database that has stopped answering stalls on
    ``SAVEPOINT`` before the probe is ever entered, and a timeout that starts
    after it bounds nothing. The rollback gets a deadline of its own because
    the first one does not fire twice: once it has expired in the probe, an
    unbounded cleanup would hold the request open exactly as long as the
    unbounded probe would have.
    """
    async with asyncio.timeout(_DEEP_CHECK_TIMEOUT_S):
        savepoint = await session.begin_nested()
        try:
            return await probe(session, settings)
        finally:
            async with asyncio.timeout(_DEEP_CHECK_TIMEOUT_S):
                await savepoint.rollback()


@router.get(
    "/health/deep",
    response_model=DeepHealthResponse,
    # The probes report by omission: a field a probe had no answer for is not
    # in its result at all, and serialising it as an explicit null would put a
    # key in front of an operator that reads as "asked, and the answer was
    # nothing".
    response_model_exclude_none=True,
    response_description=(
        "No check reported failed. Individual checks may report degraded, "
        "which is a warning rather than an outage."
    ),
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": DeepHealthResponse,
            "description": (
                "At least one check reported failed. The body is the same "
                "shape as the 200 and names which subsystem, so a client "
                "reads the failure the same way it reads the success."
            ),
        },
    },
)
async def health_deep(
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _user: object = Depends(get_current_user),
) -> dict[str, object]:
    """Per-subsystem health, for when "is it up" is not the question.

    ``/health`` answers whether the process is alive and ``/health/ready``
    whether it can serve traffic. Neither tells an operator which subsystem
    is the reason, so this one names them individually.

    Authenticated on purpose. ``/health`` is deliberately public for
    liveness probes, and the 1.6.3 advisory removed even the version string
    from it because an unauthenticated caller could use it to pin CVEs to a
    target. Subsystem topology is a larger disclosure than a version, and a
    public probe that does real work on request is also an amplification
    vector, so this lives behind auth rather than behind a query parameter
    on the public endpoint.

    Returns ``503`` when any check reports failed and ``200`` otherwise, so
    it can drive an alert directly. A degraded check is a warning rather than
    an outage and stays a 200, because a 503 would have an orchestrator
    restart a brain that is serving traffic perfectly well. A check that
    cannot complete is reported as failed rather than omitted: a silent
    omission reads as healthy, which is the one thing a health endpoint must
    never do.

    Neither verdict is a prediction of what the boot path would do with the
    same database, and ``coverage`` in the response says so.

    A green result is the narrower of the two. An ok is the checks named
    beside it and nothing else: the audit-chain check authenticates the state
    row without reading ``audit_log`` (see :func:`_check_audit_chain`), so a
    database carrying a tampered audit row passes here and is refused at boot.

    A red result is not the converse of that. Where a check completed and
    reported a schema state, that state is one the boot path refuses, and
    calling it failed rather than degraded is the deliberate part: degraded is
    a subsystem working less well than it should on a brain that can still
    restart, and a state the next restart rejects is failed however well the
    process happens to be serving right now, because reporting it as a warning
    tells an operator their brain is healthy up until the moment something asks
    it to come back. But failed is also what a check gets when it exceeds
    :data:`_DEEP_CHECK_TIMEOUT_S` or raises, and
    :func:`z4j_brain.startup.verify_production_authority_at_startup` runs its
    queries with no deadline at all, so a database slow enough to miss that
    budget is a 503 here and a successful start there. Both belong in the 503,
    because a subsystem this brain cannot answer for is worth paging on either
    way. What does not follow is reading any 503 as proof that the next restart
    will refuse; the check's own ``detail`` says which of the two it is.

    Closing that gap was considered and rejected rather than overlooked. On
    PostgreSQL startup's walk takes the chain advisory lock and ``LOCK TABLE
    audit_log IN SHARE MODE``, which stalls every audited mutation in the brain
    for as long as it runs; on SQLite it requires a unit begun with ``BEGIN
    IMMEDIATE``, which the request's read-only session is not; and on both it
    hashes every row of a table with no upper bound, against a per-check budget
    of :data:`_DEEP_CHECK_TIMEOUT_S`. Every project member can reach this
    endpoint and poll it, so an equivalent probe would hand any of them a way
    to hold up the brain's writes on demand. Walking part of the table instead would not be
    equivalent either, since tampering is not confined to the rows a partial
    walk would reach, so it would trade one untrue claim for a subtler one. The
    scheduled verifier does that work on its own schedule; what belongs here is
    an accurate statement of what was and was not asked.

    Every probe runs on the REQUEST's session rather than opening its own.
    Authentication already holds that session for the life of the request, so
    a probe that checked out a second connection needed two at once, and
    ``pool_size=1, max_overflow=0`` is a configuration this brain explicitly
    permits. On that pool each probe blocked until its own timeout and the
    endpoint reported a perfectly reachable database as failed.

    Sharing one session is why each probe runs inside :func:`_run_probe`.
    PostgreSQL aborts the whole transaction on the first statement error, so
    without isolation the first probe to fail poisons every later one: an
    un-migrated database reported its audit chain as un-activated when the
    chain was fine, and the report got worse, not better, as the probes were
    sharpened.
    """
    checks: dict[str, object] = {}
    worst = "ok"

    for name, probe in _DEEP_CHECKS.items():
        try:
            result = await _run_probe(session, probe, settings)
        except TimeoutError:
            result = {
                "status": "failed",
                "detail": f"check exceeded {_DEEP_CHECK_TIMEOUT_S}s",
            }
        except Exception as exc:
            # The class name only. An operator learns which subsystem is
            # unhappy without the response becoming a place internals leak.
            result = {"status": "failed", "detail": type(exc).__name__}
        checks[name] = result

        status_value = result.get("status")
        if status_value == "failed":
            worst = "failed"
        elif status_value == "degraded" and worst == "ok":
            worst = "degraded"

    if worst == "failed":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": worst, "coverage": dict(_DEEP_COVERAGE), "checks": checks}


__all__ = ["router"]
