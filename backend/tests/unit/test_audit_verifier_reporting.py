"""What a failed Boundary-F verification tells the operator reading it.

Neither property here is about whether the walk finds the damage. The walk
already finds it. They are about what happens to the finding afterwards, which
is the only part an operator ever sees:

* a frozen row that no longer canonicalizes has to arrive as a finding, not as
  an exception that throws away every finding gathered before it and leaves the
  scheduled verifier logging a corrupted chain as a job to retry;
* the number printed beside ``MISMATCHES`` has to be the number of findings,
  not the number of lines the capped report happens to carry.

Everything below runs the real migrations, so the frozen row, the marker CHECK
constraint, and the append-only triggers are the ones an operator has.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain import cli
from z4j_brain.domain.audit_chain import (
    canonical_audit_key_id,
    make_empty_chain_state,
)
from z4j_brain.domain.audit_verifier import (
    AuditVerificationReport,
    verify_active_audit_generation,
)
from z4j_brain.domain.workers import audit_verifier as worker_mod
from z4j_brain.domain.workers.audit_verifier import AuditChainVerifierWorker
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager, create_engine_from_settings
from z4j_brain.persistence.models import AuditLog
from z4j_brain.settings import Settings

from tests.unit.test_audit_activation_boundary_f import (
    _activate_one_frozen_row,
    activation_install,  # noqa: F401  imported for use as a fixture
)

#: Sixty-four characters of valid hexadecimal that is not the canonical form,
#: because the canonical form is lowercase. The marker CHECK constrains the
#: column to NOT NULL and nothing more, so this is a value a real database can
#: hold: a restore from a doctored dump, a hand-repaired row, anything with
#: write access to the table the chain is evidence about.
_NONCANONICAL_KEY_ID = "A" * 64

_UPDATE_TRIGGER = "audit_log_boundary_f_no_update"
_INSERT_TRIGGER = "audit_log_boundary_f_no_insert"

#: Secrets for the one case below that needs a database in a state no
#: activation ceremony produces, and so cannot use the migrated install.
_MEMORY_MASTER = "master-secret-for-the-empty-head-case-0000000000"
_MEMORY_SESSION = "session-secret-for-the-empty-head-case-000000000"
_MEMORY_AUDIT = "audit-only-secret-for-the-empty-head-case-000000"


@contextmanager
def _triggers_suspended(sync_url: str, *names: str) -> Iterator[None]:
    """Drop and restore named audit triggers around a forbidden write.

    The definitions are read back out of ``sqlite_master`` rather than copied
    into this file, so the database the verifier then walks is guarded exactly
    as the migration left it and no finding below can be explained away as a
    guard the test forgot to put back. ``scalar_one`` also fails the test if a
    trigger it means to suspend was not there to begin with.

    Dropping and restoring each commit on their own, because pysqlite leaves
    DDL out of the implicit transaction: a restore sharing a transaction with
    the write would be rolled back whenever the write is refused, which is
    exactly the case that must still hand the database back intact.
    """

    saved: list[str] = []
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            for name in names:
                saved.append(
                    connection.execute(
                        text(
                            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = :name",
                        ),
                        {"name": name},
                    ).scalar_one(),
                )
                connection.execute(text(f"DROP TRIGGER {name}"))
        try:
            yield
        finally:
            with engine.begin() as connection:
                for sql in saved:
                    connection.execute(text(sql))
    finally:
        engine.dispose()


def _update_frozen_row(sync_url: str, row_id: uuid.UUID, **values: object) -> None:
    """Attempt one UPDATE against the table exactly as the migration guards it."""

    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                update(AuditLog).where(AuditLog.id == row_id).values(**values),
            )
    finally:
        engine.dispose()


def _rewrite_frozen_row(sync_url: str, row_id: uuid.UUID, **values: object) -> None:
    """Mutate one frozen row the only way a real one ever gets mutated.

    The marker CHECK is never dropped, only the append-only trigger is, so an
    UPDATE that lands here is an UPDATE the constraint accepted.
    """

    with _triggers_suspended(sync_url, _UPDATE_TRIGGER):
        _update_frozen_row(sync_url, row_id, **values)


def _forge_active_rows(sync_url: str, count: int) -> None:
    """Append rows carrying the live generation that no key ever signed.

    Two findings apiece: the link does not follow its predecessor, and the
    signature does not hold. Timestamped a day out so they sort after every
    genuine row and cannot make a genuine one look broken.
    """

    engine = create_engine(sync_url)
    try:
        with _triggers_suspended(sync_url, _INSERT_TRIGGER), engine.begin() as connection:
            generation = uuid.UUID(
                str(
                    connection.execute(
                        text("SELECT generation FROM audit_chain_state"),
                    ).scalar_one(),
                ),
            )
            key_id = canonical_audit_key_id(b"a" * 64)
            base = datetime.now(UTC) + timedelta(days=1)
            for index in range(count):
                connection.execute(
                    AuditLog.__table__.insert().values(
                        id=uuid.uuid4(),
                        action="forged.row",
                        target_type="test",
                        target_id=str(index),
                        result="success",
                        outcome="allow",
                        metadata={},
                        occurred_at=base + timedelta(seconds=index),
                        event_id=None,
                        project_id=None,
                        user_id=None,
                        api_key_id=None,
                        source_ip=None,
                        user_agent=None,
                        legacy_frozen=False,
                        hmac_version=2,
                        hmac_key_id=key_id,
                        row_hmac=f"{index:064x}",
                        prev_row_hmac=f"{index + 1000:064x}",
                        chain_generation=generation,
                    ),
                )
    finally:
        engine.dispose()


def _frozen_key_id(sync_url: str, row_id: uuid.UUID) -> str:
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            return connection.execute(
                select(AuditLog.hmac_key_id).where(AuditLog.id == row_id),
            ).scalar_one()
    finally:
        engine.dispose()


async def _run_verify(settings: Settings) -> AuditVerificationReport:
    db = DatabaseManager(create_engine_from_settings(settings))
    try:
        async with db.session() as session:
            return await verify_active_audit_generation(session, settings, page_size=1000)
    finally:
        await db.dispose()


async def _run_worker_tick(settings: Settings) -> float | None:
    db = DatabaseManager(create_engine_from_settings(settings))
    try:
        return await AuditChainVerifierWorker(db=db, settings=settings).tick()
    finally:
        await db.dispose()


def verify(settings: Settings) -> AuditVerificationReport:
    """Walk the chain once, from a synchronous test.

    Every test here is synchronous because activation runs through
    ``cli.main``, which owns its own event loop.
    """

    return asyncio.run(_run_verify(settings))


def test_a_frozen_row_that_lost_its_canonical_form_is_a_finding(
    activation_install: tuple[Config, str, Path],  # noqa: F811  fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corrupted chain must not reach the operator disguised as a flaky job.

    Frozen rows are immutable by construction, so one that no longer
    canonicalizes is exactly the tampering the scheduled walk exists to catch.
    Canonicalizing straight into the manifest digest made that row raise
    instead: the findings gathered so far were discarded, and the worker
    recorded the run as an error it should retry in thirty seconds, which is
    what somebody watching the worker reads as a database blip.
    """

    cfg, sync_url, manifest_dir = activation_install
    legacy_id = _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="uncanonical-key-id.json",
    )
    settings = Settings()  # type: ignore[call-arg]
    assert verify(settings).clean

    # Negative control. The marker CHECK is live on UPDATE and rejects a class
    # outside the closed set, so the write that follows is one the constraint
    # accepted rather than one nothing was watching.
    with pytest.raises(IntegrityError):
        _rewrite_frozen_row(
            sync_url,
            legacy_id,
            legacy_integrity_class="legacy-fabricated",
        )

    # Positive control, and the premise: the same live CHECK accepts a frozen
    # row whose key id is not in canonical form.
    _rewrite_frozen_row(sync_url, legacy_id, hmac_key_id=_NONCANONICAL_KEY_ID)
    assert _frozen_key_id(sync_url, legacy_id) == _NONCANONICAL_KEY_ID

    # And the append-only guard is back, so what the verifier walks below is
    # the database the migration built rather than one this test left open.
    with pytest.raises(IntegrityError, match="append-only"):
        _update_frozen_row(sync_url, legacy_id, target_id="second-tamper")

    outcomes: list[str] = []
    monkeypatch.setattr(
        worker_mod,
        "_observe",
        lambda m, *, outcome, rows=0: outcomes.append(outcome),
    )
    delay = asyncio.run(_run_worker_tick(settings))

    # None means "take the configured interval". A float here is the retry
    # backoff, which is the tell that the run was filed as incomplete.
    assert delay is None
    assert outcomes == ["failed"]

    report = verify(settings)
    assert not report.clean
    assert any(str(legacy_id) in line and "not canonical" in line for line in report.mismatches), (
        report.mismatches
    )
    assert any("unprovable" in line for line in report.mismatches), report.mismatches
    # The row was compared against nothing, so it cannot be reported as one of
    # the rows this run proved.
    assert report.verified_frozen_rows == 0


def test_the_report_counts_findings_rather_than_the_lines_it_kept(
    activation_install: tuple[Config, str, Path],  # noqa: F811  fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The total survives the cap that the individual findings do not."""

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="flood.json",
    )
    settings = Settings()  # type: ignore[call-arg]
    forged = 60
    _forge_active_rows(sync_url, forged)

    capped = verify(settings)

    # Ground truth taken from the same verifier walking the same database with
    # the cap lifted, so what the capped run claims about its own total is
    # checked against a measurement that did not have to reason about the cap.
    monkeypatch.setattr(
        "z4j_brain.domain.audit_verifier._MAX_REPORTED_MISMATCHES",
        10_000,
    )
    uncapped = verify(settings)
    assert uncapped.mismatches_truncated == 0
    assert len(uncapped.mismatches) == uncapped.mismatch_count

    assert capped.mismatch_count == uncapped.mismatch_count
    # Two findings per forged row (broken link, bad signature) and three about
    # the generation as a whole: the active row count, the per-key counts, and
    # the retained tail against the authenticated head.
    assert capped.mismatch_count == 2 * forged + 3
    # What the report carries is still bounded, and still says so.
    assert len(capped.mismatches) == 101
    assert capped.mismatches_truncated == capped.mismatch_count - 100
    assert str(capped.mismatches_truncated) in capped.mismatches[-1]


def test_the_verify_command_prints_the_number_of_findings(
    activation_install: tuple[Config, str, Path],  # noqa: F811  fixture
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The one screen an operator reads while deciding how bad this is.

    Measuring the tuple announced a hundred and one findings for a chain with
    a hundred and twenty-three wrong rows, because the tuple holds the hundred
    it kept plus the line naming the overflow. Wrong, not merely incomplete.
    """

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(cfg, sync_url, manifest_dir, manifest_name="cli-flood.json")
    forged = 60
    _forge_active_rows(sync_url, forged)
    settings = Settings()  # type: ignore[call-arg]
    expected = verify(settings).mismatch_count
    assert expected == 2 * forged + 3
    capsys.readouterr()

    assert cli.main(["audit", "verify"]) == 1

    printed = capsys.readouterr().out
    assert f"MISMATCHES ({expected}):" in printed
    # Bounded output is the other half of the contract: the honest total must
    # not be bought by printing every finding into the operator's terminal.
    findings = [line for line in printed.splitlines() if line.startswith("  ")]
    assert len(findings) == 101
    assert "further finding(s) not shown" in findings[-1]


async def _report_for_rows_under_an_empty_head() -> AuditVerificationReport:
    """Verify a database whose authenticated head is empty while rows exist.

    ``make_empty_chain_state`` says in as many words that committing it without
    appending the generation-start row in the same transaction is not a valid
    activation, so the state it builds is one a database can end up holding.
    Rows carrying that generation then leave the walk with a tail and no head
    to compare it against.
    """

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=_MEMORY_MASTER,  # type: ignore[arg-type]
        session_secret=_MEMORY_SESSION,  # type: ignore[arg-type]
        audit_chain_secret=_MEMORY_AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with AsyncSession(engine, expire_on_commit=False) as session:
            state = make_empty_chain_state(secret=_MEMORY_AUDIT.encode())
            session.add(state)
            await session.flush()
            session.add(
                AuditLog(
                    action="orphan.row",
                    target_type="test",
                    result="success",
                    audit_metadata={},
                    occurred_at=datetime.now(UTC),
                    legacy_frozen=False,
                    hmac_version=2,
                    hmac_key_id=None,
                    row_hmac=None,
                    prev_row_hmac=None,
                    chain_generation=state.generation,
                ),
            )
            await session.commit()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            return await verify_active_audit_generation(session, settings, page_size=10)
    finally:
        await engine.dispose()


def test_rows_under_an_empty_authenticated_head_are_reported_not_raised() -> None:
    """The same class as the frozen row, reached through the head comparison.

    Normalizing an absent head timestamp raises out of a walk whose entire
    purpose is to report, and takes the findings already gathered with it. The
    state MAC still authenticates here, so nothing upstream refuses the
    database first: the walk really does arrive at a tail with no head.
    """

    report = asyncio.run(_report_for_rows_under_an_empty_head())

    assert not report.clean
    assert report.mismatch_count == 3
    assert any("empty authenticated head" in line for line in report.mismatches), report.mismatches
    assert any("active row count" in line for line in report.mismatches), report.mismatches
    assert any("HMAC mismatch" in line for line in report.mismatches), report.mismatches


def test_a_clean_activated_chain_still_verifies_clean(
    activation_install: tuple[Config, str, Path],  # noqa: F811  fixture
) -> None:
    """The control for everything above: untouched, all of it verifies.

    Without this the two tests above are satisfied by a verifier that reports
    findings unconditionally.
    """

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(cfg, sync_url, manifest_dir, manifest_name="clean.json")
    settings = Settings()  # type: ignore[call-arg]

    report = verify(settings)

    assert report.clean
    assert report.mismatch_count == 0
    assert report.mismatches == ()
    assert report.verified_frozen_rows == 1
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            frozen_count = connection.execute(
                text("SELECT frozen_row_count FROM audit_chain_state"),
            ).scalar_one()
    finally:
        engine.dispose()
    assert frozen_count == 1
