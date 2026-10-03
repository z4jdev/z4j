"""``z4j audit prune``: soft and hard mode, dry run, refusals, verification.

Drives the real console-script entrypoint (``main(["audit", "prune", ...])``
-> ``_run_audit_prune``) against a file-backed SQLite database whose chain
was activated and written through the real ``AuditService``, so every row
and the authenticated state are genuine. The cases the plan asks for:

- a chain with rows across the cutoff is pruned softly and ``verify``
  reports it clean with the pruned range on record (``PRUNE_MATCH`` for a
  head at the boundary);
- an unrecorded deletion still reports broken, and the prune refuses to
  bless it (negative control);
- hard mode after soft cuts the epoch: a fresh signed genesis, no boundary;
- dry run changes nothing;
- refusal without an authenticated chain state or without the audit key;
- retention by action class stops the prefix at the oldest row a longer
  window keeps.

Deliberately on a ``create_all()`` schema, like the rest of the boundary-F
unit tests: the negative control deletes a row by hand, which an activated
database refuses at the trigger.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain.audit_retention import AUDIT_PRUNE_ACTION
from z4j_brain.domain.audit_chain import make_empty_chain_state
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.persistence import models  # noqa: F401  registers metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings

MASTER = "master-secret-that-is-not-the-audit-key-000000"
SESSION = "session-secret-that-is-not-the-audit-key-0000"
AUDIT = "audit-only-secret-that-is-independent-000000000"

#: Actions seeded forty days before "now", in chain order after the genesis
#: row the activation writes (``audit.chain_generation_started``).
OLD_ACTIONS = ("command.issue", "command.issue", "auth.login", "command.issue")
FRESH_ACTIONS = ("command.issue", "auth.login")


def _settings(database_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": database_url,
        "secret": MASTER,
        "session_secret": SESSION,
        "audit_chain_secret": AUDIT,
        "environment": "dev",
        "audit_retention_days": 30,
        "audit_retention_sweep_batch_size": 100,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _clock_at(moment: datetime) -> type[datetime]:
    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return moment if tz is not None else moment.replace(tzinfo=None)

    return FrozenClock


async def _activate(engine, service: AuditService) -> None:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        state = make_empty_chain_state(secret=AUDIT.encode())
        session.add(state)
        await session.flush()
        await service.record(
            AuditLogRepository(session),
            action="audit.chain_generation_started",
            target_type="audit_chain",
            target_id=str(state.generation),
            metadata={"fresh": True},
        )
        await session.commit()


async def _record(engine, service: AuditService, action: str) -> AuditLog:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        row = await service.record(
            AuditLogRepository(session),
            action=action,
            target_type="test",
        )
        await session.commit()
        return row


async def _rows(database_url: str) -> list[AuditLog]:
    engine = create_async_engine(database_url)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            return list(
                (
                    await session.execute(
                        select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id),
                    )
                ).scalars(),
            )
    finally:
        await engine.dispose()


async def _state(database_url: str) -> AuditChainState:
    engine = create_async_engine(database_url)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            return (await session.execute(select(AuditChainState))).scalar_one()
    finally:
        await engine.dispose()


async def _verify(database_url: str, known_head: dict | None = None):
    settings = _settings(database_url)
    engine = create_async_engine(database_url)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=2,
                known_head=known_head,
            )
            await session.rollback()
            return report
    finally:
        await engine.dispose()


def _head_envelope(row: AuditLog) -> dict:
    assert row.row_hmac is not None
    return {"row_hmac": row.row_hmac, "id": str(row.id)}


@pytest.fixture
def chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """An activated chain with old rows past the cutoff and fresh rows inside it.

    Wires the process environment so the CLI's own ``Settings()`` sees the
    same database and keys as the seeding helper.
    """
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'prune.db').as_posix()}"
    settings = _settings(database_url)
    service = AuditService(settings)
    old_now = datetime.now(UTC) - timedelta(days=40)

    async def _seed() -> tuple[list[AuditLog], list[AuditLog]]:
        engine = create_async_engine(database_url)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            monkeypatch.setattr(
                "z4j_brain.domain.audit_service.datetime",
                _clock_at(old_now),
            )
            await _activate(engine, service)
            old = [await _record(engine, service, action) for action in OLD_ACTIONS]
            monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)
            fresh = [await _record(engine, service, action) for action in FRESH_ACTIONS]
            return old, fresh
        finally:
            await engine.dispose()

    old, fresh = asyncio.run(_seed())

    tmp_path.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path))
    monkeypatch.setenv("Z4J_DATABASE_URL", database_url)
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_SESSION_SECRET", SESSION)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", AUDIT)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_AUDIT_RETENTION_DAYS", "30")
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    return SimpleNamespace(database_url=database_url, old=old, fresh=fresh)


def _prune(*extra: str) -> int:
    from z4j_brain.cli import main

    return main(["audit", "prune", *extra])


def _prune_rows(rows: list[AuditLog]) -> list[AuditLog]:
    return [row for row in rows if row.action == AUDIT_PRUNE_ACTION]


def test_soft_prune_records_the_boundary_and_verify_reports_clean(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = asyncio.run(_rows(chain.database_url))
    assert len(before) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)
    assert asyncio.run(_verify(chain.database_url)).clean

    assert _prune("--apply") == 0
    out = capsys.readouterr().out
    assert "APPLY" in out
    assert f"would prune  : {1 + len(OLD_ACTIONS)} rows" in out
    assert "pruned 5 rows under the authenticated boundary" in out
    # The success line must not promise more than verify delivers: a head
    # anchored inside the pruned range is UNPROVABLE (exit 1) from now on.
    assert "reports UNPROVABLE, so export a new head" in out

    boundary = chain.old[-1]
    after = asyncio.run(_rows(chain.database_url))
    assert [row.id for row in after[: len(FRESH_ACTIONS)]] == [row.id for row in chain.fresh]
    record = _prune_rows(after)
    assert len(record) == 1
    assert record[0].audit_metadata["mode"] == "soft"
    assert record[0].audit_metadata["rows"] == 1 + len(OLD_ACTIONS)
    assert record[0].audit_metadata["cutoff_source"] == "retention"
    assert record[0].audit_metadata["boundary_id"] == str(boundary.id)
    assert record[0].audit_metadata["rows_by_class"] == {"audit": 1, "auth": 1, "command": 3}

    state = asyncio.run(_state(chain.database_url))
    assert state.prune_id == boundary.id
    assert state.prune_row_hmac == boundary.row_hmac
    assert state.active_row_count == len(FRESH_ACTIONS) + 1

    report = asyncio.run(_verify(chain.database_url))
    assert report.clean, report.mismatches
    # The pruned range is on record: a head exported at the boundary before
    # the prune still proves itself through the authenticated prune quartet.
    at_boundary = asyncio.run(_verify(chain.database_url, _head_envelope(boundary)))
    assert at_boundary.known_head_result == "PRUNE_MATCH"
    assert at_boundary.mismatches == ()
    # A head from deeper inside the pruned range is gone, not broken: the
    # chain verifies with no finding and only the anchor is unprovable.
    deeper = asyncio.run(_verify(chain.database_url, _head_envelope(chain.old[0])))
    assert deeper.known_head_result == "UNPROVABLE"
    assert deeper.mismatches == ()
    # The command the operator actually runs says the same and exits 1.
    from z4j_brain.cli import main

    envelope = json.dumps(_head_envelope(chain.old[0]))
    assert main(["audit", "verify", "--known-head", envelope]) == 1
    assert "known-head: UNPROVABLE" in capsys.readouterr().out


def test_an_interrupted_prune_leaves_signed_batches_and_a_rerun_completes_it(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each batch is its own signed transaction; the ``audit.prune`` row is last.

    A run killed after its batches committed but before it recorded itself
    leaves the boundary at the last batch and no ``audit.prune`` row. The
    chain verifies clean as it stands, and a rerun continues from the
    boundary and writes the row.
    """
    original = AuditService.record
    calls: list[str] = []

    async def record_then_die(self, repo, *, action, **kwargs):  # type: ignore[no-untyped-def]
        if action == AUDIT_PRUNE_ACTION and not calls:
            calls.append(action)
            raise ConnectionResetError("the connection dropped before the prune row")
        return await original(self, repo, action=action, **kwargs)

    monkeypatch.setattr(AuditService, "record", record_then_die)
    with pytest.raises(ConnectionResetError):
        _prune("--apply")
    capsys.readouterr()

    boundary = chain.old[-1]
    rows = asyncio.run(_rows(chain.database_url))
    assert [row.id for row in rows] == [row.id for row in chain.fresh]
    assert not _prune_rows(rows)
    state = asyncio.run(_state(chain.database_url))
    assert state.prune_id == boundary.id
    assert asyncio.run(_verify(chain.database_url)).clean

    assert _prune("--apply") == 0
    assert "pruned 0 rows under the authenticated boundary" in capsys.readouterr().out
    rows = asyncio.run(_rows(chain.database_url))
    record = _prune_rows(rows)
    assert len(record) == 1
    assert record[0].audit_metadata["rows"] == 0
    assert asyncio.run(_state(chain.database_url)).prune_id == boundary.id
    assert asyncio.run(_verify(chain.database_url)).clean


def test_a_held_sqlite_writer_is_refused_not_a_traceback(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Another connection holding the writer lock is a refusal, exit 1.

    SQLite surfaces it as ``OperationalError: database is locked`` once the
    busy timeout elapses; that used to escape as a traceback with no word on
    what had and had not been changed.
    """
    import sqlite3

    path = chain.database_url.removeprefix("sqlite+aiosqlite:///")
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        rc = _prune("--apply")
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert rc == 1
    err = capsys.readouterr().err
    assert "REFUSING" in err
    assert "database is locked" in err
    assert "rerun continues from the boundary" in err
    assert len(asyncio.run(_rows(chain.database_url))) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)
    assert asyncio.run(_state(chain.database_url)).prune_id is None


def test_hard_mode_refuses_a_row_appended_between_the_prune_and_the_reset(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The hard preconditions are re-checked inside the reset, locks held.

    The preview that cleared ``--hard`` ran before the leases were taken. A
    live brain appends an ``auth.login`` after the soft prune and before the
    reset; the reset used to delete the whole generation, that row included,
    with exit 0 and a clean verify. Now it refuses, names the row, and the
    row survives with the generation and the signed boundary intact.
    """
    from z4j_brain.audit_retention import AuditRetentionSweeper

    settings = _settings(chain.database_url)
    original = AuditRetentionSweeper.prune_authenticated
    appended: list[AuditLog] = []

    async def prune_then_append(self, *, cutoffs):  # type: ignore[no-untyped-def]
        pruned = await original(self, cutoffs=cutoffs)
        engine = create_async_engine(chain.database_url)
        try:
            appended.append(await _record(engine, AuditService(settings), "auth.login"))
        finally:
            await engine.dispose()
        return pruned

    monkeypatch.setattr(AuditRetentionSweeper, "prune_authenticated", prune_then_append)
    old_generation = asyncio.run(_state(chain.database_url)).generation
    cutoff = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")

    assert _prune("--hard", "--apply", "--before", cutoff) == 1
    err = capsys.readouterr().err
    assert "REFUSING --hard" in err
    assert str(appended[0].id) in err
    assert "auth.login" in err
    assert "generation was not reset" in err

    rows = asyncio.run(_rows(chain.database_url))
    assert [row.id for row in rows] == [appended[0].id]
    assert rows[0].action == "auth.login"
    assert not _prune_rows(rows)
    state = asyncio.run(_state(chain.database_url))
    assert state.generation == old_generation
    assert state.prune_id == chain.fresh[-1].id
    assert state.active_row_count == 1
    assert asyncio.run(_verify(chain.database_url)).clean


def test_unrecorded_deletion_still_reports_broken_and_prune_refuses(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    victim = chain.old[1]

    async def _delete_by_hand() -> None:
        engine = create_async_engine(chain.database_url)
        try:
            async with AsyncSession(engine) as attacker:
                await attacker.execute(delete(AuditLog).where(AuditLog.id == victim.id))
                await attacker.commit()
        finally:
            await engine.dispose()

    asyncio.run(_delete_by_hand())
    report = asyncio.run(_verify(chain.database_url))
    assert not report.clean
    assert any("link mismatch" in finding for finding in report.mismatches)
    assert any("row count" in finding for finding in report.mismatches)

    state_before = asyncio.run(_state(chain.database_url))
    assert _prune("--apply") == 1
    err = capsys.readouterr().err
    assert "REFUSING" in err
    assert "does not match authenticated state" in err

    state_after = asyncio.run(_state(chain.database_url))
    assert state_after.state_mac == state_before.state_mac
    assert state_after.prune_id is None
    assert not _prune_rows(asyncio.run(_rows(chain.database_url)))


def test_hard_mode_refuses_while_rows_remain_then_cuts_the_epoch_after_soft(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_generation = asyncio.run(_state(chain.database_url)).generation
    old_head = chain.fresh[-1]

    # Fresh rows are younger than the retention cutoff, so an epoch cut would
    # have to remove rows the cutoff keeps: refused before anything changes.
    assert _prune("--hard", "--apply") == 1
    assert "REFUSING --hard" in capsys.readouterr().err
    assert len(asyncio.run(_rows(chain.database_url))) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)

    # Soft first, with an explicit cutoff that covers every retained row.
    cutoff = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    assert _prune("--apply", "--before", cutoff) == 0
    assert "pruned 7 rows" in capsys.readouterr().out
    state = asyncio.run(_state(chain.database_url))
    assert state.generation == old_generation
    assert state.prune_id == old_head.id
    rows = asyncio.run(_rows(chain.database_url))
    assert [row.action for row in rows] == [AUDIT_PRUNE_ACTION]
    assert rows[0].prev_row_hmac == old_head.row_hmac

    # Hard after soft: the generation is fully pruned, so the epoch cut goes
    # through, removing the signed boundary with it.
    cutoff = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    assert _prune("--hard", "--apply", "--before", cutoff) == 0
    out = capsys.readouterr().out
    assert "cut the epoch" in out

    state = asyncio.run(_state(chain.database_url))
    assert state.generation != old_generation
    assert state.prune_id is None
    assert state.prune_row_hmac is None
    rows = asyncio.run(_rows(chain.database_url))
    assert [row.action for row in rows] == ["audit.chain_generation_reset", AUDIT_PRUNE_ACTION]
    assert rows[0].prev_row_hmac is None
    assert rows[0].chain_generation == state.generation
    assert rows[1].audit_metadata["mode"] == "hard"
    assert rows[1].audit_metadata["new_generation"] == str(state.generation)
    assert rows[1].target_id == str(old_generation)
    assert state.active_row_count == 2

    report = asyncio.run(_verify(chain.database_url))
    assert report.clean, report.mismatches
    # Every head from the old epoch is now unprovable, by design of a cut.
    assert (
        asyncio.run(_verify(chain.database_url, _head_envelope(old_head))).known_head_result
        == "UNPROVABLE"
    )


def test_dry_run_changes_nothing(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rows_before = asyncio.run(_rows(chain.database_url))
    state_before = asyncio.run(_state(chain.database_url))

    assert _prune() == 0
    out = capsys.readouterr().out
    assert "DRY RUN (pass --apply to execute)" in out
    assert "mode         : soft" in out
    assert f"would prune  : {1 + len(OLD_ACTIONS)} rows" in out
    assert f"new boundary : row {chain.old[-1].id}" in out
    assert f"remaining    : {len(FRESH_ACTIONS)} active rows" in out

    rows_after = asyncio.run(_rows(chain.database_url))
    assert [row.id for row in rows_after] == [row.id for row in rows_before]
    state_after = asyncio.run(_state(chain.database_url))
    assert state_after.state_mac == state_before.state_mac
    assert state_after.prune_id is None


def test_refuses_without_the_audit_key(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("Z4J_AUDIT_CHAIN_SECRET")
    assert _prune("--apply") == 1
    assert "no authenticated prune boundary" in capsys.readouterr().err
    assert len(asyncio.run(_rows(chain.database_url))) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)


def test_refuses_without_an_authenticated_chain_state(
    chain: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def _tamper_state() -> None:
        engine = create_async_engine(chain.database_url)
        try:
            async with AsyncSession(engine) as session:
                await session.execute(update(AuditChainState).values(state_mac="0" * 64))
                await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_tamper_state())
    assert _prune("--apply") == 1
    assert "REFUSING" in capsys.readouterr().err

    async def _drop_state() -> None:
        engine = create_async_engine(chain.database_url)
        try:
            async with AsyncSession(engine) as session:
                await session.execute(delete(AuditChainState))
                await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_drop_state())
    assert _prune("--apply") == 1
    assert "audit_chain_state holds 0 rows" in capsys.readouterr().err
    assert len(asyncio.run(_rows(chain.database_url))) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)


@pytest.mark.parametrize(
    "value",
    ["yesterday", "2026-01-31T00:00:00", "2999-01-01T00:00:00Z"],
    ids=["garbage", "naive", "future"],
)
def test_before_must_be_an_aware_past_timestamp(chain: SimpleNamespace, value: str) -> None:
    assert _prune("--apply", "--before", value) == 2
    assert len(asyncio.run(_rows(chain.database_url))) == 1 + len(OLD_ACTIONS) + len(FRESH_ACTIONS)


def test_class_window_stops_the_prefix_at_the_oldest_row_it_keeps(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("Z4J_AUDIT_RETENTION_BY_CLASS", json.dumps({"auth": 365}))

    assert _prune() == 0
    out = capsys.readouterr().out
    # Genesis plus the two command rows before the old auth.login row.
    assert "would prune  : 3 rows (audit 1, command 2)" in out
    assert "stops at     : auth.login" in out

    assert _prune("--apply") == 0
    rows = asyncio.run(_rows(chain.database_url))
    assert [row.id for row in rows[:4]] == [row.id for row in chain.old[2:] + chain.fresh]
    assert rows[-1].action == AUDIT_PRUNE_ACTION
    assert rows[-1].audit_metadata["rows"] == 3
    assert rows[-1].audit_metadata["cutoff_by_class"].keys() == {"auth"}
    state = asyncio.run(_state(chain.database_url))
    assert state.prune_id == chain.old[1].id
    assert asyncio.run(_verify(chain.database_url)).clean

    # Row ids are random UUIDs, so chain order is the timestamp; make sure the
    # retained auth row is still the oldest survivor and not merely present.
    assert isinstance(rows[0].id, uuid.UUID)
    assert rows[0].action == "auth.login"
