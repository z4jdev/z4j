"""What a SQLite restore survives when the machine stops mid-ceremony.

The ceremony's rule is that the durable phase is written before the thing it
describes happens, because the phase is what both exits read afterwards. Where
that order is inverted -- a side effect landing before the record saying it
landed -- a crash leaves an operation that neither `z4j restore --operation`
nor `z4j restore --rollback-operation` can finish, on a brain that will not
start until one of them does.

Two shapes are pinned here:

* Directory entries. A rename is only as durable as the directories on both
  ends of it, and the live database is renamed INTO the operation directory
  before its replacement is installed. Power loss cannot be staged in-process,
  so these tests pin the claim where it is made: ``_fsync_directory`` is the
  primitive, and the assertions are about the real ceremony reaching it for
  the right directory at the right moment. Everything called through is real.

* The rollback marker. It commits into the live database, which moves that
  database's manifest by one audit row, and only afterwards is ROLLED_BACK
  recorded. These tests crash the ceremony for real at that exact statement
  and then ask the next command to finish the job.

The last two tests are the ends of the same rope. One is the operator
surface, which fails the same way for a different reason: a fence naming a
command the CLI rejects has no exit either. The other pins the order that
already holds for the delivered backup archive, so that the one file a
restore is eventually pointed at keeps having its bytes before its name.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from z4j_brain import management_restore
from z4j_brain.cli import main
from z4j_brain.management_restore import (
    DatabaseRestorePending,
    _ensure_durable_directory,
    assert_database_restore_not_pending,
    restore_sqlite_database,
    rollback_sqlite_database,
)
from z4j_brain.secret_store import ensure_secret_store_directory

_PHASE_ROOT = ".z4j-restore"


class _SimulatedPowerLoss(RuntimeError):  # noqa: N818  not an error, a crash
    """Stands in for the process dying at one exact statement."""


@contextlib.contextmanager
def _cli_from_a_clean_directory():
    """Run the CLI somewhere with no repository .env in reach.

    z4j captures configuration from the current directory and refuses a .env
    whose permissions grant a non-owner trustee. A developer checkout can
    easily have one, and then a test that invokes the CLI fails for a reason
    that has nothing to do with what it is testing. Production never runs from
    a directory it does not own.
    """
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="z4j-cli-cwd-") as workdir:
        os.chdir(workdir)
        try:
            yield
        finally:
            os.chdir(previous)


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


def _file_digest_of(path: Path) -> tuple[int, str]:
    """Measure a file the way the delivery path expects to be told about it."""

    payload = path.read_bytes()
    return len(payload), hashlib.sha256(payload).hexdigest()


def _phase_state(target: Path, operation: uuid.UUID) -> str:
    phase_path = target.parent / _PHASE_ROOT / str(operation) / "phase.json"
    return str(management_restore._read_phase(phase_path)["state"])


@contextlib.contextmanager
def _lose_power_before_recording(state: str) -> Iterator[None]:
    """Stop the ceremony just before ``state`` reaches the disk.

    Patching the durable writer rather than the caller puts the interruption
    on the exact statement the crash windows are described in terms of:
    everything before that write really happened, and the phase on disk is
    left saying what it said a moment earlier.
    """

    real = management_restore._replace_phase

    def guard(path: Path, phase: Mapping[str, Any]) -> None:
        if phase.get("state") == state:
            raise _SimulatedPowerLoss(state)
        real(path, phase)

    with pytest.MonkeyPatch.context() as crash:
        crash.setattr(management_restore, "_replace_phase", guard)
        yield


@pytest.fixture
def fsync_log(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Every directory persisted, in order, with the real fsync still done."""

    recorded: list[Path] = []
    real = management_restore._fsync_directory

    def record(path: Path) -> None:
        recorded.append(Path(path))
        real(path)

    monkeypatch.setattr(management_restore, "_fsync_directory", record)
    return recorded


@pytest.fixture
def target(migrated_sqlite_template: Path, tmp_path: Path) -> Path:
    """A live database at the release head, in its own private directory."""

    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    database = home / "z4j.db"
    shutil.copyfile(migrated_sqlite_template, database)
    return database


@pytest.fixture
def source(migrated_sqlite_template: Path, tmp_path: Path) -> Path:
    """A restorable archive that is NOT the live database."""

    archive = tmp_path / "z4j-backup.db"
    shutil.copyfile(migrated_sqlite_template, archive)
    return archive


@pytest.fixture
def restore_environment(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    migrated_audit_chain_secret: str,
) -> None:
    """The environment the ceremony reads its own Settings from.

    The ceremony constructs ``Settings()`` from the process environment,
    exactly as the CLI leaves it, and the audit-chain key has to be the one
    the target was activated with or every case below stops for the wrong
    reason.
    """
    for key in list(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("Z4J_DATABASE_URL", _database_url(target))
    monkeypatch.setenv("Z4J_HOME", str(target.parent))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", migrated_audit_chain_secret)


def _plant_marker_row(database: Path) -> str:
    """Give one database a row the other copy does not have."""

    slug = f"kept-{uuid.uuid4().hex[:12]}"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "INSERT INTO projects (id, slug, name, created_at, updated_at) "
            "VALUES (?, ?, 'retained by rollback', "
            "'2026-01-01T00:00:00', '2026-01-01T00:00:00')",
            (uuid.uuid4().hex, slug),
        )
        connection.commit()
    finally:
        connection.close()
    return slug


def _has_marker_row(database: Path, slug: str) -> bool:
    connection = sqlite3.connect(database)
    try:
        found = connection.execute(
            "SELECT COUNT(*) FROM projects WHERE slug = ?",
            (slug,),
        ).fetchone()[0]
    finally:
        connection.close()
    return bool(found)


def _rollback_markers(database: Path, operation: uuid.UUID) -> list[str]:
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT id FROM audit_log "
            "WHERE action = 'audit.database_restore_rolled_back' "
            "AND target_id = ?",
            (str(operation),),
        ).fetchall()
    finally:
        connection.close()
    # SQLite keeps the id as bare hex; the ceremony hands back the dashed
    # spelling, and comparing the two textually is a difference that is not
    # one.
    return [str(uuid.UUID(str(row[0]))) for row in rows]


def test_every_new_restore_directory_gets_its_own_name_persisted(
    tmp_path: Path,
    fsync_log: list[Path],
) -> None:
    """A created directory is only reachable if its PARENT is on the platter.

    Fsyncing the new directory persists what is written inside it and nothing
    about the entry that leads to it, so a crash can return a parent with no
    such child -- taking the operation directory, the displaced live database
    inside it, and the phase that names both.
    """
    home = ensure_secret_store_directory(tmp_path / "z4j-home")
    fsync_log.clear()

    operation_dir = home / _PHASE_ROOT / str(uuid.uuid4())
    _ensure_durable_directory(operation_dir)

    assert fsync_log == [home, operation_dir.parent], (
        "each newly created directory must have its parent persisted, "
        f"shallowest first; got {fsync_log}"
    )


def test_a_directory_that_already_existed_is_not_persisted_again(
    tmp_path: Path,
    fsync_log: list[Path],
) -> None:
    """The control for the test above.

    Persisting unconditionally would satisfy it just as well, and would say
    nothing about whether the ceremony persists the names it actually
    created.
    """
    home = ensure_secret_store_directory(tmp_path / "z4j-home")
    _ensure_durable_directory(home / "already-there")
    fsync_log.clear()

    _ensure_durable_directory(home / "already-there")

    assert fsync_log == []


def test_the_displaced_live_database_is_persisted_before_its_old_name_goes(
    target: Path,
    source: Path,
    restore_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installation renames the live database into the operation directory.

    That rename is the only moment in the ceremony when the live database has
    exactly one name, and it is a name in the operation directory. Persisting
    the directory the file LEFT first, and only that one, is the order in
    which a crash takes both the live database and its sole recovery copy.
    """
    operation = uuid.uuid4()
    operation_dir = target.parent / _PHASE_ROOT / str(operation)
    displaced = operation_dir / "displaced-main.db"

    persisted_while_displaced: list[Path] = []
    real = management_restore._fsync_directory

    def record(path: Path) -> None:
        if displaced.exists():
            persisted_while_displaced.append(Path(path))
        real(path)

    monkeypatch.setattr(management_restore, "_fsync_directory", record)
    restore_sqlite_database(_database_url(target), source, operation=operation)

    assert persisted_while_displaced, (
        "the live database was never moved into the operation directory, so "
        "this test proved nothing about the window it is here for"
    )
    assert persisted_while_displaced[0] == operation_dir, (
        "the live database was renamed into the operation directory and the "
        f"first directory persisted afterwards was "
        f"{persisted_while_displaced[0]}: a crash in that gap can keep the "
        "removal of the live name and lose the entry that reaches the only "
        "remaining copy of it"
    )


def test_a_rollback_interrupted_after_its_marker_can_still_finish(
    target: Path,
    source: Path,
    restore_environment: None,
) -> None:
    """The rollback marker commits before the phase that records it.

    Committing it adds one audit row to the live database, and for a restore
    that has not installed anything yet the live database IS the captured
    one, so that single row makes every later comparison read as the target
    having been changed underfoot. Both exits then refuse forever: the fence
    stays up, and the brain stays down.
    """
    url = _database_url(target)
    operation = uuid.uuid4()
    retained = _plant_marker_row(target)

    # Stop before anything is installed, which is the phase an operator is
    # most likely to abandon. Note that "not installed" is NOT the same as
    # "untouched": the rollback below commits a marker row into the live
    # database while the phase still reads CANDIDATE_FINALIZED, which is why
    # the fence message for these states cannot promise byte-identity.
    with _lose_power_before_recording("INSTALLING"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(url, source, operation=operation)
    assert _phase_state(target, operation) == "CANDIDATE_FINALIZED"

    with _lose_power_before_recording("ROLLED_BACK"), pytest.raises(_SimulatedPowerLoss):
        rollback_sqlite_database(url, operation=operation)

    committed = _rollback_markers(target, operation)
    assert len(committed) == 1, (
        "the interrupted rollback was supposed to leave exactly one committed "
        f"marker behind; found {committed}"
    )
    assert _phase_state(target, operation) == "CANDIDATE_FINALIZED"

    result = rollback_sqlite_database(url, operation=operation)

    assert result["rolled_back"] is True
    assert result["marker_id"] == committed[0], (
        "the completed rollback must adopt the marker the crashed attempt "
        "committed, not sign a second one"
    )
    assert _rollback_markers(target, operation) == committed
    assert _has_marker_row(target, retained), (
        "rollback returned the retained pre-operation target, so the row that "
        "only the live database had must still be there"
    )
    # The property the operator actually lost: a startable brain.
    assert_database_restore_not_pending(url)
    assert rollback_sqlite_database(url, operation=operation) == result


def test_the_resume_command_the_fence_prints_is_one_the_cli_runs(
    target: Path,
    source: Path,
    restore_environment: None,
) -> None:
    """Startup names a resume command; it has to be runnable as printed.

    The fence is raised on every boot until the operation ends, and the
    commands in its text are the whole of what an operator has to go on. A
    resume takes its source from the durable phase, so the command names no
    path -- and the CLI used to reject exactly that, leaving both of the
    advertised exits unusable for anyone who pasted what they were shown.
    """
    url = _database_url(target)
    operation = uuid.uuid4()
    with _lose_power_before_recording("INSTALLING"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(url, source, operation=operation)

    with pytest.raises(DatabaseRestorePending) as fenced:
        assert_database_restore_not_pending(url)
    advertised = re.findall(r"`([^`]+)`", str(fenced.value))
    resume = [command for command in advertised if "--rollback-operation" not in command]
    assert len(resume) == 1, f"the fence advertised {advertised}"
    argv = resume[0].split()
    assert argv[0] == "z4j"

    with _cli_from_a_clean_directory():
        assert main(argv[1:]) == 0, f"the fence advertised `{resume[0]}`, which failed"

    # The restore really finished rather than the CLI merely exiting zero.
    assert_database_restore_not_pending(url)
    assert _phase_state(target, operation) == "COMPLETE"


def test_a_restore_with_neither_a_path_nor_an_operation_is_still_refused(
    target: Path,
    restore_environment: None,
) -> None:
    """The control for the test above.

    Accepting a missing PATH unconditionally would pass it, and would hand
    the next operator a restore with nothing to restore from. An --operation
    that names nothing has to say so for the same reason.
    """
    with _cli_from_a_clean_directory():
        assert main(["restore", "--force"]) == 1
        assert main(["restore", "--force", "--operation", str(uuid.uuid4())]) == 1


def test_a_delivered_backup_has_its_bytes_persisted_before_its_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The archive a restore will be pointed at is the one file that must last.

    This order already holds; the test is here to keep it. Delivery persists
    the directory entry, and persisting only that would put the name on the
    platter ahead of the contents, leaving a backup that exists, was reported
    as taken, and is short or empty by the time a restore reaches for it.
    """
    from z4j_brain.management_restore_postgres import _copy_backup_to_destination

    stage = tmp_path / "stage.dump"
    stage.write_bytes(b"PGDMP" + bytes(range(256)) * 64)
    expected_size, expected_digest = _file_digest_of(stage)
    delivered = tmp_path / "out" / "z4j-backup.dump"
    delivered.parent.mkdir(mode=0o700)

    persisted_files: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        observed = os.fstat(fd)
        if stat.S_ISREG(observed.st_mode):
            persisted_files.append((observed.st_dev, observed.st_ino))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", record)
    _copy_backup_to_destination(
        stage,
        delivered,
        expected_size=expected_size,
        expected_digest=expected_digest,
    )

    written = delivered.stat()
    assert (written.st_dev, written.st_ino) in persisted_files, (
        "the delivered archive's directory entry was persisted but its "
        "contents were not, so a crash leaves a backup that exists and is "
        "not the bytes it claims to be"
    )


# ---------------------------------------------------------------------------
# What the pending-restore fence TELLS the operator.
#
# The message is the whole interface at this point: the brain will not start,
# and the only thing guiding what happens next is that sentence. It shipped
# asserting "the live database is untouched" for every pending state, which is
# false once installation has begun -- exactly when it invites deleting the
# directory holding the only pre-restore copy.
#
# The pairing is the point. A positive assertion alone passes against a
# message that says the same thing in every state, which is the bug. These
# check that the two dispositions actually DISCRIMINATE.
# ---------------------------------------------------------------------------


def _pending_message(url: str) -> str:
    """The fence message an operator sees when the brain refuses to start."""
    with pytest.raises(DatabaseRestorePending) as excinfo:
        assert_database_restore_not_pending(url)
    return str(excinfo.value)


def test_a_pre_install_fence_does_not_promise_an_untouched_database(
    target: Path,
    source: Path,
    restore_environment: None,
) -> None:
    """CANDIDATE_FINALIZED is pre-install, and still not byte-identical.

    An abandoned rollback commits its marker row into the LIVE database
    before the phase recording it reaches disk, so this state can sit beside
    a database that differs from the operator's by one audit row. Saying
    "untouched" there is a promise the product cannot keep.
    """
    url = _database_url(target)
    operation = uuid.uuid4()

    with _lose_power_before_recording("INSTALLING"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(url, source, operation=operation)
    assert _phase_state(target, operation) == "CANDIDATE_FINALIZED"

    with _lose_power_before_recording("ROLLED_BACK"), pytest.raises(_SimulatedPowerLoss):
        rollback_sqlite_database(url, operation=operation)
    assert len(_rollback_markers(target, operation)) == 1, (
        "this test is only meaningful once the interrupted rollback has "
        "actually committed a marker into the live database"
    )

    message = _pending_message(url)
    assert "is untouched" not in message, (
        "the fence promised an untouched database in a state where an "
        f"abandoned rollback has already committed an audit row: {message}"
    )
    assert "not been displaced or replaced" in message, (
        f"the pre-install disposition is missing from the fence: {message}"
    )


def test_a_post_install_fence_warns_that_the_database_may_be_displaced(
    target: Path,
    source: Path,
    restore_environment: None,
) -> None:
    """Once installation starts, the live file may already be gone.

    This is the direction that matters: the operator must not be told to
    treat the target as their original, and must be told to keep the
    operation directory, which holds the only pre-restore copy.
    """
    url = _database_url(target)
    operation = uuid.uuid4()

    with _lose_power_before_recording("INSTALLED"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(url, source, operation=operation)
    state = _phase_state(target, operation)
    assert state not in management_restore._PRE_INSTALL_PHASE_STATES, (
        f"expected a post-install phase for this crash point, got {state}"
    )

    message = _pending_message(url)
    assert "may already have been displaced" in message, (
        f"the post-install disposition is missing from the fence: {message}"
    )
    assert "do not delete that directory" in message, (
        "the fence must name the operation directory as the thing to keep, "
        f"because it holds the only pre-restore copy: {message}"
    )
    assert "not been displaced or replaced" not in message, (
        f"the fence gave the pre-install reassurance after installing: {message}"
    )


def test_the_two_fence_dispositions_are_not_the_same_sentence(
    target: Path,
    source: Path,
    restore_environment: None,
) -> None:
    """The messages must differ, or neither assertion above proves anything.

    Written because the branch these cover was added with no coverage at
    all, and a single message reused in both states would have satisfied a
    one-sided test while telling the operator the wrong thing in one of them.
    """
    pre_url = _database_url(target)
    pre_operation = uuid.uuid4()
    with _lose_power_before_recording("INSTALLING"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(pre_url, source, operation=pre_operation)
    pre_message = _pending_message(pre_url)

    rollback_sqlite_database(pre_url, operation=pre_operation)
    assert_database_restore_not_pending(pre_url)

    post_operation = uuid.uuid4()
    with _lose_power_before_recording("INSTALLED"), pytest.raises(_SimulatedPowerLoss):
        restore_sqlite_database(pre_url, source, operation=post_operation)
    post_message = _pending_message(pre_url)

    # Compare with the operation ids and phase names masked out. Without this
    # the two messages differ trivially because they name different UUIDs, and
    # the assertion passes even when both dispositions are the same sentence.
    # The first version of this test did exactly that: it passed against the
    # unconditional message it was written to catch.
    def _disposition_only(message: str) -> str:
        masked = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<uuid>", message)
        return re.sub(r"stopped at [A-Z_]+", "stopped at <state>", masked)

    assert _disposition_only(pre_message) != _disposition_only(post_message), (
        "the pre-install and post-install fences carry the same disposition "
        "once the operation id is masked out, so the phase-aware branch is "
        "not discriminating at all"
    )
