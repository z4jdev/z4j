"""Executable gates for the on-disk permissions of a database snapshot.

A backup file is the whole database in one place: users, API keys, sessions,
task history and the audit chain. Anyone who can read it can read all of that,
so the mode it lands with is a security property of the backup command, not a
cosmetic detail.

Every test here runs under a deliberately PERMISSIVE umask (0o022, what an
ordinary shell hands a process). Under a strict umask the operating system
would mask the group and other bits away on its own and these assertions would
pass whether or not the code did anything, which is a gate that cannot fail.
``permissive_umask`` establishes that condition and
``test_a_bare_vacuum_into_is_world_readable_under_this_umask`` proves it is
really in force before the positive assertions are believed.

The mode bits are only meaningful on POSIX. Windows reports a synthetic 0o666
for any writable file regardless of what chmod was asked for, so the
assertions are skipped there rather than weakened to something that passes
everywhere.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from z4j_brain.backup import backup, backup_sqlite
from z4j_brain.management_restore_postgres import _copy_backup_to_destination

posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="file mode bits are only enforced on POSIX; Windows reports 0o666",
)

_PERMISSIVE_UMASK = 0o022


@pytest.fixture
def permissive_umask() -> Iterator[int]:
    """Run the test under the umask an ordinary operator shell has."""

    previous = os.umask(_PERMISSIVE_UMASK)
    try:
        yield _PERMISSIVE_UMASK
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _seed_database(path: Path) -> None:
    """Write a small database holding something worth protecting."""

    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, secret TEXT)")
        connection.execute("INSERT INTO api_keys VALUES (1, 'sk-live-secret')")
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


@posix_only
def test_a_bare_vacuum_into_is_world_readable_under_this_umask(
    tmp_path: Path,
    permissive_umask: int,
) -> None:
    """Negative control: the umask under test really does expose files.

    Without this, every assertion below could be passing because the
    environment was strict rather than because the backup code was careful,
    and the suite would look like a gate while guarding nothing.
    """

    source = tmp_path / "z4j.db"
    _seed_database(source)
    unguarded = tmp_path / "unguarded.dump"

    connection = sqlite3.connect(source)
    try:
        connection.execute(f"VACUUM INTO '{unguarded}'")
        connection.commit()
    finally:
        connection.close()

    assert _mode(unguarded) & 0o077, (
        f"umask {permissive_umask:#o} was expected to leave group/other bits "
        f"set, but the file landed as {_mode(unguarded):#o}"
    )


@posix_only
def test_sqlite_snapshot_is_not_readable_by_group_or_other(
    tmp_path: Path,
    permissive_umask: int,
) -> None:
    """The snapshot on disk is private to its owner."""

    source = tmp_path / "z4j.db"
    _seed_database(source)
    output = tmp_path / "snapshot.dump"

    backup_sqlite(f"sqlite+aiosqlite:///{source}", output)

    assert _mode(output) == 0o600, f"snapshot landed as {_mode(output):#o}"
    # State the consequence directly as well, so a future mode change that
    # is still private (0o400, say) does not read as a regression while a
    # mode change that leaks does.
    assert not _mode(output) & 0o077


@posix_only
def test_privacy_does_not_depend_on_a_chmod_after_the_vacuum(
    tmp_path: Path,
    permissive_umask: int,
) -> None:
    """The snapshot is born private rather than corrected afterwards.

    A chmod once the vacuum had finished would satisfy the assertion above
    while publishing the entire database for as long as the vacuum ran, and
    the two are indistinguishable from the finished file. Neutralising the
    chmod tells them apart: only a file that was created private survives
    it. Timing is not involved, so this is a decision, not a race.
    """

    source = tmp_path / "z4j.db"
    _seed_database(source)
    output = tmp_path / "snapshot.dump"

    real_chmod = os.chmod
    requested: list[int] = []

    def swallowing_chmod(path: object, mode: int, **kwargs: object) -> None:
        requested.append(mode)

    os.chmod = swallowing_chmod  # type: ignore[assignment]
    try:
        backup_sqlite(f"sqlite+aiosqlite:///{source}", output)
    finally:
        os.chmod = real_chmod  # type: ignore[assignment]

    assert _mode(output) == 0o600, (
        f"snapshot landed as {_mode(output):#o} once the trailing chmod was "
        f"removed, so it was created readable and narrowed later"
    )
    # Load-bearing, not decoration: it proves the neutralisation above
    # actually intercepted the backstop. Were the backup to stop routing its
    # chmod through this function, the assertion above would start passing
    # for the wrong reason and this one is what notices.
    assert 0o600 in requested


@posix_only
def test_dispatching_backup_produces_a_private_sqlite_snapshot(
    tmp_path: Path,
    permissive_umask: int,
) -> None:
    """The operator-facing entry point, not just its SQLite helper.

    ``z4j backup`` reaches the snapshot through ``backup()``, so that is the
    path whose result the operator actually gets.
    """

    source = tmp_path / "z4j.db"
    _seed_database(source)
    output = tmp_path / "dispatched.dump"

    result = backup(f"sqlite+aiosqlite:///{source}", output)

    assert result["backend"] == "sqlite"
    assert result["size_bytes"] > 0
    assert _mode(Path(result["path"])) == 0o600


@posix_only
def test_postgres_delivery_writes_a_private_archive(
    tmp_path: Path,
    permissive_umask: int,
) -> None:
    """The other backend's delivery step, exercised rather than assumed.

    PostgreSQL backups reach the operator through this copy, so the same
    question has to be asked of it under the same permissive umask.
    """

    body = b"PGDMP\x00" + bytes(range(256)) * 16
    stage = tmp_path / "stage" / "backup.dump"
    stage.parent.mkdir()
    stage.write_bytes(body)
    stage.chmod(0o600)
    destination = tmp_path / "delivered.dump"

    _copy_backup_to_destination(
        stage,
        destination,
        expected_size=len(body),
        expected_digest=hashlib.sha256(body).hexdigest(),
    )

    assert destination.read_bytes() == body
    assert _mode(destination) == 0o600


def test_an_existing_output_is_still_refused(tmp_path: Path) -> None:
    """Reserving the path must not turn a refusal into an overwrite."""

    source = tmp_path / "z4j.db"
    _seed_database(source)
    output = tmp_path / "taken.dump"
    output.write_bytes(b"someone else's file")

    with pytest.raises(FileExistsError) as refusal:
        backup_sqlite(f"sqlite+aiosqlite:///{source}", output)

    assert "refusing to overwrite" in str(refusal.value)
    assert output.read_bytes() == b"someone else's file"


def test_a_failed_backup_leaves_no_file_behind(tmp_path: Path) -> None:
    """A reservation that never became a snapshot is cleaned up.

    Otherwise the next attempt hits the refusal above, and an empty or
    half-written file sits on disk looking like a backup the operator has.
    """

    source = tmp_path / "z4j.db"
    source.write_bytes(b"not a database at all" * 64)
    output = tmp_path / "doomed.dump"

    with pytest.raises(sqlite3.DatabaseError):
        backup_sqlite(f"sqlite+aiosqlite:///{source}", output)

    assert not output.exists()
