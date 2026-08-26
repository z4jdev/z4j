"""The fork-cleanup backup fence has to run on every platform.

``z4j audit fork-cleanup`` refuses to touch ``audit_log`` on SQLite unless
the backup it just wrote verifies first, and ``--no-backup`` cannot bypass
that. A fence that raises before it can reach its own checks is not a
strict fence, it is a command no operator on that platform can run.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from z4j_brain.cli import _verify_fork_cleanup_backup


def _write_backup(path: Path, groups: dict[str | None, int]) -> None:
    """Write a standalone SQLite file whose audit_log carries ``groups``.

    Each key becomes a ``prev_row_hmac`` value repeated ``count`` times, so
    a key with a count above one is a chain fork the caller is expected to
    have scanned.
    """

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE audit_log (id TEXT PRIMARY KEY, prev_row_hmac TEXT)",
        )
        connection.executemany(
            "INSERT INTO audit_log (id, prev_row_hmac) VALUES (?, ?)",
            [
                (f"{prev_row_hmac}-{index}", prev_row_hmac)
                for prev_row_hmac, count in groups.items()
                for index in range(count)
            ],
        )
        connection.commit()
    finally:
        connection.close()


def test_a_backup_holding_every_scanned_fork_verifies(tmp_path: Path) -> None:
    backup = tmp_path / "z4j.db.pre-fork-cleanup.1700000000"
    _write_backup(backup, {"aa": 3, "bb": 2, "cc": 1, None: 2})

    # Deliberately out of order: the fence compares sorted sets, and single
    # rows plus NULL prev_row_hmac are not forks and must not be expected.
    _verify_fork_cleanup_backup(backup, [("bb", 2), ("aa", 3)])


def test_a_backup_missing_a_scanned_fork_is_rejected(tmp_path: Path) -> None:
    backup = tmp_path / "z4j.db.pre-fork-cleanup.1700000001"
    _write_backup(backup, {"aa": 3, "cc": 1})

    with pytest.raises(RuntimeError, match="does not contain the scanned duplicate set"):
        _verify_fork_cleanup_backup(backup, [("aa", 3), ("bb", 2)])
