"""Executable gates for the byte-exactness of a delivered PostgreSQL backup.

A ``pg_dump -Fc`` archive is compressed binary: 0x1A and bare ``\\n`` bytes
appear throughout it. On Windows ``os.open`` selects text mode unless
O_BINARY is given, which stops a read at the first 0x1A and expands ``\\n``
on the way out, so the copy that delivers the archive to the operator can
truncate it. Nothing downstream noticed, because the size and digest checks
around the copy both measured the stage against itself.

These tests run the real copy path rather than inspecting its flags.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from z4j_brain.management_restore_postgres import (
    DatabaseRestoreRefused,
    _copy_backup_to_destination,
    _read_back_archive,
)

# The first byte is what DOS used as end-of-file, and it is the byte that
# makes a text-mode read stop early. The CRLF pairs and bare newlines catch
# the other half of text mode, which rewrites line endings as it writes.
_ARCHIVE_BODY = (
    b"PGDMP\x00\x01\x1a\x00payload\r\n" + bytes(range(256)) * 64 + b"\x1a" * 8 + b"\ntail\r\n\x1a"
)


def _stage_archive(directory: Path) -> tuple[Path, int, str]:
    """Write a stage file that looks like a compressed archive."""

    directory.mkdir(parents=True, exist_ok=True)
    stage = directory / "backup.dump"
    stage.write_bytes(_ARCHIVE_BODY)
    stage.chmod(0o600)
    return (
        stage,
        len(_ARCHIVE_BODY),
        hashlib.sha256(_ARCHIVE_BODY).hexdigest(),
    )


def test_copy_delivers_an_archive_containing_0x1a_byte_for_byte(
    tmp_path: Path,
) -> None:
    """The delivered file equals the stage, 0x1A bytes and all."""

    stage, size, digest = _stage_archive(tmp_path / "stage")
    destination = tmp_path / "out" / "z4j.dump"
    destination.parent.mkdir(parents=True)

    _copy_backup_to_destination(
        stage,
        destination,
        expected_size=size,
        expected_digest=digest,
    )

    delivered = destination.read_bytes()
    assert delivered == _ARCHIVE_BODY
    assert len(delivered) == size
    assert hashlib.sha256(delivered).hexdigest() == digest


def test_read_back_sees_every_byte_past_the_first_0x1a(tmp_path: Path) -> None:
    """The verifier itself must not stop at the end-of-file byte.

    A verifier that truncated the same way as the writer would agree with
    a truncated archive and report success, so it gets its own gate.
    """

    archive = tmp_path / "z4j.dump"
    archive.write_bytes(_ARCHIVE_BODY)

    size, digest = _read_back_archive(archive)

    assert size == len(_ARCHIVE_BODY)
    assert digest == hashlib.sha256(_ARCHIVE_BODY).hexdigest()


def test_copy_refuses_when_the_delivered_bytes_differ(tmp_path: Path) -> None:
    """A copy that loses bytes on the way out fails at backup time.

    Simulates a write path that silently drops the tail, which is what the
    Windows text-mode defect looked like from the destination's side. The
    old code returned success here because it never read the destination.
    """

    stage, size, digest = _stage_archive(tmp_path / "stage")
    destination = tmp_path / "out" / "z4j.dump"
    destination.parent.mkdir(parents=True)

    real_write = os.write
    lied: list[int] = []

    def lying_write(fd: int, data: bytes) -> int:
        # Drop the tail once while reporting a full write, so the copy
        # loop believes it finished and the destination ends up short.
        if not lied and len(data) > 64:
            lied.append(fd)
            real_write(fd, data[:-64])
            return len(data)
        return real_write(fd, data)

    original = os.write
    os.write = lying_write  # type: ignore[assignment]
    try:
        with pytest.raises(DatabaseRestoreRefused) as refusal:
            _copy_backup_to_destination(
                stage,
                destination,
                expected_size=size,
                expected_digest=digest,
            )
    finally:
        os.write = original  # type: ignore[assignment]

    assert "does not match the staged archive" in str(refusal.value)
    # A backup that cannot be trusted must not be left lying around
    # looking like a backup.
    assert not destination.exists()


def test_copy_refuses_a_short_read_of_the_stage(tmp_path: Path) -> None:
    """A stage that reads back short is refused, not delivered.

    This is the exact shape of the Windows text-mode failure: the read
    stops early, so fewer bytes cross the descriptor than pg_dump wrote.
    """

    stage, size, digest = _stage_archive(tmp_path / "stage")
    destination = tmp_path / "out" / "z4j.dump"
    destination.parent.mkdir(parents=True)

    real_read = os.read
    stage_fd_sizes = {size}

    def truncating_read(fd: int, length: int) -> bytes:
        data = real_read(fd, length)
        # Only clip the archive being staged, not unrelated descriptors
        # pytest may be using underneath this test.
        if data[:5] == b"PGDMP":
            stage_fd_sizes.add(fd)
            return data[:4]
        if fd in stage_fd_sizes:
            return b""
        return data

    original = os.read
    os.read = truncating_read  # type: ignore[assignment]
    try:
        with pytest.raises(DatabaseRestoreRefused) as refusal:
            _copy_backup_to_destination(
                stage,
                destination,
                expected_size=size,
                expected_digest=digest,
            )
    finally:
        os.read = original  # type: ignore[assignment]

    assert "did not read back as it was written" in str(refusal.value)
    assert not destination.exists()


@pytest.mark.skipif(
    not hasattr(os, "O_BINARY"),
    reason="text mode is a Windows behaviour; O_BINARY is a no-op elsewhere",
)
def test_text_mode_would_truncate_this_archive(tmp_path: Path) -> None:
    """Negative control: prove the payload really does trip text mode.

    Without this, the byte-for-byte test above could pass on a platform
    where nothing was ever at risk, and it would look like a gate while
    guarding nothing.
    """

    archive = tmp_path / "z4j.dump"
    archive.write_bytes(_ARCHIVE_BODY)

    fd = os.open(archive, os.O_RDONLY)
    try:
        text_mode_bytes = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            text_mode_bytes += len(chunk)
    finally:
        os.close(fd)

    assert text_mode_bytes < len(_ARCHIVE_BODY)
