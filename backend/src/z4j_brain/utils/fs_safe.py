"""Filesystem-safe write helpers shared across z4j-brain subsystems.

Atomic-create-with-mode patterns avoid TOCTOU races on POSIX where
a colocated unprivileged process could ``open()`` a file between
the initial write (created with the process umask, typically
``0o644``) and the follow-up ``chmod(0o600)``.

Audit fix S005 (1.4.0): factored out of ``embedded_scheduler.py``
so the cert-mint helper in ``scheduler_grpc/auth.py`` shares the
same race-safe primitive instead of carrying the older
write-then-chmod pattern.
"""

from __future__ import annotations

import os
from pathlib import Path


def write_bytes_secure(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically write ``data`` to ``path`` with strict ``mode`` at create.

    Creates the file via ``os.open`` with ``O_NOFOLLOW`` (defeating
    a pre-planted-symlink race where an attacker who can create the
    destination first would otherwise have us write to the symlink
    target with our private contents) and the strict ``mode`` set
    at creation time so the file is never world-readable, even
    briefly, between create and an explicit chmod.

    A defensive belt-and-suspenders ``chmod`` follows because some
    filesystems (notably non-POSIX volumes on Windows) ignore the
    mode bits in ``os.open``.

    ``O_EXCL`` is NOT used: callers like the cert-mint helpers and
    the embedded-scheduler PKI bootstrap are documented as
    overwriting any pre-existing file on each invocation.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    # POSIX; ``getattr`` because Windows defines O_NOFOLLOW as 0
    # in stdlib so the syscall is effectively a no-op there.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    # Windows: ``os.open`` defaults to text mode if neither
    # O_TEXT nor O_BINARY is specified, which would translate
    # ``\n`` to ``\r\n`` in the written PEM. Force binary so the
    # bytes hit disk verbatim. POSIX defines O_BINARY as 0 (or
    # absent) so this is a no-op there.
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        path.chmod(mode)
    except OSError:
        # Non-POSIX volumes may reject chmod; the directory mode is
        # the access control we rely on in that case.
        pass


def ensure_dir_secure(path: Path, *, mode: int = 0o700) -> None:
    """Create ``path`` with ``mode`` OR re-chmod if it already exists.

    ``Path.mkdir(exist_ok=True, mode=...)`` only applies ``mode`` on
    creation; an already-existing directory keeps its old (possibly
    world-readable) perms. This helper closes that gap by explicitly
    chmod-ing after mkdir, so a pre-existing loose-perms dir gets
    tightened to the intended mode.

    Audit fix S005 (1.4.0): the caller in ``write_minted_cert``
    previously called ``mkdir(exist_ok=True, mode=0o700)`` and
    relied on the assumption the dir would always be freshly
    created -- but operators re-running the cert-mint command
    against an existing dir kept whatever loose perms were already
    there.
    """
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        path.chmod(mode)
    except OSError:
        pass


__all__ = ["write_bytes_secure", "ensure_dir_secure"]
