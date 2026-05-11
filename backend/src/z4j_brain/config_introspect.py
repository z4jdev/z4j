"""Settings-source attribution for ``z4j config show`` and admin UI.

Reads the same env-file chain Pydantic Settings reads
(``$Z4J_HOME/secret.env``, ``$Z4J_HOME/config.env``, ``./.env``)
plus the process environment, and reports where each effective
Settings value came from.

Hardened per audit M-7: ``secret.env`` is owner-only by design (mode
0o600). The function refuses to read it if the file's mode is wider
than that AND the operator hasn't explicitly opted into widening.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from z4j_core.paths import z4j_home

logger = logging.getLogger("z4j.brain.config_introspect")


def config_source(
    field: str,
    *,
    env: dict[str, str] | None = None,
    is_secret_field: bool = False,
) -> str:
    """Return a short label describing where ``field``'s value came from.

    Args:
        field: Settings field name (e.g. ``retention_days``). The
            corresponding env var is ``Z4J_<FIELD_UPPER>``.
        env: process environment to consult. Defaults to ``os.environ``.
        is_secret_field: if True, ``secret.env`` is omitted from the
            search path. There's no operator value in distinguishing
            "secret came from secret.env" vs "secret came from env"
            in a public report (the value is masked anyway), and
            opening secret.env from a UI surface widens the attack
            surface unnecessarily.

    Returns:
        One of: ``"env (Z4J_FIELD)"``, ``"config.env"``,
        ``"secret.env"``, ``".env"``, or ``"default"``.
    """
    if env is None:
        env = dict(os.environ)
    env_key = f"Z4J_{field.upper()}"
    if env_key in env:
        return f"env ({env_key})"

    home = z4j_home()
    candidates: list[tuple[str, Path]] = [
        ("config.env", home / "config.env"),
        (".env", Path(".env").resolve()),
    ]
    if not is_secret_field:
        # Only secret.env reads need the permission check; other
        # files are operator-managed plaintext.
        candidates.insert(1, ("secret.env", home / "secret.env"))

    for label, path in candidates:
        if not path.exists():
            continue
        if label == "secret.env" and not _secret_env_safe_to_read(path):
            continue
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, _ = line.partition("=")
                if key.strip().upper() == env_key:
                    return label
        except OSError:
            continue

    return "default"


def _secret_env_safe_to_read(path: Path) -> bool:
    """Refuse to surface secret.env content when its mode looks wrong.

    Audit M-7: a misconfigured deploy with a world-readable
    secret.env is itself a security finding. The introspection
    helper should not silently honor it; instead we WARN and skip,
    so the operator notices the setting attribution gap and
    (presumably) goes to fix the file mode.

    On POSIX we inspect ``stat().st_mode`` and require the world +
    group bits to be unset. On Windows POSIX bits are meaningless
    (NTFS ACLs handle equivalent restrictions); we accept the read
    and rely on the auto-mint code's atomic-create path.
    """
    if sys.platform == "win32" or not hasattr(os, "getuid"):
        return True
    try:
        st = path.stat()
    except OSError:
        return False
    # Mask 0o077 = group + world bits. Owner read/write is fine.
    if st.st_mode & 0o077:
        logger.warning(
            "z4j config: refusing to read %s for source attribution; "
            "file mode is too permissive (got %o, expected 0o600). "
            "Run `chmod 600 %s` to fix.",
            path, st.st_mode & 0o777, path,
        )
        return False
    return True


__all__ = ["config_source"]
