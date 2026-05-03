"""Persistent allowed-hosts file management.

Operators reaching the brain via a custom hostname (reverse-proxy domain,
Cloudflare Tunnel, internal LB) need that hostname in the ``Host:`` header
allow-list every time the brain restarts. Three transient channels exist:

- ``Z4J_ALLOWED_HOSTS`` env var (highest precedence, replaces auto-detect)
- ``z4j serve --allowed-host <name>`` CLI flag (additive)
- Auto-detect of localhost + hostname + FQDN + interface IPs

This module adds a fourth: a persistent text file at
``~/.z4j/allowed-hosts``, one host per line (``#`` comments allowed). The
file is read by ``z4j serve`` on every boot and merged into the auto-detect
set, and is writable via ``z4j allowed-hosts add/remove`` subcommands.

Format:

    # custom domains
    tasks.jfk.work
    api.example.com

    # office network reverse proxy
    z4j.internal.lan

Only plain hostnames / IP literals are supported - no CIDR ranges, no
glob patterns. The host validation middleware does exact-match comparison
(case-insensitive) on the request's ``Host`` header.
"""

from __future__ import annotations

from pathlib import Path

#: Default location for the persistent allowed-hosts file. Mirrors
#: ``~/.z4j/secret.env`` (where the brain persists auto-minted secrets);
#: the same directory is the natural home for operator-managed config.
DEFAULT_PATH = Path.home() / ".z4j" / "allowed-hosts"


def get_path() -> Path:
    """Return the canonical allowed-hosts file path.

    Honours ``Z4J_HOME`` if set (operators who relocate the brain's
    state directory); otherwise defaults to ``~/.z4j/allowed-hosts``.
    """
    import os

    home = os.environ.get("Z4J_HOME")
    if home:
        return Path(home) / "allowed-hosts"
    return DEFAULT_PATH


def read_persisted() -> list[str]:
    """Load the persisted allow-list. Returns ``[]`` if the file is missing.

    Strips comments and blank lines. Preserves operator-supplied order.
    Lower-cases hostnames so duplicates with different casing collapse.
    """
    path = get_path()
    if not path.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for raw in text.splitlines():
        line = raw.strip()
        # Allow inline comments after a `#` so operators can annotate.
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out


def write_persisted(hosts: list[str]) -> None:
    """Replace the file's contents with ``hosts``. Idempotent.

    Atomic via tmpfile + rename so an interrupted write doesn't corrupt
    the existing file. Sets the file mode to 0o644 - hosts are not
    secrets, but the directory itself is operator-owned.
    """
    path = get_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    body = (
        "# z4j allowed-hosts - one hostname or IP per line.\n"
        "# Managed by `z4j allowed-hosts add/remove`.\n"
        "# Edits here take effect on the next `z4j serve` start.\n"
        "\n"
    )
    body += "\n".join(hosts) + "\n"
    tmp.write_text(body, encoding="utf-8")
    try:
        tmp.replace(path)
    except OSError:
        # On Windows, replace can fail if the destination exists in some
        # contexts; fall back to write + remove.
        if path.exists():
            path.unlink()
        tmp.replace(path)
    try:
        path.chmod(0o644)
    except OSError:
        pass


def add(hosts_to_add: list[str]) -> tuple[list[str], list[str]]:
    """Add one or more hosts to the persisted list. Idempotent.

    Returns ``(added, already_present)`` so the caller can give a
    useful confirmation message.
    """
    current = read_persisted()
    current_lower = {h.lower() for h in current}
    added: list[str] = []
    skipped: list[str] = []
    for raw in hosts_to_add:
        h = raw.strip()
        if not h:
            continue
        if h.lower() in current_lower:
            skipped.append(h)
            continue
        current.append(h)
        current_lower.add(h.lower())
        added.append(h)
    if added:
        write_persisted(current)
    return added, skipped


def remove(hosts_to_remove: list[str]) -> tuple[list[str], list[str]]:
    """Remove one or more hosts from the persisted list. Idempotent.

    Returns ``(removed, not_found)``.
    """
    current = read_persisted()
    targets_lower = {h.strip().lower() for h in hosts_to_remove if h.strip()}
    removed: list[str] = []
    not_found = list(targets_lower)
    new_list: list[str] = []
    for h in current:
        if h.lower() in targets_lower:
            removed.append(h)
            if h.lower() in not_found:
                not_found.remove(h.lower())
        else:
            new_list.append(h)
    if removed:
        write_persisted(new_list)
    return removed, not_found


__all__ = [
    "DEFAULT_PATH",
    "add",
    "get_path",
    "read_persisted",
    "remove",
    "write_persisted",
]
