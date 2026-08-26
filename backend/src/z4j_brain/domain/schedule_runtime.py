"""Pinned cadence-runtime identity and packaged IANA timezone loading."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from functools import lru_cache
from importlib import metadata, resources
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

CADENCE_SEMANTICS_VERSION = 1
_DEPENDENCIES = ("croniter", "astral", "tzdata", "python-dateutil", "six")


@lru_cache(maxsize=1)
def _packaged_zone_names() -> frozenset[str]:
    """Every zone name the pinned ``tzdata`` wheel actually offers.

    The wheel ships an explicit manifest (``tzdata/zones``), so membership is
    the authoritative test. Everything else -- case, separators, traversal --
    falls out of it for free.
    """

    listing = resources.files("tzdata").joinpath("zones").read_text(encoding="utf-8")
    return frozenset(line.strip() for line in listing.splitlines() if line.strip())


@lru_cache(maxsize=256)
def packaged_zoneinfo(key: str) -> ZoneInfo:
    """Load a zone only from the release-pinned ``tzdata`` wheel."""

    if key not in _packaged_zone_names():
        # EXACT MEMBERSHIP, not a path-shape guard.
        #
        # This used to approximate ZoneInfo's rules by inspecting the string --
        # reject a leading "/", reject backslashes, reject a drive qualifier,
        # reject "." and ".." segments -- and then trust the filesystem to
        # resolve the rest. Every version of that was wrong somewhere, because
        # the filesystem is not a set membership test:
        #
        #   "AMERICA/NEW_YORK"   loads on Windows (case-insensitive), and on
        #   "america/New_York"   Linux does not. Published 1.8 rejected both,
        #   "America./New_York"  because bare ZoneInfo looks the key up exactly.
        #
        # So a Windows Brain accepted timezones its Linux scheduler could not
        # fire, creating a schedule that is then disabled on first tick -- the
        # exact created-but-never-firing failure the API validator exists to
        # prevent, reintroduced by the validator itself.
        #
        # The wheel ships the answer. Membership is case- and separator-exact,
        # identical on every platform, and needs no host-filesystem access at
        # all, so none of those shapes can be reached.
        raise ZoneInfoNotFoundError(key)
    node = resources.files("tzdata.zoneinfo").joinpath(*key.split("/"))
    with node.open("rb") as stream:
        return ZoneInfo.from_file(stream, key=key)


@lru_cache(maxsize=1)
def packaged_tzdata_digest() -> str:
    """Hash the exact packaged timezone tree, independent of host tzdb."""

    digest = hashlib.sha256()
    root = resources.files("tzdata.zoneinfo")

    def visit(node: resources.abc.Traversable, prefix: str) -> None:
        for child in sorted(node.iterdir(), key=lambda item: item.name):
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if child.is_dir():
                if child.name != "__pycache__":
                    visit(child, relative)
                continue
            payload = child.read_bytes()
            encoded = relative.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)

    visit(root, "")
    return digest.hexdigest()


def cadence_runtime_payload(behavior_vector_digest: str) -> dict[str, object]:
    """Return the canonical, inspectable cadence-runtime identity payload.

    Rollback preparation must compare the running candidate to a separately
    sealed compatibility image. Exposing the payload keeps that comparison
    honest: callers verify every component before accepting the digest instead
    of treating a caller-supplied fingerprint as authority.
    """

    behavior = behavior_vector_digest
    if re.fullmatch(r"[0-9a-f]{64}", behavior) is None:
        raise ValueError("cadence behavior-vector digest must be 64 lowercase SHA-256 hex digits")
    return {
        "format": "z4j-cadence-runtime-v1",
        "semantics_version": CADENCE_SEMANTICS_VERSION,
        "dependencies": {package: metadata.version(package) for package in _DEPENDENCIES},
        "tzdata_tree_sha256": packaged_tzdata_digest(),
        "python": {
            "implementation": platform.python_implementation(),
            "version": list(sys.version_info[:3]),
        },
        "behavior_vector_sha256": behavior,
    }


@lru_cache(maxsize=8)
def cadence_runtime_fingerprint(behavior_vector_digest: str) -> str:
    """Bind algorithm, dependencies, tzdata bytes, Python, and behavior."""

    payload = cadence_runtime_payload(behavior_vector_digest)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "CADENCE_SEMANTICS_VERSION",
    "cadence_runtime_fingerprint",
    "cadence_runtime_payload",
    "packaged_tzdata_digest",
    "packaged_zoneinfo",
]
