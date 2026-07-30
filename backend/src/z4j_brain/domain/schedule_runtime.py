"""Pinned cadence-runtime identity and packaged IANA timezone loading."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from functools import lru_cache
from importlib import metadata, resources
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

CADENCE_SEMANTICS_VERSION = 1
_DEPENDENCIES = ("croniter", "astral", "tzdata", "python-dateutil", "six")


@lru_cache(maxsize=256)
def packaged_zoneinfo(key: str) -> ZoneInfo:
    """Load a zone only from the release-pinned ``tzdata`` wheel."""

    clean = key.strip()
    if (
        not clean
        or clean.startswith("/")
        or any(part in {"", ".", ".."} for part in clean.split("/"))
    ):
        raise ZoneInfoNotFoundError(key)
    node = resources.files("tzdata.zoneinfo").joinpath(*clean.split("/"))
    try:
        with node.open("rb") as stream:
            return ZoneInfo.from_file(stream, key=clean)
    except (FileNotFoundError, IsADirectoryError) as exc:
        raise ZoneInfoNotFoundError(key) from exc


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


@lru_cache(maxsize=8)
def cadence_runtime_fingerprint(behavior_vector_digest: str) -> str:
    """Bind algorithm, dependencies, tzdata bytes, Python, and behavior."""

    behavior = behavior_vector_digest.strip()
    if len(behavior) != 64:
        raise ValueError("cadence behavior-vector digest must be sha256 hex")
    payload = {
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
    "packaged_tzdata_digest",
    "packaged_zoneinfo",
]
