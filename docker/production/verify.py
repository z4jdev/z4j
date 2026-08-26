#!/usr/bin/env python3
"""Fail-closed verifier for the z4j production container contract.

This module intentionally uses only the Python standard library.  It runs in
release preparation, in the Python builder stage, and in focused adversarial
tests before any dependency from the production wheelhouse is imported.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import csv
import datetime as dt
import email.parser
import email.utils
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import zipfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA_VERSION = 1
KIND = "z4j-production-container-contract"
RELEASE = "1.9.0"
FINALIZATION_CUTOFF = "2026-08-23T04:14:39.107Z"
PLATFORMS = ("linux/amd64", "linux/arm64")
ZERO_DIGEST = "sha256:" + "0" * 64
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_WHEEL_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_FILES = 20_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024
LINUX_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
LINUX_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 1)
LINUX_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 2)
LINUX_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 4)
LINUX_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
IMMUTABLE_IMAGE = re.compile(
    r"docker\.io/[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}\Z"
)
LOCK_ENTRY = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*) "
    r"--hash=sha256:([0-9a-f]{64})\Z"
)
EXPECTED_BASE = {
    "commit": "986a33eb60d3554bb1269126f9768a201349b54f",
    "tree": "bb5fc5dc7b539536e0e5d12ebdedcf54a62f0025",
    "patch": "423ce1165f34a192e1f3519d5f0bb4499b8c8f8fc9539fb40404bc518c013a38",
    "patch_size": 1716110,
}
PROJECTION_RECORD_FRAMING = (
    "canonical-json:{format,files:[{path,mode,size,sha256}]} sorted by UTF-8 logical "
    "path; mode is 0755 iff path is listed in executables, otherwise 0644"
)
EXPECTED_PYTHON = {
    "implementation": "CPython",
    "version": "3.14.7",
    "image": (
        "docker.io/library/python:3.14.7-slim-trixie@"
        "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
    ),
    "index": {
        "digest": "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4",
        "size": 10365,
    },
    "source_tar_sha256": "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81",
    "docker_library_revision": "228f71e70a42ba9f9a092321b971031603bb88ff",
    "platforms": {
        "linux/amd64": {
            "manifest_digest": "sha256:d6e0850f13fda0e2305d4c3c1c2f7930fe1042d34ddd958e49bba6ef685d0bb2",
            "manifest_size": 1745,
            "config_digest": "sha256:a41c1f663be90eb31af9864d1e1ccdaa91b6af11776b7ade1c05915e76da7aea",
            "config_size": 4934,
        },
        "linux/arm64": {
            "manifest_digest": "sha256:c65a4a1140b75416bbc7f28807f82a3746bd6567645d5848123b6a6587f86962",
            "manifest_size": 1747,
            "config_digest": "sha256:462b4d0ce92fd7559a84feb2d3ab4eca3b741c5a1a375e28cce7fd8900659688",
            "config_size": 4949,
        },
    },
}
EXPECTED_INCLUSIONS = {
    "z4j": [
        "LICENSE",
        "README.md",
        "backend/src/z4j_brain",
        "pyproject.toml",
        "src/z4j",
    ],
    "z4j-core": ["LICENSE", "README.md", "pyproject.toml", "src/z4j_core"],
    "z4j-scheduler": [
        "CHANGELOG.md",
        "LICENSE",
        "README.md",
        "proto",
        "pyproject.toml",
        "src/z4j_scheduler",
    ],
}
EXPECTED_EXCLUSIONS = [".DS_Store", "__pycache__", "*.pyc", "*.pyo"]
EXPECTED_SOURCE_EXECUTABLES: list[str] = []
EXPECTED_ALLOWED_PATHS = [
    "docker/production/locks/build-linux-amd64.txt",
    "docker/production/locks/build-linux-arm64.txt",
    "docker/production/locks/system-linux-amd64.json",
    "docker/production/locks/system-linux-arm64.json",
    "docker/production/locks/runtime-linux-amd64.txt",
    "docker/production/locks/runtime-linux-arm64.txt",
    "docker/production/locks/UNFINALIZED",
    "docker/production/manifest.json",
]
EXPECTED_RECEIPT_POLICY = {
    "kind": "z4j-production-container-finalization-v1",
    "required": True,
    "binds": [
        "release_git_commit",
        "release_git_tree",
        "manifest_sha256",
        "production_source_projection_sha256",
        "source_tag_authority",
        "system_authority_policy",
        "system_authority",
        "dashboard_authority_policy",
        "dashboard_authority",
        "wheelhouse_index_digest",
        "candidate_image_index_digest",
        "platform_manifest_and_config_digests",
        "runtime_and_build_lock_sha256",
        "wheelhouse_inventory_and_tree_sha256",
        "registry_provenance_and_resolver_receipt_sha256",
        "debian_snapshot_release_key_package_inventory_and_advisory_sha256",
        "system_real_base_installability_receipt_sha256",
        "system_bundle_index_manifest_config_and_tree_sha256",
        "dashboard_source_pnpm_lock_store_build_sbom_advisory_and_bundle_tree_sha256",
        "dashboard_bundle_index_manifest_and_config_sha256",
        "cadence_probe_sha256",
        "sbom_sha256",
        "candidate_scanner_verdict_and_report_sha256",
        "advisory_receipt_sha256",
    ],
}
EXPECTED_SYSTEM_REQUESTED = ["ca-certificates", "libpq5", "tini"]
DASHBOARD_WORKSPACE = "/tmp/z4j-dashboard-workspace"  # noqa: S108 - isolated container
DASHBOARD_HOME = "/tmp/z4j-dashboard-home"  # noqa: S108 - isolated container
DASHBOARD_PNPM = DASHBOARD_WORKSPACE + "/.tools/pnpm.cjs"
DASHBOARD_INSTALL_STORE = "/tmp/z4j-dashboard-install-store"  # noqa: S108
EXPECTED_DEBIAN_SOURCES = [
    {
        "name": "debian",
        "archive": "https://snapshot.debian.org/archive/debian/",
        "suite": "trixie",
        "release_suite": "stable",
        "components": ["main"],
        "archive_key_fingerprints": [
            "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        ],
    },
    {
        "name": "debian-security",
        "archive": "https://snapshot.debian.org/archive/debian-security/",
        "suite": "trixie-security",
        "release_suite": "stable-security",
        "components": ["main"],
        "archive_key_fingerprints": ["5E04A1E3223A19A20706E20F9904613D4CCE68C6"],
    },
    {
        "name": "debian-updates",
        "archive": "https://snapshot.debian.org/archive/debian/",
        "suite": "trixie-updates",
        "release_suite": "stable-updates",
        "components": ["main"],
        "archive_key_fingerprints": [
            "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        ],
    },
]
EXPECTED_DASHBOARD_INCLUSIONS = [
    ".npmrc",
    "components.json",
    "index.html",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "public",
    "scripts",
    "src",
    "tsconfig.json",
    "vite.config.ts",
]
EXPECTED_DASHBOARD_EXCLUSIONS = [
    ".DS_Store",
    "__pycache__",
    "*.map",
    "*.pyc",
    "*.pyo",
]
EXPECTED_DASHBOARD_EXECUTABLES: list[str] = []
EXPECTED_NODE_IMAGE = (
    "docker.io/library/node:24.19.0-bookworm-slim@"
    "sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03"
)
EXPECTED_CADENCE = {
    "astral": "3.2",
    "croniter": "6.2.2",
    "python-dateutil": "2.9.0.post0",
    "six": "1.17.0",
    "tzdata": "2026.3",
}
LOCAL_DISTRIBUTIONS = {"z4j", "z4j-core", "z4j-scheduler"}
EXPECTED_MATERIAL_AUTHORITY_POLICIES = {
    "dashboard": {
        "contract": {
            "path": "docker/production/dashboard-authority-policy.json",
            "sha256": "5aba03a9b1d8ffa0f8cb7aa0565a4ddbfdafba27413fc673a89278aab062e4ff",
            "size": 8929,
        },
        "location": "detached-pre-freeze-finalization",
        "required": True,
        "schema": "z4j.production-dashboard-authority.v1",
    },
    "system": {
        "contract": {
            "path": "docker/production/system-authority-policy.json",
            "sha256": "0d70332f66ccc7f4583fbff263609a6572d34489cbbb60ad70eb949c3500f3dd",
            "size": 10854,
        },
        "location": "detached-pre-freeze-finalization",
        "required": True,
        "schema": "z4j.production-system-authority.v2",
    },
}
EXPECTED_MATERIAL_AUTHORITY_REPOSITORIES = {
    "dashboard": "docker.io/z4jdev/z4j-production-dashboard",
    "system": "docker.io/z4jdev/z4j-production-system",
}
DASHBOARD_BUILD_CONTEXT = b"z4j-dashboard-production-v1\n"
DASHBOARD_BUILD_MARKERS = {
    ".build-context",
    ".build-inputs.sha256",
    ".build-output.sha256",
}


class ContractError(RuntimeError):
    """The production closure is absent, ambiguous, stale, or mutable."""


def _die(message: str) -> NoReturn:
    raise ContractError(message)


def _load_authority_common() -> Any:
    """Load the shared bounded Cosign supervisor from the verified sibling source."""

    module_name = "z4j_production_authority_common"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name("production_authority_common.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        _die("cannot load the production authority common helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _die(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_bytes(path: Path, *, maximum: int, context: str) -> bytes:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        _die(f"{context} is not a regular non-symlink file")
    if before.st_size > maximum:
        _die(f"{context} exceeds its bounded size")
    payload = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != before.st_size:
        _die(f"{context} changed while it was read")
    return payload


def _load_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read_bytes(path, maximum=maximum, context=str(path))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path} is not canonical UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        _die(f"{path} must contain one JSON object")
    return value, raw


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verify_dashboard_build_markers(directory: Path, *, source_projection_sha256: str) -> None:
    marker_bytes = {
        name: _read_bytes(
            directory / name,
            maximum=128,
            context=f"dashboard {name} marker",
        )
        for name in DASHBOARD_BUILD_MARKERS
    }
    if marker_bytes[".build-context"] != DASHBOARD_BUILD_CONTEXT:
        _die("dashboard production build-context marker differs")
    for name in (".build-inputs.sha256", ".build-output.sha256"):
        raw = marker_bytes[name]
        if len(raw) != 65 or raw[-1:] != b"\n" or re.fullmatch(rb"[0-9a-f]{64}", raw[:-1]) is None:
            _die(f"dashboard {name} marker is not lowercase SHA-256 plus newline")
    if marker_bytes[".build-inputs.sha256"] != (
        _require_hex(source_projection_sha256, "dashboard source projection") + "\n"
    ).encode("ascii"):
        _die("dashboard build-inputs marker differs from the source projection")
    digest_input = bytearray()
    for entry in sorted(
        directory.rglob("*"),
        key=lambda item: item.relative_to(directory).as_posix().encode("utf-8"),
    ):
        relative = entry.relative_to(directory).as_posix()
        if any(character in relative for character in ("\\", "\n", "\r")):
            _die(f"dashboard output has an unhashable release path {relative!r}")
        if entry.is_symlink() or not (entry.is_dir() or entry.is_file()):
            _die(f"dashboard output contains unsafe entry {relative}")
        if entry.is_file() and relative not in {
            ".build-inputs.sha256",
            ".build-output.sha256",
        }:
            payload = _read_bytes(entry, maximum=MAX_FILE_BYTES, context=relative)
            digest_input.extend(f"{_sha256(payload)}  {relative}\n".encode())
    if not digest_input:
        _die("dashboard output digest has no bundle files")
    expected = (_sha256(bytes(digest_input)) + "\n").encode("ascii")
    if marker_bytes[".build-output.sha256"] != expected:
        _die("dashboard build-output marker differs from the exact output tree")


def _require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        _die(
            f"{context} keys differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _die(f"{context} must be one JSON object")
    return value


def _require_hex(value: Any, context: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        _die(f"{context} must be 64 lowercase SHA-256 hex digits")
    return value


def _require_digest(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or OCI_DIGEST.fullmatch(value) is None:
        _die(f"{context} must be a sha256 OCI digest")
    if not allow_zero and value == ZERO_DIGEST:
        _die(f"{context} must not use the unfinalized zero digest")
    return value


def _require_size(value: Any, context: str, *, maximum: int = MAX_FILE_BYTES) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        _die(f"{context} must be a positive bounded byte size")
    return value


def _require_nonnegative_size(value: Any, context: str, *, maximum: int = MAX_FILE_BYTES) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        _die(f"{context} must be a bounded nonnegative byte size")
    return value


def _require_count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_FILES:
        _die(f"{context} must be a bounded nonnegative count")
    return value


def _immutable_image(value: Any, context: str) -> str:
    if not isinstance(value, str) or IMMUTABLE_IMAGE.fullmatch(value) is None:
        _die(f"{context} must be an explicit docker.io name bound by @sha256")
    if ":latest@" in value or value.endswith("@" + ZERO_DIGEST):
        _die(f"{context} must not use latest or the unfinalized digest")
    return value


def _is_excluded(path: PurePosixPath) -> bool:
    return any(
        part in {"__pycache__", ".DS_Store"} or part.endswith((".pyc", ".pyo"))
        for part in path.parts
    )


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _manifest_platform(manifest: dict[str, Any], platform: str) -> dict[str, Any]:
    if platform not in PLATFORMS:
        _die(f"unsupported production platform {platform!r}")
    platforms = manifest["wheelhouse"]["platforms"]
    value = platforms.get(platform)
    if not isinstance(value, dict):
        _die(f"manifest has no complete {platform} authority")
    return value


def _validate_source_tag_authority_policy(manifest: dict[str, Any]) -> None:
    policy = _require_object(
        manifest.get("source_tag_authority_policy"), "source tag authority policy"
    )
    _require_exact_keys(
        policy,
        {"required", "schema", "location"},
        "source tag authority policy",
    )
    if not isinstance(policy["required"], bool) or policy != {
        "required": True,
        "schema": "z4j.source-tag-authority.v1",
        "location": "detached-production-finalization",
    }:
        _die("source tag authority policy differs")


def _validate_material_authority_selection(manifest: dict[str, Any], material: str) -> None:
    """Validate one exact tracked poison-or-realized material authority root."""

    expected_policy = EXPECTED_MATERIAL_AUTHORITY_POLICIES[material]
    policy = _require_object(
        manifest.get(f"{material}_authority_policy"),
        f"{material} authority policy",
    )
    _require_exact_keys(
        policy,
        {"contract", "location", "required", "schema"},
        f"{material} authority policy",
    )
    contract = _require_object(policy["contract"], f"{material} authority policy contract")
    _require_exact_keys(
        contract,
        {"path", "sha256", "size"},
        f"{material} authority policy contract",
    )
    if policy != expected_policy:
        _die(f"{material} authority policy differs from its literal poison carrier")

    selection = _require_object(
        manifest.get(f"{material}_authority"),
        f"{material} authority selection",
    )
    _require_exact_keys(
        selection,
        {"artifact", "bundle", "receipt", "repository"},
        f"{material} authority selection",
    )
    artifact = _require_object(selection["artifact"], f"{material} authority artifact")
    bundle = _require_object(selection["bundle"], f"{material} authority bundle")
    receipt = _require_object(selection["receipt"], f"{material} authority receipt")
    _require_exact_keys(
        artifact,
        {"digest", "size", "tag"},
        f"{material} authority artifact",
    )
    _require_exact_keys(bundle, {"sha256", "size"}, f"{material} authority bundle")
    _require_exact_keys(receipt, {"sha256", "size"}, f"{material} authority receipt")
    if selection["repository"] != EXPECTED_MATERIAL_AUTHORITY_REPOSITORIES[material]:
        _die(f"{material} authority repository differs")

    realized = (
        artifact["digest"],
        artifact["size"],
        artifact["tag"],
        bundle["sha256"],
        bundle["size"],
        receipt["sha256"],
        receipt["size"],
    )
    if manifest["state"] == "unfinalized":
        if any(value is not None for value in realized):
            _die(f"unfinalized manifest selects a realized {material} authority")
        return
    if any(value is None for value in realized):
        _die(f"finalized manifest has an incomplete {material} authority")
    artifact_digest = _require_digest(artifact["digest"], f"{material} authority artifact")
    _require_size(artifact["size"], f"{material} authority artifact size")
    expected_tag = f"1.9.0-{material}-authority-" + artifact_digest.removeprefix("sha256:")
    if artifact["tag"] != expected_tag:
        _die(f"{material} authority tag is not content-derived")
    _require_hex(bundle["sha256"], f"{material} authority bundle")
    _require_size(bundle["size"], f"{material} authority bundle size")
    _require_hex(receipt["sha256"], f"{material} authority receipt")
    _require_size(receipt["size"], f"{material} authority receipt size")


def _validate_manifest_shape(manifest: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    finalization = _require_object(manifest.get("finalization"), "finalization")
    _require_exact_keys(
        finalization,
        {"not_before_utc", "allowed_post_freeze_paths", "receipt_policy"},
        "finalization",
    )
    _require_exact_keys(
        _require_object(finalization.get("receipt_policy"), "receipt policy"),
        {"kind", "required", "binds"},
        "receipt policy",
    )
    source = _require_object(manifest.get("source_authority"), "source authority")
    _require_exact_keys(
        source,
        {
            "base_commit",
            "integrated_prelock_tree",
            "integrated_prelock_patch_sha256",
            "integrated_prelock_patch_size",
            "production_source_freeze",
            "projection",
        },
        "source authority",
    )
    _require_exact_keys(
        _require_object(source.get("production_source_freeze"), "production source freeze"),
        {"commit", "tree"},
        "production source freeze",
    )
    _require_exact_keys(
        _require_object(source.get("projection"), "source projection"),
        {
            "algorithm",
            "record_framing",
            "executables",
            "inclusions",
            "exclusions",
            "sha256",
            "entries",
            "bytes",
        },
        "source projection",
    )
    resolver = _require_object(manifest.get("resolver"), "resolver")
    _require_exact_keys(
        resolver,
        {"name", "version", "binary_relative_path", "required_sync_flags"},
        "resolver",
    )
    signature_verifier = _require_object(manifest.get("signature_verifier"), "signature verifier")
    _require_exact_keys(
        signature_verifier,
        {"name", "version", "runtime_path", "release_response", "platforms"},
        "signature verifier",
    )
    _require_exact_keys(
        _require_object(
            signature_verifier.get("release_response"),
            "signature verifier release response",
        ),
        {"path", "sha256", "size"},
        "signature verifier release response",
    )
    signature_platforms = _require_object(
        signature_verifier.get("platforms"), "signature verifier platforms"
    )
    if set(signature_platforms) != set(PLATFORMS):
        _die("signature verifier platform matrix differs")
    for platform in PLATFORMS:
        _require_exact_keys(
            _require_object(signature_platforms[platform], f"{platform} signature verifier"),
            {
                "filename",
                "url",
                "sha256",
                "size",
                "version_output_sha256",
                "version_output_size",
            },
            f"{platform} signature verifier",
        )
    install = _require_object(manifest.get("install"), "install")
    _require_exact_keys(
        install,
        {
            "python_requires",
            "source_date_epoch",
            "roots",
            "local_wheel_install",
            "build_isolation",
            "cadence_dependencies",
        },
        "install",
    )
    wheelhouse = _require_object(manifest.get("wheelhouse"), "wheelhouse")
    _require_exact_keys(
        wheelhouse,
        {
            "image",
            "index",
            "payload_root",
            "inventory_format",
            "tree_format",
            "platforms",
        },
        "wheelhouse",
    )
    _require_exact_keys(
        _require_object(wheelhouse.get("index"), "wheelhouse index"),
        {"digest", "size"},
        "wheelhouse index",
    )
    platforms = _require_object(wheelhouse.get("platforms"), "wheelhouse platforms")
    if set(platforms) != set(PLATFORMS):
        _die("wheelhouse platform matrix differs")
    arch_by_platform = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
    for platform in PLATFORMS:
        info = _require_object(platforms.get(platform), f"{platform} wheelhouse authority")
        _require_exact_keys(
            info,
            {
                "manifest_digest",
                "manifest_size",
                "config_digest",
                "config_size",
                "runtime_lock",
                "build_lock",
                "inventory",
                "tree_sha256",
                "tree_bytes",
                "uv",
                "local_wheels",
                "cadence_probe",
                "sbom",
                "provenance_receipt",
                "resolver_receipt",
                "advisory_receipt",
            },
            f"{platform} wheelhouse authority",
        )
        arch = arch_by_platform[platform]
        for group, expected_path in (
            ("runtime_lock", f"locks/runtime-linux-{arch}.txt"),
            ("build_lock", f"locks/build-linux-{arch}.txt"),
        ):
            lock = _require_object(info.get(group), f"{platform} {group}")
            _require_exact_keys(lock, {"path", "sha256", "size"}, f"{platform} {group}")
            if lock.get("path") != expected_path:
                _die(f"{platform} {group} path differs")
        inventory = _require_object(info.get("inventory"), f"{platform} inventory")
        _require_exact_keys(
            inventory, {"path", "sha256", "size", "entries"}, f"{platform} inventory"
        )
        for group, keys in (
            ("uv", {"sha256", "size", "version_output", "probe_sha256"}),
            (
                "cadence_probe",
                {"sha256", "fingerprint", "behavior_vector_sha256", "tzdata_tree_sha256"},
            ),
            ("sbom", {"sha256", "size"}),
            ("provenance_receipt", {"sha256", "size"}),
            ("resolver_receipt", {"sha256", "size"}),
            ("advisory_receipt", {"sha256", "size", "verdict"}),
        ):
            value = _require_object(info.get(group), f"{platform} {group}")
            _require_exact_keys(value, keys, f"{platform} {group}")

    system = _require_object(manifest.get("system_packages"), "system package authority")
    _require_exact_keys(
        system,
        {
            "state",
            "format",
            "image",
            "index",
            "payload_root",
            "requested",
            "snapshot",
            "platforms",
        },
        "system package authority",
    )
    _require_exact_keys(
        _require_object(system["index"], "system index"), {"digest", "size"}, "system index"
    )
    _require_exact_keys(
        _require_object(system["snapshot"], "Debian snapshot"),
        {"selection_utc", "sources"},
        "Debian snapshot",
    )
    snapshot_sources = system["snapshot"]["sources"]
    if not isinstance(snapshot_sources, list) or len(snapshot_sources) != len(
        EXPECTED_DEBIAN_SOURCES
    ):
        _die("Debian snapshot source matrix differs")
    source_keys = {
        "name",
        "archive",
        "suite",
        "release_suite",
        "components",
        "timestamp_utc",
        "inrelease_sha256",
        "inrelease_size",
        "release_sha256",
        "release_size",
        "archive_keyring_sha256",
        "archive_keyring_size",
        "archive_key_fingerprints",
    }
    for source in snapshot_sources:
        _require_exact_keys(
            _require_object(source, "Debian snapshot source"),
            source_keys,
            "Debian snapshot source",
        )
    system_platforms = _require_object(system["platforms"], "system platforms")
    if set(system_platforms) != set(PLATFORMS):
        _die("system bundle platform matrix differs")
    system_keys = {
        "manifest_digest",
        "manifest_size",
        "config_digest",
        "config_size",
        "package_lock",
        "inventory_sha256",
        "inventory_size",
        "inventory_entries",
        "tree_sha256",
        "tree_bytes",
        "resolution_receipt_sha256",
        "resolution_receipt_size",
        "installability_receipt_sha256",
        "installability_receipt_size",
        "advisory_receipt_sha256",
        "advisory_receipt_size",
        "advisory_verdict",
    }
    for platform in PLATFORMS:
        info = _require_object(system_platforms[platform], f"{platform} system authority")
        _require_exact_keys(info, system_keys, f"{platform} system authority")
        _require_exact_keys(
            _require_object(info["package_lock"], f"{platform} system package lock"),
            {"path", "sha256", "size", "entries"},
            f"{platform} system package lock",
        )

    dashboard = _require_object(manifest.get("dashboard"), "dashboard authority")
    _require_exact_keys(
        dashboard,
        {
            "state",
            "format",
            "image",
            "index",
            "payload_root",
            "source_projection",
            "node",
            "pnpm",
            "platforms",
        },
        "dashboard authority",
    )
    _require_exact_keys(
        _require_object(dashboard["index"], "dashboard index"),
        {"digest", "size"},
        "dashboard index",
    )
    _require_exact_keys(
        _require_object(dashboard["source_projection"], "dashboard source projection"),
        {
            "algorithm",
            "record_framing",
            "executables",
            "inclusions",
            "exclusions",
            "sha256",
            "entries",
            "bytes",
        },
        "dashboard source projection",
    )
    _require_exact_keys(
        _require_object(dashboard["node"], "dashboard Node authority"),
        {"version", "image", "index_digest", "index_size", "platforms"},
        "dashboard Node authority",
    )
    node_platforms = _require_object(dashboard["node"]["platforms"], "dashboard Node platforms")
    if set(node_platforms) != set(PLATFORMS):
        _die("dashboard Node platform matrix differs")
    for platform in PLATFORMS:
        _require_exact_keys(
            _require_object(node_platforms[platform], f"{platform} dashboard Node authority"),
            {"manifest_digest", "manifest_size", "config_digest", "config_size"},
            f"{platform} dashboard Node authority",
        )
    _require_exact_keys(
        _require_object(dashboard["pnpm"], "dashboard pnpm authority"),
        {
            "version",
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "release_receipt_sha256",
            "release_receipt_size",
        },
        "dashboard pnpm authority",
    )
    dashboard_platforms = _require_object(dashboard["platforms"], "dashboard platforms")
    if set(dashboard_platforms) != set(PLATFORMS):
        _die("dashboard bundle platform matrix differs")
    dashboard_keys = {
        "manifest_digest",
        "manifest_size",
        "config_digest",
        "config_size",
        "inventory_sha256",
        "inventory_size",
        "inventory_entries",
        "tree_sha256",
        "tree_bytes",
        "pnpm_lock_sha256",
        "store_inventory_sha256",
        "store_inventory_size",
        "build_receipt_sha256",
        "build_receipt_size",
        "sbom_sha256",
        "sbom_size",
        "advisory_receipt_sha256",
        "advisory_receipt_size",
        "advisory_verdict",
        "bundle_tree_sha256",
        "bundle_tree_bytes",
    }
    for platform in PLATFORMS:
        _require_exact_keys(
            _require_object(dashboard_platforms[platform], f"{platform} dashboard authority"),
            dashboard_keys,
            f"{platform} dashboard authority",
        )


def _validate_unfinalized(manifest: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    source = manifest["source_authority"]
    if source["production_source_freeze"] != {"commit": None, "tree": None}:
        _die("unfinalized manifest must not claim a production source freeze")
    projection = source["projection"]
    if any(projection[key] is not None for key in ("sha256", "entries", "bytes")):
        _die("unfinalized manifest must not claim a source projection seal")
    signature_verifier = manifest["signature_verifier"]
    release_response = signature_verifier["release_response"]
    # Reviewed signature-tool material is source-independent and remains sealed
    # while release/source/registry authorities are deliberately unfinalized.
    _require_hex(release_response["sha256"], "Cosign release response")
    _require_size(release_response["size"], "Cosign release response size")
    for platform in PLATFORMS:
        tool = signature_verifier["platforms"][platform]
        _require_hex(tool["sha256"], f"{platform} Cosign binary")
        _require_size(tool["size"], f"{platform} Cosign binary size")
        _require_hex(tool["version_output_sha256"], f"{platform} Cosign version output")
        _require_size(tool["version_output_size"], f"{platform} Cosign version output size")
    wheelhouse = manifest["wheelhouse"]
    if wheelhouse["image"] is not None or wheelhouse["index"] != {
        "digest": None,
        "size": None,
    }:
        _die("unfinalized manifest must not claim a wheelhouse OCI authority")
    for platform in PLATFORMS:
        info = _manifest_platform(manifest, platform)
        for key in (
            "manifest_digest",
            "manifest_size",
            "config_digest",
            "config_size",
            "tree_sha256",
            "tree_bytes",
        ):
            if info[key] is not None:
                _die(f"unfinalized {platform} must leave {key} unset")
        for group in (
            "runtime_lock",
            "build_lock",
            "inventory",
            "uv",
            "cadence_probe",
            "sbom",
            "provenance_receipt",
            "resolver_receipt",
            "advisory_receipt",
        ):
            claimed = info[group]
            if any(value is not None for key, value in claimed.items() if key != "path"):
                _die(f"unfinalized {platform} must not claim {group} evidence")
        if info["local_wheels"] != []:
            _die(f"unfinalized {platform} must not claim local wheel readbacks")

    system = manifest["system_packages"]
    if system["state"] != "unfinalized":
        _die("unfinalized container contract must keep system packages unfinalized")
    if system["image"] is not None or system["index"] != {"digest": None, "size": None}:
        _die("unfinalized system authority must not claim an OCI bundle")
    snapshot = system["snapshot"]
    if snapshot["selection_utc"] is not None:
        _die("unfinalized Debian snapshot must leave selection_utc unset")
    for source, expected_source in zip(snapshot["sources"], EXPECTED_DEBIAN_SOURCES, strict=True):
        for key, expected in expected_source.items():
            if source[key] != expected:
                _die(f"Debian source {expected_source['name']} {key} authority differs")
        for key in (
            "timestamp_utc",
            "inrelease_sha256",
            "inrelease_size",
            "release_sha256",
            "release_size",
            "archive_keyring_sha256",
            "archive_keyring_size",
        ):
            if source[key] is not None:
                _die(f"unfinalized Debian source {source['name']} must leave {key} unset")
    for platform in PLATFORMS:
        info = system["platforms"][platform]
        for key, value in info.items():
            if key == "package_lock":
                if any(item is not None for name, item in value.items() if name != "path"):
                    _die(f"unfinalized {platform} system lock must be unset")
            elif value is not None:
                _die(f"unfinalized {platform} system authority must leave {key} unset")

    dashboard = manifest["dashboard"]
    if dashboard["state"] != "unfinalized":
        _die("unfinalized container contract must keep dashboard unfinalized")
    if dashboard["image"] is not None or dashboard["index"] != {
        "digest": None,
        "size": None,
    }:
        _die("unfinalized dashboard authority must not claim an OCI bundle")
    if any(
        dashboard["source_projection"][key] is not None for key in ("sha256", "entries", "bytes")
    ):
        _die("unfinalized dashboard must not claim a source projection seal")
    if dashboard["node"]["index_size"] is not None:
        _die("unfinalized dashboard must not claim a Node index size")
    for platform in PLATFORMS:
        if any(value is not None for value in dashboard["node"]["platforms"][platform].values()):
            _die(f"unfinalized {platform} dashboard Node authority must be unset")
    for key, value in dashboard["pnpm"].items():
        if key != "version" and value is not None:
            _die(f"unfinalized dashboard pnpm authority must leave {key} unset")
    for platform in PLATFORMS:
        for key, value in dashboard["platforms"][platform].items():
            if value is not None:
                _die(f"unfinalized {platform} dashboard authority must leave {key} unset")


def _validate_finalized(manifest: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    freeze = manifest["source_authority"]["production_source_freeze"]
    if not isinstance(freeze, dict) or set(freeze) != {"commit", "tree"}:
        _die("production source freeze shape differs")
    for key in ("commit", "tree"):
        if not isinstance(freeze[key], str) or GIT_OBJECT.fullmatch(freeze[key]) is None:
            _die(f"production source freeze {key} is not an exact Git object")
    if freeze["commit"] == freeze["tree"]:
        _die("source commit and tree identities must be distinct")
    projection = manifest["source_authority"]["projection"]
    _require_hex(projection["sha256"], "source projection sha256")
    _require_count(projection["entries"], "source projection entries")
    _require_size(projection["bytes"], "source projection bytes", maximum=8 * MAX_FILE_BYTES)

    signature_verifier = manifest["signature_verifier"]
    release_response = signature_verifier["release_response"]
    _require_hex(release_response["sha256"], "Cosign release response")
    _require_size(release_response["size"], "Cosign release response size")
    for platform in PLATFORMS:
        tool = signature_verifier["platforms"][platform]
        _require_hex(tool["sha256"], f"{platform} Cosign binary")
        _require_size(tool["size"], f"{platform} Cosign binary size")
        _require_hex(tool["version_output_sha256"], f"{platform} Cosign version output")
        _require_size(tool["version_output_size"], f"{platform} Cosign version output size")

    wheelhouse = manifest["wheelhouse"]
    image = _immutable_image(wheelhouse["image"], "wheelhouse image")
    index_digest = _require_digest(wheelhouse["index"]["digest"], "wheelhouse index")
    _require_size(wheelhouse["index"]["size"], "wheelhouse index size", maximum=1024 * 1024)
    if not image.endswith("@" + index_digest):
        _die("wheelhouse image reference and index digest differ")

    expected_local = LOCAL_DISTRIBUTIONS
    for platform in PLATFORMS:
        info = _manifest_platform(manifest, platform)
        _require_digest(info["manifest_digest"], f"{platform} wheelhouse manifest")
        _require_size(info["manifest_size"], f"{platform} wheelhouse manifest size")
        _require_digest(info["config_digest"], f"{platform} wheelhouse config")
        _require_size(info["config_size"], f"{platform} wheelhouse config size")
        for lock_name in ("runtime_lock", "build_lock"):
            lock = info[lock_name]
            if not isinstance(lock.get("path"), str):
                _die(f"{platform} {lock_name} path is absent")
            _require_hex(lock.get("sha256"), f"{platform} {lock_name}")
            _require_size(lock.get("size"), f"{platform} {lock_name} size", maximum=MAX_LOCK_BYTES)
        inventory = info["inventory"]
        if inventory.get("path") != "inventory.json":
            _die(f"{platform} wheelhouse inventory path differs")
        _require_hex(inventory.get("sha256"), f"{platform} inventory")
        _require_size(inventory.get("size"), f"{platform} inventory size")
        _require_count(inventory.get("entries"), f"{platform} inventory entries")
        _require_hex(info["tree_sha256"], f"{platform} wheelhouse tree")
        _require_size(
            info["tree_bytes"], f"{platform} wheelhouse tree bytes", maximum=8 * MAX_FILE_BYTES
        )
        uv = info["uv"]
        _require_hex(uv.get("sha256"), f"{platform} uv")
        _require_size(uv.get("size"), f"{platform} uv size")
        if not isinstance(uv.get("version_output"), str) or not uv["version_output"].startswith(
            "uv 0.12.5"
        ):
            _die(f"{platform} uv version output is not uv 0.12.5")
        _require_hex(uv.get("probe_sha256"), f"{platform} uv probe")
        wheels = info["local_wheels"]
        if not isinstance(wheels, list):
            _die(f"{platform} local wheel readbacks must be a list")
        found: set[str] = set()
        for wheel in wheels:
            if not isinstance(wheel, dict):
                _die(f"{platform} local wheel readback is malformed")
            _require_exact_keys(
                wheel,
                {
                    "distribution",
                    "version",
                    "filename",
                    "sha256",
                    "size",
                    "source_projection_sha256",
                },
                f"{platform} local wheel",
            )
            name = _normalized_name(str(wheel["distribution"]))
            if name in found:
                _die(f"{platform} has duplicate local wheel {name}")
            found.add(name)
            if wheel["version"] != RELEASE:
                _die(f"{platform} local wheel {name} version differs")
            if not isinstance(wheel["filename"], str) or not wheel["filename"].endswith(".whl"):
                _die(f"{platform} local wheel {name} filename differs")
            _require_hex(wheel["sha256"], f"{platform} local wheel {name}")
            _require_size(wheel["size"], f"{platform} local wheel {name} size")
            wheel_projection = _require_hex(
                wheel["source_projection_sha256"],
                f"{platform} local wheel {name} source projection",
            )
            if wheel_projection != projection["sha256"]:
                _die(f"{platform} local wheel {name} source projection differs")
        if found != expected_local:
            _die(
                f"{platform} local wheel closure differs; "
                f"missing={sorted(expected_local - found)}, extra={sorted(found - expected_local)}"
            )
        probe = info["cadence_probe"]
        for key in ("sha256", "fingerprint", "behavior_vector_sha256", "tzdata_tree_sha256"):
            _require_hex(probe.get(key), f"{platform} cadence {key}")
        sbom = info["sbom"]
        _require_hex(sbom.get("sha256"), f"{platform} SBOM")
        _require_size(sbom.get("size"), f"{platform} SBOM size")
        for receipt_name in ("provenance_receipt", "resolver_receipt"):
            receipt = info[receipt_name]
            _require_hex(receipt.get("sha256"), f"{platform} {receipt_name}")
            _require_size(receipt.get("size"), f"{platform} {receipt_name} size")
        advisory = info["advisory_receipt"]
        _require_hex(advisory.get("sha256"), f"{platform} advisory receipt")
        _require_size(advisory.get("size"), f"{platform} advisory receipt size")
        if advisory.get("verdict") != "pass":
            _die(f"{platform} advisory receipt does not have a pass verdict")

    system = manifest["system_packages"]
    if system["state"] != "finalized":
        _die("finalized container contract requires finalized system packages")
    system_image = _immutable_image(system["image"], "system bundle image")
    system_index = _require_digest(system["index"]["digest"], "system bundle index")
    _require_size(system["index"]["size"], "system bundle index size", maximum=1024 * 1024)
    if not system_image.endswith("@" + system_index):
        _die("system bundle image and index digest differ")
    snapshot = system["snapshot"]
    cutoff_time = _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff")
    selection_time = _receipt_time(snapshot["selection_utc"], "Debian selection timestamp")
    if selection_time < cutoff_time or selection_time > dt.datetime.now(dt.UTC) + dt.timedelta(
        minutes=5
    ):
        _die("Debian selection must occur after the cutoff and must not be future-dated")
    for source, expected_source in zip(snapshot["sources"], EXPECTED_DEBIAN_SOURCES, strict=True):
        for key, expected in expected_source.items():
            if source[key] != expected:
                _die(f"Debian source {expected_source['name']} {key} authority differs")
        source_time = _receipt_time(
            source["timestamp_utc"], f"Debian {source['name']} snapshot timestamp"
        )
        if source_time < cutoff_time or source_time > selection_time:
            _die(
                f"Debian {source['name']} snapshot must be selected between the "
                "release cutoff and the recorded selection"
            )
        for key in ("inrelease_sha256", "release_sha256", "archive_keyring_sha256"):
            _require_hex(source[key], f"Debian {source['name']} {key}")
        for key in ("inrelease_size", "release_size", "archive_keyring_size"):
            _require_size(source[key], f"Debian {source['name']} {key}")
    for platform in PLATFORMS:
        info = system["platforms"][platform]
        _require_digest(info["manifest_digest"], f"{platform} system manifest")
        _require_size(info["manifest_size"], f"{platform} system manifest size")
        _require_digest(info["config_digest"], f"{platform} system config")
        _require_size(info["config_size"], f"{platform} system config size")
        lock = info["package_lock"]
        _require_hex(lock["sha256"], f"{platform} system package lock")
        _require_size(lock["size"], f"{platform} system package lock size", maximum=MAX_LOCK_BYTES)
        if _require_count(lock["entries"], f"{platform} system package count") == 0:
            _die(f"{platform} system package closure is empty")
        for key in (
            "inventory_sha256",
            "tree_sha256",
            "resolution_receipt_sha256",
            "installability_receipt_sha256",
            "advisory_receipt_sha256",
        ):
            _require_hex(info[key], f"{platform} system {key}")
        for key in (
            "inventory_size",
            "tree_bytes",
            "resolution_receipt_size",
            "advisory_receipt_size",
        ):
            _require_size(info[key], f"{platform} system {key}", maximum=8 * MAX_FILE_BYTES)
        _require_size(
            info["installability_receipt_size"],
            f"{platform} system installability_receipt_size",
            maximum=MAX_JSON_BYTES,
        )
        _require_count(info["inventory_entries"], f"{platform} system inventory count")
        if info["advisory_verdict"] != "pass":
            _die(f"{platform} system package advisory verdict is not pass")

    dashboard = manifest["dashboard"]
    if dashboard["state"] != "finalized":
        _die("finalized container contract requires a finalized dashboard")
    dashboard_image = _immutable_image(dashboard["image"], "dashboard bundle image")
    dashboard_index = _require_digest(dashboard["index"]["digest"], "dashboard bundle index")
    _require_size(dashboard["index"]["size"], "dashboard bundle index size", maximum=1024 * 1024)
    if not dashboard_image.endswith("@" + dashboard_index):
        _die("dashboard bundle image and index digest differ")
    dashboard_projection = dashboard["source_projection"]
    _require_hex(dashboard_projection["sha256"], "dashboard source projection")
    _require_count(dashboard_projection["entries"], "dashboard source projection entries")
    _require_size(
        dashboard_projection["bytes"],
        "dashboard source projection bytes",
        maximum=8 * MAX_FILE_BYTES,
    )
    _require_size(dashboard["node"]["index_size"], "dashboard Node index size")
    for platform in PLATFORMS:
        node_info = dashboard["node"]["platforms"][platform]
        _require_digest(node_info["manifest_digest"], f"{platform} dashboard Node manifest")
        _require_size(node_info["manifest_size"], f"{platform} dashboard Node manifest size")
        _require_digest(node_info["config_digest"], f"{platform} dashboard Node config")
        _require_size(node_info["config_size"], f"{platform} dashboard Node config size")
    pnpm = dashboard["pnpm"]
    for key in ("archive_sha256", "binary_sha256", "release_receipt_sha256"):
        _require_hex(pnpm[key], f"dashboard pnpm {key}")
    for key in ("archive_size", "binary_size", "release_receipt_size"):
        _require_size(pnpm[key], f"dashboard pnpm {key}")
    common_bundle: tuple[str, int] | None = None
    common_lock: str | None = None
    for platform in PLATFORMS:
        info = dashboard["platforms"][platform]
        _require_digest(info["manifest_digest"], f"{platform} dashboard manifest")
        _require_size(info["manifest_size"], f"{platform} dashboard manifest size")
        _require_digest(info["config_digest"], f"{platform} dashboard config")
        _require_size(info["config_size"], f"{platform} dashboard config size")
        for key in (
            "inventory_sha256",
            "tree_sha256",
            "pnpm_lock_sha256",
            "store_inventory_sha256",
            "build_receipt_sha256",
            "sbom_sha256",
            "advisory_receipt_sha256",
            "bundle_tree_sha256",
        ):
            _require_hex(info[key], f"{platform} dashboard {key}")
        for key in (
            "inventory_size",
            "tree_bytes",
            "store_inventory_size",
            "build_receipt_size",
            "sbom_size",
            "advisory_receipt_size",
            "bundle_tree_bytes",
        ):
            _require_size(info[key], f"{platform} dashboard {key}", maximum=8 * MAX_FILE_BYTES)
        _require_count(info["inventory_entries"], f"{platform} dashboard inventory count")
        if info["advisory_verdict"] != "pass":
            _die(f"{platform} dashboard advisory verdict is not pass")
        bundle = (info["bundle_tree_sha256"], info["bundle_tree_bytes"])
        if common_bundle is None:
            common_bundle = bundle
            common_lock = info["pnpm_lock_sha256"]
        elif bundle != common_bundle or info["pnpm_lock_sha256"] != common_lock:
            _die("native dashboard builds do not share one byte-identical bundle and lock")


def validate_manifest(  # noqa: PLR0912, PLR0915
    manifest: dict[str, Any], *, require_finalized: bool = False
) -> None:
    _require_exact_keys(
        manifest,
        {
            "schema_version",
            "kind",
            "release",
            "state",
            "source_tag_authority_policy",
            "system_authority_policy",
            "system_authority",
            "dashboard_authority_policy",
            "dashboard_authority",
            "finalization",
            "source_authority",
            "python",
            "resolver",
            "signature_verifier",
            "install",
            "wheelhouse",
            "system_packages",
            "dashboard",
        },
        "manifest",
    )
    if manifest["schema_version"] != SCHEMA_VERSION or manifest["kind"] != KIND:
        _die("manifest kind/schema differs")
    if manifest["release"] != RELEASE:
        _die("manifest release differs")
    if manifest["state"] not in {"unfinalized", "finalized"}:
        _die("manifest state must be unfinalized or finalized")
    _validate_source_tag_authority_policy(manifest)
    _validate_material_authority_selection(manifest, "system")
    _validate_material_authority_selection(manifest, "dashboard")
    _validate_manifest_shape(manifest)
    finalization = manifest["finalization"]
    if finalization.get("not_before_utc") != FINALIZATION_CUTOFF:
        _die("production closure cutoff differs")
    if finalization.get("allowed_post_freeze_paths") != EXPECTED_ALLOWED_PATHS:
        _die("post-freeze finalization allowlist differs or is ambiguously ordered")
    if finalization.get("receipt_policy") != EXPECTED_RECEIPT_POLICY:
        _die("detached signed finalization receipt policy differs or is incomplete")

    source = manifest["source_authority"]
    if (
        source.get("base_commit") != EXPECTED_BASE["commit"]
        or source.get("integrated_prelock_tree") != EXPECTED_BASE["tree"]
        or source.get("integrated_prelock_patch_sha256") != EXPECTED_BASE["patch"]
        or source.get("integrated_prelock_patch_size") != EXPECTED_BASE["patch_size"]
    ):
        _die("frozen integrated-prelock authority differs")
    projection = source.get("projection")
    if not isinstance(projection, dict):
        _die("source projection contract is absent")
    if projection.get("algorithm") != "z4j-production-source-tree-v1":
        _die("source projection algorithm differs")
    if projection.get("record_framing") != PROJECTION_RECORD_FRAMING:
        _die("source projection record framing differs")
    if projection.get("executables") != EXPECTED_SOURCE_EXECUTABLES:
        _die("source projection executable allowlist differs")
    if projection.get("inclusions") != EXPECTED_INCLUSIONS:
        _die("source projection inclusions differ or are ambiguous")
    if projection.get("exclusions") != EXPECTED_EXCLUSIONS:
        _die("source projection exclusions differ or are ambiguous")
    if manifest["python"] != EXPECTED_PYTHON:
        _die("Python 3.14.7 image/index/platform authority differs")
    _immutable_image(manifest["python"]["image"], "Python image")

    resolver = manifest["resolver"]
    if resolver.get("name") != "uv" or resolver.get("version") != "0.12.5":
        _die("resolver must be exact uv 0.12.5")
    required_flags = resolver.get("required_sync_flags")
    if required_flags != [
        "--require-hashes",
        "--no-index",
        "--find-links",
        "--offline",
        "--no-cache",
        "--no-config",
    ]:
        _die("uv sync fail-closed flag contract differs")
    if resolver.get("binary_relative_path") != "bin/uv":
        _die("uv binary path differs")
    signature_verifier = manifest["signature_verifier"]
    if (
        signature_verifier.get("name") != "cosign"
        or signature_verifier.get("version") != "3.1.3"
        or signature_verifier.get("runtime_path") != "/usr/local/bin/cosign"
        or signature_verifier["release_response"].get("path") != "evidence/cosign-release.json"
    ):
        _die("signature verifier must be exact runtime Cosign 3.1.3")
    for platform, arch in (("linux/amd64", "amd64"), ("linux/arm64", "arm64")):
        tool = signature_verifier["platforms"][platform]
        expected_filename = f"cosign-linux-{arch}"
        if (
            tool.get("filename") != expected_filename
            or tool.get("url")
            != f"https://github.com/sigstore/cosign/releases/download/v3.1.3/{expected_filename}"
        ):
            _die(f"{platform} signature verifier origin differs")
    install = manifest["install"]
    if install.get("python_requires") != "==3.14.7":
        _die("production Python requirement must be exact 3.14.7")
    source_date_epoch = install.get("source_date_epoch")
    if manifest["state"] == "unfinalized":
        if source_date_epoch is not None:
            _die("unfinalized manifest must not claim SOURCE_DATE_EPOCH")
    elif (
        isinstance(source_date_epoch, bool)
        or not isinstance(source_date_epoch, int)
        or not 1_600_000_000 <= source_date_epoch <= 2_000_000_000
    ):
        _die("finalized manifest must bind one plausible SOURCE_DATE_EPOCH")
    if install.get("cadence_dependencies") != EXPECTED_CADENCE:
        _die("production cadence closure differs")
    if install.get("local_wheel_install") != "offline-no-deps":
        _die("local wheel install contract must remain offline/no-deps")
    if install.get("build_isolation") != "offline-hash-locked":
        _die("build isolation must remain offline and hash-locked")
    roots = install.get("roots")
    expected_roots = [
        {"distribution": "z4j-core", "version": RELEASE, "extras": []},
        {
            "distribution": "z4j",
            "version": RELEASE,
            "extras": ["postgres", "scheduler-grpc"],
        },
        {"distribution": "z4j-scheduler", "version": RELEASE, "extras": []},
    ]
    if roots != expected_roots:
        _die("production install roots/extras differ")
    wheelhouse = manifest["wheelhouse"]
    if wheelhouse.get("payload_root") != "/opt/z4j-production":
        _die("wheelhouse payload root differs")
    if wheelhouse.get("inventory_format") != "z4j-production-wheelhouse-inventory-v1":
        _die("wheelhouse inventory format differs")
    if wheelhouse.get("tree_format") != "z4j-production-wheelhouse-tree-v1":
        _die("wheelhouse tree format differs")

    system = manifest["system_packages"]
    if system["state"] != manifest["state"]:
        _die("system-package finalization state differs from the container contract")
    if system["format"] != "z4j-production-system-bundle-v2":
        _die("system bundle format differs")
    if system["payload_root"] != "/opt/z4j-production-system":
        _die("system bundle payload root differs")
    if system["requested"] != EXPECTED_SYSTEM_REQUESTED:
        _die("production apt roots differ")
    snapshot = system["snapshot"]
    for source, expected_source in zip(snapshot["sources"], EXPECTED_DEBIAN_SOURCES, strict=True):
        for key, expected in expected_source.items():
            if source[key] != expected:
                _die(f"Debian source {expected_source['name']} contract differs at {key}")
    for platform, arch in (("linux/amd64", "amd64"), ("linux/arm64", "arm64")):
        expected = f"locks/system-linux-{arch}.json"
        if system["platforms"][platform]["package_lock"]["path"] != expected:
            _die(f"{platform} system package lock path differs")

    dashboard = manifest["dashboard"]
    if dashboard["state"] != manifest["state"]:
        _die("dashboard finalization state differs from the container contract")
    if dashboard["format"] != "z4j-production-dashboard-bundle-v1":
        _die("dashboard bundle format differs")
    if dashboard["payload_root"] != "/opt/z4j-production-dashboard":
        _die("dashboard bundle payload root differs")
    dashboard_projection = dashboard["source_projection"]
    if dashboard_projection["algorithm"] != "z4j-dashboard-source-tree-v1":
        _die("dashboard source projection algorithm differs")
    if dashboard_projection["record_framing"] != PROJECTION_RECORD_FRAMING:
        _die("dashboard source projection framing differs")
    if dashboard_projection["executables"] != EXPECTED_DASHBOARD_EXECUTABLES:
        _die("dashboard source projection executable allowlist differs")
    if dashboard_projection["inclusions"] != EXPECTED_DASHBOARD_INCLUSIONS:
        _die("dashboard source projection inclusions differ")
    if dashboard_projection["exclusions"] != EXPECTED_DASHBOARD_EXCLUSIONS:
        _die("dashboard source projection exclusions differ")
    node = dashboard["node"]
    if (
        node["version"] != "24.19.0"
        or node["image"] != EXPECTED_NODE_IMAGE
        or node["index_digest"] != EXPECTED_NODE_IMAGE.rsplit("@", 1)[1]
    ):
        _die("dashboard Node authority differs")
    _immutable_image(node["image"], "dashboard Node image")
    if dashboard["pnpm"]["version"] != "11.22.0":
        _die("dashboard pnpm authority differs")

    if manifest["state"] == "unfinalized":
        _validate_unfinalized(manifest)
        if require_finalized:
            _die(
                "production closure is intentionally unfinalized until after "
                "2026-08-23T04:14:39.107Z"
            )
    else:
        cutoff = dt.datetime.fromisoformat(FINALIZATION_CUTOFF.replace("Z", "+00:00"))
        if dt.datetime.now(dt.UTC) < cutoff:
            _die("production closure cannot be finalized before its security-age cutoff")
        _validate_finalized(manifest)


def _detect_layout(repo: Path) -> tuple[str, dict[str, Path]]:
    monorepo = {
        "z4j": repo / "packages/z4j",
        "z4j-core": repo / "packages/z4j-core",
        "z4j-scheduler": repo / "packages/z4j-scheduler",
    }
    standalone = {
        "z4j": repo,
        "z4j-core": repo / "docker/vendor/z4j-core",
        "z4j-scheduler": repo / "docker/vendor/z4j-scheduler",
    }
    monorepo_ok = all((path / "pyproject.toml").is_file() for path in monorepo.values())
    standalone_ok = (
        (repo / "pyproject.toml").is_file()
        and all((path / "pyproject.toml").is_file() for path in standalone.values())
        and not (repo / "packages/z4j/pyproject.toml").is_file()
    )
    if monorepo_ok == standalone_ok:
        _die("production source layout is absent or ambiguous")
    return ("monorepo", monorepo) if monorepo_ok else ("standalone", standalone)


def _file_record(
    path: Path,
    logical: str,
    *,
    executable_paths: frozenset[str] | None = None,
) -> dict[str, Any]:
    before = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _die(f"source projection contains a nonregular entry: {logical}")
    if before.st_nlink != 1:
        _die(f"source projection contains a linked entry: {logical}")
    observed_mode = stat.S_IMODE(before.st_mode)
    record_mode = f"{observed_mode:04o}"
    if executable_paths is not None:
        if not observed_mode & stat.S_IRUSR:
            _die(f"source projection input is not owner-readable: {logical}")
        if observed_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            _die(f"source projection input has special mode bits: {logical}")
        if observed_mode & (stat.S_IWGRP | stat.S_IWOTH):
            _die(f"source projection input is group/world writable: {logical}")
        execute_bits = observed_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        expected_executable = logical in executable_paths
        if expected_executable and not observed_mode & stat.S_IXUSR:
            _die(f"source projection executable lacks owner execute permission: {logical}")
        if not expected_executable and execute_bits:
            _die(f"source projection input has unexpected execute permission: {logical}")
        record_mode = "0755" if expected_executable else "0644"
    payload = _read_bytes(path, maximum=MAX_FILE_BYTES, context=logical)
    return {
        "path": logical,
        "mode": record_mode,
        "size": len(payload),
        "sha256": _sha256(payload),
    }


def source_projection(repo: Path, manifest: dict[str, Any]) -> tuple[str, int, int, str]:
    layout, roots = _detect_layout(repo)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    projection = manifest["source_authority"]["projection"]
    inclusions = projection["inclusions"]
    executable_paths = frozenset(projection["executables"])
    for distribution in sorted(inclusions):
        root = roots[distribution]
        for relative_text in inclusions[distribution]:
            relative = PurePosixPath(relative_text)
            target = root.joinpath(*relative.parts)
            if not target.exists():
                _die(f"source projection input is absent: {distribution}/{relative}")
            candidates: list[Path]
            if target.is_dir() and not target.is_symlink():
                candidates = sorted(
                    (entry for entry in target.rglob("*") if entry.is_file() or entry.is_symlink()),
                    key=lambda entry: entry.relative_to(root).as_posix().encode("utf-8"),
                )
            else:
                candidates = [target]
            for candidate in candidates:
                rel = PurePosixPath(candidate.relative_to(root).as_posix())
                if _is_excluded(rel):
                    continue
                logical = f"{distribution}/{rel.as_posix()}"
                if logical in seen:
                    _die(f"source projection overlaps at {logical}")
                seen.add(logical)
                records.append(_file_record(candidate, logical, executable_paths=executable_paths))
                if len(records) > MAX_FILES:
                    _die("source projection exceeds its bounded entry count")
    records.sort(key=lambda record: str(record["path"]).encode("utf-8"))
    payload = {
        "format": projection["algorithm"],
        "files": records,
    }
    total = sum(int(record["size"]) for record in records)
    return _sha256(_canonical(payload)), len(records), total, layout


def dashboard_source_projection(repo: Path, manifest: dict[str, Any]) -> tuple[str, int, int, str]:
    layout, roots = _detect_layout(repo)
    dashboard_root = roots["z4j"] / "dashboard"
    if not dashboard_root.is_dir() or dashboard_root.is_symlink():
        _die("dashboard source root is absent or nonregular")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    projection = manifest["dashboard"]["source_projection"]
    inclusions = projection["inclusions"]
    executable_paths = frozenset(projection["executables"])
    for relative_text in inclusions:
        relative = PurePosixPath(relative_text)
        target = dashboard_root.joinpath(*relative.parts)
        if not target.exists():
            _die(f"dashboard source projection input is absent: {relative}")
        if target.is_dir() and not target.is_symlink():
            candidates = sorted(
                (entry for entry in target.rglob("*") if entry.is_file() or entry.is_symlink()),
                key=lambda entry: entry.relative_to(dashboard_root).as_posix().encode("utf-8"),
            )
        else:
            candidates = [target]
        for candidate in candidates:
            rel = PurePosixPath(candidate.relative_to(dashboard_root).as_posix())
            if _is_excluded(rel) or rel.name.endswith(".map"):
                continue
            logical = f"dashboard/{rel.as_posix()}"
            if logical in seen:
                _die(f"dashboard source projection overlaps at {logical}")
            seen.add(logical)
            records.append(_file_record(candidate, logical, executable_paths=executable_paths))
            if len(records) > MAX_FILES:
                _die("dashboard source projection exceeds its bounded entry count")
    records.sort(key=lambda record: str(record["path"]).encode("utf-8"))
    payload = {
        "format": projection["algorithm"],
        "files": records,
    }
    total = sum(int(record["size"]) for record in records)
    return _sha256(_canonical(payload)), len(records), total, layout


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *arguments],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if result.returncode != 0:
        _die(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _validate_post_freeze_delta(
    repo: Path,
    manifest: dict[str, Any],
    *,
    layout: str,
    release_commit: str,
    release_tree: str,
) -> None:
    if GIT_OBJECT.fullmatch(release_commit) is None or GIT_OBJECT.fullmatch(release_tree) is None:
        _die("release commit/tree inputs must be exact Git object IDs")
    if _git(repo, "rev-parse", "HEAD") != release_commit:
        _die("checked-out release commit differs from the receipt input")
    if _git(repo, "rev-parse", "HEAD^{tree}") != release_tree:
        _die("checked-out release tree differs from the receipt input")
    freeze = manifest["source_authority"]["production_source_freeze"]
    freeze_commit = freeze["commit"]
    freeze_tree = freeze["tree"]
    if _git(repo, "rev-parse", f"{freeze_commit}^{{tree}}") != freeze_tree:
        _die("production source freeze commit/tree pair differs")
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            freeze_commit,
            release_commit,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        _die("production source freeze is not an ancestor of the release commit")
    changed_raw = _git(repo, "diff", "--name-only", "--no-renames", freeze_commit, release_commit)
    changed = {line for line in changed_raw.splitlines() if line}
    prefix = "packages/z4j/" if layout == "monorepo" else ""
    allowed = {prefix + path for path in manifest["finalization"]["allowed_post_freeze_paths"]}
    unexpected = changed - allowed
    if unexpected:
        _die(f"non-allowlisted post-freeze source delta: {sorted(unexpected)}")


def _lock_records(payload: bytes, *, context: str) -> list[tuple[str, str, str]]:
    if len(payload) > MAX_LOCK_BYTES:
        _die(f"{context} exceeds its bounded size")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{context} is not UTF-8") from exc
    forbidden = ("--index-url", "--extra-index-url", "--find-links", "--trusted-host", "://", " @ ")
    if any(token in text for token in forbidden):
        _die(f"{context} contains a mutable index, URL, or embedded find-links source")
    logical: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-r", "--requirement", "-c", "--constraint", "-e")):
            _die(f"{context} contains an indirect or editable requirement")
        continuation = stripped.endswith("\\")
        piece = stripped[:-1].strip() if continuation else stripped
        current = f"{current} {piece}".strip()
        if not continuation:
            logical.append(current)
            current = ""
    if current:
        _die(f"{context} ends in an incomplete continuation")
    if not logical:
        _die(f"{context} is empty")
    records: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for requirement in logical:
        match = LOCK_ENTRY.fullmatch(requirement)
        if match is None:
            _die(f"{context} requirement is not one exact pin with one SHA-256: {requirement!r}")
        name = _normalized_name(match.group(1))
        version = match.group(2)
        if name in seen:
            _die(f"{context} contains duplicate distribution {name}")
        seen.add(name)
        records.append((name, version, match.group(3)))
    return records


def _wheel_members(path: Path) -> tuple[dict[str, bytes], str, str]:
    payload = _read_bytes(path, maximum=MAX_WHEEL_BYTES, context=str(path))
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise ContractError(f"{path} is not a valid wheel ZIP") from exc
    members: dict[str, bytes] = {}
    expanded_bytes = 0
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            _die(f"{path} has too many wheel members")
        for info in infos:
            pure = PurePosixPath(info.filename)
            if (
                info.filename in members
                or pure.as_posix() != info.filename
                or pure.is_absolute()
                or ".." in pure.parts
                or "\\" in info.filename
                or info.is_dir()
            ):
                _die(f"{path} has an unsafe or duplicate wheel member {info.filename!r}")
            unix_mode = info.external_attr >> 16
            file_type = stat.S_IFMT(unix_mode)
            if file_type not in {0, stat.S_IFREG}:
                _die(f"{path} has a nonregular wheel member {info.filename!r}")
            if info.file_size > MAX_FILE_BYTES:
                _die(f"{path} has an oversized wheel member")
            expanded_bytes += info.file_size
            if expanded_bytes > MAX_WHEEL_EXPANDED_BYTES:
                _die(f"{path} exceeds the aggregate expanded wheel limit")
            members[info.filename] = archive.read(info)
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    wheel_names = [name for name in members if name.endswith(".dist-info/WHEEL")]
    if len(metadata_names) != 1 or len(record_names) != 1 or len(wheel_names) != 1:
        _die(f"{path} does not have one METADATA/WHEEL/RECORD identity")
    metadata = email.parser.BytesParser().parsebytes(members[metadata_names[0]])
    names = metadata.get_all("Name") or []
    versions = metadata.get_all("Version") or []
    if metadata.defects or len(names) != 1 or len(versions) != 1:
        _die(f"{path} has ambiguous wheel metadata")
    dist_info = PurePosixPath(metadata_names[0]).parts[0]
    dist_component = _normalized_name(names[0]).replace("-", "_")
    version_component = re.sub(r"[^A-Za-z0-9.]+", "_", versions[0])
    expected_dist_info = f"{dist_component}-{version_component}.dist-info"
    if dist_info != expected_dist_info:
        _die(f"{path} dist-info identity differs from METADATA")
    if {
        metadata_names[0],
        wheel_names[0],
        record_names[0],
    } != {
        f"{expected_dist_info}/METADATA",
        f"{expected_dist_info}/WHEEL",
        f"{expected_dist_info}/RECORD",
    }:
        _die(f"{path} metadata files do not share the exact dist-info identity")
    _verify_record(path, members, record_names[0])
    return members, _normalized_name(names[0]), versions[0]


def _verify_record(path: Path, members: dict[str, bytes], record_name: str) -> None:
    try:
        rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ContractError(f"{path} has an invalid RECORD") from exc
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in recorded:
            _die(f"{path} has malformed or duplicate RECORD rows")
        name, digest, size_text = row
        recorded.add(name)
        if name not in members:
            _die(f"{path} RECORD references absent member {name!r}")
        if name == record_name:
            if digest or size_text:
                _die(f"{path} RECORD self-row must omit digest and size")
            continue
        payload = members[name]
        encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if digest != "sha256=" + encoded or size_text != str(len(payload)):
            _die(f"{path} RECORD digest/size differs for {name!r}")
    if recorded != set(members):
        _die(f"{path} RECORD inventory differs from wheel members")


def _wheel_tags(path: Path, members: dict[str, bytes], platform: str) -> None:
    wheel_names = [name for name in members if name.endswith(".dist-info/WHEEL")]
    if len(wheel_names) != 1:
        _die(f"{path} does not have one WHEEL identity")
    wheel_metadata = email.parser.BytesParser().parsebytes(members[wheel_names[0]])
    tags = wheel_metadata.get_all("Tag") or []
    if wheel_metadata.defects or not tags:
        _die(f"{path} has ambiguous or absent wheel tags")
    parsed_tags: set[tuple[str, str, str]] = set()
    for tag in tags:
        parts = tag.split("-")
        if len(parts) != 3 or any(
            not part or any(char.isspace() for char in part) for part in parts
        ):
            _die(f"{path} has malformed WHEEL Tag {tag!r}")
        parsed_tags.add((parts[0], parts[1], parts[2]))

    filename = path.name
    if not filename.endswith(".whl"):
        _die(f"{path} does not have a wheel filename")
    filename_parts = filename[:-4].split("-")
    if len(filename_parts) < 5:
        _die(f"{path} has a malformed wheel filename")
    python_tags, abi_tags, platform_tags = filename_parts[-3:]
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
    metadata = email.parser.BytesParser().parsebytes(members[metadata_names[0]])
    filename_distribution = _normalized_name(filename_parts[0])
    metadata_version = re.sub(r"[^A-Za-z0-9.]+", "_", str(metadata["Version"]))
    if (
        filename_distribution != _normalized_name(str(metadata["Name"]))
        or filename_parts[1] != metadata_version
    ):
        _die(f"{path} filename distribution/version differs from METADATA")
    filename_tags = {
        (python_tag, abi_tag, platform_tag)
        for python_tag in python_tags.split(".")
        for abi_tag in abi_tags.split(".")
        for platform_tag in platform_tags.split(".")
    }
    if parsed_tags != filename_tags:
        _die(f"{path} filename and WHEEL tags differ")

    expected_arch = platform.split("/", 1)[1]

    def compatible(platform_tag: str) -> bool:
        if platform_tag == "any":
            return True
        if expected_arch == "amd64":
            suffix = "_x86_64"
        elif expected_arch == "arm64":
            suffix = "_aarch64"
        else:  # platform is already constrained by _manifest_platform.
            return False
        return (
            re.fullmatch(
                rf"(?:linux|manylinux_[0-9]+_[0-9]+){re.escape(suffix)}",
                platform_tag,
            )
            is not None
        )

    def python_abi_compatible(python_tag: str, abi_tag: str) -> bool:
        if python_tag in {"py3", "py314"} and abi_tag == "none":
            return True
        if python_tag == "cp314" and abi_tag in {"cp314", "abi3"}:
            return True
        match = re.fullmatch(r"cp3([0-9]{1,2})", python_tag)
        return bool(match and 2 <= int(match.group(1)) <= 14 and abi_tag == "abi3")

    if not any(
        compatible(platform_tag) and python_abi_compatible(python_tag, abi_tag)
        for python_tag, abi_tag, platform_tag in parsed_tags
    ):
        _die(f"wrong-platform wheel for {platform}: {path.name}")


def _audit_wheel(path: Path, *, platform: str) -> tuple[str, str, str, int]:
    members, name, version = _wheel_members(path)
    _wheel_tags(path, members, platform)
    payload = _read_bytes(path, maximum=MAX_WHEEL_BYTES, context=str(path))
    return name, version, _sha256(payload), len(payload)


def _receipt_time(value: Any, context: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _die(f"{context} must be an exact UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{context} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo != dt.UTC:
        _die(f"{context} must use UTC")
    return parsed


def _validate_scanner_database(scanner_value: Any, database_value: Any, context: str) -> None:
    scanner = _require_object(scanner_value, f"{context} scanner")
    _require_exact_keys(
        scanner,
        {"name", "version", "binary_sha256", "version_output_sha256"},
        f"{context} scanner",
    )
    if scanner["name"] != "trivy" or scanner["version"] != "0.74.0":
        _die(f"{context} scanner must be exact Trivy 0.74.0")
    _require_hex(scanner["binary_sha256"], f"{context} scanner binary")
    _require_hex(scanner["version_output_sha256"], f"{context} scanner version transcript")
    database = _require_object(database_value, f"{context} database")
    _require_exact_keys(
        database,
        {
            "name",
            "schema_version",
            "updated_at_utc",
            "next_update_utc",
            "downloaded_at_utc",
            "metadata_sha256",
            "tree_sha256",
        },
        f"{context} database",
    )
    if database["name"] != "trivy-db" or database["schema_version"] != 2:
        _die(f"{context} database identity differs")
    updated = _receipt_time(database["updated_at_utc"], f"{context} database update")
    next_update = _receipt_time(database["next_update_utc"], f"{context} database next update")
    downloaded = _receipt_time(database["downloaded_at_utc"], f"{context} database download")
    cutoff = _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff")
    now = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
    if (
        updated < cutoff
        or downloaded < updated
        or downloaded > now
        or next_update < downloaded
        or next_update - updated > dt.timedelta(days=7)
    ):
        _die(f"{context} database is stale or has impossible timestamps")
    _require_hex(database["metadata_sha256"], f"{context} database metadata")
    _require_hex(database["tree_sha256"], f"{context} database tree")


def _validate_advisory_scan_time(
    advisory: dict[str, Any], database_value: Any, context: str
) -> None:
    database = _require_object(database_value, f"{context} database")
    completed = _receipt_time(advisory["scan_completed_at_utc"], f"{context} scan completion")
    downloaded = _receipt_time(database["downloaded_at_utc"], f"{context} database download")
    next_update = _receipt_time(database["next_update_utc"], f"{context} database next update")
    cutoff = _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff")
    if (
        completed < cutoff
        or completed < downloaded
        or completed > next_update
        or completed > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
    ):
        _die(f"{context} did not complete while its sealed database was current")


def _verify_retained_advisory_authority(
    root: Path,
    records: dict[str, dict[str, Any]],
    scanner_value: Any,
    database_value: Any,
    context: str,
) -> None:
    scanner = _require_object(scanner_value, f"{context} scanner")
    binary_record = records.get("evidence/trivy")
    version_record = records.get("evidence/trivy-version.txt")
    if (
        binary_record is None
        or version_record is None
        or binary_record["sha256"] != scanner["binary_sha256"]
        or version_record["sha256"] != scanner["version_output_sha256"]
        or binary_record["mode"] not in {"0555", "0755"}
    ):
        _die(f"{context} retained scanner binary/transcript differs")
    binary = root / "evidence/trivy"
    version = subprocess.run(  # noqa: S603
        [str(binary), "--version"],
        capture_output=True,
        check=False,
    )
    version_raw = version.stdout + version.stderr
    if (
        version.returncode != 0
        or _sha256(version_raw) != scanner["version_output_sha256"]
        or version_raw
        != _read_bytes(
            root / "evidence/trivy-version.txt",
            maximum=MAX_FILE_BYTES,
            context=f"{context} scanner version transcript",
        )
    ):
        _die(f"{context} retained scanner binary does not reproduce its version transcript")

    prefix = "evidence/trivy-database/"
    database_files = [
        {
            **{key: record[key] for key in ("mode", "size", "sha256")},
            "path": path.removeprefix(prefix),
        }
        for path, record in records.items()
        if path.startswith(prefix)
    ]
    database = _require_object(database_value, f"{context} database")
    database_tree = {"format": "z4j-trivy-database-tree-v1", "files": database_files}
    if not database_files or _sha256(_canonical(database_tree)) != database["tree_sha256"]:
        _die(f"{context} retained vulnerability database tree differs")
    database_records = [record for record in database_files if record["path"] == "db/trivy.db"]
    if len(database_records) != 1 or database_records[0]["size"] <= 0:
        _die(f"{context} retained vulnerability database is absent or ambiguous")
    metadata_records = [record for record in database_files if record["path"] == "db/metadata.json"]
    if len(metadata_records) != 1 or metadata_records[0]["sha256"] != database["metadata_sha256"]:
        _die(f"{context} retained vulnerability database metadata is absent or ambiguous")
    metadata, metadata_raw = _load_json(
        root / prefix / metadata_records[0]["path"],
        maximum=MAX_FILE_BYTES,
    )
    if (
        _sha256(metadata_raw) != database["metadata_sha256"]
        or metadata.get("Version") != database["schema_version"]
        or metadata.get("DownloadedAt") != database["downloaded_at_utc"]
        or metadata.get("UpdatedAt") != database["updated_at_utc"]
        or metadata.get("NextUpdate") != database["next_update_utc"]
    ):
        _die(f"{context} retained vulnerability database metadata differs")


def _trivy_package_inventory(
    results: Any,
    *,
    required_type: str,
    context: str,
) -> set[tuple[str, str]]:
    if not isinstance(results, list) or not results:
        _die(f"{context} report has no scan targets")
    selected = [
        result
        for result in results
        if isinstance(result, dict) and result.get("Type") == required_type
    ]
    if not selected:
        _die(f"{context} report has no {required_type} target")
    packages: set[tuple[str, str]] = set()
    for result in selected:
        entries = result.get("Packages")
        if not isinstance(entries, list) or not entries:
            _die(f"{context} {required_type} target has no retained package inventory")
        for package in entries:
            if not isinstance(package, dict):
                _die(f"{context} {required_type} package is malformed")
            name = package.get("Name")
            version = package.get("Version")
            if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
                _die(f"{context} {required_type} package identity is absent")
            packages.add((_normalized_name(name), version))
    return packages


def _verify_component_sbom(
    sbom: dict[str, Any],
    expected: set[tuple[str, str, str]],
    *,
    subject_name: str,
    subject_version: str,
    subject_sha256: str,
) -> None:
    if sbom.get("bomFormat") != "CycloneDX" or not isinstance(sbom.get("specVersion"), str):
        _die("SBOM is not a CycloneDX document")
    metadata = _require_object(sbom.get("metadata"), "SBOM metadata")
    subject = _require_object(metadata.get("component"), "SBOM subject")
    if (
        subject.get("type") != "application"
        or subject.get("name") != subject_name
        or subject.get("version") != subject_version
        or {
            item.get("content")
            for item in subject.get("hashes", [])
            if isinstance(item, dict) and item.get("alg") == "SHA-256"
        }
        != {subject_sha256}
    ):
        _die("SBOM subject identity/hash differs")
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) != len(expected):
        _die("SBOM component count differs from the sealed dependency closure")
    actual: set[tuple[str, str, str]] = set()
    for component in components:
        if not isinstance(component, dict):
            _die("SBOM component is malformed")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            _die("SBOM component identity is absent")
        sha_values = {
            item.get("content")
            for item in component.get("hashes", [])
            if isinstance(item, dict) and item.get("alg") == "SHA-256"
        }
        integrity_values = {
            item.get("value")
            for item in component.get("properties", [])
            if isinstance(item, dict) and item.get("name") == "z4j:pnpm-integrity"
        }
        identities = {(name, version, str(value)) for value in sha_values | integrity_values}
        matches = identities & expected
        if len(matches) != 1:
            _die(f"SBOM component seal differs: {name}=={version}")
        actual.update(matches)
    if actual != expected:
        _die("SBOM components differ from the exact dependency closure")


def _wheel_component_projection(wheels: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Return the acyclic, canonical subject shared by wheelhouse scan evidence."""

    components = [
        {
            "name": name,
            "version": value["version"],
            "wheel_sha256": value["sha256"],
        }
        for name, value in sorted(wheels.items(), key=lambda item: item[0].encode("utf-8"))
    ]
    if not components or [record["name"] for record in components] != sorted(
        {record["name"] for record in components}, key=lambda name: name.encode("utf-8")
    ):
        _die("wheel component projection is empty, duplicate, or unsorted")
    for record in components:
        if _normalized_name(record["name"]) != record["name"]:
            _die("wheel component projection name is not normalized")
        if not isinstance(record["version"], str) or not record["version"]:
            _die("wheel component projection version is absent")
        _require_hex(record["wheel_sha256"], "wheel component projection digest")
    return {
        "format": "z4j-production-wheel-components-v1",
        "components": components,
    }


def _wheel_components_sha256(wheels: dict[str, dict[str, Any]]) -> str:
    return _sha256(_canonical(_wheel_component_projection(wheels)))


def _validate_wheelhouse_advisory_binding(
    advisory: dict[str, Any],
    *,
    platform: str,
    components_sha256: str,
    expected_files: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Validate the scan receipt's acyclic subject and return its raw-report seal."""

    _require_exact_keys(
        advisory,
        {
            "format",
            "platform",
            "components_sha256",
            "scan_completed_at_utc",
            "verdict",
            "scanner",
            "database",
            "policy",
            "findings",
            "report",
        },
        "wheelhouse advisory receipt",
    )
    report = _require_object(advisory.get("report"), "wheelhouse advisory raw report")
    _require_exact_keys(report, {"path", "sha256", "size"}, "wheelhouse advisory raw report")
    report_record = expected_files.get("evidence/advisory-report.json")
    if (
        advisory["format"] != "z4j-production-advisory-receipt-v1"
        or advisory["platform"] != platform
        or advisory["components_sha256"] != components_sha256
        or advisory["verdict"] != "pass"
        or advisory["findings"] != []
        or report["path"] != "evidence/advisory-report.json"
        or report_record is None
        or report["sha256"] != report_record["sha256"]
        or report["size"] != report_record["size"]
    ):
        _die("wheelhouse advisory receipt does not prove an empty passing result")
    return report


def _verify_wheelhouse_evidence(  # noqa: PLR0912, PLR0915
    manifest: dict[str, Any],
    root: Path,
    platform: str,
    info: dict[str, Any],
    expected_files: dict[str, dict[str, Any]],
    wheels: dict[str, dict[str, Any]],
) -> None:
    components_sha256 = _wheel_components_sha256(wheels)
    sbom, _ = _load_json(root / "evidence/sbom.cyclonedx.json")
    _verify_component_sbom(
        sbom,
        {(name, str(value["version"]), str(value["sha256"])) for name, value in wheels.items()},
        subject_name="z4j-production-wheelhouse",
        subject_version=RELEASE,
        subject_sha256=components_sha256,
    )

    advisory, advisory_raw = _load_json(root / "evidence/advisory-receipt.json")
    if advisory_raw != _canonical(advisory) + b"\n":
        _die("wheelhouse advisory receipt is not canonical JSON plus one newline")
    report = _validate_wheelhouse_advisory_binding(
        advisory,
        platform=platform,
        components_sha256=components_sha256,
        expected_files=expected_files,
    )
    report_json, report_raw = _load_json(root / "evidence/advisory-report.json")
    if _sha256(report_raw) != report["sha256"] or len(report_raw) != report["size"]:
        _die("wheelhouse advisory report bytes differ")
    if report_json.get("SchemaVersion") != 2:
        _die("wheelhouse advisory report is not Trivy schema version 2")
    results = report_json.get("Results")
    if (
        not isinstance(results, list)
        or not results
        or any(
            not isinstance(result, dict) or result.get("Vulnerabilities") not in (None, [])
            for result in results
        )
    ):
        _die("wheelhouse advisory raw report contains findings or malformed results")
    expected_scanned_wheels = {
        (_normalized_name(name), str(value["version"])) for name, value in wheels.items()
    }
    if (
        _trivy_package_inventory(
            results,
            required_type="python-pkg",
            context="wheelhouse advisory",
        )
        != expected_scanned_wheels
    ):
        _die("wheelhouse advisory package inventory differs from the exact wheel closure")
    _validate_scanner_database(advisory["scanner"], advisory["database"], "wheelhouse advisory")
    _validate_advisory_scan_time(advisory, advisory["database"], "wheelhouse advisory")
    _verify_retained_advisory_authority(
        root,
        expected_files,
        advisory["scanner"],
        advisory["database"],
        "wheelhouse advisory",
    )
    if advisory["policy"] != {
        "severity": ["CRITICAL", "HIGH"],
        "ignore_unfixed": True,
        "list_all_packages": True,
        "required_result_type": "python-pkg",
    }:
        _die("wheelhouse advisory policy differs")

    provenance, provenance_raw = _load_json(root / "evidence/provenance.json")
    if provenance_raw != _canonical(provenance) + b"\n":
        _die("wheelhouse provenance receipt is not canonical JSON plus one newline")
    _require_exact_keys(
        provenance,
        {
            "format",
            "platform",
            "selection_cutoff_utc",
            "resolved_at_utc",
            "index_api",
            "uv",
            "artifacts",
        },
        "wheelhouse provenance receipt",
    )
    cutoff = _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff")
    provenance_time = _receipt_time(provenance["resolved_at_utc"], "provenance resolution time")
    now = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
    if (
        provenance["format"] != "z4j-production-wheel-provenance-v1"
        or provenance["platform"] != platform
        or provenance["selection_cutoff_utc"] != FINALIZATION_CUTOFF
        or provenance["index_api"] != "PEP-691"
        or provenance_time < cutoff
        or provenance_time > now
    ):
        _die("wheelhouse provenance context differs")
    uv_provenance = _require_object(provenance["uv"], "uv provenance")
    _require_exact_keys(
        uv_provenance,
        {
            "version",
            "filename",
            "url",
            "asset_sha256",
            "asset_size",
            "binary_sha256",
            "binary_size",
            "published_at_utc",
            "release_response",
        },
        "uv provenance",
    )
    uv_record = expected_files[manifest["resolver"]["binary_relative_path"]]
    uv_archive_record = expected_files.get("evidence/uv-archive.tar.gz")
    expected_uv_filename = {
        "linux/amd64": "uv-x86_64-unknown-linux-gnu.tar.gz",
        "linux/arm64": "uv-aarch64-unknown-linux-gnu.tar.gz",
    }[platform]
    expected_uv_url = (
        "https://github.com/astral-sh/uv/releases/download/0.12.5/" + expected_uv_filename
    )
    if (
        uv_provenance["version"] != "0.12.5"
        or uv_provenance["filename"] != expected_uv_filename
        or uv_provenance["url"] != expected_uv_url
        or uv_archive_record is None
        or uv_provenance["asset_sha256"] != uv_archive_record["sha256"]
        or uv_provenance["asset_size"] != uv_archive_record["size"]
        or uv_provenance["binary_sha256"] != uv_record["sha256"]
        or uv_provenance["binary_size"] != uv_record["size"]
        or _receipt_time(uv_provenance["published_at_utc"], "uv publication") > cutoff
    ):
        _die("uv release provenance differs from the sealed binary")
    uv_archive_raw = _read_bytes(
        root / "evidence/uv-archive.tar.gz",
        maximum=MAX_FILE_BYTES,
        context="uv release archive",
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(uv_archive_raw), mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                pure = PurePosixPath(member.name)
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or pure.as_posix() != member.name
                    or not (member.isdir() or member.isreg())
                ):
                    _die("uv release archive contains an unsafe entry")
            expected_member = expected_uv_filename.removesuffix(".tar.gz") + "/uv"
            selected_members = [member for member in members if member.name == expected_member]
            if len(selected_members) != 1 or selected_members[0].size > MAX_FILE_BYTES:
                _die("uv release archive omits its exact native uv binary")
            stream = archive.extractfile(selected_members[0])
            if stream is None:
                _die("uv release archive native binary cannot be read")
            archived_uv = stream.read(MAX_FILE_BYTES + 1)
    except (tarfile.TarError, OSError) as exc:
        raise ContractError("uv release archive is invalid") from exc
    if len(archived_uv) > MAX_FILE_BYTES or (_sha256(archived_uv), len(archived_uv)) != (
        uv_record["sha256"],
        uv_record["size"],
    ):
        _die("uv release archive binary differs from bin/uv")
    uv_release = _require_object(uv_provenance["release_response"], "uv release response")
    _require_exact_keys(uv_release, {"path", "sha256", "size"}, "uv release response")
    if uv_release["path"] != "evidence/uv-release.json":
        _die("uv release response path differs")
    uv_release_record = expected_files.get(uv_release["path"])
    if (
        uv_release_record is None
        or uv_release_record["sha256"] != uv_release["sha256"]
        or uv_release_record["size"] != uv_release["size"]
    ):
        _die("uv release response seal differs")
    uv_release_json, _ = _load_json(root / uv_release["path"])
    if (
        uv_release_json.get("tag_name") != "0.12.5"
        or uv_release_json.get("published_at") != uv_provenance["published_at_utc"]
    ):
        _die("uv GitHub release identity/publication differs")
    selected_assets = [
        asset
        for asset in uv_release_json.get("assets", [])
        if isinstance(asset, dict) and asset.get("name") == expected_uv_filename
    ]
    if len(selected_assets) != 1:
        _die("uv GitHub release response does not select one exact native asset")
    selected_asset = selected_assets[0]
    if (
        selected_asset.get("browser_download_url") != expected_uv_url
        or selected_asset.get("size") != uv_archive_record["size"]
        or selected_asset.get("digest") != "sha256:" + uv_archive_record["sha256"]
    ):
        _die("uv GitHub release asset differs from the retained archive")

    artifacts = provenance["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(wheels):
        _die("wheel provenance artifact count differs")
    proven: set[str] = set()
    index_paths: set[str] = set()
    for raw_artifact in artifacts:
        artifact = _require_object(raw_artifact, "wheel provenance artifact")
        _require_exact_keys(
            artifact,
            {
                "distribution",
                "version",
                "filename",
                "sha256",
                "size",
                "url",
                "upload_time_utc",
                "yanked",
                "index_response",
            },
            "wheel provenance artifact",
        )
        name = _normalized_name(str(artifact["distribution"]))
        if name in proven or name not in wheels:
            _die(f"wheel provenance contains duplicate or unknown distribution {name}")
        proven.add(name)
        if any(
            artifact[key] != wheels[name][key] for key in ("version", "filename", "sha256", "size")
        ):
            _die(f"wheel provenance identity differs for {name}")
        parsed_url = urllib.parse.urlsplit(str(artifact["url"]))
        if (
            parsed_url.scheme != "https"
            or parsed_url.netloc != "files.pythonhosted.org"
            or parsed_url.query
            or parsed_url.fragment
            or PurePosixPath(parsed_url.path).name != artifact["filename"]
            or artifact["yanked"] is not False
            or _receipt_time(artifact["upload_time_utc"], f"{name} upload time") > cutoff
        ):
            _die(f"wheel provenance registry origin differs for {name}")
        response = _require_object(artifact["index_response"], f"{name} index response")
        _require_exact_keys(response, {"path", "sha256", "size"}, f"{name} index response")
        expected_response_path = f"evidence/index/{name}.json"
        if response["path"] != expected_response_path:
            _die(f"{name} index response path differs")
        index_paths.add(expected_response_path)
        response_record = expected_files.get(expected_response_path)
        if (
            response_record is None
            or response_record["sha256"] != response["sha256"]
            or response_record["size"] != response["size"]
        ):
            _die(f"{name} index response seal differs")
        project, _ = _load_json(root / expected_response_path)
        if _normalized_name(str(project.get("name"))) != name:
            _die(f"{name} PEP-691 project identity differs")
        meta = _require_object(project.get("meta"), f"{name} PEP-691 metadata")
        if not isinstance(meta.get("api-version"), str) or not meta["api-version"].startswith("1."):
            _die(f"{name} PEP-691 API version differs")
        selected = [
            candidate
            for candidate in project.get("files", [])
            if isinstance(candidate, dict) and candidate.get("filename") == artifact["filename"]
        ]
        if len(selected) != 1:
            _die(f"{name} PEP-691 response does not select exactly one artifact")
        selected_file = selected[0]
        if (
            (_require_object(selected_file.get("hashes"), f"{name} hashes")).get("sha256")
            != artifact["sha256"]
            or selected_file.get("url") != artifact["url"]
            or selected_file.get("size") != artifact["size"]
            or selected_file.get("upload-time") != artifact["upload_time_utc"]
            or selected_file.get("yanked", False) is not False
        ):
            _die(f"{name} selected PEP-691 artifact differs")
    if proven != set(wheels):
        _die("wheel provenance package inventory differs")
    actual_index_paths = {path for path in expected_files if path.startswith("evidence/index/")}
    if actual_index_paths != index_paths:
        _die("wheelhouse index-response inventory differs from provenance")

    resolver, resolver_raw = _load_json(root / "evidence/resolver-transcript.json")
    if resolver_raw != _canonical(resolver) + b"\n":
        _die("resolver transcript is not canonical JSON plus one newline")
    _require_exact_keys(
        resolver,
        {
            "format",
            "platform",
            "python_version",
            "uv_version",
            "selection_cutoff_utc",
            "resolved_at_utc",
            "commands",
            "inputs",
            "runtime_lock",
            "build_lock",
            "selected_artifact_sha256",
            "transcripts",
        },
        "resolver transcript",
    )
    resolver_time = _receipt_time(resolver["resolved_at_utc"], "resolver time")
    if (
        resolver["format"] != "z4j-production-resolver-transcript-v1"
        or resolver["platform"] != platform
        or resolver["python_version"] != "3.14.7"
        or resolver["uv_version"] != "0.12.5"
        or resolver["selection_cutoff_utc"] != FINALIZATION_CUTOFF
        or resolver_time < cutoff
        or resolver_time > now
    ):
        _die("resolver transcript context or command differs")
    target = {
        "linux/amd64": "x86_64-unknown-linux-gnu",
        "linux/arm64": "aarch64-unknown-linux-gnu",
    }[platform]
    commands = _require_object(resolver["commands"], "resolver commands")
    inputs = _require_object(resolver["inputs"], "resolver inputs")
    transcripts = _require_object(resolver["transcripts"], "resolver transcripts")
    for value, context in (
        (commands, "resolver commands"),
        (inputs, "resolver inputs"),
        (transcripts, "resolver transcripts"),
    ):
        _require_exact_keys(value, {"runtime", "build"}, context)
    for role in ("runtime", "build"):
        input_path = f"evidence/{role}-requirements.in"
        output_path = f"locks/{role}.txt"
        expected_command = [
            "uv",
            "pip",
            "compile",
            input_path,
            "--output-file",
            output_path,
            "--generate-hashes",
            "--exclude-newer",
            FINALIZATION_CUTOFF,
            "--resolution",
            "highest",
            "--python-version",
            "3.14.7",
            "--python-platform",
            target,
            "--no-cache",
            "--no-config",
            "--no-sources",
        ]
        if commands[role] != expected_command:
            _die(f"resolver {role} command differs from the exact highest/cutoff policy")
        input_seal = _require_object(inputs[role], f"resolver {role} input")
        _require_exact_keys(input_seal, {"path", "sha256", "size"}, f"resolver {role} input")
        input_record = expected_files.get(input_path)
        if (
            input_seal.get("path") != input_path
            or input_record is None
            or input_seal.get("sha256") != input_record["sha256"]
            or input_seal.get("size") != input_record["size"]
        ):
            _die(f"resolver {role} input seal differs")
        transcript = _require_object(transcripts[role], f"resolver {role} transcript")
        _require_exact_keys(
            transcript,
            {"stdout", "stderr", "exit_code"},
            f"resolver {role} transcript",
        )
        if transcript["exit_code"] != 0:
            _die(f"resolver {role} did not exit successfully")
        for stream_name in ("stdout", "stderr"):
            relative = f"evidence/resolver-{role}.{stream_name}"
            seal = _require_object(transcript[stream_name], f"resolver {role} {stream_name}")
            _require_exact_keys(seal, {"path", "sha256", "size"}, f"resolver {role} {stream_name}")
            record = expected_files.get(relative)
            if (
                seal.get("path") != relative
                or record is None
                or seal.get("sha256") != record["sha256"]
                or seal.get("size") != record["size"]
            ):
                _die(f"resolver {role} {stream_name} seal differs")
    for lock_name in ("runtime_lock", "build_lock"):
        lock = _require_object(resolver[lock_name], f"resolver {lock_name}")
        _require_exact_keys(lock, {"sha256", "size"}, f"resolver {lock_name}")
        if lock != {key: info[lock_name][key] for key in ("sha256", "size")}:
            _die(f"resolver {lock_name} seal differs")
    if resolver["selected_artifact_sha256"] != sorted(
        str(record["sha256"]) for record in wheels.values()
    ):
        _die("resolver selected artifact inventory differs")


def _verify_signature_verifier(
    manifest: dict[str, Any],
    root: Path,
    platform: str,
    files: dict[str, dict[str, Any]],
) -> None:
    authority = manifest["signature_verifier"]
    tool = authority["platforms"][platform]
    binary_record = files.get("bin/cosign")
    response_record = files.get("evidence/cosign-release.json")
    release_response = authority["release_response"]
    if (
        binary_record is None
        or binary_record["sha256"] != tool["sha256"]
        or binary_record["size"] != tool["size"]
        or binary_record["mode"] not in {"0555", "0755"}
        or response_record is None
        or response_record["sha256"] != release_response["sha256"]
        or response_record["size"] != release_response["size"]
    ):
        _die("Cosign binary/release-response payload differs from the manifest")
    try:
        version = _load_authority_common().run_cosign_version(
            cosign=root / "bin/cosign",
            cosign_sha256=tool["sha256"],
            cosign_size=tool["size"],
        )
    except (ImportError, OSError, RuntimeError) as exc:
        raise ContractError("Cosign bounded custody/version probe failed") from exc
    version_raw = version.stdout + version.stderr
    if (
        version.returncode != 0
        or _sha256(version_raw) != tool["version_output_sha256"]
        or len(version_raw) != tool["version_output_size"]
    ):
        _die("Cosign binary does not reproduce its sealed version output")
    release, release_raw = _load_json(root / release_response["path"])
    if (
        _sha256(release_raw) != release_response["sha256"]
        or len(release_raw) != release_response["size"]
        or release.get("tag_name") != "v3.1.3"
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or _receipt_time(release.get("published_at"), "Cosign release publication")
        > _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff")
    ):
        _die("Cosign GitHub release identity/publication differs")
    selected = [
        asset
        for asset in release.get("assets", [])
        if isinstance(asset, dict) and asset.get("name") == tool["filename"]
    ]
    if len(selected) != 1:
        _die("Cosign GitHub release does not select one exact native binary")
    asset = selected[0]
    if (
        asset.get("browser_download_url") != tool["url"]
        or asset.get("size") != tool["size"]
        or asset.get("digest") != "sha256:" + tool["sha256"]
        or asset.get("state") != "uploaded"
    ):
        _die("Cosign GitHub release asset differs from the retained binary")


def _wheel_authority_kind(
    *,
    name: str,
    version: str,
    filename: str,
    digest: str,
    size: int,
    lock_records: dict[str, tuple[str, str]],
    local_authorities: dict[str, dict[str, Any]],
) -> str:
    """Classify one audited wheel without conflating local builds with external locks."""

    local = local_authorities.get(name)
    if local is not None:
        if (
            version != RELEASE
            or filename != local["filename"]
            or digest != local["sha256"]
            or size != local["size"]
        ):
            _die(f"wheelhouse local wheel differs from its manifest authority: {name}")
        return "local"
    if lock_records.get(name) != (version, digest):
        _die(f"wheelhouse wheel is not the exact locked artifact: {name}")
    return "external"


def verify_wheelhouse(  # noqa: PLR0912, PLR0915
    manifest: dict[str, Any],
    root: Path,
    platform: str,
    *,
    contract_root: Path | None = None,
) -> None:
    info = _manifest_platform(manifest, platform)
    inventory_path = root / info["inventory"]["path"]
    inventory, raw = _load_json(inventory_path)
    if _sha256(raw) != info["inventory"]["sha256"] or len(raw) != info["inventory"]["size"]:
        _die("wheelhouse inventory bytes differ from the source manifest")
    _require_exact_keys(inventory, {"format", "platform", "files"}, "wheelhouse inventory")
    if inventory["format"] != manifest["wheelhouse"]["inventory_format"]:
        _die("wheelhouse inventory format differs")
    if inventory["platform"] != platform:
        _die(f"wrong-platform wheelhouse: expected {platform}, found {inventory['platform']!r}")
    files = inventory["files"]
    if not isinstance(files, list) or len(files) != info["inventory"]["entries"]:
        _die("wheelhouse inventory entry count differs")
    expected: dict[str, dict[str, Any]] = {}
    previous: bytes | None = None
    for record in files:
        if not isinstance(record, dict):
            _die("wheelhouse inventory record is not an object")
        _require_exact_keys(record, {"path", "mode", "size", "sha256"}, "wheelhouse record")
        relative = PurePosixPath(str(record["path"]))
        encoded = relative.as_posix().encode("utf-8")
        if relative.is_absolute() or ".." in relative.parts or "\\" in str(record["path"]):
            _die("wheelhouse inventory has an unsafe path")
        if previous is not None and encoded <= previous:
            _die("wheelhouse inventory paths are not strictly UTF-8 sorted")
        previous = encoded
        if relative.as_posix() == info["inventory"]["path"]:
            _die("wheelhouse inventory must not self-reference")
        if (
            not isinstance(record["mode"], str)
            or re.fullmatch(r"0[4567][0-7]{2}", record["mode"]) is None
        ):
            _die("wheelhouse inventory mode is not a four-digit regular-file mode")
        allowed_static = {
            "bin/uv",
            "bin/cosign",
            "locks/runtime.txt",
            "locks/build.txt",
            "evidence/sbom.cyclonedx.json",
            "evidence/advisory-receipt.json",
            "evidence/advisory-report.json",
            "evidence/provenance.json",
            "evidence/resolver-transcript.json",
            "evidence/runtime-requirements.in",
            "evidence/build-requirements.in",
            "evidence/resolver-runtime.stdout",
            "evidence/resolver-runtime.stderr",
            "evidence/resolver-build.stdout",
            "evidence/resolver-build.stderr",
            "evidence/uv-release.json",
            "evidence/uv-archive.tar.gz",
            "evidence/cosign-release.json",
            "evidence/trivy",
            "evidence/trivy-version.txt",
        }
        path_text = relative.as_posix()
        is_wheel = (
            len(relative.parts) == 2
            and relative.parts[0] == "wheels"
            and relative.parts[1].endswith(".whl")
        )
        is_index_response = (
            len(relative.parts) == 3
            and relative.parts[:2] == ("evidence", "index")
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*\.json", relative.parts[2]) is not None
        )
        is_trivy_database = path_text.startswith("evidence/trivy-database/")
        if (
            path_text not in allowed_static
            and not is_wheel
            and not is_index_response
            and not is_trivy_database
        ):
            _die(f"wheelhouse inventory path is outside the exact payload contract: {path_text}")
        _require_size(record["size"], f"wheelhouse file {relative}")
        _require_hex(record["sha256"], f"wheelhouse file {relative}")
        expected[relative.as_posix()] = record
    tree_payload = {
        "format": manifest["wheelhouse"]["tree_format"],
        "platform": platform,
        "files": files,
    }
    if _sha256(_canonical(tree_payload)) != info["tree_sha256"]:
        _die("wheelhouse canonical tree digest differs")
    if sum(int(record["size"]) for record in files) != info["tree_bytes"]:
        _die("wheelhouse canonical tree byte total differs")

    actual: dict[str, Path] = {}
    for entry in root.rglob("*"):
        actual_relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            _die(f"wheelhouse contains symlink {actual_relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            _die(f"wheelhouse contains nonregular entry {actual_relative}")
        if actual_relative != info["inventory"]["path"]:
            actual[actual_relative] = entry
    if set(actual) != set(expected):
        _die(
            "wheelhouse inventory differs; "
            f"missing={sorted(set(expected) - set(actual))}, "
            f"extra={sorted(set(actual) - set(expected))}"
        )
    for actual_relative, path in actual.items():
        record = expected[actual_relative]
        observed = path.stat(follow_symlinks=False)
        payload = _read_bytes(path, maximum=MAX_FILE_BYTES, context=f"wheelhouse/{actual_relative}")
        if (
            f"{stat.S_IMODE(observed.st_mode):04o}" != record["mode"]
            or len(payload) != record["size"]
            or _sha256(payload) != record["sha256"]
        ):
            _die(f"wheelhouse file differs: {actual_relative}")

    _verify_signature_verifier(manifest, root, platform, expected)

    uv_record = expected.get(manifest["resolver"]["binary_relative_path"])
    if uv_record is None:
        _die("wheelhouse omits the exact uv binary")
    if (
        uv_record["sha256"] != info["uv"]["sha256"]
        or uv_record["size"] != info["uv"]["size"]
        or int(str(uv_record["mode"]), 8) & 0o111 == 0
    ):
        _die("wheelhouse uv binary seal or executable mode differs")
    for payload_name, source_name in (("runtime", "runtime_lock"), ("build", "build_lock")):
        lock_relative = f"locks/{payload_name}.txt"
        record = expected.get(lock_relative)
        if record is None or record["sha256"] != info[source_name]["sha256"]:
            _die(f"wheelhouse {payload_name} lock differs from source lock authority")
        source_lock = (contract_root or Path(__file__).resolve().parent) / info[source_name]["path"]
        source_bytes = _read_bytes(source_lock, maximum=MAX_LOCK_BYTES, context=str(source_lock))
        if (
            _sha256(source_bytes) != record["sha256"]
            or len(source_bytes) != record["size"]
            or record["size"] != info[source_name]["size"]
        ):
            _die(f"source and wheelhouse {payload_name} locks differ")
    evidence = {
        "evidence/sbom.cyclonedx.json": info["sbom"],
        "evidence/provenance.json": info["provenance_receipt"],
        "evidence/resolver-transcript.json": info["resolver_receipt"],
        "evidence/advisory-receipt.json": info["advisory_receipt"],
    }
    for evidence_relative, seal in evidence.items():
        record = expected.get(evidence_relative)
        if record is None or record["sha256"] != seal["sha256"] or record["size"] != seal["size"]:
            _die(f"wheelhouse evidence differs: {evidence_relative}")

    lock_records: dict[str, tuple[str, str]] = {}
    lock_hashes: set[str] = set()
    for name in ("runtime", "build"):
        lock_payload = _read_bytes(root / f"locks/{name}.txt", maximum=MAX_LOCK_BYTES, context=name)
        for package, version, digest in _lock_records(lock_payload, context=f"{name} lock"):
            previous_record = lock_records.get(package)
            if previous_record is not None and previous_record != (version, digest):
                _die(f"runtime/build locks disagree for {package}")
            lock_records[package] = (version, digest)
            lock_hashes.add(digest)
    if LOCAL_DISTRIBUTIONS & set(lock_records):
        _die("runtime/build locks must not resolve locally built z4j distributions")
    wheel_records = {
        path: record for path, record in expected.items() if path.startswith("wheels/")
    }
    local_authorities = {
        _normalized_name(str(record["distribution"])): record for record in info["local_wheels"]
    }
    if set(local_authorities) != LOCAL_DISTRIBUTIONS:
        _die("manifest local-wheel authority differs from the exact three distributions")
    external_wheel_hashes: set[str] = set()
    seen_external: set[str] = set()
    seen_local: set[str] = set()
    seen_wheels: set[str] = set()
    wheel_identities: dict[str, dict[str, Any]] = {}
    for wheel_relative, record in wheel_records.items():
        path = root / wheel_relative
        name, version, digest, size = _audit_wheel(path, platform=platform)
        if name in seen_wheels:
            _die(f"wheelhouse contains duplicate distribution wheel {name}")
        seen_wheels.add(name)
        if record["sha256"] != digest or record["size"] != size:
            _die(f"wheelhouse wheel seal differs: {wheel_relative}")
        authority_kind = _wheel_authority_kind(
            name=name,
            version=version,
            filename=path.name,
            digest=digest,
            size=size,
            lock_records=lock_records,
            local_authorities=local_authorities,
        )
        if authority_kind == "local":
            seen_local.add(name)
        else:
            external_wheel_hashes.add(digest)
            seen_external.add(name)
        wheel_identities[name] = {
            "version": version,
            "filename": path.name,
            "sha256": digest,
            "size": size,
        }
    if external_wheel_hashes != lock_hashes:
        _die(
            "wheelhouse and runtime/build lock artifacts differ; "
            f"missing_wheels={sorted(lock_hashes - external_wheel_hashes)}, "
            f"unlocked_wheels={sorted(external_wheel_hashes - lock_hashes)}"
        )
    if seen_external != set(lock_records):
        _die(
            "wheelhouse and runtime/build lock package names differ; "
            f"missing_wheels={sorted(set(lock_records) - seen_external)}, "
            f"unlocked_wheels={sorted(seen_external - set(lock_records))}"
        )
    if seen_local != LOCAL_DISTRIBUTIONS:
        _die(
            "wheelhouse local wheels differ from the exact three distributions; "
            f"missing_wheels={sorted(LOCAL_DISTRIBUTIONS - seen_local)}, "
            f"extra_wheels={sorted(seen_local - LOCAL_DISTRIBUTIONS)}"
        )
    _verify_wheelhouse_evidence(
        manifest,
        root,
        platform,
        info,
        expected,
        wheel_identities,
    )


def _verify_bundle_inventory(  # noqa: PLR0912, PLR0915
    *,
    root: Path,
    platform: str,
    inventory_format: str,
    tree_format: str,
    inventory_sha256: str,
    inventory_size: int,
    inventory_entries: int,
    tree_sha256: str,
    tree_bytes: int,
    allowed: Any,
) -> dict[str, dict[str, Any]]:
    inventory, raw = _load_json(root / "inventory.json")
    if raw != _canonical(inventory) + b"\n":
        _die("bundle inventory is not canonical JSON plus one newline")
    if _sha256(raw) != inventory_sha256 or len(raw) != inventory_size:
        _die("bundle inventory bytes differ from the manifest")
    _require_exact_keys(inventory, {"format", "platform", "files"}, "bundle inventory")
    if inventory["format"] != inventory_format or inventory["platform"] != platform:
        _die("bundle inventory format/platform differs")
    files = inventory["files"]
    if not isinstance(files, list) or len(files) != inventory_entries:
        _die("bundle inventory entry count differs")
    records: dict[str, dict[str, Any]] = {}
    last = b""
    for record in files:
        if not isinstance(record, dict):
            _die("bundle inventory record is malformed")
        _require_exact_keys(record, {"path", "mode", "size", "sha256"}, "bundle record")
        path_text = record["path"]
        if not isinstance(path_text, str):
            _die("bundle inventory path is not text")
        relative = PurePosixPath(path_text)
        encoded = path_text.encode("utf-8")
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or path_text in {"", ".", "inventory.json"}
            or path_text.endswith("/")
        ):
            _die("bundle inventory has an unsafe or self-referential path")
        if encoded <= last or path_text in records:
            _die("bundle inventory paths are not strictly UTF-8 sorted")
        last = encoded
        if (
            not isinstance(record["mode"], str)
            or re.fullmatch(r"0[0-7]{3}", record["mode"]) is None
        ):
            _die("bundle inventory mode is not a four-digit regular-file mode")
        _require_nonnegative_size(record["size"], f"bundle file {path_text}")
        _require_hex(record["sha256"], f"bundle file {path_text}")
        if not allowed(path_text):
            _die(f"bundle inventory path is outside its exact contract: {path_text}")
        records[path_text] = record
    tree = {"format": tree_format, "platform": platform, "files": files}
    if _sha256(_canonical(tree)) != tree_sha256:
        _die("bundle canonical tree digest differs")
    if sum(int(record["size"]) for record in files) != tree_bytes:
        _die("bundle canonical tree byte total differs")
    actual: dict[str, Path] = {}
    for entry in root.rglob("*"):
        actual_relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            _die(f"bundle contains symlink {actual_relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            _die(f"bundle contains nonregular entry {actual_relative}")
        actual[actual_relative] = entry
    expected_paths = {"inventory.json", *records}
    if set(actual) != expected_paths:
        _die(
            "bundle payload inventory differs; "
            f"missing={sorted(expected_paths - set(actual))}, "
            f"extra={sorted(set(actual) - expected_paths)}"
        )
    for record_relative, record in records.items():
        payload = _read_bytes(
            actual[record_relative], maximum=MAX_FILE_BYTES, context=record_relative
        )
        if (
            len(payload) != record["size"]
            or _sha256(payload) != record["sha256"]
            or f"{stat.S_IMODE(actual[record_relative].stat().st_mode):04o}" != record["mode"]
        ):
            _die(f"bundle file differs: {record_relative}")
    return records


def _clearsigned_payload(raw: bytes) -> bytes:
    marker = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
    signature = b"-----BEGIN PGP SIGNATURE-----\n"
    if not raw.startswith(marker) or signature not in raw:
        _die("Debian InRelease is not one ASCII-armored clear-signed document")
    header_end = raw.find(b"\n\n", len(marker))
    signature_at = raw.find(signature, header_end + 2)
    if header_end < 0 or signature_at < 0 or raw.count(signature) != 1:
        _die("Debian InRelease clear-sign framing is ambiguous")
    payload = raw[header_end + 2 : signature_at]
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    lines = payload.split(b"\n")
    unescaped = [line[2:] if line.startswith(b"- ") else line for line in lines]
    return b"\n".join(unescaped) + b"\n"


def _release_metadata(
    release_raw: bytes,
) -> tuple[dict[str, str], dict[str, tuple[str, int]]]:
    try:
        text = release_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("Debian Release metadata is not UTF-8") from exc
    parsed = email.parser.Parser().parsestr(text)
    required_headers = {"Suite", "Codename", "Date", "Architectures", "Components"}
    headers: dict[str, str] = {}
    for name in required_headers | {"Valid-Until"}:
        values = parsed.get_all(name) or []
        if len(values) > 1:
            _die(f"Debian Release field {name} is duplicate")
        if values:
            value = str(values[0]).strip()
            if not value:
                _die(f"Debian Release field {name} is empty")
            headers[name] = value
    sha_values = parsed.get_all("SHA256") or []
    if len(sha_values) != 1:
        _die("Debian Release SHA256 field is absent or duplicate")
    seals: dict[str, tuple[str, int]] = {}
    for line in str(sha_values[0]).splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3 or HEX64.fullmatch(parts[0]) is None or not parts[1].isdigit():
            _die("Debian Release SHA256 section is malformed")
        path = PurePosixPath(parts[2])
        if path.is_absolute() or ".." in path.parts or parts[2] in seals:
            _die("Debian Release index path is unsafe or duplicate")
        seals[parts[2]] = (parts[0], int(parts[1]))
    if not seals or not required_headers.issubset(headers):
        _die("Debian Release metadata lacks required identity or SHA256 fields")
    return headers, seals


def _release_index_seals(release_raw: bytes) -> dict[str, tuple[str, int]]:
    _, seals = _release_metadata(release_raw)
    if not seals:
        _die("Debian Release metadata has no SHA256 index seals")
    return seals


def _debian_sources_list(snapshot: dict[str, Any]) -> bytes:
    lines = []
    for source in snapshot["sources"]:
        timestamp = _receipt_time(
            source["timestamp_utc"], f"Debian {source['name']} snapshot timestamp"
        ).strftime("%Y%m%dT%H%M%SZ")
        components = " ".join(source["components"])
        lines.append(
            "deb [check-valid-until=yes "
            f"signed-by=/opt/z4j-production-system/snapshot/{source['name']}/"
            f"archive-keyring.gpg] {source['archive']}{timestamp}/ "
            f"{source['suite']} {components}"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def _debian_apt_config() -> bytes:
    return (
        "#clear APT::Update::Post-Invoke;\n"
        "#clear APT::Update::Post-Invoke-Success;\n"
        "#clear APT::Update::Pre-Invoke;\n"
        "#clear DPkg::Post-Invoke;\n"
        "#clear DPkg::Post-Invoke-Success;\n"
        "#clear DPkg::Pre-Invoke;\n"
        'Acquire::AllowDowngradeToInsecureRepositories "false";\n'
        'Acquire::AllowInsecureRepositories "false";\n'
        'Acquire::Check-Valid-Until "true";\n'
        'Acquire::Languages "none";\n'
        'Acquire::GzipIndexes "false";\n'
        'Acquire::Retries "0";\n'
        'APT::Get::List-Cleanup "false";\n'
        'APT::Get::AllowUnauthenticated "false";\n'
        'Debug::NoLocking "true";\n'
        'Dir::Etc::main "-";\n'
        'Dir::Etc::parts "-";\n'
        'Dir::Etc::preferences "-";\n'
        'Dir::Etc::preferencesparts "-";\n'
    ).encode("ascii")


def _isolated_apt_commands(platform: str) -> dict[str, list[str]]:
    architecture = {"linux/amd64": "amd64", "linux/arm64": "arm64"}[platform]
    common = [
        "/acquired/.generator/tools/apt-get",
        "-o",
        "Dir::Etc::sourcelist=/opt/z4j-production-system/evidence/sources.list",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "Dir::Etc::trusted=-",
        "-o",
        "Dir::Etc::trustedparts=-",
        "-o",
        "Dir::State::status=/tmp/z4j-production-system-apt/status",
        "-o",
        "Dir::State::lists=/tmp/z4j-production-system-apt/lists",
        "-o",
        "Dir::Cache::archives=/tmp/z4j-production-system-apt/archives",
        "-o",
        f"APT::Architecture={architecture}",
    ]
    return {
        "download": [
            *common,
            "--download-only",
            "--no-install-recommends",
            "--yes",
            "install",
            *EXPECTED_SYSTEM_REQUESTED,
        ],
        "resolve": [
            *common,
            "--simulate",
            "--no-install-recommends",
            "install",
            *EXPECTED_SYSTEM_REQUESTED,
        ],
        "update": [*common, "update"],
    }


def _real_base_apt_commands(platform: str, filenames: list[str]) -> dict[str, list[str]]:
    architecture = {"linux/amd64": "amd64", "linux/arm64": "arm64"}[platform]
    prefix = [
        "/acquired/.generator/tools/apt-get",
        "-o",
        "Dir::Etc::sourcelist=-",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "Dir::Etc::trusted=-",
        "-o",
        "Dir::Etc::trustedparts=-",
        "-o",
        f"APT::Architecture={architecture}",
    ]
    return {
        "check": [*prefix, "check"],
        "install": [
            *prefix,
            "--no-download",
            "--no-install-recommends",
            "--reinstall",
            "--yes",
            "install",
            *(f"/acquired/debs/{filename}" for filename in filenames),
        ],
    }


def _debian_package_index(raw: bytes, context: str) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{context} is not UTF-8") from exc
    records: list[dict[str, Any]] = []
    for stanza in text.strip().split("\n\n"):
        parsed = email.parser.Parser().parsestr(stanza + "\n")
        required = ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")
        if any(len(parsed.get_all(field) or []) != 1 for field in required):
            _die(f"{context} has an ambiguous package stanza")
        records.append(
            {
                **{field: str(parsed[field]) for field in required},
                "Depends": parsed.get("Depends"),
                "Essential": parsed.get("Essential"),
                "Pre-Depends": parsed.get("Pre-Depends"),
                "Provides": parsed.get("Provides"),
                "Stanza-SHA256": _sha256((stanza + "\n").encode("utf-8")),
            }
        )
    if not records:
        _die(f"{context} has no package records")
    return records


def _debian_control_record(raw: bytes, context: str) -> dict[str, str | None]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{context} is not UTF-8") from exc
    if not text.endswith("\n") or "\n\n" in text.rstrip("\n"):
        _die(f"{context} framing differs")
    parsed = email.parser.Parser().parsestr(text)
    required = ("Package", "Version", "Architecture")
    if any(len(parsed.get_all(field) or []) != 1 for field in required):
        _die(f"{context} identity is ambiguous")
    if parsed.get("Status") is not None:
        _die(f"{context} unexpectedly contains installed status")
    return {
        "architecture": parsed["Architecture"],
        "depends": parsed.get("Depends"),
        "essential": parsed.get("Essential"),
        "name": parsed["Package"],
        "pre_depends": parsed.get("Pre-Depends"),
        "provides": parsed.get("Provides"),
        "version": parsed["Version"],
    }


class _HeldExecutable:
    """One private, sealed executable snapshot; its source pathname is never reopened."""

    def __init__(self, *, descriptor: int, logical_path: Path, raw: bytes) -> None:
        self.descriptor = descriptor
        self.logical_path = logical_path
        self.raw = raw

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _read_descriptor_bounded(descriptor: int, *, maximum: int, context: str) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            _die(f"{context} exceeds its reviewed byte bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _capture_executable(path: Path, *, context: str) -> _HeldExecutable:
    """Capture a no-follow source into a write-sealed private memfd."""

    before = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not stat.S_IMODE(before.st_mode) & stat.S_IXUSR
        or stat.S_IMODE(before.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        or before.st_size < 1
        or before.st_size > MAX_TOOL_BYTES
    ):
        _die(f"{context} source is not an exact executable")
    source = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(source)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
        ):
            _die(f"{context} source changed during capture")
        raw = _read_descriptor_bounded(source, maximum=MAX_TOOL_BYTES, context=context)
        after = os.fstat(source)
        if (after.st_dev, after.st_ino, after.st_mode, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
        ) or len(raw) != opened.st_size:
            _die(f"{context} source changed during capture")
    finally:
        os.close(source)
    if not hasattr(os, "memfd_create"):
        _die(f"{context} private executable capture is unavailable")
    descriptor = os.memfd_create(
        "z4j-production-verifier-tool",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _die(f"{context} private executable capture is incomplete")
            written += count
        os.fchmod(descriptor, 0o500)
        fcntl.fcntl(
            descriptor,
            LINUX_F_ADD_SEALS,
            LINUX_F_SEAL_WRITE | LINUX_F_SEAL_GROW | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_SEAL,
        )
        if (
            _read_descriptor_bounded(
                descriptor, maximum=MAX_TOOL_BYTES, context=f"captured {context}"
            )
            != raw
        ):
            _die(f"{context} private executable capture differs")
    except BaseException:
        os.close(descriptor)
        raise
    return _HeldExecutable(descriptor=descriptor, logical_path=path, raw=raw)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_held_executable(  # noqa: PLR0912, PLR0915
    tool: _HeldExecutable,
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    """Execute the sealed descriptor with bounded streams and whole-group teardown."""

    if tool.descriptor < 0 or timeout_seconds < 1 or timeout_seconds > 7200:
        _die("captured system-tool execution boundary differs")
    if any(not isinstance(argument, str) or "\0" in argument for argument in arguments):
        _die("captured system-tool argument differs")
    directory = os.open(
        cwd,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    directory_before = os.fstat(directory)
    argv = [str(tool.logical_path), *arguments]
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    try:
        process = subprocess.Popen(  # noqa: S603 - exact sealed fd, no shell
            argv,
            executable=f"/proc/self/fd/{tool.descriptor}",
            cwd=f"/proc/self/fd/{directory}",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(tool.descriptor, directory),
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        streams = {process.stdout: stdout, process.stderr: stderr}
        selector = selectors.DefaultSelector()
        try:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout_seconds
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _kill_process_group(process)
                    _die("captured system-tool command timed out")
                for key, _mask in selector.select(min(remaining, 1.0)):
                    stream = next(
                        candidate for candidate in streams if candidate.fileno() == key.fd
                    )
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    streams[stream].extend(chunk)
                    if len(streams[stream]) > MAX_TOOL_OUTPUT_BYTES:
                        _kill_process_group(process)
                        _die("captured system-tool output exceeds its reviewed bound")
        finally:
            selector.close()
        returncode = process.wait(timeout=max(1.0, deadline - time.monotonic()))
        directory_after = os.fstat(directory)
        if (
            directory_after.st_dev,
            directory_after.st_ino,
            directory_after.st_mode,
        ) != (
            directory_before.st_dev,
            directory_before.st_ino,
            directory_before.st_mode,
        ):
            _die("captured system-tool working directory changed")
        if (
            _read_descriptor_bounded(
                tool.descriptor,
                maximum=MAX_TOOL_BYTES,
                context="captured system tool after execution",
            )
            != tool.raw
        ):
            _die("captured system-tool bytes changed during execution")
    except subprocess.TimeoutExpired:
        assert process is not None
        _kill_process_group(process)
        _die("captured system-tool command timed out")
    finally:
        if process is not None and process.poll() is None:
            _kill_process_group(process)
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        os.close(directory)
    return subprocess.CompletedProcess(argv, returncode, bytes(stdout), bytes(stderr))


def _verify_system_tooling(  # noqa: PLR0912
    *,
    root: Path,
    source_by_name: dict[str, dict[str, Any]],
    packages: list[dict[str, Any]],
    resolution: dict[str, Any],
    apt_get_path: Path,
    gpgv_path: Path,
    dpkg_deb_path: Path,
) -> None:
    """Run all apt/gpgv/dpkg checks from one fd-held private tool snapshot."""

    paths = {"apt": apt_get_path, "gpgv": gpgv_path, "dpkg_deb": dpkg_deb_path}
    captured: dict[str, _HeldExecutable] = {}
    try:
        for name, path in paths.items():
            captured[name] = _capture_executable(path, context=f"system {name} binary")

        for source_name, source in source_by_name.items():
            prefix = root / "snapshot" / source_name
            result = _run_held_executable(
                captured["gpgv"],
                (
                    "--status-fd",
                    "1",
                    "--keyring",
                    str(prefix / "archive-keyring.gpg"),
                    str(prefix / "InRelease"),
                ),
                cwd=root,
            )
            try:
                stdout = result.stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ContractError(f"gpgv output is not UTF-8 for {source_name}") from exc
            valid_fingerprints = sorted(
                {
                    line.split()[2]
                    for line in stdout.splitlines()
                    if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
                }
            )
            if result.returncode != 0 or valid_fingerprints != source["archive_key_fingerprints"]:
                _die(f"gpgv did not authenticate Debian {source_name} with its audited keys")

        for package in packages:
            deb = root / "debs" / package["filename"]
            inspected = _run_held_executable(
                captured["dpkg_deb"],
                (
                    "--show",
                    "--showformat=${Package}\n${Version}\n${Architecture}\n",
                    str(deb),
                ),
                cwd=root,
            )
            try:
                identity_lines = inspected.stdout.decode("utf-8", errors="strict").splitlines()
            except UnicodeDecodeError as exc:
                raise ContractError(
                    f"dpkg-deb identity output is not UTF-8: {package['name']}"
                ) from exc
            if inspected.returncode != 0 or identity_lines != [
                package["name"],
                package["version"],
                package["architecture"],
            ]:
                _die(f".deb control identity differs from the lock: {package['name']}")
            control = package["control"]
            retained_control = _read_bytes(
                root / "controls" / control["path"],
                maximum=MAX_FILE_BYTES,
                context=f"retained Debian control {package['name']}",
            )
            field = _run_held_executable(captured["dpkg_deb"], ("--field", str(deb)), cwd=root)
            control_identity = _debian_control_record(
                retained_control, f"retained Debian control {package['name']}"
            )
            if (
                field.returncode != 0
                or field.stderr
                or field.stdout != retained_control
                or _sha256(retained_control) != control["sha256"]
                or len(retained_control) != control["size"]
                or control_identity
                != {
                    "architecture": package["architecture"],
                    "depends": package["depends"],
                    "essential": package["essential"],
                    "name": package["name"],
                    "pre_depends": package["pre_depends"],
                    "provides": package["provides"],
                    "version": package["version"],
                }
            ):
                _die(f".deb full control differs from the lock: {package['name']}")

        tool_names = {"apt": "apt-get", "gpgv": "gpgv", "dpkg_deb": "dpkg-deb"}
        for tool_name, arguments in {
            "apt": ("--version",),
            "gpgv": ("--version",),
            "dpkg_deb": ("--version",),
        }.items():
            authority = _require_object(resolution[tool_name], f"system {tool_name} authority")
            _require_exact_keys(
                authority,
                {"name", "version", "binary_sha256", "version_output_sha256"},
                f"system {tool_name} authority",
            )
            if (
                authority["name"] != tool_names[tool_name]
                or not isinstance(authority["version"], str)
                or not authority["version"]
                or _sha256(captured[tool_name].raw)
                != _require_hex(authority["binary_sha256"], f"system {tool_name} binary")
            ):
                _die(f"system {tool_name} binary/identity differs")
            version = _run_held_executable(captured[tool_name], arguments, cwd=root)
            if version.returncode != 0 or _sha256(version.stdout + version.stderr) != _require_hex(
                authority["version_output_sha256"],
                f"system {tool_name} version transcript",
            ):
                _die(f"system {tool_name} version transcript differs")
    finally:
        for tool in captured.values():
            tool.close()


def verify_system_bundle(  # noqa: PLR0912, PLR0915
    manifest: dict[str, Any],
    root: Path,
    contract_root: Path,
    platform: str,
    apt_get_path: Path,
    gpgv_path: Path,
    dpkg_deb_path: Path,
) -> None:
    system = manifest["system_packages"]
    info = system["platforms"][platform]

    def allowed(path: str) -> bool:
        return (
            path
            in {
                "locks/packages.json",
                "evidence/resolution-receipt.json",
                "evidence/installability-receipt.json",
                "evidence/advisory-receipt.json",
                "evidence/advisory-report.json",
                "evidence/trivy",
                "evidence/trivy-version.txt",
                "evidence/sources.list",
                "evidence/apt.conf",
                "evidence/os-release",
            }
            or (
                path.startswith("controls/")
                and path.endswith(".deb.control")
                and path.count("/") == 1
            )
            or path.startswith("evidence/trivy-database/")
            or (path.startswith("debs/") and path.endswith(".deb") and path.count("/") == 1)
            or any(
                path
                in {
                    f"snapshot/{source['name']}/InRelease",
                    f"snapshot/{source['name']}/Release",
                    f"snapshot/{source['name']}/archive-keyring.gpg",
                }
                or path.startswith(f"snapshot/{source['name']}/indexes/")
                for source in system["snapshot"]["sources"]
            )
        )

    records = _verify_bundle_inventory(
        root=root,
        platform=platform,
        inventory_format="z4j-production-system-inventory-v1",
        tree_format="z4j-production-system-tree-v1",
        inventory_sha256=info["inventory_sha256"],
        inventory_size=info["inventory_size"],
        inventory_entries=info["inventory_entries"],
        tree_sha256=info["tree_sha256"],
        tree_bytes=info["tree_bytes"],
        allowed=allowed,
    )
    lock_path = contract_root / info["package_lock"]["path"]
    tracked_lock = _read_bytes(lock_path, maximum=MAX_LOCK_BYTES, context="tracked system lock")
    bundled_lock = _read_bytes(
        root / "locks/packages.json", maximum=MAX_LOCK_BYTES, context="bundled system lock"
    )
    if tracked_lock != bundled_lock:
        _die("tracked and bundled system package locks differ")
    lock, _ = _load_json(lock_path, maximum=MAX_LOCK_BYTES)
    if tracked_lock != _canonical(lock) + b"\n":
        _die("system package lock is not canonical JSON plus one newline")
    if (
        _sha256(tracked_lock) != info["package_lock"]["sha256"]
        or len(tracked_lock) != info["package_lock"]["size"]
    ):
        _die("system package lock seal differs")
    _require_exact_keys(
        lock,
        {
            "format",
            "platform",
            "snapshot_selection_utc",
            "sources",
            "requested",
            "indexes",
            "packages",
        },
        "system package lock",
    )
    if (
        lock["format"] != "z4j-production-debian-package-lock-v1"
        or lock["platform"] != platform
        or lock["snapshot_selection_utc"] != system["snapshot"]["selection_utc"]
        or lock["sources"] != system["snapshot"]["sources"]
        or lock["requested"] != EXPECTED_SYSTEM_REQUESTED
    ):
        _die("system package lock context differs")
    packages = lock["packages"]
    if not isinstance(packages, list) or len(packages) != info["package_lock"]["entries"]:
        _die("system package lock entry count differs")
    expected_arch = {"linux/amd64": "amd64", "linux/arm64": "arm64"}[platform]
    exact_index_path = f"main/binary-{expected_arch}/Packages"
    seen_names: set[str] = set()
    expected_debs: set[str] = set()
    expected_controls: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            _die("system package record is malformed")
        _require_exact_keys(
            package,
            {
                "name",
                "version",
                "architecture",
                "filename",
                "source",
                "repository_filename",
                "index_path",
                "sha256",
                "size",
                "depends",
                "pre_depends",
                "provides",
                "essential",
                "index_stanza_sha256",
                "control",
            },
            "system package record",
        )
        name = package["name"]
        filename = package["filename"]
        control = _require_object(package["control"], f"system package {name} control")
        _require_exact_keys(control, {"path", "sha256", "size"}, "system package control")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is None
            or name in seen_names
            or not isinstance(package["version"], str)
            or not package["version"]
            or package["architecture"] not in {expected_arch, "all"}
            or not isinstance(filename, str)
            or PurePosixPath(filename).name != filename
            or not filename.endswith(".deb")
            or package["source"] not in {source["name"] for source in system["snapshot"]["sources"]}
            or not isinstance(package["repository_filename"], str)
            or PurePosixPath(package["repository_filename"]).is_absolute()
            or ".." in PurePosixPath(package["repository_filename"]).parts
            or package["index_path"] != exact_index_path
            or any(
                value is not None and not isinstance(value, str)
                for value in (
                    package["depends"],
                    package["pre_depends"],
                    package["provides"],
                    package["essential"],
                )
            )
            or control["path"] != filename + ".control"
            or PurePosixPath(control["path"]).name != control["path"]
        ):
            _die("system package identity is unsafe, duplicate, or wrong-platform")
        _require_hex(package["index_stanza_sha256"], "system package index stanza")
        _require_hex(control["sha256"], "system package control")
        _require_size(control["size"], "system package control size")
        seen_names.add(name)
        relative = f"debs/{filename}"
        expected_debs.add(relative)
        expected_controls.add(f"controls/{control['path']}")
        record = records.get(relative)
        if (
            record is None
            or package["sha256"] != record["sha256"]
            or package["size"] != record["size"]
        ):
            _die(f"system package payload differs: {name}")
        control_record = records.get(f"controls/{control['path']}")
        if (
            control_record is None
            or control_record["sha256"] != control["sha256"]
            or control_record["size"] != control["size"]
        ):
            _die(f"system package control payload differs: {name}")
    actual_debs = {path for path in records if path.startswith("debs/")}
    actual_controls = {path for path in records if path.startswith("controls/")}
    if (
        expected_debs != actual_debs
        or expected_controls != actual_controls
        or not set(EXPECTED_SYSTEM_REQUESTED).issubset(seen_names)
    ):
        _die("system .deb closure differs from its exact package lock")
    snapshot = system["snapshot"]
    source_by_name = {source["name"]: source for source in snapshot["sources"]}
    index_locks = lock["indexes"]
    expected_index_identities = {(source_name, exact_index_path) for source_name in source_by_name}
    if not isinstance(index_locks, list) or len(index_locks) != len(source_by_name):
        _die("system package lock has no authenticated source indexes")
    expected_indexes: dict[tuple[str, str], dict[str, Any]] = {}
    previous_index: tuple[str, str] | None = None
    for index in index_locks:
        if not isinstance(index, dict):
            _die("system package index lock is malformed")
        _require_exact_keys(index, {"source", "path", "sha256", "size"}, "system index lock")
        identity = (index["source"], index["path"])
        if (
            index["source"] not in source_by_name
            or index["path"] != exact_index_path
            or (previous_index is not None and identity <= previous_index)
        ):
            _die("system package index locks are invalid, duplicate, or unsorted")
        previous_index = identity
        _require_hex(index["sha256"], "system package index")
        _require_size(index["size"], "system package index size")
        expected_indexes[identity] = index
    if set(expected_indexes) != expected_index_identities:
        _die("system package index source/path matrix differs")

    parsed_indexes: dict[tuple[str, str], list[dict[str, str]]] = {}
    for source_name, source in source_by_name.items():
        prefix = f"snapshot/{source_name}"
        for basename, digest_key, size_key in (
            ("InRelease", "inrelease_sha256", "inrelease_size"),
            ("Release", "release_sha256", "release_size"),
            ("archive-keyring.gpg", "archive_keyring_sha256", "archive_keyring_size"),
        ):
            relative = f"{prefix}/{basename}"
            record = records.get(relative)
            if (
                record is None
                or record["sha256"] != source[digest_key]
                or record["size"] != source[size_key]
            ):
                _die(f"Debian {source_name} evidence differs: {relative}")
        inrelease_raw = _read_bytes(
            root / prefix / "InRelease",
            maximum=MAX_FILE_BYTES,
            context=f"Debian {source_name} InRelease",
        )
        release_raw = _read_bytes(
            root / prefix / "Release",
            maximum=MAX_FILE_BYTES,
            context=f"Debian {source_name} Release",
        )
        if _clearsigned_payload(inrelease_raw) != release_raw:
            _die(f"Debian {source_name} InRelease signed payload differs from Release bytes")
        release_headers, release_seals = _release_metadata(release_raw)
        try:
            release_date = email.utils.parsedate_to_datetime(release_headers["Date"])
        except (TypeError, ValueError) as exc:
            raise ContractError(f"Debian {source_name} Release Date is malformed") from exc
        if release_date.tzinfo is None:
            _die(f"Debian {source_name} Release Date is not timezone-aware")
        release_date = release_date.astimezone(dt.UTC)
        source_time = _receipt_time(
            source["timestamp_utc"], f"Debian {source_name} snapshot timestamp"
        )
        release_architectures = set(release_headers["Architectures"].split())
        release_components = set(release_headers["Components"].split())
        if (
            release_headers["Codename"] != source["suite"]
            or release_headers["Suite"] != source["release_suite"]
            or expected_arch not in release_architectures
            or not set(source["components"]).issubset(release_components)
            or release_date > source_time
        ):
            _die(f"Debian {source_name} Release identity/freshness differs")
        valid_until_raw = release_headers.get("Valid-Until")
        if valid_until_raw is not None:
            try:
                valid_until = email.utils.parsedate_to_datetime(valid_until_raw)
            except (TypeError, ValueError) as exc:
                raise ContractError(
                    f"Debian {source_name} Release Valid-Until is malformed"
                ) from exc
            if valid_until.tzinfo is None or source_time > valid_until.astimezone(dt.UTC):
                _die(f"Debian {source_name} Release was expired at its snapshot")
        source_indexes = {
            path.removeprefix(f"{prefix}/indexes/")
            for path in records
            if path.startswith(f"{prefix}/indexes/")
        }
        expected_source_indexes = {
            path for locked_source, path in expected_indexes if locked_source == source_name
        }
        if source_indexes != expected_source_indexes:
            _die(f"Debian {source_name} index payload set differs from the package lock")
        for index_path in sorted(source_indexes):
            relative = f"{prefix}/indexes/{index_path}"
            record = records[relative]
            locked = expected_indexes[(source_name, index_path)]
            if (
                release_seals.get(index_path) != (record["sha256"], record["size"])
                or locked["sha256"] != record["sha256"]
                or locked["size"] != record["size"]
            ):
                _die(f"Debian {source_name} Release does not authenticate {index_path}")
            parsed_indexes[(source_name, index_path)] = _debian_package_index(
                _read_bytes(root / relative, maximum=MAX_FILE_BYTES, context=relative),
                relative,
            )
    for package in packages:
        matches = [
            record
            for record in parsed_indexes[(package["source"], str(package["index_path"]))]
            if record["Package"] == package["name"]
            and record["Version"] == package["version"]
            and record["Architecture"] == package["architecture"]
            and record["Filename"] == package["repository_filename"]
            and record["SHA256"] == package["sha256"]
            and record["Size"] == str(package["size"])
            and record["Depends"] == package["depends"]
            and record["Pre-Depends"] == package["pre_depends"]
            and record["Provides"] == package["provides"]
            and record["Essential"] == package["essential"]
            and record["Stanza-SHA256"] == package["index_stanza_sha256"]
        ]
        if len(matches) != 1:
            _die(
                f"Debian package is absent or ambiguous in authenticated indexes: {package['name']}"
            )

    resolution, resolution_raw = _load_json(root / "evidence/resolution-receipt.json")
    resolution = _require_object(resolution, "system resolution receipt")
    for relative, digest_key, size_key in (
        (
            "evidence/resolution-receipt.json",
            "resolution_receipt_sha256",
            "resolution_receipt_size",
        ),
        (
            "evidence/installability-receipt.json",
            "installability_receipt_sha256",
            "installability_receipt_size",
        ),
        (
            "evidence/advisory-receipt.json",
            "advisory_receipt_sha256",
            "advisory_receipt_size",
        ),
    ):
        record = records.get(relative)
        if (
            record is None
            or record["sha256"] != info[digest_key]
            or record["size"] != info[size_key]
        ):
            _die(f"system evidence differs: {relative}")
    expected_sources_list = _debian_sources_list(snapshot)
    expected_apt_config = _debian_apt_config()
    for relative, expected in (
        ("evidence/sources.list", expected_sources_list),
        ("evidence/apt.conf", expected_apt_config),
    ):
        actual = _read_bytes(root / relative, maximum=MAX_FILE_BYTES, context=relative)
        if actual != expected:
            _die(f"system resolver input differs: {relative}")
    if resolution_raw != _canonical(resolution) + b"\n":
        _die("system resolution receipt is not canonical JSON")
    _require_exact_keys(
        resolution,
        {
            "format",
            "platform",
            "snapshot",
            "package_lock_sha256",
            "apt",
            "gpgv",
            "isolation",
            "dpkg_deb",
            "sources_list_sha256",
            "apt_config_sha256",
            "commands",
            "exit_code",
            "list_state",
            "solver_plan",
        },
        "system resolution receipt",
    )
    if (
        resolution["format"] != "z4j-production-debian-resolution-v1"
        or resolution["platform"] != platform
        or resolution["snapshot"] != snapshot
        or resolution["package_lock_sha256"] != info["package_lock"]["sha256"]
        or resolution["sources_list_sha256"] != _sha256(expected_sources_list)
        or resolution["apt_config_sha256"] != _sha256(expected_apt_config)
        or resolution["commands"] != _isolated_apt_commands(platform)
        or resolution["isolation"]
        != {
            "ambient_dpkg_status_used": False,
            "architecture": {"linux/amd64": "amd64", "linux/arm64": "arm64"}[platform],
            "archives_initially_empty": True,
            "empty_status_sha256": _sha256(b""),
            "empty_status_size": 0,
            "lists_initially_empty": True,
            "state_root": "/tmp/z4j-production-system-apt",  # noqa: S108
            "trusted": "-",
            "trusted_parts": "-",
        }
        or resolution["exit_code"] != 0
    ):
        _die("system resolution receipt bindings differ")
    list_state = resolution["list_state"]
    if not isinstance(list_state, list):
        _die("system resolution list-state projection is malformed")
    # Flatten explicitly so the authority is independent of apt's generated list filename.
    expected_list_seals = sorted(
        [
            seal
            for source in snapshot["sources"]
            for seal in (
                (
                    source["name"],
                    "InRelease",
                    source["inrelease_sha256"],
                    source["inrelease_size"],
                ),
                (
                    source["name"],
                    "Packages",
                    expected_indexes[(source["name"], exact_index_path)]["sha256"],
                    expected_indexes[(source["name"], exact_index_path)]["size"],
                ),
            )
        ],
        key=lambda item: (item[0].encode(), item[1].encode()),
    )
    observed_list_seals: list[tuple[str, str, str, int]] = []
    observed_list_paths: set[str] = set()
    for raw_item in list_state:
        item = _require_object(raw_item, "system apt list-state record")
        _require_exact_keys(
            item,
            {"path", "mode", "sha256", "size", "kind", "source"},
            "system apt list-state record",
        )
        path = item["path"]
        if (
            not isinstance(path, str)
            or not path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or path in observed_list_paths
            or item["mode"] not in {"0600", "0644"}
            or item["kind"] not in {"InRelease", "Packages"}
            or item["source"] not in source_by_name
        ):
            _die("system apt list-state path/mode/identity differs")
        observed_list_paths.add(path)
        observed_list_seals.append(
            (
                item["source"],
                item["kind"],
                _require_hex(item["sha256"], "system apt list state"),
                _require_size(item["size"], "system apt list state size"),
            )
        )
    observed_list_seals.sort(key=lambda item: (item[0].encode(), item[1].encode()))
    if observed_list_seals != expected_list_seals:
        _die("system apt list-state projection differs from retained signed inputs")
    expected_solver_plan = sorted(
        ({"name": package["name"], "version": package["version"]} for package in packages),
        key=lambda item: (item["name"].encode(), item["version"].encode()),
    )
    if resolution["solver_plan"] != expected_solver_plan:
        _die("system solver plan differs from the authenticated package closure")
    _verify_system_tooling(
        root=root,
        source_by_name=source_by_name,
        packages=packages,
        resolution=resolution,
        apt_get_path=apt_get_path,
        gpgv_path=gpgv_path,
        dpkg_deb_path=dpkg_deb_path,
    )
    for key in ("sources_list_sha256", "apt_config_sha256"):
        _require_hex(resolution[key], f"system resolution {key}")

    installability, installability_raw = _load_json(root / "evidence/installability-receipt.json")
    if installability_raw != _canonical(installability) + b"\n":
        _die("system real-base installability receipt is not canonical JSON")
    _require_exact_keys(
        installability,
        {
            "base_status",
            "commands",
            "format",
            "installed",
            "maintainer_scripts",
            "package_lock_sha256",
            "platform",
            "result",
        },
        "system real-base installability receipt",
    )
    base_status = _require_object(
        installability["base_status"], "system real-base status authority"
    )
    _require_exact_keys(
        base_status, {"path", "sha256", "size"}, "system real-base status authority"
    )
    _require_hex(base_status["sha256"], "system real-base status")
    _require_size(base_status["size"], "system real-base status size")
    expected_installed = sorted(
        (
            {
                "architecture": package["architecture"],
                "name": package["name"],
                "status": "install ok installed",
                "version": package["version"],
            }
            for package in packages
        ),
        key=lambda item: (item["name"].encode(), item["architecture"].encode()),
    )
    if (
        installability["format"] != "z4j-production-system-real-base-installability-v1"
        or installability["platform"] != platform
        or installability["package_lock_sha256"] != info["package_lock"]["sha256"]
        or installability["commands"]
        != _real_base_apt_commands(platform, [package["filename"] for package in packages])
        or installability["installed"] != expected_installed
        or installability["maintainer_scripts"] != "disposable-network-none-build-stage-only"
        or installability["result"] != "pass"
        or base_status["path"] != "/var/lib/dpkg/status"
    ):
        _die("system real-base installability receipt bindings differ")

    os_release = _read_bytes(
        root / "evidence/os-release", maximum=MAX_FILE_BYTES, context="system os-release"
    )
    if b"ID=debian\n" not in os_release or b"VERSION_CODENAME=trixie\n" not in os_release:
        _die("system os-release identity differs")
    advisory, advisory_raw = _load_json(root / "evidence/advisory-receipt.json")
    if advisory_raw != _canonical(advisory) + b"\n":
        _die("system advisory receipt is not canonical JSON")
    _require_exact_keys(
        advisory,
        {
            "format",
            "platform",
            "package_lock_sha256",
            "scanner",
            "database",
            "policy",
            "findings",
            "verdict",
            "report",
            "synthetic_status",
        },
        "system advisory receipt",
    )
    advisory_report = _require_object(advisory.get("report"), "system advisory report")
    _require_exact_keys(advisory_report, {"path", "sha256", "size"}, "system advisory report")
    synthetic_status = _require_object(
        advisory.get("synthetic_status"), "system synthetic dpkg status"
    )
    _require_exact_keys(synthetic_status, {"sha256", "size"}, "system synthetic dpkg status")
    report_record = records.get("evidence/advisory-report.json")
    if (
        advisory["format"] != "z4j-production-system-advisory-v1"
        or advisory["platform"] != platform
        or advisory["package_lock_sha256"] != info["package_lock"]["sha256"]
        or advisory["policy"]
        != {
            "severities": ["HIGH", "CRITICAL"],
            "ignore_unfixed": False,
            "list_all_packages": True,
            "required_result_type": "debian",
        }
        or advisory["findings"] != []
        or advisory["verdict"] != "pass"
        or advisory_report["path"] != "evidence/advisory-report.json"
        or report_record is None
        or advisory_report["sha256"] != report_record["sha256"]
        or advisory_report["size"] != report_record["size"]
    ):
        _die("system advisory receipt does not prove the exact clean policy")
    report, report_raw = _load_json(root / "evidence/advisory-report.json")
    _require_exact_keys(
        report,
        {"findings", "format", "packages", "platform", "result_type"},
        "system semantic advisory report",
    )
    expected_scanned_packages = sorted(
        ({"name": package["name"], "version": package["version"]} for package in packages),
        key=lambda item: (item["name"].encode(), item["version"].encode()),
    )
    if (
        _sha256(report_raw) != advisory_report["sha256"]
        or len(report_raw) != advisory_report["size"]
        or report_raw != _canonical(report) + b"\n"
        or report["format"] != "z4j-production-system-trivy-semantic-report-v1"
        or report["platform"] != platform
        or report["result_type"] != "debian"
        or report["findings"] != []
        or report["packages"] != expected_scanned_packages
        or len({item["name"] for item in expected_scanned_packages})
        != len(expected_scanned_packages)
    ):
        _die("system semantic advisory identity/coverage/findings differ")
    control_payloads: list[bytes] = []
    for package in packages:
        control_payload = _read_bytes(
            root / "controls" / package["control"]["path"],
            maximum=MAX_FILE_BYTES,
            context=f"system control {package['name']}",
        )
        lines = control_payload.splitlines(keepends=True)
        if not lines or not lines[0].startswith(b"Package: "):
            _die("system control Package field is not first")
        control_payloads.append(lines[0] + b"Status: install ok installed\n" + b"".join(lines[1:]))
    expected_status = b"\n".join(control_payloads)
    if (
        _sha256(expected_status) != synthetic_status["sha256"]
        or len(expected_status) != synthetic_status["size"]
    ):
        _die("system synthetic dpkg status differs from authenticated controls")
    _validate_scanner_database(advisory["scanner"], advisory["database"], "system advisory")
    _verify_retained_advisory_authority(
        root,
        records,
        advisory["scanner"],
        advisory["database"],
        "system advisory",
    )


def _pnpm_lock_components(raw: bytes) -> list[dict[str, Any]]:  # noqa: PLR0912,PLR0915
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("dashboard pnpm lock is not UTF-8") from exc
    if (
        "\r" in text
        or "\t" in text
        or text.count("\nimporters:\n") != 1
        or text.count("\npackages:\n") != 1
        or text.count("\nsnapshots:\n") != 1
        or text.index("\nimporters:\n") > text.index("\npackages:\n")
        or text.index("\npackages:\n") > text.index("\nsnapshots:\n")
    ):
        _die("dashboard pnpm lock framing is unsupported or ambiguous")
    if not text.startswith("lockfileVersion: '9.0'\n"):
        _die("dashboard pnpm lock must use exact lockfileVersion 9.0")

    def scalar(value: str, context: str) -> str:
        if value.startswith("'") or value.endswith("'"):
            if not (value.startswith("'") and value.endswith("'") and len(value) >= 2):
                _die(f"{context} quoting differs")
            value = value[1:-1].replace("''", "'")
        if (
            not value
            or value.strip() != value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            _die(f"{context} scalar differs")
        return value

    def blocks(section: str, context: str) -> list[tuple[str, list[str]]]:
        lines = section.split("\n")
        starts = [
            index for index, line in enumerate(lines) if re.fullmatch(r"  \S.*:(?: \{\})?", line)
        ]
        if not starts:
            _die(f"{context} is empty")
        covered: set[int] = set()
        result: list[tuple[str, list[str]]] = []
        for offset, start in enumerate(starts):
            stop = starts[offset + 1] if offset + 1 < len(starts) else len(lines)
            covered.update(range(start, stop))
            header = lines[start][2:]
            inline_empty = header.endswith(": {}")
            header = header[: -4 if inline_empty else -1]
            body = lines[start + 1 : stop]
            if inline_empty and any(line for line in body):
                _die(f"{context} inline-empty body differs")
            result.append((scalar(header, f"{context} key"), body))
        if any(line and index not in covered for index, line in enumerate(lines)):
            _die(f"{context} top-level framing differs")
        return result

    importer_section = text.split("\nimporters:\n", 1)[1].split("\npackages:\n", 1)[0]
    importers = blocks(importer_section, "dashboard pnpm importer set")
    if len(importers) != 1 or importers[0][0] != ".":
        _die("dashboard pnpm importer set is not the exact root importer")
    root_targets: dict[str, list[str]] = {}
    importer_fields: dict[tuple[str, str], set[str]] = {}
    importer_group: str | None = None
    importer_dependency: str | None = None
    for line in importers[0][1]:
        if not line:
            continue
        group_match = re.fullmatch(
            r"    (dependencies|devDependencies|optionalDependencies):", line
        )
        if group_match:
            importer_group = group_match.group(1)
            importer_dependency = None
            continue
        dependency_match = re.fullmatch(r"      (\S.*):", line)
        if dependency_match and importer_group is not None:
            importer_dependency = scalar(
                dependency_match.group(1), "dashboard pnpm importer dependency"
            )
            identity = (importer_group, importer_dependency)
            if identity in importer_fields:
                _die("dashboard pnpm importer dependency is duplicate")
            importer_fields[identity] = set()
            continue
        field_match = re.fullmatch(r"        (specifier|version): (\S.*)", line)
        if field_match and importer_group is not None and importer_dependency is not None:
            fields = importer_fields.get((importer_group, importer_dependency))
            if fields is None or field_match.group(1) in fields:
                _die("dashboard pnpm importer field is duplicate")
            fields.add(field_match.group(1))
            if field_match.group(1) == "version":
                version = scalar(
                    field_match.group(2),
                    f"dashboard pnpm importer {importer_dependency} version",
                )
                target = f"{importer_dependency}@{version}"
                roots = root_targets.setdefault(target, [])
                if importer_group in roots:
                    _die("dashboard pnpm importer target is duplicate")
                roots.append(importer_group)
            continue
        _die("dashboard pnpm root importer framing differs")
    if any(fields != {"specifier", "version"} for fields in importer_fields.values()):
        _die("dashboard pnpm importer dependency fields differ")
    if not root_targets:
        _die("dashboard pnpm root importer is empty")

    package_section = text.split("\npackages:\n", 1)[1].split("\nsnapshots:\n", 1)[0]
    packages: dict[str, dict[str, Any]] = {}
    for key, body in blocks(package_section, "dashboard pnpm package universe"):
        if key.count("@") < 1 or "(" in key:
            _die(f"dashboard pnpm package key has no exact version: {key!r}")
        name, version = key.rsplit("@", 1)
        if not name or not version or key in packages:
            _die(f"dashboard pnpm package identity is malformed: {key!r}")
        integrity_matches: list[str] = []
        for line in body:
            match = re.search(
                r"(?:^|[,{])integrity: (sha512-[A-Za-z0-9+/=]+)(?:[,}]|$)",
                line.strip(),
            )
            if match:
                integrity_matches.append(match.group(1))
        if len(integrity_matches) != 1:
            _die(f"dashboard pnpm package has absent/ambiguous SHA-512 integrity: {key}")
        integrity = integrity_matches[0]
        try:
            decoded = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ContractError(f"dashboard pnpm integrity is invalid: {key}") from exc
        if len(decoded) != 64:
            _die(f"dashboard pnpm integrity is wrong-sized or duplicate: {key}")
        constraints: dict[str, list[str] | None] = {}
        for constraint_field in ("cpu", "libc", "os"):
            matches = [
                match.group(1)
                for line in body
                if (match := re.fullmatch(rf"{constraint_field}: \[([^\]]*)\]", line.strip()))
            ]
            if len(matches) > 1:
                _die(f"dashboard pnpm {constraint_field} constraint is ambiguous: {key}")
            if not matches:
                constraints[constraint_field] = None
                continue
            values = [item.strip() for item in matches[0].split(",")]
            if len(values) != len(set(values)) or any(
                re.fullmatch(r"!?[a-z0-9_-]+", item) is None for item in values
            ):
                _die(f"dashboard pnpm {constraint_field} constraint differs: {key}")
            constraints[constraint_field] = values
        packages[key] = {
            "cpu": constraints["cpu"],
            "integrity_sha512": integrity,
            "libc": constraints["libc"],
            "name": name,
            "os": constraints["os"],
            "version": version,
        }

    def dependency_target(name_raw: str, version_raw: str, context: str) -> str:
        name = scalar(name_raw, f"{context} name")
        version = scalar(version_raw, f"{context} version")
        if version.startswith(("file:", "link:", "workspace:")):
            _die(f"{context} uses a non-registry target")
        return f"{name}@{version}"

    snapshot_section = text.split("\nsnapshots:\n", 1)[1]
    snapshots: dict[str, dict[str, Any]] = {}
    for key, body in blocks(snapshot_section, "dashboard pnpm snapshot graph"):
        if key in snapshots:
            _die(f"dashboard pnpm snapshot is duplicate: {key}")
        package_key = key.split("(", 1)[0]
        metadata = packages.get(package_key)
        if metadata is None:
            _die(f"dashboard pnpm snapshot has no package metadata: {key}")
        dependencies: list[str] = []
        optional_dependencies: list[str] = []
        transitive_peers: list[str] = []
        field: str | None = None
        optional = False
        for line in body:
            if not line:
                continue
            field_match = re.fullmatch(
                r"    (dependencies|optionalDependencies|transitivePeerDependencies):",
                line,
            )
            if field_match:
                field = field_match.group(1)
                continue
            if line == "    optional: true":
                if optional:
                    _die(f"dashboard pnpm snapshot optional marker is duplicate: {key}")
                optional = True
                field = None
                continue
            edge_match = re.fullmatch(r"      (\S.*): (\S.*)", line)
            if edge_match and field in {"dependencies", "optionalDependencies"}:
                target = dependency_target(
                    edge_match.group(1), edge_match.group(2), f"dashboard pnpm snapshot {key}"
                )
                (dependencies if field == "dependencies" else optional_dependencies).append(target)
                continue
            peer_match = re.fullmatch(r"      - (\S.*)", line)
            if peer_match and field == "transitivePeerDependencies":
                transitive_peers.append(
                    scalar(
                        peer_match.group(1),
                        f"dashboard pnpm snapshot {key} transitive peer",
                    )
                )
                continue
            _die(f"dashboard pnpm snapshot framing differs: {key}")
        for values in (dependencies, optional_dependencies, transitive_peers):
            if len(values) != len(set(values)):
                _die(f"dashboard pnpm snapshot edge is duplicate: {key}")
            values.sort(key=str.encode)
        snapshots[key] = {
            **metadata,
            "dependencies": dependencies,
            "key": key,
            "optional": optional,
            "optional_dependencies": optional_dependencies,
            "package_key": package_key,
            "root_groups": sorted(root_targets.get(key, [])),
            "transitive_peer_dependencies": transitive_peers,
        }
    represented_packages = {item["package_key"] for item in snapshots.values()}
    if any(key not in represented_packages for key in packages):
        _die("dashboard pnpm package universe has no exact snapshot instance")
    for target in root_targets:
        if target not in snapshots:
            _die(f"dashboard pnpm importer target is dangling: {target}")
    for item in snapshots.values():
        for target in (*item["dependencies"], *item["optional_dependencies"]):
            if target not in snapshots:
                _die(f"dashboard pnpm snapshot edge is dangling: {target}")
    return sorted(snapshots.values(), key=lambda item: item["key"].encode())


def _pnpm_platform_components(
    components: list[dict[str, Any]], platform: str
) -> list[dict[str, Any]]:
    cpu = {"linux/amd64": "x64", "linux/arm64": "arm64"}[platform]

    def permits(values: list[str] | None, target: str) -> bool:
        if values is None:
            return True
        positives = [value for value in values if not value.startswith("!")]
        return f"!{target}" not in values and (not positives or target in positives)

    by_key = {item["key"]: item for item in components}
    if len(by_key) != len(components):
        _die("dashboard pnpm snapshot graph contains duplicate instances")
    queue = [
        {
            "optional": all(group == "optionalDependencies" for group in item["root_groups"]),
            "target": item["key"],
        }
        for item in components
        if item["root_groups"]
    ]
    if not queue:
        _die("dashboard pnpm native realization has no root importer targets")
    selected_keys: set[str] = set()
    while queue:
        edge = queue.pop(0)
        component = by_key.get(edge["target"])
        if component is None:
            _die(f"dashboard pnpm native realization edge is dangling: {edge['target']}")
        compatible = (
            permits(component["os"], "linux")
            and permits(component["cpu"], cpu)
            and permits(component["libc"], "glibc")
        )
        if not compatible:
            if edge["optional"] or component["optional"]:
                continue
            _die(
                f"dashboard pnpm required snapshot is incompatible with {platform}: "
                f"{component['key']}"
            )
        if component["key"] in selected_keys:
            continue
        selected_keys.add(component["key"])
        queue.extend({"optional": False, "target": target} for target in component["dependencies"])
        queue.extend(
            {"optional": True, "target": target} for target in component["optional_dependencies"]
        )
    selected = [item for item in components if item["key"] in selected_keys]
    if not selected:
        _die("dashboard pnpm native realization is empty")
    return selected


def verify_dashboard_bundle(  # noqa: PLR0912, PLR0915
    manifest: dict[str, Any], root: Path, repo_root: Path, platform: str
) -> None:
    dashboard = manifest["dashboard"]
    info = dashboard["platforms"][platform]

    def allowed(path: str) -> bool:
        return path.startswith(("dist/", "store/", "evidence/trivy-database/")) or path in {
            "bin/pnpm.cjs",
            "evidence/pnpm-lock.yaml",
            "evidence/pnpm-archive.tgz",
            "evidence/pnpm-registry.json",
            "evidence/store-inventory.json",
            "evidence/build-receipt.json",
            "evidence/sbom.cyclonedx.json",
            "evidence/advisory-receipt.json",
            "evidence/advisory-report.json",
            "evidence/trivy",
            "evidence/trivy-version.txt",
            "evidence/pnpm-release.json",
        }

    records = _verify_bundle_inventory(
        root=root,
        platform=platform,
        inventory_format="z4j-production-dashboard-inventory-v1",
        tree_format="z4j-production-dashboard-tree-v1",
        inventory_sha256=info["inventory_sha256"],
        inventory_size=info["inventory_size"],
        inventory_entries=info["inventory_entries"],
        tree_sha256=info["tree_sha256"],
        tree_bytes=info["tree_bytes"],
        allowed=allowed,
    )
    layout, roots = _detect_layout(repo_root)
    del layout
    source_lock = _read_bytes(
        roots["z4j"] / "dashboard/pnpm-lock.yaml",
        maximum=MAX_LOCK_BYTES,
        context="dashboard source pnpm lock",
    )
    bundled_lock = _read_bytes(
        root / "evidence/pnpm-lock.yaml",
        maximum=MAX_LOCK_BYTES,
        context="dashboard bundled pnpm lock",
    )
    if source_lock != bundled_lock or _sha256(source_lock) != info["pnpm_lock_sha256"]:
        _die("dashboard source and bundled pnpm locks differ")
    lock_components = _pnpm_lock_components(source_lock)
    pnpm_release, pnpm_release_raw = _load_json(root / "evidence/pnpm-release.json")
    if pnpm_release_raw != _canonical(pnpm_release) + b"\n":
        _die("dashboard pnpm release receipt is not canonical JSON")
    _require_exact_keys(
        pnpm_release,
        {
            "format",
            "version",
            "filename",
            "url",
            "archive_members_bytes",
            "archive_members_entries",
            "archive_members_sha256",
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "registry_response",
            "published_at_utc",
        },
        "dashboard pnpm release receipt",
    )
    if (
        pnpm_release["format"] != "z4j-production-pnpm-release-v1"
        or pnpm_release["version"] != "11.22.0"
        or pnpm_release["filename"] != "pnpm-11.22.0.tgz"
        or pnpm_release["url"] != "https://registry.npmjs.org/pnpm/-/pnpm-11.22.0.tgz"
        or pnpm_release["archive_sha256"] != dashboard["pnpm"]["archive_sha256"]
        or pnpm_release["archive_size"] != dashboard["pnpm"]["archive_size"]
        or pnpm_release["binary_sha256"] != dashboard["pnpm"]["binary_sha256"]
        or pnpm_release["binary_size"] != dashboard["pnpm"]["binary_size"]
    ):
        _die("dashboard pnpm release authority differs")
    _require_hex(pnpm_release["archive_members_sha256"], "dashboard pnpm archive members")
    _require_count(pnpm_release["archive_members_entries"], "dashboard pnpm archive members")
    _require_size(pnpm_release["archive_members_bytes"], "dashboard pnpm archive member bytes")
    pnpm_archive_record = records.get("evidence/pnpm-archive.tgz")
    pnpm_binary_record = records.get("bin/pnpm.cjs")
    if (
        pnpm_archive_record is None
        or pnpm_binary_record is None
        or pnpm_archive_record["sha256"] != pnpm_release["archive_sha256"]
        or pnpm_archive_record["size"] != pnpm_release["archive_size"]
        or pnpm_binary_record["sha256"] != pnpm_release["binary_sha256"]
        or pnpm_binary_record["size"] != pnpm_release["binary_size"]
    ):
        _die("dashboard pnpm archive/binary payload differs")
    registry_seal = _require_object(
        pnpm_release["registry_response"], "dashboard pnpm registry response"
    )
    _require_exact_keys(
        registry_seal, {"path", "sha256", "size"}, "dashboard pnpm registry response"
    )
    registry_record = records.get("evidence/pnpm-registry.json")
    if (
        registry_seal["path"] != "evidence/pnpm-registry.json"
        or registry_record is None
        or registry_seal["sha256"] != registry_record["sha256"]
        or registry_seal["size"] != registry_record["size"]
    ):
        _die("dashboard pnpm registry response seal differs")
    if _receipt_time(
        pnpm_release["published_at_utc"], "dashboard pnpm publication"
    ) >= _receipt_time(FINALIZATION_CUTOFF, "production selection cutoff"):
        _die("dashboard pnpm release post-dates the dependency cutoff")
    pnpm_archive_raw = _read_bytes(
        root / "evidence/pnpm-archive.tgz",
        maximum=MAX_FILE_BYTES,
        context="dashboard pnpm archive",
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(pnpm_archive_raw), mode="r:gz") as archive:
            members = archive.getmembers()
            semantic_members: list[dict[str, Any]] = []
            seen_members: dict[str, str] = {}
            for member in members:
                raw_name = member.name
                normalized = raw_name.removesuffix("/")
                pure = PurePosixPath(normalized)
                member_type = "directory" if member.isdir() else "file" if member.isreg() else None
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or not normalized
                    or raw_name.startswith("./")
                    or "//" in raw_name
                    or "\\" in raw_name
                    or pure.as_posix() != normalized
                    or member_type is None
                    or member.mode & 0o7000
                    or normalized in seen_members
                    or any(
                        seen_members.get("/".join(pure.parts[:position])) == "file"
                        for position in range(1, len(pure.parts))
                    )
                    or (
                        member_type == "file"
                        and any(path.startswith(normalized + "/") for path in seen_members)
                    )
                ):
                    _die("dashboard pnpm archive contains an unsafe entry")
                seen_members[normalized] = member_type
                semantic_members.append(
                    {
                        "mode": f"{member.mode:04o}",
                        "path": normalized,
                        "size": member.size,
                        "type": member_type,
                    }
                )
            selected = [member for member in members if member.name == "package/bin/pnpm.cjs"]
            if len(selected) != 1 or selected[0].size > MAX_FILE_BYTES:
                _die("dashboard pnpm archive omits its exact binary")
            stream = archive.extractfile(selected[0])
            if stream is None:
                _die("dashboard pnpm archive binary cannot be read")
            archived_binary = stream.read(MAX_FILE_BYTES + 1)
    except (tarfile.TarError, OSError) as exc:
        raise ContractError("dashboard pnpm archive is invalid") from exc
    semantic_raw = _canonical(
        {"files": semantic_members, "format": "z4j-production-tar-members-v1"}
    )
    if (
        _sha256(semantic_raw) != pnpm_release["archive_members_sha256"]
        or len(semantic_members) != pnpm_release["archive_members_entries"]
        or sum(member["size"] for member in semantic_members)
        != pnpm_release["archive_members_bytes"]
    ):
        _die("dashboard pnpm semantic archive authority differs")
    if len(archived_binary) > MAX_FILE_BYTES or (
        _sha256(archived_binary),
        len(archived_binary),
    ) != (pnpm_binary_record["sha256"], pnpm_binary_record["size"]):
        _die("dashboard pnpm archive binary differs from bin/pnpm.cjs")
    registry, registry_raw = _load_json(root / "evidence/pnpm-registry.json")
    if (
        _sha256(registry_raw) != registry_seal["sha256"]
        or len(registry_raw) != registry_seal["size"]
    ):
        _die("dashboard pnpm registry response bytes differ")
    version_record = _require_object(
        (_require_object(registry.get("versions"), "pnpm registry versions")).get("11.22.0"),
        "pnpm 11.22.0 registry version",
    )
    dist = _require_object(version_record.get("dist"), "pnpm 11.22.0 dist")
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        _die("pnpm registry integrity is absent")
    try:
        expected_sha512 = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("pnpm registry integrity is malformed") from exc
    if (
        registry.get("name") != "pnpm"
        or version_record.get("version") != "11.22.0"
        or dist.get("tarball") != pnpm_release["url"]
        or hashlib.sha512(pnpm_archive_raw).digest() != expected_sha512
        or (_require_object(registry.get("time"), "pnpm registry time")).get("11.22.0")
        != pnpm_release["published_at_utc"]
    ):
        _die("pnpm registry version/tarball/integrity/publication differs")
    pnpm_release_record = records.get("evidence/pnpm-release.json")
    if (
        pnpm_release_record is None
        or pnpm_release_record["sha256"] != dashboard["pnpm"]["release_receipt_sha256"]
        or pnpm_release_record["size"] != dashboard["pnpm"]["release_receipt_size"]
    ):
        _die("dashboard pnpm release receipt seal differs")
    required_evidence = {
        "evidence/store-inventory.json": ("store_inventory_sha256", "store_inventory_size"),
        "evidence/build-receipt.json": ("build_receipt_sha256", "build_receipt_size"),
        "evidence/sbom.cyclonedx.json": ("sbom_sha256", "sbom_size"),
        "evidence/advisory-receipt.json": (
            "advisory_receipt_sha256",
            "advisory_receipt_size",
        ),
    }
    for relative, (digest_key, size_key) in required_evidence.items():
        record = records.get(relative)
        if (
            record is None
            or record["sha256"] != info[digest_key]
            or record["size"] != info[size_key]
        ):
            _die(f"dashboard evidence differs: {relative}")
    dist_records = [record for path, record in records.items() if path.startswith("dist/")]
    if not dist_records:
        _die("dashboard bundle contains no dist files")
    _verify_dashboard_build_markers(
        root / "dist", source_projection_sha256=dashboard["source_projection"]["sha256"]
    )
    dist_tree = {
        "format": "z4j-production-dashboard-dist-tree-v1",
        "files": dist_records,
    }
    if (
        _sha256(_canonical(dist_tree)) != info["bundle_tree_sha256"]
        or sum(int(record["size"]) for record in dist_records) != info["bundle_tree_bytes"]
    ):
        _die("dashboard dist tree differs")
    packaged_dist = roots["z4j"] / "backend/src/z4j_brain/dashboard/dist"
    if not packaged_dist.is_dir() or packaged_dist.is_symlink():
        _die("packaged dashboard dist is absent or nonregular")
    _verify_dashboard_build_markers(
        packaged_dist, source_projection_sha256=dashboard["source_projection"]["sha256"]
    )
    packaged_records = [
        _file_record(path, f"dist/{path.relative_to(packaged_dist).as_posix()}")
        for path in sorted(
            (entry for entry in packaged_dist.rglob("*") if entry.is_file() or entry.is_symlink()),
            key=lambda entry: entry.relative_to(packaged_dist).as_posix().encode("utf-8"),
        )
        if not path.name.endswith(".map")
    ]
    packaged_tree = {
        "format": "z4j-production-dashboard-dist-tree-v1",
        "files": packaged_records,
    }
    if (
        _sha256(_canonical(packaged_tree)) != info["bundle_tree_sha256"]
        or sum(int(record["size"]) for record in packaged_records) != info["bundle_tree_bytes"]
    ):
        _die("packaged Python dashboard dist differs from the sealed dashboard bundle")
    store, store_raw = _load_json(root / "evidence/store-inventory.json")
    if store_raw != _canonical(store) + b"\n":
        _die("dashboard store inventory is not canonical JSON")
    _require_exact_keys(
        store,
        {
            "format",
            "platform",
            "store_format",
            "store_tree_sha256",
            "store_tree_bytes",
            "installed",
            "lock_universe",
            "native_realization",
        },
        "dashboard store inventory",
    )
    lock_universe = store["lock_universe"]
    native_realization = store["native_realization"]
    installed = store["installed"]
    if (
        store["format"] != "z4j-production-pnpm-store-inventory-v1"
        or store["platform"] != platform
        or store["store_format"] != "pnpm-content-addressable-store-v10"
        or not isinstance(lock_universe, list)
        or not isinstance(native_realization, list)
        or not isinstance(installed, list)
        or not installed
    ):
        _die("dashboard store inventory context differs or is empty")
    retained_store_files = [
        {
            **{key: record[key] for key in ("mode", "size", "sha256")},
            "path": path.removeprefix("store/"),
        }
        for path, record in records.items()
        if path.startswith("store/")
    ]
    store_tree = {
        "format": "z4j-production-pnpm-store-tree-v1",
        "files": retained_store_files,
    }
    if (
        not retained_store_files
        or _require_hex(store["store_tree_sha256"], "dashboard pnpm store tree")
        != _sha256(_canonical(store_tree))
        or _require_size(store["store_tree_bytes"], "dashboard pnpm store bytes")
        != sum(int(record["size"]) for record in retained_store_files)
    ):
        _die("dashboard retained pnpm store tree differs from its inventory")
    if lock_universe != lock_components:
        _die("dashboard store lock universe differs from pnpm-lock.yaml")
    expected_native = _pnpm_platform_components(lock_components, platform)
    if native_realization != expected_native:
        _die("dashboard native lock realization differs")
    previous_installed: tuple[bytes, bytes, bytes, bytes] | None = None
    installed_instances: list[tuple[str, str, str]] = []
    seen_instances: set[str] = set()
    seen_snapshots: set[str] = set()
    for raw_item in installed:
        item = _require_object(raw_item, "dashboard installed pnpm package")
        _require_exact_keys(
            item,
            {"instance", "name", "snapshot_key", "version"},
            "dashboard installed pnpm package",
        )
        if not all(isinstance(item[key], str) and item[key] for key in item):
            _die("dashboard installed pnpm package identity differs")
        ordering = (
            item["name"].encode(),
            item["version"].encode(),
            item["snapshot_key"].encode(),
            item["instance"].encode(),
        )
        if (
            (previous_installed is not None and ordering <= previous_installed)
            or item["instance"] in seen_instances
            or item["snapshot_key"] in seen_snapshots
            or PurePosixPath(item["instance"]).is_absolute()
            or ".." in PurePosixPath(item["instance"]).parts
        ):
            _die("dashboard installed pnpm instances are duplicate, unsafe, or unsorted")
        previous_installed = ordering
        seen_instances.add(item["instance"])
        seen_snapshots.add(item["snapshot_key"])
        installed_instances.append((item["name"], item["version"], item["snapshot_key"]))
    expected_instances = sorted(
        ((item["name"], item["version"], item["key"]) for item in expected_native),
        key=lambda item: tuple(part.encode() for part in item),
    )
    if installed_instances != expected_instances:
        _die("dashboard installed instances differ from reachable pnpm snapshots")
    expected_scan = {item["key"]: (item["name"], item["version"]) for item in lock_components}
    if len(expected_scan) != len(lock_components):
        _die("dashboard pnpm lock contains duplicate snapshot identities")
    build, build_raw = _load_json(root / "evidence/build-receipt.json")
    if build_raw != _canonical(build) + b"\n":
        _die("dashboard build receipt is not canonical JSON")
    _require_exact_keys(
        build,
        {
            "format",
            "platform",
            "source_projection_sha256",
            "pnpm_lock_sha256",
            "store_inventory_sha256",
            "node_image",
            "node_manifest_digest",
            "node_config_digest",
            "pnpm_binary_sha256",
            "working_directory",
            "environment",
            "commands",
            "exit_code",
            "execution_identity",
            "run_evidence_format",
            "bundle_tree_sha256",
        },
        "dashboard build receipt",
    )
    projection, _, _, _ = dashboard_source_projection(repo_root, manifest)
    if (
        build["format"] != "z4j-production-dashboard-build-v1"
        or build["platform"] != platform
        or build["source_projection_sha256"] != projection
        or build["pnpm_lock_sha256"] != info["pnpm_lock_sha256"]
        or build["store_inventory_sha256"] != info["store_inventory_sha256"]
        or build["node_image"] != EXPECTED_NODE_IMAGE
        or build["node_manifest_digest"]
        != dashboard["node"]["platforms"][platform]["manifest_digest"]
        or build["node_config_digest"] != dashboard["node"]["platforms"][platform]["config_digest"]
        or build["pnpm_binary_sha256"] != dashboard["pnpm"]["binary_sha256"]
        or build["working_directory"] != DASHBOARD_WORKSPACE
        or build["environment"]
        != {
            "CI": "true",
            "HOME": DASHBOARD_HOME,
            "LANG": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "SOURCE_DATE_EPOCH": str(manifest["install"]["source_date_epoch"]),
            "TZ": "UTC",
        }
        or build["commands"]
        != {
            "install": [
                "node",
                DASHBOARD_PNPM,
                "install",
                "--offline",
                "--frozen-lockfile",
                "--store-dir",
                DASHBOARD_INSTALL_STORE,
                "--package-import-method=copy",
            ],
            "build": [
                "node",
                DASHBOARD_PNPM,
                "run",
                "build",
            ],
        }
        or build["exit_code"] != 0
        or build["execution_identity"] != {"gid": 65532, "uid": 65532}
        or build["run_evidence_format"] != "z4j-production-dashboard-build-run-evidence-v1"
        or build["bundle_tree_sha256"] != info["bundle_tree_sha256"]
    ):
        _die("dashboard build receipt bindings differ")
    sbom, _ = _load_json(root / "evidence/sbom.cyclonedx.json")
    _require_exact_keys(
        sbom,
        {"bomFormat", "components", "metadata", "specVersion", "version"},
        "dashboard CycloneDX SBOM",
    )
    subject = _require_object(
        _require_object(sbom["metadata"], "dashboard SBOM metadata").get("component"),
        "dashboard SBOM subject",
    )
    if (
        sbom["bomFormat"] != "CycloneDX"
        or sbom["specVersion"] != "1.6"
        or sbom["version"] != 1
        or subject.get("type") != "application"
        or subject.get("name") != "z4j-dashboard"
        or subject.get("version") != RELEASE
        or subject.get("hashes") != [{"alg": "SHA-256", "content": info["bundle_tree_sha256"]}]
    ):
        _die("dashboard SBOM subject identity/tree differs")
    sbom_components = sbom["components"]
    if not isinstance(sbom_components, list) or not sbom_components:
        _die("dashboard SBOM component inventory is empty")
    component_rows: list[list[str]] = []
    component_records: list[dict[str, str]] = []
    sbom_ids: set[str] = set()
    for raw_component in sbom_components:
        component = _require_object(raw_component, "dashboard SBOM component")
        keys = {"bom-ref", "name", "properties", "purl", "type", "version"}
        if "group" in component:
            keys.add("group")
        _require_exact_keys(component, keys, "dashboard SBOM component")
        properties = component["properties"]
        if not isinstance(properties, list) or len(properties) != 2:
            _die("dashboard SBOM component properties differ")
        property_values: dict[str, str] = {}
        for raw_property in properties:
            property_value = _require_object(raw_property, "dashboard SBOM component property")
            _require_exact_keys(
                property_value, {"name", "value"}, "dashboard SBOM component property"
            )
            if (
                property_value["name"] in property_values
                or property_value["name"]
                not in {"aquasecurity:trivy:PkgID", "aquasecurity:trivy:PkgType"}
                or not isinstance(property_value["value"], str)
                or not property_value["value"]
            ):
                _die("dashboard SBOM component property differs or is duplicate")
            property_values[property_value["name"]] = property_value["value"]
        package_id = property_values.get("aquasecurity:trivy:PkgID")
        group = component.get("group")
        name = f"{group}/{component['name']}" if group is not None else component["name"]
        version = component["version"]
        expected_purl = (
            "pkg:npm/"
            + urllib.parse.quote(name, safe="/")
            + "@"
            + urllib.parse.quote(version, safe="")
            if isinstance(name, str) and isinstance(version, str)
            else ""
        )
        if (
            component["type"] != "library"
            or not isinstance(component["name"], str)
            or not component["name"]
            or (group is not None and (not isinstance(group, str) or not group.startswith("@")))
            or not isinstance(package_id, str)
            or expected_scan.get(package_id) != (name, version)
            or component["purl"] != expected_purl
            or property_values.get("aquasecurity:trivy:PkgType") != "pnpm"
            or component["bom-ref"] != "urn:z4j:pnpm:" + _sha256(package_id.encode("utf-8"))
            or package_id in sbom_ids
        ):
            _die("dashboard SBOM component identity/purl differs or is duplicate")
        sbom_ids.add(package_id)
        component_rows.append([package_id, name, version, expected_purl])
        component_records.append(
            {"id": package_id, "name": name, "purl": expected_purl, "version": version}
        )
    if set(sbom_ids) != set(expected_scan) or component_records != sorted(
        component_records, key=lambda item: item["id"].encode()
    ):
        _die("dashboard SBOM components differ from pnpm-lock.yaml")
    advisory, advisory_raw = _load_json(root / "evidence/advisory-receipt.json")
    if advisory_raw != _canonical(advisory) + b"\n":
        _die("dashboard advisory receipt is not canonical JSON")
    _require_exact_keys(
        advisory,
        {
            "format",
            "platform",
            "subject_tree_sha256",
            "components_sha256",
            "scanner",
            "database",
            "policy",
            "findings",
            "verdict",
            "report",
            "run_evidence_format",
        },
        "dashboard advisory receipt",
    )
    components_sha = _sha256(_canonical(component_rows))
    advisory_report = _require_object(advisory.get("report"), "dashboard advisory report")
    _require_exact_keys(advisory_report, {"path", "sha256", "size"}, "dashboard advisory report")
    report_record = records.get("evidence/advisory-report.json")
    if (
        advisory["format"] != "z4j-production-dashboard-advisory-v1"
        or advisory["platform"] != platform
        or advisory["subject_tree_sha256"] != info["bundle_tree_sha256"]
        or advisory["components_sha256"] != components_sha
        or advisory["policy"]
        != {
            "severities": ["HIGH", "CRITICAL"],
            "ignore_unfixed": False,
            "list_all_packages": True,
            "required_result_type": "pnpm",
        }
        or advisory["findings"] != []
        or advisory["verdict"] != "pass"
        or advisory["run_evidence_format"] != "z4j-production-dashboard-trivy-run-evidence-v1"
        or advisory_report["path"] != "evidence/advisory-report.json"
        or report_record is None
        or advisory_report["sha256"] != report_record["sha256"]
        or advisory_report["size"] != report_record["size"]
    ):
        _die("dashboard advisory receipt does not prove the exact clean policy")
    report, report_raw = _load_json(root / "evidence/advisory-report.json")
    _require_exact_keys(
        report,
        {"findings", "format", "packages", "platform", "result_type"},
        "dashboard semantic advisory report",
    )
    if (
        _sha256(report_raw) != advisory_report["sha256"]
        or len(report_raw) != advisory_report["size"]
        or report_raw != _canonical(report) + b"\n"
        or report["format"] != "z4j-production-dashboard-trivy-semantic-report-v2"
        or report["platform"] != platform
        or report["result_type"] != "pnpm"
        or report["findings"] != []
        or report["packages"] != component_records
    ):
        _die("dashboard semantic advisory identity/coverage/findings differ")
    _validate_scanner_database(advisory["scanner"], advisory["database"], "dashboard advisory")
    _verify_retained_advisory_authority(
        root,
        records,
        advisory["scanner"],
        advisory["database"],
        "dashboard advisory",
    )


def verify_dashboard_output(manifest: dict[str, Any], directory: Path, platform: str) -> None:
    if not directory.is_dir() or directory.is_symlink():
        _die("dashboard replay output is absent or nonregular")
    _verify_dashboard_build_markers(
        directory,
        source_projection_sha256=manifest["dashboard"]["source_projection"]["sha256"],
    )
    records: list[dict[str, Any]] = []
    for entry in sorted(
        directory.rglob("*"),
        key=lambda item: item.relative_to(directory).as_posix().encode("utf-8"),
    ):
        relative = entry.relative_to(directory).as_posix()
        if entry.is_symlink() or not (entry.is_dir() or entry.is_file()):
            _die(f"dashboard replay output contains unsafe entry {relative}")
        if entry.is_file():
            records.append(_file_record(entry, f"dist/{relative}"))
    if not records:
        _die("dashboard replay output is empty")
    tree = {"format": "z4j-production-dashboard-dist-tree-v1", "files": records}
    info = manifest["dashboard"]["platforms"][platform]
    if (
        _sha256(_canonical(tree)) != info["bundle_tree_sha256"]
        or sum(int(record["size"]) for record in records) != info["bundle_tree_bytes"]
    ):
        _die("offline dashboard replay output differs from the sealed bundle")


def verify_built_wheels(manifest: dict[str, Any], directory: Path, platform: str) -> None:
    expected = {
        str(record["filename"]): record
        for record in _manifest_platform(manifest, platform)["local_wheels"]
    }
    actual: dict[str, Path] = {}
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            _die(f"local wheel output contains nonregular entry {entry.name}")
        actual[entry.name] = entry
    if set(actual) != set(expected):
        _die(
            "local wheel output inventory differs; "
            f"missing={sorted(set(expected) - set(actual))}, "
            f"extra={sorted(set(actual) - set(expected))}"
        )
    for filename, path in actual.items():
        record = expected[filename]
        name, version, digest, size = _audit_wheel(path, platform=platform)
        if (
            name != _normalized_name(str(record["distribution"]))
            or version != record["version"]
            or digest != record["sha256"]
            or size != record["size"]
        ):
            _die(f"local reproducible wheel readback differs: {filename}")


def verify_oci(  # noqa: PLR0912
    manifest: dict[str, Any],
    *,
    platform: str,
    material: str,
    index_path: Path,
    manifest_path: Path,
) -> None:
    authority = (
        manifest["dashboard"]["node"] if material == "dashboard_node" else manifest[material]
    )
    platform_info = authority["platforms"][platform]
    index_raw = _read_bytes(index_path, maximum=4 * 1024 * 1024, context=f"{material} index")
    leaf_raw = _read_bytes(manifest_path, maximum=4 * 1024 * 1024, context=f"{material} manifest")
    expected_index = (
        {"digest": authority["index_digest"], "size": authority["index_size"]}
        if material == "dashboard_node"
        else authority["index"]
    )
    if (
        "sha256:" + _sha256(index_raw) != expected_index["digest"]
        or len(index_raw) != expected_index["size"]
    ):
        _die(f"{material} OCI index bytes differ")
    try:
        index = json.loads(index_raw, object_pairs_hook=_pairs)
        leaf = json.loads(leaf_raw, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{material} OCI JSON is invalid") from exc
    if not isinstance(index, dict) or not isinstance(leaf, dict):
        _die(f"{material} OCI index/manifest top level is not an object")
    index_media_types = {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
    manifest_media_types = {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in index_media_types:
        _die(f"{material} OCI index schema/media type differs")
    if leaf.get("schemaVersion") != 2 or leaf.get("mediaType") not in manifest_media_types:
        _die(f"{material} OCI manifest schema/media type differs")
    expected_os, expected_arch = platform.split("/", 1)
    descriptors = index.get("manifests", [])
    if not isinstance(descriptors, list):
        _die(f"{material} OCI index manifest inventory is malformed")
    platform_descriptors: dict[str, dict[str, Any]] = {}
    unexpected = []
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            _die(f"{material} OCI index descriptor is malformed")
        pair = (
            (descriptor.get("platform") or {}).get("os"),
            (descriptor.get("platform") or {}).get("architecture"),
        )
        key = f"{pair[0]}/{pair[1]}"
        if key in PLATFORMS:
            if key in platform_descriptors:
                _die(f"{material} OCI index has a duplicate {key} manifest")
            platform_descriptors[key] = descriptor
        # The official Python and Node indexes have additional architectures
        # and attestation descriptors. Their complete byte streams are sealed
        # above, so select and bind our two native descriptors from those
        # immutable upstream indexes. Every z4j-owned bundle is purpose-built
        # as an exact two-descriptor matrix: even unknown/unknown descriptors
        # would alter its claimed inventory and are forbidden.
        elif material not in {"python", "dashboard_node"}:
            unexpected.append(pair)
    if (
        set(platform_descriptors) != set(PLATFORMS)
        or unexpected
        or (material not in {"python", "dashboard_node"} and len(descriptors) != len(PLATFORMS))
    ):
        _die(f"{material} OCI index platform inventory differs")
    for key, descriptor in platform_descriptors.items():
        expected_descriptor = authority["platforms"][key]
        if (
            descriptor.get("digest") != expected_descriptor["manifest_digest"]
            or descriptor.get("size") != expected_descriptor["manifest_size"]
        ):
            _die(f"{material} OCI index descriptor differs for {key}")
    selected = platform_descriptors[f"{expected_os}/{expected_arch}"]
    if (
        selected.get("digest") != platform_info["manifest_digest"]
        or selected.get("size") != platform_info["manifest_size"]
        or "sha256:" + _sha256(leaf_raw) != platform_info["manifest_digest"]
        or len(leaf_raw) != platform_info["manifest_size"]
    ):
        _die(f"{material} {platform} manifest descriptor/bytes differ")
    config = leaf.get("config") or {}
    if not isinstance(config, dict):
        _die(f"{material} {platform} config descriptor is malformed")
    config_media_types = {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
    if (
        config.get("mediaType") not in config_media_types
        or not isinstance(leaf.get("layers"), list)
        or any(not isinstance(layer, dict) for layer in leaf["layers"])
        or config.get("digest") != platform_info["config_digest"]
        or config.get("size") != platform_info["config_size"]
    ):
        _die(f"{material} {platform} config descriptor differs")


def probe_uv(manifest: dict[str, Any], root: Path, platform: str, python: Path) -> str:
    info = _manifest_platform(manifest, platform)
    uv = root / manifest["resolver"]["binary_relative_path"]
    version = subprocess.run(  # noqa: S603
        [str(uv), "--version"], capture_output=True, text=True, check=False
    )
    version_output = (version.stdout or version.stderr).strip()
    if version.returncode != 0 or version_output != info["uv"]["version_output"]:
        _die("actual uv binary version output differs")
    help_result = subprocess.run(  # noqa: S603
        [str(uv), "pip", "sync", "--help"], capture_output=True, text=True, check=False
    )
    help_text = help_result.stdout + help_result.stderr
    required = manifest["resolver"]["required_sync_flags"]
    if help_result.returncode != 0 or any(flag not in help_text for flag in required):
        _die("uv pip sync does not expose every required fail-closed flag")
    runtime_lock = root / "locks/runtime.txt"
    first = _lock_records(
        _read_bytes(runtime_lock, maximum=MAX_LOCK_BYTES, context="runtime lock"),
        context="runtime lock",
    )[0]
    with tempfile.TemporaryDirectory(prefix="z4j-uv-probe-") as temporary:
        temporary_path = Path(temporary)
        venv = temporary_path / "venv"
        create = subprocess.run(  # noqa: S603
            [str(python), "-m", "venv", str(venv)], capture_output=True, text=True, check=False
        )
        if create.returncode != 0:
            _die("could not create isolated uv enforcement probe venv")
        unhashed = temporary_path / "unhashed.txt"
        unhashed.write_text(f"{first[0]}=={first[1]}\n", encoding="utf-8")
        probe = subprocess.run(  # noqa: S603
            [
                str(uv),
                "pip",
                "sync",
                "--python",
                str(venv / "bin/python"),
                "--require-hashes",
                "--no-index",
                "--find-links",
                str(root / "wheels"),
                "--offline",
                "--no-cache",
                "--no-config",
                str(unhashed),
            ],
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "UV_INDEX_URL": "https://invalid.invalid/simple",
                "UV_PYTHON_DOWNLOADS": "never",
            },
        )
    combined = probe.stdout + probe.stderr
    if probe.returncode == 0 or "hash" not in combined.lower():
        _die("uv pip sync did not enforce --require-hashes on the adversarial probe")
    transcript = {
        "format": "z4j-production-uv-enforcement-v1",
        "platform": platform,
        "version_output": version_output,
        "required_flags": required,
        "unhashed_probe_returncode": probe.returncode,
        "unhashed_probe_stdout_sha256": _sha256(probe.stdout.encode()),
        "unhashed_probe_stderr_sha256": _sha256(probe.stderr.encode()),
    }
    digest = _sha256(_canonical(transcript))
    if digest != info["uv"]["probe_sha256"]:
        _die("actual uv enforcement transcript differs from the sealed probe")
    return digest


def verify_cadence_probe(manifest: dict[str, Any], probe_path: Path, platform: str) -> None:
    probe, raw = _load_json(probe_path)
    expected = _manifest_platform(manifest, platform)["cadence_probe"]
    if _sha256(_canonical(probe)) != expected["sha256"]:
        _die("candidate cadence probe differs from the sealed canonical payload")
    if raw != _canonical(probe) + b"\n":
        _die("candidate cadence probe is not canonical JSON plus one newline")
    if probe.get("format") != "z4j-production-cadence-probe-v1":
        _die("candidate cadence probe format differs")
    if probe.get("python") != {"implementation": "CPython", "version": [3, 14, 7]}:
        _die("candidate cadence probe did not execute on CPython 3.14.7")
    expected_machine = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
    if probe.get("platform") != {"system": "Linux", "machine": expected_machine}:
        _die("candidate cadence probe platform differs")
    if probe.get("dependencies") != EXPECTED_CADENCE:
        _die("candidate cadence dependency versions differ")
    brain = probe.get("brain") or {}
    scheduler = probe.get("scheduler") or {}
    if brain != scheduler:
        _die("Brain and scheduler cadence probes differ")
    if (
        brain.get("fingerprint") != expected["fingerprint"]
        or brain.get("behavior_vector_sha256") != expected["behavior_vector_sha256"]
        or brain.get("tzdata_tree_sha256") != expected["tzdata_tree_sha256"]
    ):
        _die("candidate cadence probe components differ")


def verify_signature_verifier_probe(
    manifest: dict[str, Any], probe_path: Path, platform: str
) -> None:
    probe, raw = _load_json(probe_path)
    if raw != _canonical(probe) + b"\n":
        _die("candidate signature-verifier probe is not canonical JSON plus one newline")
    _require_exact_keys(
        probe,
        {
            "format",
            "platform",
            "runtime_path",
            "binary_sha256",
            "binary_size",
            "version_output_sha256",
            "version_output_size",
        },
        "candidate signature-verifier probe",
    )
    expected_machine = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
    authority = manifest["signature_verifier"]
    tool = authority["platforms"][platform]
    if (
        probe["format"] != "z4j-production-signature-verifier-probe-v1"
        or probe["platform"] != {"system": "Linux", "machine": expected_machine}
        or probe["runtime_path"] != authority["runtime_path"]
        or probe["binary_sha256"] != tool["sha256"]
        or probe["binary_size"] != tool["size"]
        or probe["version_output_sha256"] != tool["version_output_sha256"]
        or probe["version_output_size"] != tool["version_output_size"]
    ):
        _die("candidate signature-verifier probe differs from the finalized authority")


def _source_command(args: argparse.Namespace) -> None:
    manifest, raw = _load_json(args.manifest)
    validate_manifest(manifest, require_finalized=args.require_finalized)
    marker = args.manifest.parent / "locks/UNFINALIZED"
    digest, entries, total, layout = source_projection(args.repo_root, manifest)
    dashboard_digest, dashboard_entries, dashboard_total, dashboard_layout = (
        dashboard_source_projection(args.repo_root, manifest)
    )
    if dashboard_layout != layout:
        _die("Python and dashboard source layouts differ")
    if manifest["state"] == "finalized":
        if marker.exists() or marker.is_symlink():
            _die("finalized source contract still carries locks/UNFINALIZED")
        expected = manifest["source_authority"]["projection"]
        if (digest, entries, total) != (expected["sha256"], expected["entries"], expected["bytes"]):
            _die("production source projection differs from its frozen seal")
        dashboard_expected = manifest["dashboard"]["source_projection"]
        if (dashboard_digest, dashboard_entries, dashboard_total) != (
            dashboard_expected["sha256"],
            dashboard_expected["entries"],
            dashboard_expected["bytes"],
        ):
            _die("dashboard source projection differs from its frozen seal")
        if bool(args.release_commit) != bool(args.release_tree):
            _die("release commit and tree must be supplied together")
        if args.release_commit:
            _validate_post_freeze_delta(
                args.repo_root,
                manifest,
                layout=layout,
                release_commit=args.release_commit,
                release_tree=args.release_tree,
            )
    else:
        _read_bytes(marker, maximum=16 * 1024, context="unfinalized source contract marker")
    outputs = {
        "production_manifest_sha256": _sha256(raw),
        "production_source_projection_sha256": digest,
        "production_source_projection_entries": str(entries),
        "production_source_projection_bytes": str(total),
        "production_source_layout": layout,
        "dashboard_source_projection_sha256": dashboard_digest,
        "dashboard_source_projection_entries": str(dashboard_entries),
        "dashboard_source_projection_bytes": str(dashboard_total),
    }
    if manifest["state"] == "finalized":
        outputs.update(
            {
                "production_wheelhouse_image": manifest["wheelhouse"]["image"],
                "production_wheelhouse_index_digest": manifest["wheelhouse"]["index"]["digest"],
                "production_system_bundle_image": manifest["system_packages"]["image"],
                "production_system_bundle_index_digest": manifest["system_packages"]["index"][
                    "digest"
                ],
                "production_dashboard_bundle_image": manifest["dashboard"]["image"],
                "production_dashboard_bundle_index_digest": manifest["dashboard"]["index"][
                    "digest"
                ],
                "production_source_date_epoch": str(manifest["install"]["source_date_epoch"]),
            }
        )
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            for key in sorted(outputs):
                value = str(outputs[key])
                if "\n" in value or "\r" in value:
                    _die("GitHub output value contains a newline")
                stream.write(f"{key}={value}\n")
    sys.stdout.write(json.dumps(outputs, sort_keys=True) + "\n")


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source")
    source.add_argument("--manifest", type=Path, required=True)
    source.add_argument("--repo-root", type=Path, required=True)
    source.add_argument("--require-finalized", action="store_true")
    source.add_argument("--release-commit")
    source.add_argument("--release-tree")
    source.add_argument("--github-output", type=Path)

    wheelhouse = subparsers.add_parser("wheelhouse")
    wheelhouse.add_argument("--manifest", type=Path, required=True)
    wheelhouse.add_argument("--root", type=Path, required=True)
    wheelhouse.add_argument("--platform", choices=PLATFORMS, required=True)

    system_bundle = subparsers.add_parser("system-bundle")
    system_bundle.add_argument("--manifest", type=Path, required=True)
    system_bundle.add_argument("--root", type=Path, required=True)
    system_bundle.add_argument("--platform", choices=PLATFORMS, required=True)
    system_bundle.add_argument("--apt-get", type=Path, required=True)
    system_bundle.add_argument("--gpgv", type=Path, required=True)
    system_bundle.add_argument("--dpkg-deb", type=Path, required=True)

    dashboard_bundle = subparsers.add_parser("dashboard-bundle")
    dashboard_bundle.add_argument("--manifest", type=Path, required=True)
    dashboard_bundle.add_argument("--root", type=Path, required=True)
    dashboard_bundle.add_argument("--repo-root", type=Path, required=True)
    dashboard_bundle.add_argument("--platform", choices=PLATFORMS, required=True)

    dashboard_output = subparsers.add_parser("dashboard-output")
    dashboard_output.add_argument("--manifest", type=Path, required=True)
    dashboard_output.add_argument("--directory", type=Path, required=True)
    dashboard_output.add_argument("--platform", choices=PLATFORMS, required=True)

    built = subparsers.add_parser("built-wheels")
    built.add_argument("--manifest", type=Path, required=True)
    built.add_argument("--directory", type=Path, required=True)
    built.add_argument("--platform", choices=PLATFORMS, required=True)

    oci = subparsers.add_parser("oci")
    oci.add_argument("--manifest", type=Path, required=True)
    oci.add_argument("--platform", choices=PLATFORMS, required=True)
    oci.add_argument(
        "--material",
        choices=("python", "dashboard_node", "wheelhouse", "system_packages", "dashboard"),
        required=True,
    )
    oci.add_argument("--index-json", type=Path, required=True)
    oci.add_argument("--manifest-json", type=Path, required=True)

    uv = subparsers.add_parser("uv")
    uv.add_argument("--manifest", type=Path, required=True)
    uv.add_argument("--root", type=Path, required=True)
    uv.add_argument("--platform", choices=PLATFORMS, required=True)
    uv.add_argument("--python", type=Path, required=True)

    cadence = subparsers.add_parser("cadence-probe")
    cadence.add_argument("--manifest", type=Path, required=True)
    cadence.add_argument("--probe", type=Path, required=True)
    cadence.add_argument("--platform", choices=PLATFORMS, required=True)

    signature_probe = subparsers.add_parser("signature-verifier-probe")
    signature_probe.add_argument("--manifest", type=Path, required=True)
    signature_probe.add_argument("--probe", type=Path, required=True)
    signature_probe.add_argument("--platform", choices=PLATFORMS, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "source":
            _source_command(args)
            return 0
        manifest, _ = _load_json(args.manifest)
        validate_manifest(manifest, require_finalized=True)
        if args.command == "wheelhouse":
            verify_wheelhouse(
                manifest,
                args.root,
                args.platform,
                contract_root=args.manifest.resolve().parent,
            )
        elif args.command == "system-bundle":
            verify_system_bundle(
                manifest,
                args.root,
                args.manifest.resolve().parent,
                args.platform,
                args.apt_get,
                args.gpgv,
                args.dpkg_deb,
            )
        elif args.command == "dashboard-bundle":
            verify_dashboard_bundle(manifest, args.root, args.repo_root, args.platform)
        elif args.command == "dashboard-output":
            verify_dashboard_output(manifest, args.directory, args.platform)
        elif args.command == "built-wheels":
            verify_built_wheels(manifest, args.directory, args.platform)
        elif args.command == "oci":
            verify_oci(
                manifest,
                platform=args.platform,
                material=args.material,
                index_path=args.index_json,
                manifest_path=args.manifest_json,
            )
        elif args.command == "uv":
            probe_uv(manifest, args.root, args.platform, args.python)
        elif args.command == "cadence-probe":
            verify_cadence_probe(manifest, args.probe, args.platform)
        elif args.command == "signature-verifier-probe":
            verify_signature_verifier_probe(manifest, args.probe, args.platform)
        else:  # pragma: no cover - argparse owns this boundary
            _die(f"unsupported command {args.command!r}")
    except (ContractError, FileNotFoundError, OSError) as exc:
        sys.stderr.write(f"production closure verification failed: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
