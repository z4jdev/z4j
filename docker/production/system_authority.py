#!/usr/bin/env python3
"""Detached, acyclic authority for the z4j 1.9.0 system-package bundle.

This source is deliberately UNFINALIZED.  It validates the complete tracked
policy/selection boundary and the signed R/B/M graph, but every producer entry
point remains poisoned until the reviewed workflow, environment, Docker Hub,
Cosign, and Sigstore trust-root values in ``system-authority-policy.json`` are
realized.  It never creates a Docker Hub repository or treats a mutable tag or
an Actions artifact as authority.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import email.parser
import importlib.util
import json
import lzma
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn


def _load_common_module() -> Any:
    """Load the byte-identical sibling without relying on package installation."""

    module_name = "z4j_production_authority_common"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name("production_authority_common.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load production authority common helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


common = _load_common_module()


def _load_material_build_module() -> Any:
    module_name = "z4j_production_material_build"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name("production_material_build.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load production material build helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


material_build = _load_material_build_module()


def _load_finalize_module() -> Any:
    """Load the architecture-neutral finalizer only after CLI readiness."""

    module_name = "z4j_production_finalize"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name("production_finalize.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load production finalization helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _producer_hook(name: str) -> Any:
    value = globals().get(name)
    if not callable(value):
        _die(f"required authenticated platform-aggregation hook is absent: {name}")
    return value


RELEASE = "1.9.0"
POLICY_FORMAT = "z4j-production-system-authority-policy-v2"
AUTHORITY_FORMAT = "z4j-production-system-authority-v2"
AUTHORITY_SCHEMA = "z4j.production-system-authority.v2"
POLICY_CARRIER_PATH = "packages/z4j/docker/production/system-authority-policy.json"
POLICY_RELEASE_PATH = "docker/production/system-authority-policy.json"
TRUSTED_ROOT_RELEASE_PATH = "docker/production/trust/sigstore-trusted-root.json"
REPOSITORY = "docker.io/z4jdev/z4j-production-system"
WORKFLOW_PATH = ".github/workflows/finalize-production-system.yml"
WORKFLOW_NAME = "finalize-production-system"
WORKFLOW_IDENTITY = (
    "https://github.com/dxdevo/z4j/.github/workflows/finalize-production-system.yml@refs/heads/main"
)
ENVIRONMENT = "production-system-finalization"
RECEIPT_FILENAME = "production-system-authority.json"
BUNDLE_FILENAME = "production-system-authority.sigstore.json"
ARTIFACT_FILENAME = "production-system-authority.oci.json"
RECEIPT_MEDIA_TYPE = "application/vnd.z4j.production-system-authority-receipt.v2+json"
ARTIFACT_TYPE = "application/vnd.z4j.production-system-authority.v2+json"
SUBJECT_TAG_PATTERN = r"^1\.9\.0-digest-[0-9a-f]{64}$"
AUTHORITY_TAG_PATTERN = r"^1\.9\.0-system-authority-[0-9a-f]{64}$"
CUTOFF = "2026-08-23T04:14:39.107Z"
REKOR_INTEGRATED_TIME_MINIMUM = 1787458480
PLATFORMS = ("linux/amd64", "linux/arm64")
ARCHITECTURES = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
MAX_PACKAGES_INDEX_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_STANZA_BYTES = 1024 * 1024
MAX_RELEASE_BYTES = 16 * 1024 * 1024
MAX_RELEASE_ENTRIES = 100_000
MAX_DEBIAN_FIELDS = 256
MAX_DEBIAN_LINE_BYTES = 128 * 1024
MAX_DEB_BYTES = 512 * 1024 * 1024
MAX_CONTROL_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CONTROL_TAR_BYTES = 64 * 1024 * 1024
MAX_CONTROL_MEMBERS = 1024
MAX_CONTROL_MEMBER_BYTES = 16 * 1024 * 1024
MAX_CONTROL_STANZA_BYTES = 1024 * 1024
DEBIAN_FIELD_NAME = re.compile(rb"[A-Za-z0-9][A-Za-z0-9-]*")
DEBIAN_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*")
DEBIAN_ARCHITECTURE = re.compile(r"[a-z0-9][a-z0-9-]*")
GENERATOR_DOCKERFILE = "docker/production/generators/system.Dockerfile"
GENERATOR_BUILDER = "z4j-production-system"
GENERATOR_SOURCE_PREFIX = "packages/z4j"
GENERATOR_SOURCE_FILES = (
    "docker/production/production_authority_common.py",
    "docker/production/production_material_build.py",
    "docker/production/system_authority.py",
)
GENERATOR_CONTEXT_SELECTIONS = tuple(
    sorted(
        (
            "docker/production/system-authority-policy.json",
            "docker/production/generators/system.Dockerfile",
            *GENERATOR_SOURCE_FILES,
        ),
        key=str.encode,
    )
)
INTERNAL_POLICY_PATH = Path("/authority/system-authority-policy.json")
INTERNAL_ACQUIRED_ROOT = Path("/acquired")
INTERNAL_INSTALLABILITY_ROOT = Path("/installability")
INTERNAL_OUTPUT_ROOT = Path("/out")
SYSTEM_TOOL_PATHS = {
    "apt_get": "/usr/bin/apt-get",
    "dpkg_deb": "/usr/bin/dpkg-deb",
    "gpgv": "/usr/bin/gpgv",
    "tar": "/bin/tar",
}
ISOLATED_APT_ROOT = "/tmp/z4j-production-system-apt"  # noqa: S108 - isolated container
SYSTEM_SCAN_ROOT = "/tmp/z4j-production-system-scan-root"  # noqa: S108 - isolated container
EXPECTED_RESOLUTION_INTERFACE = {
    "architectures": ARCHITECTURES,
    "base_status": {
        "platforms": {
            platform: {"path": "/var/lib/dpkg/status", "sha256": None, "size": None}
            for platform in PLATFORMS
        }
    },
    "format": "z4j-production-isolated-apt-metadata-resolution-v1",
    "os_release": {
        "platforms": {
            platform: {"path": "/etc/os-release", "sha256": None, "size": None}
            for platform in PLATFORMS
        }
    },
    "state_root": ISOLATED_APT_ROOT,
    "status": "synthetic-from-authenticated-lock-control",
    "trusted": "-",
    "trusted_parts": "-",
}

PROFILE = common.AuthorityProfile(
    artifact_filename=ARTIFACT_FILENAME,
    artifact_media_type=common.OCI_MANIFEST,
    artifact_type=ARTIFACT_TYPE,
    authority_tag_pattern=AUTHORITY_TAG_PATTERN,
    authority_tag_prefix="1.9.0-system-authority-",
    bundle_filename=BUNDLE_FILENAME,
    bundle_media_type=common.SIGSTORE_BUNDLE_V03,
    cleanup_excludes=(SUBJECT_TAG_PATTERN, AUTHORITY_TAG_PATTERN),
    created_transition="created-content-derived-system",
    environment=ENVIRONMENT,
    material="system",
    immutability_patterns=(
        ("authority_pattern", AUTHORITY_TAG_PATTERN),
        ("subject_pattern", SUBJECT_TAG_PATTERN),
    ),
    payload_root="/opt/z4j-production-system",
    oci_tag_patterns=(
        ("authority_tag_pattern", AUTHORITY_TAG_PATTERN),
        ("subject_tag_pattern", SUBJECT_TAG_PATTERN),
    ),
    receipt_format=AUTHORITY_FORMAT,
    receipt_filename=RECEIPT_FILENAME,
    receipt_media_type=RECEIPT_MEDIA_TYPE,
    recovered_transition="recovered-existing-exact-system",
    repository=REPOSITORY,
    subject_tag_pattern=SUBJECT_TAG_PATTERN,
    subject_tag_prefix="1.9.0-digest-",
    workflow_identity=WORKFLOW_IDENTITY,
    workflow_name=WORKFLOW_NAME,
    workflow_path=WORKFLOW_PATH,
)

EXPECTED_RESOLVER_BASE = {
    "image": (
        "docker.io/library/python:3.14.7-slim-trixie@"
        "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
    ),
    "index": {
        "digest": "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4",
        "size": 10365,
    },
    "platforms": {
        "linux/amd64": {
            "config_digest": "sha256:a41c1f663be90eb31af9864d1e1ccdaa91b6af11776b7ade1c05915e76da7aea",
            "config_size": 4934,
            "manifest_digest": "sha256:d6e0850f13fda0e2305d4c3c1c2f7930fe1042d34ddd958e49bba6ef685d0bb2",
            "manifest_size": 1745,
        },
        "linux/arm64": {
            "config_digest": "sha256:462b4d0ce92fd7559a84feb2d3ab4eca3b741c5a1a375e28cce7fd8900659688",
            "config_size": 4949,
            "manifest_digest": "sha256:c65a4a1140b75416bbc7f28807f82a3746bd6567645d5848123b6a6587f86962",
            "manifest_size": 1747,
        },
    },
    "version": "3.14.7",
}

EXPECTED_SOURCES = [
    {
        "archive": "https://snapshot.debian.org/archive/debian/",
        "archive_key_fingerprints": [
            "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        ],
        "components": ["main"],
        "name": "debian",
        "release_suite": "stable",
        "suite": "trixie",
    },
    {
        "archive": "https://snapshot.debian.org/archive/debian-security/",
        "archive_key_fingerprints": ["5E04A1E3223A19A20706E20F9904613D4CCE68C6"],
        "components": ["main"],
        "name": "debian-security",
        "release_suite": "stable-security",
        "suite": "trixie-security",
    },
    {
        "archive": "https://snapshot.debian.org/archive/debian/",
        "archive_key_fingerprints": [
            "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        ],
        "components": ["main"],
        "name": "debian-updates",
        "release_suite": "stable-updates",
        "suite": "trixie-updates",
    },
]

FORBIDDEN_RECEIPT_KEYS = {
    "am",
    "am_sha256",
    "artifact_digest",
    "authority_manifest",
    "authority_tag",
    "bundle_sha256",
    "dashboard_authority",
    "downstream_run",
    "final_manifest",
    "final_manifest_sha256",
    "k",
    "qualification_run",
    "release_git_commit",
    "release_git_tree",
    "source_tag",
    "source_tag_authority",
    "standalone_commit",
    "standalone_tree",
    "system_authority",
    "wheelhouse_authority",
}


class SystemAuthorityError(common.CommonAuthorityError):
    """The system authority is malformed, untrusted, or not yet realizable."""


def _die(message: str) -> NoReturn:
    raise SystemAuthorityError(message)


def _build_file_authority(value: Any, *, path: str, context: str) -> list[str]:
    item = common.exact_object(
        value,
        {"path", "sha256", "size", "version_output_sha256"},
        context,
    )
    if item["path"] != path:
        _die(f"{context} path differs")
    poison: list[str] = []
    if item["sha256"] is None or item["size"] is None:
        poison.append(f"{context} binary seal is null")
    else:
        common.hex64(item["sha256"], f"{context} SHA-256")
        common.positive_int(item["size"], f"{context} size")
    if item["version_output_sha256"] is None:
        poison.append(f"{context} version transcript seal is null")
    else:
        common.hex64(item["version_output_sha256"], f"{context} version transcript")
    return poison


def _payload_authority(value: Any, context: str) -> list[str]:
    item = common.exact_object(value, {"sha256", "size", "url"}, context)
    poison: list[str] = []
    if item["url"] is None:
        poison.append(f"{context} URL is null")
    else:
        common.https_url(item["url"], f"{context} URL")
    if item["sha256"] is None or item["size"] is None:
        poison.append(f"{context} seal is null")
    else:
        common.hex64(item["sha256"], f"{context} SHA-256")
        common.positive_int(item["size"], f"{context} size")
    return poison


def _tar_payload_authority(value: Any, context: str) -> list[str]:
    item = common.exact_object(
        value,
        {"members_bytes", "members_entries", "members_sha256", "sha256", "size", "url"},
        context,
    )
    poison = _payload_authority({key: item[key] for key in ("sha256", "size", "url")}, context)
    if (
        item["members_bytes"] is None
        or item["members_entries"] is None
        or item["members_sha256"] is None
    ):
        poison.append(f"{context} semantic member seal is null")
    else:
        common.positive_int(item["members_bytes"], f"{context} expanded bytes")
        common.positive_int(item["members_entries"], f"{context} member count")
        common.hex64(item["members_sha256"], f"{context} member SHA-256")
    return poison


def _validate_build_policy(value: Any) -> list[str]:  # noqa: PLR0912,PLR0915 - closed poison matrix
    generator = common.exact_object(
        value,
        {
            "build_context",
            "builder",
            "docker",
            "dockerfile",
            "execution_plane",
            "resolution_interface",
            "source_date_epoch",
            "tools",
            "trivy",
        },
        "system generator policy",
    )
    if generator["builder"] != GENERATOR_BUILDER:
        _die("system generator builder differs")
    build_context = common.exact_object(
        generator["build_context"], {"format", "source_files"}, "system build context"
    )
    source_files = common.exact_object(
        build_context["source_files"], set(GENERATOR_SOURCE_FILES), "system build source files"
    )
    if build_context["format"] != "z4j-production-system-build-context-v1":
        _die("system build context format differs")
    context_poison: list[str] = []
    for path in GENERATOR_SOURCE_FILES:
        seal = common.exact_object(
            source_files[path], {"sha256", "size"}, f"system build source {path}"
        )
        if seal["sha256"] is None or seal["size"] is None:
            context_poison.append(f"system build source {path} seal is null")
        else:
            common.hex64(seal["sha256"], f"system build source {path}")
            common.positive_int(seal["size"], f"system build source {path} size")
    resolution_interface = common.exact_object(
        generator["resolution_interface"],
        set(EXPECTED_RESOLUTION_INTERFACE),
        "system isolated apt resolution interface",
    )
    os_release = common.exact_object(
        resolution_interface["os_release"],
        {"platforms"},
        "system os-release authority",
    )
    os_release_platforms = common.exact_object(
        os_release["platforms"], set(PLATFORMS), "system os-release platforms"
    )
    base_status = common.exact_object(
        resolution_interface["base_status"],
        {"platforms"},
        "system base dpkg status authority",
    )
    base_status_platforms = common.exact_object(
        base_status["platforms"], set(PLATFORMS), "system base dpkg status platforms"
    )
    resolution_identity = {
        **resolution_interface,
        "base_status": {
            "platforms": {
                platform: {
                    **common.exact_object(
                        base_status_platforms[platform],
                        {"path", "sha256", "size"},
                        f"system base dpkg status {platform}",
                    ),
                    "sha256": None,
                    "size": None,
                }
                for platform in PLATFORMS
            }
        },
        "os_release": {
            "platforms": {
                platform: {
                    **common.exact_object(
                        os_release_platforms[platform],
                        {"path", "sha256", "size"},
                        f"system os-release {platform}",
                    ),
                    "sha256": None,
                    "size": None,
                }
                for platform in PLATFORMS
            }
        },
    }
    if resolution_identity != EXPECTED_RESOLUTION_INTERFACE:
        _die("system isolated apt resolution interface differs")
    poison = material_build.validate_platform_file_authority(
        generator["docker"],
        platforms=PLATFORMS,
        path="/usr/bin/docker",
        context="system generator Docker",
    )
    for platform in PLATFORMS:
        for label, seal in (
            ("os-release", os_release_platforms[platform]),
            ("base dpkg status", base_status_platforms[platform]),
        ):
            if seal["sha256"] is None or seal["size"] is None:
                poison.append(f"system {label} {platform} seal is null")
            else:
                common.hex64(seal["sha256"], f"system {label} {platform} SHA-256")
                common.positive_int(seal["size"], f"system {label} {platform} size")
    poison.extend(context_poison)
    poison.extend(
        material_build.validate_execution_plane_policy(
            generator["execution_plane"], platforms=PLATFORMS
        )
    )
    dockerfile = common.exact_object(
        generator["dockerfile"], {"path", "sha256", "size"}, "system generator Dockerfile"
    )
    if dockerfile["path"] != GENERATOR_DOCKERFILE:
        _die("system generator Dockerfile path differs")
    if dockerfile["sha256"] is None or dockerfile["size"] is None:
        poison.append("system generator Dockerfile seal is null")
    else:
        common.hex64(dockerfile["sha256"], "system generator Dockerfile SHA-256")
        common.positive_int(dockerfile["size"], "system generator Dockerfile size")
    epoch = generator["source_date_epoch"]
    if epoch is None:
        poison.append("system generator SOURCE_DATE_EPOCH is null")
    else:
        common.positive_int(epoch, "system generator SOURCE_DATE_EPOCH")
    tools = common.exact_object(
        generator["tools"], {*SYSTEM_TOOL_PATHS, "git"}, "system generator tools"
    )
    poison.extend(
        material_build.validate_platform_git_authority(
            tools["git"],
            platforms=PLATFORMS,
            context="system generator Git",
        )
    )
    for name, path in SYSTEM_TOOL_PATHS.items():
        poison.extend(
            material_build.validate_platform_file_authority(
                tools[name],
                platforms=PLATFORMS,
                path=path,
                context=f"system generator {name.replace('_', '-')}",
            )
        )
    trivy = common.exact_object(
        generator["trivy"],
        {
            "database",
            "database_archive",
            "platforms",
            "version",
        },
        "system generator Trivy",
    )
    if trivy["version"] != "0.74.0":
        _die("system generator Trivy version differs")
    poison.extend(
        _tar_payload_authority(trivy["database_archive"], "system generator Trivy database archive")
    )
    trivy_platforms = common.exact_object(
        trivy["platforms"], set(PLATFORMS), "system generator Trivy platforms"
    )
    for platform in PLATFORMS:
        native = common.exact_object(
            trivy_platforms[platform],
            {"archive", "binary", "version_output_sha256"},
            f"system generator Trivy {platform}",
        )
        poison.extend(_tar_payload_authority(native["archive"], f"system Trivy archive {platform}"))
        binary = common.exact_object(
            native["binary"], {"sha256", "size"}, f"system Trivy binary {platform}"
        )
        if binary["sha256"] is None or binary["size"] is None:
            poison.append(f"system generator Trivy binary {platform} seal is null")
        else:
            common.hex64(binary["sha256"], f"system Trivy binary {platform} SHA-256")
            common.positive_int(binary["size"], f"system Trivy binary {platform} size")
        if native["version_output_sha256"] is None:
            poison.append(f"system Trivy {platform} version transcript seal is null")
        else:
            common.hex64(
                native["version_output_sha256"],
                f"system Trivy {platform} version transcript",
            )
    database = common.exact_object(
        trivy["database"],
        {
            "downloaded_at_utc",
            "metadata_sha256",
            "name",
            "next_update_utc",
            "schema_version",
            "tree_sha256",
            "updated_at_utc",
        },
        "system generator Trivy database",
    )
    if database["name"] != "trivy-db" or database["schema_version"] != 2:
        _die("system generator Trivy database identity differs")
    for key in ("metadata_sha256", "tree_sha256"):
        if database[key] is None:
            poison.append(f"system generator Trivy database {key} is null")
        else:
            common.hex64(database[key], f"system generator Trivy database {key}")
    for key in ("downloaded_at_utc", "next_update_utc", "updated_at_utc"):
        if database[key] is None:
            poison.append(f"system generator Trivy database {key} is null")
        else:
            common.timestamp(database[key], f"system generator Trivy database {key}")
    return poison


def _validate_snapshot_policy(value: Any) -> list[str]:
    snapshot = common.exact_object(value, {"selection_utc", "sources"}, "system generator snapshot")
    poison: list[str] = []
    if snapshot["selection_utc"] is None:
        poison.append("system snapshot selection is null")
    else:
        common.timestamp(snapshot["selection_utc"], "system snapshot selection")
    sources = snapshot["sources"]
    if not isinstance(sources, list) or len(sources) != len(EXPECTED_SOURCES):
        _die("system generator snapshot source matrix differs")
    keys = {
        "archive",
        "archive_key_fingerprints",
        "archive_keyring",
        "components",
        "inrelease",
        "name",
        "packages",
        "release",
        "release_suite",
        "suite",
        "timestamp_utc",
    }
    for position, expected in enumerate(EXPECTED_SOURCES):
        source = common.exact_object(sources[position], keys, f"system generator source {position}")
        if {key: source[key] for key in expected} != expected:
            _die(f"system generator source {position} identity differs")
        if source["timestamp_utc"] is None:
            poison.append(f"system generator source {position} timestamp is null")
        else:
            common.timestamp(source["timestamp_utc"], f"system generator source {position} time")
        for key in ("archive_keyring", "inrelease", "release"):
            poison.extend(
                _payload_authority(source[key], f"system generator source {position} {key}")
            )
        packages = common.exact_object(
            source["packages"], set(PLATFORMS), f"system generator source {position} packages"
        )
        for platform in PLATFORMS:
            poison.extend(
                _payload_authority(
                    packages[platform],
                    f"system generator source {position} packages {platform}",
                )
            )
    return poison


def validate_policy(policy: Any) -> list[str]:
    """Validate the closed system policy and return every explicit poison reason."""

    value, poison = common.validate_policy_common(
        PROFILE,
        policy,
        policy_format=POLICY_FORMAT,
        material_key="system_packages",
        trusted_root_path=TRUSTED_ROOT_RELEASE_PATH,
        cutoff_not_before_utc=CUTOFF,
    )
    material = common.exact_object(
        value["system_packages"],
        {
            "advisory_receipt_format",
            "format",
            "generator",
            "index_descriptor_order",
            "installability_receipt_format",
            "inventory_format",
            "layer_count_per_platform",
            "package_lock_format",
            "payload_root",
            "platforms",
            "requested",
            "resolution_receipt_format",
            "resolver_base",
            "snapshot",
            "tree_format",
        },
        "system package policy",
    )
    expected = {
        "advisory_receipt_format": "z4j-production-system-advisory-v1",
        "format": "z4j-production-system-bundle-v2",
        "index_descriptor_order": list(PLATFORMS),
        "installability_receipt_format": ("z4j-production-system-real-base-installability-v1"),
        "inventory_format": "z4j-production-system-inventory-v1",
        "layer_count_per_platform": 1,
        "package_lock_format": "z4j-production-debian-package-lock-v1",
        "payload_root": PROFILE.payload_root,
        "platforms": list(PLATFORMS),
        "requested": ["ca-certificates", "libpq5", "tini"],
        "resolution_receipt_format": "z4j-production-debian-resolution-v1",
        "resolver_base": EXPECTED_RESOLVER_BASE,
        "tree_format": "z4j-production-system-tree-v1",
    }
    if {key: material[key] for key in expected} != expected:
        _die("system package policy differs")
    poison.extend(_validate_build_policy(material["generator"]))
    poison.extend(_validate_snapshot_policy(material["snapshot"]))
    return poison


def require_ready(
    policy: Any,
    *,
    trusted_root_raw: bytes | None = None,
    now: dt.datetime | None = None,
) -> None:
    """Fail before any producer mutation while a reviewed prerequisite is poison."""

    poison = validate_policy(policy)
    current = now or dt.datetime.now(dt.UTC)
    cutoff = dt.datetime.fromisoformat(CUTOFF.replace("Z", "+00:00"))
    if current < cutoff:
        poison.append("security-age cutoff has not elapsed")
    if trusted_root_raw is None:
        poison.append("tracked Sigstore trusted-root bytes were not supplied")
    else:
        trusted = policy["signature"]["trusted_root"]
        try:
            common.validate_trusted_root_bootstrap(
                trusted_root_raw,
                expected_sha256=trusted["sha256"],
                expected_size=trusted["size"],
            )
        except common.CommonAuthorityError as exc:
            poison.append(str(exc))
    if poison:
        _die("system authority is UNFINALIZED: " + "; ".join(poison))


def _validate_system_selection(system: Any) -> dict[str, Any]:  # noqa: PLR0912
    """Validate the complete finalized tracked system-package selection."""

    value = common.exact_object(
        system,
        {
            "format",
            "image",
            "index",
            "payload_root",
            "platforms",
            "requested",
            "snapshot",
            "state",
        },
        "system package selection",
    )
    if (
        value["state"] != "finalized"
        or value["format"] != "z4j-production-system-bundle-v2"
        or value["payload_root"] != PROFILE.payload_root
        or value["requested"] != ["ca-certificates", "libpq5", "tini"]
    ):
        _die("finalized system package constants differ")
    index = common.exact_object(value["index"], {"digest", "size"}, "system index")
    subject = common.oci_digest(index["digest"], "system subject digest")
    common.positive_int(index["size"], "system subject size")
    expected_image = (
        f"{REPOSITORY}:{common.derived_tag(PROFILE, subject, authority=False)}@{subject}"
    )
    if value["image"] != expected_image:
        _die("system image is not the fixed-repository S-derived reference")

    snapshot = common.exact_object(
        value["snapshot"], {"selection_utc", "sources"}, "system snapshot"
    )
    selection_text = common.timestamp(snapshot["selection_utc"], "system selection time")
    selection_time = dt.datetime.strptime(selection_text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.UTC
    )
    cutoff_time = dt.datetime.fromisoformat(CUTOFF.replace("Z", "+00:00"))
    if selection_time < cutoff_time:
        _die("system snapshot selection predates the release cutoff")
    sources = snapshot["sources"]
    if not isinstance(sources, list) or len(sources) != len(EXPECTED_SOURCES):
        _die("system snapshot source matrix differs")
    source_keys = {
        "archive",
        "archive_key_fingerprints",
        "archive_keyring_sha256",
        "archive_keyring_size",
        "components",
        "inrelease_sha256",
        "inrelease_size",
        "name",
        "release_sha256",
        "release_size",
        "release_suite",
        "suite",
        "timestamp_utc",
    }
    for position, expected in enumerate(EXPECTED_SOURCES):
        source = common.exact_object(
            sources[position], source_keys, f"system snapshot source {position}"
        )
        if {key: source[key] for key in expected} != expected:
            _die(f"system snapshot source {position} identity differs")
        source_text = common.timestamp(
            source["timestamp_utc"], f"system snapshot source {position} time"
        )
        source_time = dt.datetime.strptime(source_text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=dt.UTC
        )
        if source_time < cutoff_time or source_time > selection_time:
            _die(f"system snapshot source {position} time is outside the approved interval")
        for key in ("archive_keyring_sha256", "inrelease_sha256", "release_sha256"):
            common.hex64(source[key], f"system snapshot source {position} {key}")
        for key in ("archive_keyring_size", "inrelease_size", "release_size"):
            common.positive_int(source[key], f"system snapshot source {position} {key}")

    platforms = common.exact_object(value["platforms"], set(PLATFORMS), "system platforms")
    platform_keys = {
        "advisory_receipt_sha256",
        "advisory_receipt_size",
        "advisory_verdict",
        "architecture_all_packages",
        "config_digest",
        "config_size",
        "inventory_entries",
        "inventory_sha256",
        "inventory_size",
        "installability_receipt_sha256",
        "installability_receipt_size",
        "manifest_digest",
        "manifest_size",
        "package_lock",
        "resolution_receipt_sha256",
        "resolution_receipt_size",
        "tree_bytes",
        "tree_sha256",
    }
    for platform in PLATFORMS:
        item = common.exact_object(platforms[platform], platform_keys, f"system {platform}")
        for key in ("config_digest", "manifest_digest"):
            common.oci_digest(item[key], f"system {platform} {key}")
        for key in ("config_size", "manifest_size"):
            common.positive_int(item[key], f"system {platform} {key}")
        lock = common.exact_object(
            item["package_lock"], {"entries", "path", "sha256", "size"}, f"system {platform} lock"
        )
        architecture = ARCHITECTURES[platform]
        if lock["path"] != f"locks/system-linux-{architecture}.json":
            _die(f"system {platform} lock path differs")
        common.positive_int(lock["entries"], f"system {platform} lock entries")
        common.hex64(lock["sha256"], f"system {platform} lock SHA-256")
        common.positive_int(lock["size"], f"system {platform} lock size")
        for key in (
            "advisory_receipt_sha256",
            "inventory_sha256",
            "installability_receipt_sha256",
            "resolution_receipt_sha256",
            "tree_sha256",
        ):
            common.hex64(item[key], f"system {platform} {key}")
        for key in (
            "advisory_receipt_size",
            "inventory_entries",
            "inventory_size",
            "installability_receipt_size",
            "resolution_receipt_size",
            "tree_bytes",
        ):
            size = common.positive_int(item[key], f"system {platform} {key}")
            if key == "installability_receipt_size" and size > common.MAX_JSON_BYTES:
                _die(f"system {platform} installability receipt is overlarge")
        if item["advisory_verdict"] != "pass":
            _die(f"system {platform} advisory verdict differs")
        _validate_architecture_all_projection(
            item["architecture_all_packages"], context=f"system {platform}"
        )
    if (
        platforms[PLATFORMS[0]]["architecture_all_packages"]
        != platforms[PLATFORMS[1]]["architecture_all_packages"]
    ):
        _die("system Architecture: all package projections differ across platforms")
    return value


def validate_manifest_authority(manifest: Mapping[str, Any], policy_raw: bytes) -> dict[str, Any]:
    """Validate the tracked policy carrier and null-or-complete K selection."""

    policy = common.parse_json(policy_raw, context="system authority policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("system authority policy is not canonical JSON plus one LF")
    validate_policy(policy)
    authority = common.validate_tracked_selection(
        PROFILE,
        manifest,
        policy_raw=policy_raw,
        policy_key="system_authority_policy",
        authority_key="system_authority",
        policy_schema=AUTHORITY_SCHEMA,
        policy_release_path=POLICY_RELEASE_PATH,
        require_finalized=False,
    )
    if manifest["state"] == "unfinalized":
        return authority
    _validate_system_selection(manifest.get("system_packages"))
    return authority


def _reject_downstream(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in FORBIDDEN_RECEIPT_KEYS:
                _die("system receipt contains forbidden downstream field " + ".".join((*path, key)))
            _reject_downstream(item, (*path, key))
    elif isinstance(value, list):
        for position, item in enumerate(value):
            _reject_downstream(item, (*path, str(position)))


def _validate_generator(value: Any) -> dict[str, Any]:
    generator = common.exact_object(
        value, {"commit", "ref", "repository", "tree"}, "source.generator"
    )
    common.git_sha(generator["commit"], "source.generator.commit")
    common.git_sha(generator["tree"], "source.generator.tree")
    if generator["ref"] != common.PRODUCER_REF or generator["repository"] != {
        "id": common.PRODUCER_REPOSITORY_ID,
        "name": common.PRODUCER_REPOSITORY,
        "node_id": common.PRODUCER_REPOSITORY_NODE_ID,
    }:
        _die("system generator repository/ref differs")
    return generator


def _cross_check_generator_source_context(
    generator: Mapping[str, Any], derived: Mapping[str, Any]
) -> None:
    """Bind the signed receipt source to the native carrier's authenticated Git source."""

    expected = {
        "commit": generator["commit"],
        "format": material_build.GIT_SOURCE_BINDING_FORMAT,
        "reference": generator["ref"],
        "source_prefix": "packages/z4j",
        "tree": generator["tree"],
    }
    if derived["source_context"]["git"] != expected:
        _die("system receipt generator differs from derived source context")


SYSTEM_DERIVED_CHECKS = {
    "advisory",
    "installability",
    "inventory",
    "payload",
    "resolution",
    "snapshot",
    "tree",
}
SYSTEM_PLATFORM_SELECTION_KEYS = {
    "advisory_receipt_sha256",
    "advisory_receipt_size",
    "advisory_verdict",
    "architecture_all_packages",
    "installability_receipt_sha256",
    "installability_receipt_size",
    "inventory_entries",
    "inventory_sha256",
    "inventory_size",
    "package_lock",
    "resolution_receipt_sha256",
    "resolution_receipt_size",
    "tree_bytes",
    "tree_sha256",
}

ARCHITECTURE_ALL_PACKAGE_KEYS = {
    "architecture",
    "control",
    "depends",
    "essential",
    "filename",
    "index_stanza_sha256",
    "name",
    "pre_depends",
    "provides",
    "repository_filename",
    "sha256",
    "size",
    "source",
    "version",
}


def _architecture_all_projection(packages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Carry every platform-independent field of each Architecture: all package."""

    return [
        {key: package[key] for key in package if key != "index_path"}
        for package in packages
        if package["architecture"] == "all"
    ]


def _validate_architecture_all_projection(value: Any, *, context: str) -> list[dict[str, Any]]:
    """Validate the untrusted cross-platform projection before comparing it."""

    if not isinstance(value, list):
        _die(f"{context} Architecture: all projection is not a list")
    projection: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for position, item in enumerate(value):
        package = common.exact_object(
            item,
            ARCHITECTURE_ALL_PACKAGE_KEYS,
            f"{context} Architecture: all package {position}",
        )
        if (
            package["architecture"] != "all"
            or not all(
                isinstance(package[key], str) and package[key]
                for key in ("filename", "name", "repository_filename", "source", "version")
            )
            or DEBIAN_PACKAGE_NAME.fullmatch(package["name"]) is None
            or re.fullmatch(r"[!-~]+", package["version"]) is None
            or package["essential"] not in {None, "yes"}
            or any(
                package[key] is not None and not isinstance(package[key], str)
                for key in ("depends", "pre_depends", "provides")
            )
        ):
            _die(f"{context} Architecture: all package identity differs")
        common.hex64(package["sha256"], f"{context} Architecture: all package SHA-256")
        common.hex64(
            package["index_stanza_sha256"],
            f"{context} Architecture: all package index stanza",
        )
        common.positive_int(package["size"], f"{context} Architecture: all package size")
        if package["size"] > MAX_DEB_BYTES:
            _die(f"{context} Architecture: all package exceeds its bound")
        filename = _debian_relative_path(
            package["filename"], context=f"{context} Architecture: all package filename"
        )
        repository_filename = _debian_relative_path(
            package["repository_filename"],
            context=f"{context} Architecture: all repository filename",
        )
        if (
            PurePosixPath(filename).name != filename
            or not filename.endswith(".deb")
            or not repository_filename.endswith(".deb")
        ):
            _die(f"{context} Architecture: all package filename differs")
        control = common.exact_object(
            package["control"],
            {"path", "sha256", "size"},
            f"{context} Architecture: all package control",
        )
        common.hex64(control["sha256"], f"{context} Architecture: all control SHA-256")
        common.positive_int(control["size"], f"{context} Architecture: all control size")
        if control["path"] != filename + ".control" or control["size"] > MAX_CONTROL_STANZA_BYTES:
            _die(f"{context} Architecture: all control identity differs")
        identity = (package["name"], package["version"])
        if identity in identities:
            _die(f"{context} Architecture: all projection contains a duplicate")
        identities.add(identity)
        projection.append(package)
    if [package["name"] for package in projection] != sorted(
        (package["name"] for package in projection), key=str.encode
    ):
        _die(f"{context} Architecture: all projection is unsorted")
    return projection


def _cross_check_architecture_all_platforms(platforms: Mapping[str, Any]) -> None:
    projections = {
        platform: _validate_architecture_all_projection(
            platforms[platform]["selection"]["architecture_all_packages"],
            context=f"derived system {platform}",
        )
        for platform in PLATFORMS
    }
    if projections[PLATFORMS[0]] != projections[PLATFORMS[1]]:
        _die("derived system Architecture: all package projections differ across platforms")


def _system_execution_contracts(
    policy: Mapping[str, Any], policy_sha256: str
) -> dict[str, dict[str, Any]]:
    material = policy["system_packages"]
    generator = material["generator"]
    return {
        platform: {
            "build_args": {
                "RESOLVER_IMAGE": material["resolver_base"]["image"],
                "Z4J_PLATFORM": platform,
                "Z4J_POLICY_SHA256": policy_sha256,
            },
            "build_operands": {
                "context_name": "context",
                "dockerfile": generator["dockerfile"],
                "output_directories": {"A": "A", "B": "B"},
            },
            "builder_prefix": generator["builder"],
            "docker_authority": generator["docker"]["platforms"][platform],
            "execution_plane": generator["execution_plane"],
        }
        for platform in PLATFORMS
    }


def _derive_system_trivy_semantic_report(
    value: Any,
    *,
    packages: Sequence[Mapping[str, Any]],
    platform: str,
) -> dict[str, Any]:
    """Derive the clean Debian package projection from retained raw Trivy JSON."""

    report = common.exact_object(
        value,
        {
            "ArtifactName",
            "ArtifactType",
            "CreatedAt",
            "Metadata",
            "ReportID",
            "Results",
            "SchemaVersion",
            "Trivy",
        },
        f"system {platform} raw Trivy advisory report",
    )
    if (
        report["SchemaVersion"] != 2
        or not all(
            isinstance(report[key], str) and report[key]
            for key in ("ArtifactName", "ArtifactType", "CreatedAt", "ReportID", "Trivy")
        )
        or not isinstance(report["Metadata"], dict)
    ):
        _die(f"system {platform} raw Trivy advisory envelope differs")
    results = report["Results"]
    if not isinstance(results, list) or len(results) != 1:
        _die(f"system {platform} raw Trivy result set differs")
    result = common.exact_object(
        results[0], {"Class", "Packages", "Target", "Type"}, f"system {platform} Trivy result"
    )
    raw_packages = result["Packages"]
    if (
        result["Class"] != "os-pkgs"
        or result["Type"] != "debian"
        or not isinstance(result["Target"], str)
        or not result["Target"]
        or not isinstance(raw_packages, list)
        or not raw_packages
    ):
        _die(f"system {platform} raw Trivy Debian result identity differs")
    expected = {(item["name"], item["version"]) for item in packages}
    if len(expected) != len(packages):
        _die(f"system {platform} authenticated lock package identity is duplicate")
    scanned: set[tuple[str, str]] = set()
    for position, item in enumerate(raw_packages):
        if not isinstance(item, dict):
            _die(f"system {platform} raw Trivy package {position} is malformed")
        name = item.get("Name")
        version = item.get("Version")
        identity = (name, version)
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or identity not in expected
            or identity in scanned
        ):
            _die(f"system {platform} raw Trivy package differs from authenticated lock")
        scanned.add(identity)
    if scanned != expected:
        _die(f"system {platform} raw Trivy package inventory differs from authenticated lock")
    semantic_packages = [
        {"name": name, "version": version}
        for name, version in sorted(scanned, key=lambda item: (item[0].encode(), item[1].encode()))
    ]
    return {
        "findings": [],
        "format": "z4j-production-system-trivy-semantic-report-v1",
        "packages": semantic_packages,
        "platform": platform,
        "result_type": "debian",
    }


def _validate_system_run_evidence(
    root: Path,
    *,
    platform: str,
    policy: Mapping[str, Any],
    packages: Sequence[Mapping[str, Any]],
    resolution: Mapping[str, Any],
    installability: Mapping[str, Any],
) -> dict[str, Any]:
    generator = policy["system_packages"]["generator"]
    environment = _closed_generator_environment(generator["source_date_epoch"])
    acquisition_commands = _isolated_apt_commands(
        platform, apt_get="/acquired/.generator/tools/apt-get"
    )
    apt, _apt_raw = material_build.load_canonical_evidence(
        root,
        "acquisition/apt-commands.json",
        context=f"system {platform} apt run evidence",
    )
    if set(apt) != {"commands", "format", "platform"} or (
        apt["format"] != "z4j-production-system-apt-run-evidence-v1" or apt["platform"] != platform
    ):
        _die(f"system {platform} apt run-evidence identity differs")
    apt_commands = common.exact_object(
        apt["commands"], {"apt-download", "apt-resolve", "apt-update"}, "system apt commands"
    )
    for evidence_name, command_name in (
        ("apt-download", "download"),
        ("apt-resolve", "resolve"),
        ("apt-update", "update"),
    ):
        material_build.validate_evidence_command(
            apt_commands[evidence_name],
            root / "acquisition",
            context=f"system {platform} {evidence_name}",
            expected_argv=acquisition_commands[command_name],
            expected_cwd="/authority",
            expected_environment=environment,
        )
    if resolution["commands"] != acquisition_commands:
        _die(f"system {platform} resolution commands differ from policy-derived commands")

    installed, _installed_raw = material_build.load_canonical_evidence(
        root,
        "installability/commands.json",
        context=f"system {platform} installability run evidence",
    )
    if set(installed) != {"commands", "format"} or installed["format"] != (
        "z4j-production-system-installability-run-evidence-v1"
    ):
        _die(f"system {platform} installability run-evidence identity differs")
    installed_commands = common.exact_object(
        installed["commands"],
        {"apt-check", "apt-install"},
        "system installability commands",
    )
    installability_commands = _real_base_apt_commands(
        platform,
        apt_get="/acquired/.generator/tools/apt-get",
        debs=[INTERNAL_ACQUIRED_ROOT / "debs" / item["filename"] for item in packages],
    )
    for evidence_name, command_name in (("apt-check", "check"), ("apt-install", "install")):
        material_build.validate_evidence_command(
            installed_commands[evidence_name],
            root / "installability",
            context=f"system {platform} {evidence_name}",
            expected_argv=installability_commands[command_name],
            expected_cwd="/authority",
            expected_environment=environment,
        )
    if installability["commands"] != installability_commands:
        _die(f"system {platform} installability commands differ from policy-derived commands")

    trivy, _trivy_raw = material_build.load_canonical_evidence(
        root, "trivy-run.json", context=f"system {platform} Trivy run evidence"
    )
    if set(trivy) != {"command", "format", "raw_report"} or trivy["format"] != (
        "z4j-production-system-trivy-run-evidence-v1"
    ):
        _die(f"system {platform} Trivy run-evidence identity differs")
    material_build.validate_evidence_command(
        trivy["command"],
        root,
        context=f"system {platform} Trivy command",
        expected_argv=[
            "/out/payload/evidence/trivy",
            "rootfs",
            "--cache-dir",
            "/out/payload/evidence/trivy-database",
            "--offline-scan",
            "--skip-db-update",
            "--scanners",
            "vuln",
            "--pkg-types",
            "os",
            "--list-all-pkgs",
            "--severity",
            "HIGH,CRITICAL",
            "--ignore-unfixed=false",
            "--format",
            "json",
            "--output",
            "/out/run-evidence/advisory-report.raw.json",
            SYSTEM_SCAN_ROOT,
        ],
        expected_cwd="/authority",
        expected_environment=environment,
    )
    raw_report = common.exact_object(
        trivy["raw_report"], {"path", "sha256", "size"}, "system Trivy raw report"
    )
    if material_build.evidence_file_seal(
        root, raw_report["path"], context=f"system {platform} Trivy raw report"
    ) != {"sha256": raw_report["sha256"], "size": raw_report["size"]}:
        _die(f"system {platform} Trivy raw report differs")
    raw = material_build.read_regular(
        root / raw_report["path"],
        maximum=64 * 1024 * 1024,
        context=f"system {platform} raw Trivy advisory report",
    )
    return _derive_system_trivy_semantic_report(
        common.parse_json(raw, context=f"system {platform} raw Trivy advisory report"),
        packages=packages,
        platform=platform,
    )


def _validate_system_lock(  # noqa: PLR0912, PLR0915 - one closed validation boundary
    lock: Mapping[str, Any],
    payload: Path,
    *,
    platform: str,
    policy: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    material = policy["system_packages"]
    expected_lock_keys = {
        "format",
        "indexes",
        "packages",
        "platform",
        "requested",
        "snapshot_selection_utc",
        "sources",
    }
    packages = lock.get("packages")
    snapshot = _snapshot_selection(material["snapshot"])
    if (
        set(lock) != expected_lock_keys
        or lock["format"] != material["package_lock_format"]
        or lock["platform"] != platform
        or lock["requested"] != material["requested"]
        or lock["snapshot_selection_utc"] != snapshot["selection_utc"]
        or lock["sources"] != snapshot["sources"]
        or not isinstance(packages, list)
        or not packages
    ):
        _die(f"system {platform} package lock differs")
    architecture = ARCHITECTURES[platform]
    expected_indexes = [
        {
            "path": f"main/binary-{architecture}/Packages",
            "sha256": source["packages"][platform]["sha256"],
            "size": source["packages"][platform]["size"],
            "source": source["name"],
        }
        for source in material["snapshot"]["sources"]
    ]
    if lock["indexes"] != expected_indexes:
        _die(f"system {platform} package indexes differ from policy")
    indexed_records: dict[str, dict[str, dict[str, Any]]] = {}
    for source in material["snapshot"]["sources"]:
        prefix = "snapshot/" + source["name"] + "/"
        for relative, key in (
            ("archive-keyring.gpg", "archive_keyring"),
            ("InRelease", "inrelease"),
            ("Release", "release"),
            (f"indexes/main/binary-{architecture}/Packages", "packages"),
        ):
            authority = source[key] if key != "packages" else source[key][platform]
            if material_build.evidence_file_seal(
                payload,
                prefix + relative,
                context=f"system {platform} retained {source['name']} {relative}",
            ) != {"sha256": authority["sha256"], "size": authority["size"]}:
                _die(f"system {platform} retained snapshot differs from policy")
        inrelease = material_build.read_regular(
            payload / (prefix + "InRelease"),
            maximum=source["inrelease"]["size"],
            context=f"system {platform} retained signed Release",
        )
        release = material_build.read_regular(
            payload / (prefix + "Release"),
            maximum=MAX_RELEASE_BYTES,
            context=f"system {platform} retained Release",
        )
        if _clearsigned_payload(inrelease) != release:
            _die(f"system {platform} retained signed Release bytes differ")
        index_authority = source["packages"][platform]
        index_path = f"main/binary-{architecture}/Packages"
        release_seals = _release_index_seals(
            release, context=f"system {platform} retained {source['name']} Release"
        )
        if release_seals.get(index_path) != (
            index_authority["sha256"],
            index_authority["size"],
        ):
            _die(f"system {platform} signed Release does not authenticate Packages")
        index_raw = material_build.read_regular(
            payload / (prefix + "indexes/" + index_path),
            maximum=MAX_PACKAGES_INDEX_BYTES,
            context=f"system {platform} retained {source['name']} Packages index",
        )
        if {"sha256": common.sha256(index_raw), "size": len(index_raw)} != {
            "sha256": index_authority["sha256"],
            "size": index_authority["size"],
        }:
            _die(f"system {platform} retained Packages bytes differ from policy")
        records = _parse_package_index(index_raw, source["name"], architecture)
        indexed_records[source["name"]] = {
            record["index_stanza_sha256"]: record for record in records
        }
    package_keys = {
        "architecture",
        "control",
        "depends",
        "essential",
        "filename",
        "index_path",
        "index_stanza_sha256",
        "name",
        "pre_depends",
        "provides",
        "repository_filename",
        "sha256",
        "size",
        "source",
        "version",
    }
    validated: list[Mapping[str, Any]] = []
    selected_stanzas: set[tuple[str, str]] = set()
    for value in packages:
        package = common.exact_object(value, package_keys, f"system {platform} locked package")
        if (
            package["architecture"] not in {architecture, "all"}
            or not all(
                isinstance(package[key], str) and package[key]
                for key in ("filename", "name", "source", "version")
            )
            or package["source"]
            not in {source["name"] for source in material["snapshot"]["sources"]}
            or package["index_path"] != f"main/binary-{architecture}/Packages"
        ):
            _die(f"system {platform} locked package identity differs")
        common.hex64(package["sha256"], f"system {platform} package SHA-256")
        common.hex64(package["index_stanza_sha256"], f"system {platform} package index stanza")
        common.positive_int(package["size"], f"system {platform} package size")
        filename = package["filename"]
        if (
            _debian_relative_path(filename, context=f"system {platform} package filename")
            != filename
            or PurePosixPath(filename).name != filename
            or not filename.endswith(".deb")
        ):
            _die(f"system {platform} package filename differs")
        stanza_key = (package["source"], package["index_stanza_sha256"])
        indexed = indexed_records[package["source"]].get(package["index_stanza_sha256"])
        if indexed is None or stanza_key in selected_stanzas:
            _die(f"system {platform} locked package is absent or duplicate in its index")
        selected_stanzas.add(stanza_key)
        if any(package[key] != indexed[key] for key in indexed):
            _die(f"system {platform} locked package differs from its authenticated index")
        deb_raw = material_build.read_regular(
            payload / "debs" / filename,
            maximum=MAX_DEB_BYTES,
            context=f"system {platform} package payload",
        )
        if {"sha256": common.sha256(deb_raw), "size": len(deb_raw)} != {
            "sha256": package["sha256"],
            "size": package["size"],
        }:
            _die(f"system {platform} package payload differs from its authenticated index")
        extracted_control = _extract_deb_control(
            deb_raw, context=f"system {platform} Debian package {package['name']}"
        )
        control = common.exact_object(
            package["control"], {"path", "sha256", "size"}, f"system {platform} control"
        )
        common.hex64(control["sha256"], f"system {platform} package control SHA-256")
        common.positive_int(control["size"], f"system {platform} package control size")
        if control["path"] != filename + ".control" or control["size"] > MAX_CONTROL_STANZA_BYTES:
            _die(f"system {platform} package control path or size differs")
        control_raw = material_build.read_regular(
            payload / "controls" / control["path"],
            maximum=MAX_CONTROL_STANZA_BYTES,
            context=f"system {platform} package control",
        )
        if control_raw != extracted_control or {
            "sha256": common.sha256(control_raw),
            "size": len(control_raw),
        } != {"sha256": control["sha256"], "size": control["size"]}:
            _die(f"system {platform} retained control differs from the package control member")
        control_identity = _parse_control_stanza(
            control_raw, context=f"system {platform} Debian control {package['name']}"
        )
        if control_identity != {
            key: indexed[key]
            for key in (
                "architecture",
                "depends",
                "essential",
                "name",
                "pre_depends",
                "provides",
                "version",
            )
        }:
            _die(f"system {platform} package control differs from its authenticated index")
        validated.append(package)
    names = [item["name"] for item in validated]
    if (
        names != sorted(names, key=str.encode)
        or len(set(names)) != len(names)
        or not set(material["requested"]).issubset(names)
    ):
        _die(f"system {platform} package closure is duplicate, unsorted, or incomplete")
    return validated


def _validate_system_tool_receipt(
    value: Any,
    *,
    name: str,
    authority: Mapping[str, Any],
    context: str,
) -> dict[str, Any]:
    receipt = common.exact_object(
        value,
        {"binary_sha256", "name", "version", "version_output_sha256"},
        context,
    )
    if receipt != {
        "binary_sha256": authority["sha256"],
        "name": name,
        "version": receipt["version"],
        "version_output_sha256": authority["version_output_sha256"],
    }:
        _die(f"{context} authority differs")
    common.ascii_text(receipt["version"], f"{context} version")
    return receipt


def _validate_system_resolution(
    value: Any,
    payload: Path,
    *,
    lock_sha256: str,
    packages: list[Mapping[str, Any]],
    platform: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    material = policy["system_packages"]
    generator = material["generator"]
    resolution = common.exact_object(
        value,
        {
            "apt",
            "apt_config_sha256",
            "commands",
            "dpkg_deb",
            "exit_code",
            "format",
            "gpgv",
            "isolation",
            "list_state",
            "package_lock_sha256",
            "platform",
            "snapshot",
            "solver_plan",
            "sources_list_sha256",
        },
        f"system {platform} resolution receipt",
    )
    tools = generator["tools"]
    _validate_system_tool_receipt(
        resolution["apt"],
        name="apt-get",
        authority=tools["apt_get"]["platforms"][platform],
        context=f"system {platform} apt-get receipt",
    )
    _validate_system_tool_receipt(
        resolution["dpkg_deb"],
        name="dpkg-deb",
        authority=tools["dpkg_deb"]["platforms"][platform],
        context=f"system {platform} dpkg-deb receipt",
    )
    _validate_system_tool_receipt(
        resolution["gpgv"],
        name="gpgv",
        authority=tools["gpgv"]["platforms"][platform],
        context=f"system {platform} gpgv receipt",
    )
    apt_config = material_build.evidence_file_seal(
        payload, "evidence/apt.conf", context=f"system {platform} apt configuration"
    )
    sources_list = material_build.evidence_file_seal(
        payload, "evidence/sources.list", context=f"system {platform} apt sources"
    )
    os_release = generator["resolution_interface"]["os_release"]["platforms"][platform]
    if (
        material_build.read_regular(
            payload / "evidence/apt.conf",
            maximum=material_build.MAX_FILE_BYTES,
            context=f"system {platform} apt configuration bytes",
        )
        != _system_apt_config()
        or material_build.read_regular(
            payload / "evidence/sources.list",
            maximum=material_build.MAX_FILE_BYTES,
            context=f"system {platform} apt sources bytes",
        )
        != _system_sources_list(_snapshot_selection(material["snapshot"]))
        or material_build.evidence_file_seal(
            payload, "evidence/os-release", context=f"system {platform} os-release"
        )
        != {"sha256": os_release["sha256"], "size": os_release["size"]}
    ):
        _die(f"system {platform} retained apt/base authority differs")
    expected_commands = _isolated_apt_commands(
        platform, apt_get="/acquired/.generator/tools/apt-get"
    )
    expected_solver = [{"name": item["name"], "version": item["version"]} for item in packages]
    if (
        resolution["apt_config_sha256"] != apt_config["sha256"]
        or resolution["commands"] != expected_commands
        or resolution["exit_code"] != 0
        or resolution["format"] != material["resolution_receipt_format"]
        or resolution["isolation"]
        != {
            "ambient_dpkg_status_used": False,
            "architecture": ARCHITECTURES[platform],
            "archives_initially_empty": True,
            "empty_status_sha256": common.sha256(b""),
            "empty_status_size": 0,
            "lists_initially_empty": True,
            "state_root": ISOLATED_APT_ROOT,
            "trusted": "-",
            "trusted_parts": "-",
        }
        or resolution["package_lock_sha256"] != lock_sha256
        or resolution["platform"] != platform
        or resolution["snapshot"] != _snapshot_selection(material["snapshot"])
        or resolution["solver_plan"] != expected_solver
        or resolution["sources_list_sha256"] != sources_list["sha256"]
        or not isinstance(resolution["list_state"], list)
        or not resolution["list_state"]
    ):
        _die(f"system {platform} resolution receipt differs from policy/payload")
    return resolution


def _validate_system_installability(
    value: Any,
    *,
    lock_sha256: str,
    packages: list[Mapping[str, Any]],
    platform: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    material = policy["system_packages"]
    expected_installed = sorted(
        (
            {
                "architecture": item["architecture"],
                "name": item["name"],
                "status": "install ok installed",
                "version": item["version"],
            }
            for item in packages
        ),
        key=lambda item: (item["name"].encode(), item["architecture"].encode()),
    )
    expected_commands = _real_base_apt_commands(
        platform,
        apt_get="/acquired/.generator/tools/apt-get",
        debs=[INTERNAL_ACQUIRED_ROOT / "debs" / item["filename"] for item in packages],
    )
    expected = {
        "base_status": material["generator"]["resolution_interface"]["base_status"]["platforms"][
            platform
        ],
        "commands": expected_commands,
        "format": material["installability_receipt_format"],
        "installed": expected_installed,
        "maintainer_scripts": "disposable-network-none-build-stage-only",
        "package_lock_sha256": lock_sha256,
        "platform": platform,
        "result": "pass",
    }
    if value != expected:
        _die(f"system {platform} installability receipt differs from lock/policy")
    return dict(value)


def _derive_system_platform_build(
    root: Path,
    *,
    platform: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    material = policy["system_packages"]
    inventory = material_build.derive_payload_inventory(
        root / "payload",
        platform=platform,
        inventory_format=material["inventory_format"],
        tree_format=material["tree_format"],
    )
    lock, lock_raw = material_build.load_canonical_evidence(
        root / "payload",
        "locks/packages.json",
        context=f"system {platform} package lock",
    )
    packages = _validate_system_lock(
        lock,
        root / "payload",
        platform=platform,
        policy=policy,
    )
    expected_paths = {
        "evidence/advisory-receipt.json",
        "evidence/advisory-report.json",
        "evidence/apt.conf",
        "evidence/installability-receipt.json",
        "evidence/os-release",
        "evidence/resolution-receipt.json",
        "evidence/sources.list",
        "evidence/trivy",
        "evidence/trivy-version.txt",
        "locks/packages.json",
        *("controls/" + item["control"]["path"] for item in packages),
        *("debs/" + item["filename"] for item in packages),
    }
    architecture = ARCHITECTURES[platform]
    for source in material["snapshot"]["sources"]:
        prefix = "snapshot/" + source["name"] + "/"
        expected_paths.update(
            {
                prefix + "archive-keyring.gpg",
                prefix + "InRelease",
                prefix + "Release",
                prefix + f"indexes/main/binary-{architecture}/Packages",
            }
        )
    payload_paths = {item["path"] for item in material_build.file_records(root / "payload")}
    if (
        any(
            path not in expected_paths and not path.startswith("evidence/trivy-database/")
            for path in payload_paths
        )
        or not expected_paths <= payload_paths
    ):
        _die(f"system {platform} payload path set differs")
    lock_sha256 = common.sha256(lock_raw)

    resolution, resolution_raw = material_build.load_canonical_evidence(
        root / "payload",
        "evidence/resolution-receipt.json",
        context=f"system {platform} resolution receipt",
    )
    resolution = _validate_system_resolution(
        resolution,
        root / "payload",
        lock_sha256=lock_sha256,
        packages=packages,
        platform=platform,
        policy=policy,
    )

    installability, installability_raw = material_build.load_canonical_evidence(
        root / "payload",
        "evidence/installability-receipt.json",
        context=f"system {platform} installability receipt",
    )
    installability = _validate_system_installability(
        installability,
        lock_sha256=lock_sha256,
        packages=packages,
        platform=platform,
        policy=policy,
    )

    advisory, advisory_raw = material_build.load_canonical_evidence(
        root / "payload",
        "evidence/advisory-receipt.json",
        context=f"system {platform} advisory receipt",
    )
    advisory = common.exact_object(
        advisory,
        {
            "database",
            "findings",
            "format",
            "package_lock_sha256",
            "platform",
            "policy",
            "report",
            "scanner",
            "synthetic_status",
            "verdict",
        },
        f"system {platform} advisory receipt",
    )
    native_trivy = material["generator"]["trivy"]["platforms"][platform]
    synthetic_status = _synthetic_dpkg_status(packages, root / "payload/controls")
    if (
        advisory["database"] != material["generator"]["trivy"]["database"]
        or advisory["format"] != material["advisory_receipt_format"]
        or advisory["platform"] != platform
        or advisory["verdict"] != "pass"
        or advisory["findings"] != []
        or advisory["package_lock_sha256"] != lock_sha256
        or advisory["policy"]
        != {
            "ignore_unfixed": False,
            "list_all_packages": True,
            "required_result_type": "debian",
            "severities": ["HIGH", "CRITICAL"],
        }
        or advisory["scanner"]
        != {
            "binary_sha256": native_trivy["binary"]["sha256"],
            "name": "trivy",
            "version": material["generator"]["trivy"]["version"],
            "version_output_sha256": native_trivy["version_output_sha256"],
        }
        or advisory["synthetic_status"]
        != {"sha256": common.sha256(synthetic_status), "size": len(synthetic_status)}
    ):
        _die(f"system {platform} advisory receipt differs")
    report = common.exact_object(
        advisory.get("report"), {"path", "sha256", "size"}, f"system {platform} advisory report"
    )
    if report["path"] != "evidence/advisory-report.json" or material_build.evidence_file_seal(
        root / "payload", report["path"], context=f"system {platform} advisory report"
    ) != {"sha256": report["sha256"], "size": report["size"]}:
        _die(f"system {platform} advisory report seal differs")
    semantic_report, _semantic_raw = material_build.load_canonical_evidence(
        root / "payload", report["path"], context=f"system {platform} semantic advisory report"
    )
    expected_packages = sorted(
        ({"name": item["name"], "version": item["version"]} for item in packages),
        key=lambda item: (item["name"].encode(), item["version"].encode()),
    )
    if (
        semantic_report.get("format") != "z4j-production-system-trivy-semantic-report-v1"
        or semantic_report.get("platform") != platform
        or semantic_report.get("result_type") != "debian"
        or semantic_report.get("findings") != []
        or semantic_report.get("packages") != expected_packages
    ):
        _die(f"system {platform} semantic advisory report differs")
    trivy_binary = material_build.evidence_file_seal(
        root / "payload", "evidence/trivy", context=f"system {platform} Trivy binary"
    )
    trivy_version = material_build.evidence_file_seal(
        root / "payload",
        "evidence/trivy-version.txt",
        context=f"system {platform} Trivy version",
    )
    database_records = material_build.file_records(
        root / "payload/evidence/trivy-database", exclude=frozenset()
    )
    database_framing = {"files": database_records, "format": "z4j-trivy-database-tree-v1"}
    if (
        trivy_binary != native_trivy["binary"]
        or trivy_version["sha256"] != native_trivy["version_output_sha256"]
        or trivy_version["size"] <= 0
        or common.sha256(common.canonical_json(database_framing, terminal_lf=False))
        != advisory["database"]["tree_sha256"]
        or material_build.evidence_file_seal(
            root / "payload",
            "evidence/trivy-database/db/metadata.json",
            context=f"system {platform} Trivy database metadata",
        )["sha256"]
        != advisory["database"]["metadata_sha256"]
    ):
        _die(f"system {platform} retained Trivy authority differs")
    raw_semantic_report = _validate_system_run_evidence(
        root / "run-evidence",
        platform=platform,
        policy=policy,
        packages=packages,
        resolution=resolution,
        installability=installability,
    )
    if semantic_report != raw_semantic_report:
        _die(f"system {platform} semantic report differs from raw Trivy evidence")
    return {
        "checks": dict.fromkeys(SYSTEM_DERIVED_CHECKS, True),
        "payload": inventory,
        "selection": {
            "advisory_receipt_sha256": common.sha256(advisory_raw),
            "advisory_receipt_size": len(advisory_raw),
            "advisory_verdict": "pass",
            "architecture_all_packages": _architecture_all_projection(packages),
            **inventory,
            "installability_receipt_sha256": common.sha256(installability_raw),
            "installability_receipt_size": len(installability_raw),
            "package_lock": {
                "entries": len(packages),
                "path": f"locks/system-linux-{architecture}.json",
                "sha256": lock_sha256,
                "size": len(lock_raw),
            },
            "resolution_receipt_sha256": common.sha256(resolution_raw),
            "resolution_receipt_size": len(resolution_raw),
        },
    }


def aggregate_system_platform_results(
    inputs: Mapping[str, Mapping[str, Path]],
    destination: Path,
    *,
    policy_raw: bytes,
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive the exact system material claims from two extracted native carriers."""

    policy = common.parse_json(policy_raw, context="system aggregation policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("system aggregation policy is not canonical")
    poison = [item for item in validate_policy(policy) if item.startswith(("system", "generator "))]
    if poison:
        _die("system material inputs are UNFINALIZED: " + "; ".join(poison))
    policy_sha256 = common.sha256(policy_raw)
    contracts = _system_execution_contracts(policy, policy_sha256)
    carrier = material_build.aggregate_platform_result_carriers(
        inputs,
        destination,
        material="system",
        expected_policy_sha256=policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=contracts,
    )
    platforms: dict[str, Any] = {}
    for platform, architecture in ARCHITECTURES.items():
        builds = [
            {
                "id": build_id,
                **_derive_system_platform_build(
                    destination / architecture / build_id,
                    platform=platform,
                    policy=policy,
                ),
            }
            for build_id in ("A", "B")
        ]
        derived = [{key: item for key, item in build.items() if key != "id"} for build in builds]
        if derived[0] != derived[1]:
            _die(f"system {platform} derived A/B material differs")
        platforms[platform] = {"builds": builds, **builds[0]}
        platforms[platform].pop("id", None)
    _cross_check_architecture_all_platforms(platforms)
    return {
        "carrier_aggregation": carrier,
        "format": "z4j-production-system-derived-platform-aggregation-v1",
        "material": "system",
        "platforms": platforms,
        "policy_sha256": policy_sha256,
        "run": carrier["run"],
        "selected_build": "A",
        "source_context": carrier["source_context"],
    }


def validate_system_platform_aggregation(
    value: Any,
    *,
    policy_raw: bytes,
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate one previously derived dual-platform system aggregation."""

    policy = common.parse_json(policy_raw, context="system aggregation policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("system aggregation policy is not canonical")
    poison = [item for item in validate_policy(policy) if item.startswith(("system", "generator "))]
    if poison:
        _die("system material inputs are UNFINALIZED: " + "; ".join(poison))
    policy_sha256 = common.sha256(policy_raw)
    wrapper = material_build.validate_derived_platform_aggregation(
        value,
        material="system",
        expected_policy_sha256=policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=_system_execution_contracts(policy, policy_sha256),
        derived_checks=frozenset(SYSTEM_DERIVED_CHECKS),
        selection_keys=frozenset(SYSTEM_PLATFORM_SELECTION_KEYS),
    )
    _cross_check_architecture_all_platforms(wrapper["platforms"])
    for platform, architecture in ARCHITECTURES.items():
        selection = wrapper["platforms"][platform]["selection"]
        for key in (
            "advisory_receipt_sha256",
            "installability_receipt_sha256",
            "resolution_receipt_sha256",
        ):
            common.hex64(selection[key], f"derived system {platform} {key}")
        for key in (
            "advisory_receipt_size",
            "installability_receipt_size",
            "resolution_receipt_size",
        ):
            common.positive_int(selection[key], f"derived system {platform} {key}")
        if selection["advisory_verdict"] != "pass":
            _die(f"derived system {platform} advisory verdict differs")
        lock = common.exact_object(
            selection["package_lock"],
            {"entries", "path", "sha256", "size"},
            f"derived system {platform} package lock",
        )
        common.positive_int(lock["entries"], f"derived system {platform} package count")
        common.hex64(lock["sha256"], f"derived system {platform} package lock SHA-256")
        common.positive_int(lock["size"], f"derived system {platform} package lock size")
        if lock["path"] != f"locks/system-linux-{architecture}.json":
            _die(f"derived system {platform} package lock path differs")
    return wrapper


def _validate_verification(  # noqa: PLR0912
    value: Any,
    *,
    policy_sha256: str,
    platform_aggregation: Mapping[str, Any],
) -> dict[str, Any]:
    verification = common.exact_object(value, {"aggregate", "platforms"}, "verification")
    aggregate = common.exact_object(
        verification["aggregate"],
        {
            "all_platforms_passed",
            "builds_byte_identical",
            "index_canonical",
            "native_platforms",
            "policy_sha256",
            "referrers_native",
        },
        "verification.aggregate",
    )
    if aggregate != {
        "all_platforms_passed": True,
        "builds_byte_identical": True,
        "index_canonical": True,
        "native_platforms": True,
        "policy_sha256": policy_sha256,
        "referrers_native": True,
    }:
        _die("system aggregate verification differs")
    platforms = common.exact_object(
        verification["platforms"], set(PLATFORMS), "verification.platforms"
    )
    checks = {
        "advisory",
        "installability",
        "inventory",
        "oci",
        "payload",
        "resolution",
        "snapshot",
        "tree",
    }
    for platform in PLATFORMS:
        derived = platform_aggregation["platforms"][platform]
        identity = platform_aggregation["carrier_aggregation"]["platforms"][platform]["identity"]
        item = common.exact_object(
            platforms[platform],
            {"artifact", "builds", "checks", "job", "selected_build"},
            f"verification.{platform}",
        )
        artifact = common.exact_object(
            item["artifact"], {"id", "name", "sha256", "size"}, f"{platform} artifact"
        )
        common.positive_int(artifact["id"], f"{platform} artifact ID")
        common.ascii_text(artifact["name"], f"{platform} artifact name")
        common.hex64(artifact["sha256"], f"{platform} artifact SHA-256")
        common.positive_int(artifact["size"], f"{platform} artifact size")
        if artifact != identity["artifact"]:
            _die(f"{platform} receipt artifact differs from authenticated aggregation")
        builds = item["builds"]
        if not isinstance(builds, list) or len(builds) != 2:
            _die(f"{platform} must bind exactly builds A and B")
        normalized: list[dict[str, Any]] = []
        for position, expected_id in enumerate(("A", "B")):
            build = common.exact_object(
                builds[position],
                {
                    "config_digest",
                    "config_size",
                    "id",
                    "inventory_sha256",
                    "inventory_size",
                    "layer_digest",
                    "layer_diff_id",
                    "layer_size",
                    "manifest_digest",
                    "manifest_size",
                    "tree_bytes",
                    "tree_sha256",
                },
                f"{platform} build {expected_id}",
            )
            if build["id"] != expected_id:
                _die(f"{platform} build order differs")
            for key in ("config_digest", "layer_digest", "layer_diff_id", "manifest_digest"):
                common.oci_digest(build[key], f"{platform} build {expected_id} {key}")
            for key in ("inventory_sha256", "tree_sha256"):
                common.hex64(build[key], f"{platform} build {expected_id} {key}")
            for key in (
                "config_size",
                "inventory_size",
                "layer_size",
                "manifest_size",
                "tree_bytes",
            ):
                common.positive_int(build[key], f"{platform} build {expected_id} {key}")
            normalized.append({key: item for key, item in build.items() if key != "id"})
            payload = derived["builds"][position]["payload"]
            if {
                "inventory_sha256": build["inventory_sha256"],
                "inventory_size": build["inventory_size"],
                "tree_bytes": build["tree_bytes"],
                "tree_sha256": build["tree_sha256"],
            } != {
                key: payload[key]
                for key in ("inventory_sha256", "inventory_size", "tree_bytes", "tree_sha256")
            }:
                _die(f"{platform} build {expected_id} differs from derived payload")
        if normalized[0] != normalized[1]:
            _die(f"{platform} builds A/B are not byte-identical")
        receipt_checks = common.exact_object(item["checks"], checks, f"{platform} checks")
        if (
            receipt_checks != dict.fromkeys(checks, True)
            or {key: receipt_checks[key] for key in SYSTEM_DERIVED_CHECKS} != derived["checks"]
        ):
            _die(f"{platform} system checks did not all pass")
        job = common.exact_object(
            item["job"],
            {"id", "name", "runner_arch", "runner_name", "runner_os"},
            f"{platform} job",
        )
        common.positive_int(job["id"], f"{platform} job ID")
        common.ascii_text(job["name"], f"{platform} job name")
        common.ascii_text(job["runner_name"], f"{platform} runner name")
        expected_arch = "X64" if platform.endswith("amd64") else "ARM64"
        if job["runner_arch"] != expected_arch or job["runner_os"] != "Linux":
            _die(f"{platform} native runner identity differs")
        if job != identity["job"]:
            _die(f"{platform} receipt job differs from authenticated aggregation")
        if item["selected_build"] != platform_aggregation["selected_build"]:
            _die(f"{platform} selected build differs")
    return verification


def validate_receipt(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    policy_raw: bytes,
    platform_aggregation: Mapping[str, Any],
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate the closed, pre-K signed system receipt."""

    receipt = common.exact_object(
        value,
        {
            "ceremony",
            "contract",
            "format",
            "protection",
            "readback",
            "release",
            "repository",
            "result",
            "source",
            "system_packages",
            "transition",
            "verification",
        },
        "system authority receipt",
    )
    _reject_downstream(receipt)
    if (
        receipt["format"] != AUTHORITY_FORMAT
        or receipt["release"] != RELEASE
        or receipt["repository"] != REPOSITORY
        or receipt["result"] != "pass"
    ):
        _die("system receipt identity/result differs")
    contract = common.exact_object(
        receipt["contract"],
        {"carrier_path", "release_path", "schema", "sha256", "size"},
        "receipt.contract",
    )
    if contract != {
        "carrier_path": POLICY_CARRIER_PATH,
        "release_path": POLICY_RELEASE_PATH,
        "schema": AUTHORITY_SCHEMA,
        "sha256": common.sha256(policy_raw),
        "size": len(policy_raw),
    }:
        _die("system receipt contract seal differs")
    policy = common.parse_json(policy_raw, context="system receipt policy")
    validate_policy(policy)
    derived = validate_system_platform_aggregation(
        platform_aggregation,
        policy_raw=policy_raw,
        expected_identities=expected_identities,
    )
    source = common.exact_object(
        receipt["source"], {"generator", "resolver_base"}, "receipt.source"
    )
    generator = _validate_generator(source["generator"])
    _cross_check_generator_source_context(generator, derived)
    if source["resolver_base"] != {
        "image": manifest["python"]["image"],
        "index": manifest["python"]["index"],
        "platforms": manifest["python"]["platforms"],
    } or source["resolver_base"] != {
        "image": EXPECTED_RESOLVER_BASE["image"],
        "index": EXPECTED_RESOLVER_BASE["index"],
        "platforms": EXPECTED_RESOLVER_BASE["platforms"],
    }:
        _die("system receipt resolver base differs")
    if receipt["system_packages"] != manifest["system_packages"]:
        _die("signed system package selection differs from the tracked manifest")
    system = _validate_system_selection(receipt["system_packages"])
    for platform in PLATFORMS:
        material = system["platforms"][platform]
        if {key: material[key] for key in SYSTEM_PLATFORM_SELECTION_KEYS} != derived["platforms"][
            platform
        ]["selection"]:
            _die(f"signed system {platform} material differs from derived aggregation")
    index = common.exact_object(system["index"], {"digest", "size"}, "system receipt index")
    subject = common.oci_digest(index["digest"], "system receipt subject")
    subject_size = common.positive_int(index["size"], "system receipt subject size")
    ceremony = common.validate_ceremony(
        PROFILE,
        receipt["ceremony"],
        generator_commit=generator["commit"],
        expected_workflow_id=policy["github"]["workflow"]["id"],
        expected_workflow_node_id=policy["github"]["workflow"]["node_id"],
    )
    if {"attempt": ceremony["run_attempt"], "id": ceremony["run_id"]} != derived["run"]:
        _die("system ceremony run differs from platform aggregation")
    common.validate_protection(
        PROFILE,
        receipt["protection"],
        ceremony=ceremony,
        expected_workflow_id=policy["github"]["workflow"]["id"],
        expected_workflow_node_id=policy["github"]["workflow"]["node_id"],
    )
    transition = common.validate_transition(
        PROFILE,
        receipt["transition"],
        generator_commit=generator["commit"],
        expected_workflow_id=policy["github"]["workflow"]["id"],
    )
    common.validate_readback(
        PROFILE,
        receipt["readback"],
        subject_digest=subject,
        subject_size=subject_size,
        transition_kind=transition["kind"],
    )
    _validate_verification(
        receipt["verification"],
        policy_sha256=common.sha256(policy_raw),
        platform_aggregation=derived,
    )
    return receipt


def validate_subject_index(raw: bytes, system_packages: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        platform: {
            "digest": system_packages["platforms"][platform]["manifest_digest"],
            "size": system_packages["platforms"][platform]["manifest_size"],
        }
        for platform in PLATFORMS
    }
    return common.validate_index(
        raw,
        expected_platforms=tuple((platform, ARCHITECTURES[platform]) for platform in PLATFORMS),
        expected_descriptors=expected,
    )


def build_authority_manifest(
    receipt_raw: bytes, bundle_raw: bytes, subject_digest: str, subject_size: int
) -> bytes:
    return common.build_artifact_manifest(
        PROFILE,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject_digest=subject_digest,
        subject_size=subject_size,
    )


def validate_authority_manifest(
    raw: bytes,
    *,
    receipt_raw: bytes,
    bundle_raw: bytes,
    subject_digest: str,
    subject_size: int,
    selected_tag: str | None = None,
) -> dict[str, Any]:
    return common.validate_artifact_manifest(
        PROFILE,
        raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject_digest=subject_digest,
        subject_size=subject_size,
        selected_tag=selected_tag,
    )


def _load(path: Path, *, terminal_lf: bool, context: str) -> tuple[Any, bytes]:
    return common.load_canonical(path, terminal_lf=terminal_lf, context=context)


def _load_tracked_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = common.read_regular(
        path, maximum=common.MAX_JSON_BYTES, context="tracked production manifest"
    )
    value = common.parse_json(raw, context="tracked production manifest")
    if not isinstance(value, dict):
        _die("tracked production manifest is not one JSON object")
    return value, raw


def _native_platform() -> str:
    machine = os.uname().machine
    observed = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(machine)
    if observed is None:
        _die("system generator host architecture is unsupported")
    return observed


def _internal_context() -> tuple[dict[str, Any], bytes, str, str]:
    """Validate every local build input before an internal stage may mutate."""

    policy, policy_raw = _load(
        INTERNAL_POLICY_PATH,
        terminal_lf=True,
        context="internal system authority policy",
    )
    policy_sha256 = os.environ.get("Z4J_POLICY_SHA256", "")
    platform = os.environ.get("Z4J_PLATFORM", "")
    build_id = os.environ.get("Z4J_BUILD_ID", "")
    if (
        common.hex64(policy_sha256, "internal policy SHA-256") != common.sha256(policy_raw)
        or platform not in PLATFORMS
        or platform != _native_platform()
        or build_id not in {"A", "B"}
    ):
        _die("internal system generator context differs")
    material = common.exact_object(
        policy.get("system_packages"),
        {
            "advisory_receipt_format",
            "format",
            "generator",
            "index_descriptor_order",
            "installability_receipt_format",
            "inventory_format",
            "layer_count_per_platform",
            "package_lock_format",
            "payload_root",
            "platforms",
            "requested",
            "resolution_receipt_format",
            "resolver_base",
            "snapshot",
            "tree_format",
        },
        "internal system policy",
    )
    poison = [
        *_validate_build_policy(material["generator"]),
        *_validate_snapshot_policy(material["snapshot"]),
    ]
    if poison:
        _die("system build inputs are UNFINALIZED: " + "; ".join(poison))
    source_files = material["generator"]["build_context"]["source_files"]
    for path in GENERATOR_SOURCE_FILES:
        internal_path = Path("/authority") / Path(path).name
        raw = material_build.read_regular(
            internal_path,
            maximum=material_build.MAX_FILE_BYTES,
            context=f"internal system build source {path}",
        )
        if (
            common.sha256(raw) != source_files[path]["sha256"]
            or len(raw) != source_files[path]["size"]
        ):
            _die(f"internal system build source seal differs: {path}")
    return policy, policy_raw, platform, build_id


def _closed_generator_environment(epoch: int) -> dict[str, str]:
    return {
        "APT_CONFIG": f"{PROFILE.payload_root}/evidence/apt.conf",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
    }


def _system_sources_list(snapshot: Mapping[str, Any]) -> bytes:
    lines: list[str] = []
    for source in snapshot["sources"]:
        timestamp = dt.datetime.fromisoformat(
            source["timestamp_utc"].replace("Z", "+00:00")
        ).strftime("%Y%m%dT%H%M%SZ")
        lines.append(
            "deb [check-valid-until=yes "
            f"signed-by={PROFILE.payload_root}/snapshot/{source['name']}/archive-keyring.gpg] "
            f"{source['archive']}{timestamp}/ {source['suite']} " + " ".join(source["components"])
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def _system_apt_config() -> bytes:
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


def _isolated_apt_commands(platform: str, *, apt_get: str) -> dict[str, list[str]]:
    architecture = ARCHITECTURES[platform]
    prefix = [
        apt_get,
        "-o",
        f"Dir::Etc::sourcelist={PROFILE.payload_root}/evidence/sources.list",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "Dir::Etc::trusted=-",
        "-o",
        "Dir::Etc::trustedparts=-",
        "-o",
        f"Dir::State::status={ISOLATED_APT_ROOT}/status",
        "-o",
        f"Dir::State::lists={ISOLATED_APT_ROOT}/lists",
        "-o",
        f"Dir::Cache::archives={ISOLATED_APT_ROOT}/archives",
        "-o",
        f"APT::Architecture={architecture}",
    ]
    return {
        "download": [
            *prefix,
            "--download-only",
            "--no-install-recommends",
            "--yes",
            "install",
            "ca-certificates",
            "libpq5",
            "tini",
        ],
        "resolve": [
            *prefix,
            "--simulate",
            "--no-install-recommends",
            "install",
            "ca-certificates",
            "libpq5",
            "tini",
        ],
        "update": [*prefix, "update"],
    }


def _real_base_apt_commands(
    platform: str,
    *,
    apt_get: str,
    debs: list[Path],
) -> dict[str, list[str]]:
    prefix = [
        apt_get,
        "-o",
        "Dir::Etc::sourcelist=-",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "Dir::Etc::trusted=-",
        "-o",
        "Dir::Etc::trustedparts=-",
        "-o",
        f"APT::Architecture={ARCHITECTURES[platform]}",
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
            *map(str, debs),
        ],
    }


def _new_directory(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        _die(f"generator path already exists: {path}")
    path.mkdir(mode=0o700, parents=False)
    return path


def _ensure_payload_alias(target: Path) -> None:
    alias = Path(PROFILE.payload_root)
    if alias.exists() or alias.is_symlink():
        _die("system generator payload alias already exists")
    alias.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    alias.symlink_to(target)


def _ensure_parents(path: Path) -> None:
    missing: list[Path] = []
    current = path.parent
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        _die("generator output parent is indirect")
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def _write_new(path: Path, raw: bytes, *, mode: int = 0o644) -> None:
    _ensure_parents(path)
    material_build.atomic_write_new(path, raw, mode=mode)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _fetch_exact(authority: Mapping[str, Any], context: str) -> bytes:
    url = common.https_url(authority["url"], f"{context} URL")
    expected_size = common.positive_int(authority["size"], f"{context} size")
    expected_sha256 = common.hex64(authority["sha256"], f"{context} SHA-256")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(  # noqa: S310 - exact reviewed HTTPS URL
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "z4j-production-system/1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=120) as response:
            if response.status != 200 or response.geturl() != url:
                _die(f"{context} HTTP identity differs")
            raw = response.read(expected_size + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise SystemAuthorityError(f"{context} acquisition failed") from exc
    if len(raw) != expected_size or common.sha256(raw) != expected_sha256:
        _die(f"{context} bytes differ")
    return raw


def _clearsigned_payload(raw: bytes) -> bytes:
    marker = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
    signature = b"-----BEGIN PGP SIGNATURE-----\n"
    if not raw.startswith(marker) or raw.count(signature) != 1:
        _die("Debian InRelease framing differs")
    header_end = raw.find(b"\n\n", len(marker))
    signature_at = raw.find(signature, header_end + 2)
    if header_end < 0 or signature_at < 0:
        _die("Debian InRelease payload is absent")
    payload = raw[header_end + 2 : signature_at]
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    return (
        b"\n".join(line[2:] if line.startswith(b"- ") else line for line in payload.split(b"\n"))
        + b"\n"
    )


def _tool_probe(
    runner: material_build.CommandRunner,
    authority: Mapping[str, Any],
    *,
    executable: Path,
    name: str,
    cwd: Path,
) -> material_build.CommandResult:
    material_build.verify_captured_executable(
        executable,
        expected_sha256=authority["sha256"],
        expected_size=authority["size"],
        context=f"captured system {name}",
    )
    with material_build.held_verified_executable(
        executable,
        expected_sha256=authority["sha256"],
        expected_size=authority["size"],
        context=f"captured system {name}",
    ) as executable_fd:
        result = material_build.require_success(
            runner.run(
                [str(executable), "--version"],
                cwd=cwd,
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                executable_fd=executable_fd,
                timeout_seconds=60,
            ),
            context=f"captured system {name} version probe",
        )
    if common.sha256(result.stdout + result.stderr) != authority["version_output_sha256"]:
        _die(f"captured system {name} version transcript differs")
    material_build.verify_captured_executable(
        executable,
        expected_sha256=authority["sha256"],
        expected_size=authority["size"],
        context=f"captured system {name}",
    )
    return result


def _tool_receipt(
    name: str, authority: Mapping[str, Any], transcript: material_build.CommandResult
) -> dict[str, Any]:
    version_raw = transcript.stdout + transcript.stderr
    first = version_raw.decode("utf-8", errors="strict").splitlines()
    if not first or not first[0].strip():
        _die(f"{name} version output is empty")
    return {
        "binary_sha256": authority["sha256"],
        "name": name,
        "version": first[0].strip(),
        "version_output_sha256": common.sha256(version_raw),
    }


def _run_held_tool(
    runner: material_build.CommandRunner,
    *,
    executable: Path,
    authority: Mapping[str, Any],
    argv: list[str],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    context: str,
) -> material_build.CommandResult:
    with material_build.held_verified_executable(
        executable,
        expected_sha256=authority["sha256"],
        expected_size=authority["size"],
        context=context,
    ) as executable_fd:
        return material_build.require_success(
            runner.run(
                argv,
                cwd=cwd,
                env=environment,
                executable_fd=executable_fd,
                timeout_seconds=timeout_seconds,
            ),
            context=context,
        )


def _snapshot_selection(policy_snapshot: Mapping[str, Any]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for source in policy_snapshot["sources"]:
        sources.append(
            {
                **{
                    key: source[key]
                    for key in (
                        "archive",
                        "archive_key_fingerprints",
                        "components",
                        "name",
                        "release_suite",
                        "suite",
                        "timestamp_utc",
                    )
                },
                "archive_keyring_sha256": source["archive_keyring"]["sha256"],
                "archive_keyring_size": source["archive_keyring"]["size"],
                "inrelease_sha256": source["inrelease"]["sha256"],
                "inrelease_size": source["inrelease"]["size"],
                "release_sha256": source["release"]["sha256"],
                "release_size": source["release"]["size"],
            }
        )
    return {"selection_utc": policy_snapshot["selection_utc"], "sources": sources}


def _parse_debian_fields(
    raw: bytes,
    *,
    maximum: int,
    context: str,
) -> dict[str, str]:
    """Parse one exact Debian control paragraph with closed, bounded framing."""

    if (
        not raw
        or len(raw) > maximum
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
        or b"\n\n" in raw
        or b"\x00" in raw
        or b"\r" in raw
    ):
        _die(f"{context} framing differs")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SystemAuthorityError(f"{context} is not UTF-8") from exc
    fields: dict[str, str] = {}
    current: str | None = None
    for line in raw[:-1].split(b"\n"):
        if not line or len(line) > MAX_DEBIAN_LINE_BYTES:
            _die(f"{context} contains an empty or oversized line")
        if line[:1] in {b" ", b"\t"}:
            if current is None:
                _die(f"{context} starts with a continuation line")
            fields[current] += "\n" + line.decode("utf-8")
            continue
        name, separator, value = line.partition(b":")
        if not separator or DEBIAN_FIELD_NAME.fullmatch(name) is None:
            _die(f"{context} contains an invalid field")
        key = name.decode("ascii").lower()
        if key in fields or len(fields) >= MAX_DEBIAN_FIELDS:
            _die(f"{context} contains duplicate or excessive fields")
        fields[key] = value.lstrip(b" \t").decode("utf-8")
        current = key
    return fields


def _debian_relative_path(value: str, *, context: str) -> str:
    if not value or "\\" in value or "\x00" in value or "\n" in value or "\r" in value:
        _die(f"{context} is unsafe")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SystemAuthorityError(f"{context} is not ASCII") from exc
    logical = PurePosixPath(value)
    if (
        logical.is_absolute()
        or logical.as_posix() != value
        or any(part in {"", ".", ".."} for part in logical.parts)
    ):
        _die(f"{context} is unsafe")
    return value


def _release_index_seals(raw: bytes, *, context: str) -> dict[str, tuple[str, int]]:
    """Derive the exact SHA256 index map from one retained signed Release payload."""

    fields = _parse_debian_fields(raw, maximum=MAX_RELEASE_BYTES, context=context)
    section = fields.get("sha256")
    if section is None:
        _die(f"{context} lacks one SHA256 section")
    seals: dict[str, tuple[str, int]] = {}
    for line in section.splitlines():
        if not line:
            continue
        parts = line.split()
        if (
            len(parts) != 3
            or re.fullmatch(r"[0-9a-f]{64}", parts[0]) is None
            or re.fullmatch(r"0|[1-9][0-9]*", parts[1]) is None
            or len(parts[1]) > 10
        ):
            _die(f"{context} SHA256 section is malformed")
        path = _debian_relative_path(parts[2], context=f"{context} SHA256 path")
        size = int(parts[1])
        if path in seals or size > material_build.MAX_FILE_BYTES:
            _die(f"{context} SHA256 section is duplicate or oversized")
        seals[path] = (parts[0], size)
        if len(seals) > MAX_RELEASE_ENTRIES:
            _die(f"{context} SHA256 section has too many entries")
    if not seals:
        _die(f"{context} SHA256 section is empty")
    return seals


def _parse_package_index(raw: bytes, source: str, architecture: str) -> list[dict[str, Any]]:
    """Derive the exact selected package records from one retained raw index."""

    if (
        not raw
        or len(raw) > MAX_PACKAGES_INDEX_BYTES
        or not raw.endswith(b"\n")
        or raw.startswith(b"\n")
        or b"\x00" in raw
        or b"\r" in raw
    ):
        _die(f"Debian {source} Packages index framing differs")
    body = raw[:-2] if raw.endswith(b"\n\n") else raw[:-1]
    stanzas = body.split(b"\n\n")
    if not body or any(not stanza for stanza in stanzas) or len(stanzas) > material_build.MAX_FILES:
        _die(f"Debian {source} Packages index framing differs")
    records: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    stanza_hashes: set[str] = set()
    required = {"package", "version", "architecture", "filename", "size", "sha256"}
    for stanza in stanzas:
        stanza_raw = stanza + b"\n"
        fields = _parse_debian_fields(
            stanza_raw,
            maximum=MAX_PACKAGE_STANZA_BYTES,
            context=f"Debian {source} Packages record",
        )
        if not required.issubset(fields):
            _die(f"Debian {source} Packages index contains an incomplete record")
        name = fields["package"]
        version = fields["version"]
        record_architecture = fields["architecture"]
        repository_filename = _debian_relative_path(
            fields["filename"], context=f"Debian {source} package filename"
        )
        size_text = fields["size"]
        sha256 = fields["sha256"]
        if (
            DEBIAN_PACKAGE_NAME.fullmatch(name) is None
            or re.fullmatch(r"[!-~]+", version) is None
            or DEBIAN_ARCHITECTURE.fullmatch(record_architecture) is None
            or record_architecture not in {architecture, "all"}
            or not repository_filename.endswith(".deb")
            or re.fullmatch(r"[1-9][0-9]*", size_text) is None
            or len(size_text) > 10
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
            or fields.get("essential") not in {None, "yes"}
        ):
            _die(f"Debian {source} Packages record identity differs")
        size = int(size_text)
        if size > MAX_DEB_BYTES:
            _die(f"Debian {source} package size exceeds the consumer limit")
        identity = (name, version, record_architecture)
        stanza_sha256 = common.sha256(stanza_raw)
        if identity in identities or stanza_sha256 in stanza_hashes:
            _die(f"Debian {source} Packages index contains a duplicate record")
        identities.add(identity)
        stanza_hashes.add(stanza_sha256)
        records.append(
            {
                "architecture": record_architecture,
                "depends": fields.get("depends"),
                "essential": fields.get("essential"),
                "index_path": f"main/binary-{architecture}/Packages",
                "index_stanza_sha256": stanza_sha256,
                "name": name,
                "pre_depends": fields.get("pre-depends"),
                "provides": fields.get("provides"),
                "repository_filename": repository_filename,
                "sha256": sha256,
                "size": size,
                "source": source,
                "version": version,
            }
        )
    if not records:
        _die(f"Debian {source} Packages index is empty")
    return records


def _parse_ar_number(raw: bytes, *, base: int, context: str) -> int:
    value = raw.rstrip(b" ")
    pattern = rb"[0-9]+" if base == 10 else rb"[0-7]+"
    if not value or re.fullmatch(pattern, value) is None:
        _die(f"{context} is malformed")
    return int(value, base)


def _decompress_control_archive(  # noqa: PLR0912 - one branch per closed format
    name: str, raw: bytes, *, context: str
) -> bytes:
    if not raw or len(raw) > MAX_CONTROL_ARCHIVE_BYTES:
        _die(f"{context} compressed control archive exceeds its bound")
    try:
        if name == "control.tar":
            expanded = raw
        elif name == "control.tar.gz":
            gzip_decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            expanded = gzip_decompressor.decompress(raw, MAX_CONTROL_TAR_BYTES + 1)
            if (
                not gzip_decompressor.eof
                or gzip_decompressor.unused_data
                or gzip_decompressor.unconsumed_tail
            ):
                _die(f"{context} gzip stream framing differs")
            expanded += gzip_decompressor.flush()
        elif name == "control.tar.xz":
            xz_decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            expanded = xz_decompressor.decompress(raw, MAX_CONTROL_TAR_BYTES + 1)
            if not xz_decompressor.eof or xz_decompressor.unused_data:
                _die(f"{context} xz stream framing differs")
        elif name == "control.tar.zst":
            try:
                zstd = importlib.import_module("compression.zstd")
            except ImportError as exc:
                raise SystemAuthorityError(
                    f"{context} requires the pinned Python Zstandard decoder"
                ) from exc
            try:
                decompressor = zstd.ZstdDecompressor()
                expanded = decompressor.decompress(raw, MAX_CONTROL_TAR_BYTES + 1)
            except zstd.ZstdError as exc:
                raise SystemAuthorityError(f"{context} compression stream is malformed") from exc
            if not decompressor.eof or decompressor.unused_data:
                _die(f"{context} Zstandard stream framing differs")
        else:
            _die(f"{context} compression type is unsupported")
    except (EOFError, lzma.LZMAError, OSError, ValueError, zlib.error) as exc:
        raise SystemAuthorityError(f"{context} compression stream is malformed") from exc
    if not expanded or len(expanded) > MAX_CONTROL_TAR_BYTES:
        _die(f"{context} expanded control archive exceeds its bound")
    return expanded


def _parse_tar_number(raw: bytes, *, context: str) -> int:
    if raw[:1] and raw[0] & 0x80:
        _die(f"{context} uses an unsupported base-256 number")
    value = raw.rstrip(b"\x00 ").lstrip(b" ")
    if not value:
        return 0
    if re.fullmatch(rb"[0-7]+", value) is None:
        _die(f"{context} is malformed")
    return int(value, 8)


def _tar_text(raw: bytes, *, context: str) -> str:
    value, marker, padding = raw.partition(b"\x00")
    if marker and any(padding):
        _die(f"{context} has non-NUL padding")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemAuthorityError(f"{context} is not ASCII") from exc


def _control_tar_member(  # noqa: PLR0912, PLR0915 - strict tar state machine
    raw: bytes, *, context: str
) -> bytes:
    if len(raw) % 512 or len(raw) < 1536 or len(raw) > MAX_CONTROL_TAR_BYTES:
        _die(f"{context} tar framing differs")
    offset = 0
    members = 0
    seen: set[str] = set()
    regular_files: set[str] = set()
    control: bytes | None = None
    while offset < len(raw):
        header = raw[offset : offset + 512]
        if not any(header):
            if offset + 1024 > len(raw) or any(raw[offset + 512 :]):
                _die(f"{context} tar terminator differs")
            break
        members += 1
        if members > MAX_CONTROL_MEMBERS:
            _die(f"{context} tar has too many members")
        stored_checksum = _parse_tar_number(header[148:156], context=f"{context} checksum")
        actual_checksum = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
        if stored_checksum != actual_checksum:
            _die(f"{context} tar checksum differs")
        magic = header[257:263]
        version = header[263:265]
        if (magic, version) not in {(b"ustar\x00", b"00"), (b"ustar ", b" \x00")}:
            _die(f"{context} tar format is unsupported")
        name = _tar_text(header[:100], context=f"{context} member name")
        prefix = _tar_text(header[345:500], context=f"{context} member prefix")
        if prefix:
            name = prefix + "/" + name
        if not name or "\\" in name or "\n" in name or "\r" in name:
            _die(f"{context} tar member path is unsafe")
        while name.startswith("./"):
            name = name[2:]
        is_directory_name = name.endswith("/")
        name = name.rstrip("/") or "."
        logical = PurePosixPath(name)
        if (
            logical.is_absolute()
            or logical.as_posix() != name
            or any(part in {"", ".."} for part in logical.parts)
            or name in seen
            or any(str(parent) in regular_files for parent in logical.parents if str(parent) != ".")
            or (name in regular_files)
        ):
            _die(f"{context} tar member path is unsafe or duplicate")
        type_flag = header[156:157]
        mode = _parse_tar_number(header[100:108], context=f"{context} member mode")
        size = _parse_tar_number(header[124:136], context=f"{context} member size")
        _parse_tar_number(header[108:116], context=f"{context} member uid")
        _parse_tar_number(header[116:124], context=f"{context} member gid")
        _parse_tar_number(header[136:148], context=f"{context} member mtime")
        if any(header[157:257]) or any(header[329:345]):
            _die(f"{context} tar member link or device metadata differs")
        if type_flag == b"5":
            if size or mode != 0o755 or (name != "." and not is_directory_name):
                _die(f"{context} tar directory differs")
        elif type_flag in {b"\x00", b"0"}:
            if is_directory_name or mode not in {0o644, 0o755}:
                _die(f"{context} tar regular-file mode differs")
            if size > MAX_CONTROL_MEMBER_BYTES:
                _die(f"{context} tar member exceeds its bound")
            if any(
                other != name and PurePosixPath(other).is_relative_to(logical) for other in seen
            ):
                _die(f"{context} tar file collides with a prior path")
            regular_files.add(name)
        else:
            _die(f"{context} tar member type is unsupported")
        seen.add(name)
        content_at = offset + 512
        padded = (size + 511) // 512 * 512
        next_offset = content_at + padded
        if next_offset > len(raw) or any(raw[content_at + size : next_offset]):
            _die(f"{context} tar member is truncated or has non-NUL padding")
        if name == "control":
            if type_flag not in {b"\x00", b"0"} or mode != 0o644 or control is not None:
                _die(f"{context} tar control member differs")
            control = raw[content_at : content_at + size]
        offset = next_offset
    else:
        _die(f"{context} tar lacks a terminator")
    if control is None or not control:
        _die(f"{context} tar lacks one regular control member")
    return control


def _extract_deb_control(raw: bytes, *, context: str) -> bytes:
    """Extract one control paragraph without native tools or filesystem extraction."""

    if not raw.startswith(b"!<arch>\n") or len(raw) > MAX_DEB_BYTES:
        _die(f"{context} ar framing differs")
    offset = 8
    members: list[tuple[str, bytes]] = []
    while offset < len(raw):
        if len(members) >= 3 or offset + 60 > len(raw):
            _die(f"{context} ar member count or framing differs")
        header = raw[offset : offset + 60]
        if header[58:60] != b"`\n":
            _die(f"{context} ar header trailer differs")
        try:
            name = header[:16].decode("ascii").rstrip(" ")
        except UnicodeDecodeError as exc:
            raise SystemAuthorityError(f"{context} ar member name is not ASCII") from exc
        if name.endswith("/"):
            name = name[:-1]
        if not name or "/" in name or "\\" in name or name in {item[0] for item in members}:
            _die(f"{context} ar member name is unsafe or duplicate")
        _parse_ar_number(header[16:28], base=10, context=f"{context} ar mtime")
        _parse_ar_number(header[28:34], base=10, context=f"{context} ar uid")
        _parse_ar_number(header[34:40], base=10, context=f"{context} ar gid")
        mode = _parse_ar_number(header[40:48], base=8, context=f"{context} ar mode")
        size = _parse_ar_number(header[48:58], base=10, context=f"{context} ar size")
        if mode != 0o100644 or size > MAX_DEB_BYTES:
            _die(f"{context} ar member mode or size differs")
        content_at = offset + 60
        content_end = content_at + size
        next_offset = content_end + size % 2
        if content_end > len(raw) or next_offset > len(raw):
            _die(f"{context} ar member is truncated")
        if size % 2 and raw[content_end:next_offset] != b"\n":
            _die(f"{context} ar member padding differs")
        members.append((name, raw[content_at:content_end]))
        offset = next_offset
    if offset != len(raw) or len(members) != 3:
        _die(f"{context} ar framing or member count differs")
    control_names = {"control.tar", "control.tar.gz", "control.tar.xz", "control.tar.zst"}
    data_names = {"data.tar", "data.tar.gz", "data.tar.xz", "data.tar.zst"}
    if (
        members[0] != ("debian-binary", b"2.0\n")
        or members[1][0] not in control_names
        or members[2][0] not in data_names
    ):
        _die(f"{context} Debian member identity or order differs")
    control_tar = _decompress_control_archive(members[1][0], members[1][1], context=context)
    return _control_tar_member(control_tar, context=context)


def _parse_control_stanza(raw: bytes, *, context: str) -> dict[str, str | None]:
    """Parse one bounded raw .deb control record without executing package payload."""

    fields = _parse_debian_fields(raw, maximum=MAX_CONTROL_STANZA_BYTES, context=context)
    required = {"package", "version", "architecture"}
    if not required.issubset(fields):
        _die(f"{context} identity is incomplete")
    if "status" in fields:
        _die(f"{context} unexpectedly contains installed status")
    if (
        DEBIAN_PACKAGE_NAME.fullmatch(fields["package"]) is None
        or re.fullmatch(r"[!-~]+", fields["version"]) is None
        or DEBIAN_ARCHITECTURE.fullmatch(fields["architecture"]) is None
        or fields.get("essential") not in {None, "yes"}
    ):
        _die(f"{context} identity differs")
    return {
        "architecture": fields["architecture"],
        "depends": fields.get("depends"),
        "essential": fields.get("essential"),
        "name": fields["package"],
        "pre_depends": fields.get("pre-depends"),
        "provides": fields.get("provides"),
        "version": fields["version"],
    }


def _synthetic_dpkg_status(
    packages: list[Mapping[str, Any]],
    controls_root: Path,
) -> bytes:
    """Construct scanner metadata only; never unpack or execute a maintainer script."""

    stanzas: list[bytes] = []
    for package in packages:
        control = package["control"]
        raw = material_build.read_regular(
            controls_root / control["path"],
            maximum=control["size"],
            context=f"Debian control {package['name']}",
        )
        identity = _parse_control_stanza(raw, context=f"Debian control {package['name']}")
        if (
            common.sha256(raw) != control["sha256"]
            or len(raw) != control["size"]
            or identity["name"] != package["name"]
            or identity["version"] != package["version"]
            or identity["architecture"] != package["architecture"]
            or identity["depends"] != package["depends"]
            or identity["pre_depends"] != package["pre_depends"]
            or identity["provides"] != package["provides"]
            or identity["essential"] != package["essential"]
        ):
            _die("Debian control record differs from the authenticated lock")
        lines = raw.splitlines(keepends=True)
        if not lines or not lines[0].startswith(b"Package: "):
            _die("Debian control Package field is not first")
        stanzas.append(lines[0] + b"Status: install ok installed\n" + b"".join(lines[1:]))
    return b"\n".join(stanzas)


def _installed_status_projection(
    raw: bytes,
    packages: list[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Prove every exact locked package is installed in the disposable real base."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SystemAuthorityError("installed dpkg status is not UTF-8") from exc
    installed: dict[tuple[str, str], dict[str, str]] = {}
    for stanza in text.strip().split("\n\n"):
        parsed = email.parser.Parser().parsestr(stanza + "\n")
        name = parsed.get("Package")
        architecture = parsed.get("Architecture")
        version = parsed.get("Version")
        if not all(isinstance(item, str) and item for item in (name, architecture, version)):
            continue
        key = (name, architecture)
        if key in installed:
            _die("installed dpkg status contains duplicate package identity")
        installed[key] = {
            "architecture": architecture,
            "name": name,
            "status": parsed.get("Status", ""),
            "version": version,
        }
    projection: list[dict[str, str]] = []
    for package in packages:
        key = (package["name"], package["architecture"])
        actual = installed.get(key)
        if (
            actual is None
            or actual["version"] != package["version"]
            or actual["status"] != "install ok installed"
        ):
            _die(f"real-base installability differs: {package['name']}")
        projection.append(actual)
    projection.sort(key=lambda item: (item["name"].encode(), item["architecture"].encode()))
    if len(projection) != len({(item["name"], item["architecture"]) for item in projection}):
        _die("real-base installability projection is duplicate")
    return projection


def _apt_list_projection(
    lists_root: Path,
    expected: list[tuple[str, str, bytes]],
) -> list[dict[str, Any]]:
    """Prove apt's actual solver inputs equal the retained signed inputs."""

    records = material_build.file_records(lists_root, exclude=frozenset())
    if len(records) != len(expected):
        _die("isolated apt list state has extra or missing solver inputs")
    remaining = sorted(expected, key=lambda item: (item[0].encode(), item[1].encode()))
    projection: list[dict[str, Any]] = []
    for record in records:
        raw = material_build.read_regular(
            lists_root / record["path"],
            maximum=material_build.MAX_FILE_BYTES,
            context=f"isolated apt list {record['path']}",
        )
        candidates = [
            item
            for item in remaining
            if common.sha256(item[2]) == record["sha256"]
            and len(item[2]) == record["size"]
            and item[2] == raw
        ]
        if not candidates:
            _die("apt used an index that differs from the retained signed snapshot")
        selected = candidates[0]
        remaining.remove(selected)
        projection.append(
            {
                **record,
                "kind": selected[1],
                "source": selected[0],
            }
        )
    if remaining:
        _die("apt did not use every retained signed solver input")
    return projection


def _solver_plan(raw: bytes) -> list[dict[str, str]]:
    """Normalize apt's empty-status install closure without timing text."""

    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise SystemAuthorityError("isolated apt solver output is not UTF-8") from exc
    plan: list[dict[str, str]] = []
    for line in lines:
        if not line.startswith("Inst "):
            continue
        match = re.fullmatch(r"Inst ([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9]+)? \((\S+) .+\)", line)
        if match is None:
            _die("isolated apt solver emitted an unrecognized install record")
        plan.append({"name": match.group(1), "version": match.group(2)})
    plan.sort(key=lambda item: (item["name"].encode(), item["version"].encode()))
    if not plan or len({item["name"] for item in plan}) != len(plan):
        _die("isolated apt solver closure is empty or duplicate")
    return plan


def _copy_regular_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink() or destination.exists():
        _die("generator tree copy boundary differs")
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copyfile)
    material_build.file_records(destination, exclude=frozenset())


def _validate_tar_archive(
    runner: material_build.CommandRunner,
    *,
    tar_path: str,
    archive: Path,
    environment: Mapping[str, str],
    context: str,
) -> None:
    names_result = material_build.require_success(
        runner.run(
            [tar_path, "--list", "--gzip", "--file", str(archive)],
            cwd=Path("/authority"),
            env=environment,
            timeout_seconds=300,
        ),
        context=f"{context} member listing",
    )
    verbose_result = material_build.require_success(
        runner.run(
            [tar_path, "--list", "--verbose", "--gzip", "--file", str(archive)],
            cwd=Path("/authority"),
            env=environment,
            timeout_seconds=300,
        ),
        context=f"{context} typed member listing",
    )
    names = names_result.stdout.decode("utf-8", errors="strict").splitlines()
    verbose = verbose_result.stdout.decode("utf-8", errors="strict").splitlines()
    if not names or len(names) != len(verbose):
        _die(f"{context} member listing differs")
    for name, typed in zip(names, verbose, strict=True):
        normalized = name.removesuffix("/")
        pure = PurePosixPath(normalized)
        if (
            not normalized
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in normalized
            or not typed
            or typed[0] not in {"-", "d"}
        ):
            _die(f"{context} contains an unsafe archive member")


def _command_internal_acquire(_args: argparse.Namespace) -> None:  # noqa: PLR0912,PLR0915
    policy, policy_raw, platform, build_id = _internal_context()
    material = policy["system_packages"]
    generator = material["generator"]
    snapshot_policy = material["snapshot"]
    runner = material_build.SubprocessRunner()
    tools = {name: generator["tools"][name]["platforms"][platform] for name in SYSTEM_TOOL_PATHS}
    acquired = _new_directory(INTERNAL_ACQUIRED_ROOT)
    generator_root = _new_directory(acquired / ".generator")
    tool_root = _new_directory(generator_root / "tools")
    captured_tools: dict[str, Path] = {}
    for name in SYSTEM_TOOL_PATHS:
        captured = tool_root / name.replace("_", "-")
        material_build.capture_sealed_executable(
            Path(tools[name]["path"]),
            captured,
            expected_sha256=tools[name]["sha256"],
            expected_size=tools[name]["size"],
            context=f"system {name.replace('_', '-')} executable",
        )
        captured_tools[name] = captured
    probes = {
        name: _tool_probe(
            runner,
            tools[name],
            executable=captured_tools[name],
            name=name,
            cwd=Path("/authority"),
        )
        for name in SYSTEM_TOOL_PATHS
    }
    state = Path(ISOLATED_APT_ROOT)
    _new_directory(state)
    _write_new(state / "status", b"", mode=0o600)
    for directory in (state / "lists", state / "archives"):
        _new_directory(directory)
        _new_directory(directory / "partial")
    _ensure_payload_alias(acquired)

    for source in snapshot_policy["sources"]:
        root = acquired / "snapshot" / source["name"]
        for filename, key in (
            ("archive-keyring.gpg", "archive_keyring"),
            ("InRelease", "inrelease"),
            ("Release", "release"),
        ):
            _write_new(root / filename, _fetch_exact(source[key], f"{source['name']} {filename}"))
        architecture = ARCHITECTURES[platform]
        packages_path = root / "indexes" / "main" / f"binary-{architecture}" / "Packages"
        _write_new(
            packages_path,
            _fetch_exact(
                source["packages"][platform],
                f"{source['name']} Packages {platform}",
            ),
        )
        if (
            _clearsigned_payload((root / "InRelease").read_bytes())
            != (root / "Release").read_bytes()
        ):
            _die(f"Debian {source['name']} signed Release bytes differ")
        signature = _run_held_tool(
            runner,
            executable=captured_tools["gpgv"],
            authority=tools["gpgv"],
            argv=[
                str(captured_tools["gpgv"]),
                "--status-fd",
                "1",
                "--keyring",
                str(root / "archive-keyring.gpg"),
                str(root / "InRelease"),
            ],
            cwd=Path("/authority"),
            environment=_closed_generator_environment(generator["source_date_epoch"]),
            timeout_seconds=60,
            context=f"Debian {source['name']} signature",
        )
        fingerprints = sorted(
            line.split()[2]
            for line in signature.stdout.decode("ascii", errors="strict").splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
        )
        if fingerprints != source["archive_key_fingerprints"]:
            _die(f"Debian {source['name']} signing fingerprints differ")

    snapshot = _snapshot_selection(snapshot_policy)
    sources_raw = _system_sources_list(snapshot)
    apt_config_raw = _system_apt_config()
    _write_new(acquired / "evidence/sources.list", sources_raw)
    _write_new(acquired / "evidence/apt.conf", apt_config_raw)
    os_release_authority = generator["resolution_interface"]["os_release"]["platforms"][platform]
    os_release_raw = material_build.read_regular(
        Path(os_release_authority["path"]),
        maximum=os_release_authority["size"],
        context=f"system base os-release {platform}",
    )
    if (
        len(os_release_raw) != os_release_authority["size"]
        or common.sha256(os_release_raw) != os_release_authority["sha256"]
        or b"ID=debian\n" not in os_release_raw
        or b"VERSION_CODENAME=trixie\n" not in os_release_raw
    ):
        _die("system base os-release authority differs")
    _write_new(acquired / "evidence/os-release", os_release_raw)
    commands = _isolated_apt_commands(platform, apt_get=str(captured_tools["apt_get"]))
    environment = _closed_generator_environment(generator["source_date_epoch"])
    update = _run_held_tool(
        runner,
        executable=captured_tools["apt_get"],
        authority=tools["apt_get"],
        argv=commands["update"],
        cwd=Path("/authority"),
        environment=environment,
        timeout_seconds=1800,
        context="isolated apt update",
    )
    expected_lists: list[tuple[str, str, bytes]] = []
    architecture = ARCHITECTURES[platform]
    for source in snapshot_policy["sources"]:
        snapshot_root = acquired / "snapshot" / source["name"]
        expected_lists.extend(
            (
                (
                    source["name"],
                    "InRelease",
                    material_build.read_regular(
                        snapshot_root / "InRelease",
                        maximum=source["inrelease"]["size"],
                        context=f"retained {source['name']} InRelease",
                    ),
                ),
                (
                    source["name"],
                    "Packages",
                    material_build.read_regular(
                        snapshot_root / "indexes/main" / f"binary-{architecture}" / "Packages",
                        maximum=source["packages"][platform]["size"],
                        context=f"retained {source['name']} Packages {platform}",
                    ),
                ),
            )
        )
    list_state_before = _apt_list_projection(state / "lists", expected_lists)
    resolve = _run_held_tool(
        runner,
        executable=captured_tools["apt_get"],
        authority=tools["apt_get"],
        argv=commands["resolve"],
        cwd=Path("/authority"),
        environment=environment,
        timeout_seconds=1800,
        context="isolated apt resolution",
    )
    solver_plan = _solver_plan(resolve.stdout)
    if _apt_list_projection(state / "lists", expected_lists) != list_state_before:
        _die("isolated apt list state changed during resolution")
    download = _run_held_tool(
        runner,
        executable=captured_tools["apt_get"],
        authority=tools["apt_get"],
        argv=commands["download"],
        cwd=Path("/authority"),
        environment=environment,
        timeout_seconds=3600,
        context="isolated apt download",
    )
    if _apt_list_projection(state / "lists", expected_lists) != list_state_before:
        _die("isolated apt list state changed during download")
    run_evidence = _new_directory(generator_root / "run-evidence")
    for command_name, command_result in (
        ("apt-update", update),
        ("apt-resolve", resolve),
        ("apt-download", download),
    ):
        _write_new(run_evidence / f"{command_name}.stdout", command_result.stdout)
        _write_new(run_evidence / f"{command_name}.stderr", command_result.stderr)
    _write_new(
        run_evidence / "apt-commands.json",
        common.canonical_json(
            {
                "commands": {
                    command_name: {
                        "argv": list(command_result.argv),
                        "cwd": "/authority",
                        "environment": environment,
                        "exit_code": command_result.returncode,
                        "stderr": {
                            "path": f"{command_name}.stderr",
                            "sha256": common.sha256(command_result.stderr),
                            "size": len(command_result.stderr),
                        },
                        "stdout": {
                            "path": f"{command_name}.stdout",
                            "sha256": common.sha256(command_result.stdout),
                            "size": len(command_result.stdout),
                        },
                    }
                    for command_name, command_result in (
                        ("apt-download", download),
                        ("apt-resolve", resolve),
                        ("apt-update", update),
                    )
                },
                "format": "z4j-production-system-apt-run-evidence-v1",
                "platform": platform,
            },
            terminal_lf=True,
        ),
    )
    debs = sorted((state / "archives").glob("*.deb"), key=lambda path: path.name.encode())
    if not debs:
        _die("isolated apt download produced no packages")
    indexes: list[dict[str, Any]] = []
    available: list[dict[str, Any]] = []
    for source in snapshot_policy["sources"]:
        index = source["packages"][platform]
        index_path = f"main/binary-{architecture}/Packages"
        indexes.append(
            {
                "path": index_path,
                "sha256": index["sha256"],
                "size": index["size"],
                "source": source["name"],
            }
        )
        available.extend(
            _parse_package_index(
                material_build.read_regular(
                    acquired / "snapshot" / source["name"] / "indexes" / index_path,
                    maximum=MAX_PACKAGES_INDEX_BYTES,
                    context=f"Debian {source['name']} Packages index",
                ),
                source["name"],
                architecture,
            )
        )
    packages: list[dict[str, Any]] = []
    target_debs = acquired / "debs"
    target_debs.mkdir(mode=0o700)
    controls_root = acquired / "controls"
    controls_root.mkdir(mode=0o700)
    for deb in debs:
        raw = material_build.read_regular(deb, maximum=material_build.MAX_FILE_BYTES, context="deb")
        identity = (
            _run_held_tool(
                runner,
                executable=captured_tools["dpkg_deb"],
                authority=tools["dpkg_deb"],
                argv=[
                    str(captured_tools["dpkg_deb"]),
                    "--show",
                    "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
                    str(deb),
                ],
                cwd=Path("/authority"),
                environment=environment,
                timeout_seconds=60,
                context="dpkg-deb package identity",
            )
            .stdout.decode("utf-8", errors="strict")
            .splitlines()
        )
        if len(identity) != 3:
            _die("dpkg-deb package identity output differs")
        matches = [
            item
            for item in available
            if (item["name"], item["version"], item["architecture"], item["sha256"], item["size"])
            == (identity[0], identity[1], identity[2], common.sha256(raw), len(raw))
        ]
        if len(matches) != 1:
            _die(
                f"downloaded Debian package is absent/ambiguous in authenticated indexes: {deb.name}"
            )
        control_result = _run_held_tool(
            runner,
            executable=captured_tools["dpkg_deb"],
            authority=tools["dpkg_deb"],
            argv=[str(captured_tools["dpkg_deb"]), "--field", str(deb)],
            cwd=Path("/authority"),
            environment=environment,
            timeout_seconds=60,
            context="dpkg-deb control record",
        )
        control_raw = control_result.stdout
        control_identity = _parse_control_stanza(
            control_raw,
            context=f"Debian control {identity[0]}",
        )
        if (
            control_result.stderr
            or control_identity["name"] != identity[0]
            or control_identity["version"] != identity[1]
            or control_identity["architecture"] != identity[2]
            or control_identity["depends"] != matches[0]["depends"]
            or control_identity["pre_depends"] != matches[0]["pre_depends"]
            or control_identity["provides"] != matches[0]["provides"]
            or control_identity["essential"] != matches[0]["essential"]
        ):
            _die("Debian package control differs from its authenticated index")
        target = target_debs / deb.name
        _write_new(target, raw)
        control_path = deb.name + ".control"
        _write_new(controls_root / control_path, control_raw)
        packages.append(
            {
                **matches[0],
                "control": {
                    "path": control_path,
                    "sha256": common.sha256(control_raw),
                    "size": len(control_raw),
                },
                "filename": deb.name,
            }
        )
    packages.sort(key=lambda item: item["name"].encode("utf-8"))
    names = [item["name"] for item in packages]
    if len(names) != len(set(names)) or not set(material["requested"]).issubset(names):
        _die("isolated apt closure is duplicate or incomplete")
    if [(item["name"], item["version"]) for item in packages] != [
        (item["name"], item["version"]) for item in solver_plan
    ]:
        _die("downloaded Debian closure differs from the isolated solver plan")
    lock = {
        "format": material["package_lock_format"],
        "indexes": indexes,
        "packages": packages,
        "platform": platform,
        "requested": material["requested"],
        "snapshot_selection_utc": snapshot["selection_utc"],
        "sources": snapshot["sources"],
    }
    lock_raw = common.canonical_json(lock, terminal_lf=True)
    _write_new(acquired / "locks/packages.json", lock_raw)
    resolution = {
        "apt": _tool_receipt("apt-get", tools["apt_get"], probes["apt_get"]),
        "apt_config_sha256": common.sha256(apt_config_raw),
        "commands": commands,
        "dpkg_deb": _tool_receipt("dpkg-deb", tools["dpkg_deb"], probes["dpkg_deb"]),
        "exit_code": 0,
        "format": material["resolution_receipt_format"],
        "gpgv": _tool_receipt("gpgv", tools["gpgv"], probes["gpgv"]),
        "isolation": {
            "ambient_dpkg_status_used": False,
            "architecture": architecture,
            "archives_initially_empty": True,
            "empty_status_sha256": common.sha256(b""),
            "empty_status_size": 0,
            "lists_initially_empty": True,
            "state_root": ISOLATED_APT_ROOT,
            "trusted": "-",
            "trusted_parts": "-",
        },
        "list_state": list_state_before,
        "package_lock_sha256": common.sha256(lock_raw),
        "platform": platform,
        "snapshot": snapshot,
        "sources_list_sha256": common.sha256(sources_raw),
        "solver_plan": solver_plan,
    }
    _write_new(
        acquired / "evidence/resolution-receipt.json",
        common.canonical_json(resolution, terminal_lf=True),
    )
    trivy = generator["trivy"]
    native_trivy = trivy["platforms"][platform]
    _write_new(
        acquired / ".generator/trivy-archive.tar.gz",
        _fetch_exact(native_trivy["archive"], f"Trivy archive {platform}"),
    )
    _write_new(
        acquired / ".generator/trivy-database.tar.gz",
        _fetch_exact(trivy["database_archive"], "Trivy database archive"),
    )
    records = material_build.file_records(acquired, exclude=frozenset({".acquisition.json"}))
    _write_new(
        acquired / ".acquisition.json",
        common.canonical_json(
            {
                "build_id": build_id,
                "files": records,
                "format": "z4j-production-system-acquisition-v1",
                "platform": platform,
                "policy_sha256": common.sha256(policy_raw),
            },
            terminal_lf=True,
        ),
    )


def _command_internal_installability(_args: argparse.Namespace) -> None:
    """Install every locked deb only inside a disposable network-none real base."""

    policy, policy_raw, platform, build_id = _internal_context()
    material = policy["system_packages"]
    generator = material["generator"]
    acquisition, acquisition_raw = _load(
        INTERNAL_ACQUIRED_ROOT / ".acquisition.json",
        terminal_lf=True,
        context="system acquisition receipt",
    )
    expected_acquisition = {
        "build_id": build_id,
        "files": material_build.file_records(
            INTERNAL_ACQUIRED_ROOT, exclude=frozenset({".acquisition.json"})
        ),
        "format": "z4j-production-system-acquisition-v1",
        "platform": platform,
        "policy_sha256": common.sha256(policy_raw),
    }
    if (
        acquisition != expected_acquisition
        or common.canonical_json(acquisition, terminal_lf=True) != acquisition_raw
    ):
        _die("system acquisition differs before real-base installability")
    _ensure_payload_alias(INTERNAL_ACQUIRED_ROOT)
    base_authority = generator["resolution_interface"]["base_status"]["platforms"][platform]
    base_status_raw = material_build.read_regular(
        Path(base_authority["path"]),
        maximum=base_authority["size"],
        context=f"system real-base dpkg status {platform}",
    )
    if (
        len(base_status_raw) != base_authority["size"]
        or common.sha256(base_status_raw) != base_authority["sha256"]
    ):
        _die("system real-base dpkg status authority differs")
    lock_raw = material_build.read_regular(
        INTERNAL_ACQUIRED_ROOT / "locks/packages.json",
        maximum=material_build.MAX_FILE_BYTES,
        context="system package lock",
    )
    lock = common.parse_json(lock_raw, context="system package lock")
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(packages, list) or not packages or lock.get("platform") != platform:
        _die("system package lock differs before real-base installability")
    debs = [INTERNAL_ACQUIRED_ROOT / "debs" / package["filename"] for package in packages]
    if any(not path.is_absolute() for path in debs):
        _die("system real-base deb path differs")
    tools = generator["tools"]
    apt_authority = tools["apt_get"]["platforms"][platform]
    captured_apt = INTERNAL_ACQUIRED_ROOT / ".generator/tools/apt-get"
    runner = material_build.SubprocessRunner()
    _tool_probe(
        runner,
        apt_authority,
        executable=captured_apt,
        name="apt_get",
        cwd=Path("/authority"),
    )
    environment = _closed_generator_environment(generator["source_date_epoch"])
    commands = _real_base_apt_commands(
        platform,
        apt_get=str(captured_apt),
        debs=debs,
    )
    with material_build.held_verified_executable(
        captured_apt,
        expected_sha256=apt_authority["sha256"],
        expected_size=apt_authority["size"],
        context="captured system apt-get installability",
    ) as apt_fd:
        install = material_build.require_success(
            runner.run(
                commands["install"],
                cwd=Path("/authority"),
                env=environment,
                executable_fd=apt_fd,
                timeout_seconds=7200,
            ),
            context="disposable real-base package installation",
        )
        check = material_build.require_success(
            runner.run(
                commands["check"],
                cwd=Path("/authority"),
                env=environment,
                executable_fd=apt_fd,
                timeout_seconds=1800,
            ),
            context="disposable real-base dependency audit",
        )
    installed_status_raw = material_build.read_regular(
        Path(base_authority["path"]),
        maximum=material_build.MAX_FILE_BYTES,
        context="installed real-base dpkg status",
    )
    installed = _installed_status_projection(installed_status_raw, packages)
    if (
        material_build.file_records(
            INTERNAL_ACQUIRED_ROOT, exclude=frozenset({".acquisition.json"})
        )
        != acquisition["files"]
    ):
        _die("maintainer scripts changed the authenticated acquisition")
    if (
        material_build.read_regular(
            INTERNAL_ACQUIRED_ROOT / ".acquisition.json",
            maximum=material_build.MAX_FILE_BYTES,
            context="system acquisition receipt after installability",
        )
        != acquisition_raw
    ):
        _die("maintainer scripts changed the acquisition receipt")
    result_root = _new_directory(INTERNAL_INSTALLABILITY_ROOT)
    evidence_root = _new_directory(result_root / "run-evidence")
    for name, result in (("apt-check", check), ("apt-install", install)):
        _write_new(evidence_root / f"{name}.stdout", result.stdout)
        _write_new(evidence_root / f"{name}.stderr", result.stderr)
    receipt = {
        "base_status": {
            "path": base_authority["path"],
            "sha256": common.sha256(base_status_raw),
            "size": len(base_status_raw),
        },
        "commands": {"check": list(check.argv), "install": list(install.argv)},
        "format": material["installability_receipt_format"],
        "installed": installed,
        "maintainer_scripts": "disposable-network-none-build-stage-only",
        "package_lock_sha256": common.sha256(lock_raw),
        "platform": platform,
        "result": "pass",
    }
    _write_new(
        result_root / "receipt.json",
        common.canonical_json(receipt, terminal_lf=True),
    )
    _write_new(
        evidence_root / "commands.json",
        common.canonical_json(
            {
                "commands": {
                    name: {
                        "argv": list(result.argv),
                        "cwd": "/authority",
                        "environment": environment,
                        "exit_code": result.returncode,
                        "stderr": {
                            "path": f"{name}.stderr",
                            "sha256": common.sha256(result.stderr),
                            "size": len(result.stderr),
                        },
                        "stdout": {
                            "path": f"{name}.stdout",
                            "sha256": common.sha256(result.stdout),
                            "size": len(result.stdout),
                        },
                    }
                    for name, result in (("apt-check", check), ("apt-install", install))
                },
                "format": "z4j-production-system-installability-run-evidence-v1",
            },
            terminal_lf=True,
        ),
    )


def _command_internal_build(_args: argparse.Namespace) -> None:  # noqa: PLR0915
    policy, policy_raw, platform, build_id = _internal_context()
    material = policy["system_packages"]
    generator = material["generator"]
    acquisition, acquisition_raw = _load(
        INTERNAL_ACQUIRED_ROOT / ".acquisition.json",
        terminal_lf=True,
        context="system acquisition receipt",
    )
    expected_acquisition = {
        "build_id": build_id,
        "files": material_build.file_records(
            INTERNAL_ACQUIRED_ROOT, exclude=frozenset({".acquisition.json"})
        ),
        "format": "z4j-production-system-acquisition-v1",
        "platform": platform,
        "policy_sha256": common.sha256(policy_raw),
    }
    if (
        acquisition != expected_acquisition
        or common.canonical_json(acquisition, terminal_lf=True) != acquisition_raw
    ):
        _die("system acquisition receipt/payload differs")
    output_root = _new_directory(INTERNAL_OUTPUT_ROOT)
    output = _new_directory(output_root / "payload")
    run_evidence = _new_directory(output_root / "run-evidence")
    for name in ("controls", "debs", "evidence", "locks", "snapshot"):
        _copy_regular_tree(INTERNAL_ACQUIRED_ROOT / name, output / name)
    _copy_regular_tree(
        INTERNAL_ACQUIRED_ROOT / ".generator/run-evidence",
        run_evidence / "acquisition",
    )
    scan_root = _new_directory(Path(SYSTEM_SCAN_ROOT))
    admin = scan_root / "var/lib/dpkg"
    admin.mkdir(mode=0o700, parents=True)
    runner = material_build.SubprocessRunner()
    environment = _closed_generator_environment(generator["source_date_epoch"])
    tools = {name: generator["tools"][name]["platforms"][platform] for name in SYSTEM_TOOL_PATHS}
    captured_tools = {
        name: INTERNAL_ACQUIRED_ROOT / ".generator/tools" / name.replace("_", "-")
        for name in SYSTEM_TOOL_PATHS
    }
    for name in SYSTEM_TOOL_PATHS:
        _tool_probe(
            runner,
            tools[name],
            executable=captured_tools[name],
            name=name,
            cwd=Path("/authority"),
        )
    lock_raw = material_build.read_regular(
        output / "locks/packages.json",
        maximum=material_build.MAX_FILE_BYTES,
        context="system package lock",
    )
    lock = common.parse_json(lock_raw, context="system package lock")
    if (
        not isinstance(lock, dict)
        or set(lock)
        != {
            "format",
            "indexes",
            "packages",
            "platform",
            "requested",
            "snapshot_selection_utc",
            "sources",
        }
        or lock["platform"] != platform
        or not isinstance(lock["packages"], list)
        or not lock["packages"]
    ):
        _die("system package lock shape differs")
    installability, installability_raw = _load(
        INTERNAL_INSTALLABILITY_ROOT / "receipt.json",
        terminal_lf=True,
        context="system real-base installability receipt",
    )
    expected_installed = sorted(
        (
            {
                "architecture": item["architecture"],
                "name": item["name"],
                "status": "install ok installed",
                "version": item["version"],
            }
            for item in lock["packages"]
        ),
        key=lambda item: (item["name"].encode(), item["architecture"].encode()),
    )
    base_status = generator["resolution_interface"]["base_status"]["platforms"][platform]
    deb_paths = [INTERNAL_ACQUIRED_ROOT / "debs" / item["filename"] for item in lock["packages"]]
    expected_installability = {
        "base_status": base_status,
        "commands": _real_base_apt_commands(
            platform,
            apt_get=str(INTERNAL_ACQUIRED_ROOT / ".generator/tools/apt-get"),
            debs=deb_paths,
        ),
        "format": material["installability_receipt_format"],
        "installed": expected_installed,
        "maintainer_scripts": "disposable-network-none-build-stage-only",
        "package_lock_sha256": common.sha256(lock_raw),
        "platform": platform,
        "result": "pass",
    }
    if (
        installability != expected_installability
        or common.canonical_json(installability, terminal_lf=True) != installability_raw
    ):
        _die("system real-base installability receipt differs")
    _write_new(output / "evidence/installability-receipt.json", installability_raw)
    _copy_regular_tree(
        INTERNAL_INSTALLABILITY_ROOT / "run-evidence",
        run_evidence / "installability",
    )
    status_raw = _synthetic_dpkg_status(lock["packages"], output / "controls")
    _write_new(admin / "status", status_raw)
    etc = scan_root / "etc"
    etc.mkdir(mode=0o700)
    os_release_raw = material_build.read_regular(
        output / "evidence/os-release",
        maximum=generator["resolution_interface"]["os_release"]["platforms"][platform]["size"],
        context="retained system os-release",
    )
    _write_new(etc / "os-release", os_release_raw)

    trivy = generator["trivy"]
    native_trivy = trivy["platforms"][platform]
    scanner_root = _new_directory(
        Path("/tmp/z4j-production-system-trivy")  # noqa: S108 - isolated container
    )
    trivy_archive = INTERNAL_ACQUIRED_ROOT / ".generator/trivy-archive.tar.gz"
    trivy_archive_raw = material_build.read_regular(
        trivy_archive,
        maximum=material_build.MAX_FILE_BYTES,
        context="Trivy archive",
    )
    material_build.extract_reviewed_tar(
        trivy_archive_raw,
        scanner_root,
        expected_sha256=native_trivy["archive"]["members_sha256"],
        expected_entries=native_trivy["archive"]["members_entries"],
        expected_bytes=native_trivy["archive"]["members_bytes"],
        context="Trivy archive",
    )
    scanner_candidates = [path for path in scanner_root.rglob("trivy") if path.is_file()]
    if len(scanner_candidates) != 1:
        _die("Trivy archive binary is absent or ambiguous")
    scanner_raw = material_build.read_regular(
        scanner_candidates[0], maximum=material_build.MAX_FILE_BYTES, context="Trivy binary"
    )
    if (
        common.sha256(scanner_raw) != native_trivy["binary"]["sha256"]
        or len(scanner_raw) != native_trivy["binary"]["size"]
    ):
        _die("Trivy binary seal differs")
    _write_new(output / "evidence/trivy", scanner_raw, mode=0o755)
    version = material_build.require_success(
        runner.run(
            [str(output / "evidence/trivy"), "--version"],
            cwd=Path("/authority"),
            env=environment,
            timeout_seconds=60,
        ),
        context="Trivy version probe",
    )
    version_raw = version.stdout + version.stderr
    if common.sha256(version_raw) != native_trivy["version_output_sha256"]:
        _die("Trivy version transcript differs")
    _write_new(output / "evidence/trivy-version.txt", version_raw)
    database_root = output / "evidence/trivy-database"
    database_root.mkdir(mode=0o700)
    database_archive = INTERNAL_ACQUIRED_ROOT / ".generator/trivy-database.tar.gz"
    database_archive_raw = material_build.read_regular(
        database_archive,
        maximum=material_build.MAX_FILE_BYTES,
        context="Trivy database archive",
    )
    material_build.extract_reviewed_tar(
        database_archive_raw,
        database_root,
        expected_sha256=trivy["database_archive"]["members_sha256"],
        expected_entries=trivy["database_archive"]["members_entries"],
        expected_bytes=trivy["database_archive"]["members_bytes"],
        context="Trivy database archive",
    )
    database_files = material_build.file_records(database_root, exclude=frozenset())
    database_tree = {
        "files": database_files,
        "format": "z4j-trivy-database-tree-v1",
    }
    if (
        common.sha256(common.canonical_json(database_tree, terminal_lf=False))
        != trivy["database"]["tree_sha256"]
    ):
        _die("Trivy database tree differs")
    metadata_raw = material_build.read_regular(
        database_root / "db/metadata.json",
        maximum=material_build.MAX_FILE_BYTES,
        context="Trivy database metadata",
    )
    metadata = common.parse_json(metadata_raw, context="Trivy database metadata")
    if (
        common.sha256(metadata_raw) != trivy["database"]["metadata_sha256"]
        or metadata.get("Version") != trivy["database"]["schema_version"]
        or metadata.get("DownloadedAt") != trivy["database"]["downloaded_at_utc"]
        or metadata.get("UpdatedAt") != trivy["database"]["updated_at_utc"]
        or metadata.get("NextUpdate") != trivy["database"]["next_update_utc"]
    ):
        _die("Trivy database metadata differs")
    raw_report = run_evidence / "advisory-report.raw.json"
    scan = material_build.require_success(
        runner.run(
            [
                str(output / "evidence/trivy"),
                "rootfs",
                "--cache-dir",
                str(database_root),
                "--offline-scan",
                "--skip-db-update",
                "--scanners",
                "vuln",
                "--pkg-types",
                "os",
                "--list-all-pkgs",
                "--severity",
                "HIGH,CRITICAL",
                "--ignore-unfixed=false",
                "--format",
                "json",
                "--output",
                str(raw_report),
                str(scan_root),
            ],
            cwd=Path("/authority"),
            env=environment,
            timeout_seconds=3600,
        ),
        context="offline Trivy Debian scan",
    )
    report_raw = material_build.read_regular(
        raw_report, maximum=material_build.MAX_FILE_BYTES, context="Trivy advisory report"
    )
    report_value = common.parse_json(report_raw, context="Trivy advisory report")
    semantic_report = _derive_system_trivy_semantic_report(
        report_value, packages=lock["packages"], platform=platform
    )
    semantic_report_raw = common.canonical_json(semantic_report, terminal_lf=True)
    report = output / "evidence/advisory-report.json"
    _write_new(report, semantic_report_raw)
    _write_new(run_evidence / "trivy.stdout", scan.stdout)
    _write_new(run_evidence / "trivy.stderr", scan.stderr)
    _write_new(
        run_evidence / "trivy-run.json",
        common.canonical_json(
            {
                "command": {
                    "argv": list(scan.argv),
                    "cwd": "/authority",
                    "environment": environment,
                    "exit_code": scan.returncode,
                    "stderr": {
                        "path": "trivy.stderr",
                        "sha256": common.sha256(scan.stderr),
                        "size": len(scan.stderr),
                    },
                    "stdout": {
                        "path": "trivy.stdout",
                        "sha256": common.sha256(scan.stdout),
                        "size": len(scan.stdout),
                    },
                },
                "format": "z4j-production-system-trivy-run-evidence-v1",
                "raw_report": {
                    "path": "advisory-report.raw.json",
                    "sha256": common.sha256(report_raw),
                    "size": len(report_raw),
                },
            },
            terminal_lf=True,
        ),
    )
    advisory = {
        "database": trivy["database"],
        "findings": [],
        "format": material["advisory_receipt_format"],
        "package_lock_sha256": common.sha256(lock_raw),
        "platform": platform,
        "policy": {
            "ignore_unfixed": False,
            "list_all_packages": True,
            "required_result_type": "debian",
            "severities": ["HIGH", "CRITICAL"],
        },
        "report": {
            "path": "evidence/advisory-report.json",
            "sha256": common.sha256(semantic_report_raw),
            "size": len(semantic_report_raw),
        },
        "scanner": {
            "binary_sha256": native_trivy["binary"]["sha256"],
            "name": "trivy",
            "version": trivy["version"],
            "version_output_sha256": native_trivy["version_output_sha256"],
        },
        "verdict": "pass",
        "synthetic_status": {
            "sha256": common.sha256(status_raw),
            "size": len(status_raw),
        },
    }
    _write_new(
        output / "evidence/advisory-receipt.json",
        common.canonical_json(advisory, terminal_lf=True),
    )
    material_build.install_inventory(
        output,
        platform=platform,
        inventory_format=material["inventory_format"],
        tree_format=material["tree_format"],
    )


def _command_build_platform(args: argparse.Namespace) -> None:
    """Run two clean native Buildx builds only after the full authority gate."""

    policy, policy_raw = _load(args.policy, terminal_lf=True, context="system authority policy")
    trusted_raw = common.read_regular(
        args.trusted_root,
        maximum=common.MAX_JSON_BYTES,
        context="Sigstore trusted root",
    )
    require_ready(policy, trusted_root_raw=trusted_raw)
    if args.platform != _native_platform():
        _die("build-platform requires a native runner")
    material = policy["system_packages"]
    generator = material["generator"]
    # This separate explicit gate remains useful after common/E0 readiness: no
    # output directory, Docker probe, or BuildKit action occurs before it.
    build_poison = [
        *_validate_build_policy(generator),
        *_validate_snapshot_policy(material["snapshot"]),
    ]
    if build_poison:
        _die("system build inputs are UNFINALIZED: " + "; ".join(build_poison))
    if generator["resolution_interface"] is None:
        _die("system apt resolution interface is UNFINALIZED")

    repo_root = material_build.require_direct_directory(
        args.repo_root, context="system generator repository root"
    )
    package_root = material_build.require_direct_directory(
        repo_root / "packages/z4j", context="system generator package root"
    )
    dockerfile = package_root / GENERATOR_DOCKERFILE
    dockerfile_raw = material_build.read_regular(
        dockerfile,
        maximum=common.MAX_JSON_BYTES,
        context="system generator Dockerfile",
    )
    if (
        common.sha256(dockerfile_raw) != generator["dockerfile"]["sha256"]
        or len(dockerfile_raw) != generator["dockerfile"]["size"]
    ):
        _die("system generator Dockerfile seal differs")
    material_build.validate_generator_dockerfile(
        dockerfile_raw,
        acquisition_marker=b"RUN --network=default",
        offline_markers=(
            b'RUN --network=none ["python3", "-P", "/authority/system_authority.py", "internal-installability"]',
            b'RUN --network=none ["python3", "-P", "/authority/system_authority.py", "internal-build"]',
        ),
    )
    output_root = material_build.create_empty_private_directory(
        args.output, context="system native build output"
    )
    output_identity = material_build.directory_identity(
        output_root, context="system native build output"
    )
    with material_build.private_temporary_directory(
        prefix="z4j-system-build-context."
    ) as private_root:
        context_root = private_root / "context"
        context_root.mkdir(mode=0o700)
        runner = material_build.SubprocessRunner()
        captured_source = material_build.capture_git_selected_paths(
            repo_root,
            package_root,
            context_root,
            reference=args.source_ref,
            claimed_commit=args.source_commit,
            claimed_tree=args.source_tree,
            source_prefix=GENERATOR_SOURCE_PREFIX,
            selections=GENERATOR_CONTEXT_SELECTIONS,
            git_authority=generator["tools"]["git"]["platforms"][args.platform],
            runner=runner,
        )
        captured = captured_source["files"]
        source_files = generator["build_context"]["source_files"]
        captured_by_path = {item["path"]: item for item in captured}
        for path in GENERATOR_SOURCE_FILES:
            record = captured_by_path.get(path)
            if (
                record is None
                or {
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                != source_files[path]
            ):
                _die(f"system build context source seal differs: {path}")
        execution = material_build.run_native_build_pair(
            runner,
            docker_authority=generator["docker"]["platforms"][args.platform],
            execution_plane=generator["execution_plane"],
            build_operand_contract={
                "context_name": "context",
                "dockerfile": generator["dockerfile"],
                "output_directories": {"A": "A", "B": "B"},
            },
            builder_prefix=generator["builder"],
            platform=args.platform,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            dockerfile=context_root / GENERATOR_DOCKERFILE,
            context=context_root,
            output_root=output_root,
            build_args={
                "RESOLVER_IMAGE": material["resolver_base"]["image"],
                "Z4J_PLATFORM": args.platform,
                "Z4J_POLICY_SHA256": common.sha256(policy_raw),
            },
            cwd=repo_root,
        )
        recheck_root = private_root / "recheck"
        recheck_root.mkdir(mode=0o700)
        rechecked = material_build.capture_git_selected_paths(
            repo_root,
            package_root,
            recheck_root,
            reference=args.source_ref,
            claimed_commit=args.source_commit,
            claimed_tree=args.source_tree,
            source_prefix=GENERATOR_SOURCE_PREFIX,
            selections=GENERATOR_CONTEXT_SELECTIONS,
            git_authority=generator["tools"]["git"]["platforms"][args.platform],
            runner=runner,
        )
        if rechecked != captured_source:
            _die("system generator source changed during native A/B build")
    material_build.require_directory_identity(
        output_root,
        output_identity,
        context="system native build output",
    )
    comparison = material_build.compare_payload_roots(
        output_root / "A/payload",
        output_root / "B/payload",
    )
    carrier_filename = f"production-system-{ARCHITECTURES[args.platform]}-native-result.tar"
    carrier = material_build.create_platform_result_carrier(
        output_root,
        output_root / carrier_filename,
        filename=carrier_filename,
        material="system",
        platform=args.platform,
    )
    result = {
        "carrier": carrier,
        "comparison": comparison,
        "execution": execution,
        "format": "z4j-production-system-platform-build-v1",
        "platform": args.platform,
        "policy_sha256": common.sha256(policy_raw),
        "source_context": {
            "files": captured,
            "format": "z4j-production-system-build-context-capture-v2",
            "git": captured_source["git"],
        },
        "selected_build": "A",
    }
    material_build.atomic_write_new(
        output_root / "platform-result.json",
        material_build.canonical_json(result, terminal_lf=True),
    )
    material_build.require_directory_identity(
        output_root,
        output_identity,
        context="system native build output",
    )


def _producer_oci_build_record(
    build_id: str, derived: Mapping[str, Any], oci: Any
) -> dict[str, Any]:
    payload = derived["payload"]
    return {
        "config_digest": oci.config.descriptor["digest"],
        "config_size": oci.config.descriptor["size"],
        "id": build_id,
        "inventory_sha256": payload["inventory_sha256"],
        "inventory_size": payload["inventory_size"],
        "layer_digest": oci.layer.descriptor["digest"],
        "layer_diff_id": oci.layer_diff_id,
        "layer_size": oci.layer.descriptor["size"],
        "manifest_digest": oci.leaf.descriptor["digest"],
        "manifest_size": oci.leaf.descriptor["size"],
        "tree_bytes": payload["tree_bytes"],
        "tree_sha256": payload["tree_sha256"],
    }


def _bind_system_producer_oci(
    aggregation: Mapping[str, Any],
    platform_oci: Mapping[str, Any],
    original_manifest: Mapping[str, Any],
    policy: Mapping[str, Any],
    generator: Mapping[str, Any],
    *,
    extraction_root: Path,
    subject_index: bytes,
) -> Any:
    """Project authenticated derived claims plus literal OCI bytes into R."""

    finalize = _load_finalize_module()
    material_policy = policy["system_packages"]
    platforms: dict[str, Any] = {}
    verification_platforms: dict[str, Any] = {}
    for platform, architecture in ARCHITECTURES.items():
        derived = aggregation["platforms"][platform]
        builds: list[dict[str, Any]] = []
        for position, build_id in enumerate(("A", "B")):
            observed = _producer_hook("_derive_system_platform_build")(
                extraction_root / architecture / build_id,
                platform=platform,
                policy=policy,
            )
            expected = {
                key: item for key, item in derived["builds"][position].items() if key != "id"
            }
            if observed != expected:
                _die(f"system {platform} build {build_id} changed after aggregation")
            builds.append(
                _producer_oci_build_record(
                    build_id,
                    observed,
                    platform_oci[platform].builds[build_id],
                )
            )
        selected = platform_oci[platform].selected
        platforms[platform] = {
            **derived["selection"],
            "config_digest": selected.config.descriptor["digest"],
            "config_size": selected.config.descriptor["size"],
            "manifest_digest": selected.leaf.descriptor["digest"],
            "manifest_size": selected.leaf.descriptor["size"],
        }
        identity = aggregation["carrier_aggregation"]["platforms"][platform]["identity"]
        verification_platforms[platform] = {
            "artifact": identity["artifact"],
            "builds": builds,
            "checks": {**derived["checks"], "oci": True},
            "job": identity["job"],
            "selected_build": aggregation["selected_build"],
        }
    subject_digest = common.digest(subject_index)
    subject_tag = common.derived_tag(PROFILE, subject_digest, authority=False)
    system_packages = {
        "format": material_policy["format"],
        "image": f"{REPOSITORY}:{subject_tag}@{subject_digest}",
        "index": {"digest": subject_digest, "size": len(subject_index)},
        "payload_root": PROFILE.payload_root,
        "platforms": platforms,
        "requested": material_policy["requested"],
        "snapshot": _snapshot_selection(material_policy["snapshot"]),
        "state": "finalized",
    }
    manifest = copy.deepcopy(original_manifest)
    manifest["system_packages"] = system_packages
    verification = {
        "aggregate": {
            "all_platforms_passed": True,
            "builds_byte_identical": True,
            "index_canonical": True,
            "native_platforms": True,
            "policy_sha256": common.sha256(common.canonical_json(policy, terminal_lf=True)),
            "referrers_native": True,
        },
        "platforms": verification_platforms,
    }
    return finalize.MaterialBinding(
        manifest=manifest,
        material=system_packages,
        readback_extra={},
        source={
            "generator": dict(generator),
            "resolver_base": {
                "image": original_manifest["python"]["image"],
                "index": original_manifest["python"]["index"],
                "platforms": original_manifest["python"]["platforms"],
            },
        },
        source_context=aggregation["source_context"],
        verification=verification,
    )


def _producer_adapter() -> Any:
    finalize = _load_finalize_module()
    return finalize.FinalizationAdapter(
        architectures=ARCHITECTURES,
        authority_schema=AUTHORITY_SCHEMA,
        bind_oci_platform_results=_bind_system_producer_oci,
        common=common,
        material_build=material_build,
        material_key="system_packages",
        platforms=PLATFORMS,
        policy_carrier_path=POLICY_CARRIER_PATH,
        policy_release_path=POLICY_RELEASE_PATH,
        profile=PROFILE,
        require_ready=require_ready,
        validate_authority_manifest=validate_authority_manifest,
        validate_bundle=lambda receipt, bundle, _policy: common.validate_bundle(
            bundle,
            receipt_raw=receipt,
            integrated_time_minimum=REKOR_INTEGRATED_TIME_MINIMUM,
        ),
        validate_manifest_authority=validate_manifest_authority,
        validate_platform_aggregation=_producer_hook("validate_system_platform_aggregation"),
        validate_receipt=validate_receipt,
        validate_subject_index=validate_subject_index,
        validation_errors=(
            SystemAuthorityError,
            common.CommonAuthorityError,
            material_build.MaterialBuildError,
        ),
    )


def _command_producer_finalize(args: argparse.Namespace) -> None:
    # Only policy/trusted-root bytes may be read before this unconditional gate.
    policy, policy_raw = _load(args.policy, terminal_lf=True, context="system authority policy")
    trusted_raw = common.read_regular(
        args.trusted_root,
        maximum=common.MAX_JSON_BYTES,
        context="Sigstore trusted root",
    )
    require_ready(policy, trusted_root_raw=trusted_raw)
    finalize = _load_finalize_module()
    adapter = _producer_adapter()
    finalize._assert_oci_runtime_contract(adapter)
    runtime_factory = args.producer_runtime_factory
    if not callable(runtime_factory):
        _die("zero-side-effect authenticated producer runtime factory was not injected")
    runtime = runtime_factory()
    if not isinstance(runtime, finalize.ProducerRuntime):
        _die("authenticated producer runtime factory returned the wrong type")
    manifest, _manifest_raw = _load_tracked_manifest(args.manifest)
    aggregation, _aggregation_raw = _load(
        args.aggregation,
        terminal_lf=True,
        context="system derived platform aggregation",
    )
    result = finalize.producer_finalize(
        adapter,
        aggregation=aggregation,
        extraction_root=args.extracted_root,
        github=runtime.github,
        manifest=manifest,
        now=runtime.now,
        oci=runtime.oci,
        policy=policy,
        policy_raw=policy_raw,
        recovery_polls=args.recovery_polls,
        signer=runtime.signer,
        trusted_root_raw=trusted_raw,
    )
    finalize.write_finalization_output(args.output, result, profile=PROFILE)
    sys.stdout.write(
        json.dumps(
            {
                "authority_digest": result.authority_digest,
                "authority_tag": result.authority_tag,
                "recovered_authority": result.recovered_authority,
                "subject_digest": result.subject_digest,
                "subject_tag": result.subject_tag,
                "transition_kind": result.transition_kind,
            },
            sort_keys=True,
        )
        + "\n"
    )


def _command_policy(args: argparse.Namespace) -> None:
    policy, raw = _load(args.policy, terminal_lf=True, context="system authority policy")
    poison = validate_policy(policy)
    if args.require_ready:
        trusted_raw = common.read_regular(
            args.trusted_root, maximum=common.MAX_JSON_BYTES, context="Sigstore trusted root"
        )
        require_ready(policy, trusted_root_raw=trusted_raw)
    sys.stdout.write(
        json.dumps(
            {"poison": poison, "sha256": common.sha256(raw), "size": len(raw)},
            sort_keys=True,
        )
        + "\n"
    )


def _command_manifest(args: argparse.Namespace) -> None:
    manifest, _raw = _load_tracked_manifest(args.manifest)
    _policy, policy_raw = _load(args.policy, terminal_lf=True, context="system authority policy")
    validate_manifest_authority(manifest, policy_raw)
    sys.stdout.write("system authority manifest selection: valid\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    policy = subparsers.add_parser("policy")
    policy.add_argument("--policy", type=Path, required=True)
    policy.add_argument("--require-ready", action="store_true")
    policy.add_argument("--trusted-root", type=Path)
    policy.set_defaults(handler=_command_policy)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--manifest", type=Path, required=True)
    manifest.add_argument("--policy", type=Path, required=True)
    manifest.set_defaults(handler=_command_manifest)
    build = subparsers.add_parser("build-platform")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--platform", choices=PLATFORMS, required=True)
    build.add_argument("--policy", type=Path, required=True)
    build.add_argument("--repo-root", type=Path, required=True)
    build.add_argument("--run-attempt", type=int, required=True)
    build.add_argument("--run-id", type=int, required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--source-ref", required=True)
    build.add_argument("--source-tree", required=True)
    build.add_argument("--trusted-root", type=Path, required=True)
    build.set_defaults(handler=_command_build_platform)
    producer = subparsers.add_parser("producer-finalize")
    producer.add_argument("--aggregation", type=Path, required=True)
    producer.add_argument("--extracted-root", type=Path, required=True)
    producer.add_argument("--manifest", type=Path, required=True)
    producer.add_argument("--output", type=Path, required=True)
    producer.add_argument("--policy", type=Path, required=True)
    producer.add_argument("--recovery-polls", type=int, default=4)
    producer.add_argument("--require-ready", action="store_true", required=True)
    producer.add_argument("--trusted-root", type=Path, required=True)
    producer.set_defaults(handler=_command_producer_finalize)
    internal_acquire = subparsers.add_parser("internal-acquire")
    internal_acquire.set_defaults(handler=_command_internal_acquire)
    internal_installability = subparsers.add_parser("internal-installability")
    internal_installability.set_defaults(handler=_command_internal_installability)
    internal_build = subparsers.add_parser("internal-build")
    internal_build.set_defaults(handler=_command_internal_build)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    producer_runtime_factory: Any | None = None,
) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "policy" and args.require_ready and args.trusted_root is None:
            _die("--trusted-root is required with --require-ready")
        args.producer_runtime_factory = producer_runtime_factory
        args.handler(args)
    except (
        SystemAuthorityError,
        common.CommonAuthorityError,
        material_build.MaterialBuildError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        sys.stderr.write(f"system-authority: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
