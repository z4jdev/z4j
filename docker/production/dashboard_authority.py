#!/usr/bin/env python3
"""Detached, acyclic authority for the z4j 1.9.0 dashboard data bundle.

The dashboard receipt is deliberately pre-U0: it binds Q0, the independently
reviewed SOURCE_DATE_EPOCH, and the byte-identical dashboard dist tree, but no
future U0/U/R/source-tag identity.  The tracked source is UNFINALIZED, so the
producer readiness command fails before any external mutation until every
reviewed workflow, repository, tool, trust-root, and epoch value is present.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.parse
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple, NoReturn, Protocol, cast


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
POLICY_FORMAT = "z4j-production-dashboard-authority-policy-v1"
AUTHORITY_FORMAT = "z4j-production-dashboard-authority-v1"
AUTHORITY_SCHEMA = "z4j.production-dashboard-authority.v1"
POLICY_CARRIER_PATH = "packages/z4j/docker/production/dashboard-authority-policy.json"
POLICY_RELEASE_PATH = "docker/production/dashboard-authority-policy.json"
TRUSTED_ROOT_RELEASE_PATH = "docker/production/trust/sigstore-trusted-root.json"
REPOSITORY = "docker.io/z4jdev/z4j-production-dashboard"
WORKFLOW_PATH = ".github/workflows/finalize-production-dashboard.yml"
WORKFLOW_NAME = "finalize-production-dashboard"
WORKFLOW_IDENTITY = (
    "https://github.com/dxdevo/z4j/.github/workflows/"
    "finalize-production-dashboard.yml@refs/heads/main"
)
ENVIRONMENT = "production-dashboard-finalization"
RECEIPT_FILENAME = "production-dashboard-authority.json"
BUNDLE_FILENAME = "production-dashboard-authority.sigstore.json"
ARTIFACT_FILENAME = "production-dashboard-authority.oci.json"
RECEIPT_MEDIA_TYPE = "application/vnd.z4j.production-dashboard-authority-receipt.v1+json"
ARTIFACT_TYPE = "application/vnd.z4j.production-dashboard-authority.v1+json"
SUBJECT_TAG_PATTERN = r"^1\.9\.0-digest-[0-9a-f]{64}$"
AUTHORITY_TAG_PATTERN = r"^1\.9\.0-dashboard-authority-[0-9a-f]{64}$"
CUTOFF = "2026-08-23T04:14:39.107Z"
REKOR_INTEGRATED_TIME_MINIMUM = 1787458480
PLATFORMS = ("linux/amd64", "linux/arm64")
ARCHITECTURES = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
MAX_TRIVY_REPORT_BYTES = 64 * 1024 * 1024
GENERATOR_DOCKERFILE = "docker/production/generators/dashboard.Dockerfile"
GENERATOR_BUILDER = "z4j-production-dashboard"
GENERATOR_SOURCE_PREFIX = "packages/z4j"
GENERATOR_SOURCE_FILES = (
    "docker/production/dashboard_authority.py",
    "docker/production/generators/dashboard.mjs",
    "docker/production/production_authority_common.py",
    "docker/production/production_material_build.py",
)
NODE_IMAGE = (
    "docker.io/library/node:24.19.0-bookworm-slim@"
    "sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03"
)
NODE_INDEX_DIGEST = "sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03"
PROJECTION_FRAMING = (
    "canonical-json:{format,files:[{path,mode,size,sha256}]} sorted by UTF-8 "
    "logical path; mode is 0755 iff path is listed in executables, otherwise 0644"
)
PROJECTION_INCLUSIONS = [
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
PROJECTION_EXCLUSIONS = [".DS_Store", "__pycache__", "*.map", "*.pyc", "*.pyo"]
GENERATOR_CONTEXT_SELECTIONS = tuple(
    sorted(
        (
            "docker/production/dashboard-authority-policy.json",
            "docker/production/generators/dashboard.Dockerfile",
            *GENERATOR_SOURCE_FILES,
            *(f"dashboard/{path}" for path in PROJECTION_INCLUSIONS),
        ),
        key=str.encode,
    )
)
DIST_TRANSITION_PLAN_FORMAT = "z4j-dashboard-dist-main-transition-plan-v1"
DIST_TRANSITION_READBACK_FORMAT = "z4j-dashboard-dist-main-transition-readback-v1"
DIST_TRANSITION_GRAPHQL_READBACK_FORMAT = "z4j-dashboard-dist-main-transition-readback-v2"
DIST_TRANSITION_GRAPHQL_CAS_EVIDENCE_FORMAT = "z4j-dashboard-git-graphql-cas-evidence-v1"
DIST_TRANSITION_GIT_OBJECTS_FORMAT = "z4j-dashboard-dist-git-object-set-v1"
DIST_TRANSITION_PREFIX = "packages/z4j/backend/src/z4j_brain/dashboard/dist/"
DIST_TRANSITION_MESSAGE = "Freeze z4j 1.9.0 production dashboard dist"
DIST_TRANSITION_MARKERS = frozenset(
    {".build-context", ".build-inputs.sha256", ".build-output.sha256"}
)
GITHUB_REPOSITORY_API_URL = f"https://api.github.com/repos/{common.PRODUCER_REPOSITORY}"
GITHUB_MAIN_REF_READ_URL = GITHUB_REPOSITORY_API_URL + "/git/ref/heads/main"
GITHUB_MAIN_REF_UPDATE_URL = GITHUB_REPOSITORY_API_URL + "/git/refs/heads/main"
GITHUB_MAIN_PROTECTION_URL = GITHUB_REPOSITORY_API_URL + "/branches/main/protection"
GITHUB_RULESETS_URL = GITHUB_REPOSITORY_API_URL + "/rulesets?includes_parents=true&per_page=100"
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
GITHUB_JSON_REQUEST_CONTENT_TYPE = "application/json"
GITHUB_TRANSITION_API_VERSION = "2026-03-10"
GITHUB_UPDATE_REFS_QUERY = (
    "mutation UpdateDashboardMain($input:UpdateRefsInput!){"
    "updateRefs(input:$input){clientMutationId}}"
)
GOVERNANCE_CHOICES = frozenset({"G1", "G2", "G3"})
REPOSITORY_REF_VOLATILE_FIELDS = frozenset({"pushed_at", "size", "updated_at"})
DASHBOARD_WORKSPACE = "/tmp/z4j-dashboard-workspace"  # noqa: S108 - isolated container
DASHBOARD_PNPM = DASHBOARD_WORKSPACE + "/.tools/pnpm.cjs"
DASHBOARD_INSTALL_STORE = "/tmp/z4j-dashboard-install-store"  # noqa: S108
DASHBOARD_HOME = "/tmp/z4j-dashboard-home"  # noqa: S108 - isolated container

PROFILE = common.AuthorityProfile(
    artifact_filename=ARTIFACT_FILENAME,
    artifact_media_type=common.OCI_MANIFEST,
    artifact_type=ARTIFACT_TYPE,
    authority_tag_pattern=AUTHORITY_TAG_PATTERN,
    authority_tag_prefix="1.9.0-dashboard-authority-",
    bundle_filename=BUNDLE_FILENAME,
    bundle_media_type=common.SIGSTORE_BUNDLE_V03,
    cleanup_excludes=(SUBJECT_TAG_PATTERN, AUTHORITY_TAG_PATTERN),
    created_transition="created-content-derived-dashboard",
    environment=ENVIRONMENT,
    material="dashboard",
    immutability_patterns=(
        ("authority_pattern", AUTHORITY_TAG_PATTERN),
        ("subject_pattern", SUBJECT_TAG_PATTERN),
    ),
    payload_root="/opt/z4j-production-dashboard",
    oci_tag_patterns=(
        ("authority_tag_pattern", AUTHORITY_TAG_PATTERN),
        ("subject_tag_pattern", SUBJECT_TAG_PATTERN),
    ),
    receipt_format=AUTHORITY_FORMAT,
    receipt_filename=RECEIPT_FILENAME,
    receipt_media_type=RECEIPT_MEDIA_TYPE,
    recovered_transition="recovered-existing-exact-dashboard",
    repository=REPOSITORY,
    subject_tag_pattern=SUBJECT_TAG_PATTERN,
    subject_tag_prefix="1.9.0-digest-",
    workflow_identity=WORKFLOW_IDENTITY,
    workflow_name=WORKFLOW_NAME,
    workflow_path=WORKFLOW_PATH,
)

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
    "package_projection",
    "qualification_run",
    "release_git_commit",
    "release_git_tree",
    "source_tag",
    "source_tag_authority",
    "standalone_commit",
    "standalone_tree",
    "system_authority",
    "u0",
    "wheelhouse_authority",
}


class DashboardAuthorityError(common.CommonAuthorityError):
    """The dashboard authority is malformed, untrusted, or not realizable."""


class MainTransitionGovernance(NamedTuple):
    """Reviewed E0 settings selected by the still-open G1/G2/G3 choice.

    The executor deliberately has no defaults for these values. In particular,
    repository/ruleset IDs, bypass actors, review counts, and other
    architecture-dependent settings must come from the approved E0 readback.
    """

    choice: str
    main_protection: Any
    repository: Any
    rulesets: Any


class GitHubTransitionRequest(NamedTuple):
    """One credential-free request description passed to an injected transport."""

    accept: str
    api_version: str | None
    body: bytes | None
    content_type: str | None
    method: str
    url: str


class GitHubTransitionResponse(NamedTuple):
    """Literal response bytes returned by the injected transport."""

    body: bytes
    content_type: str
    status: int


class GitHubTransitionTransport(Protocol):
    """Strict injected transport; this module provides no network implementation."""

    def request(self, request: GitHubTransitionRequest) -> GitHubTransitionResponse:
        """Return the literal authenticated GitHub response for one exact request."""


class MainTransitionExecution(NamedTuple):
    """In-memory proof accompanying the two normative detached v1 documents."""

    cas_evidence: dict[str, Any] | None
    exchanges: tuple[dict[str, Any], ...]
    governance_choice: str
    mutation_request: dict[str, Any] | None
    precondition_readback: dict[str, Any]
    readback: dict[str, Any]


def _die(message: str) -> NoReturn:
    raise DashboardAuthorityError(message)


def _file_authority(value: Any, *, path: str, context: str) -> list[str]:
    item = common.exact_object(value, {"path", "sha256", "size", "version_output_sha256"}, context)
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


def _download_authority(value: Any, context: str) -> list[str]:
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


def _archive_authority(value: Any, context: str) -> list[str]:
    item = common.exact_object(
        value,
        {"members_bytes", "members_entries", "members_sha256", "sha256", "size", "url"},
        context,
    )
    poison = _download_authority({key: item[key] for key in ("sha256", "size", "url")}, context)
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


def _validate_generator_policy(value: Any) -> list[str]:  # noqa: PLR0912,PLR0915
    generator = common.exact_object(
        value,
        {
            "build_context",
            "builder",
            "commands",
            "docker",
            "dockerfile",
            "execution_plane",
            "tools",
            "trivy",
        },
        "dashboard generator policy",
    )
    if generator["builder"] != GENERATOR_BUILDER:
        _die("dashboard generator builder differs")
    build_context = common.exact_object(
        generator["build_context"], {"format", "source_files"}, "dashboard build context"
    )
    source_files = common.exact_object(
        build_context["source_files"],
        set(GENERATOR_SOURCE_FILES),
        "dashboard build source files",
    )
    if build_context["format"] != "z4j-production-dashboard-build-context-v1":
        _die("dashboard build context format differs")
    context_poison: list[str] = []
    for path in GENERATOR_SOURCE_FILES:
        seal = common.exact_object(
            source_files[path], {"sha256", "size"}, f"dashboard build source {path}"
        )
        if seal["sha256"] is None or seal["size"] is None:
            context_poison.append(f"dashboard build source {path} seal is null")
        else:
            common.hex64(seal["sha256"], f"dashboard build source {path}")
            common.positive_int(seal["size"], f"dashboard build source {path} size")
    poison = material_build.validate_platform_file_authority(
        generator["docker"],
        platforms=PLATFORMS,
        path="/usr/bin/docker",
        context="dashboard generator Docker",
    )
    poison.extend(context_poison)
    poison.extend(
        material_build.validate_execution_plane_policy(
            generator["execution_plane"], platforms=PLATFORMS
        )
    )
    dockerfile = common.exact_object(
        generator["dockerfile"], {"path", "sha256", "size"}, "dashboard generator Dockerfile"
    )
    if dockerfile["path"] != GENERATOR_DOCKERFILE:
        _die("dashboard generator Dockerfile path differs")
    if dockerfile["sha256"] is None or dockerfile["size"] is None:
        poison.append("dashboard generator Dockerfile seal is null")
    else:
        common.hex64(dockerfile["sha256"], "dashboard generator Dockerfile SHA-256")
        common.positive_int(dockerfile["size"], "dashboard generator Dockerfile size")
    commands = common.exact_object(
        generator["commands"], {"build", "install"}, "dashboard generator commands"
    )
    if commands != {
        "build": [
            "node",
            DASHBOARD_PNPM,
            "run",
            "build",
        ],
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
    }:
        _die("dashboard generator command policy differs")
    tools = common.exact_object(generator["tools"], {"git", "tar"}, "dashboard generator tools")
    poison.extend(
        material_build.validate_platform_git_authority(
            tools["git"],
            platforms=PLATFORMS,
            context="dashboard generator Git",
        )
    )
    poison.extend(
        material_build.validate_platform_file_authority(
            tools["tar"],
            platforms=PLATFORMS,
            path="/bin/tar",
            context="dashboard generator tar",
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
        "dashboard generator Trivy",
    )
    if trivy["version"] != "0.74.0":
        _die("dashboard generator Trivy version differs")
    poison.extend(
        _archive_authority(trivy["database_archive"], "dashboard generator Trivy database archive")
    )
    native_trivy = common.exact_object(
        trivy["platforms"], set(PLATFORMS), "dashboard generator Trivy platforms"
    )
    for platform in PLATFORMS:
        native = common.exact_object(
            native_trivy[platform],
            {"archive", "binary", "version_output_sha256"},
            f"dashboard generator Trivy {platform}",
        )
        poison.extend(
            _archive_authority(native["archive"], f"dashboard generator Trivy archive {platform}")
        )
        binary = common.exact_object(
            native["binary"], {"sha256", "size"}, f"dashboard generator Trivy binary {platform}"
        )
        if binary["sha256"] is None or binary["size"] is None:
            poison.append(f"dashboard generator Trivy binary {platform} seal is null")
        else:
            common.hex64(binary["sha256"], f"dashboard generator Trivy binary {platform}")
            common.positive_int(binary["size"], f"dashboard generator Trivy binary {platform} size")
        if native["version_output_sha256"] is None:
            poison.append(f"dashboard generator Trivy {platform} version transcript is null")
        else:
            common.hex64(
                native["version_output_sha256"],
                f"dashboard generator Trivy {platform} version transcript",
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
        "dashboard generator Trivy database",
    )
    if database["name"] != "trivy-db" or database["schema_version"] != 2:
        _die("dashboard generator Trivy database identity differs")
    for key in ("metadata_sha256", "tree_sha256"):
        if database[key] is None:
            poison.append(f"dashboard generator Trivy database {key} is null")
        else:
            common.hex64(database[key], f"dashboard generator Trivy database {key}")
    for key in ("downloaded_at_utc", "next_update_utc", "updated_at_utc"):
        if database[key] is None:
            poison.append(f"dashboard generator Trivy database {key} is null")
        else:
            common.timestamp(database[key], f"dashboard generator Trivy database {key}")
    return poison


def validate_policy(policy: Any) -> list[str]:  # noqa: PLR0912 - closed poison matrix
    """Validate the closed dashboard policy and enumerate source poison."""

    value, poison = common.validate_policy_common(
        PROFILE,
        policy,
        policy_format=POLICY_FORMAT,
        material_key="dashboard",
        trusted_root_path=TRUSTED_ROOT_RELEASE_PATH,
        cutoff_not_before_utc=CUTOFF,
    )
    dashboard = common.exact_object(
        value["dashboard"],
        {
            "advisory_receipt_format",
            "build_receipt_format",
            "bundle_tree_format",
            "generator",
            "index_descriptor_order",
            "inventory_format",
            "layer_count_per_platform",
            "node",
            "payload_root",
            "platforms",
            "pnpm",
            "sbom_format",
            "source_date_epoch",
            "source_projection",
            "store_inventory_format",
            "store_tree_format",
            "tree_format",
        },
        "dashboard policy material",
    )
    node = common.exact_object(
        dashboard["node"],
        {"image", "index_digest", "index_size", "platforms", "version"},
        "dashboard node policy",
    )
    pnpm = common.exact_object(
        dashboard["pnpm"],
        {
            "archive_members_bytes",
            "archive_members_entries",
            "archive_members_sha256",
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "published_at_utc",
            "registry_packument",
            "registry_sha256",
            "registry_size",
            "release_receipt_format",
            "tarball",
            "version",
        },
        "dashboard pnpm policy",
    )
    projection = common.exact_object(
        dashboard["source_projection"],
        {
            "algorithm",
            "bytes",
            "entries",
            "exclusions",
            "executables",
            "inclusions",
            "record_framing",
            "sha256",
        },
        "dashboard projection policy",
    )
    fixed = {
        key: dashboard[key]
        for key in dashboard
        if key not in {"generator", "node", "pnpm", "source_date_epoch", "source_projection"}
    }
    if (
        fixed
        != {
            "advisory_receipt_format": "z4j-production-dashboard-advisory-v1",
            "build_receipt_format": "z4j-production-dashboard-build-v1",
            "bundle_tree_format": "z4j-production-dashboard-dist-tree-v1",
            "index_descriptor_order": list(PLATFORMS),
            "inventory_format": "z4j-production-dashboard-inventory-v1",
            "layer_count_per_platform": 1,
            "payload_root": PROFILE.payload_root,
            "platforms": list(PLATFORMS),
            "sbom_format": "CycloneDX-1.6-json",
            "store_inventory_format": "z4j-production-pnpm-store-inventory-v1",
            "store_tree_format": "z4j-production-pnpm-store-tree-v1",
            "tree_format": "z4j-production-dashboard-tree-v1",
        }
        or node
        != {
            "image": NODE_IMAGE,
            "index_digest": NODE_INDEX_DIGEST,
            "index_size": node["index_size"],
            "platforms": node["platforms"],
            "version": "24.19.0",
        }
        or {
            key: pnpm[key]
            for key in ("registry_packument", "release_receipt_format", "tarball", "version")
        }
        != {
            "registry_packument": "https://registry.npmjs.org/pnpm",
            "release_receipt_format": "z4j-production-pnpm-release-v1",
            "tarball": "https://registry.npmjs.org/pnpm/-/pnpm-11.22.0.tgz",
            "version": "11.22.0",
        }
        or {
            key: projection[key]
            for key in ("algorithm", "exclusions", "executables", "inclusions", "record_framing")
        }
        != {
            "algorithm": "z4j-dashboard-source-tree-v1",
            "exclusions": PROJECTION_EXCLUSIONS,
            "executables": [],
            "inclusions": PROJECTION_INCLUSIONS,
            "record_framing": PROJECTION_FRAMING,
        }
    ):
        _die("dashboard material policy differs")
    epoch = dashboard["source_date_epoch"]
    if epoch is None:
        poison.append("dashboard.source_date_epoch is null")
    else:
        common.positive_int(epoch, "dashboard SOURCE_DATE_EPOCH")
    poison.extend(_validate_generator_policy(dashboard["generator"]))
    if node["index_size"] is None:
        poison.append("dashboard.node.index_size is null")
    else:
        common.positive_int(node["index_size"], "dashboard Node index size")
    platforms = common.exact_object(node["platforms"], set(PLATFORMS), "dashboard Node platforms")
    for platform in PLATFORMS:
        descriptor = common.exact_object(
            platforms[platform],
            {"config_digest", "config_size", "manifest_digest", "manifest_size"},
            f"dashboard Node {platform}",
        )
        if any(value is None for value in descriptor.values()):
            poison.append(f"dashboard.node.platforms.{platform} seals are null")
        else:
            for key in ("config_digest", "manifest_digest"):
                common.oci_digest(descriptor[key], f"dashboard Node {platform} {key}")
            for key in ("config_size", "manifest_size"):
                common.positive_int(descriptor[key], f"dashboard Node {platform} {key}")
    for digest_key, size_key in (
        ("archive_sha256", "archive_size"),
        ("binary_sha256", "binary_size"),
        ("registry_sha256", "registry_size"),
    ):
        if pnpm[digest_key] is None or pnpm[size_key] is None:
            poison.append(f"dashboard.pnpm.{digest_key} seal is null")
        else:
            common.hex64(pnpm[digest_key], f"dashboard pnpm {digest_key}")
            common.positive_int(pnpm[size_key], f"dashboard pnpm {size_key}")
    if any(
        pnpm[key] is None
        for key in ("archive_members_bytes", "archive_members_entries", "archive_members_sha256")
    ):
        poison.append("dashboard.pnpm archive semantic member seal is null")
    else:
        common.positive_int(pnpm["archive_members_bytes"], "dashboard pnpm archive bytes")
        common.positive_int(pnpm["archive_members_entries"], "dashboard pnpm archive entries")
        common.hex64(pnpm["archive_members_sha256"], "dashboard pnpm archive member SHA-256")
    if pnpm["published_at_utc"] is None:
        poison.append("dashboard.pnpm.published_at_utc is null")
    else:
        common.timestamp(pnpm["published_at_utc"], "dashboard pnpm publication")
    for key in ("bytes", "entries", "sha256"):
        if projection[key] is None:
            poison.append(f"dashboard.source_projection.{key} is null")
        elif key == "sha256":
            common.hex64(projection[key], "dashboard source projection SHA-256")
        else:
            common.positive_int(projection[key], f"dashboard source projection {key}")
    return poison


def require_ready(
    policy: Any,
    *,
    trusted_root_raw: bytes | None = None,
    now: dt.datetime | None = None,
) -> None:
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
        _die("dashboard authority is UNFINALIZED: " + "; ".join(poison))


def _validate_dashboard_selection(dashboard: Any) -> dict[str, Any]:  # noqa: PLR0912
    """Validate the complete finalized tracked dashboard selection."""

    value = common.exact_object(
        dashboard,
        {
            "format",
            "image",
            "index",
            "node",
            "payload_root",
            "platforms",
            "pnpm",
            "source_projection",
            "state",
        },
        "dashboard selection",
    )
    if (
        value["state"] != "finalized"
        or value["format"] != "z4j-production-dashboard-bundle-v1"
        or value["payload_root"] != PROFILE.payload_root
    ):
        _die("finalized dashboard constants differ")
    index = common.exact_object(value["index"], {"digest", "size"}, "dashboard index")
    subject = common.oci_digest(index["digest"], "dashboard subject digest")
    common.positive_int(index["size"], "dashboard subject size")
    expected_image = (
        f"{REPOSITORY}:{common.derived_tag(PROFILE, subject, authority=False)}@{subject}"
    )
    if value["image"] != expected_image:
        _die("dashboard image is not the fixed-repository S-derived reference")

    projection = common.exact_object(
        value["source_projection"],
        {
            "algorithm",
            "bytes",
            "entries",
            "exclusions",
            "executables",
            "inclusions",
            "record_framing",
            "sha256",
        },
        "dashboard source projection",
    )
    if {
        key: projection[key]
        for key in ("algorithm", "exclusions", "executables", "inclusions", "record_framing")
    } != {
        "algorithm": "z4j-dashboard-source-tree-v1",
        "exclusions": PROJECTION_EXCLUSIONS,
        "executables": [],
        "inclusions": PROJECTION_INCLUSIONS,
        "record_framing": PROJECTION_FRAMING,
    }:
        _die("dashboard source projection policy differs")
    common.hex64(projection["sha256"], "dashboard source projection SHA-256")
    common.positive_int(projection["entries"], "dashboard source projection entries")
    common.positive_int(projection["bytes"], "dashboard source projection bytes")

    node = common.exact_object(
        value["node"],
        {"image", "index_digest", "index_size", "platforms", "version"},
        "dashboard Node",
    )
    if (
        node["version"] != "24.19.0"
        or node["image"] != NODE_IMAGE
        or node["index_digest"] != NODE_INDEX_DIGEST
    ):
        _die("dashboard Node authority differs")
    common.positive_int(node["index_size"], "dashboard Node index size")
    node_platforms = common.exact_object(
        node["platforms"], set(PLATFORMS), "dashboard Node platforms"
    )
    for platform in PLATFORMS:
        item = common.exact_object(
            node_platforms[platform],
            {"config_digest", "config_size", "manifest_digest", "manifest_size"},
            f"dashboard Node {platform}",
        )
        for key in ("config_digest", "manifest_digest"):
            common.oci_digest(item[key], f"dashboard Node {platform} {key}")
        for key in ("config_size", "manifest_size"):
            common.positive_int(item[key], f"dashboard Node {platform} {key}")

    pnpm = common.exact_object(
        value["pnpm"],
        {
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "release_receipt_sha256",
            "release_receipt_size",
            "version",
        },
        "dashboard pnpm",
    )
    if pnpm["version"] != "11.22.0":
        _die("dashboard pnpm version differs")
    for key in ("archive_sha256", "binary_sha256", "release_receipt_sha256"):
        common.hex64(pnpm[key], f"dashboard pnpm {key}")
    for key in ("archive_size", "binary_size", "release_receipt_size"):
        common.positive_int(pnpm[key], f"dashboard pnpm {key}")

    platforms = common.exact_object(value["platforms"], set(PLATFORMS), "dashboard platforms")
    platform_keys = {
        "advisory_receipt_sha256",
        "advisory_receipt_size",
        "advisory_verdict",
        "build_receipt_sha256",
        "build_receipt_size",
        "bundle_tree_bytes",
        "bundle_tree_sha256",
        "config_digest",
        "config_size",
        "inventory_entries",
        "inventory_sha256",
        "inventory_size",
        "manifest_digest",
        "manifest_size",
        "pnpm_lock_sha256",
        "sbom_sha256",
        "sbom_size",
        "store_inventory_sha256",
        "store_inventory_size",
        "tree_bytes",
        "tree_sha256",
    }
    shared_bundle: tuple[str, int] | None = None
    shared_lock: str | None = None
    for platform in PLATFORMS:
        item = common.exact_object(platforms[platform], platform_keys, f"dashboard {platform}")
        for key in ("config_digest", "manifest_digest"):
            common.oci_digest(item[key], f"dashboard {platform} {key}")
        for key in ("config_size", "manifest_size"):
            common.positive_int(item[key], f"dashboard {platform} {key}")
        for key in (
            "advisory_receipt_sha256",
            "build_receipt_sha256",
            "bundle_tree_sha256",
            "inventory_sha256",
            "pnpm_lock_sha256",
            "sbom_sha256",
            "store_inventory_sha256",
            "tree_sha256",
        ):
            common.hex64(item[key], f"dashboard {platform} {key}")
        for key in (
            "advisory_receipt_size",
            "build_receipt_size",
            "bundle_tree_bytes",
            "inventory_entries",
            "inventory_size",
            "sbom_size",
            "store_inventory_size",
            "tree_bytes",
        ):
            common.positive_int(item[key], f"dashboard {platform} {key}")
        if item["advisory_verdict"] != "pass":
            _die(f"dashboard {platform} advisory verdict differs")
        bundle = (item["bundle_tree_sha256"], item["bundle_tree_bytes"])
        if shared_bundle is None:
            shared_bundle = bundle
            shared_lock = item["pnpm_lock_sha256"]
        elif bundle != shared_bundle or item["pnpm_lock_sha256"] != shared_lock:
            _die("dashboard platform dist trees or pnpm locks differ")
    return value


def validate_manifest_authority(manifest: Mapping[str, Any], policy_raw: bytes) -> dict[str, Any]:
    policy = common.parse_json(policy_raw, context="dashboard authority policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("dashboard policy is not canonical JSON plus one LF")
    validate_policy(policy)
    authority = common.validate_tracked_selection(
        PROFILE,
        manifest,
        policy_raw=policy_raw,
        policy_key="dashboard_authority_policy",
        authority_key="dashboard_authority",
        policy_schema=AUTHORITY_SCHEMA,
        policy_release_path=POLICY_RELEASE_PATH,
        require_finalized=False,
    )
    if manifest["state"] == "unfinalized":
        return authority
    _validate_dashboard_selection(manifest.get("dashboard"))
    return authority


def _reject_downstream(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in FORBIDDEN_RECEIPT_KEYS:
                _die(
                    "dashboard receipt contains forbidden downstream field "
                    + ".".join((*path, key))
                )
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
        _die("dashboard generator repository/ref differs")
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
        _die("dashboard receipt generator differs from derived source context")


DASHBOARD_DERIVED_CHECKS = {
    "advisory",
    "build",
    "bundle_tree",
    "inventory",
    "node",
    "offline_replay",
    "packaged_dist",
    "pnpm",
    "sbom",
    "source_projection",
    "store",
    "tree",
}
DASHBOARD_PLATFORM_SELECTION_KEYS = {
    "advisory_receipt_sha256",
    "advisory_receipt_size",
    "advisory_verdict",
    "build_receipt_sha256",
    "build_receipt_size",
    "bundle_tree_bytes",
    "bundle_tree_sha256",
    "inventory_entries",
    "inventory_sha256",
    "inventory_size",
    "pnpm_lock_sha256",
    "sbom_sha256",
    "sbom_size",
    "store_inventory_sha256",
    "store_inventory_size",
    "tree_bytes",
    "tree_sha256",
}


def _dashboard_execution_contracts(
    policy: Mapping[str, Any], policy_sha256: str
) -> dict[str, dict[str, Any]]:
    dashboard = policy["dashboard"]
    generator = dashboard["generator"]
    return {
        platform: {
            "build_args": {
                "NODE_IMAGE": dashboard["node"]["image"],
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


def _dashboard_build_environment(source_date_epoch: int) -> dict[str, str]:
    return {
        "CI": "true",
        "HOME": DASHBOARD_HOME,
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TZ": "UTC",
    }


def _dashboard_trivy_argv(kind: str) -> list[str]:
    prefix = [
        "/out/payload/evidence/trivy",
        "fs",
        "--cache-dir",
        "/out/payload/evidence/trivy-database",
        "--offline-scan",
        "--skip-db-update",
        "--scanners",
        "vuln",
        "--pkg-types",
        "library",
        "--list-all-pkgs",
        "--include-dev-deps",
        "--severity",
        "HIGH,CRITICAL",
        "--ignore-unfixed=false",
    ]
    output = (
        "/out/run-evidence/advisory-report.raw.json"
        if kind == "advisory"
        else "/out/run-evidence/sbom.raw.cyclonedx.json"
    )
    return [
        *prefix,
        "--format",
        "json" if kind == "advisory" else "cyclonedx",
        "--output",
        output,
        DASHBOARD_WORKSPACE,
    ]


def _pnpm_purl(name: str, version: str) -> str:
    return (
        "pkg:npm/" + urllib.parse.quote(name, safe="/") + "@" + urllib.parse.quote(version, safe="")
    )


def _trivy_pnpm_json_packages(
    value: Any,
    expected: Mapping[str, tuple[str, str]],
) -> list[dict[str, str]]:
    """Derive exact pnpm snapshot identities from pinned Trivy JSON."""

    report = common.exact_object(
        value,
        {
            "ArtifactName",
            "ArtifactType",
            "CreatedAt",
            "ReportID",
            "Results",
            "SchemaVersion",
            "Trivy",
        },
        "dashboard raw Trivy advisory report",
    )
    if report["SchemaVersion"] != 2 or not all(
        isinstance(report[key], str) and report[key]
        for key in ("ArtifactName", "ArtifactType", "CreatedAt", "ReportID", "Trivy")
    ):
        _die("dashboard raw Trivy advisory envelope differs")
    results = report["Results"]
    if not isinstance(results, list) or len(results) != 1:
        _die("dashboard raw Trivy advisory result set differs")
    result = common.exact_object(
        results[0], {"Class", "Packages", "Target", "Type"}, "dashboard raw Trivy result"
    )
    packages = result["Packages"]
    if (
        result["Class"] != "lang-pkgs"
        or result["Type"] != "pnpm"
        or result["Target"] != "pnpm-lock.yaml"
        or not isinstance(packages, list)
        or not packages
    ):
        _die("dashboard raw Trivy pnpm result identity differs")
    required = {"AnalyzedBy", "ID", "Identifier", "Name", "Relationship", "Version"}
    allowed = required | {"DependsOn", "Dev", "Indirect"}
    actual: dict[str, dict[str, str]] = {}
    for position, item in enumerate(packages):
        if not isinstance(item, dict) or not required <= set(item) <= allowed:
            _die(f"dashboard raw Trivy package {position} fields differ")
        package_id = item["ID"]
        name = item["Name"]
        version = item["Version"]
        identifier = common.exact_object(
            item["Identifier"], {"PURL", "UID"}, f"dashboard raw Trivy package {position} ID"
        )
        purl = (
            _pnpm_purl(name, version) if isinstance(name, str) and isinstance(version, str) else ""
        )
        if (
            not all(isinstance(child, str) and child for child in (package_id, name, version))
            or expected.get(package_id) != (name, version)
            or identifier["PURL"] != purl
            or not isinstance(identifier["UID"], str)
            or re.fullmatch(r"[0-9a-f]{16}", identifier["UID"]) is None
            or item["AnalyzedBy"] != "pnpm"
            or item["Relationship"] not in {"direct", "indirect"}
            or package_id in actual
        ):
            _die("dashboard raw Trivy package identity differs from pnpm-lock.yaml")
        if any(key in item and not isinstance(item[key], bool) for key in ("Dev", "Indirect")):
            _die("dashboard raw Trivy package relationship flags differ")
        dependencies = item.get("DependsOn", [])
        if (
            not isinstance(dependencies, list)
            or any(not isinstance(child, str) or not child for child in dependencies)
            or len(dependencies) != len(set(dependencies))
        ):
            _die("dashboard raw Trivy package dependency projection differs")
        actual[package_id] = {"id": package_id, "name": name, "purl": purl, "version": version}
    if set(actual) != set(expected):
        _die("dashboard raw Trivy package inventory differs from pnpm-lock.yaml")
    return [actual[key] for key in sorted(actual, key=str.encode)]


def _trivy_property(value: Any, *, name: str, context: str) -> str:
    properties = value
    if not isinstance(properties, list):
        _die(f"{context} properties differ")
    matches = []
    for position, raw_item in enumerate(properties):
        item = common.exact_object(raw_item, {"name", "value"}, f"{context} property {position}")
        if item["name"] == name:
            matches.append(item["value"])
    if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
        _die(f"{context} property {name} differs")
    return matches[0]


def _trivy_pnpm_cyclonedx_packages(
    value: Any,
    expected: Mapping[str, tuple[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Derive the same exact snapshot map from pinned Trivy CycloneDX."""

    sbom = common.exact_object(
        value,
        {
            "$schema",
            "bomFormat",
            "components",
            "dependencies",
            "metadata",
            "serialNumber",
            "specVersion",
            "version",
            "vulnerabilities",
        },
        "dashboard raw Trivy CycloneDX",
    )
    if (
        sbom["bomFormat"] != "CycloneDX"
        or sbom["specVersion"] != "1.7"
        or sbom["version"] != 1
        or sbom["$schema"] != "http://cyclonedx.org/schema/bom-1.7.schema.json"
        or not isinstance(sbom["serialNumber"], str)
        or not sbom["serialNumber"].startswith("urn:uuid:")
        or not isinstance(sbom["dependencies"], list)
        or sbom["vulnerabilities"] != []
    ):
        _die("dashboard raw Trivy CycloneDX envelope differs")
    metadata = common.exact_object(
        sbom["metadata"], {"component", "timestamp", "tools"}, "dashboard raw Trivy metadata"
    )
    if (
        not isinstance(metadata["timestamp"], str)
        or not metadata["timestamp"]
        or not isinstance(metadata["tools"], list)
        or not metadata["tools"]
        or not isinstance(metadata["component"], dict)
        or metadata["component"].get("type") != "application"
    ):
        _die("dashboard raw Trivy metadata differs")
    components = sbom["components"]
    if not isinstance(components, list) or len(components) != len(expected) + 1:
        _die("dashboard raw Trivy CycloneDX component count differs")
    actual: dict[str, dict[str, str]] = {}
    normalized: dict[str, dict[str, Any]] = {}
    application_count = 0
    references: set[str] = set()
    for position, item in enumerate(components):
        if not isinstance(item, dict):
            _die(f"dashboard raw Trivy component {position} differs")
        reference = item.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in references:
            _die("dashboard raw Trivy component reference differs or is duplicate")
        references.add(reference)
        if item.get("type") == "application":
            application = common.exact_object(
                item,
                {"bom-ref", "name", "properties", "type"},
                "dashboard raw Trivy application component",
            )
            if (
                application["name"] != "pnpm-lock.yaml"
                or not isinstance(application["properties"], list)
                or len(application["properties"]) != 2
                or _trivy_property(
                    application["properties"],
                    name="aquasecurity:trivy:Class",
                    context="dashboard raw Trivy application",
                )
                != "lang-pkgs"
                or _trivy_property(
                    application["properties"],
                    name="aquasecurity:trivy:Type",
                    context="dashboard raw Trivy application",
                )
                != "pnpm"
            ):
                _die("dashboard raw Trivy application component differs")
            application_count += 1
            continue
        keys = {"bom-ref", "name", "properties", "purl", "type", "version"}
        if "group" in item:
            keys.add("group")
        component = common.exact_object(item, keys, f"dashboard raw Trivy library {position}")
        group = component.get("group")
        leaf = component["name"]
        name = f"{group}/{leaf}" if group is not None else leaf
        version = component["version"]
        package_id = _trivy_property(
            component["properties"],
            name="aquasecurity:trivy:PkgID",
            context=f"dashboard raw Trivy library {position}",
        )
        package_type = _trivy_property(
            component["properties"],
            name="aquasecurity:trivy:PkgType",
            context=f"dashboard raw Trivy library {position}",
        )
        purl = (
            _pnpm_purl(name, version) if isinstance(name, str) and isinstance(version, str) else ""
        )
        if (
            component["type"] != "library"
            or not isinstance(component["properties"], list)
            or len(component["properties"]) != 2
            or not isinstance(leaf, str)
            or not leaf
            or (group is not None and (not isinstance(group, str) or not group.startswith("@")))
            or expected.get(package_id) != (name, version)
            or component["purl"] != purl
            or package_type != "pnpm"
            or package_id in actual
        ):
            _die("dashboard raw Trivy CycloneDX identity differs from pnpm-lock.yaml")
        record = {"id": package_id, "name": name, "purl": purl, "version": version}
        actual[package_id] = record
        normalized_component: dict[str, Any] = {
            "bom-ref": "urn:z4j:pnpm:" + common.sha256(package_id.encode("utf-8")),
            "name": leaf,
            "properties": [
                {"name": "aquasecurity:trivy:PkgID", "value": package_id},
                {"name": "aquasecurity:trivy:PkgType", "value": "pnpm"},
            ],
            "purl": purl,
            "type": "library",
            "version": version,
        }
        if group is not None:
            normalized_component["group"] = group
        normalized[package_id] = normalized_component
    if application_count != 1 or set(actual) != set(expected):
        _die("dashboard raw Trivy CycloneDX inventory differs from pnpm-lock.yaml")
    ordered = sorted(actual, key=str.encode)
    return [actual[key] for key in ordered], [normalized[key] for key in ordered]


def _validate_dashboard_run_evidence(
    root: Path,
    *,
    policy: Mapping[str, Any],
    expected_packages: Mapping[str, tuple[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    dashboard = policy["dashboard"]
    fetch, _fetch_raw = material_build.load_canonical_evidence(
        root,
        "acquisition/pnpm-fetch.json",
        context="dashboard pnpm fetch run evidence",
    )
    fetch = common.exact_object(
        fetch,
        {"argv", "cwd", "environment", "exit_code", "format", "stderr", "stdout"},
        "dashboard pnpm fetch run evidence",
    )
    if fetch["format"] != "z4j-production-dashboard-pnpm-fetch-run-evidence-v1":
        _die("dashboard pnpm fetch run-evidence format differs")
    material_build.validate_evidence_command(
        {key: item for key, item in fetch.items() if key != "format"},
        root / "acquisition",
        context="dashboard pnpm fetch command",
        expected_argv=[
            "node",
            "/acquired/bin/pnpm.cjs",
            "fetch",
            "--frozen-lockfile",
            "--store-dir",
            "/acquired/store",
        ],
        expected_cwd="/source/dashboard",
        expected_environment={
            "CI": "true",
            "LANG": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
    )

    builds, _builds_raw = material_build.load_canonical_evidence(
        root, "build-commands.json", context="dashboard build run evidence"
    )
    builds = common.exact_object(
        builds, {"commands", "format", "identity"}, "dashboard build run evidence"
    )
    if builds["format"] != "z4j-production-dashboard-build-run-evidence-v1" or builds[
        "identity"
    ] != {"gid": 65532, "uid": 65532}:
        _die("dashboard build run-evidence identity differs")
    commands = common.exact_object(
        builds["commands"], {"build", "install"}, "dashboard build commands"
    )
    environment = _dashboard_build_environment(dashboard["source_date_epoch"])
    for name in ("build", "install"):
        material_build.validate_evidence_command(
            commands[name],
            root,
            context=f"dashboard {name} command",
            expected_argv=dashboard["generator"]["commands"][name],
            expected_cwd=DASHBOARD_WORKSPACE,
            expected_environment=environment,
        )

    trivy, _trivy_raw = material_build.load_canonical_evidence(
        root, "trivy-commands.json", context="dashboard Trivy run evidence"
    )
    trivy = common.exact_object(trivy, {"commands", "format"}, "dashboard Trivy run evidence")
    if trivy["format"] != "z4j-production-dashboard-trivy-run-evidence-v1":
        _die("dashboard Trivy run-evidence format differs")
    commands = common.exact_object(
        trivy["commands"], {"advisory", "sbom"}, "dashboard Trivy commands"
    )
    scan_environment = {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "TZ": "UTC"}
    for name in ("advisory", "sbom"):
        material_build.validate_evidence_command(
            commands[name],
            root,
            context=f"dashboard Trivy {name} command",
            expected_argv=_dashboard_trivy_argv(name),
            expected_cwd="/authority",
            expected_environment=scan_environment,
            extra_file_keys=frozenset({"report"}),
        )
    advisory_raw = material_build.read_regular(
        root / commands["advisory"]["report"]["path"],
        maximum=MAX_TRIVY_REPORT_BYTES,
        context="dashboard raw Trivy advisory report",
    )
    advisory_value = common.parse_json(advisory_raw, context="dashboard raw Trivy advisory report")
    advisory_packages = _trivy_pnpm_json_packages(advisory_value, expected_packages)
    sbom_raw = material_build.read_regular(
        root / commands["sbom"]["report"]["path"],
        maximum=MAX_TRIVY_REPORT_BYTES,
        context="dashboard raw Trivy CycloneDX report",
    )
    sbom_value = common.parse_json(sbom_raw, context="dashboard raw Trivy CycloneDX report")
    sbom_packages, normalized_components = _trivy_pnpm_cyclonedx_packages(
        sbom_value, expected_packages
    )
    if advisory_packages != sbom_packages:
        _die("dashboard raw Trivy JSON and CycloneDX package identities differ")
    return advisory_packages, normalized_components


def _dashboard_dist_tree(payload: Path, dashboard: Mapping[str, Any]) -> dict[str, Any]:
    records = material_build.file_records(payload / "dist", exclude=frozenset())
    if not records:
        _die("dashboard dist tree is empty")
    records = [{**record, "path": "dist/" + record["path"]} for record in records]
    build_context = material_build.read_regular(
        payload / "dist/.build-context", maximum=64, context="dashboard build-context marker"
    )
    build_inputs = material_build.read_regular(
        payload / "dist/.build-inputs.sha256",
        maximum=66,
        context="dashboard build-input marker",
    )
    build_output = material_build.read_regular(
        payload / "dist/.build-output.sha256",
        maximum=66,
        context="dashboard build-output marker",
    )
    marker_lines = b"".join(
        f"{record['sha256']}  {record['path'].removeprefix('dist/')}\n".encode("ascii")
        for record in records
        if record["path"] not in {"dist/.build-inputs.sha256", "dist/.build-output.sha256"}
    )
    if (
        build_context != b"z4j-dashboard-production-v1\n"
        or build_inputs != (dashboard["source_projection"]["sha256"] + "\n").encode("ascii")
        or build_output != (common.sha256(marker_lines) + "\n").encode("ascii")
    ):
        _die("dashboard deterministic build markers differ")
    framing = {"files": records, "format": dashboard["bundle_tree_format"]}
    return {
        "bundle_tree_bytes": sum(item["size"] for item in records),
        "bundle_tree_sha256": common.sha256(common.canonical_json(framing, terminal_lf=False)),
    }


def _validate_dashboard_pnpm(
    payload: Path, dashboard: Mapping[str, Any]
) -> tuple[str, list[dict[str, Any]]]:
    pnpm = dashboard["pnpm"]
    lock_raw = material_build.read_regular(
        payload / "evidence/pnpm-lock.yaml",
        maximum=material_build.MAX_FILE_BYTES,
        context="dashboard pnpm lock",
    )
    archive_raw = material_build.read_regular(
        payload / "evidence/pnpm-archive.tgz",
        maximum=material_build.MAX_FILE_BYTES,
        context="dashboard pnpm archive",
    )
    if (
        common.sha256(archive_raw) != pnpm["archive_sha256"]
        or len(archive_raw) != pnpm["archive_size"]
        or material_build.evidence_file_seal(
            payload, "bin/pnpm.cjs", context="dashboard retained pnpm binary"
        )
        != {"sha256": pnpm["binary_sha256"], "size": pnpm["binary_size"]}
    ):
        _die("dashboard retained pnpm authority differs")
    members = material_build.tar_member_records(archive_raw, context="dashboard pnpm archive")
    members_raw = common.canonical_json(
        {"files": members, "format": "z4j-production-tar-members-v1"}, terminal_lf=False
    )
    if (
        len(members) != pnpm["archive_members_entries"]
        or sum(item["size"] for item in members) != pnpm["archive_members_bytes"]
        or common.sha256(members_raw) != pnpm["archive_members_sha256"]
    ):
        _die("dashboard pnpm archive semantic authority differs")
    release, release_raw = material_build.load_canonical_evidence(
        payload, "evidence/pnpm-release.json", context="dashboard pnpm release receipt"
    )
    release = common.exact_object(
        release,
        {
            "archive_members_bytes",
            "archive_members_entries",
            "archive_members_sha256",
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "filename",
            "format",
            "published_at_utc",
            "registry_response",
            "url",
            "version",
        },
        "dashboard pnpm release receipt",
    )
    expected_release = {
        **{
            key: pnpm[key]
            for key in pnpm
            if key
            not in {
                "registry_packument",
                "registry_sha256",
                "registry_size",
                "release_receipt_format",
                "tarball",
            }
        },
        "filename": f"pnpm-{pnpm['version']}.tgz",
        "format": pnpm["release_receipt_format"],
        "registry_response": {
            "path": "evidence/pnpm-registry.json",
            "sha256": pnpm["registry_sha256"],
            "size": pnpm["registry_size"],
        },
        "url": pnpm["tarball"],
    }
    if release != expected_release or material_build.evidence_file_seal(
        payload,
        "evidence/pnpm-registry.json",
        context="dashboard pnpm registry response",
    ) != {"sha256": pnpm["registry_sha256"], "size": pnpm["registry_size"]}:
        _die("dashboard pnpm release receipt differs from policy/payload")
    if not release_raw:
        _die("dashboard pnpm release receipt is empty")
    return common.sha256(lock_raw), material_build.pnpm_lock_components(lock_raw)


def _validate_dashboard_store(
    payload: Path,
    *,
    platform: str,
    dashboard: Mapping[str, Any],
    expected_universe: list[dict[str, Any]],
) -> tuple[dict[str, Any], bytes]:
    store, store_raw = material_build.load_canonical_evidence(
        payload, "evidence/store-inventory.json", context=f"dashboard {platform} store inventory"
    )
    store = common.exact_object(
        store,
        {
            "format",
            "installed",
            "lock_universe",
            "native_realization",
            "platform",
            "store_format",
            "store_tree_bytes",
            "store_tree_sha256",
        },
        f"dashboard {platform} store inventory",
    )
    if (
        store["format"] != dashboard["store_inventory_format"]
        or store["platform"] != platform
        or store["store_format"] != "pnpm-content-addressable-store-v10"
        or not all(
            isinstance(store[key], list) and store[key]
            for key in ("installed", "lock_universe", "native_realization")
        )
    ):
        _die(f"dashboard {platform} store inventory identity differs or is empty")
    store_records = material_build.file_records(payload / "store", exclude=frozenset())
    framing = {"files": store_records, "format": dashboard["store_tree_format"]}
    if (
        not store_records
        or store["store_tree_bytes"] != sum(item["size"] for item in store_records)
        or store["store_tree_sha256"]
        != common.sha256(common.canonical_json(framing, terminal_lf=False))
    ):
        _die(f"dashboard {platform} retained store tree differs")
    universe = store["lock_universe"]
    native = store["native_realization"]
    component_keys = {
        "cpu",
        "dependencies",
        "integrity_sha512",
        "key",
        "libc",
        "name",
        "optional",
        "optional_dependencies",
        "os",
        "package_key",
        "root_groups",
        "transitive_peer_dependencies",
        "version",
    }
    universe = [
        common.exact_object(item, component_keys, f"dashboard {platform} lock component")
        for item in universe
    ]
    if any(
        not all(isinstance(item[key], str) and item[key] for key in ("key", "name", "version"))
        or not isinstance(item["optional"], bool)
        or not isinstance(item["integrity_sha512"], str)
        or not item["integrity_sha512"].startswith("sha512-")
        or not all(
            isinstance(item[key], list)
            for key in (
                "dependencies",
                "optional_dependencies",
                "root_groups",
                "transitive_peer_dependencies",
            )
        )
        for item in universe
    ):
        _die(f"dashboard {platform} lock universe differs")
    if universe != expected_universe:
        _die(f"dashboard {platform} lock universe differs from pnpm-lock.yaml")
    universe_by_key = {item["key"]: item for item in universe}
    if len(universe_by_key) != len(universe) or list(universe_by_key) != sorted(
        universe_by_key, key=str.encode
    ):
        _die(f"dashboard {platform} lock universe is duplicate or unsorted")
    expected_native = material_build.pnpm_platform_components(expected_universe, platform)
    if native != expected_native or any(
        not isinstance(item, dict) or universe_by_key.get(item.get("key")) != item
        for item in native
    ):
        _die(f"dashboard {platform} native realization differs from lock universe")
    installed = [
        common.exact_object(
            item,
            {"instance", "name", "snapshot_key", "version"},
            f"dashboard {platform} installed component",
        )
        for item in store["installed"]
    ]
    if any(not all(isinstance(item[key], str) and item[key] for key in item) for item in installed):
        _die(f"dashboard {platform} installed component identity differs")
    ordering = [
        (
            item["name"].encode(),
            item["version"].encode(),
            item["snapshot_key"].encode(),
            item["instance"].encode(),
        )
        for item in installed
    ]
    expected_instances = sorted(
        (item.get("name"), item.get("version"), item.get("key")) for item in native
    )
    observed_instances = sorted(
        (item["name"], item["version"], item["snapshot_key"]) for item in installed
    )
    if (
        ordering != sorted(ordering)
        or len({item["instance"] for item in installed}) != len(installed)
        or len({item["snapshot_key"] for item in installed}) != len(installed)
        or observed_instances != expected_instances
    ):
        _die(f"dashboard {platform} installed/native realization differs")
    return store, store_raw


def _dashboard_scanned_components(
    sbom: Mapping[str, Any],
    bundle_sha256: str,
    expected: Mapping[str, tuple[str, str]],
) -> list[dict[str, str]]:
    subject = common.exact_object(
        common.exact_object(sbom["metadata"], {"component"}, "dashboard SBOM metadata")[
            "component"
        ],
        {"hashes", "name", "type", "version"},
        "dashboard SBOM subject",
    )
    if subject != {
        "hashes": [{"alg": "SHA-256", "content": bundle_sha256}],
        "name": "z4j-dashboard",
        "type": "application",
        "version": RELEASE,
    }:
        _die("dashboard SBOM subject differs from derived bundle")
    components = sbom["components"]
    if not isinstance(components, list) or not components:
        _die("dashboard SBOM components are empty")
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for position, value in enumerate(components):
        if not isinstance(value, dict):
            _die("dashboard SBOM component differs")
        keys = {"bom-ref", "name", "properties", "purl", "type", "version"}
        if "group" in value:
            keys.add("group")
        component = common.exact_object(value, keys, "dashboard SBOM component")
        group = component.get("group")
        name = f"{group}/{component['name']}" if group is not None else component["name"]
        package_id = _trivy_property(
            component["properties"],
            name="aquasecurity:trivy:PkgID",
            context=f"dashboard SBOM component {position}",
        )
        package_type = _trivy_property(
            component["properties"],
            name="aquasecurity:trivy:PkgType",
            context=f"dashboard SBOM component {position}",
        )
        purl = (
            _pnpm_purl(name, component["version"])
            if isinstance(name, str) and isinstance(component["version"], str)
            else ""
        )
        if (
            component["type"] != "library"
            or not isinstance(component["properties"], list)
            or len(component["properties"]) != 2
            or not isinstance(component["name"], str)
            or not component["name"]
            or (group is not None and (not isinstance(group, str) or not group.startswith("@")))
            or expected.get(package_id) != (name, component["version"])
            or component["purl"] != purl
            or package_type != "pnpm"
            or component["bom-ref"] != "urn:z4j:pnpm:" + common.sha256(package_id.encode("utf-8"))
            or package_id in seen
        ):
            _die("dashboard SBOM component differs")
        seen.add(package_id)
        packages.append(
            {"id": package_id, "name": name, "purl": purl, "version": component["version"]}
        )
    if set(seen) != set(expected) or packages != sorted(
        packages, key=lambda item: item["id"].encode()
    ):
        _die("dashboard SBOM package inventory differs from pnpm-lock.yaml")
    return packages


def _derive_dashboard_platform_build(
    root: Path,
    *,
    platform: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    dashboard = policy["dashboard"]
    payload = root / "payload"
    inventory = material_build.derive_payload_inventory(
        payload,
        platform=platform,
        inventory_format=dashboard["inventory_format"],
        tree_format=dashboard["tree_format"],
    )
    records = material_build.file_records(payload)
    allowed_direct = {
        "bin/pnpm.cjs",
        "evidence/advisory-receipt.json",
        "evidence/advisory-report.json",
        "evidence/build-receipt.json",
        "evidence/pnpm-archive.tgz",
        "evidence/pnpm-lock.yaml",
        "evidence/pnpm-registry.json",
        "evidence/pnpm-release.json",
        "evidence/sbom.cyclonedx.json",
        "evidence/store-inventory.json",
        "evidence/trivy",
        "evidence/trivy-version.txt",
    }
    if any(
        record["path"] not in allowed_direct
        and not record["path"].startswith(("dist/", "store/", "evidence/trivy-database/"))
        for record in records
    ):
        _die(f"dashboard {platform} payload contains an unreviewed path")
    dist = _dashboard_dist_tree(payload, dashboard)
    lock_sha256, lock_universe = _validate_dashboard_pnpm(payload, dashboard)
    expected_scan = {item["key"]: (item["name"], item["version"]) for item in lock_universe}
    if len(expected_scan) != len(lock_universe):
        _die(f"dashboard {platform} pnpm lock contains duplicate snapshot identities")
    _store, store_raw = _validate_dashboard_store(
        payload,
        platform=platform,
        dashboard=dashboard,
        expected_universe=lock_universe,
    )
    raw_packages, raw_components = _validate_dashboard_run_evidence(
        root / "run-evidence", policy=policy, expected_packages=expected_scan
    )
    build, build_raw = material_build.load_canonical_evidence(
        payload, "evidence/build-receipt.json", context=f"dashboard {platform} build receipt"
    )
    expected_build = {
        "bundle_tree_sha256": dist["bundle_tree_sha256"],
        "commands": dashboard["generator"]["commands"],
        "environment": _dashboard_build_environment(dashboard["source_date_epoch"]),
        "execution_identity": {"gid": 65532, "uid": 65532},
        "exit_code": 0,
        "format": dashboard["build_receipt_format"],
        "node_config_digest": dashboard["node"]["platforms"][platform]["config_digest"],
        "node_image": dashboard["node"]["image"],
        "node_manifest_digest": dashboard["node"]["platforms"][platform]["manifest_digest"],
        "platform": platform,
        "pnpm_binary_sha256": dashboard["pnpm"]["binary_sha256"],
        "pnpm_lock_sha256": lock_sha256,
        "run_evidence_format": "z4j-production-dashboard-build-run-evidence-v1",
        "source_projection_sha256": dashboard["source_projection"]["sha256"],
        "store_inventory_sha256": common.sha256(store_raw),
        "working_directory": DASHBOARD_WORKSPACE,
    }
    if build != expected_build:
        _die(f"dashboard {platform} build receipt differs from derived material")

    sbom, sbom_raw = material_build.load_canonical_evidence(
        payload, "evidence/sbom.cyclonedx.json", context=f"dashboard {platform} SBOM"
    )
    sbom = common.exact_object(
        sbom,
        {"bomFormat", "components", "metadata", "specVersion", "version"},
        f"dashboard {platform} SBOM",
    )
    if sbom["bomFormat"] != "CycloneDX" or sbom["specVersion"] != "1.6" or sbom["version"] != 1:
        _die(f"dashboard {platform} SBOM schema differs")
    scanned_packages = _dashboard_scanned_components(
        sbom, dist["bundle_tree_sha256"], expected_scan
    )
    if scanned_packages != raw_packages or sbom["components"] != raw_components:
        _die(f"dashboard {platform} normalized SBOM differs from raw Trivy evidence")

    advisory, advisory_raw = material_build.load_canonical_evidence(
        payload,
        "evidence/advisory-receipt.json",
        context=f"dashboard {platform} advisory receipt",
    )
    advisory = common.exact_object(
        advisory,
        {
            "components_sha256",
            "database",
            "findings",
            "format",
            "platform",
            "policy",
            "report",
            "run_evidence_format",
            "scanner",
            "subject_tree_sha256",
            "verdict",
        },
        f"dashboard {platform} advisory receipt",
    )
    native_trivy = dashboard["generator"]["trivy"]["platforms"][platform]
    expected_scanner = {
        "binary_sha256": native_trivy["binary"]["sha256"],
        "name": "trivy",
        "version": dashboard["generator"]["trivy"]["version"],
        "version_output_sha256": native_trivy["version_output_sha256"],
    }
    if (
        advisory["components_sha256"]
        != common.sha256(
            common.canonical_json(
                [
                    [item["id"], item["name"], item["version"], item["purl"]]
                    for item in scanned_packages
                ],
                terminal_lf=False,
            )
        )
        or advisory["database"] != dashboard["generator"]["trivy"]["database"]
        or advisory["findings"] != []
        or advisory["format"] != dashboard["advisory_receipt_format"]
        or advisory["platform"] != platform
        or advisory["policy"]
        != {
            "ignore_unfixed": False,
            "list_all_packages": True,
            "required_result_type": "pnpm",
            "severities": ["HIGH", "CRITICAL"],
        }
        or advisory["run_evidence_format"] != "z4j-production-dashboard-trivy-run-evidence-v1"
        or advisory["scanner"] != expected_scanner
        or advisory["subject_tree_sha256"] != dist["bundle_tree_sha256"]
        or advisory["verdict"] != "pass"
    ):
        _die(f"dashboard {platform} advisory receipt differs")
    report = common.exact_object(
        advisory["report"], {"path", "sha256", "size"}, f"dashboard {platform} advisory report"
    )
    if report["path"] != "evidence/advisory-report.json" or material_build.evidence_file_seal(
        payload, report["path"], context=f"dashboard {platform} advisory report"
    ) != {"sha256": report["sha256"], "size": report["size"]}:
        _die(f"dashboard {platform} advisory report seal differs")
    semantic, _semantic_raw = material_build.load_canonical_evidence(
        payload, report["path"], context=f"dashboard {platform} semantic advisory report"
    )
    if semantic != {
        "findings": [],
        "format": "z4j-production-dashboard-trivy-semantic-report-v2",
        "packages": scanned_packages,
        "platform": platform,
        "result_type": "pnpm",
    }:
        _die(f"dashboard {platform} semantic advisory report differs")
    trivy_binary = material_build.evidence_file_seal(
        payload, "evidence/trivy", context=f"dashboard {platform} Trivy binary"
    )
    version_seal = material_build.evidence_file_seal(
        payload, "evidence/trivy-version.txt", context=f"dashboard {platform} Trivy version"
    )
    database_records = material_build.file_records(
        payload / "evidence/trivy-database", exclude=frozenset()
    )
    database_framing = {"files": database_records, "format": "z4j-trivy-database-tree-v1"}
    if (
        trivy_binary != native_trivy["binary"]
        or version_seal["sha256"] != native_trivy["version_output_sha256"]
        or version_seal["size"] <= 0
        or common.sha256(common.canonical_json(database_framing, terminal_lf=False))
        != advisory["database"]["tree_sha256"]
        or material_build.evidence_file_seal(
            payload,
            "evidence/trivy-database/db/metadata.json",
            context=f"dashboard {platform} Trivy database metadata",
        )["sha256"]
        != advisory["database"]["metadata_sha256"]
    ):
        _die(f"dashboard {platform} retained Trivy authority differs")
    return {
        "checks": dict.fromkeys(DASHBOARD_DERIVED_CHECKS, True),
        "payload": inventory,
        "selection": {
            "advisory_receipt_sha256": common.sha256(advisory_raw),
            "advisory_receipt_size": len(advisory_raw),
            "advisory_verdict": "pass",
            "build_receipt_sha256": common.sha256(build_raw),
            "build_receipt_size": len(build_raw),
            **dist,
            **inventory,
            "pnpm_lock_sha256": lock_sha256,
            "sbom_sha256": common.sha256(sbom_raw),
            "sbom_size": len(sbom_raw),
            "store_inventory_sha256": common.sha256(store_raw),
            "store_inventory_size": len(store_raw),
        },
    }


def aggregate_dashboard_platform_results(
    inputs: Mapping[str, Mapping[str, Path]],
    destination: Path,
    *,
    policy_raw: bytes,
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive exact dashboard material claims from two safely extracted native carriers."""

    policy = common.parse_json(policy_raw, context="dashboard aggregation policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("dashboard aggregation policy is not canonical")
    poison = [
        item for item in validate_policy(policy) if item.startswith(("dashboard", "generator "))
    ]
    if poison:
        _die("dashboard material inputs are UNFINALIZED: " + "; ".join(poison))
    policy_sha256 = common.sha256(policy_raw)
    carrier = material_build.aggregate_platform_result_carriers(
        inputs,
        destination,
        material="dashboard",
        expected_policy_sha256=policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=_dashboard_execution_contracts(policy, policy_sha256),
    )
    platforms: dict[str, Any] = {}
    for platform, architecture in ARCHITECTURES.items():
        builds = [
            {
                "id": build_id,
                **_derive_dashboard_platform_build(
                    destination / architecture / build_id,
                    platform=platform,
                    policy=policy,
                ),
            }
            for build_id in ("A", "B")
        ]
        derived = [{key: item for key, item in build.items() if key != "id"} for build in builds]
        if derived[0] != derived[1]:
            _die(f"dashboard {platform} derived A/B material differs")
        platforms[platform] = {"builds": builds, **derived[0]}
    return {
        "carrier_aggregation": carrier,
        "format": "z4j-production-dashboard-derived-platform-aggregation-v1",
        "material": "dashboard",
        "platforms": platforms,
        "policy_sha256": policy_sha256,
        "run": carrier["run"],
        "selected_build": "A",
        "source_context": carrier["source_context"],
    }


def validate_dashboard_platform_aggregation(
    value: Any,
    *,
    policy_raw: bytes,
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate one previously derived dual-platform dashboard aggregation."""

    policy = common.parse_json(policy_raw, context="dashboard aggregation policy")
    if common.canonical_json(policy, terminal_lf=True) != policy_raw:
        _die("dashboard aggregation policy is not canonical")
    poison = [
        item for item in validate_policy(policy) if item.startswith(("dashboard", "generator "))
    ]
    if poison:
        _die("dashboard material inputs are UNFINALIZED: " + "; ".join(poison))
    policy_sha256 = common.sha256(policy_raw)
    wrapper = material_build.validate_derived_platform_aggregation(
        value,
        material="dashboard",
        expected_policy_sha256=policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=_dashboard_execution_contracts(policy, policy_sha256),
        derived_checks=frozenset(DASHBOARD_DERIVED_CHECKS),
        selection_keys=frozenset(DASHBOARD_PLATFORM_SELECTION_KEYS),
    )
    shared_bundle: tuple[str, int] | None = None
    shared_lock: str | None = None
    for platform in PLATFORMS:
        selection = wrapper["platforms"][platform]["selection"]
        for key in (
            "advisory_receipt_sha256",
            "build_receipt_sha256",
            "bundle_tree_sha256",
            "pnpm_lock_sha256",
            "sbom_sha256",
            "store_inventory_sha256",
        ):
            common.hex64(selection[key], f"derived dashboard {platform} {key}")
        for key in (
            "advisory_receipt_size",
            "build_receipt_size",
            "bundle_tree_bytes",
            "sbom_size",
            "store_inventory_size",
        ):
            common.positive_int(selection[key], f"derived dashboard {platform} {key}")
        if selection["advisory_verdict"] != "pass":
            _die(f"derived dashboard {platform} advisory verdict differs")
        bundle = (selection["bundle_tree_sha256"], selection["bundle_tree_bytes"])
        if shared_bundle is None:
            shared_bundle = bundle
            shared_lock = selection["pnpm_lock_sha256"]
        elif bundle != shared_bundle or selection["pnpm_lock_sha256"] != shared_lock:
            _die("derived dashboard platform dist trees or pnpm locks differ")
    return wrapper


def _validate_node_readback(value: Any, dashboard: Mapping[str, Any]) -> dict[str, Any]:
    node = common.exact_object(value, {"index_by_digest", "platforms"}, "readback.node")
    response, index_raw = common.validate_oci_manifest_response(
        node["index_by_digest"], "readback.node.index"
    )
    expected_digest = dashboard["node"]["index_digest"]
    expected_size = dashboard["node"]["index_size"]
    if (
        response["docker_content_digest"] != expected_digest
        or common.digest(index_raw) != expected_digest
        or len(index_raw) != expected_size
    ):
        _die("dashboard Node index raw readback differs")
    platforms = common.exact_object(node["platforms"], set(PLATFORMS), "readback.node.platforms")
    for platform in PLATFORMS:
        item = common.exact_object(
            platforms[platform], {"config", "manifest"}, f"readback.node.{platform}"
        )
        manifest_response, manifest_raw = common.validate_oci_manifest_response(
            item["manifest"], f"readback.node.{platform}.manifest"
        )
        config_response, config_raw = common.validate_oci_manifest_response(
            item["config"], f"readback.node.{platform}.config"
        )
        expected = dashboard["node"]["platforms"][platform]
        if (
            manifest_response["docker_content_digest"] != expected["manifest_digest"]
            or common.digest(manifest_raw) != expected["manifest_digest"]
            or len(manifest_raw) != expected["manifest_size"]
            or config_response["docker_content_digest"] != expected["config_digest"]
            or common.digest(config_raw) != expected["config_digest"]
            or len(config_raw) != expected["config_size"]
        ):
            _die(f"dashboard Node {platform} manifest/config readback differs")
    return node


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
            "bundle_tree_byte_identical",
            "index_canonical",
            "native_platforms",
            "pnpm_lock_byte_identical",
            "policy_sha256",
            "referrers_native",
        },
        "verification.aggregate",
    )
    if aggregate != {
        "all_platforms_passed": True,
        "builds_byte_identical": True,
        "bundle_tree_byte_identical": True,
        "index_canonical": True,
        "native_platforms": True,
        "pnpm_lock_byte_identical": True,
        "policy_sha256": policy_sha256,
        "referrers_native": True,
    }:
        _die("dashboard aggregate verification differs")
    checks = {
        "advisory",
        "build",
        "bundle_tree",
        "inventory",
        "node",
        "oci",
        "offline_replay",
        "packaged_dist",
        "pnpm",
        "sbom",
        "source_projection",
        "store",
        "tree",
    }
    platforms = common.exact_object(
        verification["platforms"], set(PLATFORMS), "verification.platforms"
    )
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
            or {key: receipt_checks[key] for key in DASHBOARD_DERIVED_CHECKS} != derived["checks"]
        ):
            _die(f"{platform} dashboard checks did not all pass")
        job = common.exact_object(
            item["job"],
            {"id", "name", "runner_arch", "runner_name", "runner_os"},
            f"{platform} job",
        )
        common.positive_int(job["id"], f"{platform} job ID")
        common.ascii_text(job["name"], f"{platform} job name")
        common.ascii_text(job["runner_name"], f"{platform} runner name")
        expected_arch = "X64" if platform.endswith("amd64") else "ARM64"
        if (
            job["runner_arch"] != expected_arch
            or job["runner_os"] != "Linux"
            or item["selected_build"] != platform_aggregation["selected_build"]
        ):
            _die(f"{platform} native runner/selected build differs")
        if job != identity["job"]:
            _die(f"{platform} receipt job differs from authenticated aggregation")
    return verification


def validate_receipt(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    policy_raw: bytes,
    platform_aggregation: Mapping[str, Any],
    expected_identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate the closed pre-U0 dashboard receipt and common trust evidence."""

    receipt = common.exact_object(
        value,
        {
            "ceremony",
            "contract",
            "dashboard",
            "format",
            "protection",
            "readback",
            "release",
            "repository",
            "result",
            "source",
            "transition",
            "verification",
        },
        "dashboard authority receipt",
    )
    _reject_downstream(receipt)
    if (
        receipt["format"] != AUTHORITY_FORMAT
        or receipt["release"] != RELEASE
        or receipt["repository"] != REPOSITORY
        or receipt["result"] != "pass"
    ):
        _die("dashboard receipt identity/result differs")
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
        _die("dashboard receipt contract seal differs")
    policy = common.parse_json(policy_raw, context="dashboard receipt policy")
    validate_policy(policy)
    derived = validate_dashboard_platform_aggregation(
        platform_aggregation,
        policy_raw=policy_raw,
        expected_identities=expected_identities,
    )
    source = common.exact_object(
        receipt["source"], {"generator", "source_date_epoch"}, "receipt.source"
    )
    generator = _validate_generator(source["generator"])
    _cross_check_generator_source_context(generator, derived)
    epoch = common.positive_int(source["source_date_epoch"], "receipt SOURCE_DATE_EPOCH")
    if (
        epoch != policy["dashboard"]["source_date_epoch"]
        or epoch != manifest["install"]["source_date_epoch"]
    ):
        _die("dashboard SOURCE_DATE_EPOCH selection differs")
    if receipt["dashboard"] != manifest["dashboard"]:
        _die("signed dashboard selection differs from the tracked manifest")
    dashboard = _validate_dashboard_selection(receipt["dashboard"])
    for platform in PLATFORMS:
        material = dashboard["platforms"][platform]
        if {key: material[key] for key in DASHBOARD_PLATFORM_SELECTION_KEYS} != derived[
            "platforms"
        ][platform]["selection"]:
            _die(f"signed dashboard {platform} material differs from derived aggregation")
    index = common.exact_object(dashboard["index"], {"digest", "size"}, "dashboard receipt index")
    subject = common.oci_digest(index["digest"], "dashboard receipt subject")
    subject_size = common.positive_int(index["size"], "dashboard receipt subject size")
    ceremony = common.validate_ceremony(
        PROFILE,
        receipt["ceremony"],
        generator_commit=generator["commit"],
        expected_workflow_id=policy["github"]["workflow"]["id"],
        expected_workflow_node_id=policy["github"]["workflow"]["node_id"],
    )
    if {"attempt": ceremony["run_attempt"], "id": ceremony["run_id"]} != derived["run"]:
        _die("dashboard ceremony run differs from platform aggregation")
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
    readback = common.validate_readback(
        PROFILE,
        receipt["readback"],
        subject_digest=subject,
        subject_size=subject_size,
        transition_kind=transition["kind"],
        extra_top_keys=frozenset({"node"}),
    )
    _validate_node_readback(readback["node"], dashboard)
    _validate_verification(
        receipt["verification"],
        policy_sha256=common.sha256(policy_raw),
        platform_aggregation=derived,
    )
    return receipt


def validate_subject_index(raw: bytes, dashboard: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        platform: {
            "digest": dashboard["platforms"][platform]["manifest_digest"],
            "size": dashboard["platforms"][platform]["manifest_size"],
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


def _validate_transition_authority(value: Any) -> dict[str, Any]:
    authority = common.exact_object(
        value, {"artifact", "bundle_tree", "repository", "subject"}, "transition authority"
    )
    if authority["repository"] != REPOSITORY:
        _die("dashboard transition authority repository differs")
    subject = common.exact_object(
        authority["subject"], {"digest", "size", "tag"}, "transition authority subject"
    )
    subject_digest = common.oci_digest(subject["digest"], "transition subject digest")
    common.positive_int(subject["size"], "transition subject size")
    common.validate_derived_tag(PROFILE, subject["tag"], subject_digest, authority=False)
    artifact = common.exact_object(
        authority["artifact"], {"digest", "size", "tag"}, "transition authority artifact"
    )
    artifact_digest = common.oci_digest(artifact["digest"], "transition artifact digest")
    common.positive_int(artifact["size"], "transition artifact size")
    common.validate_derived_tag(PROFILE, artifact["tag"], artifact_digest, authority=True)
    bundle_tree = common.exact_object(
        authority["bundle_tree"], {"bytes", "sha256"}, "transition dashboard bundle tree"
    )
    common.positive_int(bundle_tree["bytes"], "transition dashboard bundle tree bytes")
    common.hex64(bundle_tree["sha256"], "transition dashboard bundle tree SHA-256")
    return authority


def _validate_git_identity(value: Any, context: str) -> dict[str, Any]:
    identity = common.exact_object(value, {"email", "name", "timestamp"}, context)
    for key in ("email", "name"):
        text = identity[key]
        if (
            not isinstance(text, str)
            or not text
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in text)
            or any(character in "<>" for character in text)
        ):
            _die(f"{context}.{key} must be nonempty printable ASCII")
    email = identity["email"]
    common.timestamp(identity["timestamp"], f"{context}.timestamp")
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        _die(f"{context}.email is malformed")
    return identity


def _git_object_id(kind: str, raw: bytes) -> str:
    """Return the Git SHA-1 object ID over exact, length-framed object bytes."""

    if kind not in {"blob", "commit", "tree"}:
        _die("Git object type differs")
    framed = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest()


def _validate_raw_git_object(
    value: Any, *, kind: str, context: str
) -> tuple[dict[str, Any], bytes]:
    record = common.exact_object(
        value,
        {"body_base64", "sha", "sha256", "size"},
        context,
    )
    sha = common.git_sha(record["sha"], f"{context}.sha")
    body_sha256 = common.hex64(record["sha256"], f"{context}.sha256")
    size = common.nonnegative_int(record["size"], f"{context}.size")
    raw = common.base64_bytes(record["body_base64"], f"{context}.body_base64", allow_empty=True)
    if len(raw) != size or common.sha256(raw) != body_sha256:
        _die(f"{context} body seal differs")
    if _git_object_id(kind, raw) != sha:
        _die(f"{context} Git object ID differs")
    return record, raw


def _git_tree_sort_key(name: bytes, *, is_tree: bool) -> bytes:
    return name + (b"/" if is_tree else b"\0")


def _parse_git_tree(raw: bytes, *, context: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    offset = 0
    previous: bytes | None = None
    seen: set[str] = set()
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\0", space + 1) if space >= 0 else -1
        if space <= offset or nul <= space + 1 or nul + 21 > len(raw):
            _die(f"{context} Git tree framing differs")
        mode_raw = raw[offset:space]
        name_raw = raw[space + 1 : nul]
        object_raw = raw[nul + 1 : nul + 21]
        offset = nul + 21
        try:
            mode = mode_raw.decode("ascii")
            name = name_raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise DashboardAuthorityError(f"{context} Git tree text differs") from exc
        if (
            mode not in {"100644", "100755", "120000", "160000", "40000"}
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
            or name in seen
        ):
            _die(f"{context} Git tree entry differs")
        entry_type = "tree" if mode == "40000" else "commit" if mode == "160000" else "blob"
        sort_key = _git_tree_sort_key(name_raw, is_tree=entry_type == "tree")
        if previous is not None and sort_key <= previous:
            _die(f"{context} Git tree order differs")
        previous = sort_key
        seen.add(name)
        entries.append(
            {
                "mode": mode,
                "name": name,
                "sha": object_raw.hex(),
                "type": entry_type,
            }
        )
    if not entries:
        _die(f"{context} Git tree is empty")
    return entries


def _flatten_git_tree(
    root_sha: str,
    trees: Mapping[str, list[dict[str, str]]],
    *,
    context: str,
) -> tuple[dict[str, dict[str, str]], set[str]]:
    leaves: dict[str, dict[str, str]] = {}
    reachable: set[str] = set()
    active: set[str] = set()

    def visit(tree_sha: str, prefix: PurePosixPath) -> None:
        if tree_sha in active:
            _die(f"{context} Git tree graph contains a cycle")
        entries = trees.get(tree_sha)
        if entries is None:
            _die(f"{context} Git tree graph is incomplete")
        active.add(tree_sha)
        reachable.add(tree_sha)
        for entry in entries:
            path = prefix / entry["name"]
            logical = path.as_posix()
            if entry["type"] == "tree":
                visit(entry["sha"], path)
            else:
                if logical in leaves:
                    _die(f"{context} Git tree graph has a duplicate path")
                leaves[logical] = {
                    "mode": entry["mode"],
                    "sha": entry["sha"],
                    "type": entry["type"],
                }
        active.remove(tree_sha)

    visit(root_sha, PurePosixPath())
    return leaves, reachable


def _old_commit_tree(raw: bytes, *, context: str) -> str:
    if b"\0" in raw or b"\r" in raw or b"\n\n" not in raw:
        _die(f"{context} Git commit framing differs")
    header, _message = raw.split(b"\n\n", 1)
    lines = header.split(b"\n")
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    if len(tree_lines) != 1:
        _die(f"{context} Git commit tree header differs")
    try:
        tree = tree_lines[0].removeprefix(b"tree ").decode("ascii")
    except UnicodeDecodeError as exc:
        raise DashboardAuthorityError(f"{context} Git commit tree differs") from exc
    return common.git_sha(tree, f"{context} tree")


def _git_identity_line(identity: Mapping[str, Any], role: str) -> bytes:
    timestamp = common.timestamp(identity["timestamp"], f"transition commit {role}.timestamp")
    instant = dt.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.UTC)
    if instant.microsecond != 0:
        _die(f"transition commit {role} timestamp is not an exact Git second")
    epoch = int(instant.timestamp())
    if epoch <= 0:
        _die(f"transition commit {role} epoch differs")
    return f"{role} {identity['name']} <{identity['email']}> {epoch} +0000\n".encode("ascii")


def _expected_new_commit_body(commit: Mapping[str, Any]) -> bytes:
    return b"".join(
        (
            f"tree {commit['tree']}\n".encode("ascii"),
            f"parent {commit['parent']}\n".encode("ascii"),
            _git_identity_line(commit["author"], "author"),
            _git_identity_line(commit["committer"], "committer"),
            b"\n",
            DIST_TRANSITION_MESSAGE.encode("utf-8"),
            b"\n",
        )
    )


def _validate_transition_git_objects(  # noqa: PLR0912, PLR0915
    value: Any,
    *,
    old: Mapping[str, Any],
    commit: Mapping[str, Any],
    resulting_files: list[dict[str, Any]],
    source_projection_sha256: str,
) -> dict[str, Any]:
    graph = common.exact_object(
        value,
        {"blobs", "format", "new_commit", "old_commit", "trees"},
        "transition Git object set",
    )
    if graph["format"] != DIST_TRANSITION_GIT_OBJECTS_FORMAT:
        _die("transition Git object-set format differs")
    old_record, old_raw = _validate_raw_git_object(
        graph["old_commit"], kind="commit", context="transition old commit object"
    )
    new_record, new_raw = _validate_raw_git_object(
        graph["new_commit"], kind="commit", context="transition new commit object"
    )
    if (
        old_record["sha"] != old["commit"]
        or _old_commit_tree(old_raw, context="transition old commit object") != old["tree"]
    ):
        _die("transition old commit object differs from Q0")
    expected_new_raw = _expected_new_commit_body(commit)
    if new_record["sha"] != commit["sha"] or new_raw != expected_new_raw:
        _die("transition new commit object differs from the exact U0 commit")

    tree_values = graph["trees"]
    if not isinstance(tree_values, list) or not tree_values:
        _die("transition Git tree object set is empty")
    parsed_trees: dict[str, list[dict[str, str]]] = {}
    tree_shas: list[str] = []
    for position, tree_value in enumerate(tree_values):
        tree_record, tree_raw = _validate_raw_git_object(
            tree_value,
            kind="tree",
            context=f"transition tree object {position}",
        )
        tree_sha = tree_record["sha"]
        if tree_sha in parsed_trees:
            _die("transition Git tree object set contains a duplicate")
        parsed_trees[tree_sha] = _parse_git_tree(
            tree_raw, context=f"transition tree object {position}"
        )
        tree_shas.append(tree_sha)
    if tree_shas != sorted(tree_shas):
        _die("transition Git tree object set is not SHA order")
    old_leaves, old_reachable = _flatten_git_tree(old["tree"], parsed_trees, context="Q0")
    new_leaves, new_reachable = _flatten_git_tree(commit["tree"], parsed_trees, context="U0")
    if old_reachable | new_reachable != set(parsed_trees):
        _die("transition Git tree object set contains an unreachable object")
    outside_paths = {
        path
        for path in old_leaves.keys() | new_leaves.keys()
        if not path.startswith(DIST_TRANSITION_PREFIX)
    }
    if any(old_leaves.get(path) != new_leaves.get(path) for path in outside_paths):
        _die("transition Git tree changes a path outside dashboard dist")
    old_dist = {
        path: item for path, item in old_leaves.items() if path.startswith(DIST_TRANSITION_PREFIX)
    }
    new_dist = {
        path: item for path, item in new_leaves.items() if path.startswith(DIST_TRANSITION_PREFIX)
    }
    if old_dist == new_dist:
        _die("transition Git tree does not change dashboard dist")

    blob_values = graph["blobs"]
    if not isinstance(blob_values, list) or not blob_values:
        _die("transition Git blob object set is empty")
    blob_records: list[dict[str, Any]] = []
    blob_bodies: dict[str, bytes] = {}
    for position, blob_value in enumerate(blob_values):
        blob = common.exact_object(
            blob_value,
            {"body_base64", "path", "sha", "sha256", "size"},
            f"transition blob object {position}",
        )
        path = common.relative_path(blob["path"], f"transition blob object {position}.path")
        if not path.startswith(DIST_TRANSITION_PREFIX):
            _die("transition Git blob escapes dashboard dist")
        object_record = {key: blob[key] for key in ("body_base64", "sha", "sha256", "size")}
        validated, raw = _validate_raw_git_object(
            object_record,
            kind="blob",
            context=f"transition blob object {position}",
        )
        record = {"path": path, **validated}
        blob_records.append(record)
        blob_bodies[path] = raw
    blob_paths = [record["path"] for record in blob_records]
    if blob_paths != sorted(blob_paths, key=lambda item: item.encode("utf-8")) or len(
        set(blob_paths)
    ) != len(blob_paths):
        _die("transition Git blob object set is not unique UTF-8 path order")
    expected_by_path = {record["path"]: record for record in resulting_files}
    if set(blob_paths) != set(expected_by_path) or set(new_dist) != set(expected_by_path):
        _die("transition Git blobs/resulting files differ from the complete U0 dist tree")
    for blob in blob_records:
        path = blob["path"]
        file_record = expected_by_path[path]
        leaf = new_dist[path]
        if (
            leaf != {"mode": "100644", "sha": blob["sha"], "type": "blob"}
            or file_record["mode"] != "0644"
            or file_record["sha256"] != blob["sha256"]
            or file_record["size"] != blob["size"]
        ):
            _die(f"transition Git blob differs from resulting file {path}")
    marker_path = DIST_TRANSITION_PREFIX + ".build-inputs.sha256"
    if blob_bodies[marker_path] != (source_projection_sha256 + "\n").encode("ascii"):
        _die("dashboard dist transition build-inputs marker differs from source projection")
    context_path = DIST_TRANSITION_PREFIX + ".build-context"
    if blob_bodies[context_path] != b"z4j-dashboard-production-v1\n":
        _die("dashboard dist transition build-context blob differs")
    output_path = DIST_TRANSITION_PREFIX + ".build-output.sha256"
    output_input = bytearray()
    for path in sorted(blob_bodies, key=lambda item: item.encode("utf-8")):
        relative = path.removeprefix(DIST_TRANSITION_PREFIX)
        if relative in {".build-inputs.sha256", ".build-output.sha256"}:
            continue
        output_input.extend(f"{common.sha256(blob_bodies[path])}  {relative}\n".encode())
    expected_output = (common.sha256(bytes(output_input)) + "\n").encode("ascii")
    if blob_bodies[output_path] != expected_output:
        _die("dashboard dist transition build-output blob differs")
    return graph


def validate_main_transition_plan(  # noqa: PLR0912, PLR0915
    value: Any,
    *,
    expected_source_projection_sha256: str,
    expected_authority: Mapping[str, Any],
    git_objects: Any,
) -> dict[str, Any]:
    """Validate the detached acyclic Q0-to-U0 dashboard-dist plan."""

    plan = common.exact_object(
        value,
        {
            "allowed_path_prefix",
            "authority",
            "commit",
            "format",
            "old",
            "ref",
            "repository",
            "resulting_files",
            "transition",
        },
        "dashboard dist transition plan",
    )
    if {
        "allowed_path_prefix": plan["allowed_path_prefix"],
        "format": plan["format"],
        "ref": plan["ref"],
        "repository": plan["repository"],
        "transition": plan["transition"],
    } != {
        "allowed_path_prefix": DIST_TRANSITION_PREFIX,
        "format": DIST_TRANSITION_PLAN_FORMAT,
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
        "transition": "create-or-recover-exact-fast-forward",
    }:
        _die("dashboard dist transition plan constants differ")
    old = common.exact_object(plan["old"], {"commit", "tree"}, "transition old")
    common.git_sha(old["commit"], "transition old commit")
    common.git_sha(old["tree"], "transition old tree")
    source_projection_sha256 = common.hex64(
        expected_source_projection_sha256,
        "expected transition source projection SHA-256",
    )
    authority = _validate_transition_authority(plan["authority"])
    if authority != dict(expected_authority):
        _die("dashboard dist transition authority differs from the selected graph")
    commit = common.exact_object(
        plan["commit"],
        {"author", "committer", "message", "parent", "sha", "tree"},
        "transition commit",
    )
    _validate_git_identity(commit["author"], "transition commit author")
    _validate_git_identity(commit["committer"], "transition commit committer")
    common.git_sha(commit["sha"], "transition commit SHA")
    common.git_sha(commit["tree"], "transition commit tree")
    if commit["message"] != DIST_TRANSITION_MESSAGE or commit["parent"] != old["commit"]:
        _die("dashboard dist transition commit message/parent differs")
    if commit["sha"] == old["commit"] or commit["tree"] == old["tree"]:
        _die("dashboard dist transition does not create a distinct U0 commit/tree")
    files = plan["resulting_files"]
    if not isinstance(files, list) or not files:
        _die("dashboard dist transition resulting file list is empty")
    paths: list[str] = []
    by_relative: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(files):
        record = common.exact_object(
            item, {"mode", "path", "sha256", "size"}, f"transition file {position}"
        )
        path = common.relative_path(record["path"], f"transition file {position} path")
        pure = PurePosixPath(path)
        if (
            not path.startswith(DIST_TRANSITION_PREFIX)
            or pure.is_absolute()
            or ".." in pure.parts
            or record["mode"] != "0644"
        ):
            _die(f"transition file {position} escapes the regular-0644 dist boundary")
        if path.endswith(".map"):
            _die("dashboard dist transition includes a forbidden source map")
        common.hex64(record["sha256"], f"transition file {position} SHA-256")
        common.nonnegative_int(record["size"], f"transition file {position} size")
        paths.append(path)
        by_relative[path.removeprefix(DIST_TRANSITION_PREFIX)] = record
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(set(paths)) != len(
        paths
    ):
        _die("dashboard dist transition file paths are not unique UTF-8 order")
    if DIST_TRANSITION_MARKERS.difference(by_relative):
        _die("dashboard dist transition build marker set differs")
    context_bytes = b"z4j-dashboard-production-v1\n"
    context_record = by_relative[".build-context"]
    if context_record["sha256"] != common.sha256(context_bytes) or context_record["size"] != len(
        context_bytes
    ):
        _die("dashboard dist transition build-context marker differs")
    if by_relative[".build-inputs.sha256"]["size"] != 65:
        _die("dashboard dist transition build-inputs marker size differs")
    output_input = bytearray()
    for relative in sorted(by_relative, key=lambda item: item.encode("utf-8")):
        if relative in {".build-inputs.sha256", ".build-output.sha256"}:
            continue
        record = by_relative[relative]
        output_input.extend(f"{record['sha256']}  {relative}\n".encode())
    expected_output = (common.sha256(bytes(output_input)) + "\n").encode("ascii")
    output_record = by_relative[".build-output.sha256"]
    if output_record["sha256"] != common.sha256(expected_output) or output_record["size"] != len(
        expected_output
    ):
        _die("dashboard dist transition build-output marker differs")
    _validate_transition_git_objects(
        git_objects,
        old=old,
        commit=commit,
        resulting_files=files,
        source_projection_sha256=source_projection_sha256,
    )
    dist_tree = {
        "files": [
            {
                "mode": record["mode"],
                "path": "dist/" + record["path"].removeprefix(DIST_TRANSITION_PREFIX),
                "sha256": record["sha256"],
                "size": record["size"],
            }
            for record in files
        ],
        "format": "z4j-production-dashboard-dist-tree-v1",
    }
    bundle_tree = authority["bundle_tree"]
    if (
        common.sha256(common.canonical_json(dist_tree, terminal_lf=False)) != bundle_tree["sha256"]
        or sum(record["size"] for record in files) != bundle_tree["bytes"]
    ):
        _die("dashboard dist transition files differ from selected bundle tree")
    return plan


def _snapshot_json(value: Any, context: str) -> Any:
    raw = common.canonical_json(value, terminal_lf=False)
    return common.parse_json(raw, context=context)


def _validate_selected_governance(  # noqa: PLR0912, PLR0915
    value: MainTransitionGovernance,
) -> dict[str, Any]:
    if not isinstance(value, MainTransitionGovernance) or value.choice not in GOVERNANCE_CHOICES:
        _die("dashboard transition governance must select exactly G1, G2, or G3")
    selected = cast(
        dict[str, Any],
        _snapshot_json(
            {
                "main_protection": value.main_protection,
                "repository": value.repository,
                "rulesets": value.rulesets,
            },
            "selected dashboard transition governance",
        ),
    )
    repository = selected["repository"]
    if not isinstance(repository, dict) or {
        "archived": repository.get("archived"),
        "default_branch": repository.get("default_branch"),
        "disabled": repository.get("disabled"),
        "full_name": repository.get("full_name"),
        "id": repository.get("id"),
        "node_id": repository.get("node_id"),
        "private": repository.get("private"),
        "visibility": repository.get("visibility"),
    } != {
        "archived": False,
        "default_branch": "main",
        "disabled": False,
        "full_name": common.PRODUCER_REPOSITORY,
        "id": common.PRODUCER_REPOSITORY_ID,
        "node_id": common.PRODUCER_REPOSITORY_NODE_ID,
        "private": True,
        "visibility": common.PRODUCER_VISIBILITY,
    }:
        _die("selected dashboard transition repository semantics differ")

    protection = selected["main_protection"]
    if not isinstance(protection, dict) or not protection:
        _die("selected dashboard transition main protection is empty")
    required_reviews = protection.get("required_pull_request_reviews")
    if (
        not isinstance(required_reviews, dict)
        or required_reviews.get("dismiss_stale_reviews") is not True
        or required_reviews.get("require_code_owner_reviews") is not True
        or required_reviews.get("require_last_push_approval") is not True
    ):
        _die("selected dashboard transition pull-request protection differs")
    common.positive_int(
        required_reviews.get("required_approving_review_count"),
        "selected dashboard transition approving-review count",
    )
    for field, expected in (
        ("allow_deletions", False),
        ("allow_force_pushes", False),
        ("enforce_admins", True),
        ("required_conversation_resolution", True),
    ):
        setting = protection.get(field)
        if not isinstance(setting, dict) or setting.get("enabled") is not expected:
            _die(f"selected dashboard transition {field} protection differs")

    ruleset_selection = common.exact_object(
        selected["rulesets"], {"details", "list"}, "selected dashboard transition rulesets"
    )
    ruleset_list = ruleset_selection["list"]
    details = ruleset_selection["details"]
    if (
        not isinstance(ruleset_list, list)
        or not isinstance(details, list)
        or not ruleset_list
        or len(ruleset_list) >= 100
        or len(details) != len(ruleset_list)
    ):
        _die("selected dashboard transition ruleset collection is incomplete")
    list_ids: list[int] = []
    for position, item in enumerate(ruleset_list):
        if not isinstance(item, dict):
            _die(f"selected ruleset list item {position} is not one object")
        identifier = common.positive_int(
            item.get("id"), f"selected ruleset list item {position}.id"
        )
        name = item.get("name")
        if (
            not isinstance(name, str)
            or not name
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in name)
        ):
            _die(f"selected ruleset list item {position}.name is not printable ASCII")
        if item.get("enforcement") != "active" or item.get("target") != "branch":
            _die("selected dashboard transition ruleset is not active for branches")
        list_ids.append(identifier)
    if len(set(list_ids)) != len(list_ids):
        _die("selected dashboard transition ruleset list contains duplicate IDs")
    detail_ids: list[int] = []
    aggregate_rule_types: set[str] = set()
    for position, item in enumerate(details):
        if not isinstance(item, dict):
            _die(f"selected ruleset detail {position} is not one object")
        identifier = common.positive_int(item.get("id"), f"selected ruleset detail {position}.id")
        if item.get("enforcement") != "active" or item.get("target") != "branch":
            _die("selected dashboard transition ruleset detail is not active for branches")
        if not isinstance(item.get("conditions"), dict) or not isinstance(
            item.get("bypass_actors"), list
        ):
            _die("selected dashboard transition ruleset conditions/bypass actors differ")
        rules = item.get("rules")
        if not isinstance(rules, list) or not rules:
            _die("selected dashboard transition ruleset has no rules")
        for rule_number, rule in enumerate(rules):
            if not isinstance(rule, dict):
                _die(f"selected ruleset detail {position} rule {rule_number} is not one object")
            aggregate_rule_types.add(
                common.ascii_text(
                    rule.get("type"),
                    f"selected ruleset detail {position} rule {rule_number}.type",
                )
            )
        detail_ids.append(identifier)
    if len(set(detail_ids)) != len(detail_ids) or set(detail_ids) != set(list_ids):
        _die("selected dashboard transition ruleset list/detail identities differ")
    if not {"deletion", "non_fast_forward", "pull_request"} <= aggregate_rule_types:
        _die("selected dashboard transition rulesets omit protected-main controls")
    return selected


def _repository_semantics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _die("dashboard transition repository response is not one object")
    return {key: item for key, item in value.items() if key not in REPOSITORY_REF_VOLATILE_FIELDS}


def _validate_settings_semantics(
    observed: Mapping[str, Any],
    selected: Mapping[str, Any],
    *,
    context: str,
) -> None:
    if _repository_semantics(observed["repository"]) != _repository_semantics(
        selected["repository"]
    ):
        _die(f"{context} repository semantics differ from selected E0")
    if observed["main_protection"] != selected["main_protection"]:
        _die(f"{context} main protection differs from selected E0")
    expected_rulesets = common.exact_object(
        selected["rulesets"], {"details", "list"}, "selected dashboard transition rulesets"
    )
    if observed["rulesets"] != expected_rulesets["list"]:
        _die(f"{context} ruleset list differs from selected E0")


def _github_response_body(
    value: Any,
    context: str,
    *,
    method: str = "GET",
    expected_content_type: str,
    expected_status: int,
    expected_url: str,
) -> Any:
    response, raw = common.validate_github_response(value, context, method=method)
    if (
        response["response_content_type"] != expected_content_type
        or response["status"] != expected_status
        or response["url"] != expected_url
    ):
        _die(f"{context} method/URL/status/content-type contract differs")
    return common.parse_json(raw, context=f"{context} body")


def _transition_rest_response_body(
    value: Any,
    context: str,
    *,
    expected_content_type: str,
    expected_status: int,
    expected_url: str,
) -> Any:
    response, raw = _validate_transition_github_response(value, context)
    if (
        response["response_content_type"] != expected_content_type
        or response["status"] != expected_status
        or response["url"] != expected_url
    ):
        _die(f"{context} method/URL/status/content-type contract differs")
    return common.parse_json(raw, context=f"{context} body")


def _http_header_value(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        _die(f"{context} must be nonempty printable ASCII without controls")
    return value


def _validate_transition_github_response(
    value: Any,
    context: str,
    *,
    method: str = "GET",
) -> tuple[dict[str, Any], bytes]:
    """Validate a literal transition carrier under the frozen API version."""

    response = common.exact_object(
        value,
        {
            "body_base64",
            "body_sha256",
            "body_size",
            "method",
            "request_accept",
            "request_api_version",
            "response_content_type",
            "status",
            "url",
        },
        context,
    )
    body = common.base64_bytes(
        response["body_base64"],
        f"{context}.body_base64",
        allow_empty=True,
    )
    common.hex64(response["body_sha256"], f"{context}.body_sha256")
    common.nonnegative_int(response["body_size"], f"{context}.body_size")
    if response["body_sha256"] != common.sha256(body) or response["body_size"] != len(body):
        _die(f"{context} retained body seal differs")
    if (
        response["method"] != method
        or response["request_accept"] != common.GITHUB_ACCEPT
        or response["request_api_version"] != GITHUB_TRANSITION_API_VERSION
    ):
        _die(f"{context} GitHub request contract differs")
    _http_header_value(response["response_content_type"], f"{context}.response_content_type")
    common.positive_int(response["status"], f"{context}.status")
    common.https_url(response["url"], f"{context}.url")
    common.parse_json(body, context=f"{context} retained JSON body")
    return response, body


def _git_ref_target(body: Any, context: str) -> str:
    if not isinstance(body, dict) or body.get("ref") != "refs/heads/main":
        _die(f"{context} is not the exact private main ref")
    target = body.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit":
        _die(f"{context} does not target a commit")
    return common.git_sha(target.get("sha"), f"{context} target")


def validate_main_transition_readback(
    value: Any,
    *,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    expected_source_projection_sha256: str,
    expected_authority: Mapping[str, Any],
    expected_governance: MainTransitionGovernance,
    expected_response_content_type: str,
    git_objects: Any,
) -> dict[str, Any]:
    """Validate create-or-truthful-recovery readback for the one Q0-to-U0 update."""

    if common.canonical_json(plan, terminal_lf=True) != plan_raw:
        _die("dashboard transition plan bytes are not canonical JSON plus one LF")
    validate_main_transition_plan(
        plan,
        expected_source_projection_sha256=expected_source_projection_sha256,
        expected_authority=expected_authority,
        git_objects=git_objects,
    )
    selected_governance = _validate_selected_governance(expected_governance)
    content_type = common.ascii_text(
        expected_response_content_type,
        "expected dashboard transition GitHub response content type",
    )
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        _die("expected dashboard transition response content type is not JSON")
    readback = common.exact_object(
        value,
        {"format", "plan", "ref", "repository", "result", "settings", "transition"},
        "dashboard dist transition readback",
    )
    if {
        "format": readback["format"],
        "ref": readback["ref"],
        "repository": readback["repository"],
    } != {
        "format": DIST_TRANSITION_READBACK_FORMAT,
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
    }:
        _die("dashboard dist transition readback constants differ")
    if readback["result"] not in {"created-exact-fast-forward", "recovered-existing-exact"}:
        _die("dashboard dist transition result differs")
    seal = common.file_seal(readback["plan"], "dashboard transition plan seal")
    if seal != {"sha256": common.sha256(plan_raw), "size": len(plan_raw)}:
        _die("dashboard dist transition plan seal differs")
    settings = common.exact_object(
        readback["settings"],
        {"main_protection", "repository", "rulesets"},
        "transition settings",
    )
    setting_urls = {
        "main_protection": GITHUB_MAIN_PROTECTION_URL,
        "repository": GITHUB_REPOSITORY_API_URL,
        "rulesets": GITHUB_RULESETS_URL,
    }
    setting_bodies = {
        name: _github_response_body(
            settings[name],
            f"transition settings {name}",
            expected_content_type=content_type,
            expected_status=200,
            expected_url=setting_urls[name],
        )
        for name in ("main_protection", "repository", "rulesets")
    }
    _validate_settings_semantics(
        setting_bodies,
        selected_governance,
        context="dashboard transition retained settings",
    )
    transition = common.exact_object(
        readback["transition"],
        {"new", "old", "ref_readback", "ref_update"},
        "transition readback state",
    )
    source = common.exact_object(transition["old"], {"commit", "tree"}, "transition old")
    target = common.exact_object(transition["new"], {"commit", "tree"}, "transition new")
    for name, identity in (("from", source), ("to", target)):
        common.git_sha(identity["commit"], f"transition {name} commit")
        common.git_sha(identity["tree"], f"transition {name} tree")
    if source != plan["old"] or target != {
        "commit": plan["commit"]["sha"],
        "tree": plan["commit"]["tree"],
    }:
        _die("dashboard transition readback source/target differs from plan")
    if readback["result"] == "created-exact-fast-forward":
        if transition["ref_update"] is None:
            _die("dashboard create transition lacks the exact U0 update")
        patch_body = _github_response_body(
            transition["ref_update"],
            "transition ref update",
            method="PATCH",
            expected_content_type=content_type,
            expected_status=200,
            expected_url=GITHUB_MAIN_REF_UPDATE_URL,
        )
        if _git_ref_target(patch_body, "transition patch") != target["commit"]:
            _die("dashboard transition update response differs from U0")
    elif transition["ref_update"] is not None:
        _die("dashboard recovery transition performed a ref update")
    ref_body = _github_response_body(
        transition["ref_readback"],
        "transition ref readback",
        expected_content_type=content_type,
        expected_status=200,
        expected_url=GITHUB_MAIN_REF_READ_URL,
    )
    if _git_ref_target(ref_body, "transition ref") != target["commit"]:
        _die("dashboard transition final ref differs from U0")
    return readback


def _request_proof(request: GitHubTransitionRequest) -> dict[str, Any]:
    body_seal: dict[str, Any] | None = None
    if request.body is not None:
        body_seal = {
            "body_base64": base64.b64encode(request.body).decode("ascii"),
            "body_sha256": common.sha256(request.body),
            "body_size": len(request.body),
        }
    return {
        "body": body_seal,
        "method": request.method,
        "request_accept": request.accept,
        "request_api_version": request.api_version,
        "request_content_type": request.content_type,
        "url": request.url,
    }


def _github_exchange(
    transport: GitHubTransitionTransport,
    exchanges: list[dict[str, Any]],
    *,
    method: str,
    url: str,
    body: bytes | None,
    expected_status: int,
    expected_response_content_type: str,
    context: str,
) -> tuple[dict[str, Any], Any]:
    if method == "GET":
        if body is not None:
            _die(f"{context} GET unexpectedly has a request body")
        request_content_type = None
    elif method == "POST":
        if body is None:
            _die(f"{context} write lacks an exact request body")
        request_content_type = GITHUB_JSON_REQUEST_CONTENT_TYPE
        parsed_request = common.parse_json(body, context=f"{context} request body")
        if common.canonical_json(parsed_request, terminal_lf=False) != body:
            _die(f"{context} request body is not canonical no-LF JSON")
    else:
        _die(f"{context} uses a forbidden GitHub method")
    common.https_url(url, f"{context} URL", expected=url)
    request = GitHubTransitionRequest(
        accept=common.GITHUB_ACCEPT,
        api_version=GITHUB_TRANSITION_API_VERSION,
        body=body,
        content_type=request_content_type,
        method=method,
        url=url,
    )
    response = transport.request(request)
    if not isinstance(response, GitHubTransitionResponse):
        _die(f"{context} transport returned a nonliteral response")
    if isinstance(response.status, bool) or response.status != expected_status:
        _die(f"{context} returned an unexpected HTTP status")
    if response.content_type != expected_response_content_type:
        _die(f"{context} returned an unexpected content type")
    if not isinstance(response.body, bytes) or len(response.body) > common.MAX_JSON_BYTES:
        _die(f"{context} returned an invalid or oversized body")
    parsed = common.parse_json(response.body, context=f"{context} response body")
    carrier = {
        "body_base64": base64.b64encode(response.body).decode("ascii"),
        "body_sha256": common.sha256(response.body),
        "body_size": len(response.body),
        "method": method,
        "request_accept": common.GITHUB_ACCEPT,
        "request_api_version": GITHUB_TRANSITION_API_VERSION,
        "response_content_type": response.content_type,
        "status": response.status,
        "url": url,
    }
    _validate_transition_github_response(carrier, context, method=method)
    exchanges.append({"request": _request_proof(request), "response": carrier})
    return carrier, parsed


def _graphql_cas_variables(
    *,
    repository_id: str,
    old_commit: str,
    target_commit: str,
) -> dict[str, Any]:
    common.ascii_text(repository_id, "dashboard transition GraphQL repository ID")
    common.git_sha(old_commit, "dashboard transition GraphQL beforeOid")
    common.git_sha(target_commit, "dashboard transition GraphQL afterOid")
    return {
        "input": {
            "refUpdates": [
                {
                    "afterOid": target_commit,
                    "beforeOid": old_commit,
                    "force": False,
                    "name": common.PRODUCER_REF,
                }
            ],
            "repositoryId": repository_id,
        }
    }


def _validate_graphql_cas_evidence(
    value: Any,
    *,
    expected_content_type: str,
    expected_old: Mapping[str, Any],
    expected_repository_id: str,
    expected_target: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    evidence = common.exact_object(
        value,
        {
            "format",
            "from",
            "ref",
            "repository",
            "repository_id",
            "request",
            "response",
            "to",
        },
        "dashboard transition GraphQL CAS evidence",
    )
    if {
        "format": evidence["format"],
        "ref": evidence["ref"],
        "repository": evidence["repository"],
        "repository_id": evidence["repository_id"],
    } != {
        "format": DIST_TRANSITION_GRAPHQL_CAS_EVIDENCE_FORMAT,
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
        "repository_id": expected_repository_id,
    }:
        _die("dashboard transition GraphQL CAS evidence constants differ")
    source = common.exact_object(evidence["from"], {"commit", "tree"}, "GraphQL CAS from")
    target = common.exact_object(evidence["to"], {"commit", "tree"}, "GraphQL CAS to")
    if source != expected_old or target != expected_target:
        _die("dashboard transition GraphQL CAS source/target differs")

    variables = _graphql_cas_variables(
        repository_id=expected_repository_id,
        old_commit=source["commit"],
        target_commit=target["commit"],
    )
    expected_body = common.canonical_json(
        {"query": GITHUB_UPDATE_REFS_QUERY, "variables": variables},
        terminal_lf=False,
    )
    request = common.exact_object(
        evidence["request"],
        {
            "body_base64",
            "body_sha256",
            "body_size",
            "method",
            "query_sha256",
            "request_accept",
            "request_api_version",
            "request_content_type",
            "url",
            "variables",
        },
        "dashboard transition GraphQL CAS request",
    )
    request_body = common.base64_bytes(
        request["body_base64"],
        "dashboard transition GraphQL CAS request body",
    )
    if (
        request
        != {
            **request,
            "body_sha256": common.sha256(expected_body),
            "body_size": len(expected_body),
            "method": "POST",
            "query_sha256": common.sha256(GITHUB_UPDATE_REFS_QUERY.encode("ascii")),
            "request_accept": common.GITHUB_ACCEPT,
            "request_api_version": None,
            "request_content_type": GITHUB_JSON_REQUEST_CONTENT_TYPE,
            "url": GITHUB_GRAPHQL_URL,
            "variables": variables,
        }
        or request_body != expected_body
    ):
        _die("dashboard transition GraphQL CAS request contract differs")

    response = common.exact_object(
        evidence["response"],
        {
            "body_base64",
            "body_sha256",
            "body_size",
            "response_content_type",
            "status",
        },
        "dashboard transition GraphQL CAS response",
    )
    response_body = common.base64_bytes(
        response["body_base64"],
        "dashboard transition GraphQL CAS response body",
    )
    if (
        response["body_sha256"] != common.sha256(response_body)
        or response["body_size"] != len(response_body)
        or response["response_content_type"] != expected_content_type
        or response["status"] != 200
    ):
        _die("dashboard transition GraphQL CAS response contract differs")
    parsed = common.parse_json(response_body, context="dashboard transition GraphQL CAS response")
    top = common.exact_object(parsed, {"data"}, "dashboard transition GraphQL CAS result")
    data = common.exact_object(top["data"], {"updateRefs"}, "dashboard transition GraphQL CAS data")
    payload = common.exact_object(
        data["updateRefs"],
        {"clientMutationId"},
        "dashboard transition GraphQL CAS payload",
    )
    if payload["clientMutationId"] is not None:
        _die("dashboard transition GraphQL CAS client mutation ID differs")
    evidence_raw = common.canonical_json(evidence, terminal_lf=True)
    return evidence, evidence_raw


def _github_graphql_cas(
    transport: GitHubTransitionTransport,
    exchanges: list[dict[str, Any]],
    *,
    expected_response_content_type: str,
    old: Mapping[str, Any],
    repository_id: str,
    target: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    variables = _graphql_cas_variables(
        repository_id=repository_id,
        old_commit=old["commit"],
        target_commit=target["commit"],
    )
    request_body = common.canonical_json(
        {"query": GITHUB_UPDATE_REFS_QUERY, "variables": variables},
        terminal_lf=False,
    )
    request = GitHubTransitionRequest(
        accept=common.GITHUB_ACCEPT,
        api_version=None,
        body=request_body,
        content_type=GITHUB_JSON_REQUEST_CONTENT_TYPE,
        method="POST",
        url=GITHUB_GRAPHQL_URL,
    )
    response = transport.request(request)
    if not isinstance(response, GitHubTransitionResponse):
        _die("dashboard transition GraphQL CAS transport returned a nonliteral response")
    if (
        isinstance(response.status, bool)
        or response.status != 200
        or response.content_type != expected_response_content_type
        or not isinstance(response.body, bytes)
        or len(response.body) > common.MAX_JSON_BYTES
    ):
        _die("dashboard transition GraphQL CAS returned an unexpected response contract")
    evidence = {
        "format": DIST_TRANSITION_GRAPHQL_CAS_EVIDENCE_FORMAT,
        "from": dict(old),
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
        "repository_id": repository_id,
        "request": {
            "body_base64": base64.b64encode(request_body).decode("ascii"),
            "body_sha256": common.sha256(request_body),
            "body_size": len(request_body),
            "method": "POST",
            "query_sha256": common.sha256(GITHUB_UPDATE_REFS_QUERY.encode("ascii")),
            "request_accept": common.GITHUB_ACCEPT,
            "request_api_version": None,
            "request_content_type": GITHUB_JSON_REQUEST_CONTENT_TYPE,
            "url": GITHUB_GRAPHQL_URL,
            "variables": variables,
        },
        "response": {
            "body_base64": base64.b64encode(response.body).decode("ascii"),
            "body_sha256": common.sha256(response.body),
            "body_size": len(response.body),
            "response_content_type": response.content_type,
            "status": response.status,
        },
        "to": dict(target),
    }
    validated, evidence_raw = _validate_graphql_cas_evidence(
        evidence,
        expected_content_type=expected_response_content_type,
        expected_old=old,
        expected_repository_id=repository_id,
        expected_target=target,
    )
    exchanges.append({"request": validated["request"], "response": validated["response"]})
    return validated, evidence_raw


def validate_main_transition_graphql_readback(  # noqa: PLR0912
    value: Any,
    *,
    cas_evidence: Mapping[str, Any] | None,
    cas_evidence_raw: bytes | None,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    expected_source_projection_sha256: str,
    expected_authority: Mapping[str, Any],
    expected_governance: MainTransitionGovernance,
    expected_response_content_type: str,
    git_objects: Any,
) -> dict[str, Any]:
    """Validate the exact v2 readback that cross-binds GraphQL CAS evidence."""

    if common.canonical_json(plan, terminal_lf=True) != plan_raw:
        _die("dashboard transition plan bytes are not canonical JSON plus one LF")
    validate_main_transition_plan(
        plan,
        expected_source_projection_sha256=expected_source_projection_sha256,
        expected_authority=expected_authority,
        git_objects=git_objects,
    )
    selected_governance = _validate_selected_governance(expected_governance)
    content_type = _http_header_value(
        expected_response_content_type,
        "expected dashboard transition GitHub response content type",
    )
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        _die("expected dashboard transition response content type is not JSON")
    readback = cast(
        dict[str, Any],
        common.exact_object(
            value,
            {"format", "plan", "ref", "repository", "result", "settings", "transition"},
            "dashboard dist GraphQL transition readback",
        ),
    )
    if {
        "format": readback["format"],
        "ref": readback["ref"],
        "repository": readback["repository"],
    } != {
        "format": DIST_TRANSITION_GRAPHQL_READBACK_FORMAT,
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
    }:
        _die("dashboard dist GraphQL transition readback constants differ")
    if readback["result"] not in {"created-exact-fast-forward", "recovered-existing-exact"}:
        _die("dashboard dist GraphQL transition result differs")
    plan_seal = common.file_seal(readback["plan"], "dashboard GraphQL transition plan seal")
    if plan_seal != {"sha256": common.sha256(plan_raw), "size": len(plan_raw)}:
        _die("dashboard dist GraphQL transition plan seal differs")

    settings = common.exact_object(
        readback["settings"],
        {"main_protection", "repository", "rulesets"},
        "GraphQL transition settings",
    )
    setting_urls = {
        "main_protection": GITHUB_MAIN_PROTECTION_URL,
        "repository": GITHUB_REPOSITORY_API_URL,
        "rulesets": GITHUB_RULESETS_URL,
    }
    setting_bodies = {
        name: _transition_rest_response_body(
            settings[name],
            f"GraphQL transition settings {name}",
            expected_content_type=content_type,
            expected_status=200,
            expected_url=setting_urls[name],
        )
        for name in ("main_protection", "repository", "rulesets")
    }
    _validate_settings_semantics(
        setting_bodies,
        selected_governance,
        context="dashboard GraphQL transition retained settings",
    )

    transition = common.exact_object(
        readback["transition"],
        {"cas_evidence", "new", "old", "ref_precondition", "ref_readback"},
        "GraphQL transition readback state",
    )
    source = common.exact_object(transition["old"], {"commit", "tree"}, "transition old")
    target = common.exact_object(transition["new"], {"commit", "tree"}, "transition new")
    if source != plan["old"] or target != {
        "commit": plan["commit"]["sha"],
        "tree": plan["commit"]["tree"],
    }:
        _die("dashboard GraphQL transition source/target differs from plan")
    precondition_body = _transition_rest_response_body(
        transition["ref_precondition"],
        "GraphQL transition immediate ref precondition",
        expected_content_type=content_type,
        expected_status=200,
        expected_url=GITHUB_MAIN_REF_READ_URL,
    )
    final_body = _transition_rest_response_body(
        transition["ref_readback"],
        "GraphQL transition final ref readback",
        expected_content_type=content_type,
        expected_status=200,
        expected_url=GITHUB_MAIN_REF_READ_URL,
    )
    if _git_ref_target(final_body, "GraphQL transition final ref") != target["commit"]:
        _die("dashboard GraphQL transition final ref differs from U0")

    if readback["result"] == "created-exact-fast-forward":
        if (
            _git_ref_target(precondition_body, "GraphQL transition precondition")
            != source["commit"]
        ):
            _die("dashboard GraphQL transition immediate ref is not Q0")
        if cas_evidence is None or cas_evidence_raw is None:
            _die("dashboard GraphQL create transition lacks CAS evidence")
        if common.canonical_json(cas_evidence, terminal_lf=True) != cas_evidence_raw:
            _die("dashboard GraphQL CAS evidence bytes are not canonical JSON plus one LF")
        validated_evidence, validated_evidence_raw = _validate_graphql_cas_evidence(
            cas_evidence,
            expected_content_type=content_type,
            expected_old=source,
            expected_repository_id=selected_governance["repository"]["node_id"],
            expected_target=target,
        )
        del validated_evidence
        evidence_seal = common.file_seal(
            transition["cas_evidence"],
            "dashboard GraphQL transition CAS evidence seal",
        )
        if evidence_seal != {
            "sha256": common.sha256(validated_evidence_raw),
            "size": len(validated_evidence_raw),
        }:
            _die("dashboard GraphQL transition CAS evidence seal differs")
    else:
        if _git_ref_target(precondition_body, "GraphQL recovery precondition") != target["commit"]:
            _die("dashboard GraphQL recovery initial ref differs from U0")
        if (
            transition["cas_evidence"] is not None
            or cas_evidence is not None
            or cas_evidence_raw is not None
        ):
            _die("dashboard GraphQL recovery transition retained mutation evidence")
    return readback


def _git_object_url(kind: str, sha: str) -> str:
    common.git_sha(sha, f"remote Git {kind} SHA")
    plural = {"blob": "blobs", "commit": "commits", "tree": "trees"}.get(kind)
    if plural is None:
        _die("remote Git object type differs")
    return f"{GITHUB_REPOSITORY_API_URL}/git/{plural}/{sha}"


def _validate_created_object(value: Any, *, kind: str, expected_sha: str) -> None:
    if (
        not isinstance(value, dict)
        or value.get("sha") != expected_sha
        or value.get("url") != _git_object_url(kind, expected_sha)
    ):
        _die(f"created remote Git {kind} differs from the exact local object")


def _decode_remote_blob_content(value: Any, context: str) -> bytes:
    if not isinstance(value, str):
        _die(f"{context} content is not base64 text")
    compact = "".join(value.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DashboardAuthorityError(f"{context} content is invalid base64") from exc
    if base64.b64encode(raw).decode("ascii") != compact:
        _die(f"{context} content is not canonical base64 modulo API folding")
    return raw


def _validate_remote_blob(value: Any, *, expected_sha: str, expected_raw: bytes) -> None:
    if not isinstance(value, dict):
        _die("remote Git blob response is not one object")
    raw = _decode_remote_blob_content(value.get("content"), "remote Git blob")
    if (
        value.get("encoding") != "base64"
        or value.get("sha") != expected_sha
        or value.get("size") != len(expected_raw)
        or value.get("url") != _git_object_url("blob", expected_sha)
        or raw != expected_raw
        or _git_object_id("blob", raw) != expected_sha
    ):
        _die("remote Git blob readback differs from the exact local object")


def _api_tree_entries(raw: bytes, *, context: str) -> list[dict[str, str]]:
    entries = _parse_git_tree(raw, context=context)
    return [
        {
            "mode": "040000" if entry["mode"] == "40000" else entry["mode"],
            "path": entry["name"],
            "sha": entry["sha"],
            "type": entry["type"],
        }
        for entry in entries
    ]


def _remote_tree_raw(value: Any, *, expected_sha: str) -> bytes:
    if (
        not isinstance(value, dict)
        or value.get("sha") != expected_sha
        or value.get("truncated") is not False
        or value.get("url") != _git_object_url("tree", expected_sha)
    ):
        _die("remote Git tree envelope differs")
    values = value.get("tree")
    if not isinstance(values, list) or not values:
        _die("remote Git tree entries differ")
    raw = bytearray()
    for position, item in enumerate(values):
        if not isinstance(item, dict):
            _die(f"remote Git tree entry {position} is not one object")
        mode = item.get("mode")
        if mode == "040000":
            raw_mode = "40000"
        elif mode in {"100644", "100755", "120000", "160000"}:
            raw_mode = mode
        else:
            _die(f"remote Git tree entry {position} mode differs")
        path = item.get("path")
        if (
            not isinstance(path, str)
            or not path
            or "/" in path
            or "\\" in path
            or path in {".", ".."}
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        ):
            _die(f"remote Git tree entry {position} path differs")
        try:
            path_raw = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise DashboardAuthorityError(
                f"remote Git tree entry {position} path is not strict UTF-8"
            ) from exc
        sha = common.git_sha(item.get("sha"), f"remote Git tree entry {position} SHA")
        expected_type = (
            "tree" if raw_mode == "40000" else "commit" if raw_mode == "160000" else "blob"
        )
        if item.get("type") != expected_type:
            _die(f"remote Git tree entry {position} type differs")
        raw.extend(raw_mode.encode("ascii") + b" " + path_raw + b"\0")
        raw.extend(bytes.fromhex(sha))
    return bytes(raw)


def _validate_remote_tree(value: Any, *, expected_sha: str, expected_raw: bytes) -> None:
    raw = _remote_tree_raw(value, expected_sha=expected_sha)
    if raw != expected_raw or _git_object_id("tree", raw) != expected_sha:
        _die("remote Git tree reconstruction differs from the exact local object")


def _validate_remote_commit(
    value: Any,
    *,
    expected_sha: str,
    expected_tree: str,
    expected_commit: Mapping[str, Any] | None,
) -> None:
    if (
        not isinstance(value, dict)
        or value.get("sha") != expected_sha
        or value.get("url") != _git_object_url("commit", expected_sha)
    ):
        _die("remote Git commit envelope differs")
    tree = value.get("tree")
    if not isinstance(tree, dict) or tree.get("sha") != expected_tree:
        _die("remote Git commit tree differs")
    if expected_commit is None:
        return
    if value.get("message") != expected_commit["message"]:
        _die("remote Git commit message differs")
    parents = value.get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or not isinstance(parents[0], dict)
        or parents[0].get("sha") != expected_commit["parent"]
    ):
        _die("remote Git commit sole parent differs")
    for role in ("author", "committer"):
        observed = value.get(role)
        selected = expected_commit[role]
        if not isinstance(observed, dict) or {
            "date": observed.get("date"),
            "email": observed.get("email"),
            "name": observed.get("name"),
        } != {
            "date": selected["timestamp"],
            "email": selected["email"],
            "name": selected["name"],
        }:
            _die(f"remote Git commit {role} differs")


def _transition_graph(value: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    graph = common.exact_object(
        value,
        {"blobs", "format", "new_commit", "old_commit", "trees"},
        "transition Git object set",
    )
    tree_raw: dict[str, bytes] = {}
    parsed_trees: dict[str, list[dict[str, str]]] = {}
    for position, item in enumerate(graph["trees"]):
        record, raw = _validate_raw_git_object(
            item,
            kind="tree",
            context=f"transition tree object {position}",
        )
        tree_raw[record["sha"]] = raw
        parsed_trees[record["sha"]] = _parse_git_tree(
            raw,
            context=f"transition tree object {position}",
        )
    old_root = plan["old"]["tree"]
    new_root = plan["commit"]["tree"]
    _old_leaves, old_reachable = _flatten_git_tree(old_root, parsed_trees, context="Q0")
    _new_leaves, new_reachable = _flatten_git_tree(new_root, parsed_trees, context="U0")
    blob_raw: dict[str, bytes] = {}
    blob_paths: dict[str, str] = {}
    for position, item in enumerate(graph["blobs"]):
        record = common.exact_object(
            item,
            {"body_base64", "path", "sha", "sha256", "size"},
            f"transition blob object {position}",
        )
        raw = common.base64_bytes(
            record["body_base64"],
            f"transition blob object {position}.body_base64",
            allow_empty=True,
        )
        blob_raw[record["sha"]] = raw
        blob_paths[record["sha"]] = record["path"]
    return {
        "blob_paths": blob_paths,
        "blob_raw": blob_raw,
        "new_reachable": new_reachable,
        "old_reachable": old_reachable,
        "parsed_trees": parsed_trees,
        "tree_raw": tree_raw,
    }


def _tree_creation_order(
    root: str,
    parsed_trees: Mapping[str, list[dict[str, str]]],
    existing: set[str],
) -> list[str]:
    ordered: list[str] = []
    visited: set[str] = set()

    def visit(tree_sha: str) -> None:
        if tree_sha in visited:
            return
        visited.add(tree_sha)
        for entry in parsed_trees[tree_sha]:
            if entry["type"] == "tree":
                visit(entry["sha"])
        if tree_sha not in existing:
            ordered.append(tree_sha)

    visit(root)
    return ordered


def _ruleset_detail_url(identifier: int) -> str:
    common.positive_int(identifier, "selected ruleset detail ID")
    return f"{GITHUB_REPOSITORY_API_URL}/rulesets/{identifier}"


def _read_transition_settings(
    transport: GitHubTransitionTransport,
    exchanges: list[dict[str, Any]],
    *,
    selected_governance: Mapping[str, Any],
    expected_response_content_type: str,
    context: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    carriers: dict[str, Any] = {}
    bodies: dict[str, Any] = {}
    endpoints = {
        "main_protection": GITHUB_MAIN_PROTECTION_URL,
        "repository": GITHUB_REPOSITORY_API_URL,
        "rulesets": GITHUB_RULESETS_URL,
    }
    for name in ("main_protection", "repository", "rulesets"):
        carrier, body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=endpoints[name],
            body=None,
            expected_status=200,
            expected_response_content_type=expected_response_content_type,
            context=f"{context} {name}",
        )
        carriers[name] = carrier
        bodies[name] = body
    _validate_settings_semantics(bodies, selected_governance, context=context)
    expected_rulesets = common.exact_object(
        selected_governance["rulesets"],
        {"details", "list"},
        "selected dashboard transition rulesets",
    )
    observed_details: list[Any] = []
    for position, expected in enumerate(expected_rulesets["details"]):
        identifier = common.positive_int(
            expected.get("id"), f"selected ruleset detail {position}.id"
        )
        _carrier, body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=_ruleset_detail_url(identifier),
            body=None,
            expected_status=200,
            expected_response_content_type=expected_response_content_type,
            context=f"{context} ruleset detail {identifier}",
        )
        observed_details.append(body)
    if observed_details != expected_rulesets["details"]:
        _die(f"{context} ruleset details differ from selected E0")
    bodies["ruleset_details"] = observed_details
    return carriers, bodies


def _assert_settings_preserved(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> None:
    if _repository_semantics(before["repository"]) != _repository_semantics(after["repository"]):
        _die("dashboard transition changed repository semantics")
    for name in ("main_protection", "rulesets", "ruleset_details"):
        if before[name] != after[name]:
            _die(f"dashboard transition changed {name.replace('_', ' ')}")


def execute_main_transition(  # noqa: PLR0912, PLR0915
    *,
    plan: Mapping[str, Any],
    plan_raw: bytes,
    expected_source_projection_sha256: str,
    expected_authority: Mapping[str, Any],
    expected_governance: MainTransitionGovernance,
    expected_response_content_type: str,
    git_objects: Any,
    transport: GitHubTransitionTransport,
) -> MainTransitionExecution:
    """Create or recover the exact Q0-to-U0 ref through an injected transport.

    The normative v1 plan remains closed. The executor emits an exact v2
    readback because the frozen v1 readback's PATCH carrier cannot truthfully
    represent the official GraphQL ``updateRefs`` compare-and-swap. Raw Git
    objects and the separately versioned CAS evidence remain outside the plan.
    No production transport or CLI activation is supplied here.
    """

    if common.canonical_json(plan, terminal_lf=True) != plan_raw:
        _die("dashboard transition plan bytes are not canonical JSON plus one LF")
    validate_main_transition_plan(
        plan,
        expected_source_projection_sha256=expected_source_projection_sha256,
        expected_authority=expected_authority,
        git_objects=git_objects,
    )
    selected_governance = _validate_selected_governance(expected_governance)
    content_type = _http_header_value(
        expected_response_content_type,
        "expected dashboard transition GitHub response content type",
    )
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        _die("expected dashboard transition response content type is not JSON")
    graph = _transition_graph(git_objects, plan)
    exchanges: list[dict[str, Any]] = []
    old_commit = plan["old"]["commit"]
    old_tree = plan["old"]["tree"]
    target_commit = plan["commit"]["sha"]
    target_tree = plan["commit"]["tree"]

    initial_ref_carrier, initial_ref_body = _github_exchange(
        transport,
        exchanges,
        method="GET",
        url=GITHUB_MAIN_REF_READ_URL,
        body=None,
        expected_status=200,
        expected_response_content_type=content_type,
        context="dashboard transition initial main read",
    )
    initial_head = _git_ref_target(initial_ref_body, "dashboard transition initial main")
    if initial_head == old_commit:
        result = "created-exact-fast-forward"
    elif initial_head == target_commit:
        result = "recovered-existing-exact"
    else:
        _die("dashboard transition main is neither exact Q0 nor exact U0")

    _settings_before_carriers, settings_before = _read_transition_settings(
        transport,
        exchanges,
        selected_governance=selected_governance,
        expected_response_content_type=content_type,
        context="dashboard transition settings before",
    )

    _old_commit_carrier, old_commit_body = _github_exchange(
        transport,
        exchanges,
        method="GET",
        url=_git_object_url("commit", old_commit),
        body=None,
        expected_status=200,
        expected_response_content_type=content_type,
        context="dashboard transition Q0 commit readback",
    )
    _validate_remote_commit(
        old_commit_body,
        expected_sha=old_commit,
        expected_tree=old_tree,
        expected_commit=None,
    )
    for tree_sha in sorted(graph["old_reachable"]):
        _carrier, tree_body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=_git_object_url("tree", tree_sha),
            body=None,
            expected_status=200,
            expected_response_content_type=content_type,
            context=f"dashboard transition Q0 tree {tree_sha} readback",
        )
        _validate_remote_tree(
            tree_body,
            expected_sha=tree_sha,
            expected_raw=graph["tree_raw"][tree_sha],
        )

    cas_evidence: dict[str, Any] | None = None
    cas_evidence_raw: bytes | None = None
    precondition_carrier = initial_ref_carrier
    if result == "created-exact-fast-forward":
        blob_order = sorted(
            graph["blob_raw"],
            key=lambda sha: (graph["blob_paths"][sha].encode("utf-8"), sha),
        )
        for blob_sha in blob_order:
            blob_raw = graph["blob_raw"][blob_sha]
            request_body = common.canonical_json(
                {
                    "content": base64.b64encode(blob_raw).decode("ascii"),
                    "encoding": "base64",
                },
                terminal_lf=False,
            )
            _carrier, created = _github_exchange(
                transport,
                exchanges,
                method="POST",
                url=GITHUB_REPOSITORY_API_URL + "/git/blobs",
                body=request_body,
                expected_status=201,
                expected_response_content_type=content_type,
                context=f"dashboard transition blob {blob_sha} creation",
            )
            _validate_created_object(created, kind="blob", expected_sha=blob_sha)

        tree_order = _tree_creation_order(
            target_tree,
            graph["parsed_trees"],
            graph["old_reachable"],
        )
        for tree_sha in tree_order:
            request_body = common.canonical_json(
                {
                    "tree": _api_tree_entries(
                        graph["tree_raw"][tree_sha],
                        context=f"dashboard transition local tree {tree_sha}",
                    )
                },
                terminal_lf=False,
            )
            _carrier, created = _github_exchange(
                transport,
                exchanges,
                method="POST",
                url=GITHUB_REPOSITORY_API_URL + "/git/trees",
                body=request_body,
                expected_status=201,
                expected_response_content_type=content_type,
                context=f"dashboard transition tree {tree_sha} creation",
            )
            _validate_created_object(created, kind="tree", expected_sha=tree_sha)

        commit_request_body = common.canonical_json(
            {
                "author": {
                    "date": plan["commit"]["author"]["timestamp"],
                    "email": plan["commit"]["author"]["email"],
                    "name": plan["commit"]["author"]["name"],
                },
                "committer": {
                    "date": plan["commit"]["committer"]["timestamp"],
                    "email": plan["commit"]["committer"]["email"],
                    "name": plan["commit"]["committer"]["name"],
                },
                "message": plan["commit"]["message"],
                "parents": [old_commit],
                "tree": target_tree,
            },
            terminal_lf=False,
        )
        _carrier, created_commit = _github_exchange(
            transport,
            exchanges,
            method="POST",
            url=GITHUB_REPOSITORY_API_URL + "/git/commits",
            body=commit_request_body,
            expected_status=201,
            expected_response_content_type=content_type,
            context="dashboard transition U0 commit creation",
        )
        _validate_created_object(created_commit, kind="commit", expected_sha=target_commit)

        precondition_carrier, guarded_ref_body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=GITHUB_MAIN_REF_READ_URL,
            body=None,
            expected_status=200,
            expected_response_content_type=content_type,
            context="dashboard transition immediate Q0 guard",
        )
        if _git_ref_target(guarded_ref_body, "dashboard transition immediate main") != old_commit:
            _die("dashboard transition immediate main guard is not exact Q0")
        cas_evidence, cas_evidence_raw = _github_graphql_cas(
            transport,
            exchanges,
            expected_response_content_type=content_type,
            old={"commit": old_commit, "tree": old_tree},
            repository_id=selected_governance["repository"]["node_id"],
            target={"commit": target_commit, "tree": target_tree},
        )

    final_ref_carrier, final_ref_body = _github_exchange(
        transport,
        exchanges,
        method="GET",
        url=GITHUB_MAIN_REF_READ_URL,
        body=None,
        expected_status=200,
        expected_response_content_type=content_type,
        context="dashboard transition final U0 readback",
    )
    if _git_ref_target(final_ref_body, "dashboard transition final main") != target_commit:
        _die("dashboard transition final main differs from exact U0")

    _new_commit_carrier, new_commit_body = _github_exchange(
        transport,
        exchanges,
        method="GET",
        url=_git_object_url("commit", target_commit),
        body=None,
        expected_status=200,
        expected_response_content_type=content_type,
        context="dashboard transition U0 commit readback",
    )
    _validate_remote_commit(
        new_commit_body,
        expected_sha=target_commit,
        expected_tree=target_tree,
        expected_commit=plan["commit"],
    )
    for tree_sha in sorted(graph["new_reachable"]):
        _carrier, tree_body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=_git_object_url("tree", tree_sha),
            body=None,
            expected_status=200,
            expected_response_content_type=content_type,
            context=f"dashboard transition U0 tree {tree_sha} readback",
        )
        _validate_remote_tree(
            tree_body,
            expected_sha=tree_sha,
            expected_raw=graph["tree_raw"][tree_sha],
        )
    for blob_sha in sorted(
        graph["blob_raw"],
        key=lambda sha: (graph["blob_paths"][sha].encode("utf-8"), sha),
    ):
        _carrier, blob_body = _github_exchange(
            transport,
            exchanges,
            method="GET",
            url=_git_object_url("blob", blob_sha),
            body=None,
            expected_status=200,
            expected_response_content_type=content_type,
            context=f"dashboard transition U0 blob {blob_sha} readback",
        )
        _validate_remote_blob(
            blob_body,
            expected_sha=blob_sha,
            expected_raw=graph["blob_raw"][blob_sha],
        )

    settings_after_carriers, settings_after = _read_transition_settings(
        transport,
        exchanges,
        selected_governance=selected_governance,
        expected_response_content_type=content_type,
        context="dashboard transition settings after",
    )
    _assert_settings_preserved(settings_before, settings_after)

    readback = {
        "format": DIST_TRANSITION_GRAPHQL_READBACK_FORMAT,
        "plan": {"sha256": common.sha256(plan_raw), "size": len(plan_raw)},
        "ref": common.PRODUCER_REF,
        "repository": common.PRODUCER_REPOSITORY,
        "result": result,
        "settings": settings_after_carriers,
        "transition": {
            "cas_evidence": (
                {
                    "sha256": common.sha256(cas_evidence_raw),
                    "size": len(cas_evidence_raw),
                }
                if cas_evidence_raw is not None
                else None
            ),
            "new": {"commit": target_commit, "tree": target_tree},
            "old": {"commit": old_commit, "tree": old_tree},
            "ref_precondition": precondition_carrier,
            "ref_readback": final_ref_carrier,
        },
    }
    validate_main_transition_graphql_readback(
        readback,
        cas_evidence=cas_evidence,
        cas_evidence_raw=cas_evidence_raw,
        plan=plan,
        plan_raw=plan_raw,
        expected_source_projection_sha256=expected_source_projection_sha256,
        expected_authority=expected_authority,
        expected_governance=expected_governance,
        expected_response_content_type=content_type,
        git_objects=git_objects,
    )
    mutation_requests = [
        exchange["request"]
        for exchange in exchanges
        if exchange["request"]["url"] == GITHUB_GRAPHQL_URL
    ]
    if result == "created-exact-fast-forward" and len(mutation_requests) != 1:
        _die("dashboard create transition did not retain one GraphQL CAS request")
    if result == "recovered-existing-exact" and mutation_requests:
        _die("dashboard recovery transition performed a GraphQL mutation")
    if result == "recovered-existing-exact" and any(
        exchange["request"]["method"] != "GET" for exchange in exchanges
    ):
        _die("dashboard recovery transition performed a remote mutation")
    return MainTransitionExecution(
        cas_evidence=cas_evidence,
        exchanges=tuple(exchanges),
        governance_choice=expected_governance.choice,
        mutation_request=mutation_requests[0] if mutation_requests else None,
        precondition_readback=precondition_carrier,
        readback=readback,
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
    observed = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(os.uname().machine)
    if observed is None:
        _die("dashboard generator host architecture is unsupported")
    return observed


def _command_build_platform(args: argparse.Namespace) -> None:
    """Run two clean native dashboard builds after every readiness check."""

    policy, policy_raw = _load(args.policy, terminal_lf=True, context="dashboard authority policy")
    trusted_raw = common.read_regular(
        args.trusted_root,
        maximum=common.MAX_JSON_BYTES,
        context="Sigstore trusted root",
    )
    require_ready(policy, trusted_root_raw=trusted_raw)
    if args.platform != _native_platform():
        _die("build-platform requires a native runner")
    dashboard = policy["dashboard"]
    generator = dashboard["generator"]
    build_poison = _validate_generator_policy(generator)
    if build_poison:
        _die("dashboard build inputs are UNFINALIZED: " + "; ".join(build_poison))

    repo_root = material_build.require_direct_directory(
        args.repo_root, context="dashboard generator repository root"
    )
    package_root = material_build.require_direct_directory(
        repo_root / "packages/z4j", context="dashboard generator package root"
    )
    dockerfile = package_root / GENERATOR_DOCKERFILE
    dockerfile_raw = material_build.read_regular(
        dockerfile,
        maximum=common.MAX_JSON_BYTES,
        context="dashboard generator Dockerfile",
    )
    if (
        common.sha256(dockerfile_raw) != generator["dockerfile"]["sha256"]
        or len(dockerfile_raw) != generator["dockerfile"]["size"]
    ):
        _die("dashboard generator Dockerfile seal differs")
    material_build.validate_generator_dockerfile(
        dockerfile_raw,
        acquisition_marker=b"RUN --network=default",
        offline_markers=(b"RUN --network=none",),
    )
    output_root = material_build.create_empty_private_directory(
        args.output, context="dashboard native build output"
    )
    output_identity = material_build.directory_identity(
        output_root, context="dashboard native build output"
    )
    with material_build.private_temporary_directory(
        prefix="z4j-dashboard-build-context."
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
            executables=tuple(
                sorted(
                    (f"dashboard/{path}" for path in dashboard["source_projection"]["executables"]),
                    key=str.encode,
                )
            ),
            exclusions=tuple(dashboard["source_projection"]["exclusions"]),
        )
        captured = captured_source["files"]
        captured_by_path = {item["path"]: item for item in captured}
        for path in GENERATOR_SOURCE_FILES:
            record = captured_by_path.get(path)
            if (
                record is None
                or {
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                != generator["build_context"]["source_files"][path]
            ):
                _die(f"dashboard build context source seal differs: {path}")
        projection_records = [item for item in captured if item["path"].startswith("dashboard/")]
        projection_raw = material_build.canonical_json(
            {
                "files": projection_records,
                "format": dashboard["source_projection"]["algorithm"],
            },
            terminal_lf=False,
        )
        if (
            common.sha256(projection_raw) != dashboard["source_projection"]["sha256"]
            or len(projection_records) != dashboard["source_projection"]["entries"]
            or sum(item["size"] for item in projection_records)
            != dashboard["source_projection"]["bytes"]
        ):
            _die("dashboard source projection differs from private build context")
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
                "NODE_IMAGE": dashboard["node"]["image"],
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
            executables=tuple(
                sorted(
                    (f"dashboard/{path}" for path in dashboard["source_projection"]["executables"]),
                    key=str.encode,
                )
            ),
            exclusions=tuple(dashboard["source_projection"]["exclusions"]),
        )
        if rechecked != captured_source:
            _die("dashboard generator source changed during native A/B build")
    material_build.require_directory_identity(
        output_root,
        output_identity,
        context="dashboard native build output",
    )
    comparison = material_build.compare_payload_roots(
        output_root / "A/payload", output_root / "B/payload"
    )
    carrier_filename = f"production-dashboard-{ARCHITECTURES[args.platform]}-native-result.tar"
    carrier = material_build.create_platform_result_carrier(
        output_root,
        output_root / carrier_filename,
        filename=carrier_filename,
        material="dashboard",
        platform=args.platform,
    )
    result = {
        "carrier": carrier,
        "comparison": comparison,
        "execution": execution,
        "format": "z4j-production-dashboard-platform-build-v1",
        "platform": args.platform,
        "policy_sha256": common.sha256(policy_raw),
        "source_context": {
            "files": captured,
            "format": "z4j-production-dashboard-build-context-capture-v2",
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
        context="dashboard native build output",
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


def _bind_dashboard_producer_oci(
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
    material_policy = policy["dashboard"]
    platforms: dict[str, Any] = {}
    verification_platforms: dict[str, Any] = {}
    release_seal: dict[str, Any] | None = None
    for platform, architecture in ARCHITECTURES.items():
        derived = aggregation["platforms"][platform]
        builds: list[dict[str, Any]] = []
        for position, build_id in enumerate(("A", "B")):
            root = extraction_root / architecture / build_id
            observed = _producer_hook("_derive_dashboard_platform_build")(
                root,
                platform=platform,
                policy=policy,
            )
            expected = {
                key: item for key, item in derived["builds"][position].items() if key != "id"
            }
            if observed != expected:
                _die(f"dashboard {platform} build {build_id} changed after aggregation")
            builds.append(
                _producer_oci_build_record(
                    build_id,
                    observed,
                    platform_oci[platform].builds[build_id],
                )
            )
            release_raw = material_build.read_regular(
                root / "payload/evidence/pnpm-release.json",
                maximum=material_build.MAX_FILE_BYTES,
                context=f"dashboard {platform} build {build_id} pnpm release receipt",
            )
            observed_release = {"sha256": common.sha256(release_raw), "size": len(release_raw)}
            if release_seal is None:
                release_seal = observed_release
            elif release_seal != observed_release:
                _die("dashboard A/B/platform pnpm release receipt bytes differ")
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
    if release_seal is None:
        _die("dashboard pnpm release receipt seal is absent")
    subject_digest = common.digest(subject_index)
    subject_tag = common.derived_tag(PROFILE, subject_digest, authority=False)
    pnpm = material_policy["pnpm"]
    dashboard = {
        "format": "z4j-production-dashboard-bundle-v1",
        "image": f"{REPOSITORY}:{subject_tag}@{subject_digest}",
        "index": {"digest": subject_digest, "size": len(subject_index)},
        "node": copy.deepcopy(material_policy["node"]),
        "payload_root": PROFILE.payload_root,
        "platforms": platforms,
        "pnpm": {
            "archive_sha256": pnpm["archive_sha256"],
            "archive_size": pnpm["archive_size"],
            "binary_sha256": pnpm["binary_sha256"],
            "binary_size": pnpm["binary_size"],
            "release_receipt_sha256": release_seal["sha256"],
            "release_receipt_size": release_seal["size"],
            "version": pnpm["version"],
        },
        "source_projection": copy.deepcopy(material_policy["source_projection"]),
        "state": "finalized",
    }
    manifest = copy.deepcopy(original_manifest)
    manifest["dashboard"] = dashboard
    verification = {
        "aggregate": {
            "all_platforms_passed": True,
            "builds_byte_identical": True,
            "bundle_tree_byte_identical": True,
            "index_canonical": True,
            "native_platforms": True,
            "pnpm_lock_byte_identical": True,
            "policy_sha256": common.sha256(common.canonical_json(policy, terminal_lf=True)),
            "referrers_native": True,
        },
        "platforms": verification_platforms,
    }
    return finalize.MaterialBinding(
        manifest=manifest,
        material=dashboard,
        readback_extra={},
        source={
            "generator": dict(generator),
            "source_date_epoch": material_policy["source_date_epoch"],
        },
        source_context=aggregation["source_context"],
        verification=verification,
    )


def _producer_adapter() -> Any:
    finalize = _load_finalize_module()
    return finalize.FinalizationAdapter(
        architectures=ARCHITECTURES,
        authority_schema=AUTHORITY_SCHEMA,
        bind_oci_platform_results=_bind_dashboard_producer_oci,
        common=common,
        material_build=material_build,
        material_key="dashboard",
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
        validate_platform_aggregation=_producer_hook("validate_dashboard_platform_aggregation"),
        validate_receipt=validate_receipt,
        validate_subject_index=validate_subject_index,
        validation_errors=(
            DashboardAuthorityError,
            common.CommonAuthorityError,
            material_build.MaterialBuildError,
        ),
    )


def _command_producer_finalize(args: argparse.Namespace) -> None:
    # Only policy/trusted-root bytes may be read before this unconditional gate.
    policy, policy_raw = _load(args.policy, terminal_lf=True, context="dashboard authority policy")
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
        context="dashboard derived platform aggregation",
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
    policy, raw = _load(args.policy, terminal_lf=True, context="dashboard authority policy")
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
    _policy, policy_raw = _load(args.policy, terminal_lf=True, context="dashboard authority policy")
    validate_manifest_authority(manifest, policy_raw)
    sys.stdout.write("dashboard authority manifest selection: valid\n")


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
        DashboardAuthorityError,
        common.CommonAuthorityError,
        material_build.MaterialBuildError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        sys.stderr.write(f"dashboard-authority: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
