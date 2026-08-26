"""Shared byte-level primitives for detached production OCI authorities.

This module is deliberately material-neutral.  Wheelhouse, system-package,
and dashboard helpers provide closed profiles and semantic receipt validators;
the common layer owns strict JSON, OCI R/B/M bytes, Sigstore framing and DER
claims, pinned-Cosign execution, and unambiguous recovery selection.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import contextlib
import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, TypeVar

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
ASCII_TEXT = re.compile(r"[\x21-\x7e]+\Z")
RFC3339_UTC = re.compile(
    r"(?:19|20)\d\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z\Z"
)
FULCIO_OID_ROOT = "1.3.6.1.4.1.57264.1"
RELEASE = "1.9.0"
PRODUCER_REPOSITORY = "dxdevo/z4j"
PRODUCER_REPOSITORY_ID = 1218205297
PRODUCER_REPOSITORY_NODE_ID = "R_kgDOSJxWcQ"
PRODUCER_REF = "refs/heads/main"
PRODUCER_VISIBILITY = "private"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2026-03-10"
REKOR_INTEGRATED_TIME_MINIMUM = 1787458480
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_EMPTY = "application/vnd.oci.empty.v1+json"
SIGSTORE_BUNDLE_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
EMPTY_CONFIG = b"{}"
EMPTY_CONFIG_DESCRIPTOR = {
    "data": "e30=",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "mediaType": OCI_EMPTY,
    "size": 2,
}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_COSIGN_BYTES = 256 * 1024 * 1024
COSIGN_PROCESS_TIMEOUT_SECONDS = 180.0
COSIGN_TERMINATION_TIMEOUT_SECONDS = 5.0
COSIGN_STDOUT_LIMIT = 1024 * 1024
COSIGN_STDERR_LIMIT = 1024 * 1024
COSIGN_AGGREGATE_OUTPUT_LIMIT = 1536 * 1024
COSIGN_READ_CHUNK = 64 * 1024
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_COSIGN_SUPERVISOR_LOCK = threading.Lock()
TRACKED_MANIFEST_ROOT_KEYS = frozenset(
    {
        "dashboard",
        "dashboard_authority",
        "dashboard_authority_policy",
        "finalization",
        "install",
        "kind",
        "python",
        "release",
        "resolver",
        "schema_version",
        "signature_verifier",
        "source_authority",
        "source_tag_authority_policy",
        "state",
        "system_authority",
        "system_authority_policy",
        "system_packages",
        "wheelhouse",
    }
)


class CommonAuthorityError(RuntimeError):
    """A shared production-authority byte or trust invariant failed."""


@dataclass(frozen=True)
class AuthorityProfile:
    """Closed material-owned constants consumed by the common authority layer."""

    artifact_filename: str
    artifact_media_type: str
    artifact_type: str
    authority_tag_pattern: str
    authority_tag_prefix: str
    bundle_filename: str
    bundle_media_type: str
    cleanup_excludes: tuple[str, ...]
    created_transition: str
    environment: str
    material: str
    immutability_patterns: tuple[tuple[str, str], ...]
    oci_tag_patterns: tuple[tuple[str, str], ...]
    payload_root: str
    receipt_format: str
    receipt_filename: str
    receipt_media_type: str
    recovered_transition: str
    repository: str
    subject_tag_pattern: str
    subject_tag_prefix: str
    workflow_identity: str
    workflow_name: str
    workflow_path: str

    def __post_init__(self) -> None:  # noqa: PLR0912 - closed profile invariants
        """Reject malformed or internally inconsistent material constants."""

        if self.artifact_media_type != OCI_MANIFEST:
            _die(f"{self.material} authority manifest media type differs")
        for label, value in (
            ("artifact filename", self.artifact_filename),
            ("artifact type", self.artifact_type),
            ("authority tag prefix", self.authority_tag_prefix),
            ("bundle filename", self.bundle_filename),
            ("bundle media type", self.bundle_media_type),
            ("created transition", self.created_transition),
            ("environment", self.environment),
            ("material", self.material),
            ("payload root", self.payload_root),
            ("receipt filename", self.receipt_filename),
            ("receipt format", self.receipt_format),
            ("receipt media type", self.receipt_media_type),
            ("recovered transition", self.recovered_transition),
            ("repository", self.repository),
            ("subject tag prefix", self.subject_tag_prefix),
            ("workflow identity", self.workflow_identity),
            ("workflow name", self.workflow_name),
            ("workflow path", self.workflow_path),
        ):
            ascii_text(value, f"authority profile {label}")
        if not self.payload_root.startswith("/opt/"):
            _die("authority profile payload root is outside /opt")
        if self.bundle_media_type != SIGSTORE_BUNDLE_V03:
            _die("authority profile bundle media type differs")
        if self.repository.count("/") != 2 or not self.repository.startswith("docker.io/"):
            _die("authority profile repository is not a fixed docker.io repository")
        expected_identity = (
            f"https://github.com/{PRODUCER_REPOSITORY}/{self.workflow_path}@{PRODUCER_REF}"
        )
        if self.workflow_identity != expected_identity:
            _die("authority profile workflow identity/path/ref differ")
        if self.subject_tag_prefix != f"{RELEASE}-digest-":
            _die("authority profile subject tag prefix differs")
        compiled_patterns = {
            self.subject_tag_pattern,
            self.authority_tag_pattern,
            *self.cleanup_excludes,
            *(pattern for _name, pattern in self.immutability_patterns),
            *(pattern for _name, pattern in self.oci_tag_patterns),
        }
        for pattern in compiled_patterns:
            _compile_fullmatch(pattern, f"{self.material} tag pattern")
        if not self.cleanup_excludes or len(set(self.cleanup_excludes)) != len(
            self.cleanup_excludes
        ):
            _die("authority profile cleanup exclusions are empty or duplicated")
        names = [name for name, _pattern in self.immutability_patterns]
        if not names or len(set(names)) != len(names):
            _die("authority profile immutability fields are empty or duplicated")
        if dict(self.immutability_patterns).get("subject_pattern") != self.subject_tag_pattern:
            _die("authority profile subject immutability pattern differs")
        if dict(self.immutability_patterns).get("authority_pattern") != self.authority_tag_pattern:
            _die("authority profile authority immutability pattern differs")
        oci_patterns = dict(self.oci_tag_patterns)
        if oci_patterns.get("subject_tag_pattern") != self.subject_tag_pattern:
            _die("authority profile subject OCI tag pattern differs")
        if oci_patterns.get("authority_tag_pattern") != self.authority_tag_pattern:
            _die("authority profile authority OCI tag pattern differs")


# Kept as a source-compatible spelling for early material helpers.
ArtifactProfile = AuthorityProfile


@dataclass(frozen=True)
class SigstoreIdentity:
    """Exact GitHub Actions identity expected in Cosign and Fulcio claims."""

    issuer: str
    repository: str
    repository_id: int
    repository_owner: str
    repository_owner_id: int
    repository_visibility: str
    ref: str
    sha: str
    workflow_identity: str
    workflow_name: str
    environment: str
    run_invocation_uri: str


@dataclass(frozen=True)
class RecoveryCandidate:
    """Literal durable candidate discovered by tag/referrer enumeration."""

    tag: str
    manifest: bytes
    receipt: bytes
    bundle: bytes


@dataclass(frozen=True)
class BoundedProcessResult:
    """Strict UTF-8 output from one closed, bounded Cosign subprocess."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _CustodiedFile:
    """One owner-private, held-fd file and its immutable post-execution seal."""

    fd: int
    identity: tuple[int, int, int, int, int, int, int, int, int]
    mode: int
    sha256: str
    size: int


T = TypeVar("T")


def _die(message: str) -> NoReturn:
    raise CommonAuthorityError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _die(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_number(value: str) -> NoReturn:
    _die(f"non-integer JSON number {value!r} is forbidden")


def parse_json(raw: bytes, *, context: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _die(f"{context} has a forbidden UTF-8 BOM")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CommonAuthorityError(f"{context} is not strict UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except json.JSONDecodeError as exc:
        raise CommonAuthorityError(f"{context} is not one JSON value") from exc


def canonical_json(value: Any, *, terminal_lf: bool) -> bytes:
    try:
        raw = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CommonAuthorityError("value cannot be canonicalized") from exc
    return raw + (b"\n" if terminal_lf else b"")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw)


def read_regular(path: Path, *, maximum: int, context: str) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise CommonAuthorityError(f"cannot stat {context}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _die(f"{context} must be a regular single-link file")
    if before.st_size > maximum:
        _die(f"{context} exceeds its bounded size")
    try:
        raw = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise CommonAuthorityError(f"cannot read {context}") from exc
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(raw) != before.st_size:
        _die(f"{context} changed while it was read")
    return raw


def load_canonical(
    path: Path,
    *,
    terminal_lf: bool,
    maximum: int = MAX_JSON_BYTES,
    context: str | None = None,
) -> tuple[Any, bytes]:
    label = context or str(path)
    raw = read_regular(path, maximum=maximum, context=label)
    value = parse_json(raw, context=label)
    if canonical_json(value, terminal_lf=terminal_lf) != raw:
        _die(f"{label} is not canonical ASCII JSON with required LF framing")
    return value, raw


def exact_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _die(f"{context} must be one object")
    actual = set(value)
    if actual != keys:
        _die(
            f"{context} keys differ; missing={sorted(keys - actual)}, extra={sorted(actual - keys)}"
        )
    return value


def _compile_fullmatch(pattern: str, context: str) -> re.Pattern[str]:
    ascii_text(pattern, context)
    if not pattern.startswith("^") or not pattern.endswith("$"):
        _die(f"{context} must be explicitly anchored")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise CommonAuthorityError(f"{context} is not a valid expression") from exc
    return compiled


def ascii_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or ASCII_TEXT.fullmatch(value) is None:
        _die(f"{context} must be a nonempty printable ASCII string")
    return value


def nonnegative_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _die(f"{context} must be a nonnegative JSON integer")
    return int(value)


def positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _die(f"{context} must be a positive JSON integer")
    return int(value)


def hex64(value: Any, context: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        _die(f"{context} must be 64 lowercase hex digits")
    return value


def git_sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        _die(f"{context} must be a lowercase 40-character Git object ID")
    return value


def timestamp(value: Any, context: str) -> str:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        _die(f"{context} must be an RFC3339 UTC timestamp with milliseconds")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise CommonAuthorityError(f"{context} is not a real timestamp") from exc
    return value


def https_url(value: Any, context: str, *, expected: str | None = None) -> str:
    text = ascii_text(value, context)
    if not text.startswith("https://") or any(char in text for char in "\r\n\t"):
        _die(f"{context} must be an absolute HTTPS URL")
    if expected is not None and text != expected:
        _die(f"{context} differs")
    return text


def relative_path(value: Any, context: str) -> str:
    text = ascii_text(value, context)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        _die(f"{context} is not a safe relative POSIX path")
    return text


def actor(value: Any, context: str) -> dict[str, Any]:
    result = exact_object(value, {"id", "login", "node_id"}, context)
    positive_int(result["id"], f"{context}.id")
    ascii_text(result["login"], f"{context}.login")
    ascii_text(result["node_id"], f"{context}.node_id")
    return result


def file_seal(value: Any, context: str) -> dict[str, Any]:
    result = exact_object(value, {"sha256", "size"}, context)
    hex64(result["sha256"], f"{context}.sha256")
    positive_int(result["size"], f"{context}.size")
    return result


def path_seal(value: Any, context: str) -> dict[str, Any]:
    result = exact_object(value, {"path", "sha256", "size"}, context)
    relative_path(result["path"], f"{context}.path")
    hex64(result["sha256"], f"{context}.sha256")
    positive_int(result["size"], f"{context}.size")
    return result


def descriptor(
    value: Any,
    context: str,
    *,
    media_type: str | None = None,
) -> dict[str, Any]:
    result = exact_object(value, {"digest", "mediaType", "size"}, context)
    oci_digest(result["digest"], f"{context}.digest")
    ascii_text(result["mediaType"], f"{context}.mediaType")
    positive_int(result["size"], f"{context}.size")
    if media_type is not None and result["mediaType"] != media_type:
        _die(f"{context}.mediaType differs")
    return result


def validate_policy_common(  # noqa: PLR0912, PLR0915 - closed shared policy schema
    profile: AuthorityProfile,
    policy: Any,
    *,
    policy_format: str,
    material_key: str,
    trusted_root_path: str = "docker/production/trust/sigstore-trusted-root.json",
    cutoff_not_before_utc: str = "2026-08-23T04:14:39.107Z",
) -> tuple[dict[str, Any], list[str]]:
    """Validate shared policy sections and return explicit source-only poison fields."""

    value = exact_object(
        policy,
        {
            "artifact",
            "canonicalization",
            "cutoff",
            "format",
            "github",
            material_key,
            "oci",
            "release",
            "signature",
        },
        f"{profile.material} authority policy",
    )
    if value["format"] != policy_format or value["release"] != RELEASE:
        _die(f"{profile.material} policy format/release differs")
    artifact = exact_object(
        value["artifact"],
        {"authority", "bundle", "empty_config", "receipt"},
        "policy.artifact",
    )
    if artifact != {
        "authority": {
            "artifact_type": profile.artifact_type,
            "filename": profile.artifact_filename,
            "manifest_media_type": profile.artifact_media_type,
        },
        "bundle": {
            "filename": profile.bundle_filename,
            "media_type": profile.bundle_media_type,
        },
        "empty_config": {
            "data": "e30=",
            "digest": EMPTY_CONFIG_DESCRIPTOR["digest"],
            "literal": "{}",
            "media_type": OCI_EMPTY,
            "size": 2,
        },
        "receipt": {
            "filename": profile.receipt_filename,
            "media_type": profile.receipt_media_type,
        },
    }:
        _die(f"{profile.material} policy artifact byte/media contract differs")
    canonicalization = exact_object(
        value["canonicalization"],
        {
            "ascii_json",
            "duplicate_keys",
            "ensure_ascii",
            "integers_only",
            "key_order",
            "manifest_terminal_lf",
            "portable_file_terminal_lf_count",
            "separators",
        },
        "policy.canonicalization",
    )
    if canonicalization != {
        "ascii_json": True,
        "duplicate_keys": "reject",
        "ensure_ascii": True,
        "integers_only": True,
        "key_order": "lexicographic",
        "manifest_terminal_lf": False,
        "portable_file_terminal_lf_count": 1,
        "separators": [",", ":"],
    }:
        _die("policy canonicalization contract differs")
    if value["cutoff"] != {
        "not_before_utc": cutoff_not_before_utc,
        "rekor_integrated_time_minimum": REKOR_INTEGRATED_TIME_MINIMUM,
    }:
        _die("policy cutoff contract differs")
    timestamp(cutoff_not_before_utc, "policy cutoff timestamp")

    poison: list[str] = []
    github = exact_object(
        value["github"], {"api", "environment", "repository", "workflow"}, "policy.github"
    )
    if github["api"] != {
        "accept": GITHUB_ACCEPT,
        "base": "https://api.github.com",
        "version": GITHUB_API_VERSION,
    }:
        _die("policy GitHub API contract differs")
    if github["repository"] != {
        "default_branch": "main",
        "full_name": None,
        "id": None,
        "node_id": None,
        "visibility": None,
    }:
        _die("policy unselected producer repository differs")
    poison.append("github.repository authority selection is null")
    environment = exact_object(
        github["environment"],
        {"deployment_branch", "name", "prevent_self_review", "required_reviewer_ids"},
        "policy.github.environment",
    )
    if (
        environment["deployment_branch"] != "main"
        or environment["name"] != profile.environment
        or environment["prevent_self_review"] is not True
    ):
        _die("policy protected environment contract differs")
    reviewer_ids = environment["required_reviewer_ids"]
    if not isinstance(reviewer_ids, list):
        _die("policy required reviewer IDs must be an array")
    for reviewer_id in reviewer_ids:
        positive_int(reviewer_id, "policy required reviewer ID")
    if reviewer_ids != sorted(set(reviewer_ids)):
        _die("policy required reviewer IDs are not strictly sorted")
    if not reviewer_ids:
        poison.append("github.environment.required_reviewer_ids is empty")
    workflow = exact_object(
        github["workflow"],
        {"event", "id", "identity", "node_id", "path", "ref"},
        "policy.github.workflow",
    )
    if {
        "event": workflow["event"],
        "path": workflow["path"],
        "ref": workflow["ref"],
    } != {
        "event": "workflow_dispatch",
        "path": profile.workflow_path,
        "ref": PRODUCER_REF,
    }:
        _die("policy workflow event/path/ref differs")
    if any(workflow[key] is not None for key in ("id", "identity", "node_id")):
        _die("policy unselected workflow authority differs")
    poison.append("github.workflow authority selection is null")

    oci = exact_object(
        value["oci"],
        {
            "api",
            "config_media_type",
            "index_media_type",
            "layer_media_type",
            "manifest_media_type",
            "repository",
            *(name for name, _pattern in profile.oci_tag_patterns),
        },
        "policy.oci",
    )
    if {
        "config_media_type": oci["config_media_type"],
        "index_media_type": oci["index_media_type"],
        "layer_media_type": oci["layer_media_type"],
        "manifest_media_type": oci["manifest_media_type"],
        "repository": oci["repository"],
    } != {
        "config_media_type": OCI_CONFIG,
        "index_media_type": OCI_INDEX,
        "layer_media_type": OCI_LAYER_GZIP,
        "manifest_media_type": OCI_MANIFEST,
        "repository": profile.repository,
    }:
        _die("policy OCI media/repository contract differs")
    for name, pattern in profile.oci_tag_patterns:
        if oci[name] != pattern:
            _die(f"policy OCI {name} differs")
    api = exact_object(
        oci["api"],
        {
            "auth_url",
            "distribution_base",
            "distribution_version",
            "hub_api_base",
            "hub_settings_endpoint",
            "native_referrers",
            "oci_subject_response",
        },
        "policy.oci.api",
    )
    if {key: item for key, item in api.items() if key != "hub_settings_endpoint"} != {
        "auth_url": "https://auth.docker.io/token",
        "distribution_base": "https://registry-1.docker.io",
        "distribution_version": "2",
        "hub_api_base": "https://hub.docker.com/v2",
        "native_referrers": True,
        "oci_subject_response": True,
    }:
        _die("policy OCI API contract differs")
    if api["hub_settings_endpoint"] is None:
        poison.append("oci.api.hub_settings_endpoint is null")
    else:
        https_url(api["hub_settings_endpoint"], "policy.oci.api.hub_settings_endpoint")

    signature = exact_object(
        value["signature"],
        {"bundle_media_type", "cosign", "issuer", "trusted_root", "workflow_identity"},
        "policy.signature",
    )
    if (
        signature["bundle_media_type"] != profile.bundle_media_type
        or signature["issuer"] != OIDC_ISSUER
        or signature["workflow_identity"] is not None
    ):
        _die("policy signature media/issuer or unselected workflow identity differs")
    poison.append("signature.workflow_identity is null")
    cosign = exact_object(signature["cosign"], {"platforms", "version"}, "policy.cosign")
    if cosign["version"] != "3.1.3":
        _die("policy Cosign version differs")
    platform_tools = exact_object(
        cosign["platforms"], {"linux/amd64", "linux/arm64"}, "policy.cosign.platforms"
    )
    for platform, architecture in (("linux/amd64", "amd64"), ("linux/arm64", "arm64")):
        tool = exact_object(
            platform_tools[platform], {"sha256", "size", "url"}, f"policy.cosign.{platform}"
        )
        expected_url = (
            "https://github.com/sigstore/cosign/releases/download/"
            f"v3.1.3/cosign-linux-{architecture}"
        )
        if tool["url"] != expected_url:
            _die(f"policy Cosign {platform} URL differs")
        if tool["sha256"] is None and tool["size"] is None:
            poison.append(f"signature.cosign.platforms.{platform} seal is null")
        elif tool["sha256"] is None or tool["size"] is None:
            _die(f"policy Cosign {platform} seal is partially populated")
        else:
            hex64(tool["sha256"], f"policy Cosign {platform} SHA-256")
            positive_int(tool["size"], f"policy Cosign {platform} size")
    trusted = exact_object(
        signature["trusted_root"],
        {
            "path",
            "sha256",
            "size",
            "target_name",
            "tuf_repository",
            "tuf_root_version",
            "tuf_snapshot_version",
        },
        "policy.signature.trusted_root",
    )
    if {
        "path": trusted["path"],
        "target_name": trusted["target_name"],
        "tuf_repository": trusted["tuf_repository"],
    } != {
        "path": trusted_root_path,
        "target_name": "trusted_root.json",
        "tuf_repository": "https://tuf-repo-cdn.sigstore.dev",
    }:
        _die("policy trusted-root location/target/repository differs")
    nullable = ("sha256", "size", "tuf_root_version", "tuf_snapshot_version")
    if all(trusted[key] is None for key in nullable):
        poison.append("signature.trusted_root seal and TUF versions are null")
    elif any(trusted[key] is None for key in nullable):
        _die("policy trusted-root seal/TUF versions are partially populated")
    else:
        hex64(trusted["sha256"], "policy trusted-root SHA-256")
        positive_int(trusted["size"], "policy trusted-root size")
        positive_int(trusted["tuf_root_version"], "policy TUF root version")
        positive_int(trusted["tuf_snapshot_version"], "policy TUF snapshot version")
    return value, poison


def validate_tracked_selection(
    profile: AuthorityProfile,
    manifest: Any,
    *,
    policy_raw: bytes,
    policy_key: str,
    authority_key: str,
    policy_schema: str,
    policy_release_path: str,
    require_finalized: bool,
) -> dict[str, Any]:
    """Validate generic tracked policy and null-or-realized authority selection."""

    manifest = exact_object(
        manifest,
        set(TRACKED_MANIFEST_ROOT_KEYS),
        "production manifest",
    )
    state = manifest.get("state")
    if state not in {"unfinalized", "finalized"}:
        _die("production manifest state differs")
    tracked_policy = exact_object(
        manifest.get(policy_key),
        {"contract", "location", "required", "schema"},
        f"manifest {profile.material} authority policy",
    )
    if tracked_policy != {
        **tracked_policy,
        "location": "detached-pre-freeze-finalization",
        "required": True,
        "schema": policy_schema,
    }:
        _die(f"manifest {profile.material} authority policy contract differs")
    contract = exact_object(
        tracked_policy["contract"], {"path", "sha256", "size"}, "tracked policy seal"
    )
    if contract["path"] != policy_release_path:
        _die("tracked authority policy release path differs")
    hex64(contract["sha256"], "tracked policy SHA-256")
    positive_int(contract["size"], "tracked policy size")
    if contract["sha256"] != sha256(policy_raw) or contract["size"] != len(policy_raw):
        _die("tracked authority policy seal differs from literal bytes")
    selection = exact_object(
        manifest.get(authority_key),
        {"artifact", "bundle", "receipt", "repository"},
        f"manifest {profile.material} authority selection",
    )
    if selection["repository"] != profile.repository:
        _die(f"manifest {profile.material} authority repository differs")
    artifact = exact_object(
        selection["artifact"], {"digest", "size", "tag"}, "tracked authority artifact"
    )
    bundle = exact_object(selection["bundle"], {"sha256", "size"}, "tracked authority bundle")
    receipt = exact_object(selection["receipt"], {"sha256", "size"}, "tracked authority receipt")
    realized = (
        artifact["digest"],
        artifact["size"],
        artifact["tag"],
        bundle["sha256"],
        bundle["size"],
        receipt["sha256"],
        receipt["size"],
    )
    if state == "unfinalized":
        if any(item is not None for item in realized):
            _die(f"unfinalized manifest selects a realized {profile.material} authority")
        if require_finalized:
            _die(f"{profile.material} authority is intentionally UNFINALIZED")
        return selection
    if any(item is None for item in realized):
        _die(f"finalized manifest has an incomplete {profile.material} authority")
    artifact_digest = oci_digest(artifact["digest"], "tracked authority artifact digest")
    positive_int(artifact["size"], "tracked authority artifact size")
    validate_derived_tag(profile, artifact["tag"], artifact_digest, authority=True)
    file_seal(bundle, "tracked authority bundle")
    file_seal(receipt, "tracked authority receipt")
    return selection


def oci_digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or OCI_DIGEST.fullmatch(value) is None:
        _die(f"{context} must be a lowercase sha256 OCI digest")
    return value


def base64_bytes(value: Any, context: str, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or any(char.isspace() for char in value):
        _die(f"{context} must be canonical padded base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CommonAuthorityError(f"{context} is invalid base64") from exc
    if (not raw and not allow_empty) or base64.b64encode(raw).decode("ascii") != value:
        _die(f"{context} is not canonical padded base64")
    return raw


def validate_github_response(
    value: Any,
    context: str,
    *,
    method: str = "GET",
) -> tuple[dict[str, Any], bytes]:
    """Validate a credential-free retained GitHub JSON response and its body seal."""

    response = exact_object(
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
    body = base64_bytes(response["body_base64"], f"{context}.body_base64", allow_empty=True)
    hex64(response["body_sha256"], f"{context}.body_sha256")
    nonnegative_int(response["body_size"], f"{context}.body_size")
    if response["body_sha256"] != sha256(body) or response["body_size"] != len(body):
        _die(f"{context} retained body seal differs")
    if (
        response["method"] != method
        or response["request_accept"] != GITHUB_ACCEPT
        or response["request_api_version"] != GITHUB_API_VERSION
    ):
        _die(f"{context} GitHub request contract differs")
    ascii_text(response["response_content_type"], f"{context}.response_content_type")
    positive_int(response["status"], f"{context}.status")
    https_url(response["url"], f"{context}.url")
    parse_json(body, context=f"{context} retained JSON body")
    return response, body


def validate_dockerhub_response(
    value: Any,
    context: str,
) -> tuple[dict[str, Any], bytes]:
    """Validate a credential-free retained Docker Hub JSON response."""

    response = exact_object(
        value,
        {
            "body_base64",
            "body_sha256",
            "body_size",
            "method",
            "request_accept",
            "response_content_type",
            "status",
            "url",
        },
        context,
    )
    body = base64_bytes(response["body_base64"], f"{context}.body_base64", allow_empty=True)
    hex64(response["body_sha256"], f"{context}.body_sha256")
    nonnegative_int(response["body_size"], f"{context}.body_size")
    if response["body_sha256"] != sha256(body) or response["body_size"] != len(body):
        _die(f"{context} retained body seal differs")
    if response["method"] != "GET" or response["request_accept"] != "application/json":
        _die(f"{context} Docker Hub request contract differs")
    ascii_text(response["response_content_type"], f"{context}.response_content_type")
    positive_int(response["status"], f"{context}.status")
    https_url(response["url"], f"{context}.url")
    parse_json(body, context=f"{context} retained JSON body")
    return response, body


def validate_oci_manifest_response(
    value: Any,
    context: str,
) -> tuple[dict[str, Any], bytes]:
    """Validate an exact raw OCI manifest/index GET response and body seal."""

    response = exact_object(
        value,
        {
            "body_base64",
            "body_sha256",
            "body_size",
            "docker_content_digest",
            "method",
            "request_accept",
            "response_content_type",
            "status",
            "url",
        },
        context,
    )
    body = base64_bytes(response["body_base64"], f"{context}.body_base64")
    hex64(response["body_sha256"], f"{context}.body_sha256")
    positive_int(response["body_size"], f"{context}.body_size")
    oci_digest(response["docker_content_digest"], f"{context}.docker_content_digest")
    if (
        response["body_sha256"] != sha256(body)
        or response["body_size"] != len(body)
        or response["docker_content_digest"] != digest(body)
    ):
        _die(f"{context} raw OCI response seal differs")
    if response["method"] != "GET" or response["status"] != 200:
        _die(f"{context} is not one successful raw OCI GET")
    ascii_text(response["request_accept"], f"{context}.request_accept")
    ascii_text(response["response_content_type"], f"{context}.response_content_type")
    https_url(response["url"], f"{context}.url")
    return response, body


def validate_oci_blob_response(value: Any, context: str) -> dict[str, Any]:
    response = exact_object(
        value,
        {
            "docker_content_digest",
            "method",
            "request_accept",
            "sha256",
            "size",
            "status",
            "url",
        },
        context,
    )
    oci_digest(response["docker_content_digest"], f"{context}.docker_content_digest")
    hex64(response["sha256"], f"{context}.sha256")
    positive_int(response["size"], f"{context}.size")
    if response["docker_content_digest"] != "sha256:" + response["sha256"]:
        _die(f"{context} blob digest and SHA-256 differ")
    if (
        response["method"] != "GET"
        or response["request_accept"] != "application/octet-stream"
        or response["status"] != 200
    ):
        _die(f"{context} blob response contract differs")
    https_url(response["url"], f"{context}.url")
    return response


def validate_oci_put_response(
    value: Any,
    context: str,
    *,
    expected_digest: str,
    expected_subject: str | None,
) -> dict[str, Any]:
    response = exact_object(
        value,
        {"docker_content_digest", "location", "oci_subject", "status", "url"},
        context,
    )
    oci_digest(expected_digest, f"{context} expected digest")
    if expected_subject is not None:
        oci_digest(expected_subject, f"{context} expected subject")
    if (
        response["docker_content_digest"] != expected_digest
        or response["oci_subject"] != expected_subject
        or response["status"] != 201
    ):
        _die(f"{context} digest/subject/status differs")
    https_url(response["location"], f"{context}.location")
    https_url(response["url"], f"{context}.url")
    return response


def derived_tag(profile: AuthorityProfile, value_digest: str, *, authority: bool) -> str:
    oci_digest(value_digest, "content-derived tag digest")
    prefix = profile.authority_tag_prefix if authority else profile.subject_tag_prefix
    return prefix + value_digest.removeprefix("sha256:")


def validate_derived_tag(
    profile: AuthorityProfile,
    value: Any,
    value_digest: str,
    *,
    authority: bool,
) -> str:
    tag = ascii_text(value, f"{profile.material} content-derived tag")
    pattern = profile.authority_tag_pattern if authority else profile.subject_tag_pattern
    if _compile_fullmatch(pattern, f"{profile.material} tag pattern").fullmatch(tag) is None:
        _die(f"{profile.material} content-derived tag does not match its exact pattern")
    if tag != derived_tag(profile, value_digest, authority=authority):
        _die(f"{profile.material} content-derived tag suffix and digest differ")
    return tag


def validate_exact_manifest_readback_pair(
    by_tag: Any,
    by_digest: Any,
    *,
    expected_digest: str,
    expected_size: int,
    context: str,
) -> bytes:
    """Require tag and digest GETs to return one identical literal OCI object."""

    tag_response, tag_raw = validate_oci_manifest_response(by_tag, f"{context} by tag")
    digest_response, digest_raw = validate_oci_manifest_response(by_digest, f"{context} by digest")
    oci_digest(expected_digest, f"{context} expected digest")
    positive_int(expected_size, f"{context} expected size")
    if (
        tag_raw != digest_raw
        or len(tag_raw) != expected_size
        or digest(tag_raw) != expected_digest
        or tag_response["docker_content_digest"] != expected_digest
        or digest_response["docker_content_digest"] != expected_digest
    ):
        _die(f"{context} tag/digest literal readbacks differ")
    return tag_raw


def validate_native_referrers(  # noqa: PLR0912 - closed OCI descriptor state machine
    pages: Sequence[bytes],
    *,
    authority_digest: str,
    authority_size: int,
    artifact_type: str,
) -> dict[str, Any]:
    """Require native paginated referrers to semantically include selected K."""

    oci_digest(authority_digest, "selected referrer digest")
    positive_int(authority_size, "selected referrer size")
    ascii_text(artifact_type, "selected referrer artifact type")
    if not pages:
        _die("native referrers returned no HTTP-200 page")
    selected: dict[str, Any] | None = None
    for page_number, raw in enumerate(pages):
        value = parse_json(raw, context=f"native referrers page {page_number}")
        page = exact_object(
            value,
            {"manifests", "mediaType", "schemaVersion"},
            f"native referrers page {page_number}",
        )
        if page["mediaType"] != OCI_INDEX or page["schemaVersion"] != 2:
            _die("native referrers page media/schema differs")
        manifests = page["manifests"]
        if not isinstance(manifests, list):
            _die("native referrers manifests must be an array")
        for descriptor_number, candidate in enumerate(manifests):
            context = f"native referrers page {page_number} descriptor {descriptor_number}"
            if not isinstance(candidate, dict):
                _die(f"{context} must be one object")
            allowed = {"annotations", "artifactType", "digest", "mediaType", "size"}
            if set(candidate) - allowed or not {"digest", "mediaType", "size"} <= set(candidate):
                _die(f"{context} has a non-OCI or incomplete descriptor shape")
            oci_digest(candidate["digest"], f"{context}.digest")
            ascii_text(candidate["mediaType"], f"{context}.mediaType")
            positive_int(candidate["size"], f"{context}.size")
            if "artifactType" in candidate:
                ascii_text(candidate["artifactType"], f"{context}.artifactType")
            if "annotations" in candidate and not isinstance(candidate["annotations"], dict):
                _die(f"{context}.annotations must be one object")
            if candidate["digest"] != authority_digest:
                continue
            expected = {
                "artifactType": artifact_type,
                "digest": authority_digest,
                "mediaType": OCI_MANIFEST,
                "size": authority_size,
            }
            projection = {key: candidate.get(key) for key in expected}
            if projection != expected:
                _die("selected authority referrer descriptor differs")
            if selected is not None and selected != candidate:
                _die("native referrers contain conflicting selected authority descriptors")
            selected = candidate
    if selected is None:
        _die("native referrers do not include the selected authority digest")
    return selected


def validate_ceremony(
    profile: AuthorityProfile,
    value: Any,
    *,
    generator_commit: str,
    expected_workflow_id: int | None = None,
    expected_workflow_node_id: str | None = None,
) -> dict[str, Any]:
    """Validate the shared private attempt-1 protected-environment ceremony."""

    git_sha(generator_commit, "generator commit")
    ceremony = exact_object(
        value,
        {
            "actor",
            "deployment",
            "environment",
            "event",
            "head_sha",
            "ref",
            "run_api_url",
            "run_attempt",
            "run_id",
            "run_invocation_uri",
            "triggering_actor",
            "workflow",
        },
        f"{profile.material} ceremony",
    )
    current_actor = actor(ceremony["actor"], "ceremony.actor")
    triggering_actor = actor(ceremony["triggering_actor"], "ceremony.triggering_actor")
    if current_actor != triggering_actor:
        _die("attempt-1 workflow_dispatch actor and triggering actor differ")
    if (
        ceremony["environment"] != profile.environment
        or ceremony["event"] != "workflow_dispatch"
        or ceremony["head_sha"] != generator_commit
        or ceremony["ref"] != PRODUCER_REF
        or ceremony["run_attempt"] != 1
    ):
        _die(f"{profile.material} ceremony environment/event/head/ref/attempt differs")
    run_id = positive_int(ceremony["run_id"], "ceremony.run_id")
    run_api_url = f"https://api.github.com/repos/{PRODUCER_REPOSITORY}/actions/runs/{run_id}"
    run_invocation_uri = (
        f"https://github.com/{PRODUCER_REPOSITORY}/actions/runs/{run_id}/attempts/1"
    )
    https_url(ceremony["run_api_url"], "ceremony.run_api_url", expected=run_api_url)
    https_url(
        ceremony["run_invocation_uri"],
        "ceremony.run_invocation_uri",
        expected=run_invocation_uri,
    )
    deployment = exact_object(
        ceremony["deployment"],
        {"created_at", "environment", "id", "node_id", "reviewer", "sha"},
        "ceremony.deployment",
    )
    timestamp(deployment["created_at"], "ceremony.deployment.created_at")
    if deployment["environment"] != profile.environment or deployment["sha"] != generator_commit:
        _die("ceremony deployment environment/SHA differs")
    positive_int(deployment["id"], "ceremony.deployment.id")
    ascii_text(deployment["node_id"], "ceremony.deployment.node_id")
    reviewer = actor(deployment["reviewer"], "ceremony.deployment.reviewer")
    if reviewer in (current_actor, triggering_actor):
        _die("protected-environment reviewer must differ from workflow actors")
    workflow = exact_object(
        ceremony["workflow"],
        {
            "blob_sha",
            "file_sha256",
            "file_size",
            "id",
            "identity",
            "node_id",
            "path",
            "ref",
            "sha",
        },
        "ceremony.workflow",
    )
    git_sha(workflow["blob_sha"], "ceremony.workflow.blob_sha")
    hex64(workflow["file_sha256"], "ceremony.workflow.file_sha256")
    positive_int(workflow["file_size"], "ceremony.workflow.file_size")
    positive_int(workflow["id"], "ceremony.workflow.id")
    ascii_text(workflow["node_id"], "ceremony.workflow.node_id")
    if (
        workflow["identity"] != profile.workflow_identity
        or workflow["path"] != profile.workflow_path
        or workflow["ref"] != PRODUCER_REF
        or workflow["sha"] != generator_commit
    ):
        _die(f"{profile.material} ceremony workflow identity/path/ref/SHA differs")
    if expected_workflow_id is not None and workflow["id"] != expected_workflow_id:
        _die("ceremony workflow ID differs from the reviewed policy")
    if expected_workflow_node_id is not None and workflow["node_id"] != expected_workflow_node_id:
        _die("ceremony workflow node ID differs from the reviewed policy")
    return ceremony


def validate_protection(  # noqa: PLR0912 - closed protection schema
    profile: AuthorityProfile,
    value: Any,
    *,
    ceremony: Mapping[str, Any],
    expected_workflow_id: int | None = None,
    expected_workflow_node_id: str | None = None,
) -> dict[str, Any]:
    """Validate shared GitHub/Docker Hub least-privilege protection evidence."""

    protection = exact_object(value, {"dockerhub", "github"}, "protection")
    dockerhub = exact_object(
        protection["dockerhub"],
        {"cleanup", "immutability", "publisher", "repository"},
        "protection.dockerhub",
    )
    if dockerhub["repository"] != profile.repository:
        _die("Docker Hub protected repository differs")
    if dockerhub["cleanup"] != {"excludes": list(profile.cleanup_excludes)}:
        _die("Docker Hub cleanup exclusions differ")
    if dockerhub["immutability"] != dict(profile.immutability_patterns):
        _die("Docker Hub immutable-tag rules differ")
    publisher = exact_object(
        dockerhub["publisher"],
        {"can_admin", "can_delete", "can_pull", "can_push", "id"},
        "protection.dockerhub.publisher",
    )
    if publisher != {
        **publisher,
        "can_admin": False,
        "can_delete": False,
        "can_pull": True,
        "can_push": True,
    }:
        _die("Docker Hub publisher is not least-privileged pull/push only")
    ascii_text(publisher["id"], "protection.dockerhub.publisher.id")

    github = exact_object(
        protection["github"],
        {"actions", "environment", "main", "repository", "workflow"},
        "protection.github",
    )
    if github["actions"] != {
        "allowed_actions": "selected",
        "can_approve_pull_request_reviews": False,
        "default_workflow_permissions": "read",
        "sha_pinning_required": True,
    }:
        _die("GitHub Actions protection differs")
    if github["repository"] != {
        "default_branch": "main",
        "full_name": PRODUCER_REPOSITORY,
        "id": PRODUCER_REPOSITORY_ID,
        "node_id": PRODUCER_REPOSITORY_NODE_ID,
        "visibility": PRODUCER_VISIBILITY,
    }:
        _die("protected private GitHub repository identity differs")
    main = exact_object(
        github["main"],
        {
            "blocks_deletion",
            "blocks_force_push",
            "dismisses_stale_reviews",
            "enforcement",
            "id",
            "name",
            "requires_code_owner_review",
            "requires_last_push_approval",
            "requires_pull_request",
            "required_approving_review_count",
        },
        "protection.github.main",
    )
    for key in (
        "blocks_deletion",
        "blocks_force_push",
        "dismisses_stale_reviews",
        "requires_code_owner_review",
        "requires_last_push_approval",
        "requires_pull_request",
    ):
        if main[key] is not True:
            _die(f"GitHub main protection {key} is not true")
    if main["enforcement"] != "active":
        _die("GitHub main ruleset is not active")
    positive_int(main["id"], "protection.github.main.id")
    ascii_text(main["name"], "protection.github.main.name")
    positive_int(
        main["required_approving_review_count"],
        "protection.github.main.required_approving_review_count",
    )
    workflow = exact_object(
        github["workflow"],
        {"enabled", "id", "node_id", "path"},
        "protection.github.workflow",
    )
    if workflow["enabled"] is not True or workflow["path"] != profile.workflow_path:
        _die("protected producer workflow differs or is disabled")
    positive_int(workflow["id"], "protection.github.workflow.id")
    ascii_text(workflow["node_id"], "protection.github.workflow.node_id")
    if expected_workflow_id is not None and workflow["id"] != expected_workflow_id:
        _die("protected workflow ID differs from the reviewed policy")
    if expected_workflow_node_id is not None and workflow["node_id"] != expected_workflow_node_id:
        _die("protected workflow node ID differs from the reviewed policy")
    environment = exact_object(
        github["environment"],
        {"deployment_branch", "name", "prevent_self_review", "required_reviewers"},
        "protection.github.environment",
    )
    if environment != {
        **environment,
        "deployment_branch": "main",
        "name": profile.environment,
        "prevent_self_review": True,
    }:
        _die("protected environment contract differs")
    reviewers = environment["required_reviewers"]
    if not isinstance(reviewers, list):
        _die("protected environment reviewers must be an array")
    normalized = [actor(item, "protected environment reviewer") for item in reviewers]
    reviewer_ids = [item["id"] for item in normalized]
    if not reviewer_ids or reviewer_ids != sorted(set(reviewer_ids)):
        _die("protected environment reviewers must be nonempty and strictly ID-sorted")
    if ceremony["deployment"]["reviewer"] not in normalized:
        _die("ceremony reviewer is not an authenticated required reviewer")
    return protection


def validate_transition(
    profile: AuthorityProfile,
    value: Any,
    *,
    generator_commit: str,
    expected_workflow_id: int | None = None,
) -> dict[str, Any]:
    """Validate the shared absent-create or authenticated exact-recovery choice."""

    transition = exact_object(
        value,
        {"kind", "prior_run", "subject_tag_put_by_current_run"},
        "transition",
    )
    if transition["kind"] == profile.created_transition:
        if (
            transition["prior_run"] is not None
            or transition["subject_tag_put_by_current_run"] is not True
        ):
            _die("created subject transition shape differs")
        return transition
    if transition["kind"] != profile.recovered_transition:
        _die(f"{profile.material} subject transition kind differs")
    if transition["subject_tag_put_by_current_run"] is not False:
        _die("recovery transition claims a current-run subject tag PUT")
    prior = exact_object(
        transition["prior_run"],
        {
            "attempt",
            "conclusion",
            "event",
            "head_sha",
            "id",
            "jobs_response",
            "run_response",
            "workflow_id",
        },
        "transition.prior_run",
    )
    if (
        prior["attempt"] != 1
        or prior["conclusion"] not in {"failure", "cancelled", "timed_out"}
        or prior["event"] != "workflow_dispatch"
        or prior["head_sha"] != generator_commit
    ):
        _die("prior recovery run conclusion/event/attempt/head differs")
    positive_int(prior["id"], "transition.prior_run.id")
    positive_int(prior["workflow_id"], "transition.prior_run.workflow_id")
    if expected_workflow_id is not None and prior["workflow_id"] != expected_workflow_id:
        _die("prior recovery run workflow ID differs")
    validate_github_response(prior["jobs_response"], "transition.prior_run.jobs_response")
    validate_github_response(prior["run_response"], "transition.prior_run.run_response")
    return transition


def _validate_dockerhub_snapshot(value: Any, context: str) -> dict[str, Any]:
    snapshot = exact_object(
        value,
        {"cleanup", "immutability", "publisher", "repository"},
        context,
    )
    for key in ("cleanup", "immutability", "publisher", "repository"):
        validate_dockerhub_response(snapshot[key], f"{context}.{key}")
    return snapshot


def validate_readback(
    profile: AuthorityProfile,
    value: Any,
    *,
    subject_digest: str,
    subject_size: int,
    transition_kind: str,
    platforms: Sequence[str] = ("linux/amd64", "linux/arm64"),
    extra_top_keys: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Validate common pre-AM GitHub, registry, and settings raw readbacks."""

    oci_digest(subject_digest, "readback subject digest")
    positive_int(subject_size, "readback subject size")
    readback = exact_object(
        value,
        {"dockerhub", "github", "oci", *extra_top_keys},
        "readback",
    )
    dockerhub = exact_object(
        readback["dockerhub"],
        {"after_subject", "before_sign", "before_subject"},
        "readback.dockerhub",
    )
    for key in ("before_subject", "after_subject", "before_sign"):
        _validate_dockerhub_snapshot(dockerhub[key], f"readback.dockerhub.{key}")
    github = exact_object(
        readback["github"],
        {
            "actions_permissions",
            "environment",
            "main_protection",
            "repository",
            "rulesets",
            "workflow",
            "workflow_jobs",
            "workflow_run",
        },
        "readback.github",
    )
    for key in sorted(github):
        validate_github_response(github[key], f"readback.github.{key}")
    oci = exact_object(
        readback["oci"],
        {
            "index_by_digest",
            "index_by_tag",
            "platforms",
            "referrers_capability",
            "subject_tag_precondition",
            "subject_tag_put",
        },
        "readback.oci",
    )
    validate_exact_manifest_readback_pair(
        oci["index_by_tag"],
        oci["index_by_digest"],
        expected_digest=subject_digest,
        expected_size=subject_size,
        context=f"{profile.material} subject index",
    )
    validate_oci_manifest_response(oci["referrers_capability"], "readback.oci.referrers_capability")
    platform_values = exact_object(oci["platforms"], set(platforms), "readback.oci.platforms")
    for platform in platforms:
        platform_value = exact_object(
            platform_values[platform],
            {"config", "layer", "manifest"},
            f"readback.oci.platforms.{platform}",
        )
        validate_oci_manifest_response(
            platform_value["config"], f"readback.oci.platforms.{platform}.config"
        )
        validate_oci_blob_response(
            platform_value["layer"], f"readback.oci.platforms.{platform}.layer"
        )
        validate_oci_manifest_response(
            platform_value["manifest"], f"readback.oci.platforms.{platform}.manifest"
        )
    precondition = exact_object(
        oci["subject_tag_precondition"],
        {"existing_digest", "status", "url"},
        "readback.oci.subject_tag_precondition",
    )
    https_url(precondition["url"], "readback.oci.subject_tag_precondition.url")
    if transition_kind == profile.created_transition:
        if precondition["existing_digest"] is not None or precondition["status"] != 404:
            _die("create transition did not observe an absent subject tag")
        validate_oci_put_response(
            oci["subject_tag_put"],
            "readback.oci.subject_tag_put",
            expected_digest=subject_digest,
            expected_subject=None,
        )
    elif transition_kind == profile.recovered_transition:
        if (
            precondition["existing_digest"] != subject_digest
            or precondition["status"] != 200
            or oci["subject_tag_put"] is not None
        ):
            _die("recovery transition did not reuse exact S without a PUT")
    else:
        _die(f"{profile.material} transition kind differs")
    return readback


def validate_index(
    raw: bytes,
    *,
    expected_platforms: Sequence[tuple[str, str]],
    expected_descriptors: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    value = parse_json(raw, context="production authority subject index")
    if canonical_json(value, terminal_lf=False) != raw:
        _die("production authority subject index is not canonical no-LF JSON")
    index = exact_object(value, {"manifests", "mediaType", "schemaVersion"}, "subject index")
    if index["mediaType"] != OCI_INDEX or index["schemaVersion"] != 2:
        _die("subject index media/schema differs")
    manifests = index["manifests"]
    if not isinstance(manifests, list) or len(manifests) != len(expected_platforms):
        _die("subject index platform descriptor count differs")
    for position, (platform, architecture) in enumerate(expected_platforms):
        descriptor = exact_object(
            manifests[position], {"digest", "mediaType", "platform", "size"}, f"index {platform}"
        )
        oci_digest(descriptor["digest"], f"index {platform} digest")
        positive_int(descriptor["size"], f"index {platform} size")
        if descriptor["mediaType"] != OCI_MANIFEST or descriptor["platform"] != {
            "architecture": architecture,
            "os": "linux",
        }:
            _die(f"index {platform} descriptor differs")
        if expected_descriptors is not None:
            expected = expected_descriptors[platform]
            if descriptor["digest"] != expected["digest"] or descriptor["size"] != expected["size"]:
                _die(f"index {platform} descriptor is not the selected literal leaf")
    return index


def validate_leaf(
    raw: bytes,
    *,
    expected_config: Mapping[str, Any] | None = None,
    expected_layer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value = parse_json(raw, context="production authority subject leaf")
    if canonical_json(value, terminal_lf=False) != raw:
        _die("production authority subject leaf is not canonical no-LF JSON")
    leaf = exact_object(value, {"config", "layers", "mediaType", "schemaVersion"}, "subject leaf")
    if leaf["mediaType"] != OCI_MANIFEST or leaf["schemaVersion"] != 2:
        _die("subject leaf media/schema differs")
    config = exact_object(leaf["config"], {"digest", "mediaType", "size"}, "leaf config")
    oci_digest(config["digest"], "leaf config digest")
    positive_int(config["size"], "leaf config size")
    if config["mediaType"] != OCI_CONFIG:
        _die("leaf config media type differs")
    layers = leaf["layers"]
    if not isinstance(layers, list) or len(layers) != 1:
        _die("subject leaf must have one distributable gzip layer")
    layer = exact_object(layers[0], {"digest", "mediaType", "size"}, "leaf layer")
    oci_digest(layer["digest"], "leaf layer digest")
    positive_int(layer["size"], "leaf layer size")
    if layer["mediaType"] != OCI_LAYER_GZIP:
        _die("leaf layer media type differs")
    if expected_config is not None and config != dict(expected_config):
        _die("leaf config descriptor differs from selected config")
    if expected_layer is not None and layer != dict(expected_layer):
        _die("leaf layer descriptor differs from selected layer")
    return leaf


def validate_config(raw: bytes, *, architecture: str, layer_diff_id: str) -> dict[str, Any]:
    value = parse_json(raw, context="production authority subject config")
    if canonical_json(value, terminal_lf=False) != raw:
        _die("production authority subject config is not canonical no-LF JSON")
    config = exact_object(value, {"architecture", "config", "os", "rootfs"}, "subject config")
    oci_digest(layer_diff_id, "subject layer diff-ID")
    if config != {
        "architecture": architecture,
        "config": {},
        "os": "linux",
        "rootfs": {"diff_ids": [layer_diff_id], "type": "layers"},
    }:
        _die("subject config architecture/rootfs differs")
    return config


def build_artifact_manifest(
    profile: ArtifactProfile,
    *,
    receipt_raw: bytes,
    bundle_raw: bytes,
    subject_digest: str,
    subject_size: int,
) -> bytes:
    oci_digest(subject_digest, "artifact subject digest")
    positive_int(subject_size, "artifact subject size")
    value = {
        "artifactType": profile.artifact_type,
        "config": EMPTY_CONFIG_DESCRIPTOR,
        "layers": [
            {
                "annotations": {"org.opencontainers.image.title": profile.receipt_filename},
                "digest": digest(receipt_raw),
                "mediaType": profile.receipt_media_type,
                "size": len(receipt_raw),
            },
            {
                "annotations": {"org.opencontainers.image.title": profile.bundle_filename},
                "digest": digest(bundle_raw),
                "mediaType": profile.bundle_media_type,
                "size": len(bundle_raw),
            },
        ],
        "mediaType": profile.artifact_media_type,
        "schemaVersion": 2,
        "subject": {"digest": subject_digest, "mediaType": OCI_INDEX, "size": subject_size},
    }
    return canonical_json(value, terminal_lf=False)


def validate_artifact_manifest(
    profile: ArtifactProfile,
    raw: bytes,
    *,
    receipt_raw: bytes,
    bundle_raw: bytes,
    subject_digest: str,
    subject_size: int,
    selected_tag: str | None = None,
) -> dict[str, Any]:
    expected = build_artifact_manifest(
        profile,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject_digest=subject_digest,
        subject_size=subject_size,
    )
    if raw != expected:
        _die("authority artifact manifest differs from exact R/B/subject graph")
    if selected_tag is not None:
        validate_derived_tag(
            profile,
            selected_tag,
            digest(raw),
            authority=True,
        )
    value = parse_json(raw, context="authority artifact manifest")
    return exact_object(
        value,
        {"artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"},
        "authority artifact manifest",
    )


def validate_bundle(
    raw: bytes,
    *,
    receipt_raw: bytes,
    integrated_time_minimum: int,
) -> dict[str, Any]:
    value = parse_json(raw, context="Sigstore bundle")
    if canonical_json(value, terminal_lf=True) != raw:
        _die("Sigstore bundle is not canonical JSON plus exactly one LF")
    bundle = exact_object(
        value, {"mediaType", "messageSignature", "verificationMaterial"}, "Sigstore bundle"
    )
    if bundle["mediaType"] != SIGSTORE_BUNDLE_V03:
        _die("Sigstore bundle media type differs")
    message = exact_object(
        bundle["messageSignature"], {"messageDigest", "signature"}, "bundle signature"
    )
    message_digest = exact_object(
        message["messageDigest"], {"algorithm", "digest"}, "bundle message digest"
    )
    if (
        message_digest["algorithm"] != "SHA2_256"
        or base64_bytes(message_digest["digest"], "bundle message digest")
        != hashlib.sha256(receipt_raw).digest()
    ):
        _die("Sigstore bundle does not bind the literal receipt SHA-256")
    base64_bytes(message["signature"], "bundle signature")
    material = bundle["verificationMaterial"]
    if not isinstance(material, dict):
        _die("bundle verification material must be one object")
    allowed = {"certificate", "tlogEntries", "timestampVerificationData"}
    if set(material) - allowed or "certificate" not in material or "publicKey" in material:
        _die("bundle must use closed certificate verification material")
    certificate = exact_object(material["certificate"], {"rawBytes"}, "bundle certificate")
    base64_bytes(certificate["rawBytes"], "bundle certificate raw bytes")
    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or not entries:
        _die("bundle has no transparency-log entry")
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or not entry:
            _die(f"bundle tlog entry {position} is malformed")
        integrated = entry.get("integratedTime")
        if isinstance(integrated, str) and integrated.isdecimal():
            integrated_value = int(integrated)
        elif isinstance(integrated, int) and not isinstance(integrated, bool):
            integrated_value = integrated
        else:
            _die(f"bundle tlog entry {position} integratedTime is malformed")
        if integrated_value < integrated_time_minimum:
            _die("bundle Rekor integrated time predates the required cutoff")
    return bundle


def _der_tlv(raw: bytes, offset: int, context: str) -> tuple[int, bytes, int]:
    if offset < 0 or offset >= len(raw):
        _die(f"{context} DER is truncated")
    tag = raw[offset]
    if tag & 0x1F == 0x1F:
        _die(f"{context} DER uses high-tag form")
    offset += 1
    if offset >= len(raw):
        _die(f"{context} DER length is truncated")
    first = raw[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        octets = first & 0x7F
        if octets == 0 or octets > 4 or offset + octets > len(raw):
            _die(f"{context} DER length is invalid")
        encoded = raw[offset : offset + octets]
        if encoded[0] == 0:
            _die(f"{context} DER length is not minimal")
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            _die(f"{context} DER long length is not minimal")
        offset += octets
    end = offset + length
    if end > len(raw):
        _die(f"{context} DER value is truncated")
    return tag, raw[offset:end], end


def _der_oid(raw: bytes, context: str) -> str:
    if not raw:
        _die(f"{context} OID is empty")
    first = raw[0]
    arcs = [0, first] if first < 40 else ([1, first - 40] if first < 80 else [2, first - 80])
    value = 0
    in_arc = False
    for byte in raw[1:]:
        if not in_arc and byte == 0x80:
            _die(f"{context} OID arc is not minimal")
        in_arc = True
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            in_arc = False
    if in_arc:
        _die(f"{context} OID is truncated")
    return ".".join(str(arc) for arc in arcs)


def fulcio_extensions(  # noqa: PLR0912, PLR0915 - strict DER parser
    certificate_raw: bytes,
) -> dict[str, str]:
    tag, certificate, end = _der_tlv(certificate_raw, 0, "Fulcio certificate")
    if tag != 0x30 or end != len(certificate_raw):
        _die("Fulcio certificate outer DER differs")
    tag, tbs, _ = _der_tlv(certificate, 0, "Fulcio TBSCertificate")
    if tag != 0x30:
        _die("Fulcio TBSCertificate is not a sequence")
    extensions_raw: bytes | None = None
    offset = 0
    while offset < len(tbs):
        child_tag, child, next_offset = _der_tlv(tbs, offset, "Fulcio TBSCertificate field")
        if child_tag == 0xA3:
            if extensions_raw is not None:
                _die("Fulcio certificate duplicates extensions")
            extensions_raw = child
        offset = next_offset
    if extensions_raw is None:
        _die("Fulcio certificate extensions are absent")
    tag, extensions, end = _der_tlv(extensions_raw, 0, "Fulcio extensions")
    if tag != 0x30 or end != len(extensions_raw):
        _die("Fulcio extensions DER differs")
    result: dict[str, str] = {}
    offset = 0
    while offset < len(extensions):
        tag, extension, next_offset = _der_tlv(extensions, offset, "Fulcio extension")
        if tag != 0x30:
            _die("Fulcio extension is not a sequence")
        item_offset = 0
        oid_tag, oid_raw, item_offset = _der_tlv(extension, item_offset, "Fulcio extension OID")
        if oid_tag != 0x06:
            _die("Fulcio extension OID tag differs")
        oid = _der_oid(oid_raw, "Fulcio extension")
        value_tag, value_raw, item_offset = _der_tlv(
            extension, item_offset, "Fulcio extension value"
        )
        if value_tag == 0x01:
            _die("Fulcio GitHub security extension has an explicit critical flag")
        if value_tag != 0x04 or item_offset != len(extension):
            _die("Fulcio extension OCTET STRING differs")
        if oid.startswith(FULCIO_OID_ROOT + "."):
            if oid in result:
                _die(f"Fulcio certificate duplicates {oid}")
            try:
                suffix = int(oid.removeprefix(FULCIO_OID_ROOT + "."))
            except ValueError as exc:
                raise CommonAuthorityError("Fulcio extension suffix differs") from exc
            if 1 <= suffix <= 6:
                encoded = value_raw
            elif 8 <= suffix <= 24:
                string_tag, encoded, string_end = _der_tlv(
                    value_raw, 0, f"Fulcio extension {oid} UTF8String"
                )
                if string_tag != 0x0C or string_end != len(value_raw):
                    _die(f"Fulcio extension {oid} framing differs")
            else:
                _die(f"Fulcio certificate has unknown security extension {oid}")
            try:
                result[oid] = encoded.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CommonAuthorityError(f"Fulcio extension {oid} is not UTF-8") from exc
        offset = next_offset
    return result


def expected_fulcio_extensions(identity: SigstoreIdentity) -> dict[str, str]:
    return {
        f"{FULCIO_OID_ROOT}.1": identity.issuer,
        f"{FULCIO_OID_ROOT}.2": "workflow_dispatch",
        f"{FULCIO_OID_ROOT}.3": identity.sha,
        f"{FULCIO_OID_ROOT}.4": identity.workflow_name,
        f"{FULCIO_OID_ROOT}.5": identity.repository,
        f"{FULCIO_OID_ROOT}.6": identity.ref,
        f"{FULCIO_OID_ROOT}.8": identity.issuer,
        f"{FULCIO_OID_ROOT}.9": identity.workflow_identity,
        f"{FULCIO_OID_ROOT}.10": identity.sha,
        f"{FULCIO_OID_ROOT}.11": "github-hosted",
        f"{FULCIO_OID_ROOT}.12": f"https://github.com/{identity.repository}",
        f"{FULCIO_OID_ROOT}.13": identity.sha,
        f"{FULCIO_OID_ROOT}.14": identity.ref,
        f"{FULCIO_OID_ROOT}.15": str(identity.repository_id),
        f"{FULCIO_OID_ROOT}.16": f"https://github.com/{identity.repository_owner}",
        f"{FULCIO_OID_ROOT}.17": str(identity.repository_owner_id),
        f"{FULCIO_OID_ROOT}.18": identity.workflow_identity,
        f"{FULCIO_OID_ROOT}.19": identity.sha,
        f"{FULCIO_OID_ROOT}.20": "workflow_dispatch",
        f"{FULCIO_OID_ROOT}.21": identity.run_invocation_uri,
        f"{FULCIO_OID_ROOT}.22": identity.repository_visibility,
        f"{FULCIO_OID_ROOT}.23": identity.environment,
        f"{FULCIO_OID_ROOT}.24": f"repo:{identity.repository}:environment:{identity.environment}",
    }


def verify_fulcio(bundle: Mapping[str, Any], identity: SigstoreIdentity) -> dict[str, str]:
    material_value = bundle.get("verificationMaterial")
    if not isinstance(material_value, dict):
        _die("bundle verification material must be one object")
    allowed = {"certificate", "timestampVerificationData", "tlogEntries"}
    if set(material_value) - allowed or not {"certificate", "tlogEntries"} <= set(material_value):
        _die("bundle verification material certificate/tlog shape differs")
    material = material_value
    certificate = exact_object(material["certificate"], {"rawBytes"}, "bundle certificate")
    observed = fulcio_extensions(base64_bytes(certificate["rawBytes"], "certificate raw bytes"))
    expected = expected_fulcio_extensions(identity)
    if observed != expected:
        _die("Fulcio GitHub identity extensions differ")
    return observed


def validate_trusted_root_bootstrap(
    raw: bytes,
    *,
    expected_sha256: str | None,
    expected_size: int | None,
) -> dict[str, Any]:
    """Reject the poison root and bind ready trusted-root bytes to reviewed H/N."""

    sentinel = {
        "format": "z4j-sigstore-trusted-root-unfinalized-v1",
        "reason": "reviewed-sigstore-trusted-root-bytes-not-supplied",
        "trusted_root": None,
    }
    value = parse_json(raw, context="Sigstore trusted root")
    if canonical_json(value, terminal_lf=True) != raw:
        _die("Sigstore trusted root is not canonical ASCII JSON plus one LF")
    if value == sentinel:
        _die("tracked Sigstore trusted root is the UNFINALIZED sentinel")
    if expected_sha256 is None or expected_size is None:
        _die("reviewed trusted-root H/N is UNFINALIZED")
    hex64(expected_sha256, "reviewed trusted-root SHA-256")
    positive_int(expected_size, "reviewed trusted-root size")
    if sha256(raw) != expected_sha256 or len(raw) != expected_size:
        _die("Sigstore trusted-root bytes differ from the reviewed seal")
    if not isinstance(value, dict) or not value:
        _die("Sigstore trusted-root target is not one nonempty object")
    return value


def repository_owner_from_readback(
    response: Any,
) -> tuple[str, int]:
    """Extract the authenticated owner identity after binding the fixed repository."""

    _retained, body = validate_github_response(response, "GitHub repository readback")
    value = parse_json(body, context="GitHub repository readback body")
    if not isinstance(value, dict):
        _die("GitHub repository readback body is not one object")
    expected = {
        "default_branch": "main",
        "full_name": PRODUCER_REPOSITORY,
        "id": PRODUCER_REPOSITORY_ID,
        "node_id": PRODUCER_REPOSITORY_NODE_ID,
        "visibility": PRODUCER_VISIBILITY,
    }
    for key, item in expected.items():
        if value.get(key) != item:
            _die(f"GitHub repository readback {key} differs")
    owner = value.get("owner")
    if not isinstance(owner, dict):
        _die("GitHub repository readback owner is absent")
    login = ascii_text(owner.get("login"), "GitHub repository owner login")
    owner_id = positive_int(owner.get("id"), "GitHub repository owner ID")
    return login, owner_id


def identity_from_receipt(
    profile: AuthorityProfile,
    receipt: Mapping[str, Any],
) -> SigstoreIdentity:
    """Derive the sole allowed private GitHub/Fulcio identity from signed AR."""

    try:
        commit = receipt["source"]["generator"]["commit"]
        ceremony = receipt["ceremony"]
        repository_response = receipt["readback"]["github"]["repository"]
    except (KeyError, TypeError) as exc:
        raise CommonAuthorityError("receipt lacks common Sigstore identity inputs") from exc
    git_sha(commit, "receipt generator commit")
    validated_ceremony = validate_ceremony(profile, ceremony, generator_commit=commit)
    owner, owner_id = repository_owner_from_readback(repository_response)
    return SigstoreIdentity(
        environment=profile.environment,
        issuer=OIDC_ISSUER,
        ref=PRODUCER_REF,
        repository=PRODUCER_REPOSITORY,
        repository_id=PRODUCER_REPOSITORY_ID,
        repository_owner=owner,
        repository_owner_id=owner_id,
        repository_visibility=PRODUCER_VISIBILITY,
        run_invocation_uri=validated_ceremony["run_invocation_uri"],
        sha=commit,
        workflow_identity=profile.workflow_identity,
        workflow_name=profile.workflow_name,
    )


def _regular_identity(
    observed: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_uid,
        observed.st_gid,
        observed.st_nlink,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _read_held_regular(
    path: Path,
    *,
    maximum: int,
    context: str,
    require_owner_execute: bool,
) -> bytes:
    """Read one path through a no-follow held fd and reject identity drift."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _die("held-fd custody requires O_NOFOLLOW")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow,
        )
    except OSError as exc:
        raise CommonAuthorityError(f"cannot open {context} through held-fd custody") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or (require_owner_execute and not before.st_mode & stat.S_IXUSR)
        ):
            _die(f"{context} is not one bounded single-link executable regular file")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(COSIGN_READ_CHUNK, before.st_size - len(payload)))
            if not chunk:
                _die(f"{context} ended before its sealed size")
            payload.extend(chunk)
        if os.read(descriptor, 1):
            _die(f"{context} exceeds its sealed size")
        after = os.fstat(descriptor)
        if _regular_identity(before) != _regular_identity(after):
            _die(f"{context} changed while held-fd custody read it")
        return bytes(payload)
    except OSError as exc:
        raise CommonAuthorityError(f"cannot read {context} through held-fd custody") from exc
    finally:
        os.close(descriptor)


def _create_custodied_file(
    directory_fd: int,
    *,
    name: str,
    payload: bytes,
    mode: int,
) -> _CustodiedFile:
    """Create one owner-private single-link file, then retain only its read fd."""

    if (
        not name.isascii()
        or not name
        or "/" in name
        or "\\" in name
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in name)
    ):
        _die("Cosign custody filename is unsafe")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _die("Cosign custody requires O_NOFOLLOW")
    writer = -1
    reader = -1
    transferred = False
    try:
        writer = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            mode,
            dir_fd=directory_fd,
        )
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(writer, view[written:])
            if count <= 0:
                _die("Cosign custody file write did not progress")
            written += count
        os.fchmod(writer, mode)
        os.fsync(writer)
        os.close(writer)
        writer = -1
        reader = os.open(name, os.O_RDONLY | os.O_CLOEXEC | nofollow, dir_fd=directory_fd)
        observed = os.fstat(reader)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != mode
            or observed.st_uid != os.geteuid()
            or observed.st_gid != os.getegid()
            or observed.st_nlink != 1
            or observed.st_size != len(payload)
        ):
            _die("Cosign custody file ownership, mode, link count, or size differs")
        record = _CustodiedFile(
            fd=reader,
            identity=_regular_identity(observed),
            mode=mode,
            sha256=sha256(payload),
            size=len(payload),
        )
        transferred = True
        return record
    except OSError as exc:
        raise CommonAuthorityError("cannot create held-fd Cosign custody file") from exc
    finally:
        if writer >= 0:
            os.close(writer)
        if reader >= 0 and not transferred:
            os.close(reader)


def _validate_custodied_file(record: _CustodiedFile) -> None:
    """Re-hash a held fd and require its complete pre/post identity to remain fixed."""

    try:
        observed = os.fstat(record.fd)
        if (
            _regular_identity(observed) != record.identity
            or stat.S_IMODE(observed.st_mode) != record.mode
            or observed.st_uid != os.geteuid()
            or observed.st_gid != os.getegid()
            or observed.st_nlink != 1
            or observed.st_size != record.size
        ):
            _die("Cosign custody file identity changed during execution")
        payload = bytearray()
        offset = 0
        while offset < record.size:
            chunk = os.pread(record.fd, min(COSIGN_READ_CHUNK, record.size - offset), offset)
            if not chunk:
                _die("Cosign custody file ended before its post-execution size")
            payload.extend(chunk)
            offset += len(chunk)
        if sha256(bytes(payload)) != record.sha256:
            _die("Cosign custody file bytes changed during execution")
        after = os.fstat(record.fd)
        if _regular_identity(after) != record.identity:
            _die("Cosign custody file identity changed while it was validated")
    except OSError as exc:
        raise CommonAuthorityError("cannot validate held-fd Cosign custody file") from exc


def _raise_prctl_error() -> NoReturn:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))


def _set_child_subreaper(enabled: bool) -> bool:
    """Set Linux child-subreaper state and return the previous value."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        current = ctypes.c_int()
        if prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
            _raise_prctl_error()
        previous = bool(current.value)
        if previous != enabled and prctl(_PR_SET_CHILD_SUBREAPER, int(enabled), 0, 0, 0) != 0:
            _raise_prctl_error()
        return previous
    except (AttributeError, OSError) as exc:
        raise CommonAuthorityError("Cosign custody cannot establish child-subreaper state") from exc


def _direct_child_pids() -> tuple[int, ...]:
    """Read the exact Linux child set for this single-task supervisor."""

    try:
        raw = Path(f"/proc/self/task/{os.getpid()}/children").read_bytes()
    except OSError as exc:
        raise CommonAuthorityError("Cosign descendant accounting is unavailable") from exc
    try:
        values = tuple(int(item) for item in raw.split())
    except ValueError as exc:
        raise CommonAuthorityError("Cosign descendant accounting is malformed") from exc
    if any(value <= 0 for value in values) or len(values) != len(set(values)):
        _die("Cosign descendant accounting differs")
    return values


def _require_private_subreaper_boundary() -> None:
    """Require exclusive process ownership before adopting untrusted descendants."""

    try:
        tasks = {item.name for item in Path("/proc/self/task").iterdir()}
    except OSError as exc:
        raise CommonAuthorityError("Cosign task accounting is unavailable") from exc
    if tasks != {str(os.getpid())} or _direct_child_pids():
        _die("Cosign custody requires one task with no pre-existing child process")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        _die("Cosign descendant custody requires Linux pidfd signaling")


def _drain_adopted_descendants() -> bool:
    """Boundedly SIGKILL and reap every child adopted by the private subreaper."""

    observed = False
    deadline = time.monotonic() + COSIGN_TERMINATION_TIMEOUT_SECONDS
    while True:
        children = _direct_child_pids()
        if not children:
            return observed
        observed = True
        if time.monotonic() >= deadline:
            _die("Cosign descendants did not reap before the cleanup deadline")
        for pid in children:
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            except OSError as exc:
                raise CommonAuthorityError("cannot retain a Cosign descendant") from exc
            try:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        for pid in children:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            except OSError as exc:
                raise CommonAuthorityError("cannot reap a Cosign descendant") from exc
        time.sleep(0.01)


def _kill_process_group_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Kill the private session, reap its leader, then drain all adopted descendants."""

    termination_error: CommonAuthorityError | None = None
    termination_cause: BaseException | None = None
    try:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            termination_error = CommonAuthorityError("cannot kill the Cosign process group")
            termination_cause = exc
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as leader_exc:
                termination_error = CommonAuthorityError(
                    "cannot kill the Cosign process group or its leader"
                )
                termination_cause = leader_exc
        try:
            process.wait(timeout=COSIGN_TERMINATION_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            if termination_error is None:
                termination_error = CommonAuthorityError("Cosign process-group leader did not reap")
                termination_cause = exc
        except OSError as exc:
            if termination_error is None:
                termination_error = CommonAuthorityError(
                    "cannot reap the Cosign process-group leader"
                )
                termination_cause = exc
    finally:
        try:
            descendants = _drain_adopted_descendants()
        except CommonAuthorityError as exc:
            if termination_error is not None:
                raise exc from termination_error
            raise
    if termination_error is not None:
        raise termination_error from termination_cause
    return descendants


def _collect_bounded_process(  # noqa: PLR0912 - concurrent closed two-stream state machine
    process: subprocess.Popen[bytes],
) -> tuple[bytes, bytes]:
    """Drain both streams concurrently under strict UTF-8, byte, and time bounds."""

    if process.stdout is None or process.stderr is None:
        _die("Cosign subprocess pipes are absent")
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": COSIGN_STDOUT_LIMIT, "stderr": COSIGN_STDERR_LIMIT}
    decoders: dict[str, codecs.IncrementalDecoder] = {
        name: codecs.getincrementaldecoder("utf-8")("strict") for name in outputs
    }
    selector = selectors.DefaultSelector()
    descriptors = {
        "stdout": process.stdout.fileno(),
        "stderr": process.stderr.fileno(),
    }
    for name, descriptor in descriptors.items():
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ, name)
    deadline = time.monotonic() + COSIGN_PROCESS_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _die("Cosign subprocess exceeded its monotonic deadline")
            events = selector.select(min(remaining, 0.05)) if selector.get_map() else []
            if not events and not selector.get_map():
                try:
                    terminal = os.waitid(
                        os.P_PID,
                        process.pid,
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    )
                except (ChildProcessError, OSError) as exc:
                    raise CommonAuthorityError(
                        "cannot inspect the unreaped Cosign process-group leader"
                    ) from exc
                if terminal is not None:
                    break
                time.sleep(min(remaining, 0.01))
            for key, _mask in events:
                name = str(key.data)
                try:
                    chunk = os.read(key.fd, COSIGN_READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    try:
                        decoders[name].decode(b"", final=True)
                    except UnicodeDecodeError as exc:
                        raise CommonAuthorityError(f"Cosign {name} is not strict UTF-8") from exc
                    continue
                stream_size = len(outputs[name]) + len(chunk)
                aggregate_size = sum(len(output) for output in outputs.values()) + len(chunk)
                if stream_size > limits[name] or aggregate_size > COSIGN_AGGREGATE_OUTPUT_LIMIT:
                    _die("Cosign subprocess output exceeded its per-stream or aggregate bound")
                try:
                    decoders[name].decode(chunk, final=False)
                except UnicodeDecodeError as exc:
                    raise CommonAuthorityError(f"Cosign {name} is not strict UTF-8") from exc
                outputs[name].extend(chunk)
        return bytes(outputs["stdout"]), bytes(outputs["stderr"])
    finally:
        selector.close()


def _run_custodied_cosign(  # noqa: PLR0912,PLR0915 - closed custody lifecycle
    *,
    cosign: Path,
    cosign_sha256: str,
    cosign_size: int,
    inputs: tuple[tuple[str, bytes], ...],
    argv_builder: Callable[[str, Mapping[str, str]], tuple[str, ...]],
) -> BoundedProcessResult:
    """Authenticate first, then execute one private held-fd Cosign copy."""

    hex64(cosign_sha256, "Cosign SHA-256")
    expected_size = positive_int(cosign_size, "Cosign size")
    if expected_size > MAX_COSIGN_BYTES:
        _die("Cosign exceeds its bounded executable size")
    cosign_raw = _read_held_regular(
        cosign,
        maximum=MAX_COSIGN_BYTES,
        context="pinned Cosign",
        require_owner_execute=True,
    )
    if sha256(cosign_raw) != cosign_sha256 or len(cosign_raw) != expected_size:
        _die("Cosign differs from its reviewed seal")
    names = [name for name, _payload in inputs]
    if len(names) != len(set(names)):
        _die("Cosign custody input names are duplicated")
    for name, payload in inputs:
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_JSON_BYTES:
            _die(f"Cosign custody input {name!r} is empty, oversized, or not bytes")
    if not Path("/proc/self/fd").is_dir():
        _die("Cosign held-fd execution requires /proc/self/fd")

    with _COSIGN_SUPERVISOR_LOCK:
        _require_private_subreaper_boundary()
        previous_subreaper = _set_child_subreaper(True)
        private_root: Path | None = None
        directory_fd = -1
        held: list[_CustodiedFile] = []
        process: subprocess.Popen[bytes] | None = None
        surviving_descendants = False
        try:
            private_root = Path(tempfile.mkdtemp(prefix="z4j-cosign-custody-", dir="/tmp"))
            private_root.chmod(0o700)
            root_stat = private_root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or stat.S_IMODE(root_stat.st_mode) != 0o700
                or root_stat.st_uid != os.geteuid()
                or root_stat.st_gid != os.getegid()
            ):
                _die("Cosign custody root is not one owner-private directory")
            directory_fd = os.open(
                private_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            executable = _create_custodied_file(
                directory_fd,
                name="cosign",
                payload=cosign_raw,
                mode=0o500,
            )
            held.append(executable)
            input_records: dict[str, _CustodiedFile] = {}
            for name, payload in inputs:
                record = _create_custodied_file(
                    directory_fd,
                    name=name,
                    payload=payload,
                    mode=0o400,
                )
                held.append(record)
                input_records[name] = record
            os.fsync(directory_fd)
            for record in held:
                _validate_custodied_file(record)
            executable_path = f"/proc/self/fd/{executable.fd}"
            input_paths = {
                name: f"/proc/self/fd/{record.fd}" for name, record in input_records.items()
            }
            command = argv_builder(executable_path, input_paths)
            if (
                not command
                or command[0] != executable_path
                or any(
                    not isinstance(argument, str)
                    or not argument
                    or "\0" in argument
                    or "\n" in argument
                    or "\r" in argument
                    for argument in command
                )
            ):
                _die("Cosign custody argv is empty, ambiguous, or changes the held executable")
            environment = {
                "HOME": str(private_root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": str(private_root),
                "TZ": "UTC",
                "XDG_CACHE_HOME": str(private_root),
            }
            try:
                process = subprocess.Popen(  # noqa: S603 - exact held-fd executable
                    command,
                    executable=executable_path,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=tuple(record.fd for record in held),
                    cwd=private_root,
                    env=environment,
                    start_new_session=True,
                    text=False,
                    bufsize=0,
                )
            except OSError as exc:
                raise CommonAuthorityError("held-fd Cosign subprocess did not start") from exc
            try:
                stdout, stderr = _collect_bounded_process(process)
            finally:
                try:
                    surviving_descendants = _kill_process_group_and_reap(process)
                finally:
                    for record in held:
                        _validate_custodied_file(record)
            if process.returncode is None:
                _die("Cosign subprocess did not expose a terminal return code")
            if surviving_descendants:
                _die("Cosign subprocess left a surviving or session-escaped descendant")
            return BoundedProcessResult(
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        finally:
            cleanup_error: CommonAuthorityError | None = None
            cleanup_cause: OSError | None = None
            try:
                if process is not None:
                    for stream in (process.stdout, process.stderr):
                        if stream is not None:
                            try:
                                stream.close()
                            except OSError as exc:
                                if cleanup_error is None:
                                    cleanup_error = CommonAuthorityError(
                                        "cannot close a Cosign subprocess stream"
                                    )
                                    cleanup_cause = exc
                for record in held:
                    try:
                        os.close(record.fd)
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = CommonAuthorityError(
                                "cannot close a Cosign custody descriptor"
                            )
                            cleanup_cause = exc
                if directory_fd >= 0:
                    try:
                        os.close(directory_fd)
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = CommonAuthorityError(
                                "cannot close the Cosign custody directory"
                            )
                            cleanup_cause = exc
                if private_root is not None:
                    try:
                        shutil.rmtree(private_root)
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = CommonAuthorityError(
                                "cannot remove the Cosign custody root"
                            )
                            cleanup_cause = exc
            finally:
                try:
                    _set_child_subreaper(previous_subreaper)
                except CommonAuthorityError as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                raise cleanup_error from cleanup_cause


def run_cosign_version(
    *,
    cosign: Path,
    cosign_sha256: str,
    cosign_size: int,
) -> BoundedProcessResult:
    """Run the one exact bounded `cosign version --json` probe."""

    result = _run_custodied_cosign(
        cosign=cosign,
        cosign_sha256=cosign_sha256,
        cosign_size=cosign_size,
        inputs=(),
        argv_builder=lambda executable, _inputs: (executable, "version", "--json"),
    )
    if result.returncode != 0:
        _die("pinned Cosign version probe failed")
    return result


def run_cosign_verify_blob(
    *,
    cosign: Path,
    cosign_sha256: str,
    cosign_size: int,
    bundle_raw: bytes,
    receipt_raw: bytes,
    trusted_root_raw: bytes,
    trusted_root_sha256: str,
    trusted_root_size: int,
    identity: SigstoreIdentity,
) -> BoundedProcessResult:
    """Run the sole exact bounded offline Cosign verification command."""

    hex64(trusted_root_sha256, "trusted-root SHA-256")
    root_size = positive_int(trusted_root_size, "trusted-root size")
    if sha256(trusted_root_raw) != trusted_root_sha256 or len(trusted_root_raw) != root_size:
        _die("trusted root differs from its reviewed seal")

    def verify_argv(executable: str, inputs: Mapping[str, str]) -> tuple[str, ...]:
        return (
            executable,
            "verify-blob",
            "--bundle",
            inputs["bundle.json"],
            "--trusted-root",
            inputs["trusted-root.json"],
            "--certificate-identity",
            identity.workflow_identity,
            "--certificate-oidc-issuer",
            identity.issuer,
            "--certificate-github-workflow-name",
            identity.workflow_name,
            "--certificate-github-workflow-repository",
            identity.repository,
            "--certificate-github-workflow-ref",
            identity.ref,
            "--certificate-github-workflow-sha",
            identity.sha,
            "--certificate-github-workflow-trigger",
            "workflow_dispatch",
            inputs["receipt.json"],
        )

    result = _run_custodied_cosign(
        cosign=cosign,
        cosign_sha256=cosign_sha256,
        cosign_size=cosign_size,
        inputs=(
            ("bundle.json", bundle_raw),
            ("trusted-root.json", trusted_root_raw),
            ("receipt.json", receipt_raw),
        ),
        argv_builder=verify_argv,
    )
    if result.returncode != 0:
        _die("Sigstore bundle cryptographic verification failed")
    return result


def verify_cosign_blob(
    *,
    cosign: Path,
    cosign_sha256: str,
    cosign_size: int,
    bundle_raw: bytes,
    receipt_raw: bytes,
    trusted_root_raw: bytes,
    trusted_root_sha256: str,
    trusted_root_size: int,
    identity: SigstoreIdentity,
) -> None:
    run_cosign_verify_blob(
        bundle_raw=bundle_raw,
        cosign=cosign,
        cosign_sha256=cosign_sha256,
        cosign_size=cosign_size,
        identity=identity,
        receipt_raw=receipt_raw,
        trusted_root_raw=trusted_root_raw,
        trusted_root_sha256=trusted_root_sha256,
        trusted_root_size=trusted_root_size,
    )


def verify_sigstore_bundle(
    profile: AuthorityProfile,
    *,
    receipt: Mapping[str, Any],
    receipt_raw: bytes,
    receipt_path: Path,
    bundle_raw: bytes,
    bundle_path: Path,
    cosign: Path,
    cosign_sha256: str,
    cosign_size: int,
    trusted_root: Path,
    trusted_root_sha256: str | None,
    trusted_root_size: int | None,
    integrated_time_minimum: int = REKOR_INTEGRATED_TIME_MINIMUM,
) -> dict[str, Any]:
    """Perform structural, identity, and independent pinned-Cosign verification."""

    if canonical_json(receipt, terminal_lf=True) != receipt_raw:
        _die(f"{profile.material} receipt bytes differ from the canonical signed object")
    if (
        read_regular(
            receipt_path, maximum=MAX_JSON_BYTES, context=f"{profile.material} receipt file"
        )
        != receipt_raw
    ):
        _die(f"{profile.material} receipt path differs from supplied literal bytes")
    if (
        read_regular(bundle_path, maximum=MAX_JSON_BYTES, context=f"{profile.material} bundle file")
        != bundle_raw
    ):
        _die(f"{profile.material} bundle path differs from supplied literal bytes")
    identity = identity_from_receipt(profile, receipt)
    bundle = validate_bundle(
        bundle_raw,
        receipt_raw=receipt_raw,
        integrated_time_minimum=integrated_time_minimum,
    )
    verify_fulcio(bundle, identity)
    trusted_raw = read_regular(
        trusted_root, maximum=MAX_JSON_BYTES, context="pinned Sigstore trusted root"
    )
    validate_trusted_root_bootstrap(
        trusted_raw,
        expected_sha256=trusted_root_sha256,
        expected_size=trusted_root_size,
    )
    if trusted_root_sha256 is None or trusted_root_size is None:
        _die("reviewed trusted-root seal is UNFINALIZED")
    verify_cosign_blob(
        bundle_raw=bundle_raw,
        cosign=cosign,
        cosign_sha256=cosign_sha256,
        cosign_size=cosign_size,
        identity=identity,
        receipt_raw=receipt_raw,
        trusted_root_raw=trusted_raw,
        trusted_root_sha256=trusted_root_sha256,
        trusted_root_size=trusted_root_size,
    )
    return bundle


def select_recovery_candidate(
    candidates: Sequence[RecoveryCandidate],
    *,
    validator: Callable[[RecoveryCandidate], T],
) -> tuple[RecoveryCandidate, T]:
    """Return exactly one fully valid candidate; zero or multiple always fail."""

    valid: list[tuple[RecoveryCandidate, T]] = []
    for candidate in candidates:
        try:
            result = validator(candidate)
        except CommonAuthorityError:
            continue
        valid.append((candidate, result))
    if not valid:
        _die("no fully valid durable authority recovery candidate exists")
    if len(valid) > 1:
        _die("multiple valid authority candidates require reviewed manual selection")
    return valid[0]
