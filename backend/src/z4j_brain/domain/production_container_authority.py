"""Authenticate the exact finalized 1.9.0 production-container carrier.

The rollback preparation command is intentionally unable to turn an
environment variable into release authority.  It consumes the four-file
``production-finalization-attestation-1.9.0`` artifact emitted by the normal
release workflow, authenticates the literal receipt bytes with Sigstore, and
re-reads the receipt-bound OCI index, native manifests, and configs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform as runtime_platform_module
import re
import selectors
import signal
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

PRODUCTION_AUTHORITY_ENV = "Z4J_PRODUCTION_FINALIZATION_ROOT"
PRODUCTION_AUTHORITY_FORMAT = "z4j-production-container-finalization-v1"
PRODUCTION_NATIVE_FORMAT = "z4j-production-native-build-v1"
PRODUCTION_RELEASE = "1.9.0"
SOURCE_TAG_AUTHORITY_SCHEMA = "z4j.source-tag-authority.v1"
PRODUCTION_IMAGE_REPOSITORY = "docker.io/z4jdev/z4j"
PRODUCTION_WORKFLOW_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/release-docker.yml@refs/tags/v1.9.0"
)
PRODUCTION_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PRODUCTION_ATTESTATION_TYPE = "https://z4j.dev/attestations/production-container-finalization/v1"
COSIGN_VERSION = "3.1.3"
COSIGN_PATH = "/usr/local/bin/cosign"
QUALIFICATION_CEREMONY_FORMAT = "z4j-production-qualification-ceremony-v1"
HANDOFF_SCHEMA = "z4j.release-docker-source-authority-handoff.v1"
GITHUB_API_VERSION = "2026-03-10"
SOURCE_REPOSITORY = "z4jdev/z4j"
SOURCE_REPOSITORY_ID = 1228454287
SOURCE_REPOSITORY_NODE_ID = "R_kgDOSTi5jw"
SOURCE_TAG = "v1.9.0"
SOURCE_TAG_REF = "refs/tags/v1.9.0"
SOURCE_WORKFLOW_PATH = ".github/workflows/source-tag-only.yml"
RELEASE_WORKFLOW_ID = 270520651
RELEASE_WORKFLOW_NODE_ID = "W_kwDOSTi5j84QH9FL"
RELEASE_WORKFLOW_NAME = "release-docker"
RELEASE_WORKFLOW_PATH = ".github/workflows/release-docker.yml"
PRODUCTION_QUALIFICATION_ENVIRONMENT = "production-qualification"
_SYSTEM_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
_COSIGN_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}

_REQUIRED_FILES = {
    "production-finalization.json",
    "production-finalization.bundle.json",
    "production-finalization.attestation.jsonl",
    "staging-index.json",
}
_AUTHORITY_FILE_LIMITS = {
    "production-finalization.json": 8 * 1024 * 1024,
    "production-finalization.bundle.json": 16 * 1024 * 1024,
    "production-finalization.attestation.jsonl": 32 * 1024 * 1024,
    "staging-index.json": 4 * 1024 * 1024,
}
_MAX_COSIGN_BINARY_BYTES = 128 * 1024 * 1024

_MAX_COSIGN_STDOUT_BYTES = 32 * 1024 * 1024
_MAX_COSIGN_STDERR_BYTES = 4 * 1024 * 1024
_COSIGN_TIMEOUT_SECONDS = 120.0
_RECEIPT_KEYS = {
    "format",
    "release",
    "release_git_commit",
    "release_git_tree",
    "manifest_sha256",
    "production_source_projection_sha256",
    "source_tag_authority",
    "qualification_ceremony",
    "signature_verifier",
    "candidate_index",
    "dashboard_sbom",
    "native",
    "native_receipts",
}
_NATIVE_KEYS = {
    "format",
    "release_git_commit",
    "release_git_tree",
    "platform",
    "contract",
    "python",
    "signature_verifier",
    "signature_verifier_probe",
    "wheelhouse",
    "system_packages",
    "dashboard",
    "candidate",
    "install",
    "cadence_probe",
    "dashboard_replay",
    "service_smoke",
    "candidate_sbom",
    "candidate_scanner",
}
_CANDIDATE_KEYS = {
    "build_output_digest",
    "manifest_digest",
    "manifest_size",
    "config_digest",
    "config_size",
    "labels",
}
_CANDIDATE_LABEL_KEYS = {
    "org.opencontainers.image.revision",
    "org.z4j.production.manifest.sha256",
    "org.z4j.production.source-projection.sha256",
    "org.z4j.production.wheelhouse.index",
    "org.z4j.production.system-bundle.index",
    "org.z4j.production.dashboard-bundle.index",
}
_OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
_HANDOFF_INPUT_KEYS = {
    "authority_artifact_digest",
    "authority_subject_digest",
    "authority_run_id",
    "authority_run_attempt",
    "initiating_source_run_id",
    "initiating_source_run_attempt",
    "source_tag_object",
    "source_commit",
    "source_tree",
    "source_repository",
    "source_workflow_id",
    "source_workflow_node_id",
    "source_workflow_path",
    "initiating_actor",
    "handoff_nonce",
    "handoff_run_name",
}


class ProductionContainerAuthorityRefused(RuntimeError):  # noqa: N818
    """The production carrier did not prove the finalized release identity."""


class CompletedProcessLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


CosignRunner = Callable[[Sequence[str]], CompletedProcessLike]
BinaryReader = Callable[[Path], bytes]
RegistryFetcher = Callable[[str, str], bytes]


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductionContainerAuthorityRefused(f"{label} is not an object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ProductionContainerAuthorityRefused(
            f"{label} keys differ from the finalized production contract",
        )


def _exact(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ProductionContainerAuthorityRefused(
            f"{label} differs from the finalized production contract",
        )


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _OCI_DIGEST.fullmatch(value) is None:
        raise ProductionContainerAuthorityRefused(
            f"{label} is not a lowercase OCI SHA-256 digest",
        )
    return value


def _hex_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProductionContainerAuthorityRefused(
            f"{label} is not a lowercase SHA-256",
        )
    return value


def _size(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ProductionContainerAuthorityRefused(f"{label} is not a positive byte size")
    return value


def _seal(value: object, label: str) -> dict[str, object]:
    record = _mapping(value, label)
    _exact_keys(record, {"sha256", "size"}, label)
    return {
        "sha256": _hex_sha256(record.get("sha256"), f"{label}.sha256"),
        "size": _size(record.get("size"), f"{label}.size"),
    }


def _validate_source_tag_authority(
    value: object,
    *,
    revision: str,
    tree: str,
) -> dict[str, Any]:
    authority = _mapping(value, "source_tag_authority")
    _exact_keys(
        authority,
        {
            "repository",
            "tag",
            "commit",
            "tree",
            "receipt",
            "bundle",
            "evidence_index",
            "workflow",
            "verification",
        },
        "source_tag_authority",
    )
    _exact(authority.get("repository"), "z4jdev/z4j", "source tag repository")
    _exact(authority.get("tag"), "v1.9.0", "source tag")
    _exact(authority.get("commit"), revision, "source tag commit")
    _exact(authority.get("tree"), tree, "source tag tree")
    receipt = _seal(authority.get("receipt"), "source_tag_authority.receipt")
    bundle = _seal(authority.get("bundle"), "source_tag_authority.bundle")
    evidence_index_value = _mapping(
        authority.get("evidence_index"),
        "source_tag_authority.evidence_index",
    )
    _exact_keys(
        evidence_index_value,
        {"sha256", "size", "artifact_digest", "index_digest"},
        "source_tag_authority.evidence_index",
    )
    evidence_index = {
        "sha256": _hex_sha256(
            evidence_index_value.get("sha256"),
            "source_tag_authority.evidence_index.sha256",
        ),
        "size": _size(
            evidence_index_value.get("size"),
            "source_tag_authority.evidence_index.size",
        ),
        "artifact_digest": _digest(
            evidence_index_value.get("artifact_digest"),
            "source_tag_authority.evidence_index.artifact_digest",
        ),
        "index_digest": _digest(
            evidence_index_value.get("index_digest"),
            "source_tag_authority.evidence_index.index_digest",
        ),
    }
    if evidence_index["artifact_digest"] != f"sha256:{evidence_index['sha256']}":
        raise ProductionContainerAuthorityRefused(
            "source-tag evidence artifact digest does not equal the raw "
            "evidence-index manifest SHA-256",
        )
    if evidence_index["artifact_digest"] == evidence_index["index_digest"]:
        raise ProductionContainerAuthorityRefused(
            "source-tag evidence referrer cannot alias its retained subject index",
        )
    workflow = _mapping(authority.get("workflow"), "source_tag_authority.workflow")
    _exact_keys(workflow, {"run_id", "run_attempt"}, "source_tag_authority.workflow")
    for field in ("run_id", "run_attempt"):
        if (
            not isinstance(workflow.get(field), int)
            or isinstance(workflow[field], bool)
            or workflow[field] <= 0
        ):
            raise ProductionContainerAuthorityRefused(
                f"source_tag_authority.workflow.{field} is not a positive integer",
            )
    verification = _mapping(
        authority.get("verification"),
        "source_tag_authority.verification",
    )
    _exact_keys(verification, {"result"}, "source_tag_authority.verification")
    _exact(verification.get("result"), "pass", "source tag verification result")
    return {
        "repository": "z4jdev/z4j",
        "tag": "v1.9.0",
        "commit": revision,
        "tree": tree,
        "receipt": receipt,
        "bundle": bundle,
        "evidence_index": evidence_index,
        "workflow": dict(workflow),
        "verification": {"result": "pass"},
    }


def _positive(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ProductionContainerAuthorityRefused(f"{label} is not a positive integer")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProductionContainerAuthorityRefused(f"{label} is not a nonempty string")
    return value


def _stable_actor(
    value: object,
    label: str,
    *,
    allowed_types: tuple[str, ...] = ("User", "Bot"),
) -> dict[str, Any]:
    actor = _mapping(value, label)
    _exact_keys(actor, {"login", "id", "node_id", "type"}, label)
    actor_type = actor.get("type")
    if actor_type not in allowed_types:
        raise ProductionContainerAuthorityRefused(f"{label}.type differs")
    return {
        "login": _nonempty(actor.get("login"), f"{label}.login"),
        "id": _positive(actor.get("id"), f"{label}.id"),
        "node_id": _nonempty(actor.get("node_id"), f"{label}.node_id"),
        "type": actor_type,
    }


def _decimal_string(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ProductionContainerAuthorityRefused(f"{label} is not a decimal string")
    parsed = int(value)
    if parsed <= 0 or str(parsed) != value:
        raise ProductionContainerAuthorityRefused(f"{label} is not canonical positive decimal")
    return parsed


def _no_floats(value: object, label: str) -> None:
    if isinstance(value, float):
        raise ProductionContainerAuthorityRefused(f"{label} contains a floating-point number")
    if isinstance(value, dict):
        for key, item in value.items():
            _no_floats(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_floats(item, f"{label}[{index}]")


def _api_carrier(value: object, *, label: str, expected_url: str) -> Any:
    carrier = _mapping(value, label)
    _exact_keys(carrier, {"url", "status", "body_base64", "sha256", "size"}, label)
    _exact(carrier.get("url"), expected_url, f"{label}.url")
    _exact(carrier.get("status"), 200, f"{label}.status")
    encoded = carrier.get("body_base64")
    if not isinstance(encoded, str) or not encoded:
        raise ProductionContainerAuthorityRefused(f"{label}.body_base64 is absent")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ProductionContainerAuthorityRefused(
            f"{label}.body_base64 is not canonical base64",
        ) from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ProductionContainerAuthorityRefused(
            f"{label}.body_base64 is not RFC4648 padded base64",
        )
    if len(raw) != _size(carrier.get("size"), f"{label}.size") or _sha256(raw) != _hex_sha256(
        carrier.get("sha256"), f"{label}.sha256"
    ):
        raise ProductionContainerAuthorityRefused(f"{label} body seal differs")
    body = _json(raw, f"{label} body")
    _no_floats(body, f"{label} body")
    if _canonical_line(body) != raw:
        raise ProductionContainerAuthorityRefused(
            f"{label} body is not canonical sorted compact ASCII JSON plus LF",
        )
    return body


def _api_actor(
    value: object,
    label: str,
    *,
    allowed_types: tuple[str, ...] = ("User", "Bot"),
) -> dict[str, Any]:
    actor = _mapping(value, label)
    return _stable_actor(
        {
            "login": actor.get("login"),
            "id": actor.get("id"),
            "node_id": actor.get("node_id"),
            "type": actor.get("type"),
        },
        label,
        allowed_types=allowed_types,
    )


def _validate_run_body(
    value: object,
    *,
    label: str,
    expected: Mapping[str, Any],
    status: str,
    conclusions: set[str | None],
) -> None:
    body = _mapping(value, label)
    for key in (
        "id",
        "run_attempt",
        "workflow_id",
        "url",
        "html_url",
        "event",
        "head_branch",
        "head_sha",
        "display_title",
    ):
        _exact(body.get(key), expected[key], f"{label}.{key}")
    _exact(body.get("status"), status, f"{label}.status")
    if body.get("conclusion") not in conclusions:
        raise ProductionContainerAuthorityRefused(f"{label}.conclusion differs")
    _exact(
        _api_actor(body.get("actor"), f"{label}.actor"),
        expected["actor"],
        f"{label}.actor",
    )
    _exact(
        _api_actor(body.get("triggering_actor"), f"{label}.triggering_actor"),
        expected["triggering_actor"],
        f"{label}.triggering_actor",
    )
    repository = _mapping(body.get("repository"), f"{label}.repository")
    _exact(repository.get("full_name"), SOURCE_REPOSITORY, f"{label}.repository.full_name")
    _exact(repository.get("id"), SOURCE_REPOSITORY_ID, f"{label}.repository.id")
    _exact(
        repository.get("node_id"),
        SOURCE_REPOSITORY_NODE_ID,
        f"{label}.repository.node_id",
    )


def _jobs(value: object, *, label: str) -> list[dict[str, Any]]:
    body = _mapping(value, label)
    jobs = body.get("jobs")
    if (
        not isinstance(jobs, list)
        or body.get("total_count") != len(jobs)
        or not jobs
        or len(jobs) > 100
    ):
        raise ProductionContainerAuthorityRefused(f"{label} job inventory differs")
    return [_mapping(item, f"{label}.jobs[{index}]") for index, item in enumerate(jobs)]


def _validate_qualification_jobs(
    value: object,
    *,
    run_id: int,
    head_sha: str,
    deployment: Mapping[str, Any],
) -> None:
    jobs = _jobs(value, label="qualification jobs readback")
    matching = [job for job in jobs if job.get("id") == deployment["job_id"]]
    if len(matching) != 1:
        raise ProductionContainerAuthorityRefused(
            "qualification jobs do not contain the unique protected job",
        )
    job = matching[0]
    for key, expected in (
        ("run_id", run_id),
        ("head_sha", head_sha),
        ("name", deployment["job_name"]),
        ("status", "in_progress"),
        ("conclusion", None),
    ):
        _exact(job.get(key), expected, f"qualification job.{key}")


def _validate_source_jobs(
    value: object,
    *,
    label: str,
    run_id: int,
    head_sha: str,
    conclusions: set[str],
) -> None:
    jobs = _jobs(value, label=label)
    matching = [
        job for job in jobs if job.get("name") == "Validate and create only immutable v1.9.0"
    ]
    if len(matching) != 1:
        raise ProductionContainerAuthorityRefused(
            f"{label} does not contain the unique source-tag-only job",
        )
    job = matching[0]
    _exact(job.get("run_id"), run_id, f"{label}.run_id")
    _exact(job.get("head_sha"), head_sha, f"{label}.head_sha")
    _exact(job.get("status"), "completed", f"{label}.status")
    if job.get("conclusion") not in conclusions:
        raise ProductionContainerAuthorityRefused(f"{label}.conclusion differs")


def _approved_review(
    value: object,
    *,
    label: str,
    environment: str,
) -> dict[str, Any]:
    if not isinstance(value, list):
        raise ProductionContainerAuthorityRefused(f"{label} is not an approval list")
    matches: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        review = _mapping(item, f"{label}[{index}]")
        environments = review.get("environments")
        if not isinstance(environments, list):
            continue
        names = [
            _mapping(environment_item, f"{label}[{index}].environment").get("name")
            for environment_item in environments
        ]
        if review.get("state") == "approved" and environment in names:
            matches.append(review)
    if len(matches) != 1:
        raise ProductionContainerAuthorityRefused(
            f"{label} does not contain one unique approved environment review",
        )
    return _api_actor(
        matches[0].get("user"),
        f"{label} reviewer",
        allowed_types=("User",),
    )


def _validate_protection_environment(value: object) -> dict[str, Any]:
    environment = _mapping(value, "qualification protection environment")
    _exact_keys(
        environment,
        {"name", "prevent_self_review", "reviewers", "allowed_refs"},
        "qualification protection environment",
    )
    _exact(
        environment.get("name"),
        PRODUCTION_QUALIFICATION_ENVIRONMENT,
        "qualification protection environment.name",
    )
    _exact(
        environment.get("prevent_self_review"),
        True,
        "qualification protection environment.prevent_self_review",
    )
    reviewers = environment.get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        raise ProductionContainerAuthorityRefused(
            "qualification protection environment has no reviewers",
        )
    normalized = [
        _stable_actor(
            item,
            f"qualification protection reviewer {index}",
            allowed_types=("User",),
        )
        for index, item in enumerate(reviewers)
    ]
    if normalized != sorted(normalized, key=lambda item: (item["id"], item["login"])):
        raise ProductionContainerAuthorityRefused(
            "qualification protection reviewers are not canonical",
        )
    _exact(
        environment.get("allowed_refs"),
        {"mode": "selected", "patterns": [SOURCE_TAG_REF]},
        "qualification protection environment.allowed_refs",
    )
    return dict(environment)


def _validate_actions_policy(value: object) -> dict[str, Any]:
    actions = _mapping(value, "qualification protection actions")
    _exact_keys(
        actions,
        {
            "enabled",
            "allowed_actions",
            "default_workflow_permissions",
            "can_approve_pull_request_reviews",
            "github_owned_allowed",
            "verified_allowed",
            "patterns_allowed",
            "write_grants",
        },
        "qualification protection actions",
    )
    patterns = actions.get("patterns_allowed")
    if (
        not isinstance(patterns, list)
        or not patterns
        or not all(isinstance(item, str) and item for item in patterns)
        or patterns != sorted(set(patterns))
    ):
        raise ProductionContainerAuthorityRefused(
            "qualification protection allowed actions differ",
        )
    _exact(actions.get("enabled"), True, "qualification protection actions.enabled")
    _exact(
        actions.get("allowed_actions"),
        "selected",
        "qualification protection actions.allowed_actions",
    )
    _exact(
        actions.get("default_workflow_permissions"),
        "read",
        "qualification protection actions.default_workflow_permissions",
    )
    _exact(
        actions.get("can_approve_pull_request_reviews"),
        False,
        "qualification protection actions.can_approve_pull_request_reviews",
    )
    _exact(
        actions.get("github_owned_allowed"),
        True,
        "qualification protection actions.github_owned_allowed",
    )
    _exact(
        actions.get("verified_allowed"),
        False,
        "qualification protection actions.verified_allowed",
    )
    _exact(
        actions.get("write_grants"),
        [
            {
                "workflow_path": SOURCE_WORKFLOW_PATH,
                "permissions": {
                    "actions": "write",
                    "contents": "write",
                    "id-token": "write",
                },
            },
        ],
        "qualification protection actions.write_grants",
    )
    return dict(actions)


def _validate_source_git_readback(
    group: Mapping[str, Any],
    *,
    tag_object: str,
    revision: str,
    tree: str,
) -> None:
    base = f"https://api.github.com/repos/{SOURCE_REPOSITORY}"
    tag_ref = _mapping(
        _api_carrier(
            group.get("tag_ref"),
            label="source tag ref readback",
            expected_url=f"{base}/git/ref/tags/{SOURCE_TAG}",
        ),
        "source tag ref body",
    )
    _exact(tag_ref.get("ref"), SOURCE_TAG_REF, "source tag ref")
    tag_ref_object = _mapping(tag_ref.get("object"), "source tag ref object")
    _exact(tag_ref_object.get("type"), "tag", "source tag ref object type")
    _exact(tag_ref_object.get("sha"), tag_object, "source tag ref object SHA")

    tag = _mapping(
        _api_carrier(
            group.get("tag_object"),
            label="source tag object readback",
            expected_url=f"{base}/git/tags/{tag_object}",
        ),
        "source tag object body",
    )
    _exact(tag.get("sha"), tag_object, "source tag object SHA")
    _exact(tag.get("tag"), SOURCE_TAG, "source tag object name")
    _exact(tag.get("message"), "Release 1.9.0", "source tag message")
    tagged = _mapping(tag.get("object"), "source tag target")
    _exact(tagged.get("type"), "commit", "source tag target type")
    _exact(tagged.get("sha"), revision, "source tag target commit")
    tagger = _mapping(tag.get("tagger"), "source tag tagger")
    _exact(tagger.get("name"), "pypv", "source tag tagger name")
    _exact(
        tagger.get("email"),
        "106410335+pypv@users.noreply.github.com",
        "source tag tagger email",
    )
    tagger_date = _nonempty(tagger.get("date"), "source tag tagger date")

    commit = _mapping(
        _api_carrier(
            group.get("commit"),
            label="source commit readback",
            expected_url=f"{base}/git/commits/{revision}",
        ),
        "source commit body",
    )
    _exact(commit.get("sha"), revision, "source commit SHA")
    commit_tree = _mapping(commit.get("tree"), "source commit tree")
    _exact(commit_tree.get("sha"), tree, "source commit tree SHA")
    commit_committer = _mapping(commit.get("committer"), "source commit committer")
    _exact(commit_committer.get("date"), tagger_date, "source tag/commit date")

    tree_body = _mapping(
        _api_carrier(
            group.get("tree"),
            label="source tree readback",
            expected_url=f"{base}/git/trees/{tree}",
        ),
        "source tree body",
    )
    _exact(tree_body.get("sha"), tree, "source tree SHA")


def _validate_settings_readback(
    group: Mapping[str, Any],
    *,
    workflow: Mapping[str, Any],
    environment: Mapping[str, Any],
    actions: Mapping[str, Any],
) -> None:
    base = f"https://api.github.com/repos/{SOURCE_REPOSITORY}"
    repository = _mapping(
        _api_carrier(
            group.get("repository"),
            label="qualification repository settings readback",
            expected_url=base,
        ),
        "qualification repository settings body",
    )
    for key, expected in (
        ("full_name", SOURCE_REPOSITORY),
        ("id", SOURCE_REPOSITORY_ID),
        ("node_id", SOURCE_REPOSITORY_NODE_ID),
        ("private", False),
        ("visibility", "public"),
        ("default_branch", "main"),
    ):
        _exact(repository.get(key), expected, f"repository settings.{key}")

    workflow_body = _mapping(
        _api_carrier(
            group.get("workflow"),
            label="qualification workflow settings readback",
            expected_url=f"{base}/actions/workflows/{RELEASE_WORKFLOW_ID}",
        ),
        "qualification workflow settings body",
    )
    for key in ("id", "node_id", "name", "path", "state"):
        _exact(workflow_body.get(key), workflow[key], f"workflow settings.{key}")

    environment_body = _mapping(
        _api_carrier(
            group.get("environment"),
            label="qualification environment settings readback",
            expected_url=f"{base}/environments/{PRODUCTION_QUALIFICATION_ENVIRONMENT}",
        ),
        "qualification environment settings body",
    )
    _exact(
        environment_body.get("name"),
        PRODUCTION_QUALIFICATION_ENVIRONMENT,
        "qualification environment settings name",
    )
    _positive(environment_body.get("id"), "qualification environment settings id")
    _nonempty(
        environment_body.get("node_id"),
        "qualification environment settings node_id",
    )

    ruleset_carrier = _mapping(group.get("tag_ruleset"), "tag ruleset readback")
    ruleset_url = ruleset_carrier.get("url")
    if (
        not isinstance(ruleset_url, str)
        or re.fullmatch(
            rf"https://api\.github\.com/repos/{SOURCE_REPOSITORY}/rulesets/[1-9][0-9]*",
            ruleset_url,
        )
        is None
    ):
        raise ProductionContainerAuthorityRefused("tag ruleset readback URL differs")
    ruleset = _mapping(
        _api_carrier(
            ruleset_carrier,
            label="tag ruleset readback",
            expected_url=ruleset_url,
        ),
        "tag ruleset body",
    )
    if (
        ruleset.get("name") != "immutable-v-tags"
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("bypass_actors") != []
    ):
        raise ProductionContainerAuthorityRefused("immutable tag ruleset differs")
    conditions = _mapping(ruleset.get("conditions"), "tag ruleset conditions")
    ref_name = _mapping(conditions.get("ref_name"), "tag ruleset ref-name condition")
    _exact(
        ref_name,
        {"include": ["refs/tags/v*.*.*"], "exclude": []},
        "tag ruleset ref-name condition",
    )
    _exact(
        ruleset.get("rules"),
        [{"type": "deletion"}, {"type": "update"}],
        "tag ruleset rules",
    )

    permissions = _mapping(
        _api_carrier(
            group.get("actions_permissions"),
            label="Actions permissions readback",
            expected_url=f"{base}/actions/permissions",
        ),
        "Actions permissions body",
    )
    _exact(permissions.get("enabled"), True, "Actions permissions enabled")
    _exact(
        permissions.get("allowed_actions"),
        actions["allowed_actions"],
        "Actions permissions allowed_actions",
    )
    selected = _mapping(
        _api_carrier(
            group.get("allowed_actions"),
            label="selected Actions readback",
            expected_url=f"{base}/actions/permissions/selected-actions",
        ),
        "selected Actions body",
    )
    for key in ("github_owned_allowed", "verified_allowed", "patterns_allowed"):
        _exact(selected.get(key), actions[key], f"selected Actions {key}")
    if environment["name"] != PRODUCTION_QUALIFICATION_ENVIRONMENT:
        raise ProductionContainerAuthorityRefused(
            "qualification environment policy/readback differs",
        )


def _validate_qualification_ceremony(  # noqa: PLR0915
    value: object,
    *,
    source_tag_authority: Mapping[str, Any],
    revision: str,
    tree: str,
) -> dict[str, Any]:
    ceremony = _mapping(value, "qualification_ceremony")
    _exact_keys(
        ceremony,
        {"format", "handoff", "qualification", "protection", "readback", "verification"},
        "qualification_ceremony",
    )
    _exact(
        ceremony.get("format"),
        QUALIFICATION_CEREMONY_FORMAT,
        "qualification_ceremony.format",
    )
    _exact(
        ceremony.get("verification"),
        {"result": "pass"},
        "qualification_ceremony.verification",
    )
    handoff = _mapping(ceremony.get("handoff"), "qualification_ceremony.handoff")
    _exact_keys(
        handoff,
        {
            "schema",
            "api_version",
            "request",
            "response",
            "authority",
            "initiating_source",
            "source",
            "handoff_nonce",
            "handoff_run_name",
        },
        "qualification_ceremony.handoff",
    )
    _exact(handoff.get("schema"), HANDOFF_SCHEMA, "qualification handoff schema")
    _exact(handoff.get("api_version"), GITHUB_API_VERSION, "qualification handoff API")
    request = _mapping(handoff.get("request"), "qualification handoff request")
    _exact_keys(request, {"ref", "inputs", "return_run_details"}, "handoff request")
    _exact(request.get("ref"), SOURCE_TAG, "handoff request ref")
    _exact(request.get("return_run_details"), True, "handoff return_run_details")
    inputs = _mapping(request.get("inputs"), "handoff request inputs")
    _exact_keys(inputs, _HANDOFF_INPUT_KEYS, "handoff request inputs")
    if not all(isinstance(item, str) for item in inputs.values()):
        raise ProductionContainerAuthorityRefused("handoff inputs must all be strings")
    authority_run_id = _decimal_string(inputs["authority_run_id"], "authority_run_id")
    authority_run_attempt = _decimal_string(
        inputs["authority_run_attempt"],
        "authority_run_attempt",
    )
    initiating_run_id = _decimal_string(
        inputs["initiating_source_run_id"],
        "initiating_source_run_id",
    )
    initiating_run_attempt = _decimal_string(
        inputs["initiating_source_run_attempt"],
        "initiating_source_run_attempt",
    )
    source_workflow_id = _decimal_string(inputs["source_workflow_id"], "source_workflow_id")
    for key in ("source_tag_object", "source_commit", "source_tree"):
        if _GIT_SHA1.fullmatch(inputs[key]) is None:
            raise ProductionContainerAuthorityRefused(f"handoff {key} is malformed")
    _exact(inputs["source_commit"], revision, "handoff source commit")
    _exact(inputs["source_tree"], tree, "handoff source tree")
    _exact(inputs["source_repository"], SOURCE_REPOSITORY, "handoff source repository")
    _exact(
        inputs["source_workflow_path"],
        SOURCE_WORKFLOW_PATH,
        "handoff source workflow path",
    )
    _exact(
        inputs["authority_artifact_digest"],
        source_tag_authority["evidence_index"]["artifact_digest"],
        "handoff source authority artifact",
    )
    _exact(
        inputs["authority_subject_digest"],
        source_tag_authority["evidence_index"]["index_digest"],
        "handoff source authority wheelhouse subject",
    )
    _exact(
        authority_run_id,
        source_tag_authority["workflow"]["run_id"],
        "handoff authority run id",
    )
    _exact(
        authority_run_attempt,
        source_tag_authority["workflow"]["run_attempt"],
        "handoff authority run attempt",
    )
    nonce_basis = {
        "schema": HANDOFF_SCHEMA,
        "inputs": {
            key: inputs[key]
            for key in sorted(
                _HANDOFF_INPUT_KEYS
                - {
                    "handoff_nonce",
                    "handoff_run_name",
                }
            )
        },
    }
    nonce = _sha256(_canonical_line(nonce_basis))
    _exact(inputs["handoff_nonce"], nonce, "handoff nonce input")
    _exact(handoff.get("handoff_nonce"), nonce, "handoff nonce")
    run_name = f"source-tag-handoff-{initiating_run_id}-{initiating_run_attempt}-{nonce[:16]}"
    _exact(inputs["handoff_run_name"], run_name, "handoff run-name input")
    _exact(handoff.get("handoff_run_name"), run_name, "handoff run name")

    response = _mapping(handoff.get("response"), "qualification handoff response")
    _exact_keys(response, {"status", "body"}, "qualification handoff response")
    _exact(response.get("status"), 200, "qualification handoff response status")
    response_body = _mapping(response.get("body"), "qualification handoff response body")
    _exact_keys(
        response_body,
        {"workflow_run_id", "run_url", "html_url"},
        "qualification handoff response body",
    )
    qualification_run_id = _positive(
        response_body.get("workflow_run_id"),
        "qualification workflow run id",
    )
    _exact(
        response_body.get("run_url"),
        f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs/{qualification_run_id}",
        "qualification workflow run URL",
    )
    _exact(
        response_body.get("html_url"),
        f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{qualification_run_id}",
        "qualification workflow HTML URL",
    )
    authority = _mapping(handoff.get("authority"), "handoff authority")
    _exact_keys(
        authority,
        {"artifact_digest", "subject_digest", "run_id", "run_attempt"},
        "handoff authority",
    )
    _exact(authority.get("artifact_digest"), inputs["authority_artifact_digest"], "authority A")
    _exact(authority.get("subject_digest"), inputs["authority_subject_digest"], "authority S")
    _exact(authority.get("run_id"), authority_run_id, "authority run id")
    _exact(authority.get("run_attempt"), authority_run_attempt, "authority run attempt")

    initiating = _mapping(handoff.get("initiating_source"), "initiating source")
    _exact_keys(
        initiating,
        {"run_id", "run_attempt", "actor", "workflow"},
        "initiating source",
    )
    _exact(initiating.get("run_id"), initiating_run_id, "initiating source run id")
    _exact(
        initiating.get("run_attempt"),
        initiating_run_attempt,
        "initiating source run attempt",
    )
    initiating_actor = _stable_actor(initiating.get("actor"), "initiating source actor")
    _exact(initiating_actor["login"], inputs["initiating_actor"], "initiating actor input")
    source_workflow = _mapping(initiating.get("workflow"), "initiating source workflow")
    _exact_keys(source_workflow, {"id", "node_id", "path"}, "initiating source workflow")
    _exact(source_workflow.get("id"), source_workflow_id, "source workflow id")
    _exact(
        source_workflow.get("node_id"),
        inputs["source_workflow_node_id"],
        "source workflow node id",
    )
    _nonempty(source_workflow.get("node_id"), "source workflow node id")
    _exact(source_workflow.get("path"), SOURCE_WORKFLOW_PATH, "source workflow path")

    source = _mapping(handoff.get("source"), "qualification handoff source")
    _exact_keys(
        source,
        {"repository", "tag", "tag_object", "commit", "tree"},
        "qualification handoff source",
    )
    expected_source = {
        "repository": SOURCE_REPOSITORY,
        "tag": SOURCE_TAG,
        "tag_object": inputs["source_tag_object"],
        "commit": revision,
        "tree": tree,
    }
    _exact(source, expected_source, "qualification handoff source")

    qualification = _mapping(ceremony.get("qualification"), "qualification")
    _exact_keys(qualification, {"repository", "workflow", "run", "deployment"}, "qualification")
    repository = _mapping(qualification.get("repository"), "qualification repository")
    expected_repository = {
        "full_name": SOURCE_REPOSITORY,
        "id": SOURCE_REPOSITORY_ID,
        "node_id": SOURCE_REPOSITORY_NODE_ID,
    }
    _exact_keys(repository, set(expected_repository), "qualification repository")
    _exact(repository, expected_repository, "qualification repository")
    workflow = _mapping(qualification.get("workflow"), "qualification workflow")
    _exact_keys(
        workflow,
        {"id", "node_id", "name", "path", "state", "ref", "sha"},
        "qualification workflow",
    )
    expected_workflow = {
        "id": RELEASE_WORKFLOW_ID,
        "node_id": RELEASE_WORKFLOW_NODE_ID,
        "name": RELEASE_WORKFLOW_NAME,
        "path": RELEASE_WORKFLOW_PATH,
        "state": "active",
        "ref": SOURCE_TAG_REF,
        "sha": revision,
    }
    _exact(workflow, expected_workflow, "qualification workflow")
    run = _mapping(qualification.get("run"), "qualification run")
    _exact_keys(
        run,
        {
            "id",
            "run_attempt",
            "workflow_id",
            "api_url",
            "html_url",
            "event",
            "ref",
            "head_branch",
            "head_sha",
            "display_title",
            "status_at_receipt",
            "conclusion_at_receipt",
            "actor",
            "triggering_actor",
        },
        "qualification run",
    )
    _exact(run.get("id"), qualification_run_id, "qualification run id")
    _exact(run.get("run_attempt"), 1, "qualification run attempt")
    _exact(run.get("workflow_id"), RELEASE_WORKFLOW_ID, "qualification run workflow id")
    _exact(run.get("api_url"), response_body["run_url"], "qualification run API URL")
    _exact(run.get("html_url"), response_body["html_url"], "qualification run HTML URL")
    _exact(run.get("event"), "workflow_dispatch", "qualification run event")
    _exact(run.get("ref"), SOURCE_TAG_REF, "qualification run ref")
    _exact(run.get("head_branch"), SOURCE_TAG, "qualification run head branch")
    _exact(run.get("head_sha"), revision, "qualification run head SHA")
    _exact(run.get("display_title"), run_name, "qualification run display title")
    _exact(run.get("status_at_receipt"), "in_progress", "qualification run receipt status")
    _exact(run.get("conclusion_at_receipt"), None, "qualification run receipt conclusion")
    run_actor = _stable_actor(run.get("actor"), "qualification run actor")
    triggering_actor = _stable_actor(
        run.get("triggering_actor"),
        "qualification run triggering actor",
    )

    deployment = _mapping(qualification.get("deployment"), "qualification deployment")
    _exact_keys(
        deployment,
        {
            "environment",
            "job_id",
            "job_name",
            "approval_state",
            "reviewer",
            "prevent_self_review",
        },
        "qualification deployment",
    )
    deployment_environment = _mapping(
        deployment.get("environment"),
        "qualification deployment environment",
    )
    _exact_keys(
        deployment_environment,
        {"id", "node_id", "name"},
        "qualification deployment environment",
    )
    _positive(deployment_environment.get("id"), "qualification environment id")
    _nonempty(deployment_environment.get("node_id"), "qualification environment node id")
    _exact(
        deployment_environment.get("name"),
        PRODUCTION_QUALIFICATION_ENVIRONMENT,
        "qualification deployment environment name",
    )
    _positive(deployment.get("job_id"), "qualification deployment job id")
    _nonempty(deployment.get("job_name"), "qualification deployment job name")
    _exact(deployment.get("approval_state"), "approved", "qualification approval state")
    reviewer = _stable_actor(
        deployment.get("reviewer"),
        "qualification reviewer",
        allowed_types=("User",),
    )
    _exact(
        deployment.get("prevent_self_review"),
        True,
        "qualification deployment prevent_self_review",
    )
    if reviewer in (run_actor, triggering_actor, initiating_actor):
        raise ProductionContainerAuthorityRefused(
            "qualification reviewer is not independent from the initiating actor",
        )

    protection = _mapping(ceremony.get("protection"), "qualification protection")
    _exact_keys(
        protection,
        {"repository", "workflow", "environment", "actions", "settings_authority"},
        "qualification protection",
    )
    _exact(protection.get("repository"), repository, "qualification protection repository")
    _exact(protection.get("workflow"), workflow, "qualification protection workflow")
    protection_environment = _validate_protection_environment(protection.get("environment"))
    if reviewer not in protection_environment["reviewers"]:
        raise ProductionContainerAuthorityRefused(
            "qualification reviewer is absent from the protected environment",
        )
    actions = _validate_actions_policy(protection.get("actions"))
    settings_authority = _mapping(
        protection.get("settings_authority"),
        "qualification settings authority",
    )
    _exact_keys(
        settings_authority,
        {"format", "sha256", "size", "automation_principal"},
        "qualification settings authority",
    )
    automation_principal = _stable_actor(
        settings_authority.get("automation_principal"),
        "qualification automation principal",
    )
    _exact(
        run_actor,
        automation_principal,
        "qualification run actor/approved automation principal",
    )
    _exact(
        triggering_actor,
        automation_principal,
        "qualification triggering actor/approved automation principal",
    )
    if automation_principal == initiating_actor:
        raise ProductionContainerAuthorityRefused(
            "qualification automation principal aliases the initiating source actor",
        )
    _exact(
        settings_authority.get("format"),
        "z4j-release-settings-authority-v1",
        "qualification settings authority format",
    )
    _hex_sha256(
        settings_authority.get("sha256"),
        "qualification settings authority sha256",
    )
    _size(settings_authority.get("size"), "qualification settings authority size")

    readback = _mapping(ceremony.get("readback"), "qualification readback")
    _exact_keys(
        readback,
        {"qualification", "initiating_source", "authority_source", "source_git", "settings"},
        "qualification readback",
    )
    base = f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs"
    decoded_groups: dict[str, dict[str, Any]] = {}
    for name, readback_run_id in (
        ("qualification", qualification_run_id),
        ("initiating_source", initiating_run_id),
        ("authority_source", authority_run_id),
    ):
        group = _mapping(readback.get(name), f"{name} readback")
        _exact_keys(group, {"run", "jobs", "approvals"}, f"{name} readback")
        decoded_groups[name] = {
            "run": _api_carrier(
                group.get("run"),
                label=f"{name} run readback",
                expected_url=f"{base}/{readback_run_id}",
            ),
            "jobs": _api_carrier(
                group.get("jobs"),
                label=f"{name} jobs readback",
                expected_url=f"{base}/{readback_run_id}/jobs?filter=all&per_page=100&page=1",
            ),
            "approvals": _api_carrier(
                group.get("approvals"),
                label=f"{name} approvals readback",
                expected_url=f"{base}/{readback_run_id}/approvals",
            ),
        }
    qualification_expected = {
        "id": qualification_run_id,
        "run_attempt": run["run_attempt"],
        "workflow_id": RELEASE_WORKFLOW_ID,
        "url": run["api_url"],
        "html_url": run["html_url"],
        "event": "workflow_dispatch",
        "head_branch": SOURCE_TAG,
        "head_sha": revision,
        "display_title": run_name,
        "actor": run_actor,
        "triggering_actor": triggering_actor,
    }
    _validate_run_body(
        decoded_groups["qualification"]["run"],
        label="qualification run readback",
        expected=qualification_expected,
        status="in_progress",
        conclusions={None},
    )
    _validate_qualification_jobs(
        decoded_groups["qualification"]["jobs"],
        run_id=qualification_run_id,
        head_sha=revision,
        deployment=deployment,
    )
    qualification_reviewer = _approved_review(
        decoded_groups["qualification"]["approvals"],
        label="qualification approvals readback",
        environment=PRODUCTION_QUALIFICATION_ENVIRONMENT,
    )
    _exact(qualification_reviewer, reviewer, "qualification approval reviewer")

    initiating_body = _mapping(
        decoded_groups["initiating_source"]["run"],
        "initiating source run readback",
    )
    initiating_triggering = _api_actor(
        initiating_body.get("triggering_actor"),
        "initiating source triggering actor",
    )
    source_run_common = {
        "workflow_id": source_workflow_id,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": revision,
        "actor": initiating_actor,
        "triggering_actor": initiating_triggering,
    }
    initiating_expected = {
        **source_run_common,
        "id": initiating_run_id,
        "run_attempt": initiating_run_attempt,
        "url": f"{base}/{initiating_run_id}",
        "html_url": f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{initiating_run_id}",
        "display_title": decoded_groups["initiating_source"]["run"].get("display_title"),
    }
    _nonempty(initiating_expected["display_title"], "initiating source display title")
    _validate_run_body(
        decoded_groups["initiating_source"]["run"],
        label="initiating source run readback",
        expected=initiating_expected,
        status="completed",
        conclusions={"success"},
    )
    _validate_source_jobs(
        decoded_groups["initiating_source"]["jobs"],
        label="initiating source jobs readback",
        run_id=initiating_run_id,
        head_sha=revision,
        conclusions={"success"},
    )
    initiating_reviewer = _approved_review(
        decoded_groups["initiating_source"]["approvals"],
        label="initiating source approvals readback",
        environment="production-release",
    )
    if initiating_reviewer in (initiating_actor, initiating_triggering):
        raise ProductionContainerAuthorityRefused(
            "initiating source reviewer is not independent",
        )

    authority_body = _mapping(
        decoded_groups["authority_source"]["run"],
        "authority source run readback",
    )
    authority_actor = _api_actor(authority_body.get("actor"), "authority source actor")
    authority_triggering = _api_actor(
        authority_body.get("triggering_actor"),
        "authority source triggering actor",
    )
    authority_conclusion = authority_body.get("conclusion")
    if authority_conclusion not in {"success", "failure", "cancelled", "timed_out"}:
        raise ProductionContainerAuthorityRefused(
            "authority source run conclusion differs",
        )
    authority_expected = {
        "workflow_id": source_workflow_id,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": revision,
        "id": authority_run_id,
        "run_attempt": authority_run_attempt,
        "url": f"{base}/{authority_run_id}",
        "html_url": f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{authority_run_id}",
        "display_title": authority_body.get("display_title"),
        "actor": authority_actor,
        "triggering_actor": authority_triggering,
    }
    _nonempty(authority_expected["display_title"], "authority source display title")
    _validate_run_body(
        authority_body,
        label="authority source run readback",
        expected=authority_expected,
        status="completed",
        conclusions={authority_conclusion},
    )
    _validate_source_jobs(
        decoded_groups["authority_source"]["jobs"],
        label="authority source jobs readback",
        run_id=authority_run_id,
        head_sha=revision,
        conclusions={str(authority_conclusion)},
    )
    authority_reviewer = _approved_review(
        decoded_groups["authority_source"]["approvals"],
        label="authority source approvals readback",
        environment="production-release",
    )
    if authority_reviewer in (authority_actor, authority_triggering):
        raise ProductionContainerAuthorityRefused(
            "authority source reviewer is not independent",
        )

    source_git = _mapping(readback.get("source_git"), "source Git readback")
    _exact_keys(
        source_git,
        {"tag_ref", "tag_object", "commit", "tree"},
        "source Git readback",
    )
    _validate_source_git_readback(
        source_git,
        tag_object=inputs["source_tag_object"],
        revision=revision,
        tree=tree,
    )
    settings = _mapping(readback.get("settings"), "qualification settings readback")
    _exact_keys(
        settings,
        {
            "repository",
            "workflow",
            "environment",
            "tag_ruleset",
            "actions_permissions",
            "allowed_actions",
        },
        "qualification settings readback",
    )
    _validate_settings_readback(
        settings,
        workflow=workflow,
        environment=protection_environment,
        actions=actions,
    )
    return dict(ceremony)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_float(value: str) -> Any:
    raise ValueError(f"floating-point JSON number is forbidden: {value}")


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionContainerAuthorityRefused(f"{label} is not valid JSON") from exc
    except ValueError as exc:
        raise ProductionContainerAuthorityRefused(
            f"{label} is not canonical JSON: {exc}",
        ) from exc


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_regular_bytes(
    descriptor: int,
    *,
    maximum: int,
    label: str,
    require_root_owned: bool,
) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ProductionContainerAuthorityRefused(f"{label} is not a regular file")
    if before.st_nlink != 1:
        raise ProductionContainerAuthorityRefused(f"{label} must have exactly one hard link")
    if before.st_size <= 0 or before.st_size > maximum:
        raise ProductionContainerAuthorityRefused(f"{label} has an invalid or oversized length")
    if require_root_owned and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o022):
        raise ProductionContainerAuthorityRefused(
            f"{label} is not root-owned and non-writable",
        )
    remaining = before.st_size
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ProductionContainerAuthorityRefused(f"{label} shortened while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ProductionContainerAuthorityRefused(f"{label} grew while being read")
    after = os.fstat(descriptor)
    raw = b"".join(chunks)
    if _stat_identity(before) != _stat_identity(after) or len(raw) != before.st_size:
        raise ProductionContainerAuthorityRefused(f"{label} changed while being read")
    return raw


def _read_exact_inventory(root: Path) -> dict[str, bytes]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ProductionContainerAuthorityRefused("no-follow authority reads are unavailable")

    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    member_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_descriptor = os.open(root, root_flags)
    except OSError as exc:
        raise ProductionContainerAuthorityRefused(
            "production finalization authority root is absent or unsafe",
        ) from exc
    result: dict[str, bytes] = {}
    try:
        root_stat = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ProductionContainerAuthorityRefused(
                "production finalization authority root must be a real directory",
            )
        root_before = _stat_identity(root_stat)
        try:
            names = os.listdir(root_descriptor)  # noqa: PTH208 - preserve fd binding
        except OSError as exc:
            raise ProductionContainerAuthorityRefused(
                "production finalization authority root cannot be read",
            ) from exc
        if len(names) != len(_REQUIRED_FILES) or set(names) != _REQUIRED_FILES:
            raise ProductionContainerAuthorityRefused(
                "production finalization authority inventory must contain exactly four files",
            )
        for name in sorted(names):
            try:
                descriptor = os.open(name, member_flags, dir_fd=root_descriptor)
            except OSError as exc:
                raise ProductionContainerAuthorityRefused(
                    f"production authority member {name!r} is not a regular file or is unsafe",
                ) from exc
            try:
                result[name] = _stable_regular_bytes(
                    descriptor,
                    maximum=_AUTHORITY_FILE_LIMITS[name],
                    label=f"production authority member {name!r}",
                    require_root_owned=False,
                )
            finally:
                os.close(descriptor)
        if (
            _stat_identity(os.fstat(root_descriptor)) != root_before
            or set(
                os.listdir(root_descriptor)  # noqa: PTH208 - preserve fd binding
            )
            != _REQUIRED_FILES
        ):
            raise ProductionContainerAuthorityRefused(
                "production finalization authority root changed while being read",
            )
    finally:
        os.close(root_descriptor)
    return result


def _default_binary_reader(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ProductionContainerAuthorityRefused("no-follow Cosign reads are unavailable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProductionContainerAuthorityRefused(
            "sealed Cosign runtime is absent or unsafe",
        ) from exc
    try:
        return _stable_regular_bytes(
            descriptor,
            maximum=_MAX_COSIGN_BINARY_BYTES,
            label="sealed Cosign runtime",
            require_root_owned=True,
        )
    finally:
        os.close(descriptor)


def _default_cosign_runner(command: Sequence[str]) -> CompletedProcessLike:  # noqa: PLR0912, PLR0915
    if not command or not Path(command[0]).is_absolute():
        raise ProductionContainerAuthorityRefused(
            "Cosign runner requires a private absolute executable path",
        )
    process = subprocess.Popen(  # noqa: S603 - fixed executable and exact arguments
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=_COSIGN_ENV,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ProductionContainerAuthorityRefused("Cosign pipes were not created")
    streams = {
        process.stdout: ("stdout", _MAX_COSIGN_STDOUT_BYTES),
        process.stderr: ("stderr", _MAX_COSIGN_STDERR_BYTES),
    }
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + _COSIGN_TIMEOUT_SECONDS

    def kill_group() -> None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(command), _COSIGN_TIMEOUT_SECONDS)  # noqa: TRY301
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _mask in events:
                stream = key.fileobj
                label, maximum = streams[stream]
                chunk = os.read(stream.fileno(), min(64 * 1024, maximum + 1))
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffers[label].extend(chunk)
                if len(buffers[label]) > maximum:
                    raise ProductionContainerAuthorityRefused(  # noqa: TRY301
                        f"Cosign {label} exceeded its transcript size limit",
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(list(command), _COSIGN_TIMEOUT_SECONDS)  # noqa: TRY301
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        kill_group()
        raise ProductionContainerAuthorityRefused(
            "Cosign process group exceeded its execution deadline",
        ) from exc
    except BaseException:
        kill_group()
        raise
    finally:
        selector.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        if process.stderr is not None and not process.stderr.closed:
            process.stderr.close()
    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", "strict")
        stderr = bytes(buffers["stderr"]).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProductionContainerAuthorityRefused(
            "Cosign transcript is not strict UTF-8",
        ) from exc
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _write_private_executable(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o500)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o500)
    finally:
        os.close(descriptor)


def _verify_cosign_with_runner(
    members: Mapping[str, bytes],
    *,
    expected_binary: Mapping[str, Any],
    candidate_reference: str,
    runner: CosignRunner,
    executable: str,
) -> None:
    version = runner((executable, "version", "--json"))
    if version.returncode != 0:
        raise ProductionContainerAuthorityRefused("Cosign version probe failed")
    version_raw = version.stdout.encode("utf-8")
    version_payload = _mapping(_json(version_raw, "Cosign version output"), "Cosign version output")
    if (
        len(version_raw) != expected_binary["version_output_size"]
        or _sha256(version_raw) != expected_binary["version_output_sha256"]
    ):
        raise ProductionContainerAuthorityRefused(
            "Cosign version output differs from signed production authority",
        )
    reported = version_payload.get("gitVersion")
    if not isinstance(reported, str) or reported.removeprefix("v") != COSIGN_VERSION:
        raise ProductionContainerAuthorityRefused(
            f"Cosign must be exactly {COSIGN_VERSION}",
        )
    # Never ask Cosign to reopen the caller-controlled authority root after its
    # bytes have been parsed. A mutable bind mount could otherwise swap them.
    with tempfile.TemporaryDirectory(prefix="z4j-production-authority-") as directory:
        private_root = Path(directory)
        receipt_path = private_root / "production-finalization.json"
        bundle_path = private_root / "production-finalization.bundle.json"
        receipt_path.write_bytes(members[receipt_path.name])
        bundle_path.write_bytes(members[bundle_path.name])
        receipt_path.chmod(0o600)
        bundle_path.chmod(0o600)
        verification = runner(
            (
                executable,
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity",
                PRODUCTION_WORKFLOW_IDENTITY,
                "--certificate-oidc-issuer",
                PRODUCTION_OIDC_ISSUER,
                str(receipt_path),
            ),
        )
    if verification.returncode != 0:
        raise ProductionContainerAuthorityRefused(
            "production finalization receipt Sigstore authentication failed",
        )
    attestation = runner(
        (
            executable,
            "verify-attestation",
            "--type",
            PRODUCTION_ATTESTATION_TYPE,
            "--certificate-identity",
            PRODUCTION_WORKFLOW_IDENTITY,
            "--certificate-oidc-issuer",
            PRODUCTION_OIDC_ISSUER,
            candidate_reference,
        ),
    )
    if attestation.returncode != 0:
        raise ProductionContainerAuthorityRefused(
            "production finalization OCI attestation authentication failed",
        )
    live_statement = _statement_from_attestation(attestation.stdout.encode("utf-8"))
    retained_statement = _statement_from_attestation(
        members["production-finalization.attestation.jsonl"],
    )
    _exact(
        live_statement,
        retained_statement,
        "live and retained production finalization attestations",
    )


def _verify_cosign(
    members: Mapping[str, bytes],
    *,
    signature_verifier: Mapping[str, Any],
    candidate_reference: str,
    runner: CosignRunner,
    binary_reader: BinaryReader,
    runtime_machine: str,
) -> None:
    machine_to_platform = {
        "x86_64": "linux/amd64",
        "amd64": "linux/amd64",
        "aarch64": "linux/arm64",
        "arm64": "linux/arm64",
    }
    runtime_platform = machine_to_platform.get(runtime_machine.lower())
    if runtime_platform_module.system() != "Linux" or runtime_platform is None:
        raise ProductionContainerAuthorityRefused(
            "production authority must run natively on sealed Linux amd64/arm64",
        )
    expected_binary = signature_verifier["platforms"][runtime_platform]
    binary = binary_reader(Path(COSIGN_PATH))
    if len(binary) != expected_binary["size"] or _sha256(binary) != expected_binary["sha256"]:
        raise ProductionContainerAuthorityRefused(
            "Cosign runtime bytes differ from signed production authority",
        )
    if runner is _default_cosign_runner and binary_reader is _default_binary_reader:
        with tempfile.TemporaryDirectory(prefix="z4j-production-cosign-") as directory:
            private_cosign = Path(directory) / "cosign"
            _write_private_executable(private_cosign, binary)
            _verify_cosign_with_runner(
                members,
                expected_binary=expected_binary,
                candidate_reference=candidate_reference,
                runner=runner,
                executable=str(private_cosign),
            )
            if binary_reader(Path(COSIGN_PATH)) != binary:
                raise ProductionContainerAuthorityRefused(
                    "sealed Cosign runtime changed during authentication",
                )
        return
    _verify_cosign_with_runner(
        members,
        expected_binary=expected_binary,
        candidate_reference=candidate_reference,
        runner=runner,
        executable=COSIGN_PATH,
    )


def _statement_from_attestation(raw: bytes) -> dict[str, Any]:
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        raise ProductionContainerAuthorityRefused(
            "production finalization attestation transcript is empty",
        )
    records: list[object] = []
    for line in lines:
        record = _json(line, "production finalization attestation record")
        if isinstance(record, list):
            records.extend(record)
        else:
            records.append(record)
    statements: dict[bytes, dict[str, Any]] = {}
    for record in records:
        statement = _statement_from_envelope(record)
        canonical = json.dumps(
            statement,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        statements[canonical] = statement
    if len(statements) != 1:
        raise ProductionContainerAuthorityRefused(
            "production finalization attestations must contain exactly one unique statement",
        )
    return next(iter(statements.values()))


def _statement_from_envelope(record: object) -> dict[str, Any]:
    envelope = _mapping(record, "production finalization attestation envelope")
    _exact_keys(
        envelope,
        {"payloadType", "payload", "signatures"},
        "production finalization DSSE envelope",
    )
    _exact(
        envelope.get("payloadType"),
        "application/vnd.in-toto+json",
        "production finalization DSSE payload type",
    )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ProductionContainerAuthorityRefused(
            "production finalization DSSE envelope has no signature",
        )
    payload = envelope.get("payload")
    if isinstance(payload, str):
        try:
            statement_raw = base64.b64decode(payload, validate=True)
        except ValueError as exc:
            raise ProductionContainerAuthorityRefused(
                "production finalization DSSE payload is not canonical base64",
            ) from exc
        return _mapping(
            _json(statement_raw, "production finalization DSSE statement"),
            "production finalization DSSE statement",
        )
    raise ProductionContainerAuthorityRefused(
        "production finalization attestation is not a DSSE envelope",
    )


def _verify_attestation(
    raw: bytes,
    *,
    receipt: dict[str, Any],
    candidate_digest: str,
) -> None:
    statement = _statement_from_attestation(raw)
    _exact_keys(
        statement,
        {"_type", "predicate", "predicateType", "subject"},
        "production finalization statement",
    )
    _exact(
        statement.get("_type"),
        "https://in-toto.io/Statement/v1",
        "production finalization statement type",
    )
    _exact(
        statement.get("predicateType"),
        PRODUCTION_ATTESTATION_TYPE,
        "production finalization predicate type",
    )
    _exact(statement.get("predicate"), receipt, "production finalization predicate")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ProductionContainerAuthorityRefused(
            "production finalization attestation must have one subject",
        )
    subject = _mapping(subjects[0], "production finalization attestation subject")
    _exact_keys(
        subject,
        {"digest", "name"},
        "production finalization attestation subject",
    )
    _exact(
        subject.get("name"),
        PRODUCTION_IMAGE_REPOSITORY,
        "production finalization subject repository",
    )
    digest = _mapping(subject.get("digest"), "production finalization subject digest")
    _exact_keys(digest, {"sha256"}, "production finalization subject digest")
    _exact(
        digest.get("sha256"),
        candidate_digest.removeprefix("sha256:"),
        "production finalization subject digest",
    )


def _validate_signature_verifier(value: object, label: str) -> dict[str, Any]:
    authority = _mapping(value, label)
    _exact_keys(
        authority,
        {"name", "version", "runtime_path", "release_response", "platforms"},
        label,
    )
    _exact(authority.get("name"), "cosign", f"{label}.name")
    _exact(authority.get("version"), COSIGN_VERSION, f"{label}.version")
    _exact(authority.get("runtime_path"), COSIGN_PATH, f"{label}.runtime_path")

    release_response = _mapping(
        authority.get("release_response"),
        f"{label}.release_response",
    )
    _exact_keys(
        release_response,
        {"path", "sha256", "size"},
        f"{label}.release_response",
    )
    _exact(
        release_response.get("path"),
        "evidence/cosign-release.json",
        f"{label}.release_response.path",
    )
    _hex_sha256(
        release_response.get("sha256"),
        f"{label}.release_response.sha256",
    )
    _size(release_response.get("size"), f"{label}.release_response.size")

    platforms = _mapping(authority.get("platforms"), f"{label}.platforms")
    _exact_keys(platforms, {"linux/amd64", "linux/arm64"}, f"{label}.platforms")
    for platform, filename in (
        ("linux/amd64", "cosign-linux-amd64"),
        ("linux/arm64", "cosign-linux-arm64"),
    ):
        record = _mapping(platforms.get(platform), f"{label}.platforms.{platform}")
        _exact_keys(
            record,
            {
                "filename",
                "url",
                "sha256",
                "size",
                "version_output_sha256",
                "version_output_size",
            },
            f"{label}.platforms.{platform}",
        )
        _exact(record.get("filename"), filename, f"{label}.platforms.{platform}.filename")
        _exact(
            record.get("url"),
            f"https://github.com/sigstore/cosign/releases/download/v{COSIGN_VERSION}/{filename}",
            f"{label}.platforms.{platform}.url",
        )
        _hex_sha256(record.get("sha256"), f"{label}.platforms.{platform}.sha256")
        _size(record.get("size"), f"{label}.platforms.{platform}.size")
        _hex_sha256(
            record.get("version_output_sha256"),
            f"{label}.platforms.{platform}.version_output_sha256",
        )
        _size(
            record.get("version_output_size"),
            f"{label}.platforms.{platform}.version_output_size",
        )
    return authority


def _validate_labels(
    value: object,
    *,
    expected: Mapping[str, str],
    label: str,
) -> dict[str, str]:
    labels = _mapping(value, label)
    _exact_keys(labels, _CANDIDATE_LABEL_KEYS, label)
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in labels.items()):
        raise ProductionContainerAuthorityRefused(f"{label} must contain string OCI labels")
    _exact(labels, dict(expected), label)
    return dict(labels)


def _validate_native(
    value: object,
    *,
    arch: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    native = _mapping(value, f"native.{arch}")
    _exact_keys(native, _NATIVE_KEYS, f"native.{arch}")
    _exact(native.get("format"), PRODUCTION_NATIVE_FORMAT, f"native.{arch}.format")
    _exact(
        native.get("release_git_commit"),
        receipt["release_git_commit"],
        f"native.{arch}.release_git_commit",
    )
    _exact(
        native.get("release_git_tree"),
        receipt["release_git_tree"],
        f"native.{arch}.release_git_tree",
    )
    _exact(native.get("platform"), f"linux/{arch}", f"native.{arch}.platform")
    contract = _mapping(native.get("contract"), f"native.{arch}.contract")
    _exact_keys(
        contract,
        {"manifest_sha256", "source_projection_sha256"},
        f"native.{arch}.contract",
    )
    _exact(
        contract.get("manifest_sha256"),
        receipt["manifest_sha256"],
        f"native.{arch}.contract.manifest_sha256",
    )
    _exact(
        contract.get("source_projection_sha256"),
        receipt["production_source_projection_sha256"],
        f"native.{arch}.contract.source_projection_sha256",
    )
    signature_verifier = _validate_signature_verifier(
        native.get("signature_verifier"),
        f"native.{arch}.signature_verifier",
    )
    _exact(
        signature_verifier,
        receipt["signature_verifier"],
        f"native.{arch}.signature_verifier",
    )
    for member in ("python", "install", "candidate_scanner"):
        if not _mapping(native.get(member), f"native.{arch}.{member}"):
            raise ProductionContainerAuthorityRefused(f"native.{arch}.{member} is empty")
    bundle_indexes: dict[str, str] = {}
    for member in ("wheelhouse", "system_packages", "dashboard"):
        bundle = _mapping(native.get(member), f"native.{arch}.{member}")
        index = _mapping(bundle.get("index"), f"native.{arch}.{member}.index")
        bundle_indexes[member] = _digest(
            index.get("digest"),
            f"native.{arch}.{member}.index.digest",
        )
    candidate = _mapping(native.get("candidate"), f"native.{arch}.candidate")
    _exact_keys(candidate, _CANDIDATE_KEYS, f"native.{arch}.candidate")
    manifest_digest = _digest(
        candidate.get("manifest_digest"),
        f"native.{arch}.candidate.manifest_digest",
    )
    build_output_digest = _digest(
        candidate.get("build_output_digest"),
        f"native.{arch}.candidate.build_output_digest",
    )
    projected_candidate = {
        "build_output_digest": build_output_digest,
        "manifest": {
            "digest": manifest_digest,
            "size": _size(
                candidate.get("manifest_size"),
                f"native.{arch}.candidate.manifest_size",
            ),
        },
        "config": {
            "digest": _digest(
                candidate.get("config_digest"),
                f"native.{arch}.candidate.config_digest",
            ),
            "size": _size(
                candidate.get("config_size"),
                f"native.{arch}.candidate.config_size",
            ),
        },
        "labels": _validate_labels(
            candidate.get("labels"),
            expected={
                "org.opencontainers.image.revision": receipt["release_git_commit"],
                "org.z4j.production.manifest.sha256": receipt["manifest_sha256"],
                "org.z4j.production.source-projection.sha256": receipt[
                    "production_source_projection_sha256"
                ],
                "org.z4j.production.wheelhouse.index": bundle_indexes["wheelhouse"],
                "org.z4j.production.system-bundle.index": bundle_indexes["system_packages"],
                "org.z4j.production.dashboard-bundle.index": bundle_indexes["dashboard"],
            },
            label=f"native.{arch}.candidate.labels",
        ),
    }
    cadence_probe = _seal(native.get("cadence_probe"), f"native.{arch}.cadence_probe")
    signature_verifier_probe = _seal(
        native.get("signature_verifier_probe"),
        f"native.{arch}.signature_verifier_probe",
    )
    dashboard_replay = _seal(native.get("dashboard_replay"), f"native.{arch}.dashboard_replay")
    service_smoke = _seal(native.get("service_smoke"), f"native.{arch}.service_smoke")
    candidate_sbom = _mapping(native.get("candidate_sbom"), f"native.{arch}.candidate_sbom")
    _exact_keys(candidate_sbom, {"cyclonedx", "spdx"}, f"native.{arch}.candidate_sbom")
    sbom = {
        name: _seal(candidate_sbom.get(name), f"native.{arch}.candidate_sbom.{name}")
        for name in ("cyclonedx", "spdx")
    }
    return {
        "candidate": projected_candidate,
        "cadence_probe": cadence_probe,
        "signature_verifier": signature_verifier,
        "signature_verifier_probe": signature_verifier_probe,
        "dashboard_replay": dashboard_replay,
        "service_smoke": service_smoke,
        "candidate_sbom": sbom,
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


def _registry_opener() -> urllib.request.OpenerDirector:
    try:
        metadata = os.stat(  # noqa: PTH116 - fixed path requires no-follow metadata
            _SYSTEM_CA_BUNDLE,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise ProductionContainerAuthorityRefused(
            "fixed system CA bundle is absent or unsafe",
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ProductionContainerAuthorityRefused(
            "fixed system CA bundle is not root-owned and non-writable",
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(_SYSTEM_CA_BUNDLE))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )


def _single_response_header(headers: Any, name: str) -> str:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name, [])
    else:
        values = [
            value
            for key, value in headers.items()
            if isinstance(key, str) and key.lower() == name.lower()
        ]
    if len(values) != 1 or not isinstance(values[0], str):
        raise ProductionContainerAuthorityRefused(
            f"registry response must contain exactly one {name} header",
        )
    value = values[0]
    if "\r" in value or "\n" in value or value != value.strip():
        raise ProductionContainerAuthorityRefused(
            f"registry response {name} header has invalid folding or whitespace",
        )
    return value


def _validate_registry_response(
    response: Any,
    *,
    expected_url: str,
    content_types: set[str],
    expected_digest: str | None,
) -> None:
    if getattr(response, "status", None) != 200:
        raise ProductionContainerAuthorityRefused("registry response status is not HTTP 200")
    if response.geturl() != expected_url:
        raise ProductionContainerAuthorityRefused("registry response URL differs or redirected")
    headers = response.headers
    content_type = _single_response_header(headers, "Content-Type").split(";", 1)[0].lower()
    if content_type not in content_types:
        raise ProductionContainerAuthorityRefused("registry response content type differs")
    if expected_digest is not None:
        observed = _single_response_header(headers, "Docker-Content-Digest")
        if observed != expected_digest:
            raise ProductionContainerAuthorityRefused(
                "registry response Docker-Content-Digest differs",
            )


def _bounded_response(response: Any, *, maximum: int, label: str) -> bytes:
    raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ProductionContainerAuthorityRefused(f"{label} is too large")
    return raw


def _default_registry_fetcher() -> RegistryFetcher:
    opener = _registry_opener()
    token_url = "https://auth.docker.io/token?" + urllib.parse.urlencode(
        {
            "service": "registry.docker.io",
            "scope": "repository:z4jdev/z4j:pull",
        },
    )
    try:
        with opener.open(token_url, timeout=30) as response:
            _validate_registry_response(
                response,
                expected_url=token_url,
                content_types={"application/json"},
                expected_digest=None,
            )
            token_payload = _mapping(
                _json(
                    _bounded_response(
                        response, maximum=1024 * 1024, label="registry token response"
                    ),
                    "registry token response",
                ),
                "registry token response",
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProductionContainerAuthorityRefused(
            "Docker registry authentication for production authority failed",
        ) from exc
    token = token_payload.get("token")
    if not isinstance(token, str) or not token:
        raise ProductionContainerAuthorityRefused(
            "Docker registry returned no production-authority pull token",
        )

    def fetch(kind: str, digest: str) -> bytes:
        if kind == "manifest":
            suffix = f"manifests/{digest}"
            accept = f"{_OCI_INDEX_MEDIA_TYPE}, {_OCI_MANIFEST_MEDIA_TYPE}"
        elif kind == "blob":
            suffix = f"blobs/{digest}"
            accept = "application/octet-stream"
        else:
            raise ProductionContainerAuthorityRefused("unsupported OCI fetch kind")
        request = urllib.request.Request(
            f"https://registry-1.docker.io/v2/z4jdev/z4j/{suffix}",
            headers={"Authorization": f"Bearer {token}", "Accept": accept},
        )
        try:
            with opener.open(request, timeout=30) as response:
                _validate_registry_response(
                    response,
                    expected_url=request.full_url,
                    content_types=(
                        {_OCI_INDEX_MEDIA_TYPE, _OCI_MANIFEST_MEDIA_TYPE}
                        if kind == "manifest"
                        else {"application/octet-stream"}
                    ),
                    expected_digest=digest,
                )
                return _bounded_response(
                    response,
                    maximum=16 * 1024 * 1024,
                    label=f"registry {kind} response",
                )
        except OSError as exc:
            raise ProductionContainerAuthorityRefused(
                f"Docker registry re-read failed for {digest}",
            ) from exc

    return fetch


def _raw_descriptor(raw: bytes, expected: Mapping[str, object], label: str) -> None:
    expected_digest = _digest(expected.get("digest"), f"{label}.digest")
    expected_size = _size(expected.get("size"), f"{label}.size")
    if len(raw) != expected_size or _sha256(raw) != expected_digest.removeprefix("sha256:"):
        raise ProductionContainerAuthorityRefused(
            f"registry bytes differ from the finalized {label} descriptor",
        )


def _verify_registry(
    *,
    raw_index: bytes,
    receipt_index: dict[str, object],
    native: dict[str, dict[str, Any]],
    fetch: RegistryFetcher,
) -> None:
    fetched_index = fetch("manifest", str(receipt_index["digest"]))
    _raw_descriptor(fetched_index, receipt_index, "candidate index")
    if fetched_index != raw_index:
        raise ProductionContainerAuthorityRefused(
            "registry candidate index bytes differ from retained staging-index.json",
        )
    index = _mapping(_json(raw_index, "staging-index.json"), "staging-index.json")
    _exact(index.get("schemaVersion"), 2, "candidate index schemaVersion")
    _exact(index.get("mediaType"), _OCI_INDEX_MEDIA_TYPE, "candidate index mediaType")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 2:
        raise ProductionContainerAuthorityRefused(
            "candidate index must contain exactly two native descriptors",
        )
    by_arch: dict[str, dict[str, Any]] = {}
    for value in manifests:
        descriptor = _mapping(value, "candidate index descriptor")
        platform = _mapping(descriptor.get("platform"), "candidate index platform")
        _exact(platform.get("os"), "linux", "candidate index platform.os")
        arch = platform.get("architecture")
        if arch not in {"amd64", "arm64"} or arch in by_arch:
            raise ProductionContainerAuthorityRefused(
                "candidate index platforms must be exactly linux/amd64 and linux/arm64",
            )
        _exact(
            descriptor.get("mediaType"),
            _OCI_MANIFEST_MEDIA_TYPE,
            f"candidate index {arch} mediaType",
        )
        by_arch[str(arch)] = descriptor
    if set(by_arch) != {"amd64", "arm64"}:
        raise ProductionContainerAuthorityRefused(
            "candidate index platforms must be exactly linux/amd64 and linux/arm64",
        )
    for arch in ("amd64", "arm64"):
        candidate = native[arch]["candidate"]
        descriptor = by_arch[arch]
        _exact(
            descriptor.get("digest"),
            candidate["manifest"]["digest"],
            f"candidate index {arch} manifest digest",
        )
        _exact(
            descriptor.get("size"),
            candidate["manifest"]["size"],
            f"candidate index {arch} manifest size",
        )
        manifest_raw = fetch("manifest", candidate["manifest"]["digest"])
        _raw_descriptor(manifest_raw, candidate["manifest"], f"{arch} manifest")
        manifest = _mapping(_json(manifest_raw, f"{arch} manifest"), f"{arch} manifest")
        _exact(manifest.get("schemaVersion"), 2, f"{arch} manifest schemaVersion")
        _exact(
            manifest.get("mediaType"),
            _OCI_MANIFEST_MEDIA_TYPE,
            f"{arch} manifest mediaType",
        )
        config_descriptor = _mapping(manifest.get("config"), f"{arch} config descriptor")
        _exact(
            config_descriptor.get("mediaType"),
            _OCI_CONFIG_MEDIA_TYPE,
            f"{arch} config mediaType",
        )
        _exact(
            config_descriptor.get("digest"),
            candidate["config"]["digest"],
            f"{arch} config digest",
        )
        _exact(
            config_descriptor.get("size"),
            candidate["config"]["size"],
            f"{arch} config size",
        )
        config_raw = fetch("blob", candidate["config"]["digest"])
        _raw_descriptor(config_raw, candidate["config"], f"{arch} config")
        config = _mapping(_json(config_raw, f"{arch} config"), f"{arch} config")
        _exact(config.get("architecture"), arch, f"{arch} config architecture")
        _exact(config.get("os"), "linux", f"{arch} config os")
        runtime_config = _mapping(config.get("config"), f"{arch} image config")
        runtime_labels = _mapping(runtime_config.get("Labels"), f"{arch} image labels")
        for key, expected in candidate["labels"].items():
            _exact(
                runtime_labels.get(key),
                expected,
                f"{arch} image label {key}",
            )


def load_finalized_production_authority(  # noqa: PLR0915 - exact fail-closed contract
    root: Path,
    *,
    source_image_assertion: str | None = None,
    cosign_runner: CosignRunner = _default_cosign_runner,
    binary_reader: BinaryReader = _default_binary_reader,
    runtime_machine: str | None = None,
    registry_fetcher: RegistryFetcher | None = None,
) -> dict[str, Any]:
    """Authenticate and project the exact normal 1.9 production carrier."""

    members = _read_exact_inventory(root)
    receipt_raw = members["production-finalization.json"]
    receipt = _mapping(
        _json(receipt_raw, "production-finalization.json"),
        "production-finalization.json",
    )
    if receipt_raw != _canonical_line(receipt):
        raise ProductionContainerAuthorityRefused(
            "production-finalization.json is not canonical sorted compact ASCII JSON plus LF",
        )
    _exact_keys(receipt, _RECEIPT_KEYS, "production finalization receipt")
    _exact(receipt.get("format"), PRODUCTION_AUTHORITY_FORMAT, "production receipt format")
    _exact(receipt.get("release"), PRODUCTION_RELEASE, "production receipt release")
    revision = receipt.get("release_git_commit")
    tree = receipt.get("release_git_tree")
    if not isinstance(revision, str) or _GIT_SHA1.fullmatch(revision) is None:
        raise ProductionContainerAuthorityRefused("production release commit is malformed")
    if not isinstance(tree, str) or _GIT_SHA1.fullmatch(tree) is None:
        raise ProductionContainerAuthorityRefused("production release tree is malformed")
    manifest_sha256 = _hex_sha256(receipt.get("manifest_sha256"), "production manifest hash")
    source_projection_sha256 = _hex_sha256(
        receipt.get("production_source_projection_sha256"),
        "production source projection hash",
    )
    source_tag_authority = _validate_source_tag_authority(
        receipt.get("source_tag_authority"),
        revision=revision,
        tree=tree,
    )
    qualification_ceremony = _validate_qualification_ceremony(
        receipt.get("qualification_ceremony"),
        source_tag_authority=source_tag_authority,
        revision=revision,
        tree=tree,
    )
    signature_verifier = _validate_signature_verifier(
        receipt.get("signature_verifier"),
        "production signature_verifier",
    )
    candidate_index = _mapping(receipt.get("candidate_index"), "candidate_index")
    _exact_keys(candidate_index, {"image", "digest", "sha256", "size"}, "candidate_index")
    _exact(
        candidate_index.get("image"),
        PRODUCTION_IMAGE_REPOSITORY,
        "candidate_index.image",
    )
    index_digest = _digest(candidate_index.get("digest"), "candidate_index.digest")
    index_sha256 = _hex_sha256(candidate_index.get("sha256"), "candidate_index.sha256")
    _exact(index_digest, f"sha256:{index_sha256}", "candidate index digest/hash")
    index_size = _size(candidate_index.get("size"), "candidate_index.size")
    index_raw = members["staging-index.json"]
    if len(index_raw) != index_size or _sha256(index_raw) != index_sha256:
        raise ProductionContainerAuthorityRefused(
            "staging-index.json bytes differ from the finalized candidate index",
        )
    dashboard_sbom_value = _mapping(receipt.get("dashboard_sbom"), "dashboard_sbom")
    _exact_keys(dashboard_sbom_value, {"cyclonedx", "spdx"}, "dashboard_sbom")
    dashboard_sbom = {
        name: _seal(dashboard_sbom_value.get(name), f"dashboard_sbom.{name}")
        for name in ("cyclonedx", "spdx")
    }

    native_value = _mapping(receipt.get("native"), "native")
    native_receipts = _mapping(receipt.get("native_receipts"), "native_receipts")
    _exact_keys(native_value, {"amd64", "arm64"}, "native")
    _exact_keys(native_receipts, {"amd64", "arm64"}, "native_receipts")
    native: dict[str, dict[str, Any]] = {}
    for arch in ("amd64", "arm64"):
        native_receipt = _mapping(native_value[arch], f"native.{arch}")
        expected_seal = _seal(native_receipts[arch], f"native_receipts.{arch}")
        native_raw = _canonical_line(native_receipt)
        if (
            len(native_raw) != expected_seal["size"]
            or _sha256(native_raw) != expected_seal["sha256"]
        ):
            raise ProductionContainerAuthorityRefused(
                f"native {arch} receipt bytes differ from their finalized seal",
            )
        native[arch] = _validate_native(native_receipt, arch=arch, receipt=receipt)

    wheelhouse_subject = source_tag_authority["evidence_index"]["index_digest"]
    for arch in ("amd64", "arm64"):
        if (
            native[arch]["candidate"]["labels"]["org.z4j.production.wheelhouse.index"]
            != wheelhouse_subject
        ):
            raise ProductionContainerAuthorityRefused(
                "source-tag evidence subject differs from the finalized "
                f"production wheelhouse index on {arch}",
            )
    _verify_cosign(
        members,
        signature_verifier=signature_verifier,
        candidate_reference=f"{PRODUCTION_IMAGE_REPOSITORY}@{index_digest}",
        runner=cosign_runner,
        binary_reader=binary_reader,
        runtime_machine=runtime_machine or runtime_platform_module.machine(),
    )
    _verify_attestation(
        members["production-finalization.attestation.jsonl"],
        receipt=receipt,
        candidate_digest=index_digest,
    )
    fetch = registry_fetcher or _default_registry_fetcher()
    _verify_registry(
        raw_index=index_raw,
        receipt_index={"digest": index_digest, "size": index_size},
        native=native,
        fetch=fetch,
    )
    source_image = f"{PRODUCTION_IMAGE_REPOSITORY}@{index_digest}"
    if source_image_assertion is not None and source_image_assertion.strip() != source_image:
        raise ProductionContainerAuthorityRefused(
            "caller source image assertion differs from the authenticated production receipt",
        )
    member_seals = {
        name: {"sha256": _sha256(raw), "size": len(raw)} for name, raw in sorted(members.items())
    }
    projection: dict[str, Any] = {
        "format": "z4j-authenticated-production-container-authority-v1",
        "release": PRODUCTION_RELEASE,
        "source_revision": revision,
        "source_tree": tree,
        "source_image": source_image,
        "manifest_sha256": manifest_sha256,
        "production_source_projection_sha256": source_projection_sha256,
        "source_tag_authority": source_tag_authority,
        "qualification_ceremony": qualification_ceremony,
        "signature_verifier": signature_verifier,
        "candidate_index": {
            "image": PRODUCTION_IMAGE_REPOSITORY,
            "digest": index_digest,
            "sha256": index_sha256,
            "size": index_size,
        },
        "dashboard_sbom": dashboard_sbom,
        "platforms": {
            arch: {
                **native[arch]["candidate"],
                "cadence_probe": native[arch]["cadence_probe"],
                "signature_verifier": native[arch]["signature_verifier"],
                "signature_verifier_probe": native[arch]["signature_verifier_probe"],
                "dashboard_replay": native[arch]["dashboard_replay"],
                "service_smoke": native[arch]["service_smoke"],
                "candidate_sbom": native[arch]["candidate_sbom"],
                "native_receipt": _seal(
                    native_receipts[arch],
                    f"native_receipts.{arch}",
                ),
            }
            for arch in ("amd64", "arm64")
        },
        "members": member_seals,
        "sigstore": {
            "cosign_version": COSIGN_VERSION,
            "identity": PRODUCTION_WORKFLOW_IDENTITY,
            "issuer": PRODUCTION_OIDC_ISSUER,
            "predicate_type": PRODUCTION_ATTESTATION_TYPE,
        },
    }
    projection["authority_sha256"] = _sha256(_canonical_line(projection))
    return projection


__all__ = [
    "COSIGN_VERSION",
    "PRODUCTION_ATTESTATION_TYPE",
    "PRODUCTION_AUTHORITY_ENV",
    "PRODUCTION_AUTHORITY_FORMAT",
    "PRODUCTION_IMAGE_REPOSITORY",
    "PRODUCTION_NATIVE_FORMAT",
    "PRODUCTION_OIDC_ISSUER",
    "PRODUCTION_RELEASE",
    "PRODUCTION_WORKFLOW_IDENTITY",
    "ProductionContainerAuthorityRefused",
    "load_finalized_production_authority",
]
