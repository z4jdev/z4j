#!/usr/bin/env python3
"""Create and verify the one-purpose, immutable v1.9.0 source-tag evidence.

The helper is intentionally standard-library only.  Network access and the
single Git ref mutation stay in the protected workflow; this module validates
captured responses, constructs deterministic tag bytes and authenticates the
detached receipt without ever trusting an ambient executable from ``PATH``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import platform
import re
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RELEASE = "1.9.0"
TAG = "v1.9.0"
TAG_REF = "refs/tags/v1.9.0"
REPOSITORY = "z4jdev/z4j"
REPOSITORY_ID = 1228454287
REPOSITORY_NODE_ID = "R_kgDOSTi5jw"
EXTERNAL_AUTHORITY_REPOSITORIES = (
    "docker.io/z4jdev/z4j-production-wheelhouse",
    "docker.io/z4jdev/z4j-production-system",
    "docker.io/z4jdev/z4j-production-dashboard",
)
MAIN_REF = "refs/heads/main"
ENVIRONMENT = "production-release"
RULESET_NAME = "immutable-v-tags"
RULESET_INCLUDE = ["refs/tags/v*.*.*"]
SOURCE_TAG_AUTHORITY_SCHEMA = "z4j.source-tag-authority.v1"
SOURCE_TAG_AUTHORITY_POLICY = {
    "required": True,
    "schema": SOURCE_TAG_AUTHORITY_SCHEMA,
    "location": "detached-production-finalization",
}
WORKFLOW_PATH = ".github/workflows/source-tag-only.yml"
WORKFLOW_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/source-tag-only.yml@refs/heads/main"
)
RELEASE_WORKFLOW_ID = 270520651
RELEASE_WORKFLOW_NODE_ID = "W_kwDOSTi5j84QH9FL"
RELEASE_WORKFLOW_PATH = ".github/workflows/release-docker.yml"
RELEASE_WORKFLOW_NAME = "release-docker"
RELEASE_WORKFLOW_HTML_URL = (
    "https://github.com/z4jdev/z4j/blob/main/.github/workflows/release-docker.yml"
)
RELEASE_WORKFLOW_CREATED_AT = "2026-05-03T23:12:28-04:00"
RELEASE_WORKFLOW_UPDATED_AT = "2026-05-03T23:12:28-04:00"
GITHUB_API_VERSION = "2026-03-10"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RECEIPT_FORMAT = "z4j-source-tag-creation-receipt-v1"
PLAN_FORMAT = "z4j-source-tag-creation-plan-v1"
DURABLE_VERIFICATION_FORMAT = "z4j-source-tag-durable-verification-v1"
RECOVERY_TRANSITION = "recovered-existing-exact-under-signed-immutable-authority"
CREATION_TRANSITION = "created-under-signed-immutable-authority"
COSIGN_VERSION = "3.1.3"
REGISTRY_ORIGIN = "https://registry-1.docker.io"
HUB_API_REPOSITORY = (
    "https://hub.docker.com/v2/namespaces/z4jdev/repositories/z4j-production-wheelhouse"
)
WHEELHOUSE_RETENTION_RULE = r"^1\.9\.0-digest-[0-9a-f]{64}$"
AUTHORITY_RETENTION_RULE = r"^1\.9\.0-source-tag-authority-[0-9a-f]{64}$"
IMMUTABLE_RETENTION_RULES = [WHEELHOUSE_RETENTION_RULE, AUTHORITY_RETENTION_RULE]
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_EMPTY = "application/vnd.oci.empty.v1+json"
AUTHORITY_ARTIFACT_TYPE = "application/vnd.z4j.source-tag-authority.v1+json"
RECEIPT_MEDIA_TYPE = "application/vnd.z4j.source-tag-creation-receipt.v1+json"
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
EMPTY_CONFIG = b"{}"
EMPTY_CONFIG_DESCRIPTOR = {
    "mediaType": OCI_EMPTY,
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2,
    "data": "e30=",
}
RECEIPT_NAME = "source-tag-creation-receipt.json"
BUNDLE_NAME = "source-tag-creation-receipt.sigstore.json"
EVIDENCE_INDEX_NAME = "source-tag-evidence-index.json"
RELEASE_SETTINGS_NAME = "release-settings-authority.json"
RELEASE_SETTINGS_FORMAT = "z4j-release-settings-authority-v1"
SOURCE_MAIN_PLAN_NAME = "source-main-transition-plan.json"
SOURCE_MAIN_PLAN_FORMAT = "z4j-source-main-transition-plan-v1"
SOURCE_MAIN_READBACK_NAME = "source-main-transition-readback.json"
SOURCE_MAIN_READBACK_FORMAT = "z4j-source-main-transition-readback-v1"
SOURCE_MAIN_PREPUSH_SEAL_NAME = "source-main-prepush-seal.json"
SOURCE_MAIN_PREPUSH_SEAL_FORMAT = "z4j-source-main-prepush-seal-v1"
SOURCE_MAIN_RECOVERY_TOKEN_GRANT_NAME = "source-main-recovery-token-grant.json"  # noqa: S105 - filename, never a credential
SOURCE_MAIN_RECOVERY_TRANSITION = {
    "operation": "recover-existing-main-authority",
    "force": False,
    "result": "recovered-existing-exact-main-under-sealed-protection",
}
SOURCE_MAIN_TRANSPORT_NAME = "source-main-authority-input.txt"
SOURCE_MAIN_TRANSPORT_MAGIC = b"Z4J-S0-S1\x00"
SOURCE_MAIN_TRANSPORT_VERSION = 1
SOURCE_MAIN_TRANSPORT_NAMES = (
    RELEASE_SETTINGS_NAME,
    SOURCE_MAIN_PLAN_NAME,
    SOURCE_MAIN_READBACK_NAME,
)
MAX_SOURCE_MAIN_TRANSPORT_ASCII = 60_000
MAX_SOURCE_MAIN_TRANSPORT_RAW = 1024 * 1024
POST_PUSH_SETTLE_SECONDS = 60
FULCIO_OID_ROOT = "1.3.6.1.4.1.57264.1"
EXPECTED_OLD_MAIN = {
    "commit": "891d66f77cd87b93311eaf2ed8189e1780430e2c",
    "tree": "0913546d59a4661ca2f2e17512ec2acfc46305ea",
}
REPOSITORY_IDENTITY = {
    "full_name": REPOSITORY,
    "id": REPOSITORY_ID,
    "node_id": REPOSITORY_NODE_ID,
    "owner": {
        "login": "z4jdev",
        "id": 275564196,
        "node_id": "O_kgDOEGzGpA",
        "type": "Organization",
    },
    "visibility": "public",
    "private": False,
    "default_branch": "main",
}
PRE_S0_WORKFLOW_INVENTORY = [
    {
        "id": 270520650,
        "node_id": "W_kwDOSTi5j84QH9FK",
        "name": "demo-deploy",
        "path": ".github/workflows/demo-deploy.yml",
        "state": "disabled_manually",
        "material_mutation_class": "push-main-material-mutator-disabled",
    },
    {
        "id": RELEASE_WORKFLOW_ID,
        "node_id": RELEASE_WORKFLOW_NODE_ID,
        "name": RELEASE_WORKFLOW_NAME,
        "path": RELEASE_WORKFLOW_PATH,
        "state": "active",
        "material_mutation_class": "tag-or-manual-material-mutator",
    },
    {
        "id": 270520654,
        "node_id": "W_kwDOSTi5j84QH9FO",
        "name": "Security",
        "path": ".github/workflows/security.yml",
        "state": "disabled_manually",
        "material_mutation_class": "push-main-material-mutator-disabled",
    },
]
EXPECTED_ADDITION_POLICIES = {
    ".github/workflows/promote-release-docker.yml": {
        "name": "promote-release-docker",
        "material_mutation_class": "manual-material-mutator",
    },
    ".github/workflows/recover-rollback-compat-promotion.yml": {
        "name": "recover-rollback-compat-promotion",
        "material_mutation_class": "manual-material-mutator",
    },
    ".github/workflows/release-rollback-compat.yml": {
        "name": "release-rollback-compat",
        "material_mutation_class": "manual-material-mutator",
    },
    WORKFLOW_PATH: {
        "name": "source-tag-only",
        "material_mutation_class": "manual-source-tag-mutator",
    },
}
S0_GRANT_PERMISSIONS = {
    "actions": "read",
    "administration": "read",
    "contents": "write",
    "environments": "read",
    "metadata": "read",
}
S0_EFFECTIVE_MUTATION = {
    "contents_fast_forward_main": True,
    "contents_other_refs": False,
    "force": False,
    "tag": False,
    "actions": False,
    "administration": False,
    "maintain": False,
    "settings": False,
    "environments": False,
    "ruleset_bypass": False,
}
PORTABLE_NAMES = {RECEIPT_NAME, BUNDLE_NAME, EVIDENCE_INDEX_NAME}
PRODUCTION_AUTHORITY_NAMES = {
    "production-finalization.json",
    "production-finalization.bundle.json",
    "production-finalization.attestation.jsonl",
    "staging-index.json",
}
PRODUCTION_AUTHORITY_HELPER_PATH = "backend/src/z4j_brain/domain/production_container_authority.py"
PRODUCTION_AUTHORITY_PROJECTION_FORMAT = "z4j-authenticated-production-container-authority-v1"
RELEASE_CONSUMER_FORMAT = "z4j-source-tag-release-consumer-v1"
SOURCE_REMOTE_URL = "https://github.com/z4jdev/z4j.git"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_REGISTRY_BYTES = 100 * 1024 * 1024
MAX_REFERRER_PAGES = 128
MAX_REFERRER_DESCRIPTORS = 4096
MAX_REFERRER_BYTES = 64 * 1024 * 1024
SYSTEM_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WHEELHOUSE_IMAGE = re.compile(
    r"^docker\.io/(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*):(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@(?P<digest>sha256:[0-9a-f]{64})$"
)
TAGGER_NAME = "pypv"
TAGGER_EMAIL = "106410335+pypv@users.noreply.github.com"
TAG_MESSAGE = f"Release {RELEASE}"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SourceTagRefusedError(RuntimeError):
    """The source-tag authority is incomplete, mutable or inconsistent."""


def canonical_line(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def canonical_oci(value: object) -> bytes:
    """Return the literal OCI-manifest framing (compact UTF-8, no trailing LF)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw)


def authority_retention_tag(artifact_digest: str) -> str:
    value = _digest(artifact_digest, "source authority artifact digest")
    tag = f"{RELEASE}-source-tag-authority-{value.removeprefix('sha256:')}"
    if re.fullmatch(AUTHORITY_RETENTION_RULE, tag) is None:
        raise SourceTagRefusedError("source authority retention tag differs")
    return tag


def require_a0_authority() -> None:
    """Fail live S1 closed until the reviewed pre-S0 A0 contract exists."""
    raise SourceTagRefusedError(
        "A0 authority/system/dashboard authority policies and authenticated E0 repository "
        "creation/settings validators unavailable"
    )


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise SourceTagRefusedError(f"{label} must be an exact sha256 OCI digest")
    return value


def _size(value: object, label: str, *, maximum: int = MAX_REGISTRY_BYTES) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > maximum:
        raise SourceTagRefusedError(f"{label} must be a positive bounded size")
    return value


def descriptor(raw: bytes, media_type: str, *, title: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mediaType": media_type,
        "digest": digest(raw),
        "size": len(raw),
    }
    if title is not None:
        result["annotations"] = {"org.opencontainers.image.title": title}
    return result


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SourceTagRefusedError(f"{label} must be an object with string keys")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise SourceTagRefusedError(
            f"{label} keys differ: missing={sorted(expected - actual)!r} "
            f"extra={sorted(actual - expected)!r}",
        )


def _hex(value: object, width: int, label: str) -> str:
    pattern = HEX40 if width == 40 else HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SourceTagRefusedError(f"{label} must be {width} lowercase hexadecimal characters")
    return value


def _positive(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SourceTagRefusedError(f"{label} must be a positive integer")
    return value


def read_regular(path: Path, *, limit: int = 16 * 1024 * 1024) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise SourceTagRefusedError(f"cannot safely open {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SourceTagRefusedError(f"{path} must be a single-link regular file")
        if metadata.st_size <= 0 or metadata.st_size > limit:
            raise SourceTagRefusedError(f"{path} has a refused size")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise SourceTagRefusedError(f"{path} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SourceTagRefusedError(f"{path} grew while being read")
        closing = os.fstat(descriptor)
        if (closing.st_dev, closing.st_ino, closing.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise SourceTagRefusedError(f"{path} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError(f"{label} is not JSON") from exc
    result = _mapping(value, label)
    if canonical_line(result) != raw:
        raise SourceTagRefusedError(f"{label} is not canonical newline JSON")
    return result, raw


def load_canonical_value(path: Path, label: str) -> tuple[object, bytes]:
    """Load a canonical LF-framed JSON value, including an API top-level array."""
    raw = read_regular(path)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError(f"{label} is not JSON") from exc
    if canonical_line(value) != raw:
        raise SourceTagRefusedError(f"{label} is not canonical newline JSON")
    return value, raw


def _canonical_object_authority(value: object, label: str) -> dict[str, Any]:
    authority = _mapping(value, label)
    _exact_keys(authority, {"object", "seal"}, label)
    response_object = _mapping(authority.get("object"), f"{label} object")
    seal = _seal(authority.get("seal"), f"{label} seal")
    raw = canonical_line(response_object)
    if seal != {"sha256": sha256(raw), "size": len(raw)}:
        raise SourceTagRefusedError(f"{label} canonical object seal differs")
    return authority


def _stable_user(value: object, label: str) -> dict[str, Any]:
    identity = _mapping(value, label)
    _exact_keys(identity, {"login", "id", "node_id", "type"}, label)
    if (
        identity.get("type") != "User"
        or not isinstance(identity.get("login"), str)
        or not identity["login"]
        or not isinstance(identity.get("node_id"), str)
        or not identity["node_id"]
    ):
        raise SourceTagRefusedError(f"{label} stable identity differs")
    _positive(identity.get("id"), f"{label} id")
    return identity


def _stable_automation_principal(
    value: object,
    label: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    identity = _mapping(value, label)
    _exact_keys(identity, {"login", "id", "node_id", "type"}, label)
    if (
        identity.get("type") not in {"User", "Bot"}
        or not isinstance(identity.get("login"), str)
        or not identity["login"]
        or not isinstance(identity.get("node_id"), str)
        or not identity["node_id"]
    ):
        raise SourceTagRefusedError(f"{label} stable identity differs")
    _positive(identity.get("id"), f"{label} id")
    return dict(identity)


def _api_user_projection(value: object, label: str) -> dict[str, Any]:
    user = _mapping(value, label)
    projection = {
        "login": user.get("login"),
        "id": user.get("id"),
        "node_id": user.get("node_id"),
        "type": user.get("type"),
    }
    return _stable_user(projection, label)


def _workflow_projection(value: object, label: str) -> dict[str, Any]:
    workflow = _mapping(value, label)
    projection = {
        "id": workflow.get("id"),
        "node_id": workflow.get("node_id"),
        "name": workflow.get("name"),
        "path": workflow.get("path"),
        "state": workflow.get("state"),
    }
    _positive(projection["id"], f"{label} id")
    for key in ("node_id", "name", "path", "state"):
        if not isinstance(projection[key], str) or not projection[key]:
            raise SourceTagRefusedError(f"{label} {key} differs")
    return projection


def _workflow_list_projection(value: object, label: str) -> list[dict[str, Any]]:
    response = _mapping(value, label)
    workflows = response.get("workflows")
    if (
        not isinstance(workflows, list)
        or response.get("total_count") != len(workflows)
        or len(workflows) > 100
    ):
        raise SourceTagRefusedError(f"{label} count/list differs")
    projection = [
        _workflow_projection(item, f"{label} workflow {index}")
        for index, item in enumerate(workflows)
    ]
    if len({item["path"] for item in projection}) != len(projection):
        raise SourceTagRefusedError(f"{label} duplicates a workflow path")
    return sorted(projection, key=lambda item: (item["path"], item["id"]))


def _stable_principal(value: object, label: str, *, principal_type: str) -> dict[str, Any]:
    identity = _mapping(value, label)
    _exact_keys(identity, {"login", "id", "node_id", "type"}, label)
    if (
        identity.get("type") != principal_type
        or not isinstance(identity.get("login"), str)
        or not identity["login"]
        or not isinstance(identity.get("node_id"), str)
        or not identity["node_id"]
    ):
        raise SourceTagRefusedError(f"{label} stable identity differs")
    _positive(identity.get("id"), f"{label} id")
    return dict(identity)


def _validate_s0_actor(value: object, label: str) -> dict[str, Any]:
    actor = _mapping(value, label)
    _exact_keys(actor, {"app", "installation", "account", "bot"}, label)
    app = _mapping(actor.get("app"), f"{label} app")
    _exact_keys(app, {"id", "slug"}, f"{label} app")
    _positive(app.get("id"), f"{label} app id")
    if not isinstance(app.get("slug"), str) or not re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", app["slug"]
    ):
        raise SourceTagRefusedError(f"{label} app slug differs")
    installation = _mapping(actor.get("installation"), f"{label} installation")
    _exact_keys(installation, {"id"}, f"{label} installation")
    _positive(installation.get("id"), f"{label} installation id")
    account = _stable_principal(
        actor.get("account"), f"{label} account", principal_type="Organization"
    )
    if account != REPOSITORY_IDENTITY["owner"]:
        raise SourceTagRefusedError(f"{label} account differs from repository owner")
    _stable_principal(actor.get("bot"), f"{label} bot", principal_type="Bot")
    return dict(actor)


def _repository_api_projection(value: object, label: str) -> dict[str, Any]:
    repository = _mapping(value, label)
    owner = _mapping(repository.get("owner"), f"{label} owner")
    result = {
        "full_name": repository.get("full_name"),
        "id": repository.get("id"),
        "node_id": repository.get("node_id"),
        "owner": {
            "login": owner.get("login"),
            "id": owner.get("id"),
            "node_id": owner.get("node_id"),
            "type": owner.get("type"),
        },
        "visibility": repository.get("visibility"),
        "private": repository.get("private"),
        "default_branch": repository.get("default_branch"),
    }
    if result != REPOSITORY_IDENTITY:
        raise SourceTagRefusedError(f"{label} repository identity differs")
    return result


def _validate_s0_token_grant(
    value: object,
    *,
    approved_actor: Mapping[str, Any],
) -> dict[str, Any]:
    if value is None:
        raise SourceTagRefusedError(
            "S0 GitHub App token_grant_authority is UNFINALIZED; source-main mutation is blocked"
        )
    grant = _mapping(value, "S0 GitHub App token grant authority")
    _exact_keys(
        grant,
        {
            "format",
            "result",
            "redacted_token_creation",
            "app",
            "installation",
            "repository_selection",
            "repositories",
            "permissions",
            "effective_mutation",
            "expires_at",
            "verification",
        },
        "S0 GitHub App token grant authority",
    )
    if (
        grant.get("format") != "z4j-s0-app-token-grant-v1"
        or grant.get("result") != "pass"
        or grant.get("app") != approved_actor["app"]
        or grant.get("installation") != approved_actor["installation"]
        or grant.get("repository_selection") != "selected"
        or grant.get("repositories") != [REPOSITORY_IDENTITY]
        or grant.get("permissions") != S0_GRANT_PERMISSIONS
        or grant.get("effective_mutation") != S0_EFFECTIVE_MUTATION
        or grant.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError("S0 GitHub App token grant projection differs")
    expires_at = grant.get("expires_at")
    if not isinstance(expires_at, str):
        raise SourceTagRefusedError("S0 GitHub App token expiry differs")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceTagRefusedError("S0 GitHub App token expiry differs") from exc
    if expiry.tzinfo is None:
        raise SourceTagRefusedError("S0 GitHub App token expiry lacks a timezone")
    response = _canonical_object_authority(
        grant.get("redacted_token_creation"),
        "S0 redacted installation-token creation response",
    )
    response_object = _mapping(response["object"], "S0 redacted installation-token creation object")
    _exact_keys(
        response_object,
        {"token", "expires_at", "permissions", "repository_selection", "repositories"},
        "S0 redacted installation-token creation object",
    )
    repositories = response_object.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise SourceTagRefusedError("S0 token response repository selection differs")
    if (
        response_object.get("token") != "<redacted>"
        or response_object.get("expires_at") != expires_at
        or response_object.get("permissions") != S0_GRANT_PERMISSIONS
        or response_object.get("repository_selection") != "selected"
        or _repository_api_projection(repositories[0], "S0 token response repository")
        != REPOSITORY_IDENTITY
    ):
        raise SourceTagRefusedError("S0 redacted token-creation response differs")
    return dict(grant)


def _validate_main_protection_responses(
    responses: Mapping[str, Any],
    *,
    main_policy: Mapping[str, Any],
    approved_actor: Mapping[str, Any],
) -> None:
    ruleset = _mapping(
        _mapping(responses["main_ruleset"], "settings main ruleset response")["object"],
        "settings main ruleset object",
    )
    conditions = _mapping(ruleset.get("conditions"), "settings main ruleset conditions")
    _exact_keys(conditions, {"ref_name"}, "settings main ruleset conditions")
    ref_name = _mapping(conditions.get("ref_name"), "settings main ruleset ref-name condition")
    _exact_keys(
        ref_name,
        {"include", "exclude"},
        "settings main ruleset ref-name condition",
    )
    rules = ruleset.get("rules")
    expected_rules = [{"type": name} for name in main_policy["rules"]]
    if (
        ruleset.get("id") != main_policy["id"]
        or ruleset.get("name") != main_policy["name"]
        or ruleset.get("target") != "branch"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("source") != REPOSITORY
        or ruleset.get("source_type") != "Repository"
        or ruleset.get("bypass_actors") != []
        or ref_name != {"include": [MAIN_REF], "exclude": []}
        or rules != expected_rules
    ):
        raise SourceTagRefusedError(
            "authenticated main ruleset is not exact no-bypass fast-forward-only policy"
        )
    protection = _mapping(
        _mapping(
            responses["main_branch_protection"],
            "settings main branch-protection response",
        )["object"],
        "settings main branch-protection object",
    )
    restrictions = _mapping(protection.get("restrictions"), "settings main push restrictions")
    users = restrictions.get("users")
    teams = restrictions.get("teams")
    apps = restrictions.get("apps")
    if (
        users != []
        or teams != []
        or not isinstance(apps, list)
        or len(apps) != 1
        or not isinstance(apps[0], dict)
        or {
            "id": apps[0].get("id"),
            "slug": apps[0].get("slug"),
        }
        != approved_actor["app"]
    ):
        raise SourceTagRefusedError(
            "authenticated main push restriction is not the approved S0 App only"
        )
    required_linear = _mapping(
        protection.get("required_linear_history"),
        "settings required-linear-history response",
    )
    force_pushes = _mapping(
        protection.get("allow_force_pushes"), "settings allow-force-pushes response"
    )
    deletions = _mapping(protection.get("allow_deletions"), "settings allow-deletions response")
    enforce_admins = _mapping(protection.get("enforce_admins"), "settings enforce-admins response")
    if (
        required_linear.get("enabled") is not True
        or force_pushes.get("enabled") is not False
        or deletions.get("enabled") is not False
        or enforce_admins.get("enabled") is not True
    ):
        raise SourceTagRefusedError("authenticated main branch protection is permissive")


def validate_release_settings_authority(  # noqa: PLR0912,PLR0915
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    _exact_keys(
        authority,
        {
            "format",
            "result",
            "release",
            "scope",
            "repository_identity",
            "response_authorities",
            "policy",
            "token_grant_authority",
            "verification",
        },
        "release settings authority",
    )
    if (
        authority.get("format") != RELEASE_SETTINGS_FORMAT
        or authority.get("result") != "pass"
        or authority.get("release") != RELEASE
        or authority.get("repository_identity") != REPOSITORY_IDENTITY
        or authority.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError("release settings authority identity/result differs")
    scope = _mapping(authority.get("scope"), "release settings scope")
    _exact_keys(scope, {"expected_old", "prepared"}, "release settings scope")
    if scope.get("expected_old") != EXPECTED_OLD_MAIN:
        raise SourceTagRefusedError("release settings expected-old main differs")
    prepared = _mapping(scope.get("prepared"), "release settings prepared source")
    _exact_keys(prepared, {"commit", "tree"}, "release settings prepared source")
    _hex(prepared.get("commit"), 40, "release settings prepared commit")
    _hex(prepared.get("tree"), 40, "release settings prepared tree")
    responses = _mapping(
        authority.get("response_authorities"),
        "release settings response authorities",
    )
    expected_responses = {
        "repository",
        "tag_ruleset",
        "main_ruleset",
        "main_branch_protection",
        "production_release_environment",
        "production_qualification_environment",
        "production_qualification_branch_policies",
        "actions_general",
        "actions_workflow",
        "actions_selected",
        "workflow_inventory",
        "demo_workflow",
        "security_workflow",
        "release_workflow",
        "installation",
        "installation_repositories",
        "bot_user",
    }
    _exact_keys(responses, expected_responses, "release settings response authorities")
    for name in sorted(expected_responses):
        _canonical_object_authority(responses[name], f"release settings {name}")
    repository = _mapping(
        _mapping(responses["repository"], "settings repository response")["object"],
        "settings repository object",
    )
    owner = _mapping(repository.get("owner"), "settings repository owner")
    if any(
        (
            repository.get("full_name") != REPOSITORY,
            repository.get("id") != REPOSITORY_ID,
            repository.get("node_id") != REPOSITORY_NODE_ID,
            repository.get("visibility") != "public",
            repository.get("private") is not False,
            repository.get("default_branch") != "main",
            owner.get("login") != "z4jdev",
            owner.get("id") != 275564196,
            owner.get("node_id") != "O_kgDOEGzGpA",
            owner.get("type") != "Organization",
        )
    ):
        raise SourceTagRefusedError("release settings repository API identity differs")
    policy = _mapping(authority.get("policy"), "release settings policy")
    _exact_keys(
        policy,
        {
            "tag_ruleset",
            "main_ruleset",
            "environments",
            "actions",
            "workflows",
            "automation_principal",
        },
        "release settings policy",
    )
    _stable_automation_principal(
        policy.get("automation_principal"),
        "release qualification automation principal",
    )
    tag_policy = _mapping(policy.get("tag_ruleset"), "release tag ruleset policy")
    _exact_keys(
        tag_policy,
        {
            "id",
            "name",
            "target",
            "enforcement",
            "include",
            "exclude",
            "bypass_actors",
            "rules",
        },
        "release tag ruleset policy",
    )
    _positive(tag_policy.get("id"), "release tag ruleset id")
    if tag_policy != {
        "id": tag_policy["id"],
        "name": RULESET_NAME,
        "target": "tag",
        "enforcement": "active",
        "include": RULESET_INCLUDE,
        "exclude": [],
        "bypass_actors": [],
        "rules": ["deletion", "update"],
    }:
        raise SourceTagRefusedError("release tag ruleset policy differs")
    main_policy = _mapping(policy.get("main_ruleset"), "release main ruleset policy")
    _exact_keys(
        main_policy,
        {
            "id",
            "name",
            "target",
            "enforcement",
            "include",
            "exclude",
            "bypass_actors",
            "rules",
            "approved_s0_actor",
        },
        "release main ruleset policy",
    )
    _positive(main_policy.get("id"), "release main ruleset id")
    approved_actor = _validate_s0_actor(
        main_policy.get("approved_s0_actor"),
        "approved S0 GitHub App actor",
    )
    token_grant = _validate_s0_token_grant(
        authority.get("token_grant_authority"),
        approved_actor=approved_actor,
    )
    installation = _mapping(
        _mapping(responses["installation"], "settings installation response")["object"],
        "settings installation object",
    )
    if (
        installation.get("id") != approved_actor["installation"]["id"]
        or installation.get("app_id") != approved_actor["app"]["id"]
        or installation.get("target_id") != approved_actor["account"]["id"]
        or installation.get("repository_selection") != "selected"
        or installation.get("permissions") != S0_GRANT_PERMISSIONS
        or _stable_principal(
            installation.get("account"),
            "settings installation account",
            principal_type="Organization",
        )
        != approved_actor["account"]
    ):
        raise SourceTagRefusedError("settings GitHub App installation differs")
    repositories_object = _mapping(
        _mapping(
            responses["installation_repositories"],
            "settings installation-repositories response",
        )["object"],
        "settings installation-repositories object",
    )
    repositories = repositories_object.get("repositories")
    if (
        repositories_object.get("total_count") != 1
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or _repository_api_projection(repositories[0], "settings installation repository")
        != REPOSITORY_IDENTITY
    ):
        raise SourceTagRefusedError("settings installation repository selection differs")
    bot = _stable_principal(
        _mapping(responses["bot_user"], "settings App bot response")["object"],
        "settings App bot",
        principal_type="Bot",
    )
    if bot != approved_actor["bot"]:
        raise SourceTagRefusedError("settings App bot identity differs")
    if token_grant["repositories"] != [REPOSITORY_IDENTITY]:
        raise SourceTagRefusedError("S0 token grant repository differs")
    _validate_main_protection_responses(
        responses,
        main_policy=main_policy,
        approved_actor=approved_actor,
    )
    if {
        key: value for key, value in main_policy.items() if key not in {"id", "approved_s0_actor"}
    } != {
        "name": "source-main-fast-forward-only",
        "target": "branch",
        "enforcement": "active",
        "include": [MAIN_REF],
        "exclude": [],
        "bypass_actors": [],
        "rules": ["deletion", "non_fast_forward", "required_linear_history"],
    }:
        raise SourceTagRefusedError("release main ruleset policy differs")
    environments = _mapping(policy.get("environments"), "release environment policy")
    _exact_keys(
        environments,
        {"production_release", "production_qualification"},
        "release environment policy",
    )
    for name, expected_name, mode, pattern in (
        ("production_release", ENVIRONMENT, "protected", MAIN_REF),
        (
            "production_qualification",
            "production-qualification",
            "selected",
            TAG_REF,
        ),
    ):
        item = _mapping(environments.get(name), f"{name} environment policy")
        _exact_keys(
            item,
            {"name", "prevent_self_review", "reviewers", "allowed_refs"},
            f"{name} environment policy",
        )
        reviewers = item.get("reviewers")
        if not isinstance(reviewers, list) or not reviewers:
            raise SourceTagRefusedError(f"{name} environment reviewers differ")
        for index, reviewer in enumerate(reviewers):
            _stable_user(reviewer, f"{name} reviewer {index}")
        if reviewers != sorted(reviewers, key=lambda value: (value["id"], value["login"])):
            raise SourceTagRefusedError(f"{name} environment reviewers are not canonical")
        if (
            item.get("name") != expected_name
            or item.get("prevent_self_review") is not True
            or item.get("allowed_refs") != {"mode": mode, "patterns": [pattern]}
        ):
            raise SourceTagRefusedError(f"{name} environment policy differs")
    actions = _mapping(policy.get("actions"), "release Actions policy")
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
        "release Actions policy",
    )
    patterns = actions.get("patterns_allowed")
    if (
        not isinstance(patterns, list)
        or not patterns
        or not all(isinstance(value, str) and value for value in patterns)
        or patterns != sorted(set(patterns))
    ):
        raise SourceTagRefusedError("release Actions allowed patterns differ")
    if (
        actions.get("enabled") is not True
        or actions.get("allowed_actions") != "selected"
        or actions.get("default_workflow_permissions") != "read"
        or actions.get("can_approve_pull_request_reviews") is not False
        or actions.get("github_owned_allowed") is not True
        or actions.get("verified_allowed") is not False
        or actions.get("write_grants")
        != [
            {
                "workflow_path": WORKFLOW_PATH,
                "permissions": {
                    "actions": "write",
                    "contents": "write",
                    "id-token": "write",
                },
            }
        ]
    ):
        raise SourceTagRefusedError("release Actions policy differs")
    workflows = _mapping(policy.get("workflows"), "release workflow-state policy")
    _exact_keys(
        workflows,
        {
            "demo",
            "security",
            "release",
            "push_main_material_mutators",
            "inventory",
            "expected_additions",
        },
        "release workflow-state policy",
    )
    expected_workflows = {
        "demo": {
            "id": 270520650,
            "name": "demo-deploy",
            "path": ".github/workflows/demo-deploy.yml",
            "state": "disabled_manually",
        },
        "security": {
            "id": 270520654,
            "name": "Security",
            "path": ".github/workflows/security.yml",
            "state": "disabled_manually",
        },
        "release": {
            "id": RELEASE_WORKFLOW_ID,
            "name": RELEASE_WORKFLOW_NAME,
            "path": RELEASE_WORKFLOW_PATH,
            "state": "active",
            "accepted_event": "workflow_dispatch",
            "accepted_ref": TAG_REF,
        },
    }
    if (
        workflows.get("demo") != expected_workflows["demo"]
        or workflows.get("security") != expected_workflows["security"]
        or workflows.get("release") != expected_workflows["release"]
        or workflows.get("push_main_material_mutators") != []
    ):
        raise SourceTagRefusedError("release workflow-state policy differs")
    inventory = workflows.get("inventory")
    if inventory != PRE_S0_WORKFLOW_INVENTORY:
        raise SourceTagRefusedError("release pre-S0 workflow inventory differs")
    inventory_response = _mapping(
        _mapping(responses["workflow_inventory"], "settings workflow inventory response")["object"],
        "settings workflow inventory object",
    )
    inventory_projection = _workflow_list_projection(
        inventory_response,
        "settings workflow inventory",
    )
    if inventory_projection != [
        {key: item[key] for key in ("id", "node_id", "name", "path", "state")}
        for item in PRE_S0_WORKFLOW_INVENTORY
    ]:
        raise SourceTagRefusedError("settings raw workflow inventory differs from policy")
    additions = workflows.get("expected_additions")
    if not isinstance(additions, list) or len(additions) != len(EXPECTED_ADDITION_POLICIES):
        raise SourceTagRefusedError("release expected workflow additions differ")
    if additions != sorted(additions, key=lambda item: item.get("path", "")):
        raise SourceTagRefusedError("release expected workflow additions are not sorted")
    for item in additions:
        addition = _mapping(item, "release expected workflow addition")
        _exact_keys(
            addition,
            {
                "id",
                "node_id",
                "name",
                "path",
                "state",
                "material_mutation_class",
                "git_oid",
                "sha256",
                "size",
                "mode",
            },
            "release expected workflow addition",
        )
        policy_entry = EXPECTED_ADDITION_POLICIES.get(addition.get("path"))
        if (
            policy_entry is None
            or addition.get("name") != policy_entry["name"]
            or addition.get("material_mutation_class") != policy_entry["material_mutation_class"]
            or addition.get("id") is not None
            or addition.get("node_id") is not None
            or addition.get("state") is not None
            or addition.get("mode") != "100644"
        ):
            raise SourceTagRefusedError("release expected workflow addition policy differs")
        _hex(addition.get("git_oid"), 40, "expected workflow addition Git OID")
        _hex(addition.get("sha256"), 64, "expected workflow addition SHA-256")
        _positive(addition.get("size"), "expected workflow addition size")
    return dict(authority)


def load_release_settings_authority(path: Path) -> tuple[dict[str, Any], bytes]:
    authority, raw = load_canonical(path, "release settings authority")
    validate_release_settings_authority(authority)
    return authority, raw


def _validate_source_blobs(value: object) -> dict[str, Any]:
    blobs = _mapping(value, "source-main blob authority")
    expected_paths = {
        ".github/source_tag_authority.py",
        ".github/workflows/source-tag-only.yml",
        ".github/workflows/release-docker.yml",
    }
    _exact_keys(blobs, expected_paths, "source-main blob authority")
    for path in sorted(expected_paths):
        item = _mapping(blobs[path], f"source-main blob {path}")
        _exact_keys(item, {"git_oid", "sha256", "size", "mode"}, f"source-main blob {path}")
        _hex(item.get("git_oid"), 40, f"source-main blob {path} Git OID")
        _hex(item.get("sha256"), 64, f"source-main blob {path} SHA-256")
        _positive(item.get("size"), f"source-main blob {path} size")
        if item.get("mode") != "100644":
            raise SourceTagRefusedError(f"source-main blob {path} is not Git100644")
    return blobs


def _validate_planned_tag(value: object, *, commit: str) -> dict[str, Any]:
    planned = _mapping(value, "source-main planned tag")
    _exact_keys(
        planned,
        {
            "name",
            "ref",
            "object",
            "target_commit",
            "raw_sha256",
            "raw_size",
            "message",
            "tagger",
        },
        "source-main planned tag",
    )
    tagger = _mapping(planned.get("tagger"), "source-main planned tagger")
    _exact_keys(
        tagger,
        {"name", "email", "git_epoch", "git_offset"},
        "source-main planned tagger",
    )
    if (
        planned.get("name") != TAG
        or planned.get("ref") != TAG_REF
        or planned.get("target_commit") != commit
        or planned.get("message") != TAG_MESSAGE
        or tagger.get("name") != TAGGER_NAME
        or tagger.get("email") != TAGGER_EMAIL
        or not isinstance(tagger.get("git_epoch"), int)
        or isinstance(tagger.get("git_epoch"), bool)
        or tagger["git_epoch"] <= 0
        or not isinstance(tagger.get("git_offset"), str)
        or re.fullmatch(r"[+-][0-9]{4}", tagger["git_offset"]) is None
    ):
        raise SourceTagRefusedError("source-main planned tag identity differs")
    _hex(planned.get("object"), 40, "source-main planned tag object")
    _hex(planned.get("raw_sha256"), 64, "source-main planned tag raw SHA-256")
    _positive(planned.get("raw_size"), "source-main planned tag raw size")
    raw = (
        f"object {commit}\n"
        "type commit\n"
        f"tag {TAG}\n"
        f"tagger {TAGGER_NAME} <{TAGGER_EMAIL}> "
        f"{tagger['git_epoch']} {tagger['git_offset']}\n\n"
        f"{TAG_MESSAGE}\n"
    ).encode("ascii")
    git_header = f"tag {len(raw)}\0".encode("ascii")
    # Git tag-object identity is defined by Git's SHA-1 object format.
    git_oid = hashlib.sha1(
        git_header + raw,
        usedforsecurity=False,
    ).hexdigest()
    if (
        planned.get("raw_sha256") != sha256(raw)
        or planned.get("raw_size") != len(raw)
        or planned.get("object") != git_oid
    ):
        raise SourceTagRefusedError("source-main planned tag payload/hash/object differ")
    return planned


def _validate_staging_tag(value: object, *, commit: str) -> dict[str, Any]:
    staging = _mapping(value, "source-main deferred staging tag")
    _exact_keys(
        staging,
        {"mode", "ref", "object", "peeled_commit"},
        "source-main deferred staging tag",
    )
    if staging != {
        "mode": "deferred-source-tag-authority",
        "ref": TAG_REF,
        "object": None,
        "peeled_commit": commit,
    }:
        raise SourceTagRefusedError("source-main deferred staging tag differs")
    return staging


def _validate_release_provenance(
    value: object,
    *,
    planned_tag: Mapping[str, Any],
    staging_tag: Mapping[str, Any],
) -> dict[str, Any]:
    provenance = _mapping(value, "source-main release provenance")
    _exact_keys(
        provenance,
        {"schema_version", "manifest", "planned_tag", "staging_tag"},
        "source-main release provenance",
    )
    manifest = _mapping(
        provenance.get("manifest"),
        "source-main release provenance manifest",
    )
    _exact_keys(
        manifest,
        {"path", "sha256", "size"},
        "source-main release provenance manifest",
    )
    if (
        provenance.get("schema_version") != 3
        or provenance.get("planned_tag") != dict(planned_tag)
        or provenance.get("staging_tag") != dict(staging_tag)
        or manifest.get("path") != "dist/.z4j-release-provenance.json"
    ):
        raise SourceTagRefusedError("source-main release provenance identity differs")
    _hex(manifest.get("sha256"), 64, "source-main release provenance SHA-256")
    _positive(manifest.get("size"), "source-main release provenance size")
    return provenance


def _validate_source_main_common(
    value: Mapping[str, Any],
    *,
    format_name: str,
    expected_keys: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_keys(value, expected_keys, f"{format_name} authority")
    if (
        value.get("format") != format_name
        or value.get("result") != "pass"
        or value.get("release") != RELEASE
        or value.get("repository") != REPOSITORY
        or value.get("repository_identity") != REPOSITORY_IDENTITY
        or value.get("ref") != MAIN_REF
        or value.get("expected_old") != EXPECTED_OLD_MAIN
        or value.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError(f"{format_name} identity/result differs")
    prepared = _mapping(value.get("prepared"), f"{format_name} prepared source")
    _exact_keys(prepared, {"commit", "tree"}, f"{format_name} prepared source")
    commit = _hex(prepared.get("commit"), 40, f"{format_name} prepared commit")
    _hex(prepared.get("tree"), 40, f"{format_name} prepared tree")
    planned_tag = _validate_planned_tag(value.get("planned_tag"), commit=commit)
    staging_tag = _validate_staging_tag(value.get("staging_tag"), commit=commit)
    _validate_release_provenance(
        value.get("release_provenance"),
        planned_tag=planned_tag,
        staging_tag=staging_tag,
    )
    _validate_source_blobs(value.get("source_blobs"))
    settings = _mapping(value.get("release_settings"), f"{format_name} release settings")
    validate_release_settings_authority(settings)
    scope = _mapping(settings["scope"], "release settings scope")
    if scope.get("expected_old") != EXPECTED_OLD_MAIN or scope.get("prepared") != prepared:
        raise SourceTagRefusedError(f"{format_name} release settings scope differs")
    return prepared, settings


def _validate_source_main_workflow(  # noqa: PLR0912, PLR0915 - closed authority schema
    value: object,
    *,
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    workflow = _mapping(value, "source-main workflow readback")
    _exact_keys(
        workflow,
        {
            "source",
            "release",
            "demo",
            "security",
            "push_main_material_mutators",
            "inventory",
        },
        "source-main workflow readback",
    )
    source = _mapping(workflow.get("source"), "source-main source workflow")
    _exact_keys(
        source,
        {"id", "node_id", "name", "path", "state", "response"},
        "source-main source workflow",
    )
    _positive(source.get("id"), "source-main source workflow id")
    if (
        not isinstance(source.get("node_id"), str)
        or not source["node_id"]
        or source.get("name") != "source-tag-only"
        or source.get("path") != WORKFLOW_PATH
        or source.get("state") != "active"
    ):
        raise SourceTagRefusedError("source-main source workflow identity differs")
    _canonical_object_authority(source.get("response"), "source-main source workflow response")
    release = _mapping(workflow.get("release"), "source-main release workflow")
    _exact_keys(
        release,
        {"id", "node_id", "name", "path", "state", "response"},
        "source-main release workflow",
    )
    if {key: value for key, value in release.items() if key != "response"} != {
        "id": RELEASE_WORKFLOW_ID,
        "node_id": RELEASE_WORKFLOW_NODE_ID,
        "name": RELEASE_WORKFLOW_NAME,
        "path": RELEASE_WORKFLOW_PATH,
        "state": "active",
    }:
        raise SourceTagRefusedError("source-main release workflow identity differs")
    _canonical_object_authority(release.get("response"), "source-main release workflow response")
    for key, expected in (
        (
            "demo",
            {
                "id": 270520650,
                "node_id": "W_kwDOSTi5j84QH9FK",
                "name": "demo-deploy",
                "path": ".github/workflows/demo-deploy.yml",
                "state": "disabled_manually",
            },
        ),
        (
            "security",
            {
                "id": 270520654,
                "node_id": "W_kwDOSTi5j84QH9FO",
                "name": "Security",
                "path": ".github/workflows/security.yml",
                "state": "disabled_manually",
            },
        ),
    ):
        item = _mapping(workflow.get(key), f"source-main {key} workflow")
        _exact_keys(
            item,
            {*expected, "response"},
            f"source-main {key} workflow",
        )
        if {name: item[name] for name in expected} != expected:
            raise SourceTagRefusedError(f"source-main {key} workflow identity differs")
        _canonical_object_authority(item.get("response"), f"source-main {key} workflow response")
    if workflow.get("push_main_material_mutators") != []:
        raise SourceTagRefusedError("source-main push-main material mutators are not empty")
    inventory = _mapping(workflow.get("inventory"), "source-main workflow inventory")
    _exact_keys(inventory, {"entries", "response"}, "source-main workflow inventory")
    entries = inventory.get("entries")
    if not isinstance(entries, list) or len(entries) != (
        len(PRE_S0_WORKFLOW_INVENTORY) + len(EXPECTED_ADDITION_POLICIES)
    ):
        raise SourceTagRefusedError("source-main post-S0 workflow inventory count differs")
    if entries != sorted(entries, key=lambda item: (item.get("path", ""), item.get("id", 0))):
        raise SourceTagRefusedError("source-main post-S0 workflow inventory is not sorted")
    settings_workflows = _mapping(
        _mapping(settings["policy"], "release settings policy")["workflows"],
        "release workflow-state policy",
    )
    expected_additions = {item["path"]: item for item in settings_workflows["expected_additions"]}
    expected_existing = {item["path"]: item for item in PRE_S0_WORKFLOW_INVENTORY}
    observed_by_path: dict[str, dict[str, Any]] = {}
    for index, entry_value in enumerate(entries):
        item = _mapping(entry_value, f"source-main workflow inventory entry {index}")
        path = item.get("path")
        if path in expected_existing:
            _exact_keys(
                item,
                {"id", "node_id", "name", "path", "state", "material_mutation_class"},
                f"source-main existing workflow {path}",
            )
            if item != expected_existing[path]:
                raise SourceTagRefusedError(f"source-main existing workflow {path} moved")
        elif path in expected_additions:
            _exact_keys(
                item,
                {
                    "id",
                    "node_id",
                    "name",
                    "path",
                    "state",
                    "material_mutation_class",
                    "git_oid",
                    "sha256",
                    "size",
                    "mode",
                },
                f"source-main added workflow {path}",
            )
            expected = expected_additions[path]
            if (
                {key: item[key] for key in expected if key not in {"id", "node_id", "state"}}
                != {key: expected[key] for key in expected if key not in {"id", "node_id", "state"}}
                or item.get("state") != "active"
                or not isinstance(item.get("node_id"), str)
                or not item["node_id"]
            ):
                raise SourceTagRefusedError(f"source-main added workflow {path} differs")
            _positive(item.get("id"), f"source-main added workflow {path} id")
        else:
            raise SourceTagRefusedError(f"source-main contains unknown workflow {path!r}")
        if path in observed_by_path:
            raise SourceTagRefusedError(f"source-main duplicates workflow {path!r}")
        observed_by_path[str(path)] = item
    if set(observed_by_path) != {*expected_existing, *expected_additions}:
        raise SourceTagRefusedError("source-main workflow inventory added/removed a path")
    response = _canonical_object_authority(
        inventory.get("response"),
        "source-main workflow inventory response",
    )
    response_projection = _workflow_list_projection(
        response["object"],
        "source-main post-S0 workflow inventory",
    )
    if response_projection != [
        {key: item[key] for key in ("id", "node_id", "name", "path", "state")} for item in entries
    ]:
        raise SourceTagRefusedError("source-main raw post-S0 workflow inventory differs")
    for key, path in (
        ("source", WORKFLOW_PATH),
        ("release", RELEASE_WORKFLOW_PATH),
        ("demo", ".github/workflows/demo-deploy.yml"),
        ("security", ".github/workflows/security.yml"),
    ):
        explicit = _mapping(workflow[key], f"source-main {key} workflow")
        if {name: explicit[name] for name in ("id", "node_id", "name", "path", "state")} != {
            name: observed_by_path[path][name]
            for name in ("id", "node_id", "name", "path", "state")
        }:
            raise SourceTagRefusedError(f"source-main {key} workflow/inventory differ")
    return workflow


def _validate_source_main_credential_authority(
    value: object,
    *,
    settings: Mapping[str, Any],
    token_grant: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    authority = _mapping(value, "source-main credential authority")
    _exact_keys(
        authority,
        {
            "pre_push",
            "post_push",
            "actor",
            "permissions",
            "effective_mutation",
            "expires_at",
            "verification",
        },
        "source-main credential authority",
    )
    main_policy = _mapping(
        _mapping(settings["policy"], "release settings policy")["main_ruleset"],
        "release main ruleset policy",
    )
    expected_actor = _validate_s0_actor(
        main_policy["approved_s0_actor"],
        "approved S0 GitHub App actor",
    )
    grant = _validate_s0_token_grant(
        token_grant if token_grant is not None else settings.get("token_grant_authority"),
        approved_actor=expected_actor,
    )
    if (
        authority.get("actor") != expected_actor
        or authority.get("permissions") != S0_GRANT_PERMISSIONS
        or authority.get("effective_mutation") != S0_EFFECTIVE_MUTATION
        or authority.get("expires_at") != grant["expires_at"]
        or authority.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError("source-main credential projection differs")
    for phase_name in ("pre_push", "post_push"):
        phase = _mapping(authority.get(phase_name), f"source-main {phase_name} credential")
        _exact_keys(
            phase,
            {"installation", "installation_repositories", "bot_user"},
            f"source-main {phase_name} credential",
        )
        for name in ("installation", "installation_repositories", "bot_user"):
            _canonical_object_authority(phase[name], f"source-main {phase_name} {name} response")
            if (
                phase[name]
                != _mapping(
                    settings["response_authorities"],
                    "release settings response authorities",
                )[name]
            ):
                raise SourceTagRefusedError(
                    f"source-main {phase_name} {name} differs from settings authority"
                )
    return authority


def _validate_source_main_credential_snapshot(
    value: object,
    *,
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    snapshot = _mapping(value, "source-main pre-push credential snapshot")
    _exact_keys(
        snapshot,
        {
            "installation",
            "installation_repositories",
            "bot_user",
            "actor",
            "permissions",
            "effective_mutation",
            "expires_at",
        },
        "source-main pre-push credential snapshot",
    )
    main_policy = _mapping(
        _mapping(settings["policy"], "release settings policy")["main_ruleset"],
        "release main ruleset policy",
    )
    expected_actor = _validate_s0_actor(
        main_policy["approved_s0_actor"], "approved S0 GitHub App actor"
    )
    grant = _validate_s0_token_grant(
        settings.get("token_grant_authority"), approved_actor=expected_actor
    )
    if (
        snapshot.get("actor") != expected_actor
        or snapshot.get("permissions") != S0_GRANT_PERMISSIONS
        or snapshot.get("effective_mutation") != S0_EFFECTIVE_MUTATION
        or snapshot.get("expires_at") != grant["expires_at"]
    ):
        raise SourceTagRefusedError("source-main pre-push credential projection differs")
    settings_responses = _mapping(
        settings["response_authorities"], "release settings response authorities"
    )
    for name in ("installation", "installation_repositories", "bot_user"):
        _canonical_object_authority(snapshot[name], f"source-main pre-push {name} response")
        if snapshot[name] != settings_responses[name]:
            raise SourceTagRefusedError(
                f"source-main pre-push {name} differs from settings authority"
            )
    return dict(snapshot)


def _canonical_value_authority(value: object, label: str) -> dict[str, Any]:
    authority = _mapping(value, label)
    _exact_keys(authority, {"value", "seal"}, label)
    seal = _seal(authority.get("seal"), f"{label} seal")
    raw = canonical_line(authority.get("value"))
    if seal != {"sha256": sha256(raw), "size": len(raw)}:
        raise SourceTagRefusedError(f"{label} canonical value seal differs")
    return dict(authority)


def _embedded_seal(value: object, label: str) -> dict[str, Any]:
    return _seal(value, f"{label} seal")


def _validate_source_main_prepush_seal(
    value: object,
    *,
    plan: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    preseal = _mapping(value, "source-main pre-push seal")
    _exact_keys(
        preseal,
        {
            "format",
            "result",
            "release",
            "repository",
            "ref",
            "plan",
            "release_settings",
            "credential_authority",
            "main_before",
            "tag_absence_before",
            "seals",
            "verification",
        },
        "source-main pre-push seal",
    )
    if (
        preseal.get("format") != SOURCE_MAIN_PREPUSH_SEAL_FORMAT
        or preseal.get("result") != "pass"
        or preseal.get("release") != RELEASE
        or preseal.get("repository") != REPOSITORY
        or preseal.get("ref") != MAIN_REF
        or preseal.get("plan") != dict(plan)
        or preseal.get("release_settings") != dict(settings)
        or preseal.get("tag_absence_before") is not True
        or preseal.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError("source-main pre-push seal identity differs")
    credential = _validate_source_main_credential_snapshot(
        preseal.get("credential_authority"), settings=settings
    )
    main_before = _mapping(preseal.get("main_before"), "source-main pre-push main")
    _exact_keys(
        main_before,
        {"ref", "commit", "tree", "repository_response", "ref_response"},
        "source-main pre-push main",
    )
    if (
        main_before.get("ref") != MAIN_REF
        or main_before.get("commit") != EXPECTED_OLD_MAIN["commit"]
        or main_before.get("tree") != EXPECTED_OLD_MAIN["tree"]
    ):
        raise SourceTagRefusedError("source-main pre-push predecessor differs")
    _canonical_object_authority(
        main_before.get("repository_response"), "source-main pre-push repository response"
    )
    _canonical_object_authority(
        main_before.get("ref_response"), "source-main pre-push ref response"
    )
    seals = _mapping(preseal.get("seals"), "source-main pre-push embedded seals")
    _exact_keys(
        seals,
        {"plan", "release_settings", "credential_authority", "main_before"},
        "source-main pre-push embedded seals",
    )
    embedded = {
        "plan": plan,
        "release_settings": settings,
        "credential_authority": credential,
        "main_before": main_before,
    }
    for name, item in embedded.items():
        raw = canonical_line(item)
        if _embedded_seal(seals.get(name), f"source-main pre-push {name}") != {
            "sha256": sha256(raw),
            "size": len(raw),
        }:
            raise SourceTagRefusedError(f"source-main pre-push {name} seal differs")
    return dict(preseal)


def _validate_source_main_recovery_authority(
    value: object,
    *,
    plan: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    recovery = _mapping(value, "source-main recovery authority")
    _exact_keys(
        recovery,
        {
            "source",
            "prepush_seal",
            "prepush_seal_bytes",
            "recovery_credential_authority",
            "response",
            "selected",
            "main_mutation",
            "verification",
        },
        "source-main recovery authority",
    )
    if (
        recovery.get("source") != "github-repository-events"
        or recovery.get("main_mutation") is not False
        or recovery.get("verification") != {"result": "pass"}
    ):
        raise SourceTagRefusedError("source-main recovery authority identity differs")
    preseal = _validate_source_main_prepush_seal(
        recovery.get("prepush_seal"), plan=plan, settings=settings
    )
    preseal_raw = canonical_line(preseal)
    if _seal(recovery.get("prepush_seal_bytes"), "source-main pre-push seal bytes") != {
        "sha256": sha256(preseal_raw),
        "size": len(preseal_raw),
    }:
        raise SourceTagRefusedError("source-main pre-push seal byte authority differs")
    main_policy = _mapping(
        _mapping(settings["policy"], "release settings policy")["main_ruleset"],
        "release main ruleset policy",
    )
    approved_actor = _validate_s0_actor(
        main_policy["approved_s0_actor"], "approved S0 GitHub App actor"
    )
    original_grant = _validate_s0_token_grant(
        settings.get("token_grant_authority"), approved_actor=approved_actor
    )
    recovery_credential = _mapping(
        recovery.get("recovery_credential_authority"),
        "source-main recovery credential authority",
    )
    _exact_keys(
        recovery_credential,
        {
            "token_grant_authority",
            "installation",
            "installation_repositories",
            "bot_user",
            "actor",
            "permissions",
            "effective_mutation",
            "expires_at",
        },
        "source-main recovery credential authority",
    )
    fresh_grant = _validate_s0_token_grant(
        recovery_credential.get("token_grant_authority"),
        approved_actor=approved_actor,
    )
    stable_grant_keys = {
        "format",
        "result",
        "app",
        "installation",
        "repository_selection",
        "repositories",
        "permissions",
        "effective_mutation",
        "verification",
    }
    if any(fresh_grant[key] != original_grant[key] for key in stable_grant_keys):
        raise SourceTagRefusedError("source-main recovery token stable grant differs")
    expected_recovery_snapshot = {
        "installation": _mapping(
            settings["response_authorities"], "release settings response authorities"
        )["installation"],
        "installation_repositories": settings["response_authorities"]["installation_repositories"],
        "bot_user": settings["response_authorities"]["bot_user"],
        "actor": approved_actor,
        "permissions": S0_GRANT_PERMISSIONS,
        "effective_mutation": S0_EFFECTIVE_MUTATION,
        "expires_at": fresh_grant["expires_at"],
    }
    if {
        key: recovery_credential[key] for key in expected_recovery_snapshot
    } != expected_recovery_snapshot:
        raise SourceTagRefusedError("source-main recovery credential snapshot differs")
    response = _canonical_value_authority(
        recovery.get("response"), "source-main GitHub events response"
    )
    events = response["value"]
    if not isinstance(events, list) or not events or len(events) > 100:
        raise SourceTagRefusedError("source-main GitHub events response differs")
    selected = _mapping(recovery.get("selected"), "source-main selected PushEvent")
    _exact_keys(
        selected,
        {"id", "type", "created_at", "actor", "repo", "ref", "before", "head"},
        "source-main selected PushEvent",
    )
    selected_actor = _mapping(selected.get("actor"), "source-main PushEvent actor")
    selected_repo = _mapping(selected.get("repo"), "source-main PushEvent repository")
    _exact_keys(selected_actor, {"login", "id"}, "source-main PushEvent actor")
    _exact_keys(selected_repo, {"id", "name"}, "source-main PushEvent repository")
    approved_bot = _mapping(
        _mapping(
            _mapping(settings["policy"], "release settings policy")["main_ruleset"],
            "release main ruleset policy",
        )["approved_s0_actor"]["bot"],
        "approved S0 App bot",
    )
    try:
        created_at = datetime.fromisoformat(str(selected.get("created_at")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceTagRefusedError("source-main PushEvent timestamp differs") from exc
    if (
        not isinstance(selected.get("id"), str)
        or not selected["id"]
        or selected.get("type") != "PushEvent"
        or created_at.tzinfo is None
        or selected_actor != {"login": approved_bot["login"], "id": approved_bot["id"]}
        or selected_repo != {"id": REPOSITORY_ID, "name": REPOSITORY}
        or selected.get("ref") != MAIN_REF
        or selected.get("before") != EXPECTED_OLD_MAIN["commit"]
        or selected.get("head") != _mapping(plan["prepared"], "prepared source")["commit"]
    ):
        raise SourceTagRefusedError("source-main selected PushEvent binding differs")
    matching = []
    for event in events:
        if not isinstance(event, dict):
            continue
        payload = event.get("payload")
        actor = event.get("actor")
        repository = event.get("repo")
        if (
            not isinstance(payload, dict)
            or not isinstance(actor, dict)
            or not isinstance(repository, dict)
        ):
            continue
        projection = {
            "id": event.get("id"),
            "type": event.get("type"),
            "created_at": event.get("created_at"),
            "actor": {"login": actor.get("login"), "id": actor.get("id")},
            "repo": {"id": repository.get("id"), "name": repository.get("name")},
            "ref": payload.get("ref"),
            "before": payload.get("before"),
            "head": payload.get("head"),
        }
        if projection == dict(selected):
            matching.append(event)
    if len(matching) != 1:
        raise SourceTagRefusedError("source-main recovery lacks one exact PushEvent")
    return dict(recovery)


def load_source_main_authority(  # noqa: PLR0912, PLR0915 - closed three-file authority
    plan_path: Path,
    readback_path: Path,
    settings_path: Path,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    plan, plan_raw = load_canonical(plan_path, "source-main transition plan")
    readback, readback_raw = load_canonical(readback_path, "source-main transition readback")
    settings, settings_raw = load_release_settings_authority(settings_path)
    plan_keys = {
        "format",
        "result",
        "release",
        "repository",
        "repository_identity",
        "ref",
        "expected_old",
        "prepared",
        "planned_tag",
        "staging_tag",
        "release_provenance",
        "source_blobs",
        "release_settings",
        "verification",
    }
    prepared, embedded_settings = _validate_source_main_common(
        plan,
        format_name=SOURCE_MAIN_PLAN_FORMAT,
        expected_keys=plan_keys,
    )
    readback_keys = plan_keys | {
        "transition",
        "main",
        "workflow",
        "credential_authority",
        "recovery_authority",
        "tag_absence",
        "post_push_runs",
    }
    readback_prepared, readback_settings = _validate_source_main_common(
        readback,
        format_name=SOURCE_MAIN_READBACK_FORMAT,
        expected_keys=readback_keys,
    )
    if (
        prepared != readback_prepared
        or embedded_settings != settings
        or readback_settings != settings
        or any(
            plan[key] != readback[key]
            for key in (
                "release",
                "repository",
                "repository_identity",
                "ref",
                "expected_old",
                "prepared",
                "planned_tag",
                "staging_tag",
                "release_provenance",
                "source_blobs",
                "release_settings",
            )
        )
    ):
        raise SourceTagRefusedError("source-main plan/readback/settings differ")
    live_transition = {
        "operation": "fast-forward-main-only",
        "force": False,
        "result": "exact",
    }
    transition = readback.get("transition")
    if transition not in (live_transition, SOURCE_MAIN_RECOVERY_TRANSITION):
        raise SourceTagRefusedError("source-main transition semantics differ")
    if transition == live_transition:
        if readback.get("recovery_authority") is not None:
            raise SourceTagRefusedError("live source-main transition contains recovery authority")
        recovery_authority = None
    else:
        recovery_authority = _validate_source_main_recovery_authority(
            readback.get("recovery_authority"), plan=plan, settings=settings
        )
    main = _mapping(readback.get("main"), "source-main main readback")
    _exact_keys(
        main,
        {
            "ref",
            "commit",
            "tree",
            "repository_response",
            "ref_response",
            "commit_response",
        },
        "source-main main readback",
    )
    if (
        main.get("ref") != MAIN_REF
        or main.get("commit") != prepared["commit"]
        or main.get("tree") != prepared["tree"]
    ):
        raise SourceTagRefusedError("source-main main ref/commit/tree readback differs")
    for name in ("repository_response", "ref_response", "commit_response"):
        _canonical_object_authority(main.get(name), f"source-main {name}")
    _validate_source_main_workflow(readback.get("workflow"), settings=settings)
    _validate_source_main_credential_authority(
        readback.get("credential_authority"),
        settings=settings,
        token_grant=(
            _mapping(
                recovery_authority["recovery_credential_authority"],
                "source-main recovery credential authority",
            )["token_grant_authority"]
            if recovery_authority is not None
            else None
        ),
    )
    if recovery_authority is not None:
        credential = _mapping(readback["credential_authority"], "source-main credential authority")
        recovery_credential = _mapping(
            recovery_authority["recovery_credential_authority"],
            "source-main recovery credential authority",
        )
        if (
            credential["pre_push"]
            != {
                key: recovery_credential[key]
                for key in ("installation", "installation_repositories", "bot_user")
            }
            or credential["post_push"] != credential["pre_push"]
            or any(
                credential[key] != recovery_credential[key]
                for key in ("actor", "permissions", "effective_mutation", "expires_at")
            )
        ):
            raise SourceTagRefusedError("source-main recovery credential and outer readback differ")
    source_blob = _mapping(plan["source_blobs"], "source-main blob authority")[WORKFLOW_PATH]
    source_addition = next(
        item
        for item in _mapping(settings["policy"], "release settings policy")["workflows"][
            "expected_additions"
        ]
        if item["path"] == WORKFLOW_PATH
    )
    if {key: source_addition[key] for key in ("git_oid", "sha256", "size", "mode")} != source_blob:
        raise SourceTagRefusedError("source-tag expected-addition and blob seals differ")
    if readback.get("tag_absence") != {"before": True, "after": True}:
        raise SourceTagRefusedError("source-main v1.9.0 absence proof differs")
    runs = _mapping(readback.get("post_push_runs"), "source-main post-push runs")
    _exact_keys(
        runs,
        {"query", "response", "matching_runs", "secondary_writes"},
        "source-main post-push runs",
    )
    query = _mapping(runs.get("query"), "source-main post-push run query")
    _exact_keys(
        query,
        {"branch", "event", "created_after", "created_before"},
        "source-main post-push run query",
    )
    try:
        after = datetime.fromisoformat(str(query.get("created_after")).replace("Z", "+00:00"))
        before = datetime.fromisoformat(str(query.get("created_before")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceTagRefusedError("source-main run query times differ") from exc
    if (
        query.get("branch") != "main"
        or query.get("event") != "push"
        or after.tzinfo is None
        or before.tzinfo is None
        or after >= before
        or (before - after).total_seconds() < POST_PUSH_SETTLE_SECONDS
        or runs.get("matching_runs") != []
        or runs.get("secondary_writes") != []
    ):
        raise SourceTagRefusedError("source-main post-push secondary-run proof differs")
    _canonical_object_authority(runs.get("response"), "source-main post-push runs response")
    response_object = _mapping(
        _mapping(runs["response"], "source-main post-push runs response")["object"],
        "source-main post-push runs response object",
    )
    if response_object != {"total_count": 0, "workflow_runs": []}:
        raise SourceTagRefusedError("source-main final post-push run response is not empty")
    return {
        "plan": plan,
        "readback": readback,
        "release_settings": settings,
        "seals": {
            "plan": {"sha256": sha256(plan_raw), "size": len(plan_raw)},
            "readback": {"sha256": sha256(readback_raw), "size": len(readback_raw)},
            "release_settings": {
                "sha256": sha256(settings_raw),
                "size": len(settings_raw),
            },
        },
    }, {
        "plan": plan_raw,
        "readback": readback_raw,
        "release_settings": settings_raw,
    }


def encode_source_main_authority_input(
    settings_path: Path,
    plan_path: Path,
    readback_path: Path,
) -> str:
    """Encode the exact three canonical authorities for one dispatch input."""
    _, raws = load_source_main_authority(plan_path, readback_path, settings_path)
    ordered = (
        (RELEASE_SETTINGS_NAME, raws["release_settings"]),
        (SOURCE_MAIN_PLAN_NAME, raws["plan"]),
        (SOURCE_MAIN_READBACK_NAME, raws["readback"]),
    )
    framed = bytearray(SOURCE_MAIN_TRANSPORT_MAGIC)
    framed.extend(struct.pack(">HH", SOURCE_MAIN_TRANSPORT_VERSION, len(ordered)))
    for name, raw in ordered:
        encoded_name = name.encode("ascii")
        framed.extend(struct.pack(">H", len(encoded_name)))
        framed.extend(encoded_name)
        framed.extend(struct.pack(">I", len(raw)))
        framed.extend(raw)
    if len(framed) > MAX_SOURCE_MAIN_TRANSPORT_RAW:
        raise SourceTagRefusedError("source-main transport raw authority exceeds 1 MiB")
    compressor = zlib.compressobj(level=9, wbits=15)
    compressed = compressor.compress(bytes(framed)) + compressor.flush(zlib.Z_FINISH)
    encoded = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
    if (
        not encoded
        or len(encoded) > MAX_SOURCE_MAIN_TRANSPORT_ASCII
        or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None
    ):
        raise SourceTagRefusedError("source-main authority does not fit exact dispatch transport")
    return encoded


def _take_frame(raw: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    if size < 0 or offset < 0 or offset + size > len(raw):
        raise SourceTagRefusedError(f"source-main transport truncates {label}")
    return raw[offset : offset + size], offset + size


def decode_source_main_authority_input(  # noqa: PLR0912 - strict framing validator
    payload: str,
    output_root: Path,
) -> dict[str, Any]:
    """Strictly decode, validate, and materialize the S0/settings handoff."""
    if (
        not isinstance(payload, str)
        or not payload
        or len(payload) > MAX_SOURCE_MAIN_TRANSPORT_ASCII
        or "=" in payload
        or re.fullmatch(r"[A-Za-z0-9_-]+", payload) is None
        or len(payload) % 4 == 1
    ):
        raise SourceTagRefusedError("source-main dispatch transport framing differs")
    padding = "=" * ((4 - len(payload) % 4) % 4)
    try:
        compressed = base64.b64decode(
            payload + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise SourceTagRefusedError("source-main dispatch transport is not exact base64") from exc
    decompressor = zlib.decompressobj(wbits=15)
    try:
        framed = decompressor.decompress(
            compressed,
            MAX_SOURCE_MAIN_TRANSPORT_RAW + 1,
        )
        remaining = MAX_SOURCE_MAIN_TRANSPORT_RAW + 1 - len(framed)
        if remaining > 0:
            framed += decompressor.flush(remaining)
    except zlib.error as exc:
        raise SourceTagRefusedError("source-main dispatch transport zlib stream differs") from exc
    if (
        len(framed) > MAX_SOURCE_MAIN_TRANSPORT_RAW
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise SourceTagRefusedError(
            "source-main dispatch transport is trailing/concatenated/oversize"
        )
    offset = 0
    magic, offset = _take_frame(
        framed,
        offset,
        len(SOURCE_MAIN_TRANSPORT_MAGIC),
        "magic",
    )
    header, offset = _take_frame(framed, offset, 4, "version/count")
    version, count = struct.unpack(">HH", header)
    if (
        magic != SOURCE_MAIN_TRANSPORT_MAGIC
        or version != SOURCE_MAIN_TRANSPORT_VERSION
        or count != len(SOURCE_MAIN_TRANSPORT_NAMES)
    ):
        raise SourceTagRefusedError("source-main transport magic/version/count differs")
    files: dict[str, bytes] = {}
    for expected_name in SOURCE_MAIN_TRANSPORT_NAMES:
        name_size_raw, offset = _take_frame(framed, offset, 2, "name length")
        (name_size,) = struct.unpack(">H", name_size_raw)
        name_raw, offset = _take_frame(framed, offset, name_size, "name")
        try:
            name = name_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SourceTagRefusedError("source-main transport filename is not ASCII") from exc
        size_raw, offset = _take_frame(framed, offset, 4, f"{name} length")
        (size,) = struct.unpack(">I", size_raw)
        content, offset = _take_frame(framed, offset, size, f"{name} content")
        if name != expected_name or name in files or size <= 0 or size > MAX_JSON_BYTES:
            raise SourceTagRefusedError("source-main transport file order/name/size differs")
        files[name] = content
    if offset != len(framed):
        raise SourceTagRefusedError("source-main transport has trailing framed bytes")
    with tempfile.TemporaryDirectory(prefix="z4j-source-main-transport-") as directory:
        private = Path(directory)
        for name in SOURCE_MAIN_TRANSPORT_NAMES:
            _write_exclusive(private / name, files[name])
        authority, _ = load_source_main_authority(
            private / SOURCE_MAIN_PLAN_NAME,
            private / SOURCE_MAIN_READBACK_NAME,
            private / RELEASE_SETTINGS_NAME,
        )
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output_root.iterdir()):
        raise SourceTagRefusedError("source-main transport output must be empty")
    for name in SOURCE_MAIN_TRANSPORT_NAMES:
        _write_exclusive(output_root / name, files[name])
    return {
        "format": "z4j-source-main-authority-transport-v1",
        "result": "pass",
        "magic": SOURCE_MAIN_TRANSPORT_MAGIC[:-1].decode("ascii"),
        "version": SOURCE_MAIN_TRANSPORT_VERSION,
        "files": [
            {
                "name": name,
                "sha256": sha256(files[name]),
                "size": len(files[name]),
            }
            for name in SOURCE_MAIN_TRANSPORT_NAMES
        ],
        "prepared": authority["plan"]["prepared"],
        "verification": {"result": "pass"},
    }


_NETWORK_OVERRIDE_NAMES = frozenset(
    {
        "all_proxy",
        "curl_ca_bundle",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "requests_ca_bundle",
        "ssl_cert_dir",
        "ssl_cert_file",
    }
)
_RUNTIME_OVERRIDE_NAMES = frozenset(
    {
        "ld_audit",
        "ld_debug",
        "ld_library_path",
        "ld_preload",
        "pythonbreakpoint",
        "pythonhome",
        "pythoninspect",
        "pythonpath",
        "pythonstartup",
        "pythonwarnings",
    }
)


def _ambient_overrides(names: frozenset[str]) -> list[str]:
    return sorted(key for key, value in os.environ.items() if value and key.casefold() in names)


def _reject_ambient_network_overrides() -> None:
    observed = _ambient_overrides(_NETWORK_OVERRIDE_NAMES)
    if observed:
        raise SourceTagRefusedError(
            "ambient proxy/TLS trust overrides are forbidden: " + ",".join(observed)
        )


def _reject_release_consumer_environment() -> None:
    observed = _ambient_overrides(_NETWORK_OVERRIDE_NAMES | _RUNTIME_OVERRIDE_NAMES)
    observed.extend(
        sorted(
            key for key, value in os.environ.items() if value and key.casefold().startswith("dyld_")
        )
    )
    if observed:
        raise SourceTagRefusedError(
            "ambient network/loader/Python overrides are forbidden: "
            + ",".join(sorted(set(observed)))
        )


def _sealed_subprocess_environment(private_root: Path) -> dict[str, str]:
    return {
        "HOME": str(private_root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": str(private_root),
        "TZ": "UTC",
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _proxyless_urlopen(request: urllib.request.Request, *, timeout: int) -> Any:
    _require_git_runtime_authority()
    _reject_ambient_network_overrides()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
    }


def _require_git_runtime_authority() -> None:
    raise SourceTagRefusedError(
        "Git executable path, byte seal, and version authority are UNFINALIZED; release consumer refuses before any Git process"
    )


def _git_result(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    _require_git_runtime_authority()
    command = ("git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *arguments)
    return subprocess.run(  # noqa: S603 - fixed command beneath authority guard
        command,
        input=input_bytes,
        env=_git_environment(),
        check=False,
        capture_output=True,
    )


def _git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = _git_result(repo, *arguments, input_bytes=input_bytes)
    if completed.returncode != 0:
        raise SourceTagRefusedError(
            f"Git command failed: {' '.join(arguments)}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()}",
        )
    return completed.stdout


def _assert_sterile_local_repository(repo: Path) -> None:
    common_text = _git(repo, "rev-parse", "--git-common-dir").decode("utf-8").strip()
    if not common_text:
        raise SourceTagRefusedError("local repository common Git directory is absent")
    common = Path(common_text)
    if not common.is_absolute():
        common = repo / common
    alternates = common / "objects" / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink():
        raise SourceTagRefusedError("local repository object alternates are forbidden")


def _validate_signature_verifier(value: object) -> dict[str, Any]:
    authority = _mapping(value, "production signature_verifier")
    _exact_keys(
        authority,
        {"name", "version", "runtime_path", "release_response", "platforms"},
        "production signature_verifier",
    )
    if (
        authority["name"] != "cosign"
        or authority["version"] != COSIGN_VERSION
        or authority["runtime_path"] != "/usr/local/bin/cosign"
    ):
        raise SourceTagRefusedError("production signature_verifier identity is not Cosign 3.1.3")
    release_response = _mapping(authority["release_response"], "Cosign release response authority")
    _exact_keys(release_response, {"path", "sha256", "size"}, "Cosign release response")
    if release_response["path"] != "evidence/cosign-release.json":
        raise SourceTagRefusedError("Cosign release response path differs")
    _hex(release_response["sha256"], 64, "Cosign release response SHA-256")
    _positive(release_response["size"], "Cosign release response size")
    platforms = _mapping(authority["platforms"], "Cosign platforms")
    _exact_keys(platforms, {"linux/amd64", "linux/arm64"}, "Cosign platforms")
    for name, filename in (
        ("linux/amd64", "cosign-linux-amd64"),
        ("linux/arm64", "cosign-linux-arm64"),
    ):
        item = _mapping(platforms[name], f"Cosign {name} authority")
        _exact_keys(
            item,
            {
                "filename",
                "url",
                "sha256",
                "size",
                "version_output_sha256",
                "version_output_size",
            },
            f"Cosign {name} authority",
        )
        expected_url = (
            f"https://github.com/sigstore/cosign/releases/download/v{COSIGN_VERSION}/{filename}"
        )
        if item["filename"] != filename or item["url"] != expected_url:
            raise SourceTagRefusedError(f"Cosign {name} filename/URL differs")
        _hex(item["sha256"], 64, f"Cosign {name} SHA-256")
        _positive(item["size"], f"Cosign {name} size")
        _hex(item["version_output_sha256"], 64, f"Cosign {name} version SHA-256")
        _positive(item["version_output_size"], f"Cosign {name} version size")
    return authority


def wheelhouse_authority(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the retained pre-tag OCI subject selected by the finalized contract."""
    wheelhouse = _mapping(manifest.get("wheelhouse"), "production wheelhouse")
    image = wheelhouse.get("image")
    if not isinstance(image, str):
        raise SourceTagRefusedError("finalized production wheelhouse image is absent")
    matched = WHEELHOUSE_IMAGE.fullmatch(image)
    if matched is None:
        raise SourceTagRefusedError("production wheelhouse image is not an exact Docker Hub digest")
    # The subject must stay in its dedicated retained repository.  A generic
    # release-image or rollback-image subject would make the source authority
    # depend on an artifact that is created after the source tag.
    repository = matched.group("repository")
    if repository != "z4jdev/z4j-production-wheelhouse":
        raise SourceTagRefusedError("production wheelhouse evidence repository differs")
    tag = matched.group("tag")
    index = _mapping(wheelhouse.get("index"), "production wheelhouse index")
    _exact_keys(index, {"digest", "size"}, "production wheelhouse index")
    subject_digest = _digest(index.get("digest"), "production wheelhouse index digest")
    subject_size = _size(
        index.get("size"),
        "production wheelhouse index size",
        maximum=1024 * 1024,
    )
    if matched.group("digest") != subject_digest:
        raise SourceTagRefusedError("wheelhouse image and index digest differ")
    expected_tag = f"{RELEASE}-digest-{subject_digest.removeprefix('sha256:')}"
    if tag != expected_tag:
        raise SourceTagRefusedError(
            "production wheelhouse tag is not exact content-derived retention"
        )
    return {
        "registry": REGISTRY_ORIGIN,
        "repository": repository,
        "reference": image,
        "retention_tag": tag,
        "subject": {
            "mediaType": OCI_INDEX,
            "digest": subject_digest,
            "size": subject_size,
        },
    }


def validate_manifest(
    path: Path,
    *,
    approved_commit: str,
    approved_tree: str,
) -> tuple[dict[str, Any], bytes]:
    manifest, raw = load_canonical(path, "production manifest")
    if manifest.get("schema_version") != 1:
        raise SourceTagRefusedError("production manifest schema_version differs")
    if manifest.get("kind") != "z4j-production-container-contract":
        raise SourceTagRefusedError("production manifest kind differs")
    if manifest.get("release") != RELEASE or manifest.get("state") != "finalized":
        raise SourceTagRefusedError("production manifest is not finalized for 1.9.0")
    finalization = _mapping(manifest.get("finalization"), "production finalization")
    if "source_tag_authority" in manifest:
        raise SourceTagRefusedError(
            "tracked production manifest must not embed realized source-tag authority",
        )
    policy = _mapping(
        manifest.get("source_tag_authority_policy"),
        "production source-tag authority policy",
    )
    _exact_keys(policy, set(SOURCE_TAG_AUTHORITY_POLICY), "source-tag authority policy")
    if policy != SOURCE_TAG_AUTHORITY_POLICY:
        raise SourceTagRefusedError("source-tag authority policy differs")
    cutoff = finalization.get("not_before_utc")
    if not isinstance(cutoff, str):
        raise SourceTagRefusedError("production cutoff is missing")
    try:
        cutoff_at = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceTagRefusedError("production cutoff is invalid") from exc
    if cutoff_at.tzinfo is None or datetime.now(UTC) < cutoff_at.astimezone(UTC):
        raise SourceTagRefusedError("production finalization cutoff has not elapsed")
    source = _mapping(manifest.get("source_authority"), "production source authority")
    freeze = _mapping(source.get("production_source_freeze"), "production source freeze")
    _exact_keys(freeze, {"commit", "tree"}, "production source freeze")
    _hex(freeze.get("commit"), 40, "production source-freeze commit")
    _hex(freeze.get("tree"), 40, "production source-freeze tree")
    _hex(approved_commit, 40, "approved release commit")
    _hex(approved_tree, 40, "approved release tree")
    _validate_signature_verifier(manifest.get("signature_verifier"))
    wheelhouse_authority(manifest)
    return manifest, raw


def _tracked_head_blob(
    repo: Path,
    path: Path,
    *,
    commit: str,
    label: str,
) -> tuple[bytes, dict[str, Any]]:
    repo_absolute = repo.absolute()
    path_absolute = path.absolute()
    try:
        relative = path_absolute.relative_to(repo_absolute).as_posix()
    except ValueError as exc:
        raise SourceTagRefusedError(f"{label} is outside the approved repository") from exc
    if not relative or relative.startswith("../"):
        raise SourceTagRefusedError(f"{label} repository path differs")
    tree_line = _git(repo, "ls-tree", commit, "--", relative).decode("ascii").strip()
    try:
        mode, object_type, git_oid, observed_path = re.split(r"[ \t]", tree_line, maxsplit=3)
    except ValueError as exc:
        raise SourceTagRefusedError(f"{label} tracked tree entry differs") from exc
    if mode != "100644" or object_type != "blob" or observed_path != relative:
        raise SourceTagRefusedError(f"{label} is not the exact Git100644 blob")
    _hex(git_oid, 40, f"{label} Git OID")
    committed = _git(repo, "cat-file", "blob", git_oid)
    worktree = read_regular(path)
    if committed != worktree:
        raise SourceTagRefusedError(f"{label} worktree bytes differ from approved HEAD")
    return committed, {
        "path": relative,
        "git_oid": git_oid,
        "sha256": sha256(committed),
        "size": len(committed),
        "mode": "100644",
    }


def verify_production_source(
    repo: Path,
    manifest_path: Path,
    *,
    release_commit: str,
    release_tree: str,
) -> dict[str, Any]:
    _require_git_runtime_authority()
    verifier = manifest_path.parent / "verify.py"
    _hex(release_commit, 40, "production verifier release commit")
    _hex(release_tree, 40, "production verifier release tree")
    verifier_raw, verifier_authority = _tracked_head_blob(
        repo,
        verifier,
        commit=release_commit,
        label="production source verifier",
    )
    manifest_raw, manifest_authority = _tracked_head_blob(
        repo,
        manifest_path,
        commit=release_commit,
        label="production manifest",
    )
    with tempfile.TemporaryDirectory(prefix="z4j-production-source-verifier-") as directory:
        environment = _sealed_subprocess_environment(Path(directory))
        private_root = Path(directory) / "docker" / "production"
        private_root.mkdir(mode=0o700, parents=True)
        private_verifier = private_root / "verify.py"
        private_manifest = private_root / "manifest.json"
        _write_exclusive(private_verifier, verifier_raw)
        _write_exclusive(private_manifest, manifest_raw)
        private_verifier.chmod(0o500)
        private_manifest.chmod(0o400)
        completed = subprocess.run(  # noqa: S603 - private exact Git blob and fixed arguments
            (
                sys.executable,
                "-I",
                "-B",
                str(private_verifier),
                "source",
                "--manifest",
                str(private_manifest),
                "--repo-root",
                str(repo),
                "--require-finalized",
                "--release-commit",
                release_commit,
                "--release-tree",
                release_tree,
            ),
            cwd=repo,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    if completed.returncode != 0:
        raise SourceTagRefusedError(
            "production source/post-freeze verifier refused the release: "
            + (completed.stderr.strip() or completed.stdout.strip()),
        )
    closing_verifier, closing_verifier_authority = _tracked_head_blob(
        repo,
        verifier,
        commit=release_commit,
        label="production source verifier final readback",
    )
    closing_manifest, closing_manifest_authority = _tracked_head_blob(
        repo,
        manifest_path,
        commit=release_commit,
        label="production manifest final readback",
    )
    if (
        closing_verifier != verifier_raw
        or closing_manifest != manifest_raw
        or closing_verifier_authority != verifier_authority
        or closing_manifest_authority != manifest_authority
    ):
        raise SourceTagRefusedError("production verifier/manifest moved during validation")
    return {
        "verifier": verifier_authority,
        "manifest": manifest_authority,
        "execution": {"result": "pass", "isolated_private_blobs": True},
    }


def runtime_platform() -> str:
    machine = platform.machine().lower()
    if platform.system() != "Linux":
        raise SourceTagRefusedError("source tag ceremony must run on Linux")
    if machine in {"x86_64", "amd64"}:
        return "linux/amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux/arm64"
    raise SourceTagRefusedError(f"unsupported source-tag runner architecture: {machine}")


def verify_cosign(
    binary_path: Path,
    version_path: Path,
    signature_verifier: Mapping[str, Any],
) -> dict[str, Any]:
    _require_git_runtime_authority()
    selected_platform = runtime_platform()
    selected = _mapping(
        _mapping(signature_verifier["platforms"], "Cosign platforms")[selected_platform],
        "selected Cosign authority",
    )
    binary = read_regular(binary_path, limit=256 * 1024 * 1024)
    version = read_regular(version_path, limit=1024 * 1024)
    if len(binary) != selected["size"] or sha256(binary) != selected["sha256"]:
        raise SourceTagRefusedError("downloaded Cosign bytes differ from finalized authority")
    if (
        len(version) != selected["version_output_size"]
        or sha256(version) != selected["version_output_sha256"]
    ):
        raise SourceTagRefusedError("Cosign version transcript differs from finalized authority")
    try:
        reported = _mapping(json.loads(version), "Cosign version transcript").get("gitVersion")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError("Cosign version transcript is not JSON") from exc
    if not isinstance(reported, str) or reported.removeprefix("v") != COSIGN_VERSION:
        raise SourceTagRefusedError("Cosign version transcript is not exactly 3.1.3")
    return {
        "platform": selected_platform,
        "binary": {"sha256": sha256(binary), "size": len(binary)},
        "version_output": {"sha256": sha256(version), "size": len(version)},
    }


def _commit_tagger(repo: Path, commit: str) -> tuple[int, str, str]:
    output = _git(repo, "show", "-s", "--format=%ct%x00%cI", commit).decode("ascii").strip()
    try:
        epoch_text, iso = output.split("\x00", 1)
        epoch = int(epoch_text)
    except (ValueError, TypeError) as exc:
        raise SourceTagRefusedError("cannot derive deterministic tagger date") from exc
    if iso.endswith("Z"):
        offset = "+0000"
    elif re.search(r"[+-][0-9]{2}:[0-9]{2}$", iso):
        offset = iso[-6:].replace(":", "")
    else:
        raise SourceTagRefusedError("commit timestamp has an unsupported offset")
    normalized = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return epoch, offset, normalized


def tag_bytes(repo: Path, commit: str) -> tuple[bytes, dict[str, Any]]:
    epoch, offset, normalized = _commit_tagger(repo, commit)
    raw = (
        f"object {commit}\n"
        "type commit\n"
        f"tag {TAG}\n"
        f"tagger {TAGGER_NAME} <{TAGGER_EMAIL}> {epoch} {offset}\n\n"
        f"{TAG_MESSAGE}\n"
    ).encode("ascii")
    expected = _git(repo, "hash-object", "-t", "tag", "--stdin", input_bytes=raw)
    tag_object = expected.decode("ascii").strip()
    _hex(tag_object, 40, "deterministic tag object")
    return raw, {
        "tagger": {
            "name": TAGGER_NAME,
            "email": TAGGER_EMAIL,
            "date": normalized,
            "git_epoch": epoch,
            "git_offset": offset,
        },
        "message": TAG_MESSAGE,
        "object": tag_object,
    }


def validate_wheelhouse_retention(
    response_path: Path,
    *,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    wheelhouse = wheelhouse_authority(manifest)
    hub, hub_raw = load_canonical(
        response_path,
        "Docker Hub wheelhouse repository response",
    )
    settings = _mapping(hub.get("immutable_tags_settings"), "wheelhouse immutable settings")
    if (
        hub.get("namespace") != "z4jdev"
        or hub.get("name") != "z4j-production-wheelhouse"
        or set(settings) != {"enabled", "rules"}
        or settings.get("enabled") is not True
        or settings.get("rules") != IMMUTABLE_RETENTION_RULES
        or re.fullmatch(WHEELHOUSE_RETENTION_RULE, wheelhouse["retention_tag"]) is None
    ):
        raise SourceTagRefusedError(
            "Docker Hub wheelhouse tag is not authenticated immutable/nondeletable authority"
        )
    return {
        "provider": "docker-hub",
        "api": HUB_API_REPOSITORY,
        "repository": "docker.io/z4jdev/z4j-production-wheelhouse",
        "reference": wheelhouse["reference"],
        "target_tag": wheelhouse["retention_tag"],
        "subject": wheelhouse["subject"],
        "immutable_tags_settings": {
            "enabled": True,
            "rules": IMMUTABLE_RETENTION_RULES,
        },
        "required_behavior": "matched-tag-cannot-be-overwritten-or-deleted",
        "response": {"sha256": sha256(hub_raw), "size": len(hub_raw)},
    }


def validate_source_workflow(response_path: Path) -> dict[str, Any]:
    workflow, raw = load_canonical(response_path, "source-tag workflow response")
    workflow_id = _positive(workflow.get("id"), "source-tag workflow id")
    node_id = workflow.get("node_id")
    if (
        not isinstance(node_id, str)
        or not node_id
        or workflow.get("name") != "source-tag-only"
        or workflow.get("path") != WORKFLOW_PATH
        or workflow.get("state") != "active"
        or workflow.get("html_url")
        != "https://github.com/z4jdev/z4j/blob/main/.github/workflows/source-tag-only.yml"
    ):
        raise SourceTagRefusedError("source-tag workflow API identity differs")
    return {
        "id": workflow_id,
        "node_id": node_id,
        "name": "source-tag-only",
        "path": WORKFLOW_PATH,
        "state": "active",
        "html_url": workflow["html_url"],
        "response": {"sha256": sha256(raw), "size": len(raw)},
    }


def validate_release_workflow(response_path: Path) -> dict[str, Any]:
    workflow, raw = load_canonical(response_path, "release-docker workflow response")
    expected = {
        "id": RELEASE_WORKFLOW_ID,
        "node_id": RELEASE_WORKFLOW_NODE_ID,
        "name": RELEASE_WORKFLOW_NAME,
        "path": RELEASE_WORKFLOW_PATH,
        "state": "active",
        "html_url": RELEASE_WORKFLOW_HTML_URL,
        "created_at": RELEASE_WORKFLOW_CREATED_AT,
        "updated_at": RELEASE_WORKFLOW_UPDATED_AT,
    }
    if any(workflow.get(key) != value for key, value in expected.items()):
        raise SourceTagRefusedError("release-docker workflow API identity differs")
    return {
        **expected,
        "response": {"sha256": sha256(raw), "size": len(raw)},
    }


def validate_pre_e0_static_source(
    *,
    repo: Path,
    source_main_plan: Path,
    source_main_readback: Path,
    release_settings_authority: Path,
    approved_commit: str,
    approved_tree: str,
) -> dict[str, Any]:
    """Validate bounded local source/S0 authority before any external trust flow."""
    _hex(approved_commit, 40, "pre-E0 approved commit")
    _hex(approved_tree, 40, "pre-E0 approved tree")
    _assert_sterile_local_repository(repo)
    if (
        _git(repo, "rev-parse", "HEAD").decode("ascii").strip() != approved_commit
        or _git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip() != approved_tree
        or _git(repo, "status", "--porcelain", "--untracked-files=all").strip()
    ):
        raise SourceTagRefusedError("pre-E0 checkout commit/tree/clean authority differs")
    if _local_tag_value(repo) is not None:
        raise SourceTagRefusedError("pre-E0 checkout already carries the deferred source tag")
    source_main, raws = load_source_main_authority(
        source_main_plan,
        source_main_readback,
        release_settings_authority,
    )
    source_plan = _mapping(source_main["plan"], "pre-E0 source-main plan")
    if source_plan.get("prepared") != {
        "commit": approved_commit,
        "tree": approved_tree,
    }:
        raise SourceTagRefusedError("pre-E0 source-main prepared source differs")
    raw_tag, tag = tag_bytes(repo, approved_commit)
    expected_planned_tag = {
        "name": TAG,
        "ref": TAG_REF,
        "object": tag["object"],
        "target_commit": approved_commit,
        "raw_sha256": sha256(raw_tag),
        "raw_size": len(raw_tag),
        "message": TAG_MESSAGE,
        "tagger": {
            "name": TAGGER_NAME,
            "email": TAGGER_EMAIL,
            "git_epoch": tag["tagger"]["git_epoch"],
            "git_offset": tag["tagger"]["git_offset"],
        },
    }
    if source_plan.get("planned_tag") != expected_planned_tag:
        raise SourceTagRefusedError("pre-E0 deterministic planned tag differs")
    staging_tag = _validate_staging_tag(
        source_plan.get("staging_tag"),
        commit=approved_commit,
    )
    source_blobs = _validate_source_blobs(source_plan.get("source_blobs"))
    for path, expected_blob in source_blobs.items():
        file_path = repo / path
        raw = read_regular(file_path)
        line = _git(repo, "ls-tree", approved_commit, "--", path).decode("ascii").strip()
        try:
            mode, object_type, git_oid, observed_path = re.split(r"[ \t]", line, maxsplit=3)
        except ValueError as exc:
            raise SourceTagRefusedError(f"pre-E0 source blob {path} tree entry differs") from exc
        if (
            mode != "100644"
            or object_type != "blob"
            or observed_path != path
            or expected_blob
            != {
                "git_oid": git_oid,
                "sha256": sha256(raw),
                "size": len(raw),
                "mode": "100644",
            }
        ):
            raise SourceTagRefusedError(f"pre-E0 source blob {path} differs")
    if (
        _git(repo, "rev-parse", "HEAD").decode("ascii").strip() != approved_commit
        or _git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip() != approved_tree
        or _git(repo, "status", "--porcelain", "--untracked-files=all").strip()
        or _local_tag_value(repo) is not None
    ):
        raise SourceTagRefusedError("pre-E0 source authority changed during validation")
    return {
        "format": "z4j-source-tag-pre-e0-static-v1",
        "result": "pass",
        "repository": REPOSITORY,
        "source": {"commit": approved_commit, "tree": approved_tree},
        "source_main": {
            name: {"sha256": sha256(raw), "size": len(raw)} for name, raw in raws.items()
        },
        "planned_tag": expected_planned_tag,
        "staging_tag": staging_tag,
        "source_blobs": source_blobs,
        "verification": {"result": "pass", "network": False, "mutation": False},
    }


def build_plan(  # noqa: PLR0912,PLR0915 - one fail-closed authority projection
    *,
    repo: Path,
    manifest_path: Path,
    repository_response: Path,
    main_ref_response: Path,
    ruleset_response: Path,
    main_ruleset_response: Path,
    main_branch_protection_response: Path,
    environment_response: Path,
    wheelhouse_repository_response: Path,
    source_workflow_response: Path,
    release_workflow_response: Path,
    source_main_plan: Path,
    source_main_readback: Path,
    release_settings_authority: Path,
    source_main_runs_response: Path,
    workflow_inventory_response: Path,
    approved_commit: str,
    approved_tree: str,
    ruleset_id: int,
    actor: str,
) -> dict[str, Any]:
    _hex(approved_commit, 40, "approved commit")
    _hex(approved_tree, 40, "approved tree")
    if not actor or actor != actor.strip():
        raise SourceTagRefusedError("GitHub actor is invalid")
    if _git(repo, "rev-parse", "HEAD").decode().strip() != approved_commit:
        raise SourceTagRefusedError("checkout HEAD differs from approved commit")
    if _git(repo, "rev-parse", "HEAD^{tree}").decode().strip() != approved_tree:
        raise SourceTagRefusedError("checkout tree differs from approved tree")
    if _git(repo, "status", "--porcelain", "--untracked-files=all").strip():
        raise SourceTagRefusedError("source-tag checkout is dirty")
    production_verifier = verify_production_source(
        repo,
        manifest_path,
        release_commit=approved_commit,
        release_tree=approved_tree,
    )
    manifest, manifest_raw = validate_manifest(
        manifest_path,
        approved_commit=approved_commit,
        approved_tree=approved_tree,
    )
    source_main, _ = load_source_main_authority(
        source_main_plan,
        source_main_readback,
        release_settings_authority,
    )
    source_main_plan_value = _mapping(source_main["plan"], "source-main plan")
    source_main_readback_value = _mapping(source_main["readback"], "source-main readback")
    embedded_settings = _mapping(source_main["release_settings"], "source-main release settings")
    settings_responses = _mapping(
        embedded_settings["response_authorities"],
        "source-main release settings response authorities",
    )
    main_ruleset_live, main_ruleset_live_raw = load_canonical(
        main_ruleset_response, "live main ruleset response"
    )
    main_protection_live, main_protection_live_raw = load_canonical(
        main_branch_protection_response, "live main branch-protection response"
    )
    if (
        main_ruleset_live
        != _mapping(settings_responses["main_ruleset"], "embedded main ruleset response")["object"]
        or main_protection_live
        != _mapping(
            settings_responses["main_branch_protection"],
            "embedded main branch-protection response",
        )["object"]
    ):
        raise SourceTagRefusedError(
            "live main ruleset/branch protection changed before tag mutation"
        )
    source_main_runs, source_main_runs_raw = load_canonical(
        source_main_runs_response,
        "source-main frozen-window run recheck",
    )
    embedded_runs = _mapping(
        source_main_readback_value["post_push_runs"],
        "source-main post-push runs",
    )
    embedded_run_response = _canonical_object_authority(
        embedded_runs["response"],
        "source-main embedded post-push runs response",
    )
    if source_main_runs != embedded_run_response["object"]:
        raise SourceTagRefusedError(
            "source-main frozen post-push run window changed before tag mutation"
        )
    workflow_inventory, workflow_inventory_raw = load_canonical(
        workflow_inventory_response,
        "source-main live workflow inventory recheck",
    )
    embedded_workflow = _mapping(
        source_main_readback_value["workflow"],
        "source-main workflow readback",
    )
    embedded_inventory = _mapping(
        embedded_workflow["inventory"],
        "source-main workflow inventory",
    )
    embedded_inventory_response = _canonical_object_authority(
        embedded_inventory["response"],
        "source-main embedded workflow inventory response",
    )
    if workflow_inventory != embedded_inventory_response["object"]:
        raise SourceTagRefusedError("live workflow inventory changed before tag mutation")
    _workflow_list_projection(workflow_inventory, "live workflow inventory recheck")
    if source_main_plan_value.get("prepared") != {"commit": approved_commit, "tree": approved_tree}:
        raise SourceTagRefusedError("source-main prepared source differs from approved source")
    raw_planned_tag, planned_tag = tag_bytes(repo, approved_commit)
    s0_planned_tag = _mapping(
        source_main_plan_value.get("planned_tag"),
        "source-main planned tag",
    )
    expected_s0_tag = {
        "name": TAG,
        "ref": TAG_REF,
        "object": planned_tag["object"],
        "target_commit": approved_commit,
        "raw_sha256": sha256(raw_planned_tag),
        "raw_size": len(raw_planned_tag),
        "message": TAG_MESSAGE,
        "tagger": {
            "name": TAGGER_NAME,
            "email": TAGGER_EMAIL,
            "git_epoch": planned_tag["tagger"]["git_epoch"],
            "git_offset": planned_tag["tagger"]["git_offset"],
        },
    }
    if s0_planned_tag != expected_s0_tag:
        raise SourceTagRefusedError("source-main planned annotated tag bytes differ")
    _validate_staging_tag(
        source_main_plan_value.get("staging_tag"),
        commit=approved_commit,
    )
    source_blobs = _validate_source_blobs(source_main_plan_value["source_blobs"])
    for path, expected_blob in source_blobs.items():
        file_path = repo / path
        raw = read_regular(file_path)
        tree_line = _git(repo, "ls-tree", approved_commit, "--", path).decode("ascii").strip()
        try:
            mode, object_type, git_oid, observed_path = re.split(r"[ \t]", tree_line, maxsplit=3)
        except ValueError as exc:
            raise SourceTagRefusedError(f"source-main blob tree entry {path} differs") from exc
        if (
            mode != "100644"
            or object_type != "blob"
            or observed_path != path
            or expected_blob
            != {
                "git_oid": git_oid,
                "sha256": sha256(raw),
                "size": len(raw),
                "mode": "100644",
            }
        ):
            raise SourceTagRefusedError(f"source-main standalone blob {path} differs")
    repository, repository_raw = load_canonical(repository_response, "repository response")
    if (
        repository.get("full_name") != REPOSITORY
        or repository.get("id") != REPOSITORY_ID
        or repository.get("node_id") != REPOSITORY_NODE_ID
        or repository.get("default_branch") != "main"
        or repository.get("archived") is not False
        or repository.get("disabled") is not False
    ):
        raise SourceTagRefusedError("repository response differs from active z4jdev/z4j main")
    source_workflow = validate_source_workflow(source_workflow_response)
    release_workflow = validate_release_workflow(release_workflow_response)
    s0_workflow = _mapping(
        source_main_readback_value["workflow"],
        "source-main workflow readback",
    )
    if {key: s0_workflow["source"][key] for key in ("id", "node_id", "name", "path", "state")} != {
        key: source_workflow[key] for key in ("id", "node_id", "name", "path", "state")
    } or {
        key: s0_workflow["release"][key] for key in ("id", "node_id", "name", "path", "state")
    } != {key: release_workflow[key] for key in ("id", "node_id", "name", "path", "state")}:
        raise SourceTagRefusedError("source-main and live workflow identities differ")
    main_ref, main_ref_raw = load_canonical(main_ref_response, "main ref response")
    main_object = _mapping(main_ref.get("object"), "main ref object")
    if (
        main_ref.get("ref") != MAIN_REF
        or main_object.get("type") != "commit"
        or main_object.get("sha") != approved_commit
    ):
        raise SourceTagRefusedError("remote main differs from the approved commit")
    ruleset, ruleset_raw = load_canonical(ruleset_response, "tag ruleset response")
    conditions = _mapping(ruleset.get("conditions"), "tag ruleset conditions")
    names = _mapping(conditions.get("ref_name"), "tag ruleset ref condition")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(isinstance(item, dict) for item in rules):
        raise SourceTagRefusedError("tag ruleset rules must be objects")
    rule_types = [item.get("type") for item in rules]
    if (
        ruleset.get("id") != ruleset_id
        or ruleset.get("name") != RULESET_NAME
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("source") != REPOSITORY
        or ruleset.get("source_type") != "Repository"
        or ruleset.get("bypass_actors") != []
        or names != {"exclude": [], "include": RULESET_INCLUDE}
        or sorted(rule_types) != ["deletion", "update"]
    ):
        raise SourceTagRefusedError("tag ruleset is not the exact no-bypass immutable v* policy")
    environment, environment_raw = load_canonical(
        environment_response, "production-release environment response"
    )
    protections = environment.get("protection_rules")
    if not isinstance(protections, list):
        raise SourceTagRefusedError("production-release protection rules are missing")
    reviewer_rules = [
        item
        for item in protections
        if isinstance(item, dict) and item.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        raise SourceTagRefusedError("production-release must have one required-reviewers rule")
    reviewer_rule = reviewer_rules[0]
    reviewers = reviewer_rule.get("reviewers")
    if (
        environment.get("name") != ENVIRONMENT
        or reviewer_rule.get("prevent_self_review") is not True
        or not isinstance(reviewers, list)
        or not reviewers
    ):
        raise SourceTagRefusedError("production-release must require a distinct reviewer")
    reviewer_projection: list[dict[str, Any]] = []
    for entry in reviewers:
        item = _mapping(entry, "environment reviewer")
        reviewer = _mapping(item.get("reviewer"), "environment reviewer identity")
        kind = item.get("type")
        if kind not in {"User", "Team"}:
            raise SourceTagRefusedError("environment reviewer type differs")
        identifier = reviewer.get("login") if kind == "User" else reviewer.get("slug")
        if not isinstance(identifier, str) or not identifier:
            raise SourceTagRefusedError("environment reviewer identity is missing")
        if kind == "User" and identifier.casefold() == actor.casefold():
            raise SourceTagRefusedError("dispatch actor cannot be the configured user reviewer")
        reviewer_projection.append({"type": kind, "identifier": identifier})
    retention = validate_wheelhouse_retention(
        wheelhouse_repository_response,
        manifest=manifest,
    )
    raw_tag, tag = tag_bytes(repo, approved_commit)
    projection = _mapping(
        _mapping(manifest["source_authority"], "production source authority").get("projection"),
        "production source projection",
    )
    projection_sha = _hex(projection.get("sha256"), 64, "production source projection SHA-256")
    return {
        "format": PLAN_FORMAT,
        "result": "pass",
        "release": RELEASE,
        "repository": REPOSITORY,
        "repository_identity": REPOSITORY_IDENTITY,
        "source_workflow": source_workflow,
        "release_workflow": release_workflow,
        "source_main_authority": source_main,
        "source": {
            "commit": approved_commit,
            "tree": approved_tree,
            "production_source_freeze": _mapping(
                manifest["source_authority"], "production source authority"
            )["production_source_freeze"],
            "production_source_projection_sha256": projection_sha,
            "production_verifier": production_verifier,
        },
        "tag": {
            "name": TAG,
            "ref": TAG_REF,
            **tag,
            "raw_sha256": sha256(raw_tag),
            "raw_size": len(raw_tag),
        },
        "manifest": {
            "path": "docker/production/manifest.json",
            "sha256": sha256(manifest_raw),
            "size": len(manifest_raw),
        },
        "signature_verifier": manifest["signature_verifier"],
        "protection": {
            "ruleset": {
                "id": ruleset_id,
                "name": RULESET_NAME,
                "target": "tag",
                "enforcement": "active",
                "include": RULESET_INCLUDE,
                "exclude": [],
                "bypass_actors": [],
                "rules": ["deletion", "update"],
                "response_sha256": sha256(ruleset_raw),
                "response_size": len(ruleset_raw),
            },
            "environment": {
                "name": ENVIRONMENT,
                "prevent_self_review": True,
                "reviewers": sorted(
                    reviewer_projection, key=lambda item: (item["type"], item["identifier"])
                ),
                "response_sha256": sha256(environment_raw),
                "response_size": len(environment_raw),
            },
            "repository_response": {"sha256": sha256(repository_raw), "size": len(repository_raw)},
            "main_ref_response": {"sha256": sha256(main_ref_raw), "size": len(main_ref_raw)},
            "source_main_runs_recheck": {
                "sha256": sha256(source_main_runs_raw),
                "size": len(source_main_runs_raw),
            },
            "workflow_inventory_recheck": {
                "sha256": sha256(workflow_inventory_raw),
                "size": len(workflow_inventory_raw),
            },
            "main_ruleset_recheck": {
                "sha256": sha256(main_ruleset_live_raw),
                "size": len(main_ruleset_live_raw),
            },
            "main_branch_protection_recheck": {
                "sha256": sha256(main_protection_live_raw),
                "size": len(main_protection_live_raw),
            },
            "wheelhouse_retention": retention,
        },
    }


def validate_remote_tag(
    plan: Mapping[str, Any],
    *,
    ref_response: Path,
    tag_response: Path,
) -> None:
    ref, _ = load_canonical(ref_response, "source tag ref response")
    tag_object, _ = load_canonical(tag_response, "source tag object response")
    expected_tag = _mapping(plan["tag"], "source tag plan")
    ref_object = _mapping(ref.get("object"), "source tag ref object")
    target = _mapping(tag_object.get("object"), "annotated tag target")
    tagger = _mapping(tag_object.get("tagger"), "annotated tagger")
    if (
        ref.get("ref") != TAG_REF
        or ref_object.get("type") != "tag"
        or ref_object.get("sha") != expected_tag["object"]
        or tag_object.get("sha") != expected_tag["object"]
        or tag_object.get("tag") != TAG
        or tag_object.get("message") != TAG_MESSAGE
        or target.get("type") != "commit"
        or target.get("sha") != _mapping(plan["source"], "plan source")["commit"]
        or tagger.get("name") != TAGGER_NAME
        or tagger.get("email") != TAGGER_EMAIL
        or tagger.get("date") != _mapping(expected_tag["tagger"], "planned tagger")["date"]
    ):
        raise SourceTagRefusedError(
            "remote source tag differs from the approved annotated tag object"
        )


def build_recovery_authority(
    *,
    run_response: Path,
    jobs_response: Path,
    approvals_response: Path,
    prior_run_id: int,
    approved_commit: str,
    source_workflow_id: int,
    source_workflow_node_id: str,
) -> dict[str, Any]:
    """Authenticate the failed protected run that reached exact tag readback."""
    prior_run_id = _positive(prior_run_id, "prior source-tag run id")
    _hex(approved_commit, 40, "approved recovery commit")
    run, run_raw = load_canonical(run_response, "prior source-tag run response")
    jobs, jobs_raw = load_canonical(jobs_response, "prior source-tag jobs response")
    approvals, approvals_raw = load_canonical_value(
        approvals_response, "prior source-tag approvals response"
    )
    authority = {
        "prior_run": _source_tag_recovery_projection(
            run,
            jobs,
            approvals,
            prior_run_id=prior_run_id,
            approved_commit=approved_commit,
            source_workflow_id=source_workflow_id,
            source_workflow_node_id=source_workflow_node_id,
        )[0],
        "run_response": {
            "object": run,
            "seal": {"sha256": sha256(run_raw), "size": len(run_raw)},
        },
        "jobs_response": {
            "object": jobs,
            "seal": {"sha256": sha256(jobs_raw), "size": len(jobs_raw)},
        },
        "approvals_response": {
            "value": approvals,
            "seal": {"sha256": sha256(approvals_raw), "size": len(approvals_raw)},
        },
        "verified_job": _source_tag_recovery_projection(
            run,
            jobs,
            approvals,
            prior_run_id=prior_run_id,
            approved_commit=approved_commit,
            source_workflow_id=source_workflow_id,
            source_workflow_node_id=source_workflow_node_id,
        )[1],
        "verified_step": "Re-read exact tag after the ceremony",
        "tag_mutation": False,
    }
    validate_source_tag_recovery_authority(
        authority,
        approved_commit=approved_commit,
        source_workflow_id=source_workflow_id,
        source_workflow_node_id=source_workflow_node_id,
    )
    return authority


def _source_tag_recovery_projection(  # noqa: PLR0912, PLR0915
    run: Mapping[str, Any],
    jobs: Mapping[str, Any],
    approvals: object,
    *,
    prior_run_id: int,
    approved_commit: str,
    source_workflow_id: int,
    source_workflow_node_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_workflow_id = _positive(source_workflow_id, "source workflow id")
    if not isinstance(source_workflow_node_id, str) or not source_workflow_node_id:
        raise SourceTagRefusedError("source workflow node id differs")
    repository = _mapping(run.get("repository"), "prior run repository")
    actor = _mapping(run.get("actor"), "prior run actor")
    triggering_actor = _mapping(run.get("triggering_actor"), "prior run triggering actor")
    run_url = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{prior_run_id}"
    html_url = f"https://github.com/{REPOSITORY}/actions/runs/{prior_run_id}"
    if (
        run.get("id") != prior_run_id
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != f"{WORKFLOW_PATH}@main"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != approved_commit
        or run.get("status") != "completed"
        or run.get("conclusion") not in {"failure", "cancelled", "timed_out"}
        or run.get("url") != run_url
        or run.get("html_url") != html_url
        or repository.get("full_name") != REPOSITORY
        or repository.get("id") != REPOSITORY_ID
        or repository.get("node_id") != REPOSITORY_NODE_ID
        or run.get("workflow_id") != source_workflow_id
        or not isinstance(actor.get("login"), str)
        or not actor.get("login")
        or not isinstance(triggering_actor.get("login"), str)
        or not triggering_actor.get("login")
    ):
        raise SourceTagRefusedError("prior source-tag recovery run identity differs")
    actor_id = _positive(actor.get("id"), "prior source-tag actor id")
    actor_node_id = actor.get("node_id")
    if not isinstance(actor_node_id, str) or not actor_node_id or actor.get("type") != "User":
        raise SourceTagRefusedError("prior source-tag actor stable identity differs")
    triggering_actor_id = _positive(
        triggering_actor.get("id"),
        "prior source-tag triggering actor id",
    )
    triggering_actor_node_id = triggering_actor.get("node_id")
    if (
        not isinstance(triggering_actor_node_id, str)
        or not triggering_actor_node_id
        or triggering_actor.get("type") != "User"
    ):
        raise SourceTagRefusedError("prior source-tag triggering actor identity differs")
    prior_attempt = _positive(run.get("run_attempt"), "prior source-tag run attempt")
    entries = jobs.get("jobs")
    if (
        not isinstance(entries, list)
        or jobs.get("total_count") != len(entries)
        or len(entries) > 100
    ):
        raise SourceTagRefusedError("prior source-tag jobs response lacks jobs")
    matching = [
        item
        for item in entries
        if isinstance(item, dict)
        and item.get("run_id") == prior_run_id
        and item.get("name") == "Validate and create only immutable v1.9.0"
    ]
    if len(matching) != 1:
        raise SourceTagRefusedError("prior source-tag run lacks its exact protected job")
    job = matching[0]
    labels = job.get("labels")
    if (
        job.get("status") != "completed"
        or job.get("conclusion") not in {"failure", "cancelled", "timed_out"}
        or not isinstance(job.get("node_id"), str)
        or not job["node_id"]
        or not isinstance(job.get("runner_name"), str)
        or not job["runner_name"]
        or not isinstance(labels, list)
        or "ubuntu-24.04" not in labels
        or not all(isinstance(label, str) and label for label in labels)
    ):
        raise SourceTagRefusedError("prior source-tag protected job identity differs")
    job_id = _positive(job.get("id"), "prior source-tag job id")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise SourceTagRefusedError("prior source-tag job lacks step evidence")
    readbacks = [
        item
        for item in steps
        if isinstance(item, dict)
        and item.get("name") == "Re-read exact tag after the ceremony"
        and item.get("conclusion") == "success"
    ]
    if len(readbacks) != 1:
        raise SourceTagRefusedError("prior authorized run never completed exact tag readback")
    if not isinstance(approvals, list) or not approvals or len(approvals) > 100:
        raise SourceTagRefusedError("prior source-tag approvals response differs")
    approval_matches: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for index, item in enumerate(approvals):
        if not isinstance(item, dict) or item.get("state") != "approved":
            continue
        environments = item.get("environments")
        user = item.get("user")
        if (
            not isinstance(environments, list)
            or len(environments) != 1
            or not isinstance(environments[0], dict)
            or not isinstance(user, dict)
        ):
            continue
        environment = environments[0]
        if environment.get("name") != ENVIRONMENT:
            continue
        reviewer = _stable_user(
            {
                "login": user.get("login"),
                "id": user.get("id"),
                "node_id": user.get("node_id"),
                "type": user.get("type"),
            },
            f"prior source-tag approval reviewer {index}",
        )
        environment_projection = {
            "id": _positive(environment.get("id"), "prior source-tag approval environment id"),
            "node_id": environment.get("node_id"),
            "name": ENVIRONMENT,
        }
        if (
            not isinstance(environment_projection["node_id"], str)
            or not environment_projection["node_id"]
            or not isinstance(item.get("comment"), str)
        ):
            raise SourceTagRefusedError("prior source-tag approval environment differs")
        approval_matches.append((item, reviewer, environment_projection))
    if len(approval_matches) != 1:
        raise SourceTagRefusedError(
            "prior source-tag run lacks one exact production-release approval"
        )
    _, reviewer, environment = approval_matches[0]
    if reviewer["id"] in {actor_id, triggering_actor_id}:
        raise SourceTagRefusedError("prior source-tag approval is not independent")
    prior_run = {
        "id": prior_run_id,
        "run_attempt": prior_attempt,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "repository_node_id": REPOSITORY_NODE_ID,
        "workflow_id": source_workflow_id,
        "workflow_node_id": source_workflow_node_id,
        "workflow_path": f"{WORKFLOW_PATH}@main",
        "event_name": "workflow_dispatch",
        "ref": MAIN_REF,
        "head_sha": approved_commit,
        "status": "completed",
        "conclusion": run["conclusion"],
        "url": run_url,
        "html_url": html_url,
        "actor": {
            "login": actor["login"],
            "id": actor_id,
            "node_id": actor_node_id,
            "type": "User",
        },
        "triggering_actor": {
            "login": triggering_actor["login"],
            "id": triggering_actor_id,
            "node_id": triggering_actor_node_id,
            "type": "User",
        },
        "environment": environment,
        "approval": {"state": "approved", "reviewer": reviewer},
    }
    verified_job = {
        "id": job_id,
        "node_id": job["node_id"],
        "name": "Validate and create only immutable v1.9.0",
        "status": "completed",
        "conclusion": job["conclusion"],
        "runner_name": job["runner_name"],
        "labels": labels,
    }
    return prior_run, verified_job


def validate_source_tag_recovery_authority(
    value: object,
    *,
    approved_commit: str,
    source_workflow_id: int,
    source_workflow_node_id: str,
) -> dict[str, Any]:
    authority = _mapping(value, "source tag recovery authority")
    _exact_keys(
        authority,
        {
            "prior_run",
            "run_response",
            "jobs_response",
            "approvals_response",
            "verified_job",
            "verified_step",
            "tag_mutation",
        },
        "source tag recovery authority",
    )
    run_response = _canonical_object_authority(
        authority.get("run_response"), "prior source-tag run response"
    )
    jobs_response = _canonical_object_authority(
        authority.get("jobs_response"), "prior source-tag jobs response"
    )
    approvals_response = _canonical_value_authority(
        authority.get("approvals_response"), "prior source-tag approvals response"
    )
    projection = _source_tag_recovery_projection(
        run_response["object"],
        jobs_response["object"],
        approvals_response["value"],
        prior_run_id=_mapping(authority.get("prior_run"), "prior source-tag run")["id"],
        approved_commit=approved_commit,
        source_workflow_id=source_workflow_id,
        source_workflow_node_id=source_workflow_node_id,
    )
    if (
        authority.get("prior_run") != projection[0]
        or authority.get("verified_job") != projection[1]
        or authority.get("verified_step") != "Re-read exact tag after the ceremony"
        or authority.get("tag_mutation") is not False
    ):
        raise SourceTagRefusedError("source tag recovery authority semantics differ")
    return dict(authority)


def _response_seal(path: Path, label: str) -> dict[str, Any]:
    _, raw = load_canonical(path, label)
    return {"sha256": sha256(raw), "size": len(raw)}


def _raw_seal(path: Path) -> dict[str, Any]:
    raw = read_regular(path, limit=1024 * 1024)
    return {"sha256": sha256(raw), "size": len(raw)}


def build_receipt(
    plan: Mapping[str, Any],
    *,
    transition: str,
    run_id: int,
    run_attempt: int,
    actor: str,
    workflow_sha: str,
    ref_response: Path,
    tag_response: Path,
    recovery_authority: Mapping[str, Any] | None,
    push_response: Path | None,
) -> dict[str, Any]:
    if transition not in {CREATION_TRANSITION, RECOVERY_TRANSITION}:
        raise SourceTagRefusedError("source tag transition differs")
    if (transition == RECOVERY_TRANSITION) != (recovery_authority is not None):
        raise SourceTagRefusedError("source tag recovery transition/authority differ")
    if recovery_authority is not None:
        source = _mapping(plan["source"], "plan source")
        source_workflow = _mapping(plan["source_workflow"], "plan source workflow")
        validate_source_tag_recovery_authority(
            recovery_authority,
            approved_commit=source["commit"],
            source_workflow_id=source_workflow["id"],
            source_workflow_node_id=source_workflow["node_id"],
        )
    _hex(workflow_sha, 40, "workflow source SHA")
    if workflow_sha != _mapping(plan["source"], "plan source")["commit"]:
        raise SourceTagRefusedError("workflow source SHA differs from approved source")
    if run_id <= 0 or run_attempt <= 0 or not actor:
        raise SourceTagRefusedError("source tag workflow run identity is invalid")
    if transition == CREATION_TRANSITION:
        if push_response is None:
            raise SourceTagRefusedError("created source tag lacks current non-force push result")
        tag_operation = {
            "operation": "non-force-create",
            "remote": "origin",
            "ref": TAG_REF,
            "object": _mapping(plan["tag"], "plan tag")["object"],
            "result": "success",
            "push_response": _raw_seal(push_response),
        }
    else:
        if push_response is not None:
            raise SourceTagRefusedError("recovery must not contain or perform a tag push")
        tag_operation = {
            "operation": "no-tag-put",
            "remote": "origin",
            "ref": TAG_REF,
            "object": _mapping(plan["tag"], "plan tag")["object"],
            "result": "recovered-existing-exact",
            "push_response": None,
        }
    return {
        "format": RECEIPT_FORMAT,
        "result": "pass",
        "release": RELEASE,
        "repository": REPOSITORY,
        "repository_identity": plan["repository_identity"],
        "source_workflow": plan["source_workflow"],
        "release_workflow": plan["release_workflow"],
        "source_main_authority": plan["source_main_authority"],
        "source_tag_authority_policy": SOURCE_TAG_AUTHORITY_POLICY,
        "source": plan["source"],
        "tag": {**_mapping(plan["tag"], "plan tag"), "transition": transition},
        "tag_operation": tag_operation,
        "manifest": plan["manifest"],
        "signature_verifier": plan["signature_verifier"],
        "protection": plan["protection"],
        "readback": {
            "tag_ref_response": _response_seal(ref_response, "source tag ref response"),
            "tag_object_response": _response_seal(tag_response, "source tag object response"),
            "verified": True,
        },
        "recovery_authority": dict(recovery_authority) if recovery_authority else None,
        "ceremony": {
            "workflow_path": WORKFLOW_PATH,
            "workflow_identity": WORKFLOW_IDENTITY,
            "event_name": "workflow_dispatch",
            "ref": MAIN_REF,
            "sha": workflow_sha,
            "authority_run_id": run_id,
            "authority_run_attempt": run_attempt,
            "actor": actor,
            "environment": ENVIRONMENT,
            "dry_run": False,
        },
    }


def _seal(value: object, label: str) -> dict[str, Any]:
    result = _mapping(value, label)
    _exact_keys(result, {"sha256", "size"}, label)
    _hex(result.get("sha256"), 64, f"{label} SHA-256")
    _positive(result.get("size"), f"{label} size")
    return result


def validate_receipt(  # noqa: PLR0912, PLR0915 - exact durable receipt schema
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    _exact_keys(
        receipt,
        {
            "format",
            "result",
            "release",
            "repository",
            "repository_identity",
            "source_workflow",
            "release_workflow",
            "source_main_authority",
            "source_tag_authority_policy",
            "source",
            "tag",
            "tag_operation",
            "manifest",
            "signature_verifier",
            "protection",
            "readback",
            "recovery_authority",
            "ceremony",
        },
        "source tag receipt",
    )
    if (
        receipt.get("format") != RECEIPT_FORMAT
        or receipt.get("result") != "pass"
        or receipt.get("release") != RELEASE
        or receipt.get("repository") != REPOSITORY
        or receipt.get("source_tag_authority_policy") != SOURCE_TAG_AUTHORITY_POLICY
    ):
        raise SourceTagRefusedError("source tag receipt identity/policy differs")
    repository_identity = _mapping(
        receipt.get("repository_identity"),
        "source tag repository identity",
    )
    if repository_identity != REPOSITORY_IDENTITY:
        raise SourceTagRefusedError("source tag repository stable identity differs")
    source_workflow = _mapping(receipt.get("source_workflow"), "source workflow authority")
    _exact_keys(
        source_workflow,
        {"id", "node_id", "name", "path", "state", "html_url", "response"},
        "source workflow authority",
    )
    _positive(source_workflow.get("id"), "source workflow id")
    if (
        not isinstance(source_workflow.get("node_id"), str)
        or not source_workflow["node_id"]
        or source_workflow.get("name") != "source-tag-only"
        or source_workflow.get("path") != WORKFLOW_PATH
        or source_workflow.get("state") != "active"
        or source_workflow.get("html_url")
        != "https://github.com/z4jdev/z4j/blob/main/.github/workflows/source-tag-only.yml"
    ):
        raise SourceTagRefusedError("source workflow authority differs")
    _seal(source_workflow.get("response"), "source workflow response")
    release_workflow = _mapping(
        receipt.get("release_workflow"),
        "release workflow authority",
    )
    release_expected = {
        "id": RELEASE_WORKFLOW_ID,
        "node_id": RELEASE_WORKFLOW_NODE_ID,
        "name": RELEASE_WORKFLOW_NAME,
        "path": RELEASE_WORKFLOW_PATH,
        "state": "active",
        "html_url": RELEASE_WORKFLOW_HTML_URL,
        "created_at": RELEASE_WORKFLOW_CREATED_AT,
        "updated_at": RELEASE_WORKFLOW_UPDATED_AT,
    }
    _exact_keys(
        release_workflow,
        {*release_expected, "response"},
        "release workflow authority",
    )
    if any(release_workflow.get(key) != value for key, value in release_expected.items()):
        raise SourceTagRefusedError("release workflow authority differs")
    _seal(release_workflow.get("response"), "release workflow response")
    source = _mapping(receipt.get("source"), "source tag receipt source")
    source_main = _mapping(
        receipt.get("source_main_authority"),
        "source-main authority",
    )
    _exact_keys(
        source_main,
        {"plan", "readback", "release_settings", "seals"},
        "source-main authority",
    )
    settings = _mapping(source_main.get("release_settings"), "embedded release settings")
    validate_release_settings_authority(settings)
    plan_value = _mapping(source_main.get("plan"), "embedded source-main plan")
    readback_value = _mapping(source_main.get("readback"), "embedded source-main readback")
    if (
        plan_value.get("release_settings") != settings
        or readback_value.get("release_settings") != settings
        or plan_value.get("prepared") != {"commit": source["commit"], "tree": source["tree"]}
        or readback_value.get("prepared") != plan_value.get("prepared")
    ):
        raise SourceTagRefusedError("embedded source-main/settings authority differs")
    seals = _mapping(source_main.get("seals"), "source-main authority seals")
    _exact_keys(seals, {"plan", "readback", "release_settings"}, "source-main authority seals")
    for name, value in (
        ("plan", plan_value),
        ("readback", readback_value),
        ("release_settings", settings),
    ):
        expected_raw = canonical_line(value)
        if _seal(seals.get(name), f"source-main {name} seal") != {
            "sha256": sha256(expected_raw),
            "size": len(expected_raw),
        }:
            raise SourceTagRefusedError(f"source-main {name} embedded byte seal differs")
    with tempfile.TemporaryDirectory(prefix="z4j-embedded-source-main-") as directory:
        embedded_root = Path(directory)
        embedded_paths = {
            "plan": embedded_root / SOURCE_MAIN_PLAN_NAME,
            "readback": embedded_root / SOURCE_MAIN_READBACK_NAME,
            "release_settings": embedded_root / RELEASE_SETTINGS_NAME,
        }
        for name, value in (
            ("plan", plan_value),
            ("readback", readback_value),
            ("release_settings", settings),
        ):
            _write_exclusive(embedded_paths[name], canonical_line(value))
        reconstructed, _ = load_source_main_authority(
            embedded_paths["plan"],
            embedded_paths["readback"],
            embedded_paths["release_settings"],
        )
    if reconstructed != source_main:
        raise SourceTagRefusedError("embedded source-main authority is not exact/reconstructable")
    _exact_keys(
        source,
        {
            "commit",
            "tree",
            "production_source_freeze",
            "production_source_projection_sha256",
            "production_verifier",
        },
        "source tag receipt source",
    )
    _hex(source.get("commit"), 40, "source tag commit")
    _hex(source.get("tree"), 40, "source tag tree")
    _hex(
        source.get("production_source_projection_sha256"),
        64,
        "production source projection",
    )
    freeze = _mapping(source.get("production_source_freeze"), "production source freeze")
    _exact_keys(freeze, {"commit", "tree"}, "production source freeze")
    _hex(freeze.get("commit"), 40, "production source-freeze commit")
    _hex(freeze.get("tree"), 40, "production source-freeze tree")
    production_verifier = _mapping(
        source.get("production_verifier"),
        "production verifier authority",
    )
    _exact_keys(
        production_verifier,
        {"verifier", "manifest", "execution"},
        "production verifier authority",
    )
    if production_verifier.get("execution") != {
        "result": "pass",
        "isolated_private_blobs": True,
    }:
        raise SourceTagRefusedError("production verifier execution authority differs")
    for name, expected_path in (
        ("verifier", "docker/production/verify.py"),
        ("manifest", "docker/production/manifest.json"),
    ):
        item = _mapping(production_verifier.get(name), f"production {name} blob authority")
        _exact_keys(
            item,
            {"path", "git_oid", "sha256", "size", "mode"},
            f"production {name} blob authority",
        )
        if item.get("path") != expected_path or item.get("mode") != "100644":
            raise SourceTagRefusedError(f"production {name} Git100644 authority differs")
        _hex(item.get("git_oid"), 40, f"production {name} Git OID")
        _hex(item.get("sha256"), 64, f"production {name} SHA-256")
        _positive(item.get("size"), f"production {name} size")
    tag = _mapping(receipt.get("tag"), "source tag receipt tag")
    _exact_keys(
        tag,
        {
            "name",
            "ref",
            "tagger",
            "message",
            "object",
            "raw_sha256",
            "raw_size",
            "transition",
        },
        "source tag receipt tag",
    )
    if (
        tag.get("name") != TAG
        or tag.get("ref") != TAG_REF
        or tag.get("message") != TAG_MESSAGE
        or tag.get("transition") not in {CREATION_TRANSITION, RECOVERY_TRANSITION}
    ):
        raise SourceTagRefusedError("source tag receipt tag identity/transition differs")
    _hex(tag.get("object"), 40, "source tag object")
    _hex(tag.get("raw_sha256"), 64, "source tag raw SHA-256")
    _positive(tag.get("raw_size"), "source tag raw size")
    tagger = _mapping(tag.get("tagger"), "source tag receipt tagger")
    _exact_keys(
        tagger,
        {"name", "email", "date", "git_epoch", "git_offset"},
        "source tag receipt tagger",
    )
    if tagger.get("name") != TAGGER_NAME or tagger.get("email") != TAGGER_EMAIL:
        raise SourceTagRefusedError("source tag receipt tagger differs")
    tag_operation = _mapping(receipt.get("tag_operation"), "source tag operation")
    _exact_keys(
        tag_operation,
        {"operation", "remote", "ref", "object", "result", "push_response"},
        "source tag operation",
    )
    if (
        tag_operation.get("remote") != "origin"
        or tag_operation.get("ref") != TAG_REF
        or tag_operation.get("object") != tag.get("object")
    ):
        raise SourceTagRefusedError("source tag operation target differs")
    if tag.get("transition") == CREATION_TRANSITION:
        if (
            tag_operation.get("operation") != "non-force-create"
            or tag_operation.get("result") != "success"
        ):
            raise SourceTagRefusedError("source tag creation operation differs")
        _seal(tag_operation.get("push_response"), "source tag push response")
    elif (
        tag_operation.get("operation") != "no-tag-put"
        or tag_operation.get("result") != "recovered-existing-exact"
        or tag_operation.get("push_response") is not None
    ):
        raise SourceTagRefusedError("source tag recovery operation differs")
    manifest = _mapping(receipt.get("manifest"), "source tag receipt manifest")
    _exact_keys(manifest, {"path", "sha256", "size"}, "source tag receipt manifest")
    if manifest.get("path") != "docker/production/manifest.json":
        raise SourceTagRefusedError("source tag receipt production manifest path differs")
    _seal({"sha256": manifest.get("sha256"), "size": manifest.get("size")}, "manifest")
    _validate_signature_verifier(receipt.get("signature_verifier"))
    protection = _mapping(receipt.get("protection"), "source tag receipt protection")
    _exact_keys(
        protection,
        {
            "ruleset",
            "environment",
            "repository_response",
            "main_ref_response",
            "source_main_runs_recheck",
            "workflow_inventory_recheck",
            "main_ruleset_recheck",
            "main_branch_protection_recheck",
            "wheelhouse_retention",
        },
        "source tag receipt protection",
    )
    _seal(protection.get("repository_response"), "repository response")
    _seal(protection.get("main_ref_response"), "main ref response")
    _seal(protection.get("source_main_runs_recheck"), "source-main run recheck")
    _seal(protection.get("workflow_inventory_recheck"), "workflow inventory recheck")
    _seal(protection.get("main_ruleset_recheck"), "main ruleset recheck")
    _seal(
        protection.get("main_branch_protection_recheck"),
        "main branch-protection recheck",
    )
    retention = _mapping(
        protection.get("wheelhouse_retention"),
        "source tag wheelhouse retention",
    )
    _exact_keys(
        retention,
        {
            "provider",
            "api",
            "repository",
            "reference",
            "target_tag",
            "subject",
            "immutable_tags_settings",
            "required_behavior",
            "response",
        },
        "source tag wheelhouse retention",
    )
    if (
        retention.get("provider") != "docker-hub"
        or retention.get("repository") != "docker.io/z4jdev/z4j-production-wheelhouse"
        or retention.get("required_behavior") != "matched-tag-cannot-be-overwritten-or-deleted"
        or retention.get("immutable_tags_settings")
        != {"enabled": True, "rules": IMMUTABLE_RETENTION_RULES}
    ):
        raise SourceTagRefusedError("source tag wheelhouse retention policy differs")
    _seal(retention.get("response"), "wheelhouse repository response")
    readback = _mapping(receipt.get("readback"), "source tag receipt readback")
    _exact_keys(
        readback,
        {"tag_ref_response", "tag_object_response", "verified"},
        "source tag receipt readback",
    )
    _seal(readback.get("tag_ref_response"), "tag ref response")
    _seal(readback.get("tag_object_response"), "tag object response")
    if readback.get("verified") is not True:
        raise SourceTagRefusedError("source tag receipt readback did not pass")
    recovery = receipt.get("recovery_authority")
    if tag["transition"] == RECOVERY_TRANSITION:
        validate_source_tag_recovery_authority(
            recovery,
            approved_commit=source["commit"],
            source_workflow_id=source_workflow["id"],
            source_workflow_node_id=source_workflow["node_id"],
        )
    elif recovery is not None:
        raise SourceTagRefusedError("created source tag receipt contains recovery authority")
    ceremony = _mapping(receipt.get("ceremony"), "source tag receipt ceremony")
    _exact_keys(
        ceremony,
        {
            "workflow_path",
            "workflow_identity",
            "event_name",
            "ref",
            "sha",
            "authority_run_id",
            "authority_run_attempt",
            "actor",
            "environment",
            "dry_run",
        },
        "source tag receipt ceremony",
    )
    if (
        ceremony.get("workflow_path") != WORKFLOW_PATH
        or ceremony.get("workflow_identity") != WORKFLOW_IDENTITY
        or ceremony.get("event_name") != "workflow_dispatch"
        or ceremony.get("ref") != MAIN_REF
        or ceremony.get("sha") != source["commit"]
        or ceremony.get("environment") != ENVIRONMENT
        or ceremony.get("dry_run") is not False
        or not isinstance(ceremony.get("actor"), str)
        or not ceremony["actor"]
    ):
        raise SourceTagRefusedError("source tag receipt workflow identity differs")
    _positive(ceremony.get("authority_run_id"), "source tag authority run id")
    _positive(ceremony.get("authority_run_attempt"), "source tag authority run attempt")
    return dict(receipt)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceTagRefusedError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SourceTagRefusedError(f"JSON contains refused non-finite value {value}")


def _base64_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SourceTagRefusedError(f"{label} must be nonempty base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SourceTagRefusedError(f"{label} must be exact base64") from exc
    if not raw or base64.b64encode(raw).decode("ascii") != value:
        raise SourceTagRefusedError(f"{label} must be canonical nonempty base64")
    return raw


def _reject_non_integer_numbers(value: object, label: str) -> None:
    if isinstance(value, float):
        raise SourceTagRefusedError(f"{label} contains a refused non-integer number")
    if isinstance(value, dict):
        for child in value.values():
            _reject_non_integer_numbers(child, label)
    elif isinstance(value, list):
        for child in value:
            _reject_non_integer_numbers(child, label)


def validate_bundle_bytes(
    bundle_raw: bytes,
    *,
    receipt_raw: bytes,
    require_canonical: bool = True,
) -> dict[str, Any]:
    try:
        bundle = _mapping(
            json.loads(
                bundle_raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            ),
            "source tag Sigstore bundle",
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError("source tag Sigstore bundle is not JSON") from exc
    _reject_non_integer_numbers(bundle, "source tag Sigstore bundle")
    if require_canonical and canonical_line(bundle) != bundle_raw:
        raise SourceTagRefusedError(
            "source tag Sigstore bundle is not canonical sorted compact ASCII newline JSON"
        )
    _exact_keys(
        bundle,
        {"mediaType", "verificationMaterial", "messageSignature"},
        "source tag Sigstore bundle",
    )
    if bundle.get("mediaType") != BUNDLE_MEDIA_TYPE:
        raise SourceTagRefusedError("source tag Sigstore bundle is not exact v0.3")
    material = _mapping(bundle.get("verificationMaterial"), "bundle verification material")
    if (
        "certificate" not in material
        or "publicKey" in material
        or set(material) - {"certificate", "tlogEntries", "timestampVerificationData"}
    ):
        raise SourceTagRefusedError("source tag bundle must use certificate verification material")
    certificate = _mapping(material.get("certificate"), "bundle certificate")
    _exact_keys(certificate, {"rawBytes"}, "bundle certificate")
    _base64_bytes(certificate.get("rawBytes"), "bundle certificate rawBytes")
    entries = material.get("tlogEntries")
    if (
        not isinstance(entries, list)
        or not entries
        or not all(isinstance(item, dict) and item for item in entries)
    ):
        raise SourceTagRefusedError("source tag bundle lacks transparency-log entries")
    message = _mapping(bundle.get("messageSignature"), "bundle message signature")
    _exact_keys(message, {"messageDigest", "signature"}, "bundle message signature")
    message_digest = _mapping(message.get("messageDigest"), "bundle message digest")
    _exact_keys(message_digest, {"algorithm", "digest"}, "bundle message digest")
    if message_digest.get("algorithm") != "SHA2_256":
        raise SourceTagRefusedError("source tag bundle digest algorithm differs")
    if (
        _base64_bytes(message_digest.get("digest"), "bundle message digest")
        != hashlib.sha256(receipt_raw).digest()
    ):
        raise SourceTagRefusedError("source tag bundle message digest differs from literal receipt")
    _base64_bytes(message.get("signature"), "bundle message signature")
    return bundle


def _der_tlv(raw: bytes, offset: int, label: str) -> tuple[int, bytes, int]:
    if offset < 0 or offset >= len(raw):
        raise SourceTagRefusedError(f"{label} DER is truncated")
    tag = raw[offset]
    if tag & 0x1F == 0x1F:
        raise SourceTagRefusedError(f"{label} DER uses a refused high-tag form")
    offset += 1
    if offset >= len(raw):
        raise SourceTagRefusedError(f"{label} DER length is truncated")
    first = raw[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        octets = first & 0x7F
        if octets == 0 or octets > 4 or offset + octets > len(raw):
            raise SourceTagRefusedError(f"{label} DER length is invalid")
        encoded = raw[offset : offset + octets]
        if encoded[0] == 0:
            raise SourceTagRefusedError(f"{label} DER length is not minimal")
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            raise SourceTagRefusedError(f"{label} DER long length is not minimal")
        offset += octets
    end = offset + length
    if end > len(raw):
        raise SourceTagRefusedError(f"{label} DER value is truncated")
    return tag, raw[offset:end], end


def _der_oid(raw: bytes, label: str) -> str:
    if not raw:
        raise SourceTagRefusedError(f"{label} OID is empty")
    first = raw[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    in_arc = False
    for byte in raw[1:]:
        if not in_arc and byte == 0x80:
            raise SourceTagRefusedError(f"{label} OID arc is not minimal")
        in_arc = True
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            in_arc = False
    if in_arc:
        raise SourceTagRefusedError(f"{label} OID arc is truncated")
    return ".".join(str(arc) for arc in arcs)


def _fulcio_extensions(  # noqa: PLR0912, PLR0915 - strict DER profile parser
    certificate_raw: bytes,
) -> dict[str, str]:
    tag, certificate, end = _der_tlv(certificate_raw, 0, "Fulcio certificate")
    if tag != 0x30 or end != len(certificate_raw):
        raise SourceTagRefusedError("Fulcio certificate outer DER differs")
    tag, tbs, _ = _der_tlv(certificate, 0, "Fulcio TBSCertificate")
    if tag != 0x30:
        raise SourceTagRefusedError("Fulcio TBSCertificate is not a sequence")
    extensions_raw: bytes | None = None
    offset = 0
    while offset < len(tbs):
        child_tag, child, next_offset = _der_tlv(tbs, offset, "Fulcio TBSCertificate field")
        if child_tag == 0xA3:
            if extensions_raw is not None:
                raise SourceTagRefusedError("Fulcio certificate duplicates extensions")
            extensions_raw = child
        offset = next_offset
    if extensions_raw is None:
        raise SourceTagRefusedError("Fulcio certificate extensions are absent")
    tag, extensions, end = _der_tlv(extensions_raw, 0, "Fulcio extensions")
    if tag != 0x30 or end != len(extensions_raw):
        raise SourceTagRefusedError("Fulcio extensions DER differs")
    result: dict[str, str] = {}
    offset = 0
    while offset < len(extensions):
        tag, extension, next_offset = _der_tlv(extensions, offset, "Fulcio extension")
        if tag != 0x30:
            raise SourceTagRefusedError("Fulcio extension is not a sequence")
        item_offset = 0
        oid_tag, oid_raw, item_offset = _der_tlv(extension, item_offset, "Fulcio extension OID")
        if oid_tag != 0x06:
            raise SourceTagRefusedError("Fulcio extension OID tag differs")
        oid = _der_oid(oid_raw, "Fulcio extension")
        value_tag, value_raw, item_offset = _der_tlv(
            extension, item_offset, "Fulcio extension value"
        )
        critical = False
        if value_tag == 0x01:
            if value_raw not in {b"\x00", b"\xff"}:
                raise SourceTagRefusedError("Fulcio extension critical flag differs")
            critical = True
            value_tag, value_raw, item_offset = _der_tlv(
                extension, item_offset, "Fulcio extension value"
            )
        if value_tag != 0x04 or item_offset != len(extension):
            raise SourceTagRefusedError("Fulcio extension OCTET STRING differs")
        if oid.startswith(FULCIO_OID_ROOT + "."):
            if oid in result:
                raise SourceTagRefusedError(f"Fulcio certificate duplicates {oid}")
            if critical:
                raise SourceTagRefusedError(f"Fulcio certificate binding {oid} must be noncritical")
            try:
                suffix = int(oid.removeprefix(FULCIO_OID_ROOT + "."))
            except ValueError as exc:
                raise SourceTagRefusedError("Fulcio extension suffix differs") from exc
            if 1 <= suffix <= 6:
                encoded = value_raw
            elif 8 <= suffix <= 24:
                string_tag, encoded, string_end = _der_tlv(
                    value_raw, 0, f"Fulcio extension {oid} UTF8String"
                )
                if string_tag != 0x0C or string_end != len(value_raw):
                    raise SourceTagRefusedError(f"Fulcio extension {oid} framing differs")
            else:
                raise SourceTagRefusedError(
                    f"Fulcio certificate has unknown authority binding {oid}"
                )
            try:
                result[oid] = encoded.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SourceTagRefusedError(f"Fulcio extension {oid} is not UTF-8") from exc
        offset = next_offset
    return result


def _verify_fulcio_certificate_bindings(
    bundle: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, str]:
    material = _mapping(bundle.get("verificationMaterial"), "bundle verification material")
    certificate = _mapping(material.get("certificate"), "bundle certificate")
    certificate_raw = _base64_bytes(certificate.get("rawBytes"), "bundle certificate rawBytes")
    ceremony = _mapping(receipt.get("ceremony"), "source tag ceremony")
    source = _mapping(receipt.get("source"), "source tag source")
    commit = _hex(source.get("commit"), 40, "source tag commit")
    run_id = _positive(ceremony.get("authority_run_id"), "source tag authority run id")
    run_attempt = _positive(
        ceremony.get("authority_run_attempt"), "source tag authority run attempt"
    )
    expected = {
        f"{FULCIO_OID_ROOT}.1": OIDC_ISSUER,
        f"{FULCIO_OID_ROOT}.2": "workflow_dispatch",
        f"{FULCIO_OID_ROOT}.3": commit,
        f"{FULCIO_OID_ROOT}.4": "source-tag-only",
        f"{FULCIO_OID_ROOT}.5": REPOSITORY,
        f"{FULCIO_OID_ROOT}.6": MAIN_REF,
        f"{FULCIO_OID_ROOT}.8": OIDC_ISSUER,
        f"{FULCIO_OID_ROOT}.9": WORKFLOW_IDENTITY,
        f"{FULCIO_OID_ROOT}.10": commit,
        f"{FULCIO_OID_ROOT}.11": "github-hosted",
        f"{FULCIO_OID_ROOT}.12": f"https://github.com/{REPOSITORY}",
        f"{FULCIO_OID_ROOT}.13": commit,
        f"{FULCIO_OID_ROOT}.14": MAIN_REF,
        f"{FULCIO_OID_ROOT}.15": str(REPOSITORY_ID),
        f"{FULCIO_OID_ROOT}.16": "https://github.com/z4jdev",
        f"{FULCIO_OID_ROOT}.17": str(REPOSITORY_IDENTITY["owner"]["id"]),
        f"{FULCIO_OID_ROOT}.18": WORKFLOW_IDENTITY,
        f"{FULCIO_OID_ROOT}.19": commit,
        f"{FULCIO_OID_ROOT}.20": "workflow_dispatch",
        f"{FULCIO_OID_ROOT}.21": (
            f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}"
        ),
        f"{FULCIO_OID_ROOT}.22": "public",
        f"{FULCIO_OID_ROOT}.23": ENVIRONMENT,
        f"{FULCIO_OID_ROOT}.24": f"repo:{REPOSITORY}:environment:{ENVIRONMENT}",
    }
    observed = _fulcio_extensions(certificate_raw)
    if set(observed) != set(expected):
        raise SourceTagRefusedError("Fulcio certificate authority binding set differs")
    for oid, value in expected.items():
        if observed.get(oid) != value:
            raise SourceTagRefusedError(f"Fulcio certificate binding {oid} differs")
    return {oid: observed[oid] for oid in sorted(expected)}


def _bundle_bytes(path: Path, *, receipt_raw: bytes) -> bytes:
    bundle_raw = read_regular(path)
    validate_bundle_bytes(bundle_raw, receipt_raw=receipt_raw)
    return bundle_raw


def canonicalize_bundle(
    input_path: Path,
    receipt_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Normalize a literal Cosign v0.3 carrier, then revalidate the frozen profile."""
    receipt, receipt_raw = load_canonical(receipt_path, "source tag receipt")
    validate_receipt(receipt)
    emitted_raw = read_regular(input_path)
    bundle = validate_bundle_bytes(
        emitted_raw,
        receipt_raw=receipt_raw,
        require_canonical=False,
    )
    canonical_raw = canonical_line(bundle)
    canonical_bundle = validate_bundle_bytes(canonical_raw, receipt_raw=receipt_raw)
    _verify_fulcio_certificate_bindings(canonical_bundle, receipt)
    _write_exclusive(output_path, canonical_raw)
    return {
        "format": "z4j-source-tag-bundle-canonicalization-v1",
        "result": "pass",
        "emitted": {"sha256": sha256(emitted_raw), "size": len(emitted_raw)},
        "canonical": {"sha256": sha256(canonical_raw), "size": len(canonical_raw)},
        "verification": {"result": "pass"},
    }


def build_evidence_index(
    receipt_raw: bytes,
    bundle_raw: bytes,
    *,
    subject: Mapping[str, Any],
) -> bytes:
    receipt = _mapping(json.loads(receipt_raw), "source tag receipt")
    validate_receipt(receipt)
    validate_bundle_bytes(bundle_raw, receipt_raw=receipt_raw)
    _exact_keys(subject, {"mediaType", "digest", "size"}, "source evidence subject")
    if subject.get("mediaType") != OCI_INDEX:
        raise SourceTagRefusedError("source evidence subject is not an OCI image index")
    _digest(subject.get("digest"), "source evidence subject digest")
    _size(subject.get("size"), "source evidence subject size", maximum=1024 * 1024)
    value = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": AUTHORITY_ARTIFACT_TYPE,
        "config": EMPTY_CONFIG_DESCRIPTOR,
        "layers": [
            descriptor(receipt_raw, RECEIPT_MEDIA_TYPE, title=RECEIPT_NAME),
            descriptor(bundle_raw, BUNDLE_MEDIA_TYPE, title=BUNDLE_NAME),
        ],
        "subject": dict(subject),
    }
    return canonical_oci(value)


def _evidence_index_structure(
    raw: bytes,
    *,
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    if raw.endswith(b"\n") or raw.startswith(b"\xef\xbb\xbf"):
        raise SourceTagRefusedError("source tag evidence index framing differs")
    try:
        value = _mapping(json.loads(raw), "source tag evidence index")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError("source tag evidence index is not JSON") from exc
    if canonical_oci(value) != raw:
        raise SourceTagRefusedError("source tag evidence index is not canonical OCI JSON")
    if any(key in {"artifact_digest", "index_digest"} for key in _walk_keys(value)):
        raise SourceTagRefusedError("source tag evidence index contains a self-reference")
    _exact_keys(
        value,
        {"schemaVersion", "mediaType", "artifactType", "config", "layers", "subject"},
        "source tag evidence index",
    )
    if (
        value.get("schemaVersion") != 2
        or value.get("mediaType") != OCI_MANIFEST
        or value.get("artifactType") != AUTHORITY_ARTIFACT_TYPE
        or value.get("config") != EMPTY_CONFIG_DESCRIPTOR
        or value.get("subject") != dict(subject)
    ):
        raise SourceTagRefusedError("source tag evidence index identity/config/subject differs")
    layers = value.get("layers")
    if not isinstance(layers, list) or len(layers) != 2:
        raise SourceTagRefusedError("source tag evidence index layer inventory differs")
    for item, media_type, title in zip(
        layers,
        (RECEIPT_MEDIA_TYPE, BUNDLE_MEDIA_TYPE),
        (RECEIPT_NAME, BUNDLE_NAME),
        strict=True,
    ):
        layer = _mapping(item, f"source tag evidence layer {title}")
        _exact_keys(
            layer,
            {"mediaType", "digest", "size", "annotations"},
            f"source tag evidence layer {title}",
        )
        if layer.get("mediaType") != media_type or layer.get("annotations") != {
            "org.opencontainers.image.title": title
        }:
            raise SourceTagRefusedError(f"source tag evidence layer {title} policy differs")
        _digest(layer.get("digest"), f"source tag evidence layer {title} digest")
        _size(layer.get("size"), f"source tag evidence layer {title} size")
    return value


def validate_evidence_index(
    raw: bytes,
    *,
    receipt_raw: bytes,
    bundle_raw: bytes,
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    value = _evidence_index_structure(raw, subject=subject)
    expected = build_evidence_index(receipt_raw, bundle_raw, subject=subject)
    if raw != expected:
        raise SourceTagRefusedError("source tag evidence index descriptors or subject differ")
    return value


def _walk_keys(value: object) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(key)
            keys.extend(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(_walk_keys(child))
    return keys


def verify_authority(  # noqa: PLR0912, PLR0915 - complete three-file verification
    root: Path,
    *,
    repo: Path,
    manifest_path: Path,
    cosign_path: Path,
    version_path: Path,
    require_local_tag: bool = True,
) -> dict[str, Any]:
    _require_git_runtime_authority()
    names = {item.name for item in root.iterdir()}
    if names != PORTABLE_NAMES or any(item.is_symlink() for item in root.iterdir()):
        raise SourceTagRefusedError("source tag authority must contain exactly three regular files")
    receipt, receipt_raw = load_canonical(root / RECEIPT_NAME, "source tag receipt")
    validate_receipt(receipt)
    source = _mapping(receipt.get("source"), "source tag receipt source")
    commit = _hex(source.get("commit"), 40, "source tag commit")
    tree = _hex(source.get("tree"), 40, "source tag tree")
    production_verifier = verify_production_source(
        repo,
        manifest_path,
        release_commit=commit,
        release_tree=tree,
    )
    if source.get("production_verifier") != production_verifier:
        raise SourceTagRefusedError("production verifier/manifest authority differs from receipt")
    manifest, manifest_raw = validate_manifest(
        manifest_path, approved_commit=commit, approved_tree=tree
    )
    if receipt.get("manifest") != {
        "path": "docker/production/manifest.json",
        "sha256": sha256(manifest_raw),
        "size": len(manifest_raw),
    }:
        raise SourceTagRefusedError("source tag receipt manifest seal differs")
    if receipt.get("signature_verifier") != manifest["signature_verifier"]:
        raise SourceTagRefusedError("source tag receipt Cosign authority differs")
    if receipt.get("source_tag_authority_policy") != SOURCE_TAG_AUTHORITY_POLICY:
        raise SourceTagRefusedError("source tag receipt stable policy differs")
    verify_cosign(cosign_path, version_path, manifest["signature_verifier"])
    retained = wheelhouse_authority(manifest)
    tag = _mapping(receipt.get("tag"), "source tag receipt tag")
    if tag.get("transition") not in {CREATION_TRANSITION, RECOVERY_TRANSITION}:
        raise SourceTagRefusedError("source tag receipt transition differs")
    raw_tag, expected_tag = tag_bytes(repo, commit)
    for key, value in {
        "name": TAG,
        "ref": TAG_REF,
        "object": expected_tag["object"],
        "raw_sha256": sha256(raw_tag),
        "raw_size": len(raw_tag),
        "message": TAG_MESSAGE,
    }.items():
        if tag.get(key) != value:
            raise SourceTagRefusedError(f"source tag receipt {key} differs")
    if require_local_tag:
        if _git(repo, "cat-file", "tag", TAG_REF) != raw_tag:
            raise SourceTagRefusedError("local annotated source tag payload bytes differ")
        if _git(repo, "rev-parse", TAG_REF).decode().strip() != expected_tag["object"]:
            raise SourceTagRefusedError(
                "local source tag object differs from authenticated receipt"
            )
        if _git(repo, "rev-parse", f"{TAG_REF}^{{commit}}").decode().strip() != commit:
            raise SourceTagRefusedError(
                "local source tag commit differs from authenticated receipt"
            )
        if _git(repo, "rev-parse", f"{TAG_REF}^{{tree}}").decode().strip() != tree:
            raise SourceTagRefusedError("local source tag tree differs from authenticated receipt")
    bundle_raw = _bundle_bytes(root / BUNDLE_NAME, receipt_raw=receipt_raw)
    bundle = validate_bundle_bytes(bundle_raw, receipt_raw=receipt_raw)
    _verify_fulcio_certificate_bindings(bundle, receipt)
    index_raw = read_regular(root / EVIDENCE_INDEX_NAME)
    validate_evidence_index(
        index_raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject=retained["subject"],
    )
    with tempfile.TemporaryDirectory(prefix="z4j-source-tag-authority-") as directory:
        private = Path(directory)
        private_receipt = private / "receipt.json"
        private_bundle = private / "bundle.json"
        private_receipt.write_bytes(receipt_raw)
        private_bundle.write_bytes(bundle_raw)
        private_receipt.chmod(0o600)
        private_bundle.chmod(0o600)
        completed = subprocess.run(  # noqa: S603 - sealed absolute executable
            (
                str(cosign_path),
                "verify-blob",
                "--bundle",
                str(private_bundle),
                "--certificate-identity",
                WORKFLOW_IDENTITY,
                "--certificate-oidc-issuer",
                OIDC_ISSUER,
                "--certificate-github-workflow-name",
                "source-tag-only",
                "--certificate-github-workflow-repository",
                REPOSITORY,
                "--certificate-github-workflow-ref",
                MAIN_REF,
                "--certificate-github-workflow-sha",
                commit,
                "--certificate-github-workflow-trigger",
                "workflow_dispatch",
                str(private_receipt),
            ),
            env=_sealed_subprocess_environment(private),
            check=False,
            capture_output=True,
            text=True,
        )
    if completed.returncode != 0:
        raise SourceTagRefusedError("source tag receipt Sigstore authentication failed")
    artifact_digest = digest(index_raw)
    if artifact_digest != digest(
        build_evidence_index(receipt_raw, bundle_raw, subject=retained["subject"])
    ):
        raise SourceTagRefusedError("source tag evidence artifact digest differs")
    ceremony = _mapping(receipt["ceremony"], "source tag ceremony")
    return {
        "repository": REPOSITORY,
        "tag": TAG,
        "commit": commit,
        "tree": tree,
        "receipt": {"sha256": sha256(receipt_raw), "size": len(receipt_raw)},
        "bundle": {"sha256": sha256(bundle_raw), "size": len(bundle_raw)},
        "evidence_index": {
            "sha256": sha256(index_raw),
            "size": len(index_raw),
            "artifact_digest": artifact_digest,
            "index_digest": retained["subject"]["digest"],
        },
        "workflow": {
            "run_id": ceremony["authority_run_id"],
            "run_attempt": ceremony["authority_run_attempt"],
        },
        "verification": {"result": "pass"},
    }


class _NoRegistryRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


def _source_registry_opener() -> urllib.request.OpenerDirector:
    _require_git_runtime_authority()
    try:
        metadata = SYSTEM_CA_BUNDLE.stat(follow_symlinks=False)
    except OSError as exc:
        raise SourceTagRefusedError("fixed system CA bundle is absent or unsafe") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SourceTagRefusedError("fixed system CA bundle is not root-owned and non-writable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(SYSTEM_CA_BUNDLE))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRegistryRedirectHandler(),
    )


def _registry_header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name, [])
    else:
        values = [
            value
            for key, value in headers.items()
            if isinstance(key, str) and key.lower() == name.lower()
        ]
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise SourceTagRefusedError(f"registry response {name} headers are invalid")
    for value in values:
        if "\r" in value or "\n" in value or value != value.strip():
            raise SourceTagRefusedError(
                f"registry response {name} header has folding or whitespace"
            )
    return values


def _registry_single_header(headers: Any, name: str) -> str:
    values = _registry_header_values(headers, name)
    if len(values) != 1:
        raise SourceTagRefusedError(f"registry response must contain exactly one {name} header")
    return values[0]


def _registry_optional_header(headers: Any, name: str) -> str | None:
    values = _registry_header_values(headers, name)
    if len(values) > 1:
        raise SourceTagRefusedError(f"registry response contains duplicate {name} headers")
    return values[0] if values else None


def _registry_content_type(headers: Any, expected: set[str]) -> str:
    observed = _registry_single_header(headers, "Content-Type").split(";", 1)[0].lower()
    if observed not in expected:
        raise SourceTagRefusedError("registry response content type differs")
    return observed


def _source_referrer_next_url(
    headers: Any,
    *,
    current_url: str,
    repository: str,
    subject_digest: str,
    artifact_type: str,
) -> str | None:
    link = _registry_optional_header(headers, "Link")
    if link is None:
        return None
    match = re.fullmatch(r'<([^<>]+)>; rel="next"', link)
    if match is None:
        raise SourceTagRefusedError("registry referrers Link header differs")
    value = urllib.parse.urljoin(current_url, match.group(1))
    parsed = urllib.parse.urlsplit(value)
    origin = urllib.parse.urlsplit(REGISTRY_ORIGIN)
    if (
        parsed.scheme != "https"
        or (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
        or parsed.path != f"/v2/{repository}/referrers/{subject_digest}"
        or parsed.fragment
    ):
        raise SourceTagRefusedError("registry referrers pagination URL differs or crosses origin")
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if len(pairs) != len({key for key, _value in pairs}):
        raise SourceTagRefusedError("registry referrers pagination query contains duplicate keys")
    query = dict(pairs)
    if (
        set(query) - {"artifactType", "last", "n"}
        or query.get("artifactType") != artifact_type
        or not query.get("last")
        or query.get("n") != "100"
    ):
        raise SourceTagRefusedError("registry referrers pagination query differs")
    return value


def _strict_registry_json(raw: bytes, label: str) -> object:
    def reject_float(value: str) -> None:
        raise SourceTagRefusedError(f"{label} contains a floating JSON number: {value}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError(f"{label} is not JSON") from exc


def _source_referrer_page(raw: bytes) -> list[dict[str, Any]]:
    value = _mapping(
        _strict_registry_json(raw, "registry referrers response"), "registry referrers response"
    )
    _exact_keys(value, {"schemaVersion", "mediaType", "manifests"}, "referrers response")
    if value.get("schemaVersion") != 2 or value.get("mediaType") != OCI_INDEX:
        raise SourceTagRefusedError("registry referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list) or any(not isinstance(item, dict) for item in manifests):
        raise SourceTagRefusedError("registry referrers response lacks descriptor objects")
    return manifests


class Registry:
    """Minimal Docker Distribution 1.1 client; mutable referrer tags are forbidden."""

    def __init__(self, *, repository: str, push: bool) -> None:
        _require_git_runtime_authority()
        if repository != "z4jdev/z4j-production-wheelhouse":
            raise SourceTagRefusedError("source evidence registry repository differs")
        if any(os.environ.get(name) for name in ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN")):
            raise SourceTagRefusedError("generic Docker Hub credential aliases are forbidden")
        del push
        raise SourceTagRefusedError(
            "common E0 registry settings authority/HMAC validator unavailable"
        )

    def _url(self, suffix: str) -> str:
        return f"{REGISTRY_ORIGIN}/v2/{self.repository}/{suffix}"

    def request(
        self,
        method: str,
        suffix_or_url: str,
        *,
        data: bytes | None = None,
        content_type: str | None = None,
        accept: str | None = None,
        expected: tuple[int, ...] = (200,),
        maximum: int = MAX_JSON_BYTES,
    ) -> tuple[bytes, Any, int]:
        _require_git_runtime_authority()
        url = suffix_or_url if suffix_or_url.startswith("https://") else self._url(suffix_or_url)
        parsed = urllib.parse.urlsplit(url)
        origin = urllib.parse.urlsplit(REGISTRY_ORIGIN)
        if (
            (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
            or not parsed.path.startswith(f"/v2/{self.repository}/")
            or parsed.fragment
        ):
            raise SourceTagRefusedError("refusing cross-origin authenticated registry request")
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(url, method=method, data=data, headers=headers)  # noqa: S310
        try:
            with self.opener.open(request, timeout=60) as response:
                raw = response.read(maximum + 1)
                code = response.status
                response_headers = response.headers
                final_url = response.geturl()
        except urllib.error.HTTPError as exc:
            with exc:
                raw = exc.read(maximum + 1)
                code = exc.code
                response_headers = exc.headers
                final_url = exc.geturl()
        if len(raw) > maximum:
            raise SourceTagRefusedError("Docker registry response exceeds evidence limit")
        if final_url != url:
            raise SourceTagRefusedError("Docker registry response URL differs or redirected")
        if code not in expected:
            raise SourceTagRefusedError(f"Docker registry {method} returned HTTP {code}")
        return raw, response_headers, code

    def get_manifest(self, reference: str, *, media_type: str) -> tuple[bytes, dict[str, str]]:
        raw, headers, _ = self.request(
            "GET",
            f"manifests/{reference}",
            accept=media_type,
        )
        content_type = _registry_content_type(headers, {media_type})
        observed = _registry_single_header(headers, "Docker-Content-Digest")
        if digest(raw) != observed or (DIGEST.fullmatch(reference) and observed != reference):
            raise SourceTagRefusedError("registry manifest digest header/raw bytes differ")
        return raw, {
            "content-type": content_type,
            "docker-content-digest": observed,
        }

    def get_optional_manifest(
        self,
        reference: str,
        *,
        media_type: str,
    ) -> tuple[bytes, dict[str, str]] | None:
        raw, headers, code = self.request(
            "GET",
            f"manifests/{reference}",
            accept=media_type,
            expected=(200, 404),
        )
        if code == 404:
            return None
        content_type = _registry_content_type(headers, {media_type})
        observed = _registry_single_header(headers, "Docker-Content-Digest")
        if digest(raw) != observed or (DIGEST.fullmatch(reference) and observed != reference):
            raise SourceTagRefusedError("registry manifest digest header/raw bytes differ")
        return raw, {
            "content-type": content_type,
            "docker-content-digest": observed,
        }

    def get_blob(self, value: str) -> bytes:
        raw, headers, _ = self.request("GET", f"blobs/{value}", maximum=MAX_REGISTRY_BYTES)
        _registry_content_type(headers, {"application/octet-stream"})
        if _registry_single_header(headers, "Docker-Content-Digest") != value:
            raise SourceTagRefusedError("registry blob response digest differs")
        if digest(raw) != value:
            raise SourceTagRefusedError("registry blob digest differs")
        return raw

    def _referrer_snapshot(
        self, subject_digest: str, artifact_type: str
    ) -> tuple[bytes, tuple[tuple[str, bytes, str, str, str | None], ...]]:
        query = urllib.parse.urlencode({"artifactType": artifact_type, "n": "100"})
        current = self._url(f"referrers/{subject_digest}?{query}")
        manifests: list[dict[str, Any]] = []
        transcript: list[tuple[str, bytes, str, str, str | None]] = []
        total = 0
        seen_urls: set[str] = set()
        seen_descriptors: set[bytes] = set()
        for _page in range(MAX_REFERRER_PAGES):
            if current in seen_urls:
                raise SourceTagRefusedError("registry referrers pagination loop detected")
            seen_urls.add(current)
            raw, headers, _ = self.request("GET", current, accept=OCI_INDEX, expected=(200,))
            total += len(raw)
            if total > MAX_REFERRER_BYTES:
                raise SourceTagRefusedError("registry referrers aggregate response is too large")
            content_type = _registry_content_type(headers, {OCI_INDEX})
            filters = _registry_single_header(headers, "OCI-Filters-Applied")
            if filters != "artifactType":
                raise SourceTagRefusedError("registry did not apply native artifactType filtering")
            response_digest = _registry_optional_header(headers, "Docker-Content-Digest")
            if response_digest is not None and response_digest != digest(raw):
                raise SourceTagRefusedError("registry referrers response digest differs")
            link = _registry_optional_header(headers, "Link")
            transcript.append((current, raw, content_type, filters, link))
            for descriptor_value in _source_referrer_page(raw):
                encoded = canonical_oci(descriptor_value)
                if encoded in seen_descriptors:
                    raise SourceTagRefusedError(
                        "registry referrers pages contain a duplicate descriptor"
                    )
                seen_descriptors.add(encoded)
                manifests.append(descriptor_value)
                if len(manifests) > MAX_REFERRER_DESCRIPTORS:
                    raise SourceTagRefusedError("registry referrers descriptor count exceeds limit")
            following = _source_referrer_next_url(
                headers,
                current_url=current,
                repository=self.repository,
                subject_digest=subject_digest,
                artifact_type=artifact_type,
            )
            if following is None:
                merged = canonical_oci(
                    {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
                )
                return merged, tuple(transcript)
            current = following
        raise SourceTagRefusedError("registry referrers pagination exceeds page limit")

    def referrers(self, subject_digest: str, artifact_type: str) -> tuple[bytes, dict[str, str]]:
        first, first_transcript = self._referrer_snapshot(subject_digest, artifact_type)
        second, second_transcript = self._referrer_snapshot(subject_digest, artifact_type)
        if first != second or first_transcript != second_transcript:
            raise SourceTagRefusedError(
                "registry referrers changed during complete paginated reread"
            )
        return first, {
            "content-type": OCI_INDEX,
            "oci-filters-applied": "artifactType",
        }

    def put_blob(self, raw: bytes) -> None:
        _, headers, _ = self.request("POST", "blobs/uploads/", expected=(202,))
        location = _registry_single_header(headers, "Location")
        absolute = urllib.parse.urljoin(REGISTRY_ORIGIN, location)
        separator = "&" if "?" in absolute else "?"
        _, completed_headers, _ = self.request(
            "PUT",
            absolute + separator + urllib.parse.urlencode({"digest": digest(raw)}),
            data=raw,
            content_type="application/octet-stream",
            expected=(201,),
        )
        if _registry_single_header(completed_headers, "Docker-Content-Digest") != digest(raw):
            raise SourceTagRefusedError("registry blob upload response digest differs")

    def put_referrer(self, raw: bytes, *, subject_digest: str) -> None:
        expected_digest = digest(raw)
        _, headers, _ = self.request(
            "PUT",
            f"manifests/{expected_digest}",
            data=raw,
            content_type=OCI_MANIFEST,
            expected=(201,),
        )
        if _registry_single_header(headers, "Docker-Content-Digest") != expected_digest:
            raise SourceTagRefusedError("registry evidence manifest response digest differs")
        if _registry_single_header(headers, "OCI-Subject") != subject_digest:
            raise SourceTagRefusedError(
                "registry lacks native OCI subject/referrers support; mutable fallback forbidden"
            )

    def put_retention_tag(self, raw: bytes, *, tag: str, subject_digest: str) -> None:
        if re.fullmatch(AUTHORITY_RETENTION_RULE, tag) is None:
            raise SourceTagRefusedError("refusing non-derived source authority retention tag")
        expected_digest = digest(raw)
        _, headers, _ = self.request(
            "PUT",
            f"manifests/{tag}",
            data=raw,
            content_type=OCI_MANIFEST,
            expected=(201,),
        )
        if _registry_single_header(headers, "Docker-Content-Digest") != expected_digest:
            raise SourceTagRefusedError("registry authority retention response digest differs")
        if _registry_single_header(headers, "OCI-Subject") != subject_digest:
            raise SourceTagRefusedError("registry authority retention subject differs")


def _referrer_descriptors(raw: bytes, artifact_type: str) -> list[dict[str, Any]]:
    value = _mapping(
        _strict_registry_json(raw, "registry referrers response"),
        "registry referrers response",
    )
    _exact_keys(value, {"schemaVersion", "mediaType", "manifests"}, "referrers response")
    if value.get("schemaVersion") != 2 or value.get("mediaType") != OCI_INDEX:
        raise SourceTagRefusedError("registry referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list):
        raise SourceTagRefusedError("registry referrers response lacks manifests")
    matches: list[dict[str, Any]] = []
    for item in manifests:
        descriptor_value = _mapping(item, "registry referrer descriptor")
        if descriptor_value.get("artifactType") != artifact_type:
            raise SourceTagRefusedError("filtered registry referrers response contains wrong type")
        if set(descriptor_value) not in (
            {"mediaType", "digest", "size", "artifactType"},
            {"mediaType", "digest", "size", "artifactType", "annotations"},
        ):
            raise SourceTagRefusedError("registry referrer descriptor keys differ")
        if descriptor_value.get("mediaType") != OCI_MANIFEST:
            raise SourceTagRefusedError("registry referrer descriptor media type differs")
        _digest(descriptor_value.get("digest"), "registry referrer digest")
        _size(descriptor_value.get("size"), "registry referrer size")
        matches.append(descriptor_value)
    return matches


def _verify_subject(registry: Registry, retained: Mapping[str, Any]) -> bytes:
    subject = _mapping(retained["subject"], "retained wheelhouse subject")
    tag_raw, tag_headers = registry.get_manifest(
        retained["retention_tag"],
        media_type=OCI_INDEX,
    )
    digest_raw, digest_headers = registry.get_manifest(
        subject["digest"],
        media_type=OCI_INDEX,
    )
    if (
        tag_headers.get("docker-content-digest") != subject["digest"]
        or digest_headers.get("docker-content-digest") != subject["digest"]
        or tag_raw != digest_raw
        or digest(tag_raw) != subject["digest"]
        or len(tag_raw) != subject["size"]
    ):
        raise SourceTagRefusedError("retained wheelhouse tag/index raw readback differs")
    value = _mapping(
        _strict_registry_json(tag_raw, "retained wheelhouse index"),
        "retained wheelhouse index",
    )
    if value.get("schemaVersion") != 2 or value.get("mediaType") != OCI_INDEX:
        raise SourceTagRefusedError("retained wheelhouse subject is not an OCI index")
    return tag_raw


def _write_readback(root: Path, name: str, raw: bytes) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_exclusive(root / name, raw)


def _artifact_descriptor(index_raw: bytes) -> dict[str, Any]:
    return {
        "mediaType": OCI_MANIFEST,
        "digest": digest(index_raw),
        "size": len(index_raw),
        "artifactType": AUTHORITY_ARTIFACT_TYPE,
    }


def _verify_artifact_readback(
    registry: Registry,
    *,
    index_raw: bytes,
    receipt_raw: bytes,
    bundle_raw: bytes,
    subject: Mapping[str, Any],
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    expected = _artifact_descriptor(index_raw)
    referrers_raw, _ = registry.referrers(subject["digest"], AUTHORITY_ARTIFACT_TYPE)
    descriptors = _referrer_descriptors(referrers_raw, AUTHORITY_ARTIFACT_TYPE)
    if [item for item in descriptors if item == expected] != [expected]:
        raise SourceTagRefusedError("registry referrers omit or duplicate exact source authority")
    manifest_raw, headers = registry.get_manifest(expected["digest"], media_type=OCI_MANIFEST)
    if (
        headers.get("docker-content-digest") != expected["digest"]
        or manifest_raw != index_raw
        or len(manifest_raw) != expected["size"]
    ):
        raise SourceTagRefusedError("registry source authority manifest raw bytes differ")
    value = validate_evidence_index(
        manifest_raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject=subject,
    )
    config_raw = registry.get_blob(value["config"]["digest"])
    remote_receipt = registry.get_blob(value["layers"][0]["digest"])
    remote_bundle = registry.get_blob(value["layers"][1]["digest"])
    if config_raw != EMPTY_CONFIG or remote_receipt != receipt_raw or remote_bundle != bundle_raw:
        raise SourceTagRefusedError("registry source authority config/layer substitution detected")
    return referrers_raw, manifest_raw, config_raw, remote_receipt, remote_bundle


def _verify_authority_retention(
    registry: Registry,
    *,
    index_raw: bytes,
    subject: Mapping[str, Any],
) -> tuple[str, bytes]:
    expected_digest = digest(index_raw)
    tag = authority_retention_tag(expected_digest)
    tag_raw, tag_headers = registry.get_manifest(tag, media_type=OCI_MANIFEST)
    digest_raw, digest_headers = registry.get_manifest(
        expected_digest,
        media_type=OCI_MANIFEST,
    )
    if (
        tag_headers.get("docker-content-digest") != expected_digest
        or digest_headers.get("docker-content-digest") != expected_digest
        or tag_raw != index_raw
        or digest_raw != index_raw
        or tag_raw != digest_raw
        or len(tag_raw) != len(index_raw)
    ):
        raise SourceTagRefusedError("source authority immutable tag/raw readback differs")
    _evidence_index_structure(tag_raw, subject=subject)
    return tag, tag_raw


def materialize_retained_authority(
    *,
    manifest_path: Path,
    approved_commit: str,
    approved_tree: str,
    artifact_digest: str,
    authority_run_id: int,
    authority_run_attempt: int,
    output_root: Path,
) -> dict[str, Any]:
    """Recover the three portable bytes from an already retained exact A."""
    _require_git_runtime_authority()
    artifact_digest = _digest(artifact_digest, "retained source authority digest")
    authority_run_id = _positive(authority_run_id, "authority run id")
    authority_run_attempt = _positive(authority_run_attempt, "authority run attempt")
    manifest, manifest_raw = validate_manifest(
        manifest_path,
        approved_commit=approved_commit,
        approved_tree=approved_tree,
    )
    retained = wheelhouse_authority(manifest)
    registry = Registry(repository=retained["repository"], push=False)
    before_subject = _verify_subject(registry, retained)
    referrers_raw, _ = registry.referrers(
        retained["subject"]["digest"],
        AUTHORITY_ARTIFACT_TYPE,
    )
    descriptors = _referrer_descriptors(referrers_raw, AUTHORITY_ARTIFACT_TYPE)
    matching = [item for item in descriptors if item.get("digest") == artifact_digest]
    if len(matching) != 1:
        raise SourceTagRefusedError("retained source authority referrer is missing or duplicated")
    tag = authority_retention_tag(artifact_digest)
    tag_raw, tag_headers = registry.get_manifest(tag, media_type=OCI_MANIFEST)
    digest_raw, digest_headers = registry.get_manifest(
        artifact_digest,
        media_type=OCI_MANIFEST,
    )
    if (
        tag_headers.get("docker-content-digest") != artifact_digest
        or digest_headers.get("docker-content-digest") != artifact_digest
        or tag_raw != digest_raw
        or digest(tag_raw) != artifact_digest
        or len(tag_raw) != matching[0]["size"]
    ):
        raise SourceTagRefusedError("retained source authority tag/digest raw bytes differ")
    value = _evidence_index_structure(tag_raw, subject=retained["subject"])
    config_raw = registry.get_blob(value["config"]["digest"])
    receipt_raw = registry.get_blob(value["layers"][0]["digest"])
    bundle_raw = registry.get_blob(value["layers"][1]["digest"])
    if (
        config_raw != EMPTY_CONFIG
        or len(receipt_raw) != value["layers"][0]["size"]
        or len(bundle_raw) != value["layers"][1]["size"]
    ):
        raise SourceTagRefusedError("retained source authority layer bytes differ")
    receipt = _mapping(
        _strict_registry_json(receipt_raw, "retained source tag receipt"),
        "retained source tag receipt",
    )
    if canonical_line(receipt) != receipt_raw:
        raise SourceTagRefusedError("retained source tag receipt framing differs")
    validate_receipt(receipt)
    source = _mapping(receipt["source"], "retained source tag source")
    ceremony = _mapping(receipt["ceremony"], "retained source tag ceremony")
    if (
        source.get("commit") != approved_commit
        or source.get("tree") != approved_tree
        or ceremony.get("authority_run_id") != authority_run_id
        or ceremony.get("authority_run_attempt") != authority_run_attempt
        or receipt.get("manifest")
        != {
            "path": "docker/production/manifest.json",
            "sha256": sha256(manifest_raw),
            "size": len(manifest_raw),
        }
    ):
        raise SourceTagRefusedError("retained source authority run/source/manifest differs")
    validate_bundle_bytes(bundle_raw, receipt_raw=receipt_raw)
    validate_evidence_index(
        tag_raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject=retained["subject"],
    )
    _verify_authority_retention(
        registry,
        index_raw=tag_raw,
        subject=retained["subject"],
    )
    final_referrers, _ = registry.referrers(
        retained["subject"]["digest"],
        AUTHORITY_ARTIFACT_TYPE,
    )
    if final_referrers != referrers_raw or _verify_subject(registry, retained) != before_subject:
        raise SourceTagRefusedError("retained source authority graph moved during recovery")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output_root.iterdir()):
        raise SourceTagRefusedError("source authority recovery output must be empty")
    for name, raw in (
        (RECEIPT_NAME, receipt_raw),
        (BUNDLE_NAME, bundle_raw),
        (EVIDENCE_INDEX_NAME, tag_raw),
    ):
        _write_exclusive(output_root / name, raw)
    return {
        "format": "z4j-source-tag-authority-materialization-v1",
        "result": "pass",
        "repository": retained["repository"],
        "subject_digest": retained["subject"]["digest"],
        "artifact_digest": artifact_digest,
        "authority_retention_tag": tag,
        "authority_run_id": authority_run_id,
        "authority_run_attempt": authority_run_attempt,
        "exact_raw_readback": True,
    }


def _production_authority_members(  # noqa: PLR0912 - strict fd-bound capture
    root: Path,
) -> dict[str, bytes]:
    root_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    member_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        root_descriptor = os.open(root, root_flags)
    except OSError as exc:
        raise SourceTagRefusedError(
            "production finalization authority root is absent or unsafe"
        ) from exc
    result: dict[str, bytes] = {}
    try:
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise SourceTagRefusedError(
                "production finalization authority root must be a real directory"
            )
        try:
            names = os.listdir(root_descriptor)  # noqa: PTH208 - preserve directory-fd binding
        except OSError as exc:
            raise SourceTagRefusedError(
                "production finalization authority root is unreadable"
            ) from exc
        if (
            len(names) != len(PRODUCTION_AUTHORITY_NAMES)
            or set(names) != PRODUCTION_AUTHORITY_NAMES
        ):
            raise SourceTagRefusedError(
                "production finalization authority must contain exactly four files"
            )
        for name in sorted(names):
            try:
                descriptor_value = os.open(
                    name,
                    member_flags,
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise SourceTagRefusedError(
                    f"production authority member {name!r} is absent or unsafe"
                ) from exc
            try:
                opening = os.fstat(descriptor_value)
                if (
                    not stat.S_ISREG(opening.st_mode)
                    or opening.st_nlink != 1
                    or opening.st_size <= 0
                    or opening.st_size > MAX_REGISTRY_BYTES
                ):
                    raise SourceTagRefusedError(
                        f"production authority member {name!r} is not an exact regular file"
                    )
                chunks: list[bytes] = []
                remaining = opening.st_size
                while remaining:
                    chunk = os.read(descriptor_value, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise SourceTagRefusedError(
                            f"production authority member {name!r} changed while read"
                        )
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor_value, 1):
                    raise SourceTagRefusedError(
                        f"production authority member {name!r} grew while read"
                    )
                closing = os.fstat(descriptor_value)
                if (
                    closing.st_dev,
                    closing.st_ino,
                    closing.st_size,
                    closing.st_mtime_ns,
                ) != (
                    opening.st_dev,
                    opening.st_ino,
                    opening.st_size,
                    opening.st_mtime_ns,
                ):
                    raise SourceTagRefusedError(
                        f"production authority member {name!r} changed while read"
                    )
                result[name] = b"".join(chunks)
            finally:
                os.close(descriptor_value)
    finally:
        os.close(root_descriptor)
    return result


def _load_finalized_production_projection(  # noqa: PLR0915 - exact private trust boundary
    *,
    repo: Path,
    production_root: Path,
    cosign_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the exact candidate-HEAD production consumer against private carrier bytes."""
    _require_git_runtime_authority()
    commit = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    _hex(commit, 40, "release consumer HEAD commit")
    _hex(tree, 40, "release consumer HEAD tree")
    helper_path = repo / PRODUCTION_AUTHORITY_HELPER_PATH
    helper_raw, helper_authority = _tracked_head_blob(
        repo,
        helper_path,
        commit=commit,
        label="production authority consumer",
    )
    members = _production_authority_members(production_root)
    cosign_raw = read_regular(cosign_path, limit=256 * 1024 * 1024)

    def cosign_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if not command or command[0] != "/usr/local/bin/cosign":
            raise SourceTagRefusedError("production consumer requested a non-sealed Cosign path")
        return subprocess.run(  # noqa: S603 - exact sealed executable and reviewed argv
            (str(cosign_path), *command[1:]),
            env=_sealed_subprocess_environment(cosign_path.parent),
            check=False,
            capture_output=True,
            text=True,
        )

    def binary_reader(path: Path) -> bytes:
        if path != Path("/usr/local/bin/cosign"):
            raise SourceTagRefusedError("production consumer read a non-sealed Cosign path")
        return cosign_raw

    module_name = f"_z4j_production_authority_{helper_authority['git_oid']}"
    with tempfile.TemporaryDirectory(prefix="z4j-production-authority-consumer-") as directory:
        private = Path(directory)
        private_helper = private / "production_container_authority.py"
        private_root = private / "authority"
        private_root.mkdir(mode=0o700)
        _write_exclusive(private_helper, helper_raw)
        private_helper.chmod(0o400)
        for name, raw in members.items():
            target = private_root / name
            _write_exclusive(target, raw)
            target.chmod(0o400)
        spec = importlib.util.spec_from_file_location(module_name, private_helper)
        if spec is None or spec.loader is None:
            raise SourceTagRefusedError("production authority consumer cannot be imported")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
            loader = getattr(module, "load_finalized_production_authority", None)
            if not callable(loader):
                raise SourceTagRefusedError("production authority consumer entry point is absent")
            try:
                projection = loader(
                    private_root,
                    cosign_runner=cosign_runner,
                    binary_reader=binary_reader,
                )
            except Exception as exc:
                raise SourceTagRefusedError(
                    f"production finalization authority refused: {exc}"
                ) from exc
        finally:
            sys.modules.pop(module_name, None)
    result = _mapping(projection, "authenticated production authority projection")
    projection_keys = {
        "format",
        "release",
        "source_revision",
        "source_tree",
        "source_image",
        "manifest_sha256",
        "production_source_projection_sha256",
        "source_tag_authority",
        "qualification_ceremony",
        "signature_verifier",
        "candidate_index",
        "dashboard_sbom",
        "platforms",
        "members",
        "sigstore",
        "authority_sha256",
    }
    _exact_keys(result, projection_keys, "authenticated production authority projection")
    member_seals = {
        name: {"sha256": sha256(raw), "size": len(raw)} for name, raw in sorted(members.items())
    }
    unhashed_projection = dict(result)
    observed_authority_hash = unhashed_projection.pop("authority_sha256", None)
    if (
        result.get("format") != PRODUCTION_AUTHORITY_PROJECTION_FORMAT
        or result.get("release") != RELEASE
        or result.get("source_revision") != commit
        or result.get("source_tree") != tree
        or result.get("members") != member_seals
        or observed_authority_hash != sha256(canonical_line(unhashed_projection))
    ):
        raise SourceTagRefusedError("authenticated production authority source/format differs")
    closing_helper, closing_authority = _tracked_head_blob(
        repo,
        helper_path,
        commit=commit,
        label="production authority consumer final readback",
    )
    closing_members = _production_authority_members(production_root)
    if (
        closing_helper != helper_raw
        or closing_authority != helper_authority
        or closing_members != members
    ):
        raise SourceTagRefusedError("production authority consumer/carrier changed during use")
    return dict(result), {
        "helper": helper_authority,
        "members": member_seals,
    }


def _github_api_get_value(url: str) -> tuple[object, bytes]:
    _require_git_runtime_authority()
    expected_prefix = f"https://api.github.com/repos/{REPOSITORY}/"
    if not url.startswith(expected_prefix):
        raise SourceTagRefusedError("qualification live-readback URL differs")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SourceTagRefusedError("GITHUB_TOKEN is absent for qualification live readback")
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS API prefix checked above
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    try:
        with _proxyless_urlopen(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                raise SourceTagRefusedError("qualification live readback status/URL differs")
            raw = response.read(MAX_JSON_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SourceTagRefusedError(
            f"qualification live readback returned HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise SourceTagRefusedError("qualification live readback transport failed") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise SourceTagRefusedError("qualification live readback exceeds size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError("qualification live readback is not JSON") from exc
    return value, raw


def _github_api_get(url: str) -> tuple[dict[str, Any], bytes]:
    value, raw = _github_api_get_value(url)
    return _mapping(value, "qualification live run response"), raw


def _signed_api_carrier(value: object, label: str) -> tuple[str, object]:
    carrier = _mapping(value, label)
    _exact_keys(
        carrier,
        {"url", "status", "body_base64", "sha256", "size"},
        label,
    )
    url = carrier.get("url")
    if (
        not isinstance(url, str)
        or not url.startswith(f"https://api.github.com/repos/{REPOSITORY}/")
        or carrier.get("status") != 200
    ):
        raise SourceTagRefusedError(f"{label} URL/status differs")
    raw = _base64_bytes(carrier.get("body_base64"), f"{label} body")
    if carrier.get("sha256") != sha256(raw) or carrier.get("size") != len(raw):
        raise SourceTagRefusedError(f"{label} body seal differs")
    try:
        body = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError(f"{label} body is not JSON") from exc
    _reject_non_integer_numbers(body, f"{label} body")
    if canonical_line(body) != raw:
        raise SourceTagRefusedError(f"{label} body framing differs")
    return url, body


def _approved_live_reviewer(
    value: object,
    *,
    environment: str,
) -> dict[str, Any]:
    if not isinstance(value, list):
        raise SourceTagRefusedError("live qualification approval response is not a list")
    matches: list[dict[str, Any]] = []
    for item in value:
        review = _mapping(item, "live qualification approval")
        environments = review.get("environments")
        if not isinstance(environments, list):
            continue
        names = [
            _mapping(candidate, "live qualification approval environment").get("name")
            for candidate in environments
        ]
        if review.get("state") == "approved" and environment in names:
            matches.append(_live_actor(review.get("user"), "live qualification reviewer"))
    if len(matches) != 1:
        raise SourceTagRefusedError(
            "live qualification approvals lack one unique protected-environment review"
        )
    return matches[0]


def _live_actor(value: object, label: str) -> dict[str, Any]:
    actor = _mapping(value, label)
    return _mapping(
        _stable_automation_principal(
            {
                "login": actor.get("login"),
                "id": actor.get("id"),
                "node_id": actor.get("node_id"),
                "type": actor.get("type"),
            },
            label,
        ),
        label,
    )


def _verify_completed_qualification_run(
    ceremony: Mapping[str, Any],
) -> dict[str, Any]:
    qualification = _mapping(ceremony.get("qualification"), "qualification ceremony run")
    signed_run = _mapping(qualification.get("run"), "signed qualification run")
    url = signed_run.get("api_url")
    if not isinstance(url, str):
        raise SourceTagRefusedError("signed qualification run URL differs")
    live, raw = _github_api_get(url)
    projection = {
        "id": live.get("id"),
        "run_attempt": live.get("run_attempt"),
        "workflow_id": live.get("workflow_id"),
        "url": live.get("url"),
        "html_url": live.get("html_url"),
        "event": live.get("event"),
        "head_branch": live.get("head_branch"),
        "head_sha": live.get("head_sha"),
        "display_title": live.get("display_title"),
        "status": live.get("status"),
        "conclusion": live.get("conclusion"),
        "actor": _live_actor(live.get("actor"), "live qualification actor"),
        "triggering_actor": _live_actor(
            live.get("triggering_actor"),
            "live qualification triggering actor",
        ),
    }
    expected = {
        "id": signed_run.get("id"),
        "run_attempt": signed_run.get("run_attempt"),
        "workflow_id": signed_run.get("workflow_id"),
        "url": signed_run.get("api_url"),
        "html_url": signed_run.get("html_url"),
        "event": signed_run.get("event"),
        "head_branch": signed_run.get("head_branch"),
        "head_sha": signed_run.get("head_sha"),
        "display_title": signed_run.get("display_title"),
        "status": "completed",
        "conclusion": "success",
        "actor": signed_run.get("actor"),
        "triggering_actor": signed_run.get("triggering_actor"),
    }
    if projection != expected:
        raise SourceTagRefusedError(
            "qualification run is not the exact authenticated completed/success attempt"
        )
    readback = _mapping(ceremony.get("readback"), "qualification ceremony readback")
    qualification_readback = _mapping(
        readback.get("qualification"),
        "qualification run readback group",
    )
    jobs_url, signed_jobs = _signed_api_carrier(
        qualification_readback.get("jobs"),
        "signed qualification jobs readback",
    )
    jobs_value, jobs_raw = _github_api_get_value(jobs_url)
    jobs_body = _mapping(jobs_value, "live qualification jobs response")
    jobs = jobs_body.get("jobs")
    if (
        not isinstance(jobs, list)
        or not jobs
        or len(jobs) > 100
        or jobs_body.get("total_count") != len(jobs)
    ):
        raise SourceTagRefusedError("live qualification job inventory is incomplete or paginated")
    deployment = _mapping(
        qualification.get("deployment"),
        "signed qualification deployment",
    )
    matches = [
        _mapping(job, "live qualification job")
        for job in jobs
        if isinstance(job, dict) and job.get("id") == deployment.get("job_id")
    ]
    if len(matches) != 1:
        raise SourceTagRefusedError("live qualification protected job is missing or duplicated")
    job = matches[0]
    job_projection = {
        "id": job.get("id"),
        "run_id": job.get("run_id"),
        "head_sha": job.get("head_sha"),
        "name": job.get("name"),
        "status": job.get("status"),
        "conclusion": job.get("conclusion"),
    }
    job_expected = {
        "id": deployment.get("job_id"),
        "run_id": signed_run.get("id"),
        "head_sha": signed_run.get("head_sha"),
        "name": deployment.get("job_name"),
        "status": "completed",
        "conclusion": "success",
    }
    if job_projection != job_expected:
        raise SourceTagRefusedError(
            "qualification protected job is not the exact completed/success job"
        )
    signed_jobs_body = _mapping(signed_jobs, "signed qualification jobs body")
    if signed_jobs_body.get("total_count") != len(signed_jobs_body.get("jobs", [])):
        raise SourceTagRefusedError("signed qualification jobs inventory differs")

    approvals_url, _ = _signed_api_carrier(
        qualification_readback.get("approvals"),
        "signed qualification approvals readback",
    )
    approvals, approvals_raw = _github_api_get_value(approvals_url)
    deployment_environment = _mapping(
        deployment.get("environment"),
        "signed qualification deployment environment",
    )
    reviewer = _approved_live_reviewer(
        approvals,
        environment=str(deployment_environment.get("name")),
    )
    if reviewer != deployment.get("reviewer"):
        raise SourceTagRefusedError("live qualification reviewer differs from signed deployment")

    settings = _mapping(readback.get("settings"), "signed qualification settings readback")
    settings_seals: dict[str, dict[str, Any]] = {}
    for name, carrier in sorted(settings.items()):
        settings_url, signed_body = _signed_api_carrier(
            carrier,
            f"signed qualification setting {name}",
        )
        live_body, settings_raw = _github_api_get_value(settings_url)
        if live_body != signed_body:
            raise SourceTagRefusedError(
                f"live qualification setting {name} changed after finalization"
            )
        settings_seals[name] = {
            "url": settings_url,
            "sha256": sha256(settings_raw),
            "size": len(settings_raw),
        }
    return {
        "url": url,
        "response": {"sha256": sha256(raw), "size": len(raw)},
        "run": projection,
        "protected_job": {
            **job_projection,
            "response": {"sha256": sha256(jobs_raw), "size": len(jobs_raw)},
        },
        "approval": {
            "environment": deployment_environment,
            "reviewer": reviewer,
            "response": {"sha256": sha256(approvals_raw), "size": len(approvals_raw)},
        },
        "settings": settings_seals,
        "verification": {"result": "pass"},
    }


def _external_git(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
) -> bytes:
    _require_git_runtime_authority()
    command = (
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "http.followRedirects=false",
        "-c",
        "http.sslVerify=true",
        *arguments,
    )
    completed = subprocess.run(  # noqa: S603 - fixed Git executable and reviewed arguments
        command,
        cwd=cwd,
        env=_git_environment(),
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise SourceTagRefusedError(
            "remote source Git verification failed: "
            + completed.stderr.decode("utf-8", "replace").strip()
        )
    return completed.stdout


def _remote_tag_snapshot() -> dict[str, str]:
    raw = _external_git(
        (
            "ls-remote",
            "--tags",
            SOURCE_REMOTE_URL,
            TAG_REF,
            f"{TAG_REF}^{{}}",
        )
    )
    lines = raw.decode("ascii").splitlines()
    refs: dict[str, str] = {}
    for line in lines:
        pieces = line.split("\t")
        if len(pieces) != 2 or pieces[1] in refs:
            raise SourceTagRefusedError("remote source tag ls-remote response differs")
        refs[pieces[1]] = _hex(pieces[0], 40, "remote source tag object")
    expected_keys = {TAG_REF, f"{TAG_REF}^{{}}"}
    if set(refs) != expected_keys:
        raise SourceTagRefusedError("remote annotated source tag direct/peeled refs differ")
    return {
        "tag_object": refs[TAG_REF],
        "commit": refs[f"{TAG_REF}^{{}}"],
    }


def _verify_remote_source_tag(
    *,
    repo: Path,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    source = _mapping(receipt.get("source"), "source tag receipt source")
    tag = _mapping(receipt.get("tag"), "source tag receipt tag")
    commit = _hex(source.get("commit"), 40, "source tag remote commit")
    tree = _hex(source.get("tree"), 40, "source tag remote tree")
    raw_tag, expected = tag_bytes(repo, commit)
    if (
        tag.get("object") != expected["object"]
        or tag.get("raw_sha256") != sha256(raw_tag)
        or tag.get("raw_size") != len(raw_tag)
    ):
        raise SourceTagRefusedError("receipt tag bytes/object differ before remote verification")
    before = _remote_tag_snapshot()
    if before != {"tag_object": expected["object"], "commit": commit}:
        raise SourceTagRefusedError("remote source tag differs from signed receipt")
    with tempfile.TemporaryDirectory(prefix="z4j-remote-source-tag-") as directory:
        bare = Path(directory) / "repository.git"
        _external_git(("init", "--bare", str(bare)))
        _external_git(
            (
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                SOURCE_REMOTE_URL,
                f"{TAG_REF}:refs/z4j-source-authority/tag",
            ),
            cwd=bare,
        )
        if _git(bare, "cat-file", "tag", "refs/z4j-source-authority/tag") != raw_tag:
            raise SourceTagRefusedError("remote annotated tag literal payload differs")
        observed = {
            "tag_object": _git(bare, "rev-parse", "refs/z4j-source-authority/tag")
            .decode("ascii")
            .strip(),
            "commit": _git(bare, "rev-parse", "refs/z4j-source-authority/tag^{commit}")
            .decode("ascii")
            .strip(),
            "tree": _git(bare, "rev-parse", "refs/z4j-source-authority/tag^{tree}")
            .decode("ascii")
            .strip(),
        }
    after = _remote_tag_snapshot()
    if before != after or observed != {
        "tag_object": expected["object"],
        "commit": commit,
        "tree": tree,
    }:
        raise SourceTagRefusedError("remote source tag moved or peeled source differs")
    snapshot_raw = canonical_line({"before": before, "after": after})
    return {
        **observed,
        "raw_sha256": sha256(raw_tag),
        "raw_size": len(raw_tag),
        "snapshots": {"sha256": sha256(snapshot_raw), "size": len(snapshot_raw)},
        "verification": {"result": "pass"},
    }


def _local_tag_value(repo: Path) -> str | None:
    symbolic = _git_result(
        repo,
        "symbolic-ref",
        "--quiet",
        "--no-recurse",
        TAG_REF,
    )
    if symbolic.returncode == 0:
        raise SourceTagRefusedError("local source tag is a symbolic ref")
    if symbolic.returncode != 1:
        raise SourceTagRefusedError("local source tag symbolic-ref readback failed")
    raw = _git(
        repo,
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(symref)",
        TAG_REF,
    )
    if not raw:
        return None
    lines = raw.rstrip(b"\n").split(b"\n")
    if len(lines) != 1:
        raise SourceTagRefusedError("local source tag raw ref inventory differs")
    fields = lines[0].split(b"\x00")
    if (
        len(fields) != 4
        or fields[0] != TAG_REF.encode("ascii")
        or fields[2] not in {b"blob", b"commit", b"tag", b"tree"}
        or fields[3] != b""
    ):
        raise SourceTagRefusedError("local source tag is not one direct annotated tag ref")
    return _hex(fields[1].decode("ascii"), 40, "local source tag object")


def _materialize_local_tag(
    *,
    repo: Path,
    receipt: Mapping[str, Any],
    install: bool,
) -> dict[str, Any]:
    source = _mapping(receipt.get("source"), "source tag receipt source")
    tag = _mapping(receipt.get("tag"), "source tag receipt tag")
    raw_tag, expected = tag_bytes(repo, source["commit"])
    object_id = expected["object"]
    current = _local_tag_value(repo)
    if current is not None and current != object_id:
        raise SourceTagRefusedError("local source tag exists with a different object")
    operation = "already-exact" if current == object_id else "absent"
    if current is None and install:
        written = (
            _git(
                repo,
                "hash-object",
                "-t",
                "tag",
                "-w",
                "--stdin",
                input_bytes=raw_tag,
            )
            .decode("ascii")
            .strip()
        )
        if written != object_id:
            raise SourceTagRefusedError("local source tag object materialization differs")
        _git(repo, "update-ref", "--no-deref", TAG_REF, object_id, "0" * 40)
        operation = "created-exact"
    closing = _local_tag_value(repo)
    if (install or current is not None) and (
        closing != object_id
        or _git(repo, "cat-file", "tag", TAG_REF) != raw_tag
        or _git(repo, "rev-parse", f"{TAG_REF}^{{commit}}").decode("ascii").strip()
        != source["commit"]
        or _git(repo, "rev-parse", f"{TAG_REF}^{{tree}}").decode("ascii").strip() != source["tree"]
    ):
        raise SourceTagRefusedError("local source tag final readback differs")
    if tag.get("object") != object_id:
        raise SourceTagRefusedError("local tag object differs from signed receipt")
    return {
        "operation": operation,
        "installed": closing == object_id,
        "object": object_id if closing == object_id else None,
        "force": False,
        "verification": {"result": "pass"},
    }


def _compare_authority_mirror(
    mirror: Path | None,
    materialized: Path,
) -> dict[str, Any]:
    if mirror is None:
        return {"present": False, "exact": None}
    try:
        children = list(mirror.iterdir())
    except OSError as exc:
        raise SourceTagRefusedError("local source authority mirror is unreadable") from exc
    if {item.name for item in children} != PORTABLE_NAMES:
        raise SourceTagRefusedError("local source authority mirror inventory differs")
    for name in sorted(PORTABLE_NAMES):
        if read_regular(mirror / name) != read_regular(materialized / name):
            raise SourceTagRefusedError("local source authority mirror bytes differ")
    return {"present": True, "exact": True}


def _verify_qualification_settings_crosslink(
    *,
    receipt: Mapping[str, Any],
    qualification: Mapping[str, Any],
) -> dict[str, Any]:
    source_main = _mapping(
        receipt.get("source_main_authority"),
        "release consumer source-main authority",
    )
    settings = _mapping(
        source_main.get("release_settings"),
        "release consumer embedded settings authority",
    )
    validate_release_settings_authority(settings)
    settings_raw = canonical_line(settings)
    policy = _mapping(settings.get("policy"), "release consumer settings policy")
    principal = _stable_automation_principal(
        policy.get("automation_principal"),
        "release consumer qualification automation principal",
    )
    if principal is None:
        raise SourceTagRefusedError(
            "release qualification automation principal remains UNFINALIZED"
        )
    protection = _mapping(
        qualification.get("protection"),
        "release consumer qualification protection",
    )
    signed_settings = _mapping(
        protection.get("settings_authority"),
        "release consumer qualification settings seal",
    )
    expected = {
        "format": RELEASE_SETTINGS_FORMAT,
        "sha256": sha256(settings_raw),
        "size": len(settings_raw),
        "automation_principal": principal,
    }
    if signed_settings != expected:
        raise SourceTagRefusedError(
            "qualification settings seal/principal differs from signed source receipt"
        )
    environments = _mapping(policy.get("environments"), "release settings environments")
    if protection.get("environment") != environments.get(
        "production_qualification"
    ) or protection.get("actions") != policy.get("actions"):
        raise SourceTagRefusedError(
            "qualification protection environment/actions differ from source settings"
        )
    return expected


def verify_release_consumer(
    *,
    repo: Path,
    manifest_path: Path,
    production_root: Path,
    cosign_path: Path,
    version_path: Path,
    wheelhouse_repository_response: Path,
    local_authority_root: Path | None,
    install_local_tag: bool,
) -> dict[str, Any]:
    """Capture caller runtime bytes once; only private copies may execute or verify."""
    _require_git_runtime_authority()
    _reject_release_consumer_environment()
    cosign_raw = read_regular(cosign_path, limit=256 * 1024 * 1024)
    version_raw = read_regular(version_path, limit=1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="z4j-release-consumer-runtime-") as directory:
        private = Path(directory)
        private_cosign = private / "cosign"
        private_version = private / "cosign-version.json"
        _write_exclusive(private_cosign, cosign_raw)
        _write_exclusive(private_version, version_raw)
        private_cosign.chmod(0o500)
        private_version.chmod(0o400)
        result = _verify_release_consumer_with_runtime(
            repo=repo,
            manifest_path=manifest_path,
            production_root=production_root,
            cosign_path=private_cosign,
            version_path=private_version,
            wheelhouse_repository_response=wheelhouse_repository_response,
            local_authority_root=local_authority_root,
            install_local_tag=install_local_tag,
        )
    if (
        read_regular(cosign_path, limit=256 * 1024 * 1024) != cosign_raw
        or read_regular(version_path, limit=1024 * 1024) != version_raw
    ):
        raise SourceTagRefusedError("caller Cosign runtime/transcript changed during release gate")
    return result


def _verify_release_consumer_with_runtime(
    *,
    repo: Path,
    manifest_path: Path,
    production_root: Path,
    cosign_path: Path,
    version_path: Path,
    wheelhouse_repository_response: Path,
    local_authority_root: Path | None,
    install_local_tag: bool,
) -> dict[str, Any]:
    _assert_sterile_local_repository(repo)
    production, production_carrier = _load_finalized_production_projection(
        repo=repo,
        production_root=production_root,
        cosign_path=cosign_path,
    )
    source_authority = _mapping(
        production.get("source_tag_authority"),
        "production source-tag authority",
    )
    qualification = _mapping(
        production.get("qualification_ceremony"),
        "production qualification ceremony",
    )
    commit = _hex(production.get("source_revision"), 40, "production source revision")
    tree = _hex(production.get("source_tree"), 40, "production source tree")
    if (
        source_authority.get("repository") != REPOSITORY
        or source_authority.get("tag") != TAG
        or source_authority.get("commit") != commit
        or source_authority.get("tree") != tree
    ):
        raise SourceTagRefusedError("production source-tag projection source differs")
    evidence = _mapping(
        source_authority.get("evidence_index"),
        "production source-tag evidence index",
    )
    workflow = _mapping(
        source_authority.get("workflow"),
        "production source-tag workflow",
    )
    artifact_digest = _digest(
        evidence.get("artifact_digest"),
        "production source-tag artifact digest",
    )
    subject_digest = _digest(
        evidence.get("index_digest"),
        "production source-tag subject digest",
    )
    if artifact_digest == subject_digest:
        raise SourceTagRefusedError("production source-tag artifact aliases its subject")
    manifest, manifest_raw = validate_manifest(
        manifest_path,
        approved_commit=commit,
        approved_tree=tree,
    )
    if production.get("manifest_sha256") != sha256(manifest_raw) or production.get(
        "signature_verifier"
    ) != manifest.get("signature_verifier"):
        raise SourceTagRefusedError("production/source manifest authority differs")
    live_retention = validate_wheelhouse_retention(
        wheelhouse_repository_response,
        manifest=manifest,
    )
    with tempfile.TemporaryDirectory(prefix="z4j-release-source-authority-") as directory:
        first_root = Path(directory) / "first"
        first_materialization = materialize_retained_authority(
            manifest_path=manifest_path,
            approved_commit=commit,
            approved_tree=tree,
            artifact_digest=artifact_digest,
            authority_run_id=_positive(workflow.get("run_id"), "authority run id"),
            authority_run_attempt=_positive(
                workflow.get("run_attempt"),
                "authority run attempt",
            ),
            output_root=first_root,
        )
        verified = verify_authority(
            first_root,
            repo=repo,
            manifest_path=manifest_path,
            cosign_path=cosign_path,
            version_path=version_path,
            require_local_tag=False,
        )
        if verified != source_authority:
            raise SourceTagRefusedError(
                "materialized source authority differs from production finalization"
            )
        receipt, _ = load_canonical(first_root / RECEIPT_NAME, "release consumer receipt")
        signed_retention = _mapping(
            _mapping(receipt.get("protection"), "release consumer receipt protection").get(
                "wheelhouse_retention"
            ),
            "release consumer signed wheelhouse retention",
        )
        if live_retention != signed_retention:
            raise SourceTagRefusedError(
                "wheelhouse retention capture differs from signed source receipt"
            )
        settings_crosslink = _verify_qualification_settings_crosslink(
            receipt=receipt,
            qualification=qualification,
        )
        mirror = _compare_authority_mirror(local_authority_root, first_root)
        remote_tag = _verify_remote_source_tag(repo=repo, receipt=receipt)
        completed_run = _verify_completed_qualification_run(qualification)
        second_root = Path(directory) / "second"
        second_materialization = materialize_retained_authority(
            manifest_path=manifest_path,
            approved_commit=commit,
            approved_tree=tree,
            artifact_digest=artifact_digest,
            authority_run_id=workflow["run_id"],
            authority_run_attempt=workflow["run_attempt"],
            output_root=second_root,
        )
        for name in sorted(PORTABLE_NAMES):
            if read_regular(first_root / name) != read_regular(second_root / name):
                raise SourceTagRefusedError("retained source authority changed during release gate")
        if second_materialization != first_materialization:
            raise SourceTagRefusedError("source authority materialization projection moved")
        final_production_verifier = verify_production_source(
            repo,
            manifest_path,
            release_commit=commit,
            release_tree=tree,
        )
        receipt_source = _mapping(receipt.get("source"), "release consumer receipt source")
        if receipt_source.get("production_verifier") != final_production_verifier:
            raise SourceTagRefusedError("production source changed during release gate")
        preinstall_remote_tag = _verify_remote_source_tag(repo=repo, receipt=receipt)
        if preinstall_remote_tag != remote_tag:
            raise SourceTagRefusedError("remote source tag changed before local materialization")
        local_tag = _materialize_local_tag(
            repo=repo,
            receipt=receipt,
            install=install_local_tag,
        )
        final_remote_tag = _verify_remote_source_tag(repo=repo, receipt=receipt)
        if final_remote_tag != remote_tag:
            raise SourceTagRefusedError("remote source tag changed after local materialization")
    qualification_raw = canonical_line(qualification)
    return {
        "format": RELEASE_CONSUMER_FORMAT,
        "result": "pass",
        "production_authority": {
            "authority_sha256": production["authority_sha256"],
            **production_carrier,
        },
        "source_tag_authority": source_authority,
        "qualification_ceremony": {
            "sha256": sha256(qualification_raw),
            "size": len(qualification_raw),
            "completed_run": completed_run,
            "settings_crosslink": settings_crosslink,
        },
        "registry": {
            "repository": "docker.io/z4jdev/z4j-production-wheelhouse",
            "subject_digest": subject_digest,
            "artifact_digest": artifact_digest,
            "retention": live_retention,
            "materialization": first_materialization,
            "stable_double_readback": True,
        },
        "remote_tag": remote_tag,
        "remote_tag_stable_triple_readback": True,
        "local_authority_mirror": mirror,
        "local_tag": local_tag,
        "verification": {"result": "pass"},
    }


def _same_receipt_conflict(
    registry: Registry,
    descriptors: Sequence[Mapping[str, Any]],
    *,
    receipt_digest: str,
    expected_artifact_digest: str,
) -> None:
    for item in descriptors:
        raw, _ = registry.get_manifest(str(item["digest"]), media_type=OCI_MANIFEST)
        value = _mapping(
            _strict_registry_json(raw, "existing source authority manifest"),
            "existing source authority manifest",
        )
        layers = value.get("layers")
        if not isinstance(layers, list) or len(layers) != 2:
            raise SourceTagRefusedError("existing source authority layer inventory differs")
        receipt_layer = _mapping(layers[0], "existing source authority receipt layer")
        if (
            receipt_layer.get("digest") == receipt_digest
            and item["digest"] != expected_artifact_digest
        ):
            raise SourceTagRefusedError(
                "registry contains conflicting artifact for the exact same source receipt"
            )


def publish_or_verify_durable(
    *,
    authority_root: Path,
    repo: Path,
    manifest_path: Path,
    cosign_path: Path,
    version_path: Path,
    output_dir: Path,
    publish: bool,
) -> dict[str, Any]:
    _require_git_runtime_authority()
    projection = verify_authority(
        authority_root,
        repo=repo,
        manifest_path=manifest_path,
        cosign_path=cosign_path,
        version_path=version_path,
    )
    _receipt, receipt_raw = load_canonical(
        authority_root / RECEIPT_NAME,
        "source tag receipt",
    )
    bundle_raw = _bundle_bytes(authority_root / BUNDLE_NAME, receipt_raw=receipt_raw)
    index_raw = read_regular(authority_root / EVIDENCE_INDEX_NAME)
    manifest, _ = validate_manifest(
        manifest_path,
        approved_commit=projection["commit"],
        approved_tree=projection["tree"],
    )
    retained = wheelhouse_authority(manifest)
    registry = Registry(repository=retained["repository"], push=publish)
    before_subject = _verify_subject(registry, retained)
    before_referrers, _ = registry.referrers(
        retained["subject"]["digest"],
        AUTHORITY_ARTIFACT_TYPE,
    )
    existing = _referrer_descriptors(before_referrers, AUTHORITY_ARTIFACT_TYPE)
    expected = _artifact_descriptor(index_raw)
    _same_receipt_conflict(
        registry,
        existing,
        receipt_digest=digest(receipt_raw),
        expected_artifact_digest=expected["digest"],
    )
    present = [item for item in existing if item == expected]
    if len(present) > 1:
        raise SourceTagRefusedError("registry duplicates exact source authority referrer")
    if not present:
        if not publish:
            raise SourceTagRefusedError("durable source tag authority referrer is missing")
        for raw in (EMPTY_CONFIG, receipt_raw, bundle_raw):
            registry.put_blob(raw)
        registry.put_referrer(index_raw, subject_digest=retained["subject"]["digest"])
    referrers_raw, artifact_raw, config_raw, _, _ = _verify_artifact_readback(
        registry,
        index_raw=index_raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject=retained["subject"],
    )
    authority_tag = authority_retention_tag(expected["digest"])
    retained_artifact = registry.get_optional_manifest(
        authority_tag,
        media_type=OCI_MANIFEST,
    )
    if retained_artifact is None:
        if not publish:
            raise SourceTagRefusedError("source authority immutable retention tag is missing")
        registry.put_retention_tag(
            index_raw,
            tag=authority_tag,
            subject_digest=retained["subject"]["digest"],
        )
    elif (
        retained_artifact[0] != index_raw
        or retained_artifact[1].get("docker-content-digest") != expected["digest"]
    ):
        raise SourceTagRefusedError("source authority immutable retention tag conflicts")
    authority_tag, authority_tag_raw = _verify_authority_retention(
        registry,
        index_raw=index_raw,
        subject=retained["subject"],
    )
    referrers_raw, artifact_raw, config_raw, _, _ = _verify_artifact_readback(
        registry,
        index_raw=index_raw,
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
        subject=retained["subject"],
    )
    final_subject = _verify_subject(registry, retained)
    if final_subject != before_subject:
        raise SourceTagRefusedError("wheelhouse tag/index moved during evidence publication")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in {
        "subject-tag.oci.json": before_subject,
        "subject-referrers.oci.json": referrers_raw,
        "artifact-manifest.oci.json": artifact_raw,
        "authority-tag.oci.json": authority_tag_raw,
        "empty-config.json": config_raw,
        "receipt.json": receipt_raw,
        "bundle.sigstore.json": bundle_raw,
    }.items():
        _write_readback(output_dir, name, raw)
    durable = {
        "format": DURABLE_VERIFICATION_FORMAT,
        "result": "pass",
        "registry": REGISTRY_ORIGIN,
        "repository": retained["repository"],
        "subject": retained["subject"],
        "subject_retention": {
            "tag": retained["retention_tag"],
            "immutable_rule": WHEELHOUSE_RETENTION_RULE,
            "exact_raw_readback": True,
        },
        "artifact": expected,
        "authority_retention": {
            "tag": authority_tag,
            "immutable_rule": AUTHORITY_RETENTION_RULE,
            "exact_raw_readback": True,
        },
        "receipt": projection["receipt"],
        "bundle": projection["bundle"],
        "evidence_index": projection["evidence_index"],
        "native_referrers": True,
        "exact_raw_readback": True,
    }
    _write_readback(output_dir, "verification.json", canonical_line(durable))
    return durable


def _validated_durable_record(path: Path) -> dict[str, Any]:
    record, _ = load_canonical(path, "source authority durable verification")
    expected_keys = {
        "format",
        "result",
        "registry",
        "repository",
        "subject",
        "subject_retention",
        "artifact",
        "authority_retention",
        "receipt",
        "bundle",
        "evidence_index",
        "native_referrers",
        "exact_raw_readback",
    }
    _exact_keys(record, expected_keys, "source authority durable verification")
    subject = _mapping(record.get("subject"), "durable source authority subject")
    artifact = _mapping(record.get("artifact"), "durable source authority artifact")
    authority_retention = _mapping(
        record.get("authority_retention"),
        "durable source authority retention",
    )
    if (
        record.get("format") != DURABLE_VERIFICATION_FORMAT
        or record.get("result") != "pass"
        or record.get("registry") != REGISTRY_ORIGIN
        or record.get("repository") != "z4jdev/z4j-production-wheelhouse"
        or record.get("native_referrers") is not True
        or record.get("exact_raw_readback") is not True
        or subject.get("mediaType") != OCI_INDEX
        or artifact.get("mediaType") != OCI_MANIFEST
        or artifact.get("artifactType") != AUTHORITY_ARTIFACT_TYPE
        or authority_retention
        != {
            "tag": authority_retention_tag(artifact.get("digest")),
            "immutable_rule": AUTHORITY_RETENTION_RULE,
            "exact_raw_readback": True,
        }
    ):
        raise SourceTagRefusedError("durable source authority verification differs")
    _digest(subject.get("digest"), "durable subject digest")
    _size(subject.get("size"), "durable subject size")
    _digest(artifact.get("digest"), "durable artifact digest")
    _size(artifact.get("size"), "durable artifact size")
    return record


def build_release_dispatch_request(
    *,
    durable_path: Path,
    receipt_path: Path,
    initiating_run_id: int,
    initiating_run_attempt: int,
    actor: str,
) -> dict[str, Any]:
    durable = _validated_durable_record(durable_path)
    receipt, receipt_raw = load_canonical(receipt_path, "source tag receipt")
    validate_receipt(receipt)
    ceremony = _mapping(receipt["ceremony"], "source tag ceremony")
    source = _mapping(receipt["source"], "source tag source")
    tag = _mapping(receipt["tag"], "source tag")
    source_workflow = _mapping(receipt["source_workflow"], "source workflow authority")
    initiating_run_id = _positive(initiating_run_id, "initiating source run id")
    initiating_run_attempt = _positive(
        initiating_run_attempt,
        "initiating source run attempt",
    )
    if not actor or actor != actor.strip():
        raise SourceTagRefusedError("initiating source actor differs")
    if durable.get("receipt") != {"sha256": sha256(receipt_raw), "size": len(receipt_raw)}:
        raise SourceTagRefusedError("durable source authority receipt seal differs")
    artifact = _mapping(durable["artifact"], "durable source artifact")
    subject = _mapping(durable["subject"], "durable source subject")
    base_inputs = {
        "authority_artifact_digest": artifact["digest"],
        "authority_subject_digest": subject["digest"],
        "authority_run_id": str(ceremony["authority_run_id"]),
        "authority_run_attempt": str(ceremony["authority_run_attempt"]),
        "initiating_source_run_id": str(initiating_run_id),
        "initiating_source_run_attempt": str(initiating_run_attempt),
        "source_tag_object": tag["object"],
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "source_repository": REPOSITORY,
        "source_workflow_id": str(source_workflow["id"]),
        "source_workflow_node_id": source_workflow["node_id"],
        "source_workflow_path": WORKFLOW_PATH,
        "initiating_actor": actor,
    }
    nonce = sha256(
        canonical_line(
            {
                "schema": "z4j.release-docker-source-authority-handoff.v1",
                "inputs": base_inputs,
            }
        )
    )
    inputs = {
        **base_inputs,
        "handoff_nonce": nonce,
        "handoff_run_name": (
            f"source-tag-handoff-{initiating_run_id}-{initiating_run_attempt}-{nonce[:16]}"
        ),
    }
    return {"ref": TAG, "inputs": inputs, "return_run_details": True}


def _load_json_regular(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path)
    try:
        value = _mapping(
            json.loads(
                raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            ),
            label,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTagRefusedError(f"{label} is not JSON") from exc
    return value, raw


def validate_release_dispatch(
    *,
    request_path: Path,
    response_path: Path,
    run_response_path: Path,
    durable_path: Path,
    receipt_path: Path,
    initiating_run_id: int,
    initiating_run_attempt: int,
    expected_actor: str,
) -> dict[str, Any]:
    request, _ = load_canonical(request_path, "release dispatch request")
    expected_request = build_release_dispatch_request(
        durable_path=durable_path,
        receipt_path=receipt_path,
        initiating_run_id=initiating_run_id,
        initiating_run_attempt=initiating_run_attempt,
        actor=expected_actor,
    )
    if request != expected_request:
        raise SourceTagRefusedError("release dispatch request was substituted or replayed")
    _exact_keys(request, {"ref", "inputs", "return_run_details"}, "release dispatch request")
    inputs = _mapping(request.get("inputs"), "release dispatch inputs")
    if (
        request.get("ref") != TAG
        or request.get("return_run_details") is not True
        or "source_run_id" in inputs
        or "version" in inputs
        or inputs.get("initiating_actor") != expected_actor
    ):
        raise SourceTagRefusedError("release dispatch request identity differs")
    expected_input_keys = {
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
    _exact_keys(inputs, expected_input_keys, "release dispatch inputs")
    _digest(inputs.get("authority_artifact_digest"), "dispatch artifact digest")
    _digest(inputs.get("authority_subject_digest"), "dispatch subject digest")
    _hex(inputs.get("source_tag_object"), 40, "dispatch source tag object")
    _hex(inputs.get("source_commit"), 40, "dispatch source commit")
    _hex(inputs.get("source_tree"), 40, "dispatch source tree")
    if (
        inputs.get("source_repository") != REPOSITORY
        or inputs.get("source_workflow_path") != WORKFLOW_PATH
        or not all(
            isinstance(inputs.get(name), str) and inputs[name].isdigit() and int(inputs[name]) > 0
            for name in (
                "authority_run_id",
                "authority_run_attempt",
                "initiating_source_run_id",
                "initiating_source_run_attempt",
                "source_workflow_id",
            )
        )
    ):
        raise SourceTagRefusedError("release dispatch initiating authority differs")
    nonce_inputs = {
        key: value
        for key, value in inputs.items()
        if key not in {"handoff_nonce", "handoff_run_name"}
    }
    expected_nonce = sha256(
        canonical_line(
            {
                "schema": "z4j.release-docker-source-authority-handoff.v1",
                "inputs": nonce_inputs,
            }
        )
    )
    expected_name = (
        "source-tag-handoff-"
        f"{inputs['initiating_source_run_id']}-"
        f"{inputs['initiating_source_run_attempt']}-{expected_nonce[:16]}"
    )
    if (
        inputs.get("handoff_nonce") != expected_nonce
        or inputs.get("handoff_run_name") != expected_name
    ):
        raise SourceTagRefusedError("release dispatch handoff nonce/run-name differs")
    response, response_raw = _load_json_regular(
        response_path,
        "release dispatch response",
    )
    _exact_keys(
        response,
        {"workflow_run_id", "run_url", "html_url"},
        "release dispatch response",
    )
    run_id = _positive(response.get("workflow_run_id"), "release dispatch run id")
    run_url = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
    html_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    if response.get("run_url") != run_url or response.get("html_url") != html_url:
        raise SourceTagRefusedError("release dispatch response URLs differ")
    run, run_raw = _load_json_regular(run_response_path, "release dispatch run response")
    repository = _mapping(run.get("repository"), "release dispatch repository")
    actor = _mapping(run.get("actor"), "release dispatch actor")
    triggering_actor = _mapping(
        run.get("triggering_actor"),
        "release dispatch triggering actor",
    )
    if (
        run.get("id") != run_id
        or run.get("workflow_id") != RELEASE_WORKFLOW_ID
        or run.get("name") != RELEASE_WORKFLOW_NAME
        or run.get("path") != RELEASE_WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != TAG
        or run.get("head_sha") != inputs["source_commit"]
        or run.get("url") != run_url
        or run.get("html_url") != html_url
        or run.get("display_title") != expected_name
        or run.get("status") not in {"queued", "in_progress", "completed"}
        or repository.get("full_name") != REPOSITORY
        or repository.get("id") != REPOSITORY_ID
        or repository.get("node_id") != REPOSITORY_NODE_ID
        or actor.get("login") != expected_actor
        or triggering_actor.get("login") != expected_actor
    ):
        raise SourceTagRefusedError("release dispatch immediate run identity differs")
    _positive(actor.get("id"), "release dispatch actor id")
    _positive(triggering_actor.get("id"), "release dispatch triggering actor id")
    return {
        "format": "z4j-release-docker-dispatch-convenience-v1",
        "result": "pass",
        "api_version": GITHUB_API_VERSION,
        "workflow": {
            "id": RELEASE_WORKFLOW_ID,
            "node_id": RELEASE_WORKFLOW_NODE_ID,
            "path": RELEASE_WORKFLOW_PATH,
        },
        "run": {
            "id": run_id,
            "url": run_url,
            "html_url": html_url,
            "handoff_nonce": expected_nonce,
            "handoff_run_name": expected_name,
        },
        "response": {"sha256": sha256(response_raw), "size": len(response_raw)},
        "run_response": {"sha256": sha256(run_raw), "size": len(run_raw)},
        "authority_bearing": False,
    }


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SourceTagRefusedError(f"could not write {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(  # noqa: PLR0912, PLR0915 - explicit fail-closed CLI dispatch
    argv: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    for flag in (
        "repo",
        "manifest",
        "repository-response",
        "main-ref-response",
        "ruleset-response",
        "main-ruleset-response",
        "main-branch-protection-response",
        "environment-response",
        "wheelhouse-repository-response",
        "source-workflow-response",
        "release-workflow-response",
        "source-main-plan",
        "source-main-readback",
        "release-settings-authority",
        "source-main-runs-response",
        "workflow-inventory-response",
        "approved-commit",
        "approved-tree",
        "ruleset-id",
        "actor",
        "output",
        "tag-object-output",
    ):
        plan_parser.add_argument(f"--{flag}", required=True)
    pre_e0_parser = subparsers.add_parser("validate-pre-e0-static")
    for flag in (
        "repo",
        "source-main-plan",
        "source-main-readback",
        "release-settings-authority",
        "approved-commit",
        "approved-tree",
        "output",
    ):
        pre_e0_parser.add_argument(f"--{flag}", required=True)
    cosign_parser = subparsers.add_parser("verify-cosign")
    for flag in ("manifest", "approved-commit", "approved-tree", "binary", "version-output"):
        cosign_parser.add_argument(f"--{flag}", required=True)
    remote_parser = subparsers.add_parser("verify-remote")
    for flag in ("plan", "ref-response", "tag-response"):
        remote_parser.add_argument(f"--{flag}", required=True)
    receipt_parser = subparsers.add_parser("receipt")
    for flag in (
        "plan",
        "transition",
        "run-id",
        "run-attempt",
        "actor",
        "workflow-sha",
        "ref-response",
        "tag-response",
        "output",
    ):
        receipt_parser.add_argument(f"--{flag}", required=True)
    receipt_parser.add_argument("--recovery-authority")
    receipt_parser.add_argument("--push-response")
    recovery_parser = subparsers.add_parser("recovery-authority")
    for flag in (
        "run-response",
        "jobs-response",
        "approvals-response",
        "prior-run-id",
        "approved-commit",
        "source-workflow-id",
        "source-workflow-node-id",
        "output",
    ):
        recovery_parser.add_argument(f"--{flag}", required=True)
    source_workflow_parser = subparsers.add_parser("verify-source-workflow")
    source_workflow_parser.add_argument("--response", required=True)
    release_workflow_parser = subparsers.add_parser("verify-release-workflow")
    release_workflow_parser.add_argument("--response", required=True)
    retention_parser = subparsers.add_parser("verify-retention")
    for flag in (
        "manifest",
        "approved-commit",
        "approved-tree",
        "repository-response",
    ):
        retention_parser.add_argument(f"--{flag}", required=True)
    probe_parser = subparsers.add_parser("probe-registry")
    for flag in (
        "manifest",
        "approved-commit",
        "approved-tree",
        "repository-response",
    ):
        probe_parser.add_argument(f"--{flag}", required=True)
    index_parser = subparsers.add_parser("build-index")
    for flag in ("receipt", "bundle", "manifest", "output"):
        index_parser.add_argument(f"--{flag}", required=True)
    canonical_bundle_parser = subparsers.add_parser("canonicalize-bundle")
    for flag in ("input", "receipt", "output"):
        canonical_bundle_parser.add_argument(f"--{flag}", required=True)
    authority_parser = subparsers.add_parser("verify-authority")
    for flag in ("root", "repo", "manifest", "cosign", "version-output"):
        authority_parser.add_argument(f"--{flag}", required=True)
    release_consumer_parser = subparsers.add_parser("verify-release-consumer")
    for flag in (
        "repo",
        "manifest",
        "production-finalization-root",
        "cosign",
        "version-output",
        "wheelhouse-repository-response",
    ):
        release_consumer_parser.add_argument(f"--{flag}", required=True)
    release_consumer_parser.add_argument("--local-authority-root")
    release_consumer_parser.add_argument("--install-local-tag", action="store_true")
    for name in ("publish-durable", "verify-durable"):
        durable_parser = subparsers.add_parser(name)
        for flag in ("root", "repo", "manifest", "cosign", "version-output", "output-dir"):
            durable_parser.add_argument(f"--{flag}", required=True)
    materialize_parser = subparsers.add_parser("materialize-durable")
    for flag in (
        "manifest",
        "approved-commit",
        "approved-tree",
        "artifact-digest",
        "authority-run-id",
        "authority-run-attempt",
        "output-root",
    ):
        materialize_parser.add_argument(f"--{flag}", required=True)
    dispatch_request_parser = subparsers.add_parser("dispatch-request")
    for flag in (
        "durable-verification",
        "receipt",
        "initiating-run-id",
        "initiating-run-attempt",
        "actor",
        "output",
    ):
        dispatch_request_parser.add_argument(f"--{flag}", required=True)
    dispatch_verify_parser = subparsers.add_parser("verify-dispatch")
    for flag in (
        "request",
        "response",
        "run-response",
        "durable-verification",
        "receipt",
        "initiating-run-id",
        "initiating-run-attempt",
        "actor",
    ):
        dispatch_verify_parser.add_argument(f"--{flag}", required=True)
    transport_encode_parser = subparsers.add_parser("encode-source-main-transport")
    for flag in ("settings", "plan", "readback", "output"):
        transport_encode_parser.add_argument(f"--{flag}", required=True)
    transport_decode_parser = subparsers.add_parser("decode-source-main-transport")
    for flag in ("input", "output-root"):
        transport_decode_parser.add_argument(f"--{flag}", required=True)
    subparsers.add_parser("require-a0-authority")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-pre-e0-static":
            result = validate_pre_e0_static_source(
                repo=Path(args.repo),
                source_main_plan=Path(args.source_main_plan),
                source_main_readback=Path(args.source_main_readback),
                release_settings_authority=Path(args.release_settings_authority),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
            )
            _write_exclusive(Path(args.output), canonical_line(result))
        elif args.command == "plan":
            result = build_plan(
                repo=Path(args.repo),
                manifest_path=Path(args.manifest),
                repository_response=Path(args.repository_response),
                main_ref_response=Path(args.main_ref_response),
                ruleset_response=Path(args.ruleset_response),
                main_ruleset_response=Path(args.main_ruleset_response),
                main_branch_protection_response=Path(args.main_branch_protection_response),
                environment_response=Path(args.environment_response),
                wheelhouse_repository_response=Path(args.wheelhouse_repository_response),
                source_workflow_response=Path(args.source_workflow_response),
                release_workflow_response=Path(args.release_workflow_response),
                source_main_plan=Path(args.source_main_plan),
                source_main_readback=Path(args.source_main_readback),
                release_settings_authority=Path(args.release_settings_authority),
                source_main_runs_response=Path(args.source_main_runs_response),
                workflow_inventory_response=Path(args.workflow_inventory_response),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
                ruleset_id=int(args.ruleset_id),
                actor=args.actor,
            )
            raw_tag, _ = tag_bytes(Path(args.repo), args.approved_commit)
            _write_exclusive(Path(args.output), canonical_line(result))
            _write_exclusive(Path(args.tag_object_output), raw_tag)
        elif args.command == "verify-cosign":
            manifest, _ = validate_manifest(
                Path(args.manifest),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
            )
            result = verify_cosign(
                Path(args.binary), Path(args.version_output), manifest["signature_verifier"]
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "verify-remote":
            plan, _ = load_canonical(Path(args.plan), "source tag plan")
            validate_remote_tag(
                plan,
                ref_response=Path(args.ref_response),
                tag_response=Path(args.tag_response),
            )
        elif args.command == "receipt":
            plan, _ = load_canonical(Path(args.plan), "source tag plan")
            recovery = None
            if args.recovery_authority:
                recovery, _ = load_canonical(
                    Path(args.recovery_authority), "source tag recovery authority"
                )
            result = build_receipt(
                plan,
                transition=args.transition,
                run_id=int(args.run_id),
                run_attempt=int(args.run_attempt),
                actor=args.actor,
                workflow_sha=args.workflow_sha,
                ref_response=Path(args.ref_response),
                tag_response=Path(args.tag_response),
                recovery_authority=recovery,
                push_response=Path(args.push_response) if args.push_response else None,
            )
            _write_exclusive(Path(args.output), canonical_line(result))
        elif args.command == "recovery-authority":
            result = build_recovery_authority(
                run_response=Path(args.run_response),
                jobs_response=Path(args.jobs_response),
                approvals_response=Path(args.approvals_response),
                prior_run_id=int(args.prior_run_id),
                approved_commit=args.approved_commit,
                source_workflow_id=int(args.source_workflow_id),
                source_workflow_node_id=args.source_workflow_node_id,
            )
            _write_exclusive(Path(args.output), canonical_line(result))
        elif args.command == "verify-source-workflow":
            sys.stdout.buffer.write(canonical_line(validate_source_workflow(Path(args.response))))
        elif args.command == "verify-release-workflow":
            sys.stdout.buffer.write(canonical_line(validate_release_workflow(Path(args.response))))
        elif args.command == "verify-retention":
            manifest, _ = validate_manifest(
                Path(args.manifest),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
            )
            result = validate_wheelhouse_retention(
                Path(args.repository_response),
                manifest=manifest,
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "probe-registry":
            manifest, _ = validate_manifest(
                Path(args.manifest),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
            )
            retention = validate_wheelhouse_retention(
                Path(args.repository_response),
                manifest=manifest,
            )
            retained = wheelhouse_authority(manifest)
            registry = Registry(repository=retained["repository"], push=False)
            subject_raw = _verify_subject(registry, retained)
            referrers_raw, _ = registry.referrers(
                retained["subject"]["digest"],
                AUTHORITY_ARTIFACT_TYPE,
            )
            _referrer_descriptors(referrers_raw, AUTHORITY_ARTIFACT_TYPE)
            result = {
                "format": "z4j-source-tag-registry-capability-v1",
                "result": "pass",
                "registry": REGISTRY_ORIGIN,
                "repository": retained["repository"],
                "retention": retention,
                "subject": retained["subject"],
                "subject_raw": {"sha256": sha256(subject_raw), "size": len(subject_raw)},
                "referrers": {"sha256": sha256(referrers_raw), "size": len(referrers_raw)},
                "native_referrers": True,
                "mutable_fallback": False,
            }
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "build-index":
            receipt, receipt_raw = load_canonical(Path(args.receipt), "source tag receipt")
            validate_receipt(receipt)
            source = _mapping(receipt["source"], "source tag source")
            manifest, manifest_raw = validate_manifest(
                Path(args.manifest),
                approved_commit=source["commit"],
                approved_tree=source["tree"],
            )
            if receipt["manifest"] != {
                "path": "docker/production/manifest.json",
                "sha256": sha256(manifest_raw),
                "size": len(manifest_raw),
            }:
                raise SourceTagRefusedError(  # noqa: TRY301 - CLI refusal boundary
                    "source tag receipt manifest seal differs"
                )
            bundle_raw = _bundle_bytes(Path(args.bundle), receipt_raw=receipt_raw)
            raw = build_evidence_index(
                receipt_raw,
                bundle_raw,
                subject=wheelhouse_authority(manifest)["subject"],
            )
            _write_exclusive(Path(args.output), raw)
        elif args.command == "canonicalize-bundle":
            result = canonicalize_bundle(Path(args.input), Path(args.receipt), Path(args.output))
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "verify-authority":
            result = verify_authority(
                Path(args.root),
                repo=Path(args.repo),
                manifest_path=Path(args.manifest),
                cosign_path=Path(args.cosign),
                version_path=Path(args.version_output),
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "verify-release-consumer":
            result = verify_release_consumer(
                repo=Path(args.repo),
                manifest_path=Path(args.manifest),
                production_root=Path(args.production_finalization_root),
                cosign_path=Path(args.cosign),
                version_path=Path(args.version_output),
                wheelhouse_repository_response=Path(args.wheelhouse_repository_response),
                local_authority_root=(
                    Path(args.local_authority_root) if args.local_authority_root else None
                ),
                install_local_tag=args.install_local_tag,
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command in {"publish-durable", "verify-durable"}:
            result = publish_or_verify_durable(
                authority_root=Path(args.root),
                repo=Path(args.repo),
                manifest_path=Path(args.manifest),
                cosign_path=Path(args.cosign),
                version_path=Path(args.version_output),
                output_dir=Path(args.output_dir),
                publish=args.command == "publish-durable",
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "materialize-durable":
            result = materialize_retained_authority(
                manifest_path=Path(args.manifest),
                approved_commit=args.approved_commit,
                approved_tree=args.approved_tree,
                artifact_digest=args.artifact_digest,
                authority_run_id=int(args.authority_run_id),
                authority_run_attempt=int(args.authority_run_attempt),
                output_root=Path(args.output_root),
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "dispatch-request":
            result = build_release_dispatch_request(
                durable_path=Path(args.durable_verification),
                receipt_path=Path(args.receipt),
                initiating_run_id=int(args.initiating_run_id),
                initiating_run_attempt=int(args.initiating_run_attempt),
                actor=args.actor,
            )
            _write_exclusive(Path(args.output), canonical_line(result))
        elif args.command == "verify-dispatch":
            result = validate_release_dispatch(
                request_path=Path(args.request),
                response_path=Path(args.response),
                run_response_path=Path(args.run_response),
                durable_path=Path(args.durable_verification),
                receipt_path=Path(args.receipt),
                initiating_run_id=int(args.initiating_run_id),
                initiating_run_attempt=int(args.initiating_run_attempt),
                expected_actor=args.actor,
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "encode-source-main-transport":
            encoded = encode_source_main_authority_input(
                Path(args.settings),
                Path(args.plan),
                Path(args.readback),
            )
            _write_exclusive(Path(args.output), encoded.encode("ascii") + b"\n")
        elif args.command == "decode-source-main-transport":
            encoded_raw = read_regular(
                Path(args.input),
                limit=MAX_SOURCE_MAIN_TRANSPORT_ASCII + 1,
            )
            if not encoded_raw.endswith(b"\n") or encoded_raw.count(b"\n") != 1:
                raise SourceTagRefusedError(  # noqa: TRY301 - CLI refusal boundary
                    "source-main transport file framing differs"
                )
            try:
                encoded = encoded_raw[:-1].decode("ascii")
            except UnicodeDecodeError as exc:
                raise SourceTagRefusedError("source-main transport file is not ASCII") from exc
            result = decode_source_main_authority_input(
                encoded,
                Path(args.output_root),
            )
            sys.stdout.buffer.write(canonical_line(result))
        elif args.command == "require-a0-authority":
            require_a0_authority()
    except (OSError, ValueError, SourceTagRefusedError) as exc:
        sys.stderr.write(f"REFUSED: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
