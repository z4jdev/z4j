#!/usr/bin/env python3
"""Fail-closed verifier for the z4j 1.8.2 / CPython 3.14.7 image rebase."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

DIGEST_HEX = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SITE_ROOT = Path("/usr/local/lib/python3.14/site-packages")
STDLIB_ROOT = Path("/usr/local/lib/python3.14")


class VerificationError(RuntimeError):
    """The runtime differs from its content lock."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def require_equal(label: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise VerificationError(f"{label} differs: expected {expected!r}, found {actual!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read lock manifest {path}: {exc}") from exc
    require(isinstance(payload, dict), "lock manifest must be a JSON object")
    return payload


def cadence_payload(lock: Mapping[str, Any]) -> dict[str, object]:
    cadence = lock["cadence"]
    return {
        "format": cadence["payload_format"],
        "semantics_version": cadence["semantics_version"],
        "dependencies": cadence["dependencies"],
        "tzdata_tree_sha256": cadence["tzdata_tree_sha256"],
        "python": cadence["python"],
        "behavior_vector_sha256": cadence["behavior_vector_sha256"],
    }


def cadence_fingerprint(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _walk_entries(
    root: Path,
    *,
    excluded_top_level: frozenset[str] = frozenset(),
) -> list[tuple[str, Path]]:
    require(root.is_dir(), f"tree root is absent or not a directory: {root}")
    entries: list[tuple[str, Path]] = []
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(directory)
        if current == root and excluded_top_level:
            directory_names[:] = [
                name for name in directory_names if name not in excluded_top_level
            ]
            file_names[:] = [name for name in file_names if name not in excluded_top_level]
        for name in directory_names:
            path = current / name
            entries.append((path.relative_to(root).as_posix(), path))
        for name in file_names:
            path = current / name
            entries.append((path.relative_to(root).as_posix(), path))
    entries.sort(key=lambda item: item[0])
    return entries


def normalized_tree_digest(
    root: Path,
    *,
    excluded_top_level: Iterable[str] = (),
) -> dict[str, int | str]:
    """Hash a tree with literal NUL separators and explicit record types."""

    digest = hashlib.sha256()
    files = directories = symlinks = byte_count = 0
    for relative, path in _walk_entries(
        root,
        excluded_top_level=frozenset(excluded_top_level),
    ):
        relative_bytes = relative.encode("utf-8")
        details = path.lstat()
        mode = f"{stat.S_IMODE(details.st_mode):o}".encode("ascii")
        if stat.S_ISLNK(details.st_mode):
            target = str(path.readlink()).encode("utf-8")
            digest.update(b"L\0" + relative_bytes + b"\0" + mode + b"\0" + target + b"\n")
            symlinks += 1
        elif stat.S_ISDIR(details.st_mode):
            digest.update(b"D\0" + relative_bytes + b"\0" + mode + b"\n")
            directories += 1
        elif stat.S_ISREG(details.st_mode):
            content_digest = sha256_file(path).encode("ascii")
            length = str(details.st_size).encode("ascii")
            digest.update(
                b"F\0"
                + relative_bytes
                + b"\0"
                + mode
                + b"\0"
                + length
                + b"\0"
                + content_digest
                + b"\n",
            )
            files += 1
            byte_count += details.st_size
        else:
            raise VerificationError(f"unsupported filesystem entry in locked tree: {path}")
    return {
        "sha256": digest.hexdigest(),
        "files": files,
        "directories": directories,
        "symlinks": symlinks,
        "bytes": byte_count,
    }


def application_content_digest(
    site_root: Path,
    roots: Sequence[str],
) -> dict[str, int | str]:
    records: list[dict[str, object]] = []
    for root_name in roots:
        root = site_root / root_name
        require(root.is_dir(), f"application package root is absent: {root}")
        for path in sorted(
            root.rglob("*"),
            key=lambda item: item.relative_to(root).as_posix(),
        ):
            relative_to_root = path.relative_to(root)
            if (
                "__pycache__" in relative_to_root.parts
                or path.suffix in {".pyc", ".pyo"}
                or path.name == ".DS_Store"
                or path.is_symlink()
                or not path.is_file()
            ):
                continue
            payload = path.read_bytes()
            relative = path.relative_to(site_root).as_posix()
            records.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                },
            )
    canonical = json.dumps(
        {"format": "z4j-old-runtime-app-tree-v1", "files": records},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return {
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "canonical_bytes": len(canonical),
        "entries": len(records),
    }


def validate_candidate_image(lock: Mapping[str, Any]) -> None:  # noqa: PLR0915
    candidate = lock["candidate_image"]
    require_equal(
        "candidate keys",
        set(candidate),
        {
            "repository",
            "public_tag",
            "finalized",
            "index",
            "platforms",
            "release_receipt_sha256",
            "qualification_durable_evidence",
            "qualification_receipt_format",
            "release_receipt_semantics",
            "finalization_receipt_format",
            "promotion_evidence_format",
            "recovery_evidence_format",
            "release_evidence_index_format",
            "finalization_rule",
        },
    )
    require_equal("candidate repository", candidate["repository"], "docker.io/z4jdev/z4j")
    require_equal(
        "candidate public tag",
        candidate["public_tag"],
        "1.8.2-py3.14.7-rollback-1.9.0",
    )
    require_equal(
        "qualification receipt format",
        candidate["qualification_receipt_format"],
        "z4j-rollback-compat-qualification-receipt-v1",
    )
    require_equal(
        "release receipt semantics",
        candidate["release_receipt_semantics"],
        (
            "sha256 of canonical manifest-independent qualification receipt; "
            "never a receipt that hashes this manifest"
        ),
    )
    require_equal(
        "finalization receipt format",
        candidate["finalization_receipt_format"],
        "z4j-rollback-compat-finalization-receipt-v1",
    )
    require_equal(
        "promotion evidence format",
        candidate["promotion_evidence_format"],
        "z4j-rollback-compat-promotion-evidence-v1",
    )
    require_equal(
        "recovery evidence format",
        candidate["recovery_evidence_format"],
        "z4j-rollback-compat-recovery-evidence-v1",
    )
    require_equal(
        "release evidence index format",
        candidate["release_evidence_index_format"],
        "z4j-rollback-compat-release-evidence-index-v1",
    )
    require_equal(
        "candidate finalization rule",
        candidate["finalization_rule"],
        (
            "qualification builds and seals one untagged digest while finalized=false; "
            "source finalization sets finalized=true and copies only the qualification "
            "receipt's exact index/platform/config descriptors and SHA-256; finalization "
            "rereads those original bytes, authenticates the exact preconfigured Docker "
            "Hub immutable-tag rule, and emits a detached receipt before create-only "
            "sole-tag promotion"
        ),
    )
    require_equal("candidate index keys", set(candidate["index"]), {"digest", "size"})
    require_equal("candidate platform keys", set(candidate["platforms"]), {"amd64", "arm64"})
    for arch in ("amd64", "arm64"):
        require_equal(
            f"candidate {arch} descriptor keys",
            set(candidate["platforms"][arch]),
            {"manifest", "config"},
        )
        for descriptor in ("manifest", "config"):
            require_equal(
                f"candidate {arch} {descriptor} keys",
                set(candidate["platforms"][arch][descriptor]),
                {"digest", "size"},
            )
    finalized = candidate["finalized"]
    require(isinstance(finalized, bool), "candidate finalized flag must be boolean")
    digest_slots = [candidate["index"]["digest"]]
    size_slots = [candidate["index"]["size"]]
    for arch in ("amd64", "arm64"):
        for descriptor in ("manifest", "config"):
            digest_slots.append(candidate["platforms"][arch][descriptor]["digest"])
            size_slots.append(candidate["platforms"][arch][descriptor]["size"])
    receipt = candidate["release_receipt_sha256"]
    qualification_evidence = candidate["qualification_durable_evidence"]

    def evidence_descriptor(
        value: object,
        *,
        label: str,
        media_type: str,
        annotations: bool,
        artifact_type: str | None = None,
    ) -> None:
        require(isinstance(value, dict), f"{label} descriptor is not an object")
        keys = {"mediaType", "digest", "size"}
        if annotations:
            keys.add("annotations")
        if artifact_type is not None:
            keys.add("artifactType")
        require_equal(f"{label} descriptor keys", set(value), keys)
        require_equal(f"{label} media type", value["mediaType"], media_type)
        require(
            isinstance(value["digest"], str) and DIGEST.fullmatch(value["digest"]) is not None,
            f"{label} digest is invalid",
        )
        require(
            isinstance(value["size"], int)
            and not isinstance(value["size"], bool)
            and value["size"] > 0,
            f"{label} size is invalid",
        )
        if annotations:
            require_equal(
                f"{label} annotations",
                set(value["annotations"]),
                {"org.opencontainers.image.title"},
            )
            title = value["annotations"]["org.opencontainers.image.title"]
            parts = title.split("/") if isinstance(title, str) else []
            require(
                isinstance(title, str)
                and title
                and title.isascii()
                and not title.startswith("/")
                and "\\" not in title
                and all(part not in ("", ".", "..") for part in parts)
                and "/".join(parts) == title,
                f"{label} title is unsafe",
            )
        if artifact_type is not None:
            require_equal(f"{label} artifact type", value["artifactType"], artifact_type)

    if qualification_evidence is not None:
        require(isinstance(qualification_evidence, dict), "qualification OCI evidence is invalid")
        require_equal(
            "qualification OCI evidence keys",
            set(qualification_evidence),
            {"artifact", "config", "receipt", "bundle", "authentication", "payload"},
        )
        durable = lock["publication_gate"]["durable_evidence"]
        qualification_policy = durable["stages"]["qualification"]
        evidence_descriptor(
            qualification_evidence["artifact"],
            label="qualification artifact",
            media_type=durable["manifest_media_type"],
            annotations=False,
            artifact_type=qualification_policy["artifact_type"],
        )
        evidence_descriptor(
            qualification_evidence["config"],
            label="qualification config",
            media_type=durable["config_media_type"],
            annotations=False,
        )
        evidence_descriptor(
            qualification_evidence["receipt"],
            label="qualification receipt",
            media_type=qualification_policy["receipt_media_type"],
            annotations=True,
        )
        evidence_descriptor(
            qualification_evidence["bundle"],
            label="qualification bundle",
            media_type=durable["bundle_layer_media_type"],
            annotations=True,
        )
        evidence_descriptor(
            qualification_evidence["authentication"],
            label="qualification authentication",
            media_type=durable["authentication_layer_media_type"],
            annotations=True,
        )
        require(
            isinstance(qualification_evidence["payload"], list)
            and qualification_evidence["payload"],
            "qualification payload seals are absent",
        )
        for number, value in enumerate(qualification_evidence["payload"]):
            evidence_descriptor(
                value,
                label=f"qualification payload {number}",
                media_type=durable["payload_layer_media_type"],
                annotations=True,
            )
        payload_titles = [
            value["annotations"]["org.opencontainers.image.title"]
            for value in qualification_evidence["payload"]
        ]
        require_equal(
            "qualification payload ordering",
            payload_titles,
            sorted(set(payload_titles)),
        )
        role_titles = [
            qualification_evidence[name]["annotations"]["org.opencontainers.image.title"]
            for name in ("receipt", "bundle", "authentication")
        ]
        require_equal(
            "qualification layer title uniqueness",
            len(role_titles + payload_titles),
            len(set(role_titles + payload_titles)),
        )
    if finalized:
        for value in digest_slots:
            require(
                isinstance(value, str) and DIGEST.fullmatch(value) is not None,
                "finalized candidate has an invalid digest slot",
            )
        for value in size_slots:
            require(
                isinstance(value, int) and not isinstance(value, bool) and value > 0,
                "finalized candidate has an invalid descriptor size",
            )
        require(
            isinstance(receipt, str) and DIGEST_HEX.fullmatch(receipt) is not None,
            "finalized candidate has an invalid release-receipt digest",
        )
        require(
            qualification_evidence is not None,
            "finalized candidate lacks durable qualification OCI evidence",
        )
        require_equal(
            "durable qualification receipt seal",
            qualification_evidence["receipt"]["digest"],
            "sha256:" + receipt,
        )
    else:
        require(
            all(
                value is None
                for value in [*digest_slots, *size_slots, receipt, qualification_evidence]
            ),
            "unfinalized candidate fields must all be null",
        )


def validate_image_descriptors(lock: Mapping[str, Any]) -> None:
    for image_key in ("released_image", "python_carrier"):
        image = lock[image_key]
        require(
            DIGEST.fullmatch(image["index"]["digest"]) is not None,
            f"{image_key} index digest is invalid",
        )
        for arch in ("amd64", "arm64"):
            platform_lock = image["platforms"][arch]
            for descriptor in ("manifest", "config"):
                require(
                    DIGEST.fullmatch(platform_lock[descriptor]["digest"]) is not None,
                    f"{image_key} {arch} {descriptor} digest is invalid",
                )
            layers = platform_lock["layers"]
            expected_layer_count = 8 if image_key == "released_image" else 4
            require_equal(
                f"{image_key} {arch} layer count",
                len(layers),
                expected_layer_count,
            )
            layer_digests = []
            for layer in layers:
                require_equal(
                    f"{image_key} {arch} layer media type",
                    layer["mediaType"],
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                )
                require(
                    DIGEST.fullmatch(layer["digest"]) is not None,
                    f"{image_key} {arch} layer digest is invalid",
                )
                require(
                    isinstance(layer["size"], int)
                    and not isinstance(layer["size"], bool)
                    and layer["size"] > 0,
                    f"{image_key} {arch} layer size is invalid",
                )
                layer_digests.append(layer["digest"])
            require_equal(
                f"{image_key} {arch} unique layer count",
                len(set(layer_digests)),
                expected_layer_count,
            )
            if image_key == "released_image":
                require(
                    platform_lock["source_copy_layer"] in layer_digests,
                    f"{arch} source-copy layer is absent from released manifest",
                )
                require(
                    platform_lock["package_install_layer"] in layer_digests,
                    f"{arch} package-install layer is absent from released manifest",
                )


def validate_publication_gate(lock: Mapping[str, Any]) -> None:
    gate = lock["publication_gate"]
    require_equal("Trivy version", gate["trivy"]["version"], "0.74.0")
    require_equal("Trivy severity", gate["trivy"]["severity"], ["HIGH", "CRITICAL"])
    require(
        gate["trivy"]["ignore_unfixed"] is False,
        "unfixed vulnerabilities cannot be ignored",
    )
    require_equal("Trivy exit code", gate["trivy"]["exit_code"], 1)
    require_equal("Syft version", gate["syft_version"], "1.50.0")
    require_equal("Cosign version", gate["cosign_version"], "3.1.3")
    immutable_authority = gate["immutable_tag_authority"]
    require_equal(
        "Docker Hub immutable-tag authority",
        immutable_authority,
        {
            "provider": "docker-hub",
            "api": ("https://hub.docker.com/v2/namespaces/z4jdev/repositories/z4j"),
            "repository": "z4jdev/z4j",
            "target_tag": "1.8.2-py3.14.7-rollback-1.9.0",
            "enabled": True,
            "rules": [r"^1\.8\.2-py3\.14\.7-rollback-1\.9\.0$"],
            "required_behavior": ("matched-tag-cannot-be-overwritten-or-deleted"),
            "authority_format": "z4j-docker-hub-immutable-tag-authority-v1",
            "authentication_format": ("z4j-docker-hub-immutable-tag-authority-authentication-v1"),
            "require_authenticated_readback": True,
            "require_prewrite_exact_reread": True,
            "require_target_absent": True,
        },
    )
    require(
        immutable_authority["enabled"] is True,
        "Docker Hub immutable-tag policy must be enabled",
    )
    require(
        immutable_authority["require_authenticated_readback"] is True,
        "Docker Hub immutable-tag readback must be authenticated",
    )
    require(
        immutable_authority["require_prewrite_exact_reread"] is True,
        "Docker Hub immutable-tag policy must be reread before create",
    )
    require(
        immutable_authority["require_target_absent"] is True,
        "the compatibility tag must be absent before create",
    )
    require_equal(
        "recovery policy",
        gate["recovery"],
        {
            "workflow": ".github/workflows/recover-rollback-compat-promotion.yml",
            "environment": "rollback-compat-publisher",
            "identity": "https://github.com/z4jdev/z4j/.github/workflows/recover-rollback-compat-promotion.yml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com",
            "evidence_format": "z4j-rollback-compat-recovery-evidence-v1",
            "authentication_format": "z4j-rollback-compat-recovery-authentication-v1",
            "release_index_format": "z4j-rollback-compat-release-evidence-index-v1",
            "release_index_authentication_format": "z4j-rollback-compat-release-evidence-index-authentication-v1",
            "transition": "recovered-existing-exact-under-signed-immutable-authority",
            "allowed_recovery_of_conclusions": ["failure", "cancelled"],
            "requires_qualification_conclusion": "success",
            "requires_existing_exact_tag": True,
            "requires_signed_prewrite_finalization": True,
            "requires_fresh_exact_immutable_authority": True,
            "existing_promotion_behavior": "publish-missing-release-index-only",
            "rejects_existing_recovery_or_release_index": True,
            "forbids_target_image_or_tag_mutation": True,
            "actions_artifacts_are_optional_mirrors": True,
            "requires_durable_oci_predecessors": True,
            "promotion_terminal_completion_transition": "authenticated-promotion-terminal-to-release-index-only",
            "recovery_terminal_completion_transition": "authenticated-finalization-to-recovery-terminal-and-release-index",
        },
    )
    require_equal(
        "durable OCI evidence policy",
        gate["durable_evidence"],
        {
            "registry": "https://registry-1.docker.io",
            "repository": "z4jdev/z4j",
            "record_format": "z4j-rollback-compat-durable-evidence-record-v1",
            "config_format": "z4j-rollback-compat-durable-evidence-config-v1",
            "release_index_format": "z4j-rollback-compat-release-evidence-index-v1",
            "completion_format": "z4j-rollback-compat-release-index-completion-v1",
            "portable_graph_format": "z4j-rollback-compat-portable-evidence-graph-verification-v1",
            "original_materialization_format": "z4j-rollback-compat-original-evidence-materialization-v1",
            "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
            "subject_media_type": "application/vnd.oci.image.index.v1+json",
            "config_media_type": "application/vnd.z4j.rollback-compat.durable-evidence-config.v1+json",
            "bundle_layer_media_type": "application/vnd.z4j.rollback-compat.sigstore-bundle.v1+json",
            "authentication_layer_media_type": "application/vnd.z4j.rollback-compat.receipt-authentication.v1+json",
            "payload_layer_media_type": "application/vnd.z4j.rollback-compat.evidence-payload.v1",
            "publication": {
                "api": "oci-distribution-1.1-referrers",
                "manifest_reference": "digest-only",
                "require_absent_or_byte_exact_idempotence": True,
                "reject_different_or_duplicate_artifact_type": True,
                "require_raw_referrers_readback": True,
                "require_raw_manifest_readback": True,
                "require_raw_blob_readback": True,
                "actions_artifacts_are_convenience_only": True,
                "github_release_asset_published": False,
            },
            "stages": {
                "qualification": {
                    "artifact_type": "application/vnd.z4j.rollback-compat.qualification-evidence.v1",
                    "receipt_media_type": "application/vnd.z4j.rollback-compat.qualification-receipt.v1+json",
                    "authentication_format": "z4j-rollback-compat-qualification-authentication-v1",
                    "identities": [
                        "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main"
                    ],
                    "predecessors": [],
                },
                "finalization": {
                    "artifact_type": "application/vnd.z4j.rollback-compat.finalization-evidence.v1",
                    "receipt_media_type": "application/vnd.z4j.rollback-compat.finalization-receipt.v1+json",
                    "authentication_format": "z4j-rollback-compat-finalization-authentication-v1",
                    "identities": [
                        "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main"
                    ],
                    "predecessors": ["qualification"],
                },
                "promotion": {
                    "artifact_type": "application/vnd.z4j.rollback-compat.promotion-evidence.v1",
                    "receipt_media_type": "application/vnd.z4j.rollback-compat.promotion-evidence.v1+json",
                    "authentication_format": "z4j-rollback-compat-promotion-authentication-v1",
                    "identities": [
                        "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main"
                    ],
                    "predecessors": ["finalization"],
                },
                "recovery": {
                    "artifact_type": "application/vnd.z4j.rollback-compat.recovery-evidence.v1",
                    "receipt_media_type": "application/vnd.z4j.rollback-compat.recovery-evidence.v1+json",
                    "authentication_format": "z4j-rollback-compat-recovery-authentication-v1",
                    "identities": [
                        "https://github.com/z4jdev/z4j/.github/workflows/recover-rollback-compat-promotion.yml@refs/heads/main"
                    ],
                    "predecessors": ["finalization"],
                },
                "release-index": {
                    "artifact_type": "application/vnd.z4j.rollback-compat.release-evidence-index.v1",
                    "receipt_media_type": "application/vnd.z4j.rollback-compat.release-evidence-index.v1+json",
                    "authentication_format": "z4j-rollback-compat-release-evidence-index-authentication-v1",
                    "identities": [
                        "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main",
                        "https://github.com/z4jdev/z4j/.github/workflows/recover-rollback-compat-promotion.yml@refs/heads/main",
                    ],
                    "predecessors": ["promotion", "recovery"],
                },
            },
        },
    )
    require_equal(
        "receipt authentication",
        gate["receipt_authentication"],
        {
            "method": "sigstore-keyless-cosign-sign-blob",
            "identity": (
                "https://github.com/z4jdev/z4j/.github/workflows/"
                "release-rollback-compat.yml@refs/heads/main"
            ),
            "issuer": "https://token.actions.githubusercontent.com",
            "qualification_format": "z4j-rollback-compat-qualification-authentication-v1",
            "finalization_format": ("z4j-rollback-compat-finalization-authentication-v1"),
            "promotion_format": "z4j-rollback-compat-promotion-authentication-v1",
            "requires_pre_promotion_upload": True,
        },
    )
    require(
        gate["require_keyless_signature"] is True,
        "candidate image keyless signature is required",
    )
    require(gate["require_provenance"] is True, "candidate provenance is required")
    require(gate["require_sbom"] is True, "candidate SBOM is required")
    require(
        gate["promote_only_after_verification"] is True,
        "promotion must follow all verification",
    )


def validate_manifest(lock: Mapping[str, Any]) -> None:
    require_equal("lock format", lock.get("format"), "z4j-rollback-compat-image-lock-v1")
    require_equal("lock version", lock.get("lock_version"), 1)
    identity = lock["identity"]
    require_equal("application version", identity["application_version"], "1.8.2")
    require_equal("rollback target", identity["rollback_target"], "1.9.0")
    require_equal("compatibility Python", identity["compatibility_python"], "3.14.7")

    tags = lock["tag_policy"]
    require_equal(
        "sole public tag",
        tags["sole_public_tag"],
        "1.8.2-py3.14.7-rollback-1.9.0",
    )
    require(tags["operators_must_use_digest"] is True, "runbooks must consume a digest")
    require_equal("forbidden tags", tags["forbidden_tags"], ["1.8.2", "1.8", "latest"])
    require_equal(
        "existing-tag policy",
        tags["existing_tag_policy"],
        (
            "normal promotion requires 404 and refuses every 200; recovery requires "
            "200 at the exact qualified digest and performs no tag mutation; every "
            "other status or transport failure is fatal"
        ),
    )
    require(tags["sole_public_tag"] not in tags["forbidden_tags"], "public tag is forbidden")

    require(
        lock["reproducibility"]["network_package_operations_permitted"] is False,
        "network package operations cannot be permitted",
    )
    require_equal(
        "released image digest",
        lock["released_image"]["index"]["digest"],
        "sha256:ed2dac96f24b4ea42fcc89e76f459035365229d62f9d8efe916741cfd9373c03",
    )
    require_equal(
        "Python carrier digest",
        lock["python_carrier"]["index"]["digest"],
        "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4",
    )

    validate_candidate_image(lock)

    validate_image_descriptors(lock)

    content = lock["runtime_content"]
    distributions = content["distributions"]
    require_equal("distribution count", len(distributions), 73)
    distribution_pairs = [(item["name"], item["version"]) for item in distributions]
    require_equal("unique distribution count", len(set(distribution_pairs)), 73)
    scripts = content["record_owned_scripts"]
    require_equal("RECORD-owned script count", len(scripts), 20)
    script_paths = [item["path"] for item in scripts]
    require_equal("unique script count", len(set(script_paths)), 20)
    for item in [*scripts, content["record_owned_header"]]:
        require(
            DIGEST_HEX.fullmatch(item["sha256"]) is not None,
            f"invalid content digest for {item['path']}",
        )
        require(item["path"].startswith("/"), f"locked path is not absolute: {item['path']}")

    app_content = content["application_content"]
    require_equal("application roots", app_content["roots"], ["z4j", "z4j_brain"])
    require_equal(
        "application content format",
        app_content["format"],
        "z4j-old-runtime-app-tree-v1",
    )
    require_equal("application canonical byte count", app_content["canonical_bytes"], 59821)
    require_equal("application content entry count", app_content["entries"], 409)
    require_equal(
        "application content digest",
        app_content["sha256"],
        "2b66900392a8dc72086c2bfee5f923b32241012cf5520bf06775cf8c03dd725a",
    )

    for arch in ("amd64", "arm64"):
        site_lock = lock["released_image"]["platforms"][arch]["site_packages"]
        stdlib_lock = lock["python_carrier"]["platforms"][arch]["stdlib_excluding_site_packages"]
        require(
            DIGEST_HEX.fullmatch(site_lock["sha256"]) is not None, f"invalid {arch} site digest"
        )
        require(
            DIGEST_HEX.fullmatch(stdlib_lock["sha256"]) is not None, f"invalid {arch} stdlib digest"
        )
        require_equal(f"{arch} site symlink count", site_lock["symlinks"], 0)
        require_equal(f"{arch} stdlib symlink count", stdlib_lock["symlinks"], 0)

    payload = cadence_payload(lock)
    require_equal(
        "locked cadence fingerprint",
        cadence_fingerprint(payload),
        lock["cadence"]["expected_runtime_fingerprint"],
    )
    require(
        lock["cadence"]["expected_runtime_fingerprint"]
        != lock["cadence"]["source_image_python_3_14_6_fingerprint"],
        "compatibility fingerprint must not alias the source image",
    )
    validate_publication_gate(lock)


def normalize_arch(machine: str) -> str:
    normalized = machine.lower()
    if normalized in {"amd64", "x86_64"}:
        return "amd64"
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    raise VerificationError(f"unsupported runtime architecture: {machine!r}")


def verify_locked_file(item: Mapping[str, Any]) -> None:
    path = Path(item["path"])
    require(
        path.is_file() and not path.is_symlink(), f"locked file is absent or not regular: {path}"
    )
    require_equal(f"{path} mode", f"{stat.S_IMODE(path.stat().st_mode):04o}", item["mode"])
    require_equal(f"{path} size", path.stat().st_size, item["size"])
    require_equal(f"{path} sha256", sha256_file(path), item["sha256"])


def verify_python_carrier(lock: Mapping[str, Any], arch: str) -> dict[str, int | str]:
    expected_version = tuple(lock["cadence"]["python"]["version"])
    require_equal("CPython version", tuple(sys.version_info[:3]), expected_version)
    require_equal("Python implementation", platform.python_implementation(), "CPython")
    require_equal("PYTHON_VERSION environment", os.environ.get("PYTHON_VERSION"), "3.14.7")
    require("3.14.6" not in sys.version, "running interpreter reports Python 3.14.6")
    require_equal("stdlib path", Path(os.__file__).parent.resolve(), STDLIB_ROOT)

    forbidden = (
        Path("/usr/local/bin/python3.14.6"),
        Path("/usr/local/lib/python3.14.6"),
        Path("/usr/local/include/python3.14.6"),
    )
    for path in forbidden:
        require(
            not path.exists() and not path.is_symlink(),
            f"old Python 3.14.6 carrier path survived: {path}",
        )

    platform_lock = lock["python_carrier"]["platforms"][arch]
    expected_bins = platform_lock["python_bin"]
    # RECORD-owned scripts are application content, not carrier binaries, and
    # they are verified individually by verify_locked_file below.  Excluding
    # them by their declared paths keeps this inventory an exact-set check on
    # the interpreter itself: any python* binary that is neither a carrier bin
    # nor a declared script still fails here.  Without the exclusion the glob
    # swept in /usr/local/bin/python-grpc-tools-protoc, which grpcio-tools owns
    # and the recipe copies on purpose, so the carrier could never verify.
    record_owned_paths = {item["path"] for item in lock["runtime_content"]["record_owned_scripts"]}
    actual_paths = {
        str(path)
        for path in Path("/usr/local/bin").glob("python*")
        if (path.exists() or path.is_symlink()) and str(path) not in record_owned_paths
    }
    require_equal("Python carrier binary inventory", actual_paths, set(expected_bins))
    for raw_path, expected in expected_bins.items():
        path = Path(raw_path)
        details = path.lstat()
        require_equal(f"{path} mode", f"{stat.S_IMODE(details.st_mode):04o}", expected["mode"])
        if expected["type"] == "symlink":
            require(path.is_symlink(), f"expected carrier symlink: {path}")
            target = str(path.readlink())
            require_equal(f"{path} target", target, expected["target"])
            require("3.14.6" not in target, f"old interpreter symlink survived: {path}")
        else:
            require(path.is_file() and not path.is_symlink(), f"expected carrier file: {path}")
            require_equal(f"{path} size", details.st_size, expected["size"])
            require_equal(f"{path} sha256", sha256_file(path), expected["sha256"])

    actual_stdlib = normalized_tree_digest(
        STDLIB_ROOT,
        excluded_top_level=("site-packages",),
    )
    require_equal(
        "CPython stdlib carrier tree",
        actual_stdlib,
        platform_lock["stdlib_excluding_site_packages"],
    )
    return actual_stdlib


def distribution_inventory(site_root: Path) -> list[dict[str, str]]:
    result = [
        {"name": distribution.metadata["Name"], "version": distribution.version}
        for distribution in importlib.metadata.distributions(path=[str(site_root)])
    ]
    return sorted(result, key=lambda item: (item["name"].casefold(), item["name"], item["version"]))


def record_owned_external_files(site_root: Path) -> set[str]:
    result: set[str] = set()
    for distribution in importlib.metadata.distributions(path=[str(site_root)]):
        record = distribution.read_text("RECORD")
        if not record:
            continue
        for row in csv.reader(record.splitlines()):
            if not row:
                continue
            target = (site_root / row[0]).resolve(strict=False)
            raw = str(target)
            if (
                raw.startswith("/usr/local/bin/") or raw.startswith("/usr/local/include/")
            ) and target.is_file():
                result.add(raw)
    return result


def verify_released_payload(
    lock: Mapping[str, Any], arch: str
) -> tuple[dict[str, int | str], dict[str, int | str]]:
    content = lock["runtime_content"]
    actual_site = normalized_tree_digest(SITE_ROOT)
    # The carrier's site-packages is the released image's tree with the
    # declared substitutions applied, so it is verified against the carrier's
    # own recorded tree rather than the source image's.  The source image's
    # tree stays locked under released_image and is what the qualification
    # step audits when it reads those original bytes.  Comparing the carrier
    # to released_image here would have made any substitution unverifiable,
    # including the interpreter swap this image already exists to perform.
    require_equal(
        "carrier site-packages tree",
        actual_site,
        content["carrier_site_packages"][arch],
    )

    app_lock = content["application_content"]
    actual_app = application_content_digest(SITE_ROOT, app_lock["roots"])
    require_equal(
        "released application content",
        actual_app,
        {
            "sha256": app_lock["sha256"],
            "canonical_bytes": app_lock["canonical_bytes"],
            "entries": app_lock["entries"],
        },
    )

    expected_inventory = sorted(
        content["distributions"],
        key=lambda item: (item["name"].casefold(), item["name"], item["version"]),
    )
    require_equal("distribution inventory", distribution_inventory(SITE_ROOT), expected_inventory)

    for item in content["record_owned_scripts"]:
        verify_locked_file(item)
    verify_locked_file(content["record_owned_header"])
    tini_lock = lock["released_image"]["platforms"][arch]["tini_static"]
    tini = Path(tini_lock["path"])
    require(tini.is_file() and not tini.is_symlink(), "tini-static is absent or not regular")
    require_equal("tini-static sha256", sha256_file(tini), tini_lock["sha256"])
    require(os.access(tini, os.X_OK), "tini-static is not executable")

    expected_external = {item["path"] for item in content["record_owned_scripts"]} | {
        content["record_owned_header"]["path"]
    }
    require_equal(
        "existing RECORD-owned external-file inventory",
        record_owned_external_files(SITE_ROOT),
        expected_external,
    )
    for excluded in content["explicitly_excluded_non_authority"]:
        path = Path(excluded)
        require(
            not path.exists() and not path.is_symlink(), f"excluded generated file survived: {path}"
        )
    return actual_site, actual_app


def actual_cadence_payload(lock: Mapping[str, Any]) -> dict[str, object]:
    from z4j_brain.domain.schedule_cadence import cadence_behavior_vector_digest
    from z4j_brain.domain.schedule_runtime import (
        CADENCE_SEMANTICS_VERSION,
        packaged_tzdata_digest,
    )

    dependencies = {
        package: importlib.metadata.version(package) for package in lock["cadence"]["dependencies"]
    }
    return {
        "format": "z4j-cadence-runtime-v1",
        "semantics_version": CADENCE_SEMANTICS_VERSION,
        "dependencies": dependencies,
        "tzdata_tree_sha256": packaged_tzdata_digest(),
        "python": {
            "implementation": platform.python_implementation(),
            "version": list(sys.version_info[:3]),
        },
        "behavior_vector_sha256": cadence_behavior_vector_digest(),
    }


def verify_cadence(lock: Mapping[str, Any]) -> tuple[dict[str, object], str]:
    from z4j_brain.domain.schedule_cadence import cadence_runtime_fingerprint

    actual_payload = actual_cadence_payload(lock)
    require_equal("cadence runtime payload", actual_payload, cadence_payload(lock))
    computed = cadence_fingerprint(actual_payload)
    require_equal(
        "computed cadence fingerprint",
        computed,
        lock["cadence"]["expected_runtime_fingerprint"],
    )
    require_equal(
        "application cadence fingerprint",
        cadence_runtime_fingerprint(),
        computed,
    )
    return actual_payload, computed


def extension_modules(site_root: Path) -> list[tuple[Path, str]]:
    suffixes = sorted(importlib.machinery.EXTENSION_SUFFIXES, key=len, reverse=True)
    result: list[tuple[Path, str]] = []
    for path in sorted(site_root.rglob("*.so")):
        relative = path.relative_to(site_root).as_posix()
        suffix = next((candidate for candidate in suffixes if relative.endswith(candidate)), None)
        require(suffix is not None, f"shared object is not an importable extension: {path}")
        module = relative[: -len(suffix)].replace("/", ".")
        require(
            all(part and (part.isidentifier() or part == "google") for part in module.split(".")),
            f"cannot derive extension module name from {path}",
        )
        result.append((path, module))
    require(result, "no extension modules found")
    return result


def verify_extensions(site_root: Path, prerequisites: Mapping[str, Any]) -> list[str]:
    imported: list[str] = []
    for path, module in extension_modules(site_root):
        completed = subprocess.run(  # noqa: S603
            ["/usr/bin/ldd", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        output = completed.stdout + completed.stderr
        require(completed.returncode == 0, f"ldd failed for {path}: {output.strip()}")
        require(
            "not found" not in output.lower(),
            f"unresolved dynamic dependency for {path}: {output.strip()}",
        )
        # A compiled module may legitimately refuse to import standalone.
        # psycopg_binary guards its modules until psycopg has initialised, so
        # importing them bare checks an import path no caller uses.  The
        # required companions are declared in the manifest rather than inferred
        # here, so an extension with an undeclared prerequisite still fails.
        for companion in prerequisites.get(module, ()):
            try:
                importlib.import_module(companion)
            except Exception as exc:
                raise VerificationError(
                    f"cannot import declared prerequisite {companion} for {module}: {exc}"
                ) from exc
        try:
            importlib.import_module(module)
        except Exception as exc:
            raise VerificationError(f"cannot import extension {module} from {path}: {exc}") from exc
        imported.append(module)
    return imported


def run_checked(command: Sequence[str], *, timeout: float = 45.0) -> str:
    completed = subprocess.run(  # noqa: S603
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = completed.stdout + completed.stderr
    require(
        completed.returncode == 0,
        f"command failed ({completed.returncode}): {command!r}\n{output[-4000:]}",
    )
    return output


def verify_dependency_consistency(substitutions: Sequence[Mapping[str, Any]]) -> None:
    """Require pip's only complaints to be the declared substitutions.

    The carrier deliberately installs a tzdata the published 1.8 metadata does
    not permit, so ``pip check`` reports that pin as unsatisfied.  Rewriting
    1.8's dist-info to agree would make the carrier misreport what 1.8
    declared, so the mismatch is expected and is verified rather than hidden.
    Every other inconsistency is still fatal, and a declared substitution only
    excuses a line naming that exact distribution at that exact version.
    """

    completed = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode == 0:
        require(
            not substitutions,
            "pip check reported no inconsistency although a substitution is declared",
        )
        return

    allowed = {(item["name"].casefold(), str(item["carrier_version"])) for item in substitutions}
    seen: set[tuple[str, str]] = set()
    pattern = re.compile(
        r"^(?P<holder>\S+) (?P<held>\S+) has requirement (?P<req>\S+?)"
        r"(?P<spec>[=<>!~][^,]*), but you have (?P<name>\S+) (?P<version>\S+)\.$"
    )
    for raw in (completed.stdout + completed.stderr).splitlines():
        line = raw.strip()
        if not line:
            continue
        match = pattern.match(line)
        require(match is not None, f"unparsed pip check output: {line}")
        key = (match.group("name").casefold(), match.group("version"))
        require(key in allowed, f"undeclared dependency inconsistency: {line}")
        seen.add(key)
    require_equal("declared substitutions observed by pip check", seen, allowed)


def verify_cli_and_imports(substitutions: Sequence[Mapping[str, Any]]) -> None:
    for module in ("z4j", "z4j_brain", "z4j_scheduler"):
        try:
            importlib.import_module(module)
        except Exception as exc:
            raise VerificationError(f"primary package import failed for {module}: {exc}") from exc
    verify_dependency_consistency(substitutions)
    run_checked(["/usr/local/bin/z4j", "--help"])
    run_checked(["/usr/local/bin/z4j-scheduler", "--help"])


def verify_live_boot(lock: Mapping[str, Any]) -> None:
    health_url = lock["runtime_contract"]["health_url"]
    require(health_url.startswith("http://127.0.0.1:"), "health URL must be loopback HTTP")
    with tempfile.TemporaryDirectory(prefix="z4j-rollback-compat-") as temporary:
        root = Path(temporary)
        log_path = root / "serve.log"
        environment = os.environ.copy()
        environment.update(
            {
                "Z4J_HOME": str(root / "home"),
                "Z4J_BIND_HOST": "127.0.0.1",
                "Z4J_BIND_PORT": "17700",
                "Z4J_PUBLIC_URL": "http://127.0.0.1:17700",
                "Z4J_ALLOWED_HOSTS": '["127.0.0.1","localhost"]',
                "Z4J_ALLOW_HTTP_PUBLIC_URL": "true",
                "Z4J_AUTO_MIGRATE": "true",
                "Z4J_LOG_JSON": "true",
            },
        )
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                ["/usr/local/bin/z4j", "serve"],
                env=environment,
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 75
                last_error = "health endpoint was not attempted"
                while time.monotonic() < deadline:
                    status = process.poll()
                    if status is not None:
                        break
                    try:
                        with urllib.request.urlopen(health_url, timeout=2) as response:  # noqa: S310
                            body = response.read(1024 * 1024)
                            require_equal("health status", response.status, 200)
                            require(body, "health response body is empty")
                            return
                    except (OSError, urllib.error.URLError) as exc:
                        last_error = str(exc)
                    time.sleep(0.5)
                status = process.poll()
                log.flush()
                output = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
                raise VerificationError(
                    f"live boot probe failed (status={status}, last_error={last_error}):\n{output}",
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)


def verify_runtime(lock: Mapping[str, Any], expected_arch: str | None) -> dict[str, object]:
    arch = normalize_arch(platform.machine())
    if expected_arch is not None:
        require_equal("requested architecture", arch, expected_arch)
    contract = lock["runtime_contract"]
    require_equal("effective uid", os.geteuid(), contract["uid"])
    require_equal("effective gid", os.getegid(), contract["gid"])
    require_equal("working directory", str(Path.cwd()), contract["workdir"])

    stdlib = verify_python_carrier(lock, arch)
    site_tree, app_tree = verify_released_payload(lock, arch)
    cadence, fingerprint = verify_cadence(lock)
    extensions = verify_extensions(
        SITE_ROOT,
        lock["runtime_content"].get("extension_import_prerequisites", {}),
    )
    verify_cli_and_imports(
        lock["runtime_content"].get("substituted_distributions", ()),
    )
    verify_live_boot(lock)
    return {
        "status": "ok",
        "architecture": arch,
        "python": platform.python_version(),
        "site_packages": site_tree,
        "application_content": app_tree,
        "stdlib_excluding_site_packages": stdlib,
        "cadence_payload": cadence,
        "cadence_runtime_fingerprint": fingerprint,
        "extension_modules_imported": extensions,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="required external compatibility-image lock manifest",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="validate lock consistency without inspecting a runtime image",
    )
    parser.add_argument(
        "--expect-arch",
        choices=("amd64", "arm64"),
        help="require this native runtime architecture",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        lock = load_manifest(arguments.manifest)
        validate_manifest(lock)
        if arguments.static_only:
            result: dict[str, object] = {"status": "ok", "mode": "static"}
        else:
            result = verify_runtime(lock, arguments.expect_arch)
    except (
        VerificationError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as exc:
        sys.stderr.write(f"rollback compatibility verification failed: {exc}\n")
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
