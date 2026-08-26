#!/usr/bin/env python3
"""Verify and seal the bounded rollback compatibility recovery outcome.

This program does not contact GitHub, Docker Hub, Sigstore, or a registry.  The
recovery workflow performs authenticated reads and cryptographic verification,
then gives their exact retained bytes to this fail-closed verifier.  The program
never builds, tags, pushes, or otherwise mutates a candidate image.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY = "z4jdev/z4j"
REPOSITORY_ID = 1228454287
REPOSITORY_NODE_ID = "R_kgDOSTi5jw"
IMAGE = "docker.io/z4jdev/z4j"
PUBLIC_TAG = "1.8.2-py3.14.7-rollback-1.9.0"
NORMAL_WORKFLOW = ".github/workflows/release-rollback-compat.yml"
RECOVERY_WORKFLOW = ".github/workflows/recover-rollback-compat-promotion.yml"
NORMAL_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main"
)
RECOVERY_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/"
    "recover-rollback-compat-promotion.yml@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
TRANSITION = "recovered-existing-exact-under-signed-immutable-authority"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class RecoveryError(RuntimeError):
    """Recovery input is incomplete, unauthenticated, stale, or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryError(message)


def _reject_constant(value: str) -> None:
    raise RecoveryError(f"non-finite JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def decode_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"invalid JSON in {label}: {exc}") from exc


def regular_bytes(path: Path, *, maximum: int = MAX_CAPTURE_BYTES) -> bytes:
    """Capture one bounded regular file through one no-follow descriptor."""
    require(hasattr(os, "O_NOFOLLOW"), "platform lacks no-follow file reads")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        file_descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise RecoveryError(f"file is absent: {path}") from exc
    except OSError as exc:
        raise RecoveryError(f"file cannot be opened safely: {path}") from exc
    try:
        before = os.fstat(file_descriptor)
        require(stat.S_ISREG(before.st_mode), f"file is not regular: {path}")
        require(0 <= before.st_size <= maximum, f"file exceeds capture bound: {path}")
        captured = bytearray()
        while len(captured) <= maximum:
            chunk = os.read(file_descriptor, min(1024 * 1024, maximum + 1 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
        after = os.fstat(file_descriptor)
    finally:
        os.close(file_descriptor)
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    require(stable, f"file changed while being read: {path}")
    require(len(captured) == before.st_size, f"file size changed while being read: {path}")
    require(len(captured) <= maximum, f"file exceeds capture bound: {path}")
    return bytes(captured)


def load_json(path: Path, *, canonical: bool = False) -> Any:
    raw = regular_bytes(path)
    value = decode_json(raw, label=str(path))
    if canonical:
        expected = canonical_json(value)
        require(raw == expected, f"JSON is not canonical newline JSON: {path}")
    return value


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def descriptor(path: Path) -> dict[str, object]:
    raw = regular_bytes(path)
    return {"path": path.name, "sha256": sha256(raw), "size": len(raw)}


def descriptor_at(path: Path, root: Path) -> dict[str, object]:
    raw = regular_bytes(path)
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(raw),
        "size": len(raw),
    }


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == expected, f"{label} keys differ")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    require(isinstance(value, str), f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecoveryError(f"{label} is not an ISO-8601 timestamp") from exc
    require(parsed.tzinfo is not None, f"{label} has no timezone")
    return parsed.astimezone(UTC)


def validate_run(
    run: object,
    *,
    run_id: int,
    conclusions: set[str],
    label: str,
) -> dict[str, object]:
    require(isinstance(run, dict), f"{label} run response is not an object")
    expected = {
        "id": run_id,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "status": "completed",
        "path": NORMAL_WORKFLOW,
    }
    for field, value in expected.items():
        require(run.get(field) == value, f"{label} run {field} differs")
    require(run.get("conclusion") in conclusions, f"{label} run conclusion differs")
    repository = run.get("head_repository")
    require(isinstance(repository, dict), f"{label} run repository is absent")
    expected_repository = {
        "full_name": REPOSITORY,
        "id": REPOSITORY_ID,
        "node_id": REPOSITORY_NODE_ID,
    }
    for field, value in expected_repository.items():
        require(
            repository.get(field) == value,
            f"{label} run repository {field} differs",
        )
    require(
        isinstance(run.get("head_sha"), str) and GIT_OBJECT.fullmatch(run["head_sha"]) is not None,
        f"{label} run head SHA is invalid",
    )
    return run


def validate_artifacts(
    response: object,
    *,
    run_id: int,
    expected_names: set[str],
    observed_at: datetime,
    forbidden_names: set[str] = frozenset(),
) -> dict[str, dict[str, object]]:
    require(isinstance(response, dict), "artifact response is not an object")
    artifacts = response.get("artifacts")
    require(isinstance(artifacts, list), "artifact response has no artifact list")
    require(response.get("total_count") == len(artifacts), "artifact count differs")
    by_name: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        require(isinstance(artifact, dict), "artifact entry is not an object")
        name = artifact.get("name")
        require(isinstance(name, str) and name, "artifact name is invalid")
        require(name not in by_name, "artifact response has duplicate names")
        by_name[name] = artifact
    require(not (set(by_name) & forbidden_names), "already-complete evidence exists")
    require(set(by_name) == expected_names, "workflow artifact set differs")
    for name, artifact in by_name.items():
        require(artifact.get("expired") is False, f"artifact expired: {name}")
        expires = parse_timestamp(artifact.get("expires_at"), f"{name} expires_at")
        require(expires > observed_at, f"artifact retention expired: {name}")
        workflow_run = artifact.get("workflow_run")
        require(isinstance(workflow_run, dict), f"artifact run binding is absent: {name}")
        require(workflow_run.get("id") == run_id, f"artifact run binding differs: {name}")
        require(
            isinstance(artifact.get("archive_download_url"), str)
            and artifact["archive_download_url"],
            f"artifact download authority is absent: {name}",
        )
    return by_name


def inspect_actions_artifact_mirror(
    response: object,
    *,
    run_id: int,
    expected_name: str,
    observed_at: datetime,
    forbidden_names: set[str] = frozenset(),
) -> dict[str, object]:
    require(isinstance(response, dict), "artifact response is not an object")
    artifacts = response.get("artifacts")
    require(isinstance(artifacts, list), "artifact response has no artifact list")
    require(response.get("total_count") == len(artifacts), "artifact count differs")
    by_name: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        require(isinstance(artifact, dict), "artifact entry is not an object")
        name = artifact.get("name")
        require(isinstance(name, str) and name, "artifact name is invalid")
        require(name not in by_name, "artifact response has duplicate names")
        by_name[name] = artifact
        workflow_run = artifact.get("workflow_run")
        require(isinstance(workflow_run, dict), f"artifact run binding is absent: {name}")
        require(workflow_run.get("id") == run_id, f"artifact run binding differs: {name}")
    require(not (set(by_name) & forbidden_names), "already-complete evidence exists")
    artifact = by_name.get(expected_name)
    if artifact is None:
        return {"name": expected_name, "state": "absent-use-durable-oci"}
    if artifact.get("expired") is True:
        return {"name": expected_name, "state": "expired-use-durable-oci"}
    require(artifact.get("expired") is False, "Actions artifact expiry state is invalid")
    expires = parse_timestamp(artifact.get("expires_at"), f"{expected_name} expires_at")
    if expires <= observed_at:
        return {"name": expected_name, "state": "expired-use-durable-oci"}
    require(
        isinstance(artifact.get("archive_download_url"), str) and artifact["archive_download_url"],
        f"artifact download authority is absent: {expected_name}",
    )
    return {
        "name": expected_name,
        "state": "available-untrusted-convenience-mirror",
        "expires_at": artifact["expires_at"],
    }


def validate_no_prior_recovery(response: object) -> None:
    require(isinstance(response, dict), "prior recovery artifact response is invalid")
    artifacts = response.get("artifacts")
    require(isinstance(artifacts, list), "prior recovery artifact list is absent")
    require(response.get("total_count") == 0, "prior recovery evidence already exists")
    require(not artifacts, "prior recovery evidence already exists")


def cadence_payload(lock: dict[str, object]) -> dict[str, object]:
    cadence = lock["cadence"]
    require(isinstance(cadence, dict), "cadence lock is invalid")
    return {
        "format": cadence["payload_format"],
        "semantics_version": cadence["semantics_version"],
        "dependencies": cadence["dependencies"],
        "tzdata_tree_sha256": cadence["tzdata_tree_sha256"],
        "python": cadence["python"],
        "behavior_vector_sha256": cadence["behavior_vector_sha256"],
    }


def validate_inventory(root: Path, receipt: dict[str, object]) -> list[dict[str, object]]:
    evidence = root / "evidence"
    inventory = exact_keys(receipt.get("evidence"), {"files"}, "evidence inventory")
    listed = inventory["files"]
    require(isinstance(listed, list) and listed, "evidence inventory is empty")
    seen: set[str] = set()
    for item in listed:
        entry = exact_keys(item, {"path", "sha256", "size"}, "evidence descriptor")
        relative_text = entry["path"]
        require(isinstance(relative_text, str), "evidence path is invalid")
        relative = Path(relative_text)
        require(
            not relative.is_absolute()
            and ".." not in relative.parts
            and relative_text.startswith("evidence/"),
            "evidence path escapes the artifact",
        )
        require(relative_text not in seen, "evidence inventory has duplicate paths")
        seen.add(relative_text)
        path = root / relative
        require(descriptor_at(path, root) == entry, f"evidence descriptor differs: {path}")
    require(
        not any(path.is_symlink() for path in evidence.rglob("*")),
        "qualification evidence contains a symlink",
    )
    actual = {
        path.relative_to(root).as_posix()
        for path in evidence.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    require(actual == seen, "qualification evidence file set differs")
    return listed


def _source_recipe(source_root: Path) -> dict[str, str]:
    recipe = source_root / "docker/rollback-1.8.2-py3147"
    return {
        "dockerfile_sha256": sha256(regular_bytes(recipe / "Dockerfile")),
        "verifier_sha256": sha256(regular_bytes(recipe / "verify.py")),
        "workflow_sha256": sha256(regular_bytes(source_root / NORMAL_WORKFLOW)),
    }


def validate_qualification(  # noqa: PLR0915
    root: Path,
    *,
    lock: dict[str, object],
    run: dict[str, object],
    qualification_source: Path,
    finalization_source: Path,
) -> tuple[dict[str, object], bytes, dict[str, dict[str, object]]]:
    receipt_path = root / "rollback-compat-qualification-receipt.json"
    raw = regular_bytes(receipt_path)
    receipt = decode_json(raw, label=str(receipt_path))
    require(raw == canonical_json(receipt), "qualification receipt is not canonical")
    require(isinstance(receipt, dict), "qualification receipt is not an object")
    receipt_sha = sha256(raw)
    candidate = lock["candidate_image"]
    require(isinstance(candidate, dict), "candidate lock is invalid")
    require(
        receipt_sha == candidate.get("release_receipt_sha256"),
        "qualification receipt differs from finalized candidate authority",
    )
    sidecar = root / "rollback-compat-qualification-receipt.sha256"
    require(
        regular_bytes(sidecar).decode("ascii") == f"{receipt_sha}  {receipt_path.name}\n",
        "qualification receipt sidecar differs",
    )
    require(
        {path.name for path in root.iterdir()}
        == {
            "evidence",
            receipt_path.name,
            "rollback-compat-qualification-receipt.sigstore.json",
            "rollback-compat-qualification-authentication.json",
            "rollback-compat-qualification-receipt-verification.txt",
            sidecar.name,
        },
        "durable qualification materialization top-level set differs",
    )
    require(
        len(regular_bytes(root / "rollback-compat-qualification-receipt-verification.txt")) > 0,
        "qualification authentication verification is empty",
    )
    exact_keys(
        receipt,
        {
            "format",
            "result",
            "qualification",
            "recipe",
            "candidate_image",
            "runtime",
            "scanner",
            "sbom",
            "proofs",
            "registry_reread",
            "evidence",
        },
        "qualification receipt",
    )
    require(
        receipt["format"] == candidate.get("qualification_receipt_format"),
        "qualification receipt format differs",
    )
    require(receipt["result"] == "pass", "qualification receipt did not pass")
    qualification = receipt["qualification"]
    require(
        qualification
        == {
            "run_id": run["id"],
            "repository": REPOSITORY,
            "workflow_ref": f"{NORMAL_WORKFLOW}@refs/heads/main",
        },
        "qualification receipt run authority differs",
    )
    recipe = receipt["recipe"]
    require(recipe == _source_recipe(qualification_source), "qualification source differs")
    require(recipe == _source_recipe(finalization_source), "finalization recipe drifted")
    expected_candidate = {
        "repository": candidate["repository"],
        "index": candidate["index"],
        "platforms": candidate["platforms"],
    }
    require(receipt["candidate_image"] == expected_candidate, "candidate descriptors differ")
    validate_inventory(root, receipt)

    evidence = root / "evidence"
    expected_cadence = cadence_payload(lock)
    platform_seals: dict[str, dict[str, object]] = {}
    for arch in ("amd64", "arm64"):
        native = evidence / "native" / arch
        seal = load_json(native / "native-seal.json", canonical=True)
        seal = exact_keys(
            seal,
            {"format", "arch", "platform", "manifest", "config", "runtime", "scanner", "sbom"},
            f"{arch} native seal",
        )
        require(
            seal["format"] == "z4j-rollback-compat-native-evidence-v1", "native seal format differs"
        )
        require(
            seal["arch"] == arch and seal["platform"] == f"linux/{arch}", "native platform differs"
        )
        require(
            {"manifest": seal["manifest"], "config": seal["config"]}
            == candidate["platforms"][arch],
            f"{arch} candidate descriptor differs",
        )
        manifest_path = native / "manifest.oci.json"
        config_path = native / "config.oci.json"
        manifest_raw = regular_bytes(manifest_path)
        config_raw = regular_bytes(config_path)
        require(
            seal["manifest"]
            == {"digest": f"sha256:{sha256(manifest_raw)}", "size": len(manifest_raw)},
            f"{arch} manifest bytes differ",
        )
        require(
            seal["config"] == {"digest": f"sha256:{sha256(config_raw)}", "size": len(config_raw)},
            f"{arch} config bytes differ",
        )
        manifest = decode_json(manifest_raw, label=str(manifest_path))
        require(isinstance(manifest, dict), f"{arch} manifest is invalid")
        require(manifest.get("config") == seal["config"], f"{arch} manifest/config link differs")
        config = decode_json(config_raw, label=str(config_path))
        require(isinstance(config, dict), f"{arch} config is invalid")
        require(config.get("architecture") == arch, f"{arch} config architecture differs")
        require(config.get("os") == "linux", f"{arch} config operating system differs")
        config_body = config.get("config")
        labels = config_body.get("Labels") if isinstance(config_body, dict) else None
        require(isinstance(labels, dict), f"{arch} config labels are absent")
        for key, value in lock["expected_labels"].items():
            require(labels.get(key) == value, f"{arch} config label differs: {key}")

        verifier_path = native / "verifier.json"
        verifier_raw = regular_bytes(verifier_path)
        runtime = decode_json(verifier_raw, label=str(verifier_path))
        require(isinstance(runtime, dict), f"{arch} runtime evidence is invalid")
        require(
            seal["runtime"] == {"sha256": sha256(verifier_raw), "result": runtime},
            f"{arch} runtime seal differs",
        )
        require(
            receipt["runtime"]["platforms"][arch]
            == {"verification_sha256": sha256(verifier_raw), "result": runtime},
            f"{arch} runtime receipt differs",
        )
        require(
            set(runtime)
            == {
                "status",
                "architecture",
                "python",
                "site_packages",
                "application_content",
                "stdlib_excluding_site_packages",
                "cadence_payload",
                "cadence_runtime_fingerprint",
                "extension_modules_imported",
            },
            f"{arch} runtime evidence keys differ",
        )
        require(runtime["status"] == "ok", f"{arch} runtime verifier did not pass")
        require(runtime["architecture"] == arch, f"{arch} runtime architecture differs")
        require(runtime["python"] == "3.14.7", f"{arch} runtime Python differs")
        require(
            runtime["site_packages"] == lock["released_image"]["platforms"][arch]["site_packages"],
            f"{arch} released site tree differs",
        )
        expected_app = {
            key: lock["runtime_content"]["application_content"][key]
            for key in ("sha256", "canonical_bytes", "entries")
        }
        require(
            runtime["application_content"] == expected_app, f"{arch} application content differs"
        )
        require(
            runtime["stdlib_excluding_site_packages"]
            == lock["python_carrier"]["platforms"][arch]["stdlib_excluding_site_packages"],
            f"{arch} Python carrier differs",
        )
        require(runtime["cadence_payload"] == expected_cadence, f"{arch} cadence payload differs")
        require(
            runtime["cadence_runtime_fingerprint"]
            == lock["cadence"]["expected_runtime_fingerprint"],
            f"{arch} cadence fingerprint differs",
        )

        trivy_path = native / "trivy.json"
        trivy_raw = regular_bytes(trivy_path)
        report = decode_json(trivy_raw, label=str(trivy_path))
        require(isinstance(report, dict), f"{arch} Trivy report is invalid")
        require(report.get("SchemaVersion") == 2, f"{arch} Trivy schema differs")
        require(isinstance(report.get("Results"), list), f"{arch} Trivy results differ")
        require(
            seal["manifest"]["digest"].encode("ascii") in trivy_raw,
            f"{arch} Trivy report does not bind the manifest",
        )
        counts = {"HIGH": 0, "CRITICAL": 0}
        for result in report["Results"]:
            if not isinstance(result, dict):
                continue
            for vulnerability in result.get("Vulnerabilities") or []:
                if isinstance(vulnerability, dict) and vulnerability.get("Severity") in counts:
                    counts[vulnerability["Severity"]] += 1
        require(counts == {"HIGH": 0, "CRITICAL": 0}, f"{arch} scan is not clean")
        require(
            seal["scanner"] == {"report_sha256": sha256(trivy_raw), "counts": counts},
            f"{arch} scanner seal differs",
        )
        sbom_path = native / "sbom.spdx.json"
        sbom_raw = regular_bytes(sbom_path)
        sbom = decode_json(sbom_raw, label=str(sbom_path))
        require(
            isinstance(sbom, dict) and sbom.get("spdxVersion") == "SPDX-2.3", f"{arch} SBOM differs"
        )
        require(
            seal["sbom"] == {"sha256": sha256(sbom_raw), "format": "spdx-json"},
            f"{arch} SBOM seal differs",
        )
        platform_seals[arch] = seal

    require(receipt["runtime"]["python"] == "3.14.7", "runtime Python policy differs")
    require(
        receipt["scanner"]
        == {
            "tool": "trivy",
            "version": "0.74.0",
            "severity": ["HIGH", "CRITICAL"],
            "ignore_unfixed": False,
            "exit_code": 1,
            "platforms": {arch: platform_seals[arch]["scanner"] for arch in ("amd64", "arm64")},
        },
        "scanner receipt differs",
    )
    index_sbom = evidence / "index" / "sbom.spdx.json"
    index_sbom_value = load_json(index_sbom)
    require(
        isinstance(index_sbom_value, dict) and index_sbom_value.get("spdxVersion") == "SPDX-2.3",
        "index SBOM differs",
    )
    require(
        receipt["sbom"]
        == {
            "tool": "syft",
            "version": "1.50.0",
            "format": "spdx-json",
            "platforms": {
                arch: {"sha256": platform_seals[arch]["sbom"]["sha256"]}
                for arch in ("amd64", "arm64")
            },
            "index_sha256": sha256(regular_bytes(index_sbom)),
        },
        "SBOM receipt differs",
    )

    index_path = evidence / "index" / "candidate.index.oci.json"
    index_raw = regular_bytes(index_path)
    expected_index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": candidate["platforms"][arch]["manifest"]["digest"],
                "size": candidate["platforms"][arch]["manifest"]["size"],
                "platform": {"architecture": arch, "os": "linux"},
            }
            for arch in ("amd64", "arm64")
        ],
    }
    require(decode_json(index_raw, label=str(index_path)) == expected_index, "OCI index differs")
    require(
        candidate["index"] == {"digest": f"sha256:{sha256(index_raw)}", "size": len(index_raw)},
        "OCI index descriptor differs",
    )
    reread = evidence / "index" / "registry-reread.index.oci.json"
    require(regular_bytes(reread) == index_raw, "qualification registry reread differs")
    require(
        receipt["registry_reread"]
        == {
            "digest": candidate["index"]["digest"],
            "size": len(index_raw),
            "sha256": sha256(index_raw),
            "exact_original_bytes": True,
        },
        "qualification registry receipt differs",
    )
    proof_names = {
        "signature": "signature-verification.json",
        "sbom_attestation": "sbom-attestation-verification.json",
        "provenance": "provenance-verification.json",
    }
    require(
        receipt["proofs"]
        == {
            label: {
                "verified": True,
                "sha256": sha256(regular_bytes(evidence / "proofs" / filename)),
            }
            for label, filename in proof_names.items()
        },
        "qualification proof inventory differs",
    )
    return receipt, raw, platform_seals


def expected_authority(lock: dict[str, object]) -> dict[str, object]:
    policy = lock["publication_gate"]["immutable_tag_authority"]
    return {
        "format": policy["authority_format"],
        "result": "pass",
        "source": {
            "api": policy["api"],
            "operation": "GetRepository",
            "authentication": "docker-hub-short-lived-bearer",
        },
        "repository": {"namespace": "z4jdev", "name": "z4j"},
        "immutable_tags_settings": {
            "enabled": True,
            "rules": policy["rules"],
        },
        "target_tag": PUBLIC_TAG,
    }


def validate_authentication(
    value: object,
    *,
    expected_format: str,
    identity: str,
    subject: Path,
    bundle: Path,
    verification: Path,
) -> dict[str, object]:
    authentication = exact_keys(
        value,
        {
            "format",
            "result",
            "method",
            "cosign_version",
            "identity",
            "issuer",
            "subject",
            "bundle",
            "verification",
        },
        "Sigstore authentication",
    )
    expected = {
        "format": expected_format,
        "result": "pass",
        "method": "sigstore-keyless-cosign-sign-blob",
        "cosign_version": "3.1.3",
        "identity": identity,
        "issuer": OIDC_ISSUER,
        "subject": descriptor(subject),
        "bundle": descriptor(bundle),
        "verification": {**descriptor(verification), "verified": True},
    }
    require(authentication == expected, "Sigstore authentication differs")
    require(isinstance(load_json(bundle), dict), "Sigstore bundle is not an object")
    require(len(regular_bytes(verification)) > 0, "Sigstore verification transcript is empty")
    return authentication


def validate_finalization(  # noqa: PLR0915
    root: Path,
    *,
    lock: dict[str, object],
    run: dict[str, object],
    git_tree: str,
    qualification_raw: bytes,
) -> tuple[dict[str, object], bytes, dict[str, object]]:
    expected_files = {
        "docker-hub-immutable-tag-authority.json",
        "docker-hub-immutable-tag-authority.sigstore.json",
        "docker-hub-immutable-tag-authority-verification.txt",
        "docker-hub-immutable-tag-authority-authentication.json",
        "rollback-compat-finalization-receipt.json",
        "rollback-compat-finalization-receipt.sha256",
        "rollback-compat-finalization-receipt.sigstore.json",
        "rollback-compat-finalization-receipt-verification.txt",
        "rollback-compat-finalization-authentication.json",
        "proofs/signature-verification.json",
        "proofs/sbom-attestation-verification.json",
        "proofs/provenance-verification.json",
        "registry-reread/candidate.index.oci.json",
        "registry-reread/native/amd64/manifest.oci.json",
        "registry-reread/native/amd64/config.oci.json",
        "registry-reread/native/arm64/manifest.oci.json",
        "registry-reread/native/arm64/config.oci.json",
    }
    require(
        not any(path.is_symlink() for path in root.rglob("*")),
        "finalization artifact has a symlink",
    )
    actual_files = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    require(actual_files == expected_files, "finalization artifact file set differs")
    receipt_path = root / "rollback-compat-finalization-receipt.json"
    receipt = load_json(receipt_path, canonical=True)
    receipt = exact_keys(
        receipt,
        {
            "format",
            "result",
            "source",
            "manifest_sha256",
            "qualification_receipt_sha256",
            "qualification_run_id",
            "qualification_source",
            "candidate_image",
            "public_reference",
            "registry_reread",
            "immutable_tag_authority",
            "proofs",
            "authorization",
            "receipt_authentication",
        },
        "finalization receipt",
    )
    receipt_raw = regular_bytes(receipt_path)
    require(receipt_raw == canonical_json(receipt), "finalization receipt capture is not canonical")
    sidecar = root / "rollback-compat-finalization-receipt.sha256"
    require(
        regular_bytes(sidecar).decode("ascii") == f"{sha256(receipt_raw)}  {receipt_path.name}\n",
        "finalization sidecar differs",
    )
    candidate = lock["candidate_image"]
    require(
        receipt["format"] == candidate["finalization_receipt_format"], "finalization format differs"
    )
    require(receipt["result"] == "pass", "finalization receipt did not pass")
    require(
        receipt["source"] == {"git_sha": run["head_sha"], "git_tree": git_tree},
        "finalization source differs",
    )
    require(
        receipt["qualification_receipt_sha256"] == sha256(qualification_raw),
        "qualification cross-link differs",
    )
    require(receipt["qualification_run_id"] > 0, "qualification run link is invalid")
    require(
        receipt["candidate_image"]
        == {
            "repository": candidate["repository"],
            "public_tag": candidate["public_tag"],
            "index": candidate["index"],
            "platforms": candidate["platforms"],
        },
        "finalization candidate differs",
    )
    require(receipt["public_reference"] == f"{IMAGE}:{PUBLIC_TAG}", "public reference differs")

    reread = root / "registry-reread"
    index_raw = regular_bytes(reread / "candidate.index.oci.json")
    platforms: dict[str, object] = {}
    for arch in ("amd64", "arm64"):
        values: dict[str, object] = {}
        for kind, filename in (("manifest", "manifest.oci.json"), ("config", "config.oci.json")):
            raw = regular_bytes(reread / "native" / arch / filename)
            values[kind] = {
                "digest": f"sha256:{sha256(raw)}",
                "size": len(raw),
                "sha256": sha256(raw),
            }
            require(
                {"digest": values[kind]["digest"], "size": values[kind]["size"]}
                == candidate["platforms"][arch][kind],
                f"finalization {arch} {kind} differs",
            )
        platforms[arch] = values
    require(
        receipt["registry_reread"]
        == {
            "original_reference": f"{IMAGE}@{candidate['index']['digest']}",
            "index": {
                "digest": f"sha256:{sha256(index_raw)}",
                "size": len(index_raw),
                "sha256": sha256(index_raw),
            },
            "platforms": platforms,
            "exact_original_bytes": True,
        },
        "finalization registry reread differs",
    )

    authority_path = root / "docker-hub-immutable-tag-authority.json"
    authority = load_json(authority_path, canonical=True)
    require(authority == expected_authority(lock), "signed immutable authority differs")
    authority_bundle = root / "docker-hub-immutable-tag-authority.sigstore.json"
    authority_verification = root / "docker-hub-immutable-tag-authority-verification.txt"
    authority_auth_path = root / "docker-hub-immutable-tag-authority-authentication.json"
    authority_auth = load_json(authority_auth_path, canonical=True)
    authority_auth = validate_authentication(
        authority_auth,
        expected_format="z4j-docker-hub-immutable-tag-authority-authentication-v1",
        identity=NORMAL_IDENTITY,
        subject=authority_path,
        bundle=authority_bundle,
        verification=authority_verification,
    )
    policy = lock["publication_gate"]["immutable_tag_authority"]
    policy_keys = (
        "provider",
        "api",
        "repository",
        "target_tag",
        "enabled",
        "rules",
        "required_behavior",
    )
    receipt_authority = receipt["immutable_tag_authority"]
    require(
        receipt_authority
        == {
            "policy": {key: policy[key] for key in policy_keys},
            "capture": descriptor(authority_path),
            "authentication": authority_auth,
        },
        "finalization immutable authority binding differs",
    )
    proof_names = {
        "signature": "signature-verification.json",
        "sbom_attestation": "sbom-attestation-verification.json",
        "provenance": "provenance-verification.json",
    }
    expected_proofs = {
        label: {
            "verified": True,
            "sha256": sha256(regular_bytes(root / "proofs" / filename)),
        }
        for label, filename in proof_names.items()
    }
    expected_proofs["final_tag_exact"] = {
        "status": "pending",
        "expected_digest": candidate["index"]["digest"],
        "enforcement": "docker-hub-immutable-create-only-after-receipt",
    }
    require(receipt["proofs"] == expected_proofs, "finalization proof binding differs")
    require(
        receipt["authorization"]
        == {
            "tag_transition": "create-only-under-preconfigured-docker-hub-immutable-rule",
            "receipt_uploaded_before_tag_mutation": True,
            "source_candidate_finalized": True,
            "target_tag_required_absent": True,
            "immutable_tag_authority_authenticated": True,
        },
        "finalization authorization differs",
    )
    require(
        receipt["receipt_authentication"]
        == {
            "method": "sigstore-keyless-cosign-sign-blob",
            "identity": NORMAL_IDENTITY,
            "issuer": OIDC_ISSUER,
            "bundle_file": "rollback-compat-finalization-receipt.sigstore.json",
            "verification_file": "rollback-compat-finalization-receipt-verification.txt",
        },
        "finalization receipt authentication policy differs",
    )
    receipt_bundle = root / "rollback-compat-finalization-receipt.sigstore.json"
    receipt_verification = root / "rollback-compat-finalization-receipt-verification.txt"
    final_auth_path = root / "rollback-compat-finalization-authentication.json"
    final_auth = load_json(final_auth_path, canonical=True)
    expected_base = validate_authentication(
        {key: final_auth[key] for key in final_auth if key != "immutable_tag_authority"},
        expected_format="z4j-rollback-compat-finalization-authentication-v1",
        identity=NORMAL_IDENTITY,
        subject=receipt_path,
        bundle=receipt_bundle,
        verification=receipt_verification,
    )
    require(
        set(final_auth) == set(expected_base) | {"immutable_tag_authority"},
        "finalization authentication keys differ",
    )
    require(
        final_auth["immutable_tag_authority"]
        == {
            "capture": descriptor(authority_path),
            "authentication": descriptor(authority_auth_path),
        },
        "finalization authentication authority binding differs",
    )
    return receipt, receipt_raw, authority


def _json_stream(path: Path) -> list[dict[str, object]]:
    raw = regular_bytes(path).decode("utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    position = 0
    values: list[object] = []
    while position < len(raw):
        while position < len(raw) and raw[position].isspace():
            position += 1
        if position == len(raw):
            break
        value, position = decoder.raw_decode(raw, position)
        values.extend(value if isinstance(value, list) else [value])
    require(
        values and all(isinstance(value, dict) for value in values),
        f"verification output is empty: {path}",
    )
    return values  # type: ignore[return-value]


def _attestation_statements(path: Path) -> list[dict[str, object]]:
    statements = []
    for envelope in _json_stream(path):
        payload = envelope.get("payload")
        require(isinstance(payload, str), f"attestation payload is absent: {path}")
        try:
            decoded = base64.b64decode(payload, validate=True)
        except ValueError as exc:
            raise RecoveryError(f"attestation payload is invalid: {path}") from exc
        statement = decode_json(decoded, label=f"attestation in {path}")
        require(isinstance(statement, dict), f"attestation statement is invalid: {path}")
        statements.append(statement)
    return statements


def validate_live_candidate_proofs(
    proof_root: Path, *, digest: str, sbom_path: Path
) -> dict[str, object]:
    signature = proof_root / "candidate-signature-verification.json"
    sbom_proof = proof_root / "candidate-sbom-attestation-verification.json"
    provenance = proof_root / "candidate-provenance-verification.json"
    _json_stream(signature)
    expected_hex = digest.removeprefix("sha256:")
    expected_sbom = load_json(sbom_path)

    def subject_matches(statement: dict[str, object]) -> bool:
        subjects = statement.get("subject")
        return isinstance(subjects, list) and any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_hex
            for subject in subjects
        )

    require(
        any(
            subject_matches(statement) and statement.get("predicate") == expected_sbom
            for statement in _attestation_statements(sbom_proof)
        ),
        "live SBOM attestation does not bind the candidate",
    )
    require(
        any(
            subject_matches(statement)
            and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
            for statement in _attestation_statements(provenance)
        ),
        "live provenance does not bind the candidate",
    )
    return {
        "candidate_signature": {**descriptor(signature), "verified": True},
        "sbom_attestation": {**descriptor(sbom_proof), "verified": True},
        "provenance": {**descriptor(provenance), "verified": True},
    }


def validate_public_registry(
    registry_root: Path,
    *,
    lock: dict[str, object],
    qualification_root: Path,
    finalization_root: Path,
) -> dict[str, object]:
    candidate = lock["candidate_image"]
    tag = load_json(registry_root / "public-tag-readback.json", canonical=True)
    require(
        tag
        == {
            "format": "z4j-rollback-compat-public-tag-readback-v1",
            "result": "pass",
            "reference": f"{IMAGE}:{PUBLIC_TAG}",
            "http_status": 200,
            "digest": candidate["index"]["digest"],
            "authentication": "docker-registry-short-lived-pull-only-bearer",
        },
        "public tag readback differs",
    )
    public_index = registry_root / "public.index.oci.json"
    index_raw = regular_bytes(public_index)
    q_index = qualification_root / "evidence/index/candidate.index.oci.json"
    f_index = finalization_root / "registry-reread/candidate.index.oci.json"
    require(index_raw == regular_bytes(q_index), "public index differs from qualification")
    require(index_raw == regular_bytes(f_index), "public index differs from finalization")
    require(
        candidate["index"] == {"digest": f"sha256:{sha256(index_raw)}", "size": len(index_raw)},
        "public index descriptor differs",
    )
    platforms: dict[str, object] = {}
    for arch in ("amd64", "arm64"):
        values: dict[str, object] = {}
        for kind, filename in (("manifest", "manifest.oci.json"), ("config", "config.oci.json")):
            public = registry_root / "native" / arch / filename
            q_path = qualification_root / "evidence" / "native" / arch / filename
            f_path = finalization_root / "registry-reread" / "native" / arch / filename
            raw = regular_bytes(public)
            require(
                raw == regular_bytes(q_path), f"public {arch} {kind} differs from qualification"
            )
            require(raw == regular_bytes(f_path), f"public {arch} {kind} differs from finalization")
            expected = candidate["platforms"][arch][kind]
            require(
                expected == {"digest": f"sha256:{sha256(raw)}", "size": len(raw)},
                f"public {arch} {kind} descriptor differs",
            )
            values[kind] = {**expected, "sha256": sha256(raw)}
        platforms[arch] = values
    return {
        "tag_readback": descriptor(registry_root / "public-tag-readback.json"),
        "index": {
            "digest": candidate["index"]["digest"],
            "size": len(index_raw),
            "sha256": sha256(index_raw),
        },
        "platforms": platforms,
        "exact_qualification_bytes": True,
        "exact_finalization_bytes": True,
    }


def validate_oci_descriptor(
    value: object,
    *,
    label: str,
    media_type: str,
    title: str | None = None,
    artifact_type: str | None = None,
) -> dict[str, object]:
    keys = {"mediaType", "digest", "size"}
    if title is not None:
        keys.add("annotations")
    if artifact_type is not None:
        keys.add("artifactType")
    result = exact_keys(value, keys, f"{label} descriptor")
    require(result["mediaType"] == media_type, f"{label} media type differs")
    require(
        isinstance(result["digest"], str) and DIGEST.fullmatch(result["digest"]) is not None,
        f"{label} digest is invalid",
    )
    require(
        isinstance(result["size"], int)
        and not isinstance(result["size"], bool)
        and result["size"] > 0,
        f"{label} size is invalid",
    )
    if title is not None:
        require(
            result["annotations"] == {"org.opencontainers.image.title": title},
            f"{label} title differs",
        )
    if artifact_type is not None:
        require(result["artifactType"] == artifact_type, f"{label} artifact type differs")
    return result


def oci_layer_descriptor(path: Path, *, media_type: str, title: str) -> dict[str, object]:
    raw = regular_bytes(path)
    return {
        "mediaType": media_type,
        "digest": f"sha256:{sha256(raw)}",
        "size": len(raw),
        "annotations": {"org.opencontainers.image.title": title},
    }


def validate_durable_predecessors(
    *,
    lock: dict[str, object],
    qualification_record_path: Path,
    finalization_record_path: Path,
    qualification_raw: bytes,
    finalization_raw: bytes,
    finalization_root: Path,
) -> dict[str, dict[str, object]]:
    durable = lock["publication_gate"]["durable_evidence"]
    candidate = lock["candidate_image"]
    record_keys = {
        "format",
        "result",
        "stage",
        "registry",
        "repository",
        "artifact_type",
        "subject",
        "artifact",
        "config",
        "receipt",
        "bundle",
        "authentication",
        "payload",
        "predecessor",
    }
    subject = {
        "mediaType": durable["subject_media_type"],
        "digest": candidate["index"]["digest"],
        "size": candidate["index"]["size"],
    }

    def record(path: Path, stage: str) -> dict[str, object]:
        value = exact_keys(load_json(path, canonical=True), record_keys, f"{stage} durable record")
        policy = durable["stages"][stage]
        require(value["format"] == durable["record_format"], f"{stage} record format differs")
        require(value["result"] == "pass", f"{stage} durable record did not pass")
        require(value["stage"] == stage, f"{stage} durable record stage differs")
        require(value["registry"] == durable["registry"], f"{stage} registry differs")
        require(value["repository"] == durable["repository"], f"{stage} repository differs")
        require(
            value["artifact_type"] == policy["artifact_type"],
            f"{stage} artifact type differs",
        )
        require(value["subject"] == subject, f"{stage} subject differs")
        validate_oci_descriptor(
            value["artifact"],
            label=f"{stage} artifact",
            media_type=durable["manifest_media_type"],
            artifact_type=policy["artifact_type"],
        )
        validate_oci_descriptor(
            value["config"],
            label=f"{stage} config",
            media_type=durable["config_media_type"],
        )
        return value

    qualification = record(qualification_record_path, "qualification")
    qualification_projection = {
        key: qualification[key]
        for key in ("artifact", "config", "receipt", "bundle", "authentication", "payload")
    }
    require(
        qualification_projection == candidate["qualification_durable_evidence"],
        "qualification durable record differs from finalized candidate seal",
    )
    require(qualification["predecessor"] is None, "qualification predecessor is forbidden")
    qualification_policy = durable["stages"]["qualification"]
    expected_q_receipt = {
        "mediaType": qualification_policy["receipt_media_type"],
        "digest": f"sha256:{sha256(qualification_raw)}",
        "size": len(qualification_raw),
        "annotations": {
            "org.opencontainers.image.title": "rollback-compat-qualification-receipt.json"
        },
    }
    require(qualification["receipt"] == expected_q_receipt, "qualification receipt seal differs")
    q_titles: list[str] = []
    require(isinstance(qualification["payload"], list), "qualification payload is invalid")
    for number, item in enumerate(qualification["payload"]):
        require(isinstance(item, dict), "qualification payload descriptor is invalid")
        annotations = item.get("annotations")
        require(isinstance(annotations, dict), "qualification payload title is absent")
        title = annotations.get("org.opencontainers.image.title")
        require(isinstance(title, str) and title, "qualification payload title is invalid")
        validate_oci_descriptor(
            item,
            label=f"qualification payload {number}",
            media_type=durable["payload_layer_media_type"],
            title=title,
        )
        q_titles.append(title)
    require(q_titles == sorted(set(q_titles)), "qualification payload ordering differs")

    finalization = record(finalization_record_path, "finalization")
    finalization_policy = durable["stages"]["finalization"]
    expected_roles = {
        "receipt": oci_layer_descriptor(
            finalization_root / "rollback-compat-finalization-receipt.json",
            media_type=finalization_policy["receipt_media_type"],
            title="rollback-compat-finalization-receipt.json",
        ),
        "bundle": oci_layer_descriptor(
            finalization_root / "rollback-compat-finalization-receipt.sigstore.json",
            media_type=durable["bundle_layer_media_type"],
            title="rollback-compat-finalization-receipt.sigstore.json",
        ),
        "authentication": oci_layer_descriptor(
            finalization_root / "rollback-compat-finalization-authentication.json",
            media_type=durable["authentication_layer_media_type"],
            title="rollback-compat-finalization-authentication.json",
        ),
    }
    require(
        expected_roles["receipt"]["digest"] == f"sha256:{sha256(finalization_raw)}",
        "finalization receipt capture differs",
    )
    for role, expected in expected_roles.items():
        require(finalization[role] == expected, f"finalization durable {role} differs")
    payload_names = {
        "docker-hub-immutable-tag-authority.json",
        "docker-hub-immutable-tag-authority-authentication.json",
        "docker-hub-immutable-tag-authority.sigstore.json",
        "docker-hub-immutable-tag-authority-verification.txt",
        "proofs/provenance-verification.json",
        "proofs/sbom-attestation-verification.json",
        "proofs/signature-verification.json",
        "registry-reread/candidate.index.oci.json",
        "registry-reread/native/amd64/config.oci.json",
        "registry-reread/native/amd64/manifest.oci.json",
        "registry-reread/native/arm64/config.oci.json",
        "registry-reread/native/arm64/manifest.oci.json",
        "rollback-compat-finalization-receipt-verification.txt",
    }
    expected_payload = [
        oci_layer_descriptor(
            finalization_root / name,
            media_type=durable["payload_layer_media_type"],
            title=name,
        )
        for name in sorted(payload_names)
    ]
    require(finalization["payload"] == expected_payload, "finalization payload seals differ")
    require(
        finalization["predecessor"]
        == {
            "stage": "qualification",
            "artifact": qualification["artifact"],
            "receipt": qualification["receipt"],
        },
        "finalization durable predecessor cross-link differs",
    )
    return {"qualification": qualification, "finalization": finalization}


def validate_promotion_terminal(  # noqa: PLR0915
    *,
    lock: dict[str, object],
    record_path: Path,
    root: Path,
    finalization_record: dict[str, object],
    finalization_root: Path,
    finalization_receipt: dict[str, object],
    finalization_raw: bytes,
    signed_authority: dict[str, object],
    recovery_of_run: dict[str, object],
    recovery_of_git_tree: str,
    qualification_run_id: int,
) -> tuple[dict[str, object], dict[str, object]]:
    durable = lock["publication_gate"]["durable_evidence"]
    candidate = lock["candidate_image"]
    policy = durable["stages"]["promotion"]
    record_value = exact_keys(
        load_json(record_path, canonical=True),
        {
            "format",
            "result",
            "stage",
            "registry",
            "repository",
            "artifact_type",
            "subject",
            "artifact",
            "config",
            "receipt",
            "bundle",
            "authentication",
            "payload",
            "predecessor",
        },
        "promotion durable record",
    )
    require(record_value["format"] == durable["record_format"], "promotion record format differs")
    require(record_value["result"] == "pass", "promotion durable record did not pass")
    require(record_value["stage"] == "promotion", "promotion durable record stage differs")
    require(record_value["registry"] == durable["registry"], "promotion registry differs")
    require(record_value["repository"] == durable["repository"], "promotion repository differs")
    require(record_value["artifact_type"] == policy["artifact_type"], "promotion type differs")
    require(
        record_value["subject"]
        == {
            "mediaType": durable["subject_media_type"],
            "digest": candidate["index"]["digest"],
            "size": candidate["index"]["size"],
        },
        "promotion subject differs",
    )
    validate_oci_descriptor(
        record_value["artifact"],
        label="promotion artifact",
        media_type=durable["manifest_media_type"],
        artifact_type=policy["artifact_type"],
    )
    validate_oci_descriptor(
        record_value["config"],
        label="promotion config",
        media_type=durable["config_media_type"],
    )
    require(
        record_value["predecessor"]
        == {
            "stage": "finalization",
            "artifact": finalization_record["artifact"],
            "receipt": finalization_record["receipt"],
        },
        "promotion durable predecessor cross-link differs",
    )
    role_names = {
        "receipt": "rollback-compat-promotion-evidence.json",
        "bundle": "rollback-compat-promotion-evidence.sigstore.json",
        "authentication": "rollback-compat-promotion-authentication.json",
    }
    role_media = {
        "receipt": policy["receipt_media_type"],
        "bundle": durable["bundle_layer_media_type"],
        "authentication": durable["authentication_layer_media_type"],
    }
    for role, title in role_names.items():
        expected = oci_layer_descriptor(root / title, media_type=role_media[role], title=title)
        require(record_value[role] == expected, f"promotion durable {role} differs")
    require(isinstance(record_value["payload"], list), "promotion payload is invalid")
    payload_titles: list[str] = []
    for number, item in enumerate(record_value["payload"]):
        require(isinstance(item, dict), "promotion payload descriptor is invalid")
        annotations = item.get("annotations")
        require(isinstance(annotations, dict), "promotion payload title is absent")
        title = annotations.get("org.opencontainers.image.title")
        require(isinstance(title, str) and title, "promotion payload title is invalid")
        expected = oci_layer_descriptor(
            root / title,
            media_type=durable["payload_layer_media_type"],
            title=title,
        )
        require(item == expected, f"promotion payload {number} differs")
        payload_titles.append(title)
    require(payload_titles == sorted(set(payload_titles)), "promotion payload ordering differs")
    require(not any(path.is_symlink() for path in root.rglob("*")), "promotion root has a symlink")
    receipt_path = root / role_names["receipt"]
    receipt_raw = regular_bytes(receipt_path)
    sidecar_name = "rollback-compat-promotion-evidence.sha256"
    require(
        regular_bytes(root / sidecar_name).decode("ascii")
        == f"{sha256(receipt_raw)}  {receipt_path.name}\n",
        "promotion receipt sidecar differs",
    )
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    require(
        actual_files == set(role_names.values()) | set(payload_titles) | {sidecar_name},
        "promotion materialized file set differs",
    )
    receipt_value = decode_json(receipt_raw, label=str(receipt_path))
    require(receipt_raw == canonical_json(receipt_value), "promotion receipt is not canonical")
    receipt = exact_keys(
        receipt_value,
        {
            "format",
            "result",
            "finalization_receipt_sha256",
            "qualification_run_id",
            "public_reference",
            "expected_digest",
            "observed_digest",
            "status",
            "transition",
            "immutable_tag_authority",
            "finalization_authentication",
            "promotion_authority",
        },
        "promotion receipt",
    )
    require(receipt["format"] == candidate["promotion_evidence_format"], "promotion format differs")
    require(receipt["result"] == "pass", "promotion receipt did not pass")
    require(
        receipt["finalization_receipt_sha256"] == sha256(finalization_raw),
        "promotion finalization receipt link differs",
    )
    require(
        receipt["qualification_run_id"] == qualification_run_id, "promotion qualification differs"
    )
    require(receipt["public_reference"] == f"{IMAGE}:{PUBLIC_TAG}", "promotion reference differs")
    require(
        receipt["expected_digest"] == candidate["index"]["digest"],
        "promotion expected digest differs",
    )
    require(
        receipt["observed_digest"] == candidate["index"]["digest"],
        "promotion observed digest differs",
    )
    require(receipt["status"] == "exact", "promotion status differs")
    require(receipt["transition"] == "created-under-immutable-rule", "promotion transition differs")
    authority_evidence = exact_keys(
        receipt["immutable_tag_authority"],
        {
            "policy",
            "finalization_capture",
            "prewrite_reread",
            "bundle_reverification",
            "exact_match",
        },
        "promotion immutable authority",
    )
    require(
        authority_evidence["policy"] == finalization_receipt["immutable_tag_authority"]["policy"],
        "promotion immutable policy differs",
    )
    require(
        authority_evidence["finalization_capture"]
        == finalization_receipt["immutable_tag_authority"]["capture"],
        "promotion finalization authority capture differs",
    )
    prewrite = exact_keys(
        authority_evidence["prewrite_reread"], {"path", "sha256", "size"}, "prewrite reread"
    )
    bundle_reverification = exact_keys(
        authority_evidence["bundle_reverification"],
        {"path", "sha256", "size", "verified"},
        "authority bundle reverification",
    )
    require(bundle_reverification["verified"] is True, "authority bundle was not reverified")
    for label, sealed in (("prewrite", prewrite), ("bundle", bundle_reverification)):
        relative = Path(str(sealed["path"]))
        require(
            not relative.is_absolute() and ".." not in relative.parts,
            f"promotion {label} authority path escapes",
        )
        path = root / relative
        require(
            descriptor_at(path, root) == {key: sealed[key] for key in ("path", "sha256", "size")},
            f"promotion {label} authority payload differs",
        )
    require(
        load_json(root / str(prewrite["path"]), canonical=True) == signed_authority,
        "promotion prewrite authority differs from signed finalization authority",
    )
    require(authority_evidence["exact_match"] is True, "promotion authority exact match is absent")
    # The signed promotion receipt must reuse the exact materialized full
    finalization_authentication = load_json(
        finalization_root / "rollback-compat-finalization-authentication.json",
        canonical=True,
    )
    # finalization authentication object, not only its embedded policy summary.
    require(
        receipt["finalization_authentication"] == finalization_authentication,
        "promotion finalization authentication differs",
    )
    authority = exact_keys(
        receipt["promotion_authority"],
        {
            "run_id",
            "repository",
            "workflow_path",
            "ref",
            "head_sha",
            "head_tree",
            "qualification_run_id",
        },
        "promotion authority",
    )
    require(
        authority
        == {
            "run_id": recovery_of_run["id"],
            "repository": REPOSITORY,
            "workflow_path": NORMAL_WORKFLOW,
            "ref": "refs/heads/main",
            "head_sha": recovery_of_run["head_sha"],
            "head_tree": recovery_of_git_tree,
            "qualification_run_id": qualification_run_id,
        },
        "promotion authority differs from exact failed/cancelled run",
    )
    return record_value, receipt


def recovery_completion_authority(
    args: argparse.Namespace, *, qualification_run_id: int, recovery_of_run: dict[str, object]
) -> dict[str, object]:
    promotion_completion = args.terminal_mode == "promotion-index-only"
    return {
        "format": "z4j-rollback-compat-release-index-completion-v1",
        "mode": (
            "recovery-completion-after-promotion"
            if promotion_completion
            else "recovery-after-tag-write"
        ),
        "workflow_identity": RECOVERY_IDENTITY,
        "recovery_run_id": str(args.recovery_run_id),
        "original_run_id": str(args.recovery_of_run_id),
        "source": {
            "repository": REPOSITORY,
            "ref": "refs/heads/main",
            "workflow_path": NORMAL_WORKFLOW,
            "sha": recovery_of_run["head_sha"],
            "tree": args.recovery_of_git_tree,
            "qualification_run_id": str(qualification_run_id),
        },
        "transition": (
            "authenticated-promotion-terminal-to-release-index-only"
            if promotion_completion
            else "authenticated-finalization-to-recovery-terminal-and-release-index"
        ),
    }


def recovery_payload_inventory(
    root: Path,
    *,
    registry_root: Path,
    fresh_authority: Path,
    finalization_live_verification: Path,
    authority_live_verification: Path,
    live_proofs_root: Path,
    qualification_durable_record: Path,
    finalization_durable_record: Path,
) -> list[dict[str, object]]:
    require(root.is_dir() and not root.is_symlink(), "recovery payload root is absent")
    expected = {
        "authority/fresh-docker-hub-immutable-tag-authority.json": fresh_authority,
        "predecessors/qualification-record.json": qualification_durable_record,
        "predecessors/finalization-record.json": finalization_durable_record,
        "registry/public-tag-readback.json": registry_root / "public-tag-readback.json",
        "registry/referrers-before-recovery.oci.json": (
            registry_root / "referrers-before-recovery.oci.json"
        ),
        "registry/recovery-referrers-before.oci.json": (
            registry_root / "recovery-referrers-before.oci.json"
        ),
        "registry/release-index-referrers-before.oci.json": (
            registry_root / "release-index-referrers-before.oci.json"
        ),
        "registry/public.index.oci.json": registry_root / "public.index.oci.json",
        "registry/native/amd64/manifest.oci.json": (
            registry_root / "native/amd64/manifest.oci.json"
        ),
        "registry/native/amd64/config.oci.json": (registry_root / "native/amd64/config.oci.json"),
        "registry/native/arm64/manifest.oci.json": (
            registry_root / "native/arm64/manifest.oci.json"
        ),
        "registry/native/arm64/config.oci.json": (registry_root / "native/arm64/config.oci.json"),
        "sigstore/prior-finalization-receipt-verification.txt": (finalization_live_verification),
        "sigstore/prior-immutable-authority-verification.txt": (authority_live_verification),
        "sigstore/candidate-signature-verification.json": (
            live_proofs_root / "candidate-signature-verification.json"
        ),
        "sigstore/candidate-sbom-attestation-verification.json": (
            live_proofs_root / "candidate-sbom-attestation-verification.json"
        ),
        "sigstore/candidate-provenance-verification.json": (
            live_proofs_root / "candidate-provenance-verification.json"
        ),
    }
    for relative, path in expected.items():
        require(
            path.absolute() == (root / relative).absolute(),
            f"recovery payload path differs: {relative}",
        )
        require(path.is_file() and not path.is_symlink(), f"recovery payload is absent: {relative}")
    require(
        not any(path.is_symlink() for path in root.rglob("*")),
        "recovery payload contains a symlink",
    )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    require(actual == set(expected), "recovery payload file set differs")
    return [descriptor_at(root / relative, root) for relative in sorted(expected)]


def emit_recovery(args: argparse.Namespace) -> None:  # noqa: PLR0915
    manifest_path = args.manifest
    manifest_raw = regular_bytes(manifest_path)
    lock = decode_json(manifest_raw, label=str(manifest_path))
    require(isinstance(lock, dict), "manifest is not an object")
    candidate = lock.get("candidate_image")
    require(isinstance(candidate, dict), "candidate lock is absent")
    require(candidate.get("finalized") is True, "recovery requires finalized candidate authority")
    require(candidate.get("repository") == IMAGE, "candidate repository differs")
    require(candidate.get("public_tag") == PUBLIC_TAG, "candidate public tag differs")
    require(
        DIGEST.fullmatch(str(candidate["index"]["digest"])) is not None,
        "candidate index digest is invalid",
    )
    require(
        isinstance(candidate["index"]["size"], int) and candidate["index"]["size"] > 0,
        "candidate index size is invalid",
    )
    promotion_completion = args.terminal_mode == "promotion-index-only"
    if promotion_completion:
        require(
            args.promotion_durable_record is not None and args.promotion_root is not None,
            "promotion completion requires the exact durable promotion terminal",
        )
        require(
            args.completion_authority_output is None,
            "promotion completion writes only its requested completion authority output",
        )
    else:
        require(
            args.promotion_durable_record is None and args.promotion_root is None,
            "recovery terminal forbids promotion evidence",
        )
        require(
            args.completion_authority_output is not None, "recovery completion output is absent"
        )
    observed_at = parse_timestamp(args.observed_at, "observed_at")
    qualification_run = validate_run(
        load_json(args.qualification_run_json),
        run_id=args.qualification_run_id,
        conclusions={"success"},
        label="qualification",
    )
    recovery_of_run = validate_run(
        load_json(args.recovery_of_run_json),
        run_id=args.recovery_of_run_id,
        conclusions={"failure", "cancelled"},
        label="recovery-of",
    )
    qualification_mirror = inspect_actions_artifact_mirror(
        load_json(args.qualification_artifacts_json),
        run_id=args.qualification_run_id,
        expected_name=f"rollback-compat-qualification-{args.qualification_run_id}",
        observed_at=observed_at,
    )
    finalization_mirror = inspect_actions_artifact_mirror(
        load_json(args.recovery_of_artifacts_json),
        run_id=args.recovery_of_run_id,
        expected_name=f"rollback-compat-finalization-{args.recovery_of_run_id}",
        forbidden_names=(
            frozenset()
            if promotion_completion
            else {f"rollback-compat-promotion-{args.recovery_of_run_id}"}
        ),
        observed_at=observed_at,
    )
    validate_no_prior_recovery(load_json(args.prior_recovery_artifacts_json))
    require(
        GIT_OBJECT.fullmatch(args.qualification_git_tree) is not None,
        "qualification git tree is invalid",
    )
    require(
        GIT_OBJECT.fullmatch(args.recovery_of_git_tree) is not None,
        "recovery-of git tree is invalid",
    )
    require(GIT_OBJECT.fullmatch(args.recovery_git_sha) is not None, "recovery git SHA is invalid")
    require(
        GIT_OBJECT.fullmatch(args.recovery_git_tree) is not None, "recovery git tree is invalid"
    )
    require(args.recovery_repository == REPOSITORY, "recovery repository differs")
    require(args.recovery_ref == "refs/heads/main", "recovery ref differs")
    require(args.recovery_run_id > 0, "recovery run id is invalid")
    require(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", args.recovery_actor) is not None,
        "recovery actor is invalid",
    )

    _qualification_receipt, qualification_raw, platform_seals = validate_qualification(
        args.qualification_root,
        lock=lock,
        run=qualification_run,
        qualification_source=args.qualification_source,
        finalization_source=args.finalization_source,
    )
    finalization_receipt, finalization_raw, signed_authority = validate_finalization(
        args.finalization_root,
        lock=lock,
        run=recovery_of_run,
        git_tree=args.recovery_of_git_tree,
        qualification_raw=qualification_raw,
    )
    durable_records = validate_durable_predecessors(
        lock=lock,
        qualification_record_path=args.qualification_durable_record,
        finalization_record_path=args.finalization_durable_record,
        qualification_raw=qualification_raw,
        finalization_raw=finalization_raw,
        finalization_root=args.finalization_root,
    )
    if promotion_completion:
        promotion_record, _promotion_receipt = validate_promotion_terminal(
            lock=lock,
            record_path=args.promotion_durable_record,
            root=args.promotion_root,
            finalization_record=durable_records["finalization"],
            finalization_root=args.finalization_root,
            finalization_receipt=finalization_receipt,
            finalization_raw=finalization_raw,
            signed_authority=signed_authority,
            recovery_of_run=recovery_of_run,
            recovery_of_git_tree=args.recovery_of_git_tree,
            qualification_run_id=args.qualification_run_id,
        )
        durable_records["promotion"] = promotion_record
    require(
        finalization_receipt["qualification_run_id"] == args.qualification_run_id,
        "finalization receipt qualification run differs",
    )
    require(
        finalization_receipt["qualification_source"]
        == {
            "git_sha": qualification_run["head_sha"],
            "repository": REPOSITORY,
            "workflow_path": NORMAL_WORKFLOW,
        },
        "finalization qualification source differs",
    )
    require(
        finalization_receipt["manifest_sha256"] == sha256(manifest_raw),
        "finalization manifest hash differs",
    )
    fresh_authority = load_json(args.fresh_authority, canonical=True)
    require(fresh_authority == signed_authority, "fresh immutable authority drifted")
    require(fresh_authority == expected_authority(lock), "fresh immutable authority differs")
    for verification in (args.finalization_live_verification, args.authority_live_verification):
        require(len(regular_bytes(verification)) > 0, "live Sigstore verification is empty")
    registry = validate_public_registry(
        args.registry_root,
        lock=lock,
        qualification_root=args.qualification_root,
        finalization_root=args.finalization_root,
    )
    live_proofs = validate_live_candidate_proofs(
        args.live_proofs_root,
        digest=candidate["index"]["digest"],
        sbom_path=args.qualification_root / "evidence/index/sbom.spdx.json",
    )
    completion_authority = recovery_completion_authority(
        args,
        qualification_run_id=args.qualification_run_id,
        recovery_of_run=recovery_of_run,
    )
    if promotion_completion:
        write_exclusive_private(args.output, canonical_json(completion_authority))
        return
    recovery_payload = recovery_payload_inventory(
        args.payload_root,
        registry_root=args.registry_root,
        fresh_authority=args.fresh_authority,
        finalization_live_verification=args.finalization_live_verification,
        authority_live_verification=args.authority_live_verification,
        live_proofs_root=args.live_proofs_root,
        qualification_durable_record=args.qualification_durable_record,
        finalization_durable_record=args.finalization_durable_record,
    )
    runtime_seals = {
        "platforms": {
            arch: {
                "native_seal": descriptor(
                    args.qualification_root / "evidence" / "native" / arch / "native-seal.json"
                ),
                "site_packages": platform_seals[arch]["runtime"]["result"]["site_packages"],
                "application_content": platform_seals[arch]["runtime"]["result"][
                    "application_content"
                ],
                "cadence_payload_sha256": sha256(
                    canonical_json(platform_seals[arch]["runtime"]["result"]["cadence_payload"])
                ),
                "cadence_runtime_fingerprint": platform_seals[arch]["runtime"]["result"][
                    "cadence_runtime_fingerprint"
                ],
            }
            for arch in ("amd64", "arm64")
        }
    }
    durable = lock["publication_gate"].get("durable_evidence")
    require(isinstance(durable, dict), "durable evidence contract is absent")
    recovery_policy = lock["publication_gate"].get("recovery")
    require(isinstance(recovery_policy, dict), "recovery policy is absent")
    require(recovery_policy.get("transition") == TRANSITION, "recovery transition policy differs")
    evidence = {
        "format": candidate["recovery_evidence_format"],
        "result": "pass",
        "recovery_of": {
            "run_id": args.recovery_of_run_id,
            "conclusion": recovery_of_run["conclusion"],
            "repository": REPOSITORY,
            "workflow_path": NORMAL_WORKFLOW,
            "head_sha": recovery_of_run["head_sha"],
            "authorized_prewrite_receipt": {
                "sha256": sha256(finalization_raw),
                "size": len(finalization_raw),
                "actions_artifact_mirror": finalization_mirror,
            },
            "creator_provenance": "not-asserted",
        },
        "qualification": {
            "run_id": args.qualification_run_id,
            "repository": REPOSITORY,
            "workflow_path": NORMAL_WORKFLOW,
            "head_sha": qualification_run["head_sha"],
            "git_tree": args.qualification_git_tree,
            "actions_artifact_mirror": qualification_mirror,
            "receipt": {
                "sha256": sha256(qualification_raw),
                "size": len(qualification_raw),
            },
        },
        "source": {
            "finalization_git_sha": recovery_of_run["head_sha"],
            "finalization_git_tree": args.recovery_of_git_tree,
            "manifest_sha256": sha256(manifest_raw),
            "recovery_git_sha": args.recovery_git_sha,
            "recovery_git_tree": args.recovery_git_tree,
        },
        "candidate_image": {
            "repository": candidate["repository"],
            "public_tag": candidate["public_tag"],
            "index": candidate["index"],
            "platforms": candidate["platforms"],
        },
        "public_reference": f"{IMAGE}:{PUBLIC_TAG}",
        "registry_reread": registry,
        "immutable_tag_authority": {
            "policy": lock["publication_gate"]["immutable_tag_authority"],
            "signed_prewrite_capture": descriptor(
                args.finalization_root / "docker-hub-immutable-tag-authority.json"
            ),
            "signed_prewrite_authentication": descriptor(
                args.finalization_root / "docker-hub-immutable-tag-authority-authentication.json"
            ),
            "fresh_authenticated_readback": descriptor(args.fresh_authority),
            "exact_match": True,
        },
        "prior_finalization": {
            "receipt": descriptor(
                args.finalization_root / "rollback-compat-finalization-receipt.json"
            ),
            "authentication": descriptor(
                args.finalization_root / "rollback-compat-finalization-authentication.json"
            ),
            "receipt_bundle": descriptor(
                args.finalization_root / "rollback-compat-finalization-receipt.sigstore.json"
            ),
            "receipt_live_reverification": {
                **descriptor(args.finalization_live_verification),
                "verified": True,
            },
            "authority_bundle": descriptor(
                args.finalization_root / "docker-hub-immutable-tag-authority.sigstore.json"
            ),
            "authority_live_reverification": {
                **descriptor(args.authority_live_verification),
                "verified": True,
            },
        },
        "cryptographic_proofs": live_proofs,
        "runtime_seals": runtime_seals,
        "evidence": {"files": recovery_payload},
        "transition": TRANSITION,
        "recovery_authority": {
            "run_id": args.recovery_run_id,
            "actor": args.recovery_actor,
            "repository": REPOSITORY,
            "ref": args.recovery_ref,
            "git_sha": args.recovery_git_sha,
            "git_tree": args.recovery_git_tree,
            "workflow_path": RECOVERY_WORKFLOW,
            "identity": RECOVERY_IDENTITY,
            "issuer": OIDC_ISSUER,
            "protected_environment": "rollback-compat-publisher",
        },
        "durable_evidence": {
            "contract": durable,
            "subject": f"{IMAGE}@{candidate['index']['digest']}",
            "predecessors": {
                stage: {
                    "record": descriptor_at(
                        getattr(args, f"{stage}_durable_record"),
                        args.payload_root,
                    ),
                    "artifact": record["artifact"],
                    "receipt": record["receipt"],
                    "predecessor": record["predecessor"],
                }
                for stage, record in durable_records.items()
            },
            "success_requires_digest_addressed_oci_referrers": True,
            "success_requires_raw_manifest_and_layer_readback": True,
        },
    }
    output_raw = canonical_json(evidence)
    output = args.output
    write_exclusive_private(output, output_raw)
    sidecar = output.with_suffix(".sha256")
    write_exclusive_private(
        sidecar,
        f"{sha256(output_raw)}  {output.name}\n".encode("ascii"),
    )
    write_exclusive_private(args.completion_authority_output, canonical_json(completion_authority))


def write_exclusive_private(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(hasattr(os, "O_NOFOLLOW"), "platform lacks no-follow evidence writes")
    parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
    except OSError as exc:
        raise RecoveryError(f"output parent cannot be opened safely: {path.parent}") from exc
    try:
        require(stat.S_ISDIR(os.fstat(parent_descriptor).st_mode), "output parent is not regular")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            file_descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        except OSError as exc:
            raise RecoveryError(f"refusing to overwrite or unsafely create: {path}") from exc
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(file_descriptor, raw[offset:])
                require(written > 0, f"short evidence write: {path}")
                offset += written
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--manifest", type=Path, required=True)
    result.add_argument("--qualification-root", type=Path, required=True)
    result.add_argument("--finalization-root", type=Path, required=True)
    result.add_argument("--qualification-durable-record", type=Path, required=True)
    result.add_argument("--finalization-durable-record", type=Path, required=True)
    result.add_argument("--qualification-source", type=Path, required=True)
    result.add_argument("--finalization-source", type=Path, required=True)
    result.add_argument("--qualification-run-json", type=Path, required=True)
    result.add_argument("--recovery-of-run-json", type=Path, required=True)
    result.add_argument("--qualification-artifacts-json", type=Path, required=True)
    result.add_argument("--recovery-of-artifacts-json", type=Path, required=True)
    result.add_argument("--prior-recovery-artifacts-json", type=Path, required=True)
    result.add_argument("--qualification-run-id", type=int, required=True)
    result.add_argument("--recovery-of-run-id", type=int, required=True)
    result.add_argument("--qualification-git-tree", required=True)
    result.add_argument("--recovery-of-git-tree", required=True)
    result.add_argument("--registry-root", type=Path, required=True)
    result.add_argument("--fresh-authority", type=Path, required=True)
    result.add_argument("--finalization-live-verification", type=Path, required=True)
    result.add_argument("--authority-live-verification", type=Path, required=True)
    result.add_argument("--live-proofs-root", type=Path, required=True)
    result.add_argument("--observed-at", required=True)
    result.add_argument("--recovery-run-id", type=int, required=True)
    result.add_argument("--recovery-actor", required=True)
    result.add_argument("--payload-root", type=Path, required=True)
    result.add_argument("--recovery-repository", required=True)
    result.add_argument("--recovery-ref", required=True)
    result.add_argument("--recovery-git-sha", required=True)
    result.add_argument("--recovery-git-tree", required=True)
    result.add_argument(
        "--terminal-mode", choices=("recovery", "promotion-index-only"), default="recovery"
    )
    result.add_argument("--promotion-durable-record", type=Path)
    result.add_argument("--promotion-root", type=Path)
    result.add_argument("--completion-authority-output", type=Path)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    try:
        emit_recovery(parser().parse_args())
    except (OSError, KeyError, TypeError, RecoveryError, ValueError) as exc:
        sys.stderr.write(f"rollback compatibility recovery refused: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
