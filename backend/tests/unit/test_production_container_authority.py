"""Fail-closed tests for the signed 1.9 production carrier authority."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from z4j_brain.domain import production_container_authority as authority_module
from z4j_brain.domain.production_container_authority import (
    PRODUCTION_ATTESTATION_TYPE,
    PRODUCTION_IMAGE_REPOSITORY,
    PRODUCTION_OIDC_ISSUER,
    PRODUCTION_WORKFLOW_IDENTITY,
    ProductionContainerAuthorityRefused,
    load_finalized_production_authority,
)

COSIGN_BINARY = b"sealed-cosign-3.1.3"
COSIGN_VERSION_STDOUT = '{"gitVersion":"v3.1.3"}'


def canonical_line(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def seal(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def signature_verifier() -> dict[str, object]:
    version_raw = COSIGN_VERSION_STDOUT.encode("utf-8")
    return {
        "name": "cosign",
        "version": "3.1.3",
        "runtime_path": "/usr/local/bin/cosign",
        "release_response": {
            "path": "evidence/cosign-release.json",
            "sha256": "a" * 64,
            "size": 200,
        },
        "platforms": {
            platform: {
                "filename": filename,
                "url": (f"https://github.com/sigstore/cosign/releases/download/v3.1.3/{filename}"),
                "sha256": hashlib.sha256(COSIGN_BINARY).hexdigest(),
                "size": len(COSIGN_BINARY),
                "version_output_sha256": hashlib.sha256(version_raw).hexdigest(),
                "version_output_size": len(version_raw),
            }
            for platform, filename in (
                ("linux/amd64", "cosign-linux-amd64"),
                ("linux/arm64", "cosign-linux-arm64"),
            )
        },
    }


def api_carrier(url: str, body: object) -> dict[str, object]:
    raw = canonical_line(body)
    return {
        "url": url,
        "status": 200,
        "body_base64": base64.b64encode(raw).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def replace_carrier_body(carrier: dict[str, object], body: object) -> None:
    raw = canonical_line(body)
    carrier.update(
        body_base64=base64.b64encode(raw).decode("ascii"),
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )


def actor(login: str, identity: int, node_id: str) -> dict[str, object]:
    return {"login": login, "id": identity, "node_id": node_id, "type": "User"}


def qualification_ceremony(
    *,
    revision: str,
    tree: str,
    source_authority: dict[str, object],
) -> dict[str, object]:
    source_actor = actor("release-bot", 1001, "U_source")
    automation_actor = {
        "login": "github-actions[bot]",
        "id": 41898282,
        "node_id": "MDM6Qm90NDE4OTgyODI=",
        "type": "Bot",
    }
    reviewer = actor("release-reviewer", 1002, "U_reviewer")
    source_workflow_id = 887766
    source_workflow_node_id = "W_source_tag_only"
    authority_run_id = source_authority["workflow"]["run_id"]
    authority_run_attempt = source_authority["workflow"]["run_attempt"]
    initiating_run_id = authority_run_id
    initiating_run_attempt = authority_run_attempt
    qualification_run_id = 5678
    tag_object = "f" * 40
    artifact_digest = source_authority["evidence_index"]["artifact_digest"]
    subject_digest = source_authority["evidence_index"]["index_digest"]
    inputs = {
        "authority_artifact_digest": artifact_digest,
        "authority_subject_digest": subject_digest,
        "authority_run_id": str(authority_run_id),
        "authority_run_attempt": str(authority_run_attempt),
        "initiating_source_run_id": str(initiating_run_id),
        "initiating_source_run_attempt": str(initiating_run_attempt),
        "source_tag_object": tag_object,
        "source_commit": revision,
        "source_tree": tree,
        "source_repository": "z4jdev/z4j",
        "source_workflow_id": str(source_workflow_id),
        "source_workflow_node_id": source_workflow_node_id,
        "source_workflow_path": ".github/workflows/source-tag-only.yml",
        "initiating_actor": source_actor["login"],
    }
    nonce = hashlib.sha256(
        canonical_line(
            {
                "schema": "z4j.release-docker-source-authority-handoff.v1",
                "inputs": inputs,
            },
        ),
    ).hexdigest()
    run_name = f"source-tag-handoff-{initiating_run_id}-{initiating_run_attempt}-{nonce[:16]}"
    inputs["handoff_nonce"] = nonce
    inputs["handoff_run_name"] = run_name
    base = "https://api.github.com/repos/z4jdev/z4j"
    qualification_api = f"{base}/actions/runs/{qualification_run_id}"
    qualification_html = f"https://github.com/z4jdev/z4j/actions/runs/{qualification_run_id}"
    source_api = f"{base}/actions/runs/{initiating_run_id}"
    source_html = f"https://github.com/z4jdev/z4j/actions/runs/{initiating_run_id}"
    repository_api = {
        "full_name": "z4jdev/z4j",
        "id": 1228454287,
        "node_id": "R_kgDOSTi5jw",
        "private": False,
        "visibility": "public",
        "default_branch": "main",
    }
    qualification_run = {
        "id": qualification_run_id,
        "run_attempt": 1,
        "workflow_id": 270520651,
        "url": qualification_api,
        "html_url": qualification_html,
        "event": "workflow_dispatch",
        "head_branch": "v1.9.0",
        "head_sha": revision,
        "display_title": run_name,
        "status": "in_progress",
        "conclusion": None,
        "actor": automation_actor,
        "triggering_actor": automation_actor,
        "repository": repository_api,
    }
    source_run = {
        "id": initiating_run_id,
        "run_attempt": initiating_run_attempt,
        "workflow_id": source_workflow_id,
        "url": source_api,
        "html_url": source_html,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": revision,
        "display_title": "source-tag-only-v1.9.0",
        "status": "completed",
        "conclusion": "success",
        "actor": source_actor,
        "triggering_actor": source_actor,
        "repository": repository_api,
    }
    approval = [
        {
            "state": "approved",
            "environments": [{"id": 41, "node_id": "ENV_source", "name": "production-release"}],
            "user": reviewer,
        },
    ]
    qualification_approval = [
        {
            "state": "approved",
            "environments": [
                {
                    "id": 42,
                    "node_id": "ENV_qualification",
                    "name": "production-qualification",
                },
            ],
            "user": reviewer,
        },
    ]
    source_jobs = {
        "total_count": 1,
        "jobs": [
            {
                "id": 7101,
                "run_id": initiating_run_id,
                "head_sha": revision,
                "name": "Validate and create only immutable v1.9.0",
                "status": "completed",
                "conclusion": "success",
            },
        ],
    }
    protection_environment = {
        "name": "production-qualification",
        "prevent_self_review": True,
        "reviewers": [reviewer],
        "allowed_refs": {"mode": "selected", "patterns": ["refs/tags/v1.9.0"]},
    }
    actions = {
        "enabled": True,
        "allowed_actions": "selected",
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
        "github_owned_allowed": True,
        "verified_allowed": False,
        "patterns_allowed": ["actions/checkout@*"],
        "write_grants": [
            {
                "workflow_path": ".github/workflows/source-tag-only.yml",
                "permissions": {
                    "actions": "write",
                    "contents": "write",
                    "id-token": "write",
                },
            },
        ],
    }
    workflow = {
        "id": 270520651,
        "node_id": "W_kwDOSTi5j84QH9FL",
        "name": "release-docker",
        "path": ".github/workflows/release-docker.yml",
        "state": "active",
        "ref": "refs/tags/v1.9.0",
        "sha": revision,
    }
    run_group = {
        "run": api_carrier(source_api, source_run),
        "jobs": api_carrier(
            f"{source_api}/jobs?filter=all&per_page=100&page=1",
            source_jobs,
        ),
        "approvals": api_carrier(f"{source_api}/approvals", approval),
    }
    return {
        "format": "z4j-production-qualification-ceremony-v1",
        "handoff": {
            "schema": "z4j.release-docker-source-authority-handoff.v1",
            "api_version": "2026-03-10",
            "request": {
                "ref": "v1.9.0",
                "inputs": inputs,
                "return_run_details": True,
            },
            "response": {
                "status": 200,
                "body": {
                    "workflow_run_id": qualification_run_id,
                    "run_url": qualification_api,
                    "html_url": qualification_html,
                },
            },
            "authority": {
                "artifact_digest": artifact_digest,
                "subject_digest": subject_digest,
                "run_id": authority_run_id,
                "run_attempt": authority_run_attempt,
            },
            "initiating_source": {
                "run_id": initiating_run_id,
                "run_attempt": initiating_run_attempt,
                "actor": source_actor,
                "workflow": {
                    "id": source_workflow_id,
                    "node_id": source_workflow_node_id,
                    "path": ".github/workflows/source-tag-only.yml",
                },
            },
            "source": {
                "repository": "z4jdev/z4j",
                "tag": "v1.9.0",
                "tag_object": tag_object,
                "commit": revision,
                "tree": tree,
            },
            "handoff_nonce": nonce,
            "handoff_run_name": run_name,
        },
        "qualification": {
            "repository": {
                "full_name": "z4jdev/z4j",
                "id": 1228454287,
                "node_id": "R_kgDOSTi5jw",
            },
            "workflow": workflow,
            "run": {
                "id": qualification_run_id,
                "run_attempt": 1,
                "workflow_id": 270520651,
                "api_url": qualification_api,
                "html_url": qualification_html,
                "event": "workflow_dispatch",
                "ref": "refs/tags/v1.9.0",
                "head_branch": "v1.9.0",
                "head_sha": revision,
                "display_title": run_name,
                "status_at_receipt": "in_progress",
                "conclusion_at_receipt": None,
                "actor": automation_actor,
                "triggering_actor": automation_actor,
            },
            "deployment": {
                "environment": {
                    "id": 42,
                    "node_id": "ENV_qualification",
                    "name": "production-qualification",
                },
                "job_id": 7201,
                "job_name": "Qualify finalized production containers",
                "approval_state": "approved",
                "reviewer": reviewer,
                "prevent_self_review": True,
            },
        },
        "protection": {
            "repository": {
                "full_name": "z4jdev/z4j",
                "id": 1228454287,
                "node_id": "R_kgDOSTi5jw",
            },
            "workflow": workflow,
            "environment": protection_environment,
            "actions": actions,
            "settings_authority": {
                "format": "z4j-release-settings-authority-v1",
                "sha256": "9" * 64,
                "size": 999,
                "automation_principal": automation_actor,
            },
        },
        "readback": {
            "qualification": {
                "run": api_carrier(qualification_api, qualification_run),
                "jobs": api_carrier(
                    f"{qualification_api}/jobs?filter=all&per_page=100&page=1",
                    {
                        "total_count": 1,
                        "jobs": [
                            {
                                "id": 7201,
                                "run_id": qualification_run_id,
                                "head_sha": revision,
                                "name": "Qualify finalized production containers",
                                "status": "in_progress",
                                "conclusion": None,
                            },
                        ],
                    },
                ),
                "approvals": api_carrier(
                    f"{qualification_api}/approvals",
                    qualification_approval,
                ),
            },
            "initiating_source": run_group,
            "authority_source": run_group,
            "source_git": {
                "tag_ref": api_carrier(
                    f"{base}/git/ref/tags/v1.9.0",
                    {"ref": "refs/tags/v1.9.0", "object": {"type": "tag", "sha": tag_object}},
                ),
                "tag_object": api_carrier(
                    f"{base}/git/tags/{tag_object}",
                    {
                        "sha": tag_object,
                        "tag": "v1.9.0",
                        "message": "Release 1.9.0",
                        "tagger": {
                            "name": "pypv",
                            "email": "106410335+pypv@users.noreply.github.com",
                            "date": "2026-08-20T12:00:00Z",
                        },
                        "object": {"type": "commit", "sha": revision},
                    },
                ),
                "commit": api_carrier(
                    f"{base}/git/commits/{revision}",
                    {
                        "sha": revision,
                        "tree": {"sha": tree},
                        "committer": {"date": "2026-08-20T12:00:00Z"},
                    },
                ),
                "tree": api_carrier(f"{base}/git/trees/{tree}", {"sha": tree, "tree": []}),
            },
            "settings": {
                "repository": api_carrier(base, repository_api),
                "workflow": api_carrier(
                    f"{base}/actions/workflows/270520651",
                    {key: workflow[key] for key in ("id", "node_id", "name", "path", "state")},
                ),
                "environment": api_carrier(
                    f"{base}/environments/production-qualification",
                    {"id": 42, "node_id": "ENV_qualification", "name": "production-qualification"},
                ),
                "tag_ruleset": api_carrier(
                    f"{base}/rulesets/123",
                    {
                        "id": 123,
                        "name": "immutable-v-tags",
                        "target": "tag",
                        "enforcement": "active",
                        "bypass_actors": [],
                        "conditions": {
                            "ref_name": {
                                "include": ["refs/tags/v*.*.*"],
                                "exclude": [],
                            },
                        },
                        "rules": [{"type": "deletion"}, {"type": "update"}],
                    },
                ),
                "actions_permissions": api_carrier(
                    f"{base}/actions/permissions",
                    {"enabled": True, "allowed_actions": "selected"},
                ),
                "allowed_actions": api_carrier(
                    f"{base}/actions/permissions/selected-actions",
                    {
                        "github_owned_allowed": True,
                        "verified_allowed": False,
                        "patterns_allowed": ["actions/checkout@*"],
                    },
                ),
            },
        },
        "verification": {"result": "pass"},
    }


@dataclass
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Cosign:
    def __init__(self, *, verify_returncode: int = 0) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.verify_returncode = verify_returncode
        self.attestation_stdout = ""

    def __call__(self, command: object) -> Result:
        parsed = tuple(command)
        self.commands.append(parsed)
        if parsed[1:3] == ("version", "--json"):
            return Result(0, COSIGN_VERSION_STDOUT)
        if parsed[1:2] == ("verify-attestation",):
            return Result(self.verify_returncode, self.attestation_stdout)
        return Result(self.verify_returncode, "Verified OK" if not self.verify_returncode else "")


def native_receipt(
    *,
    arch: str,
    revision: str,
    tree: str,
    manifest_hash: str,
    source_hash: str,
    manifest_raw: bytes,
    config_raw: bytes,
) -> dict[str, object]:
    wheelhouse_digest = "sha256:" + ("1" * 64)
    system_digest = "sha256:" + ("2" * 64)
    dashboard_digest = "sha256:" + ("3" * 64)
    labels = {
        "org.opencontainers.image.revision": revision,
        "org.z4j.production.dashboard-bundle.index": dashboard_digest,
        "org.z4j.production.manifest.sha256": manifest_hash,
        "org.z4j.production.source-projection.sha256": source_hash,
        "org.z4j.production.system-bundle.index": system_digest,
        "org.z4j.production.wheelhouse.index": wheelhouse_digest,
    }
    return {
        "format": "z4j-production-native-build-v1",
        "release_git_commit": revision,
        "release_git_tree": tree,
        "platform": f"linux/{arch}",
        "contract": {
            "manifest_sha256": manifest_hash,
            "source_projection_sha256": source_hash,
        },
        "python": {"version": "3.14.7"},
        "signature_verifier": signature_verifier(),
        "wheelhouse": {"index": {"digest": wheelhouse_digest}},
        "system_packages": {"index": {"digest": system_digest}},
        "dashboard": {"index": {"digest": dashboard_digest}},
        "candidate": {
            "build_output_digest": "sha256:" + ("e" * 64),
            "manifest_digest": digest(manifest_raw),
            "manifest_size": len(manifest_raw),
            "config_digest": digest(config_raw),
            "config_size": len(config_raw),
            "labels": labels,
        },
        "install": {"result": "pass"},
        "cadence_probe": {"sha256": "4" * 64, "size": 100},
        "signature_verifier_probe": {"sha256": "0" * 64, "size": 106},
        "dashboard_replay": {"sha256": "9" * 64, "size": 105},
        "service_smoke": {"sha256": "b" * 64, "size": 107},
        "candidate_sbom": {
            "cyclonedx": {"sha256": "5" * 64, "size": 101},
            "spdx": {"sha256": "6" * 64, "size": 102},
        },
        "candidate_scanner": {"verdict": "pass", "trivy_version": "0.74.0"},
    }


def authority_fixture(
    root: Path,
    *,
    receipt_mutator: Any = None,
) -> tuple[dict[str, object], dict[tuple[str, str], bytes], str]:
    revision = "a" * 40
    tree = "b" * 40
    manifest_hash = "c" * 64
    source_hash = "d" * 64
    configs: dict[str, bytes] = {}
    manifests: dict[str, bytes] = {}
    natives: dict[str, dict[str, object]] = {}
    for arch in ("amd64", "arm64"):
        wheelhouse_digest = "sha256:" + ("1" * 64)
        system_digest = "sha256:" + ("2" * 64)
        dashboard_digest = "sha256:" + ("3" * 64)
        labels = {
            "org.opencontainers.image.revision": revision,
            "org.z4j.production.dashboard-bundle.index": dashboard_digest,
            "org.z4j.production.manifest.sha256": manifest_hash,
            "org.z4j.production.source-projection.sha256": source_hash,
            "org.z4j.production.system-bundle.index": system_digest,
            "org.z4j.production.wheelhouse.index": wheelhouse_digest,
        }
        config_raw = canonical_line(
            {
                "architecture": arch,
                "os": "linux",
                "config": {
                    "Labels": {
                        **labels,
                        "org.opencontainers.image.version": "1.9.0",
                    },
                },
            },
        )
        manifest_raw = canonical_line(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": digest(config_raw),
                    "size": len(config_raw),
                },
                "layers": [],
            },
        )
        configs[arch] = config_raw
        manifests[arch] = manifest_raw
        natives[arch] = native_receipt(
            arch=arch,
            revision=revision,
            tree=tree,
            manifest_hash=manifest_hash,
            source_hash=source_hash,
            manifest_raw=manifest_raw,
            config_raw=config_raw,
        )
    index_raw = canonical_line(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": digest(manifests[arch]),
                    "size": len(manifests[arch]),
                    "platform": {"architecture": arch, "os": "linux"},
                }
                for arch in ("amd64", "arm64")
            ],
        },
    )
    index_digest = digest(index_raw)
    source_tag_authority = {
        "repository": "z4jdev/z4j",
        "tag": "v1.9.0",
        "commit": revision,
        "tree": tree,
        "receipt": {"sha256": "1" * 64, "size": 801},
        "bundle": {"sha256": "2" * 64, "size": 802},
        "evidence_index": {
            "sha256": "3" * 64,
            "size": 803,
            "artifact_digest": "sha256:" + ("3" * 64),
            "index_digest": "sha256:" + ("1" * 64),
        },
        "workflow": {"run_id": 1234, "run_attempt": 1},
        "verification": {"result": "pass"},
    }
    receipt: dict[str, object] = {
        "format": "z4j-production-container-finalization-v1",
        "release": "1.9.0",
        "release_git_commit": revision,
        "release_git_tree": tree,
        "manifest_sha256": manifest_hash,
        "production_source_projection_sha256": source_hash,
        "source_tag_authority": source_tag_authority,
        "qualification_ceremony": qualification_ceremony(
            revision=revision,
            tree=tree,
            source_authority=source_tag_authority,
        ),
        "signature_verifier": signature_verifier(),
        "candidate_index": {
            "image": PRODUCTION_IMAGE_REPOSITORY,
            "digest": index_digest,
            "sha256": hashlib.sha256(index_raw).hexdigest(),
            "size": len(index_raw),
        },
        "dashboard_sbom": {
            "cyclonedx": {"sha256": "7" * 64, "size": 103},
            "spdx": {"sha256": "8" * 64, "size": 104},
        },
        "native": natives,
        "native_receipts": {
            arch: seal(canonical_line(natives[arch])) for arch in ("amd64", "arm64")
        },
    }
    if receipt_mutator is not None:
        receipt_mutator(receipt)
    receipt_raw = canonical_line(receipt)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": PRODUCTION_IMAGE_REPOSITORY,
                "digest": {"sha256": index_digest.removeprefix("sha256:")},
            },
        ],
        "predicateType": PRODUCTION_ATTESTATION_TYPE,
        "predicate": receipt,
    }
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(canonical_line(statement)).decode("ascii"),
        "signatures": [{"sig": "test"}],
    }
    root.mkdir()
    (root / "production-finalization.json").write_bytes(receipt_raw)
    (root / "production-finalization.bundle.json").write_bytes(b"{}\n")
    (root / "production-finalization.attestation.jsonl").write_bytes(canonical_line(envelope))
    (root / "staging-index.json").write_bytes(index_raw)
    registry = {
        ("manifest", digest(index_raw)): index_raw,
        **{("manifest", digest(manifests[arch])): manifests[arch] for arch in ("amd64", "arm64")},
        **{("blob", digest(configs[arch])): configs[arch] for arch in ("amd64", "arm64")},
    }
    source_image = f"{PRODUCTION_IMAGE_REPOSITORY}@{digest(index_raw)}"
    return receipt, registry, source_image


def load(root: Path, registry: dict[tuple[str, str], bytes], source_image: str, cosign: Cosign):
    cosign.attestation_stdout = (root / "production-finalization.attestation.jsonl").read_text(
        encoding="utf-8"
    )
    return load_finalized_production_authority(
        root,
        source_image_assertion=source_image,
        cosign_runner=cosign,
        binary_reader=lambda _path: COSIGN_BINARY,
        runtime_machine="x86_64",
        registry_fetcher=lambda kind, value: registry[(kind, value)],
    )


def test_finalized_authority_binds_receipt_sigstore_and_oci(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    receipt, registry, source_image = authority_fixture(root)
    cosign = Cosign()

    result = load(root, registry, source_image, cosign)

    assert result["source_revision"] == receipt["release_git_commit"]
    assert result["source_tag_authority"] == receipt["source_tag_authority"]
    assert result["source_image"] == source_image
    assert result["candidate_index"] == receipt["candidate_index"]
    assert len(result["authority_sha256"]) == 64
    verify = cosign.commands[1]
    assert verify[:2] == ("/usr/local/bin/cosign", "verify-blob")
    assert verify[verify.index("--certificate-identity") + 1] == PRODUCTION_WORKFLOW_IDENTITY
    assert verify[verify.index("--certificate-oidc-issuer") + 1] == PRODUCTION_OIDC_ISSUER
    verified_receipt = Path(verify[-1])
    verified_bundle = Path(verify[verify.index("--bundle") + 1])
    assert verified_receipt.parent != root
    assert not verified_receipt.exists()
    assert not verified_bundle.exists()


def test_authority_cosign_verifies_captured_bytes_not_mutable_root(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    expected_receipt = (root / "production-finalization.json").read_bytes()
    expected_bundle = (root / "production-finalization.bundle.json").read_bytes()

    class SwappingCosign(Cosign):
        def __call__(self, command: object) -> Result:
            parsed = tuple(command)
            result = super().__call__(parsed)
            if parsed[1:2] == ("verify-blob",):
                receipt_path = Path(parsed[-1])
                bundle_path = Path(parsed[parsed.index("--bundle") + 1])
                assert receipt_path.read_bytes() == expected_receipt
                assert bundle_path.read_bytes() == expected_bundle
                assert receipt_path.parent != root
                (root / "production-finalization.json").write_bytes(b"swapped\n")
                (root / "production-finalization.bundle.json").write_bytes(b"swapped\n")
            return result

    result = load(root, registry, source_image, SwappingCosign())

    assert result["source_image"] == source_image


def test_authority_rejects_caller_image_claim(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, _source_image = authority_fixture(root)
    with pytest.raises(ProductionContainerAuthorityRefused, match="caller source image"):
        load(root, registry, f"{PRODUCTION_IMAGE_REPOSITORY}@sha256:" + ("f" * 64), Cosign())


def test_authority_rejects_extra_inventory_member(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    (root / "untrusted.json").write_text("{}", encoding="ascii")
    with pytest.raises(ProductionContainerAuthorityRefused, match="exactly four"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_symlink_member(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    bundle = root / "production-finalization.bundle.json"
    bundle.unlink()
    bundle.symlink_to(root / "production-finalization.json")
    with pytest.raises(ProductionContainerAuthorityRefused, match="regular file"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_symlink_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-authority"
    _, registry, source_image = authority_fixture(real_root)
    root = tmp_path / "authority"
    root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ProductionContainerAuthorityRefused, match="absent or unsafe"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_cosign_failure(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    with pytest.raises(ProductionContainerAuthorityRefused, match="Sigstore"):
        load(root, registry, source_image, Cosign(verify_returncode=1))


def test_authority_rejects_unsealed_cosign_binary(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    with pytest.raises(ProductionContainerAuthorityRefused, match="runtime bytes"):
        load_finalized_production_authority(
            root,
            source_image_assertion=source_image,
            cosign_runner=Cosign(),
            binary_reader=lambda _path: b"different-cosign",
            runtime_machine="x86_64",
            registry_fetcher=lambda kind, value: registry[(kind, value)],
        )


def test_authority_rejects_unsealed_cosign_version_output(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)

    class DifferentVersionOutput(Cosign):
        def __call__(self, command: object) -> Result:
            parsed = tuple(command)
            if parsed[1:3] == ("version", "--json"):
                return Result(0, '{"gitVersion":"v3.1.3"}\n')
            return super().__call__(parsed)

    with pytest.raises(ProductionContainerAuthorityRefused, match="version output"):
        load(root, registry, source_image, DifferentVersionOutput())


def test_default_cosign_runner_uses_absolute_path_and_closed_environment(monkeypatch) -> None:
    captured: dict[str, object] = {}
    real_popen = authority_module.subprocess.Popen

    def popen(command: object, **kwargs: object) -> object:
        captured["command"] = command
        captured.update(kwargs)
        return real_popen(["/usr/bin/printf", "ok"], **kwargs)

    monkeypatch.setattr(authority_module.subprocess, "Popen", popen)
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("ld_library_path", "/tmp/evil")
    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/evil-ca.pem")
    monkeypatch.setenv("HOME", "/tmp/evil-home")

    result = authority_module._default_cosign_runner(("/private/cosign", "version", "--json"))
    assert result.stdout == "ok"

    assert captured["command"] == ["/private/cosign", "version", "--json"]
    assert captured["cwd"] == "/"
    assert captured["env"] == authority_module._COSIGN_ENV
    assert not set(captured["env"]) & {
        "LD_PRELOAD",
        "ld_library_path",
        "HTTPS_PROXY",
        "SSL_CERT_FILE",
        "HOME",
    }
    with pytest.raises(ProductionContainerAuthorityRefused, match="absolute executable"):
        authority_module._default_cosign_runner(("cosign", "version"))


def test_default_cosign_runner_kills_group_on_output_overflow(monkeypatch) -> None:
    monkeypatch.setattr(authority_module, "_MAX_COSIGN_STDOUT_BYTES", 32)
    killed: list[int] = []
    real_killpg = authority_module.os.killpg

    def killpg(group: int, signal_number: int) -> None:
        killed.append(group)
        real_killpg(group, signal_number)

    monkeypatch.setattr(authority_module.os, "killpg", killpg)
    with pytest.raises(ProductionContainerAuthorityRefused, match="stdout exceeded"):
        authority_module._default_cosign_runner(
            ("/usr/bin/python3", "-c", "import sys; sys.stdout.write('x' * 4096)")
        )
    assert len(killed) == 1


def test_default_cosign_runner_kills_descendants_on_timeout(monkeypatch) -> None:
    monkeypatch.setattr(authority_module, "_COSIGN_TIMEOUT_SECONDS", 0.1)
    killed: list[int] = []
    real_killpg = authority_module.os.killpg

    def killpg(group: int, signal_number: int) -> None:
        killed.append(group)
        real_killpg(group, signal_number)

    monkeypatch.setattr(authority_module.os, "killpg", killpg)
    with pytest.raises(ProductionContainerAuthorityRefused, match="process group"):
        authority_module._default_cosign_runner(
            (
                "/usr/bin/python3",
                "-c",
                "import subprocess,time; subprocess.Popen(['/usr/bin/sleep','10']); time.sleep(10)",
            )
        )
    assert len(killed) == 1


def test_default_cosign_is_private_and_rejects_source_byte_race(
    tmp_path: Path,
    monkeypatch,
) -> None:
    del tmp_path
    reads = iter((COSIGN_BINARY, b"swapped-cosign"))
    observed: dict[str, object] = {}

    def reader(_path: Path) -> bytes:
        return next(reads)

    def runner(_command: object) -> Result:
        return Result(0)

    def verify_with_runner(
        _members: object,
        *,
        expected_binary: object,
        candidate_reference: str,
        runner: object,
        executable: str,
    ) -> None:
        private = Path(executable)
        observed.update(
            expected_binary=expected_binary,
            candidate_reference=candidate_reference,
            runner=runner,
            executable=executable,
            bytes=private.read_bytes(),
            mode=private.stat().st_mode & 0o777,
        )

    monkeypatch.setattr(authority_module, "_default_binary_reader", reader)
    monkeypatch.setattr(authority_module, "_default_cosign_runner", runner)
    monkeypatch.setattr(authority_module, "_verify_cosign_with_runner", verify_with_runner)
    with pytest.raises(ProductionContainerAuthorityRefused, match="changed during"):
        authority_module._verify_cosign(
            {},
            signature_verifier=signature_verifier(),
            candidate_reference="docker.io/z4jdev/z4j@sha256:" + "a" * 64,
            runner=runner,
            binary_reader=reader,
            runtime_machine="x86_64",
        )
    assert observed["bytes"] == COSIGN_BINARY
    assert observed["mode"] == 0o500
    assert str(observed["executable"]) != "/usr/local/bin/cosign"


def test_registry_opener_disables_proxies_and_redirects(monkeypatch) -> None:
    handlers: list[object] = []

    class Context:
        minimum_version: object = None
        check_hostname = False
        verify_mode: object = None

        def load_verify_locations(self, **_kwargs: object) -> None:
            return None

    monkeypatch.setattr(
        authority_module.os,
        "stat",
        lambda *_args, **_kwargs: type("Metadata", (), {"st_mode": 0o100444, "st_uid": 0})(),
    )
    monkeypatch.setattr(authority_module.ssl, "SSLContext", lambda *_args: Context())

    def build_opener(*values: object) -> object:
        handlers.extend(values)
        return object()

    monkeypatch.setattr(authority_module.urllib.request, "build_opener", build_opener)
    monkeypatch.setenv("https_proxy", "https://attacker.invalid")
    monkeypatch.setenv("SSL_CERT_DIR", "/tmp/evil-ca")

    authority_module._registry_opener()

    proxies = [
        value
        for value in handlers
        if isinstance(value, authority_module.urllib.request.ProxyHandler)
    ]
    assert len(proxies) == 1 and proxies[0].proxies == {}
    assert any(isinstance(value, authority_module._NoRedirectHandler) for value in handlers)


def test_authority_inventory_rejects_external_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    authority_fixture(root)
    member = root / "production-finalization.json"
    external = tmp_path / "external-receipt.json"
    external.write_bytes(member.read_bytes())
    member.unlink()
    os.link(external, member)

    with pytest.raises(ProductionContainerAuthorityRefused, match="exactly one hard link"):
        authority_module._read_exact_inventory(root)


def test_authority_inventory_rejects_oversized_member(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "authority"
    authority_fixture(root)
    member = root / "production-finalization.json"
    limits = dict(authority_module._AUTHORITY_FILE_LIMITS)
    limits[member.name] = member.stat().st_size - 1
    monkeypatch.setattr(authority_module, "_AUTHORITY_FILE_LIMITS", limits)

    with pytest.raises(ProductionContainerAuthorityRefused, match="oversized"):
        authority_module._read_exact_inventory(root)


def test_authority_inventory_rejects_concurrent_growth(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "authority"
    authority_fixture(root)
    member = root / "production-finalization.json"
    real_read = authority_module.os.read
    changed = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, size)
        try:
            target = str(Path(f"/proc/self/fd/{descriptor}").readlink())
        except OSError:
            target = ""
        if chunk and not changed and target == str(member):
            changed = True
            with member.open("ab") as stream:
                stream.write(b" ")
        return chunk

    monkeypatch.setattr(authority_module.os, "read", racing_read)
    with pytest.raises(ProductionContainerAuthorityRefused, match=r"grew|changed"):
        authority_module._read_exact_inventory(root)
    assert changed is True


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schemaVersion":2,"schemaVersion":2}',
        b'{"digest":"sha256:a","digest":"sha256:b"}',
        b'{"platform":{"architecture":"amd64","architecture":"arm64"}}',
        b'{"config":{"Labels":{},"Labels":{}}}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1.5}',
    ),
)
def test_strict_json_rejects_ambiguous_numbers_and_duplicate_oci_keys(raw: bytes) -> None:
    with pytest.raises(ProductionContainerAuthorityRefused, match="not canonical"):
        authority_module._json(raw, "adversarial OCI document")


def test_registry_response_requires_exact_status_url_type_and_digest() -> None:
    class Response:
        def __init__(
            self,
            *,
            status: int = 200,
            url: str = "https://registry-1.docker.io/v2/z4jdev/z4j/manifests/sha256:x",
            content_type: str = "application/vnd.oci.image.manifest.v1+json",
            digest: str = "sha256:x",
            headers: object | None = None,
        ) -> None:
            self.status = status
            self._url = url
            self.headers = (
                headers
                if headers is not None
                else {"Content-Type": content_type, "Docker-Content-Digest": digest}
            )

        def geturl(self) -> str:
            return self._url

    expected_url = "https://registry-1.docker.io/v2/z4jdev/z4j/manifests/sha256:x"
    expected_type = {"application/vnd.oci.image.manifest.v1+json"}
    authority_module._validate_registry_response(
        Response(),
        expected_url=expected_url,
        content_types=expected_type,
        expected_digest="sha256:x",
    )
    cases = (
        (Response(status=206), "status"),
        (Response(url="https://attacker.invalid/redirect"), "URL"),
        (Response(content_type="application/json"), "content type"),
        (Response(digest="sha256:y"), "Content-Digest"),
    )
    for response, message in cases:
        (
            (
                Response(
                    headers={
                        "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                        "content-type": "application/vnd.oci.image.manifest.v1+json",
                        "Docker-Content-Digest": "sha256:x",
                    }
                ),
                "exactly one Content-Type",
            ),
        )
        (
            (
                Response(
                    headers={
                        "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                        "Docker-Content-Digest": "sha256:x",
                        "docker-content-digest": "sha256:x",
                    }
                ),
                "exactly one Docker-Content-Digest",
            ),
        )
        (
            (
                Response(content_type="application/vnd.oci.image.manifest.v1+json\r\n folded"),
                "folding",
            ),
        )
        with pytest.raises(ProductionContainerAuthorityRefused, match=message):
            authority_module._validate_registry_response(
                response,
                expected_url=expected_url,
                content_types=expected_type,
                expected_digest="sha256:x",
            )


def test_authority_rejects_registry_leaf_drift(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    receipt, registry, source_image = authority_fixture(root)
    manifest_digest = receipt["native"]["amd64"]["candidate"]["manifest_digest"]
    registry[("manifest", manifest_digest)] += b"drift"
    with pytest.raises(ProductionContainerAuthorityRefused, match="registry bytes differ"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_noncanonical_receipt(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    receipt, registry, source_image = authority_fixture(root)
    (root / "production-finalization.json").write_text(
        json.dumps(receipt, indent=2),
        encoding="ascii",
    )
    with pytest.raises(ProductionContainerAuthorityRefused, match="not canonical"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_unfinalized_null_seals(tmp_path: Path) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        receipt["candidate_index"]["digest"] = None

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused):
        load(root, registry, source_image, Cosign())


def test_authority_accepts_duplicate_identical_authenticated_attestations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    transcript = (root / "production-finalization.attestation.jsonl").read_bytes()
    (root / "production-finalization.attestation.jsonl").write_bytes(transcript * 2)

    result = load(root, registry, source_image, Cosign())

    assert result["source_image"] == source_image


def test_authority_rejects_conflicting_authenticated_attestation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    transcript = (root / "production-finalization.attestation.jsonl").read_bytes()
    envelope = json.loads(transcript)
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    statement["predicateType"] = "https://example.invalid/conflict"
    envelope["payload"] = base64.b64encode(canonical_line(statement)).decode("ascii")
    (root / "production-finalization.attestation.jsonl").write_bytes(
        transcript + canonical_line(envelope),
    )

    with pytest.raises(ProductionContainerAuthorityRefused, match="one unique statement"):
        load(root, registry, source_image, Cosign())


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (("repository",), "other/z4j", "repository"),
        (("tag",), "v1.9.1", "source tag"),
        (("commit",), "f" * 40, "commit"),
        (("tree",), "e" * 40, "tree"),
        (("receipt", "sha256"), "not-a-sha", "SHA-256"),
        (("evidence_index", "artifact_digest"), "sha256:bad", "OCI"),
        (("workflow", "run_id"), 0, "positive"),
        (("evidence_index", "sha256"), "4" * 64, "does not equal"),
        (("evidence_index", "index_digest"), "sha256:" + ("5" * 64), "wheelhouse"),
        (("verification", "result"), "fail", "verification"),
    ),
)
def test_authority_rejects_source_tag_substitution(
    path: tuple[str, ...],
    replacement: object,
    message: str,
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        cursor = receipt["source_tag_authority"]
        for part in path[:-1]:
            cursor = cursor[part]
        cursor[path[-1]] = replacement

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match=message):
        load(root, registry, source_image, Cosign())


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (("format",), "z4j-production-qualification-ceremony-v2", "format"),
        (
            ("handoff", "request", "inputs", "authority_artifact_digest"),
            "sha256:" + ("e" * 64),
            "artifact",
        ),
        (("handoff", "authority", "run_id"), 9999, "authority run id"),
        (("handoff", "source", "tag_object"), "e" * 40, "handoff source"),
        (("qualification", "repository", "full_name"), "other/z4j", "repository"),
        (("qualification", "workflow", "ref"), "refs/heads/main", "workflow"),
        (("qualification", "run", "workflow_id"), 999, "workflow id"),
        (("qualification", "run", "status_at_receipt"), "completed", "receipt status"),
        (
            ("qualification", "run", "conclusion_at_receipt"),
            "success",
            "receipt conclusion",
        ),
        (
            ("qualification", "deployment", "reviewer"),
            {"login": "release-bot", "id": 1001, "node_id": "U_source", "type": "User"},
            "independent",
        ),
        (
            ("protection", "environment", "allowed_refs"),
            {"mode": "selected", "patterns": ["refs/heads/main"]},
            "allowed_refs",
        ),
        (
            ("readback", "source_git", "tag_object", "url"),
            "https://api.github.com/repos/z4jdev/z4j/git/tags/" + ("e" * 40),
            "url",
        ),
        (("verification", "result"), "fail", "verification"),
    ),
)
def test_authority_rejects_qualification_ceremony_substitution(
    path: tuple[str, ...],
    replacement: object,
    message: str,
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        cursor = receipt["qualification_ceremony"]
        for part in path[:-1]:
            cursor = cursor[part]
        cursor[path[-1]] = replacement

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match=message):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_realized_tag_object_in_detached_source_projection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        receipt["source_tag_authority"]["tag_object"] = "f" * 40

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match="keys differ"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_noncanonical_qualification_readback_body(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        carrier = receipt["qualification_ceremony"]["readback"]["settings"]["actions_permissions"]
        raw = b'{"enabled":true,"enabled":true}\n'
        carrier.update(
            {
                "body_base64": base64.b64encode(raw).decode("ascii"),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            },
        )

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match="not canonical"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_float_in_qualification_readback_body(tmp_path: Path) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        carrier = receipt["qualification_ceremony"]["readback"]["settings"]["actions_permissions"]
        raw = b'{"allowed_actions":"selected","enabled":true,"risk":1.5}\n'
        carrier.update(
            {
                "body_base64": base64.b64encode(raw).decode("ascii"),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            },
        )

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match="floating-point"):
        load(root, registry, source_image, Cosign())


def test_authority_rejects_source_tag_date_drift(tmp_path: Path) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        carrier = receipt["qualification_ceremony"]["readback"]["source_git"]["commit"]
        body = json.loads(base64.b64decode(carrier["body_base64"], validate=True))
        body["committer"]["date"] = "2026-08-20T12:00:01Z"
        replace_carrier_body(carrier, body)

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match="tag/commit date"):
        load(root, registry, source_image, Cosign())


def test_authority_accepts_observed_user_automation_principal(tmp_path: Path) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        ceremony = receipt["qualification_ceremony"]
        observed_actor = {
            "login": "release-automation",
            "id": 1003,
            "node_id": "U_automation",
            "type": "User",
        }
        ceremony["qualification"]["run"]["actor"] = observed_actor
        ceremony["qualification"]["run"]["triggering_actor"] = observed_actor
        ceremony["protection"]["settings_authority"]["automation_principal"] = observed_actor
        carrier = ceremony["readback"]["qualification"]["run"]
        body = json.loads(base64.b64decode(carrier["body_base64"], validate=True))
        body["actor"] = observed_actor
        body["triggering_actor"] = observed_actor
        replace_carrier_body(carrier, body)

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)

    result = load(root, registry, source_image, Cosign())

    assert result["qualification_ceremony"]["qualification"]["run"]["actor"]["type"] == "User"


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (
            ("qualification", "run", "actor", "type"),
            "Organization",
            "actor.type",
        ),
        (
            ("qualification", "deployment", "reviewer", "type"),
            "Bot",
            "reviewer.type",
        ),
        (
            ("protection", "settings_authority", "automation_principal"),
            None,
            "automation principal",
        ),
        (
            ("qualification", "run", "run_attempt"),
            2,
            "run attempt",
        ),
    ),
)
def test_authority_rejects_unsupported_principal_types(
    path: tuple[str, ...],
    replacement: object,
    message: str,
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"

    def mutate(receipt: dict[str, object]) -> None:
        cursor = receipt["qualification_ceremony"]
        for part in path[:-1]:
            cursor = cursor[part]
        cursor[path[-1]] = replacement

    _, registry, source_image = authority_fixture(root, receipt_mutator=mutate)
    with pytest.raises(ProductionContainerAuthorityRefused, match=message):
        load(root, registry, source_image, Cosign())


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("payloadType", "application/json", "payload type"),
        ("statement._type", "https://example.invalid/Statement/v1", "statement type"),
        ("statement.subject.0.name", "docker.io/example/wrong", "subject repository"),
    ),
)
def test_authority_rejects_noncanonical_dsse_contract(
    field: str,
    replacement: str,
    message: str,
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"
    _, registry, source_image = authority_fixture(root)
    path = root / "production-finalization.attestation.jsonl"
    envelope = json.loads(path.read_bytes())
    if field == "payloadType":
        envelope[field] = replacement
    else:
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if field == "statement._type":
            statement["_type"] = replacement
        else:
            statement["subject"][0]["name"] = replacement
        envelope["payload"] = base64.b64encode(canonical_line(statement)).decode("ascii")
    path.write_bytes(canonical_line(envelope))

    with pytest.raises(ProductionContainerAuthorityRefused, match=message):
        load(root, registry, source_image, Cosign())
