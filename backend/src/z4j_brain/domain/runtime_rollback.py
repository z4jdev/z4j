"""Sealed runtime authority for the 1.9.0 -> 1.8.2 rollback ceremony.

This module deliberately knows one target.  It is not a general downgrade
framework and it must never turn a caller-provided fingerprint into authority.
The separately built compatibility image and the running 1.9 carrier both have
to produce the complete payload below before schedule state can be prepared.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from importlib import util as importlib_util
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from z4j_brain.domain.schedule_cadence import (
    cadence_behavior_vector_digest,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_runtime import cadence_runtime_payload

ROLLBACK_TARGET = "1.8.2-py3.14.7-rollback-1.9.0"
ROLLBACK_TARGET_RELEASE = "1.8.2"
ROLLBACK_TARGET_IMAGE_REPOSITORY = "docker.io/z4jdev/z4j"
ROLLBACK_TARGET_OCI_TAG = "z4jdev/z4j:1.8.2-py3.14.7-rollback-1.9.0"
ROLLBACK_TARGET_SOURCE_COMMIT = "891d66f77cd87b93311eaf2ed8189e1780430e2c"
ROLLBACK_TARGET_SOURCE_TREE = "0913546d59a4661ca2f2e17512ec2acfc46305ea"
ROLLBACK_MANIFEST_RESOURCE = "rollback-1.8.2-py3147-manifest.json"
ROLLBACK_MANIFEST_SOURCE = Path(
    "docker/rollback-1.8.2-py3147/manifest.json",
)
ROLLBACK_DURABLE_EVIDENCE_SOURCE = Path(
    "docker/rollback-1.8.2-py3147/durable_evidence.py",
)
ROLLBACK_DURABLE_EVIDENCE_ENV = "Z4J_ROLLBACK_COMPAT_EVIDENCE_ROOT"
ROLLBACK_COSIGN_PATH = Path("/usr/local/bin/cosign")
_OLD_IMAGE_INDEX = "sha256:ed2dac96f24b4ea42fcc89e76f459035365229d62f9d8efe916741cfd9373c03"
_PYTHON_CARRIER_INDEX = "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
_QUALIFICATION_RECEIPT_FORMAT = "z4j-rollback-compat-qualification-receipt-v1"
_FINALIZATION_RECEIPT_FORMAT = "z4j-rollback-compat-finalization-receipt-v1"
_PROMOTION_EVIDENCE_FORMAT = "z4j-rollback-compat-promotion-evidence-v1"
_RECOVERY_EVIDENCE_FORMAT = "z4j-rollback-compat-recovery-evidence-v1"
_RELEASE_EVIDENCE_INDEX_FORMAT = "z4j-rollback-compat-release-evidence-index-v1"
_RELEASE_RECEIPT_SEMANTICS = (
    "sha256 of canonical manifest-independent qualification receipt; never a receipt "
    "that hashes this manifest"
)
_FINALIZATION_RULE = (
    "qualification builds and seals one untagged digest while finalized=false; source "
    "finalization sets finalized=true and copies only the qualification receipt's exact "
    "index/platform/config descriptors and SHA-256; finalization rereads those original "
    "bytes, authenticates the exact preconfigured Docker Hub immutable-tag rule, and "
    "emits a detached receipt before create-only sole-tag promotion"
)
_PUBLICATION_GATE_SHA256 = "04679f8790585cdc2bf99c267bbc84498a874cda6a0f0dbf961ccdbb500feb9c"
_DURABLE_GRAPH_FORMAT = "z4j-rollback-compat-portable-evidence-graph-verification-v1"

_DIGEST = r"sha256:[0-9a-f]{64}"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OCI_DIGEST = re.compile(_DIGEST)
_TARGET_IMAGE_PATTERN = re.compile(
    rf"{re.escape(ROLLBACK_TARGET_IMAGE_REPOSITORY)}@(?P<digest>{_DIGEST})"
)
_CHALLENGE_PREFIX = "I-ATTEST-ALL-BRAIN-AND-SCHEDULER-EXECUTORS-ARE-STOPPED:"

# This is the non-negotiable cadence closure embedded in both the candidate
# 1.9 runtime and the 1.8.2 compatibility carrier.  The image workflow probes
# it again from each native platform image; this source-side copy makes the
# pre-downgrade command fail before touching the database when the process
# executing it is not the target runtime.
#
# The carrier preserves the published 1.8 APPLICATION bytes.  It does not
# preserve that image's runtime, and never did: it already substitutes CPython
# 3.14.7 for the 3.14.6 the published image shipped, because unchanged 1.8 code
# accepts exactly one local cadence fingerprint and the ceremony has to restamp
# cursors that 1.8 will then agree with.  tzdata is substituted for the same
# reason and under the same rule.  Verified by execution: published z4j 1.8.0 on
# CPython 3.14.7 computes this exact fingerprint under this exact tzdata, and so
# does the 1.9 tree, because the fingerprint is a function of the closure alone
# and not of the application version.
SEALED_TARGET_CADENCE_PAYLOAD: dict[str, object] = {
    "format": "z4j-cadence-runtime-v1",
    "semantics_version": 1,
    "dependencies": {
        "astral": "3.2",
        "croniter": "6.2.2",
        "python-dateutil": "2.9.0.post0",
        "six": "1.17.0",
        "tzdata": "2026.3",
    },
    "tzdata_tree_sha256": ("864e13548b97e0e7be6bd2d4dd5e8b4a04cea0b570066ef5dfa40a424300cb0c"),
    "python": {
        "implementation": "CPython",
        "version": [3, 14, 7],
    },
    "behavior_vector_sha256": ("8e2ec76becf6ca6263805221e930c98962713ba0419c2a7e320e1dc928014a15"),
}
SEALED_TARGET_CADENCE_FINGERPRINT = (
    "5e63a2ae8ec66ec9b86f64828b7ac2499c9254531d2ceb33e32ac3a80c344ef4"
)


class RuntimeRollbackRefused(RuntimeError):  # noqa: N818 - refusal disposition
    """The exact rollback ceremony preconditions were not proved."""


def canonical_json(value: object) -> bytes:
    """Encode one receipt field without platform- or locale-dependent bytes."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def object_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def validate_target_image(value: str) -> str:
    """Require the sole compatibility repository by immutable OCI digest."""

    match = _TARGET_IMAGE_PATTERN.fullmatch(value.strip())
    if match is None:
        raise RuntimeRollbackRefused(
            "target image must be "
            f"{ROLLBACK_TARGET_IMAGE_REPOSITORY}@sha256:<64 lowercase hex>; "
            "mutable 1.8.2, 1.8, and latest tags are forbidden",
        )
    return match.group("digest")


def _manifest_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeRollbackRefused(f"rollback manifest {label} is not an object")
    return value


def _manifest_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RuntimeRollbackRefused(
            f"rollback manifest {label} keys differ from the sealed source authority",
        )


def _manifest_value(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise RuntimeRollbackRefused(
            f"rollback manifest {label} differs from the sealed source authority",
        )


def _manifest_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _OCI_DIGEST.fullmatch(value) is None:
        raise RuntimeRollbackRefused(
            f"rollback manifest {label} is not a lowercase OCI SHA-256 digest",
        )

    return value


def _manifest_layer(value: object, label: str) -> dict[str, Any]:
    record = _manifest_mapping(value, label)
    _manifest_exact_keys(
        record,
        {"mediaType", "digest", "size", "annotations"},
        label,
    )
    if not isinstance(record.get("mediaType"), str) or not record["mediaType"]:
        raise RuntimeRollbackRefused(f"rollback manifest {label} media type is absent")
    _manifest_digest(record.get("digest"), f"{label}.digest")
    _manifest_size(record.get("size"), f"{label}.size")
    annotations = _manifest_mapping(record.get("annotations"), f"{label}.annotations")
    _manifest_exact_keys(
        annotations,
        {"org.opencontainers.image.title"},
        f"{label}.annotations",
    )
    title = annotations["org.opencontainers.image.title"]
    if not isinstance(title, str) or not title or "\\" in title:
        raise RuntimeRollbackRefused(f"rollback manifest {label} title is unsafe")
    path = PurePosixPath(title)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RuntimeRollbackRefused(f"rollback manifest {label} title is unsafe")
    return record


def _manifest_candidate_durable(value: object) -> dict[str, Any]:
    label = "candidate_image.qualification_durable_evidence"
    durable = _manifest_mapping(value, label)
    _manifest_exact_keys(
        durable,
        {"artifact", "config", "receipt", "bundle", "authentication", "payload"},
        label,
    )
    artifact = _manifest_mapping(durable["artifact"], f"{label}.artifact")
    _manifest_exact_keys(
        artifact,
        {"mediaType", "digest", "size", "artifactType"},
        f"{label}.artifact",
    )
    _manifest_digest(artifact.get("digest"), f"{label}.artifact.digest")
    _manifest_size(artifact.get("size"), f"{label}.artifact.size")
    if any(
        not isinstance(artifact.get(name), str) or not artifact[name]
        for name in ("mediaType", "artifactType")
    ):
        raise RuntimeRollbackRefused("rollback manifest durable artifact type is absent")
    config = _manifest_mapping(durable["config"], f"{label}.config")
    _manifest_exact_keys(
        config,
        {"mediaType", "digest", "size"},
        f"{label}.config",
    )
    _manifest_digest(config.get("digest"), f"{label}.config.digest")
    _manifest_size(config.get("size"), f"{label}.config.size")
    if not isinstance(config.get("mediaType"), str) or not config["mediaType"]:
        raise RuntimeRollbackRefused("rollback manifest durable config type is absent")
    role_layers = [
        _manifest_layer(durable[name], f"{label}.{name}")
        for name in ("receipt", "bundle", "authentication")
    ]
    payload = durable["payload"]
    if not isinstance(payload, list) or not payload:
        raise RuntimeRollbackRefused("rollback manifest durable payload is empty")
    payload_layers = [_manifest_layer(item, f"{label}.payload") for item in payload]
    role_titles = [item["annotations"]["org.opencontainers.image.title"] for item in role_layers]
    payload_titles = [
        item["annotations"]["org.opencontainers.image.title"] for item in payload_layers
    ]
    if payload_titles != sorted(payload_titles) or len(role_titles + payload_titles) != len(
        set(role_titles + payload_titles),
    ):
        raise RuntimeRollbackRefused("rollback manifest durable layer inventory differs")
    return durable


def _manifest_size(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeRollbackRefused(
            f"rollback manifest {label} is not a positive byte size",
        )
    return value


def validate_finalized_rollback_manifest(  # noqa: PLR0915 - exhaustive sealed authority
    value: object,
    *,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Validate and project the one external compatibility-image authority."""

    if _SHA256.fullmatch(manifest_sha256) is None:
        raise RuntimeRollbackRefused("rollback manifest file hash is malformed")
    manifest = _manifest_mapping(value, "root")
    _manifest_value(manifest.get("format"), "z4j-rollback-compat-image-lock-v1", "format")
    _manifest_value(manifest.get("lock_version"), 1, "lock_version")
    identity = _manifest_mapping(manifest.get("identity"), "identity")
    _manifest_value(identity.get("application_version"), "1.8.2", "application version")
    _manifest_value(identity.get("rollback_target"), "1.9.0", "rollback target")
    _manifest_value(identity.get("compatibility_python"), "3.14.7", "Python version")

    source = _manifest_mapping(manifest.get("source_release"), "source_release")
    _manifest_value(
        source.get("tag_object_sha1"),
        "ca60bf9013ec923b64e13123c19b2bb55c798550",
        "source tag object",
    )
    _manifest_value(source.get("commit_sha1"), ROLLBACK_TARGET_SOURCE_COMMIT, "source commit")
    _manifest_value(source.get("tree_sha1"), ROLLBACK_TARGET_SOURCE_TREE, "source tree")
    released = _manifest_mapping(manifest.get("released_image"), "released_image")
    released_index = _manifest_mapping(released.get("index"), "released_image.index")
    _manifest_value(released_index.get("digest"), _OLD_IMAGE_INDEX, "released image index")
    carrier = _manifest_mapping(manifest.get("python_carrier"), "python_carrier")
    carrier_index = _manifest_mapping(carrier.get("index"), "python_carrier.index")
    _manifest_value(carrier_index.get("digest"), _PYTHON_CARRIER_INDEX, "Python carrier index")

    cadence = _manifest_mapping(manifest.get("cadence"), "cadence")
    payload = {
        "format": cadence.get("payload_format"),
        "semantics_version": cadence.get("semantics_version"),
        "dependencies": cadence.get("dependencies"),
        "tzdata_tree_sha256": cadence.get("tzdata_tree_sha256"),
        "python": cadence.get("python"),
        "behavior_vector_sha256": cadence.get("behavior_vector_sha256"),
    }
    _manifest_value(payload, SEALED_TARGET_CADENCE_PAYLOAD, "cadence payload")
    _manifest_value(
        cadence.get("expected_runtime_fingerprint"),
        SEALED_TARGET_CADENCE_FINGERPRINT,
        "cadence fingerprint",
    )

    candidate = _manifest_mapping(manifest.get("candidate_image"), "candidate_image")
    _manifest_exact_keys(
        candidate,
        {
            "finalization_receipt_format",
            "finalization_rule",
            "finalized",
            "index",
            "platforms",
            "promotion_evidence_format",
            "qualification_durable_evidence",
            "recovery_evidence_format",
            "release_evidence_index_format",
            "public_tag",
            "qualification_receipt_format",
            "release_receipt_semantics",
            "release_receipt_sha256",
            "repository",
        },
        "candidate_image",
    )
    _manifest_value(
        candidate.get("repository"),
        ROLLBACK_TARGET_IMAGE_REPOSITORY,
        "candidate repository",
    )
    _manifest_value(
        candidate.get("public_tag"),
        ROLLBACK_TARGET_OCI_TAG.rsplit(":", 1)[1],
        "candidate tag",
    )
    _manifest_value(
        candidate.get("qualification_receipt_format"),
        _QUALIFICATION_RECEIPT_FORMAT,
        "candidate qualification receipt format",
    )
    _manifest_value(
        candidate.get("release_receipt_semantics"),
        _RELEASE_RECEIPT_SEMANTICS,
        "candidate release receipt semantics",
    )
    _manifest_value(
        candidate.get("finalization_receipt_format"),
        _FINALIZATION_RECEIPT_FORMAT,
        "candidate finalization receipt format",
    )
    _manifest_value(
        candidate.get("promotion_evidence_format"),
        _PROMOTION_EVIDENCE_FORMAT,
        "candidate promotion evidence format",
    )
    _manifest_value(
        candidate.get("recovery_evidence_format"),
        _RECOVERY_EVIDENCE_FORMAT,
        "candidate recovery evidence format",
    )
    _manifest_value(
        candidate.get("release_evidence_index_format"),
        _RELEASE_EVIDENCE_INDEX_FORMAT,
        "candidate release evidence index format",
    )
    _manifest_value(candidate.get("finalization_rule"), _FINALIZATION_RULE, "finalization rule")
    if candidate.get("finalized") is not True:
        raise RuntimeRollbackRefused(
            "rollback compatibility manifest is not finalized; publication, "
            "native probes, scans, SBOM, and receipt sealing must finish first",
        )
    index_record = _manifest_mapping(candidate.get("index"), "candidate_image.index")
    _manifest_exact_keys(index_record, {"digest", "size"}, "candidate_image.index")
    index = _manifest_digest(index_record.get("digest"), "candidate_image.index.digest")
    index_size = _manifest_size(index_record.get("size"), "candidate_image.index.size")
    if index in {_OLD_IMAGE_INDEX, _PYTHON_CARRIER_INDEX}:
        raise RuntimeRollbackRefused("compatibility index aliases one of its input images")

    platforms = _manifest_mapping(candidate.get("platforms"), "candidate_image.platforms")
    if set(platforms) != {"amd64", "arm64"}:
        raise RuntimeRollbackRefused(
            "rollback manifest candidate platforms must be exactly amd64 and arm64",
        )
    projected_platforms: dict[str, Any] = {}
    for name in ("amd64", "arm64"):
        platform = _manifest_mapping(platforms[name], f"candidate_image.platforms.{name}")
        _manifest_exact_keys(
            platform,
            {"config", "manifest"},
            f"candidate_image.platforms.{name}",
        )
        projected: dict[str, Any] = {}
        for record_name in ("manifest", "config"):
            record = _manifest_mapping(
                platform.get(record_name),
                f"candidate_image.platforms.{name}.{record_name}",
            )
            _manifest_exact_keys(
                record,
                {"digest", "size"},
                f"candidate_image.platforms.{name}.{record_name}",
            )
            projected[record_name] = {
                "digest": _manifest_digest(
                    record.get("digest"),
                    f"candidate_image.platforms.{name}.{record_name}.digest",
                ),
                "size": _manifest_size(
                    record.get("size"),
                    f"candidate_image.platforms.{name}.{record_name}.size",
                ),
            }
        projected_platforms[name] = projected
    receipt_sha256 = candidate.get("release_receipt_sha256")
    if not isinstance(receipt_sha256, str) or _SHA256.fullmatch(receipt_sha256) is None:
        raise RuntimeRollbackRefused(
            "rollback manifest release receipt is not a lowercase SHA-256",
        )
    qualification_durable = _manifest_candidate_durable(
        candidate.get("qualification_durable_evidence"),
    )

    publication_gate = _manifest_mapping(
        manifest.get("publication_gate"),
        "publication_gate",
    )
    if object_sha256(publication_gate) != _PUBLICATION_GATE_SHA256:
        raise RuntimeRollbackRefused("rollback manifest publication gate differs")
    return {
        "manifest_sha256": manifest_sha256,
        "index": {"digest": index, "size": index_size},
        "platforms": projected_platforms,
        "release_receipt_sha256": receipt_sha256,
        "qualification_durable_evidence": qualification_durable,
        "publication_gate_sha256": _PUBLICATION_GATE_SHA256,
        "cadence_payload": payload,
        "cadence_runtime_fingerprint": SEALED_TARGET_CADENCE_FINGERPRINT,
    }


def load_finalized_rollback_manifest() -> dict[str, Any]:
    """Read the single tracked manifest from a wheel or a source checkout."""

    packaged = files("z4j_brain").joinpath("data", ROLLBACK_MANIFEST_RESOURCE)
    source = Path(__file__).resolve().parents[4] / ROLLBACK_MANIFEST_SOURCE
    try:
        raw = packaged.read_bytes()
    except FileNotFoundError:
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise RuntimeRollbackRefused(
                "sealed rollback compatibility manifest is absent from this installation",
            ) from exc
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeRollbackRefused(
            "sealed rollback compatibility manifest is not valid JSON",
        ) from exc
    return validate_finalized_rollback_manifest(
        manifest,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )


def require_finalized_target_image(value: str) -> dict[str, Any]:
    """Bind an operator-supplied digest to the finalized native image proof."""

    supplied = validate_target_image(value)
    authority = load_finalized_rollback_manifest()
    if supplied != authority["index"]["digest"]:
        raise RuntimeRollbackRefused(
            "target image digest differs from the finalized compatibility manifest",
        )
    return authority


def load_finalized_production_carrier(
    authority_root: Path,
    *,
    asserted_revision: str,
    asserted_image: str,
) -> dict[str, Any]:
    """Authenticate the normal 1.9 carrier; caller values are assertions only."""

    from z4j_brain.domain.production_container_authority import (
        ProductionContainerAuthorityRefused,
        load_finalized_production_authority,
    )

    try:
        authority = load_finalized_production_authority(
            authority_root,
            source_image_assertion=asserted_image,
        )
    except ProductionContainerAuthorityRefused as exc:
        raise RuntimeRollbackRefused(
            "normal 1.9 production-container authority is absent, unfinalized, "
            "unauthenticated, or differs from registry bytes",
        ) from exc
    if asserted_revision != authority["source_revision"]:
        raise RuntimeRollbackRefused(
            "caller source revision assertion differs from the authenticated "
            "production-container receipt",
        )
    return authority


def _durable_evidence_module() -> Any:
    try:
        import z4j_brain.rollback_compat_durable_evidence as module
    except ModuleNotFoundError:
        source = Path(__file__).resolve().parents[4] / ROLLBACK_DURABLE_EVIDENCE_SOURCE
        if not source.is_file() or source.is_symlink():
            raise RuntimeRollbackRefused(
                "offline rollback durable-evidence verifier is absent from this installation",
            ) from None
        name = "_z4j_source_rollback_compat_durable_evidence"
        spec = importlib_util.spec_from_file_location(name, source)
        if spec is None or spec.loader is None:
            raise RuntimeRollbackRefused(
                "offline rollback durable-evidence verifier cannot be loaded",
            ) from None
        module = importlib_util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None)
            raise
    return module


def verify_durable_rollback_evidence(
    evidence_root: Path,
    *,
    cosign_path: Path = ROLLBACK_COSIGN_PATH,
) -> dict[str, Any]:
    """Offline-verify Q/F/(P|R)/release-index evidence against this manifest."""

    source_manifest = Path(__file__).resolve().parents[4] / ROLLBACK_MANIFEST_SOURCE
    packaged_manifest = files("z4j_brain").joinpath("data", ROLLBACK_MANIFEST_RESOURCE)
    manifest_path: Path | None = None
    try:
        if packaged_manifest.is_file():
            manifest_path = Path(str(packaged_manifest))
    except (FileNotFoundError, TypeError):
        manifest_path = None
    if manifest_path is None:
        manifest_path = source_manifest
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeRollbackRefused(
            "sealed rollback manifest is unavailable to the durable-evidence verifier",
        )
    module = _durable_evidence_module()
    try:
        projection = module.verify_local_graph(
            manifest_path,
            evidence_root,
            cosign=str(cosign_path),
        )
    except module.EvidenceError as exc:
        raise RuntimeRollbackRefused(
            "portable rollback evidence graph is absent, unauthenticated, or substituted",
        ) from exc
    if (
        not isinstance(projection, dict)
        or projection.get("format") != _DURABLE_GRAPH_FORMAT
        or projection.get("result") != "pass"
        or set(projection)
        != {
            "format",
            "result",
            "subject",
            "terminal_stage",
            "records",
            "release_index",
            "manifest",
            "candidate_components",
        }
    ):
        raise RuntimeRollbackRefused("portable rollback evidence projection differs")
    authority = load_finalized_rollback_manifest()
    if (
        projection.get("subject")
        != {"mediaType": "application/vnd.oci.image.index.v1+json", **authority["index"]}
        or projection.get("manifest", {}).get("sha256") != authority["manifest_sha256"]
        or projection.get("candidate_components", {}).get(
            "qualification_durable_evidence",
        )
        != authority["qualification_durable_evidence"]
    ):
        raise RuntimeRollbackRefused(
            "portable rollback evidence projection differs from the finalized candidate",
        )
    return projection


def durable_evidence_sha256(projection: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(projection) + b"\n").hexdigest()


def actual_cadence_identity() -> tuple[dict[str, object], str]:
    """Compute the payload and digest from the process doing the write."""

    behavior = cadence_behavior_vector_digest()
    return cadence_runtime_payload(behavior), cadence_runtime_fingerprint()


def require_sealed_target_runtime() -> tuple[dict[str, object], str]:
    """Fail unless this process is the compatibility target runtime."""

    payload, fingerprint = actual_cadence_identity()
    if payload != SEALED_TARGET_CADENCE_PAYLOAD:
        raise RuntimeRollbackRefused(
            "running cadence payload does not equal the sealed "
            "1.8.2/Python-3.14.7 compatibility payload",
        )
    if fingerprint != SEALED_TARGET_CADENCE_FINGERPRINT:
        raise RuntimeRollbackRefused(
            "running cadence fingerprint does not equal the sealed compatibility fingerprint",
        )
    return payload, fingerprint


def preview_challenge(preview_without_challenge: dict[str, Any]) -> str:
    """Bind the human stop attestation to the complete preview."""

    return _CHALLENGE_PREFIX + object_sha256(preview_without_challenge)


def challenge_sha256(challenge: str) -> str:
    if not challenge.startswith(_CHALLENGE_PREFIX):
        raise RuntimeRollbackRefused(
            "stopped-executors challenge does not explicitly attest that all "
            "Brain and scheduler executors are stopped",
        )
    return hashlib.sha256(challenge.encode("ascii")).hexdigest()


def build_preview(
    *,
    source_authority: dict[str, Any],
    durable_evidence: dict[str, Any],
    database_head: str,
    target_image: str,
    row_set_digest: str,
    reserved_schedule_count: int,
    external_schedule_count: int,
) -> dict[str, Any]:
    """Return the deterministic two-phase preview and attestation challenge."""

    target_authority = require_finalized_target_image(target_image)
    if source_authority.get("format") != "z4j-authenticated-production-container-authority-v1":
        raise RuntimeRollbackRefused(
            "source carrier is not an authenticated production-container authority",
        )
    source_revision = source_authority.get("source_revision")
    source_image = source_authority.get("source_image")
    if (
        not isinstance(source_revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None
    ):
        raise RuntimeRollbackRefused("authenticated source revision is malformed")
    if not isinstance(source_image, str):
        raise RuntimeRollbackRefused("authenticated source image is absent")
    validate_target_image(source_image)
    if not isinstance(source_authority.get("authority_sha256"), str):
        raise RuntimeRollbackRefused("authenticated source authority seal is absent")
    durable_sha256 = durable_evidence_sha256(durable_evidence)
    if (
        durable_evidence.get("format") != _DURABLE_GRAPH_FORMAT
        or durable_evidence.get("result") != "pass"
        or durable_evidence.get("candidate_components", {}).get("index")
        != target_authority["index"]
        or durable_evidence.get("manifest", {}).get("sha256") != target_authority["manifest_sha256"]
    ):
        raise RuntimeRollbackRefused(
            "durable evidence does not bind the finalized rollback candidate",
        )
    payload, fingerprint = require_sealed_target_runtime()
    preview: dict[str, Any] = {
        "format": "z4j-runtime-rollback-preview-v1",
        "source_revision": source_revision,
        "source_image": source_image,
        "source_production_authority": source_authority,
        "database_head": database_head,
        "target": ROLLBACK_TARGET,
        "target_release": ROLLBACK_TARGET_RELEASE,
        "target_image": target_image,
        "target_image_digest": target_authority["index"]["digest"],
        "target_image_authority": target_authority,
        "target_durable_evidence": durable_evidence,
        "target_durable_evidence_sha256": durable_sha256,
        "target_cadence_payload": payload,
        "target_cadence_runtime_fingerprint": fingerprint,
        "row_set_digest": row_set_digest,
        "reserved_schedule_count": reserved_schedule_count,
        "external_schedule_count": external_schedule_count,
        "external_schedule_policy": (
            "excluded-from-reserved-restamp; prove external repository "
            "upsert-or-promote after downgrade"
        ),
    }
    challenge = preview_challenge(preview)
    return {
        **preview,
        "stopped_executors_challenge": challenge,
        "stopped_executors_challenge_sha256": challenge_sha256(challenge),
        "operation_id": object_sha256(
            {
                "preview": preview,
                "challenge": challenge,
            },
        )[:32],
    }


__all__ = [
    "ROLLBACK_COSIGN_PATH",
    "ROLLBACK_DURABLE_EVIDENCE_ENV",
    "ROLLBACK_DURABLE_EVIDENCE_SOURCE",
    "ROLLBACK_MANIFEST_RESOURCE",
    "ROLLBACK_TARGET",
    "ROLLBACK_TARGET_OCI_TAG",
    "ROLLBACK_TARGET_RELEASE",
    "SEALED_TARGET_CADENCE_FINGERPRINT",
    "SEALED_TARGET_CADENCE_PAYLOAD",
    "RuntimeRollbackRefused",
    "actual_cadence_identity",
    "build_preview",
    "canonical_json",
    "challenge_sha256",
    "durable_evidence_sha256",
    "load_finalized_production_carrier",
    "load_finalized_rollback_manifest",
    "object_sha256",
    "require_finalized_target_image",
    "require_sealed_target_runtime",
    "validate_finalized_rollback_manifest",
    "validate_target_image",
    "verify_durable_rollback_evidence",
]
