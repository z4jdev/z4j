"""Strict canonicalization and authentication for Boundary F.

No function in this module falls back to the application's master secret.
Callers must supply a dedicated audit-chain key selected by its one-way id.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from z4j_brain.persistence.models.audit_chain import (
    AUDIT_CHAIN_SINGLETON_ID,
    AuditChainPreparation,
    AuditChainState,
)

if TYPE_CHECKING:
    from z4j_brain.persistence.models.audit_log import AuditLog

AUDIT_ROW_HMAC_VERSION = 2
AUDIT_STATE_FORMAT_VERSION = 1
AUDIT_PREPARATION_FORMAT_VERSION = 1
MAX_ACTIVE_AUDIT_KEYS = 32
FROZEN_VERIFIED_CLASSES = frozenset(
    {
        "legacy-linked-verified",
        "legacy-standalone-verified",
        "legacy-fork-verified",
    },
)
FROZEN_UNVERIFIED_CLASSES = frozenset(
    {
        "legacy-invalid",
        "legacy-unverifiable-key-unavailable",
    },
)
FROZEN_INTEGRITY_CLASSES = FROZEN_VERIFIED_CLASSES | FROZEN_UNVERIFIED_CLASSES | {"legacy-unsigned"}
FROZEN_ORIGINS = frozenset(
    {
        "audit-log:preparation-v1",
        "fork-quarantine:audit-log-v1-15",
        "fork-quarantine:audit-log-v1-api-key-16",
    },
)

_KEY_ID_DOMAIN = b"z4j/audit-chain/key-id/v1\x00"
_ROW_MAC_DOMAIN = b"z4j/audit-chain/row/v2\x00"
_STATE_MAC_DOMAIN = b"z4j/audit-chain/state/v1\x00"
_PREPARATION_MAC_DOMAIN = b"z4j/audit-chain/preparation/v1\x00"
_FROZEN_SNAPSHOT_DOMAIN = b"z4j/audit-chain/frozen-snapshot/v1\x00"


class AuditChainIntegrityError(RuntimeError):
    """The persisted audit authority cannot be proved."""


class AuditChainConfigurationError(ValueError):
    """The configured dedicated audit-key window is unsafe or incomplete."""


def canonical_audit_key_id(secret: bytes) -> str:
    """Return the domain-separated one-way identifier for an audit key."""

    if len(secret) < 32:
        raise AuditChainConfigurationError(
            "audit-chain keys must be at least 32 bytes",
        )
    return hmac.new(secret, _KEY_ID_DOMAIN, hashlib.sha256).hexdigest()


def build_audit_keyring(
    current: bytes,
    previous: Sequence[bytes] = (),
) -> tuple[str, dict[str, bytes]]:
    """Validate and index the current plus previous audit-only keys."""

    secrets = [current, *previous]
    if len(secrets) > MAX_ACTIVE_AUDIT_KEYS:
        raise AuditChainConfigurationError(
            f"at most {MAX_ACTIVE_AUDIT_KEYS} audit-chain keys may be configured",
        )
    keyring: dict[str, bytes] = {}
    seen_secret: set[bytes] = set()
    for secret in secrets:
        if len(secret) < 32:
            raise AuditChainConfigurationError(
                "every audit-chain key must be at least 32 bytes",
            )
        if secret in seen_secret:
            raise AuditChainConfigurationError(
                "duplicate audit-chain keys are not permitted",
            )
        seen_secret.add(secret)
        key_id = canonical_audit_key_id(secret)
        prior = keyring.get(key_id)
        if prior is not None and not hmac.compare_digest(prior, secret):
            raise AuditChainConfigurationError(
                "audit-chain key-id collision",
            )
        keyring[key_id] = secret
    return canonical_audit_key_id(current), keyring


def normalize_timestamp(value: datetime | str) -> datetime:
    """Normalize a database timestamp to aware UTC microsecond precision."""

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise AuditChainIntegrityError(
                "audit timestamp is not canonical ISO-8601",
            ) from exc
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.replace(microsecond=normalized.microsecond)


def timestamp_text(value: datetime | str) -> str:
    return normalize_timestamp(value).isoformat(timespec="microseconds")


def normalize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise AuditChainIntegrityError("source_ip must be one IP address") from exc


def normalize_hmac(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    if len(normalized) != 64:
        raise AuditChainIntegrityError(f"{field} must be a 64-character HMAC")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise AuditChainIntegrityError(f"{field} must be lowercase hexadecimal") from exc
    if normalized != value:
        raise AuditChainIntegrityError(f"{field} must be lowercase hexadecimal")
    return normalized


def normalize_uuid(value: uuid.UUID | str | None, *, field: str) -> str | None:
    if value is None:
        return None
    try:
        normalized = str(value if isinstance(value, uuid.UUID) else uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuditChainIntegrityError(f"{field} must be a UUID") from exc
    if isinstance(value, str) and value != normalized:
        raise AuditChainIntegrityError(f"{field} must use canonical lowercase UUID text")
    return normalized


def _strict_json_value(value: Any, *, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuditChainIntegrityError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, list):
        return [
            _strict_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditChainIntegrityError(
                    f"{path} contains a non-string object key",
                )
            normalized[key] = _strict_json_value(item, path=f"{path}.{key}")
        return normalized
    raise AuditChainIntegrityError(
        f"{path} contains unsupported JSON value {type(value).__name__}",
    )


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Encode one closed, backend-neutral JSON envelope."""

    normalized = _strict_json_value(dict(payload))
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_row_payload(
    *,
    row_id: uuid.UUID,
    action: str,
    target_type: str,
    target_id: str | None,
    result: str,
    outcome: str | None,
    event_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    api_key_id: uuid.UUID | None,
    project_id: uuid.UUID | None,
    source_ip: str | None,
    user_agent: str | None,
    metadata: Mapping[str, Any],
    occurred_at: datetime,
    prev_row_hmac: str | None,
    hmac_key_id: str,
    chain_generation: uuid.UUID,
) -> dict[str, Any]:
    """Build the complete v2 row envelope."""

    return {
        "version": AUDIT_ROW_HMAC_VERSION,
        "id": normalize_uuid(row_id, field="id"),
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "result": result,
        "outcome": outcome,
        "event_id": normalize_uuid(event_id, field="event_id"),
        "user_id": normalize_uuid(user_id, field="user_id"),
        "api_key_id": normalize_uuid(api_key_id, field="api_key_id"),
        "project_id": normalize_uuid(project_id, field="project_id"),
        "source_ip": normalize_ip(source_ip),
        "user_agent": user_agent,
        "metadata": _strict_json_value(dict(metadata), path="$.metadata"),
        "occurred_at": timestamp_text(occurred_at),
        "prev_row_hmac": normalize_hmac(
            prev_row_hmac,
            field="prev_row_hmac",
        ),
        "hmac_key_id": normalize_hmac(hmac_key_id, field="hmac_key_id"),
        "chain_generation": normalize_uuid(
            chain_generation,
            field="chain_generation",
        ),
    }


def compute_row_hmac(secret: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        _ROW_MAC_DOMAIN + canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def strictly_later_audit_key(
    candidate: datetime,
    candidate_id: uuid.UUID,
    *,
    prior_timestamp: datetime | str | None,
    prior_id: uuid.UUID | None,
) -> datetime:
    """Clamp append time so ``(occurred_at, id)`` is strictly monotonic."""

    normalized = normalize_timestamp(candidate)
    if prior_timestamp is None and prior_id is None:
        return normalized
    if prior_timestamp is None or prior_id is None:
        raise AuditChainIntegrityError("authenticated head order key is incomplete")
    prior = normalize_timestamp(prior_timestamp)
    if (normalized, candidate_id.int) > (prior, prior_id.int):
        return normalized
    try:
        return prior + timedelta(microseconds=1)
    except OverflowError as exc:
        raise AuditChainIntegrityError("audit timestamp order overflow") from exc


_HEAD_FIELDS = (
    "head_row_hmac",
    "head_hmac_key_id",
    "head_occurred_at",
    "head_id",
)
_PRUNE_FIELDS = (
    "prune_row_hmac",
    "prune_hmac_key_id",
    "prune_occurred_at",
    "prune_id",
)
_RETIRED_RECOVERY_BINDING_FIELDS = frozenset(
    {
        "version",
        "operation_id",
        "old_bundle_manifest_digest",
        "retained_parent_identity_digest",
        "replacement_installation_id",
        "status",
        "destruction_journal_digest",
    },
)


def _quartet_presence(payload: Mapping[str, Any], fields: Sequence[str]) -> bool:
    present = [payload[field] is not None for field in fields]
    if any(present) and not all(present):
        raise AuditChainIntegrityError(
            f"{fields[0].removesuffix('_row_hmac')} quartet is incomplete",
        )
    return all(present)


def canonical_retired_recovery_binding(
    raw: Any,
) -> dict[str, Any] | None:
    """Validate the only state-MAC-authorized retired-bundle authority."""

    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != _RETIRED_RECOVERY_BINDING_FIELDS:
        raise AuditChainIntegrityError(
            "retired_recovery_binding must contain exactly the versioned "
            "operation, bundle, parent, installation, status, and journal fields",
        )
    if raw["version"] != 1 or isinstance(raw["version"], bool):
        raise AuditChainIntegrityError(
            "retired_recovery_binding version must be 1",
        )
    status = raw["status"]
    if status not in {"RECOVERABLE", "DESTROYING"}:
        raise AuditChainIntegrityError(
            "retired_recovery_binding status is unsupported",
        )
    operation_id = normalize_uuid(
        raw["operation_id"],
        field="retired_recovery_binding.operation_id",
    )
    replacement_installation_id = normalize_uuid(
        raw["replacement_installation_id"],
        field="retired_recovery_binding.replacement_installation_id",
    )
    for field in (
        "old_bundle_manifest_digest",
        "retained_parent_identity_digest",
    ):
        if not isinstance(raw[field], str):
            raise AuditChainIntegrityError(
                f"retired_recovery_binding.{field} must be lowercase hexadecimal",
            )
    old_bundle_manifest_digest = normalize_hmac(
        raw["old_bundle_manifest_digest"],
        field="retired_recovery_binding.old_bundle_manifest_digest",
    )
    retained_parent_identity_digest = normalize_hmac(
        raw["retained_parent_identity_digest"],
        field="retired_recovery_binding.retained_parent_identity_digest",
    )
    journal_raw = raw["destruction_journal_digest"]
    if journal_raw is not None and not isinstance(journal_raw, str):
        raise AuditChainIntegrityError(
            "retired_recovery_binding.destruction_journal_digest "
            "must be lowercase hexadecimal or null",
        )
    destruction_journal_digest = normalize_hmac(
        journal_raw,
        field="retired_recovery_binding.destruction_journal_digest",
    )
    if status == "RECOVERABLE" and destruction_journal_digest is not None:
        raise AuditChainIntegrityError(
            "RECOVERABLE retired_recovery_binding requires a null destruction_journal_digest",
        )
    if status == "DESTROYING" and destruction_journal_digest is None:
        raise AuditChainIntegrityError(
            "DESTROYING retired_recovery_binding requires a destruction_journal_digest",
        )
    assert operation_id is not None
    assert old_bundle_manifest_digest is not None
    assert retained_parent_identity_digest is not None
    assert replacement_installation_id is not None
    return {
        "version": 1,
        "operation_id": operation_id,
        "old_bundle_manifest_digest": old_bundle_manifest_digest,
        "retained_parent_identity_digest": retained_parent_identity_digest,
        "replacement_installation_id": replacement_installation_id,
        "status": status,
        "destruction_journal_digest": destruction_journal_digest,
    }


def canonical_state_payload(
    state: AuditChainState | Mapping[str, Any],
) -> dict[str, Any]:
    """Return and structurally validate the authenticated state payload."""

    get = state.get if isinstance(state, Mapping) else lambda name: getattr(state, name)
    counts_raw = get("active_key_counts")
    if not isinstance(counts_raw, dict):
        raise AuditChainIntegrityError("active_key_counts must be an object")
    counts: dict[str, int] = {}
    for key_id, count in counts_raw.items():
        normalized_key = normalize_hmac(str(key_id), field="active_key_counts key")
        if (
            normalized_key != key_id
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
        ):
            raise AuditChainIntegrityError(
                "active_key_counts must contain canonical key ids and positive integers",
            )
        counts[key_id] = count
    if len(counts) > MAX_ACTIVE_AUDIT_KEYS:
        raise AuditChainIntegrityError("active_key_counts exceeds its 32-key bound")

    payload = {
        "format_version": get("format_version"),
        "generation": normalize_uuid(get("generation"), field="generation"),
        "installation_id": normalize_uuid(
            get("installation_id"),
            field="installation_id",
        ),
        "state_key_id": normalize_hmac(get("state_key_id"), field="state_key_id"),
        "head_row_hmac": normalize_hmac(
            get("head_row_hmac"),
            field="head_row_hmac",
        ),
        "head_hmac_key_id": normalize_hmac(
            get("head_hmac_key_id"),
            field="head_hmac_key_id",
        ),
        "head_occurred_at": (
            timestamp_text(get("head_occurred_at")) if get("head_occurred_at") is not None else None
        ),
        "head_id": normalize_uuid(get("head_id"), field="head_id"),
        "prune_row_hmac": normalize_hmac(
            get("prune_row_hmac"),
            field="prune_row_hmac",
        ),
        "prune_hmac_key_id": normalize_hmac(
            get("prune_hmac_key_id"),
            field="prune_hmac_key_id",
        ),
        "prune_occurred_at": (
            timestamp_text(get("prune_occurred_at"))
            if get("prune_occurred_at") is not None
            else None
        ),
        "prune_id": normalize_uuid(get("prune_id"), field="prune_id"),
        "active_row_count": get("active_row_count"),
        "active_key_counts": dict(sorted(counts.items())),
        "frozen_row_count": get("frozen_row_count"),
        "frozen_snapshot_digest": normalize_hmac(
            get("frozen_snapshot_digest"),
            field="frozen_snapshot_digest",
        ),
        "retired_recovery_binding": canonical_retired_recovery_binding(
            get("retired_recovery_binding"),
        ),
    }
    if payload["format_version"] != AUDIT_STATE_FORMAT_VERSION:
        raise AuditChainIntegrityError("unsupported audit chain state format")
    active_count = payload["active_row_count"]
    frozen_count = payload["frozen_row_count"]
    if (
        not isinstance(active_count, int)
        or isinstance(active_count, bool)
        or active_count < 0
        or not isinstance(frozen_count, int)
        or isinstance(frozen_count, bool)
        or frozen_count < 0
    ):
        raise AuditChainIntegrityError("audit chain counts must be non-negative integers")
    if sum(counts.values()) != active_count:
        raise AuditChainIntegrityError("active_key_counts does not sum to active_row_count")
    head_present = _quartet_presence(payload, _HEAD_FIELDS)
    prune_present = _quartet_presence(payload, _PRUNE_FIELDS)
    if active_count > 0 and not head_present:
        raise AuditChainIntegrityError("positive active count requires a complete head")
    if not head_present and prune_present:
        raise AuditChainIntegrityError("prune boundary cannot exist without a head")
    if active_count == 0 and counts:
        raise AuditChainIntegrityError("empty active generation requires an empty key map")
    if (
        head_present
        and active_count == 0
        and (
            not prune_present
            or any(
                payload[h] != payload[p] for h, p in zip(_HEAD_FIELDS, _PRUNE_FIELDS, strict=True)
            )
        )
    ):
        raise AuditChainIntegrityError(
            "fully pruned state requires equal head and prune quartets",
        )
    if (frozen_count == 0) != (payload["frozen_snapshot_digest"] is None):
        raise AuditChainIntegrityError(
            "frozen snapshot digest must be null exactly when its count is zero",
        )
    return payload


def compute_state_mac(secret: bytes, state: AuditChainState | Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        _STATE_MAC_DOMAIN + canonical_json(canonical_state_payload(state)),
        hashlib.sha256,
    ).hexdigest()


def make_empty_chain_state(
    *,
    secret: bytes,
    generation: uuid.UUID | None = None,
    installation_id: uuid.UUID | None = None,
) -> AuditChainState:
    """Construct an authenticated in-transaction activation starting point.

    Callers must append the signed generation-start row in the same transaction;
    committing this temporary empty object is not a valid fresh activation.
    """

    state = AuditChainState(
        singleton_id=AUDIT_CHAIN_SINGLETON_ID,
        format_version=AUDIT_STATE_FORMAT_VERSION,
        generation=generation or uuid.uuid4(),
        installation_id=installation_id or uuid.uuid4(),
        state_key_id=canonical_audit_key_id(secret),
        head_row_hmac=None,
        head_hmac_key_id=None,
        head_occurred_at=None,
        head_id=None,
        prune_row_hmac=None,
        prune_hmac_key_id=None,
        prune_occurred_at=None,
        prune_id=None,
        active_row_count=0,
        active_key_counts={},
        frozen_row_count=0,
        frozen_snapshot_digest=None,
        retired_recovery_binding=None,
        state_mac="",
    )
    state.state_mac = compute_state_mac(secret, state)
    return state


def authenticate_state(
    state: AuditChainState,
    keyring: Mapping[str, bytes],
) -> dict[str, Any]:
    payload = canonical_state_payload(state)
    secret = keyring.get(payload["state_key_id"])
    if secret is None:
        raise AuditChainIntegrityError(
            "configured audit keys do not contain the authenticated state key",
        )
    expected = compute_state_mac(secret, payload)
    if len(state.state_mac) != len(expected) or not hmac.compare_digest(
        state.state_mac,
        expected,
    ):
        raise AuditChainIntegrityError("audit chain state MAC mismatch")
    missing = sorted(set(payload["active_key_counts"]) - set(keyring))
    if missing:
        raise AuditChainIntegrityError(
            "configured audit keys do not cover every live active row",
        )
    return payload


def canonical_preparation_payload(
    *,
    preparation_id: uuid.UUID,
    audit_key_id: str,
    preparation_revision: str,
    target_activation_revision: str,
) -> dict[str, Any]:
    return {
        "format_version": AUDIT_PREPARATION_FORMAT_VERSION,
        "singleton_id": AUDIT_CHAIN_SINGLETON_ID,
        "preparation_id": normalize_uuid(
            preparation_id,
            field="preparation_id",
        ),
        "audit_key_id": normalize_hmac(audit_key_id, field="audit_key_id"),
        "preparation_revision": preparation_revision,
        "target_activation_revision": target_activation_revision,
    }


def compute_preparation_mac(secret: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        _PREPARATION_MAC_DOMAIN + canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def authenticate_preparation(
    preparation: AuditChainPreparation,
    keyring: Mapping[str, bytes],
) -> dict[str, Any]:
    payload = canonical_preparation_payload(
        preparation_id=preparation.preparation_id,
        audit_key_id=preparation.audit_key_id,
        preparation_revision=preparation.preparation_revision,
        target_activation_revision=preparation.target_activation_revision,
    )
    if preparation.format_version != AUDIT_PREPARATION_FORMAT_VERSION:
        raise AuditChainIntegrityError("unsupported audit preparation format")
    secret = keyring.get(preparation.audit_key_id)
    if secret is None:
        raise AuditChainIntegrityError(
            "configured audit key does not match the preparation record",
        )
    expected = compute_preparation_mac(secret, payload)
    if len(preparation.preparation_mac) != len(expected) or not hmac.compare_digest(
        preparation.preparation_mac,
        expected,
    ):
        raise AuditChainIntegrityError("audit preparation MAC mismatch")
    return payload


def frozen_snapshot_digest(rows: Sequence[Mapping[str, Any]]) -> str | None:
    if not rows:
        return None
    digest = hashlib.sha256()
    digest.update(_FROZEN_SNAPSHOT_DOMAIN)
    for row in rows:
        encoded = canonical_json(row)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def canonical_frozen_values(
    *,
    id: uuid.UUID,  # noqa: A002  mirrors the persisted field name
    action: str,
    target_type: str,
    target_id: str | None,
    result: str,
    outcome: str | None,
    event_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    api_key_id: uuid.UUID | None,
    project_id: uuid.UUID | None,
    source_ip: str | None,
    user_agent: str | None,
    metadata: Mapping[str, Any],
    occurred_at: datetime,
    prev_row_hmac: str | None,
    row_hmac: str | None,
    legacy_frozen: bool,
    hmac_version: int | None,
    hmac_key_id: str | None,
    legacy_integrity_class: str,
    legacy_origin: str,
    chain_generation: uuid.UUID | None,
) -> dict[str, Any]:
    """Canonical persisted envelope for immutable frozen legacy values."""

    if legacy_frozen is not True or chain_generation is not None:
        raise AuditChainIntegrityError(
            "frozen audit rows require legacy_frozen=true and no generation",
        )
    if legacy_integrity_class not in FROZEN_INTEGRITY_CLASSES:
        raise AuditChainIntegrityError(
            "frozen audit integrity class is unknown",
        )
    if legacy_origin not in FROZEN_ORIGINS:
        raise AuditChainIntegrityError("frozen audit origin is unknown")
    structured_row_hmac = None
    if row_hmac is not None:
        try:
            structured_row_hmac = normalize_hmac(
                row_hmac,
                field="frozen row_hmac",
            )
        except AuditChainIntegrityError:
            structured_row_hmac = None
    if legacy_integrity_class in FROZEN_VERIFIED_CLASSES:
        if hmac_version != 1 or hmac_key_id is None or structured_row_hmac != row_hmac:
            raise AuditChainIntegrityError(
                "verified frozen rows require a canonical v1 HMAC and key id",
            )
        normalized_key_id = normalize_hmac(
            hmac_key_id,
            field="frozen hmac_key_id",
        )
        if normalized_key_id != hmac_key_id:
            raise AuditChainIntegrityError(
                "frozen hmac_key_id must be lowercase canonical hex",
            )
    elif legacy_integrity_class == "legacy-unsigned":
        if row_hmac is not None or hmac_version is not None or hmac_key_id is not None:
            raise AuditChainIntegrityError(
                "unsigned frozen rows may not claim an HMAC version or key",
            )
    elif (
        row_hmac is None
        or hmac_key_id is not None
        or hmac_version not in {None, 1}
        or (hmac_version == 1 and structured_row_hmac != row_hmac)
    ):
        raise AuditChainIntegrityError(
            "invalid/unverifiable frozen row markers are contradictory",
        )

    return {
        "id": normalize_uuid(id, field="id"),
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "result": result,
        "outcome": outcome,
        "event_id": normalize_uuid(event_id, field="event_id"),
        "user_id": normalize_uuid(user_id, field="user_id"),
        "api_key_id": normalize_uuid(api_key_id, field="api_key_id"),
        "project_id": normalize_uuid(project_id, field="project_id"),
        "source_ip": source_ip,
        "user_agent": user_agent,
        "metadata": _strict_json_value(dict(metadata), path="$.metadata"),
        "occurred_at": timestamp_text(occurred_at),
        "prev_row_hmac": prev_row_hmac,
        "row_hmac": row_hmac,
        "legacy_frozen": legacy_frozen,
        "hmac_version": hmac_version,
        "hmac_key_id": hmac_key_id,
        "legacy_integrity_class": legacy_integrity_class,
        "legacy_origin": legacy_origin,
        "chain_generation": normalize_uuid(
            chain_generation,
            field="chain_generation",
        ),
    }


def canonical_frozen_row_snapshot(row: AuditLog) -> dict[str, Any]:
    """Canonical persisted envelope for one immutable frozen legacy row."""

    if (
        row.id is None
        or row.legacy_frozen is not True
        or row.legacy_integrity_class is None
        or row.legacy_origin is None
    ):
        raise AuditChainIntegrityError("frozen audit row markers are incomplete")
    return canonical_frozen_values(
        id=row.id,
        action=row.action,
        target_type=row.target_type,
        target_id=row.target_id,
        result=row.result,
        outcome=row.outcome,
        event_id=row.event_id,
        user_id=row.user_id,
        api_key_id=row.api_key_id,
        project_id=row.project_id,
        source_ip=str(row.source_ip) if row.source_ip is not None else None,
        user_agent=row.user_agent,
        metadata=row.audit_metadata,
        occurred_at=row.occurred_at,
        prev_row_hmac=row.prev_row_hmac,
        row_hmac=row.row_hmac,
        legacy_frozen=True,
        hmac_version=row.hmac_version,
        hmac_key_id=row.hmac_key_id,
        legacy_integrity_class=row.legacy_integrity_class,
        legacy_origin=row.legacy_origin,
        chain_generation=row.chain_generation,
    )


__all__ = [
    "AUDIT_PREPARATION_FORMAT_VERSION",
    "AUDIT_ROW_HMAC_VERSION",
    "AUDIT_STATE_FORMAT_VERSION",
    "AuditChainConfigurationError",
    "AuditChainIntegrityError",
    "authenticate_preparation",
    "authenticate_state",
    "build_audit_keyring",
    "canonical_audit_key_id",
    "canonical_frozen_row_snapshot",
    "canonical_frozen_values",
    "canonical_json",
    "canonical_preparation_payload",
    "canonical_retired_recovery_binding",
    "canonical_row_payload",
    "canonical_state_payload",
    "compute_preparation_mac",
    "compute_row_hmac",
    "compute_state_mac",
    "frozen_snapshot_digest",
    "make_empty_chain_state",
    "normalize_ip",
    "normalize_timestamp",
    "strictly_later_audit_key",
    "timestamp_text",
]
