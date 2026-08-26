"""Offline, manifest-bound classification for Boundary-F activation."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import stat
import uuid
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, inspect, select, text
from sqlalchemy.orm import Session

from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    authenticate_preparation,
    canonical_audit_key_id,
    canonical_frozen_values,
    canonical_json,
    frozen_snapshot_digest,
    normalize_hmac,
    normalize_timestamp,
    normalize_uuid,
    timestamp_text,
)
from z4j_brain.domain.audit_service import AuditEntry, AuditService
from z4j_brain.persistence.models import AuditChainPreparation, AuditLog
from z4j_brain.persistence.repositories.audit_log import (
    AUDIT_PRUNE_WATERMARK_KEY,
    authenticate_prune_watermark,
)
from z4j_brain.settings import Settings

ACTIVATION_MANIFEST_VERSION = 1
ACTIVATION_MANIFEST_DOMAIN = b"z4j/audit-chain/activation-manifest/v1\x00"
MAX_ACTIVATION_MANIFEST_BYTES = 64 * 1024 * 1024
PREPARATION_REVISION = "v1_8_audit_chain_prepare"
ACTIVATION_REVISION = "v1_8_audit_chain_activate"
MAIN_ORIGIN = "audit-log:preparation-v1"
FORK_TABLE = "audit_log_legacy_forks"
FORK_SHAPE_15 = "audit-log-v1-15"
FORK_SHAPE_16 = "audit-log-v1-api-key-16"
_FORK_COLUMNS_15 = (
    "project_id",
    "user_id",
    "action",
    "target_type",
    "target_id",
    "result",
    "metadata",
    "source_ip",
    "user_agent",
    "occurred_at",
    "outcome",
    "event_id",
    "row_hmac",
    "prev_row_hmac",
    "id",
)
_FORK_COLUMNS_16 = (
    "project_id",
    "user_id",
    "api_key_id",
    "action",
    "target_type",
    "target_id",
    "result",
    "metadata",
    "source_ip",
    "user_agent",
    "occurred_at",
    "outcome",
    "event_id",
    "row_hmac",
    "prev_row_hmac",
    "id",
)
_FORK_SHAPES = {
    _FORK_COLUMNS_15: FORK_SHAPE_15,
    _FORK_COLUMNS_16: FORK_SHAPE_16,
}


@dataclass(frozen=True, slots=True)
class _LegacyCandidate:
    row: AuditLog
    origin: str
    source_envelope: list[dict[str, Any]] | None


def _uuid_or_none(value: Any, *, field: str) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuditChainIntegrityError(
            f"fork quarantine {field} is not a canonical UUID",
        ) from exc


def _required_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise AuditChainIntegrityError(
            f"fork quarantine {field} is not text",
        )
    return value


def _optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field=field)


def _metadata_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AuditChainIntegrityError(
                "fork quarantine metadata is not valid JSON",
            ) from exc
    if not isinstance(value, dict):
        raise AuditChainIntegrityError(
            "fork quarantine metadata must be a JSON object",
        )
    # ``canonical_json`` performs the strict recursive JSON-value validation.
    canonical_json(value)
    return value


def _fork_candidate(
    raw: Mapping[str, Any],
    *,
    shape_id: str,
    ordered_columns: Sequence[str],
) -> _LegacyCandidate:
    row_id = _uuid_or_none(raw.get("id"), field="id")
    if row_id is None:
        raise AuditChainIntegrityError("fork quarantine id may not be NULL")
    occurred_at_raw = raw.get("occurred_at")
    try:
        occurred_at = normalize_timestamp(occurred_at_raw)
    except (TypeError, ValueError, AuditChainIntegrityError) as exc:
        raise AuditChainIntegrityError(
            "fork quarantine occurred_at is invalid",
        ) from exc
    metadata = _metadata_object(raw.get("metadata"))
    row_hmac = _optional_text(raw.get("row_hmac"), field="row_hmac")
    structured_hmac = _structured_legacy_hmac(row_hmac)
    provisional_class = "legacy-unsigned" if row_hmac is None else "legacy-invalid"
    row = AuditLog(
        id=row_id,
        project_id=_uuid_or_none(raw.get("project_id"), field="project_id"),
        user_id=_uuid_or_none(raw.get("user_id"), field="user_id"),
        api_key_id=_uuid_or_none(raw.get("api_key_id"), field="api_key_id"),
        action=_required_text(raw.get("action"), field="action"),
        target_type=_required_text(raw.get("target_type"), field="target_type"),
        target_id=_optional_text(raw.get("target_id"), field="target_id"),
        result=_required_text(raw.get("result"), field="result"),
        audit_metadata=metadata,
        source_ip=_optional_text(raw.get("source_ip"), field="source_ip"),
        user_agent=_optional_text(raw.get("user_agent"), field="user_agent"),
        occurred_at=occurred_at,
        outcome=_optional_text(raw.get("outcome"), field="outcome"),
        event_id=_uuid_or_none(raw.get("event_id"), field="event_id"),
        row_hmac=row_hmac,
        prev_row_hmac=_optional_text(
            raw.get("prev_row_hmac"),
            field="prev_row_hmac",
        ),
    )
    snapshot = canonical_frozen_values(
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
        hmac_version=1 if structured_hmac else None,
        hmac_key_id=None,
        legacy_integrity_class=provisional_class,
        legacy_origin=f"fork-quarantine:{shape_id}",
        chain_generation=None,
    )
    source_envelope = [
        {
            "name": name,
            "value": snapshot["metadata" if name == "metadata" else name],
        }
        for name in ordered_columns
    ]
    return _LegacyCandidate(
        row=row,
        origin=f"fork-quarantine:{shape_id}",
        source_envelope=source_envelope,
    )


def _load_fork_candidates(
    connection: Connection,
) -> tuple[list[_LegacyCandidate], dict[str, Any] | None]:
    tables = set(inspect(connection).get_table_names())
    if FORK_TABLE not in tables:
        return [], None
    ordered_columns = tuple(
        str(column["name"]) for column in inspect(connection).get_columns(FORK_TABLE)
    )
    shape_id = _FORK_SHAPES.get(ordered_columns)
    if shape_id is None:
        raise AuditChainIntegrityError(
            f"audit_log_legacy_forks has an unknown shipped schema shape: {ordered_columns!r}",
        )
    selected_columns = ", ".join(f'"{column}"' for column in ordered_columns)
    raw_rows = list(
        connection.exec_driver_sql(
            "SELECT "  # noqa: S608  identifiers matched an exact shipped tuple
            f"{selected_columns} FROM audit_log_legacy_forks "
            'ORDER BY "occurred_at", "id"',
        ).mappings(),
    )
    candidates = [
        _fork_candidate(
            raw,
            shape_id=shape_id,
            ordered_columns=ordered_columns,
        )
        for raw in raw_rows
    ]
    return candidates, {
        "shape_id": shape_id,
        "ordered_columns": list(ordered_columns),
        "row_count": len(candidates),
    }


def _legacy_entry(row: AuditLog) -> AuditEntry:
    return AuditEntry(
        id=row.id,
        action=row.action,
        target_type=row.target_type,
        target_id=row.target_id,
        result=row.result,
        outcome=row.outcome,
        event_id=row.event_id,
        user_id=row.user_id,
        project_id=row.project_id,
        api_key_id=row.api_key_id,
        source_ip=str(row.source_ip) if row.source_ip is not None else None,
        user_agent=row.user_agent,
        metadata=row.audit_metadata,
        occurred_at=row.occurred_at,
        prev_row_hmac=row.prev_row_hmac,
    )


def _structured_legacy_hmac(value: str | None) -> bool:
    if value is None or len(value) != 64 or value.lower() != value:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _matching_legacy_key(
    service: AuditService,
    row: AuditLog,
    secrets: Sequence[bytes],
) -> str | None:
    if not _structured_legacy_hmac(row.row_hmac):
        return None
    assert row.row_hmac is not None
    entry = _legacy_entry(row)
    for secret in secrets:
        expected = service._compute_hmac(entry, secret=secret)
        if hmac.compare_digest(expected, row.row_hmac):
            return canonical_audit_key_id(secret)
    return None


def _preparation_payload(
    session: Session,
    settings: Settings,
) -> dict[str, Any]:
    rows = list(
        session.execute(
            select(AuditChainPreparation),
        )
        .scalars()
        .all()
    )
    if len(rows) != 1:
        raise AuditChainIntegrityError(
            "audit-chain preparation is missing or duplicated",
        )
    audit_keys = settings.all_audit_chain_secrets_for_verification()
    keyring = {canonical_audit_key_id(secret): secret for secret in audit_keys}
    payload = authenticate_preparation(rows[0], keyring)
    if (
        payload["preparation_revision"] != PREPARATION_REVISION
        or payload["target_activation_revision"] != ACTIVATION_REVISION
    ):
        raise AuditChainIntegrityError(
            "audit-chain preparation revision binding is invalid",
        )
    return payload


def _migration_head(connection: Connection) -> str:
    heads = list(
        connection.execute(text("SELECT version_num FROM alembic_version")).scalars(),
    )
    if heads != [PREPARATION_REVISION]:
        observed = heads[0] if len(heads) == 1 else repr(heads)
        raise AuditChainIntegrityError(
            f"activation requires the exact preparation migration head (observed {observed!r})",
        )
    return heads[0]


def _manifest_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        ACTIVATION_MANIFEST_DOMAIN + canonical_json(payload),
    ).hexdigest()


def _normalize_cutover_known_head(  # noqa: PLR0911, PLR0912  strict envelope
    raw: Mapping[str, Any] | None,
) -> tuple[dict[str, Any] | None, bool]:
    if raw is None:
        return None, True
    allowed = {
        "row_hmac",
        "hmac_version",
        "hmac_key_id",
        "generation",
        "occurred_at",
        "id",
    }
    if set(raw) - allowed:
        return {"__invalid__": True}, False
    row_hmac = raw.get("row_hmac")
    try:
        normalized_hmac = normalize_hmac(row_hmac, field="known-head row_hmac")
    except AuditChainIntegrityError:
        return {"__invalid__": True}, False
    if normalized_hmac is None or normalized_hmac != row_hmac:
        return {"__invalid__": True}, False
    normalized: dict[str, Any] = {"row_hmac": normalized_hmac}
    if "hmac_version" in raw:
        if raw["hmac_version"] != 1:
            return {"__invalid__": True}, False
        normalized["hmac_version"] = 1
    if "hmac_key_id" in raw:
        try:
            key_id = normalize_hmac(
                raw["hmac_key_id"],
                field="known-head hmac_key_id",
            )
        except AuditChainIntegrityError:
            return {"__invalid__": True}, False
        if key_id is None or key_id != raw["hmac_key_id"]:
            return {"__invalid__": True}, False
        normalized["hmac_key_id"] = key_id
    for field in ("generation", "id"):
        if field in raw:
            try:
                value = normalize_uuid(raw[field], field=f"known-head {field}")
            except AuditChainIntegrityError:
                return {"__invalid__": True}, False
            if value is None:
                return {"__invalid__": True}, False
            normalized[field] = value
    if "occurred_at" in raw:
        try:
            normalized["occurred_at"] = timestamp_text(raw["occurred_at"])
        except (AttributeError, TypeError, AuditChainIntegrityError):
            return {"__invalid__": True}, False
    return normalized, True


def _known_head_matches_frozen(
    envelope: Mapping[str, Any],
    classification: Mapping[str, Any],
) -> bool:
    snapshot = classification["frozen_snapshot"]
    expected = {
        "row_hmac": snapshot["row_hmac"],
        "hmac_version": snapshot["hmac_version"],
        "hmac_key_id": snapshot["hmac_key_id"],
        "occurred_at": snapshot["occurred_at"],
        "id": snapshot["id"],
    }
    if "generation" in envelope:
        return False
    return all(expected.get(field) == value for field, value in envelope.items())


def _assess_cutover_known_head(
    raw: Mapping[str, Any] | None,
    *,
    classifications: Sequence[Mapping[str, Any]],
    authenticated_watermark: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    envelope, valid = _normalize_cutover_known_head(raw)
    if not valid:
        return envelope, "INVALID"
    if envelope is None:
        return None, None
    if authenticated_watermark is not None and envelope == {"row_hmac": authenticated_watermark}:
        return envelope, "PRUNE_MATCH"
    main = [item for item in classifications if item["legacy_origin"] == MAIN_ORIGIN]
    if not main or any(item["legacy_integrity_class"] != "legacy-linked-verified" for item in main):
        return envelope, "UNPROVABLE"
    matches = [
        index for index, item in enumerate(main) if _known_head_matches_frozen(envelope, item)
    ]
    if not matches:
        return envelope, "UNPROVABLE"
    return (
        envelope,
        "CURRENT_MATCH" if matches[-1] == len(main) - 1 else "VERIFIED_ANCESTOR",
    )


def build_activation_manifest(  # noqa: PLR0912, PLR0915  exhaustive classification
    connection: Connection,
    settings: Settings,
    *,
    legacy_key_window_complete: bool,
    known_head: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify one stable preparation-head snapshot without mutating it."""

    _migration_head(connection)
    tables = set(inspect(connection).get_table_names())
    if "audit_chain_state" in tables:
        raise AuditChainIntegrityError(
            "audit_chain_state already exists before explicit activation",
        )
    with Session(bind=connection) as session:
        preparation = _preparation_payload(session, settings)
        main_rows = list(
            session.execute(
                select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id),
            )
            .scalars()
            .all()
        )
    for row in main_rows:
        if any(
            value is not None
            for value in (
                row.legacy_frozen,
                row.hmac_version,
                row.hmac_key_id,
                row.legacy_integrity_class,
                row.legacy_origin,
                row.chain_generation,
            )
        ):
            raise AuditChainIntegrityError(
                "legacy audit markers are already populated before activation",
            )
    fork_candidates, auxiliary_source = _load_fork_candidates(connection)
    candidates = [
        *(
            _LegacyCandidate(
                row=row,
                origin=MAIN_ORIGIN,
                source_envelope=None,
            )
            for row in main_rows
        ),
        *fork_candidates,
    ]
    candidate_ids = [candidate.row.id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise AuditChainIntegrityError(
            "audit_log and audit_log_legacy_forks contain a duplicate row id",
        )
    candidates.sort(
        key=lambda candidate: (
            normalize_timestamp(candidate.row.occurred_at),
            candidate.row.id.int,
        ),
    )

    master_secrets = settings.all_secrets_for_verification()
    service = AuditService(settings)
    matching = {
        candidate.row.id: _matching_legacy_key(
            service,
            candidate.row,
            master_secrets,
        )
        for candidate in candidates
    }
    stored_watermark = connection.execute(
        text("SELECT value FROM z4j_meta WHERE key = :key"),
        {"key": AUDIT_PRUNE_WATERMARK_KEY},
    ).scalar_one_or_none()
    authenticated_watermark = authenticate_prune_watermark(
        master_secrets,
        str(stored_watermark) if stored_watermark is not None else None,
    )
    failures: list[str] = []
    if stored_watermark is not None and authenticated_watermark is None:
        failures.append("unauthenticated-prune-watermark")
    if not candidates:
        failures.append("existing-empty-audit-table")

    verified_hmacs = {
        candidate.row.row_hmac
        for candidate in candidates
        if matching[candidate.row.id] is not None and candidate.row.row_hmac is not None
    }
    classifications: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    main_prior_hmac: str | None = None
    main_index = 0
    for candidate in candidates:
        row = candidate.row
        key_id = matching[row.id]
        if row.row_hmac is None:
            integrity_class = "legacy-unsigned"
        elif key_id is None:
            integrity_class = (
                "legacy-invalid"
                if legacy_key_window_complete
                else "legacy-unverifiable-key-unavailable"
            )
        elif candidate.origin != MAIN_ORIGIN:
            integrity_class = (
                "legacy-fork-verified"
                if row.prev_row_hmac in verified_hmacs
                else "legacy-standalone-verified"
            )
        else:
            expected_link = (
                authenticated_watermark
                if main_index == 0 and authenticated_watermark is not None
                else main_prior_hmac
            )
            if row.prev_row_hmac == expected_link:
                integrity_class = "legacy-linked-verified"
            elif row.prev_row_hmac in verified_hmacs:
                integrity_class = "legacy-fork-verified"
            else:
                integrity_class = "legacy-standalone-verified"
        if integrity_class != "legacy-linked-verified":
            failures.append(f"{row.id}:{integrity_class}")
        hmac_version = 1 if _structured_legacy_hmac(row.row_hmac) else None
        classification = {
            "id": str(row.id),
            "legacy_integrity_class": integrity_class,
            "legacy_origin": candidate.origin,
            "hmac_version": hmac_version,
            "hmac_key_id": key_id,
        }
        snapshot = canonical_frozen_values(
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
            hmac_version=hmac_version,
            hmac_key_id=key_id,
            legacy_integrity_class=integrity_class,
            legacy_origin=candidate.origin,
            chain_generation=None,
        )
        if candidate.source_envelope is not None:
            classification["source_envelope"] = candidate.source_envelope
        classifications.append(
            {**classification, "frozen_snapshot": snapshot},
        )
        snapshots.append(snapshot)
        if candidate.origin == MAIN_ORIGIN:
            main_prior_hmac = row.row_hmac
            main_index += 1

    normalized_known_head, known_head_result = _assess_cutover_known_head(
        known_head,
        classifications=classifications,
        authenticated_watermark=authenticated_watermark,
    )
    if known_head_result in {"INVALID", "UNPROVABLE"}:
        failures.append(f"known-head:{known_head_result}")

    payload: dict[str, Any] = {
        "format_version": ACTIVATION_MANIFEST_VERSION,
        "preparation_id": preparation["preparation_id"],
        "preparation_audit_key_id": preparation["audit_key_id"],
        "preparation_revision": PREPARATION_REVISION,
        "target_activation_revision": ACTIVATION_REVISION,
        "legacy_key_window_complete": legacy_key_window_complete,
        "authenticated_legacy_prune_watermark": authenticated_watermark,
        "known_head": normalized_known_head,
        "known_head_result": known_head_result,
        "auxiliary_source": auxiliary_source,
        "classifications": classifications,
        "frozen_row_count": len(candidates),
        "frozen_snapshot_digest": frozen_snapshot_digest(snapshots),
        "classification_failures": sorted(set(failures)),
        "requires_ambiguity_attestation": bool(failures),
    }
    return {**payload, "manifest_digest": _manifest_digest(payload)}


def validate_activation_manifest(
    manifest: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> None:
    if canonical_json(dict(manifest)) != canonical_json(dict(observed)):
        raise AuditChainIntegrityError(
            "finalized activation manifest no longer matches the locked database",
        )


_POSIX_STABLE_FILE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)

_POSIX_STABLE_PARENT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_nlink",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _posix_file_identity(observed: os.stat_result) -> tuple[int, int]:
    return observed.st_dev, observed.st_ino


def _posix_stable_file_identity(observed: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(observed, field) for field in _POSIX_STABLE_FILE_FIELDS)


def _posix_stable_parent_identity(observed: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(observed, field) for field in _POSIX_STABLE_PARENT_FIELDS)


def _close_activation_fds(*file_descriptors: int) -> None:
    """Close every owned descriptor, surfacing the first close failure."""
    first_error: OSError | None = None
    for file_descriptor in file_descriptors:
        if file_descriptor < 0:
            continue
        try:
            os.close(file_descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _require_activation_identity(
    expected: tuple[int, int],
    *observations: os.stat_result,
    message: str,
) -> None:
    if any(expected != _posix_file_identity(observed) for observed in observations):
        raise AuditChainIntegrityError(message)


def _require_activation_parent_stable(
    expected: tuple[int, ...],
    *observations: os.stat_result,
    message: str,
) -> None:
    if any(_posix_stable_parent_identity(observed) != expected for observed in observations):
        raise AuditChainIntegrityError(message)


def _require_private_activation_parent(observed: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_mode & 0o077
    ):
        raise AuditChainIntegrityError(
            "activation manifest parent must be an owner-private real directory",
        )


def _open_activation_parent_walk(parent: Path) -> int:
    """Open every lexical parent component without following links."""
    absolute_parent = parent if parent.is_absolute() else Path.cwd() / parent
    components = absolute_parent.parts[1:]
    if any(component in {os.curdir, os.pardir} for component in components):
        raise AuditChainIntegrityError(
            "activation manifest parent path must contain only real directories",
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptors = [os.open(os.sep, flags)]
    try:
        for component in components:
            try:
                descriptors.append(
                    os.open(component, flags, dir_fd=descriptors[-1]),
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise AuditChainIntegrityError(
                        "activation manifest parent path must contain only real directories",
                    ) from exc
                raise
        directory_fd = descriptors.pop()
        ancestor_fds = tuple(reversed(descriptors))
        descriptors.clear()
        try:
            _close_activation_fds(*ancestor_fds)
        except BaseException:
            with suppress(OSError):
                _close_activation_fds(directory_fd)
            raise
        return directory_fd
    except BaseException:
        with suppress(OSError):
            _close_activation_fds(*reversed(descriptors))
        raise


def _open_private_activation_parent(parent: Path) -> tuple[int, tuple[int, ...]]:
    directory_fd = _open_activation_parent_walk(parent)
    try:
        opened = os.fstat(directory_fd)
        _require_private_activation_parent(opened)
        expected = _posix_stable_parent_identity(opened)
        try:
            verification_fd = _open_activation_parent_walk(parent)
        except (AuditChainIntegrityError, OSError) as exc:
            raise AuditChainIntegrityError(
                "activation manifest parent changed while its descriptor was acquired",
            ) from exc
        try:
            after = os.fstat(verification_fd)
        finally:
            _close_activation_fds(verification_fd)
        _require_activation_parent_stable(
            expected,
            after,
            message="activation manifest parent changed while its descriptor was acquired",
        )
        _require_private_activation_parent(after)
        return directory_fd, expected
    except BaseException:
        with suppress(OSError):
            _close_activation_fds(directory_fd)
        raise


def _require_activation_parent_path(
    parent: Path,
    expected: tuple[int, ...],
    *,
    operation: str,
) -> None:
    try:
        verification_fd = _open_activation_parent_walk(parent)
    except (AuditChainIntegrityError, OSError) as exc:
        raise AuditChainIntegrityError(
            f"activation manifest parent changed while it was {operation}",
        ) from exc
    try:
        observed = os.fstat(verification_fd)
    finally:
        _close_activation_fds(verification_fd)
    if expected != _posix_stable_parent_identity(observed):
        raise AuditChainIntegrityError(
            f"activation manifest parent changed while it was {operation}",
        )
    _require_private_activation_parent(observed)


def _require_private_activation_file(
    observed: os.stat_result,
    *,
    require_empty: bool,
) -> None:
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
        or observed.st_nlink != 1
        or (require_empty and observed.st_size != 0)
    ):
        state = "new" if require_empty else "single-link"
        raise AuditChainIntegrityError(
            f"activation manifest must be an owner-private {state} file (chmod 600)",
        )


def _require_activation_file_stable(
    *observations: os.stat_result,
    expected_size: int | None = None,
    message: str,
) -> None:
    for observed in observations:
        _require_private_activation_file(observed, require_empty=False)
    identities = {_posix_stable_file_identity(observed) for observed in observations}
    if len(identities) != 1 or (
        expected_size is not None and observations[0].st_size != expected_size
    ):
        raise AuditChainIntegrityError(message)


def _write_activation_manifest_windows(path: Path, payload: bytes) -> None:
    from z4j_brain._windows_secure_io import (
        close_handle,
        create_relative_file,
        directory_path_identity,
        handle_identity,
        open_directory,
        relative_file_identity,
    )

    parent = path.parent
    before = directory_path_identity(parent, require_private=True)
    directory_handle, opened = open_directory(parent, require_private=True)
    manifest_handle = 0
    try:
        after_open = directory_path_identity(parent, require_private=True)
        if before != opened or opened != after_open:
            raise AuditChainIntegrityError(
                "activation manifest parent changed while its handle was acquired",
            )
        manifest_handle = create_relative_file(directory_handle, path.name, payload)
        manifest_identity = handle_identity(manifest_handle)
        if (
            relative_file_identity(directory_handle, path.name) != manifest_identity
            or directory_path_identity(parent, require_private=True) != opened
        ):
            raise AuditChainIntegrityError(
                "activation manifest pathname changed while it was finalized",
            )
    finally:
        try:
            if manifest_handle:
                close_handle(manifest_handle)
        finally:
            close_handle(directory_handle)


def _create_activation_file_at(
    directory_fd: int,
    name: str,
) -> tuple[int, tuple[int, int]]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        opened_file = os.fstat(file_fd)
        created_identity = _posix_file_identity(opened_file)
        _require_private_activation_file(opened_file, require_empty=True)
        opened_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _require_activation_identity(
            created_identity,
            opened_entry,
            message="activation manifest pathname changed while it was created",
        )
        return file_fd, created_identity
    except BaseException:
        with suppress(OSError):
            _close_activation_fds(file_fd)
        raise


def _write_activation_payload_at(
    directory_fd: int,
    name: str,
    file_fd: int,
    created_identity: tuple[int, int],
    payload: bytes,
) -> os.stat_result:
    offset = 0
    while offset < len(payload):
        written = os.write(file_fd, payload[offset:])
        if written <= 0:
            raise AuditChainIntegrityError("activation manifest write made no progress")
        offset += written
    os.fsync(file_fd)
    closed_file = os.fstat(file_fd)
    closed_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _require_activation_identity(
        created_identity,
        closed_file,
        closed_entry,
        message="activation manifest changed while it was finalized",
    )
    _require_activation_file_stable(
        closed_file,
        closed_entry,
        expected_size=len(payload),
        message="activation manifest changed while it was finalized",
    )
    return closed_file


def _write_activation_manifest_posix(path: Path, payload: bytes) -> None:
    directory_fd, _opened_parent_identity = _open_private_activation_parent(path.parent)
    file_fd = -1
    try:
        file_fd, created_identity = _create_activation_file_at(directory_fd, path.name)
        parent_identity = _posix_stable_parent_identity(os.fstat(directory_fd))
        _require_activation_parent_path(path.parent, parent_identity, operation="created")
        finalized_file = _write_activation_payload_at(
            directory_fd,
            path.name,
            file_fd,
            created_identity,
            payload,
        )
        _require_activation_parent_path(path.parent, parent_identity, operation="finalized")
        os.fsync(directory_fd)
        durable_entry = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        _require_activation_file_stable(
            finalized_file,
            durable_entry,
            expected_size=len(payload),
            message="activation manifest changed while it was durably finalized",
        )
        _require_activation_parent_path(
            path.parent,
            parent_identity,
            operation="durably finalized",
        )
    except BaseException:
        if file_fd >= 0:
            # Invalidate only the inode we created, through its still-owned FD.
            # Pathname cleanup cannot be made identity-conditional on POSIX and
            # could delete an attacker-swapped replacement.  Truncation makes
            # a failed publication unreadable while retaining the O_EXCL fence.
            with suppress(OSError):
                os.ftruncate(file_fd, 0)
                os.fsync(file_fd)
            closing_fd = file_fd
            file_fd = -1
            with suppress(OSError):
                _close_activation_fds(closing_fd)
        # Deliberately retain the exclusively-created entry on failure. POSIX
        # has no portable atomic "unlink this name iff it still identifies this
        # inode" operation: a stat-then-unlink cleanup can delete an attacker-
        # swapped replacement. Retention is fail closed (a retry hits O_EXCL)
        # and leaves the exact failure artifact for operator inspection.
        with suppress(OSError):
            _close_activation_fds(directory_fd)
        raise
    else:
        closing_fd = file_fd
        file_fd = -1
        try:
            _close_activation_fds(closing_fd)
        finally:
            _close_activation_fds(directory_fd)


def write_activation_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    """Create one owner-private fsynced manifest without following links."""

    payload = canonical_json(dict(manifest)) + b"\n"
    if os.name == "nt":
        _write_activation_manifest_windows(path, payload)
    else:
        _write_activation_manifest_posix(path, payload)


def _read_activation_manifest_windows(path: Path) -> bytes:
    from z4j_brain._windows_secure_io import (
        close_handle,
        directory_path_identity,
        open_directory,
        read_relative,
    )

    before = directory_path_identity(path.parent, require_private=True)
    directory_handle, opened = open_directory(
        path.parent,
        require_private=True,
    )
    try:
        after_open = directory_path_identity(
            path.parent,
            require_private=True,
        )
        if before != opened or opened != after_open:
            raise AuditChainIntegrityError(
                "activation manifest parent changed while its handle was acquired",
            )
        raw, file_identity = read_relative(
            directory_handle,
            path.name,
            maximum_bytes=MAX_ACTIVATION_MANIFEST_BYTES,
            require_private=True,
        )
        if file_identity is None:
            raise FileNotFoundError(path)
        if directory_path_identity(path.parent, require_private=True) != opened:
            raise AuditChainIntegrityError(
                "activation manifest parent changed while it was read",
            )
        return raw
    finally:
        close_handle(directory_handle)


def _read_activation_manifest_posix(path: Path) -> bytes:
    directory_fd, parent_identity = _open_private_activation_parent(path.parent)
    fd = -1
    try:
        before_path = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        _require_private_activation_file(before_path, require_empty=False)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        flags |= os.O_NONBLOCK
        fd = os.open(path.name, flags, dir_fd=directory_fd)
        before = os.fstat(fd)
        _require_activation_identity(
            _posix_file_identity(before_path),
            before,
            message="activation manifest changed while its descriptor was acquired",
        )
        _require_private_activation_file(before, require_empty=False)
        chunks: list[bytes] = []
        remaining = MAX_ACTIVATION_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        after_path = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        _require_activation_file_stable(
            before,
            after,
            message="activation manifest changed while read",
        )
        _require_activation_file_stable(
            after,
            after_path,
            message="activation manifest pathname changed",
        )
        _require_activation_parent_path(path.parent, parent_identity, operation="read")
    except BaseException:
        with suppress(OSError):
            _close_activation_fds(fd, directory_fd)
        raise
    else:
        _close_activation_fds(fd, directory_fd)
        return raw


def read_activation_manifest(path: Path) -> dict[str, Any]:
    """Read back one bounded owner-private finalized manifest."""

    raw = (
        _read_activation_manifest_windows(path)
        if os.name == "nt"
        else _read_activation_manifest_posix(path)
    )

    if len(raw) > MAX_ACTIVATION_MANIFEST_BYTES:
        raise AuditChainIntegrityError("activation manifest exceeds 64 MiB")

    def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuditChainIntegrityError(
                    f"activation manifest contains duplicate key {key!r}",
                )
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditChainIntegrityError("activation manifest is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise AuditChainIntegrityError("activation manifest root must be an object")
    digest = parsed.get("manifest_digest")
    payload = {key: value for key, value in parsed.items() if key != "manifest_digest"}
    if digest != _manifest_digest(payload):
        raise AuditChainIntegrityError("activation manifest digest mismatch")
    return parsed


__all__ = [
    "ACTIVATION_MANIFEST_VERSION",
    "MAIN_ORIGIN",
    "build_activation_manifest",
    "read_activation_manifest",
    "validate_activation_manifest",
    "write_activation_manifest",
]
