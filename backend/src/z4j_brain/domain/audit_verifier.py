"""Stable-snapshot verification for the active Boundary-F audit generation."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    authenticate_state,
    canonical_audit_key_id,
    canonical_frozen_row_snapshot,
    frozen_snapshot_digest,
    normalize_timestamp,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings

KNOWN_HEAD_RESULTS = frozenset(
    {
        "CURRENT_MATCH",
        "PRUNE_MATCH",
        "CURRENT_PRUNE_MATCH",
        "VERIFIED_ANCESTOR",
        "INVALID",
        "UNPROVABLE",
    }
)


@dataclass(frozen=True, slots=True)
class AuditVerificationReport:
    verified_active_rows: int
    verified_frozen_rows: int
    mismatches: tuple[str, ...]
    known_head_result: str | None

    @property
    def clean(self) -> bool:
        return not self.mismatches and self.known_head_result not in {
            "INVALID",
            "UNPROVABLE",
        }


def _known_head_matches(
    envelope: Mapping[str, Any],
    *,
    row_hmac: str,
    hmac_key_id: str,
    generation: uuid.UUID,
    occurred_at: datetime,
    row_id: uuid.UUID,
) -> bool:
    if envelope["row_hmac"] != row_hmac:
        return False
    optional = {
        "hmac_version": 2,
        "hmac_key_id": hmac_key_id,
        "generation": str(generation).lower(),
        "occurred_at": normalize_timestamp(occurred_at)
        .isoformat(
            timespec="microseconds",
        )
        .replace("+00:00", "Z"),
        "id": str(row_id).lower(),
    }
    return all(key not in envelope or envelope[key] == value for key, value in optional.items())


def _normalize_known_head(  # noqa: PLR0911, PLR0912  strict envelope validation
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
        return None, False
    row_hmac = raw.get("row_hmac")
    if not isinstance(row_hmac, str) or len(row_hmac) != 64 or row_hmac.lower() != row_hmac:
        return None, False
    try:
        int(row_hmac, 16)
    except ValueError:
        return None, False
    normalized: dict[str, Any] = {"row_hmac": row_hmac}
    if "hmac_version" in raw:
        if raw["hmac_version"] != 2:
            return None, False
        normalized["hmac_version"] = 2
    if "hmac_key_id" in raw:
        value = raw["hmac_key_id"]
        if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
            return None, False
        try:
            int(value, 16)
        except ValueError:
            return None, False
        normalized["hmac_key_id"] = value
    for key in ("generation", "id"):
        if key in raw:
            try:
                normalized[key] = str(uuid.UUID(str(raw[key]))).lower()
            except (TypeError, ValueError, AttributeError):
                return None, False
    if "occurred_at" in raw:
        try:
            normalized["occurred_at"] = (
                normalize_timestamp(
                    str(raw["occurred_at"]),
                )
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
        except (TypeError, ValueError, AuditChainIntegrityError):
            return None, False
    return normalized, True


async def verify_active_audit_generation(  # noqa: PLR0912, PLR0915  full verifier
    session: AsyncSession,
    settings: Settings,
    *,
    page_size: int,
    known_head: Mapping[str, Any] | None = None,
) -> AuditVerificationReport:
    """Verify state, frozen manifest, retained chain, counts, and exact head."""

    if not 1 <= page_size <= 5000:
        raise ValueError("page_size must be between 1 and 5000")
    if session.bind is None:
        raise RuntimeError("audit verifier session is not bound")

    repo = AuditLogRepository(session)
    dialect = session.bind.dialect.name
    if dialect == "sqlite":
        await repo.require_sqlite_immediate_write_unit()
    else:
        await repo.acquire_chain_lock()
        await session.execute(text("LOCK TABLE audit_log IN SHARE MODE"))

    state = await repo.get_chain_state_for_update()
    audit_secrets = settings.all_audit_chain_secrets_for_verification()
    keyring = {canonical_audit_key_id(secret): secret for secret in audit_secrets}
    authenticate_state(state, keyring)
    audit = AuditService(settings)
    mismatches: list[str] = []

    active_count = await repo.count_active_generation(generation=state.generation)
    frozen_count = await repo.count_frozen_rows()
    if active_count != state.active_row_count:
        mismatches.append(
            f"active row count {active_count} != authenticated {state.active_row_count}",
        )
    if frozen_count != state.frozen_row_count:
        mismatches.append(
            f"frozen row count {frozen_count} != authenticated {state.frozen_row_count}",
        )

    frozen_rows = list(
        (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.legacy_frozen.is_(True))
                .order_by(AuditLog.occurred_at, AuditLog.id),
            )
        )
        .scalars()
        .all()
    )
    observed_frozen_digest = frozen_snapshot_digest(
        [canonical_frozen_row_snapshot(row) for row in frozen_rows],
    )
    if observed_frozen_digest != state.frozen_snapshot_digest:
        mismatches.append("frozen snapshot digest mismatch")

    cursor_time: datetime | None = None
    cursor_id: uuid.UUID | None = None
    previous = state.prune_row_hmac
    verified = 0
    key_counts: Counter[str] = Counter()
    retained: list[AuditLog] = []
    while True:
        stmt = (
            select(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == state.generation,
            )
            .order_by(AuditLog.occurred_at, AuditLog.id)
            .limit(page_size)
        )
        if cursor_time is not None and cursor_id is not None:
            stmt = stmt.where(
                or_(
                    AuditLog.occurred_at > cursor_time,
                    (AuditLog.occurred_at == cursor_time) & (AuditLog.id > cursor_id),
                ),
            )
        rows = list((await session.execute(stmt)).scalars().all())
        if not rows:
            break
        for row in rows:
            retained.append(row)
            if row.prev_row_hmac != previous:
                mismatches.append(f"{row.id} active chain link mismatch")
            if not audit.verify_row(row):
                mismatches.append(f"{row.id} active row HMAC mismatch")
            else:
                verified += 1
            if row.hmac_key_id is not None:
                key_counts[row.hmac_key_id] += 1
            previous = row.row_hmac
        cursor_time = rows[-1].occurred_at
        cursor_id = rows[-1].id
        if len(rows) < page_size:
            break

    if dict(sorted(key_counts.items())) != dict(
        sorted(state.active_key_counts.items()),
    ):
        mismatches.append("active per-key counts mismatch")
    if retained:
        tail = retained[-1]
        if (
            tail.row_hmac != state.head_row_hmac
            or tail.hmac_key_id != state.head_hmac_key_id
            or normalize_timestamp(tail.occurred_at) != normalize_timestamp(state.head_occurred_at)
            or tail.id != state.head_id
        ):
            mismatches.append("retained tail does not match authenticated head")
    elif state.active_row_count != 0:
        mismatches.append("authenticated active head has no retained row")

    envelope, valid_envelope = _normalize_known_head(known_head)
    known_result: str | None = None
    if not valid_envelope:
        known_result = "INVALID"
    elif envelope is not None:
        current_match = (
            state.head_row_hmac is not None
            and state.head_hmac_key_id is not None
            and state.head_occurred_at is not None
            and state.head_id is not None
            and _known_head_matches(
                envelope,
                row_hmac=state.head_row_hmac,
                hmac_key_id=state.head_hmac_key_id,
                generation=state.generation,
                occurred_at=state.head_occurred_at,
                row_id=state.head_id,
            )
        )
        prune_match = (
            state.prune_row_hmac is not None
            and state.prune_hmac_key_id is not None
            and state.prune_occurred_at is not None
            and state.prune_id is not None
            and _known_head_matches(
                envelope,
                row_hmac=state.prune_row_hmac,
                hmac_key_id=state.prune_hmac_key_id,
                generation=state.generation,
                occurred_at=state.prune_occurred_at,
                row_id=state.prune_id,
            )
        )
        if current_match and prune_match:
            known_result = "CURRENT_PRUNE_MATCH"
        elif current_match:
            known_result = "CURRENT_MATCH"
        elif prune_match:
            known_result = "PRUNE_MATCH"
        elif any(
            row.row_hmac is not None
            and row.hmac_key_id is not None
            and _known_head_matches(
                envelope,
                row_hmac=row.row_hmac,
                hmac_key_id=row.hmac_key_id,
                generation=state.generation,
                occurred_at=row.occurred_at,
                row_id=row.id,
            )
            for row in retained
        ):
            known_result = "VERIFIED_ANCESTOR"
        else:
            known_result = "UNPROVABLE"

    return AuditVerificationReport(
        verified_active_rows=verified,
        verified_frozen_rows=len(frozen_rows),
        mismatches=tuple(mismatches),
        known_head_result=known_result,
    )


__all__ = [
    "KNOWN_HEAD_RESULTS",
    "AuditVerificationReport",
    "verify_active_audit_generation",
]
