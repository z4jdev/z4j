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
    frozen_row_snapshot_or_defect,
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

#: How many mismatch strings one report carries. The first hundred already
#: name the fault, and a chain producing more than that has a systemic problem
#: rather than a hundred separate ones. Most callers render the whole tuple
#: into a single log record, where an unbounded list turns "the chain did not
#: verify" into an outage, which is the one thing this machinery must never do.
#: (``z4j audit verify`` prints one line per entry to stdout instead, so the
#: outage argument does not apply there; the cap is uniform anyway so every
#: caller sees the same report, and the overflow is named in the tuple itself.)
_MAX_REPORTED_MISMATCHES = 100


@dataclass(frozen=True, slots=True)
class AuditVerificationReport:
    verified_active_rows: int
    verified_frozen_rows: int
    mismatches: tuple[str, ...]
    known_head_result: str | None
    #: How many findings this run produced, cap or no cap. ``len(mismatches)``
    #: answers a different question -- how many strings the report carries --
    #: and once the cap bites that is the cap plus the one line naming the
    #: overflow. An operator shown "MISMATCHES (101)" for a chain with 123
    #: findings has been handed a wrong number, not a rounded one, at the
    #: moment they are deciding how bad this is. Renderers count this instead.
    mismatch_count: int
    #: Mismatches found past the reporting cap, so a truncated report still
    #: says how much of the finding it is not showing.
    mismatches_truncated: int = 0
    #: Rows in ``audit_log`` that neither the active generation nor the frozen
    #: manifest accounts for. Every other check below is scoped to one of
    #: those two, so these rows are compared to nothing at all.
    unattributed_rows: int = 0

    @property
    def clean(self) -> bool:
        # Both the strings and the tally, because a report is only ever read
        # to decide whether to act, and either one of them being empty on its
        # own would be enough to make a failed run answer "nothing to do".
        if self.mismatches or self.mismatch_count:
            return False
        return self.known_head_result not in {"INVALID", "UNPROVABLE"}


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
    # One counter for every finding, which is the only number that is true
    # regardless of the cap. What was kept and what was dropped are both
    # derived from it at the single point where the report is built, so the
    # three can never disagree about the same run.
    mismatch_count = 0

    def note_mismatch(message: str) -> None:
        nonlocal mismatch_count
        mismatch_count += 1
        if len(mismatches) < _MAX_REPORTED_MISMATCHES:
            mismatches.append(message)

    total_count = await repo.count_all_rows()
    active_count = await repo.count_active_generation(generation=state.generation)
    frozen_count = await repo.count_frozen_rows()
    if active_count != state.active_row_count:
        note_mismatch(
            f"active row count {active_count} != authenticated {state.active_row_count}",
        )
    if frozen_count != state.frozen_row_count:
        note_mismatch(
            f"frozen row count {frozen_count} != authenticated {state.frozen_row_count}",
        )
    # Every check below selects on the active generation or on the frozen
    # flag, so a row carrying some other generation is counted by nothing and
    # has its HMAC compared to nothing: it verifies clean by never being
    # looked at. The activation constraint and the insert trigger both admit
    # such a row, and ``AuditService.reset_generation`` already refuses one,
    # so without this the two authorities disagree about the same database.
    #
    # Derived from the counts rather than from the ``verified`` tally below,
    # which only advances on a row that passed: subtracting that instead would
    # report every genuine HMAC failure a second time as an intruder.
    unattributed_rows = total_count - active_count - frozen_count
    if unattributed_rows > 0:
        note_mismatch(
            f"audit table contains {unattributed_rows} rows outside the authenticated generations",
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
    # A frozen row is immutable by construction, so one that no longer
    # canonicalizes is precisely the tampering this walk exists to catch, and
    # it has to arrive as a finding. Canonicalizing straight into the digest
    # made it arrive as an exception instead: the report built so far was
    # discarded, and the scheduled verifier logged the whole run as an error
    # it should retry, which is what an operator reads as a flaky job rather
    # than as a corrupted chain.
    frozen_snapshots: list[dict[str, Any]] = []
    uncanonical_frozen = 0
    for row in frozen_rows:
        snapshot, defect = frozen_row_snapshot_or_defect(row)
        if snapshot is None:
            uncanonical_frozen += 1
            note_mismatch(f"{row.id} frozen row is not canonical: {defect}")
            continue
        frozen_snapshots.append(snapshot)
    if uncanonical_frozen:
        # The authenticated digest covers these rows in their canonical form.
        # Once a row has lost that form there is nothing left to compare it
        # against, so the manifest is unproven rather than merely different,
        # and digesting the rows that survived would name the wrong fault.
        note_mismatch(
            f"frozen snapshot digest is unprovable: {uncanonical_frozen} "
            "frozen row(s) could not be canonicalized",
        )
    elif frozen_snapshot_digest(frozen_snapshots) != state.frozen_snapshot_digest:
        note_mismatch("frozen snapshot digest mismatch")

    # Normalized before the walk, not after it, so each page can answer the
    # anchor question while its rows are in scope. Pure, so the position
    # cannot change the answer.
    envelope, valid_envelope = _normalize_known_head(known_head)

    cursor_time: datetime | None = None
    cursor_id: uuid.UUID | None = None
    previous = state.prune_row_hmac
    verified = 0
    key_counts: Counter[str] = Counter()
    tail: AuditLog | None = None
    ancestor_match = False
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
            if row.prev_row_hmac != previous:
                note_mismatch(f"{row.id} active chain link mismatch")
            if not audit.verify_row(row):
                note_mismatch(f"{row.id} active row HMAC mismatch")
            else:
                verified += 1
            if row.hmac_key_id is not None:
                key_counts[row.hmac_key_id] += 1
            # Answered per page rather than from a list of every row walked:
            # pinning the whole active generation in memory to settle one
            # boolean is a cost every operator pays, since startup runs this
            # walk unconditionally on a chain of any size.
            if (
                envelope is not None
                and not ancestor_match
                and row.row_hmac is not None
                and row.hmac_key_id is not None
                and _known_head_matches(
                    envelope,
                    row_hmac=row.row_hmac,
                    hmac_key_id=row.hmac_key_id,
                    generation=state.generation,
                    occurred_at=row.occurred_at,
                    row_id=row.id,
                )
            ):
                ancestor_match = True
            previous = row.row_hmac
        tail = rows[-1]
        cursor_time = tail.occurred_at
        cursor_id = tail.id
        if len(rows) < page_size:
            break

    if dict(sorted(key_counts.items())) != dict(
        sorted(state.active_key_counts.items()),
    ):
        note_mismatch("active per-key counts mismatch")
    if tail is not None:
        if state.head_occurred_at is None:
            # Same shape as the frozen rows above: normalizing an absent head
            # timestamp raises out of a walk whose whole job is to report, and
            # the state that gets here is reachable -- rows carrying the live
            # generation while the authenticated head quartet is empty. The
            # count check has already fired; name the contradiction too rather
            # than lose the report to it.
            note_mismatch("retained rows exist under an empty authenticated head")
        elif (
            tail.row_hmac != state.head_row_hmac
            or tail.hmac_key_id != state.head_hmac_key_id
            or normalize_timestamp(tail.occurred_at) != normalize_timestamp(state.head_occurred_at)
            or tail.id != state.head_id
        ):
            note_mismatch("retained tail does not match authenticated head")
    elif state.active_row_count != 0:
        note_mismatch("authenticated active head has no retained row")

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
        elif ancestor_match:
            known_result = "VERIFIED_ANCESTOR"
        else:
            known_result = "UNPROVABLE"

    mismatches_truncated = mismatch_count - len(mismatches)
    if mismatches_truncated:
        # Carry the truncation INSIDE the tuple, not only alongside it. Eight
        # callers render the tuple, and only the worker reads the separate
        # counter, so without this line a capped report told an operator
        # running `z4j audit verify` on a chain with thousands of findings
        # nothing at all about the ones it dropped. Every renderer shows this
        # for free; the honest total is ``mismatch_count``, which the renderers
        # print instead of measuring this tuple.
        mismatches.append(
            f"and {mismatches_truncated} further finding(s) not shown; "
            f"reporting is capped at {_MAX_REPORTED_MISMATCHES}",
        )
    return AuditVerificationReport(
        verified_active_rows=verified,
        # Rows that failed to canonicalize were not verified against anything,
        # so counting them here would put them on the credit side of a report
        # that has just called them damaged.
        verified_frozen_rows=len(frozen_snapshots),
        mismatches=tuple(mismatches),
        known_head_result=known_result,
        mismatch_count=mismatch_count,
        mismatches_truncated=mismatches_truncated,
        unattributed_rows=unattributed_rows,
    )


__all__ = [
    "KNOWN_HEAD_RESULTS",
    "AuditVerificationReport",
    "verify_active_audit_generation",
]
