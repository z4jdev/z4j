"""Append-only audit log service with per-row HMAC tamper evidence.

Every privileged action goes through :meth:`AuditService.record`.
The service:

1. Builds a canonical JSON representation of the row's content.
2. Computes ``HMAC-SHA256(settings.secret, canonical)``.
3. Inserts the row via :class:`AuditLogRepository`.

The verifier (:meth:`verify_row`) recomputes the HMAC and
constant-time-compares. Combined with the database append-only
trigger, this gives us tamper evidence for any party who does
NOT also hold the master secret. A privileged DBA who DOES hold
the secret can still forge rows, that scenario is out of scope
(addressed by operational controls: secret in env, not on disk).

Secret rotation is supported transparently: callers add the old
secret to ``Z4J_SECRETS_PREVIOUS`` and writes use the new
``Z4J_SECRET``. ``verify_row`` tries every accepted secret in
order so pre-rotation rows still verify.

HMAC version is currently 1 (the v1.3.0 baseline). Future
incompatible changes to the canonical form will bump the version
and add a fallback path here so historical rows stay verifiable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from z4j_brain.persistence.models import AuditLog
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.settings import Settings


#: Canonical-form fields, in stable order. The ``_canonicalize``
#: function emits every one of these as a JSON key. Adding a field
#: here without also emitting it in ``_canonicalize`` is a drift
#: bug; the startup guard ``verify_canonical_fields_emitted``
#: catches that.
_CANONICAL_FIELDS: tuple[str, ...] = (
    "version",
    "id",
    "action",
    "target_type",
    "target_id",
    "result",
    "outcome",
    "event_id",
    "user_id",
    "api_key_id",
    "project_id",
    "source_ip",
    "user_agent",
    "metadata",
    "occurred_at",
    "prev_row_hmac",
)

#: Current HMAC canonical version. Bumped only when the canonical-
#: fields list changes shape in a way that breaks existing row
#: signatures. v1 = the v1.3.0 baseline.
_HMAC_VERSION: int = 1


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """Plain-data view of an audit row, ready for write or verify.

    The service mints ``id`` up-front so the HMAC and the
    persisted row carry the same value (prevents row-clone by an
    attacker with raw write access).
    """

    id: uuid.UUID | None
    action: str
    target_type: str
    target_id: str | None
    result: str
    outcome: str | None
    event_id: uuid.UUID | None
    user_id: uuid.UUID | None
    project_id: uuid.UUID | None
    source_ip: str | None
    user_agent: str | None
    metadata: dict[str, Any]
    occurred_at: datetime
    #: Prior row's ``row_hmac`` at the moment THIS row was written.
    #: ``None`` for the very first row (genesis). Folded into the
    #: HMAC input so deleting any row breaks the next row's
    #: ``prev_row_hmac`` anchor, detectable by ``verify_chain``.
    prev_row_hmac: str | None = None
    #: Bearer-token attribution. ``None`` for cookie-session
    #: actions (most dashboard work) or for actions taken via a
    #: non-bearer auth path.
    api_key_id: uuid.UUID | None = None


class AuditService:
    """Single entry point for writing the audit log.

    The service holds:
    - the master secret (for HMAC computation)
    - the rotation-window secrets (for verifying pre-rotation rows)

    It does NOT hold a session, callers pass the repository in
    per-request, so the audit row participates in the caller's
    transaction. An audit row that "would have been written but
    the caller's transaction rolled back" is the wrong outcome
    for both compliance and debugging.
    """

    __slots__ = ("_secret", "_verify_secrets")

    def __init__(self, settings: Settings) -> None:
        self._secret: bytes = settings.secret.get_secret_value().encode("utf-8")
        # Rotation window: ``verify_row`` accepts any of these.
        # Writes still bind to ``self._secret`` only.
        self._verify_secrets: list[bytes] = list(
            settings.all_secrets_for_verification(),
        )

    async def record(
        self,
        repo: AuditLogRepository,
        *,
        action: str,
        target_type: str,
        target_id: str | None = None,
        result: str = "success",
        outcome: str | None = None,
        event_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        api_key_id: uuid.UUID | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Append one row to the audit log inside the caller's transaction.

        ``outcome`` defaults to ``"allow"`` when ``result == "success"``,
        ``"failure"`` when ``result == "failed"``, and ``"error"``
        otherwise. The caller can override.
        """
        # Mint the row id up-front so it can be folded into the HMAC
        # input. Without this, an attacker with raw write access
        # could clone the row payload + HMAC to create an
        # undetectable duplicate.
        row_id = uuid.uuid4()
        # Take the chain advisory lock immediately before the head
        # read + insert. The lock window is "head read → HMAC
        # compute → INSERT", microseconds.
        await repo.acquire_chain_lock()
        # Fetch the prior row's hmac so we can fold it into this
        # row's input. A subsequent DELETE of any row then leaves
        # the next row's ``prev_row_hmac`` referencing a prior row
        # whose hmac no longer matches, detectable by
        # ``verify_chain``.
        prev_row_hmac = await repo.get_latest_row_hmac()
        entry = AuditEntry(
            id=row_id,
            action=action[:80],
            target_type=target_type[:40],
            target_id=target_id[:200] if target_id else None,
            result=result[:20],
            outcome=outcome or self._default_outcome(result),
            event_id=event_id,
            user_id=user_id,
            project_id=project_id,
            api_key_id=api_key_id,
            source_ip=source_ip,
            user_agent=(user_agent[:1024] if user_agent else None),
            metadata=metadata or {},
            occurred_at=datetime.now(UTC),
            prev_row_hmac=prev_row_hmac,
        )
        row_hmac = self._compute_hmac(entry)
        return await repo.insert(
            id=row_id,
            action=entry.action,
            target_type=entry.target_type,
            target_id=entry.target_id,
            result=entry.result,
            outcome=entry.outcome,
            event_id=entry.event_id,
            user_id=entry.user_id,
            project_id=entry.project_id,
            api_key_id=entry.api_key_id,
            source_ip=entry.source_ip,
            user_agent=entry.user_agent,
            metadata=entry.metadata,
            row_hmac=row_hmac,
            prev_row_hmac=prev_row_hmac,
            occurred_at=entry.occurred_at,
        )

    def verify_row(self, row: AuditLog) -> bool:
        """Recompute the HMAC for ``row`` and compare it constant-time.

        Returns False on missing ``row_hmac`` or tampered field.
        Tries every secret in the rotation window so a recent
        ``Z4J_SECRET`` rotation doesn't invalidate pre-rotation rows.
        """
        stored = row.row_hmac
        if not stored:
            return False
        entry = AuditEntry(
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
            source_ip=row.source_ip,
            user_agent=row.user_agent,
            metadata=row.audit_metadata,
            occurred_at=row.occurred_at,
            prev_row_hmac=row.prev_row_hmac,
        )
        for secret in self._verify_secrets:
            recomputed = self._compute_hmac(entry, secret=secret)
            if len(recomputed) == len(stored) and hmac.compare_digest(
                recomputed, stored,
            ):
                return True
        return False

    def verify_chain(
        self, rows: "list[AuditLog]",
    ) -> tuple[bool, list[str]]:
        """Walk a sequence of rows and verify the HMAC chain.

        Expects rows ordered by insert order (``id`` UUIDv7 or
        ``occurred_at`` ascending). Returns ``(ok, reasons)``
        where ``reasons`` is a list of human-readable descriptions
        of any chain break, "row X: prev_row_hmac mismatch" or
        "row X: bad row_hmac".

        A clean chain returns ``(True, [])``. A single deleted row
        produces a visible mismatch at the next chained row -
        that's the tamper-evidence the chain is designed to surface.
        """
        reasons: list[str] = []
        prev_hmac: str | None = None
        for row in rows:
            if not self.verify_row(row):
                reasons.append(
                    f"row {row.id}: bad row_hmac (tampered field "
                    f"or missing hmac)",
                )
                continue
            # The genesis row (first row ever written) has
            # prev_row_hmac=None and is the start of the chain.
            # Every subsequent row's prev_row_hmac must equal the
            # PRIOR row's row_hmac.
            if prev_hmac is not None:
                actual = row.prev_row_hmac
                if actual != prev_hmac:
                    reasons.append(
                        f"row {row.id}: prev_row_hmac mismatch "
                        f"(saw {actual[:12] if actual else None}, "
                        f"expected {prev_hmac[:12]}). Likely a "
                        f"deleted row between this and the prior.",
                    )
            prev_hmac = row.row_hmac
        return (len(reasons) == 0, reasons)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _compute_hmac(
        self,
        entry: AuditEntry,
        *,
        secret: bytes | None = None,
    ) -> str:
        """Canonical → HMAC-SHA256 hex digest.

        ``secret`` defaults to the current write-side key;
        ``verify_row`` passes each rotation-window secret in turn.
        """
        canonical = self._canonicalize(entry)
        digest = hmac.new(
            secret if secret is not None else self._secret,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return digest

    @staticmethod
    def _canonicalize(entry: AuditEntry) -> str:
        """Render the canonical form for HMAC input.

        Stable JSON: sorted keys at every level, ISO-8601 UTC for
        the timestamp, ``str()`` for UUIDs, ``None`` for missing
        optionals. ``version`` is part of the payload so any
        future canonical-form change can be detected by version
        mismatch (the verifier will gain a per-version fallback
        path at that time).
        """
        payload: dict[str, Any] = {
            "version": _HMAC_VERSION,
            "id": str(entry.id) if entry.id else None,
            "action": entry.action,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "result": entry.result,
            "outcome": entry.outcome,
            "event_id": str(entry.event_id) if entry.event_id else None,
            "user_id": str(entry.user_id) if entry.user_id else None,
            "api_key_id": (
                str(entry.api_key_id) if entry.api_key_id else None
            ),
            "project_id": str(entry.project_id) if entry.project_id else None,
            "source_ip": entry.source_ip,
            "user_agent": entry.user_agent,
            "metadata": entry.metadata,
            "occurred_at": (
                entry.occurred_at.astimezone(UTC).isoformat(
                    timespec="microseconds",
                )
            ),
            "prev_row_hmac": entry.prev_row_hmac,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

    @staticmethod
    def _default_outcome(result: str) -> str:
        """Map a free-form ``result`` string to the structured outcome.

        - ``"allow"``: action authorised AND succeeded.
        - ``"deny"``: action REJECTED at policy time (auth / scope /
          membership / CSRF / rate-limit). Reserved for actual
          authorization decisions so security audits can grep
          ``outcome=deny`` and find real access denials.
        - ``"failure"``: action authorised but the execution failed
          (task raised, command timed out, downstream error).
        - ``"error"``: internal panic / partial state / unknown.

        Caller can always override via the ``outcome=`` kwarg.
        """
        if result == "success":
            return "allow"
        if result == "failed":
            return "failure"
        return "error"


# ---------------------------------------------------------------------------
# Startup drift guard
# ---------------------------------------------------------------------------


def verify_canonical_fields_emitted() -> None:
    """Round-trip guard: every entry in ``_CANONICAL_FIELDS`` MUST
    appear in the JSON output of ``_canonicalize``. Catches the
    "field added to the tuple but forgotten in ``_canonicalize``"
    hole.

    Called by ``create_app`` at startup. Raises ``RuntimeError``
    on drift; the brain refuses to start so the bug is visible
    immediately.
    """
    sample = AuditEntry(
        id=uuid.uuid4(),
        action="t",
        target_type="t",
        target_id="t",
        result="success",
        outcome="allow",
        event_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        source_ip="127.0.0.1",
        user_agent="t",
        metadata={},
        occurred_at=datetime.now(UTC),
        prev_row_hmac="0" * 64,
    )
    canonical_dict = json.loads(AuditService._canonicalize(sample))
    for field in _CANONICAL_FIELDS:
        if field not in canonical_dict:
            raise RuntimeError(
                f"audit canonical drift: {field!r} is in "
                f"_CANONICAL_FIELDS but not emitted by "
                f"_canonicalize. Adding a field to the tuple "
                f"without also emitting it in _canonicalize "
                f"silently breaks HMAC verification for every row "
                f"written at the current version. See "
                f"z4j_brain/docs/audit-canonical-fields.md.",
            )


__all__ = [
    "AuditEntry",
    "AuditService",
    "verify_canonical_fields_emitted",
]
