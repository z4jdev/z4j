"""Out-of-band audit-log forwarder with a durable cursor.

Every audit row the brain writes can optionally be mirrored to an
external webhook. This is the standard pattern for:

- **SIEM ingest**: Splunk HEC, Datadog Logs, Sumo, Elastic. The
  receiver gets a JSON-per-row stream identical in shape to what
  the brain stores.
- **A copy on a separate trust boundary**: rows that reach the
  receiver land outside the brain's database, so a role that can
  rewrite ``audit_log`` does not thereby rewrite the receiver's
  history. Read the next paragraph before treating that as tamper
  detection.
- **Compliance evidence**: SOC 2 / ISO 27001 auditors often want
  audit data in a logging stack they already control rather than
  through the application's own UI.

What this forwarder is not, stated here because the shape of it
invites the assumption: it is not the out-of-band anchor that
detects a hostile database role. The cursor below lives in the same
database as the audit log, so a role that can delete audit rows can
also move the cursor past them, and the receiver cannot tell that
from a quiet period. Detection needs a sink whose retention the
brain's operator cannot relax plus a periodic
``z4j audit verify --known-head`` against an exported chain head,
which bounds how far the log can be rolled back without that
verification failing (see ``docs/SECURITY.md`` section 10.2). This
forwarder is a live mirror for a SIEM, and it is genuinely useful as
one.

How delivery works
------------------
The audit log is append-only and every row carries a strictly
monotonic chain-order key ``(occurred_at, id)``: the audit service
clamps each new row's timestamp under the chain lock so the key never
goes backwards (``audit_chain.strictly_later_audit_key``), and the
verifier walks the table in exactly that order. "What the receiver has
acknowledged" is therefore one position on that key, kept in the
``audit_forward_state`` table per sink, rather than a queue of rows
held in memory.

Each pass of the worker reads up to ``batch_size`` rows strictly after
the cursor, in chain order, and POSTs them one row per request in that
order. The cursor moves to a row only after the receiver answered with
a 2xx, by a compare-and-set UPDATE, so a brain restart, a receiver
outage, or a leadership change resumes from the last acknowledged row.
Nothing is dropped: a row the receiver has not acknowledged is sent
again on a later pass, for as long as it takes.

Delivery is at least once. A crash between the receiver's 2xx and the
cursor write re-sends that one row, and a receiver that answered 2xx
after the brain gave up waiting sees it twice. The audit-row ``id`` is
mint-once per row, so the receiver de-duplicates on the row id; the
documented receiver does.

Failure handling: a non-2xx answer, a transport error, or an SSRF
refusal ends the pass without moving the cursor and increments
``consecutive_failures`` on the state row. The next attempt waits
``min(1s * 2 ** (failures - 1), max_backoff)`` from the last attempt,
and because the counter is persisted the backoff survives a restart.
A success resets it.

Ordering across writers: the chain lock serialises audit writers, so
on the signed path commit order equals key order and a page read after
a commit cannot miss an earlier key that commits later. The unsigned
development path (no audit-chain key configured) does not take that
lock, so there, and only there, a row committed late with an earlier
timestamp can be skipped by a cursor that already passed it.

Leadership: the worker takes the per-worker advisory lock for the
whole of each pass, the same ``acquire_per_worker_lock`` the other
periodic workers use, so under ``z4j serve``'s several processes
exactly one forwards at a time. SQLite no-ops the lock. The
compare-and-set on the cursor is the second line: if the lock holder's
connection died mid-pass and another replica took over, the stale
holder's next cursor write finds the cursor moved and stops instead of
rewinding it.

What stays as it was: the single sink, the request body, and the
headers. The body is the canonical JSON of :func:`row_to_payload`, the
signature covers ``<timestamp>.<body>`` under
``Z4J_AUDIT_WEBHOOK_HMAC_SECRET``, and ``X-Z4J-Audit-Schema: 1`` names
the body shape. The receiver verifies the signature, checks the
timestamp against a skew window, then de-duplicates on the row id.

SSRF + DNS-pin: every dispatch reuses the notification channel's
:func:`_post` helper and pre-flight checks, so a configured URL
pointing at loopback / RFC1918 / metadata endpoints is refused at
startup AND at every dispatch. A refusal is a failed attempt like any
other: the row waits, and the backoff grows, until the URL is fixed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from z4j_brain.api import metrics as _metrics
from z4j_brain.api.metrics import record_swallowed
from z4j_brain.domain.notifications.channels import (
    _post,
    resolve_and_pin,
    validate_webhook_url,
)
from z4j_brain.persistence.models.audit_forward_state import (
    DEFAULT_AUDIT_FORWARD_SINK_ID,
)

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models.audit_forward_state import AuditForwardState

logger = logging.getLogger("z4j.brain.domain.audit_forwarder")


#: HTTP header name carrying the HMAC signature.
AUDIT_SIGNATURE_HEADER: str = "X-Z4J-Audit-Signature"

#: HTTP header carrying the Unix-seconds timestamp at sign time.
#: The receiver verifies the body against the signature AND checks
#: this header is within a skew window (recommended: 5 minutes)
#: before accepting the row. The timestamp is folded into the
#: HMAC input as ``<timestamp>.<body>`` so a replayed POST with the
#: original signature but a stale timestamp will not verify.
AUDIT_TIMESTAMP_HEADER: str = "X-Z4J-Audit-Timestamp"

#: HTTP header naming the body shape, and the one shape this release emits.
AUDIT_SCHEMA_HEADER: str = "X-Z4J-Audit-Schema"
AUDIT_SCHEMA_VERSION: str = "1"

#: First wait after a failed attempt, doubling per consecutive failure up to
#: the configured maximum.
_BACKOFF_BASE_SECONDS: float = 1.0

#: Ceiling on the doubling exponent so a long outage cannot grow the shift
#: without bound. The configured maximum caps the wait long before this bites.
_MAX_BACKOFF_EXPONENT: int = 20

#: What a pass asks the supervisor for when a full batch went through and
#: more rows are waiting: come back almost at once rather than after the
#: poll interval, so a backlog drains at the receiver's pace.
_CATCH_UP_DELAY_SECONDS: float = 0.05


def row_to_payload(row: Any) -> dict[str, Any]:
    """Render an :class:`AuditLog` row to the wire shape.

    Public helper (no leading underscore). Tests + the audit-service
    eager-materialisation path both consume it. The function is pure
    and accepts any object with the expected attribute names, so a
    plain SimpleNamespace works in tests without an ORM session.
    """
    metadata = getattr(row, "audit_metadata", None) or {}

    def _iso(v: datetime | None) -> str | None:
        if v is None:
            return None
        return v.astimezone(UTC).isoformat(timespec="microseconds")

    def _str_uuid(v: uuid.UUID | None) -> str | None:
        return str(v) if v is not None else None

    return {
        "id": _str_uuid(row.id),
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "result": row.result,
        "outcome": row.outcome,
        "event_id": _str_uuid(getattr(row, "event_id", None)),
        "user_id": _str_uuid(getattr(row, "user_id", None)),
        "api_key_id": _str_uuid(getattr(row, "api_key_id", None)),
        "project_id": _str_uuid(getattr(row, "project_id", None)),
        "source_ip": (
            str(getattr(row, "source_ip", None))
            if getattr(row, "source_ip", None) is not None
            else None
        ),
        "user_agent": getattr(row, "user_agent", None),
        "metadata": metadata,
        "occurred_at": _iso(row.occurred_at),
        "prev_row_hmac": row.prev_row_hmac,
        "row_hmac": row.row_hmac,
        "hmac_version": getattr(row, "hmac_version", None),
        "hmac_key_id": getattr(row, "hmac_key_id", None),
        "chain_generation": _str_uuid(
            getattr(row, "chain_generation", None),
        ),
        "legacy_frozen": getattr(row, "legacy_frozen", None),
        "legacy_integrity_class": getattr(
            row,
            "legacy_integrity_class",
            None,
        ),
        "legacy_origin": getattr(row, "legacy_origin", None),
    }


# Backwards-compat alias for the prior name. Tests written against
# the leading-underscore form continue to work.
_row_to_payload = row_to_payload


def encode_payload(payload: dict[str, Any]) -> bytes:
    """The exact request body for one row: canonical JSON, sorted keys."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sign_payload(secret: bytes, body: bytes, timestamp: str | None = None) -> str:
    """Return the ``sha256=<hex>`` signature header value.

    When ``timestamp`` is provided, the HMAC input is
    ``"<timestamp>.".encode() + body`` so a receiver that wants
    replay protection can validate the timestamp window after
    verifying the signature. Receivers that supply no timestamp
    are still supported for backwards-compat (sign over body only).
    """
    digest_input: bytes = timestamp.encode("utf-8") + b"." + body if timestamp is not None else body
    digest = hmac.new(secret, digest_input, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def backoff_seconds(consecutive_failures: int, max_backoff_seconds: float) -> float:
    """Seconds to wait after ``consecutive_failures`` attempts in a row failed.

    Zero failures means no wait. One failure waits the base, and each
    further failure doubles it, never past ``max_backoff_seconds``.
    """
    if consecutive_failures <= 0:
        return 0.0
    exponent = min(consecutive_failures - 1, _MAX_BACKOFF_EXPONENT)
    return min(_BACKOFF_BASE_SECONDS * (2.0**exponent), float(max_backoff_seconds))


def _aware(value: datetime) -> datetime:
    """SQLite hands timestamps back naive; treat those as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def backoff_remaining_seconds(
    *,
    consecutive_failures: int,
    last_attempt_at: datetime | None,
    now: datetime,
    max_backoff_seconds: float,
) -> float:
    """Seconds until the next attempt is due, or zero when it is due now."""
    if consecutive_failures <= 0 or last_attempt_at is None:
        return 0.0
    wait = backoff_seconds(consecutive_failures, max_backoff_seconds)
    due_at = _aware(last_attempt_at) + timedelta(seconds=wait)
    return max(0.0, (due_at - _aware(now)).total_seconds())


PassStatus = Literal["not_leader", "idle", "backoff", "sent", "failed"]


@dataclass(slots=True, frozen=True)
class ForwardPass:
    """What one pass of the forwarder did."""

    status: PassStatus
    sent: int = 0
    lag_rows: int = 0
    consecutive_failures: int = 0
    #: True when a full batch was acknowledged and rows are still waiting,
    #: so the next pass should run without waiting out the poll interval.
    more: bool = False


def _observe_lag(rows: int) -> None:
    """Refresh the lag gauge without letting metrics break the worker."""
    try:
        gauge = getattr(_metrics, "z4j_audit_forward_lag_rows", None)
        if gauge is not None:
            gauge.set(rows)
    except Exception:  # pragma: no cover - defensive by construction
        logger.debug("z4j audit_forwarder: lag gauge update failed", exc_info=True)


def _observe_failure(reason: str) -> None:
    try:
        counter = getattr(_metrics, "z4j_audit_forward_failures_total", None)
        if counter is not None:
            counter.labels(reason=reason).inc()
    except Exception:  # pragma: no cover - defensive by construction
        logger.debug("z4j audit_forwarder: failure counter update failed", exc_info=True)


class AuditForwarder:
    """Leader-gated periodic worker that mirrors audit rows to a webhook."""

    #: Name of the advisory lock this worker leads on, and the name the
    #: supervisor knows it by.
    LEADER_LOCK_NAME: ClassVar[str] = "audit_forwarder_worker"

    def __init__(
        self,
        *,
        db: DatabaseManager,
        webhook_url: str,
        hmac_secret: bytes,
        timeout_seconds: float = 10.0,
        batch_size: int = 100,
        max_backoff_seconds: float = 300.0,
        sink_id: str = DEFAULT_AUDIT_FORWARD_SINK_ID,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if max_backoff_seconds < _BACKOFF_BASE_SECONDS:
            raise ValueError("max_backoff_seconds must be >= 1")
        self._db = db
        self._url: str = webhook_url
        self._secret: bytes = hmac_secret
        self._timeout: float = float(timeout_seconds)
        self._batch_size: int = int(batch_size)
        self._max_backoff: float = float(max_backoff_seconds)
        self._sink_id: str = sink_id
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self._sent_count: int = 0
        self._failed_count: int = 0
        self._last_pass: ForwardPass | None = None

    @property
    def sink_id(self) -> str:
        return self._sink_id

    @property
    def batch_size(self) -> int:
        return self._batch_size

    @property
    def max_backoff_seconds(self) -> float:
        return self._max_backoff

    @property
    def sent_count(self) -> int:
        """Rows acknowledged by the receiver since this process started."""
        return self._sent_count

    @property
    def failed_count(self) -> int:
        """Attempts that did not get a 2xx since this process started."""
        return self._failed_count

    @property
    def last_pass(self) -> ForwardPass | None:
        return self._last_pass

    async def tick(self) -> float | None:
        """One leader-gated pass. Never sends unless this replica leads.

        Returns a short delay when a full batch went through and more rows
        wait, so the supervisor comes straight back; None otherwise, which
        takes the configured poll interval. Database errors propagate so the
        supervisor applies its own backoff and logs the traceback.
        """
        from z4j_brain.domain.workers._leader_lock import acquire_per_worker_lock

        async with acquire_per_worker_lock(self._db, self.LEADER_LOCK_NAME) as got:
            if not got:
                self._last_pass = ForwardPass(status="not_leader")
                return None
            outcome = await self.forward_once()
        return _CATCH_UP_DELAY_SECONDS if outcome.more else None

    async def forward_once(self) -> ForwardPass:
        """One pass without the leader lock: read, send in order, advance.

        Split from :meth:`tick` so tests and a future backfill command can
        drive a pass directly. Production always goes through ``tick``.
        """
        from z4j_brain.persistence.repositories.audit_forward_state import (
            AuditForwardStateRepository,
        )
        from z4j_brain.persistence.repositories.audit_log import AuditLogRepository

        now = self._clock()
        async with self._db.session(write=True) as session:
            state = await AuditForwardStateRepository(session).get_or_initialise(self._sink_id)
            cursor_at = state.last_forwarded_occurred_at
            cursor_id = state.last_forwarded_id
            failures = state.consecutive_failures
            last_attempt_at = state.last_attempt_at
            await session.commit()

        async with self._db.session() as session:
            lag = await AuditForwardStateRepository(session).count_pending(
                after_occurred_at=cursor_at,
                after_id=cursor_id,
            )
            _observe_lag(lag)
            remaining = backoff_remaining_seconds(
                consecutive_failures=failures,
                last_attempt_at=last_attempt_at,
                now=now,
                max_backoff_seconds=self._max_backoff,
            )
            if remaining > 0:
                outcome = ForwardPass(
                    status="backoff",
                    lag_rows=lag,
                    consecutive_failures=failures,
                )
                self._last_pass = outcome
                return outcome
            rows = await AuditLogRepository(session).stream_for_verify(
                chunk=self._batch_size,
                after_occurred_at=cursor_at,
                after_id=cursor_id,
            )

        if not rows:
            outcome = ForwardPass(status="idle", lag_rows=lag, consecutive_failures=failures)
            self._last_pass = outcome
            return outcome

        sent = 0
        for row in rows:
            delivered = await self._send_one(row_to_payload(row))
            attempted_at = self._clock()
            async with self._db.session(write=True) as session:
                repo = AuditForwardStateRepository(session)
                if delivered:
                    matched = await repo.advance(
                        self._sink_id,
                        expected_last_id=cursor_id,
                        occurred_at=row.occurred_at,
                        row_id=row.id,
                        at=attempted_at,
                    )
                else:
                    matched = await repo.record_failure(
                        self._sink_id,
                        expected_last_id=cursor_id,
                        at=attempted_at,
                    )
                await session.commit()
            if not matched:
                # The cursor is not where this pass left it. Another replica
                # has been forwarding, which the leader lock should have made
                # impossible; the only way it is not is the lock-holding
                # connection dying mid-pass. Stop here: the other replica's
                # cursor is ahead of ours, and writing ours would rewind it.
                _observe_failure("cursor_conflict")
                logger.error(
                    "z4j audit_forwarder: cursor for sink %r moved under this pass; "
                    "another replica is forwarding. Stopping this pass without "
                    "touching the cursor. Rows sent by both may reach the receiver "
                    "twice; it de-duplicates on the row id.",
                    self._sink_id,
                )
                outcome = ForwardPass(
                    status="failed",
                    sent=sent,
                    lag_rows=max(lag - sent, 0),
                    consecutive_failures=failures,
                )
                self._last_pass = outcome
                return outcome
            if not delivered:
                failures += 1
                outcome = ForwardPass(
                    status="failed",
                    sent=sent,
                    lag_rows=max(lag - sent, 0),
                    consecutive_failures=failures,
                )
                self._last_pass = outcome
                return outcome
            sent += 1
            cursor_id = row.id
            failures = 0
            _observe_lag(max(lag - sent, 0))

        outcome = ForwardPass(
            status="sent",
            sent=sent,
            lag_rows=max(lag - sent, 0),
            consecutive_failures=0,
            more=len(rows) >= self._batch_size and lag > sent,
        )
        self._last_pass = outcome
        return outcome

    async def _send_one(self, payload: dict[str, Any]) -> bool:
        """POST one row. True on a 2xx; False on anything else, nothing raised.

        The body and headers are the wire format receivers were written
        against: canonical JSON body, ``<timestamp>.<body>`` signature,
        Unix-seconds timestamp, and the schema header.
        """
        body = encode_payload(payload)
        timestamp = str(int(time.time()))
        signature = sign_payload(self._secret, body, timestamp=timestamp)
        err, safe_ip = await resolve_and_pin(self._url)
        if err is not None:
            self._failed_count += 1
            record_swallowed("audit_forwarder", "ssrf_or_dns")
            _observe_failure("ssrf_or_dns")
            logger.warning(
                "z4j audit_forwarder: refused dispatch (%s); the row waits at the cursor",
                err,
            )
            return False
        try:
            resp = await _post(
                self._url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    AUDIT_SIGNATURE_HEADER: signature,
                    AUDIT_TIMESTAMP_HEADER: timestamp,
                    AUDIT_SCHEMA_HEADER: AUDIT_SCHEMA_VERSION,
                },
                pin_ip=safe_ip,
                timeout=self._timeout,
            )
        except Exception as exc:
            self._failed_count += 1
            # Trip the Grafana swallowed-exceptions alert on this branch as
            # well as counting it on the forwarder's own series.
            record_swallowed("audit_forwarder", "post_raised")
            _observe_failure("post_raised")
            logger.warning(
                "z4j audit_forwarder: POST raised: %s; the row waits at the cursor",
                exc,
            )
            return False
        if 200 <= resp.status_code < 300:
            self._sent_count += 1
            return True
        self._failed_count += 1
        record_swallowed("audit_forwarder", "non_2xx")
        _observe_failure("non_2xx")
        logger.warning(
            "z4j audit_forwarder: receiver returned %d; the row waits at the cursor. "
            "Body (truncated): %s",
            resp.status_code,
            resp.text[:200] if hasattr(resp, "text") else "",
        )
        return False

    def snapshot(self) -> dict[str, Any]:
        """Process-local counters for the admin status endpoint."""
        last = self._last_pass
        return {
            "sink_id": self._sink_id,
            "worker": self.LEADER_LOCK_NAME,
            "batch_size": self._batch_size,
            "max_backoff_seconds": self._max_backoff,
            "sent_count": self._sent_count,
            "failed_count": self._failed_count,
            "last_pass_status": None if last is None else last.status,
        }


def state_backoff_remaining(
    state: AuditForwardState,
    *,
    now: datetime,
    max_backoff_seconds: float,
) -> float:
    """Seconds until a sink's next attempt is due, from its state row."""
    return backoff_remaining_seconds(
        consecutive_failures=state.consecutive_failures,
        last_attempt_at=state.last_attempt_at,
        now=now,
        max_backoff_seconds=max_backoff_seconds,
    )


async def validate_audit_webhook_url_at_startup(url: str) -> str | None:
    return await validate_webhook_url(url)


__all__ = [
    "AUDIT_SCHEMA_HEADER",
    "AUDIT_SCHEMA_VERSION",
    "AUDIT_SIGNATURE_HEADER",
    "AUDIT_TIMESTAMP_HEADER",
    "AuditForwarder",
    "ForwardPass",
    "backoff_remaining_seconds",
    "backoff_seconds",
    "encode_payload",
    "row_to_payload",
    "sign_payload",
    "state_backoff_remaining",
    "validate_audit_webhook_url_at_startup",
]
