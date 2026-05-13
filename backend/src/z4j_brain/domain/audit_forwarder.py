"""Out-of-band audit-log forwarder.

Every audit row written by :class:`AuditService` can optionally be
mirrored to an external webhook AFTER the writing transaction
commits. This is the standard pattern for:

- **SIEM ingest**: Splunk HEC, Datadog Logs, Sumo, Elastic. The
  receiver gets a JSON-per-row stream identical in shape to what
  the brain stores.
- **Out-of-band tamper detection**: the receiver keeps an
  append-only copy on a separate trust boundary, so an attacker
  who compromises the brain's DB cannot also rewrite the
  receiver's history.
- **Compliance evidence**: SOC 2 / ISO 27001 auditors often want
  audit data in a logging stack they already control rather than
  through the application's own UI.

Design choices an operator should know about:

- **Off by default.** No URL configured, no forwarding. The
  :class:`AuditForwarder` is only instantiated when
  ``Z4J_AUDIT_WEBHOOK_URL`` is set; the audit-service hook does
  nothing otherwise.
- **Commit-bound.** The hook fires from a SQLAlchemy session
  ``after_commit`` event, so a transaction that rolls back never
  forwards its audit rows. (v1.6 audit C6: previous behaviour
  fired hooks inline after INSERT but before COMMIT, so a writer
  that rolled back left the SIEM with phantom rows.)
- **In-memory bounded queue.** A spike in audit traffic that
  outpaces the receiver does NOT block the request; rows that
  cannot be enqueued get dropped with a WARNING and a metric
  bump.
- **HMAC-SHA256 signature over (timestamp, body).** The receiver
  verifies the body against ``Z4J_AUDIT_WEBHOOK_HMAC_SECRET`` AND
  checks that the timestamp header is within a small skew window
  before trusting the row. (v1.6 audit H10: previous behaviour
  signed only the body, allowing replay.)
- **SSRF + DNS-pin.** The forwarder reuses the notification
  channel's :func:`_post` helper and pre-flight checks so a
  configured URL pointing at loopback / RFC1918 / metadata
  endpoints is rejected at startup AND at every dispatch.
- **One row per POST.** No batching in this release. Simpler
  receivers, simpler retry semantics. A future minor can add a
  batched mode behind a separate setting.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from z4j_brain.api.metrics import record_swallowed
from z4j_brain.domain.notifications.channels import (
    _post,
    resolve_and_pin,
    validate_webhook_url,
)

logger = logging.getLogger("z4j.brain.domain.audit_forwarder")


#: HTTP header name carrying the HMAC signature.
AUDIT_SIGNATURE_HEADER: str = "X-Z4J-Audit-Signature"

#: HTTP header carrying the Unix-seconds timestamp at sign time.
#: The receiver verifies the body against the signature AND checks
#: this header is within a skew window (recommended: 5 minutes)
#: before accepting the row. The timestamp is folded into the
#: HMAC input as ``<timestamp>.<body>`` so a replayed POST with the
#: original signature but a stale timestamp will not verify.
#: (v1.6 audit H10.)
AUDIT_TIMESTAMP_HEADER: str = "X-Z4J-Audit-Timestamp"


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
        "source_ip": getattr(row, "source_ip", None),
        "user_agent": getattr(row, "user_agent", None),
        "metadata": metadata,
        "occurred_at": _iso(row.occurred_at),
        "prev_row_hmac": row.prev_row_hmac,
        "row_hmac": row.row_hmac,
    }


# Backwards-compat alias for the prior name. Tests written against
# the leading-underscore form continue to work.
_row_to_payload = row_to_payload


def sign_payload(secret: bytes, body: bytes, timestamp: str | None = None) -> str:
    """Return the ``sha256=<hex>`` signature header value.

    When ``timestamp`` is provided, the HMAC input is
    ``"<timestamp>.".encode() + body`` so a receiver that wants
    replay protection can validate the timestamp window after
    verifying the signature. Receivers that supply no timestamp
    are still supported for backwards-compat (sign over body only).
    """
    digest_input: bytes
    if timestamp is not None:
        digest_input = timestamp.encode("utf-8") + b"." + body
    else:
        digest_input = body
    digest = hmac.new(secret, digest_input, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class AuditForwarder:
    """Background worker that mirrors audit rows to a webhook."""

    def __init__(
        self,
        *,
        webhook_url: str,
        hmac_secret: bytes,
        timeout_seconds: float = 10.0,
        buffer_size: int = 1000,
    ) -> None:
        if buffer_size < 1:
            raise ValueError("buffer_size must be >= 1")
        self._url: str = webhook_url
        self._secret: bytes = hmac_secret
        self._timeout: float = float(timeout_seconds)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=buffer_size,
        )
        self._task: asyncio.Task[None] | None = None
        self._stopped: bool = False
        self._dropped_count: int = 0
        self._sent_count: int = 0
        self._failed_count: int = 0
        self._shutdown_lost: int = 0
        self._in_flight: dict[str, Any] | None = None

    @property
    def dropped_count(self) -> int:
        """Rows lost because the queue was full at enqueue time."""
        return self._dropped_count

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    @property
    def shutdown_lost(self) -> int:
        """Rows enqueued just before shutdown but never POSTed."""
        return self._shutdown_lost

    def enqueue(self, payload: Any) -> bool:
        """Queue one audit row payload for forwarding. Non-blocking.

        ``payload`` is a plain dict (the eager-materialised row).
        Callers obtained via ``AuditService.register_post_write_hook``
        receive dicts, not ORM rows -- the AuditService takes the
        snapshot inside the request transaction and fires hooks
        after commit, so ORM lazy-load cannot happen from inside the
        hook. (v1.6 audit C6 + H11.)

        Returns True when enqueued, False when the queue is full
        (row dropped + counter bump + WARNING) or the forwarder has
        been stopped.
        """
        if self._stopped:
            return False
        # Defensive: callers should send dicts now, but accept an
        # ORM-like row for back-compat with old hook registrations.
        if not isinstance(payload, dict):
            try:
                payload = row_to_payload(payload)
            except Exception:  # noqa: BLE001
                record_swallowed("audit_forwarder", "row_to_payload")
                return False
        try:
            self._queue.put_nowait(payload)
            return True
        except asyncio.QueueFull:
            self._dropped_count += 1
            record_swallowed("audit_forwarder", "queue_full")
            if self._dropped_count == 1 or self._dropped_count % 100 == 0:
                logger.warning(
                    "z4j audit_forwarder: queue full, dropping row "
                    "(total dropped=%d). Increase "
                    "Z4J_AUDIT_WEBHOOK_BUFFER_SIZE or unblock the "
                    "receiver.",
                    self._dropped_count,
                )
            return False

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopped = False
        self._task = asyncio.create_task(
            self._run_forever(), name="audit-forwarder",
        )

    async def stop(self, *, drain_timeout: float = 5.0) -> None:
        """Stop the drain task. Tries to flush the queue first, then
        cancels and accounts for any rows still in the queue.

        v1.6 audit H8: previously rows enqueued between the
        empty-check and the cancel could be silently lost. The
        cancellation now happens UNDER lock with a final residual
        accounting so the operator sees a concrete number in the
        WARNING line.
        """
        self._stopped = True
        if self._task is None:
            return
        deadline = asyncio.get_running_loop().time() + drain_timeout
        while not self._queue.empty():
            if asyncio.get_running_loop().time() >= deadline:
                logger.warning(
                    "z4j audit_forwarder: shutdown drain timed out "
                    "with %d rows still queued",
                    self._queue.qsize(),
                )
                break
            await asyncio.sleep(0.05)
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            logger.warning(
                "z4j audit_forwarder: drain task raised on cancel",
                exc_info=True,
            )
        self._task = None
        # Account for any rows enqueued after the empty-check but
        # before the cancel, PLUS the row the drain task was
        # awaiting on _send_one (which was already pulled from the
        # queue and therefore not in qsize). (Round 2 H10.)
        residual = self._queue.qsize()
        in_flight_lost = 1 if self._in_flight is not None else 0
        total_lost = residual + in_flight_lost
        if total_lost:
            self._shutdown_lost += total_lost
            for _ in range(total_lost):
                record_swallowed("audit_forwarder", "shutdown_lost")
            logger.warning(
                "z4j audit_forwarder: %d row(s) lost during shutdown "
                "(%d queued + %d in-flight)",
                total_lost,
                residual,
                in_flight_lost,
            )
        self._in_flight = None

    def queue_depth(self) -> int:
        """Current queue size; safe to call from any context.
        Used by ``register_inmemory_subsystem`` (Round 5 H) so the
        ``z4j_inmemory_state_items{subsystem="audit_forwarder_queue"}``
        gauge surfaces queue saturation."""
        try:
            return self._queue.qsize()
        except Exception:  # noqa: BLE001
            return 0

    async def _run_forever(self) -> None:
        # ``_in_flight`` is the payload the drain task is currently
        # processing. On shutdown, ``stop()`` cancels this task; if
        # cancellation lands while ``_send_one`` is awaiting the
        # HTTP response, the row is lost without showing in
        # ``_queue.qsize()``. Track it so ``stop()`` can include it
        # in ``_shutdown_lost``. (Round 2 H10.)
        #
        # CancelledError is NOT caught (would silently absorb the
        # signal); on cancellation we propagate, leaving
        # ``_in_flight`` SET so ``stop()`` can account for it.
        # Successful + raising sends both clear it.
        while True:
            payload = await self._queue.get()
            self._in_flight = payload
            try:
                await self._send_one(payload)
            except asyncio.CancelledError:
                # Re-raise without clearing _in_flight; stop() reads it.
                raise
            except Exception:  # noqa: BLE001
                self._failed_count += 1
                record_swallowed("audit_forwarder", "send_one")
                logger.warning(
                    "z4j audit_forwarder: send raised; row dropped",
                    exc_info=True,
                )
                self._in_flight = None
            else:
                self._in_flight = None

    async def _send_one(self, payload: dict[str, Any]) -> None:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = sign_payload(self._secret, body, timestamp=timestamp)
        err, safe_ip = await resolve_and_pin(self._url)
        if err is not None:
            self._failed_count += 1
            record_swallowed("audit_forwarder", "ssrf_or_dns")
            logger.warning(
                "z4j audit_forwarder: refused dispatch (%s); row dropped",
                err,
            )
            return
        try:
            resp = await _post(
                self._url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    AUDIT_SIGNATURE_HEADER: signature,
                    AUDIT_TIMESTAMP_HEADER: timestamp,
                    "X-Z4J-Audit-Schema": "1",
                },
                pin_ip=safe_ip,
                timeout=self._timeout,
            )
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            # v1.6 Round 5 I: also trip the Grafana swallowed-
            # exceptions alert on this branch. SSRF / non-2xx /
            # send_one paths already do; this one was the gap.
            record_swallowed("audit_forwarder", "post_raised")
            logger.warning(
                "z4j audit_forwarder: POST raised: %s; row dropped",
                exc,
            )
            return
        if 200 <= resp.status_code < 300:
            self._sent_count += 1
        else:
            self._failed_count += 1
            # Round 4 Sev-3: trip the same swallowed-exception
            # alert Grafana watches for the SSRF / send-raises
            # paths. Without this, a clean 5xx storm from the
            # receiver leaves every audit row dropped silently
            # while the alert dashboard stays green.
            record_swallowed("audit_forwarder", "non_2xx")
            logger.warning(
                "z4j audit_forwarder: receiver returned %d; row "
                "dropped. Body (truncated): %s",
                resp.status_code,
                resp.text[:200] if hasattr(resp, "text") else "",
            )


async def validate_audit_webhook_url_at_startup(url: str) -> str | None:
    return await validate_webhook_url(url)


__all__ = [
    "AUDIT_SIGNATURE_HEADER",
    "AUDIT_TIMESTAMP_HEADER",
    "AuditForwarder",
    "row_to_payload",
    "sign_payload",
    "validate_audit_webhook_url_at_startup",
]
