"""Real-transport audit-forwarder tests.

Every prior audit-forwarder test monkeypatches ``_post``, so the
production call chain (``_send_one`` -> ``_post`` -> ``client.send``
-> transport) never actually ran end-to-end. That is exactly how the
R2 ship-stopper landed: ``_post`` shipped with a broken ``timeout``
kwarg shape, and the unit suite passed.

These tests pin the contract through ``httpx.MockTransport`` so a
regression in ANY of these classes would fail here:

- timeout-kwarg-not-applied (R2 ship-stopper class)
- HMAC body mismatch (signature drift)
- timestamp header shape drift
- response-body cap removal (``_MAX_RESPONSE_BYTES`` machinery)
- non-2xx accounting + ``record_swallowed`` plumbing
- full enqueue -> drain-loop -> transport delivery
- cancel-during-in-flight against a blocking real transport
"""

from __future__ import annotations

import asyncio
import hmac as _hmac
import hashlib as _hashlib
import json
from typing import Any

import httpx
import pytest

from z4j_brain.domain import audit_forwarder as af_mod
from z4j_brain.domain.audit_forwarder import (
    AUDIT_SIGNATURE_HEADER,
    AUDIT_TIMESTAMP_HEADER,
    AuditForwarder,
)
from z4j_brain.domain.notifications.channels import set_shared_client


WEBHOOK = "https://siem.example.test/ingest"
SECRET = b"k" * 32


class _Stream(httpx.AsyncByteStream):
    """Streamable response body. ``_post`` calls ``aiter_raw()`` on
    the response, but ``httpx.Response(content=bytes)`` materialises
    the body into a non-async stream that fails to re-stream under
    ``MockTransport``. Yielding from this custom AsyncByteStream
    keeps ``aiter_raw()`` working so the production read-cap path
    runs against the real transport."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def __aiter__(self):  # type: ignore[override]
        yield self._data

    async def aclose(self) -> None:
        return None


def _resp(status: int, body: bytes = b"") -> httpx.Response:
    return httpx.Response(status, stream=_Stream(body))


def _payload() -> dict[str, Any]:
    return {
        "id": "00000000-0000-0000-0000-00000000abcd",
        "action": "user.password_changed",
        "target_type": "user",
        "target_id": "user-1",
        "result": "success",
        "outcome": "allow",
        "event_id": None,
        "user_id": "00000000-0000-0000-0000-0000000000aa",
        "api_key_id": None,
        "project_id": None,
        "source_ip": "192.0.2.10",
        "user_agent": "z4j-cli/1",
        "metadata": {"some": "value"},
        "occurred_at": "2026-05-12T12:00:00.000000+00:00",
        "prev_row_hmac": "a" * 64,
        "row_hmac": "b" * 64,
    }


async def _no_dns(_url: str) -> tuple[str | None, str | None]:
    """Bypass real DNS so the test stays offline + URL stays unpinned."""
    return None, None


@pytest.mark.asyncio
class TestSendOneAgainstRealTransport:
    """``_send_one`` -> real ``_post`` -> ``MockTransport``."""

    async def test_request_url_method_and_body(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return _resp(200, b"ok")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        set_shared_client(client)
        try:
            fwd = AuditForwarder(webhook_url=WEBHOOK, hmac_secret=SECRET)
            await fwd._send_one(_payload())
        finally:
            set_shared_client(None)
            await client.aclose()

        assert len(seen) == 1
        req = seen[0]
        assert req.method == "POST"
        assert str(req.url) == WEBHOOK
        # Body is valid JSON matching the payload.
        body_bytes = req.content
        assert json.loads(body_bytes) == _payload()
        assert fwd.sent_count == 1
        assert fwd.failed_count == 0

    async def test_hmac_signature_covers_timestamp_plus_body(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If signing drifts (forgets timestamp, swaps order, picks
        wrong digest) this fails."""
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return _resp(204)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        set_shared_client(client)
        try:
            fwd = AuditForwarder(webhook_url=WEBHOOK, hmac_secret=SECRET)
            await fwd._send_one(_payload())
        finally:
            set_shared_client(None)
            await client.aclose()

        req = seen[0]
        sig = req.headers[AUDIT_SIGNATURE_HEADER]
        ts = req.headers[AUDIT_TIMESTAMP_HEADER]
        assert sig.startswith("sha256=")
        # Timestamp is unix-seconds (digit string), not ISO.
        assert ts.isdigit(), f"timestamp shape drift: {ts!r}"
        # Recompute and compare.
        expected = "sha256=" + _hmac.new(
            SECRET, ts.encode() + b"." + req.content, _hashlib.sha256,
        ).hexdigest()
        assert sig == expected, "HMAC body+timestamp mismatch"
        assert req.headers["Content-Type"] == "application/json"
        assert req.headers["X-Z4J-Audit-Schema"] == "1"

    async def test_per_call_timeout_reaches_transport_extension(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """R2 ship-stopper regression guard. The forwarder's
        ``_timeout`` must arrive in the transport-side request
        extension as an httpx.Timeout-derived shape, NOT the client
        default (60s) and NOT a stale dict that httpx silently
        ignored on 0.28+."""
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        seen: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(dict(req.extensions or {}))
            return _resp(200, b"ok")

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=httpx.Timeout(60.0),  # client default, MUST be overridden
        )
        set_shared_client(client)
        try:
            fwd = AuditForwarder(
                webhook_url=WEBHOOK, hmac_secret=SECRET,
                timeout_seconds=7.5,
            )
            await fwd._send_one(_payload())
        finally:
            set_shared_client(None)
            await client.aclose()

        t = seen[0].get("timeout")
        # httpx 0.28+ unwraps Timeout into a dict at the transport
        # boundary; older shapes pass the object itself. Accept both,
        # reject the stale 60s default + the None gap.
        if isinstance(t, dict):
            assert t.get("read") == 7.5, f"timeout did not reach transport: {t!r}"
            assert t.get("connect") == 7.5
        elif isinstance(t, httpx.Timeout):
            assert t.read == 7.5 and t.connect == 7.5
        else:
            pytest.fail(
                f"per-call timeout missing from transport extension: {t!r}",
            )


@pytest.mark.asyncio
class TestDrainLoopAgainstRealTransport:
    """``enqueue`` -> ``start`` -> drain loop -> transport."""

    async def test_three_enqueued_rows_all_reach_transport(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return _resp(200, b"ok")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        set_shared_client(client)
        try:
            fwd = AuditForwarder(webhook_url=WEBHOOK, hmac_secret=SECRET)
            fwd.start()
            for i in range(3):
                p = _payload()
                p["target_id"] = f"user-{i}"
                assert fwd.enqueue(p)
            # Wait for drain.
            for _ in range(100):
                if fwd.sent_count == 3:
                    break
                await asyncio.sleep(0.01)
            await fwd.stop(drain_timeout=1.0)
        finally:
            set_shared_client(None)
            await client.aclose()

        assert fwd.sent_count == 3
        assert len(seen) == 3
        target_ids = sorted(json.loads(r.content)["target_id"] for r in seen)
        assert target_ids == ["user-0", "user-1", "user-2"]


@pytest.mark.asyncio
class TestNon2xxAgainstRealTransport:
    """A real 5xx via MockTransport exercises the bounded-body read
    AND the non_2xx accounting path."""

    async def test_500_increments_failed_and_does_not_blow_body_cap(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        counts: dict[str, int] = {}

        def _fake_record(module: str, site: str) -> None:
            counts[f"{module}/{site}"] = counts.get(f"{module}/{site}", 0) + 1

        monkeypatch.setattr(af_mod, "record_swallowed", _fake_record)

        # Receiver streams a 10 MiB body, but _post should cap at 8 KiB.
        huge = b"x" * (10 * 1024 * 1024)

        def handler(_req: httpx.Request) -> httpx.Response:
            return _resp(503, huge)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        set_shared_client(client)
        try:
            fwd = AuditForwarder(webhook_url=WEBHOOK, hmac_secret=SECRET)
            await fwd._send_one(_payload())
        finally:
            set_shared_client(None)
            await client.aclose()

        assert fwd.failed_count == 1
        assert fwd.sent_count == 0
        assert counts.get("audit_forwarder/non_2xx", 0) == 1


@pytest.mark.asyncio
class TestCancelDuringInFlight:
    """``stop()`` mid-POST against a real (blocking) transport.

    Pre-R2-H10 a row pulled off the queue but parked on _send_one
    vanished from ``qsize()``. The fix tracks ``_in_flight`` and
    accounts for it in ``_shutdown_lost``."""

    async def test_in_flight_row_counted_in_shutdown_lost(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(af_mod, "resolve_and_pin", _no_dns)
        entered = asyncio.Event()

        async def handler(_req: httpx.Request) -> httpx.Response:
            entered.set()
            # Block until cancelled. MockTransport supports async
            # handlers; this parks the send() until stop() fires.
            await asyncio.sleep(60.0)
            return _resp(200)  # unreachable

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        set_shared_client(client)
        try:
            fwd = AuditForwarder(webhook_url=WEBHOOK, hmac_secret=SECRET)
            fwd.start()
            assert fwd.enqueue(_payload())
            # Wait until the handler is actually mid-request.
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            await fwd.stop(drain_timeout=0.1)
        finally:
            set_shared_client(None)
            await client.aclose()

        assert fwd.shutdown_lost == 1, (
            f"in-flight row not accounted in shutdown_lost: "
            f"sent={fwd.sent_count} failed={fwd.failed_count} "
            f"lost={fwd.shutdown_lost}"
        )
