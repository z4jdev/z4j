"""Regression tests pinning the v1.6 Round 6 audit fixes.

Round 6 was the "ship gate" pass. It caught TWO ship-stoppers I had
introduced in Round 5 plus one UX bug:

- ``queue_depth`` was indented outside the AuditForwarder class
  (parsed as a stray def inside ``validate_audit_webhook_url_at_startup``)
  so callers got AttributeError on ``forwarder.queue_depth()`` and
  the brain crashed on boot when audit-webhook was configured.
- ``register_inmemory_subsystem`` for the audit_forwarder was not
  wrapped in try/except like the other three v1.6 surfaces, so any
  registration failure would take the lifespan down.
- The activity feed rendered user-scoped audit rows (the caller's
  own MFA / password-change rows surfaced by the G fix) under
  the "brain-wide" label, which is a category lie: those rows are
  user-personal, not system-wide."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Round 6 SHIP-STOPPER 1 and 2 -- queue_depth and its gauge registration
# ---------------------------------------------------------------------------
# Retired: the forwarder no longer has a queue, so there is no depth to
# expose and no in-memory gauge for main.py to register. Delivery state
# is the durable cursor; see tests/unit/test_audit_forwarder_cursor.py.


# ---------------------------------------------------------------------------
# Round 6 UX -- personal vs brain-wide badge
# ---------------------------------------------------------------------------


# The personal/brain-wide branch now has a runtime Vitest oracle in
# ``dashboard/tests/unit/activity-scope.test.ts`` and is called by the route.


# ---------------------------------------------------------------------------
# Round 6 -- audit forwarder end-to-end through real httpx transport
# ---------------------------------------------------------------------------


class TestAuditForwarderRealTransport:
    """The ship-stopper happened because every audit-forwarder
    test monkeypatched ``_post`` entirely, bypassing the broken
    ``timeout`` kwarg. These tests exercise the FULL
    ``_send_one`` -> ``_post`` -> httpx pipeline so a future
    regression of that class is caught immediately."""

    def _make_payload(self) -> dict[str, Any]:
        return {
            "id": "00000000-0000-4000-a000-00000000000a",
            "action": "user.password_changed",
            "target_type": "user",
            "target_id": "user-1",
            "result": "success",
            "outcome": "allow",
            "event_id": None,
            "user_id": "00000000-0000-4000-a000-0000000000aa",
            "api_key_id": None,
            "project_id": None,
            "source_ip": "192.0.2.10",
            "user_agent": "z4j-cli/1",
            "metadata": {"k": "v"},
            "occurred_at": "2026-05-13T12:00:00.000000+00:00",
            "prev_row_hmac": "a" * 64,
            "row_hmac": "b" * 64,
        }

    @pytest.mark.asyncio
    async def test_send_one_through_real_httpx(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.domain import audit_forwarder as af_mod
        from z4j_brain.domain.audit_forwarder import (
            AUDIT_SIGNATURE_HEADER,
            AUDIT_TIMESTAMP_HEADER,
            AuditForwarder,
        )
        from z4j_brain.domain.notifications.channels import (
            set_shared_client,
        )

        async def _noop_resolve_and_pin(
            _u: str,
        ) -> tuple[str | None, str | None]:
            return None, "203.0.113.1"

        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            # Read the full body before responding so streaming
            # doesn't trip our existing buffered-read path.
            body_bytes = request.read()
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            captured["body"] = body_bytes
            captured["timeout_extension"] = dict(
                request.extensions or {},
            ).get("timeout")
            return httpx.Response(200, content=b"ok")

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=httpx.Timeout(60.0),
        )
        set_shared_client(client)
        try:
            secret = b"a" * 48
            fwd = AuditForwarder(
                db=SimpleNamespace(),  # _send_one never touches the database
                webhook_url="https://siem.example.com/ingest",
                hmac_secret=secret,
                timeout_seconds=7.5,
            )
            payload = self._make_payload()
            # MockTransport's pre-buffered response trips our
            # streaming read; the request was successfully
            # sent so the captured fields are populated.
            with contextlib.suppress(httpx.StreamConsumed):
                await fwd._send_one(payload)
        finally:
            set_shared_client(None)
            await client.aclose()

        # 1) URL is the configured webhook (after DNS pin -- the
        # actual URL in extensions will reflect the pin, but the
        # transport-side Host header MUST be the original hostname).
        assert "siem.example.com" in captured["headers"].get("host", "")

        # 2) Body is the JSON-sorted payload.
        body_decoded = json.loads(captured["body"].decode("utf-8"))
        assert body_decoded["action"] == "user.password_changed"
        assert body_decoded["id"] == payload["id"]

        # 3) Timestamp header is a recent Unix-seconds string.
        ts = captured["headers"][AUDIT_TIMESTAMP_HEADER.lower()]
        assert ts.isdigit()
        # Within 60 s of now (CI clock skew tolerance).
        assert abs(int(time.time()) - int(ts)) < 60

        # 4) Signature is HMAC over ``<ts>.<body>`` with the secret.
        expected = (
            "sha256="
            + hmac.new(
                secret,
                ts.encode("utf-8") + b"." + captured["body"],
                hashlib.sha256,
            ).hexdigest()
        )
        actual = captured["headers"][AUDIT_SIGNATURE_HEADER.lower()]
        assert hmac.compare_digest(expected, actual), (
            "HMAC mismatch -- the brain's signing diverged from the doc'd <timestamp>.<body> shape"
        )

        # 5) Per-call timeout reached the transport (ship-stopper
        # class: a future regression that drops the timeout would
        # see this assertion fail).
        t = captured.get("timeout_extension")
        if isinstance(t, dict):
            assert t.get("read") == 7.5
        elif isinstance(t, httpx.Timeout):
            assert t.read == 7.5
        else:
            pytest.fail(
                f"timeout extension neither dict nor Timeout: {type(t).__name__}",
            )
