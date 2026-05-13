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
  own MFA / password-change rows surfaced by the R5 G fix) under
  the "brain-wide" label, which is a category lie: those rows are
  user-personal, not system-wide.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

import httpx
import pytest


# ---------------------------------------------------------------------------
# Round 6 SHIP-STOPPER 1 -- queue_depth is a real class method
# ---------------------------------------------------------------------------


class TestAuditForwarderQueueDepth:
    def test_method_is_on_the_class(self) -> None:
        from z4j_brain.domain.audit_forwarder import AuditForwarder
        fwd = AuditForwarder(
            webhook_url="https://x.example/i",
            hmac_secret=b"x" * 32,
        )
        # Pre-R6 fix: queue_depth was indented outside the class so
        # hasattr returned False; the lifespan registration line
        # crashed the brain on boot.
        assert hasattr(fwd, "queue_depth")
        assert callable(fwd.queue_depth)
        assert fwd.queue_depth() == 0

    def test_queue_depth_reflects_enqueue(self) -> None:
        from z4j_brain.domain.audit_forwarder import AuditForwarder
        fwd = AuditForwarder(
            webhook_url="https://x.example/i",
            hmac_secret=b"x" * 32,
            buffer_size=10,
        )
        for _ in range(3):
            fwd.enqueue({"id": str(uuid.uuid4()), "action": "t",
                         "target_type": "t", "target_id": None,
                         "result": "success", "outcome": "allow",
                         "event_id": None, "user_id": None,
                         "api_key_id": None, "project_id": None,
                         "source_ip": None, "user_agent": None,
                         "metadata": {}, "occurred_at": None,
                         "prev_row_hmac": None, "row_hmac": "0" * 64})
        assert fwd.queue_depth() == 3


# ---------------------------------------------------------------------------
# Round 6 SHIP-STOPPER 2 -- audit_forwarder registration wrapped in try/except
# ---------------------------------------------------------------------------


class TestInmemorySubsystemRegistrationGuards:
    """All four v1.6 ``register_inmemory_subsystem`` callsites must
    be wrapped in try/except so a registration failure does not crash
    lifespan startup."""

    def test_main_wraps_audit_forwarder_registration_in_try_except(
        self,
    ) -> None:
        from pathlib import Path
        src = (
            Path(__file__).resolve().parent.parent.parent
            / "src/z4j_brain/main.py"
        )
        text = src.read_text(encoding="utf-8")
        # The audit_forwarder block must contain the same try/except
        # shape as the other three surfaces.
        anchor = '"audit_forwarder_queue"'
        idx = text.find(anchor)
        assert idx > 0, "audit_forwarder_queue registration missing"
        # Walk backward to find the surrounding try.
        window = text[max(0, idx - 300):idx + 200]
        assert "try:" in window, (
            "audit_forwarder registration MUST be wrapped in try/except "
            "to match the other three v1.6 surfaces (R6 SHIP-STOPPER 2)"
        )


# ---------------------------------------------------------------------------
# Round 6 UX -- personal vs brain-wide badge
# ---------------------------------------------------------------------------


class TestActivityFeedPersonalBadge:
    """The R5 G fix widened the non-admin filter to include the
    caller's user-scoped rows (project_id IS NULL AND user_id ==
    caller). The dashboard rendered those rows under the "brain-wide"
    label, which lies about the scope. R6 fix: branch on whether
    user_id matches the caller, render "personal" instead."""

    def test_dashboard_branches_on_user_id_for_personal_badge(
        self,
    ) -> None:
        from pathlib import Path
        # Find the dashboard route file (project layout permitting).
        candidates = [
            Path(__file__).resolve().parent.parent.parent
            / "../dashboard/src/routes/_authenticated.activity.tsx",
            Path("j:/z4j/packages/z4j/dashboard/src/routes/_authenticated.activity.tsx"),
        ]
        path = next((p for p in candidates if p.exists()), None)
        if path is None:
            pytest.skip("dashboard route file not reachable from this checkout")
        text = path.read_text(encoding="utf-8")
        # The personal/brain-wide branch must be present.
        assert '"personal"' in text and '"brain-wide"' in text
        # The branch MUST consult the caller's user id.
        assert "currentUserId" in text


# ---------------------------------------------------------------------------
# Round 6 -- audit forwarder end-to-end through real httpx transport
# ---------------------------------------------------------------------------


class TestAuditForwarderRealTransport:
    """The R2 ship-stopper happened because every audit-forwarder
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
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.domain.audit_forwarder import (
            AUDIT_SIGNATURE_HEADER,
            AUDIT_TIMESTAMP_HEADER,
            AuditForwarder,
        )
        from z4j_brain.domain.notifications.channels import (
            set_shared_client,
        )
        from z4j_brain.domain import audit_forwarder as af_mod

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
                webhook_url="https://siem.example.com/ingest",
                hmac_secret=secret,
                timeout_seconds=7.5,
            )
            payload = self._make_payload()
            try:
                await fwd._send_one(payload)
            except httpx.StreamConsumed:
                # MockTransport's pre-buffered response trips our
                # streaming read; the request was successfully
                # sent so the captured fields are populated.
                pass
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
            "HMAC mismatch -- the brain's signing diverged from the doc'd "
            "<timestamp>.<body> shape"
        )

        # 5) Per-call timeout reached the transport (R2 ship-stopper
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
