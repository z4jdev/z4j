"""Regression tests pinning the v1.6 Round 5 audit fixes.

Round 5 was the "did the fixes break anything" pass. Six agents
audited Waves 5/6/7's patches plus broader v1.6 surface. Two real
regressions in my own fixes (rate-limit pin DoS; non-dict scrub
contract), plus several smaller items, plus important UX/integration
gaps (MFA visibility for own owner, swallowed-counter coverage,
naive-datetime cursor 500). Each test pins one of those fixes.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from z4j_brain.api import activity as activity_mod
from z4j_brain.api.activity import (
    _decode_cursor,
    _rate_limit_check,
    _reset_rate_limit_for_tests,
    _user_bucket,
)
from z4j_brain.observability import otel as otel_mod
from z4j_brain.observability.sentry import scrub_event


# ---------------------------------------------------------------------------
# Round 5 F1 (re) -- per-call timeout reaches the transport as a Timeout
# ---------------------------------------------------------------------------


class TestPostTimeoutReachesTransport:
    """The R2 fix tried `extensions["timeout"] = dict(...)`; the R5
    agent flagged that httpx 0.28+ expects an httpx.Timeout object,
    not a dict. The R5 fix pivots to `build_request(timeout=...)`
    which httpx unwraps to the right transport shape. This test
    pins the contract: the request's transport-side extensions
    carry the per-call timeout."""

    @pytest.mark.asyncio
    async def test_timeout_reaches_mock_transport(self) -> None:
        from z4j_brain.domain.notifications.channels import (
            _post,
            set_shared_client,
        )

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["extensions"] = dict(request.extensions or {})
            return httpx.Response(200, content=b"ok")

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=httpx.Timeout(60.0),
        )
        set_shared_client(client)
        try:
            try:
                await _post(
                    "https://example.com/x", content=b"{}", timeout=15.0,
                )
            except httpx.StreamConsumed:
                # MockTransport returns a non-streamable response; the
                # request HAS reached the transport so captured is set.
                pass
        finally:
            set_shared_client(None)
            await client.aclose()

        t = captured.get("extensions", {}).get("timeout")
        # httpx 0.28+ unwraps Timeout to a dict at transport boundary;
        # accept either shape for forward-compat.
        if isinstance(t, dict):
            assert t.get("read") == 15.0
            assert t.get("connect") == 15.0
        elif isinstance(t, httpx.Timeout):
            assert t.read == 15.0
            assert t.connect == 15.0
        else:
            pytest.fail(
                f"timeout extension is neither dict nor Timeout: {type(t).__name__}",
            )


# ---------------------------------------------------------------------------
# Round 5 F2 -- rate-limit LRU pin DoS
# ---------------------------------------------------------------------------


class TestRateLimitLRUDoesNotPinDeniedCallers:
    """A hostile caller hitting 429s repeatedly must NOT keep their
    entry pinned at MRU forever. The R5 fix only touches LRU order
    on the GRANTED path."""

    def setup_method(self) -> None:
        _reset_rate_limit_for_tests()

    def teardown_method(self) -> None:
        _reset_rate_limit_for_tests()

    def test_denied_calls_do_not_move_to_end(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Saturate 'a' first so its bucket is at the limit, then
        touch 'b' and 'c' so both are MRU AFTER 'a'. Now 'a' hammers
        the 429 boundary. The pre-fix code would have moved 'a' to
        MRU on every denial, keeping it pinned forever. The fix:
        denied calls do NOT touch LRU order. New caller 'd' should
        evict 'a' (the LRU) when the cap is reached."""
        monkeypatch.setattr(activity_mod, "_RATE_LIMIT_USER_CAP", 3)
        # Three users fill the cap.
        for uid in ("a", "b", "c"):
            _rate_limit_check(uid)
        # Saturate 'a' to the rate-limit ceiling.
        for _ in range(59):
            _rate_limit_check("a")
        # Touch 'b' THEN 'c' so they are both MRU after 'a'.
        # Order: [a, b, c] with c MRU.
        _rate_limit_check("b")
        _rate_limit_check("c")
        # Verify ordering pre-denial: 'a' is LRU.
        order = list(_user_bucket.keys())
        assert order == ["a", "b", "c"], f"unexpected order before denials: {order}"
        # 'a' hammers the 429 boundary. Each hit returns False.
        for _ in range(20):
            assert _rate_limit_check("a") is False
        # Under the fix, denied calls did NOT touch order; 'a' is
        # still LRU. Add new user 'd' to evict.
        _rate_limit_check("d")
        # 'a' must be the one evicted, not 'b' or 'c'.
        assert "a" not in _user_bucket, (
            "denied-call LRU touch let 'a' stay pinned at MRU -- "
            "rate-limit pin DoS regressed (R5 F2). "
            f"Current bucket order: {list(_user_bucket.keys())}"
        )


# ---------------------------------------------------------------------------
# Round 5 F11 -- _decode_cursor force UTC on naive datetime
# ---------------------------------------------------------------------------


class TestDecodeCursorNaiveDatetime:
    def test_naive_datetime_cursor_gets_utc(self) -> None:
        """A cursor without timezone offset (e.g.,
        ``2026-05-13T10:00:00|<uuid>``) must NOT produce a naive
        datetime; comparing naive vs aware in Postgres raises 500.
        The R5 fix forces UTC."""
        cursor = "2026-05-13T10:00:00|aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        dt, row_id = _decode_cursor(cursor)
        assert dt.tzinfo is not None
        assert dt.tzinfo == UTC
        assert row_id == uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    def test_aware_datetime_cursor_preserved(self) -> None:
        """A cursor WITH offset must preserve its timezone."""
        cursor = "2026-05-13T10:00:00+00:00|aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        dt, _ = _decode_cursor(cursor)
        assert dt.tzinfo is not None

    def test_malformed_still_raises_422(self) -> None:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as excinfo:
            _decode_cursor("not-a-cursor")
        assert excinfo.value.status_code == 422


# ---------------------------------------------------------------------------
# Round 5 F5 -- OTel _reset_for_tests clears dynamic sensitive hosts
# ---------------------------------------------------------------------------


class TestOtelResetClearsDynamicHosts:
    def test_reset_clears_dynamic_hosts(self) -> None:
        otel_mod._register_dynamic_sensitive_host(
            "https://siem.example.com/ingest",
        )
        assert "siem.example.com" in otel_mod._DYNAMIC_SENSITIVE_HOSTS
        otel_mod._reset_for_tests()
        assert "siem.example.com" not in otel_mod._DYNAMIC_SENSITIVE_HOSTS


# ---------------------------------------------------------------------------
# Round 5 F4 -- scrub_event returns None for non-dict
# ---------------------------------------------------------------------------


class TestScrubEventNonDictReturnsNone:
    @pytest.mark.parametrize(
        "bad",
        [None, "string", 42, 3.14, [], (), b"bytes", True, object()],
    )
    def test_non_dict_event_returns_none(self, bad: Any) -> None:
        """Sentry SDK before_send contract: return Event-dict or
        None. Returning anything else crashes the SDK downstream."""
        assert scrub_event(bad) is None


# ---------------------------------------------------------------------------
# Round 5 I -- record_swallowed coverage for audit-forwarder paths
# ---------------------------------------------------------------------------


class TestAuditForwarderSwallowedCoverage:
    """The Grafana alert keys on z4j_swallowed_exceptions_total
    under module=audit_forwarder. Three failure paths exist:
    queue_full, ssrf_or_dns, send_one (raised exception inside
    _send_one's try). Round 5 added post_raised (the outer except
    around _post itself) AND non_2xx (already in via Wave 7) AND
    audit_service post_commit_hook."""

    @pytest.mark.asyncio
    async def test_post_raised_bumps_swallowed(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.domain import audit_forwarder as af_mod
        from z4j_brain.domain.audit_forwarder import AuditForwarder

        counts: dict[str, int] = {}

        def _fake_record(module: str, site: str) -> None:
            key = f"{module}/{site}"
            counts[key] = counts.get(key, 0) + 1

        async def _raising_post(*_a: Any, **_kw: Any) -> httpx.Response:
            raise RuntimeError("network down")

        async def _noop_resolve_and_pin(
            _u: str,
        ) -> tuple[str | None, str | None]:
            return None, "203.0.113.1"

        monkeypatch.setattr(af_mod, "record_swallowed", _fake_record)
        monkeypatch.setattr(af_mod, "_post", _raising_post)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        # Use the JSON-serialisable dict shape directly.
        payload = {
            "id": "00000000-0000-0000-0000-00000000abcd",
            "action": "t", "target_type": "t", "target_id": None,
            "result": "success", "outcome": "allow", "event_id": None,
            "user_id": None, "api_key_id": None, "project_id": None,
            "source_ip": None, "user_agent": None, "metadata": {},
            "occurred_at": "2026-05-12T12:00:00.000000+00:00",
            "prev_row_hmac": None, "row_hmac": "0" * 64,
        }
        await fwd._send_one(payload)
        assert counts.get("audit_forwarder/post_raised", 0) == 1


# ---------------------------------------------------------------------------
# Round 5 G -- Activity feed shows user's own user-scoped audit rows
# ---------------------------------------------------------------------------


class TestActivityFeedUserScopedRowVisibility:
    """A non-admin user has MFA / auth audit rows that carry
    ``project_id=NULL`` because they aren't project-scoped. The
    pre-Round-5 filter excluded these. The R5 fix widens the
    filter so the user sees their OWN user-scoped rows (e.g.,
    their own MFA enroll) even though no project_id is set."""

    def test_filter_clause_documents_intent(self) -> None:
        """Source-level pin so a future refactor that drops the
        ``user_id == user.id`` arm fails this test. The query
        builder runs end-to-end in the existing
        test_activity_endpoint.py suite under SQLAlchemy."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parent.parent.parent
            / "src/z4j_brain/api/activity.py"
        )
        text = src.read_text(encoding="utf-8")
        # The clause must include the OR with user-scoped rows.
        assert "AuditLog.project_id.is_(None)" in text
        assert "AuditLog.user_id == user.id" in text
