"""Regression tests pinning the v1.6 Round 2 audit fixes.

Each test names the Round 2 finding it pins (Sev-N / area code). A
refactor that re-introduces any of these bugs fails CI here before
shipping.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
import uuid
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from z4j_brain.observability import sentry as sentry_mod
from z4j_brain.observability.sentry import (
    _PATH_TOKEN_HOST_RE,
    _REDACT_MAX_DEPTH,
    _SENSITIVE_HEADERS,
    _redact_mapping,
    _scrub_inline_urls,
    _scrub_url,
    _scrub_stacktrace_frames,
    scrub_event,
)
from z4j_brain.domain import audit_forwarder as af_mod
from z4j_brain.domain.audit_forwarder import (
    AUDIT_SIGNATURE_HEADER,
    AUDIT_TIMESTAMP_HEADER,
    AuditForwarder,
    row_to_payload,
    sign_payload,
)
from z4j_brain.api import activity as activity_mod


# ---------------------------------------------------------------------------
# Round 2 A -- _post timeout via request.extensions (the SHIP-STOPPER)
# ---------------------------------------------------------------------------


class TestPostTimeoutWiring:
    """v1.6 Round 2 Sev-1: ``_post`` must pass timeout via
    ``request.extensions["timeout"]``, NOT via
    ``AsyncClient.send(timeout=...)`` (which is not a valid kwarg in
    httpx 0.28+). The audit forwarder always calls _post with a
    timeout; without this fix EVERY forward POST raises TypeError."""

    @pytest.mark.asyncio
    async def test_timeout_threads_via_request_extensions(self) -> None:
        from z4j_brain.domain.notifications.channels import (
            _post,
            set_shared_client,
        )

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["extensions"] = dict(request.extensions or {})
            return httpx.Response(200, content=b"OK")

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=httpx.Timeout(10.0, connect=5.0),
        )
        set_shared_client(client)
        try:
            await _post(
                "https://hooks.example.com/ingest",
                content=b"{}",
                timeout=15.0,
            )
        except httpx.StreamConsumed:
            # MockTransport returns a non-streamable response; the
            # post-send body cap then trips. We don't care for this
            # assertion -- the request HAS been built and sent, so
            # the captured extensions are valid.
            pass
        finally:
            set_shared_client(None)
            await client.aclose()

        # The crux: the bug was passing `timeout=` to .send() which
        # raises TypeError. The fix passes it via the request's
        # extensions dict.
        ext = captured.get("extensions", {})
        assert "timeout" in ext, (
            "v1.6 Round 2 Sev-1: per-call timeout MUST be carried "
            "via request.extensions, not AsyncClient.send(timeout=)"
        )
        timeout_block = ext["timeout"]
        assert timeout_block["connect"] == 15.0
        assert timeout_block["read"] == 15.0


# ---------------------------------------------------------------------------
# Round 2 B -- Sentry deeper scrubbing
# ---------------------------------------------------------------------------


class TestRound2SentryScrubbing:
    def test_x_forwarded_for_header_redacted(self) -> None:
        """Round 2 Sev-4 / H5: IP-chain headers leak the real
        client IP via Sentry's request.env block. Now in the
        sensitive header set."""
        assert "x-forwarded-for" in _SENSITIVE_HEADERS
        assert "x-real-ip" in _SENSITIVE_HEADERS
        assert "forwarded" in _SENSITIVE_HEADERS
        # And the env scrubber catches them via HTTP_* normalisation.
        event = {
            "request": {
                "env": {
                    "HTTP_X_FORWARDED_FOR": "1.2.3.4, 5.6.7.8",
                    "HTTP_X_REAL_IP": "1.2.3.4",
                    "HTTP_FORWARDED": "for=1.2.3.4",
                },
            },
        }
        out = scrub_event(event)
        for key in ("HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "HTTP_FORWARDED"):
            assert out["request"]["env"][key] == "[REDACTED by z4j]"

    def test_exception_value_url_scrubbed(self) -> None:
        """Round 2 H2: str(exc) routinely embeds URLs with tokens
        in the path. The Sentry scrubber now strips them."""
        event = {
            "exception": {
                "values": [
                    {
                        "type": "HTTPStatusError",
                        "value": "401 Unauthorized for url 'https://hooks.slack.com/T0/B0/SECRETPATH'",
                    },
                ],
            },
        }
        out = scrub_event(event)
        msg = out["exception"]["values"][0]["value"]
        assert "SECRETPATH" not in msg, msg
        assert "[REDACTED by z4j]" in msg

    def test_stacktrace_context_line_scrubbed(self) -> None:
        """Round 2 C-1: source-code context lines around the raising
        line ship verbatim. Now scrubbed for token-in-path URLs."""
        event = {
            "exception": {
                "values": [
                    {
                        "stacktrace": {
                            "frames": [
                                {
                                    "context_line": 'token = "https://hooks.slack.com/T0/B0/SECRET"',
                                    "pre_context": [
                                        'WEBHOOK_URL = "https://contoso.webhook.office.com/x/SECRET"',
                                    ],
                                    "post_context": [],
                                },
                            ],
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        frame = out["exception"]["values"][0]["stacktrace"]["frames"][0]
        assert "SECRET" not in frame["context_line"]
        assert "SECRET" not in frame["pre_context"][0]

    def test_stacktrace_vars_redacted(self) -> None:
        """Local variables (vars dict) get the value-key scrubber."""
        event = {
            "exception": {
                "values": [
                    {
                        "stacktrace": {
                            "frames": [
                                {
                                    "vars": {
                                        "api_key": "leak",
                                        "request_id": "keep",
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        v = out["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]
        assert v["api_key"] == "[REDACTED by z4j]"
        assert v["request_id"] == "keep"

    def test_threads_block_stacktrace_scrubbed(self) -> None:
        """Round 2 C-2: thread dumps use the same stacktrace shape."""
        event = {
            "threads": {
                "values": [
                    {
                        "stacktrace": {
                            "frames": [
                                {
                                    "context_line": '"https://hooks.slack.com/T/B/LEAK"',
                                },
                            ],
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        assert (
            "LEAK"
            not in out["threads"]["values"][0]["stacktrace"]["frames"][0]["context_line"]
        )

    def test_transaction_url_scrubbed(self) -> None:
        """Round 2 H-1: when FastAPI can't match a route the
        transaction string is the raw URL. Scrub it."""
        event = {"transaction": "https://brain/webhook?token=leak"}
        out = scrub_event(event)
        assert "leak" not in out["transaction"]

    def test_redact_mapping_depth_bound(self) -> None:
        """Round 2 M4: deeply nested extra dict must not crash the
        scrubber. The depth-bound truncates the subtree."""
        nested: dict[str, Any] = {"v": "leaf"}
        for _ in range(_REDACT_MAX_DEPTH + 5):
            nested = {"deeper": nested}
        out = _redact_mapping({"root": nested})
        # The output is finite; at MAX_DEPTH the subtree becomes a
        # truncation marker, not the original deep chain.
        cur = out["root"]
        depth = 0
        while isinstance(cur, dict) and "deeper" in cur:
            cur = cur["deeper"]
            depth += 1
        assert depth <= _REDACT_MAX_DEPTH
        # The truncation marker stands in for the cut subtree.
        assert isinstance(cur, dict)
        assert "_z4j_truncated" in cur

    def test_scrub_event_handles_non_dict(self) -> None:
        """Round 2 M3 + Round 5 F4: scrubber returns None for any
        non-dict input. Returning a non-dict would crash the Sentry
        SDK's downstream envelope serialiser (before_send contract
        is ``Event | None``)."""
        assert scrub_event(None) is None  # type: ignore[arg-type]
        assert scrub_event("not a dict") is None  # type: ignore[arg-type]
        assert scrub_event(42) is None  # type: ignore[arg-type]
        assert scrub_event([]) is None  # type: ignore[arg-type]

    def test_inline_url_scrubber_handles_token_in_path(self) -> None:
        """Round 2 M-4 / C-3: ``_scrub_url`` skips URLs without a
        ``?``; the inline scrubber covers token-in-path webhook URLs
        in free-form log message text."""
        out = _scrub_inline_urls(
            "Posted to https://hooks.slack.com/T0/B0/SECRET ok",
        )
        assert "SECRET" not in out
        assert "hooks.slack.com" in out  # host kept for diagnostics

    def test_path_token_host_regex_covers_all_dispatchers(self) -> None:
        """Pin the regex against every dispatch destination so a
        future addition is forced to update the regex."""
        for url in [
            "https://hooks.slack.com/T/B/x",
            "https://discord.com/api/webhooks/x",
            "https://discordapp.com/api/webhooks/x",
            "https://contoso.webhook.office.com/x",
            "https://prod-04.eastus2.logic.azure.com/x",
            "https://outlook.office.com/webhook/x",
            "https://events.pagerduty.com/v2/enqueue",
        ]:
            assert _PATH_TOKEN_HOST_RE.search(url), f"missed: {url}"


# ---------------------------------------------------------------------------
# Round 2 C -- OTel fail-closed + response_hook
# ---------------------------------------------------------------------------


class TestRound2OtelHookFailClosed:
    """Round 2 H3: the httpx request_hook now FAILS CLOSED. A
    scrubber failure overwrites the URL to a generic marker so the
    auto-captured URL never ships."""

    def test_sensitive_host_classifier_strict(self) -> None:
        from z4j_brain.observability.otel import _is_sensitive_outbound_host

        assert _is_sensitive_outbound_host("hooks.slack.com")
        assert _is_sensitive_outbound_host("contoso.webhook.office.com")
        # Suffix smuggle (host . evil) must NOT match.
        assert not _is_sensitive_outbound_host("hooks.slack.com.evil.com")
        # Trailing-dot FQDN gets stripped before comparison.
        assert _is_sensitive_outbound_host("hooks.slack.com.")


# ---------------------------------------------------------------------------
# Round 2 D -- Audit forwarder shutdown drain in-flight tracking
# ---------------------------------------------------------------------------


class TestRound2InFlightShutdownTracking:
    @pytest.mark.asyncio
    async def test_in_flight_row_counted_at_shutdown(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Round 2 Sev-5 / H10: a row that was pulled from the
        queue and is awaiting _send_one when cancellation lands is
        lost; before this fix it was NOT counted in shutdown_lost."""

        async def _stuck_post(*_args: Any, **_kwargs: Any) -> httpx.Response:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def _noop_resolve_and_pin(
            _u: str,
        ) -> tuple[str | None, str | None]:
            return None, "203.0.113.1"

        monkeypatch.setattr(af_mod, "_post", _stuck_post)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        fwd.start()
        # Push a row; let the drain task pull it and park inside _send_one.
        row = SimpleNamespace(
            id=uuid.UUID("00000000-0000-0000-0000-00000000abcd"),
            action="test.action", target_type="t", target_id=None,
            result="success", outcome="allow", event_id=None,
            user_id=None, api_key_id=None, project_id=None,
            source_ip=None, user_agent=None, audit_metadata={},
            occurred_at=None, prev_row_hmac=None, row_hmac="0" * 64,
        )
        # Bypass _row_to_payload's occurred_at iso conversion.
        fwd.enqueue(
            {
                "id": "00000000-0000-0000-0000-00000000abcd",
                "action": "test.action", "target_type": "t",
                "target_id": None, "result": "success",
                "outcome": "allow", "event_id": None,
                "user_id": None, "api_key_id": None,
                "project_id": None, "source_ip": None,
                "user_agent": None, "metadata": {},
                "occurred_at": "2026-05-12T12:00:00.000000+00:00",
                "prev_row_hmac": None, "row_hmac": "0" * 64,
            },
        )
        await asyncio.sleep(0.05)  # let drain task pull + block
        # Stop with a short deadline so the in-flight row is forcibly
        # cancelled.
        await fwd.stop(drain_timeout=0.05)
        # The fix: in-flight row IS counted (was 0 before fix).
        assert fwd.shutdown_lost == 1, (
            f"in-flight row must increment shutdown_lost; got {fwd.shutdown_lost}"
        )


# ---------------------------------------------------------------------------
# Round 2 E -- Activity rate limit bucket cap + LRU eviction
# ---------------------------------------------------------------------------


class TestRateLimitBucketCap:
    """Round 2 Sev-7 / High-1: the per-user bucket dict was
    unbounded. Cap is 50_000 with LRU eviction."""

    def setup_method(self) -> None:
        activity_mod._reset_rate_limit_for_tests()

    def teardown_method(self) -> None:
        activity_mod._reset_rate_limit_for_tests()

    def test_lru_eviction_at_cap(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Patch the cap down so the test runs fast.
        monkeypatch.setattr(activity_mod, "_RATE_LIMIT_USER_CAP", 5)
        for uid in (f"u{i}" for i in range(5)):
            activity_mod._rate_limit_check(uid)
        assert len(activity_mod._user_bucket) == 5
        # Adding a 6th user evicts the LRU (u0).
        activity_mod._rate_limit_check("u_new")
        assert "u0" not in activity_mod._user_bucket
        assert "u_new" in activity_mod._user_bucket
        assert len(activity_mod._user_bucket) == 5

    def test_recent_access_updates_lru_order(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(activity_mod, "_RATE_LIMIT_USER_CAP", 3)
        for uid in ("a", "b", "c"):
            activity_mod._rate_limit_check(uid)
        # Touch "a" so it's MRU.
        activity_mod._rate_limit_check("a")
        # Add a new user; "b" should be evicted (LRU), not "a".
        activity_mod._rate_limit_check("d")
        assert "a" in activity_mod._user_bucket
        assert "b" not in activity_mod._user_bucket


# ---------------------------------------------------------------------------
# Round 2 -- Documentation drift checks (source-level greps)
# ---------------------------------------------------------------------------


class TestRound2DocsAlignment:
    """Greps for known wrong wording from before the doc fix.
    If a future docs edit reintroduces the wrong receiver formula,
    or the wrong cursor names, this test fails before publish.
    """

    def test_audit_webhook_doc_uses_timestamp_signing(self) -> None:
        from pathlib import Path
        doc = Path(
            "../../sites/z4j-dev/src/content/docs/operations/audit-webhook.md",
        )
        if not doc.exists():
            pytest.skip("docs not in this checkout layout")
        text = doc.read_text(encoding="utf-8")
        assert "X-Z4J-Audit-Timestamp" in text
        assert "digest_input" in text or "ts.encode" in text, (
            "audit-webhook receiver snippet MUST sign over <timestamp>.<body>"
        )

    def test_activity_feed_doc_uses_cursor_names(self) -> None:
        from pathlib import Path
        doc = Path(
            "../../sites/z4j-dev/src/content/docs/operations/activity-feed.md",
        )
        if not doc.exists():
            pytest.skip("docs not in this checkout layout")
        text = doc.read_text(encoding="utf-8")
        # No legacy _id cursor names should remain.
        for legacy in (
            "next_before_id",
            "newest_id",
            "?since_id=",
            "?before_id=",
        ):
            assert legacy not in text, (
                f"legacy cursor name remains in activity-feed.md: {legacy}"
            )
        # New cursor names + rate-limit + source_ip RBAC documented.
        assert "next_before_cursor" in text
        assert "Rate limit" in text or "60 requests / minute" in text or "60/min per worker" in text
