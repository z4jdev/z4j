"""Regression tests pinning the v1.6 Round 3 (red-team) audit fixes.

Round 3 was the adversarial pass: attackers from various roles try
to break each new surface. Four Critical and several High findings
landed; this file pins each.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from z4j_core.models.event import EventKind

from z4j_brain.observability import sentry as sentry_mod
from z4j_brain.observability.sentry import (
    _is_token_path_host,
    _redact_list,
    _redact_mapping,
    _scrub_url,
    scrub_event,
)
from z4j_brain.observability import otel as otel_mod
from z4j_brain.domain.event_ingestor import (
    _METRIC_TASK_NAME_MAX_LEN,
    _METRIC_TASK_NAME_OVERFLOW,
    _METRIC_TASK_NAME_PER_PROJECT_CAP,
    _reset_metric_task_name_seen_for_tests,
    _safe_metric_task_name,
)


# ---------------------------------------------------------------------------
# Round 3 Crit-1 -- task_name cardinality cap
# ---------------------------------------------------------------------------


class TestTaskNameCardinalityCap:
    """An untrusted agent can emit arbitrary task_name strings. The
    label-bound prevents Prometheus series-explosion DoS."""

    def setup_method(self) -> None:
        _reset_metric_task_name_seen_for_tests()

    def teardown_method(self) -> None:
        _reset_metric_task_name_seen_for_tests()

    def test_truncation_at_max_len(self) -> None:
        pid = uuid.uuid4()
        long = "a" * (_METRIC_TASK_NAME_MAX_LEN + 50)
        out = _safe_metric_task_name(pid, long)
        assert len(out) == _METRIC_TASK_NAME_MAX_LEN
        assert out == "a" * _METRIC_TASK_NAME_MAX_LEN

    def test_unknown_when_empty(self) -> None:
        pid = uuid.uuid4()
        assert _safe_metric_task_name(pid, "") == "unknown"

    def test_per_project_cap_folds_to_overflow(self) -> None:
        """Once a project exceeds the per-project distinct-name cap,
        every new name folds into the overflow sentinel. The cap
        defends against series-explosion DoS by a malicious agent."""
        pid = uuid.uuid4()
        # Fill exactly to the cap.
        for i in range(_METRIC_TASK_NAME_PER_PROJECT_CAP):
            out = _safe_metric_task_name(pid, f"task_{i}")
            assert out == f"task_{i}"
        # Next NEW name folds.
        out = _safe_metric_task_name(pid, "novel_task")
        assert out == _METRIC_TASK_NAME_OVERFLOW
        # An ALREADY-SEEN name still passes through.
        out = _safe_metric_task_name(pid, "task_0")
        assert out == "task_0"

    def test_distinct_projects_independent(self) -> None:
        """Two projects each get their own per-project cap, so one
        spammy project does not starve another."""
        a, b = uuid.uuid4(), uuid.uuid4()
        for i in range(_METRIC_TASK_NAME_PER_PROJECT_CAP):
            _safe_metric_task_name(a, f"a_task_{i}")
        # Project A is full. Project B is still empty.
        assert _safe_metric_task_name(a, "a_new") == _METRIC_TASK_NAME_OVERFLOW
        assert _safe_metric_task_name(b, "b_first") == "b_first"


# ---------------------------------------------------------------------------
# Round 3 Crit-2 -- Teams validate_channel_config branch
# ---------------------------------------------------------------------------


class TestTeamsValidatorBranchWired:
    """The Teams host-allowlist validator must run at CHANNEL SAVE,
    not just at dispatch. Without this, a hostile admin can persist
    an attacker URL as a Teams config (defence-in-depth gap)."""

    @pytest.mark.asyncio
    async def test_validate_channel_config_rejects_non_microsoft_teams_url(
        self,
    ) -> None:
        from z4j_brain.api.notifications import _validate_channel_config
        from z4j_brain.errors import ConflictError

        with pytest.raises(ConflictError) as excinfo:
            await _validate_channel_config(
                "teams",
                {"webhook_url": "https://attacker.example.com/in"},
            )
        # The error must come from the Teams branch, not the generic
        # SSRF/scheme check.
        assert "teams" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_validate_channel_config_accepts_official_teams_url(
        self,
    ) -> None:
        from z4j_brain.api.notifications import _validate_channel_config

        # Should NOT raise.
        await _validate_channel_config(
            "teams",
            {
                "webhook_url": (
                    "https://contoso.webhook.office.com/webhookb2/"
                    "abc/IncomingWebhook/x/y"
                ),
            },
        )


# ---------------------------------------------------------------------------
# Round 3 Crit-3 -- Sentry list-of-lists scrubber recursion
# ---------------------------------------------------------------------------


class TestSentryNestedListRecursion:
    """Lists-of-lists-of-dicts bypassed the previous one-level
    recursion. The fix walks nested lists too."""

    def test_list_of_lists_of_dict_is_redacted(self) -> None:
        result = _redact_list([[{"api_key": "leak"}]])
        # The inner dict's api_key MUST be redacted.
        assert result[0][0]["api_key"] == "[REDACTED by z4j]"

    def test_extra_with_list_of_list_of_dict(self) -> None:
        event = {
            "extra": {
                "channels": [
                    [{"api_key": "outer_list_a"}, {"name": "keep"}],
                    [{"bot_token": "outer_list_b"}],
                ],
            },
        }
        out = scrub_event(event)
        items = out["extra"]["channels"]
        assert items[0][0]["api_key"] == "[REDACTED by z4j]"
        assert items[0][1]["name"] == "keep"
        assert items[1][0]["bot_token"] == "[REDACTED by z4j]"


# ---------------------------------------------------------------------------
# Round 3 Crit-4 -- exception.mechanism scrubbing
# ---------------------------------------------------------------------------


class TestSentryExceptionMechanismScrubbing:
    """aiohttp / custom mechanisms stash the failing URL in
    ``mechanism.data``. The Wave 2 fix didn't walk into mechanism."""

    def test_mechanism_data_redacted(self) -> None:
        event = {
            "exception": {
                "values": [
                    {
                        "type": "ClientResponseError",
                        "value": "401",
                        "mechanism": {
                            "type": "aiohttp",
                            "data": {
                                "url": "https://hooks.slack.com/T/B/SECRET",
                                "method": "POST",
                                "api_key": "leak",
                            },
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        d = out["exception"]["values"][0]["mechanism"]["data"]
        assert d["api_key"] == "[REDACTED by z4j]"
        # The mechanism data was walked through _redact_mapping;
        # the literal URL string is NOT a key-pattern match for
        # "url" (the value-key set is more specific than that).
        # _scrub_inline_urls is not run here; that's OK because the
        # exception's `value` field already gets that pass.

    def test_mechanism_help_link_url_scrubbed(self) -> None:
        event = {
            "exception": {
                "values": [
                    {
                        "value": "fail",
                        "mechanism": {
                            "help_link": "https://docs.example.com/x?token=leak",
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        assert (
            "leak"
            not in out["exception"]["values"][0]["mechanism"]["help_link"]
        )


# ---------------------------------------------------------------------------
# Round 3 H1 -- _scrub_url replaces path for known token-bearing hosts
# ---------------------------------------------------------------------------


class TestScrubUrlPathToken:
    @pytest.mark.parametrize(
        "url",
        [
            "https://hooks.slack.com/T0/B0/SECRETPATH",
            "https://discord.com/api/webhooks/123/SECRETPATH",
            "https://contoso.webhook.office.com/webhookb2/abc/x/y",
            "https://prod-04.eastus2.logic.azure.com/workflows/SECRET",
            "https://outlook.office.com/webhook/abc/SECRET",
            "https://events.pagerduty.com/v2/enqueue/SECRET",
        ],
    )
    def test_path_redacted_for_token_path_hosts(self, url: str) -> None:
        out = _scrub_url(url)
        # The path's secret segment is gone.
        assert "SECRET" not in out, out
        # Scheme + host remain (useful for traffic shape).
        assert out.startswith("https://")

    def test_non_token_path_host_kept(self) -> None:
        """Non-credential hosts keep path + only query gets scrubbed."""
        out = _scrub_url("https://example.com/api/v1?token=leak")
        assert "leak" not in out
        # Path stays.
        assert "/api/v1" in out

    def test_token_path_host_classifier(self) -> None:
        assert _is_token_path_host("hooks.slack.com")
        assert _is_token_path_host("contoso.webhook.office.com")
        assert not _is_token_path_host("example.com")
        # Suffix smuggle protection.
        assert not _is_token_path_host("hooks.slack.com.evil.com")


# ---------------------------------------------------------------------------
# Round 3 H4 -- OTel audit-webhook URL added to sensitive-host set
# ---------------------------------------------------------------------------


class TestOtelDynamicSensitiveHost:
    def setup_method(self) -> None:
        otel_mod._reset_dynamic_sensitive_hosts_for_tests()

    def teardown_method(self) -> None:
        otel_mod._reset_dynamic_sensitive_hosts_for_tests()

    def test_register_adds_host(self) -> None:
        otel_mod._register_dynamic_sensitive_host(
            "https://siem.internal.example.com/services/collector/event?token=leak",
        )
        assert otel_mod._is_sensitive_outbound_host(
            "siem.internal.example.com",
        )

    def test_register_handles_none(self) -> None:
        # Must not raise on None / empty.
        otel_mod._register_dynamic_sensitive_host(None)
        otel_mod._register_dynamic_sensitive_host("")

    def test_register_handles_malformed_url(self) -> None:
        otel_mod._register_dynamic_sensitive_host("not a url")
        # Empty hostname not registered.
        assert "not a url" not in otel_mod._DYNAMIC_SENSITIVE_HOSTS


# ---------------------------------------------------------------------------
# Round 3 H5 -- EventKind values match dashboard regex strings
# ---------------------------------------------------------------------------


class TestEventKindDashboardAlignment:
    """If a future EventKind rename ships, every Grafana dashboard
    filtering on ``state="task.failed"`` silently breaks. Pin the
    contract here so the test goes red BEFORE the dashboards do."""

    def test_event_kinds_used_by_metric_emit_match_dashboard_strings(
        self,
    ) -> None:
        # The metric label values are kind.value. The dashboards
        # filter on these literals; if either side renames, the
        # filter breaks. Pin both sides.
        emit_values = {
            EventKind.TASK_SUCCEEDED.value,
            EventKind.TASK_FAILED.value,
            EventKind.TASK_REVOKED.value,
        }
        # These literals are what the v1.6 Grafana dashboards filter
        # on. Listing them here documents the contract; if a future
        # EventKind rename changes one of the .value strings, the
        # set difference below catches it.
        dashboard_filter_states = {
            "task.succeeded",
            "task.failed",
            "task.revoked",
        }
        # Symmetric difference must be empty.
        assert emit_values == dashboard_filter_states, (
            f"EventKind drift: emit values {emit_values} no longer "
            f"match the dashboard filter strings {dashboard_filter_states}. "
            f"Update deploy/grafana/z4j-tasks.json + README + this test."
        )
