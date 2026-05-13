"""Microsoft Teams notification dispatcher tests.

Pins the v1.6 Teams channel behaviour:

- ``validate_teams_config`` accepts the three official Microsoft
  webhook host families (outlook.office.com, *.webhook.office.com,
  *.logic.azure.com) and rejects everything else, so a tenant
  admin cannot register an arbitrary HTTPS host under the
  "teams" channel type and use it as an exfil sink that looks
  like Teams in the audit log.
- ``deliver_teams`` short-circuits with an SSRF error for private
  IPs / loopback / metadata URLs, refuses non-Microsoft hosts at
  dispatch time even if they slipped past the validator, builds
  the Adaptive Card body the documented Teams renderer expects,
  and treats the full 2xx range as success (classic O365 returns
  200, Workflow / Power Automate may return 200 or 202).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from z4j_brain.domain.notifications import channels as ch_mod
from z4j_brain.domain.notifications.channels import (
    CHANNEL_DISPATCHERS,
    DeliveryResult,
    _teams_host_allowed,
    deliver_teams,
    validate_teams_config,
)


class TestTeamsHostAllowlist:
    """The host check is the load-bearing piece of the channel's
    threat model. Cover every family explicitly so a refactor that
    breaks the suffix match cannot silently widen the egress."""

    @pytest.mark.parametrize(
        "host",
        [
            "outlook.office.com",                                     # classic
            "contoso.webhook.office.com",                             # workflow
            "tenant-name.webhook.office.com",
            "prod-12.westus.logic.azure.com",                         # power automate
            "prod-04.eastus2.logic.azure.com",
            "OUTLOOK.OFFICE.COM",                                     # case fold
        ],
    )
    def test_official_hosts_accepted(self, host: str) -> None:
        assert _teams_host_allowed(host), f"{host} should be allowed"

    @pytest.mark.parametrize(
        "host",
        [
            "attacker.example.com",
            "webhook.office.com.attacker.com",                        # suffix smuggle
            "outlook.office.com.evil.com",
            "hooks.slack.com",                                        # other vendor
            "discord.com",
            "logic.azure.com.evil.com",
            "outlook-office.com",                                     # not the same host
            "",
        ],
    )
    def test_other_hosts_rejected(self, host: str) -> None:
        assert not _teams_host_allowed(host), f"{host} should be rejected"


class TestValidateTeamsConfig:
    """Config-time validation surface."""

    def test_missing_url_rejected(self) -> None:
        assert validate_teams_config({}) is not None
        assert validate_teams_config({"webhook_url": ""}) is not None
        assert validate_teams_config({"webhook_url": "   "}) is not None

    def test_non_string_url_rejected(self) -> None:
        assert validate_teams_config({"webhook_url": 123}) is not None  # type: ignore[dict-item]
        assert validate_teams_config({"webhook_url": None}) is not None  # type: ignore[dict-item]

    @pytest.mark.parametrize(
        "url",
        [
            "https://outlook.office.com/webhook/abc/IncomingWebhook/x/y",
            "https://contoso.webhook.office.com/webhookb2/abc@def/IncomingWebhook/x/y",
            "https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
        ],
    )
    def test_official_webhook_urls_accepted(self, url: str) -> None:
        assert validate_teams_config({"webhook_url": url}) is None

    @pytest.mark.parametrize(
        "url",
        [
            "https://attacker.example.com/in",
            "https://hooks.slack.com/services/aaa/bbb/ccc",
            "https://webhook.office.com.evil.com/in",
            "not-a-url",                                              # no host
        ],
    )
    def test_non_microsoft_urls_rejected(self, url: str) -> None:
        err = validate_teams_config({"webhook_url": url})
        assert err is not None


class _RecordingPost:
    """Records the last ``_post`` call so the test can inspect what
    the dispatcher actually sent (URL, body, headers, pin_ip)
    without standing up a real HTTP transport."""

    def __init__(self, status_code: int = 200, body: str = "1") -> None:
        self.status_code = status_code
        self.body = body
        self.last_url: str | None = None
        self.last_kwargs: dict[str, Any] = {}
        self.calls = 0

    async def __call__(self, url: str, **kwargs: Any) -> httpx.Response:
        self.last_url = url
        self.last_kwargs = kwargs
        self.calls += 1
        req = httpx.Request("POST", url)
        return httpx.Response(
            status_code=self.status_code,
            content=self.body.encode("utf-8"),
            request=req,
        )


async def _noop_resolve_and_pin(url: str) -> tuple[str | None, str | None]:
    """Bypass DNS + SSRF post-check so the test stays offline.

    The dispatcher SSRF check (``validate_webhook_url``) is exercised
    in its own dedicated test below where we keep the real validator
    and feed it a deliberately blocked URL.
    """
    return None, "203.0.113.10"


async def _noop_validate_webhook_url(url: str) -> str | None:
    return None


class TestDeliverTeams:
    """End-to-end dispatcher behaviour with the HTTP transport mocked."""

    @pytest.mark.asyncio
    async def test_empty_url_short_circuits(self) -> None:
        result = await deliver_teams({"webhook_url": ""}, {"trigger": "test"})
        assert result.success is False
        assert "empty" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_ssrf_blocks_loopback(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A literal loopback URL must be rejected by the real
        ``validate_webhook_url`` before any TCP attempt."""
        recorder = _RecordingPost()
        monkeypatch.setattr(ch_mod, "_post", recorder)

        result = await deliver_teams(
            {"webhook_url": "http://127.0.0.1:9000/in"},
            {"trigger": "test"},
        )
        assert result.success is False
        assert "block" in (result.error or "").lower()
        assert recorder.calls == 0, "must not POST when SSRF check fails"

    @pytest.mark.asyncio
    async def test_non_microsoft_host_blocked_at_dispatch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Belt-and-braces: even if the validator was bypassed (direct
        DB write), the dispatcher must refuse to fan out to a
        non-Microsoft host."""
        recorder = _RecordingPost()
        monkeypatch.setattr(ch_mod, "_post", recorder)
        # Make SSRF check pass for the public-looking host.
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)

        result = await deliver_teams(
            {"webhook_url": "https://attacker.example.com/in"},
            {"trigger": "test"},
        )
        assert result.success is False
        assert "teams webhook_url" in (result.error or "").lower()
        assert recorder.calls == 0

    @pytest.mark.asyncio
    async def test_happy_path_posts_adaptive_card(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost(status_code=200, body="1")
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)

        url = "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/x/y"
        result = await deliver_teams(
            {"webhook_url": url},
            {
                "trigger": "task_failure",
                "task_name": "send_invoices",
                "priority": "critical",
                "state": "FAILURE",
                "task_id": "f1e2d3c4b5a698765432",
                "exception": "RuntimeError: payment gateway timeout",
            },
        )

        assert result.success is True
        assert result.status_code == 200
        assert recorder.calls == 1
        # We round-trip the URL unmodified -- the IP pin happens inside
        # ``_post`` via ``pin_ip``, not by rewriting the URL here.
        assert recorder.last_url == url
        assert recorder.last_kwargs.get("pin_ip") == "203.0.113.10"

        body = recorder.last_kwargs.get("json")
        assert isinstance(body, dict)
        assert body["type"] == "message"
        attachments = body["attachments"]
        assert len(attachments) == 1
        card = attachments[0]["content"]
        assert card["type"] == "AdaptiveCard"
        # Title encodes the trigger.
        title = card["body"][0]["items"][0]["text"]
        assert "task_failure" in title
        # Critical priority maps to ``attention`` Adaptive Card style.
        assert card["body"][0]["style"] == "attention"
        # Facts include task name + state + priority + id.
        facts = card["body"][1]["facts"]
        titles = {f["title"] for f in facts}
        assert {"Task", "State", "Priority", "ID"}.issubset(titles)
        # Exception block included as monospaced TextBlock.
        last_block = card["body"][-1]
        assert last_block["type"] == "TextBlock"
        assert last_block.get("fontType") == "Monospace"
        assert "RuntimeError" in last_block["text"]

    @pytest.mark.asyncio
    async def test_priority_to_style_mapping(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost()
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)
        url = "https://outlook.office.com/webhook/abc/IncomingWebhook/x/y"
        cases = {
            "critical": "attention",
            "high": "warning",
            "normal": "default",
            "low": "default",
            "made-up": "default",
        }
        for priority, expected_style in cases.items():
            await deliver_teams(
                {"webhook_url": url},
                {"trigger": "t", "priority": priority},
            )
            body = recorder.last_kwargs["json"]
            assert (
                body["attachments"][0]["content"]["body"][0]["style"]
                == expected_style
            ), f"priority={priority!r} should map to {expected_style!r}"

    @pytest.mark.asyncio
    async def test_202_accepted_as_success(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Workflow / Power Automate endpoints often return 202; the
        dispatcher must not flag those as failures."""
        recorder = _RecordingPost(status_code=202, body="{}")
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)

        url = "https://prod-04.eastus2.logic.azure.com/workflows/x/triggers/manual/paths/invoke"
        result = await deliver_teams(
            {"webhook_url": url}, {"trigger": "t"},
        )
        assert result.success is True
        assert result.status_code == 202

    @pytest.mark.asyncio
    async def test_5xx_marked_failure(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost(status_code=500, body="boom")
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)

        url = "https://outlook.office.com/webhook/abc/IncomingWebhook/x/y"
        result = await deliver_teams(
            {"webhook_url": url}, {"trigger": "t"},
        )
        assert result.success is False
        assert result.status_code == 500
        assert "boom" in (result.response_body or "")

    @pytest.mark.asyncio
    async def test_dispatch_time_resolve_failure_surfaces(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost()
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )

        async def _failing_resolve(url: str) -> tuple[str | None, str | None]:
            return "no usable IP resolved", None

        monkeypatch.setattr(ch_mod, "resolve_and_pin", _failing_resolve)

        url = "https://outlook.office.com/webhook/abc/IncomingWebhook/x/y"
        result = await deliver_teams(
            {"webhook_url": url}, {"trigger": "t"},
        )
        assert result.success is False
        assert "unsafe teams URL" in (result.error or "")
        assert recorder.calls == 0


class TestSecurityHardening:
    """v1.6 post-audit fixes pinned here so a future refactor cannot
    silently re-introduce the issues."""

    @pytest.mark.asyncio
    async def test_exception_with_triple_backticks_does_not_escape_fence(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A crafted exception message containing ``` would close the
        Markdown code fence and let an attacker inject Adaptive Card
        content. Verify the dispatcher neutralises backticks before
        embedding."""
        recorder = _RecordingPost()
        monkeypatch.setattr(ch_mod, "_post", recorder)
        monkeypatch.setattr(
            ch_mod, "validate_webhook_url", _noop_validate_webhook_url,
        )
        monkeypatch.setattr(ch_mod, "resolve_and_pin", _noop_resolve_and_pin)
        url = "https://contoso.webhook.office.com/webhookb2/abc/x/y"
        injected = (
            "RuntimeError: done\n```\n"
            "[phish](https://attacker.example/x)\n"
            "```"
        )
        await deliver_teams(
            {"webhook_url": url},
            {"trigger": "task_failure", "exception": injected},
        )
        body = recorder.last_kwargs["json"]
        card = body["attachments"][0]["content"]
        text_block = card["body"][-1]
        # The neutralised text must NOT contain the original ``` so
        # the embedded fence stays intact.
        text = text_block["text"]
        # Outer fence remains.
        assert text.startswith("```\n")
        assert text.endswith("\n```")
        # The inner injected ``` is replaced with the inert marker.
        inner = text[4:-4]
        assert "```" not in inner
        # The original injection text minus the backticks is still
        # rendered, so the operator can still read the exception.
        assert "RuntimeError" in inner
        assert "phish" in inner

    @pytest.mark.parametrize(
        "host",
        [
            "outlook.office.com.",                      # trailing dot
            "contoso.webhook.office.com.",              # trailing dot + tenant
            "prod-04.eastus2.logic.azure.com.",         # trailing dot + power-automate
            "OUTLOOK.office.com.",                       # case + trailing dot
        ],
    )
    def test_trailing_dot_hosts_accepted_after_strip(self, host: str) -> None:
        """Audit M1: a trailing-dot FQDN is the legal form. The
        host-allowlist now strips one trailing dot before comparison
        so this resolves identically to the dot-less form."""
        assert _teams_host_allowed(host), f"{host} should be allowed"


def test_teams_registered_in_dispatcher_table() -> None:
    """If someone refactors the channel registry and drops Teams, the
    notification service will silently fall back to an "unknown
    channel" branch. Pin the wire-up here."""
    assert "teams" in CHANNEL_DISPATCHERS
    assert CHANNEL_DISPATCHERS["teams"] is deliver_teams


def test_delivery_result_type_is_returned_for_empty_url() -> None:
    """Defensive: empty-URL branch is sync-async but still returns a
    proper :class:`DeliveryResult`."""
    import asyncio
    result = asyncio.run(deliver_teams({}, {}))
    assert isinstance(result, DeliveryResult)
    assert result.success is False
