"""Sentry integration tests.

Pin the load-bearing pieces of the v1.6 optional Sentry surface:

- ``init_sentry`` is a no-op when ``Z4J_SENTRY_DSN`` is unset, even
  on a process where ``sentry-sdk`` is importable. This guarantees
  the brain never opens an outbound connection to a Sentry instance
  the operator did not opt in to.
- ``init_sentry`` is idempotent. A double-call (e.g. a test rig that
  re-runs ``create_app`` in the same process) does not double-register
  integrations or send a duplicate first event.
- ``scrub_event`` strips every credential surface the brain knows
  about before the SDK ships the event. The tests run without
  ``sentry-sdk`` installed because the scrubber is a pure function.
- Settings validation rejects out-of-range sample rates so a typo
  in ``Z4J_SENTRY_TRACES_SAMPLE_RATE`` is caught at startup.
- Transaction events are scrubbed too, and an outbound webhook URL the
  dispatcher pinned to its resolved IP is still recognised by its
  path. The real-SDK variant skips when ``sentry-sdk`` is not installed.
"""

from __future__ import annotations

import secrets
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from z4j_brain.domain.notifications import channels
from z4j_brain.observability import sentry as sentry_mod
from z4j_brain.observability.sentry import (
    _REDACTED,
    _SENSITIVE_HEADERS,
    _SENSITIVE_QUERY_KEYS,
    _reset_for_tests,
    init_sentry,
    scrub_event,
)
from z4j_brain.settings import Settings

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimum env to construct a valid Settings instance.

    Anchors the unit tests to a deterministic configuration so a
    missing-DSN test is not accidentally also a missing-secret test.
    """
    monkeypatch.setenv("Z4J_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    # Make sure no host-env override leaks into the test.
    monkeypatch.delenv("Z4J_SENTRY_DSN", raising=False)
    monkeypatch.delenv("Z4J_SENTRY_ENVIRONMENT", raising=False)
    monkeypatch.delenv("Z4J_SENTRY_TRACES_SAMPLE_RATE", raising=False)
    monkeypatch.delenv("Z4J_SENTRY_PROFILES_SAMPLE_RATE", raising=False)
    monkeypatch.delenv("Z4J_SENTRY_SEND_DEFAULT_PII", raising=False)


class TestSentrySettings:
    def test_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        s = Settings()  # type: ignore[call-arg]
        assert s.sentry_dsn is None
        assert s.sentry_environment is None
        assert s.sentry_traces_sample_rate == 0.0
        assert s.sentry_profiles_sample_rate == 0.0
        assert s.sentry_send_default_pii is False

    def test_dsn_is_secretstr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DSNs can contain a project-bound public key + an instance
        URL; treating them as a SecretStr keeps them out of Pydantic's
        ValidationError reproduction and any startup log line that
        echoes the settings dict."""
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_SENTRY_DSN", "https://abc@sentry.example.com/42")
        s = Settings()  # type: ignore[call-arg]
        assert isinstance(s.sentry_dsn, SecretStr)
        assert s.sentry_dsn.get_secret_value() == "https://abc@sentry.example.com/42"
        # Default str() must NOT leak the value.
        assert "abc" not in str(s.sentry_dsn)
        assert "abc" not in repr(s.sentry_dsn)

    @pytest.mark.parametrize("rate", ["-0.1", "1.01", "2.0", "999"])
    def test_traces_sample_rate_out_of_range_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_SENTRY_TRACES_SAMPLE_RATE", rate)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize("rate", ["0.0", "0.05", "0.5", "1.0"])
    def test_traces_sample_rate_in_range_accepted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_SENTRY_TRACES_SAMPLE_RATE", rate)
        s = Settings()  # type: ignore[call-arg]
        assert s.sentry_traces_sample_rate == float(rate)

    @pytest.mark.parametrize("rate", ["-0.001", "1.5"])
    def test_profiles_sample_rate_out_of_range_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_SENTRY_PROFILES_SAMPLE_RATE", rate)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# init_sentry
# ---------------------------------------------------------------------------


class _FakeSentrySDK:
    """Stand-in for the real ``sentry_sdk`` module so the init path
    can be exercised offline. Records the kwargs ``init`` received."""

    def __init__(self) -> None:
        self.init_calls: list[dict[str, Any]] = []

    def init(self, **kwargs: Any) -> None:
        self.init_calls.append(kwargs)


@pytest.fixture(autouse=True)
def _reset_sentry_module() -> Any:
    """Each test starts with the global ``_initialised`` flag reset."""
    _reset_for_tests()
    yield
    _reset_for_tests()


class TestInitSentry:
    def test_no_dsn_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        s = Settings()  # type: ignore[call-arg]
        # Even if sentry_sdk IS installed in the test env, no DSN -> no init.
        fake = _FakeSentrySDK()
        monkeypatch.setitem(sys.modules, "sentry_sdk", fake)  # type: ignore[arg-type]
        assert init_sentry(s) is False
        assert fake.init_calls == []

    def test_empty_dsn_returns_false(self) -> None:
        s = SimpleNamespace(sentry_dsn=SecretStr(""))
        assert init_sentry(s) is False

    def test_whitespace_dsn_returns_false(self) -> None:
        s = SimpleNamespace(sentry_dsn=SecretStr("   \t  "))
        assert init_sentry(s) is False

    def test_with_dsn_calls_sdk_init_with_scrubber(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake = _FakeSentrySDK()
        monkeypatch.setitem(sys.modules, "sentry_sdk", fake)  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment="staging-eu",
            sentry_traces_sample_rate=0.1,
            sentry_profiles_sample_rate=0.05,
            sentry_send_default_pii=False,
            environment="production",
        )
        assert init_sentry(s) is True
        assert len(fake.init_calls) == 1
        kwargs = fake.init_calls[0]
        assert kwargs["dsn"] == "https://abc@sentry.example.com/42"
        # sentry_environment overrides settings.environment.
        assert kwargs["environment"] == "staging-eu"
        assert kwargs["traces_sample_rate"] == 0.1
        assert kwargs["profiles_sample_rate"] == 0.05
        assert kwargs["send_default_pii"] is False
        # The scrubber must be wired or the brain leaks credentials.
        assert kwargs["before_send"] is scrub_event

    def test_scrubber_also_registered_for_transactions(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The SDK never calls ``before_send`` for a transaction, so a
        traced request would ship its headers and span URLs unscrubbed
        unless the scrubber is registered for transactions too."""
        fake = _FakeSentrySDK()
        monkeypatch.setitem(sys.modules, "sentry_sdk", fake)  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment=None,
            sentry_traces_sample_rate=0.1,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=True,
            environment="production",
        )
        assert init_sentry(s) is True
        kwargs = fake.init_calls[0]
        assert kwargs.get("before_send_transaction") is scrub_event
        assert kwargs["before_send"] is scrub_event

    def test_environment_falls_back_to_settings_environment(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake = _FakeSentrySDK()
        monkeypatch.setitem(sys.modules, "sentry_sdk", fake)  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment=None,
            sentry_traces_sample_rate=0.0,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=False,
            environment="production",
        )
        assert init_sentry(s) is True
        assert fake.init_calls[0]["environment"] == "production"

    def test_init_is_idempotent(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake = _FakeSentrySDK()
        monkeypatch.setitem(sys.modules, "sentry_sdk", fake)  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment=None,
            sentry_traces_sample_rate=0.0,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=False,
            environment="dev",
        )
        assert init_sentry(s) is True
        # Second call must return True (already initialised) but must
        # NOT call sentry_sdk.init again. Re-registering integrations
        # is what doubles event volume in long-lived test rigs.
        assert init_sentry(s) is True
        assert len(fake.init_calls) == 1

    def test_sdk_init_failure_is_swallowed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A broken DSN / a misversioned SDK must NOT crash boot."""

        class _BrokenSDK:
            def init(self, **_: Any) -> None:
                raise RuntimeError("simulated SDK explosion")

        monkeypatch.setitem(sys.modules, "sentry_sdk", _BrokenSDK())  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment=None,
            sentry_traces_sample_rate=0.0,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=False,
            environment="dev",
        )
        assert init_sentry(s) is False

    def test_missing_sdk_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Operator set the DSN but did not `pip install z4j[sentry]`.
        Init logs a warning and returns False; the brain keeps running."""
        # Hide the real (or fake) sentry_sdk so the import fails.
        monkeypatch.setitem(sys.modules, "sentry_sdk", None)  # type: ignore[arg-type]
        s = SimpleNamespace(
            sentry_dsn=SecretStr("https://abc@sentry.example.com/42"),
            sentry_environment=None,
            sentry_traces_sample_rate=0.0,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=False,
            environment="dev",
        )
        assert init_sentry(s) is False


# ---------------------------------------------------------------------------
# scrub_event
# ---------------------------------------------------------------------------


class TestScrubHeaders:
    def test_dict_form_authorization_redacted(self) -> None:
        event = {
            "request": {
                "headers": {
                    "Authorization": "Bearer secrettoken",
                    "X-Request-Id": "keep-me",
                },
            },
        }
        out = scrub_event(event)
        assert out["request"]["headers"]["Authorization"] == _REDACTED
        assert out["request"]["headers"]["X-Request-Id"] == "keep-me"

    @pytest.mark.parametrize("header", sorted(_SENSITIVE_HEADERS))
    def test_every_sensitive_header_is_redacted(self, header: str) -> None:
        event = {
            "request": {
                "headers": {header: "secret"},
            },
        }
        out = scrub_event(event)
        assert out["request"]["headers"][header] == _REDACTED

    def test_case_insensitive_header_match(self) -> None:
        event = {
            "request": {
                "headers": {
                    "AUTHORIZATION": "Bearer x",
                    "Cookie": "session=y",
                    "x-Z4J-signature": "sha256=z",
                },
            },
        }
        out = scrub_event(event)
        h = out["request"]["headers"]
        assert h["AUTHORIZATION"] == _REDACTED
        assert h["Cookie"] == _REDACTED
        assert h["x-Z4J-signature"] == _REDACTED

    def test_list_form_pairs_redacted(self) -> None:
        event = {
            "request": {
                "headers": [
                    ["Authorization", "Bearer x"],
                    ["X-Request-Id", "rid-1"],
                ],
            },
        }
        out = scrub_event(event)
        assert out["request"]["headers"][0] == ["Authorization", _REDACTED]
        assert out["request"]["headers"][1] == ["X-Request-Id", "rid-1"]


class TestScrubQueryString:
    def test_token_value_redacted_key_preserved(self) -> None:
        event = {"request": {"query_string": "token=secret&page=2"}}
        out = scrub_event(event)
        qs = out["request"]["query_string"]
        assert "token=" in qs and "secret" not in qs
        assert "page=2" in qs

    @pytest.mark.parametrize("key", sorted(_SENSITIVE_QUERY_KEYS))
    def test_every_sensitive_query_key_value_redacted(self, key: str) -> None:
        """Distinct sentinel so a key whose name happens to equal the
        secret-value placeholder (e.g. ``secret``) does not mask a
        regression where the value escapes redaction."""
        sentinel = "PLAINTEXTLEAKVALUE"
        event = {"request": {"query_string": f"{key}={sentinel}&ok=keep"}}
        out = scrub_event(event)
        assert sentinel not in out["request"]["query_string"]
        assert "ok=keep" in out["request"]["query_string"]

    def test_case_insensitive_query_key_match(self) -> None:
        event = {"request": {"query_string": "Token=abc&API_KEY=def&Page=2"}}
        out = scrub_event(event)
        qs = out["request"]["query_string"]
        assert "abc" not in qs
        assert "def" not in qs
        assert "Page=2" in qs

    def test_list_form_query_string(self) -> None:
        event = {
            "request": {
                "query_string": [["token", "abc"], ["page", "2"]],
            },
        }
        out = scrub_event(event)
        assert out["request"]["query_string"][0] == ("token", _REDACTED)
        assert out["request"]["query_string"][1] == ("page", "2")

    def test_malformed_query_string_returned_unchanged(self) -> None:
        # parse_qsl handles all sorts of weird input; what we
        # actually care about is that the function never raises.
        event = {"request": {"query_string": ""}}
        out = scrub_event(event)
        assert out["request"]["query_string"] == ""


class TestScrubCookies:
    def test_cookies_block_redacted_wholesale(self) -> None:
        event = {
            "request": {
                "cookies": {"session": "abc", "any": "value"},
            },
        }
        out = scrub_event(event)
        assert out["request"]["cookies"] == _REDACTED

    def test_cookies_string_form_also_redacted(self) -> None:
        event = {
            "request": {
                "cookies": "session=abc; csrf=def",
            },
        }
        out = scrub_event(event)
        assert out["request"]["cookies"] == _REDACTED


class TestScrubUrl:
    def test_url_query_redacted_path_kept(self) -> None:
        event = {
            "request": {
                "url": "https://brain.example.com/api/v1/projects?token=abc&page=2",
            },
        }
        out = scrub_event(event)
        url = out["request"]["url"]
        assert "abc" not in url
        assert url.startswith("https://brain.example.com/api/v1/projects?")
        assert "page=2" in url

    def test_url_without_query_unchanged(self) -> None:
        event = {"request": {"url": "https://brain.example.com/api/v1/projects"}}
        out = scrub_event(event)
        assert out["request"]["url"] == "https://brain.example.com/api/v1/projects"


class TestScrubBody:
    def test_request_data_redacted_wholesale(self) -> None:
        """Webhook payloads can carry workflow tokens; we strip the
        whole body rather than try to walk arbitrary JSON shapes."""
        event = {
            "request": {
                "data": {"webhook_url": "https://hooks.slack.com/x/y/z"},
            },
        }
        out = scrub_event(event)
        assert out["request"]["data"] == _REDACTED

    def test_request_data_redacted_even_when_string(self) -> None:
        event = {"request": {"data": "raw=secretpayload"}}
        out = scrub_event(event)
        assert out["request"]["data"] == _REDACTED


class TestScrubBreadcrumbs:
    def test_outbound_http_url_in_breadcrumb_scrubbed(self) -> None:
        event = {
            "breadcrumbs": {
                "values": [
                    {
                        "category": "httplib",
                        "data": {
                            "url": "https://api.example.com/v1?token=abc&q=ok",
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        bc = out["breadcrumbs"]["values"][0]["data"]
        assert "abc" not in bc["url"]
        assert "q=ok" in bc["url"]

    def test_breadcrumb_data_keys_redacted(self) -> None:
        event = {
            "breadcrumbs": {
                "values": [
                    {
                        "data": {
                            "api_key": "leaky",
                            "request_id": "keep",
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        d = out["breadcrumbs"]["values"][0]["data"]
        assert d["api_key"] == _REDACTED
        assert d["request_id"] == "keep"


class TestScrubExtra:
    def test_password_key_value_redacted(self) -> None:
        event = {"extra": {"password": "p", "username": "u"}}
        out = scrub_event(event)
        assert out["extra"]["password"] == _REDACTED
        assert out["extra"]["username"] == "u"

    @pytest.mark.parametrize(
        "key",
        [
            "smtp_password",
            "bot_token",
            "api_key",
            "API-Key",
            "X-Auth",
            "mfa_secret",
            "recovery_code",
            "webhook_url",
            "integration_key",
            "private_key",
            "Z4J_SECRET",
        ],
    )
    def test_sensitive_key_value_patterns(self, key: str) -> None:
        event = {"extra": {key: "leak", "harmless": "keep"}}
        out = scrub_event(event)
        assert out["extra"][key] == _REDACTED
        assert out["extra"]["harmless"] == "keep"

    def test_nested_dict_walked(self) -> None:
        event = {
            "extra": {
                "config": {
                    "smtp_pass": "p",
                    "smtp_host": "h",
                },
            },
        }
        out = scrub_event(event)
        assert out["extra"]["config"]["smtp_pass"] == _REDACTED
        assert out["extra"]["config"]["smtp_host"] == "h"

    def test_list_of_dicts_walked(self) -> None:
        event = {
            "extra": {
                "channels": [
                    {"name": "ops", "bot_token": "1:2"},
                    {"name": "alerts", "bot_token": "3:4"},
                ],
            },
        }
        out = scrub_event(event)
        items = out["extra"]["channels"]
        assert items[0]["name"] == "ops"
        assert items[0]["bot_token"] == _REDACTED
        assert items[1]["bot_token"] == _REDACTED


class TestScrubEventNoMutationOnHarmlessEvent:
    def test_event_without_sensitive_surface_round_trips(self) -> None:
        event = {
            "exception": {"values": [{"type": "ValueError", "value": "oops"}]},
            "transaction": "POST /api/v1/projects/{slug}/commands",
            "tags": {"agent_id": "abc-123", "environment": "production"},
        }
        out = scrub_event(event)
        # No sensitive keys -> structurally unchanged.
        assert out["transaction"] == "POST /api/v1/projects/{slug}/commands"
        assert out["tags"]["agent_id"] == "abc-123"
        assert out["tags"]["environment"] == "production"

    def test_hint_argument_ignored(self) -> None:
        """The SDK contract passes a ``hint`` dict; we accept and
        ignore it. A test asserts the signature so a future refactor
        that drops the parameter is caught here, not by an SDK
        runtime TypeError."""
        event = {"request": {"headers": {"Authorization": "Bearer x"}}}
        out = scrub_event(event, hint={"exc_info": (None, None, None)})
        assert out["request"]["headers"]["Authorization"] == _REDACTED


class TestScrubRequestEnv:
    """Audit H2: CGI-style env vars carry credentials. Strip them."""

    def test_http_authorization_in_env_redacted(self) -> None:
        event = {
            "request": {
                "env": {
                    "HTTP_AUTHORIZATION": "Bearer leak",
                    "HTTP_USER_AGENT": "keep",
                    "REQUEST_METHOD": "POST",
                },
            },
        }
        out = scrub_event(event)
        assert out["request"]["env"]["HTTP_AUTHORIZATION"] == _REDACTED
        assert out["request"]["env"]["HTTP_USER_AGENT"] == "keep"
        assert out["request"]["env"]["REQUEST_METHOD"] == "POST"

    @pytest.mark.parametrize(
        "key",
        [
            "HTTP_COOKIE",
            "HTTP_X_API_KEY",
            "HTTP_X_AUTH_TOKEN",
            "HTTP_X_Z4J_SIGNATURE",
            "HTTP_X_Z4J_API_KEY",
            "HTTP_X_CSRF_TOKEN",
        ],
    )
    def test_every_sensitive_http_env_key_redacted(self, key: str) -> None:
        event = {"request": {"env": {key: "leak"}}}
        out = scrub_event(event)
        assert out["request"]["env"][key] == _REDACTED

    def test_custom_env_with_credential_pattern_redacted(self) -> None:
        """A middleware that drops DATABASE_PASSWORD or Z4J_SECRET
        into env still has its value scrubbed via the value-key
        pattern matcher."""
        event = {
            "request": {
                "env": {
                    "DATABASE_PASSWORD": "p",
                    "Z4J_SECRET": "s",
                    "HTTP_HOST": "keep",
                },
            },
        }
        out = scrub_event(event)
        assert out["request"]["env"]["DATABASE_PASSWORD"] == _REDACTED
        assert out["request"]["env"]["Z4J_SECRET"] == _REDACTED
        assert out["request"]["env"]["HTTP_HOST"] == "keep"


class TestScrubUserBlock:
    """Audit H3: even when send_default_pii is True, credential-
    adjacent fields like email/username/ip should not ship."""

    def test_email_redacted(self) -> None:
        event = {"user": {"email": "u@example.com", "id": "uuid"}}
        out = scrub_event(event)
        assert out["user"]["email"] == _REDACTED
        # ID preserved for issue grouping.
        assert out["user"]["id"] == "uuid"

    def test_username_redacted(self) -> None:
        event = {"user": {"username": "alice", "id": "uuid"}}
        out = scrub_event(event)
        assert out["user"]["username"] == _REDACTED

    def test_ip_address_redacted(self) -> None:
        event = {"user": {"ip_address": "192.0.2.10", "id": "uuid"}}
        out = scrub_event(event)
        assert out["user"]["ip_address"] == _REDACTED

    def test_user_without_pii_unchanged(self) -> None:
        event = {"user": {"id": "uuid"}}
        out = scrub_event(event)
        assert out["user"] == {"id": "uuid"}


class TestScrubLogentry:
    """Audit H4: logger.exception messages can carry tokens."""

    def test_message_url_query_scrubbed(self) -> None:
        event = {
            "logentry": {
                "message": "called https://api.example/v1?token=abc&q=x",
            },
        }
        out = scrub_event(event)
        msg = out["logentry"]["message"]
        assert "abc" not in msg
        assert "q=x" in msg

    def test_formatted_url_query_scrubbed(self) -> None:
        event = {
            "logentry": {
                "formatted": "request to https://api/v1?api_key=leak",
            },
        }
        out = scrub_event(event)
        assert "leak" not in out["logentry"]["formatted"]

    def test_params_dict_key_redacted(self) -> None:
        event = {
            "logentry": {
                "params": {"api_key": "leak", "request_id": "keep"},
            },
        }
        out = scrub_event(event)
        assert out["logentry"]["params"]["api_key"] == _REDACTED
        assert out["logentry"]["params"]["request_id"] == "keep"

    def test_params_list_redacted_wholesale(self) -> None:
        """Positional params are %s slots; we cannot identify which
        is a credential so strip all."""
        event = {"logentry": {"params": ["token=abc", "keep"]}}
        out = scrub_event(event)
        assert out["logentry"]["params"] == [_REDACTED, _REDACTED]

    def test_top_level_message_scrubbed(self) -> None:
        event = {"message": "POST https://x/y?password=p succeeded"}
        out = scrub_event(event)
        assert "password=p" not in out["message"]


class TestScrubSpanData:
    """Audit M3: span data attributes carry http.url for FastAPI
    server spans; scrub the URL query."""

    def test_spans_http_url_scrubbed(self) -> None:
        event = {
            "spans": [
                {
                    "data": {
                        "http.url": "https://b/api?token=abc&page=2",
                        "http.method": "GET",
                    },
                },
            ],
        }
        out = scrub_event(event)
        u = out["spans"][0]["data"]["http.url"]
        assert "abc" not in u
        assert "page=2" in u

    def test_contexts_trace_data_http_url_scrubbed(self) -> None:
        event = {
            "contexts": {
                "trace": {
                    "data": {
                        "http.url": "https://b/api?api_key=leak",
                    },
                },
            },
        }
        out = scrub_event(event)
        u = out["contexts"]["trace"]["data"]["http.url"]
        assert "leak" not in u


def test_module_exposes_idempotency_reset_hook() -> None:
    """The reset hook is used by the test rig. Pin it so a refactor
    that renames or drops it breaks the test suite loudly here."""
    assert callable(sentry_mod._reset_for_tests)


# ---------------------------------------------------------------------------
# Transactions and IP-pinned outbound URLs
# ---------------------------------------------------------------------------

#: The IP a notification dispatcher pins its request to. The SDK's
#: outbound breadcrumbs and spans name it instead of the webhook host.
_PINNED_IP = "93.184.216.34"

#: (pinned URL path, the credential in it), one per dispatcher whose
#: URL path carries the credential.
_PINNED_WEBHOOK_PATHS = [
    pytest.param("/services/T0ABC/B0DEF/SECRETSLACKPATH", "SECRETSLACKPATH", id="slack"),
    pytest.param(
        "/api/webhooks/123456/SECRETDISCORDTOKEN/slack",
        "SECRETDISCORDTOKEN",
        id="discord",
    ),
    pytest.param(
        "/webhookb2/a1b2@c3d4/IncomingWebhook/SECRETTEAMSID/e5f6",
        "SECRETTEAMSID",
        id="teams",
    ),
    pytest.param(
        "/bot123456:SECRETTELEGRAMTOKEN/sendMessage",
        "SECRETTELEGRAMTOKEN",
        id="telegram",
    ),
]

_REDACTED_PINNED_URL = f"https://{_PINNED_IP}/[REDACTED by z4j]"


class TestScrubTransactionEvent:
    """Transactions reach :func:`scrub_event` through
    ``before_send_transaction``. An outbound HTTP span is described as
    ``<METHOD> <url>`` and carries the URL under ``data.url``."""

    @pytest.mark.parametrize(("path", "secret"), _PINNED_WEBHOOK_PATHS)
    def test_pinned_webhook_span_redacted(self, path: str, secret: str) -> None:
        url = f"https://{_PINNED_IP}{path}"
        plain = f"https://{_PINNED_IP}/v1/receive"
        event = {
            "type": "transaction",
            "transaction": "/api/v1/projects/{slug}/notifications/channels/{channel_id}/test",
            "contexts": {"trace": {"op": "http.server", "data": {"thread.name": "MainThread"}}},
            "spans": [
                {
                    "op": "http.client",
                    "description": f"POST {url}",
                    "data": {"url": url, "http.method": "POST", "http.query": ""},
                },
                {
                    "op": "http.client",
                    "description": f"POST {plain}",
                    "data": {"url": plain, "http.method": "POST"},
                },
            ],
        }
        out = scrub_event(event)
        assert secret not in repr(out)
        webhook_span, plain_span = out["spans"]
        assert webhook_span["description"] == f"POST {_REDACTED_PINNED_URL}"
        assert webhook_span["data"]["url"] == _REDACTED_PINNED_URL
        # Control: an ordinary outbound path stays readable.
        assert plain_span["description"] == f"POST {plain}"
        assert plain_span["data"]["url"] == plain

    def test_span_query_string_keys_scrubbed(self) -> None:
        """Teams Workflows URLs carry the credential in ``sig``; the SDK
        records the query apart from the URL, under ``http.query``."""
        event = {
            "type": "transaction",
            "spans": [
                {
                    "op": "http.client",
                    "description": f"POST https://{_PINNED_IP}/v1/receive",
                    "data": {
                        "url": f"https://{_PINNED_IP}/v1/receive",
                        "http.query": "api-version=2016-06-01&sv=1.0&sig=SECRETSIG",
                    },
                },
            ],
        }
        out = scrub_event(event)
        query = out["spans"][0]["data"]["http.query"]
        assert "SECRETSIG" not in query
        assert "api-version=2016-06-01" in query


class TestScrubPinnedBreadcrumbs:
    @pytest.mark.parametrize(("path", "secret"), _PINNED_WEBHOOK_PATHS)
    def test_pinned_webhook_breadcrumb_url_redacted(self, path: str, secret: str) -> None:
        event = {
            "breadcrumbs": {
                "values": [
                    {
                        "type": "http",
                        "category": "httplib",
                        "data": {"url": f"https://{_PINNED_IP}{path}", "http.method": "POST"},
                    },
                    {
                        "type": "http",
                        "category": "httplib",
                        "data": {"url": f"https://{_PINNED_IP}/v1/receive", "http.method": "POST"},
                    },
                ],
            },
        }
        out = scrub_event(event)
        webhook, plain = (bc["data"] for bc in out["breadcrumbs"]["values"])
        assert secret not in repr(out)
        assert webhook["url"] == _REDACTED_PINNED_URL
        # Control: an ordinary outbound path stays readable.
        assert plain["url"] == f"https://{_PINNED_IP}/v1/receive"

    def test_breadcrumb_query_string_keys_scrubbed(self) -> None:
        event = {
            "breadcrumbs": {
                "values": [
                    {
                        "type": "http",
                        "data": {
                            "url": f"https://{_PINNED_IP}/v1/receive",
                            "http.query": "api-version=2016-06-01&sig=SECRETSIG",
                        },
                    },
                ],
            },
        }
        out = scrub_event(event)
        query = out["breadcrumbs"]["values"][0]["data"]["http.query"]
        assert "SECRETSIG" not in query
        assert "api-version=2016-06-01" in query

    def test_pinned_webhook_url_in_exception_value_redacted(self) -> None:
        url = f"https://{_PINNED_IP}/api/webhooks/123456/SECRETDISCORDTOKEN/slack"
        event = {
            "exception": {
                "values": [
                    {
                        "type": "HTTPStatusError",
                        "value": f"Client error '404 Not Found' for url '{url}'",
                    },
                ],
            },
        }
        out = scrub_event(event)
        value = out["exception"]["values"][0]["value"]
        assert "SECRETDISCORDTOKEN" not in value
        assert value == f"Client error '404 Not Found' for url '{_REDACTED_PINNED_URL}'"

    def test_webhook_url_inside_a_logged_traceback_redacted(self) -> None:
        """An unhandled request error reaches Sentry as a log event whose
        message is the rendered traceback: the URL sits inside a longer
        string, so the whole-string pass alone left its secret path."""
        url = "https://hooks.slack.com/services/T0ABC/B0DEF/SECRETSLACKPATH"
        traceback_text = (
            "Traceback (most recent call last):\n"
            '  File "channels.py", line 160, in _post\n'
            f"httpx.HTTPStatusError: Client error '404 Not Found' for url '{url}'\n"
        )
        event = {
            "logentry": {"message": traceback_text, "formatted": traceback_text},
            "message": traceback_text,
            "breadcrumbs": {"values": [{"message": f"POST {url} failed"}]},
        }
        out = scrub_event(event)
        assert "SECRETSLACKPATH" not in out["logentry"]["message"]
        assert "SECRETSLACKPATH" not in out["logentry"]["formatted"]
        assert "SECRETSLACKPATH" not in out["message"]
        assert "SECRETSLACKPATH" not in out["breadcrumbs"]["values"][0]["message"]
        # The rest of the traceback stays readable.
        assert 'File "channels.py", line 160' in out["logentry"]["formatted"]


class TestSentryRealSdk:
    """Drive a real ``sentry_sdk`` client configured by :func:`init_sentry`
    and keep what its transport would send. The Slack dispatcher runs
    inside a transaction, the way a channel test-fire does, and an error
    event follows in the same scope to carry the breadcrumbs."""

    async def test_transaction_and_breadcrumbs_scrubbed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sentry_sdk = pytest.importorskip("sentry_sdk")
        from sentry_sdk.integrations.httpx import HttpxIntegration
        from sentry_sdk.transport import Transport

        class _CapturingTransport(Transport):
            def __init__(self) -> None:
                super().__init__(None)
                self.envelopes: list[Any] = []

            def capture_envelope(self, envelope: Any) -> None:
                self.envelopes.append(envelope)

        transport = _CapturingTransport()
        real_init = sentry_sdk.init

        def _init(**kwargs: Any) -> Any:
            # init_sentry's options as given; capture instead of sending,
            # and patch only httpx rather than every installed library.
            return real_init(
                **kwargs,
                transport=transport,
                integrations=[HttpxIntegration()],
                default_integrations=False,
                auto_enabling_integrations=False,
            )

        def _attach_request(event: dict[str, Any], hint: Any) -> dict[str, Any]:
            event["request"] = {
                "method": "POST",
                "url": "https://brain.example.com/api/v1/notifications/test",
                "headers": {
                    "X-Z4J-Signature": "sha256=SECRETSIGNATURE",
                    "X-Forwarded-For": "198.51.100.7",
                },
                "cookies": {"z4j_session": "SECRETCOOKIE"},
            }
            return event

        class _OkBody(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                yield b"ok"

        sent: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return httpx.Response(200, stream=_OkBody())

        monkeypatch.setattr(sentry_sdk, "init", _init)
        monkeypatch.setattr(channels, "_resolve_cached", AsyncMock(return_value=[_PINNED_IP]))
        settings = SimpleNamespace(
            sentry_dsn=SecretStr("https://public@sentry.example.invalid/1"),
            sentry_environment=None,
            sentry_traces_sample_rate=1.0,
            sentry_profiles_sample_rate=0.0,
            sentry_send_default_pii=True,
            environment="production",
        )
        try:
            assert init_sentry(settings) is True
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                monkeypatch.setattr(channels, "_shared_client", client)
                with sentry_sdk.isolation_scope() as scope:
                    scope.add_event_processor(_attach_request)
                    with sentry_sdk.start_transaction(op="http.server", name="/api/v1/test"):
                        result = await channels.deliver_slack(
                            {
                                "webhook_url": (
                                    "https://hooks.slack.com/services/T0ABC/B0DEF/SECRETSLACKPATH"
                                ),
                            },
                            {"trigger": "test"},
                        )
                    sentry_sdk.capture_message("dispatch check")
            sentry_sdk.flush()
        finally:
            sentry_sdk.get_client().close()
            sentry_sdk.get_global_scope().set_client(None)

        assert result.success
        assert sent[0].url.host == _PINNED_IP
        transactions = [
            e.get_transaction_event() for e in transport.envelopes if e.get_transaction_event()
        ]
        errors = [e.get_event() for e in transport.envelopes if e.get_event()]
        assert len(transactions) == 1
        assert len(errors) == 1
        transaction, error = transactions[0], errors[0]

        assert "SECRET" not in repr(transaction)
        assert transaction["request"]["headers"]["X-Z4J-Signature"] == _REDACTED
        assert transaction["request"]["cookies"] == _REDACTED
        (http_span,) = [s for s in transaction["spans"] if s.get("op") == "http.client"]
        assert http_span["description"] == f"POST {_REDACTED_PINNED_URL}"

        assert "SECRET" not in repr(error)
        (crumb,) = [b for b in error["breadcrumbs"]["values"] if b.get("type") == "http"]
        assert crumb["data"]["url"] == _REDACTED_PINNED_URL
