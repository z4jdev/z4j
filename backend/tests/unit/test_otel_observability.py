"""OpenTelemetry integration tests.

The OTel SDK is an optional dependency. These tests deliberately do
NOT require ``opentelemetry-*`` to be installed; they exercise the
parts of ``observability/otel.py`` that matter regardless:

- ``init_otel`` is a no-op without an OTLP endpoint, even when the
  SDK is present in ``sys.modules``. This is the load-bearing
  opt-in guarantee.
- ``init_otel`` returns False (and logs a single WARNING) when the
  endpoint IS set but the SDK is missing. The brain must continue
  to boot.
- ``build_resource_attributes`` is a pure function whose output is
  the exact attribute set the SDK would install. Pinning it here
  catches drift before it reaches a collector.
- Settings validation rejects out-of-range sampler args and
  unsupported protocol values at startup.
- The init path, run against a fake SDK, hands the exporter a parsed
  header mapping, logs no endpoint path, and registers httpx hooks
  that redact a dispatcher request pinned to its resolved IP. The
  real-SDK variants skip when the ``otel`` extra is not installed.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import secrets
import sys
import types
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from z4j_brain.domain.notifications import channels
from z4j_brain.observability import otel as otel_mod
from z4j_brain.observability.otel import (
    DEFAULT_EXCLUDED_URL_PATTERNS,
    _excluded_urls_str,
    _reset_for_tests,
    build_resource_attributes,
    init_otel,
)
from z4j_brain.settings import ConfigError, Settings


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("Z4J_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    for var in (
        "Z4J_OTEL_EXPORTER_OTLP_ENDPOINT",
        "Z4J_OTEL_PROTOCOL",
        "Z4J_OTEL_EXPORTER_OTLP_HEADERS",
        "Z4J_OTEL_SERVICE_NAME",
        "Z4J_OTEL_SERVICE_NAMESPACE",
        "Z4J_OTEL_ENVIRONMENT",
        "Z4J_OTEL_TRACES_SAMPLER_ARG",
        "Z4J_OTEL_INCLUDE_HEALTH",
        "Z4J_OTEL_EXCLUDED_URL_PATTERNS",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _reset_otel_module() -> Any:
    _reset_for_tests()
    yield
    _reset_for_tests()


class TestOtelSettings:
    def test_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        s = Settings()  # type: ignore[call-arg]
        assert s.otel_exporter_otlp_endpoint is None
        assert s.otel_protocol == "http/protobuf"
        assert s.otel_service_name == "z4j-brain"
        assert s.otel_service_namespace == "z4j"
        assert s.otel_environment is None
        assert s.otel_traces_sampler_arg == 0.0
        assert s.otel_include_health is False
        assert s.otel_excluded_url_patterns == ""

    def test_endpoint_is_secretstr(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_OTEL_EXPORTER_OTLP_ENDPOINT",
            "https://api.honeycomb.io/v1/traces",
        )
        s = Settings()  # type: ignore[call-arg]
        assert isinstance(s.otel_exporter_otlp_endpoint, SecretStr)
        assert (
            s.otel_exporter_otlp_endpoint.get_secret_value() == "https://api.honeycomb.io/v1/traces"
        )
        assert "honeycomb" not in str(s.otel_exporter_otlp_endpoint)

    def test_headers_is_secretstr(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_OTEL_EXPORTER_OTLP_HEADERS",
            "x-honeycomb-team=secrettoken",
        )
        s = Settings()  # type: ignore[call-arg]
        assert isinstance(s.otel_exporter_otlp_headers, SecretStr)
        assert "secrettoken" not in str(s.otel_exporter_otlp_headers)

    @pytest.mark.parametrize("rate", ["-0.1", "1.01", "2.0", "999"])
    def test_traces_sampler_out_of_range_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_TRACES_SAMPLER_ARG", rate)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize("rate", ["0.0", "0.05", "0.5", "1.0"])
    def test_traces_sampler_in_range_accepted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_TRACES_SAMPLER_ARG", rate)
        s = Settings()  # type: ignore[call-arg]
        assert s.otel_traces_sampler_arg == float(rate)

    @pytest.mark.parametrize(
        "proto",
        ["http/protobuf", "http", "grpc"],
    )
    def test_protocol_accepted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        proto: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_PROTOCOL", proto)
        s = Settings()  # type: ignore[call-arg]
        assert s.otel_protocol == proto

    def test_unknown_protocol_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_PROTOCOL", "wireshark")
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("SECRETVALUEONLY", id="no-equals"),
            pytest.param("=SECRETVALUE", id="empty-key"),
            pytest.param("x honeycomb team=SECRETVALUE", id="space-in-key"),
            pytest.param("x-honeycomb-team=SECRET%0AVALUE", id="encoded-newline"),
            pytest.param("x-ok=fine,SECRETVALUEONLY", id="second-entry"),
        ],
    )
    def test_malformed_headers_refused_without_echo(
        self,
        monkeypatch: pytest.MonkeyPatch,
        raw: str,
    ) -> None:
        """The OTLP exporters take a header mapping; a value that does
        not parse in the ``OTEL_EXPORTER_OTLP_HEADERS`` format is refused
        at startup, and the message never repeats the value."""
        _base_env(monkeypatch)
        # Control: the documented format, URL-encoded values included.
        monkeypatch.setenv(
            "Z4J_OTEL_EXPORTER_OTLP_HEADERS",
            "x-honeycomb-team=abc%2C123, authorization=Basic%20eHl6,",
        )
        Settings()  # type: ignore[call-arg]
        monkeypatch.setenv("Z4J_OTEL_EXPORTER_OTLP_HEADERS", raw)
        with pytest.raises(ConfigError) as excinfo:
            Settings()  # type: ignore[call-arg]
        message = str(excinfo.value)
        assert "Z4J_OTEL_EXPORTER_OTLP_HEADERS" in message
        assert "SECRET" not in message


class TestBuildResourceAttributes:
    def test_defaults_pinned(self) -> None:
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace=None,
            otel_environment=None,
            environment="production",
        )
        attrs = build_resource_attributes(s)
        assert attrs["service.name"] == "z4j-brain"
        assert attrs["service.namespace"] == "z4j"
        assert attrs["deployment.environment"] == "production"

    def test_otel_environment_overrides_settings_environment(self) -> None:
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace=None,
            otel_environment="staging-eu",
            environment="production",
        )
        attrs = build_resource_attributes(s)
        assert attrs["deployment.environment"] == "staging-eu"

    def test_service_name_override(self) -> None:
        s = SimpleNamespace(
            otel_service_name="z4j-brain-eu",
            otel_service_namespace=None,
            otel_environment=None,
            environment="prod",
        )
        attrs = build_resource_attributes(s)
        assert attrs["service.name"] == "z4j-brain-eu"

    def test_service_namespace_override(self) -> None:
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace="acme",
            otel_environment=None,
            environment="prod",
        )
        attrs = build_resource_attributes(s)
        assert attrs["service.namespace"] == "acme"

    def test_environment_falls_back_to_unknown(self) -> None:
        """A settings object with no environment at all (defensive --
        normal Settings always sets it) gets 'unknown' rather than
        crashing."""
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace=None,
            otel_environment=None,
            environment=None,
        )
        attrs = build_resource_attributes(s)
        assert attrs["deployment.environment"] == "unknown"

    def test_service_version_attached_when_metadata_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The function consults importlib.metadata; pin the contract
        by monkeypatching the helper directly."""
        monkeypatch.setattr(
            otel_mod,
            "_detect_service_version",
            lambda: "1.6.0",
        )
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace=None,
            otel_environment=None,
            environment="prod",
        )
        attrs = build_resource_attributes(s)
        assert attrs["service.version"] == "1.6.0"

    def test_service_version_omitted_when_metadata_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            otel_mod,
            "_detect_service_version",
            lambda: "",
        )
        s = SimpleNamespace(
            otel_service_name=None,
            otel_service_namespace=None,
            otel_environment=None,
            environment="prod",
        )
        attrs = build_resource_attributes(s)
        assert "service.version" not in attrs


class TestExcludedUrlsString:
    def test_health_default_excluded(self) -> None:
        s = SimpleNamespace(
            otel_include_health=False,
            otel_excluded_url_patterns="",
        )
        result = _excluded_urls_str(s)
        for pattern in DEFAULT_EXCLUDED_URL_PATTERNS:
            assert pattern in result

    def test_include_health_drops_defaults(self) -> None:
        s = SimpleNamespace(
            otel_include_health=True,
            otel_excluded_url_patterns="",
        )
        result = _excluded_urls_str(s)
        assert result == ""

    def test_extra_patterns_appended(self) -> None:
        s = SimpleNamespace(
            otel_include_health=False,
            otel_excluded_url_patterns="/internal,/probe",
        )
        result = _excluded_urls_str(s)
        assert "/health" in result
        assert "/internal" in result
        assert "/probe" in result

    def test_extra_patterns_trimmed(self) -> None:
        s = SimpleNamespace(
            otel_include_health=True,
            otel_excluded_url_patterns="  /a  , ,  /b  ",
        )
        result = _excluded_urls_str(s)
        assert "/a" in result.split(",")
        assert "/b" in result.split(",")
        assert "" not in result.split(",")


class TestInitOtel:
    def test_no_endpoint_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        s = Settings()  # type: ignore[call-arg]
        assert init_otel(s) is False

    def test_empty_endpoint_returns_false(self) -> None:
        s = SimpleNamespace(otel_exporter_otlp_endpoint=SecretStr(""))
        assert init_otel(s) is False

    def test_whitespace_endpoint_returns_false(self) -> None:
        s = SimpleNamespace(otel_exporter_otlp_endpoint=SecretStr("  \t "))
        assert init_otel(s) is False

    def test_missing_sdk_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Operator set the endpoint but did not `pip install z4j[otel]`.
        Init logs a warning and returns False; the brain keeps running.
        Ensured by setting `sys.modules['opentelemetry'] = None` so
        the import in init_otel fails."""
        # Block every opentelemetry submodule so the first import line
        # in init_otel raises ImportError.
        for name in list(sys.modules):
            if name == "opentelemetry" or name.startswith("opentelemetry."):
                monkeypatch.delitem(sys.modules, name, raising=False)
        monkeypatch.setitem(sys.modules, "opentelemetry", None)  # type: ignore[arg-type]
        s = SimpleNamespace(
            otel_exporter_otlp_endpoint=SecretStr(
                "https://api.collector.example/v1/traces",
            ),
            otel_protocol="http/protobuf",
            otel_exporter_otlp_headers=None,
            otel_service_name="z4j-brain",
            otel_service_namespace="z4j",
            otel_environment="dev",
            otel_traces_sampler_arg=0.05,
            otel_include_health=False,
            otel_excluded_url_patterns="",
            environment="dev",
        )
        assert init_otel(s) is False

    def test_init_is_idempotent_on_disabled_path(self) -> None:
        """Two calls with no endpoint should both return False and
        the second call must not re-run the lazy import. Use the
        flag directly to verify."""
        s = SimpleNamespace(
            otel_exporter_otlp_endpoint=None,
        )
        assert init_otel(s) is False
        assert init_otel(s) is False  # cached path
        assert otel_mod._initialised is True
        assert otel_mod._init_succeeded is False


def test_module_exposes_idempotency_reset_hook() -> None:
    assert callable(otel_mod._reset_for_tests)


def test_default_excluded_patterns_pinned() -> None:
    """The auto-instrumentation accepts these substrings; pin the
    contract so a refactor that drops one fires a test failure
    instead of silently flooding the collector."""
    assert "/health" in DEFAULT_EXCLUDED_URL_PATTERNS
    assert "/metrics" in DEFAULT_EXCLUDED_URL_PATTERNS
    assert "/api/v1/health" in DEFAULT_EXCLUDED_URL_PATTERNS
    # Audit H7: auth routes must be excluded by default.
    assert "/api/v1/auth" in DEFAULT_EXCLUDED_URL_PATTERNS


class TestSensitiveOutboundHostFilter:
    """Audit C7: outbound calls to webhook hosts have their URL path
    redacted before export so credentials in the path do not ship
    to the OTLP collector."""

    @pytest.mark.parametrize(
        "host",
        [
            "hooks.slack.com",
            "contoso.webhook.office.com",
            "prod-04.eastus2.logic.azure.com",
            "outlook.office.com",
            "events.pagerduty.com",
            "discord.com",
            "discordapp.com",
            "HOOKS.SLACK.COM",  # case
            "hooks.slack.com.",  # trailing dot
        ],
    )
    def test_sensitive_hosts_match(self, host: str) -> None:
        from z4j_brain.observability.otel import _is_sensitive_outbound_host

        assert _is_sensitive_outbound_host(host), f"{host} should be sensitive"

    @pytest.mark.parametrize(
        "host",
        [
            "api.example.com",
            "siem.internal.example.com",
            "raw.githubusercontent.com",
            "slack.com.evil.com",  # suffix smuggle
            "hooks.slack.com.evil.com",
        ],
    )
    def test_non_sensitive_hosts_skip(self, host: str) -> None:
        from z4j_brain.observability.otel import _is_sensitive_outbound_host

        assert not _is_sensitive_outbound_host(host), f"{host} should NOT be sensitive"


# ---------------------------------------------------------------------------
# init_otel against a fake SDK
# ---------------------------------------------------------------------------

#: The public IP the mocked resolver returns. Every dispatcher connects
#: to it, so the request URL names it instead of the webhook host.
_PINNED_IP = "93.184.216.34"

_PAYLOAD: dict[str, Any] = {
    "trigger": "task.failed",
    "task_name": "billing.charge",
    "priority": "high",
    "state": "failure",
}

#: One dispatcher per channel whose URL path carries the credential,
#: with the hostname the redacted span should still show.
_DISPATCHES = [
    pytest.param(
        channels.deliver_slack,
        {"webhook_url": "https://hooks.slack.com/services/T0ABC/B0DEF/SECRETSLACKPATH"},
        "hooks.slack.com",
        id="slack",
    ),
    pytest.param(
        channels.deliver_discord,
        {"webhook_url": "https://discord.com/api/webhooks/123456/SECRETDISCORDTOKEN"},
        "discord.com",
        id="discord",
    ),
    pytest.param(
        channels.deliver_teams,
        {
            "webhook_url": (
                "https://contoso.webhook.office.com/webhookb2/a1b2@c3d4"
                "/IncomingWebhook/SECRETTEAMSID/e5f6"
            ),
        },
        "contoso.webhook.office.com",
        id="teams",
    ),
    pytest.param(
        channels.deliver_telegram,
        {"bot_token": "123456:SECRETTELEGRAMTOKEN", "chat_id": "-100123"},
        "api.telegram.org",
        id="telegram",
    ),
]


class _FakeOtel:
    """Stand-in for the ``opentelemetry`` packages :func:`init_otel`
    imports, so the init path runs offline. Records what the OTLP
    exporter and the httpx instrumentation receive."""

    def __init__(self) -> None:
        self.exporter_kwargs: list[dict[str, Any]] = []
        self.instrument_kwargs: list[dict[str, Any]] = []


@pytest.fixture
def fake_otel(monkeypatch: pytest.MonkeyPatch) -> _FakeOtel:
    fake = _FakeOtel()

    class _Exporter:
        def __init__(self, **kwargs: Any) -> None:
            fake.exporter_kwargs.append(kwargs)

    class _Instrumentor:
        def instrument(self, **kwargs: Any) -> None:
            fake.instrument_kwargs.append(kwargs)

    class _TracerProvider:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def add_span_processor(self, processor: Any) -> None:
            pass

    class _Resource:
        @staticmethod
        def create(attributes: dict[str, str]) -> dict[str, str]:
            return attributes

    trace_module = types.ModuleType("opentelemetry.trace")
    trace_module.set_tracer_provider = lambda provider: None  # type: ignore[attr-defined]
    contents: dict[str, dict[str, Any]] = {
        "opentelemetry": {"trace": trace_module},
        "opentelemetry.sdk": {},
        "opentelemetry.sdk.resources": {"Resource": _Resource},
        "opentelemetry.sdk.trace": {"TracerProvider": _TracerProvider},
        "opentelemetry.sdk.trace.export": {"BatchSpanProcessor": lambda exporter: exporter},
        "opentelemetry.sdk.trace.sampling": {
            "ALWAYS_OFF": object(),
            "ParentBased": lambda **kwargs: kwargs,
            "TraceIdRatioBased": lambda ratio: ratio,
        },
        "opentelemetry.exporter": {},
        "opentelemetry.exporter.otlp": {},
        "opentelemetry.exporter.otlp.proto": {},
        "opentelemetry.exporter.otlp.proto.http": {},
        "opentelemetry.exporter.otlp.proto.http.trace_exporter": {"OTLPSpanExporter": _Exporter},
        "opentelemetry.instrumentation": {},
        "opentelemetry.instrumentation.httpx": {"HTTPXClientInstrumentor": _Instrumentor},
    }
    for name in list(sys.modules):
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace_module)
    for name, attributes in contents.items():
        module = types.ModuleType(name)
        for key, value in attributes.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, name, module)
    return fake


def _otel_settings(
    *,
    endpoint: str = "https://collector.example.com:4318/v1/traces",
    headers: str | None = None,
    audit_webhook_url: SecretStr | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        otel_exporter_otlp_endpoint=SecretStr(endpoint),
        otel_protocol="http/protobuf",
        otel_exporter_otlp_headers=SecretStr(headers) if headers is not None else None,
        otel_service_name="z4j-brain",
        otel_service_namespace="z4j",
        otel_environment="dev",
        otel_traces_sampler_arg=0.05,
        otel_include_health=False,
        otel_excluded_url_patterns="",
        environment="dev",
        audit_webhook_url=audit_webhook_url,
    )


class _RecordingSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}

    def is_recording(self) -> bool:
        return True

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value


class _OkBody(httpx.AsyncByteStream):
    """An unread response body; ``channels._post`` streams it itself."""

    async def __aiter__(self) -> Any:
        yield b"ok"


def _request_info(request: httpx.Request) -> SimpleNamespace:
    """The ``RequestInfo`` the httpx instrumentation hands its hooks."""
    return SimpleNamespace(
        method=request.method.encode(),
        url=httpx.URL(str(request.url)),
        headers=request.headers,
        stream=None,
        extensions=request.extensions,
    )


async def _capture_requests(
    monkeypatch: pytest.MonkeyPatch,
    send: Any,
) -> list[httpx.Request]:
    """Run ``send`` with every hostname resolving to ``_PINNED_IP`` and a
    transport that records the requests the dispatcher built."""
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, stream=_OkBody())

    monkeypatch.setattr(channels, "_resolve_cached", AsyncMock(return_value=[_PINNED_IP]))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(channels, "_shared_client", client)
        await send()
    return sent


class TestInitOtelWiring:
    def test_exporter_receives_parsed_header_mapping(self, fake_otel: _FakeOtel) -> None:
        """The OTLP HTTP exporter takes ``Mapping[str, str]`` and calls
        ``.items()`` on it; the raw setting string made it raise, which
        left OpenTelemetry off."""
        settings = _otel_settings(
            headers="x-honeycomb-team=abc%2C123, Authorization = Basic%20eHl6==,",
        )
        assert init_otel(settings) is True
        assert fake_otel.exporter_kwargs[0]["headers"] == {
            "x-honeycomb-team": "abc,123",
            "authorization": "Basic eHl6==",
        }

    def test_unparseable_headers_keep_otel_off_without_echo(
        self,
        fake_otel: _FakeOtel,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Settings refuses this at startup; a settings object built any
        other way gets a warning that names the variable, not the value."""
        caplog.set_level(logging.WARNING, logger="z4j.brain.observability.otel")
        assert init_otel(_otel_settings(headers="SECRETVALUEONLY")) is False
        assert fake_otel.exporter_kwargs == []
        assert "Z4J_OTEL_EXPORTER_OTLP_HEADERS" in caplog.text
        assert "SECRET" not in caplog.text

    def test_startup_log_names_only_scheme_host_and_port(
        self,
        fake_otel: _FakeOtel,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        endpoint = (
            "https://ingest:SECRETUSERINFO@collector.example.com:4318"
            "/v1/traces/SECRETPATHKEY?api_key=SECRETQUERYKEY"
        )
        caplog.set_level(logging.INFO, logger="z4j.brain.observability.otel")
        assert init_otel(_otel_settings(endpoint=endpoint)) is True
        # The exporter still gets the endpoint exactly as configured.
        assert fake_otel.exporter_kwargs[0]["endpoint"] == endpoint
        assert "endpoint=https://collector.example.com:4318," in caplog.text
        assert "SECRET" not in caplog.text

    def test_async_client_hooks_registered(self, fake_otel: _FakeOtel) -> None:
        """The instrumentation runs only ``async_request_hook`` /
        ``async_response_hook`` for ``httpx.AsyncClient``, which every
        notification dispatcher and the audit forwarder use."""
        assert init_otel(_otel_settings()) is True
        hooks = fake_otel.instrument_kwargs[0]
        assert inspect.iscoroutinefunction(hooks.get("async_request_hook"))
        assert inspect.iscoroutinefunction(hooks.get("async_response_hook"))


class TestOtelHttpxHookOnPinnedRequests:
    """The dispatchers connect to the IP they resolved, so the URL the
    hooks see names an IP. The redaction decision has to come from the
    hostname kept in the ``Host`` header and the SNI extension, or from
    the path shape."""

    @pytest.mark.parametrize(("dispatch", "config", "host"), _DISPATCHES)
    async def test_pinned_dispatch_redacted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_otel: _FakeOtel,
        dispatch: Any,
        config: dict[str, Any],
        host: str,
    ) -> None:
        assert init_otel(_otel_settings()) is True
        hooks = fake_otel.instrument_kwargs[0]
        (request,) = await _capture_requests(monkeypatch, lambda: dispatch(config, _PAYLOAD))
        # The precondition a host-only check misses.
        assert request.url.host == _PINNED_IP
        info = _request_info(request)

        span = _RecordingSpan()
        hooks["request_hook"](span, info)
        assert span.attributes.get("http.url") == f"https://{host}/[redacted by z4j]"
        assert span.attributes.get("url.full") == f"https://{host}/[redacted by z4j]"
        assert "SECRET" not in repr(span.attributes)

        async_span = _RecordingSpan()
        await hooks["async_request_hook"](async_span, info)
        await hooks["async_response_hook"](async_span, info, None)
        assert async_span.attributes == span.attributes

        # Control: an ordinary pinned request keeps its captured URL.
        (plain,) = await _capture_requests(
            monkeypatch,
            lambda: channels._post("https://receiver.example.com/v1/notify", pin_ip=_PINNED_IP),
        )
        plain_span = _RecordingSpan()
        hooks["request_hook"](plain_span, _request_info(plain))
        assert plain_span.attributes == {}

    async def test_pinned_audit_forward_redacted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_otel: _FakeOtel,
    ) -> None:
        """The audit webhook host is registered at init; the forwarder
        posts through ``channels._post`` pinned to the resolved IP."""
        url = "https://siem.example.com/hec/SECRETHECPATH"
        assert init_otel(_otel_settings(audit_webhook_url=SecretStr(url))) is True
        hooks = fake_otel.instrument_kwargs[0]
        (request,) = await _capture_requests(
            monkeypatch,
            lambda: channels._post(url, pin_ip=_PINNED_IP),
        )
        span = _RecordingSpan()
        hooks["request_hook"](span, _request_info(request))
        assert span.attributes.get("http.url") == "https://siem.example.com/[redacted by z4j]"
        assert "SECRET" not in repr(span.attributes)


# ---------------------------------------------------------------------------
# init_otel against the real SDK (skips without the ``otel`` extra)
# ---------------------------------------------------------------------------


async def _answer_no_content(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    head = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    if length:
        await reader.readexactly(length)
    writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    await writer.drain()
    writer.close()


class TestOtelRealSdk:
    """Run :func:`init_otel` with the installed SDK. Only the global side
    effects are replaced: the tracer provider is not installed globally,
    the batch processor never exports, and the test applies the httpx
    instrumentation itself with an in-memory provider."""

    @staticmethod
    def _isolate_globals(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        httpx_instrumentation = pytest.importorskip("opentelemetry.instrumentation.httpx")
        sdk_export = pytest.importorskip("opentelemetry.sdk.trace.export")
        pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        from opentelemetry import trace

        captured: dict[str, Any] = {"exporters": [], "hooks": {}}

        def _processor(exporter: Any) -> Any:
            captured["exporters"].append(exporter)
            return sdk_export.SimpleSpanProcessor(exporter)

        monkeypatch.setattr(trace, "set_tracer_provider", lambda provider: None)
        monkeypatch.setattr(sdk_export, "BatchSpanProcessor", _processor)
        captured["real_instrument"] = httpx_instrumentation.HTTPXClientInstrumentor.instrument
        monkeypatch.setattr(
            httpx_instrumentation.HTTPXClientInstrumentor,
            "instrument",
            lambda self, **kwargs: captured["hooks"].update(kwargs),
        )
        return captured

    def test_http_exporter_accepts_configured_headers(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured = self._isolate_globals(monkeypatch)
        settings = _otel_settings(
            endpoint="http://127.0.0.1:9/v1/traces",
            headers="x-honeycomb-team=abc123",
        )
        assert init_otel(settings) is True
        assert len(captured["exporters"]) == 1

    async def test_pinned_webhook_spans_exported_redacted(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured = self._isolate_globals(monkeypatch)
        sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")
        sdk_export = pytest.importorskip("opentelemetry.sdk.trace.export")
        in_memory = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        assert init_otel(_otel_settings(endpoint="http://127.0.0.1:9/v1/traces")) is True
        exporter = in_memory.InMemorySpanExporter()
        provider = sdk_trace.TracerProvider()
        provider.add_span_processor(sdk_export.SimpleSpanProcessor(exporter))
        instrumentor = HTTPXClientInstrumentor()
        captured["real_instrument"](instrumentor, tracer_provider=provider, **captured["hooks"])
        server = await asyncio.start_server(_answer_no_content, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        urls = [
            f"http://hooks.slack.com:{port}/services/T0ABC/B0DEF/SECRETSLACKPATH",
            f"http://api.telegram.org:{port}/bot123456:SECRETTELEGRAMTOKEN/sendMessage",
            f"http://receiver.example.com:{port}/v1/notify",
        ]
        try:
            async with server, httpx.AsyncClient(trust_env=False) as client:
                monkeypatch.setattr(channels, "_shared_client", client)
                for url in urls:
                    resp = await channels._post(url, pin_ip="127.0.0.1", json={"text": "x"})
                    assert resp.status_code == 204
        finally:
            instrumentor.uninstrument()

        spans = exporter.get_finished_spans()
        assert len(spans) == 3
        slack, telegram, plain = (dict(span.attributes or {}) for span in spans)
        assert slack["http.url"] == "http://hooks.slack.com/[redacted by z4j]"
        assert telegram["http.url"] == "http://api.telegram.org/[redacted by z4j]"
        assert "SECRET" not in repr(slack) + repr(telegram)
        # Control: the instrumentation's own URL attribute is left alone.
        plain_url = plain.get("url.full", plain.get("http.url"))
        assert plain_url == f"http://127.0.0.1:{port}/v1/notify"
