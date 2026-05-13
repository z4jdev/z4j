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
"""

from __future__ import annotations

import secrets
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from z4j_brain.observability import otel as otel_mod
from z4j_brain.observability.otel import (
    DEFAULT_EXCLUDED_URL_PATTERNS,
    _excluded_urls_str,
    _reset_for_tests,
    build_resource_attributes,
    init_otel,
)
from z4j_brain.settings import Settings


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
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_OTEL_EXPORTER_OTLP_ENDPOINT",
            "https://api.honeycomb.io/v1/traces",
        )
        s = Settings()  # type: ignore[call-arg]
        assert isinstance(s.otel_exporter_otlp_endpoint, SecretStr)
        assert (
            s.otel_exporter_otlp_endpoint.get_secret_value()
            == "https://api.honeycomb.io/v1/traces"
        )
        assert "honeycomb" not in str(s.otel_exporter_otlp_endpoint)

    def test_headers_is_secretstr(
        self, monkeypatch: pytest.MonkeyPatch,
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
        self, monkeypatch: pytest.MonkeyPatch, rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_TRACES_SAMPLER_ARG", rate)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize("rate", ["0.0", "0.05", "0.5", "1.0"])
    def test_traces_sampler_in_range_accepted(
        self, monkeypatch: pytest.MonkeyPatch, rate: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_TRACES_SAMPLER_ARG", rate)
        s = Settings()  # type: ignore[call-arg]
        assert s.otel_traces_sampler_arg == float(rate)

    @pytest.mark.parametrize(
        "proto", ["http/protobuf", "http", "grpc"],
    )
    def test_protocol_accepted(
        self, monkeypatch: pytest.MonkeyPatch, proto: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_PROTOCOL", proto)
        s = Settings()  # type: ignore[call-arg]
        assert s.otel_protocol == proto

    def test_unknown_protocol_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_OTEL_PROTOCOL", "wireshark")
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]


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
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The function consults importlib.metadata; pin the contract
        by monkeypatching the helper directly."""
        monkeypatch.setattr(
            otel_mod, "_detect_service_version", lambda: "1.6.0",
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
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            otel_mod, "_detect_service_version", lambda: "",
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
        self, monkeypatch: pytest.MonkeyPatch,
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
        self, monkeypatch: pytest.MonkeyPatch,
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
            "HOOKS.SLACK.COM",                            # case
            "hooks.slack.com.",                           # trailing dot
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
            "slack.com.evil.com",                         # suffix smuggle
            "hooks.slack.com.evil.com",
        ],
    )
    def test_non_sensitive_hosts_skip(self, host: str) -> None:
        from z4j_brain.observability.otel import _is_sensitive_outbound_host
        assert not _is_sensitive_outbound_host(host), (
            f"{host} should NOT be sensitive"
        )
