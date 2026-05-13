"""Optional OpenTelemetry integration.

OpenTelemetry is a fully optional dependency. The brain ships fine
without any ``opentelemetry-*`` packages installed. Setting
:attr:`Settings.otel_exporter_otlp_endpoint` is what enables export;
the SDK is loaded lazily and an import failure degrades to a single
WARNING + a normal boot.

Design choices the operator should know about:

- **Off by default.** No endpoint, no init. Even with the SDK
  installed, an unset ``Z4J_OTEL_EXPORTER_OTLP_ENDPOINT`` is a
  complete no-op.
- **HTTP/protobuf default.** OTLP HTTP is the simpler operational
  target (Plain HTTPS, no gRPC keepalive tuning, no protobuf
  toolchain on the receiver side). Operators on a gRPC collector
  can flip ``Z4J_OTEL_PROTOCOL=grpc``.
- **Auto-instrumentation only in this release.** FastAPI requests,
  SQLAlchemy queries, and outbound httpx calls are auto-traced
  via the standard ``opentelemetry-instrumentation-*`` packages.
  Manual span boundaries for agent dispatch, command issuance,
  and task ingestion are deferred to a later minor (the wire-
  protocol needs a trace-context header for cross-process spans
  to be useful).
- **Health + metrics excluded.** ``/health*`` and ``/metrics``
  receive enough traffic that they would swamp any sampling
  budget. Tracing for those endpoints is disabled by default;
  flip ``Z4J_OTEL_INCLUDE_HEALTH=true`` to re-enable.
- **Sampling default 0.0.** With no traces sampled, the brain
  pays only the negligible cost of `set_span_in_context` calls.
  Errors still propagate via Sentry. To start collecting
  performance traces, set ``Z4J_OTEL_TRACES_SAMPLER_ARG=0.05``
  (5%) and raise from there.
- **Idempotent.** A second :func:`init_otel` call is a no-op.
  Re-instrumenting the same FastAPI app would double-register
  middleware and double every trace.

Threat model. The OTLP exporter ships span attributes (URLs,
DB statement fragments, headers if the auto-instrumentation
captures them) to a collector outside the brain. Pre-1.6 deployments
expect no outbound traffic from the brain to anywhere except the
configured notification destinations; enabling OTel changes that
contract. Operators should review what their auto-instrumentations
attach as span attributes BEFORE pointing at a multi-tenant
collector. The SQLAlchemy instrumentation in particular needs
``enable_commenter=False`` (default) for sensitive queries.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("z4j.brain.observability.otel")


# Idempotency flag. The auto-instrumentation packages all guard
# against double-instrument, but the operator-facing init still
# returns the cached result rather than redoing the work.
_initialised: bool = False
_init_succeeded: bool = False

#: URLs we never want to trace by default. The brain's health
#: endpoints and Prometheus scrape are high-volume + low-signal.
#: An operator can opt back in via ``Z4J_OTEL_INCLUDE_HEALTH=true``.
#:
#: ``/api/v1/auth`` is also defaulted off because the POST bodies on
#: login / MFA / API-key mint paths contain credentials (passwords,
#: TOTP codes, the response carrying a newly-minted bearer). The
#: FastAPI instrumentation does not capture request bodies by
#: default, but URL paths can carry identifiers; excluding the
#: subtree is cheap defence-in-depth. (Audit H7.)
DEFAULT_EXCLUDED_URL_PATTERNS: tuple[str, ...] = (
    "/health",
    "/api/v1/health",
    "/api/v1/health/",
    "/metrics",
    "/api/v1/auth",
)


#: Outbound URL hostnames we know carry credentials in the path. The
#: httpx auto-instrumentation captures ``http.url`` as a span
#: attribute; for these hosts we replace the path with a single
#: ``/[redacted]`` segment so the span still shows the host (useful
#: for traffic-shape analysis) but the token does not ship to the
#: OTLP collector. (Audit C7.)
SENSITIVE_OUTBOUND_HOST_SUFFIXES: tuple[str, ...] = (
    ".webhook.office.com",
    ".logic.azure.com",
    ".slack.com",
    ".discordapp.com",
    ".discord.com",
    ".pagerduty.com",
)
SENSITIVE_OUTBOUND_HOSTS_EXACT: frozenset[str] = frozenset({
    "outlook.office.com",
    "hooks.slack.com",
    "events.pagerduty.com",
    "discordapp.com",
    "discord.com",
})

#: Per-process set of operator-configured hostnames whose outbound
#: spans must be redacted. Populated by :func:`init_otel` from
#: ``settings.audit_webhook_url`` and any future SecretStr-typed
#: outbound URLs. (Round 3 H4: audit-webhook URL was not in the
#: static list so a path-token receiver leaked the token to OTLP.)
_DYNAMIC_SENSITIVE_HOSTS: set[str] = set()


def _register_dynamic_sensitive_host(url: str | None) -> None:
    """Extract the hostname from ``url`` and register it as
    sensitive for the duration of the process."""
    if not url:
        return
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:  # noqa: BLE001
        return
    if host:
        _DYNAMIC_SENSITIVE_HOSTS.add(host)


def _reset_dynamic_sensitive_hosts_for_tests() -> None:
    _DYNAMIC_SENSITIVE_HOSTS.clear()


def _is_sensitive_outbound_host(host: str) -> bool:
    """True iff outbound calls to ``host`` should have their span
    URL path stripped before export. Conservative list -- the cost
    of a false positive is a slightly less useful trace; the cost
    of a false negative is a credential in the OTLP collector.
    Includes both the static credential-bearing host list AND any
    dynamic operator-configured sensitive URLs (audit-webhook etc.)."""
    lower = host.lower().rstrip(".")
    if lower in SENSITIVE_OUTBOUND_HOSTS_EXACT:
        return True
    if lower in _DYNAMIC_SENSITIVE_HOSTS:
        return True
    return any(
        lower.endswith(suffix) for suffix in SENSITIVE_OUTBOUND_HOST_SUFFIXES
    )


def _detect_service_version() -> str:
    """Best-effort z4j package version for the OTel ``service.version``
    resource attribute. Mirrors the Sentry release detection. Returns
    an empty string when metadata is unavailable so callers can decide
    whether to attach the attribute at all."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover
        return ""
    for candidate in ("z4j", "z4j-brain"):
        try:
            return version(candidate)
        except PackageNotFoundError:
            continue
    return ""


def build_resource_attributes(settings: Any) -> dict[str, str]:
    """Pure function: build the resource attribute dict from settings.

    Exposed for tests so the attribute schema is pinned without
    needing the SDK installed. The returned dict is the exact set
    of OTel ``Resource`` attributes :func:`init_otel` will install.
    """
    service_name = (
        getattr(settings, "otel_service_name", None)
        or "z4j-brain"
    )
    namespace = (
        getattr(settings, "otel_service_namespace", None)
        or "z4j"
    )
    environment = (
        getattr(settings, "otel_environment", None)
        or getattr(settings, "environment", None)
        or "unknown"
    )
    attrs: dict[str, str] = {
        "service.name": service_name,
        "service.namespace": namespace,
        "deployment.environment": environment,
    }
    version_str = _detect_service_version()
    if version_str:
        attrs["service.version"] = version_str
    return attrs


def _excluded_urls_str(settings: Any) -> str:
    """The OTel FastAPI instrumentation accepts a comma-separated
    string of URL substrings to skip. Build it from the settings'
    include-health flag plus any operator-supplied additions.
    """
    if getattr(settings, "otel_include_health", False):
        base: tuple[str, ...] = ()
    else:
        base = DEFAULT_EXCLUDED_URL_PATTERNS
    extra_raw = getattr(settings, "otel_excluded_url_patterns", None) or ""
    extra = tuple(
        s.strip() for s in extra_raw.split(",") if s.strip()
    )
    combined = base + extra
    return ",".join(combined)


def _resolve_endpoint(settings: Any) -> str | None:
    """Return the OTLP endpoint string, or None if not configured.

    The Pydantic SecretStr unwrapping pattern mirrors the Sentry
    module. An empty / whitespace-only endpoint is treated as unset.
    """
    raw = getattr(settings, "otel_exporter_otlp_endpoint", None)
    if raw is None:
        return None
    value = (
        raw.get_secret_value()
        if hasattr(raw, "get_secret_value")
        else str(raw)
    )
    if not value or not value.strip():
        return None
    return value.strip()


def init_otel(
    settings: Any,
    *,
    app: Any | None = None,
    engine: Any | None = None,
) -> bool:
    """Initialise the OpenTelemetry SDK and register auto-instrumentation.

    Returns ``True`` when tracing is now active, ``False`` otherwise.
    Failure modes that return False without raising:

    - No endpoint configured (the off-by-default path).
    - The ``opentelemetry`` packages are not installed.
    - The SDK or any auto-instrumentation registration raises.

    ``app`` and ``engine`` are optional; the caller passes whatever it
    has built so far so the FastAPI / SQLAlchemy instrumentations can
    attach. ``httpx`` instrumentation patches the library globally and
    does not need a reference.
    """
    global _initialised, _init_succeeded

    if _initialised:
        return _init_succeeded

    endpoint = _resolve_endpoint(settings)
    if endpoint is None:
        _initialised = True
        _init_succeeded = False
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import (
            ALWAYS_OFF,
            ParentBased,
            TraceIdRatioBased,
        )
    except ImportError:
        logger.warning(
            "z4j observability.otel: Z4J_OTEL_EXPORTER_OTLP_ENDPOINT is "
            "set but the 'opentelemetry' packages are not installed. "
            "Run `pip install z4j[otel]` to enable. The brain will "
            "continue without OpenTelemetry.",
        )
        _initialised = True
        _init_succeeded = False
        return False

    protocol = (
        getattr(settings, "otel_protocol", None) or "http/protobuf"
    ).lower()
    try:
        if protocol in ("http/protobuf", "http"):
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        elif protocol == "grpc":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        else:
            logger.warning(
                "z4j observability.otel: unknown Z4J_OTEL_PROTOCOL=%r; "
                "expected one of http/protobuf or grpc. Skipping init.",
                protocol,
            )
            _initialised = True
            _init_succeeded = False
            return False
    except ImportError:
        logger.warning(
            "z4j observability.otel: OTLP exporter for protocol=%r is "
            "not installed. `pip install z4j[otel]` installs HTTP; "
            "add `opentelemetry-exporter-otlp-proto-grpc` for gRPC.",
            protocol,
        )
        _initialised = True
        _init_succeeded = False
        return False

    # v1.6 Round 3 H4: register operator-configured sensitive URLs
    # so their hosts are added to the OTel scrubber's host-allowlist
    # at init time. Today this is just the audit-webhook URL; future
    # SecretStr-typed outbound URLs should be registered here too.
    audit_url_secret = getattr(settings, "audit_webhook_url", None)
    if audit_url_secret is not None:
        audit_url_val = (
            audit_url_secret.get_secret_value()
            if hasattr(audit_url_secret, "get_secret_value")
            else str(audit_url_secret)
        )
        _register_dynamic_sensitive_host(audit_url_val.strip() or None)

    sampler_arg = float(getattr(settings, "otel_traces_sampler_arg", 0.0))
    # ParentBased honours an upstream trace context. Since the brain
    # has no trusted upstream today (cross-process trace propagation
    # is deferred to a later minor), an attacker who can spoof a
    # ``traceparent`` header could force-sample every request and
    # flood the collector. Override the remote-parent decisions with
    # ``ALWAYS_OFF`` so only the brain's own ratio sampler decides
    # whether to record. (Audit H6.)
    sampler = ParentBased(
        root=TraceIdRatioBased(sampler_arg),
        remote_parent_sampled=ALWAYS_OFF,
        remote_parent_not_sampled=ALWAYS_OFF,
    )
    resource = Resource.create(build_resource_attributes(settings))

    headers_raw = getattr(settings, "otel_exporter_otlp_headers", None)
    headers_value: str | None = None
    if headers_raw is not None:
        headers_value = (
            headers_raw.get_secret_value()
            if hasattr(headers_raw, "get_secret_value")
            else str(headers_raw)
        ) or None

    try:
        exporter_kwargs: dict[str, Any] = {"endpoint": endpoint}
        if headers_value:
            exporter_kwargs["headers"] = headers_value
        provider = TracerProvider(resource=resource, sampler=sampler)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(**exporter_kwargs)))
        trace.set_tracer_provider(provider)
    except Exception:  # noqa: BLE001
        logger.warning(
            "z4j observability.otel: TracerProvider setup raised; "
            "brain continues without OpenTelemetry.",
            exc_info=True,
        )
        _initialised = True
        _init_succeeded = False
        return False

    excluded = _excluded_urls_str(settings)

    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import (
                FastAPIInstrumentor,
            )
            kwargs: dict[str, Any] = {}
            if excluded:
                kwargs["excluded_urls"] = excluded
            FastAPIInstrumentor.instrument_app(app, **kwargs)
        except ImportError:
            logger.info(
                "z4j observability.otel: FastAPI instrumentation not "
                "installed; HTTP server spans disabled.",
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "z4j observability.otel: FastAPI instrumentation failed; "
                "HTTP server spans disabled.",
                exc_info=True,
            )

    if engine is not None:
        try:
            from opentelemetry.instrumentation.sqlalchemy import (
                SQLAlchemyInstrumentor,
            )
            # ``engine`` is the async engine; the instrumentation
            # accepts the underlying sync engine reference.
            sync_engine = getattr(engine, "sync_engine", engine)
            SQLAlchemyInstrumentor().instrument(
                engine=sync_engine,
                enable_commenter=False,
            )
        except ImportError:
            logger.info(
                "z4j observability.otel: SQLAlchemy instrumentation "
                "not installed; DB spans disabled.",
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "z4j observability.otel: SQLAlchemy instrumentation "
                "failed; DB spans disabled.",
                exc_info=True,
            )

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        # Outbound URL scrubber. Slack / Discord / Teams / PagerDuty
        # webhook URLs embed credentials in the path. The audit
        # forwarder is similar. Without this hook the OTLP exporter
        # ships the full URL (including token) to the collector, a
        # third-party SaaS in most deployments. (Audit C7.)
        #
        # Fail-closed: if the hook itself raises (typo, SDK upgrade
        # that renames ``request.url``, host is not a string), we
        # OVERWRITE the URL to a generic redacted marker so the
        # exporter never ships the un-scrubbed auto-captured URL.
        # We additionally log at WARNING so a regression surfaces
        # in operator dashboards instead of silently leaking.
        # (Round 2 H3.)
        def _set_redacted_attrs(span: Any, host: str, scheme: str) -> None:
            span.set_attribute(
                "http.url",
                f"{scheme}://{host}/[redacted by z4j]",
            )
            span.set_attribute("http.target", "/[redacted by z4j]")
            span.set_attribute(
                "url.full", f"{scheme}://{host}/[redacted by z4j]",
            )
            span.set_attribute("url.path", "/[redacted by z4j]")
            span.set_attribute("url.query", "")

        def _httpx_request_hook(span: Any, request: Any) -> None:
            try:
                if span is None or not span.is_recording():
                    return
                url = getattr(request, "url", None)
                if url is None:
                    return
                host = getattr(url, "host", None) or ""
                if not isinstance(host, str):
                    host = str(host)
                if not _is_sensitive_outbound_host(host):
                    return
                scheme = getattr(url, "scheme", "https") or "https"
                if not isinstance(scheme, str):
                    scheme = str(scheme)
                _set_redacted_attrs(span, host, scheme)
            except Exception:  # noqa: BLE001
                # Fail-closed: a scrubber failure must NOT ship the
                # auto-captured URL. Overwrite defensively + log.
                try:
                    _set_redacted_attrs(span, "[unknown]", "https")
                except Exception:  # noqa: BLE001
                    pass
                logger.warning(
                    "z4j observability.otel: httpx request_hook "
                    "raised; URL redacted defensively",
                    exc_info=True,
                )

        # The response hook fires AFTER the request completes. The
        # OpenTelemetry httpx instrumentation re-writes some span
        # attributes (response status, redirect target) at this
        # point. Re-run the scrubber so any URL the response side
        # touched is also redacted. (Round 2 H4.)
        def _httpx_response_hook(span: Any, request: Any, response: Any) -> None:
            _httpx_request_hook(span, request)

        HTTPXClientInstrumentor().instrument(
            request_hook=_httpx_request_hook,
            response_hook=_httpx_response_hook,
        )
    except ImportError:
        logger.info(
            "z4j observability.otel: httpx instrumentation not "
            "installed; outbound HTTP spans disabled.",
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "z4j observability.otel: httpx instrumentation failed; "
            "outbound HTTP spans disabled.",
            exc_info=True,
        )

    _initialised = True
    _init_succeeded = True
    logger.info(
        "z4j observability.otel: OpenTelemetry initialised "
        "(endpoint=%s, protocol=%s, sampler_arg=%.3f, "
        "include_health=%s)",
        endpoint,
        protocol,
        sampler_arg,
        getattr(settings, "otel_include_health", False),
    )
    return True


def _reset_for_tests() -> None:
    """Clear init flags so a test that asserts on init behaviour can
    run init twice. Mirrors the Sentry helper.

    Also clears ``_DYNAMIC_SENSITIVE_HOSTS`` so a test rig that
    swaps brain instances (different audit_webhook_url across
    test runs) does not accumulate sensitive-host entries across
    runs. (Round 5 F5: test-pollution gap.)"""
    global _initialised, _init_succeeded
    _initialised = False
    _init_succeeded = False
    _reset_dynamic_sensitive_hosts_for_tests()


__all__ = [
    "DEFAULT_EXCLUDED_URL_PATTERNS",
    "build_resource_attributes",
    "init_otel",
    "_reset_for_tests",
]
