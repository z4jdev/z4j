"""Brain configuration via :mod:`pydantic_settings`.

Twelve-factor: every value is sourced from an environment variable
prefixed ``Z4J_`` or, in development, from a ``.env`` file at the
process working directory. Missing required values cause startup to
fail fast with a Pydantic ``ValidationError``.

This module is intentionally framework-free below the FastAPI layer:
``Settings`` is just a frozen dataclass-like object passed into the
app factory. Tests construct their own ``Settings`` instance instead
of monkey-patching environment variables.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from z4j_core.paths import z4j_home


def _env_file_chain() -> tuple[str, ...]:
    """Build the env-file precedence tuple for Pydantic Settings.

    Resolved at module-load time. Pydantic's later-wins-on-collision
    behavior orders these from lowest to highest precedence:

    - secret.env: auto-minted secrets (not human-edited)
    - config.env: human-edited tunables
    - ./.env: dev-workflow CWD override

    Process env vars beat all three. Files that don't exist are
    silently ignored by Pydantic Settings.
    """
    home = z4j_home()
    return (
        str(home / "secret.env"),
        str(home / "config.env"),
        ".env",
    )


class ConfigError(ValueError):
    """Settings misconfiguration.

    Subclass of ``ValueError`` so callers can catch either, but with
    a distinct type so the brain operator-facing CLI can map this to
    a specific exit code. Raised by :meth:`Settings.model_post_init`
    when a cross-field invariant fails.

    Distinct from Pydantic's ``ValidationError`` because Pydantic
    serialises the original input dict in its error messages - and
    that input dict contains secrets we never want to land in stdout.
    """


class Settings(BaseSettings):
    """Resolved brain configuration.

    The brain refuses to start if any required value is missing or
    if a secret is shorter than 32 bytes. Operators see one clear
    Pydantic error at startup instead of obscure failures later.

    Attributes:
        database_url: Async SQLAlchemy URL,
            e.g. ``postgresql+asyncpg://user:pw@host/db``.
        secret: Master HMAC signing key. Used for command signatures
            and any HMAC-based identifier the brain mints. Must be
            at least 32 bytes.
        session_secret: Independent secret used to sign session
            cookies. Separate from ``secret`` so a session-cookie
            compromise does not extend to command signing.
        bind_host: ASGI bind host.
        bind_port: ASGI bind port.
        public_url: Externally reachable base URL of the brain.
            Used to build first-boot setup links and reverse-proxy
            redirect targets.
        cors_origins: Allowed CORS origins for the dashboard.
        log_level: stdlib logging level name.
        log_json: Emit logs as JSON when True, console-friendly when
            False (development).
        environment: Free-form environment label
            (``production``, ``staging``, ``dev``).
        event_retention_days: How long raw events live before
            partition pruning.
        audit_retention_days: How long audit-log rows live.
        command_timeout_seconds: Pending commands older than this
            are marked timed-out by the background worker.
        agent_offline_timeout_seconds: Heartbeats older than this
            mark the agent offline.
        ratelimit_commands_per_minute: Per-project upper bound for
            command issuance.
        ratelimit_events_per_second: Per-project upper bound for
            event ingestion.
        max_payload_size_bytes: Maximum REST request body size.
        max_ws_frame_bytes: Maximum inbound WebSocket frame size.
        metrics_enabled: Expose ``/metrics`` Prometheus scrape endpoint.
        session_duration_seconds: Lifetime of a dashboard session
            cookie.
        argon2_time_cost: argon2id time cost parameter.
        argon2_memory_cost: argon2id memory cost (KiB).
        argon2_parallelism: argon2id parallelism parameter.
        first_boot_token_ttl_seconds: How long the one-time setup
            token printed to stdout remains valid.
        dashboard_dist: Filesystem path to the built dashboard
            assets that will be mounted at ``/``.
    """

    # Pydantic Settings env-file precedence: the first match in the
    # tuple is the lowest-precedence file; later files override
    # earlier files; env vars override every file. Layout (1.5+):
    #
    #   1. $Z4J_HOME/secret.env  - auto-minted secrets (mode 0o600).
    #      Operators never edit this file directly.
    #   2. $Z4J_HOME/config.env  - human-edited runtime tunables.
    #      Generated as a documented template by ``z4j init``.
    #   3. ./.env  - CWD override for dev workflows. Mirrors the
    #      pre-1.5 single-file behavior so existing dev scripts keep
    #      working unchanged.
    #
    # Process env vars beat all of the above. Z4J_HOME is resolved
    # once at module-load time (the path is operator-set at process
    # start; we never relocate it mid-process).
    model_config = SettingsConfigDict(
        env_prefix="Z4J_",
        env_file=_env_file_chain(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # ------------------------------------------------------------------
    # Required secrets - startup fails fast if missing or weak.
    # ------------------------------------------------------------------
    database_url: str = Field(
        ...,
        description="postgresql+asyncpg:// async SQLAlchemy URL",
    )
    secret: SecretStr = Field(
        ...,
        description="Master HMAC signing key (>=32 bytes)",
    )
    #: Comma-separated list of
    #: previously-active master HMAC secrets accepted DURING a rotation
    #: window. The brain signs new tokens with ``secret`` only, but
    #: accepts a verification match against ``secret`` OR any of these
    #: previous values. This lets operators rotate ``Z4J_SECRET``
    #: without invalidating every agent token + session cookie at
    #: once: rotate, redeploy, wait for agents to re-mint, then drop
    #: ``Z4J_PREVIOUS_SECRETS`` from the env. Empty (default) = no
    #: rotation in progress.
    previous_secrets: SecretStr | None = Field(
        default=None,
        description=(
            "Comma-separated previous master secrets accepted during "
            "rotation. Each entry must be >=32 bytes. Drop after agents "
            "re-mint."
        ),
    )
    session_secret: SecretStr = Field(
        ...,
        description="Session cookie signing key (>=32 bytes)",
    )
    #: Same multi-key acceptance
    #: window for the session-cookie signing key. See
    #: :attr:`previous_secrets` for rotation semantics.
    previous_session_secrets: SecretStr | None = Field(
        default=None,
        description=(
            "Comma-separated previous session secrets accepted during "
            "rotation."
        ),
    )

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------
    bind_host: str = "0.0.0.0"
    bind_port: int = Field(default=7700, ge=1, le=65535)
    public_url: str = "http://localhost:7700"
    cors_origins: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Operational
    # ------------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = True
    environment: str = Field(default="production", max_length=40)

    # ------------------------------------------------------------------
    # Retention + worker cadence
    # ------------------------------------------------------------------
    event_retention_days: int = Field(default=30, ge=1, le=3650)
    audit_retention_days: int = Field(default=90, ge=1, le=3650)
    #: Periodic sweeper cadence for the audit-log retention task
    #: (1.2.2+). Default 1h is enough to keep up with even the
    #: noisiest brain (~1M rows/day). Operators worried about
    #: vacuum churn on Postgres can lengthen this freely.
    audit_retention_sweep_interval_seconds: int = Field(
        default=3600, ge=60, le=86_400,
    )
    #: Per-pass batch size. Smaller batches = shorter transactions
    #: at the cost of more passes to drain a backlog. 5_000 is a
    #: good balance for both SQLite and Postgres on a homelab box.
    audit_retention_sweep_batch_size: int = Field(
        default=5_000, ge=100, le=100_000,
    )
    #: Hard cap on rows deleted in one sweep pass. Prevents a
    #: million-row backlog from running as one runaway transaction
    #: window, the next pass picks up the remaining rows. Audit
    #: fix MED-18.
    audit_retention_sweep_max_per_pass: int = Field(
        default=200_000, ge=1_000, le=10_000_000,
    )
    #: SQLite-only periodic ``PRAGMA wal_checkpoint(TRUNCATE)`` cadence
    #: (1.2.2+). 5 minutes is enough to keep the ``-wal`` sidecar from
    #: growing unbounded under normal load. The task is a no-op on
    #: Postgres deployments.
    wal_checkpoint_interval_seconds: int = Field(
        default=300, ge=60, le=86_400,
    )
    command_timeout_seconds: int = Field(default=60, ge=1, le=86_400)
    agent_offline_timeout_seconds: int = Field(default=30, ge=1, le=3600)
    #: Delete agent rows that have been offline for more than this
    #: many days. Keeps the Agents page tidy after removed
    #: containers. Set to 0 to disable pruning (useful for long
    #: audit retention windows; rely on the ``state=offline`` badge
    #: instead).
    agent_stale_prune_days: int = Field(default=30, ge=0, le=3650)

    #: Source URL for the operator-initiated *Check for updates* button
    #: in Settings -> System (1.3.4+). The brain ships with a bundled
    #: ``versions.json`` snapshot generated from
    #: ``sites/_shared/packages.ts`` at brain release time, so the
    #: Agents page renders version comparisons WITHOUT any outbound
    #: HTTP by default. The ``Check for updates`` button lets an
    #: operator pull a fresher snapshot when they want one.
    #:
    #: Default: GitHub raw URL of the umbrella repo's bundled
    #: ``versions.json`` (committed by ``release-split.sh`` on every
    #: release wave). Operators can:
    #:
    #: - Leave the default and click the button when curious.
    #: - Set to a private mirror URL for air-gapped fleets that allow
    #:   internal HTTPS but not raw.githubusercontent.com.
    #: - Set to empty string to HIDE the button entirely (paranoid /
    #:   strict no-outbound deploys). The bundled snapshot is then
    #:   the only source.
    #:
    #: This is the ONLY URL the brain ever fetches by default and
    #: only when a logged-in admin clicks the button. There is no
    #: background polling. There is no telemetry.
    version_check_url: str = Field(
        default=(
            "https://raw.githubusercontent.com/z4jdev/z4j/main/"
            "versions.json"
        ),
        max_length=2048,
    )

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    ratelimit_commands_per_minute: int = Field(default=100, ge=1)
    ratelimit_events_per_second: int = Field(default=10_000, ge=1)

    # ------------------------------------------------------------------
    # Safety limits
    # ------------------------------------------------------------------
    max_payload_size_bytes: int = Field(default=8_192, ge=128)
    max_ws_frame_bytes: int = Field(default=1_048_576, ge=1024)
    #: Upper bound on the admin project listing endpoints
    #: (``/api/v1/projects`` and the Home dashboard). Raise this for
    #: tenants with more projects than the default ceiling; keep it
    #: low for deployments where a runaway admin UI should not DoS
    #: the backend. Audit 2026-04-24 Low-3 - was hardcoded 500.
    admin_project_list_cap: int = Field(default=500, ge=10, le=100_000)
    #: Upper bound on rows fetched by task export endpoints
    #: (``/api/v1/projects/{slug}/tasks?format=csv|xlsx|json``).
    #: Exports don't paginate; this cap is the backstop that
    #: prevents a single export from pulling a multi-million-row
    #: resultset into memory. Audit 2026-04-24 Low-3.
    # Export row cap. Pre-1.0.14 the
    # ceiling was 5_000_000 - a single CSV/XLSX export at that size
    # materializes hundreds of MB of task rows (with their JSONB
    # args/kwargs/result/traceback blobs) into Python memory before
    # serialization, which can OOM a worker. The new ceiling of
    # 100_000 keeps per-export memory bounded to ~hundreds of MB
    # worst case; the proper streaming rewrite (server-side cursor
    # via session.stream_scalars) is tracked for v1.1.x as it
    # requires a larger refactor of the repository methods.
    tasks_export_max_rows: int = Field(default=50_000, ge=100, le=100_000)

    # ------------------------------------------------------------------
    # Registry (asyncpg LISTEN/NOTIFY)
    # ------------------------------------------------------------------
    asyncpg_connect_timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    asyncpg_close_timeout: float = Field(default=5.0, ge=1.0, le=30.0)

    # ------------------------------------------------------------------
    # 1.5.1: asyncpg connection-level memory tuning.
    # ------------------------------------------------------------------
    # Round 19 memray profile (docs/perf/1.5.1-round17-gate-result.md
    # follow-up) showed Python heap peak at 58 MB while process RSS
    # grew 1.5 GB under sustained 100+ t/s burst. The delta is
    # C-level memory in asyncpg's per-connection state -- chiefly the
    # prepared-statement cache. asyncpg's default
    # ``statement_cache_size=100`` × ~30 connections × diverse query
    # set (events INSERT, agents UPDATE, workers upsert, schedules
    # SELECT, audit_log INSERT, partition mgmt, ...) accumulates
    # 300 MB - 1.5 GB depending on plan complexity.
    #
    # ``database_statement_cache_size``: per-connection cap. 0
    # disables the cache (every query re-prepares, costs a small
    # round-trip but bounds memory tightly). 50 is a small bounded
    # cache that keeps the prepare-once speedup for hot queries
    # while bounding worst-case growth.
    #
    # ``database_max_inactive_connection_lifetime_seconds``: asyncpg
    # closes a connection that has been idle in the pool longer
    # than this. Default 300s; we lower to 60s so caches naturally
    # rotate under sustained load instead of sticking until pool
    # recycle.
    database_statement_cache_size: int = Field(
        default=50, ge=0, le=10_000,
        description=(
            "Cap on asyncpg per-connection prepared-statement cache. "
            "Set to 0 to disable. See 1.5.1 leak fix notes."
        ),
    )
    database_max_inactive_connection_lifetime_seconds: float = Field(
        default=60.0, ge=1.0, le=3600.0,
        description=(
            "Seconds an idle asyncpg connection lives in the pool "
            "before being closed + reopened. Shorter = better memory "
            "hygiene under sustained load."
        ),
    )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    metrics_enabled: bool = True
    #: Bearer token that must be presented as
    #: ``Authorization: Bearer <token>`` to fetch ``/metrics``.
    #: As of 1.0.13 the CLI auto-mints this on first boot (persisted to
    #: ``~/.z4j/secret.env``) and the endpoint is fail-secure: unset +
    #: :attr:`metrics_public` False returns 401. Operators who need
    #: unauthenticated scrape (trusted LAN, sidecar Prometheus) must
    #: set :attr:`metrics_public` explicitly.
    metrics_auth_token: SecretStr | None = None
    #: Explicit opt-in to unauthenticated ``/metrics``. Default False
    #: (fail-secure). When True, the bearer-token check is skipped and
    #: the brain logs a loud WARNING at startup naming the risk.
    #: Set via ``Z4J_METRICS_PUBLIC=1``. Reverse of the pre-1.0.13
    #: default - see :func:`z4j_brain.api.metrics._check_metrics_auth`
    #: for the policy rationale.
    metrics_public: bool = False
    #: DEPRECATED in 1.6.3. Read for backwards compat with a WARN
    #: log; use :attr:`openapi_visibility` instead. Mapped on
    #: :meth:`model_post_init`: ``true`` -> ``"private"``,
    #: ``false`` -> ``"disabled"``. Leave unset on new deployments.
    #:
    #: Pre-1.6.3 the boolean defaulted to True with NO authentication
    #: requirement on the schema or Swagger UI -- which made every
    #: route, every Pydantic model, every field name and type, and
    #: every docstring readable to any anonymous caller. The 1.6.0
    #: round-3 audit Medium-1 flagged this; 1.6.3 closes it properly
    #: by replacing the boolean with a three-mode visibility setting
    #: defaulting to ``private``.
    openapi_docs_enabled: bool | None = None

    #: Visibility of the OpenAPI schema (``/api/v1/openapi.json``)
    #: and Swagger UI (``/api/v1/docs``). Three modes:
    #:
    #: - ``"public"`` -- reachable by any anonymous caller. Use when
    #:   the brain intentionally exposes its API surface (demo
    #:   sites, public API products, marketing endpoints).
    #: - ``"private"`` -- requires session cookie OR API key. Default;
    #:   appropriate for every self-hosted production deployment.
    #:   Returns 401 to anonymous callers with a generic
    #:   ``WWW-Authenticate: Bearer realm="z4j"``.
    #: - ``"disabled"`` -- not mounted. Returns 404 to everyone.
    #:   Use for compliance-bound or regulated deployments where
    #:   even authenticated discovery is not desired.
    #:
    #: Layered defenses apply regardless of mode: per-IP rate limit,
    #: ``Cache-Control`` headers, ``ETag`` round-tripping, audit-log
    #: entries on every access, and a build watermark in the schema.
    #: See :mod:`z4j_brain.api.openapi_route` for the implementation.
    #:
    #: Set via ``Z4J_OPENAPI_VISIBILITY=public|private|disabled``.
    #: (1.6.3 security advisory: replaces the boolean
    #: ``Z4J_OPENAPI_DOCS_ENABLED``; old setting kept as deprecated
    #: alias with a startup WARN log.)
    openapi_visibility: Literal["public", "private", "disabled"] = "private"

    # ------------------------------------------------------------------
    # Sentry (optional error capture; off by default)
    # ------------------------------------------------------------------
    #: Sentry DSN. Empty / unset disables Sentry entirely; even when
    #: ``sentry-sdk`` is installed the brain runs unchanged without a
    #: DSN. SecretStr so the value never lands in startup logs or in a
    #: Pydantic ``ValidationError`` reproduction. See
    #: ``observability/sentry.py`` for the init contract and the
    #: ``before_send`` scrubber that strips Authorization headers,
    #: cookies, and OAuth-style query tokens before any event leaves
    #: the brain.
    sentry_dsn: SecretStr | None = None
    #: Override the Sentry ``environment`` tag. Defaults to
    #: :attr:`environment` so a brain running with ``Z4J_ENVIRONMENT=
    #: production`` shows up under that name in Sentry without a
    #: second knob. Set this when the deployment label and the Sentry
    #: project layout disagree (e.g. multiple staging brains routing
    #: into one Sentry project distinguished by ``staging-eu`` vs
    #: ``staging-us``).
    sentry_environment: str | None = Field(default=None, max_length=64)
    #: Sentry tracing sample rate, 0.0 .. 1.0. Default 0.0: only
    #: unhandled exceptions ship; no performance spans are created.
    #: Flip to a small positive value (0.05 is a good starting point)
    #: to capture transaction performance on a fraction of requests.
    sentry_traces_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    #: Sentry profiling sample rate, 0.0 .. 1.0. Defaults to 0.0.
    #: Profiling only fires inside transactions, so this is bounded
    #: above by :attr:`sentry_traces_sample_rate`. Leave at 0 unless
    #: you have already enabled traces.
    sentry_profiles_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    #: Forward identifying data (IPs, usernames) to Sentry. Default
    #: False -- the brain's :func:`scrub_event` hook also strips
    #: Authorization / cookie / OAuth-token surfaces regardless of
    #: this flag, so flipping it on still leaves credentials redacted.
    sentry_send_default_pii: bool = False

    # ------------------------------------------------------------------
    # OpenTelemetry (optional distributed tracing; off by default)
    # ------------------------------------------------------------------
    #: OTLP exporter endpoint. Empty / unset disables OTel completely;
    #: even when the SDK is installed an unset endpoint is a no-op.
    #: SecretStr so an endpoint containing a bearer-style API key in
    #: the path (some commercial collectors do this) does not land in
    #: startup logs or in a Pydantic ValidationError reproduction.
    #: Standard Honeycomb / Lightstep / Tempo / Jaeger Collector all
    #: expose an OTLP HTTP endpoint at ``/v1/traces``.
    otel_exporter_otlp_endpoint: SecretStr | None = None
    #: OTLP transport protocol. ``http/protobuf`` is the default
    #: (simpler operational target; works through plain HTTPS); set
    #: to ``grpc`` if your collector exposes only gRPC and you have
    #: installed ``opentelemetry-exporter-otlp-proto-grpc``.
    otel_protocol: Literal["http/protobuf", "http", "grpc"] = "http/protobuf"
    #: Comma-separated ``key=value`` pairs forwarded to the OTLP
    #: exporter as ``OTEL_EXPORTER_OTLP_HEADERS``. The standard place
    #: to put an x-honeycomb-team / authorization header. SecretStr
    #: for the same reason as the endpoint.
    otel_exporter_otlp_headers: SecretStr | None = None
    #: Override the OTel ``service.name`` resource attribute. Default
    #: ``z4j-brain`` for the brain process. Multi-brain deployments
    #: (e.g. ``z4j-brain-eu`` vs ``z4j-brain-us``) set this to
    #: distinguish them on the collector side.
    otel_service_name: str = Field(default="z4j-brain", max_length=128)
    #: Override the OTel ``service.namespace`` resource attribute.
    #: Default ``z4j`` so all z4j services group in the collector UI.
    otel_service_namespace: str = Field(default="z4j", max_length=128)
    #: Override the OTel ``deployment.environment`` resource
    #: attribute. Defaults to :attr:`environment` so a brain running
    #: with ``Z4J_ENVIRONMENT=production`` shows up under that name
    #: in the collector without a second knob.
    otel_environment: str | None = Field(default=None, max_length=64)
    #: Trace sampler argument, 0.0 .. 1.0. Default 0.0 = drop every
    #: trace (errors-only effectively, since the brain still exports
    #: span structure but the sampler keeps none). Set to a small
    #: positive value to capture a fraction of requests. The sampler
    #: is ParentBased(TraceIdRatioBased(arg)) so an inbound trace
    #: context from an upstream service is always honoured.
    otel_traces_sampler_arg: float = Field(default=0.0, ge=0.0, le=1.0)
    #: When False (default), tracing for ``/health*`` and ``/metrics``
    #: is suppressed via the FastAPI instrumentation's ``excluded_urls``
    #: list. Those endpoints carry too much background traffic for
    #: any sample budget to be meaningful and the spans add nothing
    #: an operator wants to see. Flip to True if you specifically
    #: want health-check latency tracing.
    otel_include_health: bool = False
    #: Comma-separated additional URL substrings to exclude from
    #: tracing. Layered on top of :attr:`otel_include_health`.
    otel_excluded_url_patterns: str = Field(default="", max_length=512)

    # ------------------------------------------------------------------
    # Audit webhook forwarding (optional out-of-band SIEM mirror)
    # ------------------------------------------------------------------
    #: Receiver URL for the audit-forwarder. Empty / unset disables
    #: the forwarder entirely; even with the URL set, the brain's
    #: primary audit log remains the source of truth and forwarding
    #: is best-effort. SecretStr so a path-embedded token (Splunk HEC,
    #: Datadog logs intake) does not land in startup logs.
    audit_webhook_url: SecretStr | None = None
    #: HMAC-SHA256 secret used to sign forwarded audit-row bodies.
    #: REQUIRED when ``audit_webhook_url`` is set; the brain refuses
    #: to start otherwise (see ``_enforce_security_invariants``).
    #: Receivers verify by recomputing
    #: ``hmac.new(secret, body, sha256).hexdigest()`` and comparing
    #: constant-time to the value in ``X-Z4J-Audit-Signature``.
    audit_webhook_hmac_secret: SecretStr | None = None
    #: Per-row POST timeout in seconds. Default 10s matches the
    #: notification dispatcher. A slow receiver does not block the
    #: brain's audit write path because the forwarder runs in a
    #: background drain task.
    audit_webhook_timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    #: In-memory queue size between the audit-write hook and the
    #: drain task. Spikes above this cause rows to be dropped with
    #: a WARNING + a swallowed-exception metric bump. Raise on
    #: high-volume brains; the buffer is shared across all
    #: AuditService writers in this process.
    audit_webhook_buffer_size: int = Field(default=1000, ge=10, le=100_000)

    # ------------------------------------------------------------------
    # Auth - passwords
    # ------------------------------------------------------------------
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost: int = Field(default=65_536, ge=8192)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)
    password_min_length: int = Field(default=8, ge=8, le=128)

    # ------------------------------------------------------------------
    # Auth - sessions (server-side, revocable)
    # ------------------------------------------------------------------
    #: Hard cap on a single session's lifetime, regardless of activity.
    #: After this elapses since ``issued_at`` the session is rejected
    #: even if the user has been active. Default: 7 days.
    session_absolute_lifetime_seconds: int = Field(default=604_800, ge=60)
    #: Sliding idle timeout. If ``last_seen_at`` is older than this,
    #: the session is rejected even if the absolute lifetime has not
    #: elapsed. Default: 30 minutes.
    session_idle_timeout_seconds: int = Field(default=1_800, ge=60)
    #: Absolute lifetime for sessions where the user opted into
    #: "Keep me signed in" at login. Replaces (not extends)
    #: :attr:`session_absolute_lifetime_seconds` for that session.
    #: Default 30 days; the idle timeout is also bypassed for
    #: remembered sessions so a homelab operator who pokes the
    #: dashboard once a week is not kicked back to the login screen.
    session_remember_me_lifetime_seconds: int = Field(
        default=2_592_000,
        ge=60,
    )
    #: When True, the resolved client user-agent at session-issue time
    #: is enforced on every subsequent request - change of UA voids
    #: the session. Default OFF: too many false positives on mobile
    #: networks and behind corporate proxies.
    session_pin_user_agent: bool = False

    #: SameSite attribute on the session cookie.
    #:
    #: - ``"lax"`` (default): cookie IS sent on top-level GET
    #:   navigation, preserving the UX where a link in an email
    #:   that opens https://z4j.example.com/projects/... lands on
    #:   the project page rather than the login page. Already
    #:   blocks every cross-site form-POST and every cross-site
    #:   image/iframe request, which covers the standard CSRF
    #:   threat model. Combined with the double-submit CSRF token
    #:   (``require_csrf``) this is the best UX/security trade for
    #:   the typical operator dashboard.
    #: - ``"strict"``: cookie is NEVER sent on cross-site navigation
    #:   of any kind. Stronger defense in depth - useful for
    #:   security-paranoid deployments where operators always start
    #:   from a bookmark/typed URL. Costs the email-link UX above.
    #: - ``"none"`` is intentionally NOT supported. SameSite=None
    #:   requires Secure AND opens cross-site state-changing
    #:   requests; we never want it for a session cookie.
    session_cookie_samesite: str = Field(
        default="lax",
        pattern="^(lax|strict)$",
    )

    # ------------------------------------------------------------------
    # Auth - login lockout + backoff
    # ------------------------------------------------------------------
    login_lockout_threshold: int = Field(default=10, ge=3, le=100)
    login_lockout_duration_seconds: int = Field(default=900, ge=60, le=86_400)
    login_backoff_base_seconds: float = Field(default=0.5, ge=0.0, le=10.0)
    login_backoff_max_seconds: float = Field(default=5.0, ge=0.0, le=60.0)
    #: Minimum total response time for ``/auth/login`` (success OR
    #: failure). Held by ``await asyncio.sleep`` so DB-query, argon2,
    #: and cache-hit/miss variance cannot be exploited as a timing
    #: oracle for username enumeration.
    login_min_duration_ms: int = Field(default=300, ge=0, le=2000)
    #: When True, structured logs at ``z4j.brain.auth`` carry the
    #: attempted email on failed login. Always recorded in the audit
    #: log row regardless. Default OFF - emails in stdout logs are a
    #: PII liability for shipped log streams.
    log_login_email: bool = False

    # ------------------------------------------------------------------
    # MFA (TOTP). See docs/MFA-DESIGN.md.
    # ------------------------------------------------------------------
    #: Require every user with global ``is_admin=true`` to enroll in
    #: MFA within the grace window. Existing admins who upgrade to a
    #: brain with this flag set get the grace clock starting from the
    #: first login that observes the policy.
    mfa_enforce_for_admins: bool = False
    #: Require every user (admins and non-admins) to enroll in MFA
    #: within the grace window. Stricter superset of
    #: :attr:`mfa_enforce_for_admins`.
    mfa_enforce_for_all: bool = False
    #: Days an enforcement-targeted user has to enroll before login
    #: is blocked with ``mfa_enrollment_required``.
    mfa_enrollment_grace_days: int = Field(default=7, ge=1, le=90)
    #: Number of single-use recovery codes minted at enrollment time.
    mfa_recovery_code_count: int = Field(default=10, ge=5, le=50)
    #: How long a successful MFA verify is valid for the sensitive-
    #: action gate (password change, API key create, project delete,
    #: admin promote). Default 60 minutes -- matches GitHub's "sudo
    #: mode" window, which is what most operators have already
    #: internalised. High-stakes enterprise installs that want a
    #: shorter window set this explicitly via env var; 1Password
    #: and Stripe both use 30 min as their default.
    mfa_verification_ttl_seconds: int = Field(
        default=3_600,
        ge=60,
        le=86_400,
    )
    #: Lifetime of the ``z4j_mfa_trust`` "remember this device" cookie.
    #: Hard upper bound of 90 days; longer windows trade away too much
    #: of the second factor.
    mfa_remember_device_days: int = Field(default=30, ge=1, le=90)
    #: Per-IP cap on ``POST /auth/mfa/verify`` attempts per minute.
    #: Tighter than the login bucket because the verify endpoint is
    #: a code-brute-force target.
    mfa_verification_rate_per_min: int = Field(default=10, ge=1, le=300)
    #: Max active "remember this device" rows a single user can hold.
    #: Stops an attacker who briefly compromises a session from
    #: minting thousands of trust rows. When the cap is hit, the
    #: oldest active row is revoked to make room.
    mfa_trusted_devices_max_per_user: int = Field(default=20, ge=1, le=200)

    # ------------------------------------------------------------------
    # First-boot
    # ------------------------------------------------------------------
    first_boot_token_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    #: Hard cap on setup-token verification attempts per IP per 15
    #: minutes. Defends the setup endpoint against brute-forcing the
    #: 256-bit token in the (unlikely) window between mint and consume.
    # Sliding-window cap on FAILED setup attempts per IP. Bumped from
    # 5 to 30 in 1.0.4 because the original threshold tripped on common
    # operator UX patterns (form validation typos, stale browser tabs
    # from prior server runs, double-submits). The window is still 15
    # minutes; the 30 ceiling protects against credential stuffing
    # while leaving room for honest retries.
    first_boot_attempts_per_ip: int = Field(default=30, ge=1, le=100)

    # ------------------------------------------------------------------
    # Network - host + proxy + body + timeouts
    # ------------------------------------------------------------------
    #: Allowed Host headers. Production must populate this. Empty
    #: list in dev defaults to ``["localhost", "127.0.0.1"]`` via the
    #: model validator below.
    allowed_hosts: list[str] = Field(default_factory=list)
    #: CIDR list of reverse-proxy IPs whose ``X-Forwarded-For`` we
    #: trust. Empty list = trust no proxies (audit logs use the raw
    #: socket peer address). Defaults are dev-only.
    trusted_proxies: list[str] = Field(default_factory=list)
    #: Per-request handler wall-clock budget. Handlers exceeding this
    #: are cancelled and the response becomes a 504 + audit row.
    request_timeout_seconds: int = Field(default=30, ge=1, le=600)
    #: Strict-Transport-Security max-age. Only emitted when
    #: ``environment="production"`` AND ``public_url`` starts with
    #: ``https://``.
    hsts_max_age_seconds: int = Field(default=31_536_000, ge=0)
    #: ESCAPE HATCH FOR INTERNAL TEST FIXTURES ONLY. When True,
    #: skips the production-mode "public_url must use https://"
    #: validator. Set this only when the brain is provably not
    #: reachable from anywhere a real user's browser would land
    #: (closed docker network, CI runner, internal benchmark rig).
    #: Logged loudly at startup so a real-deploy operator who
    #: copies a test config sees the warning. The
    #: ``docker-compose.scheduler-test.yml`` multi-framework e2e
    #: relies on this for inter-container HTTP traffic.
    allow_http_public_url: bool = Field(default=False)
    #: Whether to append ``includeSubDomains`` to the HSTS header.
    #: Defaults to True (the safer choice for a brain deployed at
    #: a dedicated subdomain), but operators serving HTTP siblings
    #: under the same parent domain MUST set this to False or HSTS
    #: will break those siblings irreversibly for the cache window.
    hsts_include_subdomains: bool = Field(default=True)

    # ------------------------------------------------------------------
    # Database safety
    # ------------------------------------------------------------------
    db_statement_timeout_ms: int = Field(default=10_000, ge=100, le=600_000)
    db_lock_timeout_ms: int = Field(default=3_000, ge=100, le=600_000)
    db_idle_in_tx_timeout_ms: int = Field(default=30_000, ge=100, le=600_000)
    #: When True, refuse a Postgres URL that disables SSL
    #: (``sslmode=disable`` or no sslmode at all). Auto-relaxed when
    #: ``environment="dev"``.
    require_db_ssl: bool = True

    # ------------------------------------------------------------------
    # CORS hardening
    # ------------------------------------------------------------------
    cors_allow_credentials: bool = True

    # ------------------------------------------------------------------
    # Agent gateway (B4)
    # ------------------------------------------------------------------
    #: Which BrainRegistry implementation to wire at startup.
    #: Production must use ``postgres_notify``. ``local`` is the
    #: in-process map used by unit tests for speed - it does NOT
    #: route across worker processes.
    registry_backend: Literal["postgres_notify", "local"] = "postgres_notify"
    #: Heartbeat self-NOTIFY interval. The listener task NOTIFYs on
    #: a dedicated channel every N seconds and a watchdog kills the
    #: connection if its own message has not round-tripped within
    #: ``registry_listener_heartbeat_timeout_seconds``. Defends
    #: against the queue-lock failure mode.
    registry_listener_heartbeat_seconds: int = Field(default=10, ge=1, le=300)
    registry_listener_heartbeat_timeout_seconds: int = Field(
        default=25, ge=2, le=600,
    )
    #: Hard recycle interval for the listener connection. Belt-and-
    #: braces against silent NAT/proxy wedges and hung backends.
    registry_listener_max_age_seconds: int = Field(default=900, ge=60, le=86_400)
    #: Periodic poll interval for "pending commands targeting an
    #: agent I currently hold". Recovers from any notify that was
    #: lost or delivered while the listener was reconnecting.
    #: Lower bound is 1s so integration tests can drive a fast
    #: sweep; production deployments should leave the default of 30s.
    registry_reconcile_interval_seconds: int = Field(default=30, ge=1, le=600)
    #: Maximum inbound WebSocket frame size from agents. Frames
    #: larger than this kill the connection. 1 MiB is well above
    #: any legitimate event_batch shape.
    ws_max_frame_bytes: int = Field(default=1_048_576, ge=8192, le=33_554_432)
    #: Maximum number of concurrent worker connections accepted
    #: per agent_id (1.2.1+, repurposed from a dead pre-1.2.0
    #: setting that was never read in code). Default 64 covers the
    #: realistic enterprise case (gunicorn 8-16 workers + Celery
    #: 16-32 worker pool + scheduler + beat) with headroom; raise
    #: for very dense hosts. Set 0 to disable the cap.
    #:
    #: Once a connection slot is full and a NEW worker_id tries to
    #: register, the gateway rejects the handshake with WebSocket
    #: close code 4429 ("too many workers under this agent"). This
    #: bounds the worst-case fd / memory footprint per agent token
    #: even if a misbehaving (or malicious) agent invents many
    #: distinct worker_ids; defense-in-depth alongside the per-IP
    #: rate limit on /ws/agent.
    ws_per_agent_concurrency_cap: int = Field(default=64, ge=0, le=10_000)
    #: Per-connection idle timeout for both ``/ws/agent`` and
    #: ``/ws/dashboard``. If no frame arrives in this many seconds
    #: the connection is closed and the file descriptor released.
    #:
    #: For agents this MUST be larger than the heartbeat interval
    #: declared in the ``hello_ack`` frame (10s by default) - a
    #: well-behaved agent sends a heartbeat every 10s, so 60s gives
    #: 6 missed heartbeats of headroom before we kill the socket.
    #:
    #: For dashboards the client sends a ping every 25s; 90s gives
    #: 3 missed pings of headroom which is plenty for normal
    #: network jitter and tab-throttling on backgrounded tabs.
    ws_idle_timeout_seconds: int = Field(default=90, ge=15, le=3600)
    #: Bounded per-connection ingest queue. Decouples application-
    #: level frame dispatch (DB writes, notification fanout) from the
    #: WebSocket recv loop so the protocol-layer PING/PONG can drain
    #: promptly even while a slow DB transaction is in flight.
    #: Default of 2000 holds ~60 event_batch frames at the typical
    #: agent batch size of ~30 events. The recv loop blocks (rather
    #: than dropping) on full so backpressure flows back to the
    #: agent's send buffer. Single-producer / single-consumer: one
    #: worker drains the queue per connection so within-connection
    #: ordering is preserved and the per-event savepoint+retry path
    #: in the event_ingestor cannot silently skip events that fail
    #: a non-deadlock SQL exception. Larger queue depth substitutes
    #: for the parallel-worker design that briefly traded ordering
    #: for throughput.
    ws_ingest_queue_maxsize: int = Field(default=2_000, ge=16, le=50_000)
    #: Background worker poll intervals.
    command_timeout_sweep_seconds: int = Field(default=5, ge=1, le=300)
    agent_health_sweep_seconds: int = Field(default=10, ge=1, le=300)
    #: Cadence for :class:`AgentHygieneWorker`. Once a day is
    #: enough; the prune target is "weeks stale", not "minutes".
    agent_hygiene_sweep_seconds: int = Field(
        default=86_400, ge=60, le=604_800,
    )
    #: Cadence for :class:`ReconciliationWorker`. Every 5 min is a
    #: good compromise between prompt stuck-task resolution and
    #: per-agent WebSocket load.
    reconciliation_sweep_seconds: int = Field(default=300, ge=30, le=3600)
    #: Age after which a non-terminal task is considered "stuck" and
    #: eligible for result-backend reconciliation. 15 min tolerates
    #: long tasks without scheduling a reconcile for every in-flight
    #: retry.
    reconciliation_stale_threshold_seconds: int = Field(
        default=900, ge=60, le=86_400,
    )
    #: Default per-page cap on REST list endpoints.
    rest_default_page_size: int = Field(default=50, ge=1, le=1000)
    rest_max_page_size: int = Field(default=500, ge=1, le=5000)

    # ------------------------------------------------------------------
    # Dashboard assets
    # ------------------------------------------------------------------
    dashboard_dist: str = "/app/dashboard/dist"
    #: When True, ``create_app`` skips registering the SPA catch-all
    #: route. Production never sets this (the SPA must be served);
    #: the unit-test fixture sets it so tests can ``include_router``
    #: extra API routes after build time without the catch-all
    #: shadowing them. v1.0.15 enterprise-grade test isolation fix.
    disable_spa_fallback: bool = False

    # ------------------------------------------------------------------
    # z4j-scheduler gRPC service (docs/SCHEDULER.md §22)
    # ------------------------------------------------------------------
    # Off by default - operators opt in once they deploy a
    # ``z4j-scheduler`` companion process. When disabled the brain
    # behaves identically to pre-scheduler releases.
    scheduler_grpc_enabled: bool = False
    #: HTTP URLs of every scheduler instance the dashboard's
    #: Schedulers fleet page should poll for ``/info``. Empty list
    #: (default) means the page renders only the embedded sidecar
    #: at ``http://127.0.0.1:7800/info`` if ``embedded_scheduler``
    #: is on; otherwise an empty grid with a hint.
    #:
    #: Operators with multiple schedulers list them all, e.g.
    #: ``["http://scheduler-1:7800", "http://scheduler-2:7800"]``.
    #: The brain hits each URL on every dashboard refresh - keep
    #: the list bounded (~10 entries max in v1).
    scheduler_info_urls: list[str] = Field(default_factory=list)
    #: Bind interface for the gRPC server. Default ``0.0.0.0`` binds
    #: every interface; production deployments behind a private
    #: network may prefer a specific address.
    scheduler_grpc_bind_host: str = "0.0.0.0"  # noqa: S104 - opt-in gRPC service
    #: Bind port. Distinct from the FastAPI port so Prometheus,
    #: dashboard, and scheduler don't collide. Port 0 is allowed as
    #: the standard "ephemeral port" sentinel; integration tests
    #: use it so they don't have to coordinate fixed ports.
    scheduler_grpc_bind_port: int = Field(default=7701, ge=0, le=65535)
    #: Path to the brain's gRPC server certificate (PEM).
    scheduler_grpc_tls_cert: str | None = None
    #: Path to the brain's gRPC server private key (PEM).
    scheduler_grpc_tls_key: str | None = None
    #: Path to the CA bundle used to validate scheduler client certs.
    scheduler_grpc_tls_ca: str | None = None
    #: DEV / TEST ONLY: bind the scheduler gRPC port WITHOUT TLS.
    #: Mirrors the scheduler-side ``insecure_grpc`` opt-in. Refused
    #: when ``environment`` is ``"production"``: the scheduler
    #: channel is the brain's most-privileged inbound surface, so
    #: insecure transport is never acceptable in production.
    #: Use only on trusted loopback or container-internal networks
    #: (e.g. local docker-compose dev stacks where provisioning a
    #: cert chain would be friction without security benefit).
    scheduler_grpc_insecure: bool = False
    #: Allow-list of CN/SAN values accepted from client certs.
    #: Empty = trust any cert the CA bundle validates (operator
    #: chose "trust the CA"). Populate to add an extra check.
    scheduler_grpc_allowed_cns: list[str] = Field(default_factory=list)
    #: When True, brain refuses to start the scheduler gRPC server
    #: unless ``scheduler_grpc_allowed_cns`` is non-empty. Audit fix
    #: S004 (1.4.0): defaults False to preserve "trust the CA"
    #: deployments; operators wanting fail-closed defense-in-depth
    #: set ``Z4J_SCHEDULER_GRPC_REQUIRE_ALLOWLIST=true`` and the
    #: brain raises on startup if the allow-list was forgotten.
    scheduler_grpc_require_allowlist: bool = False
    #: When True, generic webhook channels accept ``http://`` target
    #: URLs in addition to ``https://``. Default False (HTTPS-only).
    #:
    #: Audit fix Low/Config-2 (1.4.0 pre-release pass): pre-fix
    #: ``_ALLOWED_SCHEMES = {"https", "http"}`` permitted plaintext
    #: webhook delivery to operator-configured URLs, leaking payloads
    #: + custom headers in cleartext. Operators with legitimate
    #: internal-network http endpoints (intranet receivers, dev
    #: rigs) opt in via ``Z4J_NOTIFICATIONS_WEBHOOK_ALLOW_HTTP=true``.
    #: HTTPS targets always work regardless of this setting.
    notifications_webhook_allow_http: bool = False
    #: Per-CN project binding. Maps a cert CN to the list of
    #: project slugs that cert is permitted to act on (FireSchedule,
    #: AcknowledgeFireResult, ListSchedules, WatchSchedules).
    #:
    #: Empty mapping (the default) preserves the legacy cross-project
    #: authority - any allow-listed CN can drive RPCs for any project.
    #: When a CN appears in this map, all of its RPCs are restricted
    #: to the listed project slugs; a request whose project does not
    #: appear in the binding list is rejected with PERMISSION_DENIED.
    #: When a CN does NOT appear, the per-cert restriction does not
    #: apply (mixed mode lets operators bind sensitive schedulers
    #: while leaving fleet-wide schedulers unconstrained).
    #:
    #: Format is a JSON object via env:
    #: ``Z4J_SCHEDULER_GRPC_CN_PROJECT_BINDINGS='{"scheduler-1":
    #: ["acme", "globex"]}'``. Slugs (not UUIDs) so operators can
    #: hand-edit the env var without pasting opaque ids.
    #:
    #: Closes the per-cert project-binding
    #: gap raised in the spec-§22 deferral. Empty default keeps
    #: existing single-tenant deployments unchanged.
    scheduler_grpc_cn_project_bindings: dict[str, list[str]] = Field(
        default_factory=dict,
    )
    #: Per-cert rate limit on FireSchedule. Defends against a
    #: scheduler agent compromised at the cert layer (or simply a
    #: misbehaving scheduler in a tight loop) DoS-ing the worker
    #: fleet by hammering FireSchedule. mTLS bounds *who* can call;
    #: this bounds *how much*. Token-bucket algorithm with state
    #: persisted in ``scheduler_rate_buckets`` so the limit survives
    #: brain restart and is shared across multi-replica brain
    #: deployments.
    #:
    #: Disable with ``scheduler_grpc_fire_rate_limit_enabled=false``
    #: when running behind an upstream rate-limiter (Envoy, NGINX
    #: mod_security) that already covers this surface.
    scheduler_grpc_fire_rate_limit_enabled: bool = True
    #: Maximum burst size (tokens). Default 600 means a freshly
    #: idle scheduler can fire 600 schedules instantly before the
    #: refill cap kicks in. Sized for a fleet of ~100 schedules
    #: triggering simultaneously at the top of an hour.
    scheduler_grpc_fire_rate_capacity: float = Field(
        default=600.0, ge=1.0, le=1_000_000.0,
    )
    #: Sustained refill rate (tokens/second). Default 10 fires/sec
    #: per cert, well above any normal scheduler workload; the cap
    #: only bites on runaway / hostile traffic. Operators with very
    #: high-volume single-cert deployments raise this; operators with
    #: a leaked-cert scenario in mind lower it.
    scheduler_grpc_fire_rate_per_second: float = Field(
        default=10.0, ge=0.01, le=10_000.0,
    )
    #: Hard cap on concurrent ``WatchSchedules`` streams per brain
    #: process. Each stream holds a dedicated asyncpg connection for
    #: LISTEN/NOTIFY (Postgres path), so unbounded streams = brain
    #: starves its own connection pool. Audit fix (Apr 2026
    #: follow-up) for the connection-exhaustion DoS surface where
    #: a misbehaving scheduler that opens streams in a loop dies
    #: brain.
    #:
    #: Default 64 covers the realistic ceiling (a fleet of 50
    #: scheduler instances + headroom). Tune up for very large
    #: fleets; tune down to be conservative on shared Postgres
    #: deployments where ``max_connections`` is tight.
    scheduler_grpc_watch_max_concurrent: int = Field(
        default=64, ge=1, le=10_000,
    )
    #: Per-CN cap on concurrent ``WatchSchedules`` streams. One
    #: scheduler should not need many streams at once - the cap
    #: stops a single misbehaving / compromised cert from filling
    #: the global limit and starving the rest of the fleet.
    scheduler_grpc_watch_max_per_cert: int = Field(
        default=4, ge=1, le=1_000,
    )
    #: Watch-stream poll cadence. Brain polls ``schedules.updated_at``
    #: every N seconds and emits diff events. 2s gives sub-3s
    #: cache-freshness end-to-end after the scheduler's tick budget.
    scheduler_grpc_watch_poll_seconds: float = Field(
        default=2.0, ge=0.5, le=60.0,
    )
    #: Graceful drain window on shutdown. In-flight RPCs get this
    #: long to complete before the runtime is torn down.
    scheduler_grpc_grace_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    #: Retention window for buffered fires that have not been
    #: replayed. After this many days the sweep worker drops the
    #: row regardless of the schedule's ``catch_up`` policy. 7d is
    #: the typical operator escalation timeline (a production agent
    #: outage is normally caught within 24h; 7d gives margin for a
    #: long weekend or holiday).
    pending_fires_retention_days: int = Field(default=7, ge=1, le=365)
    #: Cadence for :class:`PendingFiresReplayWorker`. Each tick
    #: scans for buffered fires whose project has at least one
    #: matching online agent and replays them through the existing
    #: command dispatcher.
    pending_fires_replay_interval_seconds: int = Field(
        default=10, ge=1, le=300,
    )

    # ------------------------------------------------------------------
    # Schedule circuit breaker (Phase 4)
    # ------------------------------------------------------------------
    #: After this many consecutive failed fires (any of ``failed`` or
    #: ``acked_failed``), the circuit breaker auto-disables the
    #: schedule and writes an audit row. 5 is the typical "noisy
    #: alert" threshold - one transient hiccup doesn't trip the
    #: breaker, but a persistent bug does. Set to 0 to disable the
    #: breaker entirely.
    #:
    #: **Operational note:** when the breaker fires, the schedule
    #: row's ``is_enabled`` flips to ``False`` and an audit row with
    #: ``action="schedule.auto_disabled.circuit_breaker"`` is written
    #: with the failure count + last error in metadata. Operators
    #: investigating "why did my schedule stop firing?" should look
    #: in the audit log first; the brain dashboard's schedule detail
    #: page surfaces the disable event in the fire-history panel.
    #: Re-enable from the dashboard (or
    #: ``PATCH /schedules/{id} {"is_enabled": true}``) once the
    #: underlying bug is fixed.
    schedule_circuit_breaker_threshold: int = Field(
        default=5, ge=0, le=100,
    )
    #: Cadence for :class:`ScheduleCircuitBreakerWorker`. Each tick
    #: scans every enabled schedule with at least N recent fires
    #: and disables those past the threshold.
    schedule_circuit_breaker_interval_seconds: int = Field(
        default=60, ge=5, le=3600,
    )
    #: Retention for :class:`ScheduleFire` rows. After this many
    #: days the periodic prune worker drops them. 30 days at
    #: 10 schedules × 1 fire/min is ~430k rows - well under
    #: Postgres single-table comfort. Operators with longer
    #: forensic windows raise this; operators with high-frequency
    #: schedules + tight disk budgets lower it.
    schedule_fires_retention_days: int = Field(
        default=30, ge=1, le=3650,
    )

    # ------------------------------------------------------------------
    # TriggerSchedule client - brain calls scheduler.TriggerSchedule
    # ------------------------------------------------------------------
    #: When set, the dashboard's "fire now" route on a
    #: z4j-scheduler-managed schedule routes through the scheduler
    #: rather than dispatching directly. Format: ``host:port``,
    #: typically ``scheduler:7802``. Leave unset to keep the v1
    #: direct-dispatch path.
    scheduler_trigger_url: str | None = None
    #: Brain's client cert presented to the scheduler. Required when
    #: ``scheduler_trigger_url`` is set.
    scheduler_trigger_tls_cert: str | None = None
    scheduler_trigger_tls_key: str | None = None
    #: CA bundle used to validate the scheduler's server cert.
    scheduler_trigger_tls_ca: str | None = None

    # ------------------------------------------------------------------
    # Embedded scheduler sidecar (docs/SCHEDULER.md §21.3)
    # ------------------------------------------------------------------
    #: When True, brain spawns a ``z4j-scheduler serve`` subprocess
    #: in its own lifespan and supervises it (auto-restart on crash,
    #: graceful shutdown on brain exit). The subprocess talks to
    #: brain's gRPC endpoint over the loopback interface using
    #: PKI auto-minted at boot - no operator cert management
    #: required. Intended for the single-container homelab deploy
    #: where running a separate scheduler container would be
    #: needlessly heavy.
    #:
    #: When True, ``scheduler_grpc_enabled`` is implicitly forced
    #: True (the embedded subprocess needs the wire). The minted
    #: PKI overrides any operator-supplied
    #: ``scheduler_grpc_tls_*`` paths so embedded mode is
    #: self-contained.
    embedded_scheduler: bool = False
    #: Persistent directory for the auto-minted PKI.
    #:
    #: - ``None`` (the default) → brain resolves to
    #:   ``~/.z4j/embedded-pki/`` and writes the PEM bundle there.
    #:   The CA + cert pair survives brain restarts so the
    #:   scheduler's ``INSTANCE_ID`` stays stable across reboots and
    #:   audit-log forensics keep a coherent trail.
    #: - An explicit path → operator-managed location (e.g. a
    #:   secrets volume).
    #:
    #: v1.1.0 changed the default from a per-process tempdir to
    #: ``~/.z4j/embedded-pki/`` because audit rows for ``INSTANCE_ID
    #: =<hostname>-embedded`` were getting orphaned across brain
    #: restarts. The new default writes ~10 KB of PEMs per install
    #: and the bundle is regenerated automatically if the directory
    #: is wiped.
    embedded_scheduler_pki_dir: str | None = None
    #: Argv passed to the subprocess, after the implicit
    #: ``[sys.executable, "-m", "z4j_scheduler"]`` prefix. The
    #: default ``["serve"]`` runs the FastAPI + tick-engine. Tests
    #: override this to point at a fake binary.
    embedded_scheduler_argv: list[str] = Field(
        default_factory=lambda: ["serve"],
    )
    #: Maximum auto-restart attempts before the supervisor gives
    #: up and logs CRITICAL. ``0`` disables auto-restart entirely
    #: (a single crash is permanent). Operators wanting
    #: kubernetes-style "always restart" set this very high.
    embedded_scheduler_restart_max_attempts: int = Field(
        default=10, ge=0, le=10_000,
    )
    #: Backoff between auto-restart attempts. Doubles up to a
    #: 60-second cap.
    embedded_scheduler_restart_backoff_seconds: float = Field(
        default=2.0, ge=0.1, le=60.0,
    )
    #: Grace window for SIGTERM before SIGKILL during shutdown.
    #: The scheduler's own teardown takes a few seconds (cancel
    #: tick engine, drain dispatcher, close gRPC client) - 10s
    #: covers the slowest reasonable case while still bounding
    #: brain's overall shutdown time.
    embedded_scheduler_shutdown_grace_seconds: float = Field(
        default=10.0, ge=0.5, le=60.0,
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _enforce_min_secret_length(cls, data: Any) -> Any:
        """Reject secrets shorter than 32 bytes BEFORE Pydantic sees them.

        Runs in ``mode="before"`` so we never let the raw secret
        value reach Pydantic's field-level validator - Pydantic
        echoes ``input_value`` into its ValidationError messages,
        which would put a (presumably weak but still confidential)
        secret into the brain operator's stdout. We raise our own
        ValueError that names only the field.
        """
        if not isinstance(data, dict):
            return data
        for field_name in ("secret", "session_secret"):
            raw = data.get(field_name)
            if raw is None:
                continue
            value = (
                raw.get_secret_value()
                if isinstance(raw, SecretStr)
                else str(raw)
            )
            if len(value.encode("utf-8")) < 32:
                raise ValueError(
                    f"{field_name} must be at least 32 bytes long",
                )
        # Each entry in the rotation lists must independently meet
        # the 32-byte floor.
        # An attacker who could slip in a short "previous" secret
        # would otherwise downgrade the verification surface.
        for field_name in ("previous_secrets", "previous_session_secrets"):
            raw = data.get(field_name)
            if raw is None:
                continue
            value = (
                raw.get_secret_value()
                if isinstance(raw, SecretStr)
                else str(raw)
            )
            if not value.strip():
                continue
            for entry in value.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                if len(entry.encode("utf-8")) < 32:
                    raise ValueError(
                        f"every entry in {field_name} must be at "
                        f"least 32 bytes long",
                    )
        return data

    @model_validator(mode="before")
    @classmethod
    def _coerce_registry_backend_for_sqlite(cls, data: Any) -> Any:
        """Force ``registry_backend=local`` when the DB is SQLite.

        SQLite has no ``LISTEN/NOTIFY`` primitive, so
        ``postgres_notify`` is structurally impossible on a SQLite
        URL - the only sane backend is the in-process ``local`` hub.

        Coercing here (rather than failing loudly) lets
        ``pip install z4j && z4j serve`` work out of the
        box against the default SQLite DB without the operator having
        to also set ``Z4J_REGISTRY_BACKEND=local`` AND install the
        ``[postgres]`` extra just to get past the unconditional
        ``import asyncpg`` inside ``postgres_notify.py``.
        """
        if not isinstance(data, dict):
            return data
        db_url = data.get("database_url") or ""
        if isinstance(db_url, str) and db_url.startswith("sqlite"):
            data["registry_backend"] = "local"
        return data

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_openapi_setting(cls, data: Any) -> Any:
        """Map deprecated ``Z4J_OPENAPI_DOCS_ENABLED`` to the new
        ``Z4J_OPENAPI_VISIBILITY`` setting (1.6.3 security advisory).

        The pre-1.6.3 boolean exposed the schema to any anonymous
        caller when True (the default). 1.6.3 introduces a three-mode
        setting that defaults to ``"private"`` and gates the schema
        behind authentication. Operators who explicitly set the old
        boolean are honored with a translated value AND an annotation
        consumed by ``main.py`` to emit a deprecation WARN at startup.

        Mapping:
        - ``Z4J_OPENAPI_DOCS_ENABLED=true``  -> ``openapi_visibility="private"``
        - ``Z4J_OPENAPI_DOCS_ENABLED=false`` -> ``openapi_visibility="disabled"``
        - Unset (the new default path) -> use ``openapi_visibility`` directly

        The annotation is a sentinel stored on the model under
        ``_openapi_legacy_setting_used`` (private, not a field) so
        ``main.py._build_app`` can log a single WARN line at startup.
        """
        if not isinstance(data, dict):
            return data
        legacy = data.get("openapi_docs_enabled")
        if legacy is None:
            return data
        # If the operator set BOTH, prefer the new explicit setting
        # and log the conflict so they know to drop the deprecated one.
        explicit_new = "openapi_visibility" in data
        if not explicit_new:
            data["openapi_visibility"] = "private" if legacy else "disabled"
        # Mark for main.py startup logging. Pydantic does not preserve
        # arbitrary keys but we encode the marker via the visibility
        # value AND check for the deprecated env var presence on
        # startup anyway; see ``main.py`` for the WARN call site.
        return data

    def __init__(self, **values: Any) -> None:
        """Construct, validate, then run cross-field security checks.

        We deliberately do the security checks OUTSIDE Pydantic's
        validator pipeline. Pydantic's ``ValidationError`` always
        serialises ``input_value`` in its message - and for a
        Settings object that contains secrets, that means one
        misconfiguration would dump every value (including the
        secrets) into stdout. By calling ``super().__init__`` first
        and then doing the security checks ourselves, any
        :class:`ConfigError` we raise has a message we fully control
        and never includes the input dict.
        """
        super().__init__(**values)
        self._enforce_security_invariants()

    def _enforce_security_invariants(self) -> None:
        """Cross-field security checks. See :meth:`__init__`."""
        is_dev = self.environment == "dev"

        # CORS: never wildcard with credentials.
        if self.cors_allow_credentials and "*" in self.cors_origins:
            raise ConfigError(
                "cors_origins must not contain '*' when "
                "cors_allow_credentials is True",
            )

        # Production: allowed_hosts must be explicit.
        if not is_dev and not self.allowed_hosts:
            raise ConfigError(
                "allowed_hosts must be set in non-dev environments "
                "(host header is not validated otherwise)",
            )

        # Production: public_url should be https.
        # Escape hatch: ``allow_http_public_url=True`` bypasses the
        # check. ONLY for closed environments (private docker
        # network, CI fixtures, internal benchmarks) where the brain
        # is provably not reachable from anywhere a real user's
        # browser would land. Logged loudly at startup so an
        # operator who copies a test config into a real deploy sees
        # the warning.
        if (
            not is_dev
            and not self.public_url.startswith("https://")
            and not self.allow_http_public_url
        ):
            raise ConfigError(
                "public_url must use https:// in non-dev environments. "
                "If this is an internal-network test environment, set "
                "Z4J_ALLOW_HTTP_PUBLIC_URL=true to opt in (logged + "
                "audited).",
            )

        # Audit A6: strict validation of public_url content. Newlines,
        # embedded userinfo (``user@host``), and non-http(s) schemes
        # are rejected at settings-load time so the value used to
        # build invitation + password-reset links can never be an
        # attacker-controlled string that redirects users elsewhere.
        if any(ch in self.public_url for ch in ("\r", "\n", " ", "\t")):
            raise ConfigError(
                "public_url must not contain whitespace or newlines",
            )
        if "@" in self.public_url.split("://", 1)[-1].split("/", 1)[0]:
            raise ConfigError(
                "public_url must not contain embedded userinfo (user@host); "
                "that shape would redirect users to attacker-controlled "
                "hosts when emailed",
            )
        if not (
            self.public_url.startswith("http://")
            or self.public_url.startswith("https://")
        ):
            raise ConfigError(
                "public_url must start with http:// or https://",
            )

        # Database: require SSL for production Postgres URLs.
        if (
            self.require_db_ssl
            and not is_dev
            and self.database_url.startswith("postgresql+asyncpg://")
        ):
            url_lower = self.database_url.lower()
            if "sslmode=disable" in url_lower:
                raise ConfigError(
                    "database_url has sslmode=disable which is not "
                    "permitted when require_db_ssl is True",
                )
            if "sslmode=" not in url_lower:
                raise ConfigError(
                    "database_url must include sslmode=require (or "
                    "stricter) when require_db_ssl is True",
                )

        # Audit forwarder: URL without an HMAC secret would leave
        # the receiver unable to authenticate the source of a row.
        # The forwarder is an authenticated mirror; an unauthenticated
        # one is worse than no mirror because a downstream parser
        # might trust it implicitly. Fail fast at startup.
        # (v1.6 audit C4: simplified from a brittle double-negative
        # conditional to a single readable truthiness check.)
        audit_url_value: str = ""
        if self.audit_webhook_url is not None:
            audit_url_value = self.audit_webhook_url.get_secret_value().strip()
        if audit_url_value:
            audit_hmac_value: str = ""
            if self.audit_webhook_hmac_secret is not None:
                audit_hmac_value = (
                    self.audit_webhook_hmac_secret.get_secret_value().strip()
                )
            if not audit_hmac_value:
                raise ConfigError(
                    "audit_webhook_url is set but "
                    "audit_webhook_hmac_secret is not. Forwarding audit "
                    "rows without an HMAC signature would leave the "
                    "receiver unable to authenticate the source; set "
                    "Z4J_AUDIT_WEBHOOK_HMAC_SECRET to a >=32 byte "
                    "random string.",
                )
            if len(audit_hmac_value.encode("utf-8")) < 32:
                raise ConfigError(
                    "audit_webhook_hmac_secret must be at least 32 bytes "
                    "(use `python -c \"import secrets; "
                    "print(secrets.token_urlsafe(48))\"`).",
                )

    # ------------------------------------------------------------------
    # Rotation helpers.
    # Callers that VERIFY a token signed by an unknown-but-historical
    # secret use these helpers; callers that MINT new tokens always use
    # ``self.secret`` / ``self.session_secret`` directly so a rotated-
    # in secret is never re-introduced into the persistent store.
    # ------------------------------------------------------------------

    def all_secrets_for_verification(self) -> list[bytes]:
        """Return the master signing key plus any rotation-window keys.

        Order: current first, then previous (newest-first if the
        operator listed them that way). Callers should HMAC-verify
        against each in turn and accept the first match.
        """
        out: list[bytes] = [self.secret.get_secret_value().encode("utf-8")]
        out.extend(self._parse_secret_list(self.previous_secrets))
        return out

    def all_session_secrets_for_verification(self) -> list[bytes]:
        """Return the session key plus any rotation-window keys."""
        out: list[bytes] = [
            self.session_secret.get_secret_value().encode("utf-8"),
        ]
        out.extend(self._parse_secret_list(self.previous_session_secrets))
        return out

    @staticmethod
    def _parse_secret_list(raw: SecretStr | None) -> list[bytes]:
        if raw is None:
            return []
        text = raw.get_secret_value()
        if not text.strip():
            return []
        out: list[bytes] = []
        seen: set[str] = set()
        for entry in text.split(","):
            entry = entry.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            out.append(entry.encode("utf-8"))
        return out



    @field_validator("scheduler_grpc_cn_project_bindings", mode="before")
    @classmethod
    def _parse_cn_project_bindings(cls, v: Any) -> Any:
        """Parse the env-var JSON form into ``dict[str, list[str]]``.

        Operators set this via env (``Z4J_SCHEDULER_GRPC_CN_PROJECT_BINDINGS=
        '{"scheduler-1": ["acme"]}'``); pydantic-settings forwards the
        raw string here. We accept the parsed dict form too so the
        in-process ``Settings(...)`` test path still works without
        round-tripping through JSON.
        """
        if v is None or v == "":
            return {}
        if isinstance(v, str):
            import json  # noqa: PLC0415

            try:
                parsed = json.loads(v)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "scheduler_grpc_cn_project_bindings must be a JSON "
                    f"object mapping CN -> list of slugs; got {exc}",
                ) from exc
            v = parsed
        if not isinstance(v, dict):
            raise ValueError(
                "scheduler_grpc_cn_project_bindings must be a JSON "
                "object mapping CN -> list of slugs",
            )
        # Final shape coercion: every value must be a list of strings.
        for cn, slugs in v.items():
            if not isinstance(cn, str) or not cn:
                raise ValueError(
                    "scheduler_grpc_cn_project_bindings keys must be "
                    "non-empty strings (CNs)",
                )
            if not isinstance(slugs, list) or not all(
                isinstance(s, str) and s for s in slugs
            ):
                raise ValueError(
                    f"scheduler_grpc_cn_project_bindings[{cn!r}] must be "
                    "a list of non-empty project slugs",
                )
        return v

    @field_validator("database_url")
    @classmethod
    def _enforce_async_driver(cls, v: str) -> str:
        """Database URL must use the asyncpg driver.

        SQLAlchemy will silently fall back to a sync driver if a
        plain ``postgresql://`` URL is supplied, which then explodes
        at the first ``await session.execute(...)`` call with an
        unhelpful traceback. Catch it here.
        """
        if not (
            v.startswith("postgresql+asyncpg://")
            or v.startswith("sqlite+aiosqlite://")
        ):
            raise ValueError(
                "database_url must use postgresql+asyncpg:// "
                "(or sqlite+aiosqlite:// for tests)",
            )
        return v


__all__ = ["ConfigError", "Settings"]
