"""``/metrics`` Prometheus scrape endpoint.

Exposes application-level counters, gauges, and histograms for
Grafana dashboards. The endpoint is mounted at the root (NOT
under ``/api/v1``) so Prometheus scrape configs use a stable path.

Authorization: optional bearer-token guard. Set
``Z4J_METRICS_AUTH_TOKEN`` and the endpoint requires
``Authorization: Bearer <token>``; leave it unset to keep the
legacy "open" behaviour, with a boot-time warning reminding the
operator to either set a token or block ``/metrics`` at the
reverse proxy (Caddy / nginx). Audit 2026-04-24 Medium-1.

Metric naming follows the Prometheus convention:
``z4j_{component}_{metric}_{unit}``.

These metrics are designed to be compatible with common Grafana
dashboard patterns used by Flower and Celery monitoring setups.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from z4j_brain.api.deps import get_settings

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

router = APIRouter(tags=["metrics"])

# ---------------------------------------------------------------------------
# Metric registry
# ---------------------------------------------------------------------------
#
# Brain-private registry so tests can construct multiple create_app()
# instances without "metric already registered" exceptions.

registry = CollectorRegistry()

# -- Events --

z4j_events_ingested_total = Counter(
    "z4j_events_ingested_total",
    "Total events ingested from agents.",
    labelnames=("project", "engine", "kind"),
    registry=registry,
)

# -- Tasks --

z4j_tasks_total = Counter(
    "z4j_tasks_total",
    "Total tasks observed (by final state).",
    labelnames=("project", "task_name", "state"),
    registry=registry,
)

z4j_task_duration_seconds = Histogram(
    "z4j_task_duration_seconds",
    "Task execution duration in seconds.",
    labelnames=("project", "task_name"),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
    registry=registry,
)

# -- Commands --

z4j_commands_total = Counter(
    "z4j_commands_total",
    "Total commands dispatched to agents.",
    labelnames=("project", "action", "status"),
    registry=registry,
)

#: Counter for command results that arrived AFTER the command's
#: row had already transitioned to a terminal state (almost
#: always: the timeout sweeper marked it TIMEOUT before the
#: agent's late ``command_result`` arrived). Operators can graph
#: this against ``z4j_commands_total`` to spot
#: ``command_timeout_seconds`` mis-tuning. R3 finding M7.
z4j_command_late_results_total = Counter(
    "z4j_command_late_results_total",
    "Command results that arrived after the row was already terminal "
    "(usually because timeout_sweeper won the race).",
    labelnames=("status",),
    registry=registry,
)

#: Gauge for in-memory state held by the brain process - sessions
#: in the long-poll signer registry, throttle entries, dashboard
#: subscriptions, etc. Lets operators see brain-restart drops
#: instead of guessing (R3 finding M8). Subsystems register a
#: zero-arg callable via :func:`register_inmemory_subsystem`; the
#: gauge is sampled at scrape time.
z4j_inmemory_state_items = Gauge(
    "z4j_inmemory_state_items",
    "Items held in process-local in-memory state by subsystem.",
    labelnames=("subsystem",),
    registry=registry,
)

_inmemory_subsystems: dict[str, "Callable[[], int]"] = {}


def register_inmemory_subsystem(name: str, count_fn: "Callable[[], int]") -> None:
    """Register a subsystem to be reflected in
    ``z4j_inmemory_state_items{subsystem=name}``.

    The callable is invoked at every Prometheus scrape; it should
    be cheap (read a dict ``len()``, not a DB query).
    """
    _inmemory_subsystems[name] = count_fn


def _refresh_inmemory_gauges() -> None:
    for name, fn in _inmemory_subsystems.items():
        try:
            z4j_inmemory_state_items.labels(subsystem=name).set(fn())
        except Exception:  # noqa: BLE001
            record_swallowed("metrics", f"inmemory_{name}")

# -- Agents and workers --

z4j_agents_online = Gauge(
    "z4j_agents_online",
    "Number of agents currently connected.",
    labelnames=("project",),
    registry=registry,
)

z4j_workers_online = Gauge(
    "z4j_workers_online",
    "Number of workers currently online.",
    labelnames=("project",),
    registry=registry,
)

# -- Queues --

z4j_queue_depth = Gauge(
    "z4j_queue_depth",
    "Number of pending messages in a queue.",
    labelnames=("project", "queue", "engine"),
    registry=registry,
)

# -- WebSocket --

z4j_ws_connections = Gauge(
    "z4j_ws_connections",
    "Number of live WebSocket connections held by this worker.",
    registry=registry,
)

# -- Database pool --

z4j_db_pool_size = Gauge(
    "z4j_db_pool_size",
    "Configured size of the SQLAlchemy connection pool.",
    registry=registry,
)

z4j_db_pool_checked_out = Gauge(
    "z4j_db_pool_checked_out",
    "Number of pool connections currently checked out.",
    registry=registry,
)

# -- Notifications --

z4j_notifications_sent_total = Counter(
    "z4j_notifications_sent_total",
    "Total notification deliveries attempted.",
    labelnames=("project", "channel_type", "status"),
    registry=registry,
)

z4j_notifications_cooldown_skipped_total = Counter(
    "z4j_notifications_cooldown_skipped_total",
    "Number of subscription dispatches skipped because the cooldown "
    "window had not elapsed (the conditional UPDATE returned no rows).",
    labelnames=("project", "trigger"),
    registry=registry,
)

# -- Reliability: intentional exception swallows --
#
# The brain has a small set of sites where a broad exception catch
# is the right call (WebSocket close during shutdown, Prometheus
# metric updates, asyncpg teardown) because the alternative is
# propagating a shutdown-time failure that the caller has no way
# to act on. Every such site increments this counter so a spike is
# visible in Grafana even though the individual call logged at
# debug level. Labelled by module so operators can pinpoint which
# subsystem is degrading.
z4j_swallowed_exceptions_total = Counter(
    "z4j_swallowed_exceptions_total",
    "Intentional exception swallows at I/O boundaries (metric "
    "updates, WebSocket close during shutdown, etc.). A sustained "
    "non-zero rate signals a subsystem in trouble even when no "
    "error-level log line fires.",
    labelnames=("module", "site"),
    registry=registry,
)


def record_swallowed(module: str, site: str) -> None:
    """Best-effort counter bump, itself catching any bookkeeping
    failure. Used from ``except Exception: pass`` sites so ops gets
    a signal without the caller having to think about import order
    or registry-not-initialised races.
    """
    try:
        z4j_swallowed_exceptions_total.labels(module=module, site=site).inc()
    except Exception:  # noqa: BLE001
        # The counter infra itself is broken; nothing sensible to do.
        return


# -- Self-watch (brain's own background tasks) --
#
# 1.2.2 introduces the audit-log retention sweeper and SQLite WAL
# checkpoint task. Both are silent loops that operators can't see
# from the outside. These metrics expose their state so a Grafana
# alert can fire if either stalls or starts logging errors.
#
# Audit fix CRIT-5: every self-watch metric is a Gauge sampled
# at scrape time. The earlier design used a synthetic-delta
# Counter which had two flaws:
#   1) Multiple Prometheus replicas scraping the same brain would
#      double-count the delta against the same shared baseline.
#   2) Test fixtures that call ``register_self_watch_provider``
#      twice (e.g. brain_app fixture + dedicated test) carried
#      stale baseline state across test cases.
# Gauges that mirror the underlying singleton attributes
# (``total_deleted``, ``last_pages_checkpointed``, etc.) are
# scrape-idempotent and have no in-process baseline state.

z4j_audit_retention_pruned_total = Gauge(
    "z4j_audit_retention_pruned_total",
    "Cumulative audit_log rows deleted by the retention sweeper "
    "since this brain process started (resets on restart).",
    registry=registry,
)

z4j_audit_retention_last_run_timestamp = Gauge(
    "z4j_audit_retention_last_run_timestamp",
    "Unix timestamp of the most recent audit-log retention sweep "
    "(0 if the sweeper has never run a successful pass).",
    registry=registry,
)

z4j_audit_retention_last_deleted = Gauge(
    "z4j_audit_retention_last_deleted",
    "Rows deleted in the most recent audit-log retention sweep "
    "pass.",
    registry=registry,
)

z4j_wal_checkpoint_pages_last = Gauge(
    "z4j_wal_checkpoint_pages_last",
    "Pages checkpointed in the most recent WAL checkpoint pass "
    "(SQLite-only; -1 on non-WAL or unsupported response shape).",
    registry=registry,
)

z4j_wal_checkpoint_last_run_timestamp = Gauge(
    "z4j_wal_checkpoint_last_run_timestamp",
    "Unix timestamp of the most recent WAL checkpoint pass "
    "(0 on Postgres deployments, or before the task has run once).",
    registry=registry,
)

z4j_background_task_error_active = Gauge(
    "z4j_background_task_error_active",
    "1 if the named background task's most recent pass failed, "
    "0 otherwise. Cleared when a subsequent pass succeeds.",
    labelnames=("task",),
    registry=registry,
)

#: Sampled at scrape time. Each callable returns a dict of:
#: ``{"audit_pruned_total": int, "audit_last_run_at": datetime|None,
#:    "audit_last_deleted": int, "audit_error": str|None,
#:    "wal_pages_last": int, "wal_last_run_at": datetime|None,
#:    "wal_error": str|None}``.
#: Registered by ``main.py`` once the singletons exist.
_self_watch_provider: "Callable[[], dict] | None" = None


def register_self_watch_provider(provider: "Callable[[], dict]") -> None:
    """Register the callable that supplies self-watch state.

    The provider is invoked at scrape time and should be cheap
    (read instance attributes, no DB queries).
    """
    global _self_watch_provider
    _self_watch_provider = provider


def _refresh_self_watch_gauges() -> None:
    """Pull the latest state from the registered provider."""
    if _self_watch_provider is None:
        return
    try:
        snap = _self_watch_provider()
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "self_watch_provider")
        return

    # Audit-retention gauges
    audit_total = int(snap.get("audit_pruned_total") or 0)
    try:
        z4j_audit_retention_pruned_total.set(audit_total)
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "audit_pruned_set")

    audit_last_deleted = int(snap.get("audit_last_deleted") or 0)
    try:
        z4j_audit_retention_last_deleted.set(audit_last_deleted)
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "audit_last_deleted_set")

    audit_last = snap.get("audit_last_run_at")
    try:
        z4j_audit_retention_last_run_timestamp.set(
            audit_last.timestamp() if audit_last is not None else 0,
        )
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "audit_last_run_set")

    audit_err_active = 1 if snap.get("audit_error") else 0
    try:
        z4j_background_task_error_active.labels(
            task="audit_retention",
        ).set(audit_err_active)
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "audit_err_set")

    # WAL-checkpoint gauges
    wal_pages = snap.get("wal_pages_last")
    if wal_pages is not None:
        try:
            z4j_wal_checkpoint_pages_last.set(int(wal_pages))
        except Exception:  # noqa: BLE001
            record_swallowed("metrics", "wal_pages_set")

    wal_last = snap.get("wal_last_run_at")
    try:
        z4j_wal_checkpoint_last_run_timestamp.set(
            wal_last.timestamp() if wal_last is not None else 0,
        )
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "wal_last_run_set")

    wal_err_active = 1 if snap.get("wal_error") else 0
    try:
        z4j_background_task_error_active.labels(
            task="wal_checkpoint",
        ).set(wal_err_active)
    except Exception:  # noqa: BLE001
        record_swallowed("metrics", "wal_err_set")


def _check_metrics_auth(request: Request, settings: "Settings") -> None:
    """Enforce bearer-token auth on ``/metrics`` (fail-secure default).

    Policy (as of 1.0.13):

    - ``settings.metrics_public == True`` -> serve without auth. This
      is the explicit opt-in path for closed-network deployments where
      Prometheus scrapes from a trusted LAN / localhost. Operator set
      ``Z4J_METRICS_PUBLIC=1``; a loud WARNING logged at startup names
      the risk.
    - ``settings.metrics_auth_token`` set -> require
      ``Authorization: Bearer <token>``. The token is either
      operator-provided (``Z4J_METRICS_AUTH_TOKEN``) or auto-minted on
      first boot and persisted to ``~/.z4j/secret.env`` alongside
      ``Z4J_SECRET`` / ``Z4J_SESSION_SECRET``.
    - neither -> return 401 with an instructional detail pointing at
      ``z4j metrics-token`` and ``Z4J_METRICS_PUBLIC``. This branch is
      unreachable on a normally-bootstrapped install because the CLI
      entry point auto-mints; it exists for defense-in-depth in test
      rigs or custom bootstrappers that skip the CLI.

    The prior policy (1.0.11 / 1.0.12) was the inverse: unset token
    meant "serve without auth" and just logged a warning. Every fresh
    ``pip install z4j && z4j serve`` exposed project IDs, queue names,
    task names, and in-memory-state counters to anyone who could reach
    the endpoint - a major default-insecure footgun. Audit follow-up
    to 2026-04-24 Medium-1.
    """
    if settings.metrics_public:
        return

    expected = settings.metrics_auth_token
    if expected is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "metrics: not configured. Either set Z4J_METRICS_AUTH_TOKEN "
                "and scrape with `Authorization: Bearer <token>`, or set "
                "Z4J_METRICS_PUBLIC=1 for closed-network deployments. "
                "Run `z4j metrics-token` to print the auto-minted token."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    header = request.headers.get("authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        raise HTTPException(
            status_code=401,
            detail="metrics: authorization required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(
        supplied.encode("utf-8"),
        expected.get_secret_value().encode("utf-8"),
    ):
        raise HTTPException(
            status_code=401,
            detail="metrics: invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/metrics", response_class=Response)
async def metrics_endpoint(
    request: Request,
    settings: "Settings" = Depends(get_settings),
) -> Response:
    """Render the brain's metrics in Prometheus text format.

    Refreshes lazy in-memory state gauges before rendering so a
    Prometheus scrape gets a fresh ``z4j_inmemory_state_items``
    snapshot without forcing every subsystem to update on every
    mutation (R3 finding M8).
    """
    _check_metrics_auth(request, settings)
    _refresh_inmemory_gauges()
    _refresh_self_watch_gauges()
    body = generate_latest(registry)
    return Response(content=body, media_type=CONTENT_TYPE_LATEST)


__all__ = [
    "record_swallowed",
    "register_inmemory_subsystem",
    "register_self_watch_provider",
    "registry",
    "router",
    "z4j_agents_online",
    "z4j_audit_retention_last_deleted",
    "z4j_audit_retention_last_run_timestamp",
    "z4j_audit_retention_pruned_total",
    "z4j_background_task_error_active",
    "z4j_command_late_results_total",
    "z4j_commands_total",
    "z4j_db_pool_checked_out",
    "z4j_db_pool_size",
    "z4j_events_ingested_total",
    "z4j_inmemory_state_items",
    "z4j_notifications_cooldown_skipped_total",
    "z4j_notifications_sent_total",
    "z4j_queue_depth",
    "z4j_swallowed_exceptions_total",
    "z4j_task_duration_seconds",
    "z4j_tasks_total",
    "z4j_wal_checkpoint_last_run_timestamp",
    "z4j_wal_checkpoint_pages_last",
    "z4j_workers_online",
    "z4j_ws_connections",
]
