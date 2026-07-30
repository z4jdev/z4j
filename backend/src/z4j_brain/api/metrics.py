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

Multi-worker aggregation: ``z4j serve`` defaults to
min(4, cpu) uvicorn worker PROCESSES, each with its own copy of the
private registry below, so a load-balanced scrape would otherwise
see only one worker's counters (incident counters increment in one
process and appear missing or reset from another). The serve path
(``cli.py``) exports ``PROMETHEUS_MULTIPROC_DIR`` before uvicorn
spawns the workers, flipping prometheus_client into multiprocess
mode: every process writes its values through to mmap files under
that directory, and the endpoint below aggregates ALL processes at
scrape time via ``multiprocess.MultiProcessCollector``. When the
env var is unset (single worker, tests, library embedding) the
private in-process registry is rendered exactly as before."""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

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
#
# Under multiprocess mode (PROMETHEUS_MULTIPROC_DIR set before this
# module is imported) the metric objects below transparently write
# through to shared mmap files as well; the private registry then
# only carries this process's view and the scrape endpoint switches
# to the MultiProcessCollector aggregate instead.

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
#: ``command_timeout_seconds`` mis-tuning.
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
#: Instead of guessing. Subsystems register a
#: zero-arg callable via :func:`register_inmemory_subsystem`; the
#: gauge is sampled at scrape time.
z4j_inmemory_state_items = Gauge(
    "z4j_inmemory_state_items",
    "Items held in process-local in-memory state by subsystem.",
    labelnames=("subsystem",),
    registry=registry,
    # Multiprocess: the state is process-local and disjoint (each
    # worker owns its own signer sessions, throttle buckets, etc.),
    # so the brain-wide total is the sum over live workers. Values
    # refresh only in the worker handling a scrape; the others
    # contribute their last-scrape sample (bounded staleness under
    # a load-balanced scrape rotation).
    multiprocess_mode="livesum",
)

_inmemory_subsystems: dict[str, Callable[[], int]] = {}


def register_inmemory_subsystem(name: str, count_fn: Callable[[], int]) -> None:
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
        except Exception:
            record_swallowed("metrics", f"inmemory_{name}")


# -- Agents and workers --

z4j_agents_online = Gauge(
    "z4j_agents_online",
    "Number of agents currently connected.",
    labelnames=("project",),
    registry=registry,
    # Multiprocess: ``fleet_snapshot()`` (both Local and
    # PostgresNotify registry variants) reports only THIS process's
    # connections, and each agent WebSocket lives in exactly one
    # uvicorn worker, so the per-process views are disjoint and
    # summing live workers yields the whole-brain count without
    # double-counting. See ``_refresh_fleet_gauges`` for the
    # departed-project zeroing that keeps this sum honest.
    multiprocess_mode="livesum",
)

z4j_workers_online = Gauge(
    "z4j_workers_online",
    "Number of workers currently online.",
    labelnames=("project",),
    registry=registry,
    # Multiprocess: livesum for the same disjoint-per-process reason
    # as ``z4j_agents_online`` above.
    multiprocess_mode="livesum",
)


#: Provider for the agents/workers gauges. Registered by ``main.py``
#: once the BrainRegistry exists. Returns
#: ``{"agents": {project_id_str: count, ...},
#:    "workers": {project_id_str: count, ...}}``.
#: Sampled at scrape time so per-WS connect/disconnect does not need
#: a hot-path metric update.
_fleet_gauge_provider: Callable[[], dict[str, dict[str, int]]] | None = None


def register_fleet_gauge_provider(
    provider: Callable[[], dict[str, dict[str, int]]],
) -> None:
    """Register the callable that reports current agent + worker
    counts per project. The provider is invoked at every Prometheus
    scrape; it should be cheap (read in-memory registry state, not a
    DB query)."""
    global _fleet_gauge_provider  # noqa: PLW0603  module-level singleton lazy-init
    _fleet_gauge_provider = provider


#: Projects present in this process's previous fleet snapshot, per
#: stream. Needed for multiprocess mode: ``Gauge.clear`` only drops
#: the in-process label children, it does NOT erase the mmap-file
#: entries that ``MultiProcessCollector`` aggregates, so a departed
#: project must be explicitly written as 0 or its stale count would
#: inflate the livesum forever. Process-local by design; each worker
#: only zeroes labels it wrote itself.
_fleet_prev_projects: dict[str, set[str]] = {"agents": set(), "workers": set()}


def _refresh_fleet_gauges() -> None:
    """Sample agents/workers per project at scrape time.

    Single-process path: clears prior labels first so a project that
    goes from N agents to zero drops out of the output rather than
    showing the stale N. ``Gauge.clear`` drops every label
    permutation, then the loop re-sets only the projects with
    current activity.

    Multiprocess path (``PROMETHEUS_MULTIPROC_DIR`` set): ``clear``
    does not touch the shared mmap files, so departed projects are
    additionally zeroed by explicit ``set(0)`` writes; they render
    as 0 (not absent) in the aggregated output. The zeroing also
    runs on the single-process path, where the subsequent ``clear``
    drops the label entirely, keeping that output unchanged.
    """
    if _fleet_gauge_provider is None:
        return
    try:
        snapshot = _fleet_gauge_provider()
    except Exception:
        record_swallowed("metrics", "fleet_gauges")
        return
    try:
        agents = snapshot.get("agents", {})
        workers = snapshot.get("workers", {})
        for project in _fleet_prev_projects["agents"] - set(agents):
            z4j_agents_online.labels(project=project).set(0)
        for project in _fleet_prev_projects["workers"] - set(workers):
            z4j_workers_online.labels(project=project).set(0)
        z4j_agents_online.clear()
        z4j_workers_online.clear()
        for project, count in agents.items():
            z4j_agents_online.labels(project=project).set(int(count))
        for project, count in workers.items():
            z4j_workers_online.labels(project=project).set(int(count))
        _fleet_prev_projects["agents"] = set(agents)
        _fleet_prev_projects["workers"] = set(workers)
    except Exception:
        record_swallowed("metrics", "fleet_gauges_apply")


# -- Queues --

z4j_queue_depth = Gauge(
    "z4j_queue_depth",
    "Number of pending messages in a queue.",
    labelnames=("project", "queue", "engine"),
    registry=registry,
    # Multiprocess: a broker queue's depth is a fleet-wide fact
    # reported by an agent heartbeat to whichever uvicorn worker
    # holds that agent's connection. Summing would double-count
    # after an agent reconnects to a different worker (the old
    # worker's mmap entry lingers); the most recent write is the
    # freshest truth regardless of which process received it.
    multiprocess_mode="mostrecent",
)

# -- WebSocket --

z4j_ws_connections = Gauge(
    "z4j_ws_connections",
    "Number of live WebSocket connections held by this worker.",
    registry=registry,
    # Multiprocess: connection counts are per-process and disjoint;
    # summing live workers gives the brain-wide total of live
    # WebSocket connections.
    multiprocess_mode="livesum",
)

# -- Database pool + connection-level health (1.5.1 leak-fix visibility) --
#
# These gauges let operators verify the asyncpg memory hygiene in
# their own deployments after upgrading from 1.5.0. The same signals
# we used to find the leak in the lab are exposed here so a Grafana
# panel can replicate the diagnosis. See docs/perf/1.5.1-grafana-
# dashboard.json for an importable dashboard.

z4j_db_pool_size = Gauge(
    "z4j_db_pool_size",
    "Configured size of the SQLAlchemy connection pool. "
    "Rises only when ``pool_size`` setting changes; useful baseline.",
    registry=registry,
    # Multiprocess: every uvicorn worker owns an independent pool, so
    # the brain's total configured capacity against the database (the
    # number that matters vs Postgres ``max_connections``) is the sum
    # across live workers, not one worker's ``pool_size``.
    multiprocess_mode="livesum",
)

z4j_db_pool_checked_out = Gauge(
    "z4j_db_pool_checked_out",
    "Number of pool connections currently checked out (in active "
    "use by handlers/workers). Steady-state under burst load is a "
    "key indicator of contention; should be << pool_size.",
    registry=registry,
    # Multiprocess: checked-out connections are per-process and
    # disjoint; sum over live workers is the brain-wide in-use count.
    # Refreshed at scrape time by the scraped worker only, so other
    # workers contribute their last-scrape sample.
    multiprocess_mode="livesum",
)

z4j_brain_rss_bytes = Gauge(
    "z4j_brain_rss_bytes",
    "Brain process RSS in bytes, sampled at scrape time from "
    "/proc/self/status. 0 on non-Linux. Watch the slope under "
    "sustained load -- a flat line or slow growth means the 1.5.1 "
    "leak fix is working; rapid growth indicates either an unbounded "
    "cache (tune ``Z4J_DATABASE_STATEMENT_CACHE_SIZE``) or a regression.",
    registry=registry,
    # Multiprocess: RSS is inherently per-process; sum over live
    # workers is the brain's total memory footprint, which is what
    # capacity dashboards actually watch.
    multiprocess_mode="livesum",
)

#: Counter incremented when a Postgres deadlock surfaces through
#: asyncpg/SQLAlchemy. Populated via a SQLAlchemy
#: ``handle_error`` event listener registered at engine creation.
#: A sustained non-zero rate under load indicates lock-order races
#: on write paths -- see 1.5.1 workers/queues sort fixes for the
#: pattern. Pre-1.5.1 brains under sustained 200 t/s saw ~140
#: deadlocks per 5min burst; post-1.5.1 with cache=50 default this
#: should be ~0.
z4j_postgres_deadlocks_total = Counter(
    "z4j_postgres_deadlocks_total",
    "Total Postgres DeadlockDetectedError instances observed via "
    "asyncpg/SQLAlchemy in this brain process lifetime.",
    registry=registry,
)


def _read_linux_rss_bytes() -> int:
    """Sample brain process RSS from /proc/self/status.

    Returns 0 on non-Linux (Windows dev machines, macOS) so the
    gauge is harmless to scrape there. Linux containers (the
    production target) always have /proc; the read is sub-millisecond.
    """
    try:
        with Path("/proc/self/status").open() as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    # "VmRSS:    123456 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return 0


#: Provider for pool gauges. Populated by ``main.py`` once the
#: ``DatabaseManager`` exists. Returns ``(pool_size, checked_out)``.
_pool_gauge_provider: Callable[[], tuple[int, int]] | None = None


def register_pool_gauge_provider(
    provider: Callable[[], tuple[int, int]],
) -> None:
    """Register the callable that reports pool size + checked-out count."""
    global _pool_gauge_provider  # noqa: PLW0603  module-level singleton lazy-init
    _pool_gauge_provider = provider


def _refresh_leak_visibility_gauges() -> None:
    """1.5.1: refresh the leak-visibility gauges at scrape time.

    All four gauges are cheap to sample (one /proc read + one
    pool-attribute read). Errors are swallowed via
    ``record_swallowed`` so a transient hiccup never breaks the
    ``/metrics`` response.
    """
    # RSS gauge -- pure file read, no DB hit.
    try:
        z4j_brain_rss_bytes.set(_read_linux_rss_bytes())
    except Exception:
        record_swallowed("metrics", "rss_gauge")
    # Pool gauges -- read in-memory pool state via the registered provider.
    if _pool_gauge_provider is not None:
        try:
            size, checked_out = _pool_gauge_provider()
            z4j_db_pool_size.set(size)
            z4j_db_pool_checked_out.set(checked_out)
        except Exception:
            record_swallowed("metrics", "pool_gauges")


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

# -- Automation / scheduler reliability --
#
# A brain-side misfire (a schedule that should have fired but did not,
# usually because its scheduler is dead or partitioned) is the headline
# A4 signal. It writes an audit row, but operators alert on metrics, so
# every detected misfire also bumps this counter.
z4j_scheduler_misfires_detected_total = Counter(
    "z4j_scheduler_misfires_detected_total",
    "Schedules the brain detected as misfired (expected fire is past the "
    "grace window). A sustained non-zero rate means a scheduler is dead, "
    "partitioned, or badly behind.",
    labelnames=("project",),
    registry=registry,
)

# A confirmed agent-offline episode (no heartbeat past the offline
# timeout + alert grace) is the brain-side emit for the worker.offline
# trigger. It writes an audit row, but operators alert on metrics, so
# every detected episode also bumps this counter.
z4j_agents_offline_detected_total = Counter(
    "z4j_agents_offline_detected_total",
    "Agent-offline episodes the brain confirmed (no heartbeat past the "
    "offline timeout + alert grace). Each episode counts once, however "
    "long the agent stays down.",
    labelnames=("project",),
    registry=registry,
)

# One increment per automation rule action execution (including dry-run
# and failsafe-skipped ones -- the outcome label distinguishes them).
# Labelled by project + action type + outcome, NOT by rule: rule ids are
# unbounded cardinality, and per-rule detail lives in the HMAC-chained
# ``automation.rule.fired`` audit rows this counter mirrors.
z4j_automation_rule_fires_total = Counter(
    "z4j_automation_rule_fires_total",
    "Automation rule action executions, by action type and outcome "
    "(executed / dry_run / skipped_failsafe / failed / ...).",
    labelnames=("project", "action", "outcome"),
    registry=registry,
)

# A rule's rolling-window circuit breaker tripping into notify-only
# failsafe mode. Mirrors the ``automation.rule.circuit_tripped`` audit
# row; operators alert on this.
z4j_automation_circuit_trips_total = Counter(
    "z4j_automation_circuit_trips_total",
    "Automation rule circuit-breaker trips (rule downgraded to notify-only failsafe until reset).",
    labelnames=("project",),
    registry=registry,
)

# Automation firings the frame router had to DROP (the per-connection
# pending-automation set was full under an event flood). Unlike a
# notification, a dropped firing is permanent, so this is the signal that
# automation silently stopped acting for a project.
z4j_automation_firings_dropped_total = Counter(
    "z4j_automation_firings_dropped_total",
    "Automation firings dropped before dispatch (pending queue full). A "
    "permanent drop -- a sustained rate means automation is shedding load.",
    labelnames=("project", "reason"),
    registry=registry,
)

# Notify actions suppressed by the per-rule coalesce window (a distinct-
# event flood that would otherwise fan out one notification per event per
# member). The first alert in each window still goes out; this counts the
# ones folded into it.
z4j_automation_notify_coalesced_total = Counter(
    "z4j_automation_notify_coalesced_total",
    "Automation notify actions suppressed by the per-rule coalesce window.",
    labelnames=("project",),
    registry=registry,
)

# Automation firings captured to the durable outbox because they could not
# be dispatched inline (pending queue full), to be replayed by the drain
# worker. Pairs with z4j_automation_firings_dropped_total: enqueued means
# recoverable, dropped means lost.
z4j_automation_outbox_enqueued_total = Counter(
    "z4j_automation_outbox_enqueued_total",
    "Automation firings persisted to the durable outbox for later replay.",
    labelnames=("project", "trigger"),
    registry=registry,
)

# schedule_fires partition-manager failures. reason="default_blocked" is the
# serious one: a day's rows already sit in the DEFAULT partition, so its
# daily partition can never be created and retention-by-DROP cannot reclaim
# it until DEFAULT is cleared. A sustained non-zero default_blocked rate is
# an alert.
z4j_schedule_fires_partition_failures_total = Counter(
    "z4j_schedule_fires_partition_failures_total",
    "schedule_fires partition create/drop operations that failed. "
    "reason=default_blocked means a day is un-partitionable because rows "
    "for it are stuck in the DEFAULT partition (retention-by-DROP blocked).",
    labelnames=("op", "reason"),
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
    except Exception:
        # The counter infra itself is broken; nothing sensible to do.
        return


# -- Self-watch (brain's own background tasks) --
#
# 1.2.2 introduces the audit-log retention sweeper and SQLite WAL
# checkpoint task. Both are silent loops that operators can't see
# from the outside. These metrics expose their state so a Grafana
# alert can fire if either stalls or starts logging errors.
#
# Every self-watch metric is a Gauge sampled
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
    # Multiprocess: every worker runs its own sweeper against the
    # shared DB and deletes disjoint rows, so cumulative work is the
    # sum. Deliberately NOT the live variant: a dead worker's
    # deletions really happened and must stay in the run's total (a
    # restarted worker starts a fresh per-PID series at 0, so the
    # sum stays monotone within one serve run).
    multiprocess_mode="sum",
)

z4j_audit_retention_last_run_timestamp = Gauge(
    "z4j_audit_retention_last_run_timestamp",
    "Unix timestamp of the most recent audit-log retention sweep "
    "(0 if the sweeper has never run a successful pass).",
    registry=registry,
    # Multiprocess: "when did a sweep last happen brain-wide" is the
    # max across workers. Non-live on purpose: a dead worker's
    # timestamp records a run that really happened.
    multiprocess_mode="max",
)

z4j_audit_retention_last_deleted = Gauge(
    "z4j_audit_retention_last_deleted",
    "Rows deleted in the most recent audit-log retention sweep pass.",
    registry=registry,
    # Multiprocess: "the most recent pass" is whichever worker wrote
    # last; sum or max would blend rows from different passes.
    multiprocess_mode="mostrecent",
)

z4j_wal_checkpoint_pages_last = Gauge(
    "z4j_wal_checkpoint_pages_last",
    "Pages checkpointed in the most recent WAL checkpoint pass "
    "(SQLite-only; -1 on non-WAL or unsupported response shape).",
    registry=registry,
    # Multiprocess: last-pass semantics, same reasoning as
    # ``z4j_audit_retention_last_deleted``.
    multiprocess_mode="mostrecent",
)

z4j_wal_checkpoint_last_run_timestamp = Gauge(
    "z4j_wal_checkpoint_last_run_timestamp",
    "Unix timestamp of the most recent WAL checkpoint pass "
    "(0 on Postgres deployments, or before the task has run once).",
    registry=registry,
    # Multiprocess: most-recent-run semantics, same reasoning as
    # ``z4j_audit_retention_last_run_timestamp``.
    multiprocess_mode="max",
)

z4j_background_task_error_active = Gauge(
    "z4j_background_task_error_active",
    "1 if the named background task's most recent pass failed, "
    "0 otherwise. Cleared when a subsequent pass succeeds.",
    labelnames=("task",),
    registry=registry,
    # Multiprocess: alerting semantics -- raise if ANY worker's most
    # recent pass failed. Non-live on purpose: a worker that died
    # while failing keeps the alert raised for the rest of the serve
    # run instead of silently clearing it when its PID disappears.
    multiprocess_mode="max",
)

#: Sampled at scrape time. Each callable returns a dict of:
#: ``{"audit_pruned_total": int, "audit_last_run_at": datetime|None,
#:    "audit_last_deleted": int, "audit_error": str|None,
#:    "wal_pages_last": int, "wal_last_run_at": datetime|None,
#:    "wal_error": str|None}``.
#: Registered by ``main.py`` once the singletons exist.
_self_watch_provider: Callable[[], dict] | None = None


def register_self_watch_provider(provider: Callable[[], dict]) -> None:
    """Register the callable that supplies self-watch state.

    The provider is invoked at scrape time and should be cheap
    (read instance attributes, no DB queries).
    """
    global _self_watch_provider  # noqa: PLW0603  module-level singleton lazy-init
    _self_watch_provider = provider


def _refresh_self_watch_gauges() -> None:
    """Pull the latest state from the registered provider."""
    if _self_watch_provider is None:
        return
    try:
        snap = _self_watch_provider()
    except Exception:
        record_swallowed("metrics", "self_watch_provider")
        return

    # Audit-retention gauges
    audit_total = int(snap.get("audit_pruned_total") or 0)
    try:
        z4j_audit_retention_pruned_total.set(audit_total)
    except Exception:
        record_swallowed("metrics", "audit_pruned_set")

    audit_last_deleted = int(snap.get("audit_last_deleted") or 0)
    try:
        z4j_audit_retention_last_deleted.set(audit_last_deleted)
    except Exception:
        record_swallowed("metrics", "audit_last_deleted_set")

    audit_last = snap.get("audit_last_run_at")
    try:
        z4j_audit_retention_last_run_timestamp.set(
            audit_last.timestamp() if audit_last is not None else 0,
        )
    except Exception:
        record_swallowed("metrics", "audit_last_run_set")

    audit_err_active = 1 if snap.get("audit_error") else 0
    try:
        z4j_background_task_error_active.labels(
            task="audit_retention",
        ).set(audit_err_active)
    except Exception:
        record_swallowed("metrics", "audit_err_set")

    # WAL-checkpoint gauges
    wal_pages = snap.get("wal_pages_last")
    if wal_pages is not None:
        try:
            z4j_wal_checkpoint_pages_last.set(int(wal_pages))
        except Exception:
            record_swallowed("metrics", "wal_pages_set")

    wal_last = snap.get("wal_last_run_at")
    try:
        z4j_wal_checkpoint_last_run_timestamp.set(
            wal_last.timestamp() if wal_last is not None else 0,
        )
    except Exception:
        record_swallowed("metrics", "wal_last_run_set")

    wal_err_active = 1 if snap.get("wal_error") else 0
    try:
        z4j_background_task_error_active.labels(
            task="wal_checkpoint",
        ).set(wal_err_active)
    except Exception:
        record_swallowed("metrics", "wal_err_set")


def _windows_pid_is_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    still_active = 259
    error_access_denied = 5
    error_invalid_parameter = 87
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(
        process_query_limited_information,
        False,
        pid,
    )
    if not handle:
        code = ctypes.get_last_error()
        if code == error_invalid_parameter:
            return False
        if code == error_access_denied:
            return True
        raise OSError(code, ctypes.FormatError(code))
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))
        return int(exit_code.value) == still_active
    finally:
        kernel32.CloseHandle(handle)


def _pid_is_alive(pid: int) -> bool:
    if os.name == "nt":
        return _windows_pid_is_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _reap_dead_worker_metrics(multiproc_dir: str) -> None:
    """Drop live-gauge files of workers that no longer exist.

    prometheus_client's multiprocess mode leaves one value file per
    PID; ``mark_process_dead`` is meant to run at child exit, but
    uvicorn's worker supervisor exposes no such hook -- and a
    SIGKILLed worker could never run one anyway. Without reaping, a
    replaced worker's ``livesum``/``liveall`` gauges keep counting
    (round 4 measured pool-size gauges tripling after one worker
    kill+respawn). Reaping at scrape time bounds the staleness to one
    scrape interval.

    Only gauge_live* files are removed (that is all mark_process_dead
    touches); counter/histogram files persist so a dead worker's
    already-counted work is never un-counted. PID liveness is probed
    with ``os.kill(pid, 0)``: workers are same-user siblings, and a
    recycled PID merely delays cleanup one scrape. Best-effort by
    design -- any failure is swallowed into the scrape-health counter.
    """
    try:
        from prometheus_client import multiprocess

        live_prefixes = ("gauge_live", "gauge_liveall", "gauge_livesum")
        seen: set[int] = set()
        for f in Path(multiproc_dir).glob("gauge_live*_*.db"):
            stem = f.stem
            if not stem.startswith(live_prefixes):
                continue
            pid_part = stem.rsplit("_", 1)[-1]
            if not pid_part.isdigit():
                continue
            pid = int(pid_part)
            if pid in seen or pid == os.getpid():
                continue
            seen.add(pid)
            if not _pid_is_alive(pid):
                multiprocess.mark_process_dead(pid, path=multiproc_dir)
    except Exception:
        record_swallowed("metrics", "dead_worker_reap")


def _check_metrics_auth(request: Request, settings: Settings) -> None:
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
    settings: Settings = Depends(get_settings),
) -> Response:
    """Render the brain's metrics in Prometheus text format.

    Refreshes lazy in-memory state gauges before rendering so a
    Prometheus scrape gets a fresh ``z4j_inmemory_state_items``
    snapshot without forcing every subsystem to update on every
    mutation.

    When ``PROMETHEUS_MULTIPROC_DIR`` is set (multi-worker
    serve), the response aggregates every worker process via
    ``multiprocess.MultiProcessCollector`` instead of rendering only
    this process's private registry.
    """
    _check_metrics_auth(request, settings)
    _refresh_inmemory_gauges()
    _refresh_self_watch_gauges()
    _refresh_leak_visibility_gauges()
    _refresh_fleet_gauges()
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if multiproc_dir:
        # Multi-worker serve: cli.py exported PROMETHEUS_MULTIPROC_DIR
        # before uvicorn spawned the workers (or the operator set it
        # themselves), so every worker's metric writes -- including
        # the scrape-time refreshes above, which wrote THIS worker's
        # samples through to the mmap files -- land in the shared
        # directory. Aggregate ALL workers here. A fresh throwaway
        # registry per scrape is the documented prometheus_client
        # pattern: MultiProcessCollector reads the value files at
        # collect time and must not accumulate on a long-lived
        # registry.
        from prometheus_client import multiprocess

        # Reap dead workers BEFORE collecting: uvicorn gives
        # us no child-exit hook, so a killed/replaced worker's live
        # gauge files stayed in the directory and livesum kept adding
        # the corpse's values to the aggregate (round 4 reproduced
        # z4j_db_pool_size tripling after one worker kill+respawn).
        # mark_process_dead removes only the gauge_live* files for
        # that PID -- counters correctly keep a dead worker's counts.
        # PID liveness via kill(pid, 0): workers are same-user
        # siblings in the same container/host. Best-effort; a reap
        # failure must never break the scrape.
        _reap_dead_worker_metrics(multiproc_dir)
        throwaway = CollectorRegistry()
        multiprocess.MultiProcessCollector(throwaway, path=multiproc_dir)
        body = generate_latest(throwaway)
    else:
        # Default single-process path: render the private in-process
        # registry exactly as before. Test isolation depends on this
        # branch staying the default (tests construct multiple
        # create_app() instances against the module-level registry).
        body = generate_latest(registry)
    return Response(content=body, media_type=CONTENT_TYPE_LATEST)


__all__ = [
    "record_swallowed",
    "register_fleet_gauge_provider",
    "register_inmemory_subsystem",
    "register_pool_gauge_provider",
    "register_self_watch_provider",
    "registry",
    "router",
    "z4j_agents_online",
    "z4j_audit_retention_last_deleted",
    "z4j_audit_retention_last_run_timestamp",
    "z4j_audit_retention_pruned_total",
    "z4j_background_task_error_active",
    "z4j_brain_rss_bytes",
    "z4j_command_late_results_total",
    "z4j_commands_total",
    "z4j_db_pool_checked_out",
    "z4j_db_pool_size",
    "z4j_events_ingested_total",
    "z4j_inmemory_state_items",
    "z4j_notifications_cooldown_skipped_total",
    "z4j_notifications_sent_total",
    "z4j_postgres_deadlocks_total",
    "z4j_queue_depth",
    "z4j_swallowed_exceptions_total",
    "z4j_task_duration_seconds",
    "z4j_tasks_total",
    "z4j_wal_checkpoint_last_run_timestamp",
    "z4j_wal_checkpoint_pages_last",
    "z4j_workers_online",
    "z4j_ws_connections",
]
