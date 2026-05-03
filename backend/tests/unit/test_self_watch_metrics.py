"""Tests for the brain self-watch Prometheus metrics (1.2.2+).

Audit fix CRIT-5 + MED-16: the self-watch surface uses Gauges
(not synthetic-delta Counters), so each scrape is idempotent
and there is no per-process baseline state to manage.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from z4j_brain.api.metrics import (
    _refresh_self_watch_gauges,
    register_self_watch_provider,
    z4j_audit_retention_last_deleted,
    z4j_audit_retention_last_run_timestamp,
    z4j_audit_retention_pruned_total,
    z4j_background_task_error_active,
    z4j_wal_checkpoint_last_run_timestamp,
    z4j_wal_checkpoint_pages_last,
)


@pytest.fixture(autouse=True)
def _reset_provider() -> None:
    """Reset the provider before/after each test for isolation."""
    register_self_watch_provider(lambda: {})
    yield
    register_self_watch_provider(lambda: {})


class TestSelfWatchProvider:
    def test_audit_pruned_mirrors_total(self) -> None:
        register_self_watch_provider(lambda: {"audit_pruned_total": 100})
        _refresh_self_watch_gauges()
        assert z4j_audit_retention_pruned_total._value.get() == 100  # type: ignore[attr-defined]

        # A second pass with a larger total just sets the new value.
        register_self_watch_provider(lambda: {"audit_pruned_total": 250})
        _refresh_self_watch_gauges()
        assert z4j_audit_retention_pruned_total._value.get() == 250  # type: ignore[attr-defined]

    def test_audit_pruned_handles_restart_cleanly(self) -> None:
        """A counter reset (sweeper restart) is reflected as-is.

        With the Gauge-based design, a restart from 100 -> 0 just
        sets the gauge back to 0, no negative-delta gymnastics.
        """
        register_self_watch_provider(lambda: {"audit_pruned_total": 100})
        _refresh_self_watch_gauges()
        register_self_watch_provider(lambda: {"audit_pruned_total": 0})
        _refresh_self_watch_gauges()
        assert z4j_audit_retention_pruned_total._value.get() == 0  # type: ignore[attr-defined]

    def test_audit_last_deleted_gauge(self) -> None:
        register_self_watch_provider(lambda: {"audit_last_deleted": 42})
        _refresh_self_watch_gauges()
        assert z4j_audit_retention_last_deleted._value.get() == 42  # type: ignore[attr-defined]

    def test_audit_last_run_gauge(self) -> None:
        ts = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
        register_self_watch_provider(lambda: {"audit_last_run_at": ts})
        _refresh_self_watch_gauges()
        assert z4j_audit_retention_last_run_timestamp._value.get() == (  # type: ignore[attr-defined]
            ts.timestamp()
        )

    def test_audit_error_sets_active_gauge(self) -> None:
        labels = z4j_background_task_error_active.labels(task="audit_retention")
        register_self_watch_provider(lambda: {"audit_error": "boom"})
        _refresh_self_watch_gauges()
        assert labels._value.get() == 1  # type: ignore[attr-defined]
        # Error clears: gauge returns to 0.
        register_self_watch_provider(lambda: {"audit_error": None})
        _refresh_self_watch_gauges()
        assert labels._value.get() == 0  # type: ignore[attr-defined]

    def test_wal_pages_gauge(self) -> None:
        register_self_watch_provider(lambda: {"wal_pages_last": 42})
        _refresh_self_watch_gauges()
        assert z4j_wal_checkpoint_pages_last._value.get() == 42  # type: ignore[attr-defined]

    def test_wal_last_run_gauge(self) -> None:
        ts = datetime(2026, 4, 30, 12, 0, tzinfo=UTC)
        register_self_watch_provider(lambda: {"wal_last_run_at": ts})
        _refresh_self_watch_gauges()
        assert z4j_wal_checkpoint_last_run_timestamp._value.get() == (  # type: ignore[attr-defined]
            ts.timestamp()
        )

    def test_provider_exception_does_not_crash(self) -> None:
        def bad_provider() -> dict:
            raise RuntimeError("provider broken")

        register_self_watch_provider(bad_provider)
        # Must not raise.
        _refresh_self_watch_gauges()

    def test_no_provider_is_noop(self) -> None:
        register_self_watch_provider(lambda: {})
        _refresh_self_watch_gauges()
        # No exception is the contract.

    def test_concurrent_scrapes_idempotent(self) -> None:
        """Two scrapes from different Prometheus replicas don't double-count.

        With Gauges (not synthetic-delta Counters), repeating the
        scrape just re-sets the same value. No per-process
        baseline drift.
        """
        register_self_watch_provider(lambda: {"audit_pruned_total": 5000})
        for _ in range(10):
            _refresh_self_watch_gauges()
        assert z4j_audit_retention_pruned_total._value.get() == 5000  # type: ignore[attr-defined]
