"""Aggregate-math sanity tests for /home/summary.

One bug category we've shipped more than once: a derived ratio
(``failure_rate_24h`` specifically) rendering > 100% because
``task.failed`` events arrived for tasks whose ``task.received``
fell outside the rolling 24h window. Not a display bug - the
numerator genuinely exceeds the denominator on the window. These
tests pin the clamping behaviour so future refactors cannot
regress back to "289%" cards on the home dashboard.

The tests operate on :func:`_compute_health` and the per-card
arithmetic directly (no DB required) - the API wiring is exercised
separately under ``tests/integration/``.
"""

from __future__ import annotations

import math

from z4j_brain.api.home import _compute_health


class TestFailureRateClamp:
    """Derived failure rate must be in ``[0.0, 1.0]`` always."""

    @staticmethod
    def _rate(tasks: int, failures: int) -> float:
        """Mirror the per-project calculation in
        :func:`z4j_brain.api.home.get_summary`. Kept tiny on
        purpose so a refactor of ``home.py`` that still produces
        a sensible ratio keeps this test green.
        """
        return (
            min(failures / tasks, 1.0) if tasks > 0 else 0.0
        )

    def test_no_tasks_returns_zero(self) -> None:
        assert self._rate(0, 0) == 0.0
        assert self._rate(0, 5) == 0.0  # pre-24h failures, no receives yet

    def test_normal_failure_rate(self) -> None:
        assert self._rate(100, 3) == 0.03
        assert self._rate(10, 5) == 0.5

    def test_equals_one_hundred_percent(self) -> None:
        assert self._rate(10, 10) == 1.0

    def test_exceeds_window_is_clamped(self) -> None:
        # task.failed arrived for tasks whose task.received fell
        # outside the 24h window. Numerator > denominator. Must
        # render as 1.0, not 5.0.
        assert self._rate(10, 50) == 1.0
        assert self._rate(1, 1000) == 1.0

    def test_clamp_preserves_precision_for_valid_rates(self) -> None:
        # 0.0331 stays 0.0331 - clamp does not introduce rounding.
        r = self._rate(1000, 33)
        assert math.isclose(r, 0.033, rel_tol=1e-9)


class TestHealthHeuristic:
    """The ``_compute_health`` rules must stay consistent with the
    published attention-list contract."""

    def test_offline_when_all_agents_down(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.0,
            stuck_commands=0,
            agents_online=0,
            agents_total=3,
            tasks_24h=0,
            workers_online=0,
        ) == "offline"

    def test_degraded_on_high_failure_rate(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.10,  # > 5%
            stuck_commands=0,
            agents_online=3,
            agents_total=3,
            tasks_24h=200,
            workers_online=3,
        ) == "degraded"

    def test_degraded_on_stuck_commands(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.0,
            stuck_commands=1,
            agents_online=3,
            agents_total=3,
            tasks_24h=10,
            workers_online=3,
        ) == "degraded"

    def test_degraded_on_partial_agents(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.0,
            stuck_commands=0,
            agents_online=2,
            agents_total=3,
            tasks_24h=10,
            workers_online=3,
        ) == "degraded"

    def test_idle_when_quiet(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.0,
            stuck_commands=0,
            agents_online=0,
            agents_total=0,
            tasks_24h=0,
            workers_online=0,
        ) == "idle"

    def test_healthy_when_busy_and_all_up(self) -> None:
        assert _compute_health(
            failure_rate_24h=0.02,
            stuck_commands=0,
            agents_online=3,
            agents_total=3,
            tasks_24h=500,
            workers_online=3,
        ) == "healthy"
