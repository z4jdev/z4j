"""Regression: v1.6 audit pinned three Prometheus surfaces the dashboards
depend on. Pin the wire-up here so a future refactor that drops a
``.labels(...).inc()`` site cannot silently re-break the dashboards.

- ``z4j_notifications_sent_total`` must be emitted by the notification
  service with labels ``project, channel_type, status`` and status
  values in ``{"success", "failed", "blocked"}``.
- ``z4j_agents_online`` and ``z4j_workers_online`` must be sampled at
  scrape time from the registry's ``fleet_snapshot``. The provider is
  the load-bearing piece; previously these gauges had no call site
  anywhere in the codebase.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest

from z4j_brain.api import metrics as metrics_mod
from z4j_brain.websocket.registry.local import LocalRegistry


def _reset_fleet_provider() -> None:
    metrics_mod._fleet_gauge_provider = None
    metrics_mod.z4j_agents_online.clear()
    metrics_mod.z4j_workers_online.clear()


@pytest.fixture(autouse=True)
def _isolate_fleet_provider() -> Any:
    _reset_fleet_provider()
    yield
    _reset_fleet_provider()


class TestFleetGaugeProvider:
    """The dashboard's `$project` variable + every agent/worker panel
    depend on these gauges. They MUST be sampled at scrape time."""

    def test_provider_registration_is_observable_at_scrape(self) -> None:
        snapshot = {
            "agents": {"alpha": 3, "bravo": 1},
            "workers": {"alpha": 9, "bravo": 2},
        }
        metrics_mod.register_fleet_gauge_provider(lambda: snapshot)
        metrics_mod._refresh_fleet_gauges()
        # Both projects appear with the expected counts.
        assert (
            metrics_mod.z4j_agents_online.labels(project="alpha")._value.get()
            == 3
        )
        assert (
            metrics_mod.z4j_agents_online.labels(project="bravo")._value.get()
            == 1
        )
        assert (
            metrics_mod.z4j_workers_online.labels(project="alpha")._value.get()
            == 9
        )
        assert (
            metrics_mod.z4j_workers_online.labels(project="bravo")._value.get()
            == 2
        )

    def test_provider_clears_stale_labels_between_refreshes(self) -> None:
        """A project that goes from N agents to zero must reflect zero,
        not the stale N from the prior snapshot."""
        metrics_mod.register_fleet_gauge_provider(
            lambda: {"agents": {"alpha": 5}, "workers": {"alpha": 5}},
        )
        metrics_mod._refresh_fleet_gauges()
        # Now alpha disappears; the gauge should not retain 5.
        metrics_mod.register_fleet_gauge_provider(
            lambda: {"agents": {}, "workers": {}},
        )
        metrics_mod._refresh_fleet_gauges()
        # After clear, querying the label returns a freshly-defaulted
        # zero (the label set is empty so prometheus_client returns a
        # new 0-initialised gauge on access).
        assert (
            metrics_mod.z4j_agents_online.labels(project="alpha")._value.get()
            == 0
        )

    def test_provider_exception_is_swallowed(self) -> None:
        """A broken provider must NOT break the scrape endpoint."""

        def _raising() -> dict[str, dict[str, int]]:
            raise RuntimeError("registry crashed")

        metrics_mod.register_fleet_gauge_provider(_raising)
        # Must not raise.
        metrics_mod._refresh_fleet_gauges()

    def test_no_provider_is_a_noop(self) -> None:
        metrics_mod._fleet_gauge_provider = None
        # Must not raise.
        metrics_mod._refresh_fleet_gauges()


class TestLocalRegistryFleetSnapshot:
    """The Local + PostgresNotify registries both expose
    ``fleet_snapshot()`` for the gauge provider to consume."""

    @pytest.mark.asyncio
    async def test_empty_registry_snapshot(self) -> None:
        async def _deliver(*_: Any, **__: Any) -> bool:
            return True

        reg = LocalRegistry(deliver_local=_deliver)
        snap = reg.fleet_snapshot()
        assert snap == {"agents": {}, "workers": {}}

    @pytest.mark.asyncio
    async def test_single_agent_single_worker(self) -> None:
        async def _deliver(*_: Any, **__: Any) -> bool:
            return True

        reg = LocalRegistry(deliver_local=_deliver)
        agent_id = UUID("00000000-0000-0000-0000-000000000001")
        project_id = UUID("00000000-0000-0000-0000-000000000aaa")

        class _FakeWS:
            async def close(self, code: int = 1000) -> None:
                return None

        await reg.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=_FakeWS(),
            worker_id="w1",
            cap=10,
        )
        snap = reg.fleet_snapshot()
        assert snap == {
            "agents": {str(project_id): 1},
            "workers": {str(project_id): 1},
        }

    @pytest.mark.asyncio
    async def test_multiple_workers_one_agent(self) -> None:
        async def _deliver(*_: Any, **__: Any) -> bool:
            return True

        reg = LocalRegistry(deliver_local=_deliver)
        agent_id = UUID("00000000-0000-0000-0000-000000000002")
        project_id = UUID("00000000-0000-0000-0000-000000000bbb")

        class _FakeWS:
            async def close(self, code: int = 1000) -> None:
                return None

        for worker_id in ("w1", "w2", "w3"):
            await reg.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=_FakeWS(),
                worker_id=worker_id,
                cap=10,
            )
        snap = reg.fleet_snapshot()
        # One agent process, three connected workers.
        assert snap["agents"][str(project_id)] == 1
        assert snap["workers"][str(project_id)] == 3


class TestNotificationStatusValues:
    """The notification dispatcher's status taxonomy must match what
    the Grafana dashboards filter on. Verified by direct module-level
    inspection of the dispatcher's status mapping (the integration
    test path needs a real DB + project + subscription, which is out
    of scope for this regression pin).
    """

    def test_status_values_are_taxonomy_compatible(self) -> None:
        """The dashboard regexes filter on ``failed`` and ``blocked``;
        the success donut filters on ``success``. Verify the
        instrumentation site emits exactly those three strings.
        """
        # Read the service module source and grep for the status
        # literals; the dispatcher is a deeply-async path that is
        # painful to unit-test end-to-end. The source-level pin is
        # the cheapest reliable contract.
        from pathlib import Path

        source = Path(
            "src/z4j_brain/domain/notifications/service.py",
        ).read_text(encoding="utf-8")
        # The instrumentation block must reference all three vocab
        # values; if a future refactor drops one, the dashboard
        # silently breaks again.
        assert '_status = "success"' in source
        assert '"blocked"' in source
        assert '"failed"' in source
        # Must use the counter we registered.
        assert "z4j_notifications_sent_total" in source
        # Must label by (project, channel_type, status) -- matches the
        # gauge declaration in metrics.py and the dashboard PromQL.
        assert "channel_type=" in source
        assert "status=_status" in source
