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
        assert metrics_mod.z4j_agents_online.labels(project="alpha")._value.get() == 3
        assert metrics_mod.z4j_agents_online.labels(project="bravo")._value.get() == 1
        assert metrics_mod.z4j_workers_online.labels(project="alpha")._value.get() == 9
        assert metrics_mod.z4j_workers_online.labels(project="bravo")._value.get() == 2

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
        assert metrics_mod.z4j_agents_online.labels(project="alpha")._value.get() == 0

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
    the Grafana dashboards filter on. Verified by exercising the
    production metric helper with a fake counter, without depending
    on a globally registered Prometheus collector.
    """

    @pytest.mark.parametrize(
        ("success", "error", "expected"),
        [
            (True, None, "success"),
            (False, "SSRF destination blocked", "blocked"),
            (False, "connection refused", "failed"),
        ],
    )
    def test_runtime_metric_increment_uses_dashboard_taxonomy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        success: bool,
        error: str | None,
        expected: str,
    ) -> None:
        from types import SimpleNamespace
        from unittest.mock import Mock
        from uuid import uuid4

        from z4j_brain.domain.notifications.service import (
            _DeliveryOutcome,
            _PendingDelivery,
            _record_delivery_metric,
        )

        increment = Mock()
        labels = Mock(return_value=SimpleNamespace(inc=increment))
        monkeypatch.setattr(
            metrics_mod,
            "z4j_notifications_sent_total",
            SimpleNamespace(labels=labels),
        )
        pending = _PendingDelivery(
            subscription_id=uuid4(),
            recipient_user_id=uuid4(),
            channel_id=uuid4(),
            user_channel_id=None,
            channel_type="webhook",
            channel_name="ops",
            config={},
            project_id=uuid4(),
            trigger="task.failed",
            task_id="task-1",
            task_name="tasks.fail",
        )

        status = _record_delivery_metric(
            _DeliveryOutcome(pending=pending, success=success, error=error),
        )

        assert status == expected
        labels.assert_called_once_with(
            project=str(pending.project_id),
            channel_type="webhook",
            status=expected,
        )
        increment.assert_called_once_with()
