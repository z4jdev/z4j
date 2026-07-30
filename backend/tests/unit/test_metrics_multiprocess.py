"""Multi-worker Prometheus aggregation.

``z4j serve`` defaults to min(4, cpu) uvicorn worker processes, and
the brain's metric registry is per-process, so durable-claim-gated
counters (agent-offline detections, automation fires, partition
failures) incremented in one worker were invisible to a
load-balanced scrape that landed on another. The fix has two halves:

1. ``cli.py`` exports ``PROMETHEUS_MULTIPROC_DIR`` (a fresh per-run
   temp dir) before uvicorn spawns workers, activating
   prometheus_client multiprocess mode in every worker.
2. ``api/metrics.py`` detects the env var at scrape time and renders
   an aggregate across all workers via
   ``multiprocess.MultiProcessCollector`` instead of the private
   in-process registry.

These tests pin the scrape-time branch selection, the per-gauge
``multiprocess_mode`` decisions, the fleet-gauge departed-project
zeroing (required so livesum aggregation stays honest), and the
serve-path env setup helper. A true multi-process integration test
is intentionally out of scope; the release orchestrator boot-smokes
the real image."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from prometheus_client import Gauge
from z4j_brain.api import metrics as metrics_mod

# ---------------------------------------------------------------------------
# Scrape-time branch selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestScrapeBranchSelection:
    async def test_env_unset_renders_private_registry(
        self,
        client,
        monkeypatch,
    ) -> None:
        """Default path: no PROMETHEUS_MULTIPROC_DIR, the private
        in-process registry is rendered and the multiprocess
        collector is never touched. Test isolation across multiple
        ``create_app()`` instances depends on this staying the
        default."""
        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        import prometheus_client.multiprocess as pc_mp

        calls: list[str | None] = []
        real_collector = pc_mp.MultiProcessCollector

        def _spy(registry, path=None):
            calls.append(path)
            return real_collector(registry, path=path)

        monkeypatch.setattr(pc_mp, "MultiProcessCollector", _spy)

        r = await client.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers.get("content-type", "")
        # Families registered on the private module registry render.
        assert "z4j_events_ingested_total" in r.text
        assert "z4j_agents_online" in r.text
        # The multiprocess path was never taken.
        assert calls == []

    async def test_env_set_chooses_multiprocess_collector(
        self,
        client,
        monkeypatch,
        tmp_path,
    ) -> None:
        """With PROMETHEUS_MULTIPROC_DIR set, the endpoint builds a
        throwaway registry, hands it to MultiProcessCollector with
        the configured path, and renders THAT (not the private
        registry). A fake collector plants a sentinel family so the
        response provably comes from the collector's registry."""
        mp_dir = tmp_path / "prom-multiproc"
        mp_dir.mkdir()
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(mp_dir))
        import prometheus_client.multiprocess as pc_mp

        seen: dict[str, object] = {}

        class _FakeCollector:
            def __init__(self, registry, path=None):
                seen["path"] = path
                # Register a synthetic family on the throwaway
                # registry so the rendered body can only have come
                # from this collector's registry.
                Gauge(
                    "z4j_test_multiproc_sentinel",
                    "sentinel planted by the fake collector",
                    registry=registry,
                ).set(42)

        monkeypatch.setattr(pc_mp, "MultiProcessCollector", _FakeCollector)

        r = await client.get("/metrics")
        assert r.status_code == 200
        assert seen["path"] == str(mp_dir)
        assert "z4j_test_multiproc_sentinel 42.0" in r.text
        # The private in-process registry is bypassed in this mode.
        assert "z4j_events_ingested_total" not in r.text

    async def test_env_set_real_collector_survives_empty_dir(
        self,
        client,
        monkeypatch,
        tmp_path,
    ) -> None:
        """The REAL MultiProcessCollector against an empty directory
        must not 500 a scrape. (This test process imported
        prometheus_client without the env var, so its own metric
        values are in-process and the shared dir is legitimately
        empty; only worker processes spawned AFTER the env var is
        set write mmap files.)"""
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))

        r = await client.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers.get("content-type", "")
        # Aggregate view of an empty dir renders no z4j families;
        # the private registry must NOT leak into this branch.
        assert "z4j_events_ingested_total" not in r.text

    async def test_env_set_still_enforces_auth(
        self,
        monkeypatch,
        tmp_path,
        brain_settings,
    ) -> None:
        """The multiprocess branch sits BEHIND the bearer-token
        gate; flipping aggregation on must not reopen /metrics."""
        from httpx import ASGITransport, AsyncClient
        from sqlalchemy.ext.asyncio import create_async_engine
        from z4j_brain.main import create_app

        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
        secure_settings = brain_settings.model_copy(
            update={"metrics_public": False, "metrics_auth_token": None},
        )
        engine = create_async_engine(secure_settings.database_url, future=True)
        try:
            app = create_app(secure_settings, engine=engine)
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as ac:
                r = await ac.get("/metrics")
                assert r.status_code == 401
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# Per-gauge multiprocess_mode decisions
# ---------------------------------------------------------------------------


class TestGaugeMultiprocessModes:
    def test_declared_modes(self) -> None:
        """Pin every gauge's multiprocess aggregation mode.

        These are deliberate semantic choices (rationales live as
        comments on each declaration in api/metrics.py); an
        accidental change would silently corrupt multi-worker
        dashboards, so any edit must update both places.
        """
        expected = {
            # Process-local, disjoint state: sum over live workers.
            "z4j_inmemory_state_items": "livesum",
            "z4j_agents_online": "livesum",
            "z4j_workers_online": "livesum",
            "z4j_ws_connections": "livesum",
            "z4j_db_pool_size": "livesum",
            "z4j_db_pool_checked_out": "livesum",
            "z4j_brain_rss_bytes": "livesum",
            # Fleet-wide fact reported to one worker: last write wins.
            "z4j_queue_depth": "mostrecent",
            "z4j_audit_retention_last_deleted": "mostrecent",
            "z4j_wal_checkpoint_pages_last": "mostrecent",
            # Historical facts survive worker death: non-live modes.
            "z4j_audit_retention_pruned_total": "sum",
            "z4j_audit_retention_last_run_timestamp": "max",
            "z4j_wal_checkpoint_last_run_timestamp": "max",
            # Alert if ANY worker's latest pass failed.
            "z4j_background_task_error_active": "max",
        }
        for attr, mode in expected.items():
            gauge = getattr(metrics_mod, attr)
            assert gauge._multiprocess_mode == mode, (
                f"{attr}: expected multiprocess_mode={mode!r}, got {gauge._multiprocess_mode!r}"
            )


# ---------------------------------------------------------------------------
# Fleet-gauge departed-project zeroing
# ---------------------------------------------------------------------------


class _GaugeRecorder:
    """Minimal stand-in for a labelled Gauge that records writes."""

    def __init__(self) -> None:
        self.sets: list[tuple[str, float]] = []
        self.cleared = 0

    def labels(self, project: str):
        recorder = self

        class _Child:
            def set(self, value: float) -> None:
                recorder.sets.append((project, value))

        return _Child()

    def clear(self) -> None:
        self.cleared += 1


class TestFleetGaugeDepartedProjectZeroing:
    def test_departed_projects_written_as_zero(self, monkeypatch) -> None:
        """A project that drops out of the fleet snapshot must be
        explicitly set to 0: ``Gauge.clear`` does not erase the mmap
        entries multiprocess aggregation reads, so without the zero
        write a departed project's stale count would inflate the
        livesum forever."""
        agents_rec = _GaugeRecorder()
        workers_rec = _GaugeRecorder()
        monkeypatch.setattr(metrics_mod, "z4j_agents_online", agents_rec)
        monkeypatch.setattr(metrics_mod, "z4j_workers_online", workers_rec)
        monkeypatch.setattr(
            metrics_mod,
            "_fleet_prev_projects",
            {"agents": set(), "workers": set()},
        )
        state = {"snap": {"agents": {"p1": 3, "p2": 1}, "workers": {"p1": 2}}}
        monkeypatch.setattr(
            metrics_mod,
            "_fleet_gauge_provider",
            lambda: state["snap"],
        )

        # First refresh: nothing departed yet, current values set.
        metrics_mod._refresh_fleet_gauges()
        assert ("p1", 3) in agents_rec.sets
        assert ("p2", 1) in agents_rec.sets
        assert ("p1", 2) in workers_rec.sets
        assert agents_rec.cleared == 1

        # Second refresh: p2's agents and p1's workers departed.
        agents_rec.sets.clear()
        workers_rec.sets.clear()
        state["snap"] = {"agents": {"p1": 3}, "workers": {}}
        metrics_mod._refresh_fleet_gauges()
        assert ("p2", 0) in agents_rec.sets
        assert ("p1", 0) in workers_rec.sets
        # Still-present projects keep their live values.
        assert ("p1", 3) in agents_rec.sets

        # Third refresh: no further departures, no repeat zeroing.
        agents_rec.sets.clear()
        metrics_mod._refresh_fleet_gauges()
        assert ("p2", 0) not in agents_rec.sets

    def test_single_process_output_unchanged(self, monkeypatch) -> None:
        """On the default single-process path the zero write happens
        BEFORE ``clear``, so a departed project still disappears from
        the rendered output entirely (the historical behavior)."""
        from prometheus_client import generate_latest

        monkeypatch.setattr(
            metrics_mod,
            "_fleet_prev_projects",
            {"agents": set(), "workers": set()},
        )
        state = {"snap": {"agents": {"px": 5}, "workers": {}}}
        monkeypatch.setattr(
            metrics_mod,
            "_fleet_gauge_provider",
            lambda: state["snap"],
        )
        metrics_mod._refresh_fleet_gauges()
        body = generate_latest(metrics_mod.registry).decode()
        assert 'z4j_agents_online{project="px"} 5.0' in body

        state["snap"] = {"agents": {}, "workers": {}}
        metrics_mod._refresh_fleet_gauges()
        body = generate_latest(metrics_mod.registry).decode()
        assert 'project="px"' not in body


# ---------------------------------------------------------------------------
# Serve-path env setup helper
# ---------------------------------------------------------------------------


class TestSetupMultiprocessMetricsEnv:
    def test_single_worker_is_noop(self, monkeypatch) -> None:
        from z4j_brain import cli

        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        result = cli._setup_multiprocess_metrics_env(
            1,
            reload_mode=False,
        )
        assert result is None
        assert "PROMETHEUS_MULTIPROC_DIR" not in os.environ

    def test_reload_mode_is_noop(self, monkeypatch) -> None:
        from z4j_brain import cli

        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        result = cli._setup_multiprocess_metrics_env(
            4,
            reload_mode=True,
        )
        assert result is None
        assert "PROMETHEUS_MULTIPROC_DIR" not in os.environ

    def test_operator_provided_dir_is_respected(self, monkeypatch) -> None:
        from z4j_brain import cli

        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", "/operator/owned")
        result = cli._setup_multiprocess_metrics_env(
            4,
            reload_mode=False,
        )
        assert result is None
        assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == "/operator/owned"

    def test_multiworker_creates_fresh_dir_and_logs(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        from z4j_brain import cli

        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        created = cli._setup_multiprocess_metrics_env(
            4,
            reload_mode=False,
        )
        try:
            assert created is not None
            assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == created
            path = Path(created)
            assert path.is_dir()
            # Fresh per-run dir: no stale value files can leak in.
            assert not any(path.iterdir())
            out = capsys.readouterr().out
            assert "multiprocess metrics active" in out
            assert created in out
        finally:
            os.environ.pop("PROMETHEUS_MULTIPROC_DIR", None)
            shutil.rmtree(created, ignore_errors=True)
        assert "PROMETHEUS_MULTIPROC_DIR" not in os.environ


class TestDeadWorkerReaping:
    """Dead workers' live-gauge files must not keep inflating
    livesum aggregates forever. The scrape path reaps value files of
    PIDs that no longer exist before collecting.
    """

    def _write_worker_gauge(self, multiproc_dir: str, value: float) -> int:
        """Spawn a real subprocess that sets a livesum gauge and exits.

        Returns the (now dead) worker's PID. Uses a real child so the
        prometheus_client mmap layout is authentic.
        """
        import subprocess
        import sys
        import textwrap

        code = textwrap.dedent(
            f"""
            import os
            os.environ["PROMETHEUS_MULTIPROC_DIR"] = {multiproc_dir!r}
            from prometheus_client import CollectorRegistry, Gauge

            g = Gauge(
                "z4j_reap_probe",
                "probe",
                registry=CollectorRegistry(),
                multiprocess_mode="livesum",
            )
            g.set({value})
            print(os.getpid())
            """
        )
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        return int(out.stdout.strip())

    def _aggregate(self, multiproc_dir: str) -> dict[str, float]:
        from prometheus_client import CollectorRegistry, multiprocess

        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg, path=multiproc_dir)
        out: dict[str, float] = {}
        for metric in reg.collect():
            for sample in metric.samples:
                out[sample.name] = out.get(sample.name, 0.0) + sample.value
        return out

    def test_dead_worker_livesum_is_reaped(self, tmp_path) -> None:
        from z4j_brain.api.metrics import _reap_dead_worker_metrics

        d = str(tmp_path)
        dead_pid = self._write_worker_gauge(d, 20.0)
        # Sanity: the corpse contributes before reaping.
        assert self._aggregate(d).get("z4j_reap_probe") == 20.0

        _reap_dead_worker_metrics(d)

        # The dead worker's live gauge is gone from the aggregate.
        assert self._aggregate(d).get("z4j_reap_probe") is None
        # And its files specifically: no live-gauge file for that pid.
        leftovers = [p.name for p in tmp_path.glob(f"gauge_live*_{dead_pid}.db")]
        assert leftovers == []

    def test_live_process_files_survive_reaping(self, tmp_path) -> None:
        # A file stamped with a LIVE pid must be left alone. The value
        # backend binds at import time, so an in-process Gauge would
        # not produce an mmap file here; instead take a real dead
        # worker's file and rename it to OUR (alive) pid.
        import os as _os

        from z4j_brain.api.metrics import _reap_dead_worker_metrics

        d = str(tmp_path)
        dead_pid = self._write_worker_gauge(d, 7.0)
        for f in tmp_path.glob(f"gauge_live*_{dead_pid}.db"):
            f.rename(
                f.with_name(f.name.replace(str(dead_pid), str(_os.getpid()))),
            )

        _reap_dead_worker_metrics(d)
        assert self._aggregate(d).get("z4j_reap_probe") == 7.0
