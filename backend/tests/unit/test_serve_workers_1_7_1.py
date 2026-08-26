"""1.7.1: a SQLite / local (in-memory) agent registry must be single-worker.

Multiple uvicorn workers on one SQLite file split the in-memory agent
registry (agents on worker A invisible to the dashboard on worker B),
contend on SQLite writes, and race the first-boot bootstrap. So SQLite
(Z4J_REGISTRY_BACKEND=local) is forced to --workers=1; Postgres is not.
"""

from __future__ import annotations

import pytest
from z4j_brain.cli import (
    enforce_cli_admin_password_topology,
    resolve_serve_workers,
    resolve_serve_workers_for_settings,
)


def test_local_registry_forces_single_worker() -> None:
    workers, note = resolve_serve_workers(None, local_registry=True, cpu_count=8)
    assert workers == 1
    assert note is not None and "workers=1" in note


def test_local_registry_forces_single_worker_even_if_explicitly_requested() -> None:
    workers, note = resolve_serve_workers(4, local_registry=True, cpu_count=8)
    assert workers == 1
    assert note is not None


def test_postgres_uses_cpu_default() -> None:
    workers, note = resolve_serve_workers(None, local_registry=False, cpu_count=8)
    assert workers == 4  # min(4, cpu)
    assert note is None


def test_postgres_respects_explicit_workers() -> None:
    workers, note = resolve_serve_workers(3, local_registry=False, cpu_count=8)
    assert workers == 3
    assert note is None


def test_embedded_scheduler_forces_single_worker_on_postgres() -> None:
    workers, note = resolve_serve_workers(
        4,
        local_registry=False,
        embedded_scheduler=True,
        cpu_count=8,
    )
    assert workers == 1
    assert note is not None and "embedded scheduler" in note.lower()


def test_single_cpu_defaults_to_one() -> None:
    workers, note = resolve_serve_workers(None, local_registry=False, cpu_count=1)
    assert workers == 1
    assert note is None


class TestLocalRegistryDetectionH2:
    """H2: an EXPLICIT sqlite Z4J_DATABASE_URL must still be detected as a
    local registry. The pre-fix code read os.environ["Z4J_REGISTRY_BACKEND"],
    set only on the auto-SQLite path, so an explicit sqlite URL slipped
    through and spawned min(4, cpu) workers over one in-memory registry."""

    def test_explicit_sqlite_url_coerces_registry_to_local(self) -> None:
        import os
        from unittest import mock

        from z4j_brain.settings import Settings

        env = {
            "Z4J_DATABASE_URL": "sqlite+aiosqlite:////srv/data/z4j.db",
            "Z4J_SECRET": "x" * 48,
            "Z4J_SESSION_SECRET": "y" * 48,
            "Z4J_PUBLIC_URL": "http://localhost:7700",
            "Z4J_ALLOW_HTTP_PUBLIC_URL": "true",
            "Z4J_ALLOWED_HOSTS": '["localhost","127.0.0.1"]',
            "Z4J_ENVIRONMENT": "dev",
        }
        # The sqlite coercion (settings.py _coerce_registry_backend_for_sqlite)
        # overrides registry_backend to "local" unconditionally for a sqlite
        # URL, so we do not need to touch Z4J_REGISTRY_BACKEND -- the sqlite
        # URL alone must be sufficient to trigger the H2 detection path.
        with mock.patch.dict(os.environ, env, clear=False):
            settings = Settings()  # type: ignore[call-arg]
        assert str(settings.registry_backend).lower() == "local", (
            "H2: an explicit sqlite Z4J_DATABASE_URL must coerce "
            "registry_backend to 'local' so _run_serve forces one worker."
        )

    def test_resolved_settings_drive_worker_topology(self) -> None:
        from z4j_brain.settings import Settings

        settings = Settings(
            database_url="sqlite+aiosqlite:////srv/data/z4j.db",
            secret="x" * 48,
            session_secret="y" * 48,
            environment="dev",
        )

        workers, note = resolve_serve_workers_for_settings(
            4,
            settings=settings,
            cpu_count=8,
        )

        assert workers == 1
        assert note is not None and "SQLite" in note


class TestAdminPasswordTopologyGuardCXM18:
    """CX-M18: the --admin-password guard must run against the RESOLVED
    worker topology, not the raw flag (unset --workers resolves to up to
    4 on Postgres; uvicorn spawns fresh interpreters that never receive
    the in-process password)."""

    @pytest.mark.parametrize(
        ("workers", "reload"),
        [(2, False), (4, False), (1, True)],
    )
    def test_password_is_rejected_for_spawned_topologies(
        self,
        workers: int,
        reload: bool,
    ) -> None:
        with pytest.raises(SystemExit, match="single non-reload"):
            enforce_cli_admin_password_topology(
                "correct horse battery staple",
                workers=workers,
                reload=reload,
            )

    def test_password_is_allowed_for_one_in_process_worker(self) -> None:
        enforce_cli_admin_password_topology(
            "correct horse battery staple",
            workers=1,
            reload=False,
        )

    def test_absent_password_needs_no_topology_guard(self) -> None:
        enforce_cli_admin_password_topology(None, workers=4, reload=True)
