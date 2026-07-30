"""1.7.1: a SQLite / local (in-memory) agent registry must be single-worker.

Multiple uvicorn workers on one SQLite file split the in-memory agent
registry (agents on worker A invisible to the dashboard on worker B),
contend on SQLite writes, and race the first-boot bootstrap. So SQLite
(Z4J_REGISTRY_BACKEND=local) is forced to --workers=1; Postgres is not.
"""

from __future__ import annotations

from z4j_brain.cli import resolve_serve_workers


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

    def test_run_serve_derives_local_registry_from_settings_not_env(self) -> None:
        import inspect

        from z4j_brain import cli

        src = inspect.getsource(cli._run_serve)
        assert "settings.registry_backend" in src, (
            "H2 regression: _run_serve must derive local_registry from "
            "settings.registry_backend (which Settings coerces for any "
            "sqlite URL), not from os.environ['Z4J_REGISTRY_BACKEND'] "
            "(set only on the auto-SQLite path)."
        )


class TestAdminPasswordTopologyGuardCXM18:
    """CX-M18: the --admin-password guard must run against the RESOLVED
    worker topology, not the raw flag (unset --workers resolves to up to
    4 on Postgres; uvicorn spawns fresh interpreters that never receive
    the in-process password)."""

    def test_guard_checks_resolved_workers_and_reload(self) -> None:
        import inspect

        from z4j_brain import cli

        src = inspect.getsource(cli._run_serve)
        # The guard must appear AFTER workers_resolved exists and gate on
        # it (plus --reload), not on a pre-resolution `workers_requested`.
        assert "workers_resolved > 1 or args.reload" in src, (
            "CX-M18 regression: --admin-password must be rejected when the "
            "RESOLVED topology spawns worker interpreters (workers_resolved "
            "> 1 or --reload), where the in-process password holder is empty."
        )
        assert "workers_requested" not in src, (
            "CX-M18 regression: the old pre-resolution `workers_requested "
            "or 1` guard must be gone -- it treated an unset --workers as 1 "
            "and let Postgres silently resolve it to 4."
        )
