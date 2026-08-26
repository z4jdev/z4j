"""Database-selection and mutation fences for ``z4j reset-setup``."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from z4j_brain import cli, configuration
from z4j_brain.persistence import database


class _ConfiguredDatabaseReachedError(RuntimeError):
    """Sentinel raised when the configured engine path is exercised."""


def _snapshot(database_url: str) -> SimpleNamespace:
    return SimpleNamespace(values={"Z4J_DATABASE_URL": database_url})


def _isolate_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    *,
    database_url: str | None,
    secret: str | None = None,
) -> None:
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path / "home"))
    if database_url is not None:
        monkeypatch.setenv("Z4J_DATABASE_URL", database_url)
    if secret is not None:
        monkeypatch.setenv("Z4J_SECRET", secret)


def test_reset_setup_postgres_does_not_short_circuit_on_missing_local_sqlite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    postgres_url = "postgresql+asyncpg://operator:secret@db.internal/z4j"
    settings = SimpleNamespace(database_url=postgres_url)
    observed: dict[str, object] = {}

    _isolate_configuration(
        monkeypatch,
        tmp_path,
        database_url=postgres_url,
        secret="configured-installation-secret",
    )

    def settings_from_snapshot(candidate) -> SimpleNamespace:
        observed["snapshot"] = candidate
        return settings

    engine = object()

    def create_engine_from_settings(candidate):
        observed["settings"] = candidate
        return engine

    class SessionContext:
        async def __aenter__(self):
            observed["session_entered"] = True
            raise _ConfiguredDatabaseReachedError

        async def __aexit__(self, *_exc_info) -> None:
            return None

    class DatabaseManager:
        def __init__(self, candidate) -> None:
            observed["engine"] = candidate

        def session(self, *, write: bool) -> SessionContext:
            observed["write"] = write
            return SessionContext()

        async def dispose(self) -> None:
            observed["disposed"] = True

    monkeypatch.setattr(configuration, "settings_from_snapshot", settings_from_snapshot)
    monkeypatch.setattr(
        database,
        "create_engine_from_settings",
        create_engine_from_settings,
    )
    monkeypatch.setattr(database, "DatabaseManager", DatabaseManager)

    assert not (tmp_path / "home" / "z4j.db").exists()
    with pytest.raises(_ConfiguredDatabaseReachedError):
        cli.main(["reset-setup", "--force"])

    captured_snapshot = observed.pop("snapshot")
    assert captured_snapshot.values["Z4J_DATABASE_URL"] == postgres_url
    assert observed == {
        "settings": settings,
        "engine": engine,
        "write": True,
        "session_entered": True,
        "disposed": True,
    }


def test_reset_setup_missing_file_sqlite_returns_without_engine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "state" / "configured.db"
    database_url = f"sqlite+aiosqlite:///{database_path}"
    engine_constructed = False

    _isolate_configuration(
        monkeypatch,
        tmp_path,
        database_url=database_url,
    )

    def create_engine_from_settings(_settings) -> None:
        nonlocal engine_constructed
        engine_constructed = True
        raise AssertionError("missing file-backed SQLite must not construct an engine")

    monkeypatch.setattr(
        database,
        "create_engine_from_settings",
        create_engine_from_settings,
    )

    assert cli.main(["reset-setup", "--force"]) == 0
    assert engine_constructed is False
    assert "Z4J_SECRET" not in os.environ
    assert not (tmp_path / "home" / "secret.env").exists()
    assert f"no DB found at {database_path}" in capsys.readouterr().err


def test_reset_setup_fresh_default_sqlite_requires_no_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "home" / "z4j.db"
    _isolate_configuration(
        monkeypatch,
        tmp_path,
        database_url=None,
    )

    def create_engine_from_settings(_settings) -> None:
        raise AssertionError("fresh default SQLite must not construct an engine")

    monkeypatch.setattr(
        database,
        "create_engine_from_settings",
        create_engine_from_settings,
    )

    assert cli.main(["reset-setup", "--force"]) == 0
    assert "Z4J_SECRET" not in os.environ
    assert not (tmp_path / "home" / "secret.env").exists()
    assert f"no DB found at {database_path}" in capsys.readouterr().err


@pytest.mark.parametrize("database_kind", ["postgresql", "existing_sqlite"])
def test_reset_setup_retains_secret_fence_for_reachable_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    database_kind: str,
) -> None:
    if database_kind == "postgresql":
        database_url = "postgresql+asyncpg://operator:secret@db.internal/z4j"
    else:
        database_path = tmp_path / "existing.db"
        database_path.touch()
        database_url = f"sqlite+aiosqlite:///{database_path}"

    _isolate_configuration(
        monkeypatch,
        tmp_path,
        database_url=database_url,
    )

    with pytest.raises(SystemExit, match="refusing to mint Z4J_SECRET"):
        cli.main(["reset-setup", "--force"])


def test_reset_setup_without_force_does_not_mutate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    database_path = tmp_path / "configured.db"
    database_path.touch()
    snapshot = _snapshot(f"sqlite+aiosqlite:///{database_path}")
    settings = SimpleNamespace(database_url=snapshot.values["Z4J_DATABASE_URL"])

    class Result:
        def scalars(self):
            return self

        def first(self) -> None:
            return None

    class Session:
        execute_count = 0
        committed = False

        async def execute(self, _statement) -> Result:
            self.execute_count += 1
            return Result()

        async def commit(self) -> None:
            self.committed = True

    session = Session()

    class SessionContext:
        async def __aenter__(self) -> Session:
            return session

        async def __aexit__(self, *_exc_info) -> None:
            return None

    class DatabaseManager:
        def __init__(self, _engine) -> None:
            pass

        def session(self, *, write: bool) -> SessionContext:
            assert write is True
            return SessionContext()

        async def dispose(self) -> None:
            pass

    monkeypatch.setattr(
        cli,
        "_bootstrap_env_for_management_commands",
        lambda **_kwargs: snapshot,
    )
    monkeypatch.setattr(configuration, "settings_from_snapshot", lambda _value: settings)
    monkeypatch.setattr(database, "create_engine_from_settings", lambda _value: object())
    monkeypatch.setattr(database, "DatabaseManager", DatabaseManager)

    assert cli.main(["reset-setup"]) == 1
    assert session.execute_count == 1
    assert session.committed is False
