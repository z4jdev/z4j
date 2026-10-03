"""An in-process migration run leaves the process's existing loggers enabled.

``z4j serve`` auto-migrates before it builds the app and ``z4j migrate`` runs
the chain in the CLI process, both through ``migrations/env.py``, which hands
``alembic.ini`` to ``logging.config.fileConfig``. With that function's default
every logger that already exists is disabled for the rest of the process: in
the serve order that silenced asyncio's logger (unretrieved task exceptions)
and the audit service's warnings. The environment now keeps them enabled.
"""

from __future__ import annotations

import logging
import logging.config
import os
import secrets
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_ROOT / "alembic.ini"
_MIGRATIONS = _BACKEND_ROOT / "src" / "z4j_brain" / "migrations"


def _isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    if os.name == "posix":
        home.chmod(0o700)
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'z4j.db'}")
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", secrets.token_urlsafe(48))
    monkeypatch.chdir(tmp_path)


def _all_loggers() -> list[logging.Logger]:
    return [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    ]


def test_in_process_migration_keeps_existing_loggers_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A logger created before the chain runs still emits after it."""
    _isolated_environment(tmp_path, monkeypatch)
    probe = logging.getLogger("z4j.brain.logging_probe")
    asyncio_logger = logging.getLogger("asyncio")
    probe.disabled = False
    asyncio_logger.disabled = False

    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(_MIGRATIONS))
    command.upgrade(config, "head")

    assert not probe.disabled
    assert not asyncio_logger.disabled
    assert not logging.getLogger("z4j.brain.domain.audit_service").disabled


def test_the_default_file_configuration_would_have_disabled_them() -> None:
    """Negative control: the same ini through ``fileConfig``'s default does disable.

    Every logger's flag is restored afterwards so the control does not do to
    the rest of the suite what the migration environment used to do.
    """
    flags = {logger: logger.disabled for logger in _all_loggers()}
    probe = logging.getLogger("z4j.brain.logging_probe_control")
    probe.disabled = False
    try:
        logging.config.fileConfig(str(_ALEMBIC_INI))
        assert probe.disabled
        probe.disabled = False
        logging.config.fileConfig(str(_ALEMBIC_INI), disable_existing_loggers=False)
        assert not probe.disabled
    finally:
        for logger, disabled in flags.items():
            logger.disabled = disabled
        probe.disabled = False
