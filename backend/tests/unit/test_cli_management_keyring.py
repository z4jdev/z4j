"""Management commands bind the secret keyring before they touch channel rows.

``reset``, ``backup`` and ``restore`` each run in a process of their own,
and ``reset`` and ``restore`` read every table through the ORM-typed Core
tables, where ``notification_channels.config`` and ``user_channels.config``
are decrypted on load. Until the CLI bootstrap bound the keyring, any
installation with one notification channel failed with
``SecretKeyringUnbound`` in the middle of the ceremony; on PostgreSQL the
restore had already cleared and loaded the target by then. These tests run
the real commands through ``cli.main`` with the keyring deliberately unbound
first, the way a fresh process starts, and pin the refusal that has to come
before any of that when there is no master secret to bind.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
from z4j_brain import cli
from z4j_brain.domain.secret_fields import (
    NOTIFICATION_CHANNEL_CONFIG,
    SecretKeyring,
    SecretKeyringUnbound,
    bind_keyring,
    decrypt_json,
    is_encrypted,
)
from z4j_brain.persistence.models import NotificationChannel, Project
from z4j_brain.secret_store import ensure_secret_store_directory

SECRET = "management-keyring-master-" + "k" * 40
CONFIG = {
    "webhook_url": "https://hooks.slack.com/services/T0/B0/MANAGEMENTSLACK",
    "channel": "#ops",
}


def _clear_z4j_environment() -> None:
    # Popped directly rather than through monkeypatch.delenv: the conftest
    # guard snapshots and restores the true pre-test environment, and the
    # CLI's snapshot exporter writes Z4J_* keys into os.environ itself.
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            os.environ.pop(key, None)


def _environment(home: Path, *, chain_secret: str, secret: str | None = SECRET) -> None:
    _clear_z4j_environment()
    os.environ["Z4J_HOME"] = str(home)
    os.environ["Z4J_ENVIRONMENT"] = "dev"
    os.environ["Z4J_DATABASE_URL"] = f"sqlite+aiosqlite:///{home / 'z4j.db'}"
    if secret is not None:
        os.environ["Z4J_SECRET"] = secret
    os.environ["Z4J_SESSION_SECRET"] = "session-secret-" + "s" * 40
    os.environ["Z4J_AUDIT_CHAIN_SECRET"] = chain_secret


@pytest.fixture
def install(
    migrated_sqlite_template: Path,
    migrated_audit_chain_secret: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """A release-head SQLite installation in its own private home."""
    home = ensure_secret_store_directory(tmp_path / "z4j-home")
    shutil.copyfile(migrated_sqlite_template, home / "z4j.db")
    # No repository .env in reach: the CLI captures configuration from the
    # current directory and refuses one with permissions it does not like.
    monkeypatch.chdir(tmp_path)
    _environment(home, chain_secret=migrated_audit_chain_secret)
    bind_keyring(None)
    try:
        yield home
    finally:
        bind_keyring(None)
        _clear_z4j_environment()


def _add_channel(database: Path) -> uuid.UUID:
    """Write one project and one channel the way the brain does: encrypted."""
    bind_keyring(SecretKeyring.from_secrets(SECRET))
    engine = sa.create_engine(f"sqlite:///{database}")
    try:
        with Session(engine) as session:
            project = Project(slug="ops", name="Ops")
            session.add(project)
            session.flush()
            channel = NotificationChannel(
                project_id=project.id, name="ops", type="slack", config=dict(CONFIG)
            )
            session.add(channel)
            session.commit()
            return channel.id
    finally:
        engine.dispose()
        # A fresh management process starts with nothing bound.
        bind_keyring(None)


def _stored_configs(database: Path) -> list[str]:
    connection = sqlite3.connect(database)
    try:
        return [row[0] for row in connection.execute("SELECT config FROM notification_channels")]
    finally:
        connection.close()


def _assert_row_needs_the_keyring(database: Path, channel_id: uuid.UUID) -> None:
    """Negative control: this row is one the commands cannot read unbound."""
    stored = _stored_configs(database)
    assert len(stored) == 1 and is_encrypted(stored[0])
    engine = sa.create_engine(f"sqlite:///{database}")
    try:
        with Session(engine) as session, pytest.raises(SecretKeyringUnbound):
            _ = session.get(NotificationChannel, channel_id).config  # type: ignore[union-attr]
    finally:
        engine.dispose()


def test_reset_force_succeeds_with_an_encrypted_channel_row(
    install: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = install / "z4j.db"
    channel_id = _add_channel(database)
    _assert_row_needs_the_keyring(database, channel_id)

    assert cli.main(["reset", "--force"]) == 0, capsys.readouterr()
    assert _stored_configs(database) == []


def test_backup_then_restore_carries_the_encrypted_channel_into_a_fresh_database(
    install: Path,
    migrated_sqlite_template: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = install / "z4j.db"
    channel_id = _add_channel(database)
    _assert_row_needs_the_keyring(database, channel_id)
    archive = tmp_path / "z4j-backup.db"
    assert cli.main(["backup", "--output", str(archive)]) == 0, capsys.readouterr()

    # A fresh database: the release head with no channel at all.
    shutil.copyfile(migrated_sqlite_template, database)
    assert _stored_configs(database) == []
    bind_keyring(None)

    assert cli.main(["restore", "--force", str(archive)]) == 0, capsys.readouterr()

    stored = _stored_configs(database)
    assert len(stored) == 1 and is_encrypted(stored[0])
    keyring = SecretKeyring.from_secrets(SECRET)
    assert decrypt_json(stored[0], keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG) == (
        CONFIG,
        False,
    )
    # And the way the brain reads it, under the keyring create_app binds.
    bind_keyring(keyring)
    engine = sa.create_engine(f"sqlite:///{database}")
    try:
        with Session(engine) as session:
            restored = session.get(NotificationChannel, channel_id)
            assert restored is not None
            assert restored.config == CONFIG
    finally:
        engine.dispose()


def test_without_a_master_secret_the_commands_refuse_before_touching_anything(
    install: Path,
    migrated_audit_chain_secret: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = install / "z4j.db"
    _add_channel(database)
    archive = tmp_path / "z4j-backup.db"
    assert cli.main(["backup", "--output", str(archive)]) == 0, capsys.readouterr()
    before = database.read_bytes()

    # No Z4J_SECRET anywhere: not in the environment, not in the home's store.
    _environment(install, chain_secret=migrated_audit_chain_secret, secret=None)
    for argv in (["restore", "--force", str(archive)], ["reset", "--force"]):
        with pytest.raises(SystemExit, match="Z4J_SECRET"):
            cli.main(argv)
    assert database.read_bytes() == before
    assert not (install / ".z4j-restore").exists(), "no restore operation was staged"
