"""``z4j secrets rewrap`` end to end against a migrated SQLite database.

The command is the step that makes dropping a value from
``Z4J_PREVIOUS_SECRETS`` safe, so the test asserts the user-visible outcome
both ways: after ``rewrap`` every channel and the stored TOTP secret read
under the new master alone, and without ``rewrap`` the same database does
not. It also proves the refusal: a process holding neither the current nor
the previous master writes nothing and exits 1.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from z4j_brain import cli
from z4j_brain.domain.mfa.crypto import DecryptionFailed as TotpDecryptionFailed
from z4j_brain.domain.mfa.crypto import decrypt_totp_secret, encrypt_totp_secret
from z4j_brain.domain.secret_fields import (
    NOTIFICATION_CHANNEL_CONFIG,
    USER_CHANNEL_CONFIG,
    DecryptionFailed,
    SecretKeyring,
    bind_keyring,
    decrypt_json,
    is_encrypted,
)
from z4j_brain.persistence.models import NotificationChannel, Project, User, UserChannel

REVISION = "v1_12_channel_config_encrypted"
#: The revision just below REVISION on the chain: the columns are still JSON.
BELOW_REVISION = "v1_12_audit_forward_state"
OLD = "old-master-" + "o" * 40
NEW = "new-master-" + "n" * 40
OTHER = "other-master-" + "z" * 40
TOTP = b"totp-secret-20-bytes"
SLACK = {"webhook_url": "https://hooks.slack.com/services/T0/B0/REWRAPSLACK"}
WEBHOOK = {"url": "https://hooks.example.com/x", "hmac_secret": "REWRAPHMAC"}


def _clear_z4j_environment() -> None:
    # Popped directly rather than through monkeypatch.delenv: the conftest
    # guard snapshots and restores the true pre-test environment, and the
    # CLI's snapshot exporter writes Z4J_* keys into os.environ itself.
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            os.environ.pop(key, None)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    private_home = Path(tempfile.mkdtemp(prefix="z4j-rewrap-", dir=str(tmp_path)))
    private_home.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    try:
        yield private_home
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


def _environment(home: Path, *, secret: str, previous: str | None) -> None:
    _clear_z4j_environment()
    os.environ["Z4J_HOME"] = str(home)
    os.environ["Z4J_ENVIRONMENT"] = "dev"
    os.environ["Z4J_DATABASE_URL"] = f"sqlite+aiosqlite:///{home / 'z4j.db'}"
    os.environ["Z4J_SECRET"] = secret
    os.environ["Z4J_SESSION_SECRET"] = "session-secret-" + "s" * 40
    os.environ["Z4J_AUDIT_CHAIN_SECRET"] = "audit-chain-secret-" + "a" * 40
    if previous is not None:
        os.environ["Z4J_PREVIOUS_SECRETS"] = previous


def _migrate_to_head(home: Path, revision: str = REVISION) -> None:
    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_root / "src" / "z4j_brain" / "migrations"))
    command.upgrade(cfg, revision)


def _populate_under(home: Path, secret: str) -> uuid.UUID:
    """Write one project channel, one user channel and one MFA user under ``secret``."""
    keyring = SecretKeyring.from_secrets(secret)
    bind_keyring(keyring)
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with sa.orm.Session(engine) as session:
            project = Project(slug="p", name="P")
            user = User(email="mfa@example.com", password_hash="x")
            session.add_all([project, user])
            session.flush()
            user.mfa_secret_encrypted = encrypt_totp_secret(
                TOTP, master_secret=secret.encode(), user_id=user.id
            )
            session.add(
                NotificationChannel(
                    project_id=project.id, name="ops", type="slack", config=dict(SLACK)
                )
            )
            session.add(
                UserChannel(user_id=user.id, name="mine", type="webhook", config=dict(WEBHOOK))
            )
            session.commit()
            return user.id
    finally:
        engine.dispose()
        bind_keyring(None)


def _stored(home: Path) -> dict[str, object]:
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with engine.connect() as conn:
            return {
                "channel": conn.execute(
                    sa.text("SELECT config FROM notification_channels")
                ).scalar(),
                "user_channel": conn.execute(sa.text("SELECT config FROM user_channels")).scalar(),
                "mfa": conn.execute(sa.text("SELECT mfa_secret_encrypted FROM users")).scalar(),
                "audit_rows": conn.execute(
                    sa.text("SELECT COUNT(*) FROM audit_log WHERE action = 'secrets.rewrap'")
                ).scalar(),
            }
    finally:
        engine.dispose()


def _assert_readable_under(home: Path, secret: str, user_id: uuid.UUID) -> None:
    stored = _stored(home)
    keyring = SecretKeyring.from_secrets(secret)
    assert decrypt_json(
        str(stored["channel"]), keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
    ) == (SLACK, False)
    assert decrypt_json(
        str(stored["user_channel"]), keyring=keyring, purpose=USER_CHANNEL_CONFIG
    ) == (WEBHOOK, False)
    plaintext, needs_rewrap = decrypt_totp_secret(
        bytes(stored["mfa"]),  # type: ignore[arg-type]
        master_secret=secret.encode(),
        user_id=user_id,
    )
    assert plaintext == TOTP and needs_rewrap is False


def _assert_unreadable_under(home: Path, secret: str, user_id: uuid.UUID) -> None:
    stored = _stored(home)
    keyring = SecretKeyring.from_secrets(secret)
    with pytest.raises(DecryptionFailed):
        decrypt_json(str(stored["channel"]), keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)
    with pytest.raises(DecryptionFailed):
        decrypt_json(str(stored["user_channel"]), keyring=keyring, purpose=USER_CHANNEL_CONFIG)
    with pytest.raises(TotpDecryptionFailed):
        decrypt_totp_secret(
            bytes(stored["mfa"]),  # type: ignore[arg-type]
            master_secret=secret.encode(),
            user_id=user_id,
        )


def test_rewrap_then_dropping_the_old_secret_leaves_every_channel_working(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _environment(home, secret=OLD, previous=None)
    _migrate_to_head(home)
    user_id = _populate_under(home, OLD)

    # Negative control first: rotated, nothing re-wrapped, old value gone.
    _assert_unreadable_under(home, NEW, user_id)

    # Rotation window: new master current, old one carried.
    _environment(home, secret=NEW, previous=OLD)
    before = _stored(home)
    assert cli.main(["secrets", "rewrap", "--dry-run"]) == 0
    assert _stored(home) == before, "dry run wrote nothing"
    out = capsys.readouterr().out
    assert "would re-wrap 1" in out and "dry run" in out

    assert cli.main(["secrets", "rewrap"]) == 0
    out = capsys.readouterr().out
    assert "notification_channels.config: scanned 1, already current 0, re-wrapped 1" in out
    assert "user_channels.config: scanned 1, already current 0, re-wrapped 1" in out
    assert "users.mfa_secret_encrypted: scanned 1, already current 0, re-wrapped 1" in out
    assert "3 row(s) re-wrapped" in out
    assert _stored(home)["audit_rows"] == 1

    # Old secret dropped: every channel and the TOTP secret still work.
    _environment(home, secret=NEW, previous=None)
    _assert_readable_under(home, NEW, user_id)
    assert cli.main(["secrets", "rewrap"]) == 0
    assert "0 row(s) re-wrapped, 0 plaintext row(s) encrypted, 3 scanned" in (
        capsys.readouterr().out
    )


def _insert_plaintext_channel(home: Path, config: dict[str, object]) -> None:
    """What a brain from before the column was encrypted, or a hand, leaves behind."""
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with engine.begin() as conn:
            project_id = conn.execute(sa.text("SELECT id FROM projects")).scalar_one()
            conn.execute(
                sa.text(
                    "INSERT INTO notification_channels (id, project_id, name, type, config, "
                    "is_active, created_at, updated_at) VALUES (:id, :pid, 'plain', 'slack', "
                    ":config, 1, datetime('now'), datetime('now'))",
                ),
                {"id": uuid.uuid4().hex, "pid": project_id, "config": json.dumps(config)},
            )
    finally:
        engine.dispose()


def _channel_configs(home: Path) -> dict[str, str]:
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with engine.connect() as conn:
            rows = conn.execute(sa.text("SELECT name, config FROM notification_channels")).all()
    finally:
        engine.dispose()
    return {str(name): str(config) for name, config in rows}


def test_plaintext_row_is_encrypted_and_reported(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row stored without the prefix is counted, encrypted, and exit stays 0."""
    plain = {"webhook_url": "https://hooks.slack.com/services/T0/B0/PLAINTEXTREWRAP"}
    _environment(home, secret=NEW, previous=None)
    _migrate_to_head(home)
    _populate_under(home, NEW)
    _insert_plaintext_channel(home, plain)
    before = _channel_configs(home)
    assert is_encrypted(before["ops"]) and not is_encrypted(before["plain"])

    assert cli.main(["secrets", "rewrap", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert (
        "notification_channels.config: scanned 2, already current 1, would re-wrap 0, plaintext 1"
    ) in out
    assert "0 row(s) would be re-wrapped and 1 plaintext row(s) encrypted" in out
    assert _channel_configs(home) == before, "dry run wrote nothing"

    assert cli.main(["secrets", "rewrap"]) == 0
    out = capsys.readouterr().out
    assert (
        "notification_channels.config: scanned 2, already current 1, re-wrapped 0, "
        "plaintext 1, changed under us 0, undecryptable 0"
    ) in out
    assert "0 row(s) re-wrapped, 1 plaintext row(s) encrypted, 4 scanned" in out
    stored = _channel_configs(home)
    assert all(is_encrypted(value) for value in stored.values())
    assert stored["ops"] == before["ops"]
    assert decrypt_json(
        stored["plain"],
        keyring=SecretKeyring.from_secrets(NEW),
        purpose=NOTIFICATION_CHANNEL_CONFIG,
    ) == (plain, False)
    assert _stored(home)["audit_rows"] == 1


def _insert_project(home: Path) -> None:
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with sa.orm.Session(engine) as session:
            session.add(Project(slug="p", name="P"))
            session.commit()
    finally:
        engine.dispose()


def test_refuses_below_the_migration_that_encrypts_the_columns(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run before the column is TEXT, the repair would write ciphertext into JSON.

    The database is migrated to the revision just below the one that
    encrypts the channel columns and holds one plaintext channel, the shape
    an installation has when the brain was upgraded but ``migrate`` has not
    run yet. Both modes exit 2 with a readable refusal naming the stamped
    head, the required migration and the remedy, and the row is untouched.
    Migrating the rest of the way (which encrypts that row itself) is the
    positive control: the same command is then admitted and exits 0.
    """
    plain = {"webhook_url": "https://hooks.slack.com/services/T0/B0/BELOWTHEHEAD"}
    _environment(home, secret=NEW, previous=None)
    _migrate_to_head(home, BELOW_REVISION)
    _insert_project(home)
    _insert_plaintext_channel(home, plain)
    before = _channel_configs(home)
    assert not is_encrypted(before["plain"])

    for argv in (["secrets", "rewrap"], ["secrets", "rewrap", "--dry-run"]):
        assert cli.main(argv) == 2, argv
        captured = capsys.readouterr()
        assert "refused" in captured.err
        assert BELOW_REVISION in captured.err
        assert REVISION in captured.err
        assert "z4j migrate upgrade head" in captured.err
        assert "Nothing was written" in captured.err
        assert "scanned" not in captured.out, "no column was walked"
    assert _channel_configs(home) == before
    engine = create_engine(f"sqlite:///{home / 'z4j.db'}")
    try:
        with engine.connect() as conn:
            rewrap_rows = conn.execute(
                sa.text("SELECT COUNT(*) FROM audit_log WHERE action = 'secrets.rewrap'")
            ).scalar()
            assert rewrap_rows == 0, "a refused run leaves no secrets.rewrap row"
    finally:
        engine.dispose()

    _migrate_to_head(home, REVISION)
    migrated = _channel_configs(home)
    assert is_encrypted(migrated["plain"])
    assert cli.main(["secrets", "rewrap"]) == 0
    out = capsys.readouterr().out
    assert "notification_channels.config: scanned 1, already current 1" in out
    assert _channel_configs(home) == migrated


def test_refuses_and_writes_nothing_when_no_row_decrypts(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _environment(home, secret=OLD, previous=None)
    _migrate_to_head(home)
    _populate_under(home, OLD)
    before = _stored(home)

    _environment(home, secret=OTHER, previous=None)
    assert cli.main(["secrets", "rewrap"]) == 1
    captured = capsys.readouterr()
    assert "refused" in captured.err
    assert "undecryptable 1" in captured.out
    assert _stored(home) == before
