"""``v1_12_channel_config_encrypted`` on SQLite with populated rows.

Proves, by running the migration rather than reading it: existing plaintext
configs are encrypted in place under the master the app reads
(``Z4J_SECRET``), a row already carrying the prefix is left alone, a row
written under a ``Z4J_PREVIOUS_SECRETS`` entry stays readable, the column
type moves ``JSON`` to ``TEXT`` and back, downgrade restores the exact
plaintext, and a second upgrade after that encrypts again.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine
from z4j_brain.domain.secret_fields import (
    ENCRYPTED_PREFIX,
    NOTIFICATION_CHANNEL_CONFIG,
    USER_CHANNEL_CONFIG,
    SecretKeyring,
    bind_keyring,
    decrypt_json,
    encrypt_json,
)
from z4j_brain.persistence.models import NotificationChannel, UserChannel

REVISION = "v1_12_channel_config_encrypted"
MASTER = "x" * 64
PREVIOUS = "p" * 64

SLACK = {"webhook_url": "https://hooks.slack.com/services/T0/B0/PLAINTEXTSLACK", "channel": "#ops"}
SMTP = {
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "mailer",
    "smtp_pass": "PLAINTEXTSMTPPASS",
    "to": ["ops@example.com"],
}
WEBHOOK = {"url": "https://hooks.example.com/x", "hmac_secret": "PLAINTEXTHMAC"}
PRE_ENCRYPTED = {"bot_token": "PRE-WRAPPED-UNDER-PREVIOUS", "chat_id": "42"}


@pytest.fixture
def alembic_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Config]:
    db_path = tmp_path / "brain.sqlite"
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_PREVIOUS_SECRETS", PREVIOUS)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = Path(tempfile.mkdtemp(prefix="z4j-enc-migration-", dir=str(tmp_path)))
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    cfg.attributes["test_sync_url"] = f"sqlite:///{db_path}"
    try:
        yield cfg
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


def _declared_type(conn: sa.engine.Connection, table: str) -> str:
    for row in conn.exec_driver_sql(f"PRAGMA table_info('{table}')").all():
        if row[1] == "config":
            return str(row[2]).upper()
    raise AssertionError(f"{table}.config missing")


def _force_json_declared_type(conn: sa.engine.Connection) -> None:
    """Make the two columns look like a database that shipped before this revision."""
    ops = Operations(MigrationContext.configure(conn))
    for table in ("notification_channels", "user_channels"):
        with ops.batch_alter_table(table) as batch:
            batch.alter_column(
                "config", existing_type=sa.Text(), type_=sa.JSON(), existing_nullable=False
            )


def _populate(engine: sa.engine.Engine) -> dict[str, str]:
    project_id = uuid.uuid4().hex
    user_id = uuid.uuid4().hex
    ids = {
        "slack": uuid.uuid4().hex,
        "smtp": uuid.uuid4().hex,
        "pre": uuid.uuid4().hex,
        "webhook": uuid.uuid4().hex,
    }
    with engine.begin() as conn:
        _force_json_declared_type(conn)
        assert _declared_type(conn, "notification_channels") == "JSON"
        conn.execute(
            sa.text(
                "INSERT INTO projects (id, slug, name, created_at) "
                "VALUES (:id, 'p1', 'P1', datetime('now'))",
            ),
            {"id": project_id},
        )
        conn.execute(
            sa.text(
                "INSERT INTO users (id, email, password_hash, is_admin, is_active, "
                "force_password_change, timezone, failed_login_count, failed_mfa_count, "
                "created_at, updated_at) VALUES (:id, 'u@example.com', 'x', 0, 1, 0, 'UTC', "
                "0, 0, datetime('now'), datetime('now'))",
            ),
            {"id": user_id},
        )
        channel_sql = sa.text(
            "INSERT INTO notification_channels (id, project_id, name, type, config, "
            "is_active, created_at, updated_at) VALUES (:id, :pid, :name, :type, :config, 1, "
            "datetime('now'), datetime('now'))",
        )
        conn.execute(
            channel_sql,
            [
                {
                    "id": ids["slack"],
                    "pid": project_id,
                    "name": "slack",
                    "type": "slack",
                    "config": json.dumps(SLACK),
                },
                {
                    "id": ids["smtp"],
                    "pid": project_id,
                    "name": "smtp",
                    "type": "email",
                    "config": json.dumps(SMTP),
                },
                {
                    "id": ids["pre"],
                    "pid": project_id,
                    "name": "pre",
                    "type": "telegram",
                    # Already encrypted, under the previous master: the
                    # upgrade must skip it and the app must still read it.
                    "config": encrypt_json(
                        PRE_ENCRYPTED,
                        keyring=SecretKeyring.from_secrets(PREVIOUS),
                        purpose=NOTIFICATION_CHANNEL_CONFIG,
                    ),
                },
            ],
        )
        conn.execute(
            sa.text(
                "INSERT INTO user_channels (id, user_id, name, type, config, is_verified, "
                "is_active, created_at, updated_at) VALUES (:id, :uid, 'mine', 'webhook', "
                ":config, 0, 1, datetime('now'), datetime('now'))",
            ),
            {"id": ids["webhook"], "uid": user_id, "config": json.dumps(WEBHOOK)},
        )
    return ids


def _raw(engine: sa.engine.Engine, table: str) -> dict[str, str]:
    with engine.connect() as conn:
        rows = conn.execute(sa.text(f"SELECT id, config FROM {table}")).all()
    return {str(row_id): str(config) for row_id, config in rows}


def test_upgrade_encrypts_populated_rows_and_downgrade_restores_them(
    alembic_cfg: Config,
) -> None:
    # Up to the revision before this one; then make the DB look like 1.11.
    command.upgrade(alembic_cfg, f"{REVISION}-1")
    engine = create_engine(alembic_cfg.attributes["test_sync_url"])
    try:
        ids = _populate(engine)
        before_pre = _raw(engine, "notification_channels")[ids["pre"]]

        command.upgrade(alembic_cfg, REVISION)

        with engine.connect() as conn:
            assert _declared_type(conn, "notification_channels") == "TEXT"
            assert _declared_type(conn, "user_channels") == "TEXT"
        channels = _raw(engine, "notification_channels")
        user_channels = _raw(engine, "user_channels")
        assert len(channels) == 3 and len(user_channels) == 1
        for stored in [*channels.values(), *user_channels.values()]:
            assert stored.startswith(ENCRYPTED_PREFIX)
            for secret in ("PLAINTEXTSLACK", "PLAINTEXTSMTPPASS", "PLAINTEXTHMAC", "smtp_pass"):
                assert secret not in stored
        # Already-encrypted row left byte-for-byte alone (idempotence by prefix).
        assert channels[ids["pre"]] == before_pre

        # Decrypts under the master the migration read from Z4J_SECRET, with
        # the pre-encrypted row needing the previous secret, exactly as the
        # app's keyring would resolve it.
        keyring = SecretKeyring.from_secrets(MASTER, [PREVIOUS])
        assert decrypt_json(
            channels[ids["slack"]], keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
        ) == (SLACK, False)
        assert decrypt_json(
            channels[ids["smtp"]], keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
        ) == (SMTP, False)
        assert decrypt_json(
            channels[ids["pre"]], keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
        ) == (PRE_ENCRYPTED, True)
        assert decrypt_json(
            user_channels[ids["webhook"]], keyring=keyring, purpose=USER_CHANNEL_CONFIG
        ) == (WEBHOOK, False)

        # The ORM path the dashboard and the dispatcher use.
        bind_keyring(keyring)
        with sa.orm.Session(engine) as session:
            by_name = {
                c.name: c.config for c in session.execute(sa.select(NotificationChannel)).scalars()
            }
            assert by_name == {"slack": SLACK, "smtp": SMTP, "pre": PRE_ENCRYPTED}
            mine = session.execute(sa.select(UserChannel)).scalar_one()
            assert mine.config == WEBHOOK

        # Downgrade one step: plaintext JSON again, JSON declared type again.
        command.downgrade(alembic_cfg, "-1")
        with engine.connect() as conn:
            assert _declared_type(conn, "notification_channels") == "JSON"
            assert _declared_type(conn, "user_channels") == "JSON"
        channels = _raw(engine, "notification_channels")
        assert json.loads(channels[ids["slack"]]) == SLACK
        assert json.loads(channels[ids["smtp"]]) == SMTP
        assert json.loads(channels[ids["pre"]]) == PRE_ENCRYPTED
        assert json.loads(_raw(engine, "user_channels")[ids["webhook"]]) == WEBHOOK

        # And up again: every row encrypted, nothing lost.
        command.upgrade(alembic_cfg, REVISION)
        channels = _raw(engine, "notification_channels")
        assert all(v.startswith(ENCRYPTED_PREFIX) for v in channels.values())
        assert decrypt_json(
            channels[ids["pre"]], keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
        ) == (PRE_ENCRYPTED, False), "the cycle re-wrapped it under the current master"
    finally:
        engine.dispose()


def test_fresh_schema_reaches_head_with_text_columns(alembic_cfg: Config) -> None:
    """A fresh chain declares JSON at the previous revision; this ALTER makes it TEXT.

    The initial migration builds the two channel tables in their frozen
    original shape, not from the live models, so a fresh install reaches
    this revision with ``JSON`` too and the batch ALTER runs for it exactly
    as it does for an upgraded database; head declares ``TEXT`` either way.
    """
    command.upgrade(alembic_cfg, REVISION)
    engine = create_engine(alembic_cfg.attributes["test_sync_url"])
    try:
        with engine.connect() as conn:
            assert _declared_type(conn, "notification_channels") == "TEXT"
            assert _declared_type(conn, "user_channels") == "TEXT"
            assert conn.execute(sa.text("SELECT COUNT(*) FROM notification_channels")).scalar() == 0
    finally:
        engine.dispose()
