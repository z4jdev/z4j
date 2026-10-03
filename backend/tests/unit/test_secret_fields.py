"""Encrypted JSON columns: format, rotation, re-wrap and the ORM type.

Covers ``z4j_brain.domain.secret_fields`` and ``EncryptedJSON`` on SQLite.
The rotation tests pair a negative control (dropping the old master without
a re-wrap breaks decryption) with the positive path (``rewrap`` first, then
drop), because the TOTP orphaning in the 1.9.0 audit was exactly the case
where only the positive path had been exercised.
"""

from __future__ import annotations

import base64
import json
import uuid
from unittest.mock import Mock, patch

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain import secret_fields as secret_fields_module
from z4j_brain.domain.mfa.crypto import decrypt_totp_secret, encrypt_totp_secret
from z4j_brain.domain.secret_fields import (
    ENCRYPTED_PREFIX,
    NOTIFICATION_CHANNEL_CONFIG,
    USER_CHANNEL_CONFIG,
    DecryptionFailed,
    EncryptedJSONWriteError,
    SecretKeyring,
    SecretKeyringUnbound,
    bind_keyring,
    decrypt_json,
    encrypt_json,
    is_encrypted,
    rewrap_all_secret_fields,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence import types as persistence_types
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import NotificationChannel, Project, User, UserChannel

OLD = "old-master-secret-" + "o" * 30
NEW = "new-master-secret-" + "n" * 30
OTHER = "unrelated-master-" + "u" * 30

CONFIG = {
    "webhook_url": "https://hooks.slack.com/services/T000/B000/HUNTER2SLACK",
    "hmac_secret": "hunter2-hmac",
    "headers": {"X-Custom": "1"},
    "retries": 3,
}


def _keyring(current: str, *previous: str) -> SecretKeyring:
    return SecretKeyring.from_secrets(current, previous)


# ---------------------------------------------------------------------------
# Format
# ---------------------------------------------------------------------------


class TestFormat:
    def test_round_trip_and_storage_shape(self) -> None:
        blob = encrypt_json(CONFIG, keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG)
        assert is_encrypted(blob)
        assert blob.startswith(ENCRYPTED_PREFIX)
        raw = base64.b64decode(blob[len(ENCRYPTED_PREFIX) :], validate=True)
        assert len(raw) > 12 + 16, "nonce plus tag at least"
        for secret in ("HUNTER2SLACK", "hunter2-hmac", "webhook_url"):
            assert secret not in blob
        value, needs_rewrap = decrypt_json(
            blob, keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG
        )
        assert value == CONFIG
        assert needs_rewrap is False

    def test_each_write_uses_a_fresh_nonce(self) -> None:
        keyring = _keyring(NEW)
        a = encrypt_json(CONFIG, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)
        b = encrypt_json(CONFIG, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)
        assert a != b

    def test_purpose_separates_columns(self) -> None:
        keyring = _keyring(NEW)
        blob = encrypt_json(CONFIG, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)
        with pytest.raises(DecryptionFailed):
            decrypt_json(blob, keyring=keyring, purpose=USER_CHANNEL_CONFIG)

    def test_plaintext_and_garbage_are_refused(self) -> None:
        keyring = _keyring(NEW)
        with pytest.raises(DecryptionFailed):
            decrypt_json(json.dumps(CONFIG), keyring=keyring, purpose=USER_CHANNEL_CONFIG)
        with pytest.raises(DecryptionFailed):
            decrypt_json(ENCRYPTED_PREFIX + "not base64!", keyring=keyring, purpose="x")
        with pytest.raises(DecryptionFailed):
            decrypt_json(ENCRYPTED_PREFIX + "AAAA", keyring=keyring, purpose="x")

    def test_tampered_ciphertext_is_refused(self) -> None:
        keyring = _keyring(NEW)
        blob = encrypt_json(CONFIG, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)
        raw = bytearray(base64.b64decode(blob[len(ENCRYPTED_PREFIX) :]))
        raw[-1] ^= 0x01
        tampered = ENCRYPTED_PREFIX + base64.b64encode(bytes(raw)).decode()
        with pytest.raises(DecryptionFailed):
            decrypt_json(tampered, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG)

    def test_empty_master_is_refused(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            SecretKeyring(current=b"")


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotation:
    def test_previous_secret_decrypts_and_flags_rewrap(self) -> None:
        blob = encrypt_json(CONFIG, keyring=_keyring(OLD), purpose=USER_CHANNEL_CONFIG)
        value, needs_rewrap = decrypt_json(
            blob, keyring=_keyring(NEW, OLD), purpose=USER_CHANNEL_CONFIG
        )
        assert value == CONFIG
        assert needs_rewrap is True

    def test_dropping_old_secret_without_rewrap_breaks_decrypt(self) -> None:
        """Negative control for the re-wrap tests below."""
        blob = encrypt_json(CONFIG, keyring=_keyring(OLD), purpose=USER_CHANNEL_CONFIG)
        with pytest.raises(DecryptionFailed, match="secrets rewrap"):
            decrypt_json(blob, keyring=_keyring(NEW), purpose=USER_CHANNEL_CONFIG)

    def test_rewrap_then_drop_old_secret_works(self) -> None:
        blob = encrypt_json(CONFIG, keyring=_keyring(OLD), purpose=USER_CHANNEL_CONFIG)
        value, _ = decrypt_json(blob, keyring=_keyring(NEW, OLD), purpose=USER_CHANNEL_CONFIG)
        rewrapped = encrypt_json(value, keyring=_keyring(NEW, OLD), purpose=USER_CHANNEL_CONFIG)
        value_after, needs_rewrap = decrypt_json(
            rewrapped, keyring=_keyring(NEW), purpose=USER_CHANNEL_CONFIG
        )
        assert value_after == CONFIG
        assert needs_rewrap is False


# ---------------------------------------------------------------------------
# Bulk re-wrap over a populated schema
# ---------------------------------------------------------------------------


def _populate(engine: sa.engine.Engine, keyring: SecretKeyring) -> dict[str, uuid.UUID]:
    """Create one project channel, one user channel and one MFA user under ``keyring``."""
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    channel_id = uuid.uuid4()
    user_channel_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            sa.insert(Project.__table__).values(id=project_id, slug="p", name="P"),
        )
        conn.execute(
            sa.insert(User.__table__).values(
                id=user_id,
                email="mfa@example.com",
                password_hash="x",
                mfa_secret_encrypted=encrypt_totp_secret(
                    b"totp-secret-20-bytes",
                    master_secret=keyring.current,
                    user_id=user_id,
                ),
            ),
        )
        # Raw text so the ORM type's own keyring does not take part.
        conn.execute(
            sa.text(
                "INSERT INTO notification_channels (id, project_id, name, type, config, "
                "is_active, created_at, updated_at) VALUES (:id, :pid, 'ops', 'slack', "
                ":config, 1, datetime('now'), datetime('now'))",
            ),
            {
                "id": channel_id.hex,
                "pid": project_id.hex,
                "config": encrypt_json(
                    CONFIG, keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
                ),
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO user_channels (id, user_id, name, type, config, is_verified, "
                "is_active, created_at, updated_at) VALUES (:id, :uid, 'mine', 'webhook', "
                ":config, 0, 1, datetime('now'), datetime('now'))",
            ),
            {
                "id": user_channel_id.hex,
                "uid": user_id.hex,
                "config": encrypt_json(CONFIG, keyring=keyring, purpose=USER_CHANNEL_CONFIG),
            },
        )
    return {
        "project": project_id,
        "user": user_id,
        "channel": channel_id,
        "user_channel": user_channel_id,
    }


def _stored(engine: sa.engine.Engine) -> dict[str, object]:
    with engine.connect() as conn:
        return {
            "channel": conn.execute(sa.text("SELECT config FROM notification_channels")).scalar(),
            "user_channel": conn.execute(sa.text("SELECT config FROM user_channels")).scalar(),
            "mfa": conn.execute(sa.text("SELECT mfa_secret_encrypted FROM users")).scalar(),
        }


_INSERT_CHANNEL = sa.text(
    "INSERT INTO notification_channels (id, project_id, name, type, config, "
    "is_active, created_at, updated_at) VALUES (:id, :pid, :name, 'slack', "
    ":config, 1, datetime('now'), datetime('now'))",
)


def _insert_channel_raw(
    engine: sa.engine.Engine, project_id: uuid.UUID, *, name: str, config_text: str
) -> uuid.UUID:
    """Store exactly ``config_text``: plaintext JSON, garbage, whatever a downgraded brain or a hand left there."""
    channel_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            _INSERT_CHANNEL,
            {"id": channel_id.hex, "pid": project_id.hex, "name": name, "config": config_text},
        )
    return channel_id


def _channel_configs(engine: sa.engine.Engine) -> dict[str, str]:
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT name, config FROM notification_channels")).all()
    return {str(name): str(config) for name, config in rows}


def _column(report: object, table: str) -> object:
    return next(c for c in report.columns if c.table == table)  # type: ignore[attr-defined]


def _everything_decrypts(
    engine: sa.engine.Engine, keyring: SecretKeyring, user_id: uuid.UUID
) -> None:
    stored = _stored(engine)
    assert decrypt_json(
        str(stored["channel"]), keyring=keyring, purpose=NOTIFICATION_CHANNEL_CONFIG
    ) == (CONFIG, False)
    assert decrypt_json(
        str(stored["user_channel"]), keyring=keyring, purpose=USER_CHANNEL_CONFIG
    ) == (CONFIG, False)
    plaintext, needs_rewrap = decrypt_totp_secret(
        bytes(stored["mfa"]),  # type: ignore[arg-type]
        master_secret=keyring.current,
        user_id=user_id,
        previous_secrets=keyring.previous,
    )
    assert plaintext == b"totp-secret-20-bytes"
    assert needs_rewrap is False


@pytest.fixture
def sync_engine(tmp_path):  # type: ignore[no-untyped-def]
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'fields.sqlite'}")
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


class TestRewrapAll:
    def test_rewrap_then_dropping_old_secret_leaves_everything_working(
        self, sync_engine: sa.engine.Engine
    ) -> None:
        ids = _populate(sync_engine, _keyring(OLD))

        with sync_engine.begin() as conn:
            report = rewrap_all_secret_fields(conn, keyring=_keyring(NEW, OLD))
        assert not report.refused
        assert report.failed == 0
        assert report.scanned == 3
        assert report.rewrapped == 3
        assert {c.table for c in report.columns} == {
            "notification_channels",
            "user_channels",
            "users",
        }

        # Old secret dropped: everything still decrypts under NEW alone.
        _everything_decrypts(sync_engine, _keyring(NEW), ids["user"])

        # A second run finds nothing to do.
        with sync_engine.begin() as conn:
            again = rewrap_all_secret_fields(conn, keyring=_keyring(NEW))
        assert again.rewrapped == 0
        assert again.decrypted == 3

    def test_without_rewrap_dropping_old_secret_breaks_every_row(
        self, sync_engine: sa.engine.Engine
    ) -> None:
        """Negative control: the same database, no rewrap, old secret gone."""
        ids = _populate(sync_engine, _keyring(OLD))
        stored = _stored(sync_engine)
        with pytest.raises(DecryptionFailed):
            decrypt_json(
                str(stored["channel"]), keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG
            )
        with pytest.raises(DecryptionFailed):
            decrypt_json(
                str(stored["user_channel"]), keyring=_keyring(NEW), purpose=USER_CHANNEL_CONFIG
            )
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                bytes(stored["mfa"]),  # type: ignore[arg-type]
                master_secret=NEW.encode(),
                user_id=ids["user"],
            )

    def test_refuses_and_writes_nothing_when_no_row_decrypts(
        self, sync_engine: sa.engine.Engine
    ) -> None:
        _populate(sync_engine, _keyring(OLD))
        before = _stored(sync_engine)
        with sync_engine.begin() as conn:
            report = rewrap_all_secret_fields(conn, keyring=_keyring(OTHER))
        assert report.refused
        assert report.decrypted == 0
        assert report.failed == 3
        assert _stored(sync_engine) == before

    def test_dry_run_reports_but_writes_nothing(self, sync_engine: sa.engine.Engine) -> None:
        _populate(sync_engine, _keyring(OLD))
        before = _stored(sync_engine)
        with sync_engine.begin() as conn:
            report = rewrap_all_secret_fields(conn, keyring=_keyring(NEW, OLD), dry_run=True)
        assert report.dry_run
        assert report.rewrapped == 3
        assert _stored(sync_engine) == before

    def test_plaintext_row_is_encrypted_and_counted(self, sync_engine: sa.engine.Engine) -> None:
        """One encrypted row and one plaintext row: the walk brings both under the master."""
        ids = _populate(sync_engine, _keyring(NEW))
        _insert_channel_raw(
            sync_engine, ids["project"], name="plain", config_text=json.dumps(CONFIG)
        )
        before = _channel_configs(sync_engine)
        assert is_encrypted(before["ops"]) and not is_encrypted(before["plain"])

        with sync_engine.begin() as conn:
            dry = rewrap_all_secret_fields(conn, keyring=_keyring(NEW), dry_run=True)
        assert (dry.plaintext, dry.rewrapped, dry.failed, dry.refused) == (1, 0, 0, False)
        assert _channel_configs(sync_engine) == before, "dry run wrote nothing"

        with sync_engine.begin() as conn:
            report = rewrap_all_secret_fields(conn, keyring=_keyring(NEW))
        assert (report.scanned, report.plaintext, report.failed) == (4, 1, 0)
        column = _column(report, "notification_channels")
        assert (column.scanned, column.already_current, column.plaintext) == (2, 1, 1)  # type: ignore[attr-defined]
        stored = _channel_configs(sync_engine)
        assert all(is_encrypted(value) for value in stored.values())
        assert stored["ops"] == before["ops"], "the row already under the master was not touched"
        assert decrypt_json(
            stored["plain"], keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG
        ) == (CONFIG, False)

        with sync_engine.begin() as conn:
            again = rewrap_all_secret_fields(conn, keyring=_keyring(NEW))
        assert (again.plaintext, again.rewrapped, again.decrypted) == (0, 0, 4)

    def test_non_json_plaintext_row_is_listed_not_crashed_on(
        self, sync_engine: sa.engine.Engine
    ) -> None:
        ids = _populate(sync_engine, _keyring(NEW))
        _insert_channel_raw(sync_engine, ids["project"], name="bad", config_text="not json at all")
        before = _channel_configs(sync_engine)
        with sync_engine.begin() as conn:
            report = rewrap_all_secret_fields(conn, keyring=_keyring(NEW))
        column = _column(report, "notification_channels")
        assert (len(column.failed), column.malformed, column.plaintext) == (1, 1, 0)  # type: ignore[attr-defined]
        assert not report.refused, "a row that is not ciphertext says nothing about the keyring"
        assert _channel_configs(sync_engine) == before

    @pytest.mark.parametrize("brain_wrote_under_current_master", [True, False])
    def test_row_changed_under_the_walk_keeps_the_brain_write(
        self,
        sync_engine: sa.engine.Engine,
        monkeypatch: pytest.MonkeyPatch,
        brain_wrote_under_current_master: bool,
    ) -> None:
        """A channel edit committed between the walk's read and its write wins."""
        ids = _populate(sync_engine, _keyring(OLD))
        walk_keyring = _keyring(NEW, OLD)
        brain_write = encrypt_json(
            {**CONFIG, "retries": 99},
            keyring=walk_keyring if brain_wrote_under_current_master else _keyring(OTHER),
            purpose=NOTIFICATION_CHANNEL_CONFIG,
        )
        real_encrypt = secret_fields_module.encrypt_json
        injected: list[str] = []
        with sync_engine.begin() as conn:

            def race(value: object, *, keyring: SecretKeyring, purpose: str) -> str:
                # Between SELECT and UPDATE: the row changes under the walk.
                if purpose == NOTIFICATION_CHANNEL_CONFIG and not injected:
                    injected.append(purpose)
                    conn.execute(
                        sa.text("UPDATE notification_channels SET config = :v WHERE id = :id"),
                        {"v": brain_write, "id": ids["channel"].hex},
                    )
                return real_encrypt(value, keyring=keyring, purpose=purpose)

            monkeypatch.setattr(secret_fields_module, "encrypt_json", race)
            report = rewrap_all_secret_fields(conn, keyring=walk_keyring)
        assert injected, "the race was injected"
        assert _stored(sync_engine)["channel"] == brain_write, "the brain's write survived"
        column = _column(report, "notification_channels")
        assert (column.changed_under_us, column.rewrapped) == (1, 0)  # type: ignore[attr-defined]
        assert report.rewrapped == 2, "the other two columns were still re-wrapped"
        if brain_wrote_under_current_master:
            assert column.failed == []  # type: ignore[attr-defined]
        else:
            assert column.failed == [ids["channel"].hex]  # type: ignore[attr-defined]

    def test_mfa_secret_re_enrolled_under_the_walk_keeps_the_new_secret(
        self, sync_engine: sa.engine.Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _populate(sync_engine, _keyring(OLD))
        re_enrolled = encrypt_totp_secret(
            b"re-enrolled-totp-20b", master_secret=NEW.encode(), user_id=ids["user"]
        )
        real_encrypt = secret_fields_module.encrypt_totp_secret
        injected: list[uuid.UUID] = []
        with sync_engine.begin() as conn:

            def race(plaintext: bytes, *, master_secret: bytes, user_id: uuid.UUID) -> bytes:
                if not injected:
                    injected.append(user_id)
                    conn.execute(
                        sa.text("UPDATE users SET mfa_secret_encrypted = :v WHERE id = :id"),
                        {"v": re_enrolled, "id": ids["user"].hex},
                    )
                return real_encrypt(plaintext, master_secret=master_secret, user_id=user_id)

            monkeypatch.setattr(secret_fields_module, "encrypt_totp_secret", race)
            report = rewrap_all_secret_fields(conn, keyring=_keyring(NEW, OLD))
        assert injected
        users = _column(report, "users")
        assert (users.changed_under_us, users.rewrapped, users.failed) == (1, 0, [])  # type: ignore[attr-defined]
        assert bytes(_stored(sync_engine)["mfa"]) == re_enrolled  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The ORM type
# ---------------------------------------------------------------------------


@pytest.fixture
async def session():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
class TestEncryptedJSONType:
    async def test_stored_blob_is_not_plaintext_and_reads_back_as_dict(
        self, session: AsyncSession
    ) -> None:
        bind_keyring(_keyring(NEW))
        project = Project(slug="p", name="P")
        session.add(project)
        await session.flush()
        channel = NotificationChannel(
            project_id=project.id, name="ops", type="slack", config=dict(CONFIG)
        )
        session.add(channel)
        await session.commit()

        stored = (
            await session.execute(sa.text("SELECT config FROM notification_channels"))
        ).scalar_one()
        assert isinstance(stored, str)
        assert stored.startswith(ENCRYPTED_PREFIX)
        assert "HUNTER2SLACK" not in stored and "hunter2-hmac" not in stored

        session.expire_all()
        loaded = (await session.execute(sa.select(NotificationChannel))).scalar_one()
        assert loaded.config == CONFIG

    async def test_user_channel_uses_its_own_purpose(self, session: AsyncSession) -> None:
        bind_keyring(_keyring(NEW))
        user = User(email="u@example.com", password_hash="x")
        session.add(user)
        await session.flush()
        session.add(UserChannel(user_id=user.id, name="mine", type="webhook", config=dict(CONFIG)))
        await session.commit()
        stored = (await session.execute(sa.text("SELECT config FROM user_channels"))).scalar_one()
        assert decrypt_json(stored, keyring=_keyring(NEW), purpose=USER_CHANNEL_CONFIG)[0] == CONFIG
        with pytest.raises(DecryptionFailed):
            decrypt_json(stored, keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG)

    async def test_row_under_previous_secret_reads_and_rewraps_on_write(
        self, session: AsyncSession
    ) -> None:
        bind_keyring(_keyring(OLD))
        project = Project(slug="p", name="P")
        session.add(project)
        await session.flush()
        channel = NotificationChannel(
            project_id=project.id, name="ops", type="slack", config=dict(CONFIG)
        )
        session.add(channel)
        await session.commit()
        session.expire_all()

        bind_keyring(_keyring(NEW, OLD))
        loaded = (await session.execute(sa.select(NotificationChannel))).scalar_one()
        assert loaded.config == CONFIG
        loaded.config = {**CONFIG, "retries": 5}
        await session.commit()

        stored = (
            await session.execute(sa.text("SELECT config FROM notification_channels"))
        ).scalar_one()
        value, needs_rewrap = decrypt_json(
            stored, keyring=_keyring(NEW), purpose=NOTIFICATION_CHANNEL_CONFIG
        )
        assert value["retries"] == 5
        assert needs_rewrap is False

    async def test_plaintext_json_text_is_read_and_encrypted_on_next_write(
        self, session: AsyncSession
    ) -> None:
        bind_keyring(_keyring(NEW))
        project = Project(slug="p", name="P")
        session.add(project)
        await session.commit()
        await session.execute(
            sa.text(
                "INSERT INTO notification_channels (id, project_id, name, type, config, "
                "is_active, created_at, updated_at) VALUES (:id, :pid, 'ops', 'slack', "
                ":config, 1, datetime('now'), datetime('now'))",
            ),
            {"id": uuid.uuid4().hex, "pid": project.id.hex, "config": json.dumps(CONFIG)},
        )
        await session.commit()
        loaded = (await session.execute(sa.select(NotificationChannel))).scalar_one()
        assert loaded.config == CONFIG
        loaded.config = dict(CONFIG)
        loaded.name = "ops-renamed"
        await session.commit()
        stored = (
            await session.execute(sa.text("SELECT config FROM notification_channels"))
        ).scalar_one()
        assert stored.startswith(ENCRYPTED_PREFIX)

    async def test_unbound_keyring_fails_closed_on_write(self, session: AsyncSession) -> None:
        bind_keyring(None)
        project = Project(slug="p", name="P")
        session.add(project)
        await session.flush()
        session.add(
            NotificationChannel(project_id=project.id, name="ops", type="slack", config={"a": 1})
        )
        with pytest.raises(SecretKeyringUnbound) as excinfo:
            await session.commit()
        assert "bind_keyring_from_settings" in str(excinfo.value)

    async def test_write_without_a_keyring_names_the_column_never_the_value(
        self, session: AsyncSession
    ) -> None:
        """SQLAlchemy must not wrap the error in a StatementError carrying the parameters."""
        bind_keyring(_keyring(NEW))
        project = Project(slug="p", name="P")
        session.add(project)
        await session.commit()
        bind_keyring(None)
        session.add(
            NotificationChannel(
                project_id=project.id, name="ops", type="slack", config=dict(CONFIG)
            )
        )
        with pytest.raises(SecretKeyringUnbound) as excinfo:
            await session.commit()
        text = str(excinfo.value)
        assert NOTIFICATION_CHANNEL_CONFIG in text and "bind_keyring_from_settings" in text
        for secret in ("HUNTER2SLACK", "hunter2-hmac", "webhook_url", "parameters"):
            assert secret not in text

    async def test_write_of_a_non_json_value_names_the_column_never_the_value(
        self, session: AsyncSession
    ) -> None:
        bind_keyring(_keyring(NEW))
        project = Project(slug="p", name="P")
        session.add(project)
        await session.commit()
        session.add(
            NotificationChannel(
                project_id=project.id,
                name="ops",
                type="slack",
                config={**CONFIG, "marker": uuid.uuid4()},
            )
        )
        with pytest.raises(EncryptedJSONWriteError) as excinfo:
            await session.commit()
        text = str(excinfo.value)
        assert NOTIFICATION_CHANNEL_CONFIG in text and "TypeError" in text
        for secret in ("HUNTER2SLACK", "hunter2-hmac", "webhook_url", "parameters"):
            assert secret not in text

    async def test_plaintext_read_warns_once_per_process_per_purpose(
        self, session: AsyncSession
    ) -> None:
        bind_keyring(_keyring(NEW))
        persistence_types.reset_plaintext_read_warnings()
        project = Project(slug="p", name="P")
        user = User(email="u@example.com", password_hash="x")
        session.add_all([project, user])
        await session.flush()
        session.add(
            NotificationChannel(
                project_id=project.id, name="enc", type="slack", config=dict(CONFIG)
            )
        )
        await session.commit()
        # Captured before expire_all(): an expired attribute would refresh
        # itself with sync IO, which the async session cannot do.
        project_id, user_id = project.id, user.id
        session.expire_all()

        recording = Mock()
        with patch.object(persistence_types, "logger", recording):
            # Negative control: an encrypted row does not warn.
            loaded = (await session.execute(sa.select(NotificationChannel))).scalar_one()
            assert loaded.config == CONFIG
            recording.warning.assert_not_called()

            for name in ("plain-one", "plain-two"):
                await session.execute(
                    _INSERT_CHANNEL,
                    {
                        "id": uuid.uuid4().hex,
                        "pid": project_id.hex,
                        "name": name,
                        "config": json.dumps(CONFIG),
                    },
                )
            await session.execute(
                sa.text(
                    "INSERT INTO user_channels (id, user_id, name, type, config, is_verified, "
                    "is_active, created_at, updated_at) VALUES (:id, :uid, 'mine', 'webhook', "
                    ":config, 0, 1, datetime('now'), datetime('now'))",
                ),
                {"id": uuid.uuid4().hex, "uid": user_id.hex, "config": json.dumps(CONFIG)},
            )
            await session.commit()
            session.expire_all()
            channels = (await session.execute(sa.select(NotificationChannel))).scalars().all()
            assert [c.config for c in channels] == [CONFIG] * 3
            assert (await session.execute(sa.select(UserChannel))).scalar_one().config == CONFIG
            # A flood: the same rows read again and again stay one warning.
            for _ in range(3):
                session.expire_all()
                (await session.execute(sa.select(NotificationChannel))).scalars().all()

        calls = recording.warning.call_args_list
        assert [call.kwargs["purpose"] for call in calls] == [
            NOTIFICATION_CHANNEL_CONFIG,
            USER_CHANNEL_CONFIG,
        ]
        for call in calls:
            assert call.args == ("encrypted_column_plaintext_read",)
            for secret in ("HUNTER2SLACK", "hunter2-hmac"):
                assert secret not in repr(call)
