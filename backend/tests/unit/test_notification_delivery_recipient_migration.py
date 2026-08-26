"""SQLite migration contracts for durable notification recipients."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.util import CommandError
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from z4j_brain.persistence.models import (
    NotificationDelivery,
    Project,
    User,
    UserSubscription,
)
from z4j_brain.secret_store import protect_secret_store_directory

_PRIOR_REVISION = "v1_9_automation_rolling_window"
_RECIPIENT_REVISION = "v1_9_delivery_recipient"
_TABLE = "notification_deliveries"
_COLUMN = "recipient_user_id"
_FK = "fk_notification_deliveries_recipient_user_id_users"
_INDEX = "ix_notification_deliveries_recipient_sent"


@pytest.fixture
def recipient_alembic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Config]:
    database_path = tmp_path / "notification-recipient.sqlite"
    sync_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{database_path}")
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = tmp_path / "z4j-home"
    private_home.mkdir(mode=0o700)
    protect_secret_store_directory(private_home)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    config.attributes["test_sync_url"] = sync_url
    yield config


def _engine(config: Config) -> Engine:
    return create_engine(config.attributes["test_sync_url"])


def _recipient_schema(engine: Engine) -> tuple[object, ...]:
    inspector = inspect(engine)
    columns = tuple(column["name"] for column in inspector.get_columns(_TABLE))
    foreign_keys = tuple(
        sorted(
            (
                foreign_key.get("name"),
                tuple(foreign_key.get("constrained_columns") or ()),
                foreign_key.get("referred_table"),
                tuple(foreign_key.get("referred_columns") or ()),
                str((foreign_key.get("options") or {}).get("ondelete", "")).upper(),
            )
            for foreign_key in inspector.get_foreign_keys(_TABLE)
            if _COLUMN in (foreign_key.get("constrained_columns") or ())
        ),
    )
    indexes = tuple(
        sorted(
            (
                index.get("name"),
                tuple(index.get("column_names") or ()),
                bool(index.get("unique")),
            )
            for index in inspector.get_indexes(_TABLE)
            if index.get("name") == _INDEX
        ),
    )
    with engine.connect() as connection:
        index_sql = connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
            (_INDEX,),
        ).scalar_one()
    return columns, foreign_keys, indexes, index_sql


def _assert_canonical_recipient_schema(engine: Engine) -> None:
    columns, foreign_keys, indexes, index_sql = _recipient_schema(engine)
    assert columns == tuple(column.name for column in NotificationDelivery.__table__.columns)
    assert foreign_keys == (
        (
            _FK,
            (_COLUMN,),
            "users",
            ("id",),
            "SET NULL",
        ),
    )
    assert indexes == ((_INDEX, (_COLUMN, "sent_at"), False),)
    normalized_index_sql = " ".join(str(index_sql).lower().split())
    assert "(recipient_user_id, sent_at desc)" in normalized_index_sql


def _remove_model_precreated_recipient(engine: Engine) -> None:
    """Reproduce the physical schema persisted by the prior release."""

    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}
    if _COLUMN not in columns:
        return
    indexes = {index.get("name") for index in inspector.get_indexes(_TABLE)}
    recipient_foreign_keys = {
        foreign_key.get("name")
        for foreign_key in inspector.get_foreign_keys(_TABLE)
        if _COLUMN in (foreign_key.get("constrained_columns") or ())
    }
    with engine.begin() as connection:
        operations = Operations(MigrationContext.configure(connection))
        if _INDEX in indexes:
            operations.drop_index(_INDEX, table_name=_TABLE)
        with operations.batch_alter_table(_TABLE) as batch:
            if _FK in recipient_foreign_keys:
                batch.drop_constraint(_FK, type_="foreignkey")
            batch.drop_column(_COLUMN)


def _seed_prior_delivery(engine: Engine) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    subscription_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Project(
                    id=project_id,
                    slug=f"recipient-{uuid.uuid4().hex[:8]}",
                    name="Recipient migration",
                ),
                User(
                    id=user_id,
                    email=f"recipient-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash="test-only-hash",
                ),
            ],
        )
        session.flush()
        session.add(
            UserSubscription(
                id=subscription_id,
                user_id=user_id,
                project_id=project_id,
                trigger="task.failed",
                filters={},
                in_app=False,
                project_channel_ids=[],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            ),
        )
        session.flush()
        # The current ORM knows about recipient_user_id, while this database
        # deliberately reproduces the old physical table. Use the exact old
        # insert projection so the test cannot accidentally depend on today's
        # nullable column being present.
        session.execute(
            text(
                "INSERT INTO notification_deliveries "
                "(id, subscription_id, project_id, trigger, status) "
                "VALUES (:id, :subscription_id, :project_id, 'task.failed', 'sent')",
            ),
            {
                "id": delivery_id.hex,
                "subscription_id": subscription_id.hex,
                "project_id": project_id.hex,
            },
        )
        session.commit()
    return user_id, project_id, subscription_id, delivery_id


def _prepare_prior_upgrade(config: Config) -> tuple[Engine, uuid.UUID, uuid.UUID, uuid.UUID]:
    command.upgrade(config, _PRIOR_REVISION)
    engine = _engine(config)
    _remove_model_precreated_recipient(engine)
    user_id, _project_id, subscription_id, delivery_id = _seed_prior_delivery(engine)
    command.upgrade(config, "head")
    return engine, user_id, subscription_id, delivery_id


def _database_snapshot(engine: Engine) -> tuple[object, ...]:
    with engine.connect() as connection:
        version = connection.exec_driver_sql(
            "SELECT version_num FROM alembic_version",
        ).scalar_one()
        schema = tuple(
            tuple(row)
            for row in connection.exec_driver_sql(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            ).all()
        )
        deliveries = tuple(
            tuple(row)
            for row in connection.exec_driver_sql(
                "SELECT id, subscription_id, recipient_user_id, project_id, trigger, status "
                "FROM notification_deliveries ORDER BY id",
            ).all()
        )
    return version, schema, deliveries


def _schema_snapshot(engine: Engine) -> tuple[object, ...]:
    with engine.connect() as connection:
        return (
            connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version",
            ).scalar_one(),
            tuple(
                tuple(row)
                for row in connection.exec_driver_sql(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
                ).all()
            ),
        )


def _delivery_schema_sql(engine: Engine) -> tuple[tuple[object, ...], ...]:
    with engine.connect() as connection:
        return tuple(
            tuple(row)
            for row in connection.exec_driver_sql(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE (type = 'table' AND name = ?) "
                "OR (type IN ('index', 'trigger') AND tbl_name = ?) "
                "ORDER BY type, name",
                (_TABLE, _TABLE),
            ).all()
        )


def test_fresh_head_has_canonical_recipient_schema(recipient_alembic: Config) -> None:
    command.upgrade(recipient_alembic, "head")
    engine = _engine(recipient_alembic)
    try:
        _assert_canonical_recipient_schema(engine)
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version",
                ).scalar_one()
                != _PRIOR_REVISION
            )
    finally:
        engine.dispose()


def test_fresh_and_split_upgrade_emit_identical_sqlite_schema(
    recipient_alembic: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command.upgrade(recipient_alembic, "head")
    fresh_engine = _engine(recipient_alembic)
    split_config = Config(recipient_alembic.config_file_name)
    split_config.set_main_option(
        "script_location",
        recipient_alembic.get_main_option("script_location"),
    )
    split_path = tmp_path / "notification-recipient-split.sqlite"
    split_config.attributes["test_sync_url"] = f"sqlite:///{split_path}"
    try:
        fresh_schema = _delivery_schema_sql(fresh_engine)
        monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{split_path}")
        command.upgrade(split_config, _PRIOR_REVISION)
        command.upgrade(split_config, "head")
        split_engine = _engine(split_config)
        try:
            assert _delivery_schema_sql(split_engine) == fresh_schema
        finally:
            split_engine.dispose()
    finally:
        fresh_engine.dispose()


def test_prior_upgrade_backfills_and_preserves_privacy_fk(
    recipient_alembic: Config,
) -> None:
    engine, user_id, subscription_id, delivery_id = _prepare_prior_upgrade(
        recipient_alembic,
    )
    try:
        _assert_canonical_recipient_schema(engine)
        with engine.connect() as connection:
            row = connection.exec_driver_sql(
                "SELECT subscription_id, recipient_user_id "
                "FROM notification_deliveries WHERE id = ?",
                (delivery_id.hex,),
            ).one()
        assert tuple(row) == (subscription_id.hex, user_id.hex)

        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()
            with connection.begin():
                connection.exec_driver_sql(
                    "DELETE FROM user_subscriptions WHERE id = ?",
                    (subscription_id.hex,),
                )
        with engine.connect() as connection:
            row = connection.exec_driver_sql(
                "SELECT subscription_id, recipient_user_id "
                "FROM notification_deliveries WHERE id = ?",
                (delivery_id.hex,),
            ).one()
        assert tuple(row) == (None, user_id.hex)

        # Deleting the account erases the personal association while retaining
        # the project-scoped delivery audit row.
        with engine.connect() as connection:
            # This focused migration fixture uses a plain SQLAlchemy engine,
            # outside DatabaseManager's SQLite connection hooks.  Account
            # deletion touches schedule-control triggers even though the
            # fixture has no schedules, so install the trigger's required UDF
            # with a permissive test-only result; the assertion below remains
            # solely about the recipient FK's SET NULL behaviour.
            connection.connection.driver_connection.create_function(
                "z4j_schedule_guard",
                8,
                lambda *_arguments: 1,
            )
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()
            with connection.begin():
                connection.exec_driver_sql(
                    "DELETE FROM users WHERE id = ?",
                    (user_id.hex,),
                )
        with engine.connect() as connection:
            row = connection.exec_driver_sql(
                "SELECT subscription_id, recipient_user_id "
                "FROM notification_deliveries WHERE id = ?",
                (delivery_id.hex,),
            ).one()
        assert tuple(row) == (None, None)
    finally:
        engine.dispose()


def test_stacked_downgrade_refusal_is_non_mutating(
    recipient_alembic: Config,
) -> None:
    engine, user_id, subscription_id, delivery_id = _prepare_prior_upgrade(
        recipient_alembic,
    )
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()
            with connection.begin():
                connection.exec_driver_sql(
                    "DELETE FROM user_subscriptions WHERE id = ?",
                    (subscription_id.hex,),
                )
        before = _database_snapshot(engine)
        assert before[0] != _RECIPIENT_REVISION or before[0] == _RECIPIENT_REVISION
        assert before[2] == (
            (
                delivery_id.hex,
                None,
                user_id.hex,
                before[2][0][3],
                "task.failed",
                "sent",
            ),
        )

        with pytest.raises(CommandError, match="retain personal history only"):
            command.downgrade(recipient_alembic, "v1_8_schedule_cursor_repair")

        after = _database_snapshot(engine)
        assert after == before
    finally:
        engine.dispose()


def test_reconstructable_owner_allows_round_trip(recipient_alembic: Config) -> None:
    engine, user_id, subscription_id, delivery_id = _prepare_prior_upgrade(
        recipient_alembic,
    )
    try:
        command.downgrade(recipient_alembic, _PRIOR_REVISION)
        inspector = inspect(engine)
        assert _COLUMN not in {column["name"] for column in inspector.get_columns(_TABLE)}
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT subscription_id FROM notification_deliveries WHERE id = ?",
                    (delivery_id.hex,),
                ).scalar_one()
                == subscription_id.hex
            )

        command.upgrade(recipient_alembic, "head")
        _assert_canonical_recipient_schema(engine)
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT recipient_user_id FROM notification_deliveries WHERE id = ?",
                    (delivery_id.hex,),
                ).scalar_one()
                == user_id.hex
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "index_ddl",
    [
        f"CREATE INDEX {_INDEX} ON {_TABLE} ({_COLUMN}, sent_at)",
        (
            f"CREATE INDEX {_INDEX} ON {_TABLE} ({_COLUMN}, sent_at DESC) "
            f"WHERE {_COLUMN} IS NOT NULL"
        ),
    ],
    ids=["ascending", "partial"],
)
def test_upgrade_rejects_noncanonical_recipient_index_without_mutation(
    recipient_alembic: Config,
    index_ddl: str,
) -> None:
    command.upgrade(recipient_alembic, _PRIOR_REVISION)
    engine = _engine(recipient_alembic)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER TABLE {_TABLE} ADD COLUMN {_COLUMN} CHAR(32)",
            )
            connection.exec_driver_sql(index_ddl)
        before = _schema_snapshot(engine)

        with pytest.raises(CommandError, match=f"index {_INDEX}"):
            command.upgrade(recipient_alembic, "head")

        assert _schema_snapshot(engine) == before
    finally:
        engine.dispose()


def test_upgrade_rejects_duplicate_recipient_foreign_keys_without_mutation(
    recipient_alembic: Config,
) -> None:
    command.upgrade(recipient_alembic, _PRIOR_REVISION)
    engine = _engine(recipient_alembic)
    try:
        with engine.begin() as connection:
            operations = Operations(MigrationContext.configure(connection))
            operations.drop_index(
                "ix_notification_deliveries_project_sent",
                table_name=_TABLE,
            )
            with operations.batch_alter_table(_TABLE) as batch:
                batch.add_column(sa.Column(_COLUMN, sa.Uuid(), nullable=True))
                batch.create_foreign_key(
                    _FK,
                    "users",
                    [_COLUMN],
                    ["id"],
                    ondelete="SET NULL",
                )
                batch.create_foreign_key(
                    "fk_notification_deliveries_recipient_conflict",
                    "users",
                    [_COLUMN],
                    ["id"],
                    ondelete="CASCADE",
                )
            connection.exec_driver_sql(
                "CREATE INDEX ix_notification_deliveries_project_sent "
                f"ON {_TABLE} (project_id, sent_at DESC)",
            )
        before = _schema_snapshot(engine)

        with pytest.raises(CommandError, match="duplicate or conflicting foreign keys"):
            command.upgrade(recipient_alembic, "head")

        assert _schema_snapshot(engine) == before
    finally:
        engine.dispose()


def test_upgrade_never_overwrites_conflicting_project_feed_index(
    recipient_alembic: Config,
) -> None:
    command.upgrade(recipient_alembic, _PRIOR_REVISION)
    engine = _engine(recipient_alembic)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP INDEX ix_notification_deliveries_project_sent",
            )
            connection.exec_driver_sql(
                "CREATE INDEX ix_notification_deliveries_project_sent "
                f"ON {_TABLE} (project_id, sent_at)",
            )
        before = _schema_snapshot(engine)

        with pytest.raises(
            CommandError,
            match="ix_notification_deliveries_project_sent",
        ):
            command.upgrade(recipient_alembic, "head")

        assert _schema_snapshot(engine) == before
    finally:
        engine.dispose()


def test_downgrade_rejects_conflicting_recipient_index_without_mutation(
    recipient_alembic: Config,
) -> None:
    command.upgrade(recipient_alembic, "head")
    engine = _engine(recipient_alembic)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(f"DROP INDEX {_INDEX}")
            connection.exec_driver_sql(
                f"CREATE INDEX {_INDEX} ON {_TABLE} ({_COLUMN}, sent_at)",
            )
        before = _schema_snapshot(engine)

        with pytest.raises(CommandError, match=f"index {_INDEX}"):
            command.downgrade(recipient_alembic, _PRIOR_REVISION)

        assert _schema_snapshot(engine) == before
    finally:
        engine.dispose()


def test_downgrade_never_overwrites_conflicting_project_feed_index(
    recipient_alembic: Config,
) -> None:
    command.upgrade(recipient_alembic, "head")
    engine = _engine(recipient_alembic)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP INDEX ix_notification_deliveries_project_sent",
            )
            connection.exec_driver_sql(
                "CREATE INDEX ix_notification_deliveries_project_sent "
                f"ON {_TABLE} (project_id, sent_at)",
            )
        before = _schema_snapshot(engine)

        with pytest.raises(
            CommandError,
            match="ix_notification_deliveries_project_sent",
        ):
            command.downgrade(recipient_alembic, _PRIOR_REVISION)

        assert _schema_snapshot(engine) == before
    finally:
        engine.dispose()
