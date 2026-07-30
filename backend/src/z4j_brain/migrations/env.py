"""Alembic environment for the brain.

Reads the database URL from :class:`z4j_brain.settings.Settings`
(which itself reads ``Z4J_DATABASE_URL``) so there is exactly one
source of truth for the connection string.

Async engine via SQLAlchemy 2 + asyncpg. Migrations run inside an
async transaction. ``target_metadata`` points at
:attr:`z4j_brain.persistence.Base.metadata` - every model imported
into the brain's ORM tree is therefore eligible for autogenerate.
"""

from __future__ import annotations

import asyncio
import contextlib
from logging.config import fileConfig

from alembic import context
from sqlalchemy import event, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from z4j_brain.configuration import (
    ConfigurationSnapshot,
    capture_configuration,
    export_snapshot_environment,
    settings_from_snapshot,
)
from z4j_brain.migrations import MIGRATION_SETTINGS_ATTRIBUTE
from z4j_brain.persistence import Base
from z4j_brain.persistence import models as _models  # noqa: F401
from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY

# Force-import the ``models`` submodule so every model class
# registers with ``Base.metadata`` before alembic reads it.
# Without this line, ``Base.metadata.tables`` is EMPTY when
# alembic runs from a fresh ``pip install`` (no test fixtures
# loading the models as a side effect) and
# ``Base.metadata.create_all`` silently creates zero tables.
# This was exactly the bug the 1.3.0 release-discipline smoke
# test caught, easy to miss without a clean-venv run.

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
_supplied_snapshot = config.attributes.get("z4j_configuration_snapshot")
if _supplied_snapshot is not None and not isinstance(
    _supplied_snapshot,
    ConfigurationSnapshot,
):
    raise TypeError("z4j_configuration_snapshot must be a ConfigurationSnapshot")
_migration_snapshot: ConfigurationSnapshot | None = _supplied_snapshot


def _migration_settings():
    """Bind one captured Settings object for every migration body."""

    global _migration_snapshot  # noqa: PLW0603  one invocation snapshot
    if _migration_snapshot is None:
        _migration_snapshot = capture_configuration()
        export_snapshot_environment(_migration_snapshot)
    settings = settings_from_snapshot(_migration_snapshot)
    config.attributes["z4j_configuration_snapshot"] = _migration_snapshot
    config.attributes[MIGRATION_SETTINGS_ATTRIBUTE] = settings
    return settings


def _resolve_database_url() -> str:
    """Pull the URL from settings, never from alembic.ini."""

    return _migration_settings().database_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (URL string only, no engine).

    Useful for generating SQL files for review before applying. The
    URL still comes from settings, not from alembic.ini.
    """
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(
    connection: Connection,
    *,
    schema_lock_already_held: bool = False,
) -> None:
    """Sync callback executed inside the async connection."""
    _migration_settings()
    # Per-migration transaction is required so individual
    # migrations can opt into ``op.get_context().autocommit_block()``
    # for ``CREATE INDEX CONCURRENTLY`` and other statements
    # that Postgres refuses inside a transaction. Without this
    # each ``with autocommit_block`` exits then re-enters the
    # SAME enclosing transaction; CONCURRENTLY still errors and
    # silently downgrades to a blocking lock.
    # This marker is authority only within one live Alembic invocation.  The
    # historical initial migration may set it and F activation may consume it
    # later in this same run; a later command using the same Config object gets
    # no credit for that old observation.
    config.attributes.pop("z4j_fresh_schema_bootstrap", None)

    sqlite = connection.dialect.name == "sqlite"
    postgres = connection.dialect.name == "postgresql"

    def _begin_exclusive(conn: Connection) -> None:
        conn.exec_driver_sql("BEGIN EXCLUSIVE")

    if postgres and not schema_lock_already_held:
        # Alembic deliberately commits once per migration, so retain a
        # session-scoped form of the release-wide schema lock across the
        # entire direct/CLI Alembic invocation. It conflicts with the
        # transaction-scoped form used by reset and partition DDL.
        connection.exec_driver_sql(
            f"SELECT pg_advisory_lock({SCHEMA_TRANSITION_ADVISORY_LOCK_KEY})",
        )
        connection.commit()
    if sqlite:
        # pysqlite/aiosqlite otherwise starts transactions late and Alembic
        # labels DDL non-transactional.  Disable the driver's implicit BEGIN,
        # make Alembic own the transaction, and use EXCLUSIVE for every
        # per-migration unit.  Preparation can therefore commit separately
        # while every activation DDL/DML/version-row change is all-or-nothing.
        connection.connection.dbapi_connection.isolation_level = None
        event.listen(connection.engine, "begin", _begin_exclusive)
    try:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            transaction_per_migration=True,
            transactional_ddl=True if sqlite else None,
        )
        with context.begin_transaction():
            context.run_migrations()
    finally:
        if sqlite:
            event.remove(connection.engine, "begin", _begin_exclusive)
        if postgres and not schema_lock_already_held:
            if connection.in_transaction():
                connection.rollback()
            connection.exec_driver_sql(
                f"SELECT pg_advisory_unlock({SCHEMA_TRANSITION_ADVISORY_LOCK_KEY})",
            )
            connection.commit()


async def run_async_migrations() -> None:
    """Configure and run migrations against the async engine."""
    global _migration_snapshot  # noqa: PLW0603  one invocation snapshot
    config_section = config.get_section(config.config_ini_section, {}) or {}
    coordinator: contextlib.AbstractContextManager[None]
    if _migration_snapshot is None:
        preliminary = capture_configuration(include_secret_store=False)
        database_hint = preliminary.values.get("Z4J_DATABASE_URL", "")
    else:
        database_hint = _migration_snapshot.values.get("Z4J_DATABASE_URL", "")
    if database_hint.startswith("sqlite"):
        from z4j_core.paths import z4j_home

        from z4j_brain.secret_store import audit_bootstrap_coordinator

        coordinator = audit_bootstrap_coordinator(z4j_home())
    else:
        coordinator = contextlib.nullcontext()

    with coordinator:
        if _migration_snapshot is None:
            from z4j_core.paths import z4j_home

            from z4j_brain.configuration import merge_secret_store_snapshot
            from z4j_brain.secret_store import read_secret_store

            store_path = z4j_home() / "secret.env"
            try:
                store_path.lstat()
            except FileNotFoundError:
                store_values = {}
            else:
                store_values = read_secret_store(store_path).values
            _migration_snapshot = merge_secret_store_snapshot(
                preliminary,
                store_values,
            )
            export_snapshot_environment(_migration_snapshot)
        database_url = _resolve_database_url()
        from z4j_brain.management_restore import (
            assert_database_restore_not_pending,
            install_database_restore_fence_engine_hook,
        )

        assert_database_restore_not_pending(database_url)
        config_section["sqlalchemy.url"] = database_url
        connectable = async_engine_from_config(
            config_section,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            future=True,
        )
        install_database_restore_fence_engine_hook(
            connectable,
            database_url,
        )
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
        await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against the live database."""
    supplied_connection = config.attributes.get(
        "z4j_restore_connection",
    )
    if supplied_connection is not None:
        if not isinstance(supplied_connection, Connection):
            raise TypeError(
                "z4j_restore_connection must be a synchronous Connection",
            )
        do_run_migrations(
            supplied_connection,
            schema_lock_already_held=True,
        )
        return
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
