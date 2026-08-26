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
from collections.abc import Callable, Sequence
from logging.config import fileConfig
from typing import Any

from alembic import context
from alembic.util import CommandError
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
from z4j_brain.postgres_tls import asyncpg_engine_url_and_connect_args
from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY
from z4j_brain.settings import Settings

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


def _migration_settings() -> Settings:
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


#: Module-level attribute a migration sets to declare that it will not be
#: undone, carrying the operator-facing reason as its value. Read off the
#: loaded module rather than matched against a list of revision ids kept here,
#: so a migration written later inherits the pre-flight below without anyone
#: remembering to come back and register it.
DOWNGRADE_REFUSED_ATTRIBUTE = "DOWNGRADE_REFUSED"

#: Module-level callable a migration sets when its downgrade permission depends
#: on live database state. The callable receives the online SQLAlchemy
#: connection and raises :class:`CommandError` when the downgrade would discard
#: state that the operator has not made safe. Like ``DOWNGRADE_REFUSED``, this
#: is revision metadata rather than a registry maintained in ``env.py`` so a
#: later guarded migration automatically participates in the whole-plan check.
DOWNGRADE_PREFLIGHT_ATTRIBUTE = "DOWNGRADE_PREFLIGHT"


def _assert_downgrade_plan_is_permitted(
    steps: Sequence[object],
    connection: Connection | None,
) -> None:
    """Refuse a downgrade run as a whole when any planned step refuses.

    ``transaction_per_migration`` means Alembic commits after every step, so a
    destructive step stacked above a refusing one finishes and commits before
    the refusal is ever reached. The operator is told the rollback failed while
    the columns it dropped are already gone, and the natural next move (upgrade
    back to head) re-adds them empty: the data is discarded with no error and
    no audit row. Only a decision taken over the complete plan can be honest
    about that, and taking it here covers every migration rather than the one
    that happened to expose the hole.
    """

    downgrade_revisions: list[Any] = []
    for step in steps:
        if getattr(step, "is_upgrade", True):
            continue
        revision = getattr(step, "revision", None)
        if revision is None:
            raise CommandError("downgrade plan step lacks revision metadata")
        downgrade_revisions.append(revision)
        reason = getattr(getattr(revision, "module", None), DOWNGRADE_REFUSED_ATTRIBUTE, None)
        if reason:
            raise CommandError(
                f"{reason}; refused before running any step of this downgrade, "
                f"so nothing stacked above {revision.revision} was dropped",
            )
    preflights: list[tuple[Any, Callable[[Connection], None]]] = []
    for revision in downgrade_revisions:
        callback = getattr(
            getattr(revision, "module", None),
            DOWNGRADE_PREFLIGHT_ATTRIBUTE,
            None,
        )
        if callback is None:
            continue
        if not callable(callback):
            raise CommandError(
                f"revision {revision.revision} declares "
                f"{DOWNGRADE_PREFLIGHT_ATTRIBUTE}, but it is not callable",
            )
        preflights.append((revision, callback))

    if preflights and connection is None:
        revisions = ", ".join(str(revision.revision) for revision, _ in preflights)
        raise CommandError(
            "offline downgrade SQL cannot evaluate live database-state "
            f"preflight(s) for revision(s) {revisions}; run the downgrade "
            "online so it can prove the guarded state is safe before emitting "
            "or executing destructive DDL",
        )

    if connection is not None:
        for _, callback in preflights:
            callback(connection)


def _install_downgrade_preflight(connection: Connection | None) -> None:
    """Have Alembic hand its resolved plan to the pre-flight first.

    ``MigrationContext.run_migrations`` asks the command for the step list once
    and then executes it. Wrapping that one call is the only seam that sees the
    whole plan and still runs ahead of its first step. Resolving the plan a
    second time from here instead would double the side effects of the other
    commands that route through this same hook, such as ``alembic current``.
    """

    migration_context = context.get_context()
    plan = migration_context._migrations_fn
    if plan is None:  # pragma: no cover - commands that run env with no plan
        return

    def guarded_plan(heads: Any, runtime_context: Any) -> list[Any]:
        steps = list(plan(heads, runtime_context))
        _assert_downgrade_plan_is_permitted(steps, connection)
        return steps

    migration_context._migrations_fn = guarded_plan


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
        # Conditional downgrade guards need live rows and therefore cannot be
        # represented truthfully in an offline SQL artifact. Installing the
        # plan hook with no connection makes such a downgrade fail closed
        # before any destructive SQL is emitted; offline upgrades and
        # unguarded downgrade ranges continue to render normally.
        _install_downgrade_preflight(None)
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
        dbapi_connection = connection.connection.dbapi_connection
        assert dbapi_connection is not None
        dbapi_connection.isolation_level = None
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
            _install_downgrade_preflight(connection)
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
        engine_url, tls_connect_args = asyncpg_engine_url_and_connect_args(
            database_url,
        )
        from z4j_brain.management_restore import (
            assert_database_restore_not_pending,
            install_database_restore_fence_engine_hook,
        )

        assert_database_restore_not_pending(database_url)
        config_section["sqlalchemy.url"] = engine_url
        connectable = async_engine_from_config(
            config_section,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            future=True,
            connect_args=tls_connect_args,
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
