"""Tests for password-change row locking.

SQLite covers the repository's ordinary contract.  The final, PostgreSQL-
gated test opens two independent transactions and proves that the second one
cannot acquire the same user's lock until the first transaction releases it.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import User
from z4j_brain.persistence.repositories import UserRepository


@pytest.fixture
async def engine():
    e = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with e.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield e
    await e.dispose()


@pytest.fixture
async def session(engine):
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s


@pytest.fixture
async def user(session: AsyncSession) -> User:
    u = User(
        email="alice@example.com",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$a$b",
        display_name="Alice",
        is_admin=False,
        is_active=True,
    )
    session.add(u)
    await session.commit()
    return u


@pytest.mark.asyncio
class TestLockForPasswordChange:
    async def test_returns_without_error(
        self,
        session: AsyncSession,
        user: User,
    ) -> None:
        """Minimum contract: the method runs cleanly for a real user."""
        repo = UserRepository(session)
        # Should not raise on SQLite (where FOR UPDATE is a no-op)
        # or on Postgres (where it acquires the row lock).
        await repo.lock_for_password_change(user.id)

    async def test_noop_for_missing_user(
        self,
        session: AsyncSession,
    ) -> None:
        """No error for a non-existent user id - the subsequent
        ``update_password_hash`` simply updates zero rows."""
        repo = UserRepository(session)
        await repo.lock_for_password_change(uuid.uuid4())

    async def test_ordering_with_update_password_hash(
        self,
        session: AsyncSession,
        user: User,
    ) -> None:
        """The lock → verify → update sequence used by the
        change_password handler must not raise on a happy path."""
        repo = UserRepository(session)
        await repo.lock_for_password_change(user.id)
        await repo.update_password_hash(
            user.id,
            "$argon2id$v=19$m=65536,t=3,p=4$c$d",
            password_changed=True,
        )
        await session.commit()
        refreshed = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        assert refreshed.password_hash.endswith("$c$d")
        assert refreshed.password_changed_at is not None


@pytest.mark.asyncio
async def test_postgres_serialises_two_independent_password_transactions() -> None:
    raw_url = os.environ.get("Z4J_TEST_POSTGRES_URL")
    if not raw_url:
        pytest.skip("set Z4J_TEST_POSTGRES_URL to exercise PostgreSQL row locking")
    database_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    schema_name = f"z4j_password_lock_{uuid.uuid4().hex}"
    admin_engine = create_async_engine(database_url)
    pg_engine = None
    schema_created = False
    user_id = uuid.uuid4()
    contender_started = asyncio.Event()
    contender_acquired = asyncio.Event()
    contender: asyncio.Task[None] | None = None
    primary_error: BaseException | None = None

    try:
        # This unit-suite lane receives a fresh PostgreSQL server, not a
        # migrated z4j database.  Create only the table this lock contract
        # needs, inside a run-unique schema.  Setting search_path on every
        # test-engine connection keeps both independent transactions away
        # from any pre-existing public tables or data at the explicit URL.
        async with admin_engine.begin() as admin:
            await admin.execute(CreateSchema(schema_name))
        schema_created = True

        pg_engine = create_async_engine(
            database_url,
            connect_args={"server_settings": {"search_path": schema_name}},
        )
        factory = sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
        async with pg_engine.begin() as setup:
            await setup.execute(text("CREATE TABLE users (id uuid PRIMARY KEY)"))
            await setup.execute(
                text("INSERT INTO users (id) VALUES (:user_id)"),
                {"user_id": user_id},
            )

        async def contend() -> None:
            async with factory() as second:
                contender_started.set()
                await UserRepository(second).lock_for_password_change(user_id)
                contender_acquired.set()
                await second.rollback()

        async with factory() as first:
            await UserRepository(first).lock_for_password_change(user_id)
            contender = asyncio.create_task(contend())
            await asyncio.wait_for(contender_started.wait(), timeout=2)

            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(contender_acquired.wait()),
                    timeout=0.2,
                )

            await first.commit()
            await asyncio.wait_for(asyncio.shield(contender), timeout=2)
            assert contender_acquired.is_set()
    except BaseException as exc:
        # Do not let teardown failures replace the assertion or database
        # failure that brought us here.  The finally block adds cleanup
        # failures as notes and this bare re-raise preserves the traceback.
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []

        if contender is not None:
            cancelled_for_cleanup = not contender.done()
            if cancelled_for_cleanup:
                contender.cancel()
            try:
                await contender
            except asyncio.CancelledError as exc:
                if not cancelled_for_cleanup and exc is not primary_error:
                    cleanup_errors.append(exc)
            except BaseException as exc:
                if exc is not primary_error:
                    cleanup_errors.append(exc)

        if pg_engine is not None:
            try:
                await pg_engine.dispose()
            except BaseException as exc:
                cleanup_errors.append(exc)

        if schema_created:
            try:
                async with admin_engine.begin() as admin:
                    await admin.execute(DropSchema(schema_name, cascade=True, if_exists=True))
            except BaseException as exc:
                cleanup_errors.append(exc)

        try:
            await admin_engine.dispose()
        except BaseException as exc:
            cleanup_errors.append(exc)

        if cleanup_errors:
            if primary_error is not None:
                for cleanup_error in cleanup_errors:
                    primary_error.add_note(
                        f"PostgreSQL test cleanup also failed: {cleanup_error!r}"
                    )
            else:
                raise BaseExceptionGroup(
                    "PostgreSQL password-lock test cleanup failed",
                    cleanup_errors,
                )
