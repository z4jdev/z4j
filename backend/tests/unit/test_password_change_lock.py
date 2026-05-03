"""Tests for the Batch-3 H6 fix: concurrent change_password serialises
via ``UserRepository.lock_for_password_change``.

SQLite doesn't honour ``SELECT ... FOR UPDATE`` at the row level, but
the method itself must still (a) run without error and (b) issue the
statement. On Postgres it serialises two parallel transactions.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
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
        self, session: AsyncSession, user: User,
    ) -> None:
        """Minimum contract: the method runs cleanly for a real user."""
        repo = UserRepository(session)
        # Should not raise on SQLite (where FOR UPDATE is a no-op)
        # or on Postgres (where it acquires the row lock).
        await repo.lock_for_password_change(user.id)

    async def test_noop_for_missing_user(
        self, session: AsyncSession,
    ) -> None:
        """No error for a non-existent user id - the subsequent
        ``update_password_hash`` simply updates zero rows."""
        repo = UserRepository(session)
        await repo.lock_for_password_change(uuid.uuid4())

    async def test_ordering_with_update_password_hash(
        self, session: AsyncSession, user: User,
    ) -> None:
        """The lock → verify → update sequence used by the
        change_password handler must not raise on a happy path."""
        repo = UserRepository(session)
        await repo.lock_for_password_change(user.id)
        await repo.update_password_hash(
            user.id, "$argon2id$v=19$m=65536,t=3,p=4$c$d", password_changed=True,
        )
        await session.commit()
        refreshed = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        assert refreshed.password_hash.endswith("$c$d")
        assert refreshed.password_changed_at is not None

    async def test_serialisation_semantic_documented(
        self, session: AsyncSession, user: User,
    ) -> None:
        """On Postgres, two concurrent transactions both calling
        ``lock_for_password_change`` would serialise. SQLite has no
        row-level locks so this test can only document the
        behavioural contract - the method is present and callable
        on the repo. The Postgres race is covered by integration
        tests under Z4J_TEST_POSTGRES_URL."""
        repo = UserRepository(session)
        # Two sequential calls on SQLite - no deadlock.
        await repo.lock_for_password_change(user.id)
        await repo.lock_for_password_change(user.id)
