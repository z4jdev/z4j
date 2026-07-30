"""RM13 regression: the bootstrap-admin re-check must look up the admin under
the SAME canonical email the store used, not the raw CLI value.

The admin row is stored as canonicalize_email(validate_admin_email(raw)) (NFKC +
casefold + IDNA punycode; see startup.py). UserRepository.get_by_email only
strip()+casefold()s its argument, so looking up the RAW non-ASCII / IDN-domain
email misses the just-created row -- the CLI then falsely reported "admin ... was
not created" despite a successful provision.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.auth_service import canonicalize_email, validate_admin_email
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import User
from z4j_brain.persistence.repositories import UserRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ["admin@café.example", "admin@münchen.de"])
async def test_recheck_finds_canonically_stored_admin(session: AsyncSession, raw: str) -> None:
    # Drive the ACTUAL re-check logic (_requested_admin_exists, which uses the
    # _canonical_admin_lookup the CLI call-site uses), not the repository
    # asymmetry in isolation -- so reverting the fix (raw lookup) fails this.
    from z4j_brain.cli import _requested_admin_exists

    # Store exactly as startup.py does for a bootstrap admin.
    stored = canonicalize_email(validate_admin_email(raw))
    session.add(User(id=uuid.uuid4(), email=stored, password_hash="x", is_admin=True))
    await session.flush()
    users = UserRepository(session)

    # The FIX: the re-check finds the just-created admin.
    assert await _requested_admin_exists(users, raw) is True
    # The BUG it closes: a RAW-email lookup would have missed the canonical row
    # (which made the CLI falsely report the admin as "not created").
    assert await users.get_by_email(raw) is None


@pytest.mark.asyncio
async def test_recheck_ascii_admin_unaffected(session: AsyncSession) -> None:
    from z4j_brain.cli import _requested_admin_exists

    raw = "Admin@Example.com"
    stored = canonicalize_email(validate_admin_email(raw))
    session.add(User(id=uuid.uuid4(), email=stored, password_hash="x", is_admin=True))
    await session.flush()
    users = UserRepository(session)
    assert await _requested_admin_exists(users, raw) is True


@pytest.mark.asyncio
async def test_recheck_reports_missing_when_absent(session: AsyncSession) -> None:
    from z4j_brain.cli import _requested_admin_exists

    # No admin stored -> the re-check correctly reports absent (exit-1 path).
    users = UserRepository(session)
    assert await _requested_admin_exists(users, "admin@café.example") is False


@pytest.mark.asyncio
async def test_recheck_rejects_non_admin_row(session: AsyncSession) -> None:
    # cli:4265: a pre-existing NON-admin row under that email must NOT count as a
    # provisioned admin (existence alone is insufficient).
    from z4j_brain.cli import _requested_admin_exists

    raw = "admin@example.com"
    stored = canonicalize_email(validate_admin_email(raw))
    session.add(User(id=uuid.uuid4(), email=stored, password_hash="x", is_admin=False))
    await session.flush()
    users = UserRepository(session)
    assert await _requested_admin_exists(users, raw) is False


@pytest.mark.asyncio
async def test_recheck_rejects_inactive_admin(session: AsyncSession) -> None:
    # cli:4265: an INACTIVE admin row is not a usable provisioned admin.
    from z4j_brain.cli import _requested_admin_exists

    raw = "admin@example.com"
    stored = canonicalize_email(validate_admin_email(raw))
    session.add(
        User(
            id=uuid.uuid4(),
            email=stored,
            password_hash="x",
            is_admin=True,
            is_active=False,
        )
    )
    await session.flush()
    users = UserRepository(session)
    assert await _requested_admin_exists(users, raw) is False
