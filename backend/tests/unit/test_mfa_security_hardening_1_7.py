"""1.7 security-hardening: per-account MFA lockout + TOTP anti-replay.

Two fixes, exercised at both the HTTP-route level (against a real app
on in-memory SQLite) and the repository level (the atomic primitives):

Fix 1 -- per-account failed-MFA lockout (NIST 800-63B 5.2.2):
  * N wrong TOTP codes lock the account; a locked account is then
    refused even when the CORRECT code is presented (429 ``mfa_locked``);
  * a correct code BEFORE the threshold clears the counter, so the lock
    never trips on interleaved good attempts;
  * ``UserRepository.record_mfa_failure`` / ``reset_mfa_failures`` do the
    atomic increment + conditional lock / reset.

Fix 2 -- TOTP single-use anti-replay (RFC 6238 5.2):
  * the same TOTP code cannot be verified twice (the second use is
    rejected exactly like a wrong code);
  * ``UserRepository.consume_totp_counter`` is a single-statement CAS:
    the first use of a step wins, a replay of the same/older step loses,
    a later step wins;
  * ``reset_totp_counter`` clears the high-water mark so a re-enrollment
    starts a fresh counter space.
"""

from __future__ import annotations

import secrets as _secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain.mfa import encrypt_totp_secret, generate_totp_secret
from z4j_brain.domain.mfa.totp import current_totp_code
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import User
from z4j_brain.persistence.repositories import UserRepository
from z4j_brain.settings import Settings

PASSWORD = "correct horse battery staple 9"


def make_settings(**overrides):  # type: ignore[no-untyped-def]
    values: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": _secrets.token_urlsafe(48),
        "session_secret": _secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
        "argon2_time_cost": 1,
        "argon2_memory_cost": 8192,
        "login_min_duration_ms": 0,
        "login_backoff_base_seconds": 0.0,
        "login_backoff_max_seconds": 0.0,
        "disable_spa_fallback": True,
        "mfa_recovery_code_count": 5,
        # High per-IP throttle so the lockout logic (not the throttle) is
        # what these tests observe.
        "mfa_verification_rate_per_min": 300,
        # Small threshold so the lockout trips quickly.
        "mfa_lockout_threshold": 3,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@asynccontextmanager
async def make_brain(settings: Settings):  # type: ignore[no-untyped-def]
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield app, ac
    finally:
        await engine.dispose()


async def seed_enrolled_user(app, settings: Settings, *, email: str):  # type: ignore[no-untyped-def]
    hasher = PasswordHasher(settings)
    async with app.state.db.session() as s:
        user = User(
            email=email,
            password_hash=hasher.hash(PASSWORD),
            is_admin=False,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        secret = generate_totp_secret()
        user.mfa_secret_encrypted = encrypt_totp_secret(
            secret,
            master_secret=settings.secret.get_secret_value().encode("utf-8"),
            user_id=user.id,
        )
        user.mfa_enrolled_at = datetime.now(UTC)
        await s.commit()
        return user.id, secret


async def login(client: AsyncClient, email: str) -> None:
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text


def csrf_header(client: AsyncClient, settings: Settings) -> dict[str, str]:
    token = client.cookies.get(csrf_cookie_name(environment=settings.environment))
    assert token is not None
    return {"X-CSRF-Token": token}


def wrong_totp_code(secret: bytes) -> str:
    """A 6-digit code guaranteed NOT to verify in the current window."""
    now = time.time()
    valid = {current_totp_code(secret, at_time=now + delta) for delta in (-30, 0, 30)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


async def user_lock_state(app, user_id):  # type: ignore[no-untyped-def]
    async with app.state.db.session() as s:
        return (
            await s.execute(
                select(User.failed_mfa_count, User.mfa_locked_until, User.last_totp_counter).where(
                    User.id == user_id,
                ),
            )
        ).one()


async def _verify(client, settings, code):  # type: ignore[no-untyped-def]
    return await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": code},
        headers=csrf_header(client, settings),
    )


# ---------------------------------------------------------------------------
# Fix 1 -- per-account MFA lockout (HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaLockout:
    async def test_wrong_codes_lock_account_then_correct_code_refused(self) -> None:
        settings = make_settings()  # threshold=3
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_enrolled_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")

            bad = wrong_totp_code(secret)
            # threshold-1 wrong codes: 401 wrong_totp, NOT yet locked.
            for _ in range(settings.mfa_lockout_threshold - 1):
                r = await _verify(client, settings, bad)
                assert r.status_code == 401
                assert r.json()["details"]["reason"] == "wrong_totp"
            _, locked_until, _ = await user_lock_state(app, uid)
            assert locked_until is None

            # The threshold-th wrong code trips the lock (still 401 for
            # this attempt -- it was a wrong code).
            r = await _verify(client, settings, bad)
            assert r.status_code == 401
            count, locked_until, _ = await user_lock_state(app, uid)
            assert count >= settings.mfa_lockout_threshold
            assert locked_until is not None

            # Now even the CORRECT code is refused with a 429 lockout.
            r = await _verify(client, settings, current_totp_code(secret))
            assert r.status_code == 429
            assert r.json()["details"]["reason"] == "mfa_locked"

    async def test_correct_code_before_threshold_resets_counter(self) -> None:
        settings = make_settings()  # threshold=3
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_enrolled_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")

            bad = wrong_totp_code(secret)
            # Two wrong codes (below threshold=3).
            for _ in range(2):
                assert (await _verify(client, settings, bad)).status_code == 401
            count, locked_until, _ = await user_lock_state(app, uid)
            assert count == 2
            assert locked_until is None

            # A correct code clears the counter/lock.
            r = await _verify(client, settings, current_totp_code(secret))
            assert r.status_code == 200, r.text
            count, locked_until, _ = await user_lock_state(app, uid)
            assert count == 0
            assert locked_until is None


# ---------------------------------------------------------------------------
# Fix 2 -- TOTP anti-replay (HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTotpReplay:
    async def test_same_totp_code_cannot_be_used_twice(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_enrolled_user(app, settings, email="carol@example.com")
            await login(client, "carol@example.com")

            code = current_totp_code(secret)
            # First use succeeds and advances the high-water mark.
            r1 = await _verify(client, settings, code)
            assert r1.status_code == 200, r1.text
            _, _, last_counter = await user_lock_state(app, uid)
            assert last_counter is not None

            # Second use of the SAME code (same 30s window) is a replay
            # and is rejected exactly like a wrong code.
            r2 = await _verify(client, settings, code)
            assert r2.status_code == 401
            assert r2.json()["details"]["reason"] == "wrong_totp"


# ---------------------------------------------------------------------------
# Repository-level atomic primitives (deterministic, no wall-clock TOTP)
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


async def _seed_bare_user(session: AsyncSession) -> User:
    user = User(
        email="dave@example.com",
        password_hash="x",
        is_admin=False,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    return user


@pytest.mark.asyncio
class TestConsumeTotpCounter:
    async def test_single_use_then_replay_then_later_step(
        self,
        session: AsyncSession,
    ) -> None:
        user = await _seed_bare_user(session)
        repo = UserRepository(session)

        # First claim of a step wins.
        assert await repo.consume_totp_counter(user.id, counter=100) is True
        await session.commit()
        # Replay of the SAME step loses.
        assert await repo.consume_totp_counter(user.id, counter=100) is False
        # An OLDER step also loses (monotonic advance only).
        assert await repo.consume_totp_counter(user.id, counter=99) is False
        # A LATER step wins and advances the mark.
        assert await repo.consume_totp_counter(user.id, counter=101) is True
        await session.commit()

    async def test_reset_totp_counter_reopens_counter_space(
        self,
        session: AsyncSession,
    ) -> None:
        user = await _seed_bare_user(session)
        repo = UserRepository(session)

        assert await repo.consume_totp_counter(user.id, counter=500) is True
        await session.commit()
        # A step below the mark is a replay...
        assert await repo.consume_totp_counter(user.id, counter=400) is False
        # ...until a re-enrollment resets the mark to NULL.
        await repo.reset_totp_counter(user.id)
        await session.commit()
        assert await repo.consume_totp_counter(user.id, counter=400) is True


@pytest.mark.asyncio
class TestRecordMfaFailure:
    async def test_increments_then_locks_then_resets(
        self,
        session: AsyncSession,
    ) -> None:
        user = await _seed_bare_user(session)
        repo = UserRepository(session)

        # Two failures below the threshold: counter climbs, no lock.
        for expected in (1, 2):
            row = await repo.record_mfa_failure(
                user.id,
                lockout_threshold=3,
                lockout_duration_seconds=900,
            )
            await session.commit()
            assert row is not None
            assert row.failed_mfa_count == expected
            assert row.mfa_locked_until is None

        # Third failure reaches the threshold and sets the lock boundary.
        row = await repo.record_mfa_failure(
            user.id,
            lockout_threshold=3,
            lockout_duration_seconds=900,
        )
        await session.commit()
        assert row is not None
        assert row.failed_mfa_count == 3
        assert row.mfa_locked_until is not None

        # A successful verification clears both.
        await repo.reset_mfa_failures(user.id)
        await session.commit()
        refreshed = await repo.get(user.id)
        assert refreshed is not None
        assert refreshed.failed_mfa_count == 0
        assert refreshed.mfa_locked_until is None

    async def test_unknown_user_returns_none(self, session: AsyncSession) -> None:
        import uuid

        repo = UserRepository(session)
        assert (
            await repo.record_mfa_failure(
                uuid.uuid4(),
                lockout_threshold=3,
                lockout_duration_seconds=900,
            )
            is None
        )
