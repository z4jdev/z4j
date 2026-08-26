"""CLI password recovery must revoke credentials explicitly and atomically."""

from __future__ import annotations

import asyncio
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Session, TrustedDevice, User
from z4j_brain.settings import Settings


def test_changepassword_revokes_sessions_and_trusted_devices(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    from z4j_brain import cli

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'change-password.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
    )
    engine = create_async_engine(settings.database_url)

    async def seed() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        hasher = PasswordHasher(settings)
        async with engine.begin() as conn:
            user = User(
                email="alice@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                display_name="Alice",
                is_admin=True,
                is_active=True,
            )
            async with AsyncSession(bind=conn, expire_on_commit=False) as db_session:
                db_session.add(user)
                await db_session.flush()
                db_session.add_all(
                    [
                        Session(
                            user_id=user.id,
                            csrf_token="existing-session",
                            expires_at=datetime.now(UTC) + timedelta(days=1),
                            ip_at_issue="127.0.0.1",
                            user_agent_at_issue="browser",
                        ),
                        TrustedDevice(
                            user_id=user.id,
                            cookie_id_hash="a" * 64,
                            label="Browser",
                            expires_at=datetime.now(UTC) + timedelta(days=1),
                        ),
                    ],
                )
                await db_session.flush()

    asyncio.run(seed())

    monkeypatch.setattr(
        cli,
        "_read_password_from_args",
        lambda _args: "replacement password 9!",
    )
    monkeypatch.setattr(
        cli,
        "_build_settings_from_env",
        lambda: (settings, engine),
    )

    rc = cli._run_changepassword(SimpleNamespace(email="alice@example.com"))

    async def assert_state() -> None:
        hasher = PasswordHasher(settings)
        async with AsyncSession(engine, expire_on_commit=False) as db_session:
            user = (await db_session.execute(select(User))).scalar_one()
            session_row = (await db_session.execute(select(Session))).scalar_one()
            trusted = list((await db_session.execute(select(TrustedDevice))).scalars())
        assert hasher.verify(user.password_hash, "replacement password 9!")
        assert session_row.revoked_at is not None
        assert session_row.revocation_reason == "password_changed"
        assert trusted == []
        await engine.dispose()

    assert rc == 0
    asyncio.run(assert_state())
