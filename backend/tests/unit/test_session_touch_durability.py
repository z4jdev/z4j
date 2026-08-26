"""Regression tests for durable, transaction-isolated session activity."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain.api.deps import get_current_user, get_session
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import aware_utc, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Session, User
from z4j_brain.settings import Settings
from z4j_brain.websocket.dashboard_gateway import _resolve_user


def test_touch_throttle_reopens_inside_minimum_idle_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported 60s idle floor cannot share a 60s touch cooldown."""
    from z4j_brain.api import deps

    session_id = uuid.uuid4()
    interval = deps._session_touch_interval_seconds(60)
    assert interval == 30.0

    clock = iter([0.0, 29.999, 30.001])
    monkeypatch.setattr(deps.time, "monotonic", lambda: next(clock))
    with deps._session_touch_lock:
        deps._session_touch_last_committed.pop(session_id, None)
    try:
        assert deps._claim_session_touch_slot(
            session_id,
            interval_seconds=interval,
        )
        assert not deps._claim_session_touch_slot(
            session_id,
            interval_seconds=interval,
        )
        assert deps._claim_session_touch_slot(
            session_id,
            interval_seconds=interval,
        )
    finally:
        with deps._session_touch_lock:
            deps._session_touch_last_committed.pop(session_id, None)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'session-touch.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=0,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    hasher = PasswordHasher(settings)
    async with app.state.db.session() as db_session:
        db_session.add(
            User(
                email="alice@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                display_name="Alice",
                is_admin=False,
                is_active=True,
            ),
        )
        await db_session.commit()
    yield app
    await engine.dispose()


@pytest.fixture
async def pinned_brain_app(settings: Settings):
    pinned = settings.model_copy(update={"session_pin_user_agent": True})
    engine = create_async_engine(pinned.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(pinned, engine=engine)
    hasher = PasswordHasher(pinned)
    async with app.state.db.session() as db_session:
        db_session.add(
            User(
                email="alice@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                display_name="Alice",
                is_admin=False,
                is_active=True,
            ),
        )
        await db_session.commit()
    yield app
    await engine.dispose()


async def _login(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alice@example.com",
            "password": "correct horse battery staple 9",
        },
    )
    assert response.status_code == 200, response.text


async def _only_session(brain_app) -> Session:  # type: ignore[no-untyped-def]
    async with brain_app.state.db.session() as db_session:
        return (await db_session.execute(select(Session))).scalar_one()


async def _age_session(brain_app, *, revoked: bool = False, expired: bool = False) -> datetime:  # type: ignore[no-untyped-def]
    old = datetime.now(UTC) - timedelta(minutes=10)
    async with brain_app.state.db.session() as db_session:
        row = (await db_session.execute(select(Session))).scalar_one()
        row.last_seen_at = old
        if revoked:
            row.revoked_at = datetime.now(UTC)
            row.revocation_reason = "test"
        if expired:
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db_session.commit()
    return old


@pytest.mark.asyncio
async def test_read_only_request_durably_advances_last_seen(brain_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        await _login(client)
        old = await _age_session(brain_app)

        response = await client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert aware_utc((await _only_session(brain_app)).last_seen_at) > old


@pytest.mark.asyncio
async def test_failed_handler_rolls_back_business_write_but_keeps_touch(brain_app) -> None:  # type: ignore[no-untyped-def]
    @brain_app.get("/__test/session-touch-failure")
    async def failing_handler(
        user: User = Depends(get_current_user),
        db_session: AsyncSession = Depends(get_session),
    ) -> None:
        user.display_name = "must roll back"
        await db_session.flush()
        raise RuntimeError("forced handler failure")

    # create_app's dashboard fallback is registered last and matches every
    # path. Put this test-only route ahead of it so the failure is exercised.
    brain_app.router.routes.insert(0, brain_app.router.routes.pop())

    async with AsyncClient(
        transport=ASGITransport(app=brain_app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        await _login(client)
        old = await _age_session(brain_app)

        response = await client.get("/__test/session-touch-failure")

    assert response.status_code == 500
    async with brain_app.state.db.session() as db_session:
        user = (await db_session.execute(select(User))).scalar_one()
        session_row = (await db_session.execute(select(Session))).scalar_one()
    assert user.display_name == "Alice"
    assert aware_utc(session_row.last_seen_at) > old


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["revoked", "expired"])
async def test_non_live_session_is_never_touched(brain_app, state: str) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        await _login(client)
        old = await _age_session(
            brain_app,
            revoked=state == "revoked",
            expired=state == "expired",
        )

        response = await client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert aware_utc((await _only_session(brain_app)).last_seen_at) == old


@pytest.mark.asyncio
async def test_dashboard_websocket_auth_durably_advances_last_seen(
    brain_app,
    settings: Settings,
) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        await _login(client)
        old = await _age_session(brain_app)
        session_cookie = client.cookies.get(cookie_name(environment=settings.environment))

    websocket = SimpleNamespace(
        cookies={cookie_name(environment=settings.environment): session_cookie},
        app=brain_app,
    )
    resolved = await _resolve_user(
        websocket=websocket,  # type: ignore[arg-type]
        settings=settings,
        db=brain_app.state.db,
    )

    assert resolved is not None
    assert aware_utc((await _only_session(brain_app)).last_seen_at) > old


@pytest.mark.asyncio
async def test_user_agent_pin_durably_revokes_on_change(pinned_brain_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=pinned_brain_app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/api/v1/auth/login",
            headers={"User-Agent": "browser-one"},
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200

        changed = await client.get(
            "/api/v1/auth/me",
            headers={"User-Agent": "browser-two"},
        )
        original = await client.get(
            "/api/v1/auth/me",
            headers={"User-Agent": "browser-one"},
        )

    assert changed.status_code == 401
    assert original.status_code == 401
    row = await _only_session(pinned_brain_app)
    assert row.revoked_at is not None
    assert row.revocation_reason == "user_agent_changed"


@pytest.mark.asyncio
async def test_session_list_excludes_expired_rows(brain_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        await _login(client)
        async with brain_app.state.db.session() as db_session:
            user = (await db_session.execute(select(User))).scalar_one()
            db_session.add(
                Session(
                    user_id=user.id,
                    csrf_token="expired-session-csrf",
                    expires_at=datetime.now(UTC) - timedelta(seconds=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="old-browser",
                ),
            )
            await db_session.commit()

        response = await client.get("/api/v1/auth/sessions")

    assert response.status_code == 200
    assert len(response.json()) == 1


@pytest.mark.asyncio
async def test_remembered_session_tolerates_postgres_transaction_timestamp_drift(
    brain_app,
    settings: Settings,
) -> None:  # type: ignore[no-untyped-def]
    """Server-side ``issued_at`` need not exactly match the app's expiry clock."""
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
                "remember_me": True,
            },
        )
        assert login.status_code == 200

        async with brain_app.state.db.session() as db_session:
            session_row = (await db_session.execute(select(Session))).scalar_one()
            # PostgreSQL's ``now()`` is the transaction-start timestamp while
            # AuthService computes expires_at from the later application wall
            # clock. Simulate that positive duration offset. An exact lifetime
            # comparison would misclassify this remembered row as normal.
            session_row.issued_at = session_row.expires_at - timedelta(
                seconds=settings.session_remember_me_lifetime_seconds + 3,
            )
            session_row.last_seen_at = datetime.now(UTC) - timedelta(hours=1)
            await db_session.commit()

        response = await client.get("/api/v1/auth/me")

    assert response.status_code == 200
