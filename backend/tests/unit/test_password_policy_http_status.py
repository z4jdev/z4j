"""A password-policy failure is the caller's input error, not a server error.

``PasswordHasher.validate_policy`` raises ``PasswordError``, a plain
``ValueError`` subclass that the CLI prints directly. Every HTTP write path
calls it, and before the error middleware mapped it the exception fell
through to the generic handler: the dashboard received HTTP 500
``internal_error`` and could not tell the user which rule the password broke.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import PasswordResetToken, User
from z4j_brain.settings import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'policy.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
    ) as ac:
        yield ac


async def _user_with_reset_token(brain_app, settings: Settings, plaintext: str) -> None:
    from z4j_brain.api.auth import _hash_reset_token

    hasher = PasswordHasher(settings)
    async with brain_app.state.db.session() as s:
        user = User(
            email="alice@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            display_name="Alice",
            is_admin=False,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        s.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=_hash_reset_token(plaintext, settings),
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            ),
        )
        await s.commit()


@pytest.mark.asyncio
async def test_policy_failure_answers_422_with_its_reason_and_keeps_the_token(
    client,
    brain_app,
    settings: Settings,
) -> None:
    plaintext = "policy-status-token-0123456789abcdef0123"
    await _user_with_reset_token(brain_app, settings, plaintext)

    # Long enough for the request schema and the default 12-character
    # minimum, one character class: the policy itself rejects it.
    weak = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": plaintext, "new_password": "onlylowercase"},
    )
    assert weak.status_code == 422, weak.text
    body = weak.json()
    assert body["error"] == "validation_error"
    assert body["details"] == {"reason": "password_too_simple"}
    assert "3 of" in body["message"]

    # Positive control: the refusal did not consume the single-use token, so
    # a password that satisfies the policy still completes the reset.
    strong = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": plaintext, "new_password": "Str0ng-enough-pw!"},
    )
    assert strong.status_code == 200, strong.text
    assert strong.json() == {"success": True}


@pytest.mark.asyncio
async def test_only_the_policy_error_is_reclassified() -> None:
    """The middleware maps PasswordError to 422 and nothing else.

    Negative control: a plain ``ValueError`` from a handler is still an
    unexpected server error, so the new arm cannot hide real bugs.
    """
    from httpx import ASGITransport, AsyncClient
    from starlette.applications import Starlette
    from starlette.routing import Route
    from z4j_brain.auth.passwords import PasswordError
    from z4j_brain.middleware.errors import ErrorMiddleware

    async def policy(_request):
        raise PasswordError("password_too_short", "password must be at least 12 characters")

    async def plain(_request):
        raise ValueError("not a password policy failure")

    app = Starlette(routes=[Route("/policy", policy), Route("/plain", plain)])
    app.add_middleware(ErrorMiddleware)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        refused = await client.get("/policy")
        broken = await client.get("/plain")

    assert refused.status_code == 422
    assert refused.json()["details"] == {"reason": "password_too_short"}
    assert broken.status_code == 500
    assert broken.json()["error"] == "internal_error"
