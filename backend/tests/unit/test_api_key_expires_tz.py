"""Bearer-auth expiry regression tests.

These tests execute the production dependency.  In particular, the naive
datetime case models SQLite's TIMESTAMP round-trip instead of copying the
comparison into a test helper.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from starlette.requests import Request
from z4j_brain.api import deps
from z4j_brain.errors import AuthenticationError
from z4j_brain.persistence.repositories import UserRepository
from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository


def _bearer_request() -> Request:
    token = "z4k_" + ("a" * 40)
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "client": ("127.0.0.1", 1234),
            "route": SimpleNamespace(tags=["tasks"]),
        },
    )


def _key(*, expires_at: datetime | None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        revoked_at=None,
        expires_at=expires_at,
        scopes=["tasks:read"],
        project_id=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("naive", [False, True], ids=["aware", "sqlite-naive"])
async def test_future_expiry_authenticates_through_production_dependency(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
    naive: bool,
) -> None:
    expires_at = datetime.now(UTC) + timedelta(days=30)
    if naive:
        expires_at = expires_at.replace(tzinfo=None)
    key = _key(expires_at=expires_at)
    user = SimpleNamespace(id=key.user_id, is_active=True)
    get_key = AsyncMock(return_value=key)
    get_user = AsyncMock(return_value=user)
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", get_key)
    monkeypatch.setattr(UserRepository, "get", get_user)

    request = _bearer_request()
    resolved = await deps._resolve_bearer_user(request, brain_settings, object())

    assert resolved is user
    assert request.state.api_key is key
    assert request.state.auth_kind == "api_key"
    get_key.assert_awaited_once()
    get_user.assert_awaited_once_with(key.user_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("naive", [False, True], ids=["aware", "sqlite-naive"])
async def test_past_expiry_is_rejected_by_production_dependency(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
    naive: bool,
) -> None:
    expires_at = datetime.now(UTC) - timedelta(days=1)
    if naive:
        expires_at = expires_at.replace(tzinfo=None)
    key = _key(expires_at=expires_at)
    get_user = AsyncMock()
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    monkeypatch.setattr(UserRepository, "get", get_user)

    with pytest.raises(AuthenticationError) as caught:
        await deps._resolve_bearer_user(_bearer_request(), brain_settings, object())

    assert caught.value.details == {"reason": "expired"}
    get_user.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_expiry_authenticates_through_production_dependency(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    key = _key(expires_at=None)
    user = SimpleNamespace(id=key.user_id, is_active=True)
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=user))

    assert await deps._resolve_bearer_user(_bearer_request(), brain_settings, object()) is user
