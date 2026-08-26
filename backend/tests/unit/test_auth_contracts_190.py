"""Release-1.9 authentication behavior and documentation contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import z4j_brain.auth as auth_package
from starlette.requests import Request
from z4j_brain.api import api_keys, auth, deps
from z4j_brain.auth.scopes import SCOPE_UNREACHABLE, required_scope, scope_satisfies
from z4j_brain.errors import AuthenticationError, AuthorizationError
from z4j_brain.persistence.repositories import ProjectRepository, UserRepository
from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository


def _bearer_request(*, tag: str = "setup") -> Request:
    token = "z4k_" + ("a" * 40)
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/api-keys/scopes",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "client": ("127.0.0.1", 1234),
            "route": SimpleNamespace(tags=[tag]),
        },
    )


def _key(
    *,
    revoked: bool = False,
    expired: bool = False,
    scopes: list[str] | None = None,
    project_id=None,  # type: ignore[no-untyped-def]
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        revoked_at=datetime.now(UTC) if revoked else None,
        expires_at=(datetime.now(UTC) - timedelta(minutes=1)) if expired else None,
        scopes=list(scopes or []),
        project_id=project_id,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "unknown",
        "revoked",
        "expired",
        "missing_owner",
        "inactive_owner",
        "stale_bound_project",
    ],
)
async def test_optional_bearer_auth_treats_stale_credentials_as_anonymous(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
    state: str,
) -> None:
    """Optional auth never turns a stale credential into a hard 401."""
    key = (
        None
        if state == "unknown"
        else _key(
            revoked=state == "revoked",
            expired=state == "expired",
            project_id=uuid4() if state == "stale_bound_project" else None,
        )
    )
    monkeypatch.setattr(
        ApiKeyRepository,
        "get_by_hash",
        AsyncMock(return_value=key),
    )
    owner = None
    if key is not None and state != "missing_owner":
        owner = SimpleNamespace(
            id=key.user_id,
            is_active=state != "inactive_owner",
        )
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=owner))
    if state == "stale_bound_project":
        monkeypatch.setattr(ProjectRepository, "get", AsyncMock(return_value=None))

    result = await deps.get_optional_api_key_user(
        _bearer_request(),
        brain_settings,
        object(),
        None,
    )

    assert result is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    ["revoked", "expired", "missing_owner", "inactive_owner", "stale_bound_project"],
)
async def test_required_bearer_auth_still_refuses_invalid_known_key(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
    state: str,
) -> None:
    key = _key(
        revoked=state == "revoked",
        expired=state == "expired",
        project_id=uuid4() if state == "stale_bound_project" else None,
    )
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    owner = None
    if state != "missing_owner":
        owner = SimpleNamespace(
            id=key.user_id,
            is_active=state != "inactive_owner",
        )
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=owner))
    if state == "stale_bound_project":
        monkeypatch.setattr(ProjectRepository, "get", AsyncMock(return_value=None))

    with pytest.raises(AuthenticationError):
        await deps._get_strict_api_key_user(
            _bearer_request(),
            brain_settings,
            object(),
            None,
        )


@pytest.mark.asyncio
async def test_required_auth_refuses_unknown_bearer(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    monkeypatch.setattr(
        ApiKeyRepository,
        "get_by_hash",
        AsyncMock(return_value=None),
    )
    request = _bearer_request()
    strict_result = await deps._get_strict_api_key_user(
        request,
        brain_settings,
        object(),
        None,
    )
    assert strict_result is None
    with pytest.raises(AuthenticationError, match="authentication required"):
        await deps.get_current_user(
            request,
            None,
            strict_result,
            brain_settings,
        )


@pytest.mark.asyncio
async def test_valid_cookie_has_absolute_precedence_over_bearer(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    """A coincident stale Bearer is not even resolved after cookie success."""
    request = _bearer_request()
    request.state.auth_kind = "session"
    session = SimpleNamespace(id=uuid4())
    cookie_user = SimpleNamespace(id=uuid4())
    bearer_resolver = AsyncMock(side_effect=AssertionError("Bearer must not be evaluated"))
    monkeypatch.setattr(deps, "_resolve_bearer_user", bearer_resolver)

    optional_bearer = await deps.get_optional_api_key_user(
        request,
        brain_settings,
        object(),
        (session, cookie_user),
    )
    strict_bearer = await deps._get_strict_api_key_user(
        request,
        brain_settings,
        object(),
        (session, cookie_user),
    )

    assert optional_bearer is None
    assert strict_bearer is None
    assert await deps.get_optional_user((session, cookie_user), optional_bearer) is cookie_user
    assert request.state.auth_kind == "session"
    bearer_resolver.assert_not_awaited()


@pytest.mark.asyncio
async def test_auth_me_uses_documented_admin_project_cap() -> None:
    projects = SimpleNamespace(list=AsyncMock(return_value=[]))
    user = SimpleNamespace(
        id=uuid4(),
        email="admin@example.com",
        first_name=None,
        last_name=None,
        display_name="Admin",
        is_admin=True,
        timezone="UTC",
        created_at=datetime.now(UTC),
    )

    response = await auth.me(
        user,
        SimpleNamespace(list_for_user=AsyncMock()),
        projects,
    )

    assert response.memberships == []
    projects.list.assert_awaited_once_with(limit=500, offset=0)


def _documented_method_paths(description: str) -> set[tuple[str, str]]:
    return set(
        re.findall(
            r"\b(GET|POST|PATCH|DELETE) (/api/v1/[a-z0-9_/{}/-]+)",
            description,
        ),
    )


def test_mfa_login_response_describes_exact_gate_exemptions() -> None:
    verification_description = auth.LoginResponse.model_fields["mfa_required"].description
    enrollment_description = auth.LoginResponse.model_fields["mfa_enrollment_required"].description
    deadline_description = auth.LoginResponse.model_fields["mfa_enrollment_deadline"].description
    assert verification_description is not None
    assert enrollment_description is not None
    assert deadline_description is not None

    assert _documented_method_paths(verification_description) == set(
        deps._MFA_VERIFICATION_EXEMPT_ROUTES,
    )
    enrollment_routes = set(
        deps._MFA_ENROLLMENT_EXEMPT_ROUTES,
    )
    assert _documented_method_paths(enrollment_description) == enrollment_routes
    assert _documented_method_paths(deadline_description) == enrollment_routes


def test_auth_response_and_membership_cap_docs_are_precise() -> None:
    assert auth.__doc__ is not None
    assert "sole bodyless exception" in auth.__doc__
    assert "204 No Content" in auth.__doc__

    description = auth.UserMePublic.model_fields["memberships"].description
    assert description is not None
    assert "at most the first 500 projects" in description
    assert "not a complete project catalogue" in description
    assert auth.me.__doc__ is not None and "capped at 500 projects" in auth.me.__doc__
    assert (
        auth.update_profile.__doc__ is not None
        and "capped at 500 projects" in auth.update_profile.__doc__
    )


def test_scope_catalogue_bearer_contract_is_admin_read_and_unbound() -> None:
    required = required_scope(tags=["api-keys"], method="GET")
    assert required == "admin:read"
    assert scope_satisfies(granted=["admin:*"], required=required)
    assert not scope_satisfies(granted=["projects:read"], required=required)
    assert api_keys.list_scopes.__doc__ is not None
    assert "admin:read" in api_keys.list_scopes.__doc__
    assert "must also be unbound" in api_keys.list_scopes.__doc__


def test_admin_umbrella_docs_match_broad_mapped_grant_and_unmapped_denial() -> None:
    assert scope_satisfies(granted=["admin:*"], required="tasks:write")
    assert scope_satisfies(granted=["admin:*"], required="projects:write")
    assert not scope_satisfies(granted=["admin:*"], required=SCOPE_UNREACHABLE)

    from z4j_brain.auth import scopes

    assert scopes.__doc__ is not None
    assert "satisfies every" in scopes.__doc__
    assert "including project-resource writes" in scopes.__doc__
    assert "never satisfies an unmapped route" in scopes.__doc__


def test_auth_package_docs_disclose_fastapi_response_exception() -> None:
    assert auth_package.__doc__ is not None
    assert "framework-free" in auth_package.__doc__
    assert "trusted_device" in auth_package.__doc__
    assert "fastapi.Response" in auth_package.__doc__


@pytest.mark.asyncio
async def test_scope_catalogue_accepts_unbound_admin_umbrella_key(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    key = _key(scopes=["admin:*"])
    owner = SimpleNamespace(id=key.user_id, is_active=True)
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=owner))

    assert (
        await deps._resolve_bearer_user(
            _bearer_request(tag="api-keys"),
            brain_settings,
            object(),
        )
        is owner
    )


@pytest.mark.asyncio
async def test_scope_catalogue_rejects_key_without_admin_read(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    key = _key(scopes=["projects:read"])
    owner = SimpleNamespace(id=key.user_id, is_active=True)
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=owner))

    with pytest.raises(AuthorizationError) as caught:
        await deps._resolve_bearer_user(
            _bearer_request(tag="api-keys"),
            brain_settings,
            object(),
        )
    assert caught.value.details == {
        "required_scope": "admin:read",
        "reason": "scope_missing",
    }


@pytest.mark.asyncio
async def test_scope_catalogue_rejects_project_bound_admin_key(
    monkeypatch: pytest.MonkeyPatch,
    brain_settings,
) -> None:
    project_id = uuid4()
    key = _key(scopes=["admin:*"], project_id=project_id)
    owner = SimpleNamespace(id=key.user_id, is_active=True)
    monkeypatch.setattr(ApiKeyRepository, "get_by_hash", AsyncMock(return_value=key))
    monkeypatch.setattr(UserRepository, "get", AsyncMock(return_value=owner))
    monkeypatch.setattr(
        ProjectRepository,
        "get",
        AsyncMock(return_value=SimpleNamespace(id=project_id, slug="bound")),
    )

    with pytest.raises(AuthorizationError) as caught:
        await deps._resolve_bearer_user(
            _bearer_request(tag="api-keys"),
            brain_settings,
            object(),
        )
    assert caught.value.details == {
        "reason": "project_scope_nonslug_denied",
        "tag": "api-keys",
        "bound_project": "bound",
    }
