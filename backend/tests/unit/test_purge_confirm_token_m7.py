"""M-7: the brain computes the keyed purge confirm token server-side.

Proves ``_resolve_purge_confirm_token`` returns a token that the agent
(keying with the base64-decoded per-project secret) will accept, and
that the pass-through / force / no-depth branches behave.
"""

from __future__ import annotations

import base64
import secrets
import uuid

import pytest
from z4j_brain.api.commands import PurgeQueueRequest, _resolve_purge_confirm_token
from z4j_brain.settings import Settings
from z4j_core.purge_token import verify_purge_confirm_token
from z4j_core.transport.hmac import decode_agent_hmac_secret, derive_project_secret

_PID = uuid.UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret="x" * 48,  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


class _FakeProjects:
    def __init__(self, project: object | None) -> None:
        self._project = project

    async def get_by_slug(self, slug: str) -> object | None:
        return self._project


class _Project:
    id = _PID


def _body(**kw) -> PurgeQueueRequest:
    base = {"agent_id": uuid.uuid4(), "queue": "emails"}
    base.update(kw)
    return PurgeQueueRequest(**base)


@pytest.mark.asyncio
async def test_server_side_token_accepted_by_agent(settings: Settings) -> None:
    token = await _resolve_purge_confirm_token(
        body=_body(observed_depth=17),
        slug="p",
        projects=_FakeProjects(_Project()),  # type: ignore[arg-type]
        settings=settings,
    )
    assert token is not None
    # The agent decodes the base64 secret the brain would have minted.
    minted = base64.urlsafe_b64encode(
        derive_project_secret(settings.secret.get_secret_value().encode(), _PID),
    ).decode("ascii")
    agent_secret = decode_agent_hmac_secret(minted)
    accepted, used_legacy = verify_purge_confirm_token(
        provided=token,
        queue_name="emails",
        queue_depth=17,
        secret=agent_secret,
    )
    assert accepted is True
    assert used_legacy is False  # it is the KEYED token, not legacy


@pytest.mark.asyncio
async def test_explicit_confirm_token_passed_through(settings: Settings) -> None:
    token = await _resolve_purge_confirm_token(
        body=_body(confirm_token="deadbeef", observed_depth=17),
        slug="p",
        projects=_FakeProjects(_Project()),  # type: ignore[arg-type]
        settings=settings,
    )
    assert token == "deadbeef"  # explicit token wins, no server-side compute


@pytest.mark.asyncio
async def test_force_returns_no_token(settings: Settings) -> None:
    token = await _resolve_purge_confirm_token(
        body=_body(observed_depth=17, force=True),
        slug="p",
        projects=_FakeProjects(_Project()),  # type: ignore[arg-type]
        settings=settings,
    )
    assert token is None


@pytest.mark.asyncio
async def test_no_depth_returns_no_token(settings: Settings) -> None:
    token = await _resolve_purge_confirm_token(
        body=_body(),
        slug="p",
        projects=_FakeProjects(_Project()),  # type: ignore[arg-type]
        settings=settings,
    )
    assert token is None


@pytest.mark.asyncio
async def test_unknown_project_returns_no_token(settings: Settings) -> None:
    token = await _resolve_purge_confirm_token(
        body=_body(observed_depth=17),
        slug="missing",
        projects=_FakeProjects(None),  # type: ignore[arg-type]
        settings=settings,
    )
    assert token is None
