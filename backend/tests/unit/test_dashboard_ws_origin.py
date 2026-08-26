"""Dashboard WebSocket Origin checks."""

from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from z4j_brain.settings import Settings
from z4j_brain.websocket import dashboard_gateway
from z4j_brain.websocket.dashboard_gateway import _origin_allowed


def _settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    values = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "audit_chain_secret": secrets.token_urlsafe(48),
        "environment": "production",
        "allowed_hosts": ["z4j.example.com"],
        "public_url": "https://z4j.example.com",
        "log_json": False,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


class TestDashboardWsOrigin:
    def test_public_url_origin_allowed(self) -> None:
        settings = _settings()
        assert _origin_allowed(
            "https://z4j.example.com",
            settings=settings,
        )

    def test_default_https_port_normalized(self) -> None:
        settings = _settings()
        assert _origin_allowed(
            "https://z4j.example.com:443",
            settings=settings,
        )

    def test_cross_site_origin_rejected(self) -> None:
        settings = _settings()
        assert not _origin_allowed(
            "https://evil.example",
            settings=settings,
        )

    def test_configured_cors_origin_allowed(self) -> None:
        settings = _settings(cors_origins=["https://ops.example.com"])
        assert _origin_allowed(
            "https://ops.example.com",
            settings=settings,
        )

    def test_missing_origin_only_allowed_in_dev(self) -> None:
        prod = _settings()
        dev = _settings(
            environment="dev",
            allowed_hosts=[],
            public_url="http://localhost:7700",
        )
        assert not _origin_allowed(None, settings=prod)
        assert _origin_allowed(None, settings=dev)


def test_binary_subscribe_frame_closes_with_4400(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid subscribe payload on the binary carrier is still malformed."""
    settings = _settings()
    user = SimpleNamespace(id=uuid4(), is_admin=True)
    session = SimpleNamespace(mfa_verified_at=None)

    async def resolve_user(**_kwargs):  # type: ignore[no-untyped-def]
        return session, user

    monkeypatch.setattr(dashboard_gateway, "_resolve_user", resolve_user)
    monkeypatch.setattr(
        dashboard_gateway,
        "_mfa_blocks_dashboard",
        lambda **_kwargs: False,
    )

    app = FastAPI()
    app.state.settings = settings
    app.state.db = object()
    app.state.dashboard_hub = object()
    app.include_router(dashboard_gateway.router)

    payload = json.dumps(
        {"type": "subscribe", "project_id": str(uuid4())},
    ).encode()
    with (
        TestClient(app) as client,
        client.websocket_connect(
            "/ws/dashboard",
            headers={"origin": "https://z4j.example.com"},
        ) as websocket,
    ):
        websocket.send_bytes(payload)
        with pytest.raises(WebSocketDisconnect) as closed:
            websocket.receive_text()

    assert closed.value.code == 4400


@pytest.mark.asyncio
async def test_first_frame_receive_does_not_mask_internal_key_error() -> None:
    """Only a real binary carrier is translated to the 4400 path."""

    class BrokenWebSocket:
        async def receive(self):  # type: ignore[no-untyped-def]
            raise KeyError("internal-state")

    with pytest.raises(KeyError) as raised:
        await dashboard_gateway._receive_first_text(BrokenWebSocket())  # type: ignore[arg-type]

    assert raised.value.args == ("internal-state",)
