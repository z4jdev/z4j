"""Tests for the error mapping + ErrorMiddleware."""

from __future__ import annotations

from http import HTTPStatus

import pytest
from fastapi import APIRouter

from z4j_brain.errors import (
    AgentOfflineError,
    AuthenticationError,
    AuthorizationError,
    CommandTimeoutError,
    ConflictError,
    NotFoundError,
    ProtocolError,
    RateLimitExceeded,
    SignatureError,
    ValidationError,
    Z4JError,
    http_status_for,
)


class TestStatusMap:
    def test_validation_error_is_422(self) -> None:
        assert http_status_for(ValidationError("x")) == HTTPStatus.UNPROCESSABLE_ENTITY

    def test_authentication_is_401(self) -> None:
        assert http_status_for(AuthenticationError("x")) == HTTPStatus.UNAUTHORIZED

    def test_signature_error_is_401(self) -> None:
        assert http_status_for(SignatureError("x")) == HTTPStatus.UNAUTHORIZED

    def test_authorization_is_403(self) -> None:
        assert http_status_for(AuthorizationError("x")) == HTTPStatus.FORBIDDEN

    def test_not_found_is_404(self) -> None:
        assert http_status_for(NotFoundError("x")) == HTTPStatus.NOT_FOUND

    def test_conflict_is_409(self) -> None:
        assert http_status_for(ConflictError("x")) == HTTPStatus.CONFLICT

    def test_rate_limit_is_429(self) -> None:
        assert http_status_for(RateLimitExceeded("x")) == HTTPStatus.TOO_MANY_REQUESTS

    def test_agent_offline_is_503(self) -> None:
        assert http_status_for(AgentOfflineError("x")) == HTTPStatus.SERVICE_UNAVAILABLE

    def test_command_timeout_is_504(self) -> None:
        assert http_status_for(CommandTimeoutError("x")) == HTTPStatus.GATEWAY_TIMEOUT

    def test_protocol_error_is_426(self) -> None:
        assert http_status_for(ProtocolError("x")) == HTTPStatus.UPGRADE_REQUIRED

    def test_unknown_subclass_falls_back_to_500(self) -> None:
        class Weird(Z4JError):
            code = "weird"

        assert http_status_for(Weird("x")) == HTTPStatus.INTERNAL_SERVER_ERROR


@pytest.mark.asyncio
class TestErrorMiddleware:
    async def test_z4j_error_returns_mapped_status_and_envelope(
        self, brain_app, client,
    ) -> None:
        router = APIRouter()

        @router.get("/throw-not-found")
        async def _throw() -> dict[str, str]:
            raise NotFoundError("missing widget", details={"widget_id": 7})

        brain_app.include_router(router, prefix="/api/v1")

        response = await client.get("/api/v1/throw-not-found")
        assert response.status_code == 404
        body = response.json()
        assert body["error"] == "not_found"
        assert body["message"] == "missing widget"
        assert body["details"] == {"widget_id": 7}
        assert body["request_id"]

    async def test_unhandled_exception_returns_generic_500(
        self, brain_app, client,
    ) -> None:
        router = APIRouter()

        @router.get("/boom")
        async def _boom() -> None:
            raise RuntimeError("api_key=sk_live_secret_value")

        brain_app.include_router(router, prefix="/api/v1")

        response = await client.get("/api/v1/boom")
        assert response.status_code == 500
        body = response.json()
        assert body["error"] == "internal_error"
        # The exception message MUST NOT leak into the response.
        assert "sk_live_secret_value" not in response.text
        assert "RuntimeError" not in response.text
        assert body["request_id"]
