"""Direct unit tests for :class:`TriggerScheduleClient`.

The audit caught this class at 0% coverage - it was only exercised
via the scheduler-side e2e test, which means a regression in the
client wouldn't surface until the e2e ran. These tests cover:

- Construction is cheap (no I/O).
- ``connect`` raises a clear error when ``scheduler_trigger_url``
  is unset.
- ``connect`` raises a clear error when TLS material paths are
  missing or files don't exist.
- The client builds a TriggerScheduleRequest with the right field
  shape (schedule_id stringified, optional user_id + idempotency_key).
"""

from __future__ import annotations

import secrets
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("grpc")

from z4j_brain.scheduler_grpc.trigger_client import (  # noqa: E402
    TriggerScheduleClient,
    _read_required_pem,
)
from z4j_brain.settings import Settings  # noqa: E402


def _settings(**overrides) -> Settings:
    base = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "log_json": False,
        # Brain refuses to construct in non-dev environments
        # without an allowed_hosts list. Tests run in dev mode.
        "environment": "dev",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


# =====================================================================
# Construction
# =====================================================================


class TestConstruction:
    def test_construct_does_no_io(self) -> None:
        # No connection opened, no PEM read - construction is just
        # attribute assignment so it can land in a Depends() factory
        # without paying I/O cost on every request.
        client = TriggerScheduleClient(settings=_settings())
        assert client._channel is None
        assert client._stub is None


# =====================================================================
# connect() preconditions
# =====================================================================


class TestConnectErrors:
    @pytest.mark.asyncio
    async def test_missing_url_raises_clear_error(self) -> None:
        # No scheduler_trigger_url means the operator hasn't
        # configured the singleton; hard error is the right call -
        # fall-through would mask a deployment bug.
        client = TriggerScheduleClient(settings=_settings())
        with pytest.raises(RuntimeError, match="SCHEDULER_TRIGGER_URL"):
            await client.connect()

    @pytest.mark.asyncio
    async def test_missing_tls_cert_raises_clear_error(
        self, tmp_path: Path,
    ) -> None:
        client = TriggerScheduleClient(
            settings=_settings(scheduler_trigger_url="scheduler:7802"),
        )
        with pytest.raises(RuntimeError, match="TLS_CERT"):
            await client.connect()

    @pytest.mark.asyncio
    async def test_tls_path_does_not_exist_clear_error(
        self, tmp_path: Path,
    ) -> None:
        # Three required paths; missing files raise per-file errors
        # so the operator sees exactly which path is wrong.
        client = TriggerScheduleClient(
            settings=_settings(
                scheduler_trigger_url="scheduler:7802",
                scheduler_trigger_tls_cert=str(tmp_path / "no-cert.pem"),
                scheduler_trigger_tls_key=str(tmp_path / "no-key.pem"),
                scheduler_trigger_tls_ca=str(tmp_path / "no-ca.pem"),
            ),
        )
        with pytest.raises(RuntimeError, match="does not exist"):
            await client.connect()


# =====================================================================
# Request shape (no actual gRPC server)
# =====================================================================


class TestRequestShape:
    @pytest.mark.asyncio
    async def test_trigger_passes_uuids_and_idempotency_key(
        self, tmp_path: Path,
    ) -> None:
        # Patch the stub so we can inspect the request without a
        # real server.
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

        client = TriggerScheduleClient(
            settings=_settings(
                scheduler_trigger_url="scheduler:7802",
                scheduler_trigger_tls_cert=str(cert),
                scheduler_trigger_tls_key=str(key),
                scheduler_trigger_tls_ca=str(ca),
            ),
        )

        captured: dict = {}

        class _FakeStub:
            async def TriggerSchedule(
                self, request, timeout: float | None = None,
            ):
                captured["request"] = request
                captured["timeout"] = timeout

                class _Response:
                    command_id = "deadbeef-...-cmd"
                    error_code = ""
                    error_message = ""

                return _Response()

        # Skip the real channel construction - patch connect() to
        # install our fake stub directly.
        async def _fake_connect():
            client._stub = _FakeStub()  # type: ignore[assignment]
            client._channel = object()  # type: ignore[assignment]

        with patch.object(client, "connect", _fake_connect):
            schedule_id = uuid.uuid4()
            user_id = uuid.uuid4()
            response = await client.trigger(
                schedule_id=schedule_id,
                user_id=user_id,
                idempotency_key="trigger-key-1",
            )

        request = captured["request"]
        assert request.schedule_id == str(schedule_id)
        assert request.user_id == str(user_id)
        assert request.idempotency_key == "trigger-key-1"
        # Per-call deadline applied so a hung scheduler doesn't
        # block the dashboard request thread.
        assert captured["timeout"] is not None and captured["timeout"] > 0
        assert response.command_id == "deadbeef-...-cmd"

    @pytest.mark.asyncio
    async def test_trigger_with_none_user_id_sends_empty_string(
        self, tmp_path: Path,
    ) -> None:
        # Background-trigger paths (no operator) send user_id=None.
        # The proto field is non-optional string so we must send
        # "" not omit the key.
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_bytes(b"x")

        client = TriggerScheduleClient(
            settings=_settings(
                scheduler_trigger_url="scheduler:7802",
                scheduler_trigger_tls_cert=str(cert),
                scheduler_trigger_tls_key=str(key),
                scheduler_trigger_tls_ca=str(ca),
            ),
        )

        captured: dict = {}

        class _FakeStub:
            async def TriggerSchedule(self, request, timeout=None):
                captured["request"] = request

                class _R:
                    command_id = ""
                    error_code = ""
                    error_message = ""

                return _R()

        async def _fake_connect():
            client._stub = _FakeStub()  # type: ignore[assignment]
            client._channel = object()  # type: ignore[assignment]

        with patch.object(client, "connect", _fake_connect):
            await client.trigger(
                schedule_id=uuid.uuid4(),
                user_id=None,
                idempotency_key=None,
            )

        request = captured["request"]
        assert request.user_id == ""
        assert request.idempotency_key == ""


# =====================================================================
# close() idempotency
# =====================================================================


class TestClose:
    @pytest.mark.asyncio
    async def test_close_before_connect_is_noop(self) -> None:
        client = TriggerScheduleClient(settings=_settings())
        await client.close()  # no error
        assert client._channel is None


# =====================================================================
# _read_required_pem
# =====================================================================


class TestReadRequiredPem:
    def test_none_path_raises_with_env_name(self) -> None:
        with pytest.raises(RuntimeError, match="MY_ENV_VAR"):
            _read_required_pem(None, "MY_ENV_VAR")

    def test_missing_file_raises_with_path(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="does not exist"):
            _read_required_pem(str(tmp_path / "ghost"), "MY_ENV_VAR")

    def test_empty_file_raises_with_path(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.pem"
        empty.write_bytes(b"")
        with pytest.raises(RuntimeError, match="empty"):
            _read_required_pem(str(empty), "MY_ENV_VAR")

    def test_real_file_returned(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.pem"
        f.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
        assert _read_required_pem(str(f), "X") == f.read_bytes()


# =====================================================================
# Reconnect on stale-channel error (v1.1.0)
# =====================================================================


class TestReconnectOnStaleChannel:
    """If the scheduler restarts, the cached gRPC channel goes stale
    and the next call returns UNAVAILABLE / DEADLINE_EXCEEDED. The
    client closes the dead channel, opens a fresh one, and retries
    exactly once. Other status codes propagate.
    """

    @pytest.mark.asyncio
    async def test_unavailable_triggers_reconnect_and_retry(
        self, tmp_path: Path,
    ) -> None:
        import grpc

        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

        client = TriggerScheduleClient(
            settings=_settings(
                scheduler_trigger_url="scheduler:7802",
                scheduler_trigger_tls_cert=str(cert),
                scheduler_trigger_tls_key=str(key),
                scheduler_trigger_tls_ca=str(ca),
            ),
        )

        connect_calls = {"count": 0}

        # Fake stub: first call raises UNAVAILABLE, second succeeds.
        class _FlakyStub:
            def __init__(self) -> None:
                self.call_count = 0

            async def TriggerSchedule(self, request, timeout=None):
                self.call_count += 1
                if self.call_count == 1:
                    err = grpc.aio.AioRpcError(
                        code=grpc.StatusCode.UNAVAILABLE,
                        initial_metadata=grpc.aio.Metadata(),
                        trailing_metadata=grpc.aio.Metadata(),
                        details="connection lost",
                    )
                    raise err

                class _R:
                    command_id = "after-reconnect"
                    error_code = ""
                    error_message = ""

                return _R()

        flaky = _FlakyStub()

        async def _fake_connect():
            connect_calls["count"] += 1
            client._stub = flaky  # type: ignore[assignment]
            client._channel = object()  # type: ignore[assignment]

        async def _fake_close():
            client._stub = None  # type: ignore[assignment]
            client._channel = None  # type: ignore[assignment]

        with (
            patch.object(client, "connect", _fake_connect),
            patch.object(client, "close", _fake_close),
        ):
            response = await client.trigger(
                schedule_id=uuid.uuid4(),
                user_id=uuid.uuid4(),
                idempotency_key="k",
            )

        # First call (lazy connect) + reconnect after the UNAVAILABLE
        assert connect_calls["count"] == 2, (
            f"expected exactly one reconnect; got {connect_calls['count']} "
            "connect calls"
        )
        assert flaky.call_count == 2  # original + retry
        assert response.command_id == "after-reconnect"

    @pytest.mark.asyncio
    async def test_non_retriable_status_propagates(
        self, tmp_path: Path,
    ) -> None:
        """PERMISSION_DENIED is NOT a stale-channel signal; the client
        must not retry, propagate to the caller.
        """
        import grpc

        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_bytes(b"x")

        client = TriggerScheduleClient(
            settings=_settings(
                scheduler_trigger_url="scheduler:7802",
                scheduler_trigger_tls_cert=str(cert),
                scheduler_trigger_tls_key=str(key),
                scheduler_trigger_tls_ca=str(ca),
            ),
        )

        class _DeniedStub:
            def __init__(self) -> None:
                self.call_count = 0

            async def TriggerSchedule(self, request, timeout=None):
                self.call_count += 1
                raise grpc.aio.AioRpcError(
                    code=grpc.StatusCode.PERMISSION_DENIED,
                    initial_metadata=grpc.aio.Metadata(),
                    trailing_metadata=grpc.aio.Metadata(),
                    details="not authorized",
                )

        denied = _DeniedStub()

        async def _fake_connect():
            client._stub = denied  # type: ignore[assignment]
            client._channel = object()  # type: ignore[assignment]

        with patch.object(client, "connect", _fake_connect):
            with pytest.raises(grpc.aio.AioRpcError) as exc:
                await client.trigger(
                    schedule_id=uuid.uuid4(),
                    user_id=None,
                    idempotency_key=None,
                )

        assert exc.value.code() == grpc.StatusCode.PERMISSION_DENIED
        # Must not retry, exactly one call.
        assert denied.call_count == 1
