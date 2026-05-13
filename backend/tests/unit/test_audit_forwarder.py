"""Tests for the v1.6 out-of-band audit-log forwarder."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from z4j_brain.domain import audit_forwarder as af_mod
from z4j_brain.domain.audit_forwarder import (
    AUDIT_SIGNATURE_HEADER,
    AUDIT_TIMESTAMP_HEADER,
    AuditForwarder,
    _row_to_payload,
    row_to_payload,
    sign_payload,
)
from z4j_brain.settings import ConfigError, Settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("Z4J_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    for var in (
        "Z4J_AUDIT_WEBHOOK_URL",
        "Z4J_AUDIT_WEBHOOK_HMAC_SECRET",
        "Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS",
        "Z4J_AUDIT_WEBHOOK_BUFFER_SIZE",
    ):
        monkeypatch.delenv(var, raising=False)


def _fake_row(**overrides: Any) -> SimpleNamespace:
    """Build a minimal AuditLog-shaped object for the forwarder.

    The forwarder reads attributes by name; SimpleNamespace is the
    cheapest stand-in. Tests asserting on the wire shape don't need
    the full SQLAlchemy ORM machinery.
    """
    base: dict[str, Any] = {
        "id": uuid.UUID("00000000-0000-0000-0000-00000000abcd"),
        "action": "user.password_changed",
        "target_type": "user",
        "target_id": "user-1",
        "result": "success",
        "outcome": "allow",
        "event_id": None,
        "user_id": uuid.UUID("00000000-0000-0000-0000-0000000000aa"),
        "api_key_id": None,
        "project_id": None,
        "source_ip": "192.0.2.10",
        "user_agent": "z4j-cli/1",
        "audit_metadata": {"some": "value"},
        "occurred_at": datetime(2026, 5, 12, 12, 0, 0, tzinfo=UTC),
        "prev_row_hmac": "a" * 64,
        "row_hmac": "b" * 64,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestAuditWebhookSettings:
    def test_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        s = Settings()  # type: ignore[call-arg]
        assert s.audit_webhook_url is None
        assert s.audit_webhook_hmac_secret is None
        assert s.audit_webhook_timeout_seconds == 10.0
        assert s.audit_webhook_buffer_size == 1000

    def test_url_is_secretstr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_AUDIT_WEBHOOK_URL",
            "https://siem.internal/ingest?token=embedded",
        )
        monkeypatch.setenv(
            "Z4J_AUDIT_WEBHOOK_HMAC_SECRET",
            secrets.token_urlsafe(48),
        )
        s = Settings()  # type: ignore[call-arg]
        assert isinstance(s.audit_webhook_url, SecretStr)
        assert "embedded" not in str(s.audit_webhook_url)

    def test_url_without_hmac_secret_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_AUDIT_WEBHOOK_URL", "https://siem.internal/ingest",
        )
        with pytest.raises(ConfigError):
            Settings()  # type: ignore[call-arg]

    def test_short_hmac_secret_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(
            "Z4J_AUDIT_WEBHOOK_URL", "https://siem.internal/ingest",
        )
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_HMAC_SECRET", "too-short")
        with pytest.raises(ConfigError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize("bad", ["0", "0.5", "121", "0.05"])
    def test_timeout_out_of_range_rejected(
        self, monkeypatch: pytest.MonkeyPatch, bad: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS", bad)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]

    @pytest.mark.parametrize("ok", ["1.0", "5", "10.0", "120.0"])
    def test_timeout_in_range_accepted(
        self, monkeypatch: pytest.MonkeyPatch, ok: str,
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS", ok)
        s = Settings()  # type: ignore[call-arg]
        assert s.audit_webhook_timeout_seconds == float(ok)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestRowToPayload:
    def test_canonical_shape(self) -> None:
        row = _fake_row()
        payload = _row_to_payload(row)
        # Every field a downstream parser expects.
        for key in (
            "id", "action", "target_type", "target_id", "result",
            "outcome", "event_id", "user_id", "api_key_id",
            "project_id", "source_ip", "user_agent", "metadata",
            "occurred_at", "prev_row_hmac", "row_hmac",
        ):
            assert key in payload, f"missing {key}"

    def test_uuid_stringified(self) -> None:
        row = _fake_row()
        payload = _row_to_payload(row)
        assert payload["id"] == "00000000-0000-0000-0000-00000000abcd"
        assert payload["user_id"] == "00000000-0000-0000-0000-0000000000aa"

    def test_none_fields_pass_through_as_null(self) -> None:
        row = _fake_row()
        payload = _row_to_payload(row)
        assert payload["event_id"] is None
        assert payload["api_key_id"] is None

    def test_occurred_at_iso_with_microseconds(self) -> None:
        row = _fake_row()
        payload = _row_to_payload(row)
        assert payload["occurred_at"] == "2026-05-12T12:00:00.000000+00:00"

    def test_row_hmac_included(self) -> None:
        """The receiver can re-verify against its own cached secret
        OR trust the brain's HMAC chain directly. Pin the field is
        on-wire."""
        row = _fake_row(row_hmac="c" * 64)
        payload = _row_to_payload(row)
        assert payload["row_hmac"] == "c" * 64


class TestSignPayload:
    def test_signature_shape(self) -> None:
        sig = sign_payload(b"secret", b"payload")
        assert sig.startswith("sha256=")
        assert len(sig) == len("sha256=") + 64  # hex of sha256

    def test_signature_matches_manual_hmac(self) -> None:
        body = b'{"id":"x"}'
        secret = b"the-shared-key"
        expected = (
            "sha256="
            + hmac.new(secret, body, hashlib.sha256).hexdigest()
        )
        assert sign_payload(secret, body) == expected

    def test_signature_is_deterministic(self) -> None:
        assert sign_payload(b"k", b"m") == sign_payload(b"k", b"m")

    def test_signature_changes_with_body(self) -> None:
        a = sign_payload(b"k", b"x")
        b = sign_payload(b"k", b"y")
        assert a != b

    def test_signature_changes_with_secret(self) -> None:
        assert sign_payload(b"k1", b"m") != sign_payload(b"k2", b"m")


# ---------------------------------------------------------------------------
# AuditForwarder
# ---------------------------------------------------------------------------


class _RecordingPost:
    """Stand-in for the notification _post helper.

    Records the last call so the test can assert on URL, headers,
    pin_ip, and body.
    """

    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({"url": url, "kwargs": kwargs})
        req = httpx.Request("POST", url)
        return httpx.Response(
            status_code=self.status_code,
            content=b"ok",
            request=req,
        )


async def _noop_resolve_and_pin(_url: str) -> tuple[str | None, str | None]:
    return None, "203.0.113.10"


class TestAuditForwarderQueue:
    def test_enqueue_returns_true_for_normal_row(self) -> None:
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        assert fwd.enqueue(_fake_row()) is True
        assert fwd._queue.qsize() == 1

    def test_enqueue_drops_when_queue_full(self) -> None:
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
            buffer_size=2,
        )
        for _ in range(2):
            assert fwd.enqueue(_fake_row()) is True
        # Third enqueue must drop, not block.
        assert fwd.enqueue(_fake_row()) is False
        assert fwd.dropped_count == 1

    def test_enqueue_after_stop_returns_false(self) -> None:
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        fwd._stopped = True
        assert fwd.enqueue(_fake_row()) is False

    def test_invalid_buffer_size_rejected(self) -> None:
        with pytest.raises(ValueError):
            AuditForwarder(
                webhook_url="https://siem.example/ingest",
                hmac_secret=b"x" * 32,
                buffer_size=0,
            )

    def test_misshapen_row_does_not_crash_enqueue(self) -> None:
        """An object the payload builder can't handle returns False,
        not an exception. Audit writes MUST never fail because a
        downstream mirror's serialisation broke."""
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        # A bare object has no attributes the row->payload helper
        # cares about; the lookup of ``id`` etc raises AttributeError
        # which the forwarder swallows.

        class _Broken:
            pass

        assert fwd.enqueue(_Broken()) is False


class TestAuditForwarderSendOne:
    @pytest.mark.asyncio
    async def test_happy_path_posts_signed_body(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost(status_code=200)
        monkeypatch.setattr(af_mod, "_post", recorder)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        secret = b"a" * 48
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=secret,
            timeout_seconds=15.0,
        )
        payload = _row_to_payload(_fake_row())
        await fwd._send_one(payload)

        assert len(recorder.calls) == 1
        call = recorder.calls[0]
        assert call["url"] == "https://siem.example/ingest"
        assert call["kwargs"]["pin_ip"] == "203.0.113.10"
        headers = call["kwargs"]["headers"]
        assert headers["Content-Type"] == "application/json"
        # v1.6 audit C5: per-call timeout MUST be threaded through.
        assert call["kwargs"].get("timeout") == 15.0
        assert AUDIT_SIGNATURE_HEADER in headers
        # v1.6 audit H10: timestamp header MUST be set and the
        # signature MUST cover (timestamp, body), not body alone.
        assert AUDIT_TIMESTAMP_HEADER in headers
        timestamp = headers[AUDIT_TIMESTAMP_HEADER]
        assert timestamp.isdigit() and len(timestamp) >= 10
        body = call["kwargs"]["content"]
        expected_sig = sign_payload(secret, body, timestamp=timestamp)
        assert headers[AUDIT_SIGNATURE_HEADER] == expected_sig
        # The timestamp-less sig MUST be different (proves replay
        # protection actually changes the digest input).
        body_only_sig = sign_payload(secret, body)
        assert body_only_sig != expected_sig
        # Receiver-side reproduction of the signature must match.
        decoded = json.loads(body.decode("utf-8"))
        assert decoded["action"] == "user.password_changed"
        assert fwd.sent_count == 1
        assert fwd.failed_count == 0

    @pytest.mark.asyncio
    async def test_ssrf_rejection_increments_failed_count(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost()
        monkeypatch.setattr(af_mod, "_post", recorder)

        async def _block(_url: str) -> tuple[str | None, str | None]:
            return "blocked: loopback", None

        monkeypatch.setattr(af_mod, "resolve_and_pin", _block)
        fwd = AuditForwarder(
            webhook_url="http://127.0.0.1:9000/ingest",
            hmac_secret=b"x" * 32,
        )
        await fwd._send_one(_row_to_payload(_fake_row()))
        assert len(recorder.calls) == 0
        assert fwd.failed_count == 1
        assert fwd.sent_count == 0

    @pytest.mark.asyncio
    async def test_5xx_response_marked_failed(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost(status_code=503)
        monkeypatch.setattr(af_mod, "_post", recorder)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        await fwd._send_one(_row_to_payload(_fake_row()))
        assert fwd.failed_count == 1
        assert fwd.sent_count == 0

    @pytest.mark.asyncio
    async def test_post_raises_failed_count(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _raising_post(_url: str, **_: Any) -> httpx.Response:
            raise RuntimeError("connection refused")

        monkeypatch.setattr(af_mod, "_post", _raising_post)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        await fwd._send_one(_row_to_payload(_fake_row()))
        assert fwd.failed_count == 1


class TestSignPayloadTimestamp:
    """v1.6 audit H10: replay protection via timestamp folded into
    HMAC input."""

    def test_signature_changes_with_timestamp(self) -> None:
        s = sign_payload(b"k", b"m", timestamp="1700000000")
        s2 = sign_payload(b"k", b"m", timestamp="1700000001")
        assert s != s2

    def test_signature_without_timestamp_distinct_from_with(self) -> None:
        with_ts = sign_payload(b"k", b"m", timestamp="1700000000")
        no_ts = sign_payload(b"k", b"m")
        assert with_ts != no_ts

    def test_signature_with_timestamp_is_reproducible(self) -> None:
        a = sign_payload(b"k", b"m", timestamp="1700000000")
        b = sign_payload(b"k", b"m", timestamp="1700000000")
        assert a == b


class TestEnqueueAcceptsDict:
    """v1.6 audit C6/H11: hook contract is now dict-based. ORM rows
    are still accepted for backwards-compat with the prior hook
    shape, but dicts are the preferred path."""

    def test_enqueue_dict_payload(self) -> None:
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        payload = row_to_payload(_fake_row())
        assert fwd.enqueue(payload) is True
        assert fwd._queue.qsize() == 1

    def test_enqueue_orm_row_back_compat(self) -> None:
        """Old callers may still pass a row object directly. The
        forwarder must materialise it inline rather than raising."""
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        assert fwd.enqueue(_fake_row()) is True


class TestShutdownDrainAccounting:
    """v1.6 audit H8: rows enqueued between empty-check and cancel
    must be accounted for, not silently lost."""

    @pytest.mark.asyncio
    async def test_residual_after_cancel_counted(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Use a never-resolving send so rows queued during stop()
        # cannot drain.
        async def _stuck_post(*_args: Any, **_kwargs: Any) -> httpx.Response:
            # Block forever -- the drain task will be cancelled
            # while awaiting this.
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        monkeypatch.setattr(af_mod, "_post", _stuck_post)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
            buffer_size=10,
        )
        fwd.start()
        # Let the drain task pick up one row + block on the stuck _post.
        fwd.enqueue(_fake_row())
        await asyncio.sleep(0.05)
        # Enqueue two more while the drain task is parked.
        fwd.enqueue(_fake_row())
        fwd.enqueue(_fake_row())
        # Stop with a short deadline so the queued rows stay
        # unsent. After the Round 2 in-flight tracking fix, the
        # count is 3: 2 queued + 1 in-flight (the row the drain
        # task pulled and parked on _send_one).
        await fwd.stop(drain_timeout=0.1)
        assert fwd.shutdown_lost == 3


class TestUnregisterHook:
    """v1.6 audit H9: AuditService must support unregistering a
    previously-registered hook so the lifespan teardown can remove
    the forwarder's enqueue callable before stopping the drain task.
    The contract lives on AuditService, but the forwarder tests pin
    that the function returns True on success / False on missing
    hook (defensive check; the lifespan calls it before stop()).
    """

    def test_unregister_returns_true_on_known_hook(self) -> None:
        # Local stub mirroring the AuditService API surface so this
        # test doesn't require a full AuditService instance.
        from z4j_brain.domain.audit_service import AuditService

        # Construct a minimal AuditService via a stub settings.
        class _Stub:
            class secret:
                @staticmethod
                def get_secret_value() -> str:
                    return "x" * 48

            @staticmethod
            def all_secrets_for_verification() -> list[bytes]:
                return [b"x" * 48]

        svc = AuditService.__new__(AuditService)
        svc._secret = b"x" * 48
        svc._verify_secrets = [b"x" * 48]
        svc._post_write_hooks = []
        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        svc.register_post_write_hook(fwd.enqueue)
        assert svc.unregister_post_write_hook(fwd.enqueue) is True
        # Second unregister is a no-op returning False.
        assert svc.unregister_post_write_hook(fwd.enqueue) is False


class TestAuditForwarderRunForever:
    @pytest.mark.asyncio
    async def test_start_drains_queue_through_send(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        recorder = _RecordingPost(status_code=202)
        monkeypatch.setattr(af_mod, "_post", recorder)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = AuditForwarder(
            webhook_url="https://siem.example/ingest",
            hmac_secret=b"x" * 32,
        )
        for _ in range(3):
            fwd.enqueue(_fake_row())

        fwd.start()
        # Give the drain task a moment to pick up the queue.
        for _ in range(50):
            if fwd._queue.empty() and fwd.sent_count == 3:
                break
            await asyncio.sleep(0.01)
        await fwd.stop(drain_timeout=1.0)
        assert fwd.sent_count == 3
        assert len(recorder.calls) == 3
