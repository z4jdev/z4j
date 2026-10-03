"""Tests for the out-of-band audit-log forwarder: settings, wire shape, signing.

Delivery through the durable cursor (ordering, backoff, restart, the
leader lease) lives in ``test_audit_forwarder_cursor.py``. This file pins
the parts that did not change when the in-memory queue went away: the
settings surface, the payload rendering, the signature, and what one
``_send_one`` call does with each kind of answer.
"""

from __future__ import annotations

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
    encode_payload,
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
        "Z4J_AUDIT_WEBHOOK_BATCH_SIZE",
        "Z4J_AUDIT_WEBHOOK_POLL_INTERVAL_SECONDS",
        "Z4J_AUDIT_WEBHOOK_MAX_BACKOFF_SECONDS",
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


def _forwarder(**overrides: Any) -> AuditForwarder:
    """A forwarder whose database is never touched: ``_send_one`` only."""
    kwargs: dict[str, Any] = {
        "db": SimpleNamespace(),
        "webhook_url": "https://siem.example/ingest",
        "hmac_secret": b"x" * 32,
    }
    kwargs.update(overrides)
    return AuditForwarder(**kwargs)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestAuditWebhookSettings:
    def test_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        s = Settings()
        assert s.audit_webhook_url is None
        assert s.audit_webhook_hmac_secret is None
        assert s.audit_webhook_timeout_seconds == 10.0
        assert s.audit_webhook_buffer_size == 1000
        assert s.audit_webhook_batch_size == 100
        assert s.audit_webhook_poll_interval_seconds == 5.0
        assert s.audit_webhook_max_backoff_seconds == 300.0
        assert s.audit_forwarder_enabled() is False

    def test_url_is_secretstr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_URL", "https://siem.example/ingest?token=abc")
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_HMAC_SECRET", "k" * 48)
        s = Settings()
        assert isinstance(s.audit_webhook_url, SecretStr)
        assert "abc" not in repr(s.audit_webhook_url)
        assert s.audit_forwarder_enabled() is True

    def test_blank_url_counts_as_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_URL", "   ")
        assert Settings().audit_forwarder_enabled() is False

    def test_url_without_hmac_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_URL", "https://siem.example/ingest")
        with pytest.raises(ConfigError, match="audit_webhook_hmac_secret"):
            Settings()

    def test_short_hmac_secret_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_URL", "https://siem.example/ingest")
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_HMAC_SECRET", "short")
        with pytest.raises(ConfigError, match="at least 32 bytes"):
            Settings()

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS", "0.5"),
            ("Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS", "121"),
            ("Z4J_AUDIT_WEBHOOK_BATCH_SIZE", "0"),
            ("Z4J_AUDIT_WEBHOOK_BATCH_SIZE", "1001"),
            ("Z4J_AUDIT_WEBHOOK_POLL_INTERVAL_SECONDS", "0.5"),
            ("Z4J_AUDIT_WEBHOOK_MAX_BACKOFF_SECONDS", "0"),
            ("Z4J_AUDIT_WEBHOOK_MAX_BACKOFF_SECONDS", "3601"),
        ],
    )
    def test_out_of_range_values_rejected(
        self, monkeypatch: pytest.MonkeyPatch, name: str, value: str
    ) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv(name, value)
        with pytest.raises(ValidationError):
            Settings()

    def test_in_range_values_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _base_env(monkeypatch)
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_TIMEOUT_SECONDS", "30")
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_BATCH_SIZE", "250")
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_POLL_INTERVAL_SECONDS", "2")
        monkeypatch.setenv("Z4J_AUDIT_WEBHOOK_MAX_BACKOFF_SECONDS", "60")
        s = Settings()
        assert s.audit_webhook_timeout_seconds == 30.0
        assert s.audit_webhook_batch_size == 250
        assert s.audit_webhook_poll_interval_seconds == 2.0
        assert s.audit_webhook_max_backoff_seconds == 60.0


# ---------------------------------------------------------------------------
# Payload rendering
# ---------------------------------------------------------------------------


class TestRowToPayload:
    def test_canonical_shape(self) -> None:
        payload = row_to_payload(_fake_row())
        assert set(payload) == {
            "id",
            "action",
            "target_type",
            "target_id",
            "result",
            "outcome",
            "event_id",
            "user_id",
            "api_key_id",
            "project_id",
            "source_ip",
            "user_agent",
            "metadata",
            "occurred_at",
            "prev_row_hmac",
            "row_hmac",
            "hmac_version",
            "hmac_key_id",
            "chain_generation",
            "legacy_frozen",
            "legacy_integrity_class",
            "legacy_origin",
        }
        assert payload["action"] == "user.password_changed"
        assert payload["metadata"] == {"some": "value"}

    def test_uuid_stringified(self) -> None:
        payload = row_to_payload(_fake_row())
        assert payload["id"] == "00000000-0000-0000-0000-00000000abcd"
        assert payload["user_id"] == "00000000-0000-0000-0000-0000000000aa"

    def test_none_fields_pass_through_as_null(self) -> None:
        payload = row_to_payload(_fake_row(target_id=None, source_ip=None))
        assert payload["target_id"] is None
        assert payload["source_ip"] is None
        assert payload["event_id"] is None

    def test_occurred_at_iso_with_microseconds(self) -> None:
        payload = row_to_payload(_fake_row())
        assert payload["occurred_at"] == "2026-05-12T12:00:00.000000+00:00"

    def test_row_hmac_included(self) -> None:
        payload = row_to_payload(_fake_row())
        assert payload["row_hmac"] == "b" * 64
        assert payload["prev_row_hmac"] == "a" * 64

    def test_underscore_alias_is_the_same_function(self) -> None:
        assert _row_to_payload is row_to_payload

    def test_encode_payload_is_canonical_sorted_compact_utf8(self) -> None:
        body = encode_payload({"b": 1, "a": "café", "n": None})
        assert body == '{"a":"café","b":1,"n":null}'.encode()


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestSignPayload:
    def test_signature_shape(self) -> None:
        sig = sign_payload(b"k" * 32, b"{}")
        assert sig.startswith("sha256=")
        assert len(sig) == len("sha256=") + 64

    def test_signature_matches_manual_hmac(self) -> None:
        secret = b"k" * 32
        body = b'{"a":1}'
        expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        assert sign_payload(secret, body) == expected

    def test_signature_is_deterministic(self) -> None:
        assert sign_payload(b"k" * 32, b"x") == sign_payload(b"k" * 32, b"x")

    def test_signature_changes_with_body(self) -> None:
        assert sign_payload(b"k" * 32, b"x") != sign_payload(b"k" * 32, b"y")

    def test_signature_changes_with_secret(self) -> None:
        assert sign_payload(b"k" * 32, b"x") != sign_payload(b"j" * 32, b"x")


class TestSignPayloadTimestamp:
    """The HMAC input is ``<timestamp>.<body>`` when a timestamp is given."""

    def test_signature_changes_with_timestamp(self) -> None:
        secret, body = b"k" * 32, b"{}"
        assert sign_payload(secret, body, timestamp="1") != sign_payload(
            secret, body, timestamp="2"
        )

    def test_signature_without_timestamp_distinct_from_with(self) -> None:
        secret, body = b"k" * 32, b"{}"
        assert sign_payload(secret, body) != sign_payload(secret, body, timestamp="1715515200")

    def test_signature_with_timestamp_is_reproducible(self) -> None:
        secret, body, ts = b"k" * 32, b'{"a":1}', "1715515200"
        expected = (
            "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        )
        assert sign_payload(secret, body, timestamp=ts) == expected


# ---------------------------------------------------------------------------
# One send
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


class TestAuditForwarderSendOne:
    async def test_happy_path_posts_signed_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorder = _RecordingPost(status_code=200)
        monkeypatch.setattr(af_mod, "_post", recorder)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        secret = b"a" * 48
        fwd = _forwarder(hmac_secret=secret, timeout_seconds=15.0)
        payload = _row_to_payload(_fake_row())
        assert await fwd._send_one(payload) is True

        assert len(recorder.calls) == 1
        call = recorder.calls[0]
        assert call["url"] == "https://siem.example/ingest"
        assert call["kwargs"]["pin_ip"] == "203.0.113.10"
        headers = call["kwargs"]["headers"]
        assert headers["Content-Type"] == "application/json"
        # Per-call timeout MUST be threaded through.
        assert call["kwargs"].get("timeout") == 15.0
        assert AUDIT_SIGNATURE_HEADER in headers
        # Timestamp header MUST be set and the signature MUST cover
        # (timestamp, body), not body alone.
        assert AUDIT_TIMESTAMP_HEADER in headers
        timestamp = headers[AUDIT_TIMESTAMP_HEADER]
        assert timestamp.isdigit() and len(timestamp) >= 10
        body = call["kwargs"]["content"]
        assert body == encode_payload(payload)
        expected_sig = sign_payload(secret, body, timestamp=timestamp)
        assert headers[AUDIT_SIGNATURE_HEADER] == expected_sig
        # The timestamp-less sig MUST be different (proves replay
        # protection actually changes the digest input).
        assert sign_payload(secret, body) != expected_sig
        decoded = json.loads(body.decode("utf-8"))
        assert decoded["action"] == "user.password_changed"
        assert fwd.sent_count == 1
        assert fwd.failed_count == 0

    async def test_ssrf_rejection_is_a_failed_attempt_not_a_drop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _RecordingPost()
        monkeypatch.setattr(af_mod, "_post", recorder)

        async def _block(_url: str) -> tuple[str | None, str | None]:
            return "blocked: loopback", None

        monkeypatch.setattr(af_mod, "resolve_and_pin", _block)
        fwd = _forwarder(webhook_url="http://127.0.0.1:9000/ingest")
        assert await fwd._send_one(_row_to_payload(_fake_row())) is False
        assert len(recorder.calls) == 0
        assert fwd.failed_count == 1
        assert fwd.sent_count == 0

    async def test_5xx_response_marked_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorder = _RecordingPost(status_code=503)
        monkeypatch.setattr(af_mod, "_post", recorder)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        fwd = _forwarder()
        assert await fwd._send_one(_row_to_payload(_fake_row())) is False
        assert fwd.failed_count == 1
        assert fwd.sent_count == 0

    async def test_post_raises_failed_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _raising_post(_url: str, **_: Any) -> httpx.Response:
            raise RuntimeError("connection refused")

        monkeypatch.setattr(af_mod, "_post", _raising_post)
        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)
        fwd = _forwarder()
        assert await fwd._send_one(_row_to_payload(_fake_row())) is False
        assert fwd.failed_count == 1

    async def test_every_failure_kind_is_counted_by_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reasons: list[str] = []
        monkeypatch.setattr(af_mod, "_observe_failure", reasons.append)
        payload = _row_to_payload(_fake_row())

        async def _block(_url: str) -> tuple[str | None, str | None]:
            return "blocked: loopback", None

        monkeypatch.setattr(af_mod, "resolve_and_pin", _block)
        await _forwarder()._send_one(payload)

        monkeypatch.setattr(af_mod, "resolve_and_pin", _noop_resolve_and_pin)

        async def _raising_post(_url: str, **_: Any) -> httpx.Response:
            raise RuntimeError("connection refused")

        monkeypatch.setattr(af_mod, "_post", _raising_post)
        await _forwarder()._send_one(payload)

        monkeypatch.setattr(af_mod, "_post", _RecordingPost(status_code=500))
        await _forwarder()._send_one(payload)

        assert reasons == ["ssrf_or_dns", "post_raised", "non_2xx"]


# ---------------------------------------------------------------------------
# AuditService hook registry (the forwarder no longer registers one)
# ---------------------------------------------------------------------------


class TestUnregisterHook:
    """``AuditService`` still supports unregistering a post-write hook.

    The forwarder no longer registers one: it reads the audit log past its
    cursor instead of being handed rows at commit time. The registry stays
    for other consumers, so its contract is pinned here with a plain
    callable.
    """

    def test_unregister_returns_true_on_known_hook(self) -> None:
        from z4j_brain.domain.audit_service import AuditService

        svc = AuditService.__new__(AuditService)
        svc._secret = b"x" * 48
        svc._verify_secrets = [b"x" * 48]
        svc._post_write_hooks = []

        def hook(_payload: dict[str, Any]) -> None:
            return None

        svc.register_post_write_hook(hook)
        assert svc.unregister_post_write_hook(hook) is True
        # Second unregister is a no-op returning False.
        assert svc.unregister_post_write_hook(hook) is False

    def test_forwarder_has_no_enqueue_surface(self) -> None:
        fwd = _forwarder()
        assert not hasattr(fwd, "enqueue")
        assert not hasattr(fwd, "queue_depth")
