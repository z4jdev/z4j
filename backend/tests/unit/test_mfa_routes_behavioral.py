"""Behavioral suite for the MFA route flows (1.6.0 anchor).

Exercises ``/api/v1/auth/mfa/*`` plus the login challenge the way the
dashboard drives them, against a real app on in-memory SQLite:

- enroll-start -> enroll-complete happy path: the TOTP secret is
  returned once, the stored blob is the same secret (encrypted and
  bound to the user row), recovery codes come back exactly once and
  only hashes hit the DB;
- enroll-complete with a wrong code does NOT enroll (and stays in the
  pending state); missing / duplicate enrollment states are 409s;
- restart semantics: enroll-start wipes a previous enrollment's
  secret and recovery codes and audits the restart distinctly;
- login challenge: enrolled user logs in -> ``mfa_required=True`` and
  the session is not MFA-fresh; wrong code is a 401 that leaves a
  ``user.mfa_verify_failed`` audit row; the right TOTP stamps
  ``sessions.mfa_verified_at`` and opens the fresh-MFA gate;
- recovery codes are SINGLE-USE: redeeming one flips ``consumed_at``
  and a second redemption of the same code fails like a wrong code;
  the verify scan hashes EVERY unused candidate (constant-work shape)
  and burns a dummy argon2 cycle when no codes remain;
- trusted devices ("remember this device"): the verify endpoint mints
  the ``z4j_mfa_trust`` cookie + a hashed server row honoring
  ``Z4J_MFA_REMEMBER_DEVICE_DAYS``; the next login skips the second
  step (and audits the skip); expired or revoked rows put the
  challenge back; rows are scoped per-user;
- disable requires password AND a current TOTP code, then wipes the
  secret, recovery codes, and trust rows in one shot;
- regenerate is behind the fresh-MFA gate, replaces the full code
  set, and old codes stop verifying;
- the fresh-MFA gate goes stale after ``mfa_verification_ttl_seconds``.

Wall-clock expiries (trust-row 30d, freshness TTL) are simulated by
rewriting the persisted timestamps rather than freezing time: the
comparison logic under test reads the DB values either way.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets as _secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain.mfa import encrypt_totp_secret, generate_totp_secret
from z4j_brain.domain.mfa.crypto import decrypt_totp_secret
from z4j_brain.domain.mfa.recovery import RECOVERY_CODE_PATTERN
from z4j_brain.domain.mfa.totp import SECRET_BYTES, current_totp_code
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import (
    AuditLog,
    MfaRecoveryCode,
    TrustedDevice,
    User,
)
from z4j_brain.persistence.models import (
    Session as SessionRow,
)
from z4j_brain.settings import Settings

PASSWORD = "correct horse battery staple 9"

#: Dev-environment name of the "remember this device" cookie.
TRUST_COOKIE = "z4j_mfa_trust"


# ---------------------------------------------------------------------------
# Helpers (same shape as test_mfa_enforcement.py)
# ---------------------------------------------------------------------------


def make_settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    values: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": _secrets.token_urlsafe(48),
        "session_secret": _secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
        # Cheap argon2 + no timing floor so the suite stays fast.
        "argon2_time_cost": 1,
        "argon2_memory_cost": 8192,
        "login_min_duration_ms": 0,
        "login_backoff_base_seconds": 0.0,
        "login_backoff_max_seconds": 0.0,
        "disable_spa_fallback": True,
        # Smallest legal recovery-code set: every enroll-complete
        # burns one full-cost argon2 hash per code.
        "mfa_recovery_code_count": 5,
        # Some flows verify several times in one test.
        "mfa_verification_rate_per_min": 300,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@asynccontextmanager
async def make_brain(settings: Settings):  # type: ignore[no-untyped-def]
    """Yield ``(app, client)`` on a fresh in-memory SQLite engine."""
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as ac:
            yield app, ac
    finally:
        await engine.dispose()


async def seed_user(  # type: ignore[no-untyped-def]
    app,
    settings: Settings,
    *,
    email: str,
    enrolled: bool = False,
):
    """Insert a user; returns ``(user_id, totp_secret_or_None)``."""
    hasher = PasswordHasher(settings)
    async with app.state.db.session() as s:
        user = User(
            email=email,
            password_hash=hasher.hash(PASSWORD),
            is_admin=False,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        totp_secret = None
        if enrolled:
            totp_secret = generate_totp_secret()
            user.mfa_secret_encrypted = encrypt_totp_secret(
                totp_secret,
                master_secret=settings.secret.get_secret_value().encode("utf-8"),
                user_id=user.id,
            )
            user.mfa_enrolled_at = datetime.now(UTC)
        await s.commit()
        return user.id, totp_secret


async def login(client: AsyncClient, email: str) -> dict:  # type: ignore[type-arg]
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert r.status_code == 200, r.text
    return r.json()


def csrf_header(client: AsyncClient, settings: Settings) -> dict[str, str]:
    token = client.cookies.get(csrf_cookie_name(environment=settings.environment))
    assert token is not None
    return {"X-CSRF-Token": token}


def wrong_totp_code(secret: bytes) -> str:
    """A well-formed 6-digit code guaranteed NOT to verify right now
    (avoids the +-1-step acceptance window deterministically)."""
    now = time.time()
    valid = {current_totp_code(secret, at_time=now + delta) for delta in (-30, 0, 30)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


def decode_b32(secret_base32: str) -> bytes:
    return base64.b32decode(secret_base32 + "=" * (-len(secret_base32) % 8))


async def enroll_via_routes(  # type: ignore[no-untyped-def]
    client: AsyncClient,
    settings: Settings,
):
    """Drive enroll-start -> enroll-complete; returns
    ``(totp_secret_bytes, plaintext_recovery_codes)``."""
    start = await client.post(
        "/api/v1/auth/mfa/enroll-start",
        headers=csrf_header(client, settings),
    )
    assert start.status_code == 200, start.text
    secret = decode_b32(start.json()["secret_base32"])
    complete = await client.post(
        "/api/v1/auth/mfa/enroll-complete",
        json={"code": current_totp_code(secret)},
        headers=csrf_header(client, settings),
    )
    assert complete.status_code == 200, complete.text
    return secret, complete.json()["recovery_codes"]


# --- DB inspection helpers -------------------------------------------------


async def user_mfa_state(app, user_id):  # type: ignore[no-untyped-def]
    """``(mfa_secret_encrypted, mfa_enrolled_at)`` for the user row."""
    async with app.state.db.session() as s:
        result = await s.execute(
            select(User.mfa_secret_encrypted, User.mfa_enrolled_at).where(
                User.id == user_id,
            ),
        )
        return result.one()


async def recovery_code_rows(app, user_id):  # type: ignore[no-untyped-def]
    """List of ``(code_hash, consumed_at)`` tuples for the user."""
    async with app.state.db.session() as s:
        result = await s.execute(
            select(MfaRecoveryCode.code_hash, MfaRecoveryCode.consumed_at).where(
                MfaRecoveryCode.user_id == user_id,
            ),
        )
        return list(result.all())


async def trusted_device_rows(app, user_id):  # type: ignore[no-untyped-def]
    """List of ``(id, cookie_id_hash, expires_at, revoked_at)``."""
    async with app.state.db.session() as s:
        result = await s.execute(
            select(
                TrustedDevice.id,
                TrustedDevice.cookie_id_hash,
                TrustedDevice.expires_at,
                TrustedDevice.revoked_at,
            ).where(TrustedDevice.user_id == user_id),
        )
        return list(result.all())


async def verified_session_count(app, user_id) -> int:  # type: ignore[no-untyped-def]
    async with app.state.db.session() as s:
        result = await s.execute(
            select(SessionRow.id).where(
                SessionRow.user_id == user_id,
                SessionRow.mfa_verified_at.is_not(None),
            ),
        )
        return len(list(result.scalars().all()))


async def audit_actions(app) -> list[str]:  # type: ignore[no-untyped-def]
    async with app.state.db.session() as s:
        result = await s.execute(select(AuditLog.action))
        return list(result.scalars().all())


async def audit_metadata_for(app, action: str) -> list[dict]:  # type: ignore[no-untyped-def, type-arg]
    async with app.state.db.session() as s:
        result = await s.execute(
            select(AuditLog.audit_metadata).where(AuditLog.action == action),
        )
        return list(result.scalars().all())


def trust_cookie_headers(response) -> list[str]:  # type: ignore[no-untyped-def]
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{TRUST_COOKIE}=")]


# ---------------------------------------------------------------------------
# Enrollment flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEnrollmentFlow:
    async def test_enroll_start_creates_pending_state(self) -> None:
        """The returned secret is real: it decodes to 20 bytes, it is
        what actually got persisted (encrypted, bound to this user),
        and the provisioning URL carries the same base32 form. The
        user is NOT enrolled yet."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")

            r = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            body = r.json()
            secret = decode_b32(body["secret_base32"])
            assert len(secret) == SECRET_BYTES
            assert body["provisioning_url"].startswith("otpauth://totp/")
            assert body["secret_base32"] in body["provisioning_url"]
            assert "alice%40example.com" in body["provisioning_url"]

            blob, enrolled_at = await user_mfa_state(app, uid)
            assert blob is not None
            assert enrolled_at is None  # pending, not enrolled
            stored_secret, _ = decrypt_totp_secret(
                blob,
                master_secret=settings.secret.get_secret_value().encode("utf-8"),
                user_id=uid,
            )
            assert stored_secret == secret

            status = await client.get("/api/v1/auth/mfa/status")
            assert status.json()["enrolled"] is False

            metadata = await audit_metadata_for(app, "user.mfa_enroll_started")
            assert [m["restart_of_enrolled"] for m in metadata] == [False]

    async def test_enroll_complete_wrong_code_does_not_enroll(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")

            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            secret = decode_b32(start.json()["secret_base32"])

            r = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": wrong_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401, r.text
            assert r.json()["details"]["reason"] == "wrong_totp"

            # Still pending, no recovery codes minted, no enrolled
            # audit row, session not MFA-fresh.
            _, enrolled_at = await user_mfa_state(app, uid)
            assert enrolled_at is None
            assert await recovery_code_rows(app, uid) == []
            assert "user.mfa_enrolled" not in await audit_actions(app)
            assert await verified_session_count(app, uid) == 0
            status = await client.get("/api/v1/auth/mfa/status")
            assert status.json()["enrolled"] is False

    async def test_enroll_complete_without_start_is_conflict(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": "123456"},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 409
            assert r.json()["details"]["reason"] == "no_pending_enrollment"

    async def test_enroll_happy_path(self) -> None:
        """Correct code activates MFA: recovery codes are returned
        exactly once (and only argon2id hashes reach the DB), the
        enrolling session becomes MFA-fresh, and the audit trail
        carries ``user.mfa_enrolled``."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")

            _secret, codes = await enroll_via_routes(client, settings)

            assert len(codes) == settings.mfa_recovery_code_count
            assert len(set(codes)) == len(codes)
            for code in codes:
                assert re.fullmatch(RECOVERY_CODE_PATTERN, code), code

            _, enrolled_at = await user_mfa_state(app, uid)
            assert enrolled_at is not None
            rows = await recovery_code_rows(app, uid)
            assert len(rows) == settings.mfa_recovery_code_count
            for code_hash, consumed_at in rows:
                assert code_hash.startswith("$argon2id$")
                assert consumed_at is None
                assert code_hash not in codes  # hashes, never plaintext

            status = await client.get("/api/v1/auth/mfa/status")
            body = status.json()
            assert body["enrolled"] is True
            assert body["enrolled_at"] is not None
            assert body["remaining_recovery_codes"] == settings.mfa_recovery_code_count

            # The enrolling session is MFA-fresh immediately.
            assert await verified_session_count(app, uid) == 1
            assert "user.mfa_enrolled" in await audit_actions(app)

    async def test_enroll_complete_twice_is_conflict(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")
            secret, _ = await enroll_via_routes(client, settings)
            r = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 409
            assert r.json()["details"]["reason"] == "already_enrolled"

    async def test_enroll_start_restart_wipes_previous_enrollment(self) -> None:
        """Re-running enroll-start over an active enrollment mints a
        NEW secret, drops back to the pending state, deletes the old
        recovery codes, and audits the restart distinctly."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="alice@example.com")
            await login(client, "alice@example.com")
            old_secret, _old_codes = await enroll_via_routes(client, settings)

            r = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            new_secret = decode_b32(r.json()["secret_base32"])
            assert new_secret != old_secret

            _, enrolled_at = await user_mfa_state(app, uid)
            assert enrolled_at is None  # back to pending
            assert await recovery_code_rows(app, uid) == []  # codes wiped
            status = await client.get("/api/v1/auth/mfa/status")
            assert status.json()["enrolled"] is False

            metadata = await audit_metadata_for(app, "user.mfa_enroll_started")
            assert sorted(m["restart_of_enrolled"] for m in metadata) == [False, True]


# ---------------------------------------------------------------------------
# Login challenge + TOTP verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLoginChallengeFlow:
    async def test_full_challenge_round_trip(self) -> None:
        """login -> mfa_required -> wrong code 401 (audited) ->
        correct TOTP -> session is MFA-fresh."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="carol@example.com",
                enrolled=True,
            )
            body = await login(client, "carol@example.com")
            assert body["mfa_required"] is True
            assert await verified_session_count(app, uid) == 0

            # The fresh-MFA gate is closed before the second factor.
            gated = await client.post(
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                headers=csrf_header(client, settings),
            )
            assert gated.status_code == 403
            assert gated.json()["error"] == "mfa_reverify_required"

            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": wrong_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_totp"
            assert "user.mfa_verify_failed" in await audit_actions(app)
            assert await verified_session_count(app, uid) == 0

            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["ok"] is True
            assert body["used_recovery_code"] is False
            assert body["remaining_recovery_codes"] is None
            assert await verified_session_count(app, uid) == 1
            assert "user.mfa_verified" in await audit_actions(app)

            # The fresh-MFA gate now opens.
            opened = await client.post(
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                headers=csrf_header(client, settings),
            )
            assert opened.status_code == 200, opened.text

    async def test_unenrolled_login_has_no_challenge(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            body = await login(client, "bob@example.com")
            assert body["mfa_required"] is False

    async def test_verify_without_enrollment_is_conflict(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": "123456"},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 409
            assert r.json()["details"]["reason"] == "mfa_not_enrolled"

    @pytest.mark.parametrize(
        "bad_code",
        [
            "12345",  # under the schema's min_length
            "1234567",  # 7 digits: neither TOTP nor recovery shape
            "abcdef",  # 6 non-digits
            "ABCD-EFGH",  # truncated recovery code
        ],
    )
    async def test_verify_rejects_malformed_codes(self, bad_code: str) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(
                app,
                settings,
                email="carol@example.com",
                enrolled=True,
            )
            await login(client, "carol@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": bad_code},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 422, (bad_code, r.text)
            assert await verified_session_count(app, uid) == 0

    async def test_mfa_freshness_expires_after_ttl(self) -> None:
        """A verify older than ``mfa_verification_ttl_seconds`` no
        longer satisfies the sensitive-action gate."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="carol@example.com",
                enrolled=True,
            )
            await login(client, "carol@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200

            # Age the verify stamp past the TTL.
            stale = datetime.now(UTC) - timedelta(
                seconds=settings.mfa_verification_ttl_seconds + 60,
            )
            async with app.state.db.session() as s:
                await s.execute(
                    update(SessionRow)
                    .where(SessionRow.user_id == uid)
                    .values(mfa_verified_at=stale),
                )
                await s.commit()

            gated = await client.post(
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                headers=csrf_header(client, settings),
            )
            assert gated.status_code == 403
            assert gated.json()["error"] == "mfa_reverify_required"


# ---------------------------------------------------------------------------
# Recovery-code verify (single-use semantics)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRecoveryCodeFlow:
    @asynccontextmanager
    async def _enrolled_brain(self, **settings_overrides):  # type: ignore[no-untyped-def]
        """Brain + client with a route-enrolled user (so real recovery
        codes exist); yields ``(app, client, settings, uid, secret,
        codes)`` with a FRESH (mfa-pending) login as the last step."""
        settings = make_settings(**settings_overrides)
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="dave@example.com")
            await login(client, "dave@example.com")
            secret, codes = await enroll_via_routes(client, settings)
            # New session: the MFA challenge is pending again.
            body = await login(client, "dave@example.com")
            assert body["mfa_required"] is True
            yield app, client, settings, uid, secret, codes

    async def test_recovery_code_is_single_use(self) -> None:
        async with self._enrolled_brain() as (app, client, settings, uid, _s, codes):
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["used_recovery_code"] is True
            assert body["remaining_recovery_codes"] == len(codes) - 1
            assert "user.mfa_recovery_code_used" in await audit_actions(app)

            rows = await recovery_code_rows(app, uid)
            consumed = [row for row in rows if row.consumed_at is not None]
            assert len(consumed) == 1

            # A new session presents the SAME code again: rejected
            # exactly like a wrong code, nothing else consumed.
            await login(client, "dave@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_recovery_code"
            assert "user.mfa_verify_failed" in await audit_actions(app)
            rows = await recovery_code_rows(app, uid)
            assert len([row for row in rows if row.consumed_at is not None]) == 1
            status = await client.get("/api/v1/auth/mfa/status")
            assert status.json()["remaining_recovery_codes"] == len(codes) - 1

    async def test_recovery_code_input_is_normalised(self) -> None:
        """Lowercase, hyphen-less user input redeems the code."""
        async with self._enrolled_brain() as (_app, client, settings, _uid, _s, codes):
            sloppy = codes[1].replace("-", "").lower()
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": sloppy},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            assert r.json()["used_recovery_code"] is True

    async def test_recovery_verify_stamps_session_freshness(self) -> None:
        async with self._enrolled_brain() as (app, client, settings, uid, _s, codes):
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200
            # Enrolling session + this one.
            assert await verified_session_count(app, uid) == 2

    async def test_wrong_recovery_code_rejected(self) -> None:
        async with self._enrolled_brain() as (app, client, settings, uid, _s, _codes):
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": "AAAA-AAAA-AAAA"},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_recovery_code"
            rows = await recovery_code_rows(app, uid)
            assert all(row.consumed_at is None for row in rows)

    async def test_verify_scans_every_candidate_hash(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Constant-work shape (1.6.0 audit High-1): a matching code
        must NOT short-circuit the scan; every unused row is hashed."""
        async with self._enrolled_brain() as (_app, client, settings, _uid, _s, codes):
            import z4j_brain.api.auth_mfa as auth_mfa_module

            real = auth_mfa_module.verify_recovery_code
            calls = {"n": 0}

            def counting(**kwargs):  # type: ignore[no-untyped-def]
                calls["n"] += 1
                return real(**kwargs)

            monkeypatch.setattr(auth_mfa_module, "verify_recovery_code", counting)
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": codes[1]},  # match sits mid-list
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            assert calls["n"] == len(codes)

    async def test_empty_code_set_burns_dummy_cycle(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """When every code is consumed, the verify path burns one
        argon2 cycle so 'out of codes' is timing-indistinguishable
        from 'wrong code' (1.6.0 round-2 audit High-2)."""
        async with self._enrolled_brain() as (app, client, settings, uid, _s, codes):
            async with app.state.db.session() as s:
                await s.execute(
                    update(MfaRecoveryCode)
                    .where(MfaRecoveryCode.user_id == uid)
                    .values(consumed_at=datetime.now(UTC)),
                )
                await s.commit()

            import z4j_brain.api.auth_mfa as auth_mfa_module

            burns: list[int] = []
            monkeypatch.setattr(
                auth_mfa_module,
                "burn_one_argon2_cycle",
                lambda: burns.append(1),
            )
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_recovery_code"
            assert burns == [1]


# ---------------------------------------------------------------------------
# Trusted devices ("remember this device")
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTrustedDeviceFlow:
    async def _mint_trust(self, app, client, settings, secret):  # type: ignore[no-untyped-def]
        """Verify with ``remember_device=True``; returns the verify
        response."""
        r = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": current_totp_code(secret), "remember_device": True},
            headers=csrf_header(client, settings),
        )
        assert r.status_code == 200, r.text
        return r

    async def test_remember_device_mints_cookie_and_hashed_row(self) -> None:
        settings = make_settings(mfa_remember_device_days=30)
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="erin@example.com",
                enrolled=True,
            )
            await login(client, "erin@example.com")
            before = datetime.now(UTC)
            r = await self._mint_trust(app, client, settings, secret)
            after = datetime.now(UTC)

            cookie_headers = trust_cookie_headers(r)
            assert len(cookie_headers) == 1
            header = cookie_headers[0].lower()
            assert "httponly" in header
            assert "samesite=strict" in header
            assert f"max-age={30 * 86400}" in header

            cookie_value = client.cookies.get(TRUST_COOKIE)
            assert cookie_value

            rows = await trusted_device_rows(app, uid)
            assert len(rows) == 1
            row = rows[0]
            # Server stores the SHA-256 of the cookie id, never the
            # plaintext.
            assert row.cookie_id_hash == hashlib.sha256(cookie_value.encode()).hexdigest()
            assert row.cookie_id_hash != cookie_value
            expires_at = row.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            assert before + timedelta(days=30) <= expires_at <= after + timedelta(days=30)

            assert "user.mfa_trusted_device_added" in await audit_actions(app)

            listing = await client.get("/api/v1/auth/mfa/trusted-devices")
            assert listing.status_code == 200
            devices = listing.json()
            assert len(devices) == 1
            assert devices[0]["is_current"] is True

    async def test_trusted_device_skips_next_login_challenge(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="erin@example.com",
                enrolled=True,
            )
            first = await login(client, "erin@example.com")
            assert first["mfa_required"] is True
            await self._mint_trust(app, client, settings, secret)

            # Same browser, next login: the second step is skipped,
            # the skip is audited, and the new session is already
            # MFA-verified server-side.
            second = await login(client, "erin@example.com")
            assert second["mfa_required"] is False
            assert "user.mfa_trusted_device_used" in await audit_actions(app)
            assert await verified_session_count(app, uid) == 2

    async def test_expired_trust_row_restores_the_challenge(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="erin@example.com",
                enrolled=True,
            )
            await login(client, "erin@example.com")
            await self._mint_trust(app, client, settings, secret)

            # The 30 days pass (simulated on the persisted expiry).
            async with app.state.db.session() as s:
                await s.execute(
                    update(TrustedDevice)
                    .where(TrustedDevice.user_id == uid)
                    .values(expires_at=datetime.now(UTC) - timedelta(days=1)),
                )
                await s.commit()

            body = await login(client, "erin@example.com")
            assert body["mfa_required"] is True

    async def test_revoked_trust_row_restores_the_challenge(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="erin@example.com",
                enrolled=True,
            )
            await login(client, "erin@example.com")
            await self._mint_trust(app, client, settings, secret)
            device_id = (await trusted_device_rows(app, uid))[0].id

            r = await client.post(
                f"/api/v1/auth/mfa/trusted-devices/{device_id}/revoke",
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 204, r.text
            # Revoking the CURRENT device also clears its cookie.
            cleared = trust_cookie_headers(r)
            assert len(cleared) == 1
            assert "max-age=0" in cleared[0].lower() or "expires=" in cleared[0].lower()
            assert "user.mfa_trusted_device_revoked" in await audit_actions(app)

            body = await login(client, "erin@example.com")
            assert body["mfa_required"] is True

    async def test_trust_rows_are_user_scoped(self) -> None:
        """User B logging in from a browser that carries user A's
        trust cookie still gets the full MFA challenge."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            _uid_a, secret_a = await seed_user(
                app,
                settings,
                email="a@example.com",
                enrolled=True,
            )
            _uid_b, _secret_b = await seed_user(
                app,
                settings,
                email="b@example.com",
                enrolled=True,
            )
            await login(client, "a@example.com")
            await self._mint_trust(app, client, settings, secret_a)
            assert client.cookies.get(TRUST_COOKIE)

            body = await login(client, "b@example.com")
            assert body["mfa_required"] is True
            assert "user.mfa_trusted_device_used" not in await audit_actions(app)


# ---------------------------------------------------------------------------
# Disable + regenerate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDisableFlow:
    async def test_disable_requires_both_password_and_code(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, secret = await seed_user(
                app,
                settings,
                email="frank@example.com",
                enrolled=True,
            )
            await login(client, "frank@example.com")

            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={"password": "not the password", "code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_password"

            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={"password": PASSWORD, "code": wrong_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_totp"

            blob, enrolled_at = await user_mfa_state(app, uid)
            assert blob is not None
            assert enrolled_at is not None  # still enrolled

    async def test_disable_wipes_secret_codes_and_trust(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="frank@example.com")
            await login(client, "frank@example.com")
            secret, _codes = await enroll_via_routes(client, settings)

            # Mint a trust row from the (fresh) enrolling session.
            trust = await client.post(
                "/api/v1/auth/mfa/trusted-devices",
                headers=csrf_header(client, settings),
            )
            assert trust.status_code == 201, trust.text
            assert len(await trusted_device_rows(app, uid)) == 1

            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={"password": PASSWORD, "code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            assert r.json()["ok"] is True

            blob, enrolled_at = await user_mfa_state(app, uid)
            assert blob is None
            assert enrolled_at is None
            assert await recovery_code_rows(app, uid) == []
            assert await trusted_device_rows(app, uid) == []
            assert "user.mfa_disabled" in await audit_actions(app)

            status = await client.get("/api/v1/auth/mfa/status")
            assert status.json()["enrolled"] is False

            # Even though the browser still holds the trust cookie,
            # the next login is a plain password login (no challenge,
            # no trust skip): the server-side rows are gone.
            body = await login(client, "frank@example.com")
            assert body["mfa_required"] is False

    async def test_disable_without_enrollment_is_conflict(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={"password": PASSWORD, "code": "123456"},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 409
            assert r.json()["details"]["reason"] == "mfa_not_enrolled"


@pytest.mark.asyncio
class TestRegenerateFlow:
    async def test_regenerate_replaces_the_full_code_set(self) -> None:
        """New codes replace the old atomically: the old plaintext
        stops verifying, the new plaintext works, and the unused count
        resets."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="gina@example.com")
            await login(client, "gina@example.com")
            _secret, old_codes = await enroll_via_routes(client, settings)

            r = await client.post(
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            new_codes = r.json()["recovery_codes"]
            assert len(new_codes) == settings.mfa_recovery_code_count
            assert set(new_codes).isdisjoint(set(old_codes))
            assert len(await recovery_code_rows(app, uid)) == len(new_codes)
            assert "user.mfa_recovery_codes_regenerated" in await audit_actions(app)

            # Old code: dead. New code: redeems.
            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": old_codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            assert r.json()["details"]["reason"] == "wrong_recovery_code"

            r = await client.post(
                "/api/v1/auth/mfa/verify",
                json={"code": new_codes[0]},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 200, r.text
            assert r.json()["used_recovery_code"] is True

    async def test_regenerate_without_enrollment_is_conflict(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            r = await client.post(
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 409
            assert r.json()["details"]["reason"] == "mfa_not_enrolled"


@pytest.mark.asyncio
class TestBruteForceHardening:
    """Regression pins for the audit findings the behavioral suite
    surfaced: /disable and /enroll-complete were unthrottled 6-digit
    brute-force surfaces whose failed attempts wrote no audit rows,
    and unicode digit forms 500'd the verify path instead of failing
    closed.
    """

    async def test_disable_wrong_code_audited_and_throttled(self) -> None:
        # Explicit production-default cap: this file's make_settings
        # raises the (now honored) configurable rate to 300 so that
        # multi-verify flow tests never trip; THIS test is about the
        # throttle itself, so pin the real default.
        settings = make_settings(mfa_verification_rate_per_min=10)
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            secret, _codes = await enroll_via_routes(client, settings)

            saw_401 = False
            saw_429 = False
            for _ in range(14):
                r = await client.post(
                    "/api/v1/auth/mfa/disable",
                    json={
                        "password": PASSWORD,
                        "code": wrong_totp_code(secret),
                    },
                    headers=csrf_header(client, settings),
                )
                if r.status_code == 401:
                    saw_401 = True
                if r.status_code == 429:
                    saw_429 = True
            # The shared mfa-verify bucket (10/min) must trip before an
            # attacker exhausts meaningful code space, and every failed
            # pre-throttle attempt must leave an HMAC-chained trail.
            assert saw_401 and saw_429
            actions = await audit_actions(app)
            assert "user.mfa_disabled" not in actions
            assert actions.count("user.mfa_disable_failed") >= 1
            reasons = {
                m.get("reason") for m in await audit_metadata_for(app, "user.mfa_disable_failed")
            }
            assert "wrong_totp" in reasons

    async def test_disable_wrong_password_audited(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            secret, _codes = await enroll_via_routes(client, settings)
            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={
                    "password": "not-the-password",
                    "code": current_totp_code(secret),
                },
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            reasons = {
                m.get("reason") for m in await audit_metadata_for(app, "user.mfa_disable_failed")
            }
            assert reasons == {"wrong_password"}

    async def test_enroll_complete_wrong_code_audited(self) -> None:
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            secret = decode_b32(start.json()["secret_base32"])
            r = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": wrong_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 401
            actions = await audit_actions(app)
            assert "user.mfa_enroll_failed" in actions

    async def test_unicode_digit_code_fails_closed_not_500(self) -> None:
        # str.isdigit() accepts fullwidth digits but compare_digest
        # rejects non-ASCII str; pre-fix this path raised TypeError and
        # the route returned HTTP 500. It must be an ordinary 401.
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert start.status_code == 200
            fullwidth = "".join(chr(0xFF11 + i) for i in range(6))
            r = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": fullwidth},
                headers=csrf_header(client, settings),
            )
            assert r.status_code in (401, 422)
            assert r.status_code != 500

    async def test_configured_verify_rate_is_honored(self) -> None:
        # Round-4 LOW: Z4J_MFA_VERIFICATION_RATE_PER_MIN was documented
        # as configurable but the throttle bucket was hardcoded to
        # 10/min, silently ignoring operator configuration. With the
        # cap set to 1, the second hit on any throttled MFA route must
        # be refused.
        settings = make_settings(mfa_verification_rate_per_min=1)
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            await login(client, "bob@example.com")
            first = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert first.status_code == 200
            second = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert second.status_code == 429
