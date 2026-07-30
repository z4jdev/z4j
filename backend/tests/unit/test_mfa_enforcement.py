"""MFA enrollment-enforcement policy tests (1.7 trust shell).

Covers the full policy matrix at the pure-domain level
(admin/non-admin x enforce_for_admins/enforce_for_all x
enrolled/unenrolled x within-grace/expired/zero-grace), plus the
endpoint wiring:

- login stamps ``users.mfa_enforcement_started_at`` exactly once and
  surfaces ``mfa_enrollment_required`` / ``mfa_enrollment_deadline``;
- within the grace window the product keeps working;
- past the deadline the session is RESTRICTED: only the enrollment
  allowlist (enroll-start / enroll-complete / mfa status / whoami /
  logout) answers, everything else is 403 ``mfa_enrollment_required``;
- completing enrollment lifts the restriction on the next request;
- ``grace_days == 0`` blocks from the first post-policy login;
- both flags at their defaults produce ZERO behavior change;
- audit rows ``auth.mfa_enforcement_grace_started`` /
  ``auth.mfa_enforcement_blocked`` are written by the login path;
- Bearer (API-key) resolution bypasses the gate by design.
"""

from __future__ import annotations

import base64
import secrets as _secrets
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain.mfa import encrypt_totp_secret, generate_totp_secret
from z4j_brain.domain.mfa.enforcement import (
    MFA_ENFORCEMENT_NOT_REQUIRED,
    evaluate_mfa_enforcement,
    mfa_enforcement_applies,
)
from z4j_brain.domain.mfa.totp import current_totp_code
from z4j_brain.errors import MfaEnrollmentRequiredError
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AuditLog, User
from z4j_brain.settings import Settings

PASSWORD = "correct horse battery staple 9"


# ---------------------------------------------------------------------------
# Helpers
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
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def make_user(
    *,
    is_admin: bool = False,
    enrolled: bool = False,
    pending_enrollment: bool = False,
    enforcement_started_at: datetime | None = None,
) -> User:
    """A transient (never-flushed) User for pure-domain evaluation.

    Column defaults only apply at flush, so every field the policy
    reads is set explicitly.
    """
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        password_hash="x",
        is_admin=is_admin,
        is_active=True,
    )
    user.mfa_secret_encrypted = b"blob" if (enrolled or pending_enrollment) else None
    user.mfa_enrolled_at = datetime.now(UTC) if enrolled else None
    user.mfa_enforcement_started_at = enforcement_started_at
    return user


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
    is_admin: bool = False,
    enrolled: bool = False,
    enforcement_started_at: datetime | None = None,
):
    """Insert a user; returns ``(user_id, totp_secret_or_None)``."""
    hasher = PasswordHasher(settings)
    async with app.state.db.session() as s:
        user = User(
            email=email,
            password_hash=hasher.hash(PASSWORD),
            is_admin=is_admin,
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
        if enforcement_started_at is not None:
            user.mfa_enforcement_started_at = enforcement_started_at
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


async def enforcement_started_at(app, user_id):  # type: ignore[no-untyped-def]
    async with app.state.db.session() as s:
        result = await s.execute(
            select(User.mfa_enforcement_started_at).where(User.id == user_id),
        )
        return result.scalar_one()


async def audit_actions(app) -> list[str]:  # type: ignore[no-untyped-def]
    async with app.state.db.session() as s:
        result = await s.execute(select(AuditLog.action))
        return list(result.scalars().all())


def gate_request(method: str = "GET", path: str = "/api/v1/projects"):  # type: ignore[no-untyped-def]
    """Minimal request stand-in for ``enforce_mfa_enrollment``."""
    return SimpleNamespace(
        scope={"route": SimpleNamespace(path=path)},
        method=method,
        url=SimpleNamespace(path=path),
        # get_current_user stashes the resolved user here (B17); a real
        # Starlette request.state is always assignable.
        state=SimpleNamespace(),
    )


# ---------------------------------------------------------------------------
# Pure-domain policy matrix
# ---------------------------------------------------------------------------


class TestPolicyTargeting:
    """Who does the policy apply to (before enrollment state)."""

    @pytest.mark.parametrize("is_admin", [True, False])
    def test_defaults_target_nobody(self, is_admin: bool) -> None:
        settings = make_settings()
        user = make_user(is_admin=is_admin)
        assert not mfa_enforcement_applies(user=user, settings=settings)

    def test_enforce_for_admins_targets_global_admins_only(self) -> None:
        settings = make_settings(mfa_enforce_for_admins=True)
        assert mfa_enforcement_applies(
            user=make_user(is_admin=True),
            settings=settings,
        )
        assert not mfa_enforcement_applies(
            user=make_user(is_admin=False),
            settings=settings,
        )

    @pytest.mark.parametrize("is_admin", [True, False])
    def test_enforce_for_all_targets_everyone(self, is_admin: bool) -> None:
        settings = make_settings(mfa_enforce_for_all=True)
        assert mfa_enforcement_applies(
            user=make_user(is_admin=is_admin),
            settings=settings,
        )


class TestEvaluateEnforcement:
    """Full evaluation matrix over enrollment x grace state."""

    NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("enforce_for_admins", "enforce_for_all", "is_admin"),
        [
            (False, False, True),
            (False, False, False),
            (True, False, False),
        ],
    )
    def test_untargeted_users_not_required(
        self,
        enforce_for_admins: bool,
        enforce_for_all: bool,
        is_admin: bool,
    ) -> None:
        settings = make_settings(
            mfa_enforce_for_admins=enforce_for_admins,
            mfa_enforce_for_all=enforce_for_all,
        )
        status = evaluate_mfa_enforcement(
            user=make_user(is_admin=is_admin),
            settings=settings,
            now=self.NOW,
        )
        assert status == MFA_ENFORCEMENT_NOT_REQUIRED

    @pytest.mark.parametrize(
        ("flag", "is_admin"),
        [
            ("mfa_enforce_for_admins", True),
            ("mfa_enforce_for_all", True),
            ("mfa_enforce_for_all", False),
        ],
    )
    def test_enrolled_targeted_user_not_required(
        self,
        flag: str,
        is_admin: bool,
    ) -> None:
        settings = make_settings(**{flag: True})
        status = evaluate_mfa_enforcement(
            user=make_user(is_admin=is_admin, enrolled=True),
            settings=settings,
            now=self.NOW,
        )
        assert status == MFA_ENFORCEMENT_NOT_REQUIRED

    def test_pending_enrollment_counts_as_unenrolled(self) -> None:
        """A stored secret without ``mfa_enrolled_at`` is a pending
        enrollment, not protection - the policy still demands
        completion."""
        settings = make_settings(mfa_enforce_for_all=True)
        status = evaluate_mfa_enforcement(
            user=make_user(pending_enrollment=True),
            settings=settings,
            now=self.NOW,
        )
        assert status.required is True

    def test_unstamped_anchor_is_required_but_not_blocked(self) -> None:
        """Policy applies but the user has not logged in under it yet:
        the grace clock has not started, so nothing is blocked."""
        settings = make_settings(mfa_enforce_for_all=True)
        status = evaluate_mfa_enforcement(
            user=make_user(),
            settings=settings,
            now=self.NOW,
        )
        assert status.required is True
        assert status.deadline is None
        assert status.blocked is False

    def test_within_grace_not_blocked(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
        )
        started = self.NOW - timedelta(days=3)
        status = evaluate_mfa_enforcement(
            user=make_user(enforcement_started_at=started),
            settings=settings,
            now=self.NOW,
        )
        assert status.required is True
        assert status.deadline == started + timedelta(days=7)
        assert status.blocked is False

    def test_expired_grace_is_blocked(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
        )
        started = self.NOW - timedelta(days=8)
        status = evaluate_mfa_enforcement(
            user=make_user(enforcement_started_at=started),
            settings=settings,
            now=self.NOW,
        )
        assert status.blocked is True
        assert status.deadline == started + timedelta(days=7)

    def test_zero_grace_blocks_at_the_anchor(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=0,
        )
        status = evaluate_mfa_enforcement(
            user=make_user(enforcement_started_at=self.NOW),
            settings=settings,
            now=self.NOW,
        )
        assert status.deadline == self.NOW
        assert status.blocked is True

    def test_naive_sqlite_anchor_is_treated_as_utc(self) -> None:
        """SQLite round-trips TIMESTAMPTZ as naive datetimes; the
        evaluation must not raise or mis-compare."""
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
        )
        naive_started = (self.NOW - timedelta(days=8)).replace(tzinfo=None)
        status = evaluate_mfa_enforcement(
            user=make_user(enforcement_started_at=naive_started),
            settings=settings,
            now=self.NOW,
        )
        assert status.blocked is True


class TestEnrollmentGateUnit:
    """``enforce_mfa_enrollment`` allowlist + bearer-exemption units."""

    def _blocked_user(self) -> User:
        return make_user(
            enforcement_started_at=datetime.now(UTC) - timedelta(days=30),
        )

    def test_blocked_user_on_product_route_raises(self) -> None:
        from z4j_brain.api.deps import enforce_mfa_enrollment

        settings = make_settings(mfa_enforce_for_all=True)
        with pytest.raises(MfaEnrollmentRequiredError) as exc_info:
            enforce_mfa_enrollment(
                request=gate_request("GET", "/api/v1/projects"),
                user=self._blocked_user(),
                settings=settings,
            )
        assert exc_info.value.code == "mfa_enrollment_required"
        assert exc_info.value.details["deadline"] is not None

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/v1/auth/me"),
            ("POST", "/api/v1/auth/logout"),
            ("GET", "/api/v1/auth/mfa/status"),
            ("POST", "/api/v1/auth/mfa/enroll-start"),
            ("POST", "/api/v1/auth/mfa/enroll-complete"),
        ],
    )
    def test_enrollment_allowlist_passes(self, method: str, path: str) -> None:
        from z4j_brain.api.deps import enforce_mfa_enrollment

        settings = make_settings(mfa_enforce_for_all=True)
        enforce_mfa_enrollment(
            request=gate_request(method, path),
            user=self._blocked_user(),
            settings=settings,
        )

    def test_exemption_is_method_scoped(self) -> None:
        """``GET /auth/me`` (whoami) passes; ``PATCH /auth/me``
        (profile write) shares the path template but is NOT exempt."""
        from z4j_brain.api.deps import enforce_mfa_enrollment

        settings = make_settings(mfa_enforce_for_all=True)
        with pytest.raises(MfaEnrollmentRequiredError):
            enforce_mfa_enrollment(
                request=gate_request("PATCH", "/api/v1/auth/me"),
                user=self._blocked_user(),
                settings=settings,
            )

    def test_unblocked_user_passes_everywhere(self) -> None:
        from z4j_brain.api.deps import enforce_mfa_enrollment

        settings = make_settings(mfa_enforce_for_all=True)
        enforce_mfa_enrollment(
            request=gate_request("GET", "/api/v1/projects"),
            # Grace clock not started -> not blocked.
            user=make_user(),
            settings=settings,
        )

    async def test_bearer_only_requests_skip_the_gate(self) -> None:
        """``get_current_user`` with no cookie session returns the
        bearer user WITHOUT evaluating enforcement - programmatic
        accounts are exempt by design (docs/MFA-DESIGN.md, open
        question 5)."""
        from z4j_brain.api.deps import get_current_user

        settings = make_settings(mfa_enforce_for_all=True)
        blocked = self._blocked_user()
        result = await get_current_user(
            request=gate_request("GET", "/api/v1/projects"),  # type: ignore[arg-type]
            resolved=None,
            api_key_user=blocked,
            settings=settings,
        )
        assert result is blocked


# ---------------------------------------------------------------------------
# Endpoint wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLoginPolicyDecision:
    async def test_defaults_off_zero_behavior_change(self) -> None:
        """Both flags at their defaults: no new response signal, no
        stamp, no enforcement audit rows, full product access."""
        settings = make_settings()
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(
                app,
                settings,
                email="admin@example.com",
                is_admin=True,
            )
            body = await login(client, "admin@example.com")
            assert body["mfa_enrollment_required"] is False
            assert body["mfa_enrollment_deadline"] is None
            assert await enforcement_started_at(app, uid) is None
            actions = await audit_actions(app)
            assert "auth.mfa_enforcement_grace_started" not in actions
            assert "auth.mfa_enforcement_blocked" not in actions
            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 200

    async def test_enforce_admins_stamps_admin_and_spares_others(self) -> None:
        settings = make_settings(mfa_enforce_for_admins=True)
        async with make_brain(settings) as (app, client):
            admin_id, _ = await seed_user(
                app,
                settings,
                email="admin@example.com",
                is_admin=True,
            )
            user_id, _ = await seed_user(
                app,
                settings,
                email="bob@example.com",
                is_admin=False,
            )

            body = await login(client, "admin@example.com")
            assert body["mfa_enrollment_required"] is True
            assert body["mfa_enrollment_deadline"] is not None
            stamped = await enforcement_started_at(app, admin_id)
            assert stamped is not None
            # Grace window still open -> the product keeps working.
            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 200

            # Fresh client so the admin's cookies don't leak over.
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as other:
                body = await login(other, "bob@example.com")
                assert body["mfa_enrollment_required"] is False
                assert body["mfa_enrollment_deadline"] is None
            assert await enforcement_started_at(app, user_id) is None

            actions = await audit_actions(app)
            assert actions.count("auth.mfa_enforcement_grace_started") == 1

    async def test_enforce_all_targets_non_admins(self) -> None:
        settings = make_settings(mfa_enforce_for_all=True)
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(
                app,
                settings,
                email="bob@example.com",
                is_admin=False,
            )
            body = await login(client, "bob@example.com")
            assert body["mfa_enrollment_required"] is True
            assert await enforcement_started_at(app, uid) is not None

    async def test_enrolled_user_is_unaffected(self) -> None:
        """Enforcement targets the account but MFA is already on:
        nothing changes (no stamp, no new response signal)."""
        settings = make_settings(mfa_enforce_for_all=True)
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(
                app,
                settings,
                email="carol@example.com",
                enrolled=True,
            )
            body = await login(client, "carol@example.com")
            # Ordinary step-up applies (no trust cookie presented)...
            assert body["mfa_required"] is True
            # ...but the enrollment policy has nothing to demand.
            assert body["mfa_enrollment_required"] is False
            assert body["mfa_enrollment_deadline"] is None
            assert await enforcement_started_at(app, uid) is None
            actions = await audit_actions(app)
            assert "auth.mfa_enforcement_grace_started" not in actions
            assert "auth.mfa_enforcement_blocked" not in actions

    async def test_grace_deadline_matches_grace_days(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=14,
        )
        async with make_brain(settings) as (app, client):
            _uid, _ = await seed_user(app, settings, email="bob@example.com")
            before = datetime.now(UTC)
            body = await login(client, "bob@example.com")
            after = datetime.now(UTC)
            deadline = datetime.fromisoformat(body["mfa_enrollment_deadline"])
            assert before + timedelta(days=14) <= deadline <= after + timedelta(days=14)

    async def test_stamp_once_across_logins(self) -> None:
        """The grace anchor is stamped by the FIRST login observing
        the policy and never moves; the audit row is written once."""
        settings = make_settings(mfa_enforce_for_all=True)
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="bob@example.com")
            first = await login(client, "bob@example.com")
            assert first["mfa_enrollment_required"] is True
            stamped_first = await enforcement_started_at(app, uid)
            assert stamped_first is not None

            second = await login(client, "bob@example.com")
            stamped_second = await enforcement_started_at(app, uid)
            assert stamped_second == stamped_first
            # Deadline reported on the second login derives from the
            # ORIGINAL anchor, not a fresh one.
            assert first["mfa_enrollment_deadline"] == second["mfa_enrollment_deadline"]

            actions = await audit_actions(app)
            assert actions.count("auth.mfa_enforcement_grace_started") == 1


@pytest.mark.asyncio
class TestRestrictedSession:
    @asynccontextmanager
    async def _blocked_brain(self, **settings_overrides):  # type: ignore[no-untyped-def]
        """A brain + logged-in client whose user is past the grace
        deadline (anchor seeded 30 days back, grace 7)."""
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
            **settings_overrides,
        )
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(
                app,
                settings,
                email="late@example.com",
                enforcement_started_at=datetime.now(UTC) - timedelta(days=30),
            )
            body = await login(client, "late@example.com")
            assert body["mfa_enrollment_required"] is True
            deadline = datetime.fromisoformat(body["mfa_enrollment_deadline"])
            assert deadline < datetime.now(UTC)
            yield app, client, settings, uid

    async def test_product_routes_are_403_with_stable_code(self) -> None:
        async with self._blocked_brain() as (app, client, settings, _uid):
            for method, path in (
                ("GET", "/api/v1/auth/sessions"),
                ("GET", "/api/v1/projects"),
                ("GET", "/api/v1/auth/mfa/trusted-devices"),
            ):
                r = await client.request(method, path)
                assert r.status_code == 403, (method, path, r.text)
                body = r.json()
                assert body["error"] == "mfa_enrollment_required"
                assert body["details"]["deadline"] is not None

            # Same path template as exempt GET /auth/me, but a write:
            # still blocked (method-scoped allowlist).
            r = await client.patch(
                "/api/v1/auth/me",
                json={"display_name": "Blocked"},
                headers=csrf_header(client, settings),
            )
            assert r.status_code == 403
            assert r.json()["error"] == "mfa_enrollment_required"

            # Blocked logins leave an audit trail.
            actions = await audit_actions(app)
            assert "auth.mfa_enforcement_blocked" in actions

    async def test_enrollment_surface_stays_reachable(self) -> None:
        async with self._blocked_brain() as (_app, client, settings, _uid):
            me = await client.get("/api/v1/auth/me")
            assert me.status_code == 200

            status = await client.get("/api/v1/auth/mfa/status")
            assert status.status_code == 200
            status_body = status.json()
            assert status_body["enrolled"] is False
            assert status_body["enrollment_required"] is True
            assert datetime.fromisoformat(status_body["enrollment_deadline"]) < datetime.now(UTC)

            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert start.status_code == 200, start.text

            logout = await client.post(
                "/api/v1/auth/logout",
                headers=csrf_header(client, settings),
            )
            assert logout.status_code == 204

    async def test_completing_enrollment_lifts_the_block(self) -> None:
        async with self._blocked_brain() as (app, client, settings, uid):
            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert start.status_code == 200, start.text
            secret_b32 = start.json()["secret_base32"]
            secret = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))

            complete = await client.post(
                "/api/v1/auth/mfa/enroll-complete",
                json={"code": current_totp_code(secret)},
                headers=csrf_header(client, settings),
            )
            assert complete.status_code == 200, complete.text
            assert complete.json()["recovery_codes"]

            # The very next request passes the gate - enforcement has
            # nothing left to demand from an enrolled user.
            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 200
            r = await client.get("/api/v1/projects")
            assert r.status_code == 200

            # The one-way anchor survives enrollment (forensic fact;
            # also means disabling MFA later cannot re-open a fresh
            # grace window).
            assert await enforcement_started_at(app, uid) is not None

    async def test_zero_grace_blocks_from_first_login(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=0,
        )
        async with make_brain(settings) as (app, client):
            _uid, _ = await seed_user(app, settings, email="new@example.com")
            body = await login(client, "new@example.com")
            assert body["mfa_enrollment_required"] is True
            deadline = datetime.fromisoformat(body["mfa_enrollment_deadline"])
            assert deadline <= datetime.now(UTC)

            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 403
            assert r.json()["error"] == "mfa_enrollment_required"

            # Enrollment must still be possible - that is the whole
            # point of restricting instead of refusing login.
            start = await client.post(
                "/api/v1/auth/mfa/enroll-start",
                headers=csrf_header(client, settings),
            )
            assert start.status_code == 200

            # First login under zero grace stamps AND blocks: both
            # audit rows in one login.
            actions = await audit_actions(app)
            assert actions.count("auth.mfa_enforcement_grace_started") == 1
            assert "auth.mfa_enforcement_blocked" in actions

    async def test_gate_engages_mid_session_when_deadline_passes(self) -> None:
        """The gate re-evaluates per request: a session opened within
        the grace window loses product access once the deadline is in
        the past - keeping a session alive cannot dodge the policy."""
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
        )
        async with make_brain(settings) as (app, client):
            uid, _ = await seed_user(app, settings, email="bob@example.com")
            body = await login(client, "bob@example.com")
            assert body["mfa_enrollment_required"] is True
            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 200

            # Simulate the deadline passing while the session lives.
            async with app.state.db.session() as s:
                await s.execute(
                    update(User)
                    .where(User.id == uid)
                    .values(
                        mfa_enforcement_started_at=datetime.now(UTC) - timedelta(days=30),
                    ),
                )
                await s.commit()

            r = await client.get("/api/v1/auth/sessions")
            assert r.status_code == 403
            assert r.json()["error"] == "mfa_enrollment_required"
            # Enrollment allowlist still answers.
            r = await client.get("/api/v1/auth/mfa/status")
            assert r.status_code == 200


@pytest.mark.asyncio
class TestGraceWindowSignalOnly:
    async def test_within_grace_full_access_with_deadline_surfaced(self) -> None:
        settings = make_settings(
            mfa_enforce_for_all=True,
            mfa_enrollment_grace_days=7,
        )
        async with make_brain(settings) as (app, client):
            await seed_user(app, settings, email="bob@example.com")
            body = await login(client, "bob@example.com")
            assert body["mfa_enrollment_required"] is True
            deadline = datetime.fromisoformat(body["mfa_enrollment_deadline"])
            assert deadline > datetime.now(UTC)

            # Product surface fully available inside the window.
            for method, path in (
                ("GET", "/api/v1/auth/sessions"),
                ("GET", "/api/v1/projects"),
                ("GET", "/api/v1/auth/me"),
            ):
                r = await client.request(method, path)
                assert r.status_code == 200, (method, path, r.text)

            # Status endpoint mirrors the signal for the banner.
            status = await client.get("/api/v1/auth/mfa/status")
            assert status.status_code == 200
            status_body = status.json()
            assert status_body["enrollment_required"] is True
            assert datetime.fromisoformat(status_body["enrollment_deadline"]) == deadline

            # No blocked row while the window is open.
            actions = await audit_actions(app)
            assert "auth.mfa_enforcement_blocked" not in actions
            assert actions.count("auth.mfa_enforcement_grace_started") == 1
