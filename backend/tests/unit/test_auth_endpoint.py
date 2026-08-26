"""End-to-end tests for /api/v1/auth/{login,logout,me}.

These exercise the full middleware + dep + service stack against an
in-memory SQLite database. The slow path is the argon2 verify on
login - we use the smaller test cost from the conftest fixture.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Session, User
from z4j_brain.settings import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        # Use SQLite's real multi-connection arbitration. StaticPool-backed
        # in-memory SQLite lets concurrent AsyncSessions drive one physical
        # connection at once, which produces transaction interference instead
        # of testing the password-reset token CAS.
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        # Cheap argon2 for tests.
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        # Cheap login min duration so the suite is fast.
        login_min_duration_ms=10,
        login_lockout_threshold=4,
        login_backoff_base_seconds=0.0,
        login_backoff_max_seconds=0.0,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    """Build the brain on the same file-backed SQLite shape users run."""
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded_user(settings: Settings, brain_app):
    """Insert one active user with a known password."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    async with db.session() as s:
        user = User(
            email="alice@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            display_name="Alice",
            is_admin=False,
            is_active=True,
        )
        s.add(user)
        await s.commit()
        return user


@pytest.fixture
async def client(brain_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
class TestLoginHappy:
    async def test_login_sets_session_cookie(
        self,
        client,
        settings: Settings,
        seeded_user,
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["user"]["email"] == "alice@example.com"
        assert body["user"]["is_admin"] is False
        # Sensitive fields must NOT be in the response.
        assert "password_hash" not in body["user"]
        assert "failed_login_count" not in body["user"]
        # Cookie set.
        assert cookie_name(environment=settings.environment) in [
            c.split("=", 1)[0] for c in response.headers.get_list("set-cookie")
        ]


@pytest.mark.asyncio
class TestLoginFailureShape:
    """Wrong password and unknown email return byte-identical envelopes."""

    async def test_wrong_password(self, client, seeded_user) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "WRONG"},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "unauthenticated"
        assert body["message"] == "invalid_credentials"

    async def test_unknown_email(self, client, seeded_user) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "WRONG"},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "unauthenticated"
        assert body["message"] == "invalid_credentials"

    async def test_failure_responses_byte_identical_modulo_request_id(
        self,
        client,
        seeded_user,
    ) -> None:
        r1 = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "WRONG"},
        )
        r2 = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "WRONG"},
        )
        assert r1.status_code == r2.status_code == 401
        b1 = r1.json()
        b2 = r2.json()
        b1["request_id"] = "X"
        b2["request_id"] = "X"
        assert b1 == b2


@pytest.mark.asyncio
class TestPasswordResetRequest:
    async def test_unknown_email_uses_timing_floor(
        self,
        client,
        settings: Settings,
        monkeypatch,
    ) -> None:
        from z4j_brain.api import auth as auth_api

        calls: list[int] = []

        async def fake_hold(start: float, min_duration_ms: int) -> None:
            assert start > 0
            calls.append(min_duration_ms)

        monkeypatch.setattr(
            auth_api,
            "_hold_minimum_response_time",
            fake_hold,
        )

        response = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "nobody@example.com"},
        )

        assert response.status_code == 200
        assert response.json() == {"accepted": True}
        assert calls == [settings.login_min_duration_ms]

    async def test_known_email_uses_same_timing_floor(
        self,
        client,
        settings: Settings,
        seeded_user,
        monkeypatch,
    ) -> None:
        from z4j_brain.api import auth as auth_api

        calls: list[int] = []

        async def fake_hold(start: float, min_duration_ms: int) -> None:
            assert start > 0
            calls.append(min_duration_ms)

        monkeypatch.setattr(
            auth_api,
            "_hold_minimum_response_time",
            fake_hold,
        )

        response = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )

        assert response.status_code == 200
        assert response.json() == {"accepted": True}
        assert calls == [settings.login_min_duration_ms]


@pytest.mark.asyncio
class TestPasswordResetConfirmR5M2:
    """1.6.5 round-5 audit regression.

    The confirm path must atomically claim the reset token so that
    two concurrent POST /password-reset/confirm requests with the
    same valid token cannot both succeed. Pre-1.6.5 the handler
    did SELECT, checked ``consumed_at`` in memory, updated the
    password, then assigned ``row.consumed_at = now`` -- a
    classic check-then-set race. The fix uses
    ``UPDATE ... WHERE consumed_at IS NULL ... RETURNING`` so the
    database arbitrates the single-use claim.
    """

    async def _mint_token_directly(
        self,
        brain_app,
        settings: Settings,
        user_id,
        plaintext: str,
    ) -> None:
        """Insert a fresh, unconsumed, unexpired reset token row.

        Bypasses the /password-reset/request flow so the test is
        focused on the consume race, not the mint flow.
        """
        from datetime import UTC, datetime, timedelta

        from z4j_brain.api.auth import _hash_reset_token
        from z4j_brain.persistence.models import PasswordResetToken

        db = brain_app.state.db
        async with db.session() as s:
            s.add(
                PasswordResetToken(
                    user_id=user_id,
                    token_hash=_hash_reset_token(plaintext, settings),
                    expires_at=datetime.now(UTC) + timedelta(minutes=30),
                ),
            )
            await s.commit()

    async def test_replay_after_consume_returns_404(
        self,
        client,
        settings: Settings,
        brain_app,
        seeded_user,
    ) -> None:
        """Sequential single-use invariant: consume once, replay 404."""
        plaintext = "test-token-r5m2-sequential-0123456789abcdef"
        await self._mint_token_directly(
            brain_app,
            settings,
            seeded_user.id,
            plaintext,
        )

        r1 = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": plaintext, "new_password": "new-pw-9chars-long-1!"},
        )
        assert r1.status_code == 200, r1.text
        assert r1.json() == {"success": True}

        r2 = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": plaintext, "new_password": "second-attempt-pw-1!A"},
        )
        assert r2.status_code == 404
        assert r2.json()["message"] == "invalid_or_expired"

    async def test_concurrent_confirm_exactly_one_succeeds(
        self,
        client,
        settings: Settings,
        brain_app,
        seeded_user,
    ) -> None:
        """N concurrent confirms with the same token: exactly one
        wins, the rest get 404. The database UPDATE is the
        arbitrator, not in-memory state.
        """
        import asyncio

        plaintext = "test-token-r5m2-concurrent-0123456789abcdef"
        await self._mint_token_directly(
            brain_app,
            settings,
            seeded_user.id,
            plaintext,
        )

        # Each attempt uses a distinct password so the user-visible
        # password-of-record reveals WHICH request won. If pre-fix
        # last-writer-wins were still present, multiple POSTs would
        # all return 200 and the password would be the last writer's.
        attempts = [
            ("test-pw-winner-A-9chars-1!"),
            ("test-pw-winner-B-9chars-1!"),
            ("test-pw-winner-C-9chars-1!"),
            ("test-pw-winner-D-9chars-1!"),
            ("test-pw-winner-E-9chars-1!"),
        ]

        async def confirm(pw: str):
            return await client.post(
                "/api/v1/auth/password-reset/confirm",
                json={"token": plaintext, "new_password": pw},
            )

        results = await asyncio.gather(
            *(confirm(pw) for pw in attempts),
            return_exceptions=False,
        )

        success_count = sum(1 for r in results if r.status_code == 200)
        failure_count = sum(1 for r in results if r.status_code == 404)
        assert success_count == 1, (
            f": expected exactly 1 successful confirm, got "
            f"{success_count}. Statuses: {[r.status_code for r in results]}"
        )
        assert failure_count == len(attempts) - 1, (
            f": expected {len(attempts) - 1} 404 confirms, got "
            f"{failure_count}. Statuses: {[r.status_code for r in results]}"
        )

        # Every failure body must match a fresh /invalid_or_expired
        # response shape, NOT leak which attempt won or the token state.
        for r in results:
            if r.status_code == 404:
                assert r.json()["message"] == "invalid_or_expired"

    async def test_expired_token_rejected(
        self,
        client,
        settings: Settings,
        brain_app,
        seeded_user,
    ) -> None:
        """An already-expired token is rejected by the atomic
        WHERE clause even before the consumed_at check fires.
        """
        from datetime import UTC, datetime, timedelta

        from z4j_brain.api.auth import _hash_reset_token
        from z4j_brain.persistence.models import PasswordResetToken

        plaintext = "test-token-r5m2-expired-0123456789abcdef"
        db = brain_app.state.db
        async with db.session() as s:
            s.add(
                PasswordResetToken(
                    user_id=seeded_user.id,
                    token_hash=_hash_reset_token(plaintext, settings),
                    expires_at=datetime.now(UTC) - timedelta(minutes=1),
                ),
            )
            await s.commit()

        r = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": plaintext, "new_password": "expired-token-pw-1!A"},
        )
        assert r.status_code == 404
        assert r.json()["message"] == "invalid_or_expired"


@pytest.mark.asyncio
class TestPasswordResetFailedAudit:
    """1.7 audit: a FAILED password-reset confirm must leave a
    durable ``auth.password_reset_failed`` audit row.

    Pre-fix the invalid / expired / replayed-token path raised before
    any ``AuditService.record``, so brute-force + replay attempts
    against the reset endpoint were invisible in the chained log. The
    response body stays the generic ``invalid_or_expired`` so token
    existence is not leaked.
    """

    async def _failed_reset_rows(self, brain_app):  # type: ignore[no-untyped-def]
        from sqlalchemy import select
        from z4j_brain.persistence.models import AuditLog

        db = brain_app.state.db
        async with db.session() as s:
            return (
                (
                    await s.execute(
                        select(AuditLog).where(
                            AuditLog.action == "auth.password_reset_failed",
                        ),
                    )
                )
                .scalars()
                .all()
            )

    async def test_invalid_token_writes_failure_audit_row(
        self,
        client,
        brain_app,
    ) -> None:
        r = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={
                "token": "totally-invalid-token-abcdef0123456789",
                "new_password": "brand-new-pw-1!Aa",
            },
        )
        assert r.status_code == 404
        assert r.json()["message"] == "invalid_or_expired"

        rows = await self._failed_reset_rows(brain_app)
        assert len(rows) == 1
        assert rows[0].result == "failure"
        assert rows[0].outcome == "deny"
        assert rows[0].audit_metadata.get("reason") == "invalid_or_expired_token"

    async def test_successful_reset_writes_no_failure_row(
        self,
        client,
        settings: Settings,
        brain_app,
        seeded_user,
    ) -> None:
        """The happy path records ``auth.password_reset_completed`` only;
        no spurious failure row is emitted.
        """
        from datetime import UTC, datetime, timedelta

        from z4j_brain.api.auth import _hash_reset_token
        from z4j_brain.persistence.models import PasswordResetToken

        plaintext = "valid-reset-token-abcdef0123456789xyz"
        db = brain_app.state.db
        async with db.session() as s:
            s.add(
                PasswordResetToken(
                    user_id=seeded_user.id,
                    token_hash=_hash_reset_token(plaintext, settings),
                    expires_at=datetime.now(UTC) + timedelta(minutes=30),
                ),
            )
            await s.commit()

        r = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": plaintext, "new_password": "brand-new-pw-1!Aa"},
        )
        assert r.status_code == 200, r.text
        assert await self._failed_reset_rows(brain_app) == []


@pytest.mark.asyncio
class TestLockout:
    async def test_lockout_triggers_after_threshold(
        self,
        client,
        settings: Settings,
        seeded_user,
    ) -> None:
        # threshold is 4 in the fixture; 4 wrong attempts → locked.
        for _ in range(settings.login_lockout_threshold):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": "alice@example.com", "password": "WRONG"},
            )
            assert r.status_code == 401
        # 5th attempt with the CORRECT password is also rejected
        # because the account is locked.
        r = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert r.status_code == 401
        # Same envelope as wrong-password - the lockout state
        # never leaks to the response.
        assert r.json()["error"] == "unauthenticated"
        assert r.json()["message"] == "invalid_credentials"


@pytest.mark.asyncio
class TestMe:
    async def test_me_unauthenticated_is_401(self, client) -> None:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_me_after_login(self, client, seeded_user) -> None:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        body = me.json()
        # Field whitelist enforced. ``memberships`` was added in
        # B5 so the dashboard's project switcher can render roles.
        assert set(body.keys()) == {
            "id",
            "email",
            "display_name",
            "first_name",
            "last_name",
            "is_admin",
            "timezone",
            "created_at",
            "memberships",
        }
        assert isinstance(body["memberships"], list)


@pytest.mark.asyncio
class TestLogout:
    async def test_logout_revokes_session(
        self,
        client,
        settings: Settings,
        seeded_user,
    ) -> None:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200
        # Pull the CSRF cookie value out of the login response.
        from z4j_brain.auth.csrf import csrf_cookie_name

        csrf_name = csrf_cookie_name(environment=settings.environment)
        csrf_value = client.cookies.get(csrf_name)
        assert csrf_value is not None
        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": csrf_value},
        )
        assert logout.status_code == 204
        # /me now fails - session was revoked.
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 401

    async def test_logout_without_csrf_is_403(
        self,
        client,
        seeded_user,
    ) -> None:
        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        logout = await client.post("/api/v1/auth/logout")
        assert logout.status_code == 403


@pytest.mark.asyncio
class TestSessionRevocation:
    async def test_revoke_others_is_not_limited_by_session_listing(
        self,
        client,
        settings: Settings,
        seeded_user,
        brain_app,
    ) -> None:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert login.status_code == 200

        expires_at = datetime.now(UTC) + timedelta(days=1)
        async with brain_app.state.db.session() as db_session:
            current = (
                await db_session.execute(
                    select(Session).where(Session.user_id == seeded_user.id),
                )
            ).scalar_one()
            other_user = User(
                email="bob@example.com",
                password_hash=seeded_user.password_hash,
                display_name="Bob",
                is_admin=False,
                is_active=True,
            )
            db_session.add(other_user)
            await db_session.flush()
            db_session.add_all(
                [
                    Session(
                        user_id=seeded_user.id,
                        csrf_token=f"extra-{index}",
                        expires_at=expires_at,
                        ip_at_issue="127.0.0.1",
                        user_agent_at_issue="old-browser",
                    )
                    for index in range(101)
                ]
                + [
                    Session(
                        user_id=other_user.id,
                        csrf_token="other-user-session",
                        expires_at=expires_at,
                        ip_at_issue="127.0.0.2",
                        user_agent_at_issue="other-browser",
                    ),
                ],
            )
            await db_session.commit()
            current_id = current.id
            other_user_id = other_user.id

        from z4j_brain.auth.csrf import csrf_cookie_name

        csrf_value = client.cookies.get(
            csrf_cookie_name(environment=settings.environment),
        )
        assert csrf_value is not None
        response = await client.post(
            "/api/v1/auth/sessions/revoke-others",
            headers={"X-CSRF-Token": csrf_value},
        )
        assert response.status_code == 200, response.text

        async with brain_app.state.db.session() as db_session:
            own_rows = list(
                (
                    await db_session.execute(
                        select(Session).where(Session.user_id == seeded_user.id),
                    )
                ).scalars(),
            )
            other_rows = list(
                (
                    await db_session.execute(
                        select(Session).where(Session.user_id == other_user_id),
                    )
                ).scalars(),
            )

        assert len(own_rows) == 102
        live_own = [row for row in own_rows if row.revoked_at is None]
        assert [row.id for row in live_own] == [current_id]
        assert all(
            row.revocation_reason == "user_revoke_others"
            for row in own_rows
            if row.id != current_id
        )
        # Negative control: the unbounded UPDATE is still scoped by user.
        assert len(other_rows) == 1
        assert other_rows[0].revoked_at is None
