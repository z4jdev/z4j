"""Endpoint tests for the automation-rules API (Cluster R3).

Exercises the full HTTP path -- CRUD, grammar validation, RBAC role
differentiation, and the destructive-action fresh-MFA step-up -- against
the real ``create_app`` on in-memory SQLite, mirroring
``test_b5_endpoints``'s seeded-session pattern.
"""

from __future__ import annotations

import contextlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import CSRF_HEADER_NAME
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    ApiKey,
    AuditLog,
    AutomationRule,
    Membership,
    Project,
    Session,
    User,
)
from z4j_brain.settings import Settings

_PW = "correct horse battery staple 9"
_BASE = "/api/v1/projects/default/automation/rules"
_SETTINGS = "/api/v1/projects/default/automation/settings"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


async def _seed_actor(
    brain_app,
    settings,
    *,
    is_admin: bool = False,
    role: ProjectRole | None = None,
    mfa: bool = False,
    mfa_fresh: bool = True,
    slug: str = "default",
) -> dict:
    """Insert a project (get-or-create) + user (+ optional membership) +
    session, and return the handles a client needs to act as that user."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        proj = (await s.execute(select(Project).where(Project.slug == slug))).scalar_one_or_none()
        if proj is None:
            proj = Project(id=uuid.uuid4(), slug=slug, name=slug)
            s.add(proj)
            await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_admin=is_admin,
            is_active=True,
        )
        if mfa:
            user.mfa_secret_encrypted = b"secret-bytes"
            user.mfa_enrolled_at = datetime.now(UTC)
        s.add(user)
        await s.flush()
        if role is not None:
            s.add(
                Membership(user_id=user.id, project_id=proj.id, role=role),
            )
        session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
            mfa_verified_at=datetime.now(UTC) if (mfa and mfa_fresh) else None,
        )
        s.add(session_row)
        await s.commit()
    return {
        "session_id": session_row.id,
        "csrf": csrf,
        "project_id": proj.id,
        "slug": slug,
        "user_id": user.id,
    }


async def _seed_api_key(
    brain_app,
    settings,
    *,
    is_admin: bool = False,
    role: ProjectRole | None = None,
    scopes: list[str],
    slug: str = "default",
) -> tuple[str, uuid.UUID]:
    """Seed a project + user (+ optional membership) + a project-bound
    API key with ``scopes``. Returns (plaintext_token, key_id)."""
    from z4j_brain.api.api_keys import _hash_api_key

    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    token = "z4k_" + secrets.token_urlsafe(32)
    secret = settings.secret.get_secret_value().encode("utf-8")
    async with db.session() as s:
        proj = (await s.execute(select(Project).where(Project.slug == slug))).scalar_one_or_none()
        if proj is None:
            proj = Project(id=uuid.uuid4(), slug=slug, name=slug)
            s.add(proj)
            await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@x.io",
            password_hash=hasher.hash(_PW),
            is_admin=is_admin,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        if role is not None:
            s.add(
                Membership(user_id=user.id, project_id=proj.id, role=role),
            )
        key = ApiKey(
            id=uuid.uuid4(),
            user_id=user.id,
            name="test-key",
            token_hash=_hash_api_key(plaintext=token, secret=secret),
            prefix=token[:8],
            scopes=list(scopes),
            project_id=proj.id,
        )
        s.add(key)
        await s.commit()
        return token, key.id


@contextlib.asynccontextmanager
async def _bearer_client(brain_app, token: str):
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@contextlib.asynccontextmanager
async def _client(brain_app, settings, ctx):
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(ctx["session_id"]),
        )
        yield ac


def _hdr(ctx) -> dict:
    return {CSRF_HEADER_NAME: ctx["csrf"]}


@pytest.mark.asyncio
class TestCrud:
    async def test_create_notify_then_get_list_audit(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "alert-fails",
                    "trigger": "task.failed",
                    "conditions": {"queue": "critical"},
                    "actions": [{"type": "notify"}],
                },
            )
            assert r.status_code == 201, r.text
            rule = r.json()
            assert rule["dry_run"] is True  # new rules default to dry-run
            assert rule["is_enabled"] is True
            rid = rule["id"]

            g = await ac.get(f"{_BASE}/{rid}")
            assert g.status_code == 200
            assert g.json()["name"] == "alert-fails"

            lst = await ac.get(_BASE)
            assert lst.status_code == 200
            assert [x["id"] for x in lst.json()["items"]] == [rid]

        db = brain_app.state.db
        async with db.session() as s:
            rows = (
                (
                    await s.execute(
                        select(AuditLog).where(
                            AuditLog.action == "automation.rule.created",
                        ),
                    )
                )
                .scalars()
                .all()
            )
        assert len(rows) == 1

    async def test_create_destructive_as_global_admin(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "auto-retry",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                    "dry_run": False,
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["dry_run"] is False

    async def test_update_toggle_and_delete(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "r1",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
            rid = r.json()["id"]
            p = await ac.patch(
                f"{_BASE}/{rid}",
                headers=_hdr(ctx),
                json={"is_enabled": False, "dry_run": False},
            )
            assert p.status_code == 200, p.text
            assert p.json()["is_enabled"] is False
            assert p.json()["dry_run"] is False

            d = await ac.delete(f"{_BASE}/{rid}", headers=_hdr(ctx))
            assert d.status_code == 204
            g = await ac.get(f"{_BASE}/{rid}")
            assert g.status_code == 404

    async def test_reset_circuit(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        db = brain_app.state.db
        async with db.session() as s:
            rule = AutomationRule(
                project_id=ctx["project_id"],
                name="tripped",
                trigger="task.failed",
                actions=[{"type": "notify"}],
                cb_tripped=True,
                cb_execution_count=999,
            )
            s.add(rule)
            await s.commit()
            rid = str(rule.id)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(f"{_BASE}/{rid}/reset-circuit", headers=_hdr(ctx))
            assert r.status_code == 200, r.text
            assert r.json()["cb_tripped"] is False
            assert r.json()["cb_execution_count"] == 0


@pytest.mark.asyncio
class TestValidation:
    async def _post(self, ac, ctx, **body):
        return await ac.post(_BASE, headers=_hdr(ctx), json=body)

    async def test_unknown_trigger_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await self._post(
                ac,
                ctx,
                name="x",
                trigger="task.exploded",
                actions=[{"type": "notify"}],
            )
        assert r.status_code == 422, r.text

    async def test_bad_condition_key_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await self._post(
                ac,
                ctx,
                name="x",
                trigger="task.failed",
                conditions={"bogus_key": "y"},
                actions=[{"type": "notify"}],
            )
        assert r.status_code == 422, r.text

    async def test_unsupported_action_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await self._post(
                ac,
                ctx,
                name="x",
                trigger="task.failed",
                actions=[{"type": "purge"}],  # known but not yet executable
            )
        assert r.status_code == 422, r.text

    async def test_empty_actions_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await self._post(
                ac,
                ctx,
                name="x",
                trigger="task.failed",
                actions=[],
            )
        assert r.status_code == 422, r.text

    async def test_duplicate_name_409(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            body = {
                "name": "dup",
                "trigger": "task.failed",
                "actions": [{"type": "notify"}],
            }
            first = await ac.post(_BASE, headers=_hdr(ctx), json=body)
            assert first.status_code == 201
            second = await ac.post(_BASE, headers=_hdr(ctx), json=body)
        assert second.status_code == 409, second.text


@pytest.mark.asyncio
class TestRbac:
    async def test_viewer_cannot_create(self, brain_app, settings) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.VIEWER,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 403, r.text

    async def test_operator_creates_notify(self, brain_app, settings) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.OPERATOR,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 201, r.text

    async def test_operator_cannot_create_destructive(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.OPERATOR,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 403, r.text

    async def test_project_admin_creates_destructive(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.ADMIN,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 201, r.text


@pytest.mark.asyncio
class TestKillSwitch:
    async def test_default_enabled(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.get(_SETTINGS)
        assert r.status_code == 200, r.text
        assert r.json()["automation_enabled"] is True

    async def test_admin_disables_then_reenables(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            off = await ac.put(
                _SETTINGS,
                headers=_hdr(ctx),
                json={"automation_enabled": False},
            )
            assert off.status_code == 200, off.text
            assert off.json()["automation_enabled"] is False
            g = await ac.get(_SETTINGS)
            assert g.json()["automation_enabled"] is False
            on = await ac.put(
                _SETTINGS,
                headers=_hdr(ctx),
                json={"automation_enabled": True},
            )
            assert on.json()["automation_enabled"] is True

    async def test_operator_cannot_toggle(self, brain_app, settings) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.OPERATOR,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.put(
                _SETTINGS,
                headers=_hdr(ctx),
                json={"automation_enabled": False},
            )
        assert r.status_code == 403, r.text


@pytest.mark.asyncio
class TestAuditFixes:
    async def test_undispatched_trigger_rejected_422(
        self,
        brain_app,
        settings,
        monkeypatch,
    ) -> None:
        # Every grammar trigger currently has a live emit site, so
        # simulate a FUTURE grammar addition whose emit site is not
        # wired yet: pull worker.offline back out of the dispatched set
        # and confirm the write-time guard still rejects arming a rule
        # that would silently never fire.
        import z4j_brain.api.automation_rules as rules_api

        monkeypatch.setattr(
            rules_api,
            "DISPATCHED_TRIGGERS",
            rules_api.DISPATCHED_TRIGGERS - {"worker.offline"},
        )
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "wo",
                    "trigger": "worker.offline",  # simulated undispatched
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 422, r.text

    async def test_trimmed_trigger_rejected_422(
        self,
        brain_app,
        settings,
    ) -> None:
        # task.slow / queue.depth_exceeded were removed from the grammar
        # in 1.7 (no emit site was ever designed for them): creating a
        # rule on either is an unknown-trigger 422.
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            for trigger in ("task.slow", "queue.depth_exceeded"):
                r = await ac.post(
                    _BASE,
                    headers=_hdr(ctx),
                    json={
                        "name": "dead",
                        "trigger": trigger,
                        "actions": [{"type": "notify"}],
                    },
                )
                assert r.status_code == 422, r.text

    async def test_newly_wired_triggers_accepted(
        self,
        brain_app,
        settings,
    ) -> None:
        # worker.offline + task.orphaned gained real emit sites in 1.7
        # (agent-health episode detection / reconciliation apply path),
        # so rules on them are now creatable.
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            for trigger in ("worker.offline", "task.orphaned"):
                r = await ac.post(
                    _BASE,
                    headers=_hdr(ctx),
                    json={
                        "name": f"on-{trigger}",
                        "trigger": trigger,
                        "actions": [{"type": "notify"}],
                    },
                )
                assert r.status_code == 201, r.text
                assert r.json()["trigger"] == trigger

    async def test_patch_explicit_null_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            c = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "n",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
            rid = c.json()["id"]
            r = await ac.patch(
                f"{_BASE}/{rid}",
                headers=_hdr(ctx),
                json={"dry_run": None},
            )
        assert r.status_code == 422, r.text

    async def test_blank_name_422(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "   ",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 422, r.text

    async def test_name_is_trimmed(self, brain_app, settings) -> None:
        ctx = await _seed_actor(brain_app, settings, is_admin=True)
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "  spaced  ",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 201, r.text
        assert r.json()["name"] == "spaced"

    async def test_nonmember_gets_404_not_422(self, brain_app, settings) -> None:
        # An admin seeds the project; a non-member then probes with an
        # invalid body and must get the membership 404, not a 422 that
        # would confirm the project exists.
        await _seed_actor(brain_app, settings, is_admin=True)
        outsider = await _seed_actor(brain_app, settings, role=None)
        async with _client(brain_app, settings, outsider) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(outsider),
                json={
                    "name": "x",
                    "trigger": "not.a.real.trigger",
                    "actions": [],
                },
            )
        assert r.status_code == 404, r.text

    async def test_kill_switch_enable_requires_fresh_mfa(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.ADMIN,
            mfa=True,
            mfa_fresh=False,
        )
        async with _client(brain_app, settings, ctx) as ac:
            on = await ac.put(
                _SETTINGS,
                headers=_hdr(ctx),
                json={"automation_enabled": True},
            )
            assert on.status_code == 403, on.text
            assert "mfa_reverify_required" in on.text
            # Disabling reduces blast radius -> no MFA step-up.
            off = await ac.put(
                _SETTINGS,
                headers=_hdr(ctx),
                json={"automation_enabled": False},
            )
            assert off.status_code == 200, off.text


@pytest.mark.asyncio
class TestMfaStepUp:
    async def test_destructive_requires_fresh_mfa(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.ADMIN,
            mfa=True,
            mfa_fresh=False,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 403, r.text
        assert "mfa_reverify_required" in r.text

    async def test_fresh_mfa_allows_destructive(
        self,
        brain_app,
        settings,
    ) -> None:
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.ADMIN,
            mfa=True,
            mfa_fresh=True,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 201, r.text

    async def test_notify_needs_no_mfa(self, brain_app, settings) -> None:
        # Stale MFA but a NON-destructive rule -> no step-up required.
        ctx = await _seed_actor(
            brain_app,
            settings,
            role=ProjectRole.OPERATOR,
            mfa=True,
            mfa_fresh=False,
        )
        async with _client(brain_app, settings, ctx) as ac:
            r = await ac.post(
                _BASE,
                headers=_hdr(ctx),
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 201, r.text


@pytest.mark.asyncio
class TestBearerAuth:
    async def test_bearer_admin_creates_destructive_no_mfa(
        self,
        brain_app,
        settings,
    ) -> None:
        # An API key is its own factor: a bearer caller with the scope +
        # ADMIN reaches the endpoint WITHOUT a fresh-MFA step-up, and the
        # audit row attributes the action to the key.
        token, key_id = await _seed_api_key(
            brain_app,
            settings,
            is_admin=True,
            scopes=["automation:write"],
        )
        async with _bearer_client(brain_app, token) as ac:
            r = await ac.post(
                _BASE,
                json={
                    "name": "auto-retry",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 201, r.text
        db = brain_app.state.db
        async with db.session() as s:
            result = await s.execute(
                select(AuditLog).where(
                    AuditLog.action == "automation.rule.created",
                ),
            )
            rows = result.scalars().all()
        assert len(rows) == 1
        assert rows[0].api_key_id == key_id

    async def test_bearer_missing_scope_403(self, brain_app, settings) -> None:
        # Without automation:write the key cannot reach the endpoint even
        # for the owning admin (the tag maps to a real scope now).
        token, _ = await _seed_api_key(
            brain_app,
            settings,
            is_admin=True,
            scopes=["tasks:read"],
        )
        async with _bearer_client(brain_app, token) as ac:
            r = await ac.post(
                _BASE,
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "notify"}],
                },
            )
        assert r.status_code == 403, r.text

    async def test_bearer_rbac_still_applies(self, brain_app, settings) -> None:
        # Scope grants API reach; the per-request role gate still blocks a
        # non-ADMIN key from arming a destructive rule.
        token, _ = await _seed_api_key(
            brain_app,
            settings,
            role=ProjectRole.OPERATOR,
            scopes=["automation:write"],
        )
        async with _bearer_client(brain_app, token) as ac:
            r = await ac.post(
                _BASE,
                json={
                    "name": "x",
                    "trigger": "task.failed",
                    "actions": [{"type": "retry"}],
                },
            )
        assert r.status_code == 403, r.text
