"""Separation of duties for the ``auditor`` project role, over HTTP.

The auditor reads the record and changes nothing. This module proves
that against the real application, not the policy table: an auditor can
list, export and (through the API-key scope) read the audit trail, and
every mutating route under the project refuses the auditor with the
engine's own 403. The route list is enumerated from the FastAPI route
table, so a route added later is covered without being named here.

The other three roles are checked at the same time, because the
guarantee is relational: an admin still holds everything, a viewer still
cannot read the trail, and an operator, whose actions the trail records,
cannot read it either.
"""

from __future__ import annotations

import contextlib
import enum
import secrets
import types
import typing
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import CSRF_HEADER_NAME, csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.scopes import ALL_SCOPES, TAG_TO_RESOURCE
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    ApiKey,
    AuditLog,
    Membership,
    Project,
    Session,
    User,
)
from z4j_brain.settings import Settings

_PW = "correct horse battery staple 9"
_SLUG = "default"
_AUDIT = f"/api/v1/projects/{_SLUG}/audit"

#: Mutating project routes a member may use at the viewer floor because
#: they write the caller's own state and nothing shared. They are not
#: separation-of-duties surfaces; the test checks the auditor is treated
#: there exactly as a viewer is.
PERSONAL_STATE_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/projects/{slug}/saved-views"),
        ("PUT", "/api/v1/projects/{slug}/saved-views/{view_id}"),
        ("DELETE", "/api/v1/projects/{slug}/saved-views/{view_id}"),
    },
)

#: Writes that belong to the audit tier itself: queueing a background
#: export reveals what the synchronous export reveals and changes nothing
#: else, so the auditor is admitted (it answers 202, or 409 without a sink).
AUDIT_TIER_WRITES: frozenset[tuple[str, str]] = frozenset(
    {("POST", "/api/v1/projects/{slug}/audit/export-jobs")},
)

#: Routes the brain gates on the instance-wide tier (``is_admin``) rather
#: than a project role. A project admin is refused there too, with the
#: dependency's own message.
INSTANCE_TIER_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("PATCH", "/api/v1/projects/{slug}"),
        ("DELETE", "/api/v1/projects/{slug}"),
    },
)

#: Request bodies for routes whose models carry validators the generic
#: sampler cannot satisfy. Validation runs before the handler, so a body
#: that fails it would turn the role refusal into a 422 and prove nothing.
_AGENT_ID = str(uuid.uuid4())
_RULE_BODY: dict[str, Any] = {
    "name": "separation of duties",
    "trigger": "task.failed",
    "actions": [{"type": "notify"}],
}
BODY_OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    ("POST", "/api/v1/projects/{slug}/automation/rules"): _RULE_BODY,
    ("POST", "/api/v1/projects/{slug}/commands/rate-limit"): {
        "agent_id": _AGENT_ID,
        "task_name": "t.t",
        "rate": "10/m",
    },
    ("POST", "/api/v1/projects/{slug}/notifications/channels"): {
        "name": "sod",
        "type": "webhook",
        "config": {"url": "https://hooks.example.test/x"},
    },
    ("POST", "/api/v1/projects/{slug}/notifications/channels/test"): {
        "type": "webhook",
        "config": {"url": "https://hooks.example.test/x"},
    },
    ("POST", "/api/v1/projects/{slug}/notifications/defaults"): {"trigger": "task.failed"},
    ("POST", "/api/v1/projects/{slug}/schedules"): {
        "name": "sod",
        "engine": "celery",
        "kind": "cron",
        "expression": "0 * * * *",
        "task_name": "t.t",
    },
    ("POST", "/api/v1/projects/{slug}/schedules/{schedule_id}/resolve-legacy-evidence"): {
        "fire_id": str(uuid.uuid4()),
        "source_evidence_kind": "PENDING_FIRE",
        "source_evidence_id": str(uuid.uuid4()),
        "observed_control_token": str(uuid.uuid4()),
        "work_may_have_executed": True,
    },
    ("POST", "/api/v1/projects/{slug}/tasks/bulk-delete"): {"task_ids": [str(uuid.uuid4())]},
}


# ---------------------------------------------------------------------------
# App and actors
# ---------------------------------------------------------------------------


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
    settings: Settings,
    *,
    role: ProjectRole | None,
    is_admin: bool = False,
) -> dict[str, Any]:
    """Insert the project (once), a user, a membership at ``role`` and a session."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    csrf = secrets.token_urlsafe(32)
    async with db.session() as s:
        project = (
            await s.execute(select(Project).where(Project.slug == _SLUG))
        ).scalar_one_or_none()
        if project is None:
            project = Project(id=uuid.uuid4(), slug=_SLUG, name="Default")
            s.add(project)
            await s.flush()
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@example.com",
            password_hash=hasher.hash(_PW),
            is_admin=is_admin,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        if role is not None:
            s.add(Membership(user_id=user.id, project_id=project.id, role=role))
        session_row = Session(
            id=uuid.uuid4(),
            user_id=user.id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add(session_row)
        s.add(
            AuditLog(
                project_id=project.id,
                user_id=user.id,
                action="membership.granted",
                target_type="membership",
                target_id=str(user.id),
                result="success",
                outcome="allow",
                audit_metadata={"role": role.value if role else None},
            ),
        )
        await s.commit()
    return {
        "session_id": session_row.id,
        "csrf": csrf,
        "user_id": user.id,
        "project_id": project.id,
    }


async def _seed_api_key(
    brain_app,
    settings: Settings,
    *,
    role: ProjectRole,
    scopes: list[str],
) -> str:
    from z4j_brain.api.api_keys import _hash_api_key

    actor = await _seed_actor(brain_app, settings, role=role)
    token = "z4k_" + secrets.token_urlsafe(32)
    secret = settings.secret.get_secret_value().encode("utf-8")
    async with brain_app.state.db.session() as s:
        s.add(
            ApiKey(
                id=uuid.uuid4(),
                user_id=actor["user_id"],
                name="test-key",
                token_hash=_hash_api_key(plaintext=token, secret=secret),
                prefix=token[:8],
                scopes=list(scopes),
                project_id=actor["project_id"],
            ),
        )
        await s.commit()
    return token


@contextlib.asynccontextmanager
async def _session_client(
    brain_app, settings: Settings, actor: dict[str, Any]
) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={CSRF_HEADER_NAME: actor["csrf"]},
    ) as client:
        codec = SessionCookieCodec(settings)
        client.cookies.set(
            cookie_name(environment=settings.environment), codec.encode(actor["session_id"])
        )
        client.cookies.set(csrf_cookie_name(environment=settings.environment), actor["csrf"])
        yield client


@contextlib.asynccontextmanager
async def _bearer_client(brain_app, token: str) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        yield client


async def _reset_rate_limits() -> None:
    """Every actor shares the loopback IP; drain the buckets between calls."""
    from z4j_brain.domain import ip_rate_limit as ipl

    for name in dir(ipl):
        if name.endswith("_bucket"):
            bucket = getattr(ipl, name)
            if hasattr(bucket, "prune_idle"):
                await bucket.prune_idle(idle_seconds=0)


# ---------------------------------------------------------------------------
# Route table and request synthesis
# ---------------------------------------------------------------------------


def _walk_routes(routes, prefix: str = ""):
    """Yield (effective path, APIRoute) through every included router."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif hasattr(route, "original_router"):
            yield from _walk_routes(
                route.original_router.routes, prefix + route.include_context.prefix
            )
        elif hasattr(route, "routes"):
            yield from _walk_routes(route.routes, prefix + getattr(route, "path", ""))


def mutating_project_routes(app) -> list[tuple[str, str, APIRoute]]:
    """Every (method, path template, route) under the project that is not a GET."""
    found: list[tuple[str, str, APIRoute]] = []
    for path, route in _walk_routes(app.routes):
        if "/projects/{slug}" not in path:
            continue
        for method in sorted(route.methods - {"GET", "HEAD", "OPTIONS"}):
            found.append((method, path, route))
    return sorted(found, key=lambda item: (item[1], item[0]))


def _sample(annotation: Any) -> Any:
    """A value of ``annotation``'s type that passes ordinary validation."""
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Literal:
        return args[0]
    if origin in (typing.Union, types.UnionType):
        candidates = [a for a in args if a is not type(None)]
        return _sample(candidates[0]) if candidates else None
    if origin in (list, set, frozenset, tuple):
        return []
    if origin is dict:
        return {}
    if origin is typing.Annotated:
        return _sample(args[0])
    if annotation is Any:
        return {}
    if isinstance(annotation, type):
        if issubclass(annotation, bool):
            return True
        if issubclass(annotation, enum.Enum):
            return next(iter(annotation)).value
        if issubclass(annotation, BaseModel):
            return _body_from_model(annotation)
        if issubclass(annotation, uuid.UUID):
            return str(uuid.uuid4())
        if issubclass(annotation, datetime):
            return datetime.now(UTC).isoformat()
        if issubclass(annotation, int):
            return 1
        if issubclass(annotation, float):
            return 1.0
        if issubclass(annotation, str):
            return "sample"
        if issubclass(annotation, (list, tuple, set)):
            return []
        if issubclass(annotation, dict):
            return {}
    name = getattr(annotation, "__name__", str(annotation))
    if "Email" in name:
        return "sample@example.com"
    return "sample"


def _body_from_model(model: type[BaseModel]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for name, field in model.model_fields.items():
        if not field.is_required():
            continue
        if "email" in name.lower():
            body[name] = "sample@example.com"
            continue
        body[name] = _sample(field.annotation)
    return body


def request_for(
    method: str,
    template: str,
    route: APIRoute,
    known_ids: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Concrete URL and JSON body for one route table entry.

    ``known_ids`` maps a path parameter to a real row's id for the routes
    that load the target before authorizing the write (automation rules),
    where a made-up id would answer 404 before the role is checked.
    """
    url = template.replace("{slug}", _SLUG)
    while "{" in url:
        start = url.index("{")
        end = url.index("}", start)
        param = url[start + 1 : end]
        url = url[:start] + (known_ids or {}).get(param, str(uuid.uuid4())) + url[end + 1 :]
    body: dict[str, Any] | None = None
    if (method, template) in BODY_OVERRIDES:
        body = BODY_OVERRIDES[method, template]
    elif route.body_field is not None:
        model = route.body_field.field_info.annotation
        if isinstance(model, type) and issubclass(model, BaseModel):
            body = _body_from_model(model)
        else:
            body = {}
    return url, body


def _is_role_refusal(response) -> bool:
    if response.status_code != 403:
        return False
    payload = response.json()
    message = str(payload.get("message", ""))
    return payload.get("error") == "forbidden" and (
        "is not sufficient" in message or message == "admin role required"
    )


def _is_request_validation_error(response) -> bool:
    """A 422 raised before the handler ran (FastAPI's own envelope)."""
    return response.status_code == 422 and "error" not in response.json()


async def _seed_rule(brain_app, settings: Settings) -> str:
    """Create one automation rule as an admin and return its id."""
    admin = await _seed_actor(brain_app, settings, role=ProjectRole.ADMIN)
    async with _session_client(brain_app, settings, admin) as client:
        created = await client.post(f"/api/v1/projects/{_SLUG}/automation/rules", json=_RULE_BODY)
        assert created.status_code == 201, created.text
        return created.json()["id"]


# ---------------------------------------------------------------------------
# The guarantees
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAuditorReadsTheRecord:
    async def test_auditor_lists_and_exports_the_audit_trail(
        self, brain_app, settings: Settings
    ) -> None:
        auditor = await _seed_actor(brain_app, settings, role=ProjectRole.AUDITOR)
        async with _session_client(brain_app, settings, auditor) as client:
            listed = await client.get(_AUDIT)
            assert listed.status_code == 200, listed.text
            assert listed.json()["items"], "the seeded audit row must be visible"
            for export_format, content_type in (
                ("csv", "text/csv"),
                ("json", "application/json"),
                ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            ):
                exported = await client.get(f"{_AUDIT}?format={export_format}")
                assert exported.status_code == 200, (export_format, exported.text)
                assert content_type in exported.headers["content-type"], export_format
                assert "attachment" in exported.headers["content-disposition"]

    async def test_admin_still_reads_and_exports(self, brain_app, settings: Settings) -> None:
        admin = await _seed_actor(brain_app, settings, role=ProjectRole.ADMIN)
        async with _session_client(brain_app, settings, admin) as client:
            assert (await client.get(_AUDIT)).status_code == 200
            assert (await client.get(f"{_AUDIT}?format=csv")).status_code == 200

    @pytest.mark.parametrize("role", [ProjectRole.VIEWER, ProjectRole.OPERATOR])
    async def test_viewer_and_operator_cannot_read_the_trail(
        self, brain_app, settings: Settings, role: ProjectRole
    ) -> None:
        actor = await _seed_actor(brain_app, settings, role=role)
        async with _session_client(brain_app, settings, actor) as client:
            for url in (_AUDIT, f"{_AUDIT}?format=csv"):
                response = await client.get(url)
                assert response.status_code == 403, (role, url, response.text)
                payload = response.json()
                assert payload["error"] == "forbidden"
                assert payload["details"] == {"have": role.value, "need": "auditor"}

    async def test_non_member_gets_the_anti_enumeration_404(
        self, brain_app, settings: Settings
    ) -> None:
        stranger = await _seed_actor(brain_app, settings, role=None)
        async with _session_client(brain_app, settings, stranger) as client:
            assert (await client.get(_AUDIT)).status_code == 404


@pytest.mark.asyncio
class TestAuditorChangesNothing:
    async def test_every_mutating_project_route_refuses_the_auditor(
        self, brain_app, settings: Settings
    ) -> None:
        routes = mutating_project_routes(brain_app)
        assert len(routes) >= 50, "the route table lost its project writes"
        known_ids = {"rule_id": await _seed_rule(brain_app, settings)}
        auditor = await _seed_actor(brain_app, settings, role=ProjectRole.AUDITOR)
        failures: list[str] = []
        personal_seen: set[tuple[str, str]] = set()
        async with _session_client(brain_app, settings, auditor) as client:
            for method, template, route in routes:
                await _reset_rate_limits()
                url, body = request_for(method, template, route, known_ids)
                response = await client.request(method, url, json=body)
                if (method, template) in AUDIT_TIER_WRITES:
                    if _is_role_refusal(response):
                        failures.append(
                            f"{method} {template}: audit-tier write refused the auditor"
                        )
                    continue
                if (method, template) in PERSONAL_STATE_ROUTES:
                    personal_seen.add((method, template))
                    # Own-state writes: the auditor is a member, so it is
                    # not refused for its role (404 for a made-up id is fine).
                    if _is_role_refusal(response):
                        failures.append(
                            f"{method} {template}: personal-state route refused the auditor"
                        )
                    continue
                if not _is_role_refusal(response):
                    failures.append(
                        f"{method} {template} -> {response.status_code} {response.text[:160]}"
                    )
        assert failures == [], "\n".join(failures)
        assert personal_seen == PERSONAL_STATE_ROUTES

    async def test_admin_is_not_refused_anywhere_for_its_role(
        self, brain_app, settings: Settings
    ) -> None:
        routes = mutating_project_routes(brain_app)
        known_ids = {"rule_id": await _seed_rule(brain_app, settings)}
        admin = await _seed_actor(brain_app, settings, role=ProjectRole.ADMIN)
        refusals: list[str] = []
        async with _session_client(brain_app, settings, admin) as client:
            for method, template, route in routes:
                await _reset_rate_limits()
                url, body = request_for(method, template, route, known_ids)
                response = await client.request(method, url, json=body)
                if (method, template) in INSTANCE_TIER_ROUTES:
                    assert response.status_code == 403, (method, template, response.text)
                    assert response.json()["message"] == "admin role required"
                    continue
                if _is_role_refusal(response):
                    refusals.append(f"{method} {template}: {response.text[:160]}")
                # Request validation runs before the handler; a body it
                # rejects never reached the role check for the auditor
                # either. Keep the sampler honest. (A handler's own 422,
                # raised after authorization, is fine.)
                assert not _is_request_validation_error(response), (
                    method,
                    template,
                    response.text[:300],
                )
        assert refusals == [], "\n".join(refusals)

    async def test_viewer_is_refused_on_the_same_routes(
        self, brain_app, settings: Settings
    ) -> None:
        # The auditor adds audit reads to the viewer and nothing else, so the
        # viewer's refusals are the auditor's refusals.
        routes = mutating_project_routes(brain_app)
        known_ids = {"rule_id": await _seed_rule(brain_app, settings)}
        viewer = await _seed_actor(brain_app, settings, role=ProjectRole.VIEWER)
        async with _session_client(brain_app, settings, viewer) as client:
            for method, template, route in routes:
                if (method, template) in PERSONAL_STATE_ROUTES:
                    continue
                await _reset_rate_limits()
                url, body = request_for(method, template, route, known_ids)
                response = await client.request(method, url, json=body)
                assert _is_role_refusal(response), (
                    method,
                    template,
                    response.status_code,
                    response.text[:160],
                )


@pytest.mark.asyncio
class TestApiKeyScopeUnchanged:
    def test_audit_read_scope_still_exists(self) -> None:
        assert "audit:read" in ALL_SCOPES
        assert TAG_TO_RESOURCE["audit"] == "audit"

    async def test_scoped_key_needs_both_the_scope_and_the_role(
        self, brain_app, settings: Settings
    ) -> None:
        auditor_key = await _seed_api_key(
            brain_app, settings, role=ProjectRole.AUDITOR, scopes=["audit:read"]
        )
        admin_key = await _seed_api_key(
            brain_app, settings, role=ProjectRole.ADMIN, scopes=["audit:read"]
        )
        viewer_key = await _seed_api_key(
            brain_app, settings, role=ProjectRole.VIEWER, scopes=["audit:read"]
        )
        unscoped_key = await _seed_api_key(
            brain_app, settings, role=ProjectRole.AUDITOR, scopes=["tasks:read"]
        )

        async with _bearer_client(brain_app, auditor_key) as client:
            assert (await client.get(_AUDIT)).status_code == 200
            assert (await client.get(f"{_AUDIT}?format=json")).status_code == 200
        async with _bearer_client(brain_app, admin_key) as client:
            assert (await client.get(_AUDIT)).status_code == 200
        async with _bearer_client(brain_app, viewer_key) as client:
            response = await client.get(_AUDIT)
            assert response.status_code == 403
            assert response.json()["details"] == {"have": "viewer", "need": "auditor"}
        async with _bearer_client(brain_app, unscoped_key) as client:
            response = await client.get(_AUDIT)
            assert response.status_code == 403
            assert "is not sufficient" not in response.json().get("message", "")


# ---------------------------------------------------------------------------
# The cross-project feed is the same record behind the same tier
# ---------------------------------------------------------------------------

_ACTIVITY = "/api/v1/activity"


async def _audit_rows(brain_app, action: str) -> list[AuditLog]:
    async with brain_app.state.db.session() as s:
        return list(
            (await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
        )


@pytest.mark.asyncio
class TestActivityFeedKeepsTheAuditTier:
    """``/activity`` serves ``audit_log`` rows across projects, so a project
    is in a caller's feed exactly when the caller could open that project's
    audit page: a membership at the auditor tier (``auditor`` or ``admin``,
    decided by the core table), or the instance-admin bypass. A viewer or
    operator membership puts nothing in the feed; the slug filter is no
    side door; a non-member sees nothing of the project.

    Every seeded actor leaves a ``membership.granted`` row on the project,
    so the project always has rows to withhold or show.
    """

    async def _project_rows(
        self, client: AsyncClient, project_id: uuid.UUID
    ) -> list[dict[str, Any]]:
        listed = await client.get(_ACTIVITY)
        assert listed.status_code == 200, listed.text
        return [item for item in listed.json()["items"] if item["project_id"] == str(project_id)]

    @pytest.mark.parametrize("role", [ProjectRole.VIEWER, ProjectRole.OPERATOR])
    async def test_viewer_and_operator_get_no_project_rows(
        self, brain_app, settings: Settings, role: ProjectRole
    ) -> None:
        actor = await _seed_actor(brain_app, settings, role=role)
        async with _session_client(brain_app, settings, actor) as client:
            # The per-project page refuses the role; the feed must not hand
            # the same rows out one level up.
            refused = await client.get(_AUDIT)
            assert refused.status_code == 403, refused.text
            assert await self._project_rows(client, actor["project_id"]) == []
            scoped = await client.get(_ACTIVITY, params={"project_slug": _SLUG})
            assert scoped.status_code == 200, scoped.text
            assert scoped.json()["items"] == []

    @pytest.mark.parametrize("role", [ProjectRole.AUDITOR, ProjectRole.ADMIN])
    async def test_auditor_and_admin_get_the_project_rows(
        self, brain_app, settings: Settings, role: ProjectRole
    ) -> None:
        actor = await _seed_actor(brain_app, settings, role=role)
        async with _session_client(brain_app, settings, actor) as client:
            rows = await self._project_rows(client, actor["project_id"])
            assert rows, "the seeded membership.granted row must be in the feed"
            assert {row["project_slug"] for row in rows} == {_SLUG}
            scoped = await client.get(_ACTIVITY, params={"project_slug": _SLUG})
            assert scoped.status_code == 200, scoped.text
            assert scoped.json()["items"]

    async def test_instance_admin_sees_the_project_without_a_membership(
        self, brain_app, settings: Settings
    ) -> None:
        admin = await _seed_actor(brain_app, settings, role=None, is_admin=True)
        async with _session_client(brain_app, settings, admin) as client:
            assert await self._project_rows(client, admin["project_id"])

    async def test_a_non_member_sees_nothing_of_the_project(
        self, brain_app, settings: Settings
    ) -> None:
        await _seed_actor(brain_app, settings, role=ProjectRole.AUDITOR)
        stranger = await _seed_actor(brain_app, settings, role=None)
        async with _session_client(brain_app, settings, stranger) as client:
            assert await self._project_rows(client, stranger["project_id"]) == []
            scoped = await client.get(_ACTIVITY, params={"project_slug": _SLUG})
            assert scoped.status_code == 200, scoped.text
            assert scoped.json()["items"] == []


@pytest.mark.asyncio
class TestExportsAreRecorded:
    async def test_a_served_export_is_recorded_and_a_list_read_is_not(
        self, brain_app, settings: Settings
    ) -> None:
        auditor = await _seed_actor(brain_app, settings, role=ProjectRole.AUDITOR)
        async with _session_client(brain_app, settings, auditor) as client:
            listed = await client.get(_AUDIT)
            assert listed.status_code == 200, listed.text
            assert await _audit_rows(brain_app, "audit.export") == [], (
                "a page read is not an extraction"
            )
            exported = await client.get(
                f"{_AUDIT}?format=json&fields=action,result&action_prefix=membership."
            )
            assert exported.status_code == 200, exported.text

        (row,) = await _audit_rows(brain_app, "audit.export")
        assert row.user_id == auditor["user_id"]
        assert row.project_id == auditor["project_id"]
        assert row.target_type == "audit_log"
        assert row.target_id == _SLUG
        assert row.result == "success"
        assert row.outcome == "allow"
        assert row.row_hmac, "written through the chained writer"
        assert row.audit_metadata["format"] == "json"
        # One membership.granted row (this actor's) matched the filter.
        assert row.audit_metadata["row_count"] == 1
        assert row.audit_metadata["fields"] == ["action", "result"]
        assert row.audit_metadata["filters"] == {
            "action_prefix": "membership.",
            "outcome": None,
            "user_id": None,
            "since": None,
        }

    async def test_a_refused_export_leaves_no_export_row(
        self, brain_app, settings: Settings
    ) -> None:
        operator = await _seed_actor(brain_app, settings, role=ProjectRole.OPERATOR)
        async with _session_client(brain_app, settings, operator) as client:
            assert (await client.get(f"{_AUDIT}?format=csv")).status_code == 403
        assert await _audit_rows(brain_app, "audit.export") == []
