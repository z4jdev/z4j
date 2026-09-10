"""Saved Views use real session/CSRF and project/owner authorization boundaries."""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, SavedView, Session, User

BODY = {
    "name": "Failed payments",
    "filters": {"state": "failure", "search": "payment", "priority": ["high"]},
}
PATH = "/api/v1/projects/alpha/saved-views"


@pytest.fixture
async def workspace(brain_settings, tmp_path):
    # Optional replay against disposable PostgreSQL, with a fresh database per
    # test. Default unit runs use SQLite and require no external service.
    pg_url = os.environ.get("Z4J_TEST_SAVED_VIEWS_POSTGRES_URL")
    database = f"saved_views_{uuid.uuid4().hex}"
    admin = None
    url = f"sqlite+aiosqlite:///{tmp_path / 'views.sqlite'}"
    if pg_url:
        admin = create_async_engine(pg_url, isolation_level="AUTOCOMMIT")
        async with admin.connect() as connection:
            await connection.execute(text(f'CREATE DATABASE "{database}"'))
        url = make_url(pg_url).set(database=database).render_as_string(hide_password=False)
    brain_settings = brain_settings.model_copy(update={"database_url": url})
    engine = create_async_engine(brain_settings.database_url)
    async with engine.begin() as connection:
        if pg_url:
            await connection.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))
        await connection.run_sync(Base.metadata.create_all)
    app = create_app(brain_settings, engine=engine)
    users = [
        User(email=f"view-{i}@example.com", password_hash="unused", is_active=True, is_admin=i == 2)
        for i in range(3)
    ]
    projects = [Project(slug=slug, name=slug) for slug in ("alpha", "bravo")]
    sessions = []
    async with app.state.db.session(write=True) as session:
        session.add_all([*users, *projects])
        await session.flush()
        for user in users:
            row = Session(
                user_id=user.id,
                csrf_token=secrets.token_urlsafe(32),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            )
            sessions.append(row)
            session.add(row)
        for user in users[:2]:
            for project in projects:
                session.add(
                    Membership(user_id=user.id, project_id=project.id, role=ProjectRole.VIEWER)
                )
        await session.commit()
    clients = []
    for row in sessions:
        client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
            headers={"X-CSRF-Token": row.csrf_token},
        )
        client.cookies.set(
            cookie_name(environment=brain_settings.environment),
            SessionCookieCodec(brain_settings).encode(row.id),
        )
        clients.append(client)
    yield app, clients, users, projects
    for client in clients:
        await client.aclose()
    await engine.dispose()
    if admin is not None:
        async with admin.connect() as connection:
            await connection.execute(text(f'DROP DATABASE "{database}" WITH (FORCE)'))
        await admin.dispose()


async def test_create_list_replace_and_delete_persist(workspace):
    _, clients, _, _ = workspace
    client = clients[0]
    response = await client.post(PATH, json=BODY)
    assert response.status_code == 201, response.text
    view = response.json()
    assert "user_id" not in view and "project_id" not in view
    assert (await client.get(PATH)).json() == [view]
    body = {"name": "  Urgent tasks  ", "filters": {"priority": ["high", "critical", "high"]}}
    response = await client.put(f"{PATH}/{view['id']}", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Urgent tasks"
    assert set(response.json()["filters"]["priority"]) == {"critical", "high"}
    assert len(response.json()["filters"]["priority"]) == 2
    assert response.json()["filters"]["state"] is None
    assert (await client.delete(f"{PATH}/{view['id']}")).status_code == 204
    assert (await client.get(PATH)).json() == []


async def test_other_members_and_global_admins_cannot_access_personal_views(workspace):
    _, clients, _, _ = workspace
    view = (await clients[0].post(PATH, json=BODY)).json()
    for client in clients[1:]:
        assert (await client.get(PATH)).json() == []
        assert (await client.put(f"{PATH}/{view['id']}", json=BODY)).status_code == 404
        assert (await client.delete(f"{PATH}/{view['id']}")).status_code == 404
    assert len((await clients[0].get(PATH)).json()) == 1


async def test_cross_project_ids_and_revoked_membership_are_rejected(workspace):
    app, clients, users, projects = workspace
    client = clients[0]
    view = (await client.post(PATH, json=BODY)).json()
    other = PATH.replace("alpha", "bravo")
    assert (await client.get(other)).json() == []
    assert (await client.delete(f"{other}/{view['id']}")).status_code == 404
    async with app.state.db.session(write=True) as session:
        await session.execute(
            delete(Membership).where(
                Membership.user_id == users[0].id, Membership.project_id == projects[0].id
            )
        )
        await session.commit()
    for method, url, data in [
        ("GET", PATH, None),
        ("POST", PATH, BODY),
        ("PUT", f"{PATH}/{view['id']}", BODY),
        ("DELETE", f"{PATH}/{view['id']}", None),
    ]:
        # Existing project policy hides projects after membership is revoked.
        assert (await client.request(method, url, json=data)).status_code == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_csrf_required_for_every_mutation(workspace, method):
    _, clients, _, _ = workspace
    client = clients[0]
    client.headers.pop("X-CSRF-Token")
    url = PATH if method == "POST" else f"{PATH}/{uuid.uuid4()}"
    assert (await client.request(method, url, json=BODY)).status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {**BODY, "name": "   "},
        {**BODY, "name": "x" * 81},
        {**BODY, "user_id": str(uuid.uuid4())},
        {**BODY, "filters": {"state": "invalid"}},
        {**BODY, "filters": {"priority": ["invalid"]}},
        {**BODY, "filters": {"search": "x" * 201}},
        {**BODY, "filters": {"cursor": "stale-page"}},
        {**BODY, "filters": {"project_id": str(uuid.uuid4())}},
    ],
)
async def test_invalid_or_unbounded_presets_are_rejected(workspace, body):
    _, clients, _, _ = workspace
    response = await clients[0].post(PATH, json=body)
    assert response.status_code == 422, response.text
    assert (await clients[0].get(PATH)).json() == []


async def test_cap_and_case_insensitive_names_are_atomic(workspace):
    app, clients, users, projects = workspace
    client = clients[0]
    responses = await asyncio.gather(
        *(
            client.post(PATH, json={**BODY, "name": "Same name" if index % 2 else "SAME NAME"})
            for index in range(6)
        )
    )
    assert sorted(response.status_code for response in responses) == [201, 409, 409, 409, 409, 409]
    async with app.state.db.session(write=True) as session:
        session.add_all(
            SavedView(
                user_id=users[0].id,
                project_id=projects[0].id,
                page="tasks",
                name=f"View {index}",
                filters={},
            )
            for index in range(98)
        )
        await session.commit()
    responses = await asyncio.gather(
        *(client.post(PATH, json={**BODY, "name": f"Last {index}"}) for index in range(4))
    )
    assert sorted(response.status_code for response in responses) == [201, 409, 409, 409]
    assert len((await client.get(PATH)).json()) == 100
    assert (await clients[1].post(PATH, json=BODY)).status_code == 201


async def test_anonymous_requests_are_rejected(workspace):
    app, _, _, _ = workspace
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        assert (await client.get(PATH)).status_code == 401
