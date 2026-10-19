"""The subscription API preserves mute instants across SQLite round trips."""

from __future__ import annotations

import os
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.notifications.service import NotificationService
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Session,
    User,
    UserNotification,
    UserSubscription,
)
from z4j_brain.settings import Settings


@dataclass
class _SubscriptionAPI:
    client: AsyncClient
    database: DatabaseManager
    subscription_id: uuid.UUID
    project_id: uuid.UUID

    @property
    def url(self) -> str:
        return f"/api/v1/user/subscriptions/{self.subscription_id}"


@pytest.fixture
async def subscription_api(brain_app, brain_settings: Settings) -> AsyncIterator[_SubscriptionAPI]:
    database = brain_app.state.db
    async with database.engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    user_id, project_id, sub_id, session_id = (uuid.uuid4() for _ in range(4))
    csrf = secrets.token_urlsafe(32)
    async with database.session(write=True) as session:
        session.add_all(
            [
                User(
                    id=user_id,
                    email="mute@example.test",
                    password_hash="not-used-by-session",
                    is_active=True,
                ),
                Project(id=project_id, slug="mute-timezone", name="Mute timezone"),
            ]
        )
        await session.flush()
        session.add_all(
            [
                Membership(user_id=user_id, project_id=project_id, role=ProjectRole.VIEWER),
                Session(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
                UserSubscription(
                    id=sub_id,
                    user_id=user_id,
                    project_id=project_id,
                    trigger="task.failed",
                    in_app=True,
                    filters={},
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                    is_active=True,
                ),
            ]
        )
        await session.commit()
    async with AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
        headers={"X-CSRF-Token": csrf},
    ) as client:
        client.cookies.set(
            cookie_name(environment=brain_settings.environment),
            SessionCookieCodec(brain_settings).encode(session_id),
        )
        client.cookies.set(csrf_cookie_name(environment=brain_settings.environment), csrf)
        yield _SubscriptionAPI(client, database, sub_id, project_id)


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("2027-01-02T02:15:30+05:30", "2027-01-01T20:45:30+00:00"),
        ("2027-01-01T22:15:30-07:00", "2027-01-02T05:15:30+00:00"),
        ("2027-01-01T22:15:30Z", "2027-01-01T22:15:30+00:00"),
        ("2027-01-01T22:15:30", "2027-01-01T22:15:30+00:00"),
    ],
    ids=["positive-offset-crosses-date", "negative-offset-crosses-date", "utc", "naive-utc"],
)
async def test_mute_api_preserves_instant_in_storage_update_and_list(
    subscription_api: _SubscriptionAPI, supplied: str, expected: str
) -> None:
    api = subscription_api
    response = await api.client.patch(api.url, json={"muted_until": supplied})
    assert response.status_code == 200, response.text
    expected_instant = datetime.fromisoformat(expected)
    async with api.database.session() as session:
        stored = await session.get(UserSubscription, api.subscription_id)
        # SQLite's representation is naive; its clock values must be UTC.
        assert stored.muted_until.replace(tzinfo=UTC) == expected_instant
    assert datetime.fromisoformat(response.json()["muted_until"]) == expected_instant
    listed = await api.client.get("/api/v1/user/subscriptions")
    assert listed.status_code == 200, listed.text
    assert datetime.fromisoformat(listed.json()["items"][0]["muted_until"]) == expected_instant


async def test_omitting_mute_preserves_it_and_null_unmutes(
    subscription_api: _SubscriptionAPI,
) -> None:
    api = subscription_api
    initial = await api.client.patch(api.url, json={"muted_until": "2027-01-01T15:00:00+05:00"})
    assert initial.status_code == 200, initial.text
    omitted = await api.client.patch(api.url, json={"cooldown_seconds": 17})
    assert omitted.status_code == 200, omitted.text
    assert omitted.json()["muted_until"] == initial.json()["muted_until"]
    cleared = await api.client.patch(api.url, json={"muted_until": None})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["muted_until"] is None
    async with api.database.session() as session:
        stored = await session.get(UserSubscription, api.subscription_id)
        assert stored.muted_until is None


@pytest.mark.parametrize(
    ("hours", "offset_hours", "expected_count"),
    [(1, -7, 0), (-1, 5, 1)],
    ids=["future-mute-negative-offset", "expired-mute-positive-offset"],
)
async def test_offset_mute_controls_real_dispatch_at_the_intended_instant(
    subscription_api: _SubscriptionAPI, hours: int, offset_hours: int, expected_count: int
) -> None:
    from datetime import timezone

    api = subscription_api
    deadline = datetime.now(UTC) + timedelta(hours=hours)
    supplied = deadline.astimezone(timezone(timedelta(hours=offset_hours))).isoformat()
    response = await api.client.patch(api.url, json={"muted_until": supplied})
    assert response.status_code == 200, response.text
    async with api.database.session(write=True) as session:
        count = await NotificationService().evaluate_and_dispatch(
            session=session, project_id=api.project_id, trigger="task.failed"
        )
    assert count == expected_count
    async with api.database.session() as session:
        assert len((await session.scalars(select(UserNotification))).all()) == expected_count


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="host timezone switching requires tzset")
async def test_naive_input_is_utc_independent_of_process_timezone(
    subscription_api: _SubscriptionAPI,
) -> None:
    api = subscription_api
    previous_timezone = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "EST5EDT"
        time.tzset()
        response = await api.client.patch(api.url, json={"muted_until": "2027-01-01T22:15:30"})
    finally:
        if previous_timezone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_timezone
        time.tzset()
    assert response.status_code == 200, response.text
    assert datetime.fromisoformat(response.json()["muted_until"]) == datetime(
        2027, 1, 1, 22, 15, 30, tzinfo=UTC
    )


@pytest.mark.parametrize("supplied", ["9999-12-31T23:59:59-01:00", "0001-01-01T00:00:00+01:00"])
async def test_unrepresentable_utc_mute_is_rejected_without_mutation(
    subscription_api: _SubscriptionAPI, supplied: str
) -> None:
    api = subscription_api
    response = await api.client.patch(api.url, json={"muted_until": supplied})
    assert response.status_code == 422, response.text
    async with api.database.session() as session:
        stored = await session.get(UserSubscription, api.subscription_id)
        assert stored.muted_until is None
