"""Only successfully committed subscription staging may produce deliveries."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.notifications.channels import CHANNEL_DISPATCHERS, DeliveryResult
from z4j_brain.domain.notifications.service import NotificationService
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    NotificationDelivery,
    Project,
    User,
    UserChannel,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.repositories import UserSubscriptionRepository


@pytest.fixture
async def database() -> AsyncIterator[DatabaseManager]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    manager = DatabaseManager(engine)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield manager
    finally:
        await engine.dispose()


async def _seed(database: DatabaseManager, channel_scope: str) -> uuid.UUID:
    project_id = uuid.uuid4()
    async with database.session(write=True) as session:
        session.add(Project(id=project_id, slug="staging-transaction", name="Staging"))
        await session.flush()
        for index in range(2):
            user_id, channel_id = uuid.uuid4(), uuid.uuid4()
            session.add(
                User(
                    id=user_id,
                    email=f"recipient-{index}@example.test",
                    password_hash="not-used-by-dispatch",
                    is_active=True,
                )
            )
            await session.flush()
            session.add(Membership(user_id=user_id, project_id=project_id, role=ProjectRole.VIEWER))
            if channel_scope == "project":
                session.add(
                    NotificationChannel(
                        id=channel_id,
                        project_id=project_id,
                        name=f"channel-{index}",
                        type="webhook",
                        config={"url": f"https://example.test/{user_id}"},
                        is_active=True,
                    )
                )
            elif channel_scope == "personal":
                session.add(
                    UserChannel(
                        id=channel_id,
                        user_id=user_id,
                        name=f"channel-{index}",
                        type="webhook",
                        config={"url": f"https://example.test/{user_id}"},
                        is_active=True,
                    )
                )
            session.add(
                UserSubscription(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    project_id=project_id,
                    trigger="task.failed",
                    filters={},
                    in_app=True,
                    project_channel_ids=[channel_id] if channel_scope == "project" else [],
                    user_channel_ids=[channel_id] if channel_scope == "personal" else [],
                    cooldown_seconds=300,
                    is_active=True,
                )
            )
        await session.commit()
    return project_id


@pytest.mark.parametrize("channel_scope", ["project", "personal", "in-app-only"])
@pytest.mark.parametrize("failed_position", [0, 1], ids=["first-fails", "last-fails"])
async def test_savepoint_failure_discards_only_that_subscription_delivery(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
    channel_scope: str,
    failed_position: int,
) -> None:
    project_id = await _seed(database, channel_scope)
    async with database.session() as session:
        subs = await UserSubscriptionRepository(session).list_active_for_dispatch(
            project_id=project_id, trigger="task.failed"
        )
        failed = subs[failed_position]
        succeeded = subs[1 - failed_position]
        failed_id, failed_user_id = failed.id, failed.user_id
        succeeded_id, succeeded_user_id = succeeded.id, succeeded.user_id

    # A real database error at savepoint exit: INSERT and the earlier
    # cooldown UPDATE must roll back together. The SQLAlchemy transaction
    # machinery, repositories, flush, and commit remain unmocked.
    async with database.engine.begin() as connection:
        await connection.execute(
            text(
                "CREATE TRIGGER reject_notification_staging BEFORE INSERT ON user_notifications "
                f"WHEN NEW.subscription_id = '{failed_id.hex}' "
                "BEGIN SELECT RAISE(ABORT, 'injected notification storage failure'); END"
            )
        )

    calls: list[str] = []

    async def deliver(config: dict, payload: dict) -> DeliveryResult:
        assert payload["trigger"] == "task.failed"
        calls.append(config["url"])
        return DeliveryResult(success=True, status_code=204)

    monkeypatch.setitem(CHANNEL_DISPATCHERS, "webhook", deliver)
    service = NotificationService()
    async with database.session(write=True) as session:
        count = await service.evaluate_and_dispatch(
            session=session, project_id=project_id, trigger="task.failed"
        )

    expected_count = 1 if channel_scope == "in-app-only" else 2
    assert count == expected_count, {"count": count, "outbound_calls": calls}
    assert calls == (
        [] if channel_scope == "in-app-only" else [f"https://example.test/{succeeded_user_id}"]
    )
    async with database.session() as session:
        inbox = (await session.scalars(select(UserNotification))).all()
        audits = (await session.scalars(select(NotificationDelivery))).all()
        assert [row.subscription_id for row in inbox] == [succeeded_id]
        assert [row.subscription_id for row in audits] == (
            [] if channel_scope == "in-app-only" else [succeeded_id]
        )
        failed = await session.get(UserSubscription, failed_id)
        succeeded = await session.get(UserSubscription, succeeded_id)
        assert failed.last_fired_at is None
        assert succeeded.last_fired_at is not None

    # Remove only the storage failure and retry. The failed subscription
    # is eligible; the successful one keeps its committed cooldown.
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP TRIGGER reject_notification_staging"))
    calls.clear()
    async with database.session(write=True) as session:
        count = await service.evaluate_and_dispatch(
            session=session, project_id=project_id, trigger="task.failed"
        )
    assert count == expected_count
    assert calls == (
        [] if channel_scope == "in-app-only" else [f"https://example.test/{failed_user_id}"]
    )
    async with database.session() as session:
        inbox = (await session.scalars(select(UserNotification))).all()
        audits = (await session.scalars(select(NotificationDelivery))).all()
        assert {row.subscription_id for row in inbox} == {succeeded_id, failed_id}
        assert len(inbox) == 2
        assert len(audits) == (0 if channel_scope == "in-app-only" else 2)


@pytest.mark.parametrize("mute_days", [-1, 1], ids=["expired", "active"])
async def test_persisted_sqlite_mute_does_not_abort_other_subscriptions(
    database: DatabaseManager, monkeypatch: pytest.MonkeyPatch, mute_days: int
) -> None:
    project_id = await _seed(database, "project")
    async with database.session(write=True) as session:
        subs = await UserSubscriptionRepository(session).list_active_for_dispatch(
            project_id=project_id, trigger="task.failed"
        )
        muted_id, other_id = subs[0].id, subs[1].id
        subs[0].muted_until = datetime.now(UTC) + timedelta(days=mute_days)
        await session.commit()

    calls: list[str] = []

    async def deliver(config: dict, payload: dict) -> DeliveryResult:
        calls.append(config["url"])
        return DeliveryResult(success=True, status_code=204)

    monkeypatch.setitem(CHANNEL_DISPATCHERS, "webhook", deliver)
    async with database.session(write=True) as session:
        muted = await session.get(UserSubscription, muted_id)
        assert muted.muted_until.tzinfo is None  # SQLite dropped the stored UTC tzinfo.
        count = await NotificationService().evaluate_and_dispatch(
            session=session, project_id=project_id, trigger="task.failed"
        )
    expected_ids = {other_id} if mute_days > 0 else {muted_id, other_id}
    assert count == 2 * len(expected_ids)
    assert len(calls) == len(expected_ids)
    async with database.session() as session:
        inbox = (await session.scalars(select(UserNotification))).all()
        audits = (await session.scalars(select(NotificationDelivery))).all()
        assert {row.subscription_id for row in inbox} == expected_ids
        assert {row.subscription_id for row in audits} == expected_ids
