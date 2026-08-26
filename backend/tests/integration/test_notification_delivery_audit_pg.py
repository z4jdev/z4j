"""PostgreSQL concurrency coverage for external-delivery audit ownership."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from z4j_brain.domain.notifications import channels as channels_module
from z4j_brain.domain.notifications import service as notification_service_module
from z4j_brain.domain.notifications.channels import DeliveryResult
from z4j_brain.domain.notifications.service import NotificationService
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    NotificationDelivery,
    Project,
    User,
    UserChannel,
    UserSubscription,
)

pytestmark = pytest.mark.asyncio


async def _seed_target(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    personal_channel: bool,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    channel_id = uuid.uuid4()
    subscription_id = uuid.uuid4()

    async with session_factory() as session:
        session.add(
            Project(
                id=project_id,
                slug=f"delivery-audit-{project_id.hex[:12]}",
                name="Delivery audit",
            ),
        )
        session.add(
            User(
                id=user_id,
                email=f"delivery-audit-{user_id}@example.invalid",
                password_hash="not-a-login-credential",
                is_active=True,
            ),
        )
        await session.flush()
        session.add(
            Membership(
                user_id=user_id,
                project_id=project_id,
                role=ProjectRole.VIEWER,
            ),
        )
        if personal_channel:
            session.add(
                UserChannel(
                    id=channel_id,
                    user_id=user_id,
                    name="target",
                    type="webhook",
                    config={"url": "https://example.invalid/hook"},
                    is_active=True,
                ),
            )
        else:
            session.add(
                NotificationChannel(
                    id=channel_id,
                    project_id=project_id,
                    name="target",
                    type="webhook",
                    config={"url": "https://example.invalid/hook"},
                    is_active=True,
                ),
            )
        await session.flush()
        session.add(
            UserSubscription(
                id=subscription_id,
                user_id=user_id,
                project_id=project_id,
                trigger="task.failed",
                filters={},
                in_app=False,
                project_channel_ids=[] if personal_channel else [channel_id],
                user_channel_ids=[channel_id] if personal_channel else [],
                cooldown_seconds=0,
                is_active=True,
            ),
        )
        await session.commit()

    return user_id, project_id, channel_id, subscription_id


@pytest.mark.parametrize(
    ("delete_target", "personal_channel"),
    [
        ("subscription", False),
        ("project_channel", False),
        ("user_channel", True),
        ("recipient", False),
    ],
)
async def test_postgres_delete_after_probe_retries_only_stale_nullable_fks(
    migrated_engine,
    monkeypatch: pytest.MonkeyPatch,
    delete_target: str,
    personal_channel: bool,
) -> None:
    """A committed delete after the probes cannot erase an attempted-send audit."""

    Session = async_sessionmaker(migrated_engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
    user_id, project_id, channel_id, subscription_id = await _seed_target(
        Session,
        personal_channel=personal_channel,
    )

    async def _stub_webhook(config, payload) -> DeliveryResult:
        del config, payload
        return DeliveryResult(success=True, status_code=204)

    monkeypatch.setitem(
        channels_module.CHANNEL_DISPATCHERS,
        "webhook",
        _stub_webhook,
    )

    original_flush = notification_service_module._flush_delivery_audit
    flush_calls = 0

    async def _flush_after_target_delete(
        *,
        session: AsyncSession,
        pending: notification_service_module._PendingDelivery,
        outcome: notification_service_module._DeliveryOutcome,
        references: notification_service_module._LiveDeliveryReferences,
        sanitized_error: str | None,
        sanitized_body: str | None,
    ) -> None:
        nonlocal flush_calls
        flush_calls += 1
        if flush_calls == 1:
            async with Session() as delete_session:
                if delete_target == "subscription":
                    statement = delete(UserSubscription).where(
                        UserSubscription.id == subscription_id,
                    )
                elif delete_target == "project_channel":
                    statement = delete(NotificationChannel).where(
                        NotificationChannel.id == channel_id,
                    )
                elif delete_target == "user_channel":
                    statement = delete(UserChannel).where(UserChannel.id == channel_id)
                else:
                    statement = delete(User).where(User.id == user_id)
                await delete_session.execute(statement)
                await delete_session.commit()
        await original_flush(
            session=session,
            pending=pending,
            outcome=outcome,
            references=references,
            sanitized_error=sanitized_error,
            sanitized_body=sanitized_body,
        )

    monkeypatch.setattr(
        notification_service_module,
        "_flush_delivery_audit",
        _flush_after_target_delete,
    )

    async with Session() as session:
        dispatched = await NotificationService().evaluate_and_dispatch(
            session=session,
            project_id=project_id,
            trigger="task.failed",
            task_id=f"postgres-fk-race-{delete_target}",
            task_name="postgres.fk.race",
            project_slug="delivery-audit",
        )

    assert dispatched == 1
    assert flush_calls == 2
    async with Session() as session:
        row = (
            await session.scalars(
                select(NotificationDelivery).where(
                    NotificationDelivery.project_id == project_id,
                ),
            )
        ).one()

    assert row.status == "sent"
    assert row.channel_name == "target"
    assert row.channel_type == "webhook"
    assert row.subscription_id == (
        None if delete_target in {"subscription", "recipient"} else subscription_id
    )
    assert row.recipient_user_id == (None if delete_target == "recipient" else user_id)
    assert row.channel_id == (
        channel_id if not personal_channel and delete_target != "project_channel" else None
    )
    assert row.user_channel_id == (
        channel_id
        if personal_channel and delete_target not in {"user_channel", "recipient"}
        else None
    )
