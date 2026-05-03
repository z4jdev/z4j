"""Regression test for the v1.0.0..v1.0.16 SQLite uuid_array bug.

``uuid_array()`` falls back to ``JSON`` on SQLite. Pre-v1.0.17 the
fallback was raw SQLAlchemy ``JSON``, which calls ``json.dumps`` on
the bind value. ``json.dumps`` cannot serialize ``uuid.UUID``
instances - so any write to a ``list[UUID]`` column raised
``TypeError: Object of type UUID is not JSON serializable``, which
the brain's error middleware mapped to a generic 500 response with
``message: "the brain encountered an unexpected error"``.

Three production columns hit this bug:
- ``user_subscriptions.project_channel_ids``
- ``user_subscriptions.user_channel_ids``
- ``project_default_subscriptions.project_channel_ids``

Reported live by an operator on tasks.jfk.work who tried to save a
default subscription with three project channel ids.

The fix: a ``TypeDecorator`` that converts UUIDs to strings on
write and back to UUIDs on read. This file pins the fix so any
future regression (e.g. someone reverting to plain JSON, or
landing a new ``list[UUID]`` column without using ``uuid_array()``)
fails loudly.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import (
    NotificationChannel,
    Project,
    ProjectDefaultSubscription,
    User,
    UserSubscription,
)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="default", name="Default")
    session.add(p)
    await session.commit()
    return p


@pytest.fixture
async def channels(
    session: AsyncSession, project: Project,
) -> list[NotificationChannel]:
    chs = [
        NotificationChannel(
            project_id=project.id,
            type="webhook",
            name=f"ch-{i}",
            config={"url": f"https://example.test/{i}"},
        )
        for i in range(3)
    ]
    for ch in chs:
        session.add(ch)
    await session.commit()
    return chs


@pytest.mark.asyncio
class TestProjectDefaultSubscriptionWithChannels:
    async def test_create_with_uuid_channel_ids_round_trips(
        self,
        session: AsyncSession,
        project: Project,
        channels: list[NotificationChannel],
    ) -> None:
        """The exact failure path from the live operator report.

        Pre-fix: writing a ``ProjectDefaultSubscription`` with a
        non-empty ``project_channel_ids`` list raised
        ``TypeError: Object of type UUID is not JSON serializable``
        on commit. Post-fix: round-trips cleanly with UUIDs preserved.
        """
        sub = ProjectDefaultSubscription(
            project_id=project.id,
            trigger="task.failed",
            filters={},
            in_app=True,
            project_channel_ids=[ch.id for ch in channels],
            cooldown_seconds=300,
        )
        session.add(sub)
        await session.commit()
        await session.refresh(sub)

        # Assert the IDs round-trip as UUIDs (matches the Postgres
        # path's behavior so callers don't need a dialect-aware cast).
        assert isinstance(sub.project_channel_ids, list)
        assert len(sub.project_channel_ids) == 3
        for stored, original in zip(
            sub.project_channel_ids, channels, strict=True,
        ):
            assert isinstance(stored, uuid.UUID), (
                f"expected UUID, got {type(stored)}: {stored!r}"
            )
            assert stored == original.id

    async def test_empty_list_round_trips(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """The other common case: in_app-only default with no channels."""
        sub = ProjectDefaultSubscription(
            project_id=project.id,
            trigger="task.succeeded",
            filters={},
            in_app=True,
            project_channel_ids=[],
            cooldown_seconds=0,
        )
        session.add(sub)
        await session.commit()
        await session.refresh(sub)
        assert sub.project_channel_ids == []

    async def test_separate_select_returns_uuids(
        self,
        session: AsyncSession,
        project: Project,
        channels: list[NotificationChannel],
    ) -> None:
        """A cold-cache SELECT also gets UUIDs back.

        Catches a refactor that accidentally only normalises on
        write but leaves read returning raw strings. We close out
        the writing session and open a fresh one for the read so
        the ORM identity map can't paper over a missing decoder.
        """
        bind = await session.connection()
        engine = bind.engine
        sub_id = uuid.uuid4()
        sub = ProjectDefaultSubscription(
            id=sub_id,
            project_id=project.id,
            trigger="task.failed",
            filters={},
            in_app=False,
            project_channel_ids=[channels[0].id, channels[2].id],
            cooldown_seconds=60,
        )
        session.add(sub)
        await session.commit()

        # Fresh session (no identity map carryover).
        from sqlalchemy.orm import sessionmaker as _sm

        factory = _sm(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as fresh:
            result = await fresh.execute(
                select(ProjectDefaultSubscription).where(
                    ProjectDefaultSubscription.id == sub_id,
                ),
            )
            loaded = result.scalar_one()
            assert all(
                isinstance(i, uuid.UUID) for i in loaded.project_channel_ids
            )
            assert loaded.project_channel_ids == [
                channels[0].id, channels[2].id,
            ]


@pytest.mark.asyncio
class TestUserSubscriptionWithChannels:
    async def test_user_subscription_uuid_arrays_round_trip(
        self,
        session: AsyncSession,
        project: Project,
        channels: list[NotificationChannel],
    ) -> None:
        """Same defect on the per-user subscription path."""
        user = User(
            email="alice@example.com",
            password_hash=secrets.token_hex(32),
            is_admin=False,
            is_active=True,
        )
        session.add(user)
        await session.commit()

        sub = UserSubscription(
            user_id=user.id,
            project_id=project.id,
            trigger="task.failed",
            filters={},
            in_app=True,
            project_channel_ids=[channels[0].id, channels[1].id],
            user_channel_ids=[],
            cooldown_seconds=120,
        )
        session.add(sub)
        await session.commit()
        await session.refresh(sub)

        assert all(
            isinstance(i, uuid.UUID) for i in sub.project_channel_ids
        )
        assert sub.project_channel_ids == [channels[0].id, channels[1].id]
        assert sub.user_channel_ids == []
