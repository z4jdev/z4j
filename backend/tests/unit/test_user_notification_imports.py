"""Regression tests for project -> personal notification channel imports."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.api.user_notifications import (
    UserChannelImportFromProjectRequest,
    import_user_channel_from_project,
)
from z4j_brain.errors import AuthorizationError
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, User
from z4j_brain.persistence.models.notification import (
    NotificationChannel,
    UserChannel,
)
from z4j_brain.persistence.repositories import (
    MembershipRepository,
    ProjectRepository,
)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _seed_project_channel(
    session: AsyncSession,
    *,
    role: ProjectRole,
    channel_type: str = "pagerduty",
    config: dict[str, str] | None = None,
) -> tuple[Project, User, NotificationChannel]:
    project = Project(slug=f"source-{role.value}", name="Source")
    user = User(
        email=f"{role.value}-{uuid.uuid4()}@example.com",
        password_hash="x",
        is_admin=False,
        is_active=True,
    )
    session.add_all([project, user])
    await session.flush()
    session.add(
        Membership(
            user_id=user.id,
            project_id=project.id,
            role=role,
        ),
    )
    channel = NotificationChannel(
        project_id=project.id,
        name="Primary PagerDuty",
        type=channel_type,
        config=config if config is not None else {"integration_key": "SecretKey123"},
        is_active=True,
    )
    session.add(channel)
    await session.commit()
    return project, user, channel


@pytest.mark.asyncio
class TestProjectChannelImport:
    async def test_viewer_cannot_clone_project_channel_secret(
        self,
        session: AsyncSession,
    ) -> None:
        project, user, channel = await _seed_project_channel(
            session,
            role=ProjectRole.VIEWER,
        )

        with pytest.raises(AuthorizationError):
            await import_user_channel_from_project(
                UserChannelImportFromProjectRequest(
                    project_slug=project.slug,
                    channel_id=channel.id,
                ),
                user,
                MembershipRepository(session),
                ProjectRepository(session),
                session,
            )

        count = await session.scalar(select(func.count()).select_from(UserChannel))
        assert count == 0

    async def test_project_admin_can_clone_project_channel_secret(
        self,
        session: AsyncSession,
    ) -> None:
        project, user, channel = await _seed_project_channel(
            session,
            role=ProjectRole.ADMIN,
        )

        response = await import_user_channel_from_project(
            UserChannelImportFromProjectRequest(
                project_slug=project.slug,
                channel_id=channel.id,
                name="Personal PD",
            ),
            user,
            MembershipRepository(session),
            ProjectRepository(session),
            session,
        )

        assert response.name == "Personal PD"
        assert response.config["integration_key"] != "SecretKey123"

        copied = await session.scalar(select(UserChannel))
        assert copied is not None
        assert copied.user_id == user.id
        assert copied.config["integration_key"] == "SecretKey123"

    @pytest.mark.parametrize(
        ("channel_type", "secret_key", "secret_value"),
        [
            (
                "webhook",
                "url",
                "https://hooks.example.test/delivery/bearer-secret",
            ),
            (
                "slack",
                "webhook_url",
                "https://hooks.slack.com/services/T000/B000/bearer-secret",
            ),
        ],
    )
    async def test_import_never_returns_secret_bearing_url(
        self,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        channel_type: str,
        secret_key: str,
        secret_value: str,
    ) -> None:
        async def _accept_test_config(
            candidate_type: str,
            candidate_config: dict[str, str],
        ) -> None:
            assert candidate_type == channel_type
            assert candidate_config[secret_key] == secret_value

        monkeypatch.setattr(
            "z4j_brain.api.user_notifications._validate_channel_config",
            _accept_test_config,
        )
        project, user, channel = await _seed_project_channel(
            session,
            role=ProjectRole.ADMIN,
            channel_type=channel_type,
            config={secret_key: secret_value},
        )

        response = await import_user_channel_from_project(
            UserChannelImportFromProjectRequest(
                project_slug=project.slug,
                channel_id=channel.id,
            ),
            user,
            MembershipRepository(session),
            ProjectRepository(session),
            session,
        )

        assert response.config[secret_key] == "••••••••"
        assert secret_value not in response.model_dump_json()

        copied = await session.scalar(select(UserChannel))
        assert copied is not None
        assert copied.config[secret_key] == secret_value
