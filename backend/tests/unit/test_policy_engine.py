"""Tests for ``z4j_brain.domain.policy_engine``."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.domain.policy_engine import PolicyEngine, role_rank
from z4j_brain.errors import AuthorizationError, NotFoundError
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, User
from z4j_brain.persistence.repositories import (
    MembershipRepository,
    ProjectRepository,
)


class TestRoleRank:
    def test_admin_outranks_operator(self) -> None:
        assert role_rank(ProjectRole.ADMIN) > role_rank(ProjectRole.OPERATOR)

    def test_operator_outranks_viewer(self) -> None:
        assert role_rank(ProjectRole.OPERATOR) > role_rank(ProjectRole.VIEWER)


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
async def viewer_user(session: AsyncSession, project: Project) -> User:
    user = User(
        email="viewer@example.com",
        password_hash="x",
        is_admin=False,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    session.add(Membership(user_id=user.id, project_id=project.id, role=ProjectRole.VIEWER))
    await session.commit()
    return user


@pytest.fixture
async def operator_user(session: AsyncSession, project: Project) -> User:
    user = User(
        email="op@example.com",
        password_hash="x",
        is_admin=False,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    session.add(Membership(user_id=user.id, project_id=project.id, role=ProjectRole.OPERATOR))
    await session.commit()
    return user


@pytest.fixture
async def global_admin(session: AsyncSession) -> User:
    user = User(
        email="admin@example.com",
        password_hash="x",
        is_admin=True,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    return user


@pytest.mark.asyncio
class TestGetProject:
    async def test_get_project_or_404_found(
        self, session: AsyncSession, project: Project,  # noqa: ARG002
    ) -> None:
        policy = PolicyEngine()
        projects = ProjectRepository(session)
        result = await policy.get_project_or_404(projects, "default")
        assert result.slug == "default"

    async def test_get_project_or_404_missing(
        self, session: AsyncSession,
    ) -> None:
        policy = PolicyEngine()
        projects = ProjectRepository(session)
        with pytest.raises(NotFoundError):
            await policy.get_project_or_404(projects, "nope")


@pytest.mark.asyncio
class TestRequireMember:
    async def test_viewer_can_view(
        self,
        session: AsyncSession,
        project: Project,
        viewer_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        membership = await policy.require_member(
            memberships,
            user=viewer_user,
            project_id=project.id,
            min_role=ProjectRole.VIEWER,
        )
        assert membership.role == ProjectRole.VIEWER

    async def test_viewer_cannot_operate(
        self,
        session: AsyncSession,
        project: Project,
        viewer_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        with pytest.raises(AuthorizationError):
            await policy.require_member(
                memberships,
                user=viewer_user,
                project_id=project.id,
                min_role=ProjectRole.OPERATOR,
            )

    async def test_operator_can_view(
        self,
        session: AsyncSession,
        project: Project,
        operator_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        membership = await policy.require_member(
            memberships,
            user=operator_user,
            project_id=project.id,
            min_role=ProjectRole.VIEWER,
        )
        assert membership.role == ProjectRole.OPERATOR

    async def test_global_admin_bypasses(
        self,
        session: AsyncSession,
        project: Project,
        global_admin: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        # No membership row exists; admin must still pass.
        membership = await policy.require_member(
            memberships,
            user=global_admin,
            project_id=project.id,
            min_role=ProjectRole.ADMIN,
        )
        assert membership.role == ProjectRole.ADMIN

    async def test_no_membership_denied(
        self,
        session: AsyncSession,
        global_admin: User,  # not actually used
    ) -> None:
        # Create a non-admin user with no memberships at all.
        user = User(email="lone@example.com", password_hash="x", is_admin=False, is_active=True)
        session.add(user)
        await session.commit()

        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        with pytest.raises(AuthorizationError):
            await policy.require_member(
                memberships,
                user=user,
                project_id=uuid.uuid4(),
                min_role=ProjectRole.VIEWER,
            )
