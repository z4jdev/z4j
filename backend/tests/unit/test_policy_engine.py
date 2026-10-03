"""Tests for ``z4j_brain.domain.policy_engine``."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.policy_engine import Action, PolicyEngine, role_rank
from z4j_brain.errors import AuthorizationError, NotFoundError
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, User
from z4j_brain.persistence.repositories import (
    MembershipRepository,
    ProjectRepository,
)


class TestRoleRank:
    def test_admin_outranks_operator(self) -> None:
        assert role_rank(ProjectRole.ADMIN) > role_rank(ProjectRole.OPERATOR)

    def test_operator_outranks_auditor(self) -> None:
        assert role_rank(ProjectRole.OPERATOR) > role_rank(ProjectRole.AUDITOR)

    def test_auditor_outranks_viewer(self) -> None:
        assert role_rank(ProjectRole.AUDITOR) > role_rank(ProjectRole.VIEWER)

    def test_rank_is_the_core_table(self) -> None:
        # D-4: the brain carries no role order of its own.
        import z4j_brain.domain.policy_engine as brain_policy
        from z4j_core.policy import ROLE_ORDER
        from z4j_core.policy import role_rank as core_role_rank

        assert brain_policy.role_rank is core_role_rank
        assert not hasattr(brain_policy, "_ROLE_RANK")
        assert {role: role_rank(role) for role in ProjectRole} == ROLE_ORDER


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
async def auditor_user(session: AsyncSession, project: Project) -> User:
    user = User(
        email="auditor@example.com",
        password_hash="x",
        is_admin=False,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    session.add(Membership(user_id=user.id, project_id=project.id, role=ProjectRole.AUDITOR))
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
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        policy = PolicyEngine()
        projects = ProjectRepository(session)
        result = await policy.get_project_or_404(projects, "default")
        assert result.slug == "default"

    async def test_get_project_or_404_missing(
        self,
        session: AsyncSession,
    ) -> None:
        policy = PolicyEngine()
        projects = ProjectRepository(session)
        with pytest.raises(NotFoundError):
            await policy.get_project_or_404(projects, "nope")

    @pytest.mark.parametrize(
        "slug",
        [
            "aa",  # public project creation requires at least three characters
            "a" * 51,
            "Uppercase",
            "under_score",
            "abc\n",
            "-abc",
            "abc-",
        ],
    )
    async def test_noncanonical_slug_is_rejected_without_querying(self, slug: str) -> None:
        projects = AsyncMock(spec=ProjectRepository)

        with pytest.raises(NotFoundError):
            await PolicyEngine().get_project_or_404(projects, slug)

        projects.get_by_slug.assert_not_awaited()

    async def test_three_character_slug_reaches_the_repository(self) -> None:
        projects = AsyncMock(spec=ProjectRepository)
        projects.get_by_slug.return_value = None

        with pytest.raises(NotFoundError):
            await PolicyEngine().get_project_or_404(projects, "a-b")

        projects.get_by_slug.assert_awaited_once_with("a-b")


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
            project=project,
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
                project=project,
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
            project=project,
            min_role=ProjectRole.VIEWER,
        )
        assert membership.role == ProjectRole.OPERATOR

    async def test_action_resolves_through_the_core_table(
        self,
        session: AsyncSession,
        project: Project,
        auditor_user: User,
        operator_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        membership = await policy.require_member(
            memberships,
            user=auditor_user,
            project=project,
            action=Action.READ_AUDIT,
        )
        assert membership.role == ProjectRole.AUDITOR
        # The denial names the role the core table requires, so the
        # 403 envelope's ``need`` is the same vocabulary the docs use.
        with pytest.raises(AuthorizationError) as denied:
            await policy.require_member(
                memberships,
                user=operator_user,
                project=project,
                action=Action.READ_AUDIT,
            )
        assert denied.value.details == {"have": "operator", "need": "auditor"}
        with pytest.raises(AuthorizationError) as denied:
            await policy.require_member(
                memberships,
                user=auditor_user,
                project=project,
                action=Action.RETRY_TASK,
            )
        assert denied.value.details == {"have": "auditor", "need": "operator"}

    async def test_auditor_is_a_member_for_viewer_floors(
        self,
        session: AsyncSession,
        project: Project,
        auditor_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        membership = await policy.require_member(
            memberships,
            user=auditor_user,
            project=project,
            min_role=ProjectRole.VIEWER,
        )
        assert membership.role == ProjectRole.AUDITOR
        with pytest.raises(AuthorizationError):
            await policy.require_member(
                memberships,
                user=auditor_user,
                project=project,
                min_role=ProjectRole.OPERATOR,
            )

    async def test_exactly_one_of_action_or_min_role(
        self,
        session: AsyncSession,
        project: Project,
        viewer_user: User,
    ) -> None:
        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        with pytest.raises(TypeError):
            await policy.require_member(memberships, user=viewer_user, project=project)
        with pytest.raises(TypeError):
            await policy.require_member(
                memberships,
                user=viewer_user,
                project=project,
                min_role=ProjectRole.VIEWER,
                action=Action.READ_PROJECT,
            )

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
            project=project,
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
        # S-3 (2026-05): non-member denial returns 404, not 403.
        # Build a synthetic Project so we can pass it positionally.
        from z4j_brain.persistence.models import Project as _Proj

        ghost = _Proj(slug="nope")
        # Stash an id without committing - the test only reads
        # ``project.id`` and ``project.slug`` inside the helper.
        ghost.id = uuid.uuid4()  # type: ignore[assignment]

        policy = PolicyEngine()
        memberships = MembershipRepository(session)
        with pytest.raises(NotFoundError):
            await policy.require_member(
                memberships,
                user=user,
                project=ghost,
                min_role=ProjectRole.VIEWER,
            )
