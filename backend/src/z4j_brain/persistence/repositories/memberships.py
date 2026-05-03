"""``memberships`` repository.

In B3 the only writer is the setup service, which grants the
bootstrap admin a membership on the ``default`` project. The
``list_for_user`` finder is used by the auth service's
:meth:`current_user` payload assembly to expose project roles
to the dashboard.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership
from z4j_brain.persistence.repositories._base import BaseRepository


class MembershipRepository(BaseRepository[Membership]):
    """Membership CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Membership)

    async def grant(
        self,
        *,
        user_id: UUID,
        project_id: UUID,
        role: ProjectRole,
    ) -> Membership:
        """Insert a fresh membership row.

        Caller is responsible for the unique-constraint contract:
        the ``(user_id, project_id)`` pair must not already exist.
        """
        row = Membership(user_id=user_id, project_id=project_id, role=role)
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_for_user(self, user_id: UUID) -> list[Membership]:
        """Return every membership row for one user.

        Bounded by the user's project count, never large enough to
        justify pagination in v1.
        """
        result = await self.session.execute(
            select(Membership).where(Membership.user_id == user_id),
        )
        return list(result.scalars().all())

    async def list_for_project(self, project_id: UUID) -> list[Membership]:
        """Return every membership row for one project."""
        result = await self.session.execute(
            select(Membership)
            .where(Membership.project_id == project_id)
            .order_by(Membership.created_at.asc()),
        )
        return list(result.scalars().all())

    async def get_for_user_project(
        self, *, user_id: UUID, project_id: UUID,
    ) -> Membership | None:
        """Return the membership for a specific user on a specific project."""
        result = await self.session.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.project_id == project_id,
            ),
        )
        return result.scalars().first()

    async def count_admins_for_project(self, project_id: UUID) -> int:
        """Return the number of ``ADMIN``-role memberships on a project.

        Used by update / revoke endpoints to refuse operations that
        would leave the project with zero admins, which would lock
        every member out of admin-scoped settings (members, channels,
        default subscriptions, delivery log).
        """
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.project_id == project_id,
                Membership.role == ProjectRole.ADMIN,
            ),
        )
        return int(result.scalar_one() or 0)

    async def count_admins_for_project_for_update(
        self, project_id: UUID,
    ) -> int:
        """Row-locking variant of :meth:`count_admins_for_project`.

        Closes the TOCTOU window between concurrent project-admin
        demotions / revocations (two admins in the same project
        editing each other in parallel). See
        ``UserRepository.count_active_admins_for_update`` for the
        full explanation.
        """
        stmt = (
            select(Membership.id)
            .where(
                Membership.project_id == project_id,
                Membership.role == ProjectRole.ADMIN,
            )
            .with_for_update(of=Membership)
        )
        result = await self.session.execute(stmt)
        return len(list(result.scalars().all()))

    async def list_active_user_ids_for_project(
        self, project_id: UUID,
    ) -> set[UUID]:
        """Return the set of user_ids that are currently members of
        the project. Used by the notification dispatcher to batch the
        membership check that otherwise costs one SELECT per subscription.
        """
        result = await self.session.execute(
            select(Membership.user_id).where(
                Membership.project_id == project_id,
            ),
        )
        return {row[0] for row in result.all()}


__all__ = ["MembershipRepository"]
