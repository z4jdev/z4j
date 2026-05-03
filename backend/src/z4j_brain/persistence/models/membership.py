"""``memberships`` table - user ↔ project with role.

A user joins a project via a membership row. The role on that row
controls what the user can do *within* that project - separate from
the global :attr:`User.is_admin` flag.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class Membership(PKMixin, TimestampsMixin, Base):
    """A user's role within a single project.

    The same user may have different roles in different projects;
    the global :attr:`User.is_admin` flag is independent and only
    affects the brain-level admin endpoints (project CRUD, user CRUD).

    Attributes:
        user_id: Owning user. ``ON DELETE CASCADE`` - deleting a
            user removes their memberships.
        project_id: Owning project. ``ON DELETE CASCADE`` - deleting
            a project removes its memberships.
        role: ``viewer`` (read-only), ``operator`` (issue commands),
            or ``admin`` (manage memberships and tokens).
    """

    __tablename__ = "memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[ProjectRole] = mapped_column(
        Enum(
            ProjectRole,
            name="project_role",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=ProjectRole.VIEWER,
        server_default=ProjectRole.VIEWER.value,
    )

    __table_args__ = (
        UniqueConstraint("user_id", "project_id", name="uq_memberships_user_project"),
    )


__all__ = ["Membership"]
