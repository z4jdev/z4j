"""Project membership / role policy.

The brain has three roles per :class:`ProjectRole`: ``viewer``,
``operator``, ``admin``. Routes call :class:`PolicyEngine` to
verify "this user can perform this action on this project". The
engine raises :class:`AuthorizationError` on denial; routes never
do their own role math.

The policy is small enough in v1 to fit in one class. When the
brain grows resource-level permissions in Phase 2 we'll add a
real ABAC layer; for now, role-on-project is sufficient.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from uuid import UUID

from z4j_brain.errors import AuthorizationError, NotFoundError
from z4j_brain.persistence.enums import ProjectRole

# Mirrors ``_SLUG_RE`` in ``api/projects.py`` (the creation-side
# validator): one alnum, then 1..48 alnum/hyphen, then one alnum.
# Any slug that doesn't match this shape cannot possibly exist in
# the database - the CHECK constraint on ``projects.slug``
# (migration ``2026_04_15_0001-initial_schema``) rejects it. We
# short-circuit here to avoid a DB round-trip AND to avoid
# shipping control bytes (notably NUL ``0x00``) into the
# ``asyncpg`` driver, which raises ``CharacterNotInRepertoireError``
# and produces a generic HTTP 500 instead of the clean 404 the
# caller deserves. Pass 5 security audit on 2026-04-21 surfaced
# this as finding S1 via ``GET /projects/default%00b/tasks``.
_SLUG_SAFE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$")

if TYPE_CHECKING:
    from z4j_brain.persistence.models import Membership, Project, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


_ROLE_RANK: dict[ProjectRole, int] = {
    ProjectRole.VIEWER: 0,
    ProjectRole.OPERATOR: 1,
    ProjectRole.ADMIN: 2,
}


def role_rank(role: ProjectRole) -> int:
    """Return a comparable integer rank for a role."""
    return _ROLE_RANK[role]


class PolicyEngine:
    """Stateless permission checks. Construct once per request."""

    async def get_project_or_404(
        self,
        projects: ProjectRepository,
        slug: str,
    ) -> Project:
        """Resolve a project by slug or raise 404.

        Validates the slug shape BEFORE the DB query. Callers can
        put anything in a path param - FastAPI doesn't enforce the
        slug's own format constraint - so a slug like
        ``"default\\x00b"`` would otherwise reach ``asyncpg`` and
        raise ``CharacterNotInRepertoireError`` (HTTP 500). The
        short-circuit returns the clean 404 the user would get for
        any other unknown slug, with no leak of internal errors
        and no pollution of the ``error``-level log with
        attacker-triggerable stack traces.
        """
        if not _SLUG_SAFE_RE.match(slug):
            raise NotFoundError(
                f"project {slug!r} not found",
                details={"slug": slug},
            )
        project = await projects.get_by_slug(slug)
        if project is None or not project.is_active:
            raise NotFoundError(
                f"project {slug!r} not found",
                details={"slug": slug},
            )
        return project

    async def require_member(
        self,
        memberships: MembershipRepository,
        *,
        user: User,
        project_id: UUID,
        min_role: ProjectRole,
    ) -> Membership:
        """Verify ``user`` has at least ``min_role`` on ``project_id``.

        Global brain admins (``user.is_admin``) bypass the check -
        they always have admin-equivalent access on every project.
        Returns the membership row on success so callers can
        inspect the actual role.
        """
        if user.is_admin:
            # Synthesize an admin-grade membership row for the
            # bypass case. We do NOT touch the database - there
            # may not even be a membership row for a global admin.
            from z4j_brain.persistence.models import Membership

            return Membership(
                user_id=user.id,
                project_id=project_id,
                role=ProjectRole.ADMIN,
            )

        all_memberships = await memberships.list_for_user(user.id)
        for m in all_memberships:
            if m.project_id == project_id:
                if role_rank(m.role) >= role_rank(min_role):
                    return m
                raise AuthorizationError(
                    f"role {m.role.value!r} is not sufficient "
                    f"(need at least {min_role.value!r})",
                    details={"have": m.role.value, "need": min_role.value},
                )
        raise AuthorizationError(
            "no membership on this project",
            details={"need": min_role.value},
        )


__all__ = ["PolicyEngine", "role_rank"]
