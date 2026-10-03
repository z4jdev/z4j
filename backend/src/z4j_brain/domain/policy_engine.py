"""Project membership / role policy.

Routes call :class:`PolicyEngine` to verify "this user can perform this
action on this project". The engine raises :class:`AuthorizationError`
on denial; routes never do their own role math.

The role vocabulary is not defined here. The role order and the
role-to-action table live in :mod:`z4j_core.policy` (decision D-4: core
is authoritative) and this module takes both from there. What this
module adds is everything that needs the database or the HTTP contract:
resolving the project by slug, loading the caller's membership,
synthesising the instance-admin membership, and answering 404 rather
than 403 to a non-member so project slugs cannot be enumerated. A
contract test under ``tests/contract`` enumerates every (role, action)
pair through both engines and fails when they disagree.

Routes may state their requirement either as an :class:`Action` (the
preferred form; the required role comes from the core table) or as a
``min_role`` floor (the historical form, still a core role). Both go
through the same comparison.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from z4j_core.policy import (
    Action,
    action_allowed,
    action_required_role,
    role_rank,
    role_satisfies,
)

from z4j_brain.errors import AuthorizationError, NotFoundError
from z4j_brain.persistence.enums import ProjectRole

# Mirrors ``_SLUG_RE`` in ``api/projects.py`` (the public creation/update
# validator): one alnum, then 1..48 alnum/hyphen, then one alnum. The database
# constraint is deliberately broader and is not the authority for URL input.
# We short-circuit non-canonical public slugs here to avoid a DB round-trip and
# avoid shipping control bytes (notably NUL ``0x00``) into the
# ``asyncpg`` driver, which raises ``CharacterNotInRepertoireError``
# and produces a generic HTTP 500 instead of the clean 404 the
# caller deserves (e.g. ``GET /projects/default%00b/tasks``).
_SLUG_SAFE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$")

if TYPE_CHECKING:
    from z4j_brain.persistence.models import Membership, Project, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


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
        if _SLUG_SAFE_RE.fullmatch(slug) is None:
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
        project: Project,
        min_role: ProjectRole | None = None,
        action: Action | None = None,
    ) -> Membership:
        """Verify ``user`` may act on ``project`` and return the membership.

        Exactly one of ``action`` and ``min_role`` must be given.
        ``action`` is decided by the core table
        (:func:`z4j_core.policy.action_allowed`, which keeps the audit
        tier away from operators); ``min_role`` is a rank floor
        (:func:`z4j_core.policy.role_satisfies`). Audit routes must
        name the action: a ``min_role`` of ``auditor`` would admit
        every higher rank, operator included, which is exactly the
        separation the auditor role exists to keep.

        Global brain admins (``user.is_admin``) bypass the check -
        they always have admin-equivalent access on every project.
        Returns the membership row on success so callers can
        inspect the actual role.

        When a non-admin user has NO membership on a project,
        raises 404 ``project not found`` instead of 403, so the
        response is byte-identical to ``get_project_or_404`` for
        nonexistent slugs. A 403/404 split would otherwise let
        any authenticated user enumerate every project slug in
        the brain. The insufficient-role branch keeps 403 because
        at that point the user already PROVED membership and the
        slug is not a secret to them.
        """
        if (action is None) == (min_role is None):
            raise TypeError("require_member needs exactly one of action= or min_role=")
        if action is not None:
            required = action_required_role(action)

            def _permits(held: ProjectRole) -> bool:
                return action_allowed(held, action)

        else:
            required = min_role  # type: ignore[assignment]

            def _permits(held: ProjectRole) -> bool:
                return role_satisfies(held, required)

        if user.is_admin:
            # Synthesize an admin-grade membership row for the
            # bypass case. We do NOT touch the database - there
            # may not even be a membership row for a global admin.
            from z4j_brain.persistence.models import Membership

            return Membership(
                user_id=user.id,
                project_id=project.id,
                role=ProjectRole.ADMIN,
            )

        all_memberships = await memberships.list_for_user(user.id)
        for m in all_memberships:
            if m.project_id == project.id:
                if _permits(m.role):
                    return m
                raise AuthorizationError(
                    f"role {m.role.value!r} is not sufficient (need at least {required.value!r})",
                    details={"have": m.role.value, "need": required.value},
                )
        # S-3: indistinguishable from a true 404 for non-admins.
        raise NotFoundError(
            f"project {project.slug!r} not found",
            details={"slug": project.slug},
        )


__all__ = ["Action", "PolicyEngine", "action_allowed", "role_rank"]
