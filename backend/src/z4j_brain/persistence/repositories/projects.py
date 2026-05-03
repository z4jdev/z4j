"""``projects`` repository.

In B3 the only writer is the setup service, which creates the
``default`` project on first boot. Project CRUD endpoints land in
B5 - they reuse this same repository.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Project
from z4j_brain.persistence.repositories._base import BaseRepository

# Mirrors the ``slug_format`` CHECK constraint on ``projects.slug``
# (migration ``2026_04_15_0001-initial_schema``) and the
# creation-side ``_SLUG_RE`` in ``api/projects.py``. Any slug that
# doesn't match this shape cannot exist in the DB, so we short-
# circuit to ``None`` before the query runs. Pre-validation
# prevents ``asyncpg.CharacterNotInRepertoireError`` on path
# params that carry NUL (``0x00``) or other bytes Postgres
# refuses to accept as UTF-8 text - surfaced by the 2026-04-21
# Pass 5 security audit as finding S1 (null-byte injection
# turning a slug lookup into an unhandled HTTP 500).
_SLUG_SAFE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$")


class ProjectRepository(BaseRepository[Project]):
    """Project CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Project)

    async def get_by_slug(self, slug: str) -> Project | None:
        """Lookup by slug. Slug is unique per project.

        Returns ``None`` for slugs that cannot possibly exist -
        wrong length, wrong characters, contains NUL/control bytes
        - without making a DB round-trip. Callers that already
        did their own shape-check pay one extra regex match;
        callers that didn't stay safe.
        """
        if not _SLUG_SAFE_RE.match(slug):
            return None
        result = await self.session.execute(
            select(Project).where(Project.slug == slug),
        )
        return result.scalar_one_or_none()

    async def list_by_ids(
        self, ids: Iterable[UUID], *, only_active: bool = False,
    ) -> list[Project]:
        """Batch lookup. One ``IN``-query, not N round-trips.

        Used by every endpoint that resolves a user's membership
        list to the matching project rows. The naive per-id loop
        was the dominant N+1 in the dashboard's home / project-
        switcher / change-password flows.
        """
        ids_list = list(ids)
        if not ids_list:
            return []
        stmt = select(Project).where(Project.id.in_(ids_list))
        if only_active:
            stmt = stmt.where(Project.is_active.is_(True))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_active(self) -> int:
        """Return the number of active (non-archived) projects."""
        result = await self.session.execute(
            select(func.count())
            .select_from(Project)
            .where(Project.is_active.is_(True)),
        )
        return int(result.scalar_one())


__all__ = ["ProjectRepository"]
