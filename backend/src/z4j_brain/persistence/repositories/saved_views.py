"""Personal view persistence, bounded and scoped on every read and write."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.models import SavedView, User

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

MAX_VIEWS = 100


class SavedViewRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_owner(self, user_id: uuid.UUID, project_id: uuid.UUID) -> list[SavedView]:
        result = await self.session.scalars(
            select(SavedView)
            .where(
                SavedView.user_id == user_id,
                SavedView.project_id == project_id,
                SavedView.page == "tasks",
            )
            .order_by(SavedView.name, SavedView.id),
        )
        return list(result)

    async def _locked_views(self, user_id: uuid.UUID, project_id: uuid.UUID) -> list[SavedView]:
        # PostgreSQL serializes this owner's writes across Brain replicas.
        # SQLite mutations already reserve the writer in get_session before
        # the first read, so both backends enforce the cap/name check atomically.
        await self.session.execute(select(User.id).where(User.id == user_id).with_for_update())
        return await self.list_for_owner(user_id, project_id)

    async def save(
        self,
        user_id: uuid.UUID,
        project_id: uuid.UUID,
        *,
        name: str,
        filters: dict[str, Any],
        view_id: uuid.UUID | None = None,
    ) -> SavedView:
        views = await self._locked_views(user_id, project_id)
        existing = next((view for view in views if view.id == view_id), None)
        if view_id is not None and existing is None:
            raise NotFoundError("saved view not found")
        if any(view.id != view_id and view.name.casefold() == name.casefold() for view in views):
            raise ConflictError("A saved view with this name already exists in this project.")
        if existing is None:
            if len(views) >= MAX_VIEWS:
                raise ConflictError(
                    "This project already has 100 personal task views. Delete a view first."
                )
            existing = SavedView(user_id=user_id, project_id=project_id, page="tasks", name=name)
            self.session.add(existing)
        existing.name = name
        existing.filters = filters
        await self.session.flush()
        await self.session.refresh(existing)
        return existing

    async def delete(self, user_id: uuid.UUID, project_id: uuid.UUID, view_id: uuid.UUID) -> None:
        views = await self._locked_views(user_id, project_id)
        view = next((item for item in views if item.id == view_id), None)
        if view is None:
            raise NotFoundError("saved view not found")
        await self.session.delete(view)
