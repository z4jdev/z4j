"""Key-value storage tables for extensible configuration.

Three scoped K/V stores for different use cases:

``user_preferences``
    Per-user settings (theme, notification level, locale, etc.).
    Scoped to a user_id. The dashboard reads these on login.
    Example keys: ``theme``, ``notification_level``, ``locale``,
    ``sidebar_collapsed``, ``default_project``.

``project_config``
    Per-project overrides and plugin configuration.
    Scoped to a project_id. Agents and the brain read these.
    Example keys: ``retention_days_override``, ``alert_cooldown``,
    ``plugin.sentry.dsn``, ``plugin.datadog.api_key``.

``extension_store``
    Global schemaless storage for plugins and extensions.
    The WordPress wp_options equivalent. Namespaced by convention:
    plugins prefix their keys (e.g., ``ext.slack.workspace_id``).
    The brain never reads this directly - only plugins do.

Design decisions:
- Separate tables (not one mega-table) for query performance
- JSONB ``value`` column (not TEXT) so plugins can store structured data
- ``autoload`` flag on extension_store for startup performance
- Unique constraint on (scope_id, key) prevents duplicates
- All nullable scope_ids allow global entries (scope_id IS NULL = global)
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class UserPreference(PKMixin, TimestampsMixin, Base):
    """Per-user key-value preferences.

    The dashboard reads these on login to restore the user's
    personalization (theme, locale, notification level, etc.).
    """

    __tablename__ = "user_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[Any] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )

    __table_args__ = (
        UniqueConstraint("user_id", "key", name="uq_user_preferences_user_key"),
        Index("ix_user_preferences_user", "user_id"),
    )


class ProjectConfig(PKMixin, TimestampsMixin, Base):
    """Per-project configuration overrides.

    Stores project-specific settings that override brain defaults.
    Also used by plugins to store project-scoped config.
    Keys are namespaced by convention: ``plugin.<name>.<key>``.
    """

    __tablename__ = "project_config"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    value: Mapped[Any] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )

    __table_args__ = (
        UniqueConstraint("project_id", "key", name="uq_project_config_project_key"),
        Index("ix_project_config_project", "project_id"),
    )


class ExtensionStore(PKMixin, TimestampsMixin, Base):
    """Global schemaless storage for plugins and extensions.

    The WordPress wp_options equivalent. Namespaced by convention:
    plugins prefix their keys (e.g., ``ext.slack.workspace_id``).

    The ``autoload`` flag controls whether the value is loaded into
    memory at brain startup. Set to True for frequently-accessed
    config, False for large blobs or rarely-used data.
    """

    __tablename__ = "extension_store"

    key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    value: Mapped[Any] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )
    autoload: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    description: Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (
        Index("ix_extension_store_autoload", "autoload"),
    )


__all__ = ["ExtensionStore", "ProjectConfig", "UserPreference"]
