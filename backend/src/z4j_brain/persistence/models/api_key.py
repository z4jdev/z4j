"""``api_keys`` table - personal API keys for programmatic access.

Dashboard users create these tokens for CI/CD pipelines, scripts,
and Grafana integration. Separate from agent tokens which are
project-scoped. The plaintext token is shown exactly once at
creation time; only the HMAC-SHA256 hash is persisted.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import text_array


class ApiKey(PKMixin, TimestampsMixin, Base):
    """A personal API key for programmatic access to the brain.

    Attributes:
        user_id: Owning user. ``ON DELETE CASCADE``.
        name: Human-friendly label (e.g. "CI pipeline", "Grafana").
        token_hash: HMAC-SHA256 hex digest of the plaintext token.
            The plaintext is shown to the user exactly once at
            creation time and never persisted.
        prefix: First 8 characters of the plaintext token for
            identification in listings (e.g. "z4k_a1b2").
        last_used_at: Most recent successful authentication with
            this key.
        last_used_ip: IP address of the most recent authentication.
        expires_at: Expiration timestamp. Null means the key never
            expires.
        revoked_at: Set when the user revokes the key. Non-null
            means the key is inactive.
    """

    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String, nullable=False, unique=True,
    )
    prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    last_used_ip: Mapped[str | None] = mapped_column(
        String, nullable=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    revoked_reason: Mapped[str | None] = mapped_column(
        String(200), nullable=True,
    )
    # Fine-grained authorization. See :mod:`z4j_brain.auth.scopes`
    # for the full catalogue. Empty list means the token has no
    # access (legacy / tombstoned). The owning user's role is a
    # hard upper bound - a non-admin cannot grant ``users:write``
    # even if they request it.
    scopes: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list, server_default="{}",
    )
    # Optional per-project scope. When set, every request from this
    # token must hit a URL whose ``{slug}`` maps to this project.
    # When null, the token is bounded only by ``scopes`` + the
    # owner's visible projects.
    project_id: Mapped["uuid.UUID | None"] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_api_keys_token_hash", "token_hash"),
        Index("ix_api_keys_user_id", "user_id"),
        Index("ix_api_keys_project_id", "project_id"),
    )


__all__ = ["ApiKey"]
