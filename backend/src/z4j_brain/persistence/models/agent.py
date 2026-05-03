"""``agents`` table - one row per registered agent.

An agent is a `z4j-bare` runtime running inside a customer process.
The brain learns about it via the WebSocket handshake (or via
admin-side token minting before the agent ever connects).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb, text_array


class Agent(PKMixin, TimestampsMixin, Base):
    """A connected (or registered-but-offline) agent.

    Attributes:
        project_id: Owning project. ``ON DELETE CASCADE``.
        name: Operator-chosen friendly name (``web-01``,
            ``celery-worker-prod``, ...).
        token_hash: HMAC-SHA256 hash of the bearer token. The
            plaintext token is shown to the operator exactly once
            at mint time and never persisted.
        protocol_version: Wire-protocol version the agent advertised
            in its ``hello`` frame.
        framework_adapter: ``django`` / ``flask`` / ``fastapi`` /
            ``bare``.
        engine_adapters: List of queue engine adapters the agent has
            registered (e.g. ``["celery"]``).
        scheduler_adapters: List of scheduler adapters
            (``["celery-beat"]``).
        capabilities: Per-adapter capability map advertised in
            ``hello``. Free-form JSON; the brain uses it to enable
            or disable dashboard actions per agent.
        state: ``online`` while the WebSocket is connected and the
            heartbeat is fresh, ``offline`` after the heartbeat
            timeout, ``unknown`` for never-connected.
        last_seen_at: Most recent heartbeat timestamp.
        last_connect_at: Most recent successful WebSocket handshake.
        metadata: Free-form JSON for adapter-specific extras.
    """

    __tablename__ = "agents"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String, nullable=False, unique=True,
    )
    protocol_version: Mapped[str] = mapped_column(String(20), nullable=False)
    framework_adapter: Mapped[str] = mapped_column(String(40), nullable=False)
    engine_adapters: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list, server_default="{}",
    )
    scheduler_adapters: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list, server_default="{}",
    )
    capabilities: Mapped[dict[str, Any]] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )
    state: Mapped[AgentState] = mapped_column(
        Enum(
            AgentState,
            name="agent_state",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=AgentState.UNKNOWN,
        server_default=AgentState.UNKNOWN.value,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    last_connect_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    agent_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )

    __table_args__ = (
        Index("ix_agents_project_state", "project_id", "state"),
        Index("ix_agents_last_seen_at", "last_seen_at"),
        # Audit A5: prevent duplicate agents with the same name in
        # one project. Two concurrent admin POSTs with the same
        # name previously both succeeded silently; now one hits
        # an IntegrityError that the API handler converts to 409.
        UniqueConstraint(
            "project_id", "name", name="uq_agents_project_name",
        ),
    )


__all__ = ["Agent"]
