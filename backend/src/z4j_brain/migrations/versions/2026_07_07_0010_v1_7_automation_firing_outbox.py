"""z4j 1.7 add ``automation_firing_outbox`` table (durable firing buffer).

Revision ID: v1_7_automation_firing_outbox
Revises: v1_7_automation_notify_coalesce
Create Date: 2026-07-07

A firing the frame router cannot dispatch inline (its pending set is full
under an event flood) is persisted here instead of being dropped, and a
leader-only drain worker replays it. Mirrors the ``pending_fires`` buffer
+ replay pattern for scheduler fires.

Schema mirrors ``z4j_brain.persistence.models.automation_firing_outbox``:
project-scoped, a trigger string, a JSONB ``fields`` payload, an attempts
counter, and a created_at index for FIFO drain.

Idempotent via ``create_all(checkfirst=True)`` (a fresh install already has
the table from the initial migration's metadata build). ``downgrade()``
drops the table; any firings buffered at downgrade time are lost, which is
acceptable because they are best-effort deferrals of transient drops. On
Postgres the id column also gets the ``gen_random_uuid()`` server default
the other UUID-id tables carry, so a non-ORM insert omitting id still works
on both the fresh-install and upgrade paths.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.automation_firing_outbox import (
    AutomationFiringOutbox,
)

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_automation_firing_outbox"
down_revision: str | Sequence[str] | None = "v1_7_automation_notify_coalesce"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_automation_notify_coalesce",
    "downgrade_to": "v1_7_automation_notify_coalesce",
}


def upgrade() -> None:
    """Create ``automation_firing_outbox`` (+ index), idempotently."""
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind,
        tables=[AutomationFiringOutbox.__table__],
        checkfirst=True,
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "ALTER TABLE IF EXISTS automation_firing_outbox "
                "ALTER COLUMN id SET DEFAULT gen_random_uuid()",
            ),
        )


def downgrade() -> None:
    """Drop the ``automation_firing_outbox`` table (index drops with it)."""
    bind = op.get_bind()
    AutomationFiringOutbox.__table__.drop(bind=bind, checkfirst=True)
