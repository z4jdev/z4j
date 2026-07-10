"""z4j 1.7 add ``agent_offline_alerts`` table (durable cross-replica dedup).

Revision ID: v1_7_agent_offline_alerts
Revises: v1_7_tasks_last_failed_at
Create Date: 2026-07-10

The AgentHealthWorker runs on every brain replica, each with its own
in-memory state, so an offline episode would be alerted once per replica
(duplicate audit rows / notifications / rule firings under HA) and again
after every brain restart. This shared table is the durable claim,
mirroring ``misfire_alerts``: a replica inserts one ``(agent_id,
anchor_at)`` row and alerts only if the insert won the UNIQUE, so an
episode is alerted exactly once fleet-wide.

Schema mirrors ``z4j_brain.persistence.models.agent_offline_alert``.
Idempotent via ``create_all(checkfirst=True)`` (a fresh install already
has the table from the initial migration's metadata build).
``downgrade()`` drops it; any in-flight claims are lost, which only
re-alerts a currently-offline episode once -- acceptable (fail toward
visibility). On Postgres the id column also gets the
``gen_random_uuid()`` server default the other UUID-id tables carry, so
a non-ORM insert omitting id still works on both the fresh-install and
upgrade paths.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.agent_offline_alert import AgentOfflineAlert

revision: str = "v1_7_agent_offline_alerts"
down_revision: str | Sequence[str] | None = "v1_7_tasks_last_failed_at"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_tasks_last_failed_at",
    "downgrade_to": "v1_7_tasks_last_failed_at",
}


def upgrade() -> None:
    """Create ``agent_offline_alerts`` (+ constraints/index), idempotently."""
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind,
        tables=[AgentOfflineAlert.__table__],
        checkfirst=True,
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "ALTER TABLE IF EXISTS agent_offline_alerts "
                "ALTER COLUMN id SET DEFAULT gen_random_uuid()",
            ),
        )


def downgrade() -> None:
    """Drop the ``agent_offline_alerts`` table (constraints/index drop with it)."""
    bind = op.get_bind()
    AgentOfflineAlert.__table__.drop(bind=bind, checkfirst=True)
