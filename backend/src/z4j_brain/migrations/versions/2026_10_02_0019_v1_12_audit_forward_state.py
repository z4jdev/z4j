"""Durable cursor for the audit webhook forwarder.

The forwarder used to hold undelivered rows in an in-memory queue and drop
them when the receiver was slow, unreachable, or the brain restarted. It now
records, per sink, the chain-order key of the newest audit row the receiver
acknowledged, and resumes from there. This table is that record.

Additive. Downgrade drops the table; a release that still runs the in-memory
forwarder has no use for the cursor, and re-upgrading starts a new cursor at
the then-current audit head.

Revision ID: v1_12_audit_forward_state
Revises: v1_12_api_key_allowed_cidrs
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v1_12_audit_forward_state"
down_revision: str | Sequence[str] | None = "v1_12_api_key_allowed_cidrs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "audit_forward_state"


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    """Create the cursor table, unless the initial migration already did.

    Fresh installs materialise every table from current ``Base.metadata`` in
    the initial migration, so this is guarded like the other additive
    migrations. The column list mirrors the ORM model exactly, in order, so a
    database upgraded through here and one created fresh carry the same
    schema definition.
    """
    bind = op.get_bind()
    if _table_exists(bind, _TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("sink_id", sa.String(64), nullable=False),
        sa.Column("last_forwarded_occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_forwarded_id", sa.Uuid(), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("sink_id", name=op.f("pk_audit_forward_state")),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, _TABLE):
        op.drop_table(_TABLE)
