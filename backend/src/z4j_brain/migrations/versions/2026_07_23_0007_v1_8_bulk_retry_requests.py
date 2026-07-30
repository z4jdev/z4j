"""Durable bulk-retry request ledger and sealed child outbox.

Revision ID: v1_8_bulk_retry_requests
Revises: v1_7_security_hardening
Create Date: 2026-07-23

The migration is additive on upgrade.  Downgrade is deliberately refused while
any durable parent exists: a pre-1.8 process cannot represent or safely resume
the sealed plan, so dropping the tables would erase destructive-operation
state and make rollback lie about what may have executed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from z4j_brain.persistence.types import jsonb

revision: str = "v1_8_bulk_retry_requests"
down_revision: str | Sequence[str] | None = "v1_7_security_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.8.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_security_hardening",
    "downgrade_to": "v1_7_security_hardening",
}

_PARENTS = "bulk_retry_requests"
_CHILDREN = "bulk_retry_request_children"
_COMMAND_CHILD_COLUMN = "bulk_retry_child_id"


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    """Create the durable parent/outbox and link managed commands."""

    bind = op.get_bind()
    # Fresh installs are materialized from current Base.metadata by the initial
    # migration, so every operation is guarded.
    if not _table_exists(bind, _PARENTS):
        op.create_table(
            _PARENTS,
            sa.Column("project_id", sa.Uuid(), nullable=False),
            sa.Column("issued_by", sa.Uuid(), nullable=True),
            sa.Column("idempotency_key", sa.String(200), nullable=False),
            sa.Column("canonicalizer_version", sa.Integer(), nullable=False),
            sa.Column("canonical_request", sa.LargeBinary(), nullable=False),
            sa.Column("canonical_digest", sa.String(64), nullable=False),
            sa.Column("effective_request", jsonb(), nullable=False),
            sa.Column("plan_digest", sa.String(64), nullable=False),
            sa.Column(
                "control_state",
                sa.String(16),
                nullable=False,
                server_default="running",
            ),
            sa.Column("target_agent_id", sa.Uuid(), nullable=True),
            sa.Column("child_count", sa.Integer(), nullable=False),
            sa.Column("max_in_flight", sa.Integer(), nullable=False),
            sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "sealed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.ForeignKeyConstraint(
                ["issued_by"],
                ["users.id"],
                name="fk_bulk_retry_requests_issued_by_users",
                ondelete="SET NULL",
            ),
            sa.ForeignKeyConstraint(
                ["project_id"],
                ["projects.id"],
                name="fk_bulk_retry_requests_project_id_projects",
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", name="pk_bulk_retry_requests"),
            sa.UniqueConstraint(
                "project_id",
                "idempotency_key",
                name="uq_bulk_retry_requests_project_key",
            ),
        )
        op.create_index(
            "ix_bulk_retry_requests_control_progress",
            _PARENTS,
            ["control_state", "last_progress_at", "created_at"],
        )
        op.create_index(
            "ix_bulk_retry_requests_deadline",
            _PARENTS,
            ["deadline_at"],
        )

    if not _table_exists(bind, _CHILDREN):
        op.create_table(
            _CHILDREN,
            sa.Column("parent_id", sa.Uuid(), nullable=False),
            sa.Column("project_id", sa.Uuid(), nullable=False),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("engine", sa.String(40), nullable=False),
            sa.Column("target_agent_id", sa.Uuid(), nullable=True),
            sa.Column("payload", jsonb(), nullable=False),
            sa.Column("payload_digest", sa.String(64), nullable=False),
            sa.Column("payload_size", sa.Integer(), nullable=False),
            sa.Column(
                "required_contract_version",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
            sa.Column(
                "delivery_state",
                sa.String(24),
                nullable=False,
                server_default="pending",
            ),
            sa.Column(
                "outcome",
                sa.String(16),
                nullable=False,
                server_default="unobserved",
            ),
            sa.Column("claimed_agent_id", sa.Uuid(), nullable=True),
            sa.Column("claimed_generation", sa.Uuid(), nullable=True),
            sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("claim_deadline_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.ForeignKeyConstraint(
                ["parent_id"],
                [f"{_PARENTS}.id"],
                name="fk_bulk_retry_request_children_parent_id_bulk_retry_requests",
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["project_id"],
                ["projects.id"],
                name="fk_bulk_retry_request_children_project_id_projects",
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", name="pk_bulk_retry_request_children"),
            sa.UniqueConstraint(
                "parent_id",
                "ordinal",
                name="uq_bulk_retry_request_children_parent_ordinal",
            ),
        )
        op.create_index(
            "ix_bulk_retry_children_parent_delivery",
            _CHILDREN,
            ["parent_id", "delivery_state", "ordinal"],
        )
        op.create_index(
            "ix_bulk_retry_children_project_delivery",
            _CHILDREN,
            ["project_id", "delivery_state", "engine"],
        )
        op.create_index(
            "ix_bulk_retry_children_claim_deadline",
            _CHILDREN,
            ["claim_deadline_at"],
        )

    if not _column_exists(bind, "commands", _COMMAND_CHILD_COLUMN):
        foreign_key_name = (
            "fk_commands_bulk_retry_child_id_bulk_retry_request_children"
        )
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("commands") as batch:
                batch.add_column(
                    sa.Column(_COMMAND_CHILD_COLUMN, sa.Uuid(), nullable=True)
                )
                batch.create_foreign_key(
                    foreign_key_name,
                    _CHILDREN,
                    [_COMMAND_CHILD_COLUMN],
                    ["id"],
                    ondelete="SET NULL",
                )
                batch.create_index(
                    "ux_commands_bulk_retry_child",
                    [_COMMAND_CHILD_COLUMN],
                    unique=True,
                )
        else:
            op.add_column(
                "commands",
                sa.Column(
                    _COMMAND_CHILD_COLUMN,
                    sa.Uuid(),
                    sa.ForeignKey(
                        f"{_CHILDREN}.id",
                        name=foreign_key_name,
                        ondelete="SET NULL",
                    ),
                    nullable=True,
                ),
            )
            op.create_index(
                "ux_commands_bulk_retry_child",
                "commands",
                [_COMMAND_CHILD_COLUMN],
                unique=True,
            )


def downgrade() -> None:
    """Drop the boundary only when no durable operation can be lost."""

    bind = op.get_bind()
    if _table_exists(bind, _PARENTS):
        count = bind.execute(
            sa.select(sa.func.count()).select_from(sa.table(_PARENTS))
        ).scalar_one()
        if count:
            raise CommandError(
                "refusing downgrade below z4j 1.8: durable bulk-retry parents "
                "exist; finish/resolve them and perform the documented manual "
                "handoff before rollback"
            )

    if _column_exists(bind, "commands", _COMMAND_CHILD_COLUMN):
        if bind.dialect.name == "postgresql":
            op.drop_index("ux_commands_bulk_retry_child", table_name="commands")
            op.drop_column("commands", _COMMAND_CHILD_COLUMN)
        else:
            with op.batch_alter_table("commands") as batch:
                batch.drop_index("ux_commands_bulk_retry_child")
                batch.drop_column(_COMMAND_CHILD_COLUMN)

    if _table_exists(bind, _CHILDREN):
        op.drop_table(_CHILDREN)
    if _table_exists(bind, _PARENTS):
        op.drop_table(_PARENTS)
