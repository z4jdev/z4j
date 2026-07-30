"""Prepare the authenticated Boundary-F audit-chain transition.

Revision ID: v1_8_audit_chain_prepare
Revises: v1_8_bulk_retry_requests
Create Date: 2026-07-25

This revision is intentionally a committed recovery point.  It binds the exact
dedicated audit key to the later activation; normal runtime must not serve at
this head.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from z4j_brain.domain.audit_chain import (
    canonical_audit_key_id,
    canonical_preparation_payload,
    compute_preparation_mac,
)
from z4j_brain.migrations import settings_from_context
from z4j_brain.persistence.models import AuditChainPreparation

revision: str = "v1_8_audit_chain_prepare"
down_revision: str | Sequence[str] | None = "v1_8_bulk_retry_requests"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.8.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_8_bulk_retry_requests",
    "downgrade_to": "v1_8_bulk_retry_requests",
}

_PREPARATION = "audit_chain_preparation"
_STATE = "audit_chain_state"
_AUDIT = "audit_log"
_PREPARATION_REVISION = revision
_ACTIVATION_REVISION = "v1_8_audit_chain_activate"


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _column_exists(bind: sa.engine.Connection, table: str, name: str) -> bool:
    return any(column["name"] == name for column in sa.inspect(bind).get_columns(table))


def _audit_secret() -> bytes:
    settings = settings_from_context()
    if settings.audit_chain_secret is None:
        raise CommandError(
            "Boundary-F preparation requires Z4J_AUDIT_CHAIN_SECRET; "
            "PostgreSQL deployments must configure it explicitly and packaged "
            "SQLite bootstrap must persist it before migration"
        )
    return settings.audit_chain_secret.get_secret_value().encode("utf-8")


def upgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, _STATE):
        raise CommandError(
            "audit_chain_state already exists before Boundary-F preparation",
        )

    if not _table_exists(bind, _PREPARATION):
        op.create_table(
            _PREPARATION,
            sa.Column("singleton_id", sa.String(32), nullable=False),
            sa.Column("format_version", sa.Integer(), nullable=False),
            sa.Column("preparation_id", sa.Uuid(), nullable=False),
            sa.Column("audit_key_id", sa.String(64), nullable=False),
            sa.Column("preparation_revision", sa.String(80), nullable=False),
            sa.Column("target_activation_revision", sa.String(80), nullable=False),
            sa.Column("preparation_mac", sa.String(64), nullable=False),
            sa.PrimaryKeyConstraint(
                "singleton_id",
                name="pk_audit_chain_preparation",
            ),
            sa.UniqueConstraint(
                "preparation_id",
                name="uq_audit_chain_preparation_preparation_id",
            ),
            sa.CheckConstraint(
                "singleton_id = 'audit-chain'",
                name="ck_audit_chain_preparation_singleton_id",
            ),
            sa.CheckConstraint(
                "format_version = 1",
                name="ck_audit_chain_preparation_format_version",
            ),
        )

    existing = bind.execute(
        sa.text("SELECT COUNT(*) FROM audit_chain_preparation"),
    ).scalar_one()
    if existing:
        raise CommandError(
            "audit_chain_preparation is not empty before preparation",
        )

    marker_columns: tuple[sa.Column, ...] = (
        sa.Column("legacy_frozen", sa.Boolean(), nullable=True),
        sa.Column("hmac_version", sa.Integer(), nullable=True),
        sa.Column("hmac_key_id", sa.String(64), nullable=True),
        sa.Column("legacy_integrity_class", sa.String(64), nullable=True),
        sa.Column("legacy_origin", sa.String(120), nullable=True),
        sa.Column("chain_generation", sa.Uuid(), nullable=True),
    )
    for column in marker_columns:
        if not _column_exists(bind, _AUDIT, column.name):
            op.add_column(_AUDIT, column)

    # Signed attribution must never be rewritten by a cascading principal
    # deletion.  Both UUIDs remain as historical values without an FK, matching
    # the existing api_key_id posture.
    foreign_keys = {
        fk["name"]: tuple(fk.get("constrained_columns") or ())
        for fk in sa.inspect(bind).get_foreign_keys(_AUDIT)
    }
    for constraint_name, columns in foreign_keys.items():
        if columns not in {("project_id",), ("user_id",)}:
            continue
        if not constraint_name:
            raise CommandError(
                f"cannot identify mutating audit_log foreign key on {columns[0]}",
            )
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(_AUDIT) as batch:
                batch.drop_constraint(constraint_name, type_="foreignkey")
        else:
            op.drop_constraint(
                constraint_name,
                _AUDIT,
                type_="foreignkey",
            )

    if bind.dialect.name == "postgresql":
        # Migration-only UPDATE permission: marker fields may change only when
        # every original signed field is byte-equivalent.  Activation also
        # takes a table write-exclusion before enabling this transaction-local
        # branch.
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION audit_log_forbid_mutation()
                RETURNS trigger AS $$
                BEGIN
                  IF TG_OP = 'UPDATE'
                     AND current_setting('z4j.audit_activation', true) = 'on'
                     AND ROW(
                       OLD.id, OLD.action, OLD.target_type, OLD.target_id,
                       OLD.result, OLD.outcome, OLD.event_id, OLD.user_id,
                       OLD.project_id, OLD.api_key_id, OLD.source_ip,
                       OLD.user_agent, OLD.metadata, OLD.occurred_at,
                       OLD.prev_row_hmac, OLD.row_hmac
                     ) IS NOT DISTINCT FROM ROW(
                       NEW.id, NEW.action, NEW.target_type, NEW.target_id,
                       NEW.result, NEW.outcome, NEW.event_id, NEW.user_id,
                       NEW.project_id, NEW.api_key_id, NEW.source_ip,
                       NEW.user_agent, NEW.metadata, NEW.occurred_at,
                       NEW.prev_row_hmac, NEW.row_hmac
                     ) THEN
                    RETURN NEW;
                  END IF;
                  IF TG_OP = 'DELETE'
                     AND current_setting('z4j.audit_transition', true)
                         = 'retention-v1' THEN
                    RETURN OLD;
                  END IF;
                  RAISE EXCEPTION 'audit_log is append-only';
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )

    secret = _audit_secret()
    preparation_id = uuid.uuid4()
    key_id = canonical_audit_key_id(secret)
    payload = canonical_preparation_payload(
        preparation_id=preparation_id,
        audit_key_id=key_id,
        preparation_revision=_PREPARATION_REVISION,
        target_activation_revision=_ACTIVATION_REVISION,
    )
    bind.execute(
        AuditChainPreparation.__table__.insert().values(
            {
                **payload,
                "preparation_id": preparation_id,
                "preparation_mac": compute_preparation_mac(secret, payload),
            }
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, _STATE):
        raise CommandError(
            "refusing downgrade: authenticated audit chain state exists",
        )
    # Preparation binds a key and classification decision.  A generic
    # downgrade must not erase it and make a later migration guess again.
    if _table_exists(bind, _PREPARATION):
        count = bind.execute(
            sa.text("SELECT COUNT(*) FROM audit_chain_preparation"),
        ).scalar_one()
        if count:
            raise CommandError(
                "refusing downgrade while audit-chain preparation is pending",
            )
        op.drop_table(_PREPARATION)
