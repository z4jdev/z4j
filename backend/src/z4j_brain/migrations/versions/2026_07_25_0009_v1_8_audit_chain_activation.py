"""Activate authenticated Boundary-F audit state.

Revision ID: v1_8_audit_chain_activate
Revises: v1_8_audit_chain_prepare
Create Date: 2026-07-25

A genuinely fresh schema activates automatically only when the historical
initial migration marked this exact Alembic invocation.  Existing empty or
ambiguous databases remain safely parked at the authenticated preparation head
for the explicit manifest-bound activation ceremony.
"""

from __future__ import annotations

import hmac
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from sqlalchemy.orm import Session
from z4j_brain.domain.audit_activation import (
    build_activation_manifest,
    validate_activation_manifest,
)
from z4j_brain.domain.audit_chain import (
    AUDIT_ROW_HMAC_VERSION,
    AUDIT_STATE_FORMAT_VERSION,
    AuditChainIntegrityError,
    build_audit_keyring,
    canonical_frozen_row_snapshot,
    canonical_json,
    canonical_preparation_payload,
    canonical_retired_recovery_binding,
    canonical_row_payload,
    compute_preparation_mac,
    compute_row_hmac,
    compute_state_mac,
    frozen_snapshot_digest,
    normalize_timestamp,
)
from z4j_brain.migrations import settings_from_context
from z4j_brain.persistence.models import (
    AuditChainPreparation,
    AuditChainState,
    AuditLog,
)
from z4j_brain.persistence.repositories.audit_log import (
    AUDIT_CHAIN_ADVISORY_LOCK_KEY,
)
from z4j_brain.persistence.types import jsonb

revision: str = "v1_8_audit_chain_activate"
down_revision: str | Sequence[str] | None = "v1_8_audit_chain_prepare"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.8.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_8_audit_chain_prepare",
    "downgrade_to": None,
}

#: Declares to ``env.py`` that this revision will not be undone, so a whole
#: downgrade run planned through it is refused before its first step executes.
#: Without that, a destructive step stacked above here commits, and is lost,
#: while the operator is being told the rollback was refused.
DOWNGRADE_REFUSED = "refusing downgrade below Boundary F while authenticated audit state exists"

_PREPARATION = "audit_chain_preparation"
_STATE = "audit_chain_state"
_AUDIT = "audit_log"


def _settings_keyring() -> tuple[str, dict[str, bytes]]:
    settings = settings_from_context()
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise CommandError(
            "Boundary-F activation requires Z4J_AUDIT_CHAIN_SECRET",
        )
    return build_audit_keyring(secrets[0], secrets[1:])


def _authenticate_preparation(
    bind: sa.engine.Connection,
    keyring: dict[str, bytes],
    current_key_id: str,
) -> None:
    rows = (
        bind.execute(
            sa.select(AuditChainPreparation.__table__),
        )
        .mappings()
        .all()
    )
    if len(rows) != 1:
        raise CommandError(
            "audit-chain preparation is missing or duplicated",
        )
    row = rows[0]
    if (
        row["singleton_id"] != "audit-chain"
        or row["format_version"] != 1
        or row["preparation_revision"] != "v1_8_audit_chain_prepare"
        or row["target_activation_revision"] != revision
    ):
        raise CommandError("audit-chain preparation shape/revision mismatch")
    key_id = row["audit_key_id"]
    if key_id != current_key_id:
        raise CommandError(
            "configured current audit key differs from the pending preparation",
        )
    secret = keyring.get(key_id)
    if secret is None:
        raise CommandError(
            "configured audit key window does not contain the preparation key",
        )
    payload = canonical_preparation_payload(
        preparation_id=row["preparation_id"],
        audit_key_id=key_id,
        preparation_revision=row["preparation_revision"],
        target_activation_revision=row["target_activation_revision"],
    )
    expected = compute_preparation_mac(secret, payload)
    stored = row["preparation_mac"]
    if len(stored) != len(expected) or not hmac.compare_digest(stored, expected):
        raise CommandError("audit-chain preparation MAC mismatch")


def _create_state_table() -> None:
    op.create_table(
        _STATE,
        sa.Column("singleton_id", sa.String(32), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("state_key_id", sa.String(64), nullable=False),
        sa.Column("head_row_hmac", sa.String(64), nullable=True),
        sa.Column("head_hmac_key_id", sa.String(64), nullable=True),
        sa.Column("head_occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("head_id", sa.Uuid(), nullable=True),
        sa.Column("prune_row_hmac", sa.String(64), nullable=True),
        sa.Column("prune_hmac_key_id", sa.String(64), nullable=True),
        sa.Column("prune_occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("prune_id", sa.Uuid(), nullable=True),
        sa.Column("active_row_count", sa.BigInteger(), nullable=False),
        sa.Column("active_key_counts", jsonb(), nullable=False),
        sa.Column("frozen_row_count", sa.BigInteger(), nullable=False),
        sa.Column("frozen_snapshot_digest", sa.String(64), nullable=True),
        sa.Column("retired_recovery_binding", jsonb(), nullable=True),
        sa.Column("state_mac", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_audit_chain_state"),
        sa.CheckConstraint(
            "singleton_id = 'audit-chain'",
            name="ck_audit_chain_state_singleton_id",
        ),
        sa.CheckConstraint(
            "format_version = 1",
            name="ck_audit_chain_state_format_version",
        ),
        sa.CheckConstraint(
            "active_row_count >= 0",
            name="ck_audit_chain_state_active_row_count_nonnegative",
        ),
        sa.CheckConstraint(
            "frozen_row_count >= 0",
            name="ck_audit_chain_state_frozen_row_count_nonnegative",
        ),
    )


def _marker_constraint_sql(*, true_literal: str, false_literal: str) -> str:
    return f"""
        (
          legacy_frozen = {false_literal}
          AND hmac_version = 2
          AND hmac_key_id IS NOT NULL
          AND row_hmac IS NOT NULL
          AND legacy_integrity_class IS NULL
          AND legacy_origin IS NULL
          AND chain_generation IS NOT NULL
        ) OR (
          legacy_frozen = {true_literal}
          AND chain_generation IS NULL
          AND legacy_origin IN (
            'audit-log:preparation-v1',
            'fork-quarantine:audit-log-v1-15',
            'fork-quarantine:audit-log-v1-api-key-16'
          )
          AND (
            (
              legacy_integrity_class IN (
                'legacy-linked-verified',
                'legacy-standalone-verified',
                'legacy-fork-verified'
              )
              AND hmac_version = 1
              AND hmac_key_id IS NOT NULL
              AND row_hmac IS NOT NULL
            ) OR (
              legacy_integrity_class = 'legacy-unsigned'
              AND hmac_version IS NULL
              AND hmac_key_id IS NULL
              AND row_hmac IS NULL
            ) OR (
              legacy_integrity_class IN (
                'legacy-invalid',
                'legacy-unverifiable-key-unavailable'
              )
              AND (hmac_version IS NULL OR hmac_version = 1)
              AND hmac_key_id IS NULL
              AND row_hmac IS NOT NULL
            )
          )
        )
    """


def upgrade() -> None:  # noqa: PLR0912, PLR0915  atomic activation ceremony
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
        )
        bind.execute(sa.text("LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE"))
        bind.execute(
            sa.text(
                "LOCK TABLE audit_chain_preparation IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
        bind.execute(sa.text("SET LOCAL z4j.audit_activation = 'on'"))

    current_key_id, keyring = _settings_keyring()
    _authenticate_preparation(bind, keyring, current_key_id)

    fresh_bootstrap = op.get_context().config.attributes.get(
        "z4j_fresh_schema_bootstrap",
        False,
    )
    retirement_context = op.get_context().config.attributes.get(
        "z4j_installation_retirement",
    )
    if retirement_context is not None and not fresh_bootstrap:
        raise CommandError(
            "installation-retirement authority is valid only for a fresh "
            "same-invocation activation",
        )
    finalized_manifest = op.get_context().config.attributes.get(
        "z4j_audit_activation_manifest",
    )
    if not fresh_bootstrap and finalized_manifest is None:
        # Classify the existing audit history in place. The operator
        # ceremony exists to make a human attest to AMBIGUITY: history
        # that cannot be classified (forked, unsigned, key-unavailable,
        # suffix-truncated, an unprovable known head). When there is no
        # ambiguity there is nothing to attest to, and the manifest is a
        # pure function of the locked database, so an operator
        # "inspecting" it is rubber-stamping a computation.
        #
        # Previously this gate was unconditional and stopped EVERY
        # existing database, which turned an ordinary minor upgrade into
        # a mandatory offline ceremony and made a supervised container
        # restart-loop until a human intervened. Classification runs on
        # the same locked preparation-head snapshot the explicit CLI
        # path uses, so the security property is unchanged: ambiguous
        # history still cannot enter a signed chain without an explicit,
        # digest-bound operator attestation.
        auto_manifest = build_activation_manifest(
            bind,
            settings_from_context(),
            legacy_key_window_complete=False,
            known_head=None,
        )
        if auto_manifest["requires_ambiguity_attestation"]:
            raise CommandError(
                "audit history could not be classified unambiguously "
                f"({', '.join(auto_manifest['classification_failures'])}); "
                "database remains at v1_8_audit_chain_prepare. Finalize with "
                "`z4j audit activate-chain-state --manifest "
                "<owner-private-path>`, inspect that immutable manifest, then "
                "rerun with `--apply` and the exact "
                "`--attest-manifest-digest`. See the 1.7 -> 1.8 ceremony in "
                "docs/UPGRADE.md."
            )
        finalized_manifest = auto_manifest
    if fresh_bootstrap and bind.execute(sa.text("SELECT COUNT(*) FROM audit_log")).scalar_one():
        raise CommandError(
            "fresh-schema marker conflicts with non-empty audit history",
        )
    if _STATE in sa.inspect(bind).get_table_names():
        raise CommandError("audit_chain_state already exists before activation")

    frozen_row_count = 0
    frozen_digest = None
    activation_metadata: dict[str, object] = {
        "activation": "fresh-same-invocation",
        "frozen_row_count": 0,
        "frozen_snapshot_digest": None,
        "known_head_result": None,
    }
    if finalized_manifest is not None:
        if not isinstance(finalized_manifest, dict):
            raise CommandError("activation manifest attribute must be an object")
        observed_manifest = build_activation_manifest(
            bind,
            settings_from_context(),
            legacy_key_window_complete=bool(
                finalized_manifest.get("legacy_key_window_complete"),
            ),
            known_head=finalized_manifest.get("known_head"),
        )
        try:
            validate_activation_manifest(finalized_manifest, observed_manifest)
        except Exception as exc:
            raise CommandError(str(exc)) from exc
        attestation = op.get_context().config.attributes.get(
            "z4j_audit_activation_attestation",
        )
        if finalized_manifest.get("requires_ambiguity_attestation") and (
            attestation != finalized_manifest.get("manifest_digest")
        ):
            raise CommandError(
                "activation ambiguity attestation must equal the finalized manifest digest",
            )
        audit_table = AuditLog.__table__
        indexes = {index["name"] for index in sa.inspect(bind).get_indexes(_AUDIT)}
        if "ux_audit_log_prev_row_hmac" in indexes:
            op.drop_index("ux_audit_log_prev_row_hmac", table_name=_AUDIT)
        for classification in finalized_manifest["classifications"]:
            snapshot = classification["frozen_snapshot"]
            marker_values = {
                "legacy_frozen": True,
                "hmac_version": classification["hmac_version"],
                "hmac_key_id": classification["hmac_key_id"],
                "legacy_integrity_class": classification["legacy_integrity_class"],
                "legacy_origin": classification["legacy_origin"],
                "chain_generation": None,
            }
            if classification["legacy_origin"].startswith(
                "fork-quarantine:",
            ):
                result = bind.execute(
                    audit_table.insert().values(
                        id=uuid.UUID(snapshot["id"]),
                        action=snapshot["action"],
                        target_type=snapshot["target_type"],
                        target_id=snapshot["target_id"],
                        result=snapshot["result"],
                        outcome=snapshot["outcome"],
                        event_id=(
                            uuid.UUID(snapshot["event_id"])
                            if snapshot["event_id"] is not None
                            else None
                        ),
                        user_id=(
                            uuid.UUID(snapshot["user_id"])
                            if snapshot["user_id"] is not None
                            else None
                        ),
                        api_key_id=(
                            uuid.UUID(snapshot["api_key_id"])
                            if snapshot["api_key_id"] is not None
                            else None
                        ),
                        project_id=(
                            uuid.UUID(snapshot["project_id"])
                            if snapshot["project_id"] is not None
                            else None
                        ),
                        source_ip=snapshot["source_ip"],
                        user_agent=snapshot["user_agent"],
                        metadata=snapshot["metadata"],
                        occurred_at=normalize_timestamp(
                            snapshot["occurred_at"],
                        ),
                        prev_row_hmac=snapshot["prev_row_hmac"],
                        row_hmac=snapshot["row_hmac"],
                        **marker_values,
                    ),
                )
            else:
                result = bind.execute(
                    audit_table.update()
                    .where(
                        audit_table.c.id == uuid.UUID(classification["id"]),
                    )
                    .values(**marker_values),
                )
            if result.rowcount != 1:
                raise CommandError(
                    "finalized activation row id did not persist exactly once",
                )
        with Session(bind=bind) as session:
            frozen_rows = list(
                session.execute(
                    sa.select(AuditLog)
                    .where(AuditLog.legacy_frozen.is_(True))
                    .order_by(AuditLog.occurred_at, AuditLog.id),
                )
                .scalars()
                .all()
            )
        frozen_row_count = len(frozen_rows)
        frozen_snapshots = [canonical_frozen_row_snapshot(row) for row in frozen_rows]
        frozen_digest = frozen_snapshot_digest(frozen_snapshots)
        if (
            frozen_row_count != finalized_manifest["frozen_row_count"]
            or frozen_digest != finalized_manifest["frozen_snapshot_digest"]
            or frozen_snapshots
            != [item["frozen_snapshot"] for item in finalized_manifest["classifications"]]
        ):
            raise CommandError(
                "persisted frozen audit snapshot differs from finalized manifest",
            )
        auxiliary_source = finalized_manifest["auxiliary_source"]
        if auxiliary_source is not None:
            imported = sum(
                item["legacy_origin"].startswith("fork-quarantine:")
                for item in finalized_manifest["classifications"]
            )
            if imported != auxiliary_source["row_count"]:
                raise CommandError(
                    "fork quarantine import count differs from manifest",
                )
            op.drop_table("audit_log_legacy_forks")
        activation_metadata = {
            "activation": "offline-manifest-bound",
            "manifest_digest": finalized_manifest["manifest_digest"],
            "frozen_row_count": frozen_row_count,
            "frozen_snapshot_digest": frozen_digest,
            "classification_failures": finalized_manifest["classification_failures"],
            "ambiguity_attested": bool(
                finalized_manifest["requires_ambiguity_attestation"],
            ),
            "known_head": finalized_manifest["known_head"],
            "known_head_result": finalized_manifest["known_head_result"],
        }

    _create_state_table()
    secret = keyring[current_key_id]
    generation = uuid.uuid4()
    installation_id = uuid.uuid4()
    retired_recovery_binding = None
    if retirement_context is not None:
        if (
            not isinstance(retirement_context, dict)
            or set(retirement_context)
            != {
                "version",
                "operation_id",
                "old_bundle_manifest_digest",
                "retained_parent_identity_digest",
            }
            or retirement_context.get("version") != 1
        ):
            raise CommandError(
                "installation-retirement activation context is invalid",
            )
        try:
            retired_recovery_binding = canonical_retired_recovery_binding(
                {
                    **retirement_context,
                    "replacement_installation_id": str(installation_id),
                    "status": "RECOVERABLE",
                    "destruction_journal_digest": None,
                },
            )
        except AuditChainIntegrityError as exc:
            raise CommandError(str(exc)) from exc
        activation_metadata = {
            **activation_metadata,
            "installation_retirement": {
                **retirement_context,
                "replacement_installation_id": str(installation_id),
            },
        }
    row_id = uuid.uuid4()
    occurred_at = datetime.now(UTC)
    metadata = activation_metadata
    row_payload = canonical_row_payload(
        row_id=row_id,
        action="audit.chain_generation_started",
        target_type="audit_chain",
        target_id=str(generation),
        result="success",
        outcome="allow",
        event_id=None,
        user_id=None,
        api_key_id=None,
        project_id=None,
        source_ip=None,
        user_agent=None,
        metadata=metadata,
        occurred_at=occurred_at,
        prev_row_hmac=None,
        hmac_key_id=current_key_id,
        chain_generation=generation,
    )
    row_hmac = compute_row_hmac(secret, row_payload)
    audit_table = AuditLog.__table__
    bind.execute(
        audit_table.insert().values(
            id=row_id,
            action="audit.chain_generation_started",
            target_type="audit_chain",
            target_id=str(generation),
            result="success",
            outcome="allow",
            event_id=None,
            user_id=None,
            api_key_id=None,
            project_id=None,
            source_ip=None,
            user_agent=None,
            metadata=metadata,
            occurred_at=occurred_at,
            prev_row_hmac=None,
            row_hmac=row_hmac,
            legacy_frozen=False,
            hmac_version=AUDIT_ROW_HMAC_VERSION,
            hmac_key_id=current_key_id,
            legacy_integrity_class=None,
            legacy_origin=None,
            chain_generation=generation,
        )
    )
    persisted = (
        bind.execute(
            sa.select(audit_table).where(audit_table.c.id == row_id),
        )
        .mappings()
        .one()
    )
    persisted_payload = canonical_row_payload(
        row_id=persisted["id"],
        action=persisted["action"],
        target_type=persisted["target_type"],
        target_id=persisted["target_id"],
        result=persisted["result"],
        outcome=persisted["outcome"],
        event_id=persisted["event_id"],
        user_id=persisted["user_id"],
        api_key_id=persisted["api_key_id"],
        project_id=persisted["project_id"],
        source_ip=(str(persisted["source_ip"]) if persisted["source_ip"] is not None else None),
        user_agent=persisted["user_agent"],
        metadata=persisted["metadata"],
        occurred_at=persisted["occurred_at"],
        prev_row_hmac=persisted["prev_row_hmac"],
        hmac_key_id=persisted["hmac_key_id"],
        chain_generation=persisted["chain_generation"],
    )
    if canonical_json(persisted_payload) != canonical_json(row_payload):
        raise CommandError(
            "database normalized the Boundary-F generation marker differently",
        )

    state = {
        "format_version": AUDIT_STATE_FORMAT_VERSION,
        "generation": generation,
        "installation_id": installation_id,
        "state_key_id": current_key_id,
        "head_row_hmac": row_hmac,
        "head_hmac_key_id": current_key_id,
        "head_occurred_at": persisted["occurred_at"],
        "head_id": row_id,
        "prune_row_hmac": None,
        "prune_hmac_key_id": None,
        "prune_occurred_at": None,
        "prune_id": None,
        "active_row_count": 1,
        "active_key_counts": {current_key_id: 1},
        "frozen_row_count": frozen_row_count,
        "frozen_snapshot_digest": frozen_digest,
        "retired_recovery_binding": retired_recovery_binding,
    }
    state_mac = compute_state_mac(secret, state)
    bind.execute(
        AuditChainState.__table__.insert().values(
            singleton_id="audit-chain",
            **state,
            state_mac=state_mac,
        ),
    )
    bind.execute(sa.text("DELETE FROM audit_chain_preparation"))
    if op.get_context().config.attributes.get(
        "z4j_test_fail_audit_activation_after_state",
        False,
    ):
        raise RuntimeError("injected Boundary-F activation failure after state")

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes(_AUDIT)}
    if "ux_audit_log_prev_row_hmac" in indexes:
        op.drop_index("ux_audit_log_prev_row_hmac", table_name=_AUDIT)
    op.create_index(
        "ux_audit_log_prev_row_hmac",
        _AUDIT,
        ["prev_row_hmac"],
        unique=True,
        postgresql_where=sa.text("prev_row_hmac IS NOT NULL AND legacy_frozen = false"),
        sqlite_where=sa.text("prev_row_hmac IS NOT NULL AND legacy_frozen = 0"),
    )

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(_AUDIT) as batch:
            batch.alter_column(
                "legacy_frozen",
                existing_type=sa.Boolean(),
                nullable=False,
            )
            batch.create_check_constraint(
                "ck_audit_log_boundary_f_markers",
                _marker_constraint_sql(
                    true_literal="1",
                    false_literal="0",
                ),
            )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_log_boundary_f_no_insert
                BEFORE INSERT ON audit_log
                FOR EACH ROW
                BEGIN
                  SELECT z4j_audit_guard('insert', '');
                  SELECT CASE
                    WHEN NEW.legacy_frozen != 0
                      OR NEW.hmac_version != 2
                      OR NEW.hmac_key_id IS NULL
                      OR NEW.row_hmac IS NULL
                      OR NEW.chain_generation IS NULL
                    THEN RAISE(ABORT, 'audit insert is not an active signed row')
                  END;
                END
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_log_boundary_f_no_update
                BEFORE UPDATE ON audit_log
                FOR EACH ROW
                BEGIN
                  SELECT RAISE(ABORT, 'audit_log is append-only');
                END
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_log_boundary_f_no_delete
                BEFORE DELETE ON audit_log
                FOR EACH ROW
                BEGIN
                  SELECT z4j_audit_guard('delete', '');
                END
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_chain_state_boundary_f_no_update
                BEFORE UPDATE ON audit_chain_state
                FOR EACH ROW
                BEGIN
                  SELECT z4j_audit_guard('state_update', '');
                END
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_chain_state_boundary_f_no_delete
                BEFORE DELETE ON audit_chain_state
                FOR EACH ROW
                BEGIN
                  SELECT z4j_audit_guard('state_delete', '');
                END
                """
            )
        )
    else:
        op.alter_column(_AUDIT, "legacy_frozen", nullable=False)
        op.create_check_constraint(
            "ck_audit_log_boundary_f_markers",
            _AUDIT,
            _marker_constraint_sql(
                true_literal="true",
                false_literal="false",
            ),
        )
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION audit_log_forbid_mutation()
                RETURNS trigger AS $$
                BEGIN
                  IF TG_OP = 'DELETE'
                     AND current_setting('z4j.audit_transition', true)
                         IN ('retention-v1', 'reset-v1',
                             'frozen-export-delete-v1') THEN
                    RETURN OLD;
                  END IF;
                  RAISE EXCEPTION 'audit_log is append-only';
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION audit_chain_state_forbid_mutation()
                RETURNS trigger AS $$
                BEGIN
                  IF current_setting('z4j.audit_transition', true)
                     IN ('append-v1', 'retention-v1', 'reset-v1',
                         'frozen-export-delete-v1', 'key-rotation-v1',
                         'restore-v1') THEN
                    RETURN COALESCE(NEW, OLD);
                  END IF;
                  RAISE EXCEPTION 'audit_chain_state is signer-managed';
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER audit_chain_state_no_update
                BEFORE UPDATE OR DELETE ON audit_chain_state
                FOR EACH ROW EXECUTE FUNCTION audit_chain_state_forbid_mutation()
                """
            )
        )


def downgrade() -> None:
    raise CommandError(DOWNGRADE_REFUSED)
