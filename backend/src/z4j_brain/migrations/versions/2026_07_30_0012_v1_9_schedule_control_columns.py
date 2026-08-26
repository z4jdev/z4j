"""z4j 1.9: schedule controls and durable agent revocation.

Two columns on ``schedules`` are added together because they answer the same
operator question from opposite ends: what should happen to a schedule that
should not run right now.

``overlap_policy``
    What to do when the schedule comes due while its previous run is still
    in flight. Defaults to ``allow``, which is exactly what every existing
    schedule does today. Defaulting to ``skip`` would be safer in the
    abstract and wrong in practice: an upgrade would silently start
    withholding fires an operator was relying on, which is a data-affecting
    change wearing the clothes of a new feature.

``paused_at``
    When a schedule was paused, or NULL if it is not paused. Distinct from
    ``is_enabled`` on purpose. Disabling says "this schedule should not
    exist for now" and is how you retire something; pausing says "hold it,
    I am dealing with an incident" and carries the timestamp that tells you
    how long the hold has been in place. Collapsing them loses the operator's
    intent, and an incident pause that looks identical to a retirement is
    one someone forgets to undo.

Both are additive and nullable-or-defaulted, so the upgrade is non-destructive
and the downgrade is a plain DROP COLUMN. That drop is not free, though:
``paused_at`` is the only record that a hold exists, and dropping it releases
every held schedule at once. The downgrade therefore refuses while any hold is
in place, so rolling back is reversible in the only sense an operator cares
about. It takes ``schedules`` against writers to do that, which means a
rollback attempted against a running brain waits for the pause traffic instead
of racing it.

``overlap_policy`` does NOT round-trip: the drop discards it and the
re-upgrade gives every row the default again. That is harmless only while
nothing can write it (no create or update path sets it today, and the field is
read-only on the API), and it stops being harmless the day a write path lands.
Whoever adds that write path owns extending the guard below to refuse on a
non-default policy the same way it refuses on a live hold.

The schema drop also crosses a cadence-runtime boundary. Rows written by the
published 1.8.2 image carry its Python 3.14.6 runtime fingerprint while rows
written by 1.9 carry Python 3.14.7. Before this revision may downgrade a
non-empty reserved schedule set, the exact 1.9 carrier must run the two-phase
``prepare-runtime-rollback`` ceremony against the finalized compatibility
image authority. That transaction restamps/replans every reserved row through
ordinary Boundary-D revisions and emits authenticated audit evidence. This
migration rechecks the exact image/manifest/qualification receipt, complete
row population, global revision and prune watermarks, per-row stamp/revision,
and latest snapshots immediately before dropping the columns. An unfinalized
image authority or any schedule transition after preparation refuses the
whole downgrade plan.

``agents.revoked_at``
    Records the soft delete that ``events.agent_id ON DELETE RESTRICT`` has
    always required. A revoked row keeps event history attached while its
    token hash is replaced with a non-user sentinel. If a replacement later
    reuses the operational name, creation moves the tombstone into a reserved
    namespace under the same row lock. Downgrade is refused while a tombstone
    exists: the older hygiene worker hard-deletes stale agents, which would
    either fail on PostgreSQL or orphan events on SQLite.

Revision ID: v1_9_schedule_control_columns
Revises: v1_8_schedule_cursor_repair
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_9_schedule_control_columns"
down_revision: str | Sequence[str] | None = "v1_8_schedule_cursor_repair"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "schedules"
_OVERLAP = "overlap_policy"
_PAUSED_AT = "paused_at"
_AGENTS = "agents"
_REVOKED_AT = "revoked_at"

#: Allowed overlap policies. Enforced as a CHECK on Postgres only, matching
#: how ``catch_up`` is handled: the model keeps a plain String so a
#: SQLite-mode downgrade can DROP COLUMN without rebuilding the table.
_OVERLAP_VALUES = ("allow", "skip", "queue")

_ROLLBACK_AUDIT_ACTION = "system.prepare_runtime_rollback"
_ROLLBACK_TARGET_RELEASE = "1.8.2"
_ROLLBACK_TARGET_FINGERPRINT = "5e63a2ae8ec66ec9b86f64828b7ac2499c9254531d2ceb33e32ac3a80c344ef4"
_ROLLBACK_IMAGE_PATTERN = re.compile(r"docker[.]io/z4jdev/z4j@sha256:[0-9a-f]{64}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _json_object(value: object, *, field: str) -> dict[str, object]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise CommandError(
                f"refusing downgrade: runtime rollback {field} is invalid JSON",
            ) from exc
    if not isinstance(value, dict):
        raise CommandError(
            f"refusing downgrade: runtime rollback {field} is not an object",
        )
    return value


_TARGET_NATIVE_ENV = "Z4J_ROLLBACK_TARGET_FINGERPRINT"


def _assert_rows_are_target_native(
    reserved: Sequence[sa.RowMapping],
    declared_target: str,
) -> None:
    """Admit a downgrade when no row has been written since the target wrote it.

    The container ceremony exists because a restamp is a claim: it rewrites
    cursors and asserts the target will agree with them. This path makes no
    such claim, because it rewrites nothing. It admits the downgrade only when
    every reserved row still carries the identity the target itself wrote, in
    which case going back restores exactly the state the target last saw.

    That is checkable rather than attested, so it needs no image, no registry
    and no signature. Nothing in the current release re-stamps a row: the five
    write sites are all creation or owner cutover, and neither the fire path
    nor the cursor path touches the column. So an installation that upgraded
    and then merely ran is admissible, which is the ordinary case.

    The operator declares what their target computes. That declaration cannot
    make a bad downgrade succeed, because it has to equal what the rows already
    carry; its purpose is to force the operator to measure the target they are
    about to install rather than assume it. What the check cannot do is verify
    the declaration was actually measured, and the refusals say so.
    """

    from z4j_brain.domain.schedule_cadence import (
        CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint,
    )

    declared = declared_target.strip().lower()
    if _SHA256_PATTERN.fullmatch(declared) is None:
        raise CommandError(
            f"refusing downgrade: {_TARGET_NATIVE_ENV} is not a sha256 digest. "
            "Set it to the cadence runtime fingerprint your target install "
            "computes, obtained by running this in the target environment: "
            "python -c 'from z4j_brain.domain.schedule_cadence import "
            "cadence_runtime_fingerprint as f; print(f())'",
        )

    running = cadence_runtime_fingerprint()
    if declared == running:
        raise CommandError(
            f"refusing downgrade: {_TARGET_NATIVE_ENV} equals the fingerprint "
            "this release computes, so it does not describe a downgrade "
            "target. Measure the release you are returning to, not this one.",
        )

    observed = {str(row["cadence_runtime_fingerprint"] or "") for row in reserved}
    if len(observed) != 1:
        raise CommandError(
            "refusing downgrade: reserved schedules carry "
            f"{len(observed)} different cadence identities, so they were not "
            "all written by one release. Restore the pre-upgrade backup under "
            "the release you are returning to; see docs/UPGRADE.md.",
        )

    stored = observed.pop()
    if stored != declared:
        raise CommandError(
            "refusing downgrade: reserved schedules carry cadence fingerprint "
            f"{stored}, but {_TARGET_NATIVE_ENV} declares {declared}. Rows "
            "written by this release cannot be handed to a target that "
            "computes something else; it disables every schedule it cannot "
            "agree with. Restore the pre-upgrade backup instead.",
        )

    for row in reserved:
        if (
            int(row["cadence_semantics_version"] or 0) != CADENCE_SEMANTICS_VERSION
            or not row["schedule_revision"]
            or _SHA256_PATTERN.fullmatch(str(row["definition_digest"] or "")) is None
        ):
            raise CommandError(
                f"refusing downgrade: schedule {row['id']} has an incomplete "
                "Boundary-D identity, so it cannot be shown to predate this "
                "release. Restore the pre-upgrade backup instead.",
            )


def _assert_runtime_rollback_prepared(  # noqa: PLR0912, PLR0915
    bind: sa.engine.Connection,
) -> None:
    """Require the durable all-row target preparation before dropping 1.9."""

    schedules = sa.table(
        _TABLE,
        sa.column("id"),
        sa.column("scheduler"),
        sa.column("schedule_revision"),
        sa.column("definition_digest"),
        sa.column("cadence_semantics_version"),
        sa.column("cadence_runtime_fingerprint"),
    )
    change_log = sa.table(
        "schedule_change_log",
        sa.column("revision"),
        sa.column("schedule_id"),
        sa.column("change_kind"),
        sa.column("snapshot", sa.JSON()),
    )
    audit_log = sa.table(
        "audit_log",
        sa.column("id"),
        sa.column("action"),
        sa.column("target_id"),
        sa.column("result"),
        sa.column("outcome"),
        sa.column("metadata", sa.JSON()),
        sa.column("occurred_at"),
        sa.column("legacy_frozen"),
        sa.column("hmac_version"),
        sa.column("row_hmac"),
        sa.column("chain_generation"),
    )
    revision_state = sa.table(
        "schedule_revision_state",
        sa.column("current_revision"),
        sa.column("change_log_pruned_through"),
    )
    reserved = list(
        bind.execute(
            sa.select(
                schedules.c.id,
                schedules.c.schedule_revision,
                schedules.c.definition_digest,
                schedules.c.cadence_semantics_version,
                schedules.c.cadence_runtime_fingerprint,
            )
            .where(schedules.c.scheduler == "z4j-scheduler")
            .order_by(schedules.c.id),
        ).mappings(),
    )
    external_count = bind.execute(
        sa.select(sa.func.count())
        .select_from(schedules)
        .where(schedules.c.scheduler != "z4j-scheduler"),
    ).scalar_one()
    if not reserved:
        return
    state = (
        bind.execute(
            sa.select(
                revision_state.c.current_revision,
                revision_state.c.change_log_pruned_through,
            ),
        )
        .mappings()
        .one_or_none()
    )
    if state is None:
        raise CommandError("refusing downgrade: Boundary-D revision state is absent")

    # Second admissible path, discriminated by the operator explicitly declaring
    # a target. Absent that declaration this is the container ceremony exactly as
    # before, byte for byte. The two never interleave.
    declared_target = os.environ.get(_TARGET_NATIVE_ENV, "").strip()
    if declared_target:
        _assert_rows_are_target_native(reserved, declared_target)
        return

    from z4j_brain.domain.runtime_rollback import (
        ROLLBACK_COSIGN_PATH,
        ROLLBACK_DURABLE_EVIDENCE_ENV,
        RuntimeRollbackRefused,
        durable_evidence_sha256,
        load_finalized_rollback_manifest,
        verify_durable_rollback_evidence,
    )

    try:
        target_authority = load_finalized_rollback_manifest()
    except RuntimeRollbackRefused as exc:
        raise CommandError(
            "refusing downgrade: rollback compatibility image authority is not finalized",
        ) from exc
    from z4j_brain.domain.production_container_authority import (
        PRODUCTION_AUTHORITY_ENV,
        ProductionContainerAuthorityRefused,
        load_finalized_production_authority,
    )

    production_root = os.environ.get(PRODUCTION_AUTHORITY_ENV, "").strip()
    if not production_root:
        raise CommandError(
            "refusing downgrade: Z4J_PRODUCTION_FINALIZATION_ROOT must name the "
            "read-only finalized 1.9 production-container authority",
        )
    try:
        source_authority = load_finalized_production_authority(Path(production_root))
    except ProductionContainerAuthorityRefused as exc:
        raise CommandError(
            "refusing downgrade: normal 1.9 production-container authority "
            "is absent, unfinalized, unauthenticated, or differs from registry bytes",
        ) from exc
    durable_root = os.environ.get(ROLLBACK_DURABLE_EVIDENCE_ENV, "").strip()
    if not durable_root:
        raise CommandError(
            "refusing downgrade: Z4J_ROLLBACK_COMPAT_EVIDENCE_ROOT must name the "
            "read-only portable Q/F/(P|R)/release-index evidence graph",
        )
    try:
        durable_evidence = verify_durable_rollback_evidence(
            Path(durable_root),
            cosign_path=ROLLBACK_COSIGN_PATH,
        )
    except RuntimeRollbackRefused as exc:
        raise CommandError(
            "refusing downgrade: durable rollback evidence graph is absent, "
            "unauthenticated, expired-without-an-OCI-copy, or substituted",
        ) from exc
    durable_evidence_digest = durable_evidence_sha256(durable_evidence)
    if durable_evidence["candidate_components"]["index"] != target_authority["index"]:
        raise CommandError(
            "refusing downgrade: durable rollback evidence binds a different candidate",
        )
    from z4j_brain.persistence.repositories.audit_log import AUDIT_CHAIN_ADVISORY_LOCK_KEY

    # Match every Boundary-F writer before selecting the claimed audit head.
    # The transaction-scoped advisory lock and later state/head row locks
    # remain held through the protected DROP.
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
        )
    expected_target_image = f"docker.io/z4jdev/z4j@{target_authority['index']['digest']}"
    audit = (
        bind.execute(
            sa.select(audit_log)
            .where(audit_log.c.action == _ROLLBACK_AUDIT_ACTION)
            .order_by(audit_log.c.occurred_at.desc(), audit_log.c.id.desc())
            .limit(1),
        )
        .mappings()
        .first()
    )
    if audit is None:
        raise CommandError(
            "refusing downgrade: run 'z4j migrate "
            "prepare-runtime-rollback' before crossing the 1.9 schedule boundary",
        )

    # The receipt is an authority only when both its row and the active chain
    # state authenticate under the configured Boundary-F keys.  Requiring the
    # preparation row to be the exact authenticated head also makes any later
    # audit-producing activity invalidate the quiescent downgrade ceremony.
    from sqlalchemy.orm import Session
    from z4j_brain.domain.audit_chain import (
        AUDIT_ROW_HMAC_VERSION,
        AuditChainIntegrityError,
        authenticate_state,
        canonical_audit_key_id,
        normalize_timestamp,
    )
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import AuditChainState, AuditLog
    from z4j_brain.persistence.models.audit_chain import AUDIT_CHAIN_SINGLETON_ID
    from z4j_brain.settings import Settings

    with Session(bind=bind) as orm_session:
        chain_state = orm_session.execute(
            sa.select(AuditChainState)
            .where(AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID)
            .with_for_update(),
        ).scalar_one_or_none()
        audit_row = orm_session.execute(
            sa.select(AuditLog).where(AuditLog.id == audit["id"]).with_for_update(),
        ).scalar_one_or_none()
    if audit_row is None or chain_state is None:
        raise CommandError(
            "refusing downgrade: runtime rollback audit row or active chain state is absent",
        )
    try:
        settings = Settings()  # type: ignore[call-arg]
        audit_secrets = settings.all_audit_chain_secrets_for_verification()
        keyring = {canonical_audit_key_id(secret): secret for secret in audit_secrets}
        authenticate_state(chain_state, keyring)
        row_verified = AuditService(settings).verify_row(audit_row)
        row_time = normalize_timestamp(audit_row.occurred_at)
        head_time = normalize_timestamp(chain_state.head_occurred_at)
    except (AuditChainIntegrityError, RuntimeError, TypeError, ValueError) as exc:
        raise CommandError(
            "refusing downgrade: runtime rollback audit-chain authentication failed",
        ) from exc
    if (
        not row_verified
        or audit_row.hmac_version != AUDIT_ROW_HMAC_VERSION
        or audit_row.legacy_frozen is not False
        or audit_row.chain_generation != chain_state.generation
        or audit_row.id != chain_state.head_id
        or audit_row.row_hmac != chain_state.head_row_hmac
        or audit_row.hmac_key_id != chain_state.head_hmac_key_id
        or row_time != head_time
    ):
        raise CommandError(
            "refusing downgrade: runtime rollback audit row is not the "
            "verified active-generation head",
        )

    metadata = _json_object(audit["metadata"], field="audit metadata")
    target_image = str(metadata.get("target_image", ""))
    operation_id = str(metadata.get("operation_id", ""))
    schedule_revisions = _json_object(metadata.get("schedule_revisions"), field="revisions")
    if (
        audit["result"] != "success"
        or audit["outcome"] != "allow"
        or audit["target_id"] != operation_id
        or audit["legacy_frozen"] is not False
        or audit["hmac_version"] != AUDIT_ROW_HMAC_VERSION
        or audit["row_hmac"] != audit_row.row_hmac
        or audit["chain_generation"] != chain_state.generation
        or metadata.get("candidate_source_revision") != source_authority["source_revision"]
        or metadata.get("candidate_image") != source_authority["source_image"]
        or metadata.get("candidate_production_authority") != source_authority
        or metadata.get("candidate_production_authority_sha256")
        != source_authority["authority_sha256"]
        or metadata.get("target_release") != _ROLLBACK_TARGET_RELEASE
        or metadata.get("target_cadence_runtime_fingerprint") != _ROLLBACK_TARGET_FINGERPRINT
        or _ROLLBACK_IMAGE_PATTERN.fullmatch(target_image) is None
        or target_image != expected_target_image
        or metadata.get("target_image_manifest_sha256") != target_authority["manifest_sha256"]
        or metadata.get("target_image_platforms") != target_authority["platforms"]
        or metadata.get("target_image_release_receipt_sha256")
        != target_authority["release_receipt_sha256"]
        or metadata.get("target_durable_evidence") != durable_evidence
        or metadata.get("target_durable_evidence_sha256") != durable_evidence_digest
        or metadata.get("target_release_evidence_index") != durable_evidence["release_index"]
        or metadata.get("target_evidence_terminal_stage") != durable_evidence["terminal_stage"]
        or _SHA256_PATTERN.fullmatch(str(metadata.get("row_set_digest", ""))) is None
        or _SHA256_PATTERN.fullmatch(
            str(metadata.get("quiescence_challenge_sha256", "")),
        )
        is None
        or metadata.get("quiescence_assertion") != "all Brain and scheduler executors are stopped"
        or metadata.get("schedule_revision_watermark") != state["current_revision"]
        or metadata.get("change_log_pruned_through") != state["change_log_pruned_through"]
    ):
        raise CommandError(
            "refusing downgrade: latest runtime rollback audit receipt is "
            "incomplete, unauthenticated, or bound to the wrong target",
        )

    prepared_ids = {str(value) for value in metadata.get("prepared_schedule_ids", [])}
    noop_ids = {str(value) for value in metadata.get("noop_schedule_ids", [])}
    reserved_ids = {str(row["id"]) for row in reserved}
    if (
        set(schedule_revisions) != reserved_ids
        or prepared_ids & noop_ids
        or prepared_ids | noop_ids != reserved_ids
        or metadata.get("changed_count") != len(prepared_ids)
        or metadata.get("noop_count") != len(noop_ids)
        or metadata.get("block_count") != 0
        or metadata.get("external_schedule_count") != external_count
    ):
        raise CommandError(
            "refusing downgrade: runtime rollback audit row set does not "
            "equal the current reserved/external schedule population",
        )

    for row in reserved:
        schedule_id = str(row["id"])
        if schedule_revisions.get(schedule_id) != row["schedule_revision"]:
            raise CommandError(
                f"refusing downgrade: schedule {schedule_id} changed after preparation",
            )
        if (
            row["cadence_semantics_version"] != 1
            or row["cadence_runtime_fingerprint"] != _ROLLBACK_TARGET_FINGERPRINT
            or not row["schedule_revision"]
            or _SHA256_PATTERN.fullmatch(str(row["definition_digest"] or "")) is None
        ):
            raise CommandError(
                f"refusing downgrade: schedule {schedule_id} is not stamped "
                "for the sealed compatibility runtime",
            )
        latest = (
            bind.execute(
                sa.select(change_log)
                .where(
                    change_log.c.schedule_id == row["id"],
                    change_log.c.revision == row["schedule_revision"],
                )
                .limit(1),
            )
            .mappings()
            .first()
        )
        if latest is None or latest["change_kind"] != "upsert":
            raise CommandError(
                f"refusing downgrade: schedule {schedule_id} has no latest "
                "Boundary-D upsert snapshot",
            )
        snapshot = _json_object(latest["snapshot"], field="schedule snapshot")
        stored = _json_object(snapshot.get("schedule"), field="schedule payload")
        if (
            stored.get("cadence_semantics_version") != 1
            or stored.get("cadence_runtime_fingerprint") != _ROLLBACK_TARGET_FINGERPRINT
            or stored.get("definition_digest") != row["definition_digest"]
            or stored.get("schedule_revision") != row["schedule_revision"]
        ):
            raise CommandError(
                f"refusing downgrade: schedule {schedule_id} latest snapshot "
                "does not prove the target cadence identity",
            )
        transition_value = snapshot.get("transition")
        transition = (
            _json_object(transition_value, field="rollback transition")
            if transition_value is not None
            else None
        )
        if schedule_id in prepared_ids:
            if (
                transition is None
                or transition.get("kind") != "prepare_runtime_rollback"
                or transition.get("operation_id") != operation_id
                or transition.get("target_release") != _ROLLBACK_TARGET_RELEASE
                or transition.get("target_image") != target_image
                or transition.get("target_image_digest") != target_authority["index"]["digest"]
                or transition.get("target_image_manifest_sha256")
                != target_authority["manifest_sha256"]
                or transition.get("target_image_platforms") != target_authority["platforms"]
                or transition.get("target_image_release_receipt_sha256")
                != target_authority["release_receipt_sha256"]
                or transition.get("target_durable_evidence_sha256") != durable_evidence_digest
                or transition.get("target_release_evidence_index")
                != durable_evidence["release_index"]
                or transition.get("target_evidence_terminal_stage")
                != durable_evidence["terminal_stage"]
                or transition.get("target_cadence_semantics_version") != 1
                or transition.get("target_cadence_runtime_fingerprint")
                != _ROLLBACK_TARGET_FINGERPRINT
                or transition.get("definition_digest") != row["definition_digest"]
                or transition.get("quiescence_challenge_sha256")
                != metadata.get("quiescence_challenge_sha256")
            ):
                raise CommandError(
                    f"refusing downgrade: schedule {schedule_id} lacks the "
                    "operation-bound rollback transition",
                )
        elif schedule_id not in noop_ids:
            raise CommandError(
                f"refusing downgrade: schedule {schedule_id} is absent from "
                "the operation-bound no-op set",
            )


def upgrade() -> None:
    bind = op.get_bind()
    # Column additions are guarded so a partially-applied development database
    # can continue without duplicating a column. This is not a general repair
    # routine: for example, an existing overlap column with a missing CHECK
    # still needs operator inspection. The historical initial migration emits
    # the old table shapes, so fresh release-chain installs add these columns
    # here just like real upgrades.
    if not _column_exists(bind, _TABLE, _OVERLAP):
        op.add_column(
            _TABLE,
            sa.Column(
                _OVERLAP,
                sa.String(32),
                nullable=False,
                server_default="allow",
            ),
        )
        if bind.dialect.name == "postgresql":
            values = ", ".join(f"'{v}'" for v in _OVERLAP_VALUES)
            op.create_check_constraint(
                "ck_schedules_overlap_policy",
                _TABLE,
                f"{_OVERLAP} IN ({values})",
            )

    if not _column_exists(bind, _TABLE, _PAUSED_AT):
        op.add_column(
            _TABLE,
            sa.Column(_PAUSED_AT, sa.DateTime(timezone=True), nullable=True),
        )
    if not _column_exists(bind, _AGENTS, _REVOKED_AT):
        op.add_column(
            _AGENTS,
            sa.Column(_REVOKED_AT, sa.DateTime(timezone=True), nullable=True),
        )


def _assert_downgrade_state_is_safe(bind: sa.engine.Connection) -> None:
    """Refuse before any planned 1.9 revision mutates the database.

    Alembic commits each revision separately. When later 1.9 revisions are
    stacked above this one, waiting until this migration's ``downgrade`` body
    would let those revisions drop and commit their schema first. ``env.py``
    discovers this callback as explicit revision metadata and runs it while
    resolving the complete downgrade plan, ahead of its first migration body.

    ``downgrade()`` invokes the same check again immediately before its own
    drops. The second call closes the gap after an allowed plan preflight has
    stepped through newer revisions. PostgreSQL's table locks and SQLite's
    migration-wide exclusive transaction keep each check and its protected
    mutation on one database state.
    """

    has_paused_at = _column_exists(bind, _TABLE, _PAUSED_AT)
    has_overlap = _column_exists(bind, _TABLE, _OVERLAP)
    has_revoked_at = _column_exists(bind, _AGENTS, _REVOKED_AT)
    if bind.dialect.name == "postgresql" and (has_paused_at or has_overlap or has_revoked_at):
        # Boundary-D mutations lock their schedule row before allocating the
        # singleton revision. Take the schedules table first in that same
        # order, then lock the singleton and its append-only proof table so a
        # concurrent prune cannot advance the watermark or delete a validated
        # snapshot between preflight and DROP. Reversing the first two tables
        # makes a live pause wait on the singleton while the downgrade waits on
        # schedules: an avoidable deadlock at the exact rollback boundary this
        # guard is meant to make safe.
        bind.exec_driver_sql(
            f"LOCK TABLE {_TABLE}, schedule_revision_state, "
            f"schedule_change_log, {_AGENTS} IN ACCESS EXCLUSIVE MODE",
        )

    if has_paused_at:
        # The count and the DROP are two different instants. The PostgreSQL
        # lock above makes both statements see one state. SQLite needs no
        # extra lock because env.py runs the migration inside BEGIN EXCLUSIVE.
        schedules = sa.table(_TABLE, sa.column(_PAUSED_AT))
        held = bind.execute(
            sa.select(sa.func.count())
            .select_from(schedules)
            .where(schedules.c[_PAUSED_AT].is_not(None)),
        ).scalar_one()
        if held:
            # The column IS the hold. Dropping it releases every paused
            # schedule at once, silently, and the schedules start firing again
            # on the next cadence tick during whatever incident the operator
            # paused them for. Make them say so explicitly instead.
            raise CommandError(
                f"refusing downgrade: {held} schedule(s) are paused and "
                f"{_PAUSED_AT} is the only record of those holds; resume them "
                "first (they will start firing again) or roll back from a "
                "backup taken before the hold",
            )

        _assert_runtime_rollback_prepared(bind)

    if has_revoked_at:
        agents = sa.table(_AGENTS, sa.column(_REVOKED_AT))
        revoked = bind.execute(
            sa.select(sa.func.count())
            .select_from(agents)
            .where(agents.c[_REVOKED_AT].is_not(None)),
        ).scalar_one()
        if revoked:
            raise CommandError(
                f"refusing downgrade: {revoked} agent(s) are revoked and "
                f"{_REVOKED_AT} is the durable tombstone marker; restore a "
                "backup taken before those revocations to run the older "
                "release",
            )


# Read by migrations/env.py from every revision in the resolved downgrade
# plan. This explicit callback contract is deliberately independent of the
# revision id so future state-dependent migrations inherit whole-plan safety.
DOWNGRADE_PREFLIGHT = _assert_downgrade_state_is_safe


def downgrade() -> None:
    """Drop all three columns only when neither durable state would be lost."""

    bind = op.get_bind()
    _assert_downgrade_state_is_safe(bind)
    has_paused_at = _column_exists(bind, _TABLE, _PAUSED_AT)
    has_overlap = _column_exists(bind, _TABLE, _OVERLAP)
    has_revoked_at = _column_exists(bind, _AGENTS, _REVOKED_AT)

    if has_paused_at:
        op.drop_column(_TABLE, _PAUSED_AT)
    if has_overlap:
        # No explicit constraint drop. The CHECK the upgrade creates lands under
        # the metadata naming convention as ``ck_schedules_ck_schedules_overlap_policy``,
        # not under the bare name passed to ``create_check_constraint``, so a
        # ``drop_constraint`` by that bare name always failed with "constraint
        # does not exist". A first fix guarded the drop with a reflection check
        # for the same bare name, which never matched either: the downgrade then
        # passed, but only because the guarded statement never ran.
        #
        # Dropping the column removes every constraint that references it, on
        # both dialects. Verified on PostgreSQL 18: two overlap CHECKs before the
        # downgrade, zero after, column gone.
        op.drop_column(_TABLE, _OVERLAP)
    if has_revoked_at:
        op.drop_column(_AGENTS, _REVOKED_AT)
