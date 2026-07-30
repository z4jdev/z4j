"""Connection-local Boundary-D database transition authority.

The database triggers installed by the authenticated Boundary-D activation
accept schedule mutations only when the current transaction owns one exact,
one-shot descriptor.  PostgreSQL stores that descriptor in a transaction-local
GUC.  SQLite uses a connection-local UDF closure; a legacy connection does not
have the function and therefore fails closed in the trigger.

Direct ``Base.metadata.create_all()`` schemas deliberately have no activated
guard version.  This keeps model-only unit tests useful without representing
them as migration or enforcement evidence.
"""

from __future__ import annotations

import json
from typing import Any
from weakref import WeakSet

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import Session

SCHEDULE_GUARD_VERSION = 1

_ACTIVE_CACHE_KEY = "_z4j_schedule_guard_active"
_TRANSITION_ARMED_KEY = "_z4j_schedule_transition_armed"
_EVIDENCE_ARMED_KEY = "_z4j_schedule_evidence_armed"
_PRUNE_ARMED_KEY = "_z4j_schedule_prune_armed"
_RESET_ARMED_KEY = "_z4j_schedule_reset_armed"
_RESTORE_ARMED_KEY = "_z4j_schedule_restore_armed"
_ENGINES_WITH_HOOKS: WeakSet[Engine] = WeakSet()

_EVIDENCE_TRANSITION_REASONS: dict[str, frozenset[str]] = {
    "commands:delete": frozenset(
        {"command_retention", "legacy_resolution", "reset"},
    ),
    "schedule_fires:delete": frozenset(
        {"history_retention", "legacy_resolution", "reset"},
    ),
    "pending_fires:delete": frozenset(
        {
            "pending_expiry",
            "pending_replay",
            "pending_stale",
            "legacy_resolution",
            "schedule_delete",
            "reset",
        },
    ),
    "schedule_terminal_holds:insert": frozenset({"terminal_hold"}),
    "schedule_terminal_holds:update": frozenset(
        {"operator_resolution", "schedule_delete"},
    ),
    "schedule_terminal_holds:delete": frozenset(
        {"hold_retention", "reset"},
    ),
    "schedule_occurrence_resolutions:insert": frozenset(
        {"operator_resolution", "schedule_delete"},
    ),
    "schedule_occurrence_resolutions:delete": frozenset(
        {"resolution_retention", "reset"},
    ),
}


def _normalized(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("-", "").lower()


def _sqlite_guard_function() -> Any:  # noqa: PLR0915
    state: dict[str, Any] = {
        "allocation": False,
        "transition": None,
        "evidence": None,
        "prune": None,
        "reset": None,
        "restore": None,
    }

    def guard(  # noqa: PLR0911, PLR0912, PLR0915
        mode: str,
        operation: Any,
        schedule_id: Any,
        old_revision: Any,
        new_revision: Any,
        change_kind: Any,
        old_token: Any,
        new_token: Any,
    ) -> int:
        descriptor = (
            str(operation or ""),
            _normalized(schedule_id),
            str(old_revision or 0),
            str(new_revision or 0),
            str(change_kind or ""),
            _normalized(old_token),
            _normalized(new_token),
        )
        if mode == "arm_allocation":
            if state["allocation"]:
                raise RuntimeError("schedule revision allocation is already armed")
            state["allocation"] = True
            return 1
        if mode == "consume_allocation":
            if not state["allocation"]:
                raise RuntimeError("schedule revision allocation is not armed")
            state["allocation"] = False
            return 1
        if mode == "check_allocation":
            if state["allocation"]:
                raise RuntimeError("schedule revision allocation was not consumed")
            return 1
        if mode == "arm_transition":
            if state["transition"] is not None:
                raise RuntimeError("schedule transition is already armed")
            state["transition"] = descriptor
            return 1
        if mode == "consume_transition":
            if state["transition"] != descriptor:
                raise RuntimeError("schedule transition descriptor mismatch")
            state["transition"] = None
            return 1
        if mode == "check_transition":
            if state["transition"] is not None:
                raise RuntimeError("schedule transition was not consumed")
            return 1
        if mode == "arm_evidence":
            scope = str(operation or "")
            reason = str(change_kind or "")
            if reason not in _EVIDENCE_TRANSITION_REASONS.get(
                scope,
                frozenset(),
            ):
                raise RuntimeError("invalid schedule evidence transition")
            if state["evidence"] is not None:
                raise RuntimeError("schedule evidence transition is already armed")
            state["evidence"] = (
                scope,
                _normalized(schedule_id),
                _normalized(old_revision),
                reason,
            )
            return 1
        if mode == "consume_evidence":
            armed = state["evidence"]
            requested = (
                str(operation or ""),
                _normalized(schedule_id),
                _normalized(old_revision),
            )
            if not isinstance(armed, tuple) or armed[:3] != requested:
                raise RuntimeError("schedule evidence transition mismatch")
            state["evidence"] = None
            return 1
        if mode == "check_evidence":
            if state["evidence"] is not None:
                raise RuntimeError("schedule evidence transition was not consumed")
            return 1
        if mode == "arm_prune":
            old_boundary = int(operation)
            new_boundary = int(schedule_id)
            expected_count = int(old_revision)
            if (
                state["prune"] is not None
                or old_boundary < 0
                or new_boundary <= old_boundary
                or expected_count < 0
            ):
                raise RuntimeError("invalid schedule change-log prune")
            state["prune"] = (
                str(old_boundary),
                str(new_boundary),
                str(expected_count),
                "0",
            )
            return 1
        if mode == "consume_prune":
            armed = state["prune"]
            if not isinstance(armed, tuple):
                raise RuntimeError("schedule change-log prune is not armed")
            revision = int(old_revision)
            new_boundary = int(armed[1])
            expected_count = int(armed[2])
            consumed_count = int(armed[3])
            if revision <= 0 or revision > new_boundary or consumed_count >= expected_count:
                raise RuntimeError("schedule change-log prune row mismatch")
            state["prune"] = (
                armed[0],
                armed[1],
                armed[2],
                str(consumed_count + 1),
            )
            return 1
        if mode == "finalize_prune":
            armed = state["prune"]
            requested = (
                str(int(operation)),
                str(int(schedule_id)),
            )
            if not isinstance(armed, tuple) or armed[:2] != requested or armed[2] != armed[3]:
                raise RuntimeError(
                    "schedule change-log prune descriptor mismatch",
                )
            state["prune"] = None
            return 1
        if mode == "check_prune":
            if state["prune"] is not None:
                raise RuntimeError("schedule change-log prune was not consumed")
            return 1
        if mode == "arm_reset":
            if state["reset"] is not None:
                raise RuntimeError("schedule reset is already armed")
            try:
                expected_counts = json.loads(str(operation))
            except (TypeError, ValueError) as exc:
                raise RuntimeError("schedule reset descriptor is malformed") from exc
            if (
                not isinstance(expected_counts, dict)
                or not expected_counts
                or any(
                    not isinstance(table_name, str) or not isinstance(count, int) or count < 0
                    for table_name, count in expected_counts.items()
                )
                or int(old_revision) < 0
                or int(new_revision) != int(old_revision) + 1
                or int(change_kind) < 0
                or int(old_token) <= int(change_kind)
                or len(str(schedule_id)) != 64
                or len(str(new_token)) != 64
            ):
                raise RuntimeError("invalid schedule reset descriptor")
            state["reset"] = {
                "expected_counts": dict(expected_counts),
                "consumed_counts": dict.fromkeys(expected_counts, 0),
                "manifest_digest": str(schedule_id),
                "old_revision": int(old_revision),
                "new_revision": int(new_revision),
                "old_epoch": int(change_kind),
                "new_epoch": int(old_token),
                "attestation_digest": str(new_token),
                "revision_consumed": False,
                "epoch_consumed": False,
            }
            return 1
        if mode == "is_reset":
            return int(state["reset"] is not None)
        if mode == "consume_reset_row":
            reset = state["reset"]
            table_name = str(operation)
            if (
                not isinstance(reset, dict)
                or table_name not in reset["expected_counts"]
                or reset["consumed_counts"][table_name] >= reset["expected_counts"][table_name]
            ):
                raise RuntimeError("schedule reset row is outside the manifest")
            reset["consumed_counts"][table_name] += 1
            return 1
        if mode == "consume_reset_revision":
            reset = state["reset"]
            if (
                not isinstance(reset, dict)
                or reset["revision_consumed"]
                or int(old_revision) != reset["old_revision"]
                or int(new_revision) != reset["new_revision"]
            ):
                raise RuntimeError("schedule reset revision barrier mismatch")
            reset["revision_consumed"] = True
            return 1
        if mode == "consume_reset_epoch":
            reset = state["reset"]
            if (
                not isinstance(reset, dict)
                or reset["epoch_consumed"]
                or int(old_revision) != reset["old_epoch"]
                or int(new_revision) != reset["new_epoch"]
            ):
                raise RuntimeError("schedule reset epoch barrier mismatch")
            reset["epoch_consumed"] = True
            return 1
        if mode == "finalize_reset":
            reset = state["reset"]
            if (
                not isinstance(reset, dict)
                or reset["manifest_digest"] != str(schedule_id)
                or reset["attestation_digest"] != str(new_token)
                or not reset["revision_consumed"]
                or not reset["epoch_consumed"]
                or reset["consumed_counts"] != reset["expected_counts"]
            ):
                raise RuntimeError("schedule reset descriptor was not consumed")
            state["reset"] = None
            return 1
        if mode == "check_reset":
            if state["reset"] is not None:
                raise RuntimeError("schedule reset was not consumed")
            return 1
        if mode == "arm_restore":
            if state["restore"] is not None:
                raise RuntimeError("schedule restore is already armed")
            try:
                raw = json.loads(str(operation))
                schedules = {
                    _normalized(item["schedule_id"]): {
                        "old_revision": int(item["old_revision"]),
                        "new_revision": int(item["new_revision"]),
                        "control_token": _normalized(
                            item["control_token"],
                        ),
                    }
                    for item in raw["schedules"]
                }
                restore = {
                    "manifest_digest": str(raw["manifest_digest"]),
                    "attestation_digest": str(
                        raw["attestation_digest"],
                    ),
                    "restored_revision": int(
                        raw["restored_revision"],
                    ),
                    "barrier_revision": int(raw["barrier_revision"]),
                    "final_revision": int(raw["final_revision"]),
                    "restored_epoch": int(raw["restored_epoch"]),
                    "epoch_barrier": int(raw["epoch_barrier"]),
                    "schedules": schedules,
                    "revision_consumed": False,
                    "epoch_consumed": False,
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "schedule restore descriptor is malformed",
                ) from exc
            ordered = sorted(
                schedules.items(),
                key=lambda item: item[0],
            )
            expected_revisions = list(
                range(
                    restore["barrier_revision"] + 1,
                    restore["final_revision"] + 1,
                ),
            )
            if (
                len(schedules) != len(raw["schedules"])
                or len(restore["manifest_digest"]) != 64
                or len(restore["attestation_digest"]) != 64
                or restore["restored_revision"] < 0
                or restore["barrier_revision"] <= restore["restored_revision"]
                or restore["final_revision"] != restore["barrier_revision"] + len(schedules)
                or restore["restored_epoch"] < 0
                or restore["epoch_barrier"] <= restore["restored_epoch"]
                or [item[1]["new_revision"] for item in ordered] != expected_revisions
                or any(
                    not schedule_id or item["old_revision"] <= 0 or not item["control_token"]
                    for schedule_id, item in ordered
                )
            ):
                raise RuntimeError("invalid schedule restore descriptor")
            state["restore"] = restore
            return 1
        if mode == "is_restore":
            return int(state["restore"] is not None)
        if mode == "consume_restore_revision":
            restore = state["restore"]
            if (
                not isinstance(restore, dict)
                or restore["revision_consumed"]
                or int(operation) != restore["restored_revision"]
                or int(schedule_id) != restore["barrier_revision"]
                or int(old_revision) != restore["restored_revision"]
                or int(new_revision) != restore["final_revision"]
            ):
                raise RuntimeError(
                    "schedule restore revision barrier mismatch",
                )
            restore["revision_consumed"] = True
            return 1
        if mode == "consume_restore_epoch":
            restore = state["restore"]
            if (
                not isinstance(restore, dict)
                or restore["epoch_consumed"]
                or int(old_revision) != restore["restored_epoch"]
                or int(new_revision) != restore["epoch_barrier"]
            ):
                raise RuntimeError(
                    "schedule restore epoch barrier mismatch",
                )
            restore["epoch_consumed"] = True
            return 1
        if mode == "consume_restore_schedule":
            restore = state["restore"]
            schedule_key = _normalized(schedule_id)
            expected = restore["schedules"].get(schedule_key) if isinstance(restore, dict) else None
            if (
                not isinstance(expected, dict)
                or str(operation) != "update"
                or int(old_revision) != expected["old_revision"]
                or int(new_revision) != expected["new_revision"]
                or str(change_kind) not in {"upsert", "gap"}
                or _normalized(old_token) != expected["control_token"]
                or _normalized(new_token) != expected["control_token"]
            ):
                raise RuntimeError(
                    "schedule restore row is outside the manifest",
                )
            del restore["schedules"][schedule_key]
            return 1
        if mode == "finalize_restore":
            restore = state["restore"]
            if (
                not isinstance(restore, dict)
                or restore["manifest_digest"] != str(schedule_id)
                or restore["attestation_digest"] != str(new_token)
                or not restore["revision_consumed"]
                or not restore["epoch_consumed"]
                or restore["schedules"]
            ):
                raise RuntimeError(
                    "schedule restore descriptor was not consumed",
                )
            state["restore"] = None
            return 1
        if mode == "check_restore":
            if state["restore"] is not None:
                raise RuntimeError("schedule restore was not consumed")
            return 1
        if mode == "clear":
            state["allocation"] = False
            state["transition"] = None
            state["evidence"] = None
            state["prune"] = None
            state["reset"] = None
            state["restore"] = None
            return 1
        raise RuntimeError("unknown schedule guard operation")

    return guard


def register_sqlite_schedule_guard(dbapi_connection: Any) -> None:
    """Register a fresh fail-closed guard closure on one SQLite connection."""

    from z4j_brain.persistence.audit_guard import register_sqlite_audit_guard

    register_sqlite_audit_guard(dbapi_connection)
    dbapi_connection.create_function(
        "z4j_schedule_guard",
        8,
        _sqlite_guard_function(),
    )
    from z4j_brain.persistence.schedule_external_guard import (
        register_sqlite_schedule_external_guard,
    )

    register_sqlite_schedule_external_guard(dbapi_connection)


def install_schedule_guard_engine_hooks(engine: AsyncEngine) -> None:
    """Install SQLite guard UDFs on every connection of ``engine``."""

    sync_engine = engine.sync_engine
    if sync_engine in _ENGINES_WITH_HOOKS:
        return
    _ENGINES_WITH_HOOKS.add(sync_engine)
    if sync_engine.dialect.name != "sqlite":
        return

    def _register(dbapi_connection: Any, *_unused: Any) -> None:
        register_sqlite_schedule_guard(dbapi_connection)

    event.listen(sync_engine, "connect", _register)
    event.listen(sync_engine, "checkout", _register)


async def _guard_active(session: AsyncSession) -> bool:
    cached = session.sync_session.info.get(_ACTIVE_CACHE_KEY)
    if cached is not None:
        return bool(cached)
    result = await session.execute(
        text(
            "SELECT guard_version FROM schedule_revision_state "
            "WHERE singleton_id = 'schedule-revision'",
        ),
    )
    value = result.scalar_one_or_none()
    active = value == SCHEDULE_GUARD_VERSION
    session.sync_session.info[_ACTIVE_CACHE_KEY] = active
    return active


async def arm_revision_allocation(session: AsyncSession) -> bool:
    """Arm one current-revision increment, returning whether D is active."""

    if not await _guard_active(session):
        return False
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard('arm_allocation', '', '', 0, 0, '', '', '')",
            ),
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_allocation_guard', 'armed', true)",
            ),
        )
    else:
        raise RuntimeError(f"unsupported Boundary-D database: {dialect}")
    return True


async def assert_revision_allocation_consumed(
    session: AsyncSession,
    *,
    active: bool,
) -> None:
    if not active:
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard('check_allocation', '', '', 0, 0, '', '', '')",
            ),
        )
        return
    remaining = await session.scalar(
        text(
            "SELECT current_setting('z4j.schedule_allocation_guard', true)",
        ),
    )
    if remaining:
        raise RuntimeError("schedule revision allocation was not consumed")


async def arm_schedule_transition(
    session: AsyncSession,
    *,
    operation: str,
    schedule_id: Any,
    old_revision: int,
    new_revision: int,
    change_kind: str,
    old_token: Any,
    new_token: Any,
) -> None:
    """Arm exactly one schedule INSERT/UPDATE/DELETE descriptor."""

    if not await _guard_active(session):
        return
    descriptor = {
        "operation": operation,
        "schedule_id": str(schedule_id),
        "old_revision": old_revision,
        "new_revision": new_revision,
        "change_kind": change_kind,
        "old_token": str(old_token) if old_token is not None else None,
        "new_token": str(new_token) if new_token is not None else None,
    }
    if session.sync_session.info.get(_TRANSITION_ARMED_KEY):
        raise RuntimeError("a schedule transition is already armed")
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'arm_transition', :operation, :schedule_id, "
                ":old_revision, :new_revision, :change_kind, "
                ":old_token, :new_token)",
            ),
            descriptor,
        )
    elif dialect == "postgresql":
        encoded = json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded) > 4096:
            raise RuntimeError("schedule transition descriptor is oversized")
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_transition_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(f"unsupported Boundary-D database: {dialect}")
    session.sync_session.info[_TRANSITION_ARMED_KEY] = True


async def arm_evidence_delete(
    session: AsyncSession,
    *,
    table_name: str,
    row_id: Any,
    old_nonce: Any,
    reason: str,
) -> bool:
    """Arm one exact marked-evidence DELETE and return whether D is active."""

    return await arm_evidence_transition(
        session,
        table_name=table_name,
        operation="delete",
        row_id=row_id,
        nonce=old_nonce,
        reason=reason,
    )


async def arm_evidence_transition(
    session: AsyncSession,
    *,
    table_name: str,
    operation: str,
    row_id: Any,
    nonce: Any,
    reason: str,
) -> bool:
    """Arm one exact evidence INSERT/UPDATE/DELETE transition."""

    scope = f"{table_name}:{operation}"
    if reason not in _EVIDENCE_TRANSITION_REASONS.get(
        scope,
        frozenset(),
    ):
        raise ValueError("unsupported schedule evidence transition")
    if not await _guard_active(session):
        return False
    if session.sync_session.info.get(_EVIDENCE_ARMED_KEY):
        raise RuntimeError("a schedule evidence transition is already armed")
    descriptor = {
        "scope": scope,
        "row_id": str(row_id),
        "old_nonce": str(nonce),
        "reason": reason,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'arm_evidence', :scope, :row_id, :old_nonce, "
                "0, :reason, '', '')",
            ),
            descriptor,
        )
    elif dialect == "postgresql":
        encoded = json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
        )
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_evidence_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(f"unsupported Boundary-D database: {dialect}")
    session.sync_session.info[_EVIDENCE_ARMED_KEY] = True
    return True


async def assert_evidence_delete_consumed(
    session: AsyncSession,
    *,
    active: bool,
) -> None:
    """Fail if an armed evidence delete did not consume its descriptor."""

    await assert_evidence_transition_consumed(
        session,
        active=active,
    )


async def assert_evidence_transition_consumed(
    session: AsyncSession,
    *,
    active: bool,
) -> None:
    """Fail if an armed evidence transition was not consumed."""

    if not active:
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard('check_evidence', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        remaining = await session.scalar(
            text(
                "SELECT current_setting('z4j.schedule_evidence_guard', true)",
            ),
        )
        if remaining:
            raise RuntimeError("schedule evidence transition was not consumed")
    session.sync_session.info.pop(_EVIDENCE_ARMED_KEY, None)


async def arm_change_log_prune(
    session: AsyncSession,
    *,
    old_boundary: int,
    new_boundary: int,
    expected_count: int,
) -> bool:
    """Arm one contiguous schedule change-log prefix prune."""

    if old_boundary < 0 or new_boundary <= old_boundary or expected_count < 0:
        raise ValueError("invalid schedule change-log prune descriptor")
    if not await _guard_active(session):
        return False
    if session.sync_session.info.get(_PRUNE_ARMED_KEY):
        raise RuntimeError("a schedule change-log prune is already armed")
    descriptor = {
        "old_boundary": old_boundary,
        "new_boundary": new_boundary,
        "expected_count": expected_count,
        "consumed_count": 0,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'arm_prune', :old_boundary, :new_boundary, "
                ":expected_count, 0, '', '', '')",
            ),
            descriptor,
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_prune_guard', :descriptor, true)",
            ),
            {
                "descriptor": json.dumps(
                    descriptor,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )
    else:
        raise RuntimeError(f"unsupported Boundary-D database: {dialect}")
    session.sync_session.info[_PRUNE_ARMED_KEY] = True
    return True


async def assert_change_log_prune_consumed(
    session: AsyncSession,
    *,
    active: bool,
) -> None:
    """Fail if the database did not finalize an armed change-log prune."""

    if not active:
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard('check_prune', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        remaining = await session.scalar(
            text(
                "SELECT current_setting('z4j.schedule_prune_guard', true)",
            ),
        )
        if remaining:
            raise RuntimeError("schedule change-log prune was not consumed")
    session.sync_session.info.pop(_PRUNE_ARMED_KEY, None)


async def arm_generation_reset(
    session: AsyncSession,
    *,
    expected_counts: dict[str, int],
    manifest_digest: str,
    old_revision: int,
    new_revision: int,
    old_epoch: int,
    new_epoch: int,
    attestation_digest: str,
) -> bool:
    """Arm one exact full-install Boundary-D destruction transition."""

    if (
        not expected_counts
        or any(not table or count < 0 for table, count in expected_counts.items())
        or len(manifest_digest) != 64
        or len(attestation_digest) != 64
        or old_revision < 0
        or new_revision != old_revision + 1
        or old_epoch < 0
        or new_epoch <= old_epoch
    ):
        raise ValueError("invalid schedule generation-reset descriptor")
    if not await _guard_active(session):
        return False
    if session.sync_session.info.get(_RESET_ARMED_KEY):
        raise RuntimeError("a schedule generation reset is already armed")
    descriptor = {
        "expected_counts": dict(sorted(expected_counts.items())),
        "consumed_counts": dict.fromkeys(sorted(expected_counts), 0),
        "manifest_digest": manifest_digest,
        "old_revision": old_revision,
        "new_revision": new_revision,
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
        "attestation_digest": attestation_digest,
        "revision_consumed": False,
        "epoch_consumed": False,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'arm_reset', :expected_counts, :manifest_digest, "
                ":old_revision, :new_revision, :old_epoch, "
                ":new_epoch, :attestation_digest)",
            ),
            {
                **descriptor,
                "expected_counts": json.dumps(
                    descriptor["expected_counts"],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )
    elif dialect == "postgresql":
        encoded = json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded) > 16_384:
            raise RuntimeError("schedule generation-reset descriptor is oversized")
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_reset_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(f"unsupported Boundary-D database: {dialect}")
    session.sync_session.info[_RESET_ARMED_KEY] = True
    return True


async def finalize_generation_reset(
    session: AsyncSession,
    *,
    active: bool,
    manifest_digest: str,
    attestation_digest: str,
) -> None:
    """Consume and prove the exact full-install reset descriptor."""

    if not active:
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'finalize_reset', '', :manifest_digest, 0, 0, '', '', "
                ":attestation_digest)",
            ),
            {
                "manifest_digest": manifest_digest,
                "attestation_digest": attestation_digest,
            },
        )
    else:
        await session.execute(
            text(
                "SELECT z4j_finalize_schedule_reset_v1(:manifest_digest, :attestation_digest)",
            ),
            {
                "manifest_digest": manifest_digest,
                "attestation_digest": attestation_digest,
            },
        )
    session.sync_session.info.pop(_RESET_ARMED_KEY, None)


async def arm_restore_rebase(
    session: AsyncSession,
    *,
    manifest_digest: str,
    attestation_digest: str,
    restored_revision: int,
    barrier_revision: int,
    final_revision: int,
    restored_epoch: int,
    epoch_barrier: int,
    schedules: list[dict[str, Any]],
) -> None:
    """Arm one exact revision-only database-restore rebase."""

    dialect = session.get_bind().dialect.name
    if session.sync_session.info.get(_RESTORE_ARMED_KEY):
        raise RuntimeError("a schedule restore rebase is already armed")
    descriptor = {
        "manifest_digest": manifest_digest,
        "attestation_digest": attestation_digest,
        "restored_revision": int(restored_revision),
        "barrier_revision": int(barrier_revision),
        "final_revision": int(final_revision),
        "restored_epoch": int(restored_epoch),
        "epoch_barrier": int(epoch_barrier),
        "schedules": schedules,
    }
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded) > 4 * 1024 * 1024:
        raise RuntimeError("schedule restore descriptor is oversized")
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard('arm_restore', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_restore_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_RESTORE_ARMED_KEY] = True


async def finalize_restore_rebase(
    session: AsyncSession,
    *,
    manifest_digest: str,
    attestation_digest: str,
) -> None:
    """Prove every manifested restore-rebase mutation was consumed."""

    if not session.sync_session.info.get(_RESTORE_ARMED_KEY):
        raise RuntimeError("schedule restore rebase is not armed")
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_guard("
                "'finalize_restore', '', :manifest_digest, 0, 0, '', '', "
                ":attestation_digest)",
            ),
            {
                "manifest_digest": manifest_digest,
                "attestation_digest": attestation_digest,
            },
        )
    else:
        await session.execute(
            text(
                "SELECT z4j_finalize_schedule_restore_v1(:manifest_digest, :attestation_digest)",
            ),
            {
                "manifest_digest": manifest_digest,
                "attestation_digest": attestation_digest,
            },
        )
    session.sync_session.info.pop(_RESTORE_ARMED_KEY, None)


def _assert_armed_guards_consumed(  # noqa: PLR0912  one commit gate covers every distinct descriptor
    session: Session,
    *_unused: Any,
) -> None:
    connection = session.connection()
    if session.info.get(_TRANSITION_ARMED_KEY):
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(
                "SELECT z4j_schedule_guard('check_transition', '', '', 0, 0, '', '', '')",
            )
        else:
            remaining = connection.exec_driver_sql(
                "SELECT current_setting('z4j.schedule_transition_guard', true)",
            ).scalar_one_or_none()
            if remaining:
                raise RuntimeError("schedule transition was not consumed")
        session.info.pop(_TRANSITION_ARMED_KEY, None)
    if session.info.get(_EVIDENCE_ARMED_KEY):
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(
                "SELECT z4j_schedule_guard('check_evidence', '', '', 0, 0, '', '', '')",
            )
        else:
            remaining = connection.exec_driver_sql(
                "SELECT current_setting('z4j.schedule_evidence_guard', true)",
            ).scalar_one_or_none()
            if remaining:
                raise RuntimeError(
                    "schedule evidence transition was not consumed",
                )
        session.info.pop(_EVIDENCE_ARMED_KEY, None)
    if session.info.get(_PRUNE_ARMED_KEY):
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(
                "SELECT z4j_schedule_guard('check_prune', '', '', 0, 0, '', '', '')",
            )
        else:
            remaining = connection.exec_driver_sql(
                "SELECT current_setting('z4j.schedule_prune_guard', true)",
            ).scalar_one_or_none()
            if remaining:
                raise RuntimeError(
                    "schedule change-log prune was not consumed",
                )
        session.info.pop(_PRUNE_ARMED_KEY, None)
    if session.info.get(_RESET_ARMED_KEY):
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(
                "SELECT z4j_schedule_guard('check_reset', '', '', 0, 0, '', '', '')",
            )
        else:
            remaining = connection.exec_driver_sql(
                "SELECT current_setting('z4j.schedule_reset_guard', true)",
            ).scalar_one_or_none()
            if remaining:
                raise RuntimeError(
                    "schedule generation reset was not consumed",
                )
        session.info.pop(_RESET_ARMED_KEY, None)
    if session.info.get(_RESTORE_ARMED_KEY):
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(
                "SELECT z4j_schedule_guard('check_restore', '', '', 0, 0, '', '', '')",
            )
        else:
            remaining = connection.exec_driver_sql(
                "SELECT current_setting('z4j.schedule_restore_guard', true)",
            ).scalar_one_or_none()
            if remaining:
                raise RuntimeError(
                    "schedule restore descriptor was not consumed",
                )
        session.info.pop(_RESTORE_ARMED_KEY, None)


def _clear_session_guard_state(session: Session, *_unused: Any) -> None:
    session.info.pop(_TRANSITION_ARMED_KEY, None)
    session.info.pop(_EVIDENCE_ARMED_KEY, None)
    session.info.pop(_PRUNE_ARMED_KEY, None)
    session.info.pop(_RESET_ARMED_KEY, None)
    session.info.pop(_RESTORE_ARMED_KEY, None)
    session.info.pop(_ACTIVE_CACHE_KEY, None)


def _reject_unconsumed_commit(session: Session) -> None:
    if (
        session.info.get(_TRANSITION_ARMED_KEY)
        or session.info.get(
            _EVIDENCE_ARMED_KEY,
        )
        or session.info.get(_PRUNE_ARMED_KEY)
        or session.info.get(
            _RESET_ARMED_KEY,
        )
        or session.info.get(_RESTORE_ARMED_KEY)
    ):
        raise RuntimeError(
            "refusing commit with an unconsumed schedule transition",
        )


_SESSION_LISTENERS_INSTALLED = False


def _install_session_listeners() -> None:
    global _SESSION_LISTENERS_INSTALLED  # noqa: PLW0603
    if _SESSION_LISTENERS_INSTALLED:
        return
    event.listen(Session, "after_flush_postexec", _assert_armed_guards_consumed)
    event.listen(Session, "before_commit", _reject_unconsumed_commit)
    event.listen(Session, "after_rollback", _clear_session_guard_state)
    event.listen(Session, "after_soft_rollback", _clear_session_guard_state)
    _SESSION_LISTENERS_INSTALLED = True


_install_session_listeners()


__all__ = [
    "SCHEDULE_GUARD_VERSION",
    "arm_change_log_prune",
    "arm_evidence_delete",
    "arm_evidence_transition",
    "arm_generation_reset",
    "arm_restore_rebase",
    "arm_revision_allocation",
    "arm_schedule_transition",
    "assert_change_log_prune_consumed",
    "assert_evidence_delete_consumed",
    "assert_evidence_transition_consumed",
    "assert_revision_allocation_consumed",
    "finalize_generation_reset",
    "finalize_restore_rebase",
    "install_schedule_guard_engine_hooks",
    "register_sqlite_schedule_guard",
]
