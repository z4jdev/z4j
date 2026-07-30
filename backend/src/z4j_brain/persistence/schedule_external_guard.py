"""One-shot database authority for Boundary-D external projections."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

_PROJECTION_ARMED_KEY = "_z4j_schedule_external_projection_armed"
_ALLOCATION_ARMED_KEY = "_z4j_schedule_external_allocation_armed"
_CONTROL_ARMED_KEY = "_z4j_schedule_external_control_armed"
_LIFECYCLE_ARMED_KEY = "_z4j_schedule_external_lifecycle_armed"


def _normalized(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("-", "").lower()


def _sqlite_external_guard_function() -> Any:  # noqa: PLR0915
    state: dict[str, Any] = {
        "projection": None,
        "allocation": None,
        "control": None,
        "lifecycle": None,
    }

    def guard(  # noqa: PLR0911, PLR0912, PLR0915
        mode: str,
        stream_id: Any,
        epoch_uuid: Any,
        epoch_number: Any,
        sequence: Any,
        payload_digest: Any,
        source_key: Any,
        operation: Any,
    ) -> int:
        if mode == "arm_control":
            if state["control"] is not None:
                raise RuntimeError(
                    "external control transition is already armed",
                )
            try:
                descriptor = json.loads(str(stream_id))
                state["control"] = {
                    "transition": str(descriptor["transition"]),
                    "operation_id": _normalized(
                        descriptor["operation_id"],
                    ),
                    "stream_id": _normalized(descriptor["stream_id"]),
                    "epoch_number": int(descriptor["epoch_number"]),
                    "reserved_sequence": int(
                        descriptor.get("reserved_sequence") or 0,
                    ),
                    "state_nonce": _normalized(
                        descriptor["state_nonce"],
                    ),
                    "dispatch_lease": _normalized(
                        descriptor.get("dispatch_lease"),
                    ),
                    "terminal_id": _normalized(
                        descriptor.get("terminal_id"),
                    ),
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "invalid external control descriptor",
                ) from exc
            return 1
        if mode == "check_control":
            if state["control"] is not None:
                raise RuntimeError(
                    "external control transition was not consumed",
                )
            return 1
        if mode.startswith("consume_control_"):
            control = state["control"]
            if not isinstance(control, dict):
                raise TypeError(
                    "external control transition is not armed",
                )
            actual = {
                "transition": mode.removeprefix("consume_control_"),
                "operation_id": _normalized(stream_id),
                "stream_id": _normalized(epoch_uuid),
                "epoch_number": int(epoch_number),
                "reserved_sequence": int(sequence),
                "state_nonce": _normalized(payload_digest),
                "dispatch_lease": _normalized(source_key),
                "terminal_id": _normalized(operation),
            }
            if actual != control:
                raise RuntimeError(
                    "external control transition descriptor mismatch",
                )
            state["control"] = None
            return 1
        if mode == "arm_allocation":
            if state["allocation"] is not None:
                raise RuntimeError(
                    "external epoch allocation is already armed",
                )
            try:
                descriptor = json.loads(str(stream_id))
                state["allocation"] = {
                    "stream_id": _normalized(descriptor["stream_id"]),
                    "epoch_uuid": _normalized(descriptor["epoch_uuid"]),
                    "epoch_number": int(descriptor["epoch_number"]),
                    "old_epoch_number": int(
                        descriptor["old_epoch_number"],
                    ),
                    "project_id": _normalized(descriptor["project_id"]),
                    "owner": str(descriptor["owner"]),
                    "source_scope_digest": str(
                        descriptor["source_scope_digest"],
                    ),
                    "adapter_instance_id": str(
                        descriptor.get("adapter_instance_id") or "",
                    ),
                    "allocator": False,
                    "epoch": False,
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "invalid external allocation descriptor",
                ) from exc
            return 1
        if mode == "check_allocation":
            if state["allocation"] is not None:
                raise RuntimeError(
                    "external epoch allocation was not consumed",
                )
            return 1
        if mode.startswith("consume_allocation_"):
            allocation = state["allocation"]
            if not isinstance(allocation, dict):
                raise TypeError(
                    "external epoch allocation is not armed",
                )
            if mode == "consume_allocation_allocator":
                if (
                    allocation["allocator"]
                    or int(sequence) != allocation["old_epoch_number"]
                    or int(epoch_number) != allocation["epoch_number"]
                ):
                    raise RuntimeError(
                        "external allocator transition mismatch",
                    )
                allocation["allocator"] = True
                return 1
            core = (
                _normalized(stream_id),
                _normalized(epoch_uuid),
                int(epoch_number),
            )
            expected_core = (
                allocation["stream_id"],
                allocation["epoch_uuid"],
                allocation["epoch_number"],
            )
            if core != expected_core:
                raise RuntimeError(
                    "external epoch allocation descriptor mismatch",
                )
            if mode == "consume_allocation_epoch":
                if allocation["epoch"] or str(source_key) != allocation["adapter_instance_id"]:
                    raise RuntimeError(
                        "external allocated epoch authority mismatch",
                    )
                allocation["epoch"] = True
                return 1
            if mode == "consume_allocation_stream":
                if (
                    not allocation["allocator"]
                    or not allocation["epoch"]
                    or _normalized(operation) != allocation["project_id"]
                    or str(source_key) != allocation["owner"]
                    or str(payload_digest) != allocation["source_scope_digest"]
                ):
                    raise RuntimeError(
                        "external stream allocation is incomplete",
                    )
                state["allocation"] = None
                return 1
            raise RuntimeError(
                "unknown external allocation guard operation",
            )
        if mode == "arm_lifecycle":
            if state["lifecycle"] is not None:
                raise RuntimeError(
                    "external lifecycle transition is already armed",
                )
            try:
                descriptor = json.loads(str(stream_id))
                mutations = {
                    (
                        _normalized(item["schedule_id"]),
                        str(item["from_owner"]),
                        str(item["to_owner"]),
                    )
                    for item in descriptor["mutations"]
                }
                lifecycle = {
                    "transition": str(descriptor["transition"]),
                    "operation_id": _normalized(
                        descriptor.get("operation_id"),
                    ),
                    "manifest_digest": str(
                        descriptor.get("manifest_digest") or "",
                    ),
                    "project_id": _normalized(
                        descriptor.get("project_id"),
                    ),
                    "from_owner": str(
                        descriptor.get("from_owner") or "",
                    ),
                    "to_owner": str(
                        descriptor.get("to_owner") or "",
                    ),
                    "stream_id": _normalized(descriptor["stream_id"]),
                    "epoch_uuid": _normalized(descriptor["epoch_uuid"]),
                    "epoch_number": int(descriptor["epoch_number"]),
                    "accepted_sequence": int(
                        descriptor["accepted_sequence"],
                    ),
                    "from_phase": str(descriptor["from_phase"]),
                    "to_phase": str(descriptor["to_phase"]),
                    "sealed_sequence": int(
                        descriptor.get("sealed_sequence") or 0,
                    ),
                    "last_snapshot_digest": str(
                        descriptor.get("last_snapshot_digest") or "",
                    ),
                    "mutations": mutations,
                    "cutover": False,
                    "epoch": False,
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "invalid external lifecycle descriptor",
                ) from exc
            if len(mutations) != len(descriptor["mutations"]):
                raise RuntimeError(
                    "external lifecycle contains duplicate mutations",
                )
            state["lifecycle"] = lifecycle
            return 1
        if mode == "check_lifecycle":
            if state["lifecycle"] is not None:
                raise RuntimeError(
                    "external lifecycle transition was not consumed",
                )
            return 1
        if mode.startswith("consume_lifecycle_"):
            lifecycle = state["lifecycle"]
            if not isinstance(lifecycle, dict):
                raise TypeError(
                    "external lifecycle transition is not armed",
                )
            if mode == "consume_lifecycle_schedule":
                if (
                    _normalized(stream_id) != lifecycle["stream_id"]
                    or _normalized(epoch_uuid) != lifecycle["epoch_uuid"]
                    or int(epoch_number) != lifecycle["epoch_number"]
                ):
                    raise RuntimeError(
                        "external lifecycle schedule stream mismatch",
                    )
                mutation = (
                    _normalized(payload_digest),
                    str(source_key),
                    str(operation),
                )
                if mutation not in lifecycle["mutations"]:
                    raise RuntimeError(
                        "external lifecycle schedule is not manifested",
                    )
                lifecycle["mutations"].remove(mutation)
                return 1
            if mode == "consume_lifecycle_cutover":
                actual = (
                    _normalized(stream_id),
                    _normalized(epoch_uuid),
                    str(payload_digest),
                    str(source_key),
                    str(operation),
                )
                expected = (
                    lifecycle["operation_id"],
                    lifecycle["project_id"],
                    lifecycle["manifest_digest"],
                    lifecycle["from_owner"],
                    lifecycle["to_owner"],
                )
                if lifecycle["cutover"] or actual != expected:
                    raise RuntimeError(
                        "external cutover evidence descriptor mismatch",
                    )
                lifecycle["cutover"] = True
                return 1
            if mode == "consume_lifecycle_finish":
                header = (
                    _normalized(stream_id),
                    _normalized(epoch_uuid),
                    int(epoch_number),
                )
                expected_header = (
                    lifecycle["stream_id"],
                    lifecycle["epoch_uuid"],
                    lifecycle["epoch_number"],
                )
                if (
                    lifecycle["transition"] != "cutover"
                    or lifecycle["from_owner"] != "z4j-scheduler"
                    or lifecycle["to_owner"] == "z4j-scheduler"
                    or lifecycle["from_phase"] != "ACTIVATING"
                    or lifecycle["to_phase"] != "ACTIVATING"
                    or header != expected_header
                    or lifecycle["mutations"]
                    or not lifecycle["cutover"]
                    or lifecycle["epoch"]
                ):
                    raise RuntimeError(
                        "external target cutover transition is incomplete",
                    )
                state["lifecycle"] = None
                return 1
            header = (
                _normalized(stream_id),
                _normalized(epoch_uuid),
                int(epoch_number),
                int(sequence),
                str(payload_digest),
                str(source_key),
                int(operation),
            )
            expected = (
                lifecycle["stream_id"],
                lifecycle["epoch_uuid"],
                lifecycle["epoch_number"],
                lifecycle["accepted_sequence"],
                lifecycle["to_phase"],
                lifecycle["last_snapshot_digest"],
                lifecycle["sealed_sequence"],
            )
            if header != expected:
                raise RuntimeError(
                    "external lifecycle descriptor mismatch",
                )
            if mode == "consume_lifecycle_epoch":
                if lifecycle["epoch"]:
                    raise RuntimeError(
                        "external lifecycle epoch was already consumed",
                    )
                lifecycle["epoch"] = True
                return 1
            if mode == "consume_lifecycle_stream":
                if (
                    lifecycle["mutations"]
                    or not lifecycle["epoch"]
                    or (lifecycle["transition"] == "cutover" and not lifecycle["cutover"])
                ):
                    raise RuntimeError(
                        "external lifecycle transition is incomplete",
                    )
                state["lifecycle"] = None
                return 1
            raise RuntimeError(
                "unknown external lifecycle guard operation",
            )
        if mode == "arm_projection":
            if state["projection"] is not None:
                raise RuntimeError(
                    "external projection is already armed",
                )
            try:
                descriptor = json.loads(str(stream_id))
                mutations = {
                    (
                        str(item["operation"]),
                        str(item["source_key"]),
                        _normalized(item["schedule_id"]),
                    )
                    for item in descriptor["mutations"]
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "invalid external projection descriptor",
                ) from exc
            if len(mutations) != len(descriptor["mutations"]):
                raise RuntimeError(
                    "external projection contains duplicate mutations",
                )
            state["projection"] = {
                "guard_kind": str(descriptor.get("guard_kind") or "projection"),
                "stream_id": _normalized(descriptor["stream_id"]),
                "epoch_uuid": _normalized(descriptor["epoch_uuid"]),
                "epoch_number": int(descriptor["epoch_number"]),
                "sequence": int(descriptor["sequence"]),
                "payload_digest": str(descriptor["payload_digest"]),
                "adapter_instance_id": str(
                    descriptor["adapter_instance_id"],
                ),
                "operation_id": _normalized(
                    descriptor.get("operation_id"),
                ),
                "snapshot_id": str(descriptor.get("snapshot_id") or ""),
                "frame_index": int(descriptor.get("frame_index") or 0),
                "mutations": mutations,
                "ledger": False,
                "epoch": False,
            }
            return 1
        if mode == "check_projection":
            if state["projection"] is not None:
                raise RuntimeError(
                    "external projection was not consumed",
                )
            return 1
        projection = state["projection"]
        if not isinstance(projection, dict):
            raise TypeError("external projection is not armed")
        if mode == "consume_snapshot_frame":
            header = (
                _normalized(stream_id),
                _normalized(epoch_uuid),
                int(epoch_number),
                int(sequence),
                str(payload_digest),
                _normalized(source_key),
                int(operation),
            )
            expected_header = (
                projection["stream_id"],
                projection["epoch_uuid"],
                projection["epoch_number"],
                projection["sequence"],
                projection["payload_digest"],
                _normalized(projection["snapshot_id"]),
                projection["frame_index"],
            )
            if projection["guard_kind"] != "snapshot_frame" or header != expected_header:
                raise RuntimeError(
                    "external snapshot frame descriptor mismatch",
                )
            state["projection"] = None
            return 1
        if mode.startswith("consume_ambiguity_"):
            header = (
                _normalized(stream_id),
                _normalized(epoch_uuid),
                int(epoch_number),
            )
            expected_header = (
                projection["stream_id"],
                projection["epoch_uuid"],
                projection["epoch_number"],
            )
            if (
                projection["guard_kind"] != "ambiguity"
                or header != expected_header
                or str(source_key) != projection["adapter_instance_id"]
            ):
                raise RuntimeError(
                    "external ambiguity descriptor mismatch",
                )
            if mode == "consume_ambiguity_epoch":
                if projection["epoch"]:
                    raise RuntimeError(
                        "external epoch ambiguity was already consumed",
                    )
                projection["epoch"] = True
                return 1
            if mode == "consume_ambiguity_stream":
                if not projection["epoch"]:
                    raise RuntimeError(
                        "external ambiguity transition is incomplete",
                    )
                state["projection"] = None
                return 1
            raise RuntimeError(
                "unknown external ambiguity guard operation",
            )
        if projection["guard_kind"] != "projection":
            raise RuntimeError("external projection guard kind mismatch")
        if mode == "consume_schedule":
            header = (
                _normalized(stream_id),
                _normalized(epoch_uuid),
                int(epoch_number),
            )
            expected_header = (
                projection["stream_id"],
                projection["epoch_uuid"],
                projection["epoch_number"],
            )
            if header != expected_header or (int(sequence) not in {0, projection["sequence"]}):
                raise RuntimeError(
                    "external schedule projection descriptor mismatch",
                )
            mutation = (
                str(operation),
                str(source_key),
                _normalized(payload_digest),
            )
            if mutation not in projection["mutations"]:
                raise RuntimeError(
                    "external schedule mutation is not manifested",
                )
            projection["mutations"].remove(mutation)
            return 1
        header = (
            _normalized(stream_id),
            _normalized(epoch_uuid),
            int(epoch_number),
            int(sequence),
            str(payload_digest),
        )
        expected = (
            projection["stream_id"],
            projection["epoch_uuid"],
            projection["epoch_number"],
            projection["sequence"],
            projection["payload_digest"],
        )
        if header != expected:
            raise RuntimeError("external projection descriptor mismatch")
        if (
            mode in {"consume_epoch", "consume_stream"}
            and str(
                source_key,
            )
            != projection["adapter_instance_id"]
        ):
            raise RuntimeError(
                "external projection adapter instance mismatch",
            )
        if mode == "consume_ledger":
            if projection["ledger"] or _normalized(source_key) != projection["operation_id"]:
                raise RuntimeError(
                    "external projection ledger identity mismatched or was already consumed",
                )
            projection["ledger"] = True
            return 1
        if mode == "consume_epoch":
            if projection["epoch"]:
                raise RuntimeError(
                    "external epoch projection was already consumed",
                )
            projection["epoch"] = True
            return 1
        if mode == "consume_stream":
            if projection["mutations"] or not projection["ledger"] or not projection["epoch"]:
                raise RuntimeError(
                    "external projection mutation set is incomplete",
                )
            state["projection"] = None
            return 1
        if mode == "clear":
            state["projection"] = None
            state["allocation"] = None
            state["control"] = None
            state["lifecycle"] = None
            return 1
        raise RuntimeError("unknown external schedule guard operation")

    return guard


def register_sqlite_schedule_external_guard(
    dbapi_connection: Any,
) -> None:
    """Register fresh external projection authority on one connection."""

    dbapi_connection.create_function(
        "z4j_schedule_external_guard",
        8,
        _sqlite_external_guard_function(),
    )


async def arm_external_projection(
    session: AsyncSession,
    *,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
    sequence: int,
    payload_digest: str,
    adapter_instance_id: str,
    operation_id: Any | None,
    mutations: list[dict[str, str]],
) -> None:
    """Arm one exact stream-first projection and its complete mutation set."""

    if session.sync_session.info.get(_PROJECTION_ARMED_KEY):
        raise RuntimeError("an external projection is already armed")
    descriptor = {
        "guard_kind": "projection",
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": int(epoch_number),
        "sequence": int(sequence),
        "payload_digest": payload_digest,
        "adapter_instance_id": adapter_instance_id,
        "operation_id": (str(operation_id) if operation_id is not None else None),
        "mutations": mutations,
    }
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded) > 64 * 1024:
        raise RuntimeError("external projection descriptor is oversized")
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_projection', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_projection_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_PROJECTION_ARMED_KEY] = True


async def arm_external_lifecycle_transition(
    session: AsyncSession,
    *,
    transition: str,
    operation_id: Any | None,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
    accepted_sequence: int,
    from_phase: str,
    to_phase: str,
    sealed_sequence: int | None,
    last_snapshot_digest: str | None,
    mutations: list[dict[str, str]],
    manifest_digest: str | None = None,
    project_id: Any | None = None,
    from_owner: str | None = None,
    to_owner: str | None = None,
) -> None:
    """Arm one exact drain/seal/retire/hold stream transition."""

    if transition not in {
        "drain",
        "seal",
        "retire",
        "cutover",
        "restore_hold",
        "reset_retire",
        "abandon_activation",
    }:
        raise ValueError("unsupported external lifecycle transition")
    if session.sync_session.info.get(_LIFECYCLE_ARMED_KEY):
        raise RuntimeError(
            "an external lifecycle transition is already armed",
        )
    descriptor = {
        "transition": transition,
        "operation_id": (str(operation_id) if operation_id is not None else None),
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": int(epoch_number),
        "accepted_sequence": int(accepted_sequence),
        "from_phase": from_phase,
        "to_phase": to_phase,
        "sealed_sequence": int(sealed_sequence or 0),
        "last_snapshot_digest": last_snapshot_digest or "",
        "manifest_digest": manifest_digest or "",
        "project_id": (str(project_id) if project_id is not None else None),
        "from_owner": from_owner or "",
        "to_owner": to_owner or "",
        "mutations": mutations,
    }
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded) > 64 * 1024:
        raise RuntimeError(
            "external lifecycle descriptor is oversized",
        )
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_lifecycle', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_lifecycle_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_LIFECYCLE_ARMED_KEY] = True


async def arm_external_control_transition(
    session: AsyncSession,
    *,
    transition: str,
    operation_id: Any,
    stream_id: Any,
    epoch_number: int,
    reserved_sequence: int | None,
    state_nonce: Any,
    dispatch_lease: Any | None,
    terminal_id: Any | None,
) -> None:
    """Arm one exact durable external-control state transition."""

    if transition not in {"insert", "claim", "apply", "ambiguity"}:
        raise ValueError("unsupported external control transition")
    if session.sync_session.info.get(_CONTROL_ARMED_KEY):
        raise RuntimeError(
            "an external control transition is already armed",
        )
    descriptor = {
        "transition": transition,
        "operation_id": str(operation_id),
        "stream_id": str(stream_id),
        "epoch_number": int(epoch_number),
        "reserved_sequence": int(reserved_sequence or 0),
        "state_nonce": str(state_nonce),
        "dispatch_lease": (str(dispatch_lease) if dispatch_lease is not None else None),
        "terminal_id": (str(terminal_id) if terminal_id is not None else None),
    }
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_control', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_control_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_CONTROL_ARMED_KEY] = True


async def arm_external_ambiguity(
    session: AsyncSession,
    *,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
    sequence: int,
    payload_digest: str,
    adapter_instance_id: str,
) -> None:
    """Arm one fail-closed transition for a conflicting accepted sequence."""

    if session.sync_session.info.get(_PROJECTION_ARMED_KEY):
        raise RuntimeError("an external projection is already armed")
    descriptor = {
        "guard_kind": "ambiguity",
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": int(epoch_number),
        "sequence": int(sequence),
        "payload_digest": payload_digest,
        "adapter_instance_id": adapter_instance_id,
        "operation_id": None,
        "mutations": [],
    }
    encoded = json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_projection', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_projection_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_PROJECTION_ARMED_KEY] = True


async def arm_external_snapshot_frame(
    session: AsyncSession,
    *,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
    sequence: int,
    frame_digest: str,
    snapshot_id: Any,
    frame_index: int,
) -> None:
    """Arm one exact immutable snapshot staging insert."""

    if session.sync_session.info.get(_PROJECTION_ARMED_KEY):
        raise RuntimeError("an external projection is already armed")
    descriptor = {
        "guard_kind": "snapshot_frame",
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": int(epoch_number),
        "sequence": int(sequence),
        "payload_digest": frame_digest,
        "adapter_instance_id": "",
        "operation_id": None,
        "snapshot_id": str(snapshot_id),
        "frame_index": int(frame_index),
        "mutations": [],
    }
    encoded = json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_projection', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_projection_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_PROJECTION_ARMED_KEY] = True


async def arm_external_epoch_allocation(
    session: AsyncSession,
    *,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
    old_epoch_number: int,
    project_id: Any,
    owner: str,
    source_scope_digest: str,
    adapter_instance_id: str | None,
) -> None:
    """Arm one new stream plus one never-reused epoch allocation."""

    if session.sync_session.info.get(_ALLOCATION_ARMED_KEY):
        raise RuntimeError("an external epoch allocation is already armed")
    descriptor = {
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": epoch_number,
        "old_epoch_number": old_epoch_number,
        "project_id": str(project_id),
        "owner": owner,
        "source_scope_digest": source_scope_digest,
        "adapter_instance_id": adapter_instance_id,
    }
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'arm_allocation', :descriptor, '', 0, 0, '', '', '')",
            ),
            {"descriptor": encoded},
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT set_config('z4j.schedule_external_allocation_guard', :descriptor, true)",
            ),
            {"descriptor": encoded},
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info[_ALLOCATION_ARMED_KEY] = True


async def assert_external_epoch_allocation_consumed(
    session: AsyncSession,
) -> None:
    """Refuse an allocation whose DB transition did not consume all parts."""

    if not session.sync_session.info.get(_ALLOCATION_ARMED_KEY):
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard('check_allocation', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        remaining = await session.scalar(
            text(
                "SELECT current_setting('z4j.schedule_external_allocation_guard', true)",
            ),
        )
        if remaining:
            raise RuntimeError(
                "external epoch allocation was not consumed",
            )
    session.sync_session.info.pop(_ALLOCATION_ARMED_KEY, None)


async def assert_external_projection_consumed(
    session: AsyncSession,
) -> None:
    """Refuse a handler that did not consume its exact DB descriptor."""

    if not session.sync_session.info.get(_PROJECTION_ARMED_KEY):
        return
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard('check_projection', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        remaining = await session.scalar(
            text(
                "SELECT current_setting('z4j.schedule_external_projection_guard', true)",
            ),
        )
        if remaining:
            raise RuntimeError(
                "external projection descriptor was not consumed",
            )
    session.sync_session.info.pop(_PROJECTION_ARMED_KEY, None)


async def assert_external_control_consumed(
    session: AsyncSession,
) -> None:
    """Assert the one-shot external-control transition was consumed."""

    if not session.sync_session.info.get(_CONTROL_ARMED_KEY):
        return
    if session.get_bind().dialect.name == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard('check_control', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        raw = (
            await session.execute(
                text(
                    "SELECT current_setting('z4j.schedule_external_control_guard', true)",
                ),
            )
        ).scalar_one_or_none()
        if raw:
            raise RuntimeError(
                "external control transition was not consumed",
            )
    session.sync_session.info.pop(_CONTROL_ARMED_KEY, None)


async def finish_external_target_cutover(
    session: AsyncSession,
    *,
    stream_id: Any,
    epoch_uuid: Any,
    epoch_number: int,
) -> None:
    """Consume a reserved-source cutover after its manifested writes."""

    if not session.sync_session.info.get(_LIFECYCLE_ARMED_KEY):
        raise RuntimeError(
            "external lifecycle transition is not armed",
        )
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard("
                "'consume_lifecycle_finish', :stream_id, "
                ":epoch_uuid, :epoch_number, 0, '', '', '')",
            ),
            {
                "stream_id": str(stream_id),
                "epoch_uuid": str(epoch_uuid),
                "epoch_number": int(epoch_number),
            },
        )
    elif dialect == "postgresql":
        await session.execute(
            text(
                "SELECT "
                "z4j_finish_external_target_cutover_guard_v1("
                ":stream_id, :epoch_uuid, :epoch_number)",
            ),
            {
                "stream_id": str(stream_id),
                "epoch_uuid": str(epoch_uuid),
                "epoch_number": int(epoch_number),
            },
        )
    else:
        raise RuntimeError(
            f"unsupported Boundary-D database: {dialect}",
        )
    session.sync_session.info.pop(_LIFECYCLE_ARMED_KEY, None)


async def assert_external_lifecycle_consumed(
    session: AsyncSession,
) -> None:
    """Assert that every manifested lifecycle edge was consumed."""

    if not session.sync_session.info.get(_LIFECYCLE_ARMED_KEY):
        return
    if session.get_bind().dialect.name == "sqlite":
        await session.execute(
            text(
                "SELECT z4j_schedule_external_guard('check_lifecycle', '', '', 0, 0, '', '', '')",
            ),
        )
    else:
        raw = (
            await session.execute(
                text(
                    "SELECT current_setting('z4j.schedule_external_lifecycle_guard', true)",
                ),
            )
        ).scalar_one_or_none()
        if raw:
            raise RuntimeError(
                "external lifecycle transition was not consumed",
            )
    session.sync_session.info.pop(_LIFECYCLE_ARMED_KEY, None)


def _reject_unconsumed_commit(session: Session) -> None:
    if (
        session.info.get(_PROJECTION_ARMED_KEY)
        or session.info.get(_ALLOCATION_ARMED_KEY)
        or session.info.get(_CONTROL_ARMED_KEY)
        or session.info.get(_LIFECYCLE_ARMED_KEY)
    ):
        raise RuntimeError(
            "refusing commit with an unconsumed external projection",
        )


def _clear_guard_state(session: Session, *_unused: Any) -> None:
    session.info.pop(_PROJECTION_ARMED_KEY, None)
    session.info.pop(_ALLOCATION_ARMED_KEY, None)
    session.info.pop(_CONTROL_ARMED_KEY, None)
    session.info.pop(_LIFECYCLE_ARMED_KEY, None)


event.listen(Session, "before_commit", _reject_unconsumed_commit)
event.listen(Session, "after_rollback", _clear_guard_state)
event.listen(Session, "after_soft_rollback", _clear_guard_state)


__all__ = [
    "arm_external_ambiguity",
    "arm_external_control_transition",
    "arm_external_epoch_allocation",
    "arm_external_lifecycle_transition",
    "arm_external_projection",
    "arm_external_snapshot_frame",
    "assert_external_control_consumed",
    "assert_external_epoch_allocation_consumed",
    "assert_external_lifecycle_consumed",
    "assert_external_projection_consumed",
    "finish_external_target_cutover",
    "register_sqlite_schedule_external_guard",
]
