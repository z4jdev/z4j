"""Wire-frame helpers shared by the command delivery transports.

Both the WebSocket gateway and the long-poll endpoint serialize a stored
``Command`` into a ``CommandPayload``; keeping the ``target`` construction in one
place stops the two transports from drifting.
"""

from __future__ import annotations

from typing import Any


def wire_target(target_type: str, target_id: str | None, parameters: Any) -> dict[str, Any]:
    """Build the wire ``target`` dict the agent receives.

    Always carries ``type`` + ``id``. For a ``bulk_retry`` / ``requeue_dead_letter``
    command whose filter names an engine, it ALSO surfaces that engine as
    ``target["engine"]`` (P1-6 / N-1).

    Rationale: a pre-1.7.1 agent resolves the adapter for these bulk actions from
    ``target.get("engine")`` ALONE -- it does not read ``filter["engine"]`` (the
    RH3 routing). Since the brain now resolves and scopes each bulk command to a
    single engine, echoing that engine into ``target`` lets an older agent bind
    the correct adapter on a multi-engine host (instead of falling back to its
    sole-engine guess and failing with "no adapter"). A 1.7.1 agent still treats
    ``filter["engine"]`` as authoritative, and the two always agree because the
    brain sets both from the same resolved value.
    """
    target: dict[str, Any] = {"type": target_type, "id": target_id}
    if isinstance(parameters, dict):
        filt = parameters.get("filter")
        if isinstance(filt, dict):
            engine = filt.get("engine")
            if isinstance(engine, str) and engine:
                target["engine"] = engine
    return target
