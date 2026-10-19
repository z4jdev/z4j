"""Wire-frame helpers shared by the command delivery transports.

Both the WebSocket gateway and the long-poll endpoint serialize a stored
``Command`` into a ``CommandPayload``; keeping the ``target`` construction in one
place stops the two transports from drifting.
"""

from __future__ import annotations

from typing import Any


def wire_target(target_type: str, target_id: str | None, parameters: Any) -> dict[str, Any]:
    """Build the target with the engine and scheduler selected by the server.

    Bulk filters retain precedence. Ordinary task, worker and queue commands
    also carry their engine explicitly so older and current agents can select
    it when several engine adapters share one process. A scheduler parameter
    similarly disambiguates multiple native scheduler adapters.
    """
    target: dict[str, Any] = {"type": target_type, "id": target_id}
    if isinstance(parameters, dict):
        filt = parameters.get("filter")
        if isinstance(filt, dict):
            engine = filt.get("engine")
            if isinstance(engine, str) and engine:
                target["engine"] = engine
        else:
            engine = parameters.get("engine")
            if isinstance(engine, str) and engine:
                target["engine"] = engine
        scheduler = parameters.get("scheduler")
        if isinstance(scheduler, str) and scheduler:
            target["scheduler"] = scheduler
    return target
