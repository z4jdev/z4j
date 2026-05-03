"""Agent WebSocket gateway.

The brain's bidirectional link with every connected ``z4j-bare``
agent. Multi-worker safe via the :class:`BrainRegistry` Protocol -
see :mod:`z4j_brain.websocket.registry`.

Submodules:

- :mod:`z4j_brain.websocket.gateway` - the FastAPI ``/ws/agent``
  endpoint and the per-connection state machine.
- :mod:`z4j_brain.websocket.frame_router` - dispatches inbound
  frames by type to the right domain service.
- :mod:`z4j_brain.websocket.registry` - the cluster-wide "where is
  agent X connected" map.
- :mod:`z4j_brain.websocket.auth` - bearer token resolution against
  the ``agents.token_hash`` column.
"""

from __future__ import annotations
