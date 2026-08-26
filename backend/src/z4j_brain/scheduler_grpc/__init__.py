"""Brain-side gRPC service for the z4j-scheduler companion process.

Exposes the ``SchedulerService`` defined in
``packages/z4j-scheduler/proto/scheduler.proto``. Bound to a
separate port (``Z4J_SCHEDULER_GRPC_PORT``, default 7701) so it
does not interfere with the public REST/WebSocket surface on 7700.

The brain implements every declared RPC except the legacy reverse
``TriggerSchedule`` method. The current protocol uses exact capability
negotiation, validated snapshots, revisioned replay and receipt-bound cadence
transitions. Operator manual fires are dispatched directly by the Brain; the
scheduler-side reverse server remains disabled by default for compatibility
with older Brain deployments.

Production authentication is mTLS. An explicit development-only setting
permits a plaintext channel in the exact ``dev`` environment; there is no
bearer-token authentication on this gRPC service. See ``docs/SCHEDULER.md
§22``.

Submodules:

- :mod:`~z4j_brain.scheduler_grpc.server` - gRPC server lifecycle
- :mod:`~z4j_brain.scheduler_grpc.handlers` - per-RPC handlers
- :mod:`~z4j_brain.scheduler_grpc.proto` - generated stubs
- :mod:`~z4j_brain.scheduler_grpc.auth` - mTLS certificate support
"""
