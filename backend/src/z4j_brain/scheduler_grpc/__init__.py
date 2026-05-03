"""Brain-side gRPC service for the z4j-scheduler companion process.

Exposes the ``SchedulerService`` defined in
``packages/z4j-scheduler/proto/scheduler.proto``. Bound to a
separate port (``Z4J_SCHEDULER_GRPC_PORT``, default 7701) so it
does not interfere with the public REST/WebSocket surface on 7700.

Implementation lands in Phase 1 alongside the scheduler. This
package currently scaffolds the module structure so the brain's
test suite is aware of it and the Phase 0 commit is complete.

Per ``docs/SCHEDULER.md §7.3``, this module implements:

- ``ListSchedules`` - reads from existing ``SchedulesRepository``,
  filters by ``scheduler='z4j-scheduler'``, emits Pydantic-to-protobuf
  conversion
- ``WatchSchedules`` - subscribes to a Postgres LISTEN channel
  (``schedules_changed``) and pushes ``ScheduleEvent`` messages
- ``FireSchedule`` - creates a ``Command`` row via the existing
  ``CommandDispatcher.issue(...)``, returns the command_id
- ``TriggerSchedule`` - same as FireSchedule but tagged
  ``audit.action='schedule.trigger_now'`` for audit clarity
- ``AcknowledgeFireResult`` - updates ``schedules.last_run_at``,
  ``schedules.next_run_at``, ``schedules.total_runs`` via the
  existing schedules repository
- ``Ping`` - liveness

Authentication: mTLS with client certs minted by brain on first
scheduler enrollment. See ``docs/SCHEDULER.md §22``.

Submodules:

- :mod:`~z4j_brain.scheduler_grpc.server` - gRPC server lifecycle
- :mod:`~z4j_brain.scheduler_grpc.handlers` - per-RPC handlers
- :mod:`~z4j_brain.scheduler_grpc.proto` - generated stubs
- :mod:`~z4j_brain.scheduler_grpc.auth` - mTLS + cert enrollment
"""
