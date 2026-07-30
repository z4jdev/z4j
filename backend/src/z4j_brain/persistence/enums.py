"""SQL-side enums for the brain.

Re-exports the canonical Python ``StrEnum`` types from
:mod:`z4j_core.models` so the brain and the wire protocol speak the
same vocabulary. The brain does NOT define its own duplicate enum
classes - that would let the two sides drift.

Each enum is mapped to a Postgres ``CREATE TYPE`` of the same name
(``project_role``, ``agent_state``, ...). On SQLite the same
SQLAlchemy ``Enum`` declaration becomes a ``CHECK`` constraint with
the same allowed values, so unit tests exercise the same vocabulary.
"""

from __future__ import annotations

from z4j_core.models.agent import AgentState
from z4j_core.models.command import CommandStatus
from z4j_core.models.schedule import ScheduleKind
from z4j_core.models.task import TaskPriority, TaskState
from z4j_core.models.user import ProjectRole
from z4j_core.models.worker import WorkerState

#: Task states that are TERMINAL. Once a task row reaches one of
#: these, no late event and no reconciliation probe result may move
#: it back to a non-terminal state - terminal states are terminal.
#: Shared by the EventIngestor's out-of-order-event guard and by
#: ``TaskRepository.apply_reconciled_state`` so the two
#: write paths cannot drift on what "terminal" means. RETRY and
#: REJECTED are deliberately NOT terminal: both can legitimately
#: re-enter the queue (Celery retries; reject with requeue).
TERMINAL_TASK_STATES: frozenset[TaskState] = frozenset(
    {
        TaskState.SUCCESS,
        TaskState.FAILURE,
        TaskState.REVOKED,
    },
)

#: Postgres ``CREATE TYPE`` name → Python enum class.
#: Used by the alembic migration to render ``CREATE TYPE`` /
#: ``DROP TYPE`` statements deterministically.
SQL_ENUM_NAMES: dict[str, type] = {
    "project_role": ProjectRole,
    "agent_state": AgentState,
    "worker_state": WorkerState,
    "task_state": TaskState,
    "task_priority": TaskPriority,
    "schedule_kind": ScheduleKind,
    "command_status": CommandStatus,
}


__all__ = [
    "SQL_ENUM_NAMES",
    "TERMINAL_TASK_STATES",
    "AgentState",
    "CommandStatus",
    "ProjectRole",
    "ScheduleKind",
    "TaskPriority",
    "TaskState",
    "WorkerState",
]
