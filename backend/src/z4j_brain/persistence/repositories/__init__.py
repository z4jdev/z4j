"""Repository layer.

Per :doc:`docs/BACKEND.md` §6.2: every database access goes through
a repository. Domain services depend on repository **interfaces**,
not on SQLAlchemy directly. Routers depend on services. Tests can
swap a repository for an in-memory fake without touching either
side. There is no SQL anywhere outside this package.

Public surface:

- :class:`BaseRepository` - generic CRUD on a single ORM model
- :class:`UserRepository` - users + lockout state
- :class:`SessionRepository` - server-side sessions
- :class:`ProjectRepository`
- :class:`MembershipRepository`
- :class:`FirstBootTokenRepository`
- :class:`AuditLogRepository`
- :class:`ApiKeyRepository` - personal API keys
"""

from __future__ import annotations

from z4j_brain.persistence.repositories._base import BaseRepository
from z4j_brain.persistence.repositories.agent_workers import (
    AgentWorkerRepository,
)
from z4j_brain.persistence.repositories.agents import AgentRepository
from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository
from z4j_brain.persistence.repositories.audit_log import AuditLogRepository
from z4j_brain.persistence.repositories.commands import CommandRepository
from z4j_brain.persistence.repositories.events import EventRepository
from z4j_brain.persistence.repositories.first_boot_tokens import (
    FirstBootTokenRepository,
)
from z4j_brain.persistence.repositories.invitations import InvitationRepository
from z4j_brain.persistence.repositories.memberships import MembershipRepository
from z4j_brain.persistence.repositories.notifications import (
    NotificationChannelRepository,
    NotificationDeliveryRepository,
    ProjectDefaultSubscriptionRepository,
    UserChannelRepository,
    UserNotificationRepository,
    UserSubscriptionRepository,
)
from z4j_brain.persistence.repositories.pending_fires import (
    PendingFiresRepository,
)
from z4j_brain.persistence.repositories.projects import ProjectRepository
from z4j_brain.persistence.repositories.queues import QueueRepository
from z4j_brain.persistence.repositories.schedule_fires import (
    ScheduleFireRepository,
)
from z4j_brain.persistence.repositories.schedules import (
    ScheduleRepository,
    upsert_imported_schedule,
)
from z4j_brain.persistence.repositories.sessions import SessionRepository
from z4j_brain.persistence.repositories.tasks import TaskRepository
from z4j_brain.persistence.repositories.users import UserRepository
from z4j_brain.persistence.repositories.workers import WorkerRepository

__all__ = [
    "AgentRepository",
    "AgentWorkerRepository",
    "ApiKeyRepository",
    "AuditLogRepository",
    "BaseRepository",
    "CommandRepository",
    "EventRepository",
    "FirstBootTokenRepository",
    "InvitationRepository",
    "MembershipRepository",
    "NotificationChannelRepository",
    "NotificationDeliveryRepository",
    "PendingFiresRepository",
    "ProjectDefaultSubscriptionRepository",
    "ProjectRepository",
    "QueueRepository",
    "ScheduleFireRepository",
    "ScheduleRepository",
    "SessionRepository",
    "TaskRepository",
    "UserChannelRepository",
    "UserNotificationRepository",
    "UserRepository",
    "UserSubscriptionRepository",
    "WorkerRepository",
    "upsert_imported_schedule",
]
