"""ORM model registry.

Importing this package populates ``z4j_brain.persistence.Base.metadata``
with every brain table. Alembic's ``env.py`` imports it so
``--autogenerate`` sees the full schema; production code imports it
to access the model classes.

Adding a new model? Import it here AND add it to ``__all__``. The
import-side-effect is what registers the table on ``Base.metadata``;
forgetting it is the most common way to ship a model that alembic
silently ignores.
"""

from __future__ import annotations

from z4j_brain.persistence.models.agent import Agent
from z4j_brain.persistence.models.agent_worker import AgentWorker
from z4j_brain.persistence.models.alert_event import AlertEvent
from z4j_brain.persistence.models.api_key import ApiKey
from z4j_brain.persistence.models.audit_log import AuditLog
from z4j_brain.persistence.models.command import Command
from z4j_brain.persistence.models.event import Event
from z4j_brain.persistence.models.export_job import ExportJob
from z4j_brain.persistence.models.feature_flag import FeatureFlag
from z4j_brain.persistence.models.first_boot_token import FirstBootToken
from z4j_brain.persistence.models.invitation import Invitation
from z4j_brain.persistence.models.kv_store import ExtensionStore, ProjectConfig, UserPreference
from z4j_brain.persistence.models.membership import Membership
from z4j_brain.persistence.models.password_reset_token import (
    PasswordResetToken,
)
from z4j_brain.persistence.models.pending_fire import PendingFire
from z4j_brain.persistence.models.project import Project
from z4j_brain.persistence.models.queue import Queue
from z4j_brain.persistence.models.schedule import Schedule
from z4j_brain.persistence.models.schedule_fire import ScheduleFire
from z4j_brain.persistence.models.scheduler_rate_bucket import SchedulerRateBucket
from z4j_brain.persistence.models.session import Session
from z4j_brain.persistence.models.notification import (
    NotificationChannel,
    NotificationDelivery,
    ProjectDefaultSubscription,
    UserChannel,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.models.meta import Z4JMeta
from z4j_brain.persistence.models.saved_view import SavedView
from z4j_brain.persistence.models.task import Task
from z4j_brain.persistence.models.task_annotation import TaskAnnotation
from z4j_brain.persistence.models.user import User
from z4j_brain.persistence.models.worker import Worker

__all__ = [
    "Agent",
    "AgentWorker",
    "AlertEvent",
    "ApiKey",
    "AuditLog",
    "Command",
    "Event",
    "ExportJob",
    "FeatureFlag",
    "FirstBootToken",
    "ExtensionStore",
    "Invitation",
    "Membership",
    "ProjectConfig",
    "NotificationChannel",
    "NotificationDelivery",
    "PasswordResetToken",
    "PendingFire",
    "Project",
    "ProjectDefaultSubscription",
    "Queue",
    "SavedView",
    "Schedule",
    "ScheduleFire",
    "SchedulerRateBucket",
    "Session",
    "Task",
    "TaskAnnotation",
    "User",
    "UserChannel",
    "UserNotification",
    "UserPreference",
    "UserSubscription",
    "Worker",
    "Z4JMeta",
]
