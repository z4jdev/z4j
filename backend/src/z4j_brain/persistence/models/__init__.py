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
from z4j_brain.persistence.models.agent_offline_alert import AgentOfflineAlert
from z4j_brain.persistence.models.agent_status_history import AgentStatusHistory
from z4j_brain.persistence.models.agent_worker import AgentWorker
from z4j_brain.persistence.models.api_key import ApiKey
from z4j_brain.persistence.models.audit_chain import (
    AuditChainPreparation,
    AuditChainState,
)
from z4j_brain.persistence.models.audit_log import AuditLog
from z4j_brain.persistence.models.automation_firing_outbox import (
    AutomationFiringOutbox,
)
from z4j_brain.persistence.models.automation_rule import AutomationRule
from z4j_brain.persistence.models.bulk_retry_request import (
    BulkRetryControlState,
    BulkRetryDeliveryState,
    BulkRetryOutcome,
    BulkRetryRequest,
    BulkRetryRequestChild,
)
from z4j_brain.persistence.models.command import Command
from z4j_brain.persistence.models.event import Event
from z4j_brain.persistence.models.export_job import ExportJob
from z4j_brain.persistence.models.feature_flag import FeatureFlag
from z4j_brain.persistence.models.first_boot_token import FirstBootToken
from z4j_brain.persistence.models.invitation import Invitation
from z4j_brain.persistence.models.kv_store import ExtensionStore, ProjectConfig, UserPreference
from z4j_brain.persistence.models.membership import Membership
from z4j_brain.persistence.models.meta import Z4JMeta
from z4j_brain.persistence.models.mfa_recovery_code import MfaRecoveryCode
from z4j_brain.persistence.models.misfire_alert import MisfireAlert
from z4j_brain.persistence.models.notification import (
    NotificationChannel,
    NotificationDelivery,
    ProjectDefaultSubscription,
    UserChannel,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.models.password_reset_token import (
    PasswordResetToken,
)
from z4j_brain.persistence.models.pending_fire import PendingFire
from z4j_brain.persistence.models.project import Project
from z4j_brain.persistence.models.queue import Queue
from z4j_brain.persistence.models.saved_view import SavedView
from z4j_brain.persistence.models.schedule import Schedule
from z4j_brain.persistence.models.schedule_control import (
    ScheduleChangeLog,
    ScheduleRevisionState,
)
from z4j_brain.persistence.models.schedule_external import (
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalProjection,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleOwnerCutover,
)
from z4j_brain.persistence.models.schedule_fire import ScheduleFire
from z4j_brain.persistence.models.schedule_occurrence_resolution import (
    ScheduleOccurrenceResolution,
)
from z4j_brain.persistence.models.schedule_terminal_hold import (
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.scheduler_rate_bucket import SchedulerRateBucket
from z4j_brain.persistence.models.session import Session
from z4j_brain.persistence.models.task import Task
from z4j_brain.persistence.models.task_annotation import TaskAnnotation
from z4j_brain.persistence.models.trusted_device import TrustedDevice
from z4j_brain.persistence.models.user import User
from z4j_brain.persistence.models.worker import Worker

__all__ = [
    "Agent",
    "AgentOfflineAlert",
    "AgentStatusHistory",
    "AgentWorker",
    "ApiKey",
    "AuditChainPreparation",
    "AuditChainState",
    "AuditLog",
    "AutomationFiringOutbox",
    "AutomationRule",
    "BulkRetryControlState",
    "BulkRetryDeliveryState",
    "BulkRetryOutcome",
    "BulkRetryRequest",
    "BulkRetryRequestChild",
    "Command",
    "Event",
    "ExportJob",
    "ExtensionStore",
    "FeatureFlag",
    "FirstBootToken",
    "Invitation",
    "Membership",
    "MfaRecoveryCode",
    "MisfireAlert",
    "NotificationChannel",
    "NotificationDelivery",
    "PasswordResetToken",
    "PendingFire",
    "Project",
    "ProjectConfig",
    "ProjectDefaultSubscription",
    "Queue",
    "SavedView",
    "Schedule",
    "ScheduleChangeLog",
    "ScheduleExternalControlOperation",
    "ScheduleExternalEpochAllocator",
    "ScheduleExternalProjection",
    "ScheduleExternalSnapshotFrame",
    "ScheduleExternalStream",
    "ScheduleExternalStreamEpoch",
    "ScheduleFire",
    "ScheduleOccurrenceResolution",
    "ScheduleOwnerCutover",
    "ScheduleRevisionState",
    "ScheduleTerminalHold",
    "SchedulerRateBucket",
    "Session",
    "Task",
    "TaskAnnotation",
    "TrustedDevice",
    "User",
    "UserChannel",
    "UserNotification",
    "UserPreference",
    "UserSubscription",
    "Worker",
    "Z4JMeta",
]
