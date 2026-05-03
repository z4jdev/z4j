"""Domain services.

Per :doc:`docs/BACKEND.md` §4: services hold business logic and
depend only on :mod:`z4j_core` and the brain's repository
interfaces. They have no awareness of FastAPI, HTTP, or asyncio
internals beyond the ``async def`` keyword. Routers depend on
services; tests can swap repositories for fakes.

Public surface:

- :class:`AuditService` - append-only audit log writer with
  per-row HMAC tamper-evidence.
- :class:`AuthService` - login orchestration with timing
  normalisation, lockout, and session creation.
- :class:`SetupService` - first-boot detection and one-time
  token verification.
"""

from __future__ import annotations

from z4j_brain.domain.audit_service import AuditEntry, AuditService
from z4j_brain.domain.auth_service import AuthService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.domain.policy_engine import PolicyEngine
from z4j_brain.domain.setup_service import SetupResult, SetupService

__all__ = [
    "AuditEntry",
    "AuditService",
    "AuthService",
    "CommandDispatcher",
    "EventIngestor",
    "PolicyEngine",
    "SetupResult",
    "SetupService",
]
