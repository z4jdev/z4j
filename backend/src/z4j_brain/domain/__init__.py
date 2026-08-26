"""Domain services.

This package groups business/application services and related helpers. It
is not a strict clean-architecture dependency boundary: implementations
use :mod:`z4j_core` alongside brain persistence, authentication, settings,
and other infrastructure modules, and some helpers in the wider package are
FastAPI-aware. Routers generally delegate core workflows to these services,
whose explicit repository collaborators can be replaced by fakes in tests.

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
