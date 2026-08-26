"""Release-wide schema transition constants.

Migration, reset, restore, and partition-maintenance paths must agree on both
the exact release head and the PostgreSQL advisory-lock namespace used to
serialize catalog changes.
"""

from __future__ import annotations

RELEASE_MIGRATION_HEAD = "v1_9_audit_action_pattern"
SCHEMA_TRANSITION_ADVISORY_LOCK_KEY = 0x7A_34_6A_DD
