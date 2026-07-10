"""Automation rule engine (Cluster R).

A composition layer over primitives that already exist -- the event
taxonomy, the notification channels, the command dispatcher, and the
HMAC-chained audit log. This subpackage owns the FIXED condition grammar
and its evaluator; the action executor + circuit breaker + event-path
wiring land in R2.
"""

from __future__ import annotations

from z4j_brain.domain.automation.evaluator import (
    DESTRUCTIVE_ACTIONS,
    DISPATCHED_TRIGGERS,
    KNOWN_ACTIONS,
    NOTIFY_ACTIONS,
    SUPPORTED_ACTIONS,
    TRIGGER_FOR_EVENT_KIND,
    TRIGGER_TYPES,
    actions_are_destructive,
    evaluate_conditions,
    matching_rules,
    validate_actions,
    validate_conditions,
)
from z4j_brain.domain.automation.executor import (
    ActionRunner,
    AutomationExecutor,
)
from z4j_brain.domain.automation.runner import AutomationActionRunner

__all__ = [
    "DESTRUCTIVE_ACTIONS",
    "DISPATCHED_TRIGGERS",
    "KNOWN_ACTIONS",
    "NOTIFY_ACTIONS",
    "SUPPORTED_ACTIONS",
    "TRIGGER_FOR_EVENT_KIND",
    "TRIGGER_TYPES",
    "ActionRunner",
    "AutomationActionRunner",
    "AutomationExecutor",
    "actions_are_destructive",
    "evaluate_conditions",
    "matching_rules",
    "validate_actions",
    "validate_conditions",
]
