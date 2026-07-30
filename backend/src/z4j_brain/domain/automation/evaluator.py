"""Automation-rule condition grammar + evaluator.

DESIGN (the load-bearing decision): a FIXED, statically-analyzable
condition grammar, NOT CEL or an arbitrary expression sandbox. On a
compliance product a Turing-complete predicate evaluator is a standing
sandbox-escape / ReDoS liability, and rules can drive DESTRUCTIVE actions
(cancel / revoke / purge). The grammar is a strict superset of the
notification-subscription filter matcher
(``NotificationService._matches_filters``): the same
glob / substring / exact / list-membership keys plus ``engine``,
``exception`` matching, and a runtime threshold, combined with at most
one level of AND / OR grouping (no recursion).

Two entry points:

- :func:`validate_conditions` runs at rule WRITE time (the API) and
  returns a list of human-readable errors; the API rejects the rule if
  the list is non-empty.
- :func:`evaluate_conditions` runs on the hot event path and is
  FAIL-CLOSED: any malformed shape returns ``False`` (the rule does NOT
  fire) and never raises. Because rules can act destructively,
  "do not fire on garbage" is the safe default -- the opposite of the
  notification matcher, which is permissive because it only sends mail.

"pattern" fields are shell GLOBS (``fnmatch``), never regexes, so there
is no catastrophic-backtracking surface; complexity is bounded by the
same rule the notification matcher uses.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from typing import Any

import structlog

logger = structlog.get_logger("z4j.brain.automation.evaluator")


#: The trigger vocabulary. Plain strings so adding a trigger needs no
#: migration. ``task.failed`` / ``task.succeeded`` / ``task.retried`` map
#: directly from ``EventKind`` (see :data:`TRIGGER_FOR_EVENT_KIND`).
#: ``task.orphaned`` / ``worker.offline`` / ``schedule.misfired`` are
#: emitted by their own detection subsystems (the reconciliation apply
#: path in ``CommandDispatcher``, the :class:`AgentHealthWorker` offline
#: sweep, the :class:`MisfireDetector`).
#:
#: ``task.slow`` and ``queue.depth_exceeded`` were REMOVED from the
#: grammar in 1.7: neither ever had an emit site, so a rule (or a
#: notification subscription) on them could never fire -- vapor. Stored
#: rows that still carry the removed strings fail closed on the read
#: path (they load + list fine but never match a dispatch); re-adding
#: either string requires designing its real detection first.
TRIGGER_TYPES: tuple[str, ...] = (
    "task.failed",
    "task.succeeded",
    "task.retried",
    "task.orphaned",
    "worker.offline",
    "schedule.misfired",
)

#: Direct EventKind-value -> trigger mappings. uses this to decide
#: which rules an inbound event invokes. ``worker.offline`` is
#: intentionally NOT here: the agent-emitted ``worker.offline`` EVENT
#: (an engine worker announcing its own restart) is a different signal
#: from the trigger, which the brain-side :class:`AgentHealthWorker`
#: emits when it confirms an AGENT is dead -- an agent cannot report
#: its own death, so the event kind must never double as the emit site.
TRIGGER_FOR_EVENT_KIND: dict[str, str] = {
    "task.failed": "task.failed",
    "task.succeeded": "task.succeeded",
    "task.retried": "task.retried",
}

#: The subset of :data:`TRIGGER_TYPES` that a live emit site actually
#: dispatches today. Four emit sites feed it: the frame router's inbound
#: task-event path (task.failed / task.succeeded / task.retried), the
#: brain-side :class:`MisfireDetector` worker (schedule.misfired), the
#: :class:`AgentHealthWorker` offline-episode detection (worker.offline)
#: and the reconciliation apply path in ``CommandDispatcher``
#: (task.orphaned). Every grammar trigger is currently dispatched, but
#: the API's write-time guard stays: a future grammar addition without
#: an emit site must be rejected rather than let an operator arm a rule
#: that silently never fires -- the same fail-closed posture as
#: SUPPORTED_ACTIONS vs KNOWN_ACTIONS. Expand this set (do NOT drop the
#: guard) as each emit site is wired.
DISPATCHED_TRIGGERS: frozenset[str] = frozenset(
    {
        "task.failed",
        "task.succeeded",
        "task.retried",
        "schedule.misfired",
        "worker.offline",
        "task.orphaned",
    },
)


# ---------------------------------------------------------------------------
# Action taxonomy. Lives here (the grammar owner) rather than in the
# executor so the write-time validator, the executor, and the API all
# read one source of truth.
# ---------------------------------------------------------------------------
#: Actions that only inform (safe to run even under circuit-breaker
#: failsafe).
NOTIFY_ACTIONS: frozenset[str] = frozenset({"notify", "webhook"})
#: Actions that change engine / task / schedule state (skipped under
#: failsafe, ADMIN + fresh-MFA gated at rule-creation time,
#: capability-gated agent-side at run time).
DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset(
    {"retry", "cancel", "revoke", "purge", "pause_schedule"},
)
#: The full grammar-valid action vocabulary.
KNOWN_ACTIONS: frozenset[str] = NOTIFY_ACTIONS | DESTRUCTIVE_ACTIONS
#: The subset the action runner actually executes today; everything else
#: audits ``"unsupported"`` at fire time. The API rejects the rest at
#: write time so operators never create a rule that silently no-ops.
#: Keep in sync with ``runner.AutomationActionRunner``.
SUPPORTED_ACTIONS: frozenset[str] = frozenset({"notify", "retry", "cancel"})

_MAX_ACTIONS = 10


# ---------------------------------------------------------------------------
# The flat condition keys. All optional; within a flat dict they are AND'd.
# ---------------------------------------------------------------------------
_STRING_EXACT_KEYS = frozenset({"queue", "engine", "fingerprint"})
_SUBSTRING_KEYS = frozenset({"task_name", "exception"})
_GLOB_KEYS = frozenset({"task_name_pattern", "exception_pattern"})
_LIST_KEYS = frozenset({"priority"})
_INT_GT_KEYS = frozenset({"runtime_ms_gt"})
_FLAT_KEYS: frozenset[str] = (
    _STRING_EXACT_KEYS | _SUBSTRING_KEYS | _GLOB_KEYS | _LIST_KEYS | _INT_GT_KEYS
)

#: Which event field each condition key tests.
_KEY_FIELD: dict[str, str] = {
    "queue": "queue",
    "engine": "engine",
    "fingerprint": "fingerprint",
    "task_name": "task_name",
    "task_name_pattern": "task_name",
    "exception": "exception",
    "exception_pattern": "exception",
    "priority": "priority",
    "runtime_ms_gt": "runtime_ms",
}

_MAX_GROUP_MEMBERS = 20


def _glob_too_complex(pattern: str) -> bool:
    """The same ReDoS bound the notification filter matcher uses."""
    return (
        pattern.count("*") + pattern.count("?") > 5 or pattern.count("[") > 3 or len(pattern) > 200
    )


# ---------------------------------------------------------------------------
# Validation (write time). Per-type validators keyed off the condition
# key, so there is no giant multi-branch function.
# ---------------------------------------------------------------------------


def _err_string(key: str, val: Any) -> str | None:
    if not isinstance(val, str) or not val:
        return f"'{key}' must be a non-empty string"
    return None


def _err_glob(key: str, val: Any) -> str | None:
    if not isinstance(val, str) or not val:
        return f"'{key}' must be a non-empty string"
    if _glob_too_complex(val):
        return f"'{key}' is too complex (max 5 wildcards, 3 char-classes, 200 chars)"
    return None


def _err_list(key: str, val: Any) -> str | None:
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        return f"'{key}' must be a list of strings"
    return None


def _err_int(key: str, val: Any) -> str | None:
    if not isinstance(val, int) or isinstance(val, bool) or val < 0:
        return f"'{key}' must be a non-negative integer"
    return None


_VALIDATORS: tuple[tuple[frozenset[str], Callable[[str, Any], str | None]], ...] = (
    (_STRING_EXACT_KEYS | _SUBSTRING_KEYS, _err_string),
    (_GLOB_KEYS, _err_glob),
    (_LIST_KEYS, _err_list),
    (_INT_GT_KEYS, _err_int),
)


def _validate_value(key: str, val: Any) -> str | None:
    if key not in _FLAT_KEYS:
        return f"unknown condition key '{key}'"
    for keyset, validator in _VALIDATORS:
        if key in keyset:
            return validator(key, val)
    return None


def _validate_flat(cond: Any) -> list[str]:
    if not isinstance(cond, dict):
        return ["condition must be an object"]
    errors: list[str] = []
    for key, val in cond.items():
        err = _validate_value(key, val)
        if err is not None:
            errors.append(err)
    return errors


def _validate_group(group: str, conditions: dict[str, Any]) -> list[str]:
    if set(conditions) != {group}:
        return [f"'{group}' must be the only top-level key"]
    members = conditions[group]
    if not isinstance(members, list):
        return [f"'{group}' must be a list"]
    if not members:
        return [f"'{group}' must not be empty"]
    if len(members) > _MAX_GROUP_MEMBERS:
        return [f"'{group}' has too many members (max {_MAX_GROUP_MEMBERS})"]
    errors: list[str] = []
    for i, member in enumerate(members):
        errors.extend(f"{group}[{i}]: {e}" for e in _validate_flat(member))
    return errors


def validate_conditions(conditions: Any) -> list[str]:
    """Return a list of grammar errors (empty == valid).

    Called by the rule create/update API; a non-empty list is a 422.
    Accepts a flat condition dict, or a single ``{"all": [...]}`` /
    ``{"any": [...]}`` group (one level only, no nesting).
    """
    if not isinstance(conditions, dict):
        return ["conditions must be an object"]
    for group in ("all", "any"):
        if group in conditions:
            return _validate_group(group, conditions)
    return _validate_flat(conditions)


def validate_actions(actions: Any) -> list[str]:
    """Return a list of action-spec errors (empty == valid).

    Called by the rule create/update API; a non-empty list is a 422.
    Enforces: a non-empty, bounded list of ``{"type": ...}`` objects,
    each a KNOWN action type AND one the runner currently executes
    (rejecting a not-yet-wired type up front beats creating a dead rule).
    """
    if not isinstance(actions, list):
        return ["actions must be a list"]
    if not actions:
        return ["actions must not be empty"]
    if len(actions) > _MAX_ACTIONS:
        return [f"too many actions (max {_MAX_ACTIONS})"]
    errors: list[str] = []
    for i, action in enumerate(actions):
        if not isinstance(action, dict):
            errors.append(f"actions[{i}] must be an object")
            continue
        atype = action.get("type")
        if atype not in KNOWN_ACTIONS:
            errors.append(f"actions[{i}]: unknown action type {atype!r}")
        elif atype not in SUPPORTED_ACTIONS:
            errors.append(
                f"actions[{i}]: action type {atype!r} is not yet supported "
                f"(supported: {sorted(SUPPORTED_ACTIONS)})",
            )
    return errors


def actions_are_destructive(actions: Any) -> bool:
    """True if any action would change task / schedule / engine state.

    Used by the API to require ADMIN role + fresh MFA on create / update.
    Fail-safe: a malformed ``actions`` value is treated as destructive so
    the STRICTER gate applies (the write is rejected downstream anyway).
    """
    if not isinstance(actions, list):
        return True
    for action in actions:
        if not isinstance(action, dict):
            return True
        if action.get("type") in DESTRUCTIVE_ACTIONS:
            return True
    return False


# ---------------------------------------------------------------------------
# Evaluation (hot path, fail-closed). Per-type matchers keyed off the
# condition key.
# ---------------------------------------------------------------------------


def _m_exact(val: Any, field_val: Any) -> bool:
    return isinstance(val, str) and field_val == val


def _m_substring(val: Any, field_val: Any) -> bool:
    if not isinstance(val, str) or not isinstance(field_val, str):
        return False
    return val.lower() in field_val.lower()


def _m_glob(val: Any, field_val: Any) -> bool:
    if not isinstance(val, str) or _glob_too_complex(val):
        return False
    if not isinstance(field_val, str):
        return False
    return fnmatch.fnmatch(field_val.lower(), val.lower())


def _m_list(val: Any, field_val: Any) -> bool:
    return isinstance(val, list) and field_val in val


def _m_int_gt(val: Any, field_val: Any) -> bool:
    if not isinstance(val, int) or isinstance(val, bool) or field_val is None:
        return False
    try:
        return int(field_val) > val
    except (TypeError, ValueError):
        return False


_MATCHERS: tuple[tuple[frozenset[str], Callable[[Any, Any], bool]], ...] = (
    (_STRING_EXACT_KEYS, _m_exact),
    (_SUBSTRING_KEYS, _m_substring),
    (_GLOB_KEYS, _m_glob),
    (_LIST_KEYS, _m_list),
    (_INT_GT_KEYS, _m_int_gt),
)


def _match_one(key: str, val: Any, field_val: Any) -> bool:
    for keyset, matcher in _MATCHERS:
        if key in keyset:
            return matcher(val, field_val)
    return False


def _match_flat(cond: Any, fields: dict[str, Any]) -> bool:
    if not isinstance(cond, dict):
        return False
    for key, val in cond.items():
        if key not in _FLAT_KEYS:
            return False  # unknown key -> fail closed
        if not _match_one(key, val, fields.get(_KEY_FIELD[key])):
            return False
    return True


def evaluate_conditions(conditions: Any, fields: dict[str, Any]) -> bool:
    """Fail-closed match of ``conditions`` against event ``fields``.

    Never raises. Any malformed shape returns ``False``.
    """
    try:
        if not isinstance(conditions, dict):
            return False
        for op, combine in (("all", all), ("any", any)):
            if op in conditions:
                members = conditions.get(op)
                if not isinstance(members, list):
                    return False
                return combine(_match_flat(m, fields) for m in members)
        return _match_flat(conditions, fields)
    except Exception:
        # Never crash the event path; any malformed shape is a non-match
        # (fail closed).
        logger.warning(
            "z4j automation: condition evaluation crashed; treating as no-match (fail closed)",
        )
        return False


def matching_rules(
    rules: Any,
    trigger: str,
    fields: dict[str, Any],
) -> list[Any]:
    """Return the enabled rules whose ``trigger`` and conditions match.

    Dry-run rules ARE returned (the executor records what they would do);
    the caller distinguishes execute vs dry-run. Circuit-breaker state is
    checked by the executor, not here.
    """
    out: list[Any] = []
    for rule in rules:
        if not getattr(rule, "is_enabled", False):
            continue
        if getattr(rule, "trigger", None) != trigger:
            continue
        if evaluate_conditions(getattr(rule, "conditions", None) or {}, fields):
            out.append(rule)
    return out


__all__ = [
    "DESTRUCTIVE_ACTIONS",
    "DISPATCHED_TRIGGERS",
    "KNOWN_ACTIONS",
    "NOTIFY_ACTIONS",
    "SUPPORTED_ACTIONS",
    "TRIGGER_FOR_EVENT_KIND",
    "TRIGGER_TYPES",
    "actions_are_destructive",
    "evaluate_conditions",
    "matching_rules",
    "validate_actions",
    "validate_conditions",
]
