"""Flag worker configurations that lose or leak work.

Every rule here fires on a setting an operator almost certainly did not
choose. Most of them are defaults, which is exactly what makes them
dangerous: nobody decided to run this way, and nothing tells them they do.

The data is already on hand. Engine adapters report an allowlisted slice of
the worker configuration on the heartbeat, and the brain stores it on
``workers.worker_metadata["conf"]``. So this is evaluation over data we
already hold, not new collection, and it costs an operator nothing to learn.

Scope and honesty
-----------------
Rules are per engine, because a setting means different things in different
engines and a rule that fires on the wrong one is worse than no rule. Only
Celery reports the keys these rules need today, so only Celery has rules. An
engine with no rules returns no findings rather than a reassuring empty
"all clear", because those are not the same claim.

A rule fires only when the reported configuration proves the condition. A
missing key means the worker did not report it, which is not evidence that
the setting is safe, so absence never fires a rule on its own except where
the absence IS the finding: a reported configuration with no time limit in it
has no time limit, however the adapter chose to say so. ``None`` still means
there was no configuration report at all and is not evaluated.

Reading a value the way the worker reads it
-------------------------------------------
A rule that matches on the one value an operator would have typed is a rule
that reports a dangerous worker as clean, because the value that actually
arrives is usually the one nobody typed. Three shapes matter and every rule
here is written against them:

- Absent and present-but-empty are different claims. Celery's untouched
  ``task_reject_on_worker_lost`` is ``None``, which the worker treats as off,
  while an adapter that never reported the key tells us nothing. They are
  distinguished by membership, never by ``.get()`` returning ``None``.
- A switch is on when the worker would find it truthy, because that is
  literally what the worker does with it. ``"False"`` is a non-empty string
  and therefore enables the setting, in Celery and here.
- Zero is a value, and in Celery it usually means "no limit" rather than
  "none": a zero time limit disables the limit, and a zero prefetch
  multiplier removes the reservation ceiling entirely.

Rules are a list rather than a run of ``if`` statements so a new rule cannot
be added without an id, and so the tests can enumerate them and require each
one to be exercised both ways.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["high", "medium", "low"]

#: Ordering for display and for "what is the worst thing here" summaries.
SEVERITY_ORDER: dict[Severity, int] = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    """One dangerous setting on one worker.

    ``remedy`` is mandatory. A finding an operator cannot act on is noise,
    and noise is how a panel like this gets ignored and then removed.
    """

    rule_id: str
    severity: Severity
    setting: str
    title: str
    detail: str
    remedy: str


def _as_iterable(value: Any) -> tuple[Any, ...]:
    """Normalize a scalar-or-list config value into a tuple."""
    if value is None:
        return ()
    if isinstance(value, str | bytes):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)


def _switch_is_off(conf: Mapping[str, Any], key: str) -> bool:
    """Did the worker report this switch, and would it read as off?

    Off means the worker finds the value falsy, which covers the setting
    nobody touched (``None``), the one turned off deliberately (``False``),
    and the empty string an environment-driven config can produce. A key the
    worker never reported is not off, it is unknown.
    """
    return key in conf and not conf[key]


def _switch_is_on(conf: Mapping[str, Any], key: str) -> bool:
    """Did the worker report this switch, and would it read as on?"""
    return key in conf and bool(conf[key])


def _number(conf: Mapping[str, Any], key: str) -> float | None:
    """The reported value as the number the worker would compute with.

    Anything the worker could not do arithmetic on is returned as ``None``:
    a string there is a broken configuration that fails at startup, not a
    tuning choice this module has an opinion about. Booleans are numbers on
    purpose, because Celery multiplies the prefetch multiplier by the
    concurrency and ``False`` genuinely produces zero.
    """
    if key not in conf:
        return None
    value = conf[key]
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float):
        return float(value)
    return None


def _limit_in_force(conf: Mapping[str, Any], key: str) -> bool:
    """Is a positive limit configured under this key?

    Zero and ``None`` both mean "no limit" to Celery rather than "a limit of
    nothing", and a negative limit is not one either.
    """
    value = _number(conf, key)
    return value is not None and value > 0


#: Both spellings that turn on Kombu's pickle decoder, and only those.
#:
#: ``accept_content`` takes serializer names or the content types they
#: register under, and Kombu resolves an entry one of two ways: an entry
#: containing a slash is passed through as a content type, and any other entry
#: is looked up in the alias registry. Matching only the friendly alias, as the
#: first version of this rule did, reports the content-type spelling as clean
#: while the same decoder is wired up.
#:
#: The match is exact on purpose, and that cuts the other way too. A near miss
#: does not quietly enable pickle: an unknown alias (``" pickle "``, or a
#: capitalised one) raises SerializerNotInstalled and the worker never starts,
#: and a content type that differs in case is passed through and then matches
#: no message, so every pickled payload is refused. Being lenient here would
#: report a worker as executing pickle when it demonstrably cannot.
_PICKLE_ACCEPT_ENTRIES = frozenset(
    {
        "pickle",
        "application/x-python-serialize",
    },
)


def _pickle_accepted(conf: Mapping[str, Any]) -> Finding | None:
    if "accept_content" not in conf:
        return None
    accepted = {item for item in _as_iterable(conf["accept_content"]) if isinstance(item, str)}
    if not accepted & _PICKLE_ACCEPT_ENTRIES:
        return None
    return Finding(
        rule_id="celery.pickle-accepted",
        severity="high",
        setting="accept_content",
        title="Workers deserialize pickle",
        detail=(
            "This worker accepts pickled task payloads. Unpickling "
            "executes code by design, so anything able to place a "
            "message on the broker can run arbitrary code inside the "
            "worker. That turns broker access, a stolen credential, "
            "or a misconfigured network boundary into remote code "
            "execution."
        ),
        remedy=(
            "Set accept_content to ['json'] and task_serializer to "
            "'json'. If a task genuinely needs to move Python objects, "
            "serialize them explicitly rather than reopening pickle "
            "for every task."
        ),
    )


def _acks_late_off(conf: Mapping[str, Any]) -> Finding | None:
    if not _switch_is_off(conf, "task_acks_late"):
        return None
    return Finding(
        rule_id="celery.acks-late-off",
        severity="medium",
        setting="task_acks_late",
        title="Tasks are acknowledged before they run",
        detail=(
            "The broker is told the task is handled the moment it is "
            "delivered, before the work happens. If the worker is "
            "killed, runs out of memory, or the host disappears "
            "mid-task, the task is gone: it will not be redelivered "
            "and nothing records that it was lost. This is Celery's "
            "default, so most deployments are here without choosing "
            "to be."
        ),
        remedy=(
            "Set task_acks_late = True so the acknowledgement happens "
            "after the task completes. Tasks must be idempotent first, "
            "because a redelivered task may have partially run."
        ),
    )


def _lost_task_not_requeued(conf: Mapping[str, Any]) -> Finding | None:
    if not _switch_is_on(conf, "task_acks_late"):
        return None
    if not _switch_is_off(conf, "task_reject_on_worker_lost"):
        return None
    return Finding(
        rule_id="celery.lost-task-not-requeued",
        severity="medium",
        setting="task_reject_on_worker_lost",
        title="Late acknowledgement without redelivery on worker loss",
        detail=(
            "Acknowledging late is what makes redelivery possible, but "
            "redelivery on worker loss is not in force, so a task "
            "running when its worker dies is still lost. The setting "
            "that was meant to protect the work does not, which is "
            "worse than not having it: it reads as protected. Celery "
            "leaves this one unset, so switching acks_late on without "
            "it is the usual way to arrive here."
        ),
        remedy=(
            "Set task_reject_on_worker_lost = True so a task whose "
            "worker vanished is returned to the queue."
        ),
    )


def _prefetch_unbounded(conf: Mapping[str, Any]) -> Finding | None:
    prefetch = _number(conf, "worker_prefetch_multiplier")
    if prefetch is None or prefetch > 0:
        return None
    return Finding(
        rule_id="celery.prefetch-unbounded",
        severity="medium",
        setting="worker_prefetch_multiplier",
        title="Each worker reserves the queue without limit",
        detail=(
            "A multiplier of zero does not mean no prefetching, it "
            "removes the ceiling: the worker reserves every message it "
            "can and holds them. One worker can take the entire queue "
            "while the others idle, and if it dies with tasks "
            "acknowledged early, all of them are lost at once rather "
            "than a handful."
        ),
        remedy=(
            "Set worker_prefetch_multiplier = 1 for long or "
            "variable-length tasks, or a small number for short ones. "
            "Use zero only deliberately, with late acknowledgement on, "
            "and knowing one worker may hold the whole queue."
        ),
    )


def _prefetch_hoarding(conf: Mapping[str, Any]) -> Finding | None:
    prefetch = _number(conf, "worker_prefetch_multiplier")
    if prefetch is None or prefetch <= 1:
        return None
    return Finding(
        rule_id="celery.prefetch-hoarding",
        severity="low",
        setting="worker_prefetch_multiplier",
        title=f"Each worker reserves {prefetch:g} tasks per slot",
        detail=(
            "A worker claims several tasks at once and holds them "
            "until it gets to them. With short, uniform tasks this is "
            "a throughput win. With long or uneven tasks it means work "
            "sits idle inside a busy worker while another worker has "
            "nothing to do, and a queue that looks backed up is really "
            "just badly distributed."
        ),
        remedy=(
            "Set worker_prefetch_multiplier = 1 for long or "
            "variable-length tasks. Leave it higher only when tasks "
            "are short and predictable."
        ),
    )


def _no_time_limit(conf: Mapping[str, Any]) -> Finding | None:
    # The one rule that fires on absence, because here the absence is the
    # finding: a worker that reports a configuration without a time limit in
    # it has no time limit. An adapter reporting with defaults sends the keys
    # holding Celery's ``None``, and one reporting only what was set omits
    # them; both mean the same thing, and both must reach the operator.
    if _limit_in_force(conf, "task_time_limit"):
        return None
    if _limit_in_force(conf, "task_soft_time_limit"):
        return None
    return Finding(
        rule_id="celery.no-time-limit",
        severity="medium",
        setting="task_time_limit",
        title="Tasks can run forever",
        detail=(
            "No hard or soft time limit is in force, so a task that "
            "hangs on a socket, a lock, or an external call occupies "
            "its slot indefinitely. Enough of them and the pool is "
            "full of tasks that will never finish, which presents as a "
            "queue backing up for no visible reason. A limit of zero "
            "reads like a setting but disables the limit, so a worker "
            "can be here with the keys apparently configured."
        ),
        remedy=(
            "Set task_soft_time_limit to the longest a healthy task "
            "should take, and task_time_limit somewhat above it, so a "
            "task gets the chance to clean up before it is killed. "
            "Both must be greater than zero to take effect."
        ),
    )


_RuleCheck = Callable[[Mapping[str, Any]], "Finding | None"]

#: Celery's rules, by id. The id is declared beside the check so a rule
#: cannot be added without one, and so the tests can walk this list and
#: require every rule to have a row that fires it and a row that does not.
_CELERY_RULES: tuple[tuple[str, _RuleCheck], ...] = (
    ("celery.pickle-accepted", _pickle_accepted),
    ("celery.acks-late-off", _acks_late_off),
    ("celery.lost-task-not-requeued", _lost_task_not_requeued),
    ("celery.prefetch-unbounded", _prefetch_unbounded),
    ("celery.prefetch-hoarding", _prefetch_hoarding),
    ("celery.no-time-limit", _no_time_limit),
)

#: Per-engine rule lists. An engine absent from this map has no rules yet,
#: which is reported as "not evaluated" rather than as a clean result.
_ENGINE_RULES: dict[str, tuple[tuple[str, _RuleCheck], ...]] = {
    "celery": _CELERY_RULES,
}


def supported_engines() -> frozenset[str]:
    """Engines this module can actually evaluate."""
    return frozenset(_ENGINE_RULES)


def rules_for_engine(engine: str) -> tuple[tuple[str, _RuleCheck], ...]:
    """Every rule one engine can produce, as ``(rule_id, check)`` pairs."""
    return _ENGINE_RULES.get(engine.lower(), ())


def lint_worker_conf(engine: str, conf: Mapping[str, Any] | None) -> list[Finding]:
    """Evaluate one worker's reported configuration.

    Returns findings sorted worst-first. An unknown engine, or ``conf=None``
    (no configuration report), yields no findings: there is nothing to judge.
    An explicitly reported empty mapping is evaluated; for Celery it proves no
    time-limit setting was reported and therefore triggers that rule.
    """
    rules = rules_for_engine(engine)
    if not rules or conf is None:
        return []
    findings = [finding for _rule_id, check in rules if (finding := check(conf)) is not None]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))
    return findings
