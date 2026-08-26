"""Worker lint, driven over the values that actually arrive.

The rules read a configuration nobody wrote by hand. It is Celery's own
``app.conf`` with defaults filled in, shipped over a heartbeat, so the value
under a key is far more often the untouched default, the content type rather
than the friendly alias, or a zero that means "no limit", than the one value
an operator would have typed. A rule matched against the typed value reports
a dangerous worker as clean, which is worse than having no rule.

So the coverage here is a table over the value space per setting rather than
one example per rule, and two structural tests hold it to that: every rule
the module declares must have a row that fires it and a row that does not, so
a rule added later cannot ship with one hand-picked example, and no rule may
report an id other than the one it is registered under.
"""

from __future__ import annotations

from typing import Any

import pytest
from z4j_brain.domain.worker_lint import (
    SEVERITY_ORDER,
    lint_worker_conf,
    rules_for_engine,
    supported_engines,
)

#: A worker an operator would be happy with: nothing here should fire.
SAFE: dict[str, Any] = {
    "accept_content": ["json"],
    "task_serializer": "json",
    "task_acks_late": True,
    "task_reject_on_worker_lost": True,
    "worker_prefetch_multiplier": 1,
    "task_time_limit": 300,
    "task_soft_time_limit": 240,
}

#: Marks a key the worker did not report at all, as opposed to one it
#: reported as empty. The rules are required to tell those apart.
UNREPORTED = object()


def _conf(**overrides: Any) -> dict[str, Any]:
    conf = dict(SAFE)
    for key, value in overrides.items():
        if value is UNREPORTED:
            conf.pop(key, None)
        else:
            conf[key] = value
    return conf


def _fired(conf: dict[str, Any]) -> set[str]:
    return {f.rule_id for f in lint_worker_conf("celery", conf)}


PICKLE = "celery.pickle-accepted"
ACKS_LATE_OFF = "celery.acks-late-off"
NOT_REQUEUED = "celery.lost-task-not-requeued"
UNBOUNDED = "celery.prefetch-unbounded"
HOARDING = "celery.prefetch-hoarding"
NO_LIMIT = "celery.no-time-limit"


#: (overrides, exactly the rule ids that must fire).
_VALUE_SPACE = [
    pytest.param({}, set(), id="a-worker-configured-well"),
    # --- accept_content: every spelling that reaches Kombu's pickle decoder
    pytest.param({"accept_content": ["pickle"]}, {PICKLE}, id="pickle-by-alias"),
    pytest.param(
        {"accept_content": ["application/x-python-serialize"]},
        {PICKLE},
        id="pickle-by-content-type",
    ),
    # Kombu resolves a slash-bearing entry as a content type, verbatim, and
    # looks anything else up in its alias registry. So a near miss does not
    # enable pickle: a capitalised content type matches no message, and an
    # unknown alias raises SerializerNotInstalled before the worker starts.
    # Reporting either as "this worker executes pickle" would be false.
    pytest.param(
        {"accept_content": ["json", "Application/X-Python-Serialize"]},
        set(),
        id="a-content-type-differing-in-case-accepts-nothing",
    ),
    pytest.param(
        {"accept_content": ["json", " pickle "]},
        set(),
        id="an-unknown-alias-stops-the-worker-starting",
    ),
    pytest.param({"accept_content": ["json", "msgpack"]}, set(), id="json-and-msgpack"),
    pytest.param({"accept_content": ["yaml"]}, set(), id="yaml-is-loaded-safely"),
    pytest.param({"accept_content": UNREPORTED}, set(), id="serializers-unreported"),
    # --- task_acks_late: on is truthy, off is anything falsy that was reported
    pytest.param({"task_acks_late": False}, {ACKS_LATE_OFF}, id="acks-late-off"),
    pytest.param({"task_acks_late": None}, {ACKS_LATE_OFF}, id="acks-late-null"),
    pytest.param({"task_acks_late": ""}, {ACKS_LATE_OFF}, id="acks-late-empty-string"),
    pytest.param({"task_acks_late": 0}, {ACKS_LATE_OFF}, id="acks-late-zero"),
    pytest.param({"task_acks_late": UNREPORTED}, set(), id="acks-late-unreported"),
    pytest.param(
        {"task_acks_late": "False"},
        set(),
        id="acks-late-non-empty-string-is-on-in-celery-too",
    ),
    # --- task_reject_on_worker_lost: only meaningful once acks are late
    pytest.param(
        {"task_reject_on_worker_lost": None},
        {NOT_REQUEUED},
        id="redelivery-untouched-celery-default",
    ),
    pytest.param(
        {"task_reject_on_worker_lost": False},
        {NOT_REQUEUED},
        id="redelivery-switched-off",
    ),
    pytest.param(
        {"task_reject_on_worker_lost": 0},
        {NOT_REQUEUED},
        id="redelivery-zero",
    ),
    pytest.param(
        {"task_reject_on_worker_lost": UNREPORTED},
        set(),
        id="redelivery-unreported",
    ),
    pytest.param(
        {"task_acks_late": "1", "task_reject_on_worker_lost": None},
        {NOT_REQUEUED},
        id="redelivery-off-under-acks-late-from-an-environment-string",
    ),
    pytest.param(
        {"task_acks_late": False, "task_reject_on_worker_lost": None},
        {ACKS_LATE_OFF},
        id="early-acks-make-redelivery-moot",
    ),
    # --- worker_prefetch_multiplier: zero is no ceiling, not no prefetch
    pytest.param({"worker_prefetch_multiplier": 4}, {HOARDING}, id="prefetch-celery-default"),
    pytest.param({"worker_prefetch_multiplier": 2.5}, {HOARDING}, id="prefetch-fractional"),
    pytest.param({"worker_prefetch_multiplier": 1}, set(), id="prefetch-one"),
    pytest.param({"worker_prefetch_multiplier": True}, set(), id="prefetch-true-is-one"),
    pytest.param({"worker_prefetch_multiplier": 0}, {UNBOUNDED}, id="prefetch-zero-unbounded"),
    pytest.param({"worker_prefetch_multiplier": False}, {UNBOUNDED}, id="prefetch-false-is-zero"),
    pytest.param({"worker_prefetch_multiplier": -1}, {UNBOUNDED}, id="prefetch-negative"),
    pytest.param({"worker_prefetch_multiplier": "4"}, set(), id="prefetch-string-is-not-a-number"),
    pytest.param({"worker_prefetch_multiplier": UNREPORTED}, set(), id="prefetch-unreported"),
    # --- time limits: zero disables the limit rather than setting one
    pytest.param(
        {"task_time_limit": None, "task_soft_time_limit": None},
        {NO_LIMIT},
        id="limits-untouched-celery-default",
    ),
    pytest.param(
        {"task_time_limit": UNREPORTED, "task_soft_time_limit": UNREPORTED},
        {NO_LIMIT},
        id="limits-absent-from-the-report",
    ),
    pytest.param(
        {"task_time_limit": 0, "task_soft_time_limit": 0},
        {NO_LIMIT},
        id="limits-zero-disables-them",
    ),
    pytest.param(
        {"task_time_limit": 0, "task_soft_time_limit": None},
        {NO_LIMIT},
        id="limits-hard-zero-soft-unset",
    ),
    pytest.param(
        {"task_time_limit": -30, "task_soft_time_limit": None},
        {NO_LIMIT},
        id="limits-negative-is-not-a-limit",
    ),
    pytest.param(
        {"task_time_limit": "300", "task_soft_time_limit": None},
        {NO_LIMIT},
        id="limits-string-cannot-bound-anything",
    ),
    pytest.param(
        {"task_time_limit": 0, "task_soft_time_limit": 240},
        set(),
        id="limits-soft-alone-is-a-real-answer",
    ),
    pytest.param(
        {"task_time_limit": 300, "task_soft_time_limit": 0},
        set(),
        id="limits-hard-alone-is-a-real-answer",
    ),
    # --- several at once, because that is what a stock worker looks like
    pytest.param(
        {
            "accept_content": ["json", "pickle"],
            "task_acks_late": False,
            "task_reject_on_worker_lost": None,
            "worker_prefetch_multiplier": 4,
            "task_time_limit": None,
            "task_soft_time_limit": None,
        },
        {PICKLE, ACKS_LATE_OFF, HOARDING, NO_LIMIT},
        id="a-stock-worker-with-pickle-turned-back-on",
    ),
    pytest.param(
        {
            "task_acks_late": True,
            "task_reject_on_worker_lost": None,
            "worker_prefetch_multiplier": 0,
            "task_time_limit": 0,
            "task_soft_time_limit": 0,
        },
        {NOT_REQUEUED, UNBOUNDED, NO_LIMIT},
        id="every-zero-shaped-mistake-at-once",
    ),
]


@pytest.mark.parametrize(("overrides", "expected"), _VALUE_SPACE)
def test_the_value_space(overrides: dict[str, Any], expected: set[str]) -> None:
    """Exactly these rules fire, for exactly these values.

    Equality rather than membership: a rule that fires on a value it should
    not is as damaging as one that stays quiet, because the panel is only
    worth reading if every line on it is real.
    """
    assert _fired(_conf(**overrides)) == expected


def test_every_rule_is_exercised_both_ways() -> None:
    """A rule with no firing row, or no quiet row, is not covered.

    This is the part that survives the next rule: adding one to the module
    without adding rows here fails immediately, rather than shipping with a
    single hand-picked example and no idea what it does to the values it will
    actually meet.
    """
    declared = {rule_id for rule_id, _check in rules_for_engine("celery")}
    assert declared, "celery must declare rules"

    fires: set[str] = set()
    stays_quiet: set[str] = set()
    for param in _VALUE_SPACE:
        overrides, _expected = param.values
        observed = _fired(_conf(**overrides))
        fires |= observed
        stays_quiet |= declared - observed

    assert declared - fires == set(), "no row in the table fires these rules"
    assert declared - stays_quiet == set(), "no row in the table leaves these rules quiet"
    assert fires <= declared, "a rule fired an id it is not registered under"


def test_each_rule_reports_the_id_it_is_registered_under() -> None:
    """The registry is what the coverage test walks, so it has to be true."""
    for rule_id, check in rules_for_engine("celery"):
        for param in _VALUE_SPACE:
            overrides, _expected = param.values
            finding = check(_conf(**overrides))
            if finding is not None:
                assert finding.rule_id == rule_id


def test_every_finding_is_actionable_and_ordered() -> None:
    """Worst first, and never a finding an operator cannot do anything with."""
    conf = _conf(
        accept_content=["pickle"],
        task_acks_late=False,
        worker_prefetch_multiplier=4,
        task_time_limit=0,
        task_soft_time_limit=0,
    )

    findings = lint_worker_conf("celery", conf)

    assert findings, "the worst configuration in the file produced nothing"
    ranks = [SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks)
    for finding in findings:
        assert finding.remedy.strip()
        assert finding.detail.strip()
        assert finding.setting in conf


def test_an_engine_without_rules_is_not_called_clean() -> None:
    """Silence, not a false all-clear, for an engine nothing here understands."""
    assert lint_worker_conf("rq", SAFE) == []
    assert rules_for_engine("rq") == ()
    assert supported_engines() == {"celery"}


def test_an_empty_report_is_evaluated_but_an_absent_report_is_not() -> None:
    assert _fired({}) == {NO_LIMIT}
    assert lint_worker_conf("celery", None) == []
