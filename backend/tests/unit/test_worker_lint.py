"""The worker-configuration lint.

Two failure modes matter here and they pull in opposite directions. A rule
that misses a real problem leaves an operator losing tasks silently. A rule
that fires on a safe configuration gets the whole panel dismissed, and a
dismissed panel protects nobody. So every rule is pinned from both sides.
"""

from __future__ import annotations

import pytest
from z4j_brain.domain.worker_lint import (
    SEVERITY_ORDER,
    lint_worker_conf,
    supported_engines,
)


def _ids(conf: dict, engine: str = "celery") -> set[str]:
    return {f.rule_id for f in lint_worker_conf(engine, conf)}


#: A configuration that should produce nothing. Used as the base for
#: single-setting mutations so each test isolates one rule.
SAFE = {
    "accept_content": ["json"],
    "task_serializer": "json",
    "task_acks_late": True,
    "task_reject_on_worker_lost": True,
    "worker_prefetch_multiplier": 1,
    "task_time_limit": 300,
    "task_soft_time_limit": 240,
}


def test_a_well_configured_worker_produces_nothing() -> None:
    """The negative control the whole panel rests on."""
    assert lint_worker_conf("celery", SAFE) == []


def test_pickle_is_the_highest_severity_finding() -> None:
    """Broker access becoming code execution outranks losing a task."""
    findings = lint_worker_conf("celery", {**SAFE, "accept_content": ["json", "pickle"]})

    assert [f.rule_id for f in findings] == ["celery.pickle-accepted"]
    assert findings[0].severity == "high"


@pytest.mark.parametrize(
    "accepted",
    [["pickle"], ["json", "application/x-python-serialize"]],
)
def test_pickle_is_detected_however_it_is_expressed(accepted: object) -> None:
    """The alias and the content type wire up the same decoder.

    This once also claimed ``["json", "PICKLE"]`` and a bare ``"pickle"``
    string, which are not configurations a running worker can have. Kombu
    resolves an entry with no slash through its alias registry, so an unknown
    alias raises SerializerNotInstalled at startup, and a bare string is
    iterated character by character and fails the same way. The conf being
    linted comes from a worker that is up and answering, so a spelling that
    prevents startup cannot appear in it, and reporting one as executing
    pickle would be a high-severity finding about something that is not true.
    The near misses are pinned as non-findings in
    ``test_worker_lint_value_space``.
    """
    assert "celery.pickle-accepted" in _ids({**SAFE, "accept_content": accepted})


def test_acks_late_off_is_flagged() -> None:
    findings = lint_worker_conf("celery", {**SAFE, "task_acks_late": False})

    assert [f.rule_id for f in findings] == ["celery.acks-late-off"]


def test_late_ack_without_redelivery_is_flagged() -> None:
    """The setting that reads as protection but is not.

    acks_late alone does not save a task whose worker died unless the task is
    also rejected back onto the queue.
    """
    assert "celery.lost-task-not-requeued" in _ids(
        {**SAFE, "task_acks_late": True, "task_reject_on_worker_lost": False}
    )


def test_the_two_ack_rules_never_fire_together() -> None:
    """They describe different configurations, so both firing is a bug.

    Reporting "you ack early" and "your late ack does not redeliver" about
    the same worker would be self-contradictory.
    """
    both_off = _ids({**SAFE, "task_acks_late": False, "task_reject_on_worker_lost": False})

    assert "celery.acks-late-off" in both_off
    assert "celery.lost-task-not-requeued" not in both_off


@pytest.mark.parametrize("value", [2, 4, 16])
def test_prefetch_above_one_is_flagged_with_the_number(value: int) -> None:
    findings = [
        f
        for f in lint_worker_conf("celery", {**SAFE, "worker_prefetch_multiplier": value})
        if f.rule_id == "celery.prefetch-hoarding"
    ]

    assert len(findings) == 1
    assert str(value) in findings[0].title


def test_prefetch_of_one_is_not_flagged() -> None:
    assert "celery.prefetch-hoarding" not in _ids({**SAFE, "worker_prefetch_multiplier": 1})


def test_a_boolean_is_not_mistaken_for_a_prefetch_count() -> None:
    """``True`` is an int in Python and would otherwise read as "1"... or worse.

    Without the bool guard, ``True > 1`` is False so it passes silently, but
    the type confusion is the kind that surfaces later as a nonsense title.
    """
    assert "celery.prefetch-hoarding" not in _ids({**SAFE, "worker_prefetch_multiplier": True})


def test_missing_both_time_limits_is_flagged() -> None:
    conf = {k: v for k, v in SAFE.items() if "time_limit" not in k}

    assert "celery.no-time-limit" in _ids(conf)


@pytest.mark.parametrize("key", ["task_time_limit", "task_soft_time_limit"])
def test_either_time_limit_alone_satisfies_the_rule(key: str) -> None:
    """A soft limit is a real answer, so demanding both would be noise."""
    conf = {k: v for k, v in SAFE.items() if "time_limit" not in k}
    conf[key] = 120

    assert "celery.no-time-limit" not in _ids(conf)


def test_an_unreported_setting_does_not_fire_a_rule() -> None:
    """Absence is not evidence of a bad value.

    A worker that reports nothing is unevaluated, not healthy and not broken.
    The only rule allowed to fire on absence is the time-limit one, where the
    absence IS the finding.
    """
    findings = _ids({"accept_content": ["json"]})

    assert findings == {"celery.no-time-limit"}


def test_an_engine_with_no_rules_returns_nothing() -> None:
    """Silence rather than a false all-clear.

    Only Celery reports the keys these rules need. Claiming a clean bill of
    health for an engine we cannot evaluate would be a lie of omission.
    """
    assert lint_worker_conf("rq", SAFE) == []
    assert "celery" in supported_engines()
    assert "rq" not in supported_engines()


def test_missing_conf_is_not_judged() -> None:
    assert lint_worker_conf("celery", None) == []


def test_reported_empty_conf_still_warns_about_missing_time_limit() -> None:
    assert _ids({}) == {"celery.no-time-limit"}


def test_findings_are_ordered_worst_first() -> None:
    """An operator reads the top of the list, so the top must be the worst."""
    conf = {
        "accept_content": ["pickle"],
        "task_acks_late": False,
        "worker_prefetch_multiplier": 8,
    }
    findings = lint_worker_conf("celery", conf)
    severities = [SEVERITY_ORDER[f.severity] for f in findings]

    assert severities == sorted(severities)
    assert findings[0].rule_id == "celery.pickle-accepted"


def test_every_finding_carries_an_actionable_remedy() -> None:
    """A finding without a fix is noise, and noise gets the panel switched off."""
    conf = {
        "accept_content": ["pickle"],
        "task_acks_late": False,
        "worker_prefetch_multiplier": 8,
    }

    for finding in lint_worker_conf("celery", conf):
        assert finding.remedy.strip()
        assert finding.detail.strip()
        assert finding.setting.strip()
        assert finding.rule_id.startswith("celery.")
