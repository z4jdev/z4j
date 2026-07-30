"""Automation rule condition grammar + evaluator.

The evaluator is the security-critical core: a FIXED grammar (no CEL /
sandbox), fail-closed on the hot path so a malformed rule that could
drive a destructive action simply never fires."""

from __future__ import annotations

from types import SimpleNamespace

from z4j_brain.domain.automation import (
    evaluate_conditions,
    matching_rules,
    validate_conditions,
)

# A representative task.failed event field set.
_FAILED = {
    "task_name": "myapp.tasks.send_email",
    "queue": "default",
    "engine": "celery",
    "priority": "high",
    "exception": "smtplib.SMTPServerDisconnected: connection lost",
    "runtime_ms": 12000,
}


# ---------------------------------------------------------------------------
# validate_conditions
# ---------------------------------------------------------------------------


class TestValidate:
    def test_empty_is_valid(self) -> None:
        assert validate_conditions({}) == []

    def test_all_flat_keys_valid(self) -> None:
        assert (
            validate_conditions(
                {
                    "task_name": "send_email",
                    "task_name_pattern": "myapp.*",
                    "queue": "default",
                    "engine": "celery",
                    "priority": ["high", "critical"],
                    "exception": "SMTP",
                    "exception_pattern": "*Disconnected*",
                    "runtime_ms_gt": 5000,
                },
            )
            == []
        )

    def test_unknown_key_rejected(self) -> None:
        errors = validate_conditions({"task_naem": "typo"})
        assert errors and "unknown condition key" in errors[0]

    def test_wrong_types_rejected(self) -> None:
        assert validate_conditions({"queue": 5})
        assert validate_conditions({"priority": "high"})  # must be a list
        assert validate_conditions({"priority": [1, 2]})  # list of strings
        assert validate_conditions({"runtime_ms_gt": "5000"})
        assert validate_conditions({"runtime_ms_gt": -1})
        assert validate_conditions({"runtime_ms_gt": True})  # bool is not int

    def test_glob_complexity_bounded(self) -> None:
        assert validate_conditions(
            {"task_name_pattern": "a*a*a*a*a*a*b"},
        )
        assert validate_conditions({"task_name_pattern": "x" * 201})

    def test_and_group_valid(self) -> None:
        assert (
            validate_conditions(
                {"all": [{"engine": "celery"}, {"queue": "default"}]},
            )
            == []
        )

    def test_or_group_valid(self) -> None:
        assert (
            validate_conditions(
                {"any": [{"engine": "celery"}, {"engine": "rq"}]},
            )
            == []
        )

    def test_group_must_be_only_top_level_key(self) -> None:
        assert validate_conditions(
            {"all": [{"engine": "celery"}], "queue": "default"},
        )

    def test_group_must_be_nonempty_list(self) -> None:
        assert validate_conditions({"all": []})
        assert validate_conditions({"any": "nope"})

    def test_no_nested_groups(self) -> None:
        # A group member with an unknown key ("all") is rejected -- there
        # is no second level of nesting.
        assert validate_conditions({"all": [{"all": [{"engine": "celery"}]}]})

    def test_too_many_group_members(self) -> None:
        assert validate_conditions(
            {"any": [{"engine": "celery"}] * 21},
        )

    def test_non_dict_is_invalid(self) -> None:
        assert validate_conditions("nope")
        assert validate_conditions(None)


# ---------------------------------------------------------------------------
# evaluate_conditions
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_empty_matches_everything(self) -> None:
        assert evaluate_conditions({}, _FAILED) is True

    def test_exact_match(self) -> None:
        assert evaluate_conditions({"engine": "celery"}, _FAILED) is True
        assert evaluate_conditions({"engine": "rq"}, _FAILED) is False

    def test_substring_is_case_insensitive(self) -> None:
        assert evaluate_conditions({"task_name": "send_email"}, _FAILED) is True
        assert evaluate_conditions({"task_name": "SEND"}, _FAILED) is True
        assert evaluate_conditions({"exception": "smtp"}, _FAILED) is True
        assert evaluate_conditions({"task_name": "nope"}, _FAILED) is False

    def test_glob(self) -> None:
        assert (
            evaluate_conditions(
                {"task_name_pattern": "myapp.*"},
                _FAILED,
            )
            is True
        )
        assert (
            evaluate_conditions(
                {"exception_pattern": "*disconnected*"},
                _FAILED,
            )
            is True
        )
        assert (
            evaluate_conditions(
                {"task_name_pattern": "other.*"},
                _FAILED,
            )
            is False
        )

    def test_priority_membership(self) -> None:
        assert (
            evaluate_conditions(
                {"priority": ["high", "critical"]},
                _FAILED,
            )
            is True
        )
        assert evaluate_conditions({"priority": ["low"]}, _FAILED) is False

    def test_runtime_threshold(self) -> None:
        assert evaluate_conditions({"runtime_ms_gt": 5000}, _FAILED) is True
        assert evaluate_conditions({"runtime_ms_gt": 20000}, _FAILED) is False
        # Missing runtime -> no match.
        assert (
            evaluate_conditions(
                {"runtime_ms_gt": 1},
                {"task_name": "x"},
            )
            is False
        )

    def test_flat_keys_are_anded(self) -> None:
        assert (
            evaluate_conditions(
                {"engine": "celery", "queue": "default"},
                _FAILED,
            )
            is True
        )
        assert (
            evaluate_conditions(
                {"engine": "celery", "queue": "other"},
                _FAILED,
            )
            is False
        )

    def test_all_group(self) -> None:
        assert (
            evaluate_conditions(
                {"all": [{"engine": "celery"}, {"priority": ["high"]}]},
                _FAILED,
            )
            is True
        )
        assert (
            evaluate_conditions(
                {"all": [{"engine": "celery"}, {"priority": ["low"]}]},
                _FAILED,
            )
            is False
        )

    def test_any_group(self) -> None:
        assert (
            evaluate_conditions(
                {"any": [{"engine": "rq"}, {"engine": "celery"}]},
                _FAILED,
            )
            is True
        )
        assert (
            evaluate_conditions(
                {"any": [{"engine": "rq"}, {"engine": "dramatiq"}]},
                _FAILED,
            )
            is False
        )

    def test_fail_closed_on_malformed(self) -> None:
        # Unknown key, wrong types, non-dict, huge glob -- all no-match,
        # never raise.
        assert evaluate_conditions({"bogus": "x"}, _FAILED) is False
        assert evaluate_conditions({"queue": 5}, _FAILED) is False
        assert evaluate_conditions("not a dict", _FAILED) is False
        assert evaluate_conditions(None, _FAILED) is False
        assert (
            evaluate_conditions(
                {"task_name_pattern": "a*a*a*a*a*a*b"},
                _FAILED,
            )
            is False
        )
        assert evaluate_conditions({"all": "not a list"}, _FAILED) is False


# ---------------------------------------------------------------------------
# matching_rules
# ---------------------------------------------------------------------------


def _rule(**kw):
    kw.setdefault("is_enabled", True)
    kw.setdefault("conditions", {})
    return SimpleNamespace(**kw)


class TestMatchingRules:
    def test_filters_by_trigger_enabled_and_conditions(self) -> None:
        rules = [
            _rule(trigger="task.failed", conditions={"engine": "celery"}),
            _rule(trigger="task.failed", conditions={"engine": "rq"}),
            _rule(trigger="task.succeeded", conditions={}),
            _rule(trigger="task.failed", conditions={}, is_enabled=False),
        ]
        matched = matching_rules(rules, "task.failed", _FAILED)
        # Only the celery-condition enabled task.failed rule matches.
        assert len(matched) == 1
        assert matched[0].conditions == {"engine": "celery"}

    def test_empty_condition_rule_matches_every_event(self) -> None:
        rules = [_rule(trigger="task.failed", conditions={})]
        assert len(matching_rules(rules, "task.failed", _FAILED)) == 1


# ---------------------------------------------------------------------------
# fingerprint condition
# ---------------------------------------------------------------------------


class TestFingerprintCondition:
    def test_fingerprint_is_a_valid_exact_key(self) -> None:
        assert validate_conditions({"fingerprint": "a1b2c3d4"}) == []
        # wrong type rejected like the other exact keys
        assert validate_conditions({"fingerprint": 5})

    def test_rule_matches_specific_fingerprint(self) -> None:
        rules = [
            _rule(trigger="task.failed", conditions={"fingerprint": "deadbeef"}),
        ]
        fields = {**_FAILED, "fingerprint": "deadbeef"}
        assert len(matching_rules(rules, "task.failed", fields)) == 1

    def test_rule_does_not_match_other_fingerprint(self) -> None:
        rules = [
            _rule(trigger="task.failed", conditions={"fingerprint": "deadbeef"}),
        ]
        fields = {**_FAILED, "fingerprint": "cafef00d"}
        assert matching_rules(rules, "task.failed", fields) == []
