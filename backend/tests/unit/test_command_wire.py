"""P1-6: the wire target surfaces the resolved engine for bulk commands so a
pre-1.7.1 agent (which routes bulk_retry/requeue off target["engine"] alone,
not filter["engine"]) binds the correct adapter on a multi-engine host."""

from __future__ import annotations

from z4j_brain.domain.command_wire import wire_target


def test_bulk_command_surfaces_filter_engine_into_target() -> None:
    target = wire_target(
        "bulk", None, {"filter": {"engine": "celery", "task_ids": ["a", "b"]}, "max": 50}
    )
    assert target == {"type": "bulk", "id": None, "engine": "celery"}


def test_engine_surfaced_regardless_of_filter_shape() -> None:
    # wire_target is action-AGNOSTIC: it keys purely off parameters["filter"]
    # ["engine"], so ANY future command carrying a filter.engine (the brain does
    # not currently emit requeue_dead_letter, only bulk_retry) gets the engine
    # surfaced for a pre-1.7.1 agent. Verify a filter with no task_ids still works.
    target = wire_target("bulk", None, {"filter": {"engine": "rq"}, "max": 10})
    assert target["engine"] == "rq"


def test_single_task_command_has_no_engine_key() -> None:
    # A single-task command carries engine in parameters, not a filter, and its
    # target_id already encodes it; the target must not sprout an engine key.
    target = wire_target("task", "celery:abc123", {"engine": "celery", "task_id": "abc123"})
    assert target == {"type": "task", "id": "celery:abc123"}


def test_empty_or_missing_engine_is_not_surfaced() -> None:
    # A multi-engine "retry all" batch with no engine filter must NOT set the
    # key (an empty engine would mislead an older agent).
    assert "engine" not in wire_target("bulk", None, {"filter": {}, "max": 5})
    assert "engine" not in wire_target("bulk", None, {"filter": {"engine": ""}, "max": 5})
    assert "engine" not in wire_target("bulk", None, {"max": 5})
    assert "engine" not in wire_target("worker", "w1", None)


def test_non_string_engine_is_ignored() -> None:
    assert "engine" not in wire_target("bulk", None, {"filter": {"engine": 123}})
