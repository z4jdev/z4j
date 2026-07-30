"""RetryTaskRequest enforces override_args/override_kwargs both-or-neither.

A native retry (celery/rq/dramatiq) runs by reference and needs no overrides,
but a PARTIAL override -- exactly one half supplied -- is ambiguous: an older
(N-1) agent could substitute an empty value for the missing half and re-run
with dropped inputs. The request model refuses a partial override statically at
the boundary, for every engine, so the unsafe combination never reaches the
dispatcher. Neither (by-reference) or both (full operator inputs) are accepted."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from z4j_brain.api.commands import RetryTaskRequest


def _kwargs(**over: object) -> dict[str, object]:
    return {
        "agent_id": uuid.uuid4(),
        "engine": "celery",
        "task_id": "task-123",
        **over,
    }


class TestRetryOverridesBothOrNeither:
    def test_neither_override_accepted(self) -> None:
        req = RetryTaskRequest(**_kwargs())
        assert req.override_args is None
        assert req.override_kwargs is None

    def test_both_overrides_accepted(self) -> None:
        req = RetryTaskRequest(
            **_kwargs(override_args=[1, 2], override_kwargs={"x": 1}),
        )
        assert req.override_args == [1, 2]
        assert req.override_kwargs == {"x": 1}

    def test_only_args_rejected(self) -> None:
        with pytest.raises(ValidationError, match="override_kwargs is missing"):
            RetryTaskRequest(**_kwargs(override_args=[1, 2]))

    def test_only_kwargs_rejected(self) -> None:
        with pytest.raises(ValidationError, match="override_args is missing"):
            RetryTaskRequest(**_kwargs(override_kwargs={"x": 1}))

    def test_empty_both_is_not_partial(self) -> None:
        # Explicit empty containers are "present" on BOTH halves, not partial:
        # the operator deliberately cleared args and kwargs. Accepted.
        req = RetryTaskRequest(**_kwargs(override_args=[], override_kwargs={}))
        assert req.override_args == []
        assert req.override_kwargs == {}


class TestRejectReservedControlKeys:
    """override_kwargs may not carry a reserved __z4j_ control key. The
    dispatcher injects control metadata (actor/task/queue name) under that
    namespace; an operator-supplied key could steer a (notably N-1) agent to
    enqueue a different registered actor/task than the one being retried."""

    def test_actor_name_control_key_rejected(self) -> None:
        with pytest.raises(ValidationError, match="reserved control keys"):
            RetryTaskRequest(
                **_kwargs(
                    override_args=[],
                    override_kwargs={"__z4j_actor_name__": "evil.actor"},
                ),
            )

    def test_any_z4j_prefixed_key_rejected(self) -> None:
        for key in ("__z4j_task_name__", "__z4j_queue_name__", "__z4j_anything"):
            with pytest.raises(ValidationError, match="reserved control keys"):
                RetryTaskRequest(
                    **_kwargs(override_args=[], override_kwargs={key: "x"}),
                )

    def test_ordinary_kwargs_still_accepted(self) -> None:
        req = RetryTaskRequest(
            **_kwargs(override_args=[], override_kwargs={"user_id": 5, "z4j": "ok"}),
        )
        assert req.override_kwargs == {"user_id": 5, "z4j": "ok"}
