"""The denial-audit path must never change the response the caller gets.

Regression coverage for a 1.8.0 defect found by running the product: ``POST
/api/v1/projects/{slug}/schedules/{id}/trigger`` returned 500 whenever no
agent was online, instead of the 1.7 behaviour of 404 with "no online agent
for this project; start the agent and retry".

The endpoint was correct. ``ErrorMiddleware`` caught the intended
``NotFoundError`` and called the denial-audit helper first, which read
``user.id`` off ``request.state.current_user``. By then the request session
had been committed and closed, so the instance was detached with expired
attributes and SQLAlchemy raised ``DetachedInstanceError``. That escaped the
``Z4JError`` arm of ``dispatch`` and landed in the generic ``except
Exception`` arm, replacing the actionable 4xx with an opaque 500.

``getattr(user, "id", None)`` did not protect against it: the default only
suppresses ``AttributeError``, and ``DetachedInstanceError`` is a
``SQLAlchemyError``.

Two independent guarantees are asserted here, because either alone would have
prevented the outage and both are worth keeping:

1. the id is taken from a plain value stashed while the session was alive, so
   the ORM is not touched at error time at all; and
2. even when the denial-audit raises anyway, the caller still receives the
   response the endpoint intended.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm.exc import DetachedInstanceError
from starlette.requests import Request
from z4j_brain.errors import NotFoundError
from z4j_brain.middleware.errors import _record_denial_if_relevant

_PATH = "/api/v1/projects/acme/schedules/2f1c9b0e-0000-4000-8000-000000000000"


class _DetachedUser:
    """Stand-in for an ORM User whose session has closed.

    Accessing any mapped attribute raises, exactly as SQLAlchemy does for a
    detached instance with expired attributes.
    """

    @property
    def id(self) -> uuid.UUID:
        raise DetachedInstanceError(
            "Instance <User> is not bound to a Session; attribute refresh operation cannot proceed",
        )


def _request(*, audit_queue: object) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": _PATH,
        "raw_path": _PATH.encode(),
        "headers": [],
        "query_string": b"",
    }
    request = Request(scope)
    request.scope["app"] = MagicMock()
    request.app.state.audit_queue = audit_queue
    request.state.client_ip = "127.0.0.1"
    return request


@pytest.mark.asyncio
async def test_detached_user_does_not_break_the_denial_audit() -> None:
    """A detached ORM user must not raise out of the denial-audit helper."""
    queue = MagicMock()
    request = _request(audit_queue=queue)
    # No current_user_id: force the fallback path onto the detached instance.
    request.state.current_user = _DetachedUser()

    # Must not raise. Before the fix this propagated DetachedInstanceError.
    await _record_denial_if_relevant(
        request,
        exc=NotFoundError("no online agent for this project"),
    )

    # The denial is still recorded, just without attribution rather than not
    # at all -- losing the actor is acceptable, losing the row is not.
    assert queue.enqueue.call_count == 1
    assert queue.enqueue.call_args.args[0].user_id is None


@pytest.mark.asyncio
async def test_stashed_user_id_is_used_without_touching_the_orm() -> None:
    """The plain UUID stashed at auth time attributes the row correctly."""
    queue = MagicMock()
    request = _request(audit_queue=queue)
    actor_id = uuid.uuid4()
    request.state.current_user_id = actor_id
    # Present but unusable: if the helper reads this, the test fails loudly.
    request.state.current_user = _DetachedUser()

    await _record_denial_if_relevant(
        request,
        exc=NotFoundError("no online agent for this project"),
    )

    assert queue.enqueue.call_count == 1
    assert queue.enqueue.call_args.args[0].user_id == actor_id


@pytest.mark.asyncio
async def test_a_failing_audit_queue_still_leaves_the_response_intact() -> None:
    """Any failure while recording a denial is swallowed, not propagated.

    The specific failure does not matter. What matters is that no exception
    from this best-effort path can reach ``dispatch`` and pre-empt the real
    error response.
    """
    queue = MagicMock()
    queue.enqueue.side_effect = RuntimeError("audit backend exploded")
    request = _request(audit_queue=queue)
    request.state.current_user_id = uuid.uuid4()

    await _record_denial_if_relevant(
        request,
        exc=NotFoundError("no online agent for this project"),
    )

    assert queue.enqueue.call_count == 1


@pytest.mark.asyncio
async def test_error_middleware_returns_the_intended_4xx() -> None:
    """End to end: the caller gets 404 with the actionable message.

    This is the assertion that actually encodes the bug report. The unit
    guarantees above could both be satisfied while the caller still received
    the wrong status, so assert the user-visible outcome directly.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.testclient import TestClient
    from z4j_brain.middleware.errors import ErrorMiddleware

    async def _trigger(request: Request) -> None:
        # Mirror the real endpoint: a detached user on state, then the
        # NotFoundError the agent picker raises when nothing is online.
        request.state.current_user = _DetachedUser()
        raise NotFoundError(
            "no online agent for this project; start the agent and retry",
            details={"reason": "no_online_agent"},
        )

    app = Starlette(routes=[Route(_PATH, _trigger, methods=["POST"])])
    app.add_middleware(ErrorMiddleware)
    # A queue that raises, so both failure modes are active at once.
    app.state.audit_queue = MagicMock()
    app.state.audit_queue.enqueue.side_effect = RuntimeError("boom")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(_PATH)

    assert response.status_code == 404, response.text
    assert "start the agent and retry" in response.text
