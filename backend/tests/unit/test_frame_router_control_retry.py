"""External round-8 H4: command_ack / command_result are fire-and-forget on
the WS transport -- the agent deletes the outbound control frame the instant
it is written, so there is no agent-side resend to recover a transient DB
failure while the brain persists the ack/result (unlike event_batch, which
the agent retries until the brain confirms durable storage).

The brain therefore owns a bounded internal retry for the control-plane
persist: a transient (self-healing) DB error is retried a few times; a
permanent error, or a transient one after the budget is spent, re-raises so
dispatch() classifies + logs it (and the long-poll path, where the agent CAN
retry, sees the TRANSIENT verdict).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError
from z4j_brain.websocket.frame_router import (
    _CONTROL_FRAME_DB_RETRIES,
    FrameRouter,
)

pytestmark = pytest.mark.asyncio


class _FakeSession:
    async def commit(self) -> None:  # pragma: no cover - trivial
        return None


class _FakeDb:
    """Yields a trivial session; the persist callback drives success/failure
    so the retry loop can be exercised without a real engine."""

    def session(self, *, write: bool = False):
        assert write is True

        class _CM:
            async def __aenter__(self) -> _FakeSession:
                return _FakeSession()

            async def __aexit__(self, *_a: object) -> bool:
                return False

        return _CM()


def _router() -> FrameRouter:
    return FrameRouter(
        db=_FakeDb(),  # type: ignore[arg-type]
        ingestor=None,  # type: ignore[arg-type]
        dispatcher=None,  # type: ignore[arg-type]
        project_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        dashboard_hub=None,
        worker_id=None,
    )


def _transient() -> OperationalError:
    # No SQLSTATE, catch-all OperationalError -> classified TRANSIENT.
    return OperationalError("UPDATE ...", {}, Exception("deadlock detected"))


def _permanent() -> IntegrityError:
    # A constraint violation IS the content -> classified PERMANENT.
    return IntegrityError("UPDATE ...", {}, Exception("unique violation"))


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse the retry backoff so the test does not actually sleep."""
    import asyncio

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _instant)


async def test_transient_persist_retries_then_succeeds() -> None:
    router = _router()
    calls = {"n": 0}

    async def persist(_session: object) -> None:
        calls["n"] += 1
        if calls["n"] < 3:
            raise _transient()
        # third attempt succeeds

    # Must NOT raise -- the transient failures were retried away.
    await router._run_control_persist("command_result", uuid.uuid4(), persist)
    assert calls["n"] == 3


async def test_permanent_persist_does_not_retry() -> None:
    router = _router()
    calls = {"n": 0}

    async def persist(_session: object) -> None:
        calls["n"] += 1
        raise _permanent()

    with pytest.raises(IntegrityError):
        await router._run_control_persist("command_result", uuid.uuid4(), persist)
    # A permanent error is surfaced on the FIRST attempt -- no wasted retries.
    assert calls["n"] == 1


async def test_transient_persist_reraises_after_budget_spent() -> None:
    router = _router()
    calls = {"n": 0}

    async def persist(_session: object) -> None:
        calls["n"] += 1
        raise _transient()

    with pytest.raises(OperationalError):
        await router._run_control_persist("command_ack", uuid.uuid4(), persist)
    # Exactly _CONTROL_FRAME_DB_RETRIES attempts, then re-raise so dispatch()
    # classifies it (long-poll agent can still retry the whole batch).
    assert calls["n"] == _CONTROL_FRAME_DB_RETRIES
