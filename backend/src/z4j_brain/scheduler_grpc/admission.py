"""Whether this brain process still admits new scheduler fires.

A fire that ``FireSchedule`` accepts is a promise that THIS process hands the
command to an agent. A process that has begun shutting down cannot keep it:
the HTTP server is already closing the agents' connections, while the gRPC
listener stays up until the lifespan teardown reaches it several seconds
later. A fire accepted in that window is committed and never delivered. The
next brain times it out, and when no later acceptance has superseded it, the
timeout leaves a terminal hold that disables the schedule until an operator
resolves it.

So admission closes the moment the process knows it is stopping, and stays
closed. The handler answers a closed admission with gRPC ``UNAVAILABLE``, the
status a scheduler already sees from a brain that is gone: it is retried, it
is not a disposition, and it writes nothing on either side.

Closing is one attribute store, so it is safe to do from a signal handler.
"""

from __future__ import annotations


class FireAdmission:
    """One process's answer to "may a new fire still be accepted here?"."""

    __slots__ = ("_closed", "_refused")

    def __init__(self) -> None:
        self._closed = False
        self._refused = 0

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def refused(self) -> int:
        """How many fires were turned away since admission closed."""

        return self._refused

    def close(self) -> None:
        """Stop admitting fires. Idempotent, and never reopened."""

        self._closed = True

    def count_refusal(self) -> int:
        """Record one refused fire and return the running total."""

        self._refused += 1
        return self._refused


__all__ = ["FireAdmission"]
