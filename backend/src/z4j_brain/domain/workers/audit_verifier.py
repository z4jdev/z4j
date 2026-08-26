"""``AuditChainVerifierWorker`` - walks the audit chain on a schedule.

A chain check is only worth anything if somebody runs it. Verification has
always been available on demand, which means in practice it runs when an
operator already suspects something, and that is the one moment its answer
is least useful: by then the question is what happened, not whether anything
did.

This worker closes that gap by walking the chain on a schedule and recording
the result, so "the chain verified an hour ago" is a fact rather than an
assumption. It bounds how long a break can sit undetected to one interval,
where an on-demand run says nothing about any moment except the one someone
asked about.

What a clean run means, since a scheduled one invites reading more into it:
the retained rows agree with the authenticated head, so nothing edited a row
or removed one from the middle. That covers the failures this worker exists
for, an application path writing outside :class:`AuditService`, a downgraded
adapter, a hand-run statement. It does not cover a role that can write both
``audit_log`` and ``audit_chain_state``, which can delete recent rows and put
back an earlier copy of the state row; that copy authenticates, because the
brain signed it when it was current, and this walk then reports the
shortened history as clean.

Turning these runs into evidence against that case takes a head exported to
a sink outside the database and ``--known-head`` on the verify, which no
in-database walk can substitute for. The worker passes through whatever
known-head result the report carries and does not itself supply an anchor
(see ``docs/SECURITY.md`` section 10.2).

Cost and posture
----------------
Verification takes a share lock and walks every retained row, so it is not
free and it is not something to run every minute. The default interval is
daily, and the whole worker is opt-in: an operator who has not asked for it
pays nothing. Leader-gated like the other periodic workers, because N
replicas each locking and walking the same table is N times the cost for
exactly one answer.

A failed verification is logged at error and counted, and deliberately does
NOT stop the brain. The chain failing to verify is a fact to escalate, not a
reason to take the control plane down: refusing to serve would destroy the
operator's ability to investigate the very thing that just tripped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import structlog

if TYPE_CHECKING:
    from z4j_brain.domain.workers._leader_lock import SingletonLockLease
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.workers.audit_verifier")

#: Rows per verification page. The verifier bounds this to 1..5000.
_PAGE_SIZE: int = 1000

#: First wait after a run that could not complete, doubling per consecutive
#: failure. Short, because the usual cause is a blip and the alternative is
#: waiting out an interval whose accepted bound is a week.
_RETRY_BASE_SECONDS: float = 30.0

#: Ceiling on the doubling exponent, so a long outage cannot grow the shift
#: without bound. The interval caps the wait long before this bites.
_MAX_RETRY_EXPONENT: int = 16


class AuditChainVerifierWorker:
    """Periodically verify the active audit generation."""

    #: Name of the advisory lock this worker leads on, and the name the
    #: supervisor knows it by. One string rather than two so the lock a tick
    #: takes cannot drift from the worker an operator sees in the logs.
    LEADER_LOCK_NAME: ClassVar[str] = "audit_chain_verifier_worker"

    def __init__(self, *, db: DatabaseManager, settings: Settings) -> None:
        self._db = db
        self._settings = settings
        self._consecutive_errors = 0
        self._already_verified = False

    def note_already_verified(self) -> None:
        """Credit a walk this worker did not have to run itself.

        Startup verifies the whole chain before serving, and the supervisor
        runs every worker once before its first sleep. Without this each
        enabled process walks the entire chain twice within seconds of boot,
        both times holding the lock every audit write queues behind.
        """
        self._already_verified = True

    async def tick(self) -> float | None:
        """Claim leadership, walk the chain once, and record the outcome.

        Returns the seconds to wait before the next run, or None to take the
        configured interval.

        Never raises. A verifier that can take the brain down converts a
        detection mechanism into an outage mechanism, and an operator who
        has been burned by that once will switch it off, which leaves the
        chain unwatched again.

        The leader lock is taken here rather than by whatever wires this
        worker up, because the two failures the lock can produce need the
        retry policy that lives in this class. Losing the race means another
        replica is producing the answer, so there is nothing to retry; being
        unable to ask means nobody is, and waiting out an interval that
        reaches a week is not an acceptable response to a blip. A gate
        outside this method cannot tell those apart, and its errors would
        reach the supervisor instead of this worker's own bounded retry.
        """
        from z4j_brain.api import metrics as m
        from z4j_brain.domain.workers._leader_lock import try_acquire_singleton_lock

        if self._already_verified:
            self._already_verified = False
            return None

        try:
            lease = await try_acquire_singleton_lock(
                self._db,
                self.LEADER_LOCK_NAME,
                announce=False,
            )
        except Exception:
            # The run did not happen, and the reason is neither "the chain
            # is bad" nor "the walk broke". It is recorded as an error for
            # the same reason those are: the operator-visible fact is that
            # nothing looked at the chain this interval.
            logger.exception(
                "z4j audit verifier: could not determine whether this replica leads",
            )
            _observe(m, outcome="error")
            self._consecutive_errors += 1
            return self._retry_delay()

        if lease is None:
            # Another replica holds the lock and is walking the chain, so the
            # answer this worker exists to produce is being produced. Take
            # the operator's interval rather than a retry.
            logger.debug(
                "z4j audit verifier: another replica is walking the chain this interval",
            )
            return None

        try:
            return await self._verify_and_report(m)
        finally:
            await self._release(lease)

    async def _release(self, lease: SingletonLockLease) -> None:
        """Give the leader lock back, loudly if it was not ours to give.

        The walk is over by the time this runs, so raising here would only
        turn a completed verification into a supervisor-level failure. What
        is left to do is say so when the lock did not survive the walk: that
        means a second replica could have been walking the same chain,
        taking the same blocking lock every audit write queues behind.
        """
        try:
            held_throughout = await lease.release()
        except Exception:
            logger.exception("z4j audit verifier: releasing the leader lock failed")
            return
        if not held_throughout:
            logger.error(
                "z4j audit verifier: the leader lock was gone before the walk "
                "finished, so another replica may have been walking the same "
                "chain concurrently",
            )

    async def _verify_and_report(self, m: object) -> float | None:
        """Walk the chain under the leader lock and record what came back."""
        from z4j_brain.domain.audit_verifier import verify_active_audit_generation

        try:
            async with self._db.session() as session:
                report = await verify_active_audit_generation(
                    session,
                    self._settings,
                    page_size=_PAGE_SIZE,
                )
        except Exception:
            # Could not complete. Distinct from "completed and found
            # tampering", and reported as such: conflating the two would
            # let a database blip read as evidence of tampering, or worse,
            # tampering read as a blip.
            logger.exception("z4j audit verifier: verification could not complete")
            _observe(m, outcome="error")
            self._consecutive_errors += 1
            return self._retry_delay()

        self._consecutive_errors = 0
        rows = report.verified_active_rows + report.verified_frozen_rows
        if report.clean:
            logger.info(
                "z4j audit verifier: chain verified",
                rows_verified=rows,
                active_rows=report.verified_active_rows,
                frozen_rows=report.verified_frozen_rows,
            )
            _observe(m, outcome="clean", rows=rows)
            return None

        # The finding this worker exists to produce. Log the mismatches
        # themselves: an operator investigating needs to know WHICH rows
        # failed, and the chain is already the authoritative record.
        logger.error(
            "z4j audit verifier: CHAIN DID NOT VERIFY",
            rows_verified=rows,
            mismatches=list(report.mismatches),
            mismatches_truncated=report.mismatches_truncated,
            unattributed_rows=report.unattributed_rows,
            known_head_result=report.known_head_result,
            remedy=(
                "Investigate before writing further audit rows. See "
                "docs/security/hmac-audit-chain for what each mismatch means."
            ),
        )
        _observe(m, outcome="failed", rows=rows)
        return None

    def _retry_delay(self) -> float:
        """Seconds until the next attempt after a run that could not complete.

        Bounded and short at first: the configured interval reaches a week, so
        deferring a whole one on a transient error means seven days with
        nobody looking. Doubling, and never past that interval, because the
        walk takes the same lock every audit write blocks on -- retrying a
        genuinely broken database every 30 seconds forever would cost the
        operator more than the verification is worth.
        """
        exponent = min(max(self._consecutive_errors - 1, 0), _MAX_RETRY_EXPONENT)
        interval = float(self._settings.audit_chain_verify_interval_seconds)
        return min(_RETRY_BASE_SECONDS * (2**exponent), interval)


def _observe(m: object, *, outcome: str, rows: int = 0) -> None:
    """Record the run without letting metrics break the worker.

    Metrics are observability, not the job. A missing counter must never be
    the reason a verification result goes unrecorded in the log.
    """
    try:
        counter = getattr(m, "z4j_audit_chain_verifications_total", None)
        if counter is not None:
            counter.labels(outcome=outcome).inc()
        gauge = getattr(m, "z4j_audit_chain_rows_verified", None)
        if gauge is not None and rows:
            gauge.set(rows)
    except Exception:  # pragma: no cover - defensive by construction
        logger.debug("z4j audit verifier: metric update failed", exc_info=True)


__all__ = ["AuditChainVerifierWorker"]
