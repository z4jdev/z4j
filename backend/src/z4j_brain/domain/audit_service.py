"""Append-only audit log service with per-row HMAC tamper evidence.

Every privileged action goes through :meth:`AuditService.record`.
The service:

1. Builds a canonical JSON representation of the row's content.
2. Computes ``HMAC-SHA256(settings.secret, canonical)``.
3. Inserts the row via :class:`AuditLogRepository`.

The verifier (:meth:`verify_row`) recomputes the HMAC and
constant-time-compares. Combined with the database append-only
trigger, this gives us tamper evidence for any party who does
NOT also hold the master secret. A privileged DBA who DOES hold
the secret can still forge rows, that scenario is out of scope
(addressed by operational controls: secret in env, not on disk).

Secret rotation is supported transparently: callers add the old
secret to ``Z4J_SECRETS_PREVIOUS`` and writes use the new
``Z4J_SECRET``. ``verify_row`` tries every accepted secret in
order so pre-rotation rows still verify.

HMAC version is currently 1 (the v1.3.0 baseline). Future
incompatible changes to the canonical form will bump the version
and add a fallback path here so historical rows stay verifiable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import event as _sa_event
from sqlalchemy.orm import Session as _SyncSession

from z4j_brain.domain.audit_chain import (
    AUDIT_ROW_HMAC_VERSION,
    AuditChainIntegrityError,
    authenticate_state,
    build_audit_keyring,
    canonical_frozen_row_snapshot,
    canonical_json,
    canonical_row_payload,
    compute_row_hmac,
    compute_state_mac,
    frozen_snapshot_digest,
    normalize_ip,
    normalize_timestamp,
    strictly_later_audit_key,
)

logger = logging.getLogger("z4j.brain.domain.audit_service")


#: Session.info key under which AuditService stages pending forwarder
#: payloads. The dict-of-(payload, hooks) tuples is drained by the
#: ``after_commit`` listener installed at module-load below; an
#: ``after_rollback`` listener clears the staging so a rolled-back
#: transaction never forwards. (v1.6 audit C6.)
_PENDING_KEY: str = "_z4j_pending_audit_forwards"
_ROLLBACK_ONLY_KEY: str = "_z4j_audit_integrity_rollback_only"


def _fire_pending_audit_forwards(session: _SyncSession) -> None:
    """Drain the session's pending-forward list and fire hooks."""
    items = session.info.pop(_PENDING_KEY, None) or []
    for payload, hooks in items:
        for hook in hooks:
            try:
                hook(payload)
            except Exception:
                # v1.6 Round 5 I: route the failure through the
                # swallowed-exceptions counter so the Grafana alert
                # picks it up alongside the other audit-fwd sites.
                try:
                    from z4j_brain.api.metrics import record_swallowed

                    record_swallowed("audit_service", "post_commit_hook")
                except Exception:  # noqa: S110  best-effort metrics increment, import + call
                    pass
                logger.warning(
                    "z4j audit_service: post-commit hook raised; audit row written, mirror dropped",
                    exc_info=True,
                )


def _drop_pending_audit_forwards(
    session: _SyncSession,
    *_unused: Any,
) -> None:
    """Clear the pending-forward list on rollback so phantom rows
    are never forwarded. (v1.6 audit C6.)

    Accepts ``*_unused`` because SQLAlchemy's ``after_soft_rollback``
    event passes ``(session, previous_transaction)`` while
    ``after_rollback`` passes only ``(session,)``. Both fire on the
    same listener; the extra positional is silently ignored.
    """
    session.info.pop(_PENDING_KEY, None)
    session.info.pop(_ROLLBACK_ONLY_KEY, None)


def _clear_completed_sqlite_write_unit(
    session: _SyncSession,
    transaction: Any,
) -> None:
    """A mid-session commit cannot authorize the next SQLite write unit.

    ``DatabaseManager.session(write=True)`` and
    ``AuditLogRepository.require_sqlite_immediate_write_unit`` mark the
    transaction that actually began with ``BEGIN IMMEDIATE``.  SQLAlchemy
    sessions may commit and then begin another transaction (notably the
    durable-intent / outbound-effect / result pattern).  Leaving the marker in
    ``Session.info`` would let that later transaction skip its own immediate
    begin and race after an ordinary read.  Clear it only when the outermost
    transaction ends; nested savepoints remain part of the same write unit.
    """

    if getattr(transaction, "parent", None) is None:
        session.info.pop("z4j_sqlite_immediate", None)


def _reject_integrity_failed_commit(session: _SyncSession) -> None:
    """Prevent a caught audit-integrity exception from committing business data."""

    if session.info.get(_ROLLBACK_ONLY_KEY):
        raise AuditChainIntegrityError(
            "audit integrity failed earlier in this transaction; rollback is required",
        )


# Register once at import time. Idempotent: registering the same
# listener twice on the Session class raises, so guard via a module
# flag.
_AUDIT_EVENT_LISTENERS_REGISTERED: bool = False


def _ensure_session_listeners_registered() -> None:
    global _AUDIT_EVENT_LISTENERS_REGISTERED  # noqa: PLW0603  module-level singleton lazy-init
    if _AUDIT_EVENT_LISTENERS_REGISTERED:
        return
    _sa_event.listen(_SyncSession, "after_commit", _fire_pending_audit_forwards)
    _sa_event.listen(_SyncSession, "before_commit", _reject_integrity_failed_commit)
    _sa_event.listen(_SyncSession, "after_rollback", _drop_pending_audit_forwards)
    _sa_event.listen(
        _SyncSession,
        "after_transaction_end",
        _clear_completed_sqlite_write_unit,
    )
    # Some async test setups create + close sessions in the same
    # tick; ``after_soft_rollback`` covers nested-savepoint paths.
    _sa_event.listen(
        _SyncSession,
        "after_soft_rollback",
        _drop_pending_audit_forwards,
    )
    _AUDIT_EVENT_LISTENERS_REGISTERED = True


_ensure_session_listeners_registered()


def _build_forward_payload(row: Any) -> dict[str, Any]:
    """Eagerly snapshot an :class:`AuditLog` row into the wire shape
    audit_forwarder expects. Called INSIDE the writing transaction
    so ORM attribute access does not trigger lazy-load from inside
    a post-commit hook. (v1.6 audit H11.)
    """
    # Import locally to avoid a domain<->infrastructure import cycle
    # (audit_forwarder imports notifications.channels for _post).
    from z4j_brain.domain.audit_forwarder import row_to_payload

    return row_to_payload(row)


if TYPE_CHECKING:
    from z4j_brain.persistence.models import AuditLog
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.settings import Settings


#: Canonical-form fields, in stable order. The ``_canonicalize``
#: function emits every one of these as a JSON key. Adding a field
#: here without also emitting it in ``_canonicalize`` is a drift
#: bug; the startup guard ``verify_canonical_fields_emitted``
#: catches that.
_CANONICAL_FIELDS: tuple[str, ...] = (
    "version",
    "id",
    "action",
    "target_type",
    "target_id",
    "result",
    "outcome",
    "event_id",
    "user_id",
    "api_key_id",
    "project_id",
    "source_ip",
    "user_agent",
    "metadata",
    "occurred_at",
    "prev_row_hmac",
)

#: Current HMAC canonical version. Bumped only when the canonical-
#: fields list changes shape in a way that breaks existing row
#: signatures. v1 = the v1.3.0 baseline.
_HMAC_VERSION: int = 1


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """Plain-data view of an audit row, ready for write or verify.

    The service mints ``id`` up-front so the HMAC and the
    persisted row carry the same value (prevents row-clone by an
    attacker with raw write access).
    """

    id: uuid.UUID | None
    action: str
    target_type: str
    target_id: str | None
    result: str
    outcome: str | None
    event_id: uuid.UUID | None
    user_id: uuid.UUID | None
    project_id: uuid.UUID | None
    source_ip: str | None
    user_agent: str | None
    metadata: dict[str, Any]
    occurred_at: datetime
    #: Prior row's ``row_hmac`` at the moment THIS row was written.
    #: ``None`` for the very first row (genesis). Folded into the
    #: HMAC input so deleting any row breaks the next row's
    #: ``prev_row_hmac`` anchor, detectable by ``verify_chain``.
    prev_row_hmac: str | None = None
    #: Bearer-token attribution. ``None`` for cookie-session
    #: actions (most dashboard work) or for actions taken via a
    #: non-bearer auth path.
    api_key_id: uuid.UUID | None = None


class AuditService:
    """Single entry point for writing the audit log.

    The service holds:
    - the master secret (for HMAC computation)
    - the rotation-window secrets (for verifying pre-rotation rows)

    It does NOT hold a session, callers pass the repository in
    per-request, so the audit row participates in the caller's
    transaction. An audit row that "would have been written but
    the caller's transaction rolled back" is the wrong outcome
    for both compliance and debugging.
    """

    __slots__ = (
        "_audit_current_key_id",
        "_audit_keyring",
        "_post_write_hooks",
        "_secret",
        "_verify_secrets",
    )

    def __init__(self, settings: Settings) -> None:
        self._secret: bytes = settings.secret.get_secret_value().encode("utf-8")
        # Rotation window: ``verify_row`` accepts any of these.
        # Writes still bind to ``self._secret`` only.
        self._verify_secrets: list[bytes] = list(
            settings.all_secrets_for_verification(),
        )
        audit_secrets = settings.all_audit_chain_secrets_for_verification()
        if audit_secrets:
            self._audit_current_key_id, self._audit_keyring = build_audit_keyring(
                audit_secrets[0],
                audit_secrets[1:],
            )
        else:
            # Keyless mode exists only for development and pre-activation
            # compatibility.  Production Settings refuses it and no v2 state
            # operation can enter this path.
            self._audit_current_key_id = None
            self._audit_keyring = {}
        # Post-commit hooks fire AFTER a committed transaction
        # successfully writes audit rows (via the SQLAlchemy
        # ``after_commit`` listener installed at module load). Each
        # hook receives an eagerly-materialised dict payload (see
        # ``_build_forward_payload``), NOT the ORM row, so the hook
        # cannot accidentally trigger an out-of-transaction lazy
        # load. Hooks must be non-blocking; an exception is caught
        # and logged + ``record_swallowed("audit_service",
        # "post_commit_hook")`` so the existing Grafana alert
        # surfaces the failure.
        self._post_write_hooks: list[Any] = []

    def register_post_write_hook(self, hook: Any) -> None:
        """Add a callable invoked after a committing transaction
        successfully writes an audit row.

        ``hook`` is called as ``hook(payload_dict)`` from the
        SQLAlchemy ``after_commit`` event listener. The payload is
        an eagerly-materialised dict (no ORM lazy-load can fire
        from inside the hook), and the hook is only called when
        the writing transaction actually commits -- a rollback
        clears the staged payload and the hook is NEVER called for
        that row. (v1.6 audit C6 + H11.)

        Hooks must be non-blocking and must never raise; exceptions
        are caught and logged at WARNING.
        """
        self._post_write_hooks.append(hook)

    def unregister_post_write_hook(self, hook: Any) -> bool:
        """Drop a previously-registered hook. Returns True if a hook
        was removed. Used at lifespan teardown so rows written
        DURING shutdown teardown do not get queued into a forwarder
        whose drain task is about to be cancelled. (v1.6 audit H9.)
        """
        try:
            self._post_write_hooks.remove(hook)
            return True
        except ValueError:
            return False

    async def record(
        self,
        repo: AuditLogRepository,
        *,
        action: str,
        target_type: str,
        target_id: str | None = None,
        result: str = "success",
        outcome: str | None = None,
        event_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        api_key_id: uuid.UUID | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Append one row to the audit log inside the caller's transaction.

        ``outcome`` defaults to ``"allow"`` when ``result == "success"``,
        ``"failure"`` when ``result == "failed"``, and ``"error"``
        otherwise. The caller can override.
        """
        if self._audit_current_key_id is not None:
            try:
                return await self._record_v2(
                    repo,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    result=result,
                    outcome=outcome,
                    event_id=event_id,
                    user_id=user_id,
                    project_id=project_id,
                    api_key_id=api_key_id,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    metadata=metadata,
                )
            except Exception:
                # A v2 audit append is part of the caller's business
                # transaction.  Any refusal after that transaction has begun
                # must make the unit rollback-only, even when the low-level
                # authority lookup reports a RuntimeError (for example a
                # missing/duplicated authenticated singleton) rather than an
                # AuditChainIntegrityError.  Otherwise a legacy caller can
                # catch the refusal and commit the business mutation without
                # its required audit row.
                sync_session = getattr(repo.session, "sync_session", None)
                if sync_session is not None:
                    sync_session.info[_ROLLBACK_ONLY_KEY] = True
                raise

        # Mint the row id up-front so it can be folded into the HMAC
        # input. Without this, an attacker with raw write access
        # could clone the row payload + HMAC to create an
        # undetectable duplicate.
        row_id = uuid.uuid4()
        # Take the chain advisory lock immediately before the head
        # read + insert. The lock window is "head read → HMAC
        # compute → INSERT", microseconds.
        await repo.acquire_chain_lock()
        # Fetch the prior row's hmac so we can fold it into this
        # row's input. A subsequent DELETE of any row then leaves
        # the next row's ``prev_row_hmac`` referencing a prior row
        # whose hmac no longer matches, detectable by
        # ``verify_chain``.
        prev_row_hmac = await repo.get_latest_row_hmac()
        entry = AuditEntry(
            id=row_id,
            action=action[:80],
            target_type=target_type[:40],
            target_id=target_id[:200] if target_id else None,
            result=result[:20],
            outcome=outcome or self._default_outcome(result),
            event_id=event_id,
            user_id=user_id,
            project_id=project_id,
            api_key_id=api_key_id,
            source_ip=source_ip,
            user_agent=(user_agent[:1024] if user_agent else None),
            metadata=metadata or {},
            occurred_at=datetime.now(UTC),
            prev_row_hmac=prev_row_hmac,
        )
        row_hmac = self._compute_hmac(entry)
        inserted = await repo.insert(
            id=row_id,
            action=entry.action,
            target_type=entry.target_type,
            target_id=entry.target_id,
            result=entry.result,
            outcome=entry.outcome,
            event_id=entry.event_id,
            user_id=entry.user_id,
            project_id=entry.project_id,
            api_key_id=entry.api_key_id,
            source_ip=entry.source_ip,
            user_agent=entry.user_agent,
            metadata=entry.metadata,
            row_hmac=row_hmac,
            prev_row_hmac=prev_row_hmac,
            occurred_at=entry.occurred_at,
        )
        # Stage the row for post-COMMIT fan-out to registered hooks.
        # Two-step design (v1.6 audit C6 + H11):
        #   1. eagerly materialise the row into a plain dict so no
        #      ORM lazy-load can fire from inside the hook;
        #   2. push the dict onto ``session.info`` keyed under
        #      ``_PENDING_KEY``. The module-level ``after_commit``
        #      listener drains and fires hooks ONLY on successful
        #      commit; the ``after_rollback`` listener drops the
        #      staged dict so a rolled-back transaction never
        #      forwards.
        if self._post_write_hooks:
            try:
                payload = _build_forward_payload(inserted)
                # ``repo.session`` is the AsyncSession; its
                # ``sync_session`` is the SQLAlchemy Session the
                # event listeners are bound to.
                async_session = getattr(repo, "session", None)
                sync_session = getattr(async_session, "sync_session", None)
                if sync_session is not None:
                    pending = sync_session.info.setdefault(_PENDING_KEY, [])
                    pending.append((payload, list(self._post_write_hooks)))
            except Exception:
                logger.warning(
                    "z4j audit_service: failed to stage post-commit "
                    "hook payload; audit row written, mirror dropped",
                    exc_info=True,
                )
        return inserted

    async def rotate_chain_key(
        self,
        repo: AuditLogRepository,
    ) -> AuditLog | None:
        """Move authenticated state to the configured current audit key.

        ``None`` is an idempotent success: the database already committed this
        key transition, which is the expected resume state after a crash.
        """

        current_key_id = self._audit_current_key_id
        if current_key_id is None:
            raise AuditChainIntegrityError(
                "dedicated audit-chain key is unavailable",
            )
        try:
            await repo.require_sqlite_immediate_write_unit()
            await repo.acquire_chain_lock()
            await repo.set_chain_transition("key-rotation-v1")
            state = await repo.get_chain_state_for_update()
            state_payload = authenticate_state(state, self._audit_keyring)
            old_key_id = state_payload["state_key_id"]
            if old_key_id == current_key_id:
                return None
            return await self._record_v2(
                repo,
                action="audit.chain_key_rotated",
                target_type="audit_chain",
                target_id=str(state.generation),
                result="success",
                outcome="allow",
                event_id=None,
                user_id=None,
                project_id=None,
                api_key_id=None,
                source_ip=None,
                user_agent=None,
                metadata={
                    "from_hmac_key_id": old_key_id,
                    "to_hmac_key_id": current_key_id,
                },
                rotation_from_key_id=old_key_id,
            )
        except AuditChainIntegrityError:
            sync_session = getattr(repo.session, "sync_session", None)
            if sync_session is not None:
                sync_session.info[_ROLLBACK_ONLY_KEY] = True
            raise

    async def reset_generation(  # noqa: PLR0912, PLR0915  complete authenticated generation transition
        self,
        repo: AuditLogRepository,
        *,
        metadata: dict[str, Any],
    ) -> AuditLog:
        """Replace one verified generation with one signed reset genesis.

        The caller owns the surrounding offline domain/reset transaction.
        This method deliberately performs the audit transition last: it fully
        authenticates the old active and frozen evidence, deletes exactly that
        verified set, writes one visible generation-reset marker, and advances
        the authenticated singleton without changing the installation id or a
        retired-recovery binding.
        """

        from sqlalchemy import delete, select, text

        from z4j_brain.persistence.models import AuditLog

        current_key_id = self._audit_current_key_id
        if current_key_id is None:
            raise AuditChainIntegrityError(
                "dedicated audit-chain key is unavailable",
            )
        current_secret = self._audit_keyring[current_key_id]
        await repo.require_sqlite_immediate_write_unit()
        await repo.acquire_chain_lock()
        if repo.session.bind is not None and (repo.session.bind.dialect.name == "postgresql"):
            await repo.session.execute(
                text("LOCK TABLE audit_log IN EXCLUSIVE MODE"),
            )
        await repo.set_chain_transition("reset-v1")
        state = await repo.get_chain_state_for_update()
        state_payload = authenticate_state(state, self._audit_keyring)
        if state_payload["state_key_id"] != current_key_id:
            raise AuditChainIntegrityError(
                "configured current audit key differs from authenticated state; "
                "complete chain-key rotation before reset",
            )

        rows = list(
            (
                await repo.session.execute(
                    select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id).with_for_update(),
                )
            )
            .scalars()
            .all(),
        )
        active = [
            row
            for row in rows
            if row.legacy_frozen is False and row.chain_generation == state.generation
        ]
        frozen = [row for row in rows if row.legacy_frozen is True]
        if len(active) != state.active_row_count:
            raise AuditChainIntegrityError(
                "active audit row count does not match authenticated state",
            )
        if len(frozen) != state.frozen_row_count:
            raise AuditChainIntegrityError(
                "frozen audit row count does not match authenticated state",
            )
        if len(active) + len(frozen) != len(rows):
            raise AuditChainIntegrityError(
                "audit table contains rows outside authenticated generations",
            )
        if (
            frozen_snapshot_digest(
                [canonical_frozen_row_snapshot(row) for row in frozen],
            )
            != state.frozen_snapshot_digest
        ):
            raise AuditChainIntegrityError(
                "frozen audit snapshot does not match authenticated state",
            )

        prior_hmac = state.prune_row_hmac
        key_counts: Counter[str] = Counter()
        for row in active:
            if row.prev_row_hmac != prior_hmac or not self._verify_v2_row(row):
                raise AuditChainIntegrityError(
                    "active audit generation does not authenticate",
                )
            if row.hmac_key_id is None:
                raise AuditChainIntegrityError(
                    "active audit row lacks its HMAC key identity",
                )
            key_counts[row.hmac_key_id] += 1
            prior_hmac = row.row_hmac
        if dict(sorted(key_counts.items())) != dict(
            sorted(state.active_key_counts.items()),
        ):
            raise AuditChainIntegrityError(
                "active audit key counts do not match authenticated state",
            )
        if active:
            head = active[-1]
            if (
                head.row_hmac != state.head_row_hmac
                or head.hmac_key_id != state.head_hmac_key_id
                or normalize_timestamp(head.occurred_at)
                != normalize_timestamp(state.head_occurred_at)
                or head.id != state.head_id
            ):
                raise AuditChainIntegrityError(
                    "active audit head does not match authenticated state",
                )
        else:
            # Retention deliberately preserves the complete signed head as the
            # equal prune boundary after deleting the last active row.  That is
            # the only empty generation reset may authenticate: a markerless
            # empty state still cannot mint an unanchored reset genesis.
            head_quartet = (
                state.head_row_hmac,
                state.head_hmac_key_id,
                state.head_occurred_at,
                state.head_id,
            )
            prune_quartet = (
                state.prune_row_hmac,
                state.prune_hmac_key_id,
                state.prune_occurred_at,
                state.prune_id,
            )
            if any(value is None for value in head_quartet) or head_quartet != prune_quartet:
                raise AuditChainIntegrityError(
                    "empty active generation lacks an authenticated fully-pruned head",
                )

        deleted = await repo.session.execute(delete(AuditLog))
        if (deleted.rowcount or 0) != len(rows):
            raise AuditChainIntegrityError(
                "audit generation changed during reset",
            )

        old_generation = state.generation
        new_generation = uuid.uuid4()
        row_id = uuid.uuid4()
        occurred_at = strictly_later_audit_key(
            datetime.now(UTC),
            row_id,
            prior_timestamp=state.head_occurred_at,
            prior_id=state.head_id,
        )
        normalized_metadata = dict(metadata)
        payload = canonical_row_payload(
            row_id=row_id,
            action="audit.chain_generation_reset",
            target_type="audit_chain",
            target_id=str(old_generation),
            result="success",
            outcome="allow",
            event_id=None,
            user_id=None,
            api_key_id=None,
            project_id=None,
            source_ip=None,
            user_agent=None,
            metadata=normalized_metadata,
            occurred_at=occurred_at,
            prev_row_hmac=None,
            hmac_key_id=current_key_id,
            chain_generation=new_generation,
        )
        row_hmac = compute_row_hmac(current_secret, payload)
        marker = await repo.insert(
            id=row_id,
            action="audit.chain_generation_reset",
            target_type="audit_chain",
            target_id=str(old_generation),
            result="success",
            outcome="allow",
            event_id=None,
            user_id=None,
            project_id=None,
            api_key_id=None,
            source_ip=None,
            user_agent=None,
            metadata=normalized_metadata,
            row_hmac=row_hmac,
            prev_row_hmac=None,
            occurred_at=occurred_at,
            legacy_frozen=False,
            hmac_version=AUDIT_ROW_HMAC_VERSION,
            hmac_key_id=current_key_id,
            legacy_integrity_class=None,
            legacy_origin=None,
            chain_generation=new_generation,
        )
        await repo.session.refresh(marker)
        if canonical_json(self._v2_payload_from_row(marker)) != canonical_json(
            payload,
        ):
            raise AuditChainIntegrityError(
                "database normalized a signed reset marker differently",
            )

        state.generation = new_generation
        state.state_key_id = current_key_id
        state.head_row_hmac = row_hmac
        state.head_hmac_key_id = current_key_id
        state.head_occurred_at = marker.occurred_at
        state.head_id = marker.id
        state.prune_row_hmac = None
        state.prune_hmac_key_id = None
        state.prune_occurred_at = None
        state.prune_id = None
        state.active_row_count = 1
        state.active_key_counts = {current_key_id: 1}
        state.frozen_row_count = 0
        state.frozen_snapshot_digest = None
        state.state_mac = compute_state_mac(current_secret, state)
        await repo.session.flush()
        self._stage_forward(marker, repo)
        return marker

    async def _record_v2(  # noqa: PLR0915  atomic row/state signing transition
        self,
        repo: AuditLogRepository,
        *,
        action: str,
        target_type: str,
        target_id: str | None,
        result: str,
        outcome: str | None,
        event_id: uuid.UUID | None,
        user_id: uuid.UUID | None,
        project_id: uuid.UUID | None,
        api_key_id: uuid.UUID | None,
        source_ip: str | None,
        user_agent: str | None,
        metadata: dict[str, Any] | None,
        rotation_from_key_id: str | None = None,
    ) -> AuditLog:
        """Append one active v2 row and advance authenticated state atomically."""

        current_key_id = self._audit_current_key_id
        if current_key_id is None:
            raise AuditChainIntegrityError("dedicated audit-chain key is unavailable")
        current_secret = self._audit_keyring[current_key_id]

        await repo.require_sqlite_immediate_write_unit()
        await repo.acquire_chain_lock()
        await repo.set_chain_transition(
            "key-rotation-v1" if rotation_from_key_id is not None else "append-v1",
        )
        state = await repo.get_chain_state_for_update()
        state_payload = authenticate_state(state, self._audit_keyring)
        expected_state_key_id = rotation_from_key_id or current_key_id
        if state_payload["state_key_id"] != expected_state_key_id:
            raise AuditChainIntegrityError(
                "configured current audit key differs from authenticated state; "
                "run the explicit audit chain-key rotation ceremony",
            )

        head = await repo.get_active_head_for_update(
            generation=state.generation,
        )
        actual_active_count = await repo.count_active_generation(
            generation=state.generation,
        )
        if actual_active_count != state.active_row_count:
            raise AuditChainIntegrityError(
                "active audit row count does not match authenticated state",
            )
        if state.active_row_count == 0:
            if head is not None:
                raise AuditChainIntegrityError(
                    "authenticated state says the active generation is empty but live rows exist",
                )
        else:
            if head is None:
                raise AuditChainIntegrityError(
                    "authenticated state names active rows but the head is missing",
                )
            if (
                head.row_hmac != state.head_row_hmac
                or head.hmac_key_id != state.head_hmac_key_id
                or normalize_timestamp(head.occurred_at)
                != normalize_timestamp(state.head_occurred_at)
                or head.id != state.head_id
                or head.chain_generation != state.generation
                or head.legacy_frozen is not False
                or head.hmac_version != AUDIT_ROW_HMAC_VERSION
            ):
                raise AuditChainIntegrityError(
                    "live audit head does not match authenticated state",
                )
            if not self._verify_v2_row(head):
                raise AuditChainIntegrityError(
                    "live audit head HMAC does not authenticate",
                )

        row_id = uuid.uuid4()
        occurred_at = strictly_later_audit_key(
            datetime.now(UTC),
            row_id,
            prior_timestamp=state.head_occurred_at,
            prior_id=state.head_id,
        )
        normalized_metadata = metadata or {}
        normalized_source_ip = normalize_ip(source_ip)
        normalized_action = action[:80]
        normalized_target_type = target_type[:40]
        normalized_target_id = target_id[:200] if target_id else None
        normalized_result = result[:20]
        normalized_outcome = outcome or self._default_outcome(result)
        normalized_user_agent = user_agent[:1024] if user_agent else None
        payload = canonical_row_payload(
            row_id=row_id,
            action=normalized_action,
            target_type=normalized_target_type,
            target_id=normalized_target_id,
            result=normalized_result,
            outcome=normalized_outcome,
            event_id=event_id,
            user_id=user_id,
            api_key_id=api_key_id,
            project_id=project_id,
            source_ip=normalized_source_ip,
            user_agent=normalized_user_agent,
            metadata=normalized_metadata,
            occurred_at=occurred_at,
            prev_row_hmac=state.head_row_hmac,
            hmac_key_id=current_key_id,
            chain_generation=state.generation,
        )
        row_hmac = compute_row_hmac(current_secret, payload)
        inserted = await repo.insert(
            id=row_id,
            action=normalized_action,
            target_type=normalized_target_type,
            target_id=normalized_target_id,
            result=normalized_result,
            outcome=normalized_outcome,
            event_id=event_id,
            user_id=user_id,
            project_id=project_id,
            api_key_id=api_key_id,
            source_ip=normalized_source_ip,
            user_agent=normalized_user_agent,
            metadata=dict(normalized_metadata),
            row_hmac=row_hmac,
            prev_row_hmac=state.head_row_hmac,
            occurred_at=occurred_at,
            legacy_frozen=False,
            hmac_version=AUDIT_ROW_HMAC_VERSION,
            hmac_key_id=current_key_id,
            legacy_integrity_class=None,
            legacy_origin=None,
            chain_generation=state.generation,
        )
        await repo.session.refresh(inserted)
        persisted_payload = self._v2_payload_from_row(inserted)
        if canonical_json(persisted_payload) != canonical_json(payload):
            raise AuditChainIntegrityError(
                "database normalized a signed audit field differently",
            )

        counts = dict(state.active_key_counts)
        counts[current_key_id] = counts.get(current_key_id, 0) + 1
        state.head_row_hmac = row_hmac
        state.head_hmac_key_id = current_key_id
        state.head_occurred_at = inserted.occurred_at
        state.head_id = inserted.id
        state.active_row_count += 1
        state.active_key_counts = counts
        if rotation_from_key_id is not None:
            state.state_key_id = current_key_id
        state.state_mac = compute_state_mac(current_secret, state)
        await repo.session.flush()

        self._stage_forward(inserted, repo)
        return inserted

    def _stage_forward(
        self,
        inserted: AuditLog,
        repo: AuditLogRepository,
    ) -> None:
        """Stage one already-inserted row for post-commit forwarding."""

        if not self._post_write_hooks:
            return
        try:
            payload = _build_forward_payload(inserted)
            async_session = getattr(repo, "session", None)
            sync_session = getattr(async_session, "sync_session", None)
            if sync_session is not None:
                pending = sync_session.info.setdefault(_PENDING_KEY, [])
                pending.append((payload, list(self._post_write_hooks)))
        except Exception:
            logger.warning(
                "z4j audit_service: failed to stage post-commit hook payload; "
                "audit row written, mirror dropped",
                exc_info=True,
            )

    def verify_row(self, row: AuditLog) -> bool:
        """Recompute the HMAC for ``row`` and compare it constant-time.

        Returns False on missing ``row_hmac`` or tampered field.
        Tries every secret in the rotation window so a recent
        ``Z4J_SECRET`` rotation doesn't invalidate pre-rotation rows.
        """
        if row.hmac_version == AUDIT_ROW_HMAC_VERSION and row.legacy_frozen is False:
            return self._verify_v2_row(row)

        stored = row.row_hmac
        if not stored:
            return False
        entry = AuditEntry(
            id=row.id,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            result=row.result,
            outcome=row.outcome,
            event_id=row.event_id,
            user_id=row.user_id,
            project_id=row.project_id,
            api_key_id=row.api_key_id,
            source_ip=row.source_ip,
            user_agent=row.user_agent,
            metadata=row.audit_metadata,
            occurred_at=row.occurred_at,
            prev_row_hmac=row.prev_row_hmac,
        )
        for secret in self._verify_secrets:
            recomputed = self._compute_hmac(entry, secret=secret)
            if len(recomputed) == len(stored) and hmac.compare_digest(
                recomputed,
                stored,
            ):
                return True
        return False

    def _v2_payload_from_row(self, row: AuditLog) -> dict[str, Any]:
        if row.hmac_key_id is None or row.chain_generation is None or row.id is None:
            raise AuditChainIntegrityError("active v2 row markers are incomplete")
        return canonical_row_payload(
            row_id=row.id,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            result=row.result,
            outcome=row.outcome,
            event_id=row.event_id,
            user_id=row.user_id,
            api_key_id=row.api_key_id,
            project_id=row.project_id,
            source_ip=str(row.source_ip) if row.source_ip is not None else None,
            user_agent=row.user_agent,
            metadata=row.audit_metadata,
            occurred_at=row.occurred_at,
            prev_row_hmac=row.prev_row_hmac,
            hmac_key_id=row.hmac_key_id,
            chain_generation=row.chain_generation,
        )

    def _verify_v2_row(self, row: AuditLog) -> bool:
        stored = row.row_hmac
        key_id = row.hmac_key_id
        if (
            not stored
            or not key_id
            or row.hmac_version != AUDIT_ROW_HMAC_VERSION
            or row.legacy_frozen is not False
            or row.chain_generation is None
        ):
            return False
        secret = self._audit_keyring.get(key_id)
        if secret is None:
            return False
        try:
            expected = compute_row_hmac(secret, self._v2_payload_from_row(row))
        except AuditChainIntegrityError:
            return False
        return len(expected) == len(stored) and hmac.compare_digest(
            expected,
            stored,
        )

    def verify_chain(
        self,
        rows: list[AuditLog],
        *,
        prune_watermark: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Walk a sequence of rows and verify the HMAC chain.

        Expects rows ordered by insert order (``id`` UUIDv7 or
        ``occurred_at`` ascending). The input MUST start at the
        genesis row (the first row ever written, which has
        ``prev_row_hmac IS NULL``); otherwise a prefix-deletion
        attack would pass silently because the chain would simply
        re-anchor at whatever the caller fed in. Returns
        ``(ok, reasons)`` where ``reasons`` is a list of human-
        readable descriptions of any chain break.

        ``prune_watermark`` is the ``row_hmac`` of the newest row the
        retention sweeper has deleted (stored in ``z4j_meta``; see
        ``AuditLogRepository.get_prune_watermark``). When retention has
        legitimately deleted the genesis row, the first surviving row's
        ``prev_row_hmac`` equals this watermark, so we accept it as the
        new anchor instead of flagging a truncation. A first row whose
        ``prev_row_hmac`` is neither NULL nor the watermark is still
        flagged -- that is a real prefix truncation. When no prune has
        occurred (``prune_watermark`` is None) the NULL-genesis anchor is
        required exactly as before.

        A clean, fully-anchored chain returns ``(True, [])``.
        """
        reasons: list[str] = []
        prev_hmac: str | None = None
        # Genesis-row anchor: the FIRST row in the input must have
        # prev_row_hmac=None. Without this check, an operator with
        # DB write access who deletes the first N rows would produce
        # a "valid" trimmed chain because the verifier silently
        # re-anchors at whatever row is fed in first. (1.6.0
        # round-2 audit High-3.) Exception: after retention prunes the
        # genesis row, the first survivor legitimately anchors on the
        # stored prune watermark rather than NULL. (1.7 audit.)
        if rows and rows[0].prev_row_hmac is not None and rows[0].prev_row_hmac != prune_watermark:
            reasons.append(
                f"row {rows[0].id}: input does not start at the "
                f"genesis row (prev_row_hmac is not NULL); the "
                f"chain prefix may have been truncated",
            )
        for row in rows:
            if not self.verify_row(row):
                reasons.append(
                    f"row {row.id}: bad row_hmac (tampered field or missing hmac)",
                )
                continue
            # The genesis row (first row ever written) has
            # prev_row_hmac=None and is the start of the chain.
            # Every subsequent row's prev_row_hmac must equal the
            # PRIOR row's row_hmac.
            if prev_hmac is not None:
                actual = row.prev_row_hmac
                if actual != prev_hmac:
                    reasons.append(
                        f"row {row.id}: prev_row_hmac mismatch "
                        f"(saw {actual[:12] if actual else None}, "
                        f"expected {prev_hmac[:12]}). Likely a "
                        f"deleted row between this and the prior.",
                    )
            prev_hmac = row.row_hmac
        return (len(reasons) == 0, reasons)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _compute_hmac(
        self,
        entry: AuditEntry,
        *,
        secret: bytes | None = None,
    ) -> str:
        """Canonical → HMAC-SHA256 hex digest.

        ``secret`` defaults to the current write-side key;
        ``verify_row`` passes each rotation-window secret in turn.
        """
        canonical = self._canonicalize(entry)
        return hmac.new(
            secret if secret is not None else self._secret,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _canonicalize(entry: AuditEntry) -> str:
        """Render the canonical form for HMAC input.

        Stable JSON: sorted keys at every level, ISO-8601 UTC for
        the timestamp, ``str()`` for UUIDs, ``None`` for missing
        optionals. ``version`` is part of the payload so any
        future canonical-form change can be detected by version
        mismatch (the verifier will gain a per-version fallback
        path at that time).
        """
        payload: dict[str, Any] = {
            "version": _HMAC_VERSION,
            "id": str(entry.id) if entry.id else None,
            "action": entry.action,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "result": entry.result,
            "outcome": entry.outcome,
            "event_id": str(entry.event_id) if entry.event_id else None,
            "user_id": str(entry.user_id) if entry.user_id else None,
            "api_key_id": (str(entry.api_key_id) if entry.api_key_id else None),
            "project_id": str(entry.project_id) if entry.project_id else None,
            "source_ip": entry.source_ip,
            "user_agent": entry.user_agent,
            "metadata": entry.metadata,
            # A NAIVE occurred_at must be interpreted as UTC, never
            # local time. The service always signs an aware-UTC value,
            # but SQLite's DateTime(timezone=True) drops the offset in
            # storage, so verification re-reads a naive datetime.
            # ``astimezone(UTC)`` on a naive value assumes LOCAL time,
            # which on any non-UTC host shifted the canonical string
            # and false-positived the ENTIRE log as tampered. Aware
            # values (record time, Postgres reads) are unaffected.
            "occurred_at": (
                (
                    entry.occurred_at.replace(tzinfo=UTC)
                    if entry.occurred_at.tzinfo is None
                    else entry.occurred_at.astimezone(UTC)
                ).isoformat(timespec="microseconds")
            ),
            "prev_row_hmac": entry.prev_row_hmac,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

    @staticmethod
    def _default_outcome(result: str) -> str:
        """Map a free-form ``result`` string to the structured outcome.

        - ``"allow"``: action authorised AND succeeded.
        - ``"deny"``: action REJECTED at policy time (auth / scope /
          membership / CSRF / rate-limit). Reserved for actual
          authorization decisions so security audits can grep
          ``outcome=deny`` and find real access denials.
        - ``"failure"``: action authorised but the execution failed
          (task raised, command timed out, downstream error).
        - ``"error"``: internal panic / partial state / unknown.

        Caller can always override via the ``outcome=`` kwarg.
        """
        if result == "success":
            return "allow"
        if result == "failed":
            return "failure"
        return "error"


# ---------------------------------------------------------------------------
# Startup drift guard
# ---------------------------------------------------------------------------


def verify_canonical_fields_emitted() -> None:
    """Round-trip guard: every entry in ``_CANONICAL_FIELDS`` MUST
    appear in the JSON output of ``_canonicalize``. Catches the
    "field added to the tuple but forgotten in ``_canonicalize``"
    hole.

    Called by ``create_app`` at startup. Raises ``RuntimeError``
    on drift; the brain refuses to start so the bug is visible
    immediately.
    """
    sample = AuditEntry(
        id=uuid.uuid4(),
        action="t",
        target_type="t",
        target_id="t",
        result="success",
        outcome="allow",
        event_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        source_ip="127.0.0.1",
        user_agent="t",
        metadata={},
        occurred_at=datetime.now(UTC),
        prev_row_hmac="0" * 64,
    )
    canonical_dict = json.loads(AuditService._canonicalize(sample))
    for field in _CANONICAL_FIELDS:
        if field not in canonical_dict:
            raise RuntimeError(
                f"audit canonical drift: {field!r} is in "
                f"_CANONICAL_FIELDS but not emitted by "
                f"_canonicalize. Adding a field to the tuple "
                f"without also emitting it in _canonicalize "
                f"silently breaks HMAC verification for every row "
                f"written at the current version. See "
                f"z4j_brain/docs/audit-canonical-fields.md.",
            )


__all__ = [
    "AuditEntry",
    "AuditService",
    "verify_canonical_fields_emitted",
]
