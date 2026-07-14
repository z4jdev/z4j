"""``users`` repository.

Encapsulates every read/write of the ``users`` table, including
the lockout / failed-login bookkeeping. The auth service depends
only on this interface - there is no SQL outside this module.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import User
from z4j_brain.persistence.repositories._base import BaseRepository

#: Argument used to sentinel "ip not supplied / unknown".
_UNKNOWN_IP = "0.0.0.0"  # noqa: S104  sentinel for unknown IP, never used as a bind address


class UserRepository(BaseRepository[User]):
    """User CRUD + lockout state."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, User)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    async def get_by_email(self, email: str) -> User | None:
        """Case-insensitive lookup by email.

        On Postgres the column is ``CITEXT`` so the comparison is
        already case-insensitive at the storage layer. On SQLite the
        column is ``TEXT``, so we explicitly lowercase both sides.
        Either way, the auth service is expected to canonicalize
        the email BEFORE calling here - the lowercase here is
        belt-and-braces. We use ``str.casefold`` rather than
        ``str.lower`` so the in-Python value matches what
        ``canonicalize_email`` stores (handles non-ASCII letters
        like German ``ß`` → ``ss`` consistently).
        """
        normalized = email.strip().casefold()
        result = await self.session.execute(
            select(User).where(func.lower(User.email) == normalized),
        )
        return result.scalar_one_or_none()

    async def count_active_admins(self) -> int:
        """Return the number of *active* global-admin users.

        Used by the user-admin endpoints to refuse operations that
        would leave the instance with zero admins - which locks
        everybody out of instance administration (creating users,
        managing projects, modifying retention/quotas, etc.).

        Only active users count. A deactivated admin cannot log in,
        so it does not satisfy the "must have at least one admin"
        invariant.
        """
        result = await self.session.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.is_admin.is_(True),
                User.is_active.is_(True),
            ),
        )
        return int(result.scalar_one() or 0)

    async def count_active_admins_for_update(self) -> int:
        """Same as :meth:`count_active_admins` but row-locks the set.

        TOCTOU protection: ``demote`` / ``deactivate`` / ``delete``
        all check "is this the last admin?" before mutating. Two
        admin sessions racing each other can both observe
        ``count == 2`` and each demote the other, leaving zero
        admins. Holding ``SELECT ... FOR UPDATE`` over the active-
        admin row set serialises every concurrent admin-mutation
        within the same transaction so the second one re-reads
        ``count == 1`` and refuses.

        SQLite ignores ``FOR UPDATE`` (no row-level locks); on
        SQLite the worst-case race is a per-process lock anyway,
        which the test suite covers. Postgres honours it strictly.

        Callers MUST be inside an open transaction (the FastAPI
        ``get_session`` dependency provides one) AND MUST call this
        instead of the unlocked variant when they're about to
        mutate. The next ``await session.commit()`` releases the
        lock; bailing out without committing also releases it.
        """
        from sqlalchemy import select as _select

        # Lock the rows themselves (every active admin) for the
        # duration of this transaction. ``of=User`` scopes the
        # FOR UPDATE to ONLY the users table even if the query
        # joins other tables in the future.
        stmt = (
            _select(User.id)
            .where(
                User.is_admin.is_(True),
                User.is_active.is_(True),
            )
            .with_for_update(of=User)
        )
        result = await self.session.execute(stmt)
        return len(list(result.scalars().all()))

    async def lock_for_password_change(self, user_id: UUID) -> None:
        """``SELECT ... FOR UPDATE`` on the user row.

        Serialises concurrent ``change_password`` requests for the
        same user - without this, two parallel password-change
        requests can both pass ``verify(current_password)``, both
        ``revoke_all_for_user``, both ``sessions.create`` - and
        the user ends with two live, post-rotation sessions
        instead of one.

        Caller MUST be inside an open transaction and MUST commit
        (or rollback) before releasing. SQLite ignores FOR UPDATE
        (no row-level locks); per-process serialisation in tests
        is sufficient. Postgres honours it strictly.
        """
        from sqlalchemy import select as _select

        stmt = _select(User.id).where(User.id == user_id).with_for_update(of=User)
        await self.session.execute(stmt)

    # ------------------------------------------------------------------
    # Lockout bookkeeping
    # ------------------------------------------------------------------

    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        ip: str | None,
        lockout_threshold: int,
        lockout_duration_seconds: int,
    ) -> User | None:
        """Atomically increment the failure counter + maybe lock.

        Single-statement ``UPDATE ... SET counter = counter + 1``
        so concurrent failed logins from the same IP (or two
        attacker workers hammering the same account) can never race
        to lose an increment. Audit H4 fixed the prior read-
        modify-write which let two workers both read N and both
        write N+1.

        Implemented with a CTE + two-phase UPDATE so we can compute
        the post-bump count and conditionally set ``locked_until``
        in the same round trip on Postgres, and a fallback SELECT-
        then-UPDATE path on SQLite (SQLite doesn't support the CTE
        pattern with RETURNING in all versions). Under Postgres
        this is truly atomic; under SQLite we rely on the brain
        being single-process for the moment (single-writer DB
        anyway).

        Returns the updated User row, or None if user_id is
        unknown.
        """
        from sqlalchemy import literal
        from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: F401

        now = datetime.now(UTC)
        locked_boundary = now + timedelta(seconds=lockout_duration_seconds)

        bind = self.session.get_bind() if hasattr(self.session, "get_bind") else None
        dialect_name = getattr(getattr(bind, "dialect", None), "name", "")

        if dialect_name == "postgresql":
            # Atomic increment + conditional lock in one statement.
            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(
                    failed_login_count=User.failed_login_count + 1,
                    last_failed_login_at=now,
                    last_failed_login_ip=ip or _UNKNOWN_IP,
                    locked_until=literal(None),  # placeholder; recomputed below
                )
                .returning(User.failed_login_count)
            )
            result = await self.session.execute(stmt)
            row = result.first()
            if row is None:
                return None
            new_count = int(row[0])
            if new_count >= lockout_threshold:
                await self.session.execute(
                    update(User).where(User.id == user_id).values(locked_until=locked_boundary),
                )
            await self.session.flush()
            return await self.get(user_id)

        # SQLite fallback: single-writer DB serialises writes at
        # the sqlite-lock level, so the read-then-write is atomic
        # enough for dev + single-process deployments. This branch
        # is NOT safe under a multi-process SQLite deployment, but
        # we don't target that shape.
        user = await self.get(user_id)
        if user is None:
            return None
        user.failed_login_count = user.failed_login_count + 1
        user.last_failed_login_at = now
        user.last_failed_login_ip = ip or _UNKNOWN_IP
        if user.failed_login_count >= lockout_threshold:
            user.locked_until = locked_boundary
        await self.session.flush()
        return user

    async def reset_failed_login(self, user_id: UUID) -> None:
        """Clear the failure counter and any active lock.

        Called after a successful login or password change.
        """
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_count=0,
                locked_until=None,
                last_failed_login_at=None,
                last_failed_login_ip=None,
            ),
        )

    # ------------------------------------------------------------------
    # MFA lockout bookkeeping (1.7 security hardening)
    # ------------------------------------------------------------------

    async def record_mfa_failure(
        self,
        user_id: UUID,
        *,
        lockout_threshold: int,
        lockout_duration_seconds: int,
    ) -> User | None:
        """Atomically increment the failed-MFA counter + maybe lock.

        Per-account failed-MFA lockout (NIST 800-63B 5.2.2). Direct
        analogue of :meth:`record_failed_login`: a single-statement
        ``UPDATE ... SET failed_mfa_count = failed_mfa_count + 1`` so two
        attacker workers (or replicas) hammering the same account's
        /verify, /enroll-complete, or /disable endpoint can never race to
        lose an increment. When the bumped count reaches
        ``lockout_threshold`` we set ``mfa_locked_until = now + duration``.

        Implemented as an atomic increment + conditional lock on Postgres
        (increment with RETURNING, then a guarded second UPDATE) and a
        read-then-write fallback on SQLite (single-writer, serialised at
        the sqlite-lock level), exactly like ``record_failed_login``.

        Returns the updated User row, or None if user_id is unknown.
        """
        now = datetime.now(UTC)
        locked_boundary = now + timedelta(seconds=lockout_duration_seconds)

        bind = self.session.get_bind() if hasattr(self.session, "get_bind") else None
        dialect_name = getattr(getattr(bind, "dialect", None), "name", "")

        if dialect_name == "postgresql":
            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(failed_mfa_count=User.failed_mfa_count + 1)
                .returning(User.failed_mfa_count)
            )
            result = await self.session.execute(stmt)
            row = result.first()
            if row is None:
                return None
            new_count = int(row[0])
            if new_count >= lockout_threshold:
                await self.session.execute(
                    update(User).where(User.id == user_id).values(mfa_locked_until=locked_boundary),
                )
            await self.session.flush()
            return await self.get(user_id)

        # SQLite fallback: single-writer DB serialises writes, so the
        # read-then-write is atomic enough for the dev + single-process
        # deployments SQLite targets (mirrors ``record_failed_login``).
        user = await self.get(user_id)
        if user is None:
            return None
        user.failed_mfa_count = user.failed_mfa_count + 1
        if user.failed_mfa_count >= lockout_threshold:
            user.mfa_locked_until = locked_boundary
        await self.session.flush()
        return user

    async def reset_mfa_failures(self, user_id: UUID) -> None:
        """Clear the failed-MFA counter and any active MFA lock.

        Called after a successful MFA verification: a good code proves
        possession of the second factor, so the brute-force counter
        resets. Mirrors :meth:`reset_failed_login`.
        """
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_mfa_count=0,
                mfa_locked_until=None,
            ),
        )

    async def consume_totp_counter(self, user_id: UUID, *, counter: int) -> bool:
        """Atomically claim a TOTP time-step as single-use (anti-replay).

        RFC 6238 5.2: a TOTP code stays valid across the +/-1 step
        acceptance window (~90s), so a captured code is replayable until
        it ages out. This closes that window with a single monotonic-
        advance UPDATE::

            UPDATE users SET last_totp_counter = :counter
             WHERE id = :id
               AND (last_totp_counter IS NULL OR last_totp_counter < :counter)

        ``rowcount == 1`` -> the step was unused (or strictly older than
        this one) and is now claimed: accept. ``rowcount == 0`` -> the
        step was already consumed (an equal-or-newer counter is stored):
        the caller rejects it as a replay. One statement, no read-then-
        write, so two parallel verifies presenting the same code can
        never both win.
        """
        result = await self.session.execute(
            update(User)
            .where(
                User.id == user_id,
                or_(
                    User.last_totp_counter.is_(None),
                    User.last_totp_counter < counter,
                ),
            )
            .values(last_totp_counter=counter),
        )
        return int(result.rowcount or 0) == 1

    async def reset_totp_counter(self, user_id: UUID) -> None:
        """Reset the TOTP anti-replay high-water mark to NULL.

        Called on enroll-complete (a NEW secret starts a fresh counter
        space -- otherwise a stale high-water mark from a prior
        enrollment could pre-reject the first post-enroll code) and on
        disable (MFA removed). See :meth:`consume_totp_counter`.
        """
        await self.session.execute(
            update(User).where(User.id == user_id).values(last_totp_counter=None),
        )

    async def update_profile(
        self,
        user_id: UUID,
        *,
        first_name: str | None = ...,  # type: ignore[assignment]
        last_name: str | None = ...,  # type: ignore[assignment]
        display_name: str | None = ...,  # type: ignore[assignment]
        timezone: str | None = ...,  # type: ignore[assignment]
    ) -> User | None:
        """Update whitelisted profile fields for a user.

        Only non-sentinel values are applied so the caller can omit
        fields it does not want to change. Returns the refreshed
        User row, or None if the user_id is unknown.
        """
        sentinel = ...
        values: dict[str, object] = {}
        if first_name is not sentinel:
            values["first_name"] = first_name
        if last_name is not sentinel:
            values["last_name"] = last_name
        if display_name is not sentinel:
            values["display_name"] = display_name
        if timezone is not sentinel:
            values["timezone"] = timezone
        if not values:
            return await self.get(user_id)
        # Always bump updated_at on a profile write so the admin
        # list + external SCIM consumers see the row as recently
        # modified. The server-side ``onupdate`` would do this too,
        # but populating the value explicitly avoids a post-commit
        # lazy refresh which breaks on aiosqlite (see
        # ``api/users.py::update_user`` for the same reason).
        values["updated_at"] = datetime.now(UTC)
        await self.session.execute(
            update(User).where(User.id == user_id).values(**values),
        )
        await self.session.flush()
        # Expire and re-fetch so the caller sees the updated state.
        user = await self.get(user_id)
        if user is not None:
            await self.session.refresh(user)
        return user

    async def set_mfa_state(
        self,
        user_id: UUID,
        *,
        secret_encrypted: bytes | None,
        enrolled_at: datetime | None,
    ) -> None:
        """Write the MFA columns on a user row in a single statement.

        Either of ``secret_encrypted`` / ``enrolled_at`` can be ``None``
        to clear the corresponding column (e.g. when disabling MFA or
        resetting via ``z4j reset-mfa``). To start a pending enrollment
        pass ``secret_encrypted=<blob>, enrolled_at=None``; to complete
        the enrollment, pass both. To rewrite a stored secret after a
        ``Z4J_SECRET`` rotation pass ``secret_encrypted=<rewrapped>,
        enrolled_at=<existing value>``.
        """
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                mfa_secret_encrypted=secret_encrypted,
                mfa_enrolled_at=enrolled_at,
                updated_at=datetime.now(UTC),
            ),
        )

    async def set_mfa_enforcement_started(
        self,
        user_id: UUID,
        *,
        when: datetime,
    ) -> bool:
        """Stamp ``mfa_enforcement_started_at`` iff it is still NULL.

        Atomic stamp-once: the ``WHERE ... IS NULL`` clause makes the
        database arbitrate between concurrent first logins under a
        freshly-enabled enforcement policy, so exactly one caller
        returns True (and writes the grace-started audit row); every
        later caller returns False and the original grace anchor is
        never moved. Deliberately NO clear counterpart -- the anchor
        is a one-way historical fact, so a user cannot reset their
        grace window by cycling MFA off and on.

        Returns True when this call performed the stamp.
        """
        result = await self.session.execute(
            update(User)
            .where(
                User.id == user_id,
                User.mfa_enforcement_started_at.is_(None),
            )
            .values(
                mfa_enforcement_started_at=when,
                updated_at=datetime.now(UTC),
            ),
        )
        return int(result.rowcount or 0) == 1

    async def update_password_hash(
        self,
        user_id: UUID,
        new_hash: str,
        *,
        password_changed: bool,
    ) -> None:
        """Persist a new password hash.

        ``password_changed=True`` updates ``password_changed_at``
        which (combined with the session's ``issued_at``) is the
        anchor for "password rotated → revoke older sessions".
        Pass False when this is a silent rehash for parameter
        rotation - those should NOT log out other devices.
        """
        now = datetime.now(UTC)
        values: dict[str, object] = {
            "password_hash": new_hash,
            "updated_at": now,
        }
        if password_changed:
            values["password_changed_at"] = now
        await self.session.execute(
            update(User).where(User.id == user_id).values(**values),
        )


__all__ = ["UserRepository"]
