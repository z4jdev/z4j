"""First-boot setup service.

Two operations:

- :meth:`SetupService.is_first_boot` - true while ``users`` is empty.
- :meth:`SetupService.mint_token` - wipe any old token, generate a
  new 256-bit token, store its HMAC-SHA256 hash, return the
  PLAINTEXT (only ever returned by this call - never persisted).
- :meth:`SetupService.complete` - verify token, validate password,
  create the bootstrap admin, create the default project, write the
  audit row, delete the token. Race-safe via inner re-check.

Verification uses an HMAC of the supplied token (with
``settings.secret`` as key) and constant-time-compares to the
stored hash. Even an attacker who somehow gets the hash table cannot
precompute candidate tokens without the master secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from z4j_brain.auth.passwords import PasswordError
from z4j_brain.auth.sessions import aware_utc
from z4j_brain.errors import (
    ConflictError,
    NotFoundError,
)
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        FirstBootTokenRepository,
        MembershipRepository,
        ProjectRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


_DEFAULT_PROJECT_SLUG: str = "default"
_DEFAULT_PROJECT_NAME: str = "Default"
#: Salt baked into the HMAC so the same secret used for command
#: signing cannot be repurposed against the setup-token table.
_SETUP_TOKEN_SALT: bytes = b"z4j-setup-token-v1"


@dataclass(frozen=True, slots=True)
class SetupResult:
    """Result of a successful first-boot completion."""

    user: User
    project_id: uuid.UUID


class SetupService:
    """First-boot orchestration.

    The brain instantiates one of these in the lifespan startup
    hook and calls :meth:`is_first_boot` + :meth:`mint_token`. The
    setup endpoint instantiates a request-scoped instance and calls
    :meth:`complete`.

    The per-IP rate limiter is sourced from the ``audit_log`` table
    so it survives worker restarts AND is consistent across multiple
    uvicorn workers. Every failed setup attempt writes a
    ``setup.attempt`` row with the source IP; the budget query
    counts those rows in the sliding window. Defends against the
    unlikely case of someone brute-forcing the 256-bit token from
    a single source.
    """

    __slots__ = ("_secret", "_settings", "_hasher", "_audit", "_db_manager")

    def __init__(
        self,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
        db_manager: "Any" = None,
    ) -> None:
        self._secret: bytes = settings.secret.get_secret_value().encode("utf-8")
        self._settings = settings
        self._hasher = hasher
        self._audit = audit
        # Optional reference to the brain's DatabaseManager so
        # _record_setup_failure can open a dedicated short-lived
        # session - the failure audit then survives a rollback of
        # the caller's transaction (R3 finding H4). The CLI path
        # constructs SetupService without a db_manager (it has
        # its own session); the production path threads it in
        # from main.py's lifespan.
        self._db_manager = db_manager

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    async def is_first_boot(users: UserRepository) -> bool:
        """True iff no rows exist in ``users``."""
        return await users.count() == 0

    # ------------------------------------------------------------------
    # Mint
    # ------------------------------------------------------------------

    async def mint_token(
        self,
        tokens: FirstBootTokenRepository,
    ) -> tuple[str, datetime]:
        """Wipe any stale token rows and store a fresh one.

        Returns ``(plaintext_token, expires_at)``. The plaintext is
        the only place this token ever exists in cleartext - the
        startup hook prints it to stdout once and never persists it.

        Side effect: deletes every existing row in
        ``first_boot_tokens``. There must be at most one valid
        token at a time.
        """
        await tokens.delete_all()
        plaintext = secrets.token_urlsafe(32)
        token_hash = self._hash_token(plaintext)
        expires_at = datetime.now(UTC) + timedelta(
            seconds=self._settings.first_boot_token_ttl_seconds,
        )
        await tokens.insert(token_hash=token_hash, expires_at=expires_at)
        return plaintext, expires_at

    # ------------------------------------------------------------------
    # Complete
    # ------------------------------------------------------------------

    async def complete(
        self,
        *,
        users: UserRepository,
        projects: ProjectRepository,
        memberships: MembershipRepository,
        tokens: FirstBootTokenRepository,
        audit_log: AuditLogRepository,
        token: str,
        email: str,
        display_name: str | None,
        password: str,
        ip: str,
        user_agent: str | None,
    ) -> SetupResult:
        """Verify the token + bootstrap the brain.

        Steps (all inside the caller's transaction):
        1. Per-IP rate limit check.
        2. Re-check ``users`` is still empty.
        3. Read the active token row.
        4. Verify the supplied token via HMAC + constant-time
           comparison.
        5. Verify the TTL.
        6. Validate the password against the policy.
        7. Hash the password.
        8. Create the admin user.
        9. Create the ``default`` project.
        10. Grant the admin a membership.
        11. Delete the token row (single-use).
        12. Audit ``setup.completed``.

        Any failure raises a brain exception. The endpoint maps
        these to 410 / 422 / 429 / 409 / 503.
        """
        if not await self._check_attempt_budget(audit_log, ip):
            # Deliberately do NOT write a setup.attempt audit row here.
            # The budget check counts ALL setup.* rows in the window,
            # so adding one per blocked request would perpetuate the
            # lockout indefinitely - each retry would push the window
            # forward by another row. The original failures that
            # triggered the lockout are still in the table and still
            # count for the full 15-minute TTL; that's the correct
            # behavior. Use a non-counted action prefix if a future
            # version wants to record the rate-limit signal.
            from z4j_brain.errors import RateLimitExceeded

            raise RateLimitExceeded(
                "too many setup attempts from this address. "
                "Wait 15 minutes for the rate-limit window to clear, "
                "or restart the brain to mint a fresh setup token.",
            )

        # Re-check the user count BEFORE consulting the token table.
        # If a previous setup completed in the gap between the
        # browser loading /setup and submitting the form, the
        # endpoint should fail with 409, not 410, so the operator
        # knows the brain is already initialised.
        if not await self.is_first_boot(users):
            await self._record_setup_failure(
                audit_log, ip=ip, user_agent=user_agent, reason="already_initialised",
            )
            raise ConflictError(
                "brain has already been initialised",
                details={"reason": "already_initialised"},
            )

        # SELECT ... FOR UPDATE so two concurrent complete() calls
        # serialize on the token row. The loser blocks until the
        # winner commits (and deletes the token), then sees None
        # and gets a clean "expired or already used" error instead
        # of an opaque unique-constraint violation downstream.
        token_row = await tokens.get_active(lock=True)
        if token_row is None:
            await self._record_setup_failure(
                audit_log, ip=ip, user_agent=user_agent, reason="no_active_token",
            )
            raise NotFoundError(
                "No active setup token. Restart the brain to mint a "
                "fresh setup URL, or run `z4j-brain reset-setup` to "
                "explicitly reset the bootstrap state.",
                details={"reason": "no_active_token"},
            )

        if aware_utc(token_row.expires_at) <= datetime.now(UTC):
            # Token row has aged out. Delete defensively.
            await tokens.delete_by_id(token_row.id)
            await self._record_setup_failure(
                audit_log, ip=ip, user_agent=user_agent, reason="expired",
            )
            raise NotFoundError(
                "Setup token has expired (15-minute lifetime). "
                "Restart the brain to mint a fresh setup URL.",
                details={"reason": "expired"},
            )

        supplied_hash = self._hash_token(token)
        if not (
            len(supplied_hash) == len(token_row.token_hash)
            and hmac.compare_digest(supplied_hash, token_row.token_hash)
        ):
            await self._record_setup_failure(
                audit_log, ip=ip, user_agent=user_agent, reason="invalid_token",
            )
            raise NotFoundError(
                "This setup link is from a previous server run. The "
                "current server has minted a new token - check your "
                "terminal for the latest setup URL printed at startup, "
                "or run `z4j-brain reset-setup` to mint a fresh one.",
                details={"reason": "invalid_token"},
            )

        # Validate password BEFORE hashing - argon2 is expensive
        # and we don't want to spend it on a doomed input.
        try:
            self._hasher.validate_policy(password)
        except PasswordError as exc:
            await self._record_setup_failure(
                audit_log,
                ip=ip,
                user_agent=user_agent,
                reason=f"password_{exc.code}",
            )
            raise

        # Canonicalize email defensively. The endpoint already
        # validated, but we treat this as the trust boundary.
        from z4j_brain.domain.auth_service import canonicalize_email

        email_canonical = canonicalize_email(email)

        password_hash = self._hasher.hash(password)
        from z4j_brain.persistence.models import Project, User

        user = User(
            email=email_canonical,
            password_hash=password_hash,
            display_name=(display_name.strip() if display_name else None),
            is_admin=True,
            is_active=True,
            password_changed_at=datetime.now(UTC),
        )
        await users.add(user)

        project = Project(
            slug=_DEFAULT_PROJECT_SLUG,
            name=_DEFAULT_PROJECT_NAME,
        )
        await projects.add(project)
        await memberships.grant(
            user_id=user.id,
            project_id=project.id,
            role=ProjectRole.ADMIN,
        )

        # Seed the default project with one project_default_subscription:
        # task.failed -> in-app, no external channels. New members
        # auto-pick this up and immediately get failure notifications
        # in their bell without any setup.
        from z4j_brain.persistence.models.notification import (
            ProjectDefaultSubscription,
        )

        # All these repos share the same session (caller-managed
        # transaction). Use any one of them to reach the session.
        db_session = users.session
        db_session.add(
            ProjectDefaultSubscription(
                project_id=project.id,
                trigger="task.failed",
                in_app=True,
            ),
        )
        await db_session.flush()

        # Materialize that default into a real user_subscription for
        # the newly-created admin, so they're set up too.
        from z4j_brain.domain.notifications import NotificationService

        await NotificationService().materialize_defaults_for_member(
            session=db_session,
            user_id=user.id,
            project_id=project.id,
        )

        # Consume the token (single-use).
        await tokens.delete_by_id(token_row.id)

        await self._audit.record(
            audit_log,
            action="setup.completed",
            target_type="user",
            target_id=str(user.id),
            result="success",
            outcome="allow",
            user_id=user.id,
            project_id=project.id,
            source_ip=ip,
            user_agent=user_agent,
            metadata={
                "email": email_canonical,
                "project_slug": _DEFAULT_PROJECT_SLUG,
            },
        )

        return SetupResult(user=user, project_id=project.id)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _hash_token(self, plaintext: str) -> str:
        """HMAC-SHA256 hex digest of ``plaintext`` keyed by the master secret.

        Salted by ``_SETUP_TOKEN_SALT`` so a future feature using
        the same secret cannot collide. Returns the hex digest, 64
        chars.
        """
        h = hmac.new(self._secret + _SETUP_TOKEN_SALT, plaintext.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()

    async def _check_attempt_budget(
        self,
        audit_log: AuditLogRepository,
        ip: str,
    ) -> bool:
        """Sliding 15-minute window of failed attempts per IP.

        Sourced from the ``audit_log`` table so the budget is
        shared across uvicorn workers and survives restarts.
        Returns ``True`` when the IP is still under budget.
        Successful setups don't need to be counted: they delete
        the token, so any further attempt against the consumed
        token will be a failure that bumps the counter normally.

        Known limitation (R3 finding M9 - accepted trade-off):
        two concurrent pre-checks can both observe ``count <
        threshold`` and both proceed, so the budget can overshoot
        by at most ``uvicorn_workers × concurrency - 1``. Making
        this truly atomic would require coupling the budget
        check into the audit INSERT via a Postgres CTE, which
        mixes concerns and complicates the audit chain. At the
        default threshold (10 attempts per 15 min per IP) the
        overshoot is a rounding error on the rate-limit signal,
        not a security bypass.
        """
        cutoff = datetime.now(UTC) - timedelta(minutes=15)
        existing = await audit_log.count_recent_by_action_and_ip(
            action_prefix="setup.",
            source_ip=ip,
            since=cutoff,
        )
        if existing >= self._settings.first_boot_attempts_per_ip:
            return False
        # Round-8 audit fix R8-HIGH-6 (Apr 2026): also enforce a
        # GLOBAL cap so an attacker who rotates source IPs (NAT
        # botnet, X-Forwarded-For abuse if proxy chain is misconfigured,
        # cloud function fan-out) can't multiply the per-IP budget by
        # the IP space they control. The 256-bit token has astronomical
        # entropy so the global cap can be loose; we set it at 8x the
        # per-IP cap which still terminates the brute-force in seconds
        # of attempts even at the most permissive setting.
        global_cap = self._settings.first_boot_attempts_per_ip * 8
        # Round-9 audit fix R9-Reaud-H1 (Apr 2026): exclude
        # ``setup.completed`` from the count. On a brand-new install
        # the success row would otherwise immediately consume one of
        # the 8x retry budget, hurting the next legitimate
        # operator-driven setup if the brain is reset for testing.
        global_existing = await audit_log.count_recent_by_action(
            action_prefix="setup.",
            since=cutoff,
            exclude_actions=("setup.completed",),
        )
        return global_existing < global_cap

    async def _record_setup_failure(
        self,
        audit_log: AuditLogRepository,
        *,
        ip: str,
        user_agent: str | None,
        reason: str,
    ) -> None:
        """Record a failed setup attempt.

        Uses a DEDICATED short-lived session when a db_manager was
        wired in at construction time, so the failure row survives
        a rollback of the caller's transaction (R3 finding H4 -
        without this, an exception in the success path further
        down ``complete()`` would also wipe the failure audit,
        leaving no trace AND under-counting the attempt budget).
        Falls back to the caller's session when no db_manager is
        available (CLI path, tests).
        """
        if self._db_manager is not None:
            try:
                async with self._db_manager.session() as audit_session:
                    from z4j_brain.persistence.repositories import (
                        AuditLogRepository as _AuditLogRepo,
                    )

                    await self._audit.record(
                        _AuditLogRepo(audit_session),
                        action="setup.attempt",
                        target_type="setup",
                        result="failed",
                        outcome="deny",
                        source_ip=ip,
                        user_agent=user_agent,
                        metadata={"reason": reason},
                    )
                    await audit_session.commit()
                return
            except Exception:  # noqa: BLE001
                # Dedicated-session write failed (DB blip). Fall
                # back to the caller's session - better to risk
                # losing the audit on rollback than to silently
                # drop it now.
                pass
        await self._audit.record(
            audit_log,
            action="setup.attempt",
            target_type="setup",
            result="failed",
            outcome="deny",
            source_ip=ip,
            user_agent=user_agent,
            metadata={"reason": reason},
        )


__all__ = ["SetupResult", "SetupService"]
