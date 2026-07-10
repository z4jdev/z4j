"""MFA enrollment-enforcement policy evaluation.

Pure functions, no I/O. The policy is driven by two settings flags
(``Z4J_MFA_ENFORCE_FOR_ADMINS`` / ``Z4J_MFA_ENFORCE_FOR_ALL``, both
default OFF) plus the per-user grace anchor
``users.mfa_enforcement_started_at``:

- Enforcement TARGETS a user when ``mfa_enforce_for_all`` is true, or
  when ``mfa_enforce_for_admins`` is true and the user carries the
  global ``is_admin`` bit. Project-level ``admin`` memberships do NOT
  count: the settings docstring documents the flag against the global
  bit, and project roles are per-project authorization that a user can
  gain/lose many times a day -- anchoring an account-level grace clock
  to them would make the deadline flap.
- A targeted user WITH MFA enrolled is unaffected.
- A targeted user WITHOUT MFA gets ``mfa_enrollment_grace_days`` days
  of grace, anchored at ``mfa_enforcement_started_at``. Login stamps
  the anchor the first time it observes the policy applying to the
  user; until then the clock has not started and nothing is blocked
  (see ``api/auth.py::login``).
- Past the deadline (immediately, when ``grace_days == 0``) the user
  is ``blocked``: login still succeeds -- refusing outright would make
  enrollment impossible, because enrollment itself requires an
  authenticated session -- but the request-time gate in
  ``api/deps.py::enforce_mfa_enrollment`` restricts the session to the
  MFA-enrollment endpoints and answers everything else with 403
  ``mfa_enrollment_required``.

Bearer (API-key) callers are deliberately NOT evaluated. API keys are
a separate credential class with explicit scopes and no second-factor
ceremony; docs/MFA-DESIGN.md (open question 5) records the decision
that programmatic accounts are exempt. Blocked users still cannot
mint NEW keys: the API-key endpoints are session-gated and therefore
behind this gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from z4j_brain.auth.sessions import aware_utc

if TYPE_CHECKING:
    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings


def is_mfa_enrolled(user: User) -> bool:
    """Canonical "MFA is enabled" predicate.

    Same expression the login gate and every ``auth_mfa`` handler use:
    a stored secret alone (``mfa_enrolled_at IS NULL``) is a PENDING
    enrollment, not an enrolled user.
    """
    return user.mfa_secret_encrypted is not None and user.mfa_enrolled_at is not None


def mfa_enforcement_applies(*, user: User, settings: Settings) -> bool:
    """True when the enrollment-enforcement policy targets ``user``.

    ``mfa_enforce_for_all`` targets everyone; ``mfa_enforce_for_admins``
    targets the global ``is_admin`` bit only (module docstring has the
    project-role rationale). Enrollment state is NOT considered here --
    the policy targets the account; whether it has anything left to
    demand is :func:`evaluate_mfa_enforcement`'s job.
    """
    if settings.mfa_enforce_for_all:
        return True
    return bool(settings.mfa_enforce_for_admins and user.is_admin)


@dataclass(frozen=True, slots=True)
class MfaEnforcementStatus:
    """Outcome of evaluating the policy against one user.

    Attributes:
        required: The policy targets this user and they have not
            enrolled yet. The dashboard should surface the enrollment
            banner (or route to the enrollment page when ``blocked``).
        deadline: End of the grace window
            (``mfa_enforcement_started_at + grace_days``). ``None``
            when not ``required`` OR when the anchor has not been
            stamped yet (the user has not logged in under the policy).
        blocked: ``required`` and the deadline has passed. The
            request-time gate restricts blocked sessions to the
            MFA-enrollment endpoints.
    """

    required: bool
    deadline: datetime | None
    blocked: bool


#: Shared "nothing to enforce" result -- unenforced users, enrolled
#: users, and every install with the flags at their defaults.
MFA_ENFORCEMENT_NOT_REQUIRED = MfaEnforcementStatus(
    required=False,
    deadline=None,
    blocked=False,
)


def evaluate_mfa_enforcement(
    *,
    user: User,
    settings: Settings,
    now: datetime | None = None,
) -> MfaEnforcementStatus:
    """Evaluate the enrollment-enforcement policy for ``user``.

    Pure and cheap (no queries) so it is safe to run on every
    authenticated request. ``now`` is injectable for tests; production
    callers omit it.
    """
    if is_mfa_enrolled(user) or not mfa_enforcement_applies(user=user, settings=settings):
        return MFA_ENFORCEMENT_NOT_REQUIRED

    started_at = user.mfa_enforcement_started_at
    if started_at is None:
        # Policy applies but the grace clock has not started: the user
        # has not logged in since the policy came on. Login stamps the
        # anchor; until then there is no deadline to have missed.
        return MfaEnforcementStatus(required=True, deadline=None, blocked=False)

    deadline = aware_utc(started_at) + timedelta(
        days=settings.mfa_enrollment_grace_days,
    )
    current = now if now is not None else datetime.now(UTC)
    return MfaEnforcementStatus(
        required=True,
        deadline=deadline,
        blocked=aware_utc(current) >= deadline,
    )


__all__ = [
    "MFA_ENFORCEMENT_NOT_REQUIRED",
    "MfaEnforcementStatus",
    "evaluate_mfa_enforcement",
    "is_mfa_enrolled",
    "mfa_enforcement_applies",
]
