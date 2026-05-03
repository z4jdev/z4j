"""argon2id password hashing.

Wraps :class:`argon2.PasswordHasher` with the brain's tunable
parameters from :class:`Settings`. Public surface:

- :meth:`PasswordHasher.hash` - argon2id hash a plaintext password.
- :meth:`PasswordHasher.verify` - constant-time verify, returns
  ``bool``, never raises.
- :meth:`PasswordHasher.needs_rehash` - true when the stored hash
  used weaker parameters than the current configuration. The auth
  service uses this to lazily upgrade hashes on next login.
- :attr:`PasswordHasher.dummy_hash` - a real argon2 hash of a random
  string, generated once at construction. Used by
  :class:`AuthService` for the absent-user branch of login so the
  two paths take comparable wall-clock time.

Why argon2id (not bcrypt, scrypt, PBKDF2):

- Memory-hard - defeats GPU/ASIC parallelism the way bcrypt cannot.
- Constant-time verify (compare_digest internally).
- OWASP 2024 recommendation, NIST 800-63B accepted.
- Active maintenance, audited C bindings via ``argon2-cffi``.

Defaults: ``time_cost=3, memory_cost=64MiB, parallelism=4``. These
are the OWASP 2024 minimums for argon2id. Operators tune via
``Z4J_ARGON2_*`` env vars; defaults give roughly 50-80ms on a 2024
server CPU.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

from z4j_brain.auth.common_passwords import is_common_password

if TYPE_CHECKING:
    from z4j_brain.settings import Settings


class PasswordError(ValueError):
    """A password failed policy validation.

    Carries a stable ``code`` that the API layer translates into a
    user-visible error key. The message itself is operator-friendly
    English; the dashboard renders the code, not the message.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PasswordHasher:
    """Stateful argon2id hasher bound to brain settings.

    One instance per process - pass it around explicitly via the
    domain services. Construction is cheap (microseconds); the
    expensive bit is :meth:`hash` and :meth:`verify` themselves.

    Attributes:
        dummy_hash: A real argon2id hash of a random 32-byte string,
            computed once at construction. The auth service verifies
            wrong-username login attempts against this hash so the
            timing is indistinguishable from a real account.
    """

    __slots__ = ("_hasher", "_min_length", "dummy_hash")

    def __init__(self, settings: Settings) -> None:
        self._hasher = _Argon2Hasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
        )
        self._min_length = settings.password_min_length
        # Generate a real argon2 hash of a random secret. Same
        # parameters as production, so verify takes the same wall
        # time. Re-generated on every process boot - there is no
        # value in persisting it.
        self.dummy_hash: str = self._hasher.hash(
            secrets.token_urlsafe(32),
        )

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def validate_policy(self, plaintext: str) -> None:
        """Enforce the brain's password policy.

        Rules:
        1. Minimum length from ``settings.password_min_length`` (≥8).
        2. At least one letter and one digit.
        3. Not in the common-password denylist.

        Raises:
            PasswordError: If any rule fails. The ``code`` field is
                stable; the human message is operator-friendly.
        """
        if len(plaintext) < self._min_length:
            raise PasswordError(
                "password_too_short",
                f"password must be at least {self._min_length} characters",
            )
        # Hard cap to prevent extreme inputs from blowing argon2's
        # memory budget. argon2id itself accepts up to 4 GiB but
        # we have no use for >256-char passwords.
        if len(plaintext) > 256:
            raise PasswordError(
                "password_too_long",
                "password must be at most 256 characters",
            )
        # Audit A3: require at least 3 of 4 character classes
        # (upper / lower / digit / symbol). Previously "letter+digit"
        # accepted ``Summer24`` or ``qwertyui1`` - both in the top
        # 1k of breach lists. Three-class minimum knocks out the
        # long tail of dictionary-plus-one-digit passwords.
        has_lower = any(c.islower() for c in plaintext)
        has_upper = any(c.isupper() for c in plaintext)
        has_digit = any(c.isdigit() for c in plaintext)
        has_symbol = any(not c.isalnum() for c in plaintext)
        classes = sum([has_lower, has_upper, has_digit, has_symbol])
        if classes < 3:
            raise PasswordError(
                "password_too_simple",
                "password must contain at least 3 of: lowercase, "
                "uppercase, digits, symbols",
            )
        if is_common_password(plaintext):
            raise PasswordError(
                "password_in_breach_list",
                "password is too common; choose another one",
            )

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def hash(self, plaintext: str) -> str:
        """Argon2id-hash a plaintext password.

        Does NOT validate policy - call :meth:`validate_policy`
        first if the password came from a user. The auth service
        does both in the right order.

        Returns:
            The PHC-string-encoded argon2id hash, ready for storage
            in ``users.password_hash``.
        """
        return self._hasher.hash(plaintext)

    def verify(self, stored_hash: str, plaintext: str) -> bool:
        """Constant-time verify ``plaintext`` against ``stored_hash``.

        Never raises. Returns False on every failure mode (mismatch,
        malformed hash, wrong algorithm). The auth service treats
        every False the same way - there is no value in distinguishing
        "wrong password" from "corrupt hash" at the application layer.
        """
        try:
            return self._hasher.verify(stored_hash, plaintext)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """True if ``stored_hash`` was produced with weaker parameters.

        Called after a successful verify. When True, the auth
        service rehashes the password with current parameters and
        updates ``users.password_hash`` - silent upgrade for users
        who logged in before a parameter bump.
        """
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            # Treat malformed hash as "needs rehash" so the next
            # successful login replaces it. Belt-and-braces.
            return True


__all__ = ["PasswordError", "PasswordHasher"]
