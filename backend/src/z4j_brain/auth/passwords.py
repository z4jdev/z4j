"""argon2id password hashing.

Wraps :class:`argon2.PasswordHasher` with the brain's tunable
parameters from :class:`Settings`. Public surface:

- :meth:`PasswordHasher.hash` - argon2id hash a plaintext password.
- :meth:`PasswordHasher.verify` - argon2id verify, returns ``bool``,
  never raises.
- :meth:`PasswordHasher.needs_rehash` - true only when rehashing is a
  monotonic upgrade from the stored Argon2 parameters to the current
  configuration. Lower or incomparable operator settings never silently
  downgrade a stronger dimension.
- :attr:`PasswordHasher.dummy_hash` - a real argon2 hash of a random
  string, generated once at construction. Used by
  :class:`AuthService` for the absent-user branch of login so the
  two paths take comparable wall-clock time.

Why argon2id (not bcrypt, scrypt, PBKDF2):

- Memory-hard - raises the cost of GPU/ASIC parallelism.
- OWASP 2024 recommendation, NIST 800-63B accepted.
- Active maintenance, audited C bindings via ``argon2-cffi``.

Defaults: ``time_cost=3, memory_cost=64MiB, parallelism=4``. Operators
can tune them via ``Z4J_ARGON2_*`` after benchmarking their own host.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from argon2 import Parameters, extract_parameters
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
    domain services. Construction performs one real Argon2 hash for
    :attr:`dummy_hash`, so callers should reuse the instance.

    Attributes:
        dummy_hash: A real argon2id hash of a random 32-byte string,
            computed once at construction. The auth service verifies
            wrong-username login attempts against this hash so the
            unknown-account attempts perform comparable Argon2 work.
    """

    __slots__ = ("_hasher", "_min_length", "_parameters", "dummy_hash")

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
        # Derive the exact effective PHC parameters from a hash this
        # configured hasher just produced. This stays aligned with argon2-cffi
        # defaults (algorithm type/version included) without reaching into
        # private hasher attributes.
        self._parameters: Parameters = extract_parameters(self.dummy_hash)

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def validate_policy(self, plaintext: str) -> None:
        """Enforce the brain's password policy.

        Rules:
        1. Minimum length from ``settings.password_min_length`` (≥8).
        2. Passwords shorter than 16 characters use at least three of
           lowercase, uppercase, digits and non-whitespace symbols.
        3. Maximum length 256.
        4. Not in the common-password denylist.

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
        #
        # Length escape hatch: passwords of 16+ chars get the
        # breach-list check only. NIST SP 800-63B deprecates strict
        # composition rules in favour of length + breach detection,
        # and a long passphrase ("correct horse battery staple 9")
        # is high-entropy even with only two classes. Round-2 audit
        # Medium-1 caught a 12-char hole where space-as-symbol let
        # low-entropy strings like "Aa 1 . . ." satisfy 3-of-4;
        # excluding whitespace from "symbol" closes that hole for
        # short passwords without rejecting passphrases.
        if len(plaintext) < 16:
            has_lower = any(c.islower() for c in plaintext)
            has_upper = any(c.isupper() for c in plaintext)
            has_digit = any(c.isdigit() for c in plaintext)
            has_symbol = any(not c.isalnum() and not c.isspace() for c in plaintext)
            classes = sum([has_lower, has_upper, has_digit, has_symbol])
            if classes < 3:
                raise PasswordError(
                    "password_too_simple",
                    "password must contain at least 3 of: lowercase, "
                    "uppercase, digits, symbols (or use a 16+ "
                    "character passphrase)",
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
        """Verify ``plaintext`` against an Argon2 ``stored_hash``.

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
        """True only when current parameters monotonically upgrade the hash.

        Called after a successful verify. A rehash is requested when every
        comparable current parameter is at least as strong as the stored one
        and at least one parameter, the Argon2 version, or the algorithm type
        changes. If any stored dimension is stronger than the current
        configuration, the profiles are stronger or incomparable and this
        returns False: an operator lowering one setting must never silently
        downgrade hashes on login. Deliberate migrations from a non-Argon2id
        type are allowed only when no numeric dimension or version decreases.

        The compared PHC parameters are ``time_cost``, ``memory_cost``,
        ``parallelism``, ``hash_len``, ``salt_len``, algorithm type, and
        version. Malformed hashes return True for compatibility, although the
        auth service calls this only after successful verification.
        """
        try:
            stored = extract_parameters(stored_hash)
        except InvalidHashError:
            # Treat malformed hash as "needs rehash" so the next
            # successful login replaces it. Belt-and-braces.
            return True

        current = self._parameters
        # A future/newer PHC version must not be rewritten by an older
        # implementation. Likewise, never lower any independently encoded
        # work/output dimension even if another configured dimension rose.
        if stored.version > current.version:
            return False
        dimensions = (
            "time_cost",
            "memory_cost",
            "parallelism",
            "hash_len",
            "salt_len",
        )
        if any(getattr(current, name) < getattr(stored, name) for name in dimensions):
            return False

        return (
            stored.type != current.type
            or stored.version < current.version
            or any(getattr(current, name) > getattr(stored, name) for name in dimensions)
        )


__all__ = ["PasswordError", "PasswordHasher"]
