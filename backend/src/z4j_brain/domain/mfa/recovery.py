"""Recovery-code minting, hashing, and single-use verification.

Each user is issued N recovery codes at enrollment time (default 10,
controlled by ``Z4J_MFA_RECOVERY_CODE_COUNT``). The plaintext codes
are returned ONCE to the user, who is expected to download them.

Format: ``XXXX-XXXX-XXXX`` where each X is drawn from a 31-character
non-confusable alphabet (A-Z minus I, L, O plus 2-9). 12 characters
of ``log2(31) * 12 ~= 59.4`` bits of entropy, which is the strongest
we can reach without re-introducing a 0/O/1/I/L lookalike. The
hyphens are visual only; verification strips them. (1.6.0 audit M2:
the doc previously claimed 60 bits / 32-char base32; corrected to
match the actual alphabet.)

Hashing reuses the brain's argon2id password hasher so MFA recovery
codes get the same per-hash cost as passwords (resistant to offline
attack if the DB leaks). The plaintext never lives in the DB.
"""

from __future__ import annotations

import re
import secrets
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

#: Characters used to compose recovery codes. Crockford-ish: drops
#: 0/O/1/I/L to keep printed codes legible on paper.
_ALPHABET: Final[str] = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

#: Number of characters per group.
_GROUP_LEN: Final[int] = 4

#: Number of groups separated by hyphens.
_GROUP_COUNT: Final[int] = 3

#: Regex that matches a normalised (hyphenated-uppercase) recovery
#: code. Exposed so the API endpoint can pre-validate the format
#: cheaply before hitting the DB.
RECOVERY_CODE_PATTERN: Final[str] = (
    f"^[{_ALPHABET}]{{{_GROUP_LEN}}}-"
    f"[{_ALPHABET}]{{{_GROUP_LEN}}}-"
    f"[{_ALPHABET}]{{{_GROUP_LEN}}}$"
)
_RECOVERY_CODE_RX = re.compile(RECOVERY_CODE_PATTERN)

#: Internal: argon2id hasher tuned to the same parameters as
#: ``Z4J_ARGON2_*`` (the lazy module-level instance is fine; argon2
#: hashes embed every parameter in their string form so a later
#: parameter change does not invalidate existing hashes).
_HASHER = PasswordHasher()


def _generate_one() -> str:
    """Return a single freshly-minted recovery code."""
    groups = []
    for _ in range(_GROUP_COUNT):
        groups.append(
            "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN)),
        )
    return "-".join(groups)


def normalize_recovery_code(raw: str) -> str:
    """Trim whitespace, drop hyphens, uppercase. Used before hashing
    and before regex validation.

    Accepts user input like ``a1b2-c3d4-e5f6`` and produces the
    canonical hyphenated-uppercase form.
    """
    stripped = "".join(raw.split())
    stripped = stripped.replace("-", "").upper()
    if len(stripped) != _GROUP_LEN * _GROUP_COUNT:
        return stripped  # let the regex reject it
    return "-".join(
        stripped[i : i + _GROUP_LEN]
        for i in range(0, len(stripped), _GROUP_LEN)
    )


def generate_recovery_codes(count: int) -> list[str]:
    """Return ``count`` freshly-minted recovery codes."""
    if count < 1:
        raise ValueError("count must be at least 1")
    return [_generate_one() for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    """argon2id-hash a normalised recovery code for storage."""
    return _HASHER.hash(code)


def verify_recovery_code(*, plaintext: str, hashed: str) -> bool:
    """Constant-time-ish verify of a recovery code against its hash.

    Returns True on match, False on mismatch. Any other argon2 error
    (bad hash format, etc.) is logged by the caller and treated as
    False -- the user sees the same "invalid code" response either
    way.
    """
    try:
        _HASHER.verify(hashed, plaintext)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


#: Pre-baked argon2id hash of a value no real recovery code can equal.
#: Used by the API verify path to burn one constant argon2 cycle when
#: a user has zero unused codes, so the response time matches the
#: "user has codes" path. Without this, an attacker observing timing
#: can distinguish "MFA-enrolled, all codes consumed" from "MFA-
#: enrolled, codes still available". (1.6.0 round-2 audit High-2.)
_DUMMY_HASH: Final[str] = _HASHER.hash("z4j-mfa-dummy-recovery-code")


def burn_one_argon2_cycle() -> None:
    """Run one argon2 verify against a sentinel hash and discard.
    Caller uses this on the empty-list branch of the recovery-code
    scan so the wall-clock cost of an "no codes left" verify matches
    a "codes present" verify. Cost is one argon2 cycle (~100 ms with
    default parameters); throws nothing.
    """
    try:
        _HASHER.verify(_DUMMY_HASH, "z4j-mfa-no-match-sentinel")
    except (VerifyMismatchError, InvalidHash):
        return


__all__ = [
    "RECOVERY_CODE_PATTERN",
    "burn_one_argon2_cycle",
    "generate_recovery_codes",
    "hash_recovery_code",
    "normalize_recovery_code",
    "verify_recovery_code",
]
