"""TOTP MFA domain logic.

Four submodules:

- :mod:`z4j_brain.domain.mfa.crypto` -- HKDF key derivation from
  ``Z4J_SECRET`` + AES-GCM encrypt / decrypt for TOTP secrets at rest.
  Supports key rotation via ``Z4J_PREVIOUS_SECRETS``.
- :mod:`z4j_brain.domain.mfa.totp` -- TOTP secret generation,
  ``otpauth://`` provisioning URL builder, RFC 6238 code verification
  with single-step skew tolerance.
- :mod:`z4j_brain.domain.mfa.recovery` -- recovery-code minting,
  argon2id hashing, single-use verification.
- :mod:`z4j_brain.domain.mfa.enforcement` -- pure evaluation of the
  opt-in enrollment-enforcement policy
  (``Z4J_MFA_ENFORCE_FOR_ADMINS`` / ``Z4J_MFA_ENFORCE_FOR_ALL`` +
  the per-user grace anchor).

The API router (``api/auth_mfa.py``, phase 3+) drives all of them.
See ``docs/MFA-DESIGN.md`` for the threat model and lifecycle.
"""

from __future__ import annotations

from z4j_brain.domain.mfa.crypto import (
    decrypt_totp_secret,
    encrypt_totp_secret,
)
from z4j_brain.domain.mfa.enforcement import (
    MfaEnforcementStatus,
    evaluate_mfa_enforcement,
    is_mfa_enrolled,
    mfa_enforcement_applies,
)
from z4j_brain.domain.mfa.recovery import (
    RECOVERY_CODE_PATTERN,
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
)
from z4j_brain.domain.mfa.totp import (
    TOTP_STEP_SECONDS,
    generate_totp_secret,
    provisioning_url,
    verify_totp_code,
)

__all__ = [
    "RECOVERY_CODE_PATTERN",
    "TOTP_STEP_SECONDS",
    "MfaEnforcementStatus",
    "decrypt_totp_secret",
    "encrypt_totp_secret",
    "evaluate_mfa_enforcement",
    "generate_recovery_codes",
    "generate_totp_secret",
    "hash_recovery_code",
    "is_mfa_enrolled",
    "mfa_enforcement_applies",
    "provisioning_url",
    "verify_recovery_code",
    "verify_totp_code",
]
