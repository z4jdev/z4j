"""HKDF-derived AES-GCM encryption for TOTP secrets at rest.

The TOTP shared secret cannot be stored as a hash (unlike a password):
the brain needs the secret in plaintext to derive the rolling 6-digit
code on every verify. We encrypt it with AES-GCM using a 256-bit key
derived from ``Z4J_SECRET`` via HKDF-SHA256. The DB column carries
``nonce || ciphertext_with_auth_tag`` in a single ``BYTEA``.

Threat model: a brain operator with DB access but WITHOUT
``Z4J_SECRET`` cannot decrypt the TOTP secrets. This raises the bar
to "operator has both Z4J_SECRET (env / file) and DB rows" -- the
same trust boundary the audit chain already assumes.

Key rotation: when ``Z4J_SECRET`` is rotated, the operator lists the
old value in ``Z4J_PREVIOUS_SECRETS``. Decryption tries the current
key first; on failure (any of ``InvalidTag``, ``InvalidKey``) it
falls back to each previous-key derivation in order. On successful
decryption with a previous key the caller is expected to re-encrypt
with the current key. See ``docs/MFA-DESIGN.md`` for the rotation
playbook.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: AES-GCM nonce length (NIST SP 800-38D recommends 96-bit / 12-byte).
NONCE_BYTES = 12

#: HKDF salt. A fixed app-wide salt is fine here because the input
#: keying material (``Z4J_SECRET``) is itself high-entropy.
_HKDF_SALT = b"z4j-mfa-totp-salt-v1"

#: HKDF info string. Domain-separates the MFA key from any other
#: HKDF-derived key the brain might mint in the future.
_HKDF_INFO = b"z4j-mfa-totp-secret"

#: AES-256.
_KEY_LEN = 32


class DecryptionFailed(RuntimeError):
    """Raised when no candidate key can decrypt the ciphertext.

    A correctly-authenticated AES-GCM payload returns the plaintext;
    a wrong key produces ``InvalidTag``. This exception is raised
    after every candidate (current + each previous secret) has been
    tried without success. The caller should treat it as "this user's
    MFA is unrecoverable from the current key set" -- usually a sign
    that ``Z4J_SECRET`` was rotated without listing the old value in
    ``Z4J_PREVIOUS_SECRETS``.
    """


def _derive_key(master: bytes) -> bytes:
    """Derive a 32-byte AES key from a master secret via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(master)


def _aad_for_user(user_id: object) -> bytes:
    """Build the AES-GCM associated-data bytes that bind a ciphertext
    to a specific user row.
    The AAD is included in the AEAD tag but not in the ciphertext, so
    an operator who steals a row and pastes it onto a different user
    will get InvalidTag at decrypt time -- the "encrypted-secret swap"
    attack the audit caught. (1.6.0 audit Medium-1.)
    """
    return f"z4j-mfa-totp:user={user_id!s}".encode("utf-8")


def encrypt_totp_secret(
    plaintext: bytes,
    *,
    master_secret: bytes,
    user_id: object,
) -> bytes:
    """Encrypt a raw TOTP secret for storage, bound to ``user_id``.

    Args:
        plaintext: Raw TOTP secret (typically 20 bytes from
            :func:`secrets.token_bytes`).
        master_secret: Bytes of ``Z4J_SECRET``. The caller passes
            ``settings.secret.get_secret_value().encode("utf-8")``.
        user_id: The ``users.id`` row this secret belongs to. Folded
            into the AES-GCM AAD so a ciphertext minted for user A
            cannot be reused on user B's row.

    Returns:
        ``nonce || ciphertext_with_tag`` as a single ``bytes`` value
        suitable for storage in ``users.mfa_secret_encrypted``.
    """
    if not master_secret:
        raise ValueError("master_secret is empty")
    key = _derive_key(master_secret)
    nonce = os.urandom(NONCE_BYTES)
    aad = _aad_for_user(user_id)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=aad)
    return nonce + ciphertext


def decrypt_totp_secret(
    blob: bytes,
    *,
    master_secret: bytes,
    user_id: object,
    previous_secrets: Iterable[bytes] = (),
) -> tuple[bytes, bool]:
    """Decrypt a stored TOTP secret bound to ``user_id``.

    Args:
        blob: ``users.mfa_secret_encrypted`` value
            (``nonce || ciphertext_with_tag``).
        master_secret: Bytes of the current ``Z4J_SECRET``.
        user_id: ``users.id`` of the row the blob lives on; folded
            into AES-GCM AAD. A mismatch (someone swapped rows) yields
            DecryptionFailed.
        previous_secrets: Iterable of bytes for every value in
            ``Z4J_PREVIOUS_SECRETS``. The caller normalises these from
            ``Settings.all_secrets_for_verification()``.

    Returns:
        A tuple ``(plaintext, needs_rewrite)``. ``needs_rewrite`` is
        True iff decryption succeeded with a previous-secret rather
        than the current one; the caller should re-encrypt the stored
        ciphertext with the current key before returning.

    Raises:
        DecryptionFailed: if no candidate key produced a valid
            authentication tag.
    """
    if len(blob) <= NONCE_BYTES:
        raise DecryptionFailed("blob too short to contain nonce + ciphertext")
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    aad = _aad_for_user(user_id)

    # Try the current key first.
    try:
        key = _derive_key(master_secret)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=aad)
        return plaintext, False
    except InvalidTag:
        pass

    # Fall back to each previous key in turn.
    for prev in previous_secrets:
        if not prev:
            continue
        try:
            key = _derive_key(prev)
            plaintext = AESGCM(key).decrypt(
                nonce, ciphertext, associated_data=aad,
            )
            return plaintext, True
        except InvalidTag:
            continue

    raise DecryptionFailed(
        "TOTP secret could not be decrypted with the current "
        "Z4J_SECRET or any value listed in Z4J_PREVIOUS_SECRETS",
    )


__all__ = [
    "DecryptionFailed",
    "NONCE_BYTES",
    "decrypt_totp_secret",
    "encrypt_totp_secret",
]
