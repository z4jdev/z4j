"""Behavioral suite for the MFA primitives shipped in 1.6.0.

Covers the three pure-domain modules the route layer builds on:

- ``domain/mfa/totp.py``: RFC 6238 correctness (pinned against the
  RFC's Appendix B SHA-1 test vectors, truncated to the module's
  6-digit output), the exact +-1-step clock-skew acceptance window,
  and rejection of malformed / wrong-secret codes;
- ``domain/mfa/crypto.py``: AES-GCM round-trip, fail-closed behavior
  (wrong key, tampered blob, truncated blob, AAD user-binding), nonce
  uniqueness, and the ``Z4J_PREVIOUS_SECRETS`` rotation contract
  (``needs_rewrite`` flag, fallback ordering, empty-entry skipping);
- ``domain/mfa/recovery.py``: code shape / alphabet / entropy sanity,
  normalisation, argon2id hash-verify round trip, and the documented
  false-not-raise verify contract.

Deliberately NOT asserted here:

- TOTP replay tracking: ``verify_totp_code`` is stateless by design
  (no last-used-counter store exists at any layer), so there is
  nothing to assert; the gap is tracked outside this suite.
- Constant-TIME claims: timing assertions are flaky in CI. The
  constant-WORK shape of the API-layer recovery scan (hash every
  candidate, burn a dummy cycle when the set is empty) is asserted
  behaviorally in ``test_mfa_routes_behavioral.py``.
- Single-use recovery semantics: consumption lives in the repository
  (``consumed_at`` flip), not in this module; covered at the route
  level in ``test_mfa_routes_behavioral.py``.
"""

from __future__ import annotations

import base64
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from z4j_brain.domain.mfa.crypto import (
    NONCE_BYTES,
    DecryptionFailed,
    decrypt_totp_secret,
    encrypt_totp_secret,
)
from z4j_brain.domain.mfa.recovery import (
    RECOVERY_CODE_PATTERN,
    burn_one_argon2_cycle,
    generate_recovery_codes,
    hash_recovery_code,
    normalize_recovery_code,
    verify_recovery_code,
)
from z4j_brain.domain.mfa.totp import (
    SECRET_BYTES,
    TOTP_DIGITS,
    TOTP_STEP_SECONDS,
    current_totp_code,
    generate_totp_secret,
    provisioning_url,
    secret_to_base32,
    verify_totp_code,
)

# ---------------------------------------------------------------------------
# TOTP: fixtures + RFC vectors
# ---------------------------------------------------------------------------

#: RFC 4226 / RFC 6238 Appendix B shared test secret (ASCII
#: "12345678901234567890", exactly 20 bytes -- the module's own
#: SECRET_BYTES).
RFC_SECRET = b"12345678901234567890"

#: RFC 6238 Appendix B SHA-1 vectors. The RFC publishes 8-digit
#: values; a 6-digit TOTP is the same dynamic truncation mod 10^6,
#: i.e. the last six digits of the 8-digit value.
RFC_6238_SHA1_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

#: A counter-aligned fixed timestamp for window tests (multiple of
#: the 30s step, far from any epoch edge).
T0 = TOTP_STEP_SECONDS * 1_000_000


class TestTotpParameters:
    """The advertised universal-compatibility parameters."""

    def test_documented_parameters(self) -> None:
        assert TOTP_STEP_SECONDS == 30
        assert TOTP_DIGITS == 6
        assert SECRET_BYTES == 20


class TestTotpSecretGeneration:
    def test_secret_is_twenty_bytes(self) -> None:
        secret = generate_totp_secret()
        assert isinstance(secret, bytes)
        assert len(secret) == SECRET_BYTES

    def test_secrets_do_not_repeat(self) -> None:
        secrets_batch = {generate_totp_secret() for _ in range(64)}
        assert len(secrets_batch) == 64

    def test_base32_form_round_trips_without_padding(self) -> None:
        secret = generate_totp_secret()
        b32 = secret_to_base32(secret)
        assert "=" not in b32
        # RFC 4648 base32 alphabet only.
        assert re.fullmatch(r"[A-Z2-7]+", b32)
        repadded = b32 + "=" * (-len(b32) % 8)
        assert base64.b32decode(repadded) == secret


class TestProvisioningUrl:
    ISSUER = "z4j (brain.example.com)"
    ACCOUNT = "user@example.com"

    def _url(self, secret: bytes) -> str:
        return provisioning_url(
            secret=secret,
            account_label=self.ACCOUNT,
            issuer=self.ISSUER,
        )

    def test_scheme_and_type(self) -> None:
        url = self._url(RFC_SECRET)
        parts = urlsplit(url)
        assert parts.scheme == "otpauth"
        assert parts.netloc == "totp"

    def test_label_carries_issuer_and_account(self) -> None:
        url = self._url(RFC_SECRET)
        label = unquote(urlsplit(url).path.lstrip("/"))
        assert label == f"{self.ISSUER}:{self.ACCOUNT}"

    def test_query_params_pin_the_advertised_algorithm(self) -> None:
        url = self._url(RFC_SECRET)
        params = parse_qs(urlsplit(url).query)
        assert params["secret"] == [secret_to_base32(RFC_SECRET)]
        assert params["issuer"] == [self.ISSUER]
        assert params["algorithm"] == ["SHA1"]
        assert params["digits"] == ["6"]
        assert params["period"] == ["30"]

    def test_secret_in_url_is_the_actual_secret(self) -> None:
        """An authenticator app scanning the URL must derive the same
        codes the brain verifies."""
        secret = generate_totp_secret()
        params = parse_qs(urlsplit(self._url(secret)).query)
        b32 = params["secret"][0]
        decoded = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        assert decoded == secret
        assert verify_totp_code(secret, current_totp_code(decoded, at_time=T0), at_time=T0)


class TestRfc6238Vectors:
    """The implementation is standard SHA-1 / 30s / 6-digit TOTP, so
    it must reproduce the RFC 6238 Appendix B vectors exactly."""

    @pytest.mark.parametrize(("at_time", "eight_digit"), RFC_6238_SHA1_VECTORS)
    def test_generation_matches_rfc(self, at_time: int, eight_digit: str) -> None:
        assert current_totp_code(RFC_SECRET, at_time=at_time) == eight_digit[-6:]

    @pytest.mark.parametrize(("at_time", "eight_digit"), RFC_6238_SHA1_VECTORS)
    def test_verification_accepts_rfc_vector(self, at_time: int, eight_digit: str) -> None:
        assert verify_totp_code(RFC_SECRET, eight_digit[-6:], at_time=at_time)

    def test_leading_zeros_are_significant(self) -> None:
        """T=1234567890 yields "005924": the zero-padded form verifies,
        the int-collapsed forms do not (a client that drops leading
        zeros must be rejected, not silently accepted)."""
        assert current_totp_code(RFC_SECRET, at_time=1234567890) == "005924"
        assert verify_totp_code(RFC_SECRET, "005924", at_time=1234567890)
        assert not verify_totp_code(RFC_SECRET, "5924", at_time=1234567890)
        assert not verify_totp_code(RFC_SECRET, "05924", at_time=1234567890)


class TestTotpSkewWindow:
    """The documented acceptance window is exactly one 30s step on
    either side of the current counter: a code minted for counter C
    verifies while the clock reads counter C-1, C, or C+1, and at no
    other time."""

    def _code(self) -> str:
        return current_totp_code(RFC_SECRET, at_time=T0)

    def test_current_window_accepted(self) -> None:
        assert verify_totp_code(RFC_SECRET, self._code(), at_time=T0)

    def test_code_from_previous_step_accepted(self) -> None:
        """User typed the code just before the step rolled over."""
        stale = current_totp_code(RFC_SECRET, at_time=T0 - TOTP_STEP_SECONDS)
        assert verify_totp_code(RFC_SECRET, stale, at_time=T0)

    def test_code_from_next_step_accepted(self) -> None:
        """Client clock runs up to one step ahead of the brain."""
        ahead = current_totp_code(RFC_SECRET, at_time=T0 + TOTP_STEP_SECONDS)
        assert verify_totp_code(RFC_SECRET, ahead, at_time=T0)

    def test_acceptance_window_edges(self) -> None:
        """A code minted for counter C (at T0) verifies while the
        verifier's clock reads base counter C-1, C, or C+1: from
        T0-30 up to (but not including) T0+60."""
        code = self._code()
        assert verify_totp_code(RFC_SECRET, code, at_time=T0 - TOTP_STEP_SECONDS)
        assert not verify_totp_code(RFC_SECRET, code, at_time=T0 - TOTP_STEP_SECONDS - 1)
        assert verify_totp_code(RFC_SECRET, code, at_time=T0 + 2 * TOTP_STEP_SECONDS - 1)
        assert not verify_totp_code(RFC_SECRET, code, at_time=T0 + 2 * TOTP_STEP_SECONDS)

    def test_two_steps_out_rejected_both_directions(self) -> None:
        code = self._code()
        assert not verify_totp_code(
            RFC_SECRET,
            code,
            at_time=T0 - 2 * TOTP_STEP_SECONDS,
        )
        assert not verify_totp_code(
            RFC_SECRET,
            code,
            at_time=T0 + 2 * TOTP_STEP_SECONDS,
        )


class TestTotpRejection:
    @pytest.mark.parametrize(
        "bad_code",
        [
            "",
            "12345",  # too short
            "1234567",  # too long
            "abcdef",  # letters
            "12345a",  # trailing letter
            "123 456",  # interior whitespace survives strip -> len 7
            "12-345",  # punctuation
            "......",
        ],
    )
    def test_malformed_codes_rejected(self, bad_code: str) -> None:
        assert not verify_totp_code(RFC_SECRET, bad_code, at_time=T0)

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        """The verifier strips leading/trailing whitespace (copy-paste
        from an authenticator app commonly carries it)."""
        code = current_totp_code(RFC_SECRET, at_time=T0)
        assert verify_totp_code(RFC_SECRET, f"  {code}\n", at_time=T0)

    def test_code_for_another_secret_rejected(self) -> None:
        other = b"AAAAAAAAAAAAAAAAAAAA"
        code_for_other = current_totp_code(other, at_time=T0)
        assert not verify_totp_code(RFC_SECRET, code_for_other, at_time=T0)

    def test_wrong_six_digit_code_rejected(self) -> None:
        valid = {
            current_totp_code(RFC_SECRET, at_time=T0 + delta * TOTP_STEP_SECONDS)
            for delta in (-1, 0, 1)
        }
        wrong = next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)
        assert not verify_totp_code(RFC_SECRET, wrong, at_time=T0)


# ---------------------------------------------------------------------------
# crypto.py: AES-GCM secret-at-rest wrapping
# ---------------------------------------------------------------------------

MASTER = b"unit-test-master-secret-0123456789abcdef"
OTHER_MASTER = b"a-completely-different-master-secret-xyz"
USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
OTHER_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")
PLAINTEXT = b"12345678901234567890"


class TestCryptoRoundTrip:
    def test_encrypt_decrypt_round_trip(self) -> None:
        blob = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        plaintext, needs_rewrite = decrypt_totp_secret(
            blob,
            master_secret=MASTER,
            user_id=USER_ID,
        )
        assert plaintext == PLAINTEXT
        assert needs_rewrite is False

    def test_blob_layout_is_nonce_plus_ciphertext_and_tag(self) -> None:
        """nonce (12) || ciphertext (len(pt)) || GCM tag (16)."""
        blob = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        assert len(blob) == NONCE_BYTES + len(PLAINTEXT) + 16

    def test_identical_plaintexts_produce_distinct_ciphertexts(self) -> None:
        """Fresh random nonce per encryption: equal secrets stored for
        two calls must not be linkable via equal ciphertexts."""
        blob_a = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        blob_b = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        assert blob_a != blob_b
        assert blob_a[:NONCE_BYTES] != blob_b[:NONCE_BYTES]
        for blob in (blob_a, blob_b):
            plaintext, _ = decrypt_totp_secret(
                blob,
                master_secret=MASTER,
                user_id=USER_ID,
            )
            assert plaintext == PLAINTEXT

    def test_nonce_uniqueness_over_many_encryptions(self) -> None:
        nonces = {
            encrypt_totp_secret(
                PLAINTEXT,
                master_secret=MASTER,
                user_id=USER_ID,
            )[:NONCE_BYTES]
            for _ in range(64)
        }
        assert len(nonces) == 64

    def test_aad_uses_the_string_form_of_user_id(self) -> None:
        """The AAD canonicalises user_id via str(); a UUID and its
        string form are the same binding (the routes always pass the
        UUID, but the contract is the string form)."""
        blob = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        plaintext, _ = decrypt_totp_secret(
            blob,
            master_secret=MASTER,
            user_id=str(USER_ID),
        )
        assert plaintext == PLAINTEXT


class TestCryptoFailsClosed:
    def _blob(self) -> bytes:
        return encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)

    def test_wrong_master_secret_raises(self) -> None:
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                self._blob(),
                master_secret=OTHER_MASTER,
                user_id=USER_ID,
            )

    @pytest.mark.parametrize(
        "position",
        [
            0,  # nonce
            NONCE_BYTES,  # first ciphertext byte
            -1,  # inside the GCM auth tag
        ],
    )
    def test_single_bit_flip_anywhere_raises(self, position: int) -> None:
        blob = bytearray(self._blob())
        blob[position] ^= 0x01
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                bytes(blob),
                master_secret=MASTER,
                user_id=USER_ID,
            )

    @pytest.mark.parametrize("length", [0, 1, NONCE_BYTES])
    def test_truncated_blob_raises(self, length: int) -> None:
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                self._blob()[:length],
                master_secret=MASTER,
                user_id=USER_ID,
            )

    def test_ciphertext_swapped_onto_another_user_raises(self) -> None:
        """The encrypted-secret-swap attack: a blob minted for user A
        pasted onto user B's row must not decrypt (AAD binding)."""
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                self._blob(),
                master_secret=MASTER,
                user_id=OTHER_USER_ID,
            )

    def test_empty_master_secret_refused_at_encrypt_time(self) -> None:
        with pytest.raises(ValueError, match="master_secret is empty"):
            encrypt_totp_secret(PLAINTEXT, master_secret=b"", user_id=USER_ID)

    def test_exception_contract(self) -> None:
        """DecryptionFailed is the module's documented public failure
        type and is a RuntimeError (callers catch either)."""
        assert issubclass(DecryptionFailed, RuntimeError)


class TestCryptoKeyRotation:
    OLD = b"the-rotated-out-master-secret-000000"
    OLDER = b"an-even-older-master-secret-11111111"

    def _old_blob(self) -> bytes:
        return encrypt_totp_secret(PLAINTEXT, master_secret=self.OLD, user_id=USER_ID)

    def test_previous_secret_decrypts_and_flags_rewrite(self) -> None:
        plaintext, needs_rewrite = decrypt_totp_secret(
            self._old_blob(),
            master_secret=MASTER,
            user_id=USER_ID,
            previous_secrets=[self.OLD],
        )
        assert plaintext == PLAINTEXT
        assert needs_rewrite is True

    def test_current_key_never_flags_rewrite(self) -> None:
        blob = encrypt_totp_secret(PLAINTEXT, master_secret=MASTER, user_id=USER_ID)
        _, needs_rewrite = decrypt_totp_secret(
            blob,
            master_secret=MASTER,
            user_id=USER_ID,
            previous_secrets=[self.OLD, self.OLDER],
        )
        assert needs_rewrite is False

    def test_later_entries_in_previous_list_are_reached(self) -> None:
        plaintext, needs_rewrite = decrypt_totp_secret(
            self._old_blob(),
            master_secret=MASTER,
            user_id=USER_ID,
            previous_secrets=[self.OLDER, self.OLD],
        )
        assert plaintext == PLAINTEXT
        assert needs_rewrite is True

    def test_empty_previous_entries_are_skipped(self) -> None:
        plaintext, needs_rewrite = decrypt_totp_secret(
            self._old_blob(),
            master_secret=MASTER,
            user_id=USER_ID,
            previous_secrets=[b"", self.OLD],
        )
        assert plaintext == PLAINTEXT
        assert needs_rewrite is True

    def test_unlisted_old_key_fails_closed(self) -> None:
        """Rotation without listing the old value in
        Z4J_PREVIOUS_SECRETS makes the secret unrecoverable -- the
        documented operator error the exception message points at."""
        with pytest.raises(DecryptionFailed, match="Z4J_PREVIOUS_SECRETS"):
            decrypt_totp_secret(
                self._old_blob(),
                master_secret=MASTER,
                user_id=USER_ID,
                previous_secrets=[self.OLDER],
            )

    def test_previous_key_does_not_bypass_user_binding(self) -> None:
        """The AAD check applies on the fallback path too: a stolen
        blob plus a leaked previous key still cannot be re-homed."""
        with pytest.raises(DecryptionFailed):
            decrypt_totp_secret(
                self._old_blob(),
                master_secret=MASTER,
                user_id=OTHER_USER_ID,
                previous_secrets=[self.OLD],
            )


# ---------------------------------------------------------------------------
# recovery.py: recovery-code minting / hashing / verification
# ---------------------------------------------------------------------------

#: The documented 31-character non-confusable alphabet (A-Z minus
#: I, L, O plus 2-9). Restated literally so a silent alphabet change
#: in the module fails this suite.
EXPECTED_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


class TestRecoveryCodeGeneration:
    @pytest.mark.parametrize("count", [1, 5, 10])
    def test_count_is_respected(self, count: int) -> None:
        assert len(generate_recovery_codes(count)) == count

    @pytest.mark.parametrize("count", [0, -1])
    def test_non_positive_count_rejected(self, count: int) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            generate_recovery_codes(count)

    def test_shape_is_three_hyphenated_groups_of_four(self) -> None:
        rx = re.compile(RECOVERY_CODE_PATTERN)
        for code in generate_recovery_codes(50):
            assert rx.fullmatch(code), code
            assert len(code) == 14  # 12 chars + 2 hyphens

    def test_alphabet_contract(self) -> None:
        """31 non-confusable characters; the 0/O/1/I/L lookalikes must
        never appear on a printed recovery sheet."""
        assert len(set(EXPECTED_ALPHABET)) == 31
        for confusable in "0O1IL":
            assert confusable not in EXPECTED_ALPHABET
        observed: set[str] = set()
        for code in generate_recovery_codes(300):
            observed.update(code.replace("-", ""))
        assert observed <= set(EXPECTED_ALPHABET)

    def test_entropy_sanity(self) -> None:
        """~59 bits per code: a 300-code batch must contain no
        duplicates, and (3600 character draws) must exercise the whole
        alphabet -- a stuck RNG or truncated alphabet fails both."""
        codes = generate_recovery_codes(300)
        assert len(set(codes)) == 300
        observed = {ch for code in codes for ch in code.replace("-", "")}
        assert observed == set(EXPECTED_ALPHABET)


class TestRecoveryCodeNormalisation:
    def test_lowercase_and_hyphenless_input_canonicalised(self) -> None:
        assert normalize_recovery_code("abcd-efgh-jkmn") == "ABCD-EFGH-JKMN"
        assert normalize_recovery_code("abcdefghjkmn") == "ABCD-EFGH-JKMN"

    def test_whitespace_stripped(self) -> None:
        assert normalize_recovery_code("  ABCD EFGH JKMN \n") == "ABCD-EFGH-JKMN"
        assert normalize_recovery_code("\tabcd efgh jkmn") == "ABCD-EFGH-JKMN"

    def test_arbitrary_hyphen_positions_tolerated(self) -> None:
        assert normalize_recovery_code("ab-cd-ef-gh-jk-mn") == "ABCD-EFGH-JKMN"

    def test_wrong_length_passes_through_for_regex_rejection(self) -> None:
        """Too-short / too-long input is returned unhyphenated so the
        pattern rejects it downstream."""
        rx = re.compile(RECOVERY_CODE_PATTERN)
        for raw in ("abc", "abcd-efgh", "abcdefghjkmnp"):
            normalised = normalize_recovery_code(raw)
            assert not rx.fullmatch(normalised), raw

    def test_generated_codes_are_already_canonical(self) -> None:
        for code in generate_recovery_codes(20):
            assert normalize_recovery_code(code) == code

    @pytest.mark.parametrize(
        "rejected",
        [
            "abcd-efgh-jkmn",  # lowercase (pre-normalisation form)
            "0000-0000-0000",  # confusable characters outside alphabet
            "ABCI-LOEF-GHJK",  # I, L, O excluded
            "ABCD-EFGH",  # short
            "ABCDE-FGHJ-KMNP",  # wrong group size
        ],
    )
    def test_pattern_rejects_non_canonical_forms(self, rejected: str) -> None:
        assert not re.fullmatch(RECOVERY_CODE_PATTERN, rejected)


class TestRecoveryCodeHashVerify:
    def test_hash_verify_round_trip(self) -> None:
        code = generate_recovery_codes(1)[0]
        hashed = hash_recovery_code(code)
        assert verify_recovery_code(plaintext=code, hashed=hashed)

    def test_hash_is_argon2id_and_never_embeds_plaintext(self) -> None:
        code = "ABCD-EFGH-JKMN"
        hashed = hash_recovery_code(code)
        assert hashed.startswith("$argon2id$")
        assert code not in hashed
        assert code.replace("-", "") not in hashed

    def test_wrong_code_returns_false(self) -> None:
        hashed = hash_recovery_code("ABCD-EFGH-JKMN")
        assert not verify_recovery_code(plaintext="ABCD-EFGH-JKMP", hashed=hashed)

    def test_hashes_are_salted(self) -> None:
        """Equal codes hash to distinct strings (per-hash salt), and
        both hashes verify -- a DB leak cannot cluster users by code."""
        code = "QRST-UVWX-YZ23"
        hash_a = hash_recovery_code(code)
        hash_b = hash_recovery_code(code)
        assert hash_a != hash_b
        assert verify_recovery_code(plaintext=code, hashed=hash_a)
        assert verify_recovery_code(plaintext=code, hashed=hash_b)

    def test_garbage_hash_fails_closed_without_raising(self) -> None:
        """The documented contract: bad hash material reads as
        "invalid code" (False), never as an exception the route would
        turn into a 500."""
        assert not verify_recovery_code(
            plaintext="ABCD-EFGH-JKMN",
            hashed="not-an-argon2-hash",
        )
        assert not verify_recovery_code(plaintext="ABCD-EFGH-JKMN", hashed="")

    def test_burn_one_argon2_cycle_is_silent(self) -> None:
        """The timing-equalisation helper must never raise and never
        return a value the caller could branch on."""
        assert burn_one_argon2_cycle() is None
