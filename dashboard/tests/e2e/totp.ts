/**
 * RFC 6238 TOTP helper for the MFA E2E spec.
 *
 * The dashboard has no TOTP library (otplib and friends) in its
 * dependency tree, and adding one just to test the flow would widen
 * the supply-chain surface of a security feature for no product
 * reason. The brain itself implements TOTP with stdlib HMAC only
 * (``z4j_brain/domain/mfa/totp.py``) for exactly that reason, so this
 * mirrors it: a tiny, dependency-free generator that computes the
 * 6-digit code a real authenticator app would display for the secret
 * the brain hands us at enroll time.
 *
 * Parameters match the backend byte-for-byte:
 *   - HMAC-SHA1
 *   - 6 digits
 *   - 30-second step
 *   - secret is RFC 4648 base32, no padding (as emitted by
 *     ``secret_to_base32`` and shown to the user during enrollment).
 */
import { createHmac } from "node:crypto";

/** TOTP step in seconds. Matches ``TOTP_STEP_SECONDS`` on the brain. */
export const TOTP_STEP_SECONDS = 30;

/** Digits in the emitted code. Matches ``TOTP_DIGITS`` on the brain. */
export const TOTP_DIGITS = 6;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decode an unpadded, upper-case RFC 4648 base32 string to bytes.
 *
 * The brain strips ``=`` padding before handing the secret to the
 * dashboard, so we tolerate its absence (and re-strip defensively).
 */
export function base32Decode(input: string): Buffer {
  const clean = input
    .replace(/\s+/g, "")
    .replace(/=+$/, "")
    .toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`invalid base32 character in TOTP secret: ${ch}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** RFC 4226 HOTP value for a given counter. */
function hotp(secret: Buffer, counter: number): string {
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", secret).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const truncated =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(truncated % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

export interface TotpToken {
  /** The 6-digit code to type into the app. */
  code: string;
  /** The 30s time-step the code belongs to. The brain single-uses
   * each step (anti-replay), so a caller that has already spent a
   * step can pass it to ``avoidCounter`` to force a fresh window. */
  counter: number;
}

/**
 * Compute the TOTP code and its 30s counter for a base32 secret at a
 * point in time (defaults to now).
 */
export function totpAt(
  secretBase32: string,
  atMs: number = Date.now(),
): TotpToken {
  const counter = Math.floor(atMs / 1000 / TOTP_STEP_SECONDS);
  return { code: hotp(base32Decode(secretBase32), counter), counter };
}
