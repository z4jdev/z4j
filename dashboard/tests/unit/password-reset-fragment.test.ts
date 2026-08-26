import { describe, expect, it } from "vitest";

import {
  describePasswordResetError,
  passwordCharacterClassCount,
  passwordResetTokenFromHash,
  validatePasswordResetForm,
} from "@/routes/reset";
import { ApiError } from "@/lib/api";

const token = `${"A".repeat(41)}-_`;
const policy = {
  min_length: 12,
  required_character_classes: 3,
  character_class_names: ["lowercase", "uppercase", "digit", "symbol"],
};

describe("passwordResetTokenFromHash", () => {
  it("accepts exactly the fragment grammar emitted by the backend", () => {
    expect(passwordResetTokenFromHash(`#token=${token}`)).toBe(token);
  });

  it.each([
    "",
    `token=${token}`,
    `?token=${token}`,
    "#token=short",
    `#token=${"A".repeat(42)}`,
    `#token=${"A".repeat(44)}`,
    `#token=${"!".repeat(43)}`,
    `#token=${token}&token=${"B".repeat(43)}`,
    `#token=${token}&next=/admin`,
    `#other=${token}`,
    `#token=%41${"A".repeat(42)}`,
  ])("rejects non-canonical or non-fragment input: %s", (hash) => {
    expect(passwordResetTokenFromHash(hash)).toBeUndefined();
  });
});

describe("password reset policy validation", () => {
  it("matches the backend's non-whitespace character-class rules", () => {
    expect(passwordCharacterClassCount("lower UPPER 123 !")).toBe(4);
    expect(passwordCharacterClassCount("lower upper 123   ")).toBe(2);
  });

  it("rejects short, overlong, simple, and mismatched passwords", () => {
    expect(validatePasswordResetForm("Ab1!", "Ab1!", policy)).toMatchObject({
      field: "password",
      message: "Use at least 12 characters.",
    });
    expect(
      validatePasswordResetForm("a".repeat(257), "a".repeat(257), policy),
    ).toMatchObject({ field: "password", message: /no more than 256/i });
    expect(
      validatePasswordResetForm("abcdefghijkl", "abcdefghijkl", policy),
    ).toMatchObject({ field: "password", message: /character types/i });
    expect(
      validatePasswordResetForm("Abcd1234!xyz", "Abcd1234!xyZ", policy),
    ).toMatchObject({ field: "confirmation", message: /do not match/i });
  });

  it("accepts a compliant short password and the backend's 16+ passphrase exception", () => {
    expect(
      validatePasswordResetForm("Abcd1234!xyz", "Abcd1234!xyz", policy),
    ).toBeNull();
    expect(
      validatePasswordResetForm(
        "sixteencharacters",
        "sixteencharacters",
        policy,
      ),
    ).toBeNull();
  });
});

describe("password reset error descriptions", () => {
  it.each([
    [422, "password_too_simple", "Password not accepted"],
    [429, "rate_limited", "Too many attempts"],
    [0, "network_error", "Could not reach z4j"],
    [503, "internal_error", "Server error"],
  ])("maps status %s to a safe retry message", (status, code, title) => {
    const secret = "never-render-this-reset-token";
    const described = describePasswordResetError(
      new ApiError(status, { error: code, message: secret }),
    );

    expect(described.title).toBe(title);
    expect(JSON.stringify(described)).not.toContain(secret);
  });
});
