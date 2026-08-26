import { describe, expect, it } from "vitest";

import {
  invitationTokenFromHash,
  safeInvitationErrorMessage,
  scrubInvitationLocation,
} from "@/routes/invite";

const token = "A".repeat(43);

describe("invitationTokenFromHash", () => {
  it("accepts the single URL-fragment token emitted by the backend", () => {
    expect(invitationTokenFromHash(`#token=${token}`)).toBe(token);
  });

  it.each([
    "",
    "#token=short",
    `#token=${token}&token=${"B".repeat(43)}`,
    `?token=${token}`,
    `#other=${token}`,
    `#token=${"!".repeat(43)}`,
    `#token=%41${"A".repeat(42)}`,
    `#token=${token}&next=/admin`,
  ])(
    "refuses missing, ambiguous, query-shaped, or malformed input: %s",
    (hash) => {
      expect(invitationTokenFromHash(hash)).toBeUndefined();
    },
  );

  it("scrubs query and fragment data without retaining a history entry", () => {
    window.history.replaceState({}, "", `/invite?token=query#token=${token}`);

    scrubInvitationLocation();

    expect(window.location.pathname).toBe("/invite");
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
    expect(window.location.href).not.toContain(token);
  });

  it("redacts a token if an upstream error reflects it", () => {
    const password = "Correct-Horse-Battery-9!";
    const message = safeInvitationErrorMessage(
      new Error(`invalid credential ${token} ${password}`),
      token,
      password,
    );

    expect(message).toBe("invalid credential [redacted] [redacted]");
    expect(message).not.toContain(token);
    expect(message).not.toContain(password);
  });
});
