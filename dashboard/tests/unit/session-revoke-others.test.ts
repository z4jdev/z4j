import { beforeEach, describe, expect, it, vi } from "vitest";

const postSpy = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { post: (...args: unknown[]) => postSpy(...args) },
}));
import { revokeOtherSessions } from "@/lib/session-actions";

describe("revokeOtherSessions", () => {
  beforeEach(() => postSpy.mockReset());

  it("uses the server-side bulk endpoint exactly once", async () => {
    postSpy.mockResolvedValue(undefined);
    await revokeOtherSessions();
    expect(postSpy).toHaveBeenCalledTimes(1);
    expect(postSpy).toHaveBeenCalledWith("/auth/sessions/revoke-others");
    expect(postSpy.mock.calls[0]?.[0]).not.toMatch(
      /\/sessions\/[0-9a-f-]+\/revoke/,
    );
  });
});
