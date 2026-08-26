import { describe, expect, it } from "vitest";
import { projectlessActivityScope } from "../../src/lib/activity-scope";

describe("projectlessActivityScope", () => {
  it("labels the caller's user-scoped row as personal", () => {
    expect(projectlessActivityScope("user-1", "user-1")).toBe("personal");
  });

  it.each([
    [null, "user-1"],
    ["user-2", "user-1"],
    ["user-1", null],
  ])("labels a non-personal projectless row as brain-wide", (row, caller) => {
    expect(projectlessActivityScope(row, caller)).toBe("brain-wide");
  });
});
