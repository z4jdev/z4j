import { describe, expect, it } from "vitest";
import {
  auditableProjects,
  holdsAuditTier,
  projectlessActivityScope,
  type ActivityCaller,
} from "../../src/lib/activity-scope";

const projects = [
  { slug: "alpha", name: "Alpha" },
  { slug: "beta", name: "Beta" },
  { slug: "gamma", name: "Gamma" },
];

function member(
  role: ActivityCaller["memberships"][number]["role"],
  project_slug: string,
) {
  return { project_slug, role };
}

describe("auditableProjects", () => {
  it("is empty until the caller is known", () => {
    expect(auditableProjects(undefined, projects)).toEqual([]);
  });

  it("gives an instance admin every project, memberships or not", () => {
    expect(
      auditableProjects({ is_admin: true, memberships: [] }, projects),
    ).toEqual(projects);
  });

  it("keeps only the projects where the role satisfies read_audit", () => {
    const caller: ActivityCaller = {
      is_admin: false,
      memberships: [
        member("auditor", "alpha"),
        member("viewer", "beta"),
        member("operator", "gamma"),
        member("admin", "delta"),
      ],
    };
    expect(auditableProjects(caller, projects).map((p) => p.slug)).toEqual([
      "alpha",
    ]);
  });

  it("ignores a membership on a project the list does not carry", () => {
    const caller: ActivityCaller = {
      is_admin: false,
      memberships: [member("admin", "delta")],
    };
    expect(auditableProjects(caller, projects)).toEqual([]);
  });
});

describe("holdsAuditTier", () => {
  it("is true for an instance admin and for any auditor or admin membership", () => {
    expect(holdsAuditTier({ is_admin: true, memberships: [] })).toBe(true);
    expect(
      holdsAuditTier({
        is_admin: false,
        memberships: [member("viewer", "alpha"), member("auditor", "beta")],
      }),
    ).toBe(true);
    expect(
      holdsAuditTier({
        is_admin: false,
        memberships: [member("admin", "alpha")],
      }),
    ).toBe(true);
  });

  it("is false when every membership is viewer or operator", () => {
    expect(holdsAuditTier({ is_admin: false, memberships: [] })).toBe(false);
    expect(
      holdsAuditTier({
        is_admin: false,
        memberships: [member("viewer", "alpha"), member("operator", "beta")],
      }),
    ).toBe(false);
  });
});

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
