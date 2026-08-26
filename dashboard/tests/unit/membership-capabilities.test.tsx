import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({
  me: null as null | {
    is_admin: boolean;
    memberships: { project_slug: string; role: string }[];
  },
}));

vi.mock("@/hooks/use-auth", () => ({
  useMe: () => ({ data: auth.me }),
}));

import {
  canProjectRole,
  useCan,
  type ProjectCapability,
  type ProjectRole,
} from "@/hooks/use-memberships";

const actions: ProjectCapability[] = [
  "view",
  "retry_task",
  "cancel_task",
  "delete_tasks",
  "bulk_action",
  "purge_queue",
  "operate_schedules",
  "admin_schedules",
  "manage_schedules",
  "manage_automation",
  "manage_agents",
  "manage_members",
  "manage_channels",
  "manage_invitations",
];

const operatorActions = new Set<ProjectCapability>([
  "view",
  "retry_task",
  "cancel_task",
  "bulk_action",
  "purge_queue",
  "operate_schedules",
  "manage_schedules",
  "manage_automation",
]);

describe("project capability role parity", () => {
  beforeEach(() => {
    auth.me = null;
  });

  it.each<ProjectRole | null>([null, "viewer", "operator", "admin"])(
    "matches the complete backend-aligned matrix for %s",
    (role) => {
      for (const action of actions) {
        const expected =
          role === "admin" ||
          (role === "viewer" && action === "view") ||
          (role === "operator" && operatorActions.has(action));
        expect(canProjectRole(role, action), `${role}:${action}`).toBe(
          expected,
        );
      }
    },
  );

  it("treats a global admin without project membership as project admin", () => {
    auth.me = { is_admin: true, memberships: [] };

    const { result: deleteTasks } = renderHook(() =>
      useCan("project", "delete_tasks"),
    );
    const { result: adminSchedules } = renderHook(() =>
      useCan("project", "admin_schedules"),
    );

    expect(deleteTasks.current).toBe(true);
    expect(adminSchedules.current).toBe(true);
  });
});
