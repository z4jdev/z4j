import { describe, expect, it } from "vitest";
import { canManageNativeSchedule } from "@/hooks/use-schedules";

describe("native schedule action availability", () => {
  const row = { scheduler: "huey-periodic", source: "huey-periodic:code" };
  it("requires both write protocol and the requested action", () => {
    expect(canManageNativeSchedule(row, "update", undefined)).toBe(false);
    expect(
      canManageNativeSchedule(row, "update", { "huey-periodic": ["update"] }),
    ).toBe(false);
    expect(
      canManageNativeSchedule(row, "update", {
        "huey-periodic": ["external_schedule_mutation_v1", "update"],
      }),
    ).toBe(true);
    expect(
      canManageNativeSchedule(row, "delete", {
        "huey-periodic": ["external_schedule_mutation_v1", "update"],
      }),
    ).toBe(false);
  });
  it("allows manual runs without promising reversible edits", () => {
    expect(
      canManageNativeSchedule(row, "trigger_now", {
        "huey-periodic": ["trigger_now"],
      }),
    ).toBe(true);
    expect(
      canManageNativeSchedule(row, "toggle", {
        "huey-periodic": ["external_schedule_mutation_v1", "disable"],
      }),
    ).toBe(false);
  });
  it("keeps static Beat definitions protected even with a writable database producer", () => {
    const beat = { scheduler: "celery-beat", source: "celery-beat:static" };
    expect(
      canManageNativeSchedule(beat, "update", {
        "celery-beat": ["external_schedule_mutation_v1", "update"],
      }),
    ).toBe(false);
    expect(
      canManageNativeSchedule(beat, "trigger_now", {
        "celery-beat": ["trigger_now"],
      }),
    ).toBe(true);
  });
});
