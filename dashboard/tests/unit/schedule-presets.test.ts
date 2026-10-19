/**
 * Cron presets are written per scheduler. APScheduler 3.x and arq number the
 * weekday field Monday 0 through Sunday 6, so the crontab "1-5" runs Tuesday
 * to Saturday there; every other scheduler follows crontab (Monday is 1).
 */
import { describe, expect, it } from "vitest";

import { cronPresetsFor, scheduleSummary } from "@/lib/schedule-presets";

const weekdayPreset = (scheduler: string) =>
  cronPresetsFor(scheduler).find((p) => p.label === "Weekdays at 09:00")
    ?.expression;

describe("cronPresetsFor", () => {
  it("writes Monday to Friday as 0-4 where Monday is 0", () => {
    expect(weekdayPreset("apscheduler")).toBe("0 9 * * 0-4");
    expect(weekdayPreset("arq-cron")).toBe("0 9 * * 0-4");
  });

  it("writes Monday to Friday as 1-5 where Monday is 1", () => {
    for (const scheduler of [
      "z4j-scheduler",
      "celery-beat",
      "rq-scheduler",
      "huey-periodic",
      "taskiq-scheduler",
    ]) {
      expect(weekdayPreset(scheduler)).toBe("0 9 * * 1-5");
    }
  });

  it("keeps the presets that name no weekday the same everywhere", () => {
    const expressions = (scheduler: string) =>
      cronPresetsFor(scheduler)
        .filter((p) => p.label !== "Weekdays at 09:00")
        .map((p) => p.expression);
    expect(expressions("apscheduler")).toEqual(expressions("z4j-scheduler"));
  });
});

describe("scheduleSummary", () => {
  it("names the weekday preset only in the scheduler's own numbering", () => {
    expect(scheduleSummary("cron", "0 9 * * 0-4", "UTC", "apscheduler")).toBe(
      "Weekdays at 09:00 · UTC",
    );
    // Tuesday to Saturday on APScheduler: not the weekday preset.
    expect(scheduleSummary("cron", "0 9 * * 1-5", "UTC", "apscheduler")).toBe(
      "Custom cron · UTC",
    );
    expect(scheduleSummary("cron", "0 9 * * 1-5", "UTC", "arq-cron")).toBe(
      "Custom cron · UTC",
    );
    expect(
      scheduleSummary("cron", "0 9 * * 1-5", "UTC", "z4j-scheduler"),
    ).toBe("Weekdays at 09:00 · UTC");
    // Sunday to Thursday under crontab numbering.
    expect(
      scheduleSummary("cron", "0 9 * * 0-4", "UTC", "z4j-scheduler"),
    ).toBe("Custom cron · UTC");
  });
});
