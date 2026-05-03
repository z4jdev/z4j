/**
 * Tests for the DST fall-back / spring-forward warning helper.
 *
 * docs/SCHEDULER.md §5.5 promises the dashboard create form will
 * warn the operator when their cron + timezone combination would
 * produce a fall-back duplicate. These tests pin the contract:
 *
 * - Non-cron kinds never warn (intervals + one_shot fire on
 *   absolute UTC instants and don't see DST).
 * - UTC and non-DST timezones never warn.
 * - A cron firing at 02:00 in America/New_York triggers a
 *   fall-back warning (US DST ends 02:00 -> 01:00 in November).
 * - A cron firing at 02:00 in Europe/Berlin triggers a fall-back
 *   warning (EU DST ends 03:00 -> 02:00 in October).
 * - The hour-field parser handles ``*``, lists, ranges, steps.
 *
 * The warning DATE in the message is computed from the actual
 * timezone's DST schedule at test time, so we assert on the
 * presence of "fires TWICE" / "skips" rather than on a specific
 * year that would go stale.
 */

import { describe, expect, it } from "vitest";

import { computeDstWarning } from "@/lib/dst-warnings";

describe("computeDstWarning", () => {
  it("returns null for non-cron kinds", () => {
    expect(
      computeDstWarning("interval", "60s", "America/New_York"),
    ).toBeNull();
    expect(
      computeDstWarning("one_shot", "2026-12-25T09:00:00Z", "Europe/Berlin"),
    ).toBeNull();
  });

  it("returns null for UTC", () => {
    expect(
      computeDstWarning("cron", "0 2 * * *", "UTC"),
    ).toBeNull();
    expect(
      computeDstWarning("cron", "0 2 * * *", "Etc/UTC"),
    ).toBeNull();
  });

  it("returns null for timezones that do not observe DST", () => {
    // Phoenix is in Arizona which doesn't observe DST.
    expect(
      computeDstWarning("cron", "0 2 * * *", "America/Phoenix"),
    ).toBeNull();
    // Tokyo never observes DST.
    expect(
      computeDstWarning("cron", "0 2 * * *", "Asia/Tokyo"),
    ).toBeNull();
  });

  it("warns on fall-back duplicate for US Eastern", () => {
    // US DST ends in November - clocks fall back from 02:00 to 01:00.
    // A cron firing at 01:00 fires twice on that day.
    const w = computeDstWarning("cron", "0 1 * * *", "America/New_York");
    expect(w).not.toBeNull();
    expect(w!.level).toBe("warning");
    expect(w!.message).toMatch(/fires? TWICE/i);
    expect(w!.message).toContain("America/New_York");
  });

  it("warns on fall-back duplicate for Europe/Berlin", () => {
    // EU DST ends in October - clocks fall back from 03:00 to 02:00.
    // A cron firing at 02:00 fires twice on that day.
    const w = computeDstWarning("cron", "0 2 * * *", "Europe/Berlin");
    expect(w).not.toBeNull();
    expect(w!.level).toBe("warning");
    expect(w!.message).toMatch(/fires? TWICE/i);
  });

  it("returns null when cron fires outside the ambiguous window", () => {
    // 03:00 in NY is past the fall-back ambiguous window (which
    // is 01:00 there), so no warning.
    expect(
      computeDstWarning("cron", "0 3 * * *", "America/New_York"),
    ).toBeNull();
    // Same for 04:00.
    expect(
      computeDstWarning("cron", "0 4 * * *", "America/New_York"),
    ).toBeNull();
  });

  it("warns when hour field uses '*' (fires every hour, including ambiguous one)", () => {
    const w = computeDstWarning("cron", "0 * * * *", "Europe/Berlin");
    expect(w).not.toBeNull();
    expect(w!.level).toBe("warning");
  });

  it("warns when hour field is a range covering the ambiguous hour", () => {
    // 1-3 in NY covers 01:00 which is ambiguous.
    const w = computeDstWarning("cron", "0 1-3 * * *", "America/New_York");
    expect(w).not.toBeNull();
  });

  it("warns when hour field uses a step covering the ambiguous hour", () => {
    // */2 in Berlin = 0,2,4,6,...,22 - includes 02:00 which is ambiguous.
    const w = computeDstWarning("cron", "0 */2 * * *", "Europe/Berlin");
    expect(w).not.toBeNull();
  });

  it("returns null on a malformed cron expression", () => {
    // Defensive: don't throw on garbage. The form's validator
    // catches malformed input separately.
    expect(
      computeDstWarning("cron", "not a cron", "Europe/Berlin"),
    ).toBeNull();
    expect(
      computeDstWarning("cron", "* * *", "Europe/Berlin"),
    ).toBeNull();
  });

  it("returns null on an empty timezone", () => {
    expect(computeDstWarning("cron", "0 2 * * *", "")).toBeNull();
  });
});
