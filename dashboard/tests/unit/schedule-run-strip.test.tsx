/**
 * The run strip is the picture behind the Health column. Its colour buckets
 * have to cover the brain's whole status vocabulary, because a status it
 * does not know must never draw as a success, and its accessible summary
 * must not claim "no fires" while the history is unknown.
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  OUTCOME_BY_STATUS,
  ScheduleRunStrip,
  outcomeOf,
  statusLabel,
  stripSummary,
} from "@/components/domain/schedule-run-strip";
import type { ScheduleRunCell } from "@/hooks/use-schedules";

const BRAIN_STATUSES = [
  "pending",
  "accepted",
  "delivered",
  "buffered",
  "buffer_expired",
  "buffer_stale",
  "operator_skipped",
  "acked_success",
  "acked_failed",
  "failed",
  "terminal_completed",
  "terminal_failed",
  "terminal_cancelled",
  "terminal_timeout",
] as const;

function cell(status: string, minutesAgo: number, latency: number | null = 120): ScheduleRunCell {
  const fired = new Date(Date.now() - minutesAgo * 60_000);
  return {
    fire_id: `fire-${minutesAgo}`,
    status,
    scheduled_for: fired.toISOString(),
    fired_at: fired.toISOString(),
    latency_ms: latency,
  };
}

describe("outcomeOf", () => {
  it("decides a colour for every status the brain writes", () => {
    for (const status of BRAIN_STATUSES) {
      expect(Object.keys(OUTCOME_BY_STATUS)).toContain(status);
      expect(statusLabel(status)).toBeTruthy();
    }
    // A status this build does not know is echoed as-is rather than invented.
    expect(statusLabel("something_new")).toBe("something_new");
  });

  it("draws in-flight and timed-out fires as anything but success", () => {
    expect(outcomeOf("accepted")).toBe("pending");
    expect(outcomeOf("delivered")).toBe("pending");
    expect(outcomeOf("terminal_timeout")).toBe("failed");
    expect(outcomeOf("acked_success")).toBe("ok");
    expect(outcomeOf("terminal_completed")).toBe("ok");
    expect(outcomeOf("operator_skipped")).toBe("skipped");
  });

  it("never turns an unknown status green", () => {
    expect(outcomeOf("acked_ok")).toBe("pending");
    expect(outcomeOf("something_new")).toBe("pending");
  });
});

describe("stripSummary", () => {
  it("does not claim no fires while the history is unknown", () => {
    expect(stripSummary(undefined, false)).toBe("run history not loaded yet");
    expect(stripSummary(undefined, true)).toBe("run history unavailable");
    expect(stripSummary([], false)).toBe("no fires in the retention window");
  });

  it("counts every failed outcome", () => {
    const cells = [cell("acked_failed", 1), cell("terminal_timeout", 2), cell("acked_success", 3)];
    expect(stripSummary(cells, false)).toBe("3 recent fires, 2 failed");
  });
});

describe("ScheduleRunStrip", () => {
  it("renders the newest fire on the right", () => {
    const runs = [cell("acked_failed", 1), cell("acked_success", 2), cell("acked_success", 3)];
    render(<ScheduleRunStrip runs={runs} slots={5} />);
    const strip = screen.getByRole("img", { name: "3 recent fires, 1 failed" });
    const cells = Array.from(strip.querySelectorAll("span[title]"));
    expect(cells).toHaveLength(3);
    expect(cells[cells.length - 1].getAttribute("title")).toContain("failed");
    expect(cells[0].getAttribute("title")).toContain("succeeded");
    // Two empty slots pad the left.
    expect(strip.querySelectorAll("span[aria-hidden]")).toHaveLength(2);
  });

  it("keys duplicate fire ids apart by their fire time", () => {
    const a = cell("acked_success", 1);
    const b = { ...cell("acked_success", 2), fire_id: a.fire_id };
    render(<ScheduleRunStrip runs={[a, b]} slots={2} />);
    expect(screen.getByRole("img").querySelectorAll("span[title]")).toHaveLength(2);
  });

  it("announces an unavailable history instead of an empty one", () => {
    render(<ScheduleRunStrip runs={undefined} error />);
    expect(screen.getByRole("img", { name: "run history unavailable" })).toBeInTheDocument();
  });
});
