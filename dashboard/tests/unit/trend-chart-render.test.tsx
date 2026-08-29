/**
 * The rendered chart: round whole-number gridline labels, and the first and
 * last time labels anchored to the chart edges so the last one is never
 * clipped.
 */
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";

import { TrendChart } from "@/components/domain/trend-chart";
import type { TrendBucket } from "@/hooks/use-trends";

function buckets(peaks: number[]): TrendBucket[] {
  const start = Date.parse("2026-08-28T00:00:00Z");
  return peaks.map((success, i) => ({
    t: new Date(start + i * 900_000).toISOString(),
    bucket: new Date(start + i * 900_000).toISOString(),
    success,
    failure: i % 5 === 0 ? 3 : 0,
    retry: 0,
    revoked: 0,
  })) as unknown as TrendBucket[];
}

describe("TrendChart", () => {
  it("labels the axis with whole numbers and anchors the edge time labels", () => {
    const { container } = render(<TrendChart series={buckets([4, 9, 13, 11, 7, 12, 13])} />);
    const texts = Array.from(container.querySelectorAll("text"));
    const ticks = texts.map((t) => t.textContent ?? "").filter((t) => /^[0-9.]+[kM]?$/.test(t));
    expect(ticks.length).toBeGreaterThanOrEqual(3);
    for (const t of ticks) expect(t, `tick ${t}`).not.toMatch(/^\d+\.\d+$/);
    const anchors = texts.map((t) => t.getAttribute("text-anchor") ?? t.getAttribute("textAnchor"));
    expect(anchors).toContain("start");
    expect(anchors).toContain("end");
  });

  it("renders an empty state without a series", () => {
    const { container } = render(<TrendChart series={[]} />);
    expect(container.querySelector("svg")).toBeNull();
  });
});
