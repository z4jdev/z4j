/**
 * The trend chart's axis helpers: every gridline label must be a number a
 * reader would say out loud, and a count axis must never show a fraction.
 */
import { describe, expect, it } from "vitest";

import { compactTick, niceCeiling, niceStep } from "@/components/domain/trend-chart";

describe("niceStep / niceCeiling", () => {
  it("keeps count axes on whole numbers", () => {
    for (let max = 1; max <= 2000; max += 1) {
      const step = niceStep(max);
      expect(Number.isInteger(step), `step for ${max} is ${step}`).toBe(true);
      expect(step).toBeGreaterThanOrEqual(1);
      const ceiling = niceCeiling(max);
      expect(ceiling).toBeGreaterThanOrEqual(max);
      expect(Math.round(ceiling / step)).toBeLessThanOrEqual(6);
    }
  });

  it("picks the expected steps", () => {
    expect([niceStep(3), niceCeiling(3)]).toEqual([1, 3]);
    expect([niceStep(13), niceCeiling(13)]).toEqual([5, 15]);
    expect([niceStep(61), niceCeiling(61)]).toEqual([20, 80]);
    expect([niceStep(843), niceCeiling(843)]).toEqual([200, 1000]);
    expect([niceStep(21225), niceCeiling(21225)]).toEqual([5000, 25000]);
    expect([niceStep(271291), niceCeiling(271291)]).toEqual([50000, 300000]);
  });

  it("labels compactly", () => {
    expect(compactTick(0)).toBe("0");
    expect(compactTick(5000)).toBe("5k");
    expect(compactTick(12500)).toBe("12.5k");
    expect(compactTick(2_000_000)).toBe("2M");
  });
});
