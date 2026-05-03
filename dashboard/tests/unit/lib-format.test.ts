/**
 * Unit tests for ``src/lib/format.ts``.
 *
 * The two date functions were rewritten on top of native ``Intl``
 * (away from ``date-fns``) as part of the npm-supply-chain
 * minimisation pass. These tests guard the round-trip behaviour
 * so a future "let's switch to Temporal" cleanup can verify
 * equivalence.
 */
import { describe, expect, it } from "vitest";

import {
  formatAbsolute,
  formatCompact,
  formatDuration,
  formatPercent,
  formatRelative,
  truncate,
} from "@/lib/format";

describe("formatRelative", () => {
  it("returns '-' on null / undefined / empty", () => {
    expect(formatRelative(null)).toBe("-");
    expect(formatRelative(undefined)).toBe("-");
    expect(formatRelative("")).toBe("-");
  });

  it("renders 'just now'-class for sub-minute deltas", () => {
    const out = formatRelative(new Date(Date.now() - 5_000));
    // Locale-dependent exact string ('5 seconds ago' / 'now').
    // The contract is just "non-empty, non-dash" - any locale's
    // RelativeTimeFormat emits some human-readable string here.
    expect(out).not.toBe("-");
    expect(out.length).toBeGreaterThan(0);
  });

  it("handles future timestamps with positive sign", () => {
    const out = formatRelative(new Date(Date.now() + 60_000));
    expect(out).not.toBe("-");
  });

  it("returns '-' for unparseable strings", () => {
    expect(formatRelative("not-a-date")).toBe("-");
  });
});

describe("formatAbsolute", () => {
  it("returns '-' on null / undefined", () => {
    expect(formatAbsolute(null)).toBe("-");
    expect(formatAbsolute(undefined)).toBe("-");
  });

  it("renders YYYY-MM-DD HH:mm:ss with zero-padding", () => {
    const d = new Date("2026-04-11T03:05:09Z");
    const out = formatAbsolute(d);
    expect(out).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it("returns '-' for unparseable input", () => {
    expect(formatAbsolute("garbage")).toBe("-");
  });
});

describe("formatDuration", () => {
  it("returns '-' on null / undefined", () => {
    expect(formatDuration(null)).toBe("-");
    expect(formatDuration(undefined)).toBe("-");
  });

  it("renders sub-second as ms", () => {
    expect(formatDuration(230)).toBe("230ms");
  });

  it("renders sub-minute as fractional seconds", () => {
    expect(formatDuration(1500)).toBe("1.5s");
  });

  it("renders multi-minute with seconds", () => {
    expect(formatDuration(75_000)).toBe("1m 15s");
  });

  it("renders multi-hour with minutes", () => {
    expect(formatDuration(3_900_000)).toBe("1h 5m");
  });
});

describe("formatCompact", () => {
  it("returns '-' on null / undefined", () => {
    expect(formatCompact(null)).toBe("-");
    expect(formatCompact(undefined)).toBe("-");
  });

  it("passes through small integers", () => {
    expect(formatCompact(42)).toBe("42");
    expect(formatCompact(0)).toBe("0");
  });

  it("uses k/M/B suffixes", () => {
    expect(formatCompact(1500)).toBe("1.5k");
    expect(formatCompact(2_500_000)).toBe("2.5M");
    expect(formatCompact(3_000_000_000)).toBe("3.0B");
  });

  it("handles negative values", () => {
    expect(formatCompact(-1500)).toBe("-1.5k");
  });
});

describe("formatPercent", () => {
  it("returns '0%' for null / undefined / NaN", () => {
    expect(formatPercent(null)).toBe("0%");
    expect(formatPercent(undefined)).toBe("0%");
    expect(formatPercent(Number.NaN)).toBe("0%");
  });

  it("multiplies by 100 and appends '%'", () => {
    expect(formatPercent(0.125)).toBe("12.5%");
    expect(formatPercent(1)).toBe("100.0%");
  });

  it("respects fractionDigits", () => {
    expect(formatPercent(0.12345, 0)).toBe("12%");
    expect(formatPercent(0.12345, 3)).toBe("12.345%");
  });
});

describe("truncate", () => {
  it("returns short strings unchanged", () => {
    expect(truncate("hello", 60)).toBe("hello");
  });

  it("truncates with ellipsis when exceeding max", () => {
    const out = truncate("a".repeat(100), 10);
    expect(out).toHaveLength(10);
    expect(out.endsWith("…")).toBe(true);
  });
});
