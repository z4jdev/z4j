/**
 * demo-timestamps.ts -- relative-time anchor for demo seed data.
 *
 * Static seed timestamps go stale immediately ("Last fired: 11
 * months ago"). Solution: seed JSON stores time as
 * `<final_field>_offset_s` integers (seconds relative to "now"), and
 * `applyDemoTimestamps()` walks the parsed JSON tree just before
 * it is returned to the dashboard, replacing each `_offset_s`
 * suffix with an ISO timestamp computed from the page-load anchor.
 *
 * Convention: the field is named with the FINAL desired name plus
 * `_offset_s`. The suffix is stripped entirely:
 *
 *   "last_fired_at_offset_s": -300   -> "last_fired_at": "<iso 5min ago>"
 *   "occurred_at_offset_s":  -3600   -> "occurred_at":  "<iso 1h ago>"
 *   "t_offset_s":            -60     -> "t":            "<iso 1min ago>"
 *
 * If the field name does not end in `_offset_s` the value is left
 * untouched. The transform recurses into nested objects + arrays.
 *
 * Anchor is captured once per module load (which happens on first
 * page load), so refreshing the demo nudges all timestamps "into
 * the present" again.
 */

const ANCHOR_MS = Date.now();

function applyOne(value: unknown): unknown {
  if (value === null) return null;
  if (Array.isArray(value)) return value.map(applyOne);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      if (key.endsWith("_offset_s") && typeof v === "number") {
        // Strip the _offset_s suffix entirely. Convention: the field
        // was named "<final>_offset_s", so the new key is "<final>".
        const newKey = key.slice(0, -"_offset_s".length);
        result[newKey] = new Date(ANCHOR_MS + v * 1000).toISOString();
      } else {
        result[key] = applyOne(v);
      }
    }
    return result;
  }
  return value;
}

export function applyDemoTimestamps<T>(payload: T): T {
  return applyOne(payload) as T;
}

/**
 * Test helper: re-anchor for snapshot tests. Not used at runtime.
 */
export function _setAnchorForTests(ms: number): void {
  // Module-level const can't be mutated; tests should not depend on
  // re-anchoring. Provided as a no-op so tests fail loudly if they
  // try, instead of silently working in dev and breaking in CI.
  void ms;
  throw new Error(
    "Demo timestamp anchor is set once per module load and cannot be mutated. " +
    "Restructure the test to use absolute mocked Date.now() if needed.",
  );
}
