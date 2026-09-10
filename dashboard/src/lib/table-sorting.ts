import { parseTimestamp } from "@/lib/format";

export type TableSortValue = string | number | boolean | null | undefined;
const collator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

/** Missing values stay last in either direction; ties retain server order. */
export function compareTableValues(
  a: TableSortValue,
  b: TableSortValue,
  direction: "asc" | "desc" = "asc",
): number {
  const missingA = a == null || (typeof a === "number" && !Number.isFinite(a));
  const missingB = b == null || (typeof b === "number" && !Number.isFinite(b));
  if (missingA || missingB)
    return missingA === missingB ? 0 : missingA ? 1 : -1;
  const result =
    typeof a === "number" && typeof b === "number"
      ? a - b
      : typeof a === "boolean" && typeof b === "boolean"
        ? Number(a) - Number(b)
        : collator.compare(String(a), String(b));
  return direction === "asc" ? result : -result;
}

/** API timestamps without offsets are UTC, just as in DateCell. */
export function sortTimestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const timestamp = parseTimestamp(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : null;
}
