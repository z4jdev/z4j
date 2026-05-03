/**
 * Display formatters for dates, durations, numbers, and bytes.
 *
 * Used by every list view in the dashboard. Centralised here so
 * the same task in two different views shows the same human
 * representation.
 *
 * Implementation note (npm supply-chain hardening, April 2026):
 * this module previously depended on ``date-fns``. The two
 * functions we used (``formatDistanceToNow`` + a fixed-pattern
 * ``format``) are 30 lines of native code against ``Intl``, and
 * dropping the dep removes one direct + ~30 transitive npm
 * packages from our publish surface. See SECURITY.md §16 for the
 * supply-chain policy that motivated this.
 */

const _RTF = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

// Detect a trailing timezone marker on an ISO-8601 string. Matches:
//   "...Z"            (UTC)
//   "...+00:00"       (offset with colon)
//   "...+0000"        (offset without colon)
//   "...-05:00"       (negative offset)
const _ZONE_SUFFIX = /(?:[zZ]|[+-]\d{2}:?\d{2})$/;

/**
 * Parse a wire-format timestamp into a Date, treating the value as UTC
 * when no timezone marker is present.
 *
 * z4j's REST API serializes timestamps via Python's
 * ``datetime.isoformat()``. When the underlying ``datetime`` instance
 * is naive (no ``tzinfo``), the wire string lacks ``Z`` / ``+00:00``,
 * and the ``Date`` constructor follows ECMA-262 by interpreting it as
 * **local time**. For an operator in EDT (UTC-4) reading a UTC-stored
 * task that just ran, that produced "in 4 hours" for a value 5 minutes
 * in the past - a confusing demo bug for anyone outside UTC.
 *
 * The defensive fix here normalises before parsing: if the string has
 * no timezone marker, we append ``Z`` so the parse is unambiguously
 * UTC. Strings that already carry a marker are passed through verbatim
 * (the marker, whatever it is, takes precedence).
 */
function _parseAsUtc(value: string | Date): Date {
  if (value instanceof Date) return value;
  return new Date(_ZONE_SUFFIX.test(value) ? value : value + "Z");
}

/**
 * Public parser: use this anywhere outside lib/format.ts that needs to
 * read a wire-format timestamp into a Date. The same UTC-default rule
 * applies (see _parseAsUtc above for the rationale).
 */
export function parseTimestamp(value: string | Date): Date {
  return _parseAsUtc(value);
}

/** Render an ISO timestamp as "5 minutes ago". */
export function formatRelative(value: string | Date | null | undefined): string {
  if (!value) return "-";
  try {
    const date = _parseAsUtc(value);
    const diffMs = date.getTime() - Date.now();
    const absSec = Math.abs(diffMs) / 1000;
    if (absSec < 45) return _RTF.format(Math.round(diffMs / 1000), "second");
    if (absSec < 2700) return _RTF.format(Math.round(diffMs / 60_000), "minute");
    if (absSec < 64_800) return _RTF.format(Math.round(diffMs / 3_600_000), "hour");
    if (absSec < 2_160_000) return _RTF.format(Math.round(diffMs / 86_400_000), "day");
    if (absSec < 31_104_000) return _RTF.format(Math.round(diffMs / 2_592_000_000), "month");
    return _RTF.format(Math.round(diffMs / 31_536_000_000), "year");
  } catch {
    return "-";
  }
}

/** Render an ISO timestamp as "2026-04-11 14:30:05" in the operator's local timezone. */
export function formatAbsolute(
  value: string | Date | null | undefined,
): string {
  if (!value) return "-";
  try {
    const d = _parseAsUtc(value);
    if (Number.isNaN(d.getTime())) return "-";
    const pad = (n: number) => n.toString().padStart(2, "0");
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    );
  } catch {
    return "-";
  }
}

/** Render a millisecond duration as "1.2s" or "230ms" or "-". */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  return `${Math.floor(ms / 3_600_000)}h ${Math.round((ms % 3_600_000) / 60_000)}m`;
}

/** Compact integer rendering: 1234 → "1.2k". */
export function formatCompact(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  if (Math.abs(value) < 1000) return value.toString();
  if (Math.abs(value) < 1_000_000) return `${(value / 1000).toFixed(1)}k`;
  if (Math.abs(value) < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  return `${(value / 1_000_000_000).toFixed(1)}B`;
}

/** "12.5%" with a sensible default for 0/0 and NaN. */
export function formatPercent(
  value: number | null | undefined,
  fractionDigits = 1,
): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "0%";
  return `${(value * 100).toFixed(fractionDigits)}%`;
}

/** Truncate a long string with an ellipsis. */
export function truncate(value: string, max = 60): string {
  if (value.length <= max) return value;
  return value.slice(0, max - 1) + "…";
}
