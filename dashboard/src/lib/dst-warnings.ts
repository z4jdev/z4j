/**
 * Conditional DST guidance for cron schedule editors.
 *
 * The browser scans timezone offsets over the next year and checks a limited
 * numeric hour-field grammar. It does not evaluate minutes, calendar fields,
 * seconds, or a scheduler's DST policy, so it cannot predict a particular fire.
 */

export interface DstWarning {
  level: "warning" | "info";
  message: string;
}

/**
 * Return a conditional warning when selected hours are near a detected DST
 * transition. Null means no warning from this limited check, not proof that
 * the expression is valid or unaffected by DST. Full validation is server-side.
 */
export function computeDstWarning(
  kind: string,
  expression: string,
  timezone: string,
): DstWarning | null {
  if (kind !== "cron") return null;
  if (!timezone || timezone === "UTC" || timezone === "Etc/UTC") return null;

  // Five fields, or croniter's trailing-seconds sixth field. Only the
  // numeric hour field is interpreted here; calendar fields remain unchecked.
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5 && fields.length !== 6) return null;
  const hours = expandHourField(fields[1]);
  if (hours.length === 0) return null;
  let transitions: DstTransition[];
  try {
    transitions = findDstTransitions(timezone, 12);
  } catch (error) {
    if (error instanceof RangeError) return null; // unknown timezone
    throw error;
  }
  if (transitions.length === 0) return null;

  const fallBack = transitions.find((t) => t.kind === "fall_back");
  const springForward = transitions.find((t) => t.kind === "spring_forward");

  if (fallBack && hours.includes(fallBack.ambiguousHour)) {
    return {
      level: "warning",
      message:
        `The selected hours overlap repeated local times near a DST change in ${timezone}. ` +
        `If the calendar fields match a transition day, a scheduled time may occur twice. ` +
        `This hour-only check does not predict a firing date or minute; actual execution ` +
        `depends on the scheduler's DST policy. Review upcoming runs or choose another hour.`,
    };
  }
  if (springForward && hours.includes(springForward.skippedHour)) {
    return {
      level: "info",
      message:
        `The selected hours overlap a local-time gap near a DST change in ${timezone}. ` +
        `If the calendar fields match a transition day, a scheduled time may not exist. ` +
        `This hour-only check does not predict a firing date or minute; whether a fire ` +
        `is skipped or shifted depends on the scheduler. Review upcoming runs.`,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface DstTransition {
  kind: "fall_back" | "spring_forward";
  transitionAt: Date; // UTC instant of the transition
  ambiguousHour: number; // (fall_back only) wall-clock hour that fires twice
  skippedHour: number; // (spring_forward only) wall-clock hour that's skipped
}

/**
 * Walk forward N months from now, sampling the timezone's UTC
 * offset every hour to find DST transitions.
 *
 * Returns transitions in chronological order. Empty when the
 * timezone doesn't observe DST.
 */
function findDstTransitions(
  timezone: string,
  monthsAhead: number,
): DstTransition[] {
  let prevOffset: number | null = null;
  const out: DstTransition[] = [];
  const now = new Date();
  const horizon = new Date(now);
  horizon.setMonth(horizon.getMonth() + monthsAhead);

  // Sample every hour. ~720 samples per month = 8640 per year - cheap
  // for the form's debounced re-render; only runs when expression /
  // timezone change.
  const cursor = new Date(now);
  while (cursor < horizon) {
    const offset = getTzOffsetMinutes(timezone, cursor);
    if (prevOffset !== null && offset !== prevOffset) {
      // Transition. Positive delta = DST starts (clock springs forward),
      // negative delta = DST ends (clock falls back).
      // The PREVIOUS sample is just before the transition; CURRENT is
      // just after. We use cursor (just after) as the transition
      // instant, accurate to within an hour.
      const isSpringForward = offset > prevOffset;
      const localHour = getTzWallHour(
        timezone,
        new Date(cursor.getTime() - 3600_000),
      );
      out.push({
        kind: isSpringForward ? "spring_forward" : "fall_back",
        transitionAt: new Date(cursor),
        // For fall-back the ambiguous wall-clock hour is the hour
        // we just rolled OUT of (e.g. 02:00 in Europe). For
        // spring-forward the SKIPPED hour is the hour we just
        // rolled INTO (the wall clock jumped over).
        ambiguousHour: isSpringForward ? -1 : localHour,
        skippedHour: isSpringForward ? (localHour + 1) % 24 : -1,
      });
    }
    prevOffset = offset;
    cursor.setUTCHours(cursor.getUTCHours() + 1);
  }
  return out;
}

/**
 * Return the UTC offset (in minutes) for ``date`` interpreted in
 * ``timezone``. Negative offsets mean west of UTC.
 *
 * Uses ``Intl.DateTimeFormat`` to format the date with offset and
 * parses the result. Available in every modern browser; no library
 * needed.
 */
function getTzOffsetMinutes(timezone: string, date: Date): number {
  // Format in two timezones and diff. Fast, precise, no parsing of
  // localized strings beyond the ISO bits.
  const utc = formatToParts(date, "UTC");
  const tz = formatToParts(date, timezone);
  const utcMs = partsToUtc(utc);
  const tzMs = partsToUtc(tz);
  return Math.round((tzMs - utcMs) / 60_000);
}

function getTzWallHour(timezone: string, date: Date): number {
  const parts = formatToParts(date, timezone);
  return parseInt(parts.hour, 10);
}

interface FormattedParts {
  year: string;
  month: string;
  day: string;
  hour: string;
  minute: string;
  second: string;
}

const dateTimeFormatters = new Map<string, Intl.DateTimeFormat>();

function getDateTimeFormatter(timezone: string): Intl.DateTimeFormat {
  const existing = dateTimeFormatters.get(timezone);
  if (existing) return existing;

  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  dateTimeFormatters.set(timezone, formatter);
  return formatter;
}

function formatToParts(date: Date, timezone: string): FormattedParts {
  const fmt = getDateTimeFormatter(timezone);
  const parts = fmt.formatToParts(date);
  const out: Record<string, string> = {};
  for (const p of parts) {
    if (p.type !== "literal") {
      out[p.type] = p.value;
    }
  }
  // Hour can come back as "24" instead of "00" on some platforms.
  if (out.hour === "24") out.hour = "00";
  return out as unknown as FormattedParts;
}

function partsToUtc(p: FormattedParts): number {
  return Date.UTC(
    parseInt(p.year, 10),
    parseInt(p.month, 10) - 1,
    parseInt(p.day, 10),
    parseInt(p.hour, 10),
    parseInt(p.minute, 10),
    parseInt(p.second, 10),
  );
}

/**
 * Expand the cron HOUR field into the concrete list of hours it
 * matches. Supports the 90% subset of crontab(5) syntax:
 *
 * - ``*`` -> 0..23
 * - integer -> [N]
 * - comma list ``1,3,5`` -> [1, 3, 5]
 * - range ``1-4`` -> [1, 2, 3, 4]
 * - step ``* /2`` (no space) -> [0, 2, ..., 22]
 * - step over range ``1-10/2`` -> [1, 3, 5, 7, 9]
 *
 * We don't support week-aware modifiers (``L``, ``#``) - those
 * appear only in the day-of-week field, not hour.
 */
function expandHourField(field: string): number[] {
  const values = new Set<number>();
  for (const term of field.split(",")) {
    if (!/^(?:\*|\d{1,2}(?:-\d{1,2})?)(?:\/[1-9]\d*)?$/.test(term)) return [];
    const [base, stepText] = term.split("/");
    const step = stepText === undefined ? 1 : Number(stepText);
    if (!Number.isSafeInteger(step) || step < 1) return [];
    let start = 0;
    let end = 23;
    if (base !== "*") {
      const parts = base.split("-").map(Number);
      start = parts[0];
      end = parts[1] ?? (stepText === undefined ? start : 23);
    }
    if (start < 0 || start > 23 || end < start || end > 23) return [];
    for (let hour = start; hour <= end; hour += step) values.add(hour);
  }
  return [...values].sort((a, b) => a - b);
}
