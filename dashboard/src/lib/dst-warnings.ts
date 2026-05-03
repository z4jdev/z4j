/**
 * DST fall-back / spring-forward warnings for cron schedules.
 *
 * Implements docs/SCHEDULER.md §5.5: the dashboard schedule-create
 * form should warn the operator when their cron + timezone
 * combination would produce a fall-back duplicate fire (the day
 * has 25 hours, and a wall-clock time inside the ambiguous window
 * fires for both the DST and the standard-time interpretation) or
 * a spring-forward gap (a wall-clock time that does not exist on
 * spring-forward day).
 *
 * The check runs entirely in the browser using ``Intl.DateTimeFormat``
 * to detect timezone offset transitions over the next year. No
 * server round-trip; no croniter dep in JS.
 *
 * The cron parser here understands the 5-field syntax
 * (``minute hour dom month dow``) and only matches against the
 * HOUR field - which is what determines whether a fire lands
 * inside the ambiguous window. We intentionally don't ship a
 * full cron evaluator; the goal is to catch the 99% case (operator
 * picks ``0 2 * * *`` in a DST-observing timezone) without
 * dragging in a heavy parser.
 */

export interface DstWarning {
  level: "warning" | "info";
  message: string;
}

/**
 * Compute DST warnings for the (cron, timezone) pair, if any.
 *
 * Returns ``null`` when there's nothing to warn about - a non-cron
 * kind, a UTC timezone, a cron that fires only outside the
 * ambiguous DST windows, or an unparseable expression (we don't
 * second-guess the croniter parser - syntactic errors get caught
 * at server validation time).
 */
export function computeDstWarning(
  kind: string,
  expression: string,
  timezone: string,
): DstWarning | null {
  if (kind !== "cron") return null;
  if (!timezone || timezone === "UTC" || timezone === "Etc/UTC") return null;

  // Accept both 5-field (``m h dom month dow``) and 6-field
  // (``m h dom month dow s``) cron expressions. The hour field is
  // index 1 either way; the trailing seconds field on a 6-field
  // expression doesn't affect DST analysis (DST transitions
  // happen on hour boundaries).
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5 && fields.length !== 6) return null;
  const hourField = fields[1];
  if (!hourField) return null;

  const transitions = findDstTransitions(timezone, 12);
  if (transitions.length === 0) {
    // Timezone doesn't observe DST in the next 12 months
    // (e.g. Asia/Tokyo, America/Phoenix) - no risk.
    return null;
  }

  const fallBack = transitions.find((t) => t.kind === "fall_back");
  const springForward = transitions.find((t) => t.kind === "spring_forward");

  // Hours that the cron would fire in (in the timezone's local clock).
  const hours = expandHourField(hourField);
  if (hours.length === 0) return null;

  // Fall-back: clocks repeat 02:00 -> 01:00 on most US zones, or
  // 03:00 -> 02:00 on most EU zones. The ambiguous hour is the
  // one BEFORE the transition. Any cron firing inside that hour
  // will fire twice.
  if (fallBack) {
    const ambig = fallBack.ambiguousHour;
    if (hours.includes(ambig)) {
      const dateStr = fallBack.transitionAt.toISOString().slice(0, 10);
      return {
        level: "warning",
        message:
          `On ${dateStr}, ${timezone} ends DST and clocks repeat from ` +
          `${pad2(ambig + 1)}:00 back to ${pad2(ambig)}:00. ` +
          `This schedule fires at ${pad2(ambig)}:00, so it will fire ` +
          `TWICE on that day. To pick a non-ambiguous time, use any ` +
          `hour outside ${pad2(ambig)}:00–${pad2(ambig + 1)}:00 ` +
          `(e.g. ${pad2((ambig + 2) % 24)}:00).`,
      };
    }
  }

  // Spring-forward: clocks skip 02:00 -> 03:00 on most US zones,
  // 02:00 -> 03:00 on most EU zones. A cron firing inside that
  // gap (e.g. ``30 2 * * *``) will not fire on the transition
  // day. We surface this as ``info`` because the next-on-time
  // semantics from §5.5 mean the fire just shifts forward to
  // the first valid wall-clock time - it isn't lost.
  if (springForward) {
    const skipped = springForward.skippedHour;
    if (hours.includes(skipped)) {
      const dateStr = springForward.transitionAt.toISOString().slice(0, 10);
      return {
        level: "info",
        message:
          `On ${dateStr}, ${timezone} starts DST and the wall clock ` +
          `skips from ${pad2(skipped)}:00 directly to ${pad2(skipped + 1)}:00. ` +
          `This schedule fires at ${pad2(skipped)}:00. The fire is not ` +
          `lost - z4j-scheduler shifts it to the next valid wall-clock ` +
          `time. Pick an hour outside ${pad2(skipped)}:00–${pad2(skipped + 1)}:00 ` +
          `if you want to avoid the shift.`,
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface DstTransition {
  kind: "fall_back" | "spring_forward";
  transitionAt: Date;       // UTC instant of the transition
  ambiguousHour: number;    // (fall_back only) wall-clock hour that fires twice
  skippedHour: number;      // (spring_forward only) wall-clock hour that's skipped
}

/**
 * Walk forward N months from now, sampling the timezone's UTC
 * offset every hour to find DST transitions.
 *
 * Returns transitions in chronological order. Empty when the
 * timezone doesn't observe DST.
 */
function findDstTransitions(timezone: string, monthsAhead: number): DstTransition[] {
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
      const localHour = getTzWallHour(timezone, new Date(cursor.getTime() - 3600_000));
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

function formatToParts(date: Date, timezone: string): FormattedParts {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
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
  const set = new Set<number>();
  for (const term of field.split(",")) {
    expandOneTerm(term, set);
  }
  return Array.from(set).sort((a, b) => a - b);
}

function expandOneTerm(term: string, into: Set<number>): void {
  let stepDivisor = 1;
  let base = term;
  if (term.includes("/")) {
    const [b, s] = term.split("/", 2);
    base = b;
    const parsed = parseInt(s, 10);
    if (!isNaN(parsed) && parsed >= 1 && parsed <= 23) {
      stepDivisor = parsed;
    }
  }
  let start = 0;
  let end = 23;
  if (base === "*") {
    // start/end stay at full range
  } else if (base.includes("-")) {
    const [a, b] = base.split("-", 2);
    const ai = parseInt(a, 10);
    const bi = parseInt(b, 10);
    if (isNaN(ai) || isNaN(bi)) return;
    start = ai;
    end = bi;
  } else {
    const v = parseInt(base, 10);
    if (isNaN(v)) return;
    start = end = v;
  }
  for (let i = start; i <= end; i++) {
    if ((i - start) % stepDivisor === 0) {
      into.add(i);
    }
  }
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}
