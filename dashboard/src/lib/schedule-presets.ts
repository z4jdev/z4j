/** These are descriptions of explicit expressions, not a competing scheduler. */
export interface CronPreset {
  label: string;
  expression: string;
}

/**
 * Schedulers whose cron weekday field numbers Monday 0 through Sunday 6:
 * APScheduler 3.x (``CronTrigger.from_crontab``) and arq. Every other
 * scheduler follows crontab, where Sunday is 0 and Monday is 1, so the same
 * ``1-5`` means Monday to Friday there and Tuesday to Saturday here.
 */
const MONDAY_ZERO_SCHEDULERS: ReadonlySet<string> = new Set([
  "apscheduler",
  "arq-cron",
]);

/** The cron presets, written in ``scheduler``'s weekday numbering. */
export function cronPresetsFor(scheduler: string): readonly CronPreset[] {
  const weekdays = MONDAY_ZERO_SCHEDULERS.has(scheduler) ? "0-4" : "1-5";
  return [
    { label: "Every 5 minutes", expression: "*/5 * * * *" },
    { label: "Every hour", expression: "0 * * * *" },
    { label: "Daily at 09:00", expression: "0 9 * * *" },
    { label: "Weekdays at 09:00", expression: `0 9 * * ${weekdays}` },
  ];
}

export const KIND_LABELS = {
  cron: "Calendar (cron)",
  interval: "Repeating interval",
  clocked: "Once at a specific time",
  solar: "Solar event",
} as const;
export function scheduleSummary(
  kind: string,
  expression: string,
  timezone: string,
  scheduler: string,
): string {
  if (kind === "cron") {
    const preset = cronPresetsFor(scheduler).find(
      (p) => p.expression === expression.trim(),
    );
    return preset
      ? `${preset.label} · ${timezone || "UTC"}`
      : `Custom cron · ${timezone || "UTC"}`;
  }
  if (kind === "interval") return `Repeat every ${expression || "…"}`;
  if (kind === "clocked")
    return `Run once · ${expression || "choose a timestamp with a UTC offset"}`;
  return `Solar event · ${expression || "choose an event and location"}`;
}
