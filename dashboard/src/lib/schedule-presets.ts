/** These are descriptions of explicit expressions, not a competing scheduler. */
export const CRON_PRESETS = [
  { label: "Every 5 minutes", expression: "*/5 * * * *" },
  { label: "Every hour", expression: "0 * * * *" },
  { label: "Daily at 09:00", expression: "0 9 * * *" },
  { label: "Weekdays at 09:00", expression: "0 9 * * 1-5" },
] as const;
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
): string {
  if (kind === "cron") {
    const preset = CRON_PRESETS.find((p) => p.expression === expression.trim());
    return preset
      ? `${preset.label} · ${timezone || "UTC"}`
      : `Custom cron · ${timezone || "UTC"}`;
  }
  if (kind === "interval") return `Repeat every ${expression || "…"}`;
  if (kind === "clocked")
    return `Run once · ${expression || "choose a timestamp with a UTC offset"}`;
  return `Solar event · ${expression || "choose an event and location"}`;
}
