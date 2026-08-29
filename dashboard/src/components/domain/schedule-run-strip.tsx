/**
 * Cross-run strip: one schedule's last N fires as a row of cells, oldest on
 * the left, newest on the right, so a glance reads like a timeline.
 *
 * This is the picture behind the Health column's number. The number says
 * "3 of 5 failing"; the strip says whether those three are the tail of a
 * long clean run, a flapping schedule that fails every other fire, or a
 * schedule that has been dead for a week. Those want different responses
 * and the number cannot tell them apart.
 *
 * Deliberately not a chart: no axes, no legend, nothing that needs a
 * library. A cell per fire, colour by outcome, brightness by recency, and a
 * native tooltip per cell so the detail is one hover away without a popover.
 */
import { Link } from "@tanstack/react-router";
import type { ScheduleRunCell } from "@/hooks/use-schedules";
import type { ScheduleFireStatus } from "@/lib/api-types";
import { cn } from "@/lib/utils";

/**
 * Outcome classes for a fire status. Four buckets on purpose: an operator
 * scanning forty schedules needs "fine / broke / undecided / did not run",
 * not the fourteen-state machine the brain tracks. The full status is in
 * the tooltip.
 *
 * "failed" colours every outcome that ended badly, including fires an
 * operator marked failed during recovery and fires that timed out. The
 * Health badge beside the strip follows the circuit breaker, which counts
 * only `failed` and `acked_failed`, so the two can differ by design: the
 * strip answers "what happened", the badge answers "what will the breaker
 * do".
 */
export type Outcome = "ok" | "failed" | "pending" | "skipped";

/**
 * Exhaustive over the brain's vocabulary: adding a status to
 * `ScheduleFireStatus` without deciding its colour is a type error here.
 */
export const OUTCOME_BY_STATUS = {
  pending: "pending",
  accepted: "pending",
  delivered: "pending",
  buffered: "pending",
  buffer_stale: "pending",
  acked_success: "ok",
  terminal_completed: "ok",
  acked_failed: "failed",
  failed: "failed",
  terminal_failed: "failed",
  terminal_timeout: "failed",
  buffer_expired: "skipped",
  operator_skipped: "skipped",
  terminal_cancelled: "skipped",
} as const satisfies Record<ScheduleFireStatus, Outcome>;

/** A status this build does not know is undecided, never a success. */
export function outcomeOf(status: string): Outcome {
  return (OUTCOME_BY_STATUS as Record<string, Outcome>)[status] ?? "pending";
}

const CELL: Record<Outcome, string> = {
  ok: "bg-success",
  failed: "bg-destructive",
  pending: "bg-muted-foreground/40",
  skipped: "bg-muted-foreground/20 ring-1 ring-inset ring-muted-foreground/40",
};

const STATUS_LABEL = {
  pending: "pending",
  accepted: "accepted, awaiting dispatch",
  delivered: "delivered, awaiting result",
  buffered: "buffered, no agent online",
  buffer_stale: "buffered, definition changed since",
  acked_success: "succeeded",
  terminal_completed: "completed by recovery",
  acked_failed: "failed",
  failed: "failed to dispatch",
  terminal_failed: "failed, marked by recovery",
  terminal_timeout: "timed out",
  buffer_expired: "expired in the buffer",
  operator_skipped: "skipped by an operator",
  terminal_cancelled: "cancelled",
} as const satisfies Record<ScheduleFireStatus, string>;

export function statusLabel(status: string): string {
  return (STATUS_LABEL as Record<string, string>)[status] ?? status;
}

function formatLatency(ms: number | null): string {
  if (ms === null) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function cellTitle(cell: ScheduleRunCell): string {
  const when = new Date(cell.fired_at).toLocaleString();
  const label = statusLabel(cell.status);
  const latency = formatLatency(cell.latency_ms);
  return latency ? `${when}: ${label} in ${latency}` : `${when}: ${label}`;
}

/**
 * What the strip says about itself. Three states, because "no fires" is a
 * factual claim about the schedule and must not be made while the history
 * is still loading or after the request failed.
 */
export function stripSummary(
  cells: readonly ScheduleRunCell[] | undefined,
  error: boolean,
): string {
  if (cells === undefined) {
    return error ? "run history unavailable" : "run history not loaded yet";
  }
  if (cells.length === 0) return "no fires in the retention window";
  const failures = cells.filter((c) => outcomeOf(c.status) === "failed").length;
  return `${cells.length} recent fires, ${failures} failed`;
}

export interface ScheduleRunStripProps {
  /** Newest first, as the API returns them. undefined while unknown. */
  runs: readonly ScheduleRunCell[] | undefined;
  /** True when the request for the history failed. */
  error?: boolean;
  /** Width of the strip in cells. Missing history renders as empty slots. */
  slots?: number;
  /** Compact for table rows, roomy for a detail header. */
  size?: "sm" | "md";
  /** When set, the strip links to this schedule's detail page. */
  href?: { slug: string; scheduleId: string };
  className?: string;
}

export function ScheduleRunStrip({
  runs,
  error = false,
  slots = 20,
  size = "sm",
  href,
  className,
}: ScheduleRunStripProps) {
  const cells = runs === undefined ? undefined : runs.slice(0, slots);
  // Oldest on the left so the newest cell sits where the eye lands last.
  const ordered = [...(cells ?? [])].reverse();
  const missing = Math.max(0, slots - ordered.length);
  const dim = size === "sm" ? "h-3 w-1.5" : "h-6 w-2.5";
  const gap = size === "sm" ? "gap-px" : "gap-0.5";
  const summary = stripSummary(cells, error);

  const strip = (
    <span
      role="img"
      aria-label={summary}
      title={cells === undefined ? undefined : summary}
      className={cn(
        "inline-flex items-end",
        gap,
        href && "rounded-sm ring-offset-background transition-shadow hover:ring-2 hover:ring-ring/40 hover:ring-offset-2",
        className,
      )}
    >
      {Array.from({ length: missing }).map((_, i) => (
        <span
          key={`empty-${i}`}
          aria-hidden
          className={cn(dim, "rounded-[1px] bg-border/60")}
        />
      ))}
      {ordered.map((cell, i) => {
        const outcome = outcomeOf(cell.status);
        // The newest handful are drawn at full strength; older cells fade so
        // recency reads without a time axis. Failures never fade below 70%:
        // an old failure still has to be findable at a glance.
        const age = ordered.length - 1 - i;
        const floor = outcome === "failed" ? 0.7 : 0.35;
        const opacity = Math.max(floor, 1 - age * (0.65 / Math.max(1, slots - 1)));
        return (
          <span
            // A fire can legitimately be recorded twice under different
            // receipt generations, so fire_id alone is not a unique key.
            key={`${cell.fire_id}:${cell.fired_at}`}
            title={cellTitle(cell)}
            className={cn(dim, "rounded-[1px]", CELL[outcome])}
            style={{ opacity }}
          />
        );
      })}
    </span>
  );

  if (!href) return strip;
  return (
    <Link
      to="/projects/$slug/schedules/$scheduleId"
      params={{ slug: href.slug, scheduleId: href.scheduleId }}
      aria-label={`${summary}; open schedule`}
      className="inline-flex"
    >
      {strip}
    </Link>
  );
}
