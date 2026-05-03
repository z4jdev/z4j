import { useMemo, useState } from "react";
import type { TrendBucket } from "@/hooks/use-trends";
import { cn } from "@/lib/utils";

/**
 * Stacked-line trend chart for task outcomes, rendered as native
 * SVG so we don't have to add a charting library to the bundle.
 * Two series: success (green) + failure (red). Retry / revoked
 * are surfaced via the tooltip but omitted from the line set to
 * keep the chart legible.
 */
export function TrendChart({
  series,
  height = 240,
}: {
  series: TrendBucket[];
  height?: number;
}) {
  const [hover, setHover] = useState<number | null>(null);

  const { width, padding, successPath, failurePath, xs, maxY } = useMemo(() => {
    const w = 720;
    const pad = { top: 16, right: 16, bottom: 32, left: 40 };
    if (series.length === 0) {
      return {
        width: w,
        padding: pad,
        successPath: "",
        failurePath: "",
        xs: [] as number[],
        maxY: 0,
      };
    }
    const maxY = Math.max(
      1,
      ...series.map((b) => Math.max(b.success, b.failure)),
    );
    const innerW = w - pad.left - pad.right;
    const innerH = height - pad.top - pad.bottom;
    const xOf = (i: number) =>
      pad.left +
      (series.length === 1 ? innerW / 2 : (i / (series.length - 1)) * innerW);
    const yOf = (v: number) => pad.top + innerH - (v / maxY) * innerH;
    const toPath = (getter: (b: TrendBucket) => number) =>
      series
        .map((b, i) => `${i === 0 ? "M" : "L"}${xOf(i)},${yOf(getter(b))}`)
        .join(" ");
    return {
      width: w,
      padding: pad,
      successPath: toPath((b) => b.success),
      failurePath: toPath((b) => b.failure),
      xs: series.map((_, i) => xOf(i)),
      maxY,
    };
  }, [series, height]);

  if (series.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
        no data in this window yet
      </div>
    );
  }

  const innerH = height - padding.top - padding.bottom;
  const tickCount = 4;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) => {
    const v = Math.round((maxY / tickCount) * i);
    const y = padding.top + innerH - (v / maxY) * innerH;
    return { v, y };
  });

  return (
    <div className="relative w-full">
      <svg
        role="img"
        aria-label="Task outcome trend"
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full"
        onMouseLeave={() => setHover(null)}
      >
        {/* Horizontal grid */}
        {ticks.map((t) => (
          <g key={t.v}>
            <line
              x1={padding.left}
              x2={width - padding.right}
              y1={t.y}
              y2={t.y}
              className="stroke-border"
              strokeDasharray="2 3"
            />
            <text
              x={padding.left - 6}
              y={t.y + 3}
              textAnchor="end"
              className="fill-muted-foreground text-[10px]"
            >
              {t.v}
            </text>
          </g>
        ))}

        {/* Success + failure lines */}
        <path
          d={successPath}
          fill="none"
          strokeWidth={2}
          className="stroke-emerald-500"
        />
        <path
          d={failurePath}
          fill="none"
          strokeWidth={2}
          className="stroke-red-500"
        />

        {/* Hover overlay - one invisible rect per bucket */}
        {xs.map((x, i) => {
          const leftEdge =
            i === 0 ? padding.left : (xs[i - 1]! + x) / 2;
          const rightEdge =
            i === xs.length - 1 ? width - padding.right : (x + xs[i + 1]!) / 2;
          return (
            <rect
              key={i}
              x={leftEdge}
              width={Math.max(1, rightEdge - leftEdge)}
              y={padding.top}
              height={innerH}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
            />
          );
        })}

        {/* Hover vertical line + dots */}
        {hover !== null && (
          <g>
            <line
              x1={xs[hover]}
              x2={xs[hover]}
              y1={padding.top}
              y2={height - padding.bottom}
              className="stroke-muted-foreground/40"
            />
          </g>
        )}

        {/* X-axis labels - first, middle, last */}
        {Array.from(
          new Set([0, Math.floor(series.length / 2), series.length - 1]),
        )
          .map((i) => (
            <text
              key={i}
              x={xs[i]}
              y={height - 10}
              textAnchor="middle"
              className="fill-muted-foreground text-[10px]"
            >
              {formatTick(series[i]!.t)}
            </text>
          ))}
      </svg>

      {/* Tooltip */}
      {hover !== null && (
        <TrendTooltip bucket={series[hover]!} />
      )}

      {/* Legend */}
      <div className="mt-2 flex items-center justify-center gap-4 text-xs text-muted-foreground">
        <LegendDot className="bg-emerald-500" label="success" />
        <LegendDot className="bg-red-500" label="failure" />
      </div>
    </div>
  );
}

function LegendDot({ className, label }: { className: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={cn("size-2.5 rounded-full", className)} />
      {label}
    </span>
  );
}

function TrendTooltip({ bucket }: { bucket: TrendBucket }) {
  return (
    <div className="pointer-events-none absolute left-1/2 top-0 -translate-x-1/2 rounded-md border bg-popover px-3 py-2 text-xs shadow-sm">
      <div className="font-mono text-muted-foreground">
        {formatTooltipTime(bucket.t)}
      </div>
      <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5">
        <span>success</span>
        <span className="text-right font-mono">{bucket.success}</span>
        <span>failure</span>
        <span className="text-right font-mono">{bucket.failure}</span>
        {bucket.retry > 0 && (
          <>
            <span>retry</span>
            <span className="text-right font-mono">{bucket.retry}</span>
          </>
        )}
        {bucket.revoked > 0 && (
          <>
            <span>revoked</span>
            <span className="text-right font-mono">{bucket.revoked}</span>
          </>
        )}
        {bucket.avg_runtime_ms !== null && (
          <>
            <span className="text-muted-foreground">avg runtime</span>
            <span className="text-right font-mono text-muted-foreground">
              {formatMs(bucket.avg_runtime_ms)}
            </span>
          </>
        )}
      </div>
    </div>
  );
}

// Match a trailing timezone marker (Z / ±HH:MM / ±HHMM). When the
// backend serializes a naive Python datetime via isoformat() the
// marker is missing, and the JS Date constructor would interpret it
// as local time - producing tick labels that are off by the operator's
// UTC offset. See lib/format.ts for the same fix in the global formatters.
const _ZONE_SUFFIX = /(?:[zZ]|[+-]\d{2}:?\d{2})$/;
function _parseAsUtc(iso: string): Date {
  return new Date(_ZONE_SUFFIX.test(iso) ? iso : iso + "Z");
}

function formatTick(iso: string): string {
  const d = _parseAsUtc(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatTooltipTime(iso: string): string {
  const d = _parseAsUtc(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}
