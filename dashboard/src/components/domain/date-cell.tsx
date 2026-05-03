/**
 * Two-line date display for table cells.
 *
 * Line 1: Relative time (e.g., "2 minutes ago")
 * Line 2: Absolute datetime (e.g., "2026-04-13 18:01:54")
 *
 * Used across all data tables for consistent date rendering.
 */
import { formatRelative, formatAbsolute } from "@/lib/format";

export function DateCell({
  value,
  className,
}: {
  value: string | Date | null | undefined;
  className?: string;
}) {
  if (!value) return <span className="text-muted-foreground">-</span>;

  return (
    <div className={className}>
      <div className="text-xs">{formatRelative(value)}</div>
      <div className="text-[11px] text-muted-foreground">
        {formatAbsolute(value)}
      </div>
    </div>
  );
}
