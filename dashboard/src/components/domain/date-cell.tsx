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
  compact = false,
}: {
  value: string | Date | null | undefined;
  className?: string;
  /**
   * One line: the relative time, with the absolute timestamp as the hover
   * title. For dense tables, where the two-line form wrapped into four lines
   * inside a narrow column and doubled the row height of every table that
   * shows two dates.
   */
  compact?: boolean;
}) {
  if (!value) return <span className="text-muted-foreground">-</span>;
  if (compact) {
    return (
      <span
        className={["whitespace-nowrap text-xs", className].filter(Boolean).join(" ")}
        title={formatAbsolute(value)}
      >
        {formatRelative(value)}
      </span>
    );
  }
  return (
    <div className={className}>
      <div className="whitespace-nowrap text-xs">{formatRelative(value)}</div>
      <div className="whitespace-nowrap text-[11px] text-muted-foreground">
        {formatAbsolute(value)}
      </div>
    </div>
  );
}
