/**
 * Consistent relative dates, with an absolute timestamp on hover.
 * Set compact=false to also display the absolute datetime on a second line.
 */
import { formatAbsolute, formatRelative } from "@/lib/format";

export function DateCell({
  value,
  className,
  compact = true,
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
        className={["whitespace-nowrap text-xs", className]
          .filter(Boolean)
          .join(" ")}
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
