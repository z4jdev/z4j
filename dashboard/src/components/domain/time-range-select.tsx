import { Clock } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export interface TimeRangeOption<T extends string> {
  value: T;
  label: string;
}

export interface TimeRangeSelectProps<T extends string> {
  value: T;
  onValueChange: (value: T) => void;
  options: ReadonlyArray<TimeRangeOption<T>>;
  /** Override the default trigger width. Rarely needed -- only for
   * very long labels. */
  className?: string;
  "aria-label"?: string;
}

/**
 * Canonical time-range / time-window picker used in page headers.
 *
 * Every page that lets the operator pick "Last 1 hour / 6 hours /
 * 24 hours / 3 days / 7 days" (Overview, Trends, anything future)
 * renders this component so they're visually identical: same clock
 * icon, same width, same chevron and the same control sizing. The
 * SelectTrigger below owns its size; PageHeader.actions only lays it out.
 *
 * Value vocabularies are generic on T so consumers stay typed --
 * Overview uses ``"1" | "24" | "168" | ...`` (hour-count strings)
 * while Trends uses ``"1h" | "24h" | "7d"`` (Prometheus-style
 * durations). Both render identically.
 */
export function TimeRangeSelect<T extends string>({
  value,
  onValueChange,
  options,
  className = "w-44",
  ...aria
}: TimeRangeSelectProps<T>) {
  return (
    <Select value={value} onValueChange={(v) => onValueChange(v as T)}>
      <SelectTrigger className={className} aria-label={aria["aria-label"]}>
        <Clock className="size-4 opacity-60" aria-hidden="true" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((opt) => (
          <SelectItem key={opt.value} value={opt.value}>
            {opt.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
