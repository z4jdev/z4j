import { Search, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export interface FilterToolbarProps {
  /** Search-input value (controlled). */
  searchValue: string;
  /** Search-input onChange handler. */
  onSearchChange: (value: string) => void;
  /** Search-input placeholder. */
  searchPlaceholder?: string;
  /** Slot for one or more `<Select>` filter dropdowns. They render to the
   * right of the search input, in source order. Each Select should have
   * its own width class (typically `w-36` or `w-44`). */
  filters?: React.ReactNode;
  /** Slot for trailing actions (Export menu, etc.). Sits right of the
   * Clear button. */
  trailing?: React.ReactNode;
  /** Show a "Clear" button on the far right when there are active filters. */
  onClear?: () => void;
  /** Number of active filters to badge alongside the Clear button. */
  activeFilterCount?: number;
  className?: string;
}

/**
 * Canonical filter toolbar shared by every list page (commands,
 * schedules, tasks, agents, queues, workers, audit). Stops every
 * page from rolling its own `flex flex-row gap-3` + leading-icon
 * Input + ad-hoc Select widths.
 *
 * Visual contract:
 *   - Search Input has a leading magnifying-glass icon. Always 36px
 *     tall (the default Input height; matches the Selects + Clear
 *     button on the same row).
 *   - Filter Selects sit to the right of the search input, each
 *     `shrink-0` so they don't collapse.
 *   - Clear button is invisible-but-reserved when no filters active
 *     (no layout shift when the badge appears).
 *   - Trailing slot for things like the Export dropdown menu.
 *
 * Don't render an ad-hoc filter row inside a route file. Add the
 * dropdown into the `filters` slot. If a route needs something this
 * component doesn't support, extend the component, don't fork it.
 */
export function FilterToolbar({
  searchValue,
  onSearchChange,
  searchPlaceholder = "Search...",
  filters,
  trailing,
  onClear,
  activeFilterCount = 0,
  className,
}: FilterToolbarProps) {
  return (
    <div className={cn("flex flex-col gap-3 sm:flex-row sm:items-center", className)}>
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder={searchPlaceholder}
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9"
          aria-label="Search"
        />
      </div>
      {filters}
      {/* Clear is rendered ONLY when there are active filters. Older
       * version reserved space-when-invisible to avoid layout shift,
       * but that left a permanent ~75px gap on the right of every
       * filter row, so the toolbar never lined up with the card
       * below it. The shift on first filter activation is minimal
       * and only affects the search input width. */}
      {onClear !== undefined && activeFilterCount > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="h-9 shrink-0 gap-1 text-xs text-muted-foreground"
          onClick={onClear}
        >
          <X className="size-3" />
          Clear
          <Badge variant="secondary" className="ml-0.5 px-1.5 py-0 text-[10px]">
            {activeFilterCount}
          </Badge>
        </Button>
      )}
      {trailing}
    </div>
  );
}
