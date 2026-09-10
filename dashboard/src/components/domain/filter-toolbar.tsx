import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { Search, X } from "lucide-react";

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

/** Search is always first and 320px on desktop, full-width on mobile.
 * Filters wrap after it. Clearing filters never changes the search width.
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
    <div
      data-slot="filter-toolbar"
      role="search"
      className={cn("flex min-h-9 flex-wrap items-center gap-2", className)}
    >
      <div className="relative w-full shrink-0 sm:w-80">
        <Search
          aria-hidden="true"
          className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          type="search"
          placeholder={searchPlaceholder}
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9"
          aria-label="Search"
        />
      </div>
      {filters}
      {onClear !== undefined && (
        <Button
          variant="ghost"
          size="sm"
          className="shrink-0 text-muted-foreground"
          disabled={activeFilterCount === 0}
          onClick={onClear}
        >
          <X className="size-3" />
          Clear
          {activeFilterCount > 0 && (
            <Badge
              variant="secondary"
              className="ml-0.5 px-1.5 py-0 text-[10px]"
            >
              {activeFilterCount}
            </Badge>
          )}
        </Button>
      )}
      {trailing}
    </div>
  );
}
