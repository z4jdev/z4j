import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export interface PageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: LucideIcon;
  /** Pills shown inline with the title (e.g. "read-only", "admin only", status). */
  badges?: React.ReactNode;
  /** Right-aligned action area (buttons, links). */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * Canonical page header used by every page (settings + project pages).
 *
 * Visual contract:
 *   - Icon (optional) is rendered in a soft-bg rounded square on the
 *     left so the eye lands on it consistently.
 *   - Title is `text-lg font-semibold`. Badges sit inline with the
 *     title (they belong to the title, not the description).
 *   - Description is `text-sm text-muted-foreground`. ONE short
 *     sentence. Long explanatory paragraphs belong in a notice
 *     banner BELOW the header, not inside it.
 *   - Actions sit on the far right and stay vertically centered
 *     against the title block.
 *
 * **Action sizing is enforced.** Every Button / DropdownMenuTrigger /
 * link inside the `actions` slot is forced to small-button shape via
 * the `[&_[data-slot=button]]:h-8 ...` selectors on the wrapper.
 * This means a caller can pass `<Button>New agent</Button>` without
 * `size="sm"` and the button still renders at the canonical 32px
 * height to match every other page-header action in the dashboard.
 * The convention is "every page-header action is small" -- enforced
 * here so it cannot drift out of sync ever again.
 *
 * Don't render your own ad-hoc header div. If you need something
 * this component doesn't support, extend it - don't fork it.
 */
export function PageHeader({
  title,
  description,
  icon: Icon,
  badges,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-4 sm:flex-row sm:items-start",
        className,
      )}
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        {Icon && (
          <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted/60 text-muted-foreground">
            <Icon className="size-5" aria-hidden="true" />
          </div>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold leading-tight">{title}</h2>
            {badges}
          </div>
          {description && (
            <p className="mt-1 text-sm text-muted-foreground">
              {description}
            </p>
          )}
        </div>
      </div>
      {actions && (
        <div
          className={cn(
            "flex shrink-0 items-center gap-2 sm:pt-1",
            // Enforced canonical sizing for every action element.
            // `data-slot="button"` is set by the Button component so this
            // also catches DropdownMenuTrigger asChild + Dialog triggers
            // that wrap a Button. Order matters: padding/gap/text first,
            // then height, so any cva default in the child loses.
            "[&_[data-slot=button]]:gap-1.5",
            "[&_[data-slot=button]]:px-3",
            "[&_[data-slot=button]]:has-[>svg]:px-2.5",
            "[&_[data-slot=button]]:text-xs",
            "[&_[data-slot=button]]:h-8",
            "[&_[data-slot=button]]:rounded-md",
            // Lucide icons inside actions are always 14px (size-3.5)
            // so the icon doesn't make the chip-like buttons feel
            // top-heavy. Matches the `size="sm"` button's intrinsic
            // svg sizing.
            "[&_[data-slot=button]_svg:not([class*='size-'])]:size-3.5",
            // Same enforcement for SelectTrigger so dropdown filter chips
            // line up with the buttons (both at 32px / h-8). Without this
            // a `<Select>` next to a `<Button>` lands 4px taller and the
            // header looks visually misaligned (Trends "Last 24 hours"
            // beside Refresh was the canonical example).
            "[&_[data-slot=select-trigger]]:h-8",
            "[&_[data-slot=select-trigger]]:px-3",
            "[&_[data-slot=select-trigger]]:py-0",
            "[&_[data-slot=select-trigger]]:text-xs",
            "[&_[data-slot=select-trigger]]:gap-1.5",
            "[&_[data-slot=select-trigger]_svg]:size-3.5",
          )}
        >
          {actions}
        </div>
      )}
    </div>
  );
}
