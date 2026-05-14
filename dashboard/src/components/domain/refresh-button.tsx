import { RefreshCw } from "lucide-react";
import { Button, type ButtonProps } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface RefreshButtonProps {
  /** Refetch handler. Wired to onClick. */
  onRefresh: () => void;
  /** True while a refetch is in flight. Spins the icon and disables the button. */
  pending?: boolean;
  /** Override the visible label. Defaults to "Refresh". */
  label?: string;
  /** Override the button variant. Defaults to "outline" (the canonical look in
   * the page-header actions slot). */
  variant?: ButtonProps["variant"];
  className?: string;
}

/**
 * Canonical refresh button used in every list-page PageHeader.actions slot.
 * Replaces 8+ near-identical inline copies of:
 *
 *   <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
 *     <RefreshCw className={isFetching ? "size-4 animate-spin" : "size-4"} />
 *     Refresh
 *   </Button>
 *
 * The PageHeader.actions CSS enforcement already locks the button to the
 * canonical h-8 / text-xs / px-3 chip shape, so this component doesn't
 * need to hard-code size="sm" -- but we set it anyway as a hint for any
 * caller that uses this OUTSIDE a PageHeader (e.g. inline beside a
 * filter row).
 */
export function RefreshButton({
  onRefresh,
  pending = false,
  label = "Refresh",
  variant = "outline",
  className,
}: RefreshButtonProps) {
  return (
    <Button
      variant={variant}
      size="sm"
      onClick={onRefresh}
      disabled={pending}
      className={className}
      aria-label={label}
    >
      <RefreshCw className={cn("size-4", pending && "animate-spin")} />
      {label}
    </Button>
  );
}
