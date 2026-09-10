import { Button, type ButtonProps } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { RefreshCw } from "lucide-react";

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

/** Shared refresh action, including its pending state. */
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
