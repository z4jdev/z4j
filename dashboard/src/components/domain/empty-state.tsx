import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      data-slot="empty-state"
      className={cn(
        "flex min-h-[260px] flex-col items-center justify-center gap-3 panel-surface p-10 text-center",
        className,
      )}
    >
      {Icon && (
        <div className="flex size-12 items-center justify-center rounded-full bg-muted">
          <Icon className="size-5 text-muted-foreground" />
        </div>
      )}
      <h3 className="text-base font-semibold">{title}</h3>
      {description && (
        <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
      )}
      {action}
    </div>
  );
}
