import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

export interface PageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: LucideIcon;
  badges?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
  level?: "page" | "section";
}

/** Shared page identity and actions. Control sizes belong to their primitives. */
export function PageHeader({
  title,
  description,
  icon: Icon,
  badges,
  actions,
  className,
  level = "page",
}: PageHeaderProps) {
  const Heading = level === "page" ? "h1" : "h2";
  return (
    <div
      data-slot={level === "page" ? "page-header" : "section-header"}
      className={cn(
        "flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start",
        className,
      )}
    >
      <div className="flex min-w-0 flex-1 items-start gap-3 sm:min-w-[min(100%,16rem)]">
        {Icon && (
          <div className="flex size-8 shrink-0 items-center justify-center text-primary">
            <Icon className="size-5" aria-hidden="true" />
          </div>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Heading
              className={cn(
                "min-w-0 max-w-full break-words font-semibold leading-tight tracking-tight",
                level === "page" ? "text-2xl" : "text-lg",
              )}
            >
              {title}
            </Heading>
            {badges}
          </div>
          {description && (
            <p className="mt-1 min-h-10 text-sm text-muted-foreground sm:min-h-0">
              {description}
            </p>
          )}
        </div>
      </div>
      {actions && (
        <div
          data-slot="page-actions"
          className="flex max-w-full shrink-0 flex-wrap items-center gap-2 sm:pt-1 [&>div]:max-w-full [&>div]:flex-wrap"
        >
          {actions}
        </div>
      )}
    </div>
  );
}
