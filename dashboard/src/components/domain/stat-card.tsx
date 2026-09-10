import { Link } from "@tanstack/react-router";
import type { LucideIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export interface StatCardProps {
  label: string;
  value: string | number;
  hint?: string;
  icon?: LucideIcon;
  trend?: "up" | "down" | "flat";
  accent?: "default" | "success" | "warning" | "destructive";
  /** If set, the entire card becomes a clickable link. */
  href?: string;
  className?: string;
}

const ACCENT_TEXT: Record<NonNullable<StatCardProps["accent"]>, string> = {
  default: "text-muted-foreground",
  success: "text-success",
  warning: "text-warning",
  destructive: "text-destructive",
};

const ACCENT_ICON: Record<NonNullable<StatCardProps["accent"]>, string> = {
  default: "bg-primary/10 text-primary",
  success: "bg-success/10 text-success",
  warning: "bg-warning/10 text-warning",
  destructive: "bg-destructive/10 text-destructive",
};

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  accent = "default",
  href,
  className,
}: StatCardProps) {
  const card = (
    <Card
      className={cn(
        "flex h-full flex-col overflow-hidden",
        href && "cursor-pointer transition-colors hover:bg-muted/40",
        className,
      )}
    >
      <CardHeader className="flex flex-row items-center justify-between !grid-rows-1 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
        {Icon && (
          <span
            className={cn(
              "flex size-8 shrink-0 items-center justify-center rounded-md",
              ACCENT_ICON[accent],
            )}
          >
            <Icon className="size-4" aria-hidden="true" />
          </span>
        )}
      </CardHeader>
      <CardContent className="flex flex-1 flex-col pt-0">
        <div className="text-3xl font-semibold tracking-tight tabular-nums">
          {value}
        </div>
        <p className={cn("mt-1 min-h-[1rem] text-xs", ACCENT_TEXT[accent])}>
          {hint ?? "\u00A0"}
        </p>
      </CardContent>
    </Card>
  );

  if (href) {
    return (
      <Link to={href} className="block no-underline">
        {card}
      </Link>
    );
  }
  return card;
}
