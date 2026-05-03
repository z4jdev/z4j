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

const ACCENT_RING: Record<NonNullable<StatCardProps["accent"]>, string> = {
  default: "ring-1 ring-border",
  success: "ring-1 ring-success/40",
  warning: "ring-1 ring-warning/40",
  destructive: "ring-1 ring-destructive/40",
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
        ACCENT_RING[accent],
        href && "cursor-pointer transition-shadow hover:shadow-md",
        className,
      )}
    >
      <CardHeader className="flex flex-row items-center justify-between !grid-rows-1 pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </CardTitle>
        {Icon && <Icon className="size-4 text-muted-foreground" />}
      </CardHeader>
      <CardContent className="flex flex-1 flex-col pt-0">
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
        <p className="mt-1 min-h-[1rem] text-xs text-muted-foreground">
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
