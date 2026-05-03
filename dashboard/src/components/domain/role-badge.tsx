import { ShieldCheck, User2, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";

export type Role = "admin" | "operator" | "viewer";

/**
 * Color-coded role chip. One visual language used everywhere a
 * project role surfaces: Members table, profile overviews, the
 * role-at-a-glance list under /settings/memberships.
 */
export function RoleBadge({
  role,
  className,
}: {
  role: Role | string;
  className?: string;
}) {
  const meta = ROLE_META[role as Role] ?? ROLE_META.viewer;
  const Icon = meta.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
        meta.classes,
        className,
      )}
      aria-label={`role: ${role}`}
    >
      <Icon className="size-3" />
      {role}
    </span>
  );
}

const ROLE_META: Record<Role, { icon: typeof ShieldCheck; classes: string }> = {
  admin: {
    icon: ShieldCheck,
    classes:
      "border-primary/30 bg-primary/10 text-primary",
  },
  operator: {
    icon: Wrench,
    classes:
      "border-warning/30 bg-warning/10 text-warning",
  },
  viewer: {
    icon: User2,
    classes:
      "border-muted-foreground/20 bg-muted text-muted-foreground",
  },
};
