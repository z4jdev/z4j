/**
 * Global Settings → "My memberships" - a one-look view of every
 * project the signed-in user belongs to plus their role in each.
 *
 * No admin tooling here; this is the *user's own* profile surface.
 * Operators and viewers need somewhere to read "what am I allowed
 * to do on which project?" without opening the Members settings
 * inside each project separately.
 */
import { createFileRoute, Link } from "@tanstack/react-router";
import { Users } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/domain/page-header";
import { RoleBadge } from "@/components/domain/role-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useMe } from "@/hooks/use-auth";

export const Route = createFileRoute("/_authenticated/settings/memberships")({
  component: MembershipsPage,
});

function MembershipsPage() {
  const { data: me, isLoading } = useMe();
  const memberships = me?.memberships ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="My memberships"
        icon={Users}
        description="every project you belong to, and the role you have on each"
      />

      {isLoading && <Skeleton className="h-48 w-full" />}

      {!isLoading && memberships.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            you don't belong to any projects yet
          </CardContent>
        </Card>
      )}

      {memberships.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2">
          {memberships.map((m) => (
            <Card key={m.project_id} className="transition-colors hover:bg-muted/30">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center justify-between text-base">
                  <Link
                    to="/projects/$slug"
                    params={{ slug: m.project_slug }}
                    className="font-medium hover:underline"
                  >
                    {m.project_slug}
                  </Link>
                  <RoleBadge role={m.role} />
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground">
                <div className="font-mono">{m.project_slug}</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {capabilitiesFor(m.role).map((cap) => (
                    <span
                      key={cap}
                      className="rounded bg-muted px-1.5 py-0.5 text-[10px]"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function capabilitiesFor(role: string): string[] {
  if (role === "admin")
    return [
      "retry",
      "cancel",
      "bulk",
      "rate-limit",
      "schedules",
      "agents",
      "members",
      "invites",
    ];
  if (role === "operator")
    return ["retry", "cancel", "bulk", "rate-limit", "schedules"];
  return ["view only"];
}
