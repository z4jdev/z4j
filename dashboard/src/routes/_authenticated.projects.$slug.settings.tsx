/**
 * Project settings layout route.
 *
 * Left sidebar navigation (mirrors the global settings layout) with a
 * single "Project" section. Renders an Outlet for the active child
 * settings page (members, notifications hub).
 *
 * The entries come from ``projectSettingsNavigation``, the same list the
 * workspace rail gates its Project Settings link on. Every page here reads
 * an admin-only collection (memberships and invitations, notification
 * routing), so a role below admin gets no entry; members manage their own
 * subscriptions in Global Notifications under their account. A non-admin
 * who lands here by URL sees the reason instead of a failed load.
 */
import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { Settings2 } from "lucide-react";
import { EmptyState } from "@/components/domain/empty-state";
import { PageShell } from "@/components/domain/page-shell";
import { projectSettingsNavigation } from "@/components/layout/project-navigation";
import { useMe } from "@/hooks/use-auth";
import { useCurrentUserRole } from "@/hooks/use-memberships";

export const Route = createFileRoute("/_authenticated/projects/$slug/settings")(
  {
    component: ProjectSettingsLayout,
  },
);

function ProjectSettingsLayout() {
  const { slug } = Route.useParams();
  const me = useMe();
  const role = useCurrentUserRole(slug);
  const items = projectSettingsNavigation(role);
  // Decided only once the caller is known: a null role before /auth/me
  // resolves is "not loaded yet", not "refused".
  const refused = me.isSuccess && items.length === 0;

  return (
    <PageShell>
      {/* Each child route renders its own PageHeader. The shell only
       * provides the navigation. Project scope is conveyed by the
       * project switcher in the workspace sidebar. */}

      <div className="flex flex-col gap-6 lg:flex-row">
        {items.length > 0 && (
          <nav
            aria-label="Project settings"
            className="shrink-0 border-b pb-5 lg:w-48 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4"
          >
            <div className="space-y-4 lg:sticky lg:top-24">
              <div role="group" aria-label="Project">
                <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Project
                </p>
                <ul className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,10.5rem),1fr))] gap-1 lg:grid-cols-1 lg:gap-0.5">
                  {items.map((item) => (
                    <li key={item.to}>
                      <Link
                        to={item.to}
                        params={{ slug }}
                        className="navigation-link min-h-11 px-2 py-2 lg:min-h-9 lg:py-1.5"
                        activeProps={{ className: "navigation-link-active" }}
                      >
                        <item.icon
                          className="size-4 shrink-0"
                          aria-hidden="true"
                        />
                        <span>{item.label}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </nav>
        )}

        {/* Content area */}
        <div className="min-w-0 flex-1">
          {refused ? (
            <EmptyState
              icon={Settings2}
              title="Project settings need the admin role"
              description="Members, invitations and notification routing are managed by a project admin. Your own subscriptions are under Global Settings, Notifications."
            />
          ) : (
            <Outlet />
          )}
        </div>
      </div>
    </PageShell>
  );
}
