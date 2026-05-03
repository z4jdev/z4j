/**
 * Project Notifications hub - "Project Notifications" page.
 *
 * v1.0.18: collapsed three separate routes into one tabbed page so
 * the admin has ONE place to manage everything notification-sending
 * for THIS project.
 *
 * v1.1.0: tabs are now path-based:
 *
 *   /projects/$slug/settings/notifications/channels
 *   /projects/$slug/settings/notifications/subscriptions
 *   /projects/$slug/settings/notifications/deliveries
 *
 * Bare hub path redirects to ``/channels`` (the default project tab).
 * Old ``?tab=X`` URLs are translated by the index route. Old route
 * paths (``/providers`` ``/defaults``) keep their existing redirect
 * shims, just retargeted at the new path.
 *
 * Admin-gated. Members see this entry hidden from the project sidebar;
 * if they URL-jump in directly, the inner tab components render their
 * own admin-only EmptyState.
 */
import { createFileRoute, Link, Outlet, useRouterState } from "@tanstack/react-router";
import { PageHeader } from "@/components/domain/page-header";
import { cn } from "@/lib/utils";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications",
)({
  component: ProjectNotificationsLayout,
});

function ProjectNotificationsLayout() {
  const { slug } = Route.useParams();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const segments = pathname.split("/").filter(Boolean);
  const activeSegment = segments[segments.length - 1];

  const tabClass = (isActive: boolean) =>
    cn(
      "border-b-2 px-1 py-2 text-sm font-medium transition-colors",
      isActive
        ? "border-primary text-foreground"
        : "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
    );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Project Notifications"
        description="What this project announces, through which channels, and to whom by default. Members can wire their own personal subscriptions in Global Notifications under their account."
      />
      <div className="border-b">
        <nav
          className="-mb-px flex gap-4"
          aria-label="Project notification settings"
        >
          <Link
            to="/projects/$slug/settings/notifications/channels"
            params={{ slug }}
            replace
            className={tabClass(activeSegment === "channels")}
          >
            Project Channels
          </Link>
          <Link
            to="/projects/$slug/settings/notifications/subscriptions"
            params={{ slug }}
            replace
            className={tabClass(activeSegment === "subscriptions")}
          >
            Project Subscriptions
          </Link>
          <Link
            to="/projects/$slug/settings/notifications/deliveries"
            params={{ slug }}
            replace
            className={tabClass(activeSegment === "deliveries")}
          >
            Project Notification Log
          </Link>
        </nav>
      </div>
      <div className="mt-4">
        <Outlet />
      </div>
    </div>
  );
}
