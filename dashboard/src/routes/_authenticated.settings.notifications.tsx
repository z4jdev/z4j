/**
 * Personal Notifications hub - "Global Notifications" page.
 *
 * v1.0.18: collapsed three separate routes into one tabbed page so
 * the user has ONE place to manage everything notification-receiving
 * across all their projects (channels / subscriptions / delivery
 * history).
 *
 * v1.1.0: tabs are now path-based instead of query-string-based:
 *
 *   /settings/notifications/channels       (Global Channels)
 *   /settings/notifications/subscriptions  (Global Subscriptions)
 *   /settings/notifications/deliveries     (Global Notification Log)
 *
 * Bare ``/settings/notifications`` redirects to ``/subscriptions``.
 * Old ``?tab=X`` URLs are redirected by the index route so existing
 * bookmarks survive.
 *
 * The mirror page on the project side
 * (``_authenticated.projects.$slug.settings.notifications.tsx``) is
 * admin-only and follows the same path-based tab structure.
 */
import { createFileRoute, Link, Outlet, useRouterState } from "@tanstack/react-router";
import { PageHeader } from "@/components/domain/page-header";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/settings/notifications")({
  component: GlobalNotificationsLayout,
});

function GlobalNotificationsLayout() {
  // Path-driven tab highlight: read the active path segment so the
  // current child route's tab is visually selected. ``useRouterState``
  // re-renders on navigation so the highlight stays in sync as the
  // user clicks between tabs.
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
        title="Global Notifications"
        description="Personal notification settings that follow you across every project, your channels, your subscriptions, and the full log of notifications that landed in your inbox."
      />
      <div className="border-b">
        <nav className="-mb-px flex gap-4" aria-label="Notification settings">
          <Link
            to="/settings/notifications/channels"
            replace
            className={tabClass(activeSegment === "channels")}
          >
            Global Channels
          </Link>
          <Link
            to="/settings/notifications/subscriptions"
            replace
            className={tabClass(activeSegment === "subscriptions")}
          >
            Global Subscriptions
          </Link>
          <Link
            to="/settings/notifications/deliveries"
            replace
            className={tabClass(activeSegment === "deliveries")}
          >
            Global Notification Log
          </Link>
        </nav>
      </div>
      <div className="mt-4">
        <Outlet />
      </div>
    </div>
  );
}
