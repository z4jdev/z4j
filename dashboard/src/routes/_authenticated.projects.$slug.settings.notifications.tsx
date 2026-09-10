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
import { PageHeader } from "@/components/domain/page-header";
import { NotificationNavigation } from "@/components/notifications/notification-navigation";
import { createFileRoute, Outlet } from "@tanstack/react-router";
import { BellRing } from "lucide-react";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications",
)({
  component: ProjectNotificationsLayout,
});

function ProjectNotificationsLayout() {
  const { slug } = Route.useParams();
  return (
    <div className="space-y-6">
      <PageHeader
        icon={BellRing}
        title="Notifications"
        description="What this project announces, through which channels, and to whom by default."
      />
      <NotificationNavigation slug={slug} />
      <div className="mt-4">
        <Outlet />
      </div>
    </div>
  );
}
