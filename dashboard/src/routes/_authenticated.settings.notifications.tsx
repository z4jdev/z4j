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
import { PageHeader } from "@/components/domain/page-header";
import { NotificationNavigation } from "@/components/notifications/notification-navigation";
import { createFileRoute, Outlet } from "@tanstack/react-router";
import { Bell } from "lucide-react";

export const Route = createFileRoute("/_authenticated/settings/notifications")({
  component: GlobalNotificationsLayout,
});

function GlobalNotificationsLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        icon={Bell}
        title="Notifications"
        description="Your personal channels, subscriptions, and delivery log across every project."
      />
      <NotificationNavigation />
      <div className="mt-4">
        <Outlet />
      </div>
    </div>
  );
}
