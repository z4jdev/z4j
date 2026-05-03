/**
 * Personal Notifications - "Global Channels" tab content.
 * Path: /settings/notifications/channels
 *
 * Layout (header + nav) lives in
 * ``_authenticated.settings.notifications.tsx``; this route only
 * renders the tab body via the parent's <Outlet />.
 */
import { createFileRoute } from "@tanstack/react-router";
import { MyChannelsTab } from "@/components/notifications/my-channels-tab";

export const Route = createFileRoute(
  "/_authenticated/settings/notifications/channels",
)({
  component: MyChannelsTab,
});
