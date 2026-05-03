/**
 * Personal Notifications - "Global Subscriptions" tab content.
 * Path: /settings/notifications/subscriptions  (default tab)
 */
import { createFileRoute } from "@tanstack/react-router";
import { MySubscriptionsTab } from "@/components/notifications/my-subscriptions-tab";

export const Route = createFileRoute(
  "/_authenticated/settings/notifications/subscriptions",
)({
  component: MySubscriptionsTab,
});
