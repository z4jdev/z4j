/**
 * Personal Notifications - "Global Notification Log" tab content.
 * Path: /settings/notifications/deliveries
 */
import { createFileRoute } from "@tanstack/react-router";
import { MyDeliveriesTab } from "@/components/notifications/my-deliveries-tab";

export const Route = createFileRoute(
  "/_authenticated/settings/notifications/deliveries",
)({
  component: MyDeliveriesTab,
});
