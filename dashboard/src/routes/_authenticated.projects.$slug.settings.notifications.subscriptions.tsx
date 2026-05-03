/**
 * Project Notifications - "Project Subscriptions" tab content.
 * Path: /projects/$slug/settings/notifications/subscriptions
 *
 * The underlying component is still ``DefaultSubscriptionsTab``
 * (project default subscriptions); only the dashboard label + URL
 * segment was renamed in v1.1.0. The DB tables and API routes keep
 * the ``defaults`` naming so existing operator integrations don't
 * break.
 */
import { createFileRoute } from "@tanstack/react-router";
import { DefaultSubscriptionsTab } from "@/components/notifications/default-subscriptions-tab";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications/subscriptions",
)({
  component: ProjectSubscriptionsTabPage,
});

function ProjectSubscriptionsTabPage() {
  const { slug } = Route.useParams();
  return <DefaultSubscriptionsTab slug={slug} />;
}
