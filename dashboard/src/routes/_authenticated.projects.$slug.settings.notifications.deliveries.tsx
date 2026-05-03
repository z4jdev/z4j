/**
 * Project Notifications - "Project Notification Log" tab content.
 * Path: /projects/$slug/settings/notifications/deliveries
 */
import { createFileRoute } from "@tanstack/react-router";
import { ProjectDeliveriesTab } from "@/components/notifications/project-deliveries-tab";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications/deliveries",
)({
  component: ProjectDeliveriesTabPage,
});

function ProjectDeliveriesTabPage() {
  const { slug } = Route.useParams();
  return <ProjectDeliveriesTab slug={slug} />;
}
