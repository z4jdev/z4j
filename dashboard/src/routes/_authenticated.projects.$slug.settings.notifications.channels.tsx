/**
 * Project Notifications - "Project Channels" tab content.
 * Path: /projects/$slug/settings/notifications/channels  (default)
 */
import { createFileRoute } from "@tanstack/react-router";
import { ProjectChannelsTab } from "@/components/notifications/project-channels-tab";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications/channels",
)({
  component: ProjectChannelsTabPage,
});

function ProjectChannelsTabPage() {
  const { slug } = Route.useParams();
  return <ProjectChannelsTab slug={slug} />;
}
