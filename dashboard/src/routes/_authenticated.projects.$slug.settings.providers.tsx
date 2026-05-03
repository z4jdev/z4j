/**
 * Permanent redirect to the unified Project Notifications hub
 * (v1.0.18). The page itself moved to
 * ``components/notifications/project-channels-tab.tsx`` and is
 * rendered as the ``?tab=channels`` panel of the new hub. Old
 * bookmarks keep working forever.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/providers",
)({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/projects/$slug/settings/notifications/channels",
      params: { slug: params.slug },
      replace: true,
    });
  },
});
