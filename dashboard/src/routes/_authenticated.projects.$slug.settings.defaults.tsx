/**
 * Permanent redirect to the unified Project Notifications hub.
 * Pre-1.0.18: dedicated /defaults route.
 * v1.0.18: ``?tab=defaults`` of the new hub.
 * v1.1.0: legacy ``defaults`` tab name renamed to ``subscriptions``;
 *         path-based child route.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/defaults",
)({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/projects/$slug/settings/notifications/subscriptions",
      params: { slug: params.slug },
      replace: true,
    });
  },
});
