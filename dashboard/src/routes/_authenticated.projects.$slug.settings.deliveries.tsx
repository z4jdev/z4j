/**
 * Permanent redirect to the unified Project Notifications hub.
 * Pre-1.0.18: dedicated /deliveries route.
 * v1.0.18: ``?tab=deliveries`` of the new hub.
 * v1.1.0: ``/notifications/deliveries`` path-based child route.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/deliveries",
)({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/projects/$slug/settings/notifications/deliveries",
      params: { slug: params.slug },
      replace: true,
    });
  },
});
