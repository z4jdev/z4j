/**
 * Permanent redirect to the unified Global Notifications hub.
 *
 * v1.0.18: page moved to components/notifications/my-channels-tab.tsx
 * and rendered as ``?tab=channels`` of the new hub.
 * v1.1.0: tabs went path-based; this shim now redirects to
 * ``/settings/notifications/channels``. Bookmarks from v1.0 - v1.1
 * all land on the right page.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/_authenticated/settings/channels")({
  beforeLoad: () => {
    throw redirect({
      to: "/settings/notifications/channels",
      replace: true,
    });
  },
});
