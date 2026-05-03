/**
 * Redirect: /admin/users -> /settings/users
 *
 * User management has been merged into the unified settings hub.
 * This redirect keeps old bookmarks and links working.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/_authenticated/admin/users")({
  beforeLoad: () => {
    throw redirect({ to: "/settings/users" });
  },
});
