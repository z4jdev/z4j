/**
 * Redirect: /account -> /settings/account
 *
 * The account page has been merged into the unified settings hub.
 * This redirect keeps old bookmarks and links working.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/_authenticated/account")({
  beforeLoad: () => {
    throw redirect({ to: "/settings/account" });
  },
});
