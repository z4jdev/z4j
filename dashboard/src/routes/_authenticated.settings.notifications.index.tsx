/**
 * Index route for /settings/notifications.
 *
 * Two responsibilities:
 *
 * 1. Bare `/settings/notifications` redirects to the default tab
 *    (`subscriptions`) so the layout always has a child to render.
 * 2. Legacy `?tab=channels` / `?tab=subscriptions` / `?tab=deliveries`
 *    URLs (v1.0.18 - 1.0.19) redirect to the new path-based form
 *    (`/settings/notifications/<tab>`). Bookmarks from the old
 *    query-string era keep working forever.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";
import { z } from "zod";

const LEGACY_TABS = ["channels", "subscriptions", "deliveries"] as const;
type LegacyTab = (typeof LEGACY_TABS)[number];

const searchSchema = z.object({
  tab: z.enum(LEGACY_TABS).optional(),
});

export const Route = createFileRoute("/_authenticated/settings/notifications/")({
  validateSearch: searchSchema,
  beforeLoad: ({ search }) => {
    const raw: LegacyTab | undefined = (search as { tab?: LegacyTab }).tab;
    if (raw === "channels") {
      throw redirect({ to: "/settings/notifications/channels", replace: true });
    }
    if (raw === "deliveries") {
      throw redirect({ to: "/settings/notifications/deliveries", replace: true });
    }
    // Bare path or `?tab=subscriptions`: default to Subscriptions.
    throw redirect({ to: "/settings/notifications/subscriptions", replace: true });
  },
});
