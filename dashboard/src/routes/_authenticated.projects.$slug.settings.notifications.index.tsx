/**
 * Index route for /projects/$slug/settings/notifications.
 *
 * 1. Bare path redirects to the default tab (`channels`) so the
 *    layout always has a child to render.
 * 2. Legacy `?tab=channels` / `?tab=defaults` / `?tab=deliveries`
 *    URLs (v1.0.18 - 1.0.19) redirect to the new path-based form.
 *    The legacy `defaults` tab key maps to the renamed
 *    `subscriptions` path (the underlying component is the same
 *    `DefaultSubscriptionsTab`).
 */
import { createFileRoute, redirect } from "@tanstack/react-router";
import { z } from "zod";

const LEGACY_TABS = ["channels", "defaults", "subscriptions", "deliveries"] as const;
type LegacyTab = (typeof LEGACY_TABS)[number];

const searchSchema = z.object({
  tab: z.enum(LEGACY_TABS).optional(),
});

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/notifications/",
)({
  validateSearch: searchSchema,
  beforeLoad: ({ params, search }) => {
    const slug = (params as { slug: string }).slug;
    const raw: LegacyTab | undefined = (search as { tab?: LegacyTab }).tab;
    if (raw === "channels") {
      throw redirect({
        to: "/projects/$slug/settings/notifications/channels",
        params: { slug },
        replace: true,
      });
    }
    if (raw === "defaults" || raw === "subscriptions") {
      throw redirect({
        to: "/projects/$slug/settings/notifications/subscriptions",
        params: { slug },
        replace: true,
      });
    }
    if (raw === "deliveries") {
      throw redirect({
        to: "/projects/$slug/settings/notifications/deliveries",
        params: { slug },
        replace: true,
      });
    }
    // Bare path: project default lands on Channels.
    throw redirect({
      to: "/projects/$slug/settings/notifications/channels",
      params: { slug },
      replace: true,
    });
  },
});
