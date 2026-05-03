/**
 * Root landing route at `/`.
 *
 * Two responsibilities, in order:
 *
 *   1. First-boot check. If z4j has not been set up yet
 *      (`/setup/status.first_boot == true`) we hard-redirect the
 *      browser to `/setup`, which is served by z4j itself.
 *
 *   2. Post-login branching. For an authenticated user we branch
 *      on membership count:
 *
 *        - 0 memberships AND not global admin → /settings/account
 *        - 0 memberships AND global admin     → /home (they can
 *          create/manage projects from there)
 *        - 1 membership                       → /projects/{slug}
 *        - 2+ memberships                     → /home
 *
 *      Unauthenticated users fall through to `/login`.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";
import { api, ApiError } from "@/lib/api";
import type { SetupStatusResponse, UserMePublic } from "@/lib/api-types";

export const Route = createFileRoute("/")({
  beforeLoad: async ({ context }) => {
    // 1. First-boot redirect. If we can't reach /setup/status we
    // assume z4j is already set up and keep going.
    try {
      const status = await api.get<SetupStatusResponse>("/setup/status");
      if (status.first_boot) {
        // The setup HTML form is served by z4j itself at
        // /setup, so we do a hard navigate rather than a router
        // redirect.
        if (typeof window !== "undefined") {
          window.location.href = "/setup";
        }
        throw redirect({ to: "/login" });
      }
    } catch (err) {
      if (!(err instanceof ApiError)) throw err;
    }

    // 2. Branch on memberships. Read-through the query client so
    // this doubles as a cache seed for the rest of the app.
    try {
      const me = await context.queryClient.fetchQuery<UserMePublic>({
        queryKey: ["auth", "me"],
        queryFn: () => api.get<UserMePublic>("/auth/me"),
        staleTime: 30_000,
      });

      const memberships = me.memberships ?? [];

      if (memberships.length === 0) {
        if (me.is_admin) {
          throw redirect({ to: "/home" });
        }
        throw redirect({ to: "/settings/account" });
      }

      if (memberships.length === 1) {
        throw redirect({
          to: "/projects/$slug",
          params: { slug: memberships[0].project_slug },
        });
      }

      throw redirect({ to: "/home" });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        throw redirect({ to: "/login" });
      }
      throw err;
    }
  },
});
