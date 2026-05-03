/**
 * Project settings index - redirects to the default section (Members).
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/",
)({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/projects/$slug/settings/members",
      params: { slug: params.slug },
    });
  },
});
