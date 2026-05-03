import { createFileRoute, Outlet } from "@tanstack/react-router";
import { VersionMismatchBanner } from "@/components/domain/version-mismatch-banner";
import { useDashboardSocket } from "@/hooks/use-dashboard-socket";

export const Route = createFileRoute("/_authenticated/projects/$slug")({
  component: ProjectLayout,
});

function ProjectLayout() {
  const { slug } = Route.useParams();
  // Live-updates: opens /ws/dashboard for this project, invalidates
  // TanStack Query caches whenever z4j pushes a "topic.changed"
  // notification. The hook returns a status we don't currently
  // surface in the UI - a small "live" indicator can land later.
  useDashboardSocket(slug);

  return (
    <>
      <VersionMismatchBanner slug={slug} />
      <Outlet />
    </>
  );
}
