import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";

import { DemoBanner } from "@/components/layout/demo-banner";

interface RouterContext {
  queryClient: QueryClient;
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
});

function RootLayout() {
  // Wrap the whole app in a min-h-screen flex column so the demo
  // banner (when rendered) takes its natural height at the top and
  // the auth layout below it (also flex-1) fills exactly the
  // remaining viewport. In production DemoBanner returns null so
  // the wrapper is a one-child flex column with no visible effect.
  // The combination prevents the "banner + auth-layout-min-h-screen
  // = 100vh + banner_height" scroll-overflow that a naive sibling
  // banner would introduce.
  return (
    <div className="flex min-h-screen flex-col">
      <DemoBanner />
      <div className="flex min-h-0 flex-1 flex-col">
        <Outlet />
      </div>
    </div>
  );
}
