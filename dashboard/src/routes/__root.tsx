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
  // DemoBanner renders nothing in production builds (gated on
  // VITE_Z4J_DEMO_MODE inside the component). In demo builds it
  // renders the sticky top banner AND mounts the mutation-toast
  // listener that the mock-fetch interceptor (api.demo.ts) talks
  // to via window events.
  return (
    <>
      <DemoBanner />
      <Outlet />
    </>
  );
}
