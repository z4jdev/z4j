/**
 * DemoBanner -- sticky top banner + mutation-toast listener for the
 * demo.z4j.dev build.
 *
 * Renders nothing in production (gated on VITE_Z4J_DEMO_MODE). In
 * demo builds it does two jobs:
 *
 * 1. Renders the persistent yellow "DEMO MODE" banner across the top
 *    of every page, with a "reset", "show first-boot", and "install
 *    for real" link.
 * 2. Listens for `demo:blocked-mutation` window events fired by the
 *    mock-fetch interceptor (src/lib/api.demo.ts) and surfaces them
 *    as a single sonner toast. The toast is throttled so a burst of
 *    blocked mutations (e.g. clicking Save then immediately Save
 *    again) shows only once.
 *
 * See DEMO-Z4J-DEV-DESIGN.md for the design rationale.
 */
import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { useNavigate } from "@tanstack/react-router";

const IS_DEMO = import.meta.env.VITE_Z4J_DEMO_MODE === "true";

const TOAST_THROTTLE_MS = 2_000;

export function DemoBanner() {
  // Render-side gate. Strict equality so a missing env var (undefined,
  // empty string) does NOT trigger demo mode.
  if (!IS_DEMO) return null;
  return <DemoBannerInner />;
}

function DemoBannerInner() {
  const navigate = useNavigate();
  const lastToastAt = useRef(0);

  useEffect(() => {
    const handler = () => {
      const now = Date.now();
      if (now - lastToastAt.current < TOAST_THROTTLE_MS) return;
      lastToastAt.current = now;
      toast("This is a demo", {
        description:
          "Mutations are disabled. Refresh to reset; install z4j to make changes for real.",
        duration: 4_000,
      });
    };
    window.addEventListener("demo:blocked-mutation", handler);
    return () => window.removeEventListener("demo:blocked-mutation", handler);
  }, []);

  return (
    <div
      role="banner"
      aria-label="Demo mode"
      className="sticky top-0 z-50 flex items-center justify-center gap-3 bg-yellow-300 px-4 py-1.5 text-xs font-medium text-yellow-950 sm:text-sm"
    >
      <span>
        <strong className="font-bold">DEMO MODE</strong>
        <span className="ml-1 hidden sm:inline">
          {" "}
          -- data is fake, no services connected.
        </span>
      </span>
      <span className="hidden h-3 w-px bg-yellow-900/30 sm:inline-block" />
      <button
        type="button"
        onClick={() => window.location.reload()}
        className="underline decoration-1 underline-offset-2 hover:decoration-2"
      >
        Reset demo
      </button>
      <span className="h-3 w-px bg-yellow-900/30" />
      <button
        type="button"
        onClick={() => navigate({ to: "/setup" }).catch(() => undefined)}
        className="hidden underline decoration-1 underline-offset-2 hover:decoration-2 sm:inline"
      >
        First-boot setup
      </button>
      <span className="hidden h-3 w-px bg-yellow-900/30 sm:inline-block" />
      <a
        href="https://z4j.com/install/"
        target="_blank"
        rel="noopener"
        className="underline decoration-1 underline-offset-2 hover:decoration-2"
      >
        Install z4j for real
      </a>
    </div>
  );
}
