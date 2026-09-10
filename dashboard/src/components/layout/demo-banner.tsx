import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useLayoutEffect, useRef } from "react";
import { RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

const IS_DEMO = import.meta.env.VITE_Z4J_DEMO_MODE === "true";

const TOAST_THROTTLE_MS = 2_000;

export function DemoBanner() {
  // Render-side gate. Strict equality so a missing env var (undefined,
  // empty string) does NOT trigger demo mode.
  if (!IS_DEMO) return null;
  return <DemoBannerInner />;
}

function DemoBannerInner() {
  const footer = useRef<HTMLElement>(null);
  const lastToastAt = useRef(0);
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const scenarios = [
    { path: "/projects/example.com", label: "Healthy project" },
    {
      path: "/projects/django.example.com/issues",
      label: "Investigate an incident",
    },
    { path: "/projects/django.example.com/schedules", label: "Scheduled work" },
    { path: "/projects/tasks.example.com/tasks", label: "Mixed task engines" },
  ];
  const active =
    scenarios.find((scenario) => pathname === scenario.path)?.path ?? "";

  // Reserve the actual footer height, including wrapping and browser zoom.
  // Content and the sidebar remain reachable above this demo-only overlay.
  useLayoutEffect(() => {
    const element = footer.current;
    if (!element) return;
    const root = document.documentElement;
    const measure = () =>
      root.style.setProperty(
        "--demo-footer-height",
        `${element.getBoundingClientRect().height}px`,
      );
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => {
      observer.disconnect();
      root.style.removeProperty("--demo-footer-height");
    };
  }, []);

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
    <footer
      ref={footer}
      data-slot="demo-footer"
      aria-label="Demo mode"
      className="fixed inset-x-0 bottom-0 z-40 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t bg-card px-4 py-2 md:px-6"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className="font-semibold tracking-wide text-foreground">
          DEMO
        </span>
        <span className="text-muted-foreground">
          Sample data · changes are disabled
        </span>
      </div>
      <div className="flex w-full min-w-0 items-center gap-2 sm:w-auto">
        <Select value={active} onValueChange={(path) => navigate({ to: path })}>
          <SelectTrigger
            aria-label="Explore a demo scenario"
            className="min-w-0 flex-1 sm:w-52 sm:flex-none"
          >
            <SelectValue placeholder="Explore a scenario" />
          </SelectTrigger>
          <SelectContent>
            {scenarios.map((scenario) => (
              <SelectItem key={scenario.path} value={scenario.path}>
                {scenario.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Reset demo"
          title="Reset demo"
          onClick={() => window.location.reload()}
        >
          <RotateCcw className="size-4" />
        </Button>
        <Button asChild variant="outline">
          <a href="https://z4j.com/install/" target="_blank" rel="noopener">
            Install z4j
          </a>
        </Button>
      </div>
    </footer>
  );
}
