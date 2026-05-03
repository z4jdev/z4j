/**
 * Sticky topbar - global chrome above every authenticated page.
 *
 * The topbar is page-agnostic: it does NOT render the page title
 * or description. Each page renders its own ``<PageHeader>`` so
 * the heading isn't duplicated. The topbar's job is to host
 * cross-page concerns:
 *
 *   1. Hamburger        (mobile only - opens sidebar drawer)
 *   2. Search           (placeholder - wired in a later phase)
 *   3. Server status    (live /health pill)
 *   4. Theme            (icon dropdown - light/dark/system)
 *   5. Notifications    (icon dropdown with unread dot)
 *   6. User menu        (avatar dropdown)
 *
 * Mounted exactly once by the authenticated layout
 * (``_authenticated.tsx``) - pages no longer instantiate it.
 */
import {
  Activity,
  AlertCircle,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { NotificationBell } from "./notification-bell";
import { ThemeToggle } from "./theme-toggle";
import { UserMenu } from "./user-menu";
import { useSidebar } from "./sidebar-context";

interface HealthResponse {
  status: string;
  version: string;
}

const isMac =
  typeof navigator !== "undefined" &&
  /mac|iphone|ipad/i.test(navigator.userAgent);

export function Topbar() {
  const { collapsed, toggleCollapsed, setMobileOpen } = useSidebar();
  const { data: health, isError } = useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: () => api.get<HealthResponse>("/health"),
    refetchInterval: 30_000,
    refetchOnWindowFocus: false,
  });

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur-md md:px-6">
      {/* Mobile hamburger */}
      <Button
        variant="ghost"
        size="icon"
        aria-label="Open menu"
        className="md:hidden"
        onClick={() => setMobileOpen(true)}
      >
        <Menu className="size-5" />
      </Button>

      {/* Desktop sidebar toggle */}
      <TooltipProvider delayDuration={150}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className="hidden md:inline-flex"
              onClick={toggleCollapsed}
            >
              {collapsed ? (
                <PanelLeftOpen className="size-4" />
              ) : (
                <PanelLeftClose className="size-4" />
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="bottom">
            {collapsed ? "Expand sidebar" : "Collapse sidebar"}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>

      {/* Search trigger - opens the command palette (⌘K). The input
          is a styled button, not a real input, so clicking it opens
          the palette overlay. */}
      {/* Centered search trigger - opens the command palette (⌘K) */}
      <div className="hidden flex-1 items-center justify-center md:flex">
        <button
          type="button"
          onClick={() => {
            document.dispatchEvent(
              new KeyboardEvent("keydown", {
                key: "k",
                metaKey: true,
                bubbles: true,
              }),
            );
          }}
          className={cn(
            "relative flex h-9 w-full max-w-sm cursor-pointer items-center rounded-md border border-input bg-card pl-9 pr-12 text-sm",
            "text-muted-foreground transition-colors",
            "hover:border-ring/40 hover:bg-accent",
          )}
        >
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <span>Search...</span>
          <kbd className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 select-none items-center gap-0.5 rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
            {isMac ? "⌘" : "Ctrl"} K
          </kbd>
        </button>
      </div>

      {/* Mobile spacer */}
      <div className="flex-1 md:hidden" />

      {/* z4j status - hidden on the smallest screens. */}
      <ServerStatus
        ok={!isError && health?.status === "ok"}
        version={health?.version ?? "unknown"}
        className="hidden sm:inline-flex"
      />

      <Separator orientation="vertical" className="hidden h-6 sm:block" />

      {/* Global toolbar.
          ``gap-2`` (was ``gap-1``) so the NotificationBell doesn't
          crowd the user avatar - operators were hitting the J avatar
          when aiming for the bell on touch laptops. */}
      <div className="flex items-center gap-2">
        <ThemeToggle />
        <NotificationBell />
        <UserMenu />
      </div>
    </header>
  );
}

function ServerStatus({
  ok,
  version,
  className,
}: {
  ok: boolean;
  version: string;
  className?: string;
}) {
  const displayVersion =
    version === "0.0.0" || version === "unknown" ? "dev" : `v${version}`;
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant={ok ? "muted" : "destructive"}
            className={cn(
              "cursor-default gap-1.5",
              ok && "border-success/20 bg-success/10 text-success",
              className,
            )}
          >
            <span
              className={cn(
                "size-2 rounded-full",
                ok ? "animate-pulse bg-success" : "bg-destructive",
              )}
            />
            {ok ? `z4j ${displayVersion}` : "z4j offline"}
          </Badge>
        </TooltipTrigger>
        <TooltipContent side="bottom" className="max-w-xs text-xs">
          {ok ? (
            <div className="space-y-1">
              <p className="font-medium">z4j connected</p>
              <p className="text-muted-foreground">
                Version {version} - health check OK.
                The dashboard has a live connection to the z4j API.
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="font-medium">z4j unreachable</p>
              <p className="text-muted-foreground">
                Cannot reach the z4j API. Data shown may be stale.
                Check that z4j is running.
              </p>
            </div>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
