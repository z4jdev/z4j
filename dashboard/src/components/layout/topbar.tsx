import { Link, useParams } from "@tanstack/react-router";
import { Menu, PanelLeftClose, PanelLeftOpen, Search } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { NotificationBell } from "./notification-bell";
import { ThemeToggle } from "./theme-toggle";
import { UserMenu } from "./user-menu";
import { useSidebar } from "./sidebar-context";

/** Global scope and API availability. Public health deliberately exposes no version. */
export function Topbar({ onOpenSearch }: { onOpenSearch: () => void }) {
  const { collapsed, toggleCollapsed, setMobileOpen } = useSidebar();
  const { slug } = useParams({ strict: false }) as { slug?: string };
  const { data, isError, isPending, dataUpdatedAt } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<{ status: string }>("/health"),
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
  const ok = !isError && data?.status === "ok";
  const isMac = /mac|iphone|ipad/i.test(navigator.userAgent);
  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-2 border-b bg-card px-4 md:gap-4 md:px-6">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Open menu"
        className="md:hidden"
        onClick={() => setMobileOpen(true)}
      >
        <Menu className="size-5" />
      </Button>
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
      <div className="min-w-0 flex-1 text-sm">
        <Link
          to="/home"
          className="hidden text-muted-foreground underline decoration-border underline-offset-4 hover:text-foreground lg:inline"
        >
          Workspace
        </Link>
        {slug ? (
          <>
            <span
              className="mx-3 hidden text-muted-foreground lg:inline"
              aria-hidden="true"
            >
              /
            </span>
            <span className="inline-block max-w-full truncate align-middle font-medium">
              {slug}
            </span>
          </>
        ) : (
          <span className="font-medium lg:hidden">Workspace</span>
        )}
      </div>
      <button
        type="button"
        onClick={onOpenSearch}
        aria-label="Search pages and tasks"
        className="flex h-9 items-center gap-2 rounded-md border bg-card px-2.5 text-sm text-muted-foreground transition-colors hover:bg-accent md:min-w-48"
      >
        <Search className="size-4" />
        <span className="hidden md:inline">Search</span>
        <kbd className="ml-auto hidden rounded border bg-card px-1.5 text-xs md:inline">
          {isMac ? "⌘" : "Ctrl"} K
        </kbd>
      </button>
      <span
        role="status"
        title={
          isPending
            ? "Checking the API"
            : ok
              ? `API health checked at ${new Date(dataUpdatedAt).toLocaleTimeString()}. This does not describe agent or worker health.`
              : "The API is unavailable. Displayed data may be stale."
        }
        className="hidden items-center gap-2 text-xs text-muted-foreground xl:inline-flex"
      >
        <span
          className={cn(
            "size-1.5 rounded-full",
            isPending
              ? "bg-muted-foreground"
              : ok
                ? "bg-success"
                : "bg-destructive",
          )}
        />
        {isPending ? "Connecting" : ok ? "API connected" : "API unavailable"}
      </span>
      <div className="flex items-center gap-1 border-l pl-2 md:gap-2 md:pl-4">
        <ThemeToggle />
        <NotificationBell />
        <UserMenu />
      </div>
    </header>
  );
}
