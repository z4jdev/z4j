/**
 * Project sidebar - the dashboard's primary navigation surface.
 *
 * Layout (top to bottom):
 *
 *   1. Brand row             (z4j logo + name + beta pill)
 *   2. Project switcher      (current project, dropdown)
 *   3. OPERATE nav group     (Overview / Tasks / Workers / ...)
 *   4. Footer
 *      ├ Settings link       (pinned)
 *      └ Collapse chevron    (only on desktop)
 *
 * Three rendering modes:
 *
 *   desktop expanded   240px wide, full labels                  (md+)
 *   desktop collapsed  64px wide, icons only with tooltips      (md+)
 *   mobile drawer      fixed off-canvas, slides in from left    (<md)
 *
 * State is managed by SidebarProvider and read via useSidebar().
 * The user menu, theme toggle, language switcher, and notifications
 * all live in the topbar - NOT in this sidebar - to match modern
 * enterprise dashboard conventions (Linear, Vercel, Grafana).
 */
import { Link, useParams, useRouterState } from "@tanstack/react-router";
import {
  ClipboardList,
  Cpu,
  History,
  Home,
  Layers,
  LayoutDashboard,
  LineChart,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Settings as SettingsIcon,
  Settings2,
  Shield,
  Terminal,
} from "lucide-react";
import { useEffect } from "react";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ProjectSwitcher } from "./project-switcher";
import { useSidebar } from "./sidebar-context";
import { Z4jMark } from "@/components/z4j-mark";
import { useCan, useCurrentUserRole } from "@/hooks/use-memberships";

interface NavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

function buildNav(
  slug: string,
  opts: { canManageAgents: boolean; isAdmin: boolean },
): NavItem[] {
  const items: NavItem[] = [
    { label: "Overview", to: `/projects/${slug}`, icon: LayoutDashboard },
    { label: "Tasks", to: `/projects/${slug}/tasks`, icon: ClipboardList },
    { label: "Trends", to: `/projects/${slug}/trends`, icon: LineChart },
    { label: "Workers", to: `/projects/${slug}/workers`, icon: Cpu },
    { label: "Queues", to: `/projects/${slug}/queues`, icon: Layers },
    { label: "Schedules", to: `/projects/${slug}/schedules`, icon: History },
    { label: "Commands", to: `/projects/${slug}/commands`, icon: Terminal },
  ];
  // Agents page is admin-territory (mint + revoke tokens). Hide the
  // sidebar link for non-admin members - they'd hit a read-only
  // page otherwise.
  if (opts.canManageAgents) {
    items.push({
      label: "Agents",
      to: `/projects/${slug}/agents`,
      icon: Network,
    });
  }
  // Audit Log is admin-only per the backend's ``require_admin`` gate
  // on ``GET /projects/{slug}/audit``.
  if (opts.isAdmin) {
    items.push({
      label: "Audit Log",
      to: `/projects/${slug}/audit`,
      icon: Shield,
    });
  }
  return items;
}

export function AppSidebar() {
  const params = useParams({ strict: false });
  const slug = (params as { slug?: string }).slug;
  // When we're not on a project-scoped route (e.g. `/home` or
  // `/settings/*`) there's no "current project" context. We keep a
  // fallback slug for the footer links but hide the per-project
  // OPERATE section entirely - those items need a valid slug and
  // it's clearer UX to show nothing than a link to a stale project.
  const fallbackSlug = slug ?? "default";
  const hasProjectContext = !!slug;
  const canManageAgents = useCan(slug, "manage_agents");
  const isAdmin = useCurrentUserRole(slug) === "admin";
  const items = hasProjectContext
    ? buildNav(slug, { canManageAgents, isAdmin })
    : [];
  const { collapsed, toggleCollapsed, mobileOpen, setMobileOpen } = useSidebar();
  const routerState = useRouterState();

  // Auto-close the mobile drawer on every navigation, otherwise the
  // drawer stays over the page after the user picks a destination.
  useEffect(() => {
    if (mobileOpen) setMobileOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routerState.location.pathname]);

  return (
    <TooltipProvider delayDuration={150}>
      {/* Mobile backdrop. Only renders when drawer is open. */}
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close menu"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-foreground/40 backdrop-blur-sm md:hidden"
        />
      )}

      <aside
        data-collapsed={collapsed}
        className={cn(
          // Base
          "flex h-screen shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground",
          "transition-[width,transform] duration-200 ease-out",
          // Desktop width: collapsed icon-rail vs full
          "md:sticky md:top-0",
          collapsed ? "md:w-16" : "md:w-64",
          // Mobile: fixed off-canvas drawer
          "fixed inset-y-0 left-0 z-50 w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          "md:translate-x-0",
        )}
      >
        {/* ───────────────────────── Brand ───────────────────────── */}
        {/*
          Clicking the z4j mark navigates to `/`, which re-runs the
          membership-count branching logic (see routes/index.tsx).
          A user with 2+ projects lands on /home, a user with 1
          lands on that project's overview, etc.
        */}
        <Link
          to="/"
          aria-label="Go home"
          className={cn(
            "flex h-16 shrink-0 cursor-pointer items-center gap-2 border-b outline-none",
            "transition-colors hover:bg-sidebar-accent/50",
            "focus-visible:bg-sidebar-accent/60",
            collapsed ? "justify-center px-2" : "px-4",
          )}
        >
          <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Z4jMark className="size-5" />
          </div>
          {!collapsed && (
            <div className="flex min-w-0 flex-col">
              <span className="text-sm font-semibold leading-none">z4j</span>
              <span className="text-xs text-muted-foreground">control plane</span>
            </div>
          )}
        </Link>

        {/* ─────────────────── Project switcher ─────────────────── */}
        {!collapsed && (
          <div className="border-b p-3">
            <ProjectSwitcher currentSlug={fallbackSlug} />
          </div>
        )}

        {/* ────────────────────── Navigation ────────────────────── */}
        <nav className={cn("flex-1 overflow-y-auto", collapsed ? "p-2" : "p-3")}>
          {hasProjectContext ? (
            <>
              {!collapsed && (
                <div className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Operate
                </div>
              )}
              <ul className="space-y-1">
                {items.map((item) => (
                  <li key={item.to}>
                    <NavLink item={item} slug={fallbackSlug} collapsed={collapsed} />
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              {!collapsed && (
                <div className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Workspace
                </div>
              )}
              <ul className="space-y-1">
                <li>
                  <NavLink
                    item={{ label: "Home", to: "/home", icon: Home }}
                    slug={fallbackSlug}
                    collapsed={collapsed}
                  />
                </li>
              </ul>
            </>
          )}
        </nav>

        {/* ─────────────────────── Footer ────────────────────────── */}
        <div className={cn("border-t", collapsed ? "p-2" : "p-3")}>
          <ul className="space-y-1">
            {hasProjectContext && (
              <li>
                <NavLink
                  item={{
                    label: "Project Settings",
                    to: `/projects/${fallbackSlug}/settings/members`,
                    icon: Settings2,
                  }}
                  slug={fallbackSlug}
                  collapsed={collapsed}
                  // Active on any /projects/:slug/settings/* sub-route,
                  // not just the default /members landing page.
                  forceActive={routerState.location.pathname.startsWith(
                    `/projects/${fallbackSlug}/settings`,
                  )}
                />
              </li>
            )}
            <li>
              <NavLink
                item={{
                  label: "Global Settings",
                  to: "/settings/account",
                  icon: SettingsIcon,
                }}
                slug={fallbackSlug}
                collapsed={collapsed}
                // Active on any /settings/* path - the link points at
                // /settings/account by default but the user might be
                // on /settings/users, /settings/system, etc. TanStack
                // Router's default activeProps only matches the exact
                // target, so we compute the prefix match ourselves.
                forceActive={routerState.location.pathname.startsWith(
                  "/settings/",
                )}
              />
            </li>
          </ul>

          {/* Collapse / expand chevron - desktop only. */}
          <div className="mt-2 hidden md:block">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={toggleCollapsed}
                  aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                  className={cn(
                    "flex w-full cursor-pointer items-center justify-center rounded-md py-2",
                    "text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                  )}
                >
                  {collapsed ? (
                    <PanelLeftOpen className="size-4" />
                  ) : (
                    <PanelLeftClose className="size-4" />
                  )}
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">
                {collapsed ? "Expand sidebar" : "Collapse sidebar"}
              </TooltipContent>
            </Tooltip>
          </div>
        </div>
      </aside>
    </TooltipProvider>
  );
}

function NavLink({
  item,
  slug,
  collapsed,
  forceActive,
}: {
  item: NavItem;
  slug: string;
  collapsed: boolean;
  /**
   * Override TanStack Router's default active matching. Used by the
   * footer Settings links which point at a default landing page
   * (e.g. ``/settings/account``) but should remain active on every
   * sibling route under the same parent.
   */
  forceActive?: boolean;
}) {
  const activeClassName =
    "bg-sidebar-accent text-sidebar-accent-foreground shadow-sm";
  const link = (
    <Link
      to={item.to}
      activeOptions={{ exact: item.to === `/projects/${slug}` }}
      className={cn(
        "group flex items-center gap-3 rounded-md text-sm font-medium transition-colors",
        "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
        collapsed ? "justify-center p-2" : "px-3 py-2",
        forceActive && activeClassName,
      )}
      activeProps={forceActive ? undefined : { className: activeClassName }}
    >
      <item.icon className="size-4 shrink-0 opacity-70 group-hover:opacity-100" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  );

  if (!collapsed) return link;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  );
}
