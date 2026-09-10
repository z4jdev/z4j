import { Link, useParams, useRouterState } from "@tanstack/react-router";
import {
  History,
  Home,
  Settings,
  Settings2,
  type LucideIcon,
} from "lucide-react";
import { useEffect } from "react";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { Z4jMark } from "@/components/z4j-mark";
import { useCurrentUserRole } from "@/hooks/use-memberships";
import { ProjectSwitcher } from "./project-switcher";
import { projectNavigation } from "./project-navigation";
import { useSidebar } from "./sidebar-context";

/** Persistent workspace access and a project rail with a focus-trapped mobile drawer. */
export function AppSidebar() {
  const { collapsed, mobileOpen, setMobileOpen } = useSidebar();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname, setMobileOpen]);
  return (
    <TooltipProvider delayDuration={150}>
      <aside
        aria-label="Primary navigation"
        className={cn(
          "app-sidebar z4j-navigation sticky top-0 hidden shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground transition-[width] duration-200 md:flex",
          collapsed ? "w-16" : "w-60",
        )}
      >
        <SidebarContent collapsed={collapsed} />
      </aside>
      <Dialog open={mobileOpen} onOpenChange={setMobileOpen}>
        <DialogContent
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            document
              .querySelector<HTMLButtonElement>('[aria-label="Open menu"]')
              ?.focus();
          }}
          className="z4j-navigation inset-y-0 left-0 flex h-dvh w-72 max-w-[85vw] translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-0 bg-sidebar p-0 text-sidebar-foreground sm:max-w-72"
        >
          <DialogTitle className="sr-only">Navigation</DialogTitle>
          <DialogDescription className="sr-only">
            Switch projects or open a workspace page.
          </DialogDescription>
          <SidebarContent collapsed={false} />
        </DialogContent>
      </Dialog>
    </TooltipProvider>
  );
}

function SidebarContent({ collapsed }: { collapsed: boolean }) {
  const { slug } = useParams({ strict: false }) as { slug?: string };
  const role = useCurrentUserRole(slug);
  const items = projectNavigation(slug, role);
  return (
    <>
      <Link
        to="/home"
        aria-label="z4j workspace"
        className={cn(
          "flex h-16 shrink-0 items-center gap-3 border-b border-sidebar-border",
          collapsed ? "justify-center" : "px-5",
        )}
      >
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <Z4jMark className="size-5" />
        </span>
        {!collapsed && (
          <span className="flex flex-col">
            <span className="text-lg font-semibold leading-5 tracking-tight">
              z4j
            </span>
            <span className="text-xs text-muted-foreground">Control plane</span>
          </span>
        )}
      </Link>
      <div className={cn("py-3", collapsed ? "px-2" : "px-3")}>
        <ProjectSwitcher currentSlug={slug} collapsed={collapsed} />
      </div>
      <nav
        aria-label="Workspace and project"
        className={cn(
          "min-h-0 flex-1 overflow-y-auto pb-3",
          collapsed ? "px-2" : "px-3",
        )}
      >
        {!slug && (
          <div className="space-y-1">
            <NavLink
              label="Home"
              to="/home"
              icon={Home}
              collapsed={collapsed}
            />
            <NavLink
              label="Activity"
              to="/activity"
              icon={History}
              collapsed={collapsed}
            />
          </div>
        )}
        {(["Monitor", "Infrastructure", "Control"] as const).map((group) => {
          const groupItems = items.filter((item) => item.group === group);
          if (!groupItems.length) return null;
          return (
            <div key={group} className="mt-4 space-y-1">
              {!collapsed && (
                <p className="mb-2 px-3 text-xs font-medium tracking-wide text-muted-foreground">
                  {group}
                </p>
              )}
              {groupItems.map((item) => (
                <NavLink
                  key={item.to}
                  {...item}
                  collapsed={collapsed}
                  exact={item.label === "Overview"}
                />
              ))}
            </div>
          );
        })}
      </nav>
      <div
        className={cn(
          "space-y-1 border-t border-sidebar-border py-3",
          collapsed ? "px-2" : "px-3",
        )}
      >
        {slug && (
          <NavLink
            label="Project Settings"
            to={`/projects/${encodeURIComponent(slug)}/settings/members`}
            activePrefix={`/projects/${encodeURIComponent(slug)}/settings`}
            icon={Settings2}
            collapsed={collapsed}
          />
        )}
        <NavLink
          label="Global Settings"
          to="/settings/account"
          activePrefix="/settings/"
          icon={Settings}
          collapsed={collapsed}
        />
      </div>
    </>
  );
}

function NavLink({
  label,
  to,
  icon: Icon,
  collapsed,
  exact,
  activePrefix,
}: {
  label: string;
  to: string;
  icon: LucideIcon;
  collapsed: boolean;
  exact?: boolean;
  activePrefix?: string;
}) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const activeClass = "navigation-link-active";
  const link = (
    <Link
      to={to}
      aria-label={collapsed ? label : undefined}
      aria-current={
        activePrefix && pathname.startsWith(activePrefix) ? "page" : undefined
      }
      activeOptions={{ exact }}
      className={cn(
        "navigation-link",
        collapsed ? "justify-center px-2" : "px-3",
        activePrefix && pathname.startsWith(activePrefix) && activeClass,
      )}
      activeProps={{ className: activeClass }}
    >
      <Icon className="size-4 shrink-0 opacity-80" aria-hidden="true" />
      {!collapsed && <span className="truncate">{label}</span>}
    </Link>
  );
  return collapsed ? (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  ) : (
    link
  );
}
