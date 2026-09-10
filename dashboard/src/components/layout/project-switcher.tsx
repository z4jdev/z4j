import { useNavigate, useRouterState } from "@tanstack/react-router";
import { Check, ChevronsUpDown, FolderKanban, Settings } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { useMe } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";

// Sub-routes of /projects/:slug that make sense to carry over when the
// user switches projects. Deeper paths (e.g. /tasks/celery/:taskId,
// /workers/:workerId) reference resources that are unique per project,
// so we drop them and land on the sibling's list page instead.
const PRESERVABLE_SUBPATHS = new Set([
  "tasks",
  "issues",
  "trends",
  "automation",
  "workers",
  "queues",
  "schedules",
  "commands",
  "agents",
  "audit",
  "settings",
]);

export function ProjectSwitcher({
  currentSlug,
  collapsed = false,
}: {
  currentSlug?: string;
  collapsed?: boolean;
}) {
  const { data: me, isLoading } = useMe();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  if (isLoading) {
    return <Skeleton className="h-12 w-full" />;
  }

  const memberships = me?.memberships ?? [];
  const current = memberships.find((m) => m.project_slug === currentSlug);

  // Multiple projects - show the dropdown switcher.
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Switch project: ${current?.project_slug ?? "Workspace"}`}
          className={cn(
            "flex w-full items-center gap-2 rounded-md border bg-card p-2 text-left",
            "transition-colors hover:bg-accent",
            collapsed && "justify-center border-0 bg-transparent p-1",
          )}
        >
          <div className="flex size-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
            <FolderKanban className="size-4" />
          </div>
          {!collapsed && (
            <div className="flex min-w-0 flex-1 flex-col">
              <span className="truncate text-sm font-semibold">
                {current?.project_slug ?? "Workspace"}
              </span>
              <span className="truncate text-xs text-muted-foreground">
                {current ? current.role : `${memberships.length} projects`}
              </span>
            </div>
          )}
          {!collapsed && (
            <ChevronsUpDown className="size-4 text-muted-foreground" />
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" sideOffset={4} className="w-64">
        <DropdownMenuItem onSelect={() => navigate({ to: "/home" })}>
          Workspace home
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Projects</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {memberships.map((m) => (
          <DropdownMenuItem
            key={m.project_id}
            onSelect={() => {
              // If the user is on a sibling sub-page (workers, agents,
              // queues, ...), keep them on that page in the target
              // project - much more useful than always dumping them on
              // the overview.
              const match = pathname.match(/^\/projects\/[^/]+\/([^/]+)/);
              const sub = match?.[1];
              if (sub && PRESERVABLE_SUBPATHS.has(sub)) {
                navigate({ to: `/projects/${m.project_slug}/${sub}` });
              } else {
                navigate({
                  to: "/projects/$slug",
                  params: { slug: m.project_slug },
                });
              }
            }}
          >
            <FolderKanban className="size-4 opacity-60" />
            <span className="truncate">{m.project_slug}</span>
            {m.project_slug === currentSlug && (
              <Check className="ml-auto size-4" />
            )}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        {me?.is_admin && (
          <DropdownMenuItem
            onSelect={() => navigate({ to: "/settings/projects" })}
          >
            <Settings className="size-4 opacity-60" />
            <span>Manage projects</span>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
