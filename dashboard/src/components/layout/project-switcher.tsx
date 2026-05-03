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
  "workers",
  "queues",
  "schedules",
  "commands",
  "agents",
  "audit",
  "settings",
]);

export function ProjectSwitcher({ currentSlug }: { currentSlug: string }) {
  const { data: me, isLoading } = useMe();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  if (isLoading) {
    return <Skeleton className="h-12 w-full" />;
  }

  const memberships = me?.memberships ?? [];
  const current =
    memberships.find((m) => m.project_slug === currentSlug) ?? memberships[0];

  // Single project - show a simple static label instead of a dropdown.
  if (memberships.length <= 1) {
    return (
      <div className="flex items-center gap-2 rounded-md border bg-card p-2">
        <div className="flex size-8 items-center justify-center rounded-md bg-primary/10 text-primary">
          <FolderKanban className="size-4" />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="truncate text-sm font-semibold">
            {current?.project_slug ?? "default"}
          </span>
          <span className="truncate text-xs text-muted-foreground">
            {current ? current.role : "-"}
          </span>
        </div>
      </div>
    );
  }

  // Multiple projects - show the dropdown switcher.
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "flex w-full items-center gap-2 rounded-md border bg-card p-2 text-left",
            "shadow-sm transition-colors hover:bg-accent",
          )}
        >
          <div className="flex size-8 items-center justify-center rounded-md bg-primary/10 text-primary">
            <FolderKanban className="size-4" />
          </div>
          <div className="flex min-w-0 flex-1 flex-col">
            <span className="truncate text-sm font-semibold">
              {current?.project_slug ?? "no project"}
            </span>
            <span className="truncate text-xs text-muted-foreground">
              {current ? current.role : "-"}
            </span>
          </div>
          <ChevronsUpDown className="size-4 text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        sideOffset={4}
        className="w-(--radix-dropdown-menu-trigger-width) min-w-0"
      >
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
        <DropdownMenuItem
          onSelect={() => navigate({ to: "/settings/projects" })}
        >
          <Settings className="size-4 opacity-60" />
          <span>Manage projects</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
