/**
 * Home - cross-project landing page for users who operate on
 * multiple z4j projects.
 *
 * Sections top-to-bottom:
 *
 *   1. Greeting header            (time-of-day + user + attention count)
 *   2. KPI banner                 (aggregate 24h stats across projects)
 *   3. Attention list (optional)  (warning/critical per-project issues)
 *   4. Projects grid              (one card per membership)
 *   5. Recent failures feed       (paginated, clickable → task detail)
 *
 * Users with exactly one project never see this page: the
 * `/_authenticated/` branching sends them straight to
 * `/projects/{slug}`. Users with zero memberships are sent to
 * `/settings/account`.
 */
import { useEffect, useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  ClipboardList,
  Cpu,
  Home,
  Network,
  Terminal,
} from "lucide-react";
import { DateCell } from "@/components/domain/date-cell";
import { QueryError } from "@/components/domain/query-error";
import { TaskPriorityBadge } from "@/components/domain/state-badges";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useHomeRecentFailures,
  useHomeSummary,
  type HomeAttentionItem,
  type HomeProjectCard,
  type HomeProjectHealth,
  type HomeRecentFailure,
  type HomeSummary,
} from "@/hooks/use-home";
import {
  formatCompact,
  formatPercent,
  formatRelative,
  truncate,
} from "@/lib/format";
import type { TaskPriority } from "@/lib/api-types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/home")({
  component: HomePage,
});

// ---------------------------------------------------------------------------
// Greeting logic
// ---------------------------------------------------------------------------

/**
 * Pick a greeting based on the user's *local* wall clock hour.
 *
 * We use `new Date().getHours()` which reads the browser's local
 * timezone - not the backend's. This matches how every other
 * consumer web app greets users: "Good morning" tracks where the
 * user is sitting right now, not where the server lives.
 */
function greetingForHour(hour: number): string {
  if (hour < 5) return "Good evening";
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

function greeting(): string {
  return greetingForHour(new Date().getHours());
}

function displayName(summary: HomeSummary): string {
  const { display_name, email } = summary.user;
  if (display_name && display_name.trim()) return display_name;
  return email.split("@")[0];
}

// ---------------------------------------------------------------------------
// Sort options for the projects grid
// ---------------------------------------------------------------------------

type SortBy = "activity" | "name" | "failures";

const SORT_LABELS: Record<SortBy, string> = {
  activity: "Sort by activity",
  name: "Sort by name",
  failures: "Sort by failures",
};

function sortProjects(
  projects: HomeProjectCard[],
  sortBy: SortBy,
): HomeProjectCard[] {
  const copy = projects.slice();
  switch (sortBy) {
    case "activity":
      copy.sort((a, b) => {
        // Nulls sort to the end.
        const at = a.last_activity_at
          ? Date.parse(a.last_activity_at)
          : -Infinity;
        const bt = b.last_activity_at
          ? Date.parse(b.last_activity_at)
          : -Infinity;
        return bt - at;
      });
      break;
    case "name":
      copy.sort((a, b) => a.name.localeCompare(b.name));
      break;
    case "failures":
      copy.sort((a, b) => b.failures_24h - a.failures_24h);
      break;
  }
  return copy;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function HomePage() {
  const summaryQuery = useHomeSummary();
  const [sortBy, setSortBy] = useState<SortBy>("activity");

  const summary = summaryQuery.data;

  const sortedProjects = useMemo(
    () => (summary ? sortProjects(summary.projects, sortBy) : []),
    [summary, sortBy],
  );

  const stuckTarget = useMemo(() => {
    if (!summary) return null;
    return summary.projects.find((p) => p.stuck_commands > 0) ?? null;
  }, [summary]);

  return (
    <div className="mx-auto w-full max-w-7xl space-y-8 p-4 md:p-6">
      {/* Greeting */}
      <section className="flex items-center gap-3">
        <Home className="size-6 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          {summary ? (
            <>
              <h1 className="truncate text-2xl font-semibold leading-tight">
                {greeting()}, {displayName(summary)}
              </h1>
              <p className="mt-0.5 text-sm text-muted-foreground">
                {summary.projects.length}{" "}
                {summary.projects.length === 1 ? "project" : "projects"} ·{" "}
                {summary.attention.length > 0
                  ? `${summary.attention.length} need${summary.attention.length === 1 ? "s" : ""} attention`
                  : "all healthy"}
              </p>
            </>
          ) : (
            <>
              <Skeleton className="h-7 w-64" />
              <Skeleton className="mt-2 h-4 w-40" />
            </>
          )}
        </div>
      </section>

      {summaryQuery.isError && (
        <QueryError
          message="Failed to load home summary"
          onRetry={() => summaryQuery.refetch()}
        />
      )}

      {/* KPI banner */}
      <KpiBanner summary={summary} stuckTarget={stuckTarget} />

      {/* Attention */}
      {summary && summary.attention.length > 0 && (
        <AttentionList items={summary.attention} />
      )}

      {/* Projects */}
      <section className="space-y-3">
        <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold leading-tight">Projects</h2>
            <p className="text-xs text-muted-foreground">
              Click a card to jump into its overview.
            </p>
          </div>
          {summary && summary.projects.length > 1 && (
            <Select
              value={sortBy}
              onValueChange={(v) => setSortBy(v as SortBy)}
            >
              <SelectTrigger className="h-8 w-48 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(SORT_LABELS) as [SortBy, string][]).map(
                  ([value, label]) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          )}
        </div>

        {summary ? (
          summary.projects.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
                <p className="text-sm font-medium">No projects yet</p>
                <p className="text-xs text-muted-foreground">
                  Projects you belong to will show up here.
                </p>
                <Button asChild size="sm" variant="outline" className="mt-2">
                  <Link to="/settings/projects">Manage projects</Link>
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {sortedProjects.map((p) => (
                <ProjectGridCard key={p.id} project={p} />
              ))}
            </div>
          )
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-44 w-full" />
            ))}
          </div>
        )}
      </section>

      {/* Recent failures */}
      <RecentFailuresFeed />
    </div>
  );
}

// ---------------------------------------------------------------------------
// KPI banner
// ---------------------------------------------------------------------------

function KpiBanner({
  summary,
  stuckTarget,
}: {
  summary: HomeSummary | undefined;
  stuckTarget: HomeProjectCard | null;
}) {
  const agg = summary?.aggregate;

  const items: Array<{
    label: string;
    value: string;
    icon: typeof ClipboardList;
    tone?: "default" | "warning" | "destructive" | "success";
    href?: string;
  }> = [
    {
      label: "Tasks (24h)",
      value: agg ? formatCompact(agg.tasks_24h) : "-",
      icon: ClipboardList,
    },
    {
      label: "Failures (24h)",
      value: agg ? formatCompact(agg.failures_24h) : "-",
      icon: AlertTriangle,
      tone: agg && agg.failures_24h > 0 ? "destructive" : "default",
    },
    {
      label: "Failure rate",
      value: agg ? formatPercent(agg.failure_rate_24h) : "-",
      icon: AlertTriangle,
      tone:
        agg && agg.failure_rate_24h > 0.1
          ? "destructive"
          : agg && agg.failure_rate_24h > 0.02
            ? "warning"
            : "default",
    },
    {
      label: "Workers online",
      value: agg ? `${agg.workers_online}/${agg.workers_total}` : "-",
      icon: Cpu,
    },
    {
      label: "Agents online",
      value: agg ? `${agg.agents_online}/${agg.agents_total}` : "-",
      icon: Network,
    },
    {
      label: "Stuck commands",
      value: agg ? formatCompact(agg.stuck_commands) : "-",
      icon: Terminal,
      tone: agg && agg.stuck_commands > 0 ? "warning" : "default",
      href:
        stuckTarget && summary && agg && agg.stuck_commands > 0
          ? `/projects/${stuckTarget.slug}/commands`
          : undefined,
    },
  ];

  return (
    <section>
      <Card className="bg-card">
        <CardContent className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3 lg:grid-cols-6">
          {items.map((item) => {
            const body = (
              <div
                className={cn(
                  "flex flex-col gap-1 rounded-md px-2 py-1",
                  item.href &&
                    "cursor-pointer transition-colors hover:bg-accent",
                )}
              >
                <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <item.icon className="size-3.5" />
                  <span>{item.label}</span>
                </div>
                <div
                  className={cn(
                    "text-2xl font-semibold tabular-nums",
                    item.tone === "destructive" && "text-destructive",
                    item.tone === "warning" && "text-warning",
                  )}
                >
                  {item.value}
                </div>
              </div>
            );
            if (item.href) {
              return (
                <Link key={item.label} to={item.href} className="no-underline">
                  {body}
                </Link>
              );
            }
            return <div key={item.label}>{body}</div>;
          })}
        </CardContent>
      </Card>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Attention list
// ---------------------------------------------------------------------------

function AttentionList({ items }: { items: HomeAttentionItem[] }) {
  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold leading-tight">Needs attention</h2>
        <p className="text-xs text-muted-foreground">
          Issues detected across your projects in the last 24 hours.
        </p>
      </div>
      <Card className="overflow-hidden">
        <ul className="divide-y">
          {items.map((item, idx) => {
            const isCritical = item.severity === "critical";
            return (
              <li key={`${item.project_id}-${item.kind}-${idx}`}>
                <Link
                  to="/projects/$slug"
                  params={{ slug: item.project_slug }}
                  className={cn(
                    "flex items-center gap-3 px-4 py-3 text-sm transition-colors hover:bg-accent",
                    "border-l-2",
                    isCritical
                      ? "border-l-destructive/70"
                      : "border-l-warning/70",
                  )}
                >
                  <AlertTriangle
                    className={cn(
                      "size-4 shrink-0",
                      isCritical ? "text-destructive" : "text-warning",
                    )}
                    aria-label={item.severity}
                  />
                  <Badge variant="outline" className="font-mono text-[11px]">
                    {item.project_slug}
                  </Badge>
                  <span className="min-w-0 flex-1 truncate text-foreground">
                    {item.message}
                  </span>
                  <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
                </Link>
              </li>
            );
          })}
        </ul>
      </Card>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Project card
// ---------------------------------------------------------------------------

const HEALTH_DOT: Record<HomeProjectHealth, string> = {
  healthy: "bg-emerald-500",
  degraded: "bg-amber-500",
  offline: "bg-red-500",
  idle: "bg-neutral-400",
};

const HEALTH_LABEL: Record<HomeProjectHealth, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  offline: "Offline",
  idle: "Idle",
};

function ProjectGridCard({ project }: { project: HomeProjectCard }) {
  return (
    <Link
      to="/projects/$slug"
      params={{ slug: project.slug }}
      className="block no-underline focus-visible:outline-none"
    >
      <Card className="h-full transition-shadow hover:shadow-md focus-visible:ring-2 focus-visible:ring-ring/40">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <span
                className={cn(
                  "size-2 shrink-0 rounded-full",
                  HEALTH_DOT[project.health],
                )}
                aria-label={HEALTH_LABEL[project.health]}
              />
              <CardTitle className="truncate text-base">
                {project.name}
              </CardTitle>
            </div>
            <Badge variant="muted" className="shrink-0 text-[10px] uppercase">
              {project.environment}
            </Badge>
          </div>
          <div className="mt-1 font-mono text-xs text-muted-foreground">
            {project.slug}
          </div>
        </CardHeader>
        <CardContent className="space-y-1.5 pt-0 text-sm">
          <div className="tabular-nums">
            <span className="font-medium">
              {formatCompact(project.tasks_24h)}
            </span>{" "}
            <span className="text-muted-foreground">tasks/24h</span>{" "}
            <span className="text-muted-foreground">·</span>{" "}
            <span
              className={cn(
                "font-medium",
                project.failure_rate_24h > 0.1 && "text-destructive",
                project.failure_rate_24h > 0.02 &&
                  project.failure_rate_24h <= 0.1 &&
                  "text-warning",
              )}
            >
              {formatPercent(project.failure_rate_24h)}
            </span>{" "}
            <span className="text-muted-foreground">fails</span>
          </div>
          <div className="tabular-nums text-muted-foreground">
            <span className="text-foreground">
              {project.workers_online}/{project.workers_total}
            </span>{" "}
            workers <span>·</span>{" "}
            <span className="text-foreground">
              {project.agents_online}/{project.agents_total}
            </span>{" "}
            agents
          </div>
          {project.stuck_commands > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-warning">
              <Terminal className="size-3.5" />
              {project.stuck_commands} stuck command
              {project.stuck_commands === 1 ? "" : "s"}
            </div>
          )}
          <div className="flex items-center gap-1.5 pt-1 text-xs text-muted-foreground">
            <Activity className="size-3.5" />
            {project.last_activity_at
              ? `last activity ${formatRelative(project.last_activity_at)}`
              : "no activity"}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Recent failures feed
// ---------------------------------------------------------------------------

function RecentFailuresFeed() {
  const [cursor, setCursor] = useState<string | null>(null);
  const [acc, setAcc] = useState<HomeRecentFailure[]>([]);
  const [loadedCursors, setLoadedCursors] = useState<Set<string>>(
    () => new Set(),
  );

  const query = useHomeRecentFailures({ limit: 50, cursor });
  const { data, isLoading, isError, isFetching, refetch } = query;

  // Accumulate across "Load more" clicks. When cursor is null the
  // first page replaces the accumulator. Subsequent pages append
  // once per unique cursor.
  useEffect(() => {
    if (!data) return;
    if (cursor === null) {
      setAcc(data.items);
      setLoadedCursors(new Set([""]));
      return;
    }
    if (loadedCursors.has(cursor)) return;
    setAcc((prev) => [...prev, ...data.items]);
    setLoadedCursors((prev) => {
      const next = new Set(prev);
      next.add(cursor);
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, cursor]);

  const nextCursor = data?.next_cursor ?? null;

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold leading-tight">Recent failures</h2>
        <p className="text-xs text-muted-foreground">
          Failed tasks across all your projects, newest first.
        </p>
      </div>

      {isError ? (
        <QueryError
          message="Failed to load recent failures"
          onRetry={() => refetch()}
        />
      ) : (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-44">When</TableHead>
                <TableHead className="w-36">Project</TableHead>
                <TableHead>Task</TableHead>
                <TableHead className="hidden lg:table-cell">
                  Exception
                </TableHead>
                <TableHead className="w-28">Priority</TableHead>
                <TableHead className="w-8"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && acc.length === 0 ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={6}>
                      <Skeleton className="h-10 w-full" />
                    </TableCell>
                  </TableRow>
                ))
              ) : acc.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-sm text-muted-foreground"
                  >
                    No failures in the visible window. Nice.
                  </TableCell>
                </TableRow>
              ) : (
                acc.map((f) => (
                  <FailureRow key={f.id} failure={f} />
                ))
              )}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between gap-2 border-t bg-muted/20 px-4 py-2 text-xs text-muted-foreground">
            <span className="tabular-nums">
              {acc.length} failure{acc.length === 1 ? "" : "s"} loaded
            </span>
            {nextCursor && (
              <Button
                size="sm"
                variant="outline"
                disabled={isFetching}
                onClick={() => setCursor(nextCursor)}
              >
                Load more
              </Button>
            )}
          </div>
        </Card>
      )}
    </section>
  );
}

function FailureRow({ failure }: { failure: HomeRecentFailure }) {
  // Multi-engine: the backend stamps the engine onto every failure
  // (see RecentFailurePublic in api/home.py). Deep-linking to
  // /tasks/celery/... for an RQ or Dramatiq failure would 404.
  const engine = failure.engine;
  return (
    <TableRow className="group cursor-pointer">
      <TableCell className="align-middle">
        <Link
          to="/projects/$slug/tasks/$engine/$taskId"
          params={{
            slug: failure.project_slug,
            engine,
            taskId: failure.task_id,
          }}
          className="block no-underline"
        >
          <DateCell value={failure.occurred_at} />
        </Link>
      </TableCell>
      <TableCell>
        <Link
          to="/projects/$slug"
          params={{ slug: failure.project_slug }}
          className="no-underline"
        >
          <Badge variant="outline" className="font-mono text-[11px]">
            {failure.project_slug}
          </Badge>
        </Link>
      </TableCell>
      <TableCell>
        <Link
          to="/projects/$slug/tasks/$engine/$taskId"
          params={{
            slug: failure.project_slug,
            engine,
            taskId: failure.task_id,
          }}
          className="block truncate text-sm no-underline"
        >
          <span className="font-medium">
            {failure.task_name ?? "(unnamed)"}
          </span>
          {failure.worker && (
            <span className="ml-1 text-xs text-muted-foreground">
              on {failure.worker}
            </span>
          )}
        </Link>
      </TableCell>
      <TableCell className="hidden max-w-[28rem] lg:table-cell">
        <Link
          to="/projects/$slug/tasks/$engine/$taskId"
          params={{
            slug: failure.project_slug,
            engine,
            taskId: failure.task_id,
          }}
          className="block truncate font-mono text-xs text-muted-foreground no-underline"
        >
          {failure.exception ? truncate(failure.exception, 60) : "-"}
        </Link>
      </TableCell>
      <TableCell>
        <TaskPriorityBadge
          priority={(failure.priority as TaskPriority) ?? "normal"}
        />
      </TableCell>
      <TableCell className="pr-3 text-right">
        <Link
          to="/projects/$slug/tasks/$engine/$taskId"
          params={{
            slug: failure.project_slug,
            engine,
            taskId: failure.task_id,
          }}
          aria-label="Open task"
          className="inline-flex text-muted-foreground transition-colors group-hover:text-foreground"
        >
          <ChevronRight className="size-4" />
        </Link>
      </TableCell>
    </TableRow>
  );
}
