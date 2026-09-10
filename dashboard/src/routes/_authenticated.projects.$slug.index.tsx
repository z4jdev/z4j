import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { ProjectOnboarding } from "@/components/domain/project-onboarding";
import { QueryError } from "@/components/domain/query-error";
import { RefreshButton } from "@/components/domain/refresh-button";
import { ScheduleRunStrip } from "@/components/domain/schedule-run-strip";
import { StatCard } from "@/components/domain/stat-card";
import {
  ScheduleHealthBadge,
  TaskStateBadge,
} from "@/components/domain/state-badges";
import { TimeRangeSelect } from "@/components/domain/time-range-select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useCircuitBreakerThreshold,
  useScheduleRuns,
  useSchedules,
} from "@/hooks/use-schedules";
import { TIME_RANGE_LABELS, useStats, type TimeRange } from "@/hooks/use-stats";
import { useTasks } from "@/hooks/use-tasks";
import type { TaskState } from "@/lib/api-types";
import { formatCompact, formatPercent, formatRelative } from "@/lib/format";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  Clock,
  Cpu,
  LayoutDashboard,
  Network,
  Terminal,
} from "lucide-react";
import { useMemo, useState } from "react";

export const Route = createFileRoute("/_authenticated/projects/$slug/")({
  component: OverviewPage,
});

function OverviewPage() {
  const { slug } = Route.useParams();
  const [timeRange, setTimeRange] = useState<TimeRange>("24");
  const {
    data: stats,
    isFetching,
    isError,
    refetch,
  } = useStats(slug, timeRange);
  const { data: recent } = useTasks(slug, { limit: 5 });

  const rangeLabel = TIME_RANGE_LABELS[timeRange]
    .replace("Last ", "")
    .toLowerCase();

  return (
    <PageShell>
      <PageHeader
        title="Overview"
        icon={LayoutDashboard}
        description="Health, recent activity and the work that needs attention."
        actions={
          <div className="flex items-center gap-2">
            <TimeRangeSelect
              value={timeRange}
              onValueChange={setTimeRange}
              options={(
                Object.entries(TIME_RANGE_LABELS) as [TimeRange, string][]
              ).map(([value, label]) => ({ value, label }))}
              aria-label="Time range"
            />
            <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
          </div>
        }
      />

      {isError && (
        <QueryError
          message="Failed to load project stats"
          onRetry={() => refetch()}
        />
      )}

      {stats && stats.agents_online + stats.agents_offline === 0 && (
        <ProjectOnboarding slug={slug} />
      )}

      {/* Stat cards row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label={`Tasks (${rangeLabel})`}
          value={
            stats
              ? formatCompact(
                  stats.tasks_succeeded_24h + stats.tasks_failed_24h,
                )
              : "-"
          }
          hint={
            stats
              ? `${formatCompact(stats.tasks_succeeded_24h)} succeeded - ${formatCompact(stats.tasks_failed_24h)} failed`
              : undefined
          }
          icon={ClipboardList}
          href={`/projects/${slug}/tasks`}
        />
        <StatCard
          label={`Failure rate (${rangeLabel})`}
          value={stats ? formatPercent(stats.failure_rate_24h) : "-"}
          hint="based on terminal task outcomes"
          icon={AlertTriangle}
          accent={
            stats && stats.failure_rate_24h > 0.1 ? "destructive" : "default"
          }
          href={`/projects/${slug}/tasks?state=failure`}
        />
        <StatCard
          label="Agents online"
          value={
            stats
              ? `${stats.agents_online}/${stats.agents_online + stats.agents_offline}`
              : "-"
          }
          hint={
            !stats
              ? "Checking connection"
              : stats.agents_online + stats.agents_offline === 0
                ? "Connect your first agent"
                : stats.agents_offline > 0
                  ? `${stats.agents_offline} offline · check connectivity`
                  : "All registered agents connected"
          }
          icon={Network}
          accent={
            !stats || stats.agents_online + stats.agents_offline === 0
              ? "default"
              : stats.agents_offline > 0
                ? "warning"
                : "success"
          }
          href={`/projects/${slug}/agents`}
        />
        <StatCard
          label="Workers online"
          value={
            stats
              ? `${stats.workers_online}/${stats.workers_online + stats.workers_offline}`
              : "-"
          }
          hint="active worker processes"
          icon={Cpu}
          href={`/projects/${slug}/workers`}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3 lg:items-start">
        {/* Task state breakdown */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Tasks by state</CardTitle>
            <CardDescription>
              Live counts across the entire project history.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-3 min-[480px]:grid-cols-3 sm:grid-cols-5">
            {stats &&
              (Object.keys(stats.tasks_by_state) as TaskState[]).map(
                (state) => (
                  <a
                    key={state}
                    href={`/projects/${slug}/tasks?state=${state}`}
                    className="flex flex-col items-center gap-2 rounded-lg border bg-card/40 p-3 transition-colors hover:bg-accent"
                  >
                    <TaskStateBadge state={state} />
                    <span className="text-2xl font-semibold tabular-nums">
                      {formatCompact(stats.tasks_by_state[state])}
                    </span>
                  </a>
                ),
              )}
            {!stats &&
              Array.from({ length: 9 }).map((_, i) => (
                <Skeleton key={i} className="h-20 w-full" />
              ))}
          </CardContent>
        </Card>

        {/* Recent tasks: spans both rows of the right column so the first
            row has no empty cell beside Tasks by state. */}
        <Card className="lg:row-span-2">
          <CardHeader>
            <CardTitle>Recent tasks</CardTitle>
            <CardDescription>
              Most recent activity for this project.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {recent?.items.map((task) => (
              <Link
                key={task.id}
                to="/projects/$slug/tasks/$engine/$taskId"
                params={{
                  slug,
                  engine: task.engine,
                  taskId: task.task_id,
                }}
                className="flex items-center gap-3 rounded-md border bg-card/40 p-2 transition-colors hover:bg-accent"
              >
                <Activity className="size-4 shrink-0 opacity-60" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">
                    {task.name}
                  </div>
                  <div className="truncate text-xs text-muted-foreground">
                    {formatRelative(
                      task.finished_at ??
                        task.started_at ??
                        task.received_at ??
                        task.created_at,
                    )}
                  </div>
                </div>
                <TaskStateBadge state={task.state} />
              </Link>
            ))}
            {recent && recent.items.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">
                no tasks yet - start a z4j-connected worker (Celery, RQ, or
                Dramatiq)
              </p>
            )}
            {!recent &&
              Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
          </CardContent>
        </Card>

        {/* Schedules needing attention: under Tasks by state in the wide
            column. Silent when everything is healthy, because a panel that
            always says "fine" trains the eye to skip it. */}
        <ScheduleAttentionCard slug={slug} className="lg:col-span-2" />
      </div>
      <section aria-label="Command delivery" className="space-y-3">
        <h2 className="text-lg font-semibold">Command delivery</h2>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Pending commands"
            value={stats ? formatCompact(stats.commands_pending) : "-"}
            hint="awaiting agent ack"
            icon={Terminal}
            accent={stats && stats.commands_pending > 5 ? "warning" : "default"}
            href={`/projects/${slug}/commands`}
          />
          <StatCard
            label={`Commands done (${rangeLabel})`}
            value={stats ? formatCompact(stats.commands_completed_24h) : "-"}
            icon={CheckCircle2}
            accent="success"
            href={`/projects/${slug}/commands`}
          />
          <StatCard
            label={`Commands failed (${rangeLabel})`}
            value={stats ? formatCompact(stats.commands_failed_24h) : "-"}
            icon={AlertTriangle}
            accent={
              stats && stats.commands_failed_24h > 0 ? "destructive" : "default"
            }
            href={`/projects/${slug}/commands`}
          />
          <StatCard
            label={`Commands timed out (${rangeLabel})`}
            value={stats ? formatCompact(stats.commands_timeout_24h) : "-"}
            icon={Clock}
            href={`/projects/${slug}/commands`}
          />
        </div>
      </section>
    </PageShell>
  );
}

/**
 * Schedules whose most recent fires are an unbroken run of failures, worst
 * first, each with its run strip. This is the "which of my schedules are
 * chronically failing" answer on the page an operator lands on, drawn from
 * the same counts the circuit breaker acts on.
 */
export function ScheduleAttentionCard({
  slug,
  className,
}: {
  slug: string;
  className?: string;
}) {
  const {
    data: schedules,
    isPending: schedulesPending,
    isError: schedulesError,
  } = useSchedules(slug);
  const { data: threshold = 0 } = useCircuitBreakerThreshold(slug);
  const failing = useMemo(
    () =>
      (schedules ?? [])
        .filter((s) => (s.consecutive_failures ?? 0) > 0)
        .sort(
          (a, b) =>
            (b.consecutive_failures ?? 0) - (a.consecutive_failures ?? 0),
        )
        .slice(0, 8),
    [schedules],
  );
  const ids = useMemo(() => failing.map((s) => s.id), [failing]);
  const { data: runsById, isError: runsError } = useScheduleRuns(slug, ids);

  // Nothing until the list has loaded and nothing on an error: a warning
  // card over skeletons, or over a failed request, is a false alarm on the
  // page an operator lands on.
  if (schedulesPending || schedulesError || failing.length === 0) return null;

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="size-4 text-warning" aria-hidden />
              Schedules needing attention
            </CardTitle>
            <CardDescription>
              Consecutive failures on the most recent fires.{" "}
              {threshold > 0
                ? `The breaker auto-disables a schedule at ${threshold}.`
                : "The circuit breaker is switched off, so nothing is auto-disabled."}
            </CardDescription>
          </div>
          <Link
            to="/projects/$slug/schedules"
            params={{ slug }}
            className="whitespace-nowrap text-sm text-primary hover:underline"
          >
            all schedules
          </Link>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        {failing.map((s) => (
          <Link
            key={s.id}
            to="/projects/$slug/schedules/$scheduleId"
            params={{ slug, scheduleId: s.id }}
            className="flex items-center gap-4 rounded-md border bg-card/40 p-2 pl-3 transition-colors hover:bg-accent"
          >
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{s.name}</div>
              <div className="truncate text-xs text-muted-foreground">
                {s.task_name}
                {s.last_run_at
                  ? ` · last fired ${formatRelative(s.last_run_at)}`
                  : ""}
              </div>
            </div>
            <ScheduleRunStrip runs={runsById?.get(s.id)} error={runsError} />
            <ScheduleHealthBadge
              consecutiveFailures={s.consecutive_failures ?? 0}
              threshold={threshold}
            />
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}
