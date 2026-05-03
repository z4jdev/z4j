import { useState } from "react";
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
  RefreshCw,
  Terminal,
} from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { QueryError } from "@/components/domain/query-error";
import { StatCard } from "@/components/domain/stat-card";
import { TaskStateBadge } from "@/components/domain/state-badges";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useStats,
  TIME_RANGE_LABELS,
  type TimeRange,
} from "@/hooks/use-stats";
import { useTasks } from "@/hooks/use-tasks";
import { formatCompact, formatPercent, formatRelative } from "@/lib/format";
import type { TaskState } from "@/lib/api-types";

export const Route = createFileRoute("/_authenticated/projects/$slug/")({
  component: OverviewPage,
});

function OverviewPage() {
  const { slug } = Route.useParams();
  const [timeRange, setTimeRange] = useState<TimeRange>("24");
  const { data: stats, isFetching, isError, refetch } = useStats(slug, timeRange);
  const { data: recent } = useTasks(slug, { limit: 5 });

  const rangeLabel = TIME_RANGE_LABELS[timeRange]
    .replace("Last ", "")
    .toLowerCase();

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Overview"
        icon={LayoutDashboard}
        description={`live state of project ${slug}`}
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={timeRange}
              onValueChange={(v) => setTimeRange(v as TimeRange)}
            >
              <SelectTrigger className="h-9 w-36">
                <Clock className="size-4 opacity-60" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(TIME_RANGE_LABELS) as [TimeRange, string][]).map(
                  ([value, label]) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw
                className={isFetching ? "size-4 animate-spin" : "size-4"}
              />
              Refresh
            </Button>
          </div>
        }
      />

      {isError && (
        <QueryError
          message="Failed to load project stats"
          onRetry={() => refetch()}
        />
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
          hint="connected to the brain"
          icon={Network}
          accent={
            stats && stats.agents_online === 0 && stats.agents_offline > 0
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
        <StatCard
          label="Pending commands"
          value={stats ? formatCompact(stats.commands_pending) : "-"}
          hint="awaiting agent ack"
          icon={Terminal}
          accent={
            stats && stats.commands_pending > 5 ? "warning" : "default"
          }
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

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Task state breakdown */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Tasks by state</CardTitle>
            <CardDescription>
              Live counts across the entire project history.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-3 gap-3 sm:grid-cols-5">
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

        {/* Recent tasks */}
        <Card>
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
                no tasks yet - start a z4j-connected worker (Celery, RQ, or Dramatiq)
              </p>
            )}
            {!recent &&
              Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
