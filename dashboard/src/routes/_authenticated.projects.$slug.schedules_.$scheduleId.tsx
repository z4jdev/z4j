/**
 * Schedule detail page (docs/SCHEDULER.md §13.1).
 *
 * Shows the schedule's metadata header (kind, expression, source,
 * catch-up policy) plus the Phase 4 fire-history panel - the most
 * recent 50 fires returned by ``GET /projects/{slug}/schedules/{id}/fires``,
 * with status, latency, and any error message visible inline.
 *
 * The page is intentionally read-mostly: enable/disable + trigger live
 * on the list page where they batch naturally; the detail page is
 * where operators come to investigate "why did this fire fail at 03:00?"
 */
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock,
  History,
  Inbox,
  Play,
  RefreshCw,
  XCircle,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/domain/page-header";
import { TaskPriorityBadge } from "@/components/domain/state-badges";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DateCell } from "@/components/domain/date-cell";
import { useCan } from "@/hooks/use-memberships";
import {
  useSchedule,
  useScheduleFires,
  useToggleSchedule,
  useTriggerSchedule,
} from "@/hooks/use-schedules";
import { ApiError } from "@/lib/api";
import type { ScheduleFirePublic, ScheduleFireStatus } from "@/lib/api-types";
import { cn } from "@/lib/utils";
import {
  CatchUpBadge,
  SourceBadge,
} from "@/routes/_authenticated.projects.$slug.schedules";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/schedules_/$scheduleId",
)({
  component: ScheduleDetailPage,
});

function ScheduleDetailPage() {
  const { slug, scheduleId } = Route.useParams();
  const {
    data: schedule,
    isLoading: scheduleLoading,
    error: scheduleError,
  } = useSchedule(slug, scheduleId);
  const {
    data: fires,
    isFetching: firesFetching,
    refetch: refetchFires,
  } = useScheduleFires(slug, scheduleId);

  const canManage = useCan(slug, "manage_schedules");
  const toggle = useToggleSchedule(slug);
  const trigger = useTriggerSchedule(slug);

  async function onToggle(enabled: boolean) {
    try {
      await toggle.mutateAsync({ scheduleId, enabled });
      toast.success(enabled ? "schedule enabled" : "schedule disabled");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`toggle failed: ${message}`);
    }
  }

  async function onTrigger() {
    try {
      await trigger.mutateAsync(scheduleId);
      toast.success("trigger command issued");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`trigger failed: ${message}`);
    }
  }

  if (scheduleError) {
    return (
      <div className="space-y-6 p-4 md:p-6">
        <Link
          to="/projects/$slug/schedules"
          params={{ slug }}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-3" />
          back to schedules
        </Link>
        <EmptyState
          icon={AlertTriangle}
          title="failed to load schedule"
          description={
            scheduleError instanceof Error
              ? scheduleError.message
              : "unknown error"
          }
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6">
      <Link
        to="/projects/$slug/schedules"
        params={{ slug }}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3" />
        back to schedules
      </Link>

      <PageHeader
        title={schedule?.name ?? "loading..."}
        icon={History}
        description={
          schedule?.task_name ?? "schedule fire history and metadata"
        }
        actions={
          <div className="flex items-center gap-2">
            {schedule && (
              <div className="flex items-center gap-2 px-2 text-xs text-muted-foreground">
                <span>{schedule.is_enabled ? "enabled" : "disabled"}</span>
                <Switch
                  checked={schedule.is_enabled}
                  onCheckedChange={onToggle}
                  disabled={!canManage || toggle.isPending}
                />
              </div>
            )}
            {schedule && canManage && (
              <Button
                size="sm"
                variant="outline"
                onClick={onTrigger}
                disabled={trigger.isPending}
              >
                <Play className="size-3" />
                Trigger now
              </Button>
            )}
          </div>
        }
      />

      {scheduleLoading && <Skeleton className="h-40 w-full" />}
      {schedule && <ScheduleMetadataCard schedule={schedule} />}

      <FireHistoryCard
        fires={fires}
        loading={!fires}
        fetching={firesFetching}
        onRefresh={() => refetchFires()}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Metadata card - schedule shape + provenance + scheduling parameters
// ---------------------------------------------------------------------------

function ScheduleMetadataCard({
  schedule,
}: {
  schedule: NonNullable<ReturnType<typeof useSchedule>["data"]>;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Schedule</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-3">
          <Field label="Kind">
            <Badge variant="outline">{schedule.kind}</Badge>
          </Field>
          <Field label="Expression">
            <span className="font-mono text-xs">{schedule.expression}</span>
          </Field>
          <Field label="Timezone">
            <span className="font-mono text-xs">{schedule.timezone}</span>
          </Field>
          <Field label="Engine / Scheduler">
            <span className="font-mono text-xs">
              {schedule.engine} / {schedule.scheduler}
            </span>
          </Field>
          <Field label="Queue">
            <span className="font-mono text-xs text-muted-foreground">
              {schedule.queue ?? "default"}
            </span>
          </Field>
          <Field label="Priority">
            <TaskPriorityBadge priority={schedule.priority} compact />
          </Field>
          <Field label="Source">
            <SourceBadge source={schedule.source} />
          </Field>
          <Field label="Catch-up">
            <CatchUpBadge value={schedule.catch_up} />
          </Field>
          <Field label="Total runs">
            <span className="tabular-nums">{schedule.total_runs}</span>
          </Field>
          <Field label="Last run">
            <DateCell value={schedule.last_run_at} />
          </Field>
          <Field label="Next run">
            <DateCell value={schedule.next_run_at} />
          </Field>
          {schedule.source_hash && (
            <Field label="Source hash">
              <span
                className="font-mono text-[10px] text-muted-foreground"
                title={schedule.source_hash}
              >
                {schedule.source_hash.slice(0, 12)}…
              </span>
            </Field>
          )}
        </dl>
      </CardContent>
    </Card>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <dt className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fire history card - "Last 50 fires" panel
// ---------------------------------------------------------------------------

function FireHistoryCard({
  fires,
  loading,
  fetching,
  onRefresh,
}: {
  fires: ScheduleFirePublic[] | undefined;
  loading: boolean;
  fetching: boolean;
  onRefresh: () => void;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-base">Last 50 fires</CardTitle>
        <Button
          size="sm"
          variant="ghost"
          onClick={onRefresh}
          disabled={fetching}
          className="h-8"
        >
          <RefreshCw
            className={cn("size-4", fetching && "animate-spin")}
          />
        </Button>
      </CardHeader>
      <CardContent>
        {loading && (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        )}
        {fires && fires.length === 0 && (
          <EmptyState
            icon={Inbox}
            title="no fires recorded"
            description="this schedule has not fired yet, or its fires predate the schedule_fires history retention window"
          />
        )}
        {fires && fires.length > 0 && (
          <div className="overflow-hidden rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-32">Status</TableHead>
                  <TableHead>Scheduled for</TableHead>
                  <TableHead>Fired at</TableHead>
                  <TableHead className="text-right">Latency</TableHead>
                  <TableHead>Detail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {fires.map((fire) => (
                  <TableRow key={fire.id}>
                    <TableCell>
                      <FireStatusBadge status={fire.status} />
                    </TableCell>
                    <TableCell>
                      <DateCell value={fire.scheduled_for} />
                    </TableCell>
                    <TableCell>
                      <DateCell value={fire.fired_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      <FireLatency latencyMs={fire.latency_ms} />
                    </TableCell>
                    <TableCell className="max-w-md">
                      <FireDetailCell fire={fire} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Status pill that visually separates the lifecycle stages a fire
 * can land in, mirroring z4j's ``schedule_fires.status`` enum.
 *
 * Distinct icon + color for each so a row of 50 fires is scannable
 * at a glance: green for clean acks, red for failures, amber for
 * buffered (no agent online), blue for the in-flight states.
 */
function FireStatusBadge({ status }: { status: ScheduleFireStatus }) {
  const map: Record<
    ScheduleFireStatus,
    { label: string; className: string; icon: typeof CheckCircle2 }
  > = {
    pending: {
      label: "pending",
      className:
        "border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-400",
      icon: Clock,
    },
    delivered: {
      label: "delivered",
      className:
        "border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-400",
      icon: Zap,
    },
    buffered: {
      label: "buffered",
      className:
        "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
      icon: Inbox,
    },
    acked_success: {
      label: "success",
      className:
        "border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400",
      icon: CheckCircle2,
    },
    acked_failed: {
      label: "failed",
      className:
        "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
      icon: XCircle,
    },
    failed: {
      label: "failed",
      className:
        "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
      icon: AlertTriangle,
    },
  };
  const config = map[status] ?? {
    label: status,
    className: "",
    icon: Clock,
  };
  const Icon = config.icon;
  return (
    <Badge
      variant="outline"
      className={cn("gap-1 text-[10px]", config.className)}
    >
      <Icon className="size-3" />
      {config.label}
    </Badge>
  );
}

function FireLatency({ latencyMs }: { latencyMs: number | null }) {
  if (latencyMs === null) {
    return <span className="text-xs text-muted-foreground">-</span>;
  }
  // Sub-second rendered as ms; multi-second rendered as seconds with
  // one decimal so the column is scannable for both fast successes
  // and slow timeouts in the same view.
  if (latencyMs < 1000) {
    return (
      <span className="font-mono text-xs tabular-nums">{latencyMs}ms</span>
    );
  }
  return (
    <span className="font-mono text-xs tabular-nums">
      {(latencyMs / 1000).toFixed(1)}s
    </span>
  );
}

function FireDetailCell({ fire }: { fire: ScheduleFirePublic }) {
  if (fire.error_message) {
    return (
      <div className="space-y-0.5">
        {fire.error_code && (
          <div className="font-mono text-[10px] uppercase text-red-700 dark:text-red-400">
            {fire.error_code}
          </div>
        )}
        <div
          className="line-clamp-2 text-xs text-muted-foreground"
          title={fire.error_message}
        >
          {fire.error_message}
        </div>
      </div>
    );
  }
  if (fire.command_id) {
    return (
      <span
        className="font-mono text-[10px] text-muted-foreground"
        title={fire.command_id}
      >
        cmd:{fire.command_id.slice(0, 8)}…
      </span>
    );
  }
  return <span className="text-xs text-muted-foreground">-</span>;
}
