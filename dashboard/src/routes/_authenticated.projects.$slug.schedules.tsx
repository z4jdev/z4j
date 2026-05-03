/**
 * Schedules page - sortable schedule list with DataTable.
 *
 * Features:
 * - Full-text search across name, task
 * - Kind filter (cron/interval/solar/clocked)
 * - Enabled/disabled filter
 * - Sortable columns (name, kind, task, priority, next_run, last_run, total_runs)
 * - Inline enable/disable switch and trigger button
 */
import { useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import {
  GitCompare,
  History,
  Pencil,
  Play,
  Plus,
  RefreshCcwDot,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/domain/page-header";
import { TaskPriorityBadge } from "@/components/domain/state-badges";
import { EmptyState } from "@/components/domain/empty-state";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { ScheduleFormDialog } from "@/components/domain/schedule-form-dialog";
import { DataTable } from "@/components/ui/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useCan } from "@/hooks/use-memberships";
import {
  useDeleteSchedule,
  useScheduleResync,
  useSchedules,
  useToggleSchedule,
  useTriggerSchedule,
} from "@/hooks/use-schedules";
import { DateCell } from "@/components/domain/date-cell";
import { ApiError } from "@/lib/api";
import type { ScheduleKind, SchedulePublic } from "@/lib/api-types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/schedules",
)({
  component: SchedulesPage,
});

const SCHEDULE_KINDS: ScheduleKind[] = ["cron", "interval", "solar", "clocked"];

function SchedulesPage() {
  const { slug } = Route.useParams();
  const { data: schedules, isLoading, isFetching, refetch } = useSchedules(slug);
  const toggle = useToggleSchedule(slug);
  const trigger = useTriggerSchedule(slug);
  const deleteSched = useDeleteSchedule(slug);
  const resync = useScheduleResync(slug);
  const { confirm, dialog: confirmDialog } = useConfirm();

  // Form-dialog state. Single component handles both create and
  // edit; ``editing`` carries the row when in edit mode.
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<SchedulePublic | undefined>(undefined);

  const [searchQuery, setSearchQuery] = useState("");
  const [kindFilter, setKindFilter] = useState<ScheduleKind | "all">("all");
  const [enabledFilter, setEnabledFilter] = useState<
    "all" | "enabled" | "disabled"
  >("all");

  const activeFilterCount =
    (kindFilter !== "all" ? 1 : 0) + (enabledFilter !== "all" ? 1 : 0);

  const clearFilters = () => {
    setSearchQuery("");
    setKindFilter("all");
    setEnabledFilter("all");
  };

  // Client-side filtering
  const filteredSchedules = useMemo(() => {
    if (!schedules) return [];
    return schedules.filter((s) => {
      if (kindFilter !== "all" && s.kind !== kindFilter) return false;
      if (enabledFilter === "enabled" && !s.is_enabled) return false;
      if (enabledFilter === "disabled" && s.is_enabled) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !s.name.toLowerCase().includes(q) &&
          !s.task_name.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [schedules, kindFilter, enabledFilter, searchQuery]);

  async function onToggle(scheduleId: string, enabled: boolean) {
    try {
      await toggle.mutateAsync({ scheduleId, enabled });
      toast.success(enabled ? "schedule enabled" : "schedule disabled");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`toggle failed: ${message}`);
    }
  }

  async function onTrigger(scheduleId: string) {
    try {
      await trigger.mutateAsync(scheduleId);
      toast.success("trigger command issued");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`trigger failed: ${message}`);
    }
  }

  function onEdit(s: SchedulePublic) {
    setEditing(s);
    setFormOpen(true);
  }

  function onCreate() {
    setEditing(undefined);
    setFormOpen(true);
  }

  // Sync now: ask every online agent to drain their scheduler
  // adapters (celery-beat, apscheduler, rq-scheduler, arqcron,
  // hueyperiodic, taskiqscheduler) and re-emit a full inventory
  // snapshot. z4j reconciles each snapshot against the DB
  // (insert / update / delete-missing) scoped to (project,
  // scheduler). Used for first-time onboarding (existing celery-
  // beat schedules show up without editing each one) and drift
  // recovery (schedules added directly via SQL while the agent
  // was offline). Returns 202 - the snapshot events arrive
  // async; the hook auto-refetches at 0s and 3s.
  async function onResync() {
    try {
      const result = await resync.mutateAsync();
      const adapters =
        result.schedulers_observed.length > 0
          ? result.schedulers_observed.join(", ")
          : "no scheduler adapters";
      toast.success(
        `Sync requested - ${result.agents_dispatched} agent${result.agents_dispatched === 1 ? "" : "s"} (${adapters}). Schedules will refresh in a moment.`,
      );
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : "failed to dispatch sync command";
      toast.error(msg);
    }
  }

  // ---------------------------------------------------------------
  // Bulk actions. Each bulk handler runs the per-row mutation in
  // parallel via Promise.allSettled so a single failed row doesn't
  // abort the rest. The summary toast names success + failure
  // counts; the operator can re-run on the failed subset.
  //
  // The mutation hooks already invalidate the schedules query on
  // success, so the dashboard refreshes itself once the bulk runs
  // complete.
  // ---------------------------------------------------------------

  async function _runBulk<T>(
    rows: SchedulePublic[],
    label: string,
    fn: (s: SchedulePublic) => Promise<T>,
    clearSelection: () => void,
  ) {
    if (rows.length === 0) return;
    const results = await Promise.allSettled(rows.map(fn));
    const ok = results.filter((r) => r.status === "fulfilled").length;
    const fail = results.length - ok;
    if (fail === 0) {
      toast.success(`${label}: ${ok} schedule${ok === 1 ? "" : "s"}`);
    } else if (ok === 0) {
      toast.error(`${label} failed for all ${fail} selected`);
    } else {
      toast.warning(`${label}: ${ok} ok / ${fail} failed`);
    }
    clearSelection();
  }

  async function onBulkEnable(rows: SchedulePublic[], clear: () => void) {
    await _runBulk(
      rows.filter((r) => !r.is_enabled),
      "enable",
      (s) => toggle.mutateAsync({ scheduleId: s.id, enabled: true }),
      clear,
    );
  }

  async function onBulkDisable(rows: SchedulePublic[], clear: () => void) {
    await _runBulk(
      rows.filter((r) => r.is_enabled),
      "disable",
      (s) => toggle.mutateAsync({ scheduleId: s.id, enabled: false }),
      clear,
    );
  }

  async function onBulkTrigger(rows: SchedulePublic[], clear: () => void) {
    await _runBulk(
      rows,
      "trigger",
      (s) => trigger.mutateAsync(s.id),
      clear,
    );
  }

  function onBulkDelete(rows: SchedulePublic[], clear: () => void) {
    confirm({
      title: `Delete ${rows.length} schedule${rows.length === 1 ? "" : "s"}?`,
      description: (
        <>
          This permanently removes the selected schedules. Any{" "}
          <code>pending_fires</code> rows attached to them are
          cascaded; fire history is preserved.{" "}
          {rows.some((r) => r.source !== "dashboard") && (
            <>
              <strong>Heads up:</strong> some selected rows have a
              non-dashboard source, they may be re-created on the
              next reconcile pass unless you also remove them
              upstream.
            </>
          )}
        </>
      ),
      confirmLabel: `Delete ${rows.length}`,
      onConfirm: () =>
        _runBulk(rows, "delete", (s) => deleteSched.mutateAsync(s.id), clear),
    });
  }

  function onDelete(s: SchedulePublic) {
    confirm({
      title: `Delete schedule "${s.name}"?`,
      description: (
        <>
          This permanently removes the schedule and any{" "}
          <code>pending_fires</code> rows attached to it. The schedule's
          fire history (last 30 days by default) is kept for forensics.
          {s.source !== "dashboard" && (
            <>
              {" "}
              <strong>Heads up:</strong> this schedule has{" "}
              <code>source={s.source}</code>. Deleting it here will be
              re-created on the next reconcile pass from that source
              unless you also remove it from the upstream config.
            </>
          )}
        </>
      ),
      confirmLabel: "Delete",
      onConfirm: async () => {
        try {
          await deleteSched.mutateAsync(s.id);
          toast.success(`schedule "${s.name}" deleted`);
        } catch (err) {
          const message =
            err instanceof ApiError ? err.message : (err as Error).message;
          toast.error(`delete failed: ${message}`);
        }
      },
    });
  }

  const canManage = useCan(slug, "manage_schedules");
  const columns = useScheduleColumns({
    slug,
    onToggle,
    onTrigger,
    onEdit,
    onDelete,
    triggerPending: trigger.isPending,
    canManage,
  });

  // Filter toolbar - rendered inside the DataTable toolbar slot
  const filterToolbar = (
    <div className="flex items-center gap-3">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search schedules..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="h-9 pl-9"
        />
      </div>
      <Select
        value={kindFilter}
        onValueChange={(v) => setKindFilter(v as ScheduleKind | "all")}
      >
        <SelectTrigger className="h-9 w-36 shrink-0">
          <SelectValue placeholder="Kind" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All kinds</SelectItem>
          {SCHEDULE_KINDS.map((k) => (
            <SelectItem key={k} value={k}>
              {k}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={enabledFilter}
        onValueChange={(v) =>
          setEnabledFilter(v as "all" | "enabled" | "disabled")
        }
      >
        <SelectTrigger className="h-9 w-36 shrink-0">
          <SelectValue placeholder="Status" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All</SelectItem>
          <SelectItem value="enabled">Enabled</SelectItem>
          <SelectItem value="disabled">Disabled</SelectItem>
        </SelectContent>
      </Select>
      {/* Always reserve space - invisible when no filters active */}
      <Button
        variant="ghost"
        size="sm"
        className={cn(
          "h-9 shrink-0 gap-1 text-xs text-muted-foreground",
          activeFilterCount === 0 && "pointer-events-none invisible",
        )}
        onClick={clearFilters}
      >
        <X className="size-3" />
        Clear
        <Badge variant="secondary" className="ml-0.5 px-1.5 py-0 text-[10px]">
          {activeFilterCount}
        </Badge>
      </Button>
    </div>
  );

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Schedules"
        icon={History}
        description="manage every schedule the z4j-scheduler ticks for this project"
        actions={
          <div className="flex items-center gap-2">
            {canManage && (
              <Button size="sm" onClick={onCreate}>
                <Plus className="size-4" />
                New schedule
              </Button>
            )}
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                onClick={onResync}
                disabled={resync.isPending}
                title={
                  "Force every online agent to re-emit a full schedule " +
                  "inventory (boot snapshot). Use after first-time " +
                  "install to surface existing celery-beat / aps / rq " +
                  "schedules, or to recover from drift."
                }
              >
                <RefreshCcwDot
                  className={
                    resync.isPending ? "size-4 animate-spin" : "size-4"
                  }
                />
                Sync now
              </Button>
            )}
            {canManage && (
              <Button asChild variant="outline" size="sm">
                <Link
                  to="/projects/$slug/schedules/reconcile"
                  params={{ slug }}
                >
                  <GitCompare className="size-4" />
                  Reconcile diff
                </Link>
              </Button>
            )}
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

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}
      {schedules && filteredSchedules.length === 0 && (
        <div>
          <div className="flex h-[52px] items-center">
            <div className="w-full">{filterToolbar}</div>
          </div>
          <div className="mt-2 overflow-hidden rounded-lg border">
            <EmptyState
              icon={History}
              title="no schedules match"
              description={
                activeFilterCount > 0 || searchQuery
                  ? "try adjusting your filters or search query"
                  : "schedules your scheduler has published (celery-beat, rq-scheduler, etc.) will sync here once the agent observes them"
              }
            />
          </div>
        </div>
      )}
      {schedules && filteredSchedules.length > 0 && (
        <DataTable
          columns={columns}
          data={filteredSchedules}
          enableSelection
          enableSorting
          totalLabel={`${filteredSchedules.length} schedule${filteredSchedules.length === 1 ? "" : "s"}`}
          toolbar={(ctx) =>
            ctx.selectedCount > 0 ? (
              <BulkActionToolbar
                ctx={ctx as { selectedRows: SchedulePublic[]; selectedCount: number; clearSelection: () => void }}
                canManage={canManage}
                onBulkEnable={(rows) => onBulkEnable(rows, ctx.clearSelection)}
                onBulkDisable={(rows) => onBulkDisable(rows, ctx.clearSelection)}
                onBulkTrigger={(rows) => onBulkTrigger(rows, ctx.clearSelection)}
                onBulkDelete={(rows) => onBulkDelete(rows, ctx.clearSelection)}
              />
            ) : (
              filterToolbar
            )
          }
        />
      )}

      <ScheduleFormDialog
        slug={slug}
        open={formOpen}
        onClose={() => setFormOpen(false)}
        existing={editing}
      />
      {confirmDialog}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

function useScheduleColumns({
  slug,
  onToggle,
  onTrigger,
  onEdit,
  onDelete,
  triggerPending,
  canManage,
}: {
  slug: string;
  onToggle: (scheduleId: string, enabled: boolean) => void;
  onTrigger: (scheduleId: string) => void;
  onEdit: (s: SchedulePublic) => void;
  onDelete: (s: SchedulePublic) => void;
  triggerPending: boolean;
  canManage: boolean;
}): ColumnDef<SchedulePublic, unknown>[] {
  return useMemo(
    () => [
      {
        accessorKey: "name",
        header: "Name",
        cell: ({ row }: { row: { original: SchedulePublic } }) => {
          const s = row.original;
          // Linkify the name to the schedule detail page where the
          // "Last 50 fires" panel lives. Keep the scheduler subtitle
          // unlinked so it reads as plain metadata.
          return (
            <div>
              <Link
                to="/projects/$slug/schedules/$scheduleId"
                params={{ slug, scheduleId: s.id }}
                className="font-medium underline-offset-4 hover:underline"
              >
                {s.name}
              </Link>
              <div className="font-mono text-xs text-muted-foreground">
                {s.scheduler}
              </div>
            </div>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "kind",
        header: "Kind",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <Badge variant="outline">{row.original.kind}</Badge>
        ),
        enableSorting: true,
      },
      {
        id: "expression",
        accessorKey: "expression",
        header: "Expression",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <span className="font-mono text-xs">{row.original.expression}</span>
        ),
        enableSorting: false,
      },
      {
        accessorKey: "task_name",
        header: "Task",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.task_name}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "source",
        header: "Source",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <SourceBadge source={row.original.source} />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "scheduler",
        header: "Scheduler",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.scheduler}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "catch_up",
        header: "Catch-up",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <CatchUpBadge value={row.original.catch_up} />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "priority",
        header: "Priority",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <TaskPriorityBadge priority={row.original.priority} compact />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "last_run_at",
        header: "Last run",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <DateCell value={row.original.last_run_at} />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "next_run_at",
        header: "Next run",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <DateCell value={row.original.next_run_at} />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "total_runs",
        header: "Runs",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <span className="tabular-nums text-sm">
            {row.original.total_runs}
          </span>
        ),
        enableSorting: true,
      },
      {
        id: "enabled",
        header: "Enabled",
        cell: ({ row }: { row: { original: SchedulePublic } }) => (
          <Switch
            checked={row.original.is_enabled}
            onCheckedChange={(checked) => onToggle(row.original.id, checked)}
            disabled={!canManage}
          />
        ),
        enableSorting: false,
      },
      {
        id: "actions",
        header: "",
        cell: ({ row }: { row: { original: SchedulePublic } }) => {
          if (!canManage) return null;
          const s = row.original;
          return (
            <div className="flex items-center justify-end gap-1">
              <Button
                size="sm"
                variant="outline"
                onClick={() => onTrigger(s.id)}
                disabled={triggerPending}
                title="Trigger this schedule now"
              >
                <Play className="size-3" />
                Run
              </Button>
              <Button
                size="icon"
                variant="ghost"
                className="h-8 w-8"
                onClick={() => onEdit(s)}
                title="Edit"
              >
                <Pencil className="size-3.5" />
              </Button>
              <Button
                size="icon"
                variant="ghost"
                className="h-8 w-8 text-destructive hover:bg-destructive/10 hover:text-destructive"
                onClick={() => onDelete(s)}
                title="Delete"
              >
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          );
        },
        enableSorting: false,
      },
    ],
    [slug, onToggle, onTrigger, onEdit, onDelete, triggerPending, canManage],
  );
}

// ---------------------------------------------------------------------------
// Source / catch-up badges - small UI helpers shared with the detail page.
// ---------------------------------------------------------------------------

/**
 * Badge that shows where a schedule originated. The vocabulary is open
 * (z4j stores arbitrary strings up to 64 chars) but in practice
 * we recognise three families: ``dashboard`` (created in-app),
 * ``imported`` / ``imported_*`` (one-shot migration from celery-beat,
 * rq-scheduler, cron, ...), and ``declarative:*`` (managed by a
 * framework reconciler running inside the customer's app process).
 *
 * The visual treatment makes the lifecycle obvious: dashboard rows are
 * the operator's playground (default outline), imported rows are
 * historical artifacts (muted secondary), declarative rows are
 * machine-managed and not safe to edit by hand (subtle warning tone).
 */
function SourceBadge({ source }: { source: string }) {
  const lower = source.toLowerCase();
  if (lower === "dashboard") {
    return (
      <Badge variant="outline" className="font-mono text-[10px]">
        dashboard
      </Badge>
    );
  }
  if (lower.startsWith("declarative")) {
    return (
      <Badge
        variant="outline"
        className="border-amber-500/40 bg-amber-500/10 font-mono text-[10px] text-amber-700 dark:text-amber-400"
        title="Managed by an in-process declarative reconciler. Edits via the dashboard will be reverted on next sync."
      >
        {source}
      </Badge>
    );
  }
  if (lower.startsWith("imported")) {
    return (
      <Badge variant="secondary" className="font-mono text-[10px]">
        {source}
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="font-mono text-[10px]">
      {source}
    </Badge>
  );
}

/**
 * Badge for the per-schedule catch-up policy.
 *
 * The default ``skip`` is rendered intentionally muted because it is
 * the safe choice and any operator who wants to know about it can
 * read the column. The two firing variants get a brighter blue so
 * they stand out: ``fire_one_missed`` is harmless (one extra fire
 * after an outage) and ``fire_all_missed`` can be a foot-gun (a long
 * outage on a per-minute schedule produces a flood of fires) - we
 * make sure operators eyeballing the table see them.
 */
function CatchUpBadge({ value }: { value: SchedulePublic["catch_up"] }) {
  const label = value.replace(/_/g, " ");
  if (value === "skip") {
    return (
      <Badge variant="outline" className="text-[10px] text-muted-foreground">
        {label}
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="border-blue-500/40 bg-blue-500/10 text-[10px] text-blue-700 dark:text-blue-400"
    >
      {label}
    </Badge>
  );
}

export { CatchUpBadge, SourceBadge };

// ---------------------------------------------------------------------------
// Bulk-action toolbar
// ---------------------------------------------------------------------------

/**
 * Renders inside the DataTable's toolbar slot when one or more
 * schedules are selected. Operations run in parallel via the
 * page-level handlers; this component is purely the UI surface.
 *
 * Design choices:
 *
 * - The four primary actions (Trigger / Enable / Disable / Delete)
 *   match the per-row icons. Operators learn the column once.
 * - Delete is intentionally last, in destructive red. The page-level
 *   handler routes through ``useConfirm`` so a stray double-click
 *   doesn't wipe schedules.
 * - Enable / Disable apply only to schedules that need the change
 *   (the handler filters by current state). The button is enabled
 *   whenever at least one matching row is in the selection.
 */
function BulkActionToolbar({
  ctx,
  canManage,
  onBulkEnable,
  onBulkDisable,
  onBulkTrigger,
  onBulkDelete,
}: {
  ctx: {
    selectedRows: SchedulePublic[];
    selectedCount: number;
    clearSelection: () => void;
  };
  canManage: boolean;
  onBulkEnable: (rows: SchedulePublic[]) => void;
  onBulkDisable: (rows: SchedulePublic[]) => void;
  onBulkTrigger: (rows: SchedulePublic[]) => void;
  onBulkDelete: (rows: SchedulePublic[]) => void;
}) {
  const enableCount = ctx.selectedRows.filter((r) => !r.is_enabled).length;
  const disableCount = ctx.selectedRows.filter((r) => r.is_enabled).length;
  return (
    <div className="flex items-center gap-3 rounded-md bg-primary/10 px-4 py-2">
      <span className="text-sm font-medium">
        {ctx.selectedCount} selected
      </span>
      <div className="ml-auto flex items-center gap-2">
        {canManage && (
          <>
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1 text-xs"
              onClick={() => onBulkTrigger(ctx.selectedRows)}
              title="Fire all selected schedules now"
            >
              <Play className="size-3" />
              Trigger
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() => onBulkEnable(ctx.selectedRows)}
              disabled={enableCount === 0}
              title={
                enableCount === 0
                  ? "All selected schedules are already enabled"
                  : `Enable ${enableCount} disabled schedule${enableCount === 1 ? "" : "s"}`
              }
            >
              Enable {enableCount > 0 ? `(${enableCount})` : ""}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() => onBulkDisable(ctx.selectedRows)}
              disabled={disableCount === 0}
              title={
                disableCount === 0
                  ? "All selected schedules are already disabled"
                  : `Disable ${disableCount} enabled schedule${disableCount === 1 ? "" : "s"}`
              }
            >
              Disable {disableCount > 0 ? `(${disableCount})` : ""}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
              onClick={() => onBulkDelete(ctx.selectedRows)}
              title="Delete all selected schedules"
            >
              <Trash2 className="size-3" />
              Delete
            </Button>
          </>
        )}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-xs"
          onClick={ctx.clearSelection}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}
