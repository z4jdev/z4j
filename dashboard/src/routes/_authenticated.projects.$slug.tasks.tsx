/**
 * Tasks page - enterprise-grade task list with DataTable.
 *
 * Features:
 * - Full-text search across name, queue, worker, task ID
 * - State + priority multi-select filters
 * - Sortable columns (name, state, priority, queue, worker, duration, started)
 * - Row selection with checkboxes + bulk actions
 * - Pagination with rows-per-page selector
 * - Export: CSV / Excel / JSON with field selection (metadata / full)
 */
import { useCallback, useMemo, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Ban,
  ClipboardList,
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  RotateCcw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import {
  TaskPriorityBadge,
  TaskStateBadge,
} from "@/components/domain/state-badges";
import { EmptyState } from "@/components/domain/empty-state";
import { QueryError } from "@/components/domain/query-error";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { api } from "@/lib/api";
import {
  buildExportUrl,
  useTasks,
  type ExportFieldSet,
  type TaskFilters,
} from "@/hooks/use-tasks";
import { useCan } from "@/hooks/use-memberships";
import { DateCell } from "@/components/domain/date-cell";
import {
  formatDuration,
  truncate,
} from "@/lib/format";
import type { TaskPriority, TaskPublic, TaskState } from "@/lib/api-types";
import { cn } from "@/lib/utils";

interface TasksSearch {
  state?: TaskState | "all";
  search?: string;
}

export const Route = createFileRoute("/_authenticated/projects/$slug/tasks")({
  component: TasksPage,
  validateSearch: (search: Record<string, unknown>): TasksSearch => ({
    state: (search.state as TaskState | "all") ?? undefined,
    search: (search.search as string) ?? undefined,
  }),
});

const TASK_STATES: TaskState[] = [
  "pending", "received", "started",
  "success", "failure", "retry", "revoked",
  "rejected", "unknown",
];

const PRIORITIES: TaskPriority[] = ["critical", "high", "normal", "low"];

function TasksPage() {
  const { slug } = Route.useParams();
  const searchParams = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const [stateFilter, setStateFilter] = useState<TaskState | "all">(
    searchParams.state ?? "all",
  );
  const [priorityFilter, setPriorityFilter] = useState<TaskPriority[]>([]);
  const [searchQuery, setSearchQuery] = useState(searchParams.search ?? "");
  const [cursor, setCursor] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState(50);

  // Sync state filter changes to URL search params.
  const updateStateFilter = (v: TaskState | "all") => {
    setStateFilter(v);
    setCursor(null);
    navigate({
      search: (prev: TasksSearch) => ({
        ...prev,
        state: v === "all" ? undefined : v,
      }),
      replace: true,
    });
  };

  const filters: TaskFilters = {
    state: stateFilter === "all" ? "" : stateFilter,
    priority: priorityFilter.length > 0 ? priorityFilter : undefined,
    search: searchQuery || undefined,
    cursor,
    limit: pageSize,
  };

  const { data, isLoading, isError, isFetching, refetch } = useTasks(slug, filters);

  const activeFilterCount =
    (stateFilter !== "all" ? 1 : 0) + (priorityFilter.length > 0 ? 1 : 0);

  const clearFilters = () => {
    setStateFilter("all");
    setPriorityFilter([]);
    setSearchQuery("");
    setCursor(null);
    navigate({ search: {}, replace: true });
  };

  const togglePriority = (p: TaskPriority) => {
    setPriorityFilter((prev) =>
      prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p],
    );
    setCursor(null);
  };

  const columns = useTaskColumns(slug);
  const queryClient = useQueryClient();
  const [bulkLoading, setBulkLoading] = useState(false);

  // RBAC UI gates - backend enforces these too (see api/deps.py),
  // this is the UI mirror that hides buttons the user can't click.
  const canRetry = useCan(slug, "retry_task");
  const canCancel = useCan(slug, "cancel_task");
  const canBulk = useCan(slug, "bulk_action");

  const handleBulkDelete = useCallback(
    async (
      selectedRows: TaskPublic[],
      allPages: boolean,
      clearSelection: () => void,
    ) => {
      const count = allPages ? "all matching" : selectedRows.length;
      if (!window.confirm(`Delete ${count} task records? This cannot be undone.`))
        return;

      setBulkLoading(true);
      try {
        if (allPages) {
          await api.post(`/projects/${slug}/tasks/bulk-delete`, {
            filter_state: stateFilter === "all" ? undefined : stateFilter,
            filter_name: searchQuery || undefined,
          });
        } else {
          await api.post(`/projects/${slug}/tasks/bulk-delete`, {
            task_ids: selectedRows.map((r) => r.id),
          });
        }
        clearSelection();
        queryClient.invalidateQueries({ queryKey: ["tasks", slug] });
        queryClient.invalidateQueries({ queryKey: ["stats", slug] });
      } catch {
        window.alert("Failed to delete tasks. Check permissions.");
      } finally {
        setBulkLoading(false);
      }
    },
    [slug, stateFilter, searchQuery, queryClient],
  );

  const handleBulkRetry = useCallback(
    async (
      selectedRows: TaskPublic[],
      allPages: boolean,
      clearSelection: () => void,
    ) => {
      const count = allPages ? "all matching" : selectedRows.length;
      if (!window.confirm(`Retry ${count} tasks?`)) return;

      setBulkLoading(true);
      try {
        // For individual tasks, issue retry commands one by one.
        // For all-pages, use the bulk-retry command endpoint.
        if (allPages) {
          // Get the first available agent.
          const agents = await api.get<{ id: string }[]>(
            `/projects/${slug}/agents`,
          );
          const agent = agents[0];
          if (!agent) {
            window.alert("No agent available to retry tasks.");
            return;
          }
          await api.post(`/projects/${slug}/commands/bulk-retry`, {
            agent_id: agent.id,
            filter: {
              state: stateFilter === "all" ? "failure" : stateFilter,
            },
            max: 1000,
          });
        } else {
          const agents = await api.get<{ id: string }[]>(
            `/projects/${slug}/agents`,
          );
          const agent = agents[0];
          if (!agent) {
            window.alert("No agent available to retry tasks.");
            return;
          }
          for (const row of selectedRows) {
            await api.post(`/projects/${slug}/commands/retry-task`, {
              agent_id: agent.id,
              engine: row.engine,
              task_id: row.task_id,
            });
          }
        }
        clearSelection();
        queryClient.invalidateQueries({ queryKey: ["tasks", slug] });
        queryClient.invalidateQueries({ queryKey: ["commands", slug] });
      } catch {
        window.alert("Failed to retry tasks. Check permissions.");
      } finally {
        setBulkLoading(false);
      }
    },
    [slug, stateFilter, searchQuery, queryClient],
  );

  const handleBulkCancel = useCallback(
    async (
      selectedRows: TaskPublic[],
      _allPages: boolean,
      clearSelection: () => void,
    ) => {
      if (
        !window.confirm(
          `Cancel/revoke ${selectedRows.length} tasks? Running tasks will be terminated.`,
        )
      )
        return;

      setBulkLoading(true);
      try {
        const agents = await api.get<{ id: string }[]>(
          `/projects/${slug}/agents`,
        );
        const agent = agents[0];
        if (!agent) {
          window.alert("No agent available to cancel tasks.");
          return;
        }
        for (const row of selectedRows) {
          await api.post(`/projects/${slug}/commands/cancel-task`, {
            agent_id: agent.id,
            engine: row.engine,
            task_id: row.task_id,
          });
        }
        clearSelection();
        queryClient.invalidateQueries({ queryKey: ["tasks", slug] });
        queryClient.invalidateQueries({ queryKey: ["commands", slug] });
      } catch {
        window.alert("Failed to cancel tasks. Check permissions.");
      } finally {
        setBulkLoading(false);
      }
    },
    [slug, queryClient],
  );

  // Filter toolbar (default state) - rendered inside the DataTable toolbar slot.
  // The Clear button always reserves its space (invisible when no filters)
  // to prevent layout shift.
  const filterToolbar = (
    <div className="flex items-center gap-3">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search tasks..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setCursor(null);
          }}
          className="h-9 pl-9"
        />
      </div>
      <Select
        value={stateFilter}
        onValueChange={(v) => updateStateFilter(v as TaskState | "all")}
      >
        <SelectTrigger className="h-9 w-36 shrink-0">
          <SelectValue placeholder="State" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All states</SelectItem>
          {TASK_STATES.map((s) => (
            <SelectItem key={s} value={s}>
              {s}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={priorityFilter.length === 1 ? priorityFilter[0] : "all"}
        onValueChange={(v) => {
          if (v === "all") {
            setPriorityFilter([]);
          } else {
            setPriorityFilter([v as TaskPriority]);
          }
          setCursor(null);
        }}
      >
        <SelectTrigger className="h-9 w-36 shrink-0">
          <SelectValue placeholder="Priority" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All priorities</SelectItem>
          {PRIORITIES.map((p) => (
            <SelectItem key={p} value={p}>
              {p}
            </SelectItem>
          ))}
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
        title="Tasks"
        icon={ClipboardList}
        description="search, filter, and export task history"
        actions={
          <div className="flex items-center gap-2">
            <ExportMenu slug={slug} filters={filters} />
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

      {/* DataTable with inline toolbar */}
      {isError && !data && (
        <QueryError message="Failed to load tasks" onRetry={() => refetch()} />
      )}
      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}
      {data && data.items.length === 0 && (
        <div>
          <div className="flex h-[52px] items-center">
            <div className="w-full">{filterToolbar}</div>
          </div>
          <div className="mt-2 overflow-hidden rounded-lg border">
            <EmptyState
              icon={ClipboardList}
              title="no tasks match"
              description={
                activeFilterCount > 0 || searchQuery
                  ? "try adjusting your filters or search query"
                  : "connect a z4j agent in your worker (Celery, RQ, or Dramatiq) to see tasks here"
              }
            />
          </div>
        </div>
      )}
      {data && data.items.length > 0 && (
        <DataTable
          columns={columns}
          data={data.items}
          enableSelection
          enableSorting
          pageSize={pageSize}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setCursor(null);
          }}
          hasNextPage={!!data.next_cursor}
          hasPreviousPage={!!cursor}
          onNextPage={() => setCursor(data.next_cursor)}
          onFirstPage={() => setCursor(null)}
          totalLabel={`${data.items.length} task${data.items.length === 1 ? "" : "s"}`}
          toolbar={(ctx) =>
            ctx.selectedCount > 0 ? (
              // Bulk action bar - replaces filter bar in-place, same height
              <div className="flex items-center gap-3 rounded-md bg-primary/10 px-4 py-2">
                <span className="text-sm font-medium">
                  {ctx.allPagesSelected
                    ? "All matching tasks selected"
                    : `${ctx.selectedCount} selected`}
                </span>
                {ctx.showSelectAllPages && (
                  <Button
                    variant="link"
                    size="sm"
                    className="h-7 px-0 text-xs"
                    onClick={ctx.selectAllPages}
                  >
                    Select all matching
                  </Button>
                )}
                {ctx.allPagesSelected && (
                  <Button
                    variant="link"
                    size="sm"
                    className="h-7 px-0 text-xs"
                    onClick={ctx.selectPageOnly}
                  >
                    This page only
                  </Button>
                )}
                <div className="ml-auto flex items-center gap-2">
                  {(canRetry || canBulk) && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1 text-xs"
                      disabled={bulkLoading}
                      onClick={() =>
                        handleBulkRetry(
                          ctx.selectedRows,
                          ctx.allPagesSelected,
                          ctx.clearSelection,
                        )
                      }
                    >
                      <RotateCcw className="size-3" />
                      Retry
                    </Button>
                  )}
                  {canCancel && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1 text-xs"
                      disabled={bulkLoading || ctx.allPagesSelected}
                      onClick={() =>
                        handleBulkCancel(
                          ctx.selectedRows,
                          ctx.allPagesSelected,
                          ctx.clearSelection,
                        )
                      }
                    >
                      <Ban className="size-3" />
                      Revoke
                    </Button>
                  )}
                  {canBulk && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1 text-xs text-destructive hover:bg-destructive/10"
                      disabled={bulkLoading}
                      onClick={() =>
                        handleBulkDelete(
                          ctx.selectedRows,
                          ctx.allPagesSelected,
                          ctx.clearSelection,
                        )
                      }
                    >
                      <Trash2 className="size-3" />
                      Delete
                    </Button>
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
            ) : (
              // Filter bar - default state
              filterToolbar
            )
          }
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

function useTaskColumns(slug: string): ColumnDef<TaskPublic, unknown>[] {
  return useMemo(
    () => [
      {
        accessorKey: "name",
        header: "Task",
        cell: ({ row }: { row: { original: TaskPublic } }) => {
          const task = row.original;
          return (
            <div>
              <Link
                to="/projects/$slug/tasks/$engine/$taskId"
                params={{
                  slug,
                  engine: task.engine,
                  taskId: task.task_id,
                }}
                className="font-medium text-foreground hover:underline"
                title={task.name}
              >
                {truncate(task.name, 40)}
              </Link>
              <div className="font-mono text-xs text-muted-foreground">
                {task.task_id.slice(0, 12)}
              </div>
            </div>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "state",
        header: "State",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <TaskStateBadge state={row.original.state} />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "priority",
        header: "Priority",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <TaskPriorityBadge priority={row.original.priority} compact />
        ),
        enableSorting: true,
      },
      {
        accessorKey: "queue",
        header: "Queue",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <span className="text-muted-foreground">
            {row.original.queue ?? "-"}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "worker_name",
        header: "Worker",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <span className="text-muted-foreground">
            {row.original.worker_name ?? "-"}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "runtime_ms",
        header: "Duration",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <span className="tabular-nums">
            {formatDuration(row.original.runtime_ms)}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "started_at",
        header: "Started",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <DateCell value={row.original.started_at} />
        ),
        enableSorting: true,
      },
    ],
    [slug],
  );
}

// ---------------------------------------------------------------------------
// Export menu
// ---------------------------------------------------------------------------

function ExportMenu({
  slug,
  filters,
}: {
  slug: string;
  filters: TaskFilters;
}) {
  const [fieldSet, setFieldSet] = useState<ExportFieldSet>("metadata");

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <Download className="size-4" />
          Export
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>Export tasks</DropdownMenuLabel>
        <DropdownMenuSeparator />

        {/* Field selection toggle */}
        <div className="px-2 py-1.5">
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Fields
          </p>
          <div className="flex gap-1">
            <Button
              variant={fieldSet === "metadata" ? "default" : "outline"}
              size="sm"
              className="h-6 flex-1 text-[10px]"
              onClick={() => setFieldSet("metadata")}
            >
              Quick
            </Button>
            <Button
              variant={fieldSet === "full" ? "default" : "outline"}
              size="sm"
              className="h-6 flex-1 text-[10px]"
              onClick={() => setFieldSet("full")}
            >
              Full data
            </Button>
          </div>
          <p className="mt-1 text-[10px] text-muted-foreground">
            {fieldSet === "metadata"
              ? "ID, name, state, priority, queue, worker, timestamps"
              : "Everything including args, kwargs, result, traceback"}
          </p>
        </div>
        <DropdownMenuSeparator />

        <DropdownMenuItem asChild>
          <a
            href={buildExportUrl(slug, "csv", filters, fieldSet)}
            download
            className="gap-2"
          >
            <FileText className="size-4" />
            CSV
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a
            href={buildExportUrl(slug, "xlsx", filters, fieldSet)}
            download
            className="gap-2"
          >
            <FileSpreadsheet className="size-4" />
            Excel (.xlsx)
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a
            href={buildExportUrl(slug, "json", filters, fieldSet)}
            download
            className="gap-2"
          >
            <FileJson className="size-4" />
            JSON
          </a>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
