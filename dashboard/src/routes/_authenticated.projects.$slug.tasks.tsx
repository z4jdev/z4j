import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { sortTimestamp } from "@/lib/table-sorting";
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
import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { SavedTaskViews } from "@/components/domain/saved-task-views";
import {
  TaskPriorityBadge,
  TaskStateBadge,
} from "@/components/domain/state-badges";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useCan } from "@/hooks/use-memberships";
import {
  buildExportUrl,
  useTasks,
  type ExportFieldSet,
  type TaskFilters,
} from "@/hooks/use-tasks";
import { resolveCommandTargets } from "@/lib/agent-capabilities";
import { api, ApiError } from "@/lib/api";
import type {
  AgentPublic,
  TaskPriority,
  TaskPublic,
  TaskState,
} from "@/lib/api-types";
import {
  apiPathFromLocation,
  clearStoredBulkRetry,
  hasSameBulkRetrySelection,
  hasStoredBulkRetryRecord,
  isTerminalBulkRetry,
  parseStoredBulkRetryBody,
  persistBulkRetry,
  readStoredBulkRetry,
  storedBulkRetryMatchesResource,
  type DurableBulkRetryBody,
} from "@/lib/bulk-retry-storage";
import { formatDuration, truncate } from "@/lib/format";
import {
  parseTaskListSearch,
  type TaskListSearch as TasksSearch,
} from "@/lib/task-list-search";
import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Ban,
  ChevronDown,
  ClipboardList,
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  RotateCcw,
  Trash2,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";

interface BulkRetryResource {
  id: string;
  idempotency_key: string;
  status: string;
}

export const Route = createFileRoute("/_authenticated/projects/$slug/tasks")({
  component: TasksPage,
  validateSearch: parseTaskListSearch,
});

const TASK_STATES: TaskState[] = [
  "pending",
  "received",
  "started",
  "success",
  "failure",
  "retry",
  "revoked",
  "rejected",
  "unknown",
];

const PRIORITIES: TaskPriority[] = ["critical", "high", "normal", "low"];
const taskRowId = (row: TaskPublic) => row.id;

function TasksPage() {
  const { slug } = Route.useParams();
  const searchParams = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const stateFilter = searchParams.state ?? "all";
  const priorityFilter = useMemo(
    () => searchParams.priority ?? [],
    [searchParams.priority],
  );
  const searchQuery = searchParams.search ?? "";
  const setSearchQuery = (search: string) =>
    navigate({
      search: (prev) => ({ ...prev, search: search || undefined }),
      replace: true,
    });
  const [cursor, setCursor] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState(50);

  // Sync state filter changes to URL search params.
  const updateStateFilter = (v: TaskState | "all") => {
    setCursor(null);
    navigate({
      search: (prev: TasksSearch) => ({
        ...prev,
        state: v === "all" ? undefined : v,
      }),
      replace: true,
    });
  };

  const debouncedSearch = useDebouncedValue(searchQuery);
  const filters: TaskFilters = {
    state: stateFilter === "all" ? "" : stateFilter,
    priority: priorityFilter.length > 0 ? priorityFilter : undefined,
    search: searchQuery || undefined,
    cursor,
    limit: pageSize,
  };
  const taskSelectionScopeKey = JSON.stringify({
    slug,
    state: stateFilter,
    priority: PRIORITIES.filter((priority) =>
      priorityFilter.includes(priority),
    ),
    search: searchQuery,
    cursor,
    pageSize,
  });

  const { data, isLoading, isError, isFetching, isPlaceholderData, refetch } =
    useTasks(
      slug,
      { ...filters, search: debouncedSearch || undefined },
      { includeTotal: true },
    );
  const pendingResults =
    isLoading || isPlaceholderData || searchQuery !== debouncedSearch;
  // Never label the previous filter's rows or count as the current selection.
  const totalCount =
    pendingResults || isError ? undefined : (data?.total_count ?? undefined);
  const totalText = totalCount?.toLocaleString();
  const pageCount = data?.items.length ?? 0;

  const activeFilterCount =
    (stateFilter !== "all" ? 1 : 0) +
    (priorityFilter.length > 0 ? 1 : 0) +
    (searchQuery ? 1 : 0);

  const clearFilters = () => {
    setCursor(null);
    navigate({ search: {}, replace: true });
  };

  const columns = useTaskColumns(slug, searchParams);
  const queryClient = useQueryClient();
  const [bulkLoading, setBulkLoading] = useState(false);

  // RBAC UI gates - backend enforces these too (see api/deps.py),
  // this is the UI mirror that hides buttons the user can't click.
  const canRetry = useCan(slug, "retry_task");
  const canCancel = useCan(slug, "cancel_task");
  const canDeleteTasks = useCan(slug, "delete_tasks");

  const handleBulkDelete = useCallback(
    async (
      selectedRows: TaskPublic[],
      allPages: boolean,
      clearSelection: () => void,
    ) => {
      if (!canDeleteTasks) return;
      if (!allPages && selectedRows.length === 0) {
        window.alert("Select at least one task before deleting task records.");
        return;
      }
      const count = allPages
        ? `up to ${Math.min(totalCount ?? 10_000, 10_000).toLocaleString()} matching`
        : selectedRows.length.toLocaleString();
      if (
        !window.confirm(`Delete ${count} task records? This cannot be undone.`)
      )
        return;

      setBulkLoading(true);
      try {
        if (allPages) {
          const filterBody = {
            ...(stateFilter !== "all" ? { filter_state: stateFilter } : {}),
            ...(priorityFilter.length > 0
              ? { filter_priority: priorityFilter }
              : {}),
            ...(searchQuery ? { filter_search: searchQuery } : {}),
          };
          if (Object.keys(filterBody).length === 0) {
            window.alert(
              "Choose at least one task filter before deleting all matching tasks.",
            );
            return;
          }
          await api.post(`/projects/${slug}/tasks/bulk-delete`, {
            ...filterBody,
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
    [
      canDeleteTasks,
      slug,
      stateFilter,
      priorityFilter,
      searchQuery,
      queryClient,
      totalCount,
    ],
  );

  const handleBulkRetry = useCallback(
    async (
      selectedRows: TaskPublic[],
      allPages: boolean,
      clearSelection: () => void,
    ) => {
      const count = allPages
        ? `all ${totalText !== undefined ? `${totalText} ` : ""}matching`
        : selectedRows.length.toLocaleString();
      if (!window.confirm(`Retry ${count} tasks?`)) return;

      setBulkLoading(true);
      try {
        // For individual tasks, issue retry commands one by one.
        // For all-pages, use the durable request resource.
        if (allPages) {
          if (stateFilter === "all") {
            window.alert(
              "Choose an explicit task state before retrying all matching tasks.",
            );
            return;
          }
          const intendedSelection: Omit<
            DurableBulkRetryBody,
            "idempotency_key"
          > = {
            filter: {
              state: stateFilter,
              ...(priorityFilter.length > 0
                ? { priority: priorityFilter }
                : {}),
              ...(searchQuery ? { search: searchQuery } : {}),
            },
            max: 1000,
          };
          const storedRecordExists = hasStoredBulkRetryRecord(slug);
          let stored = readStoredBulkRetry(slug);
          if (storedRecordExists && !stored) {
            window.alert(
              "The saved retry request is unreadable. No new request was " +
                "sent because the previous operation may still be unresolved.",
            );
            return;
          }
          if (stored?.location) {
            const priorPath = apiPathFromLocation(stored.location, slug);
            if (priorPath === null) {
              window.alert(
                "The saved retry request points outside this project. No new " +
                  "request was sent because the previous operation may still be unresolved.",
              );
              return;
            }
            const prior = await api.get<BulkRetryResource>(priorPath);
            if (!storedBulkRetryMatchesResource(stored, prior)) {
              window.alert(
                "The saved retry request does not match the server resource. " +
                  "No new request was sent because the previous operation may still be unresolved.",
              );
              return;
            }
            if (isTerminalBulkRetry(prior.status)) {
              clearStoredBulkRetry(slug);
              stored = null;
            }
          }

          let body: DurableBulkRetryBody;
          if (stored) {
            const parsed = parseStoredBulkRetryBody(stored);
            if (
              parsed === null ||
              !hasSameBulkRetrySelection(parsed, intendedSelection)
            ) {
              window.alert(
                "A retry request for a different task filter is still " +
                  "unresolved. Resolve that request before starting another.",
              );
              return;
            }
            body = parsed;
          } else {
            const key = crypto.randomUUID();
            body = {
              idempotency_key: key,
              ...intendedSelection,
            };
            stored = {
              key,
              canonicalBody: JSON.stringify(body),
              location: null,
            };
            // This is the safety boundary: if persistence is unavailable, do
            // not send a destructive request whose ambiguous response cannot
            // be replayed with the exact same key and body.
            if (!persistBulkRetry(slug, stored)) {
              window.alert(
                "Cannot persist the retry request in this browser. " +
                  "No tasks were retried.",
              );
              return;
            }
          }

          let created: {
            data: BulkRetryResource;
            location: string | null;
          };
          let responseLocationObserved = stored.location !== null;
          try {
            created = await api.postResource<BulkRetryResource>(
              `/projects/${slug}/bulk-retry-requests`,
              body,
              (location) => {
                responseLocationObserved = true;
                // Persist the server identity as soon as response headers
                // arrive, before parsing the body can introduce ambiguity.
                persistBulkRetry(slug, { ...stored, location });
              },
            );
          } catch (error) {
            if (
              error instanceof ApiError &&
              error.status === 400 &&
              error.code === "matching task count exceeds max" &&
              !responseLocationObserved
            ) {
              // Only the Brain's exact pre-parent over-limit refusal is
              // definitive. A generic/re-written 400 can follow an ambiguous
              // commit and must retain the durable browser identity.
              clearStoredBulkRetry(slug);
              window.alert(
                "The matching selection exceeds the retry limit. " +
                  "Narrow the filters and try again; no tasks were retried.",
              );
              return;
            }
            throw error;
          }
          const location =
            created.location ??
            `/api/v1/projects/${slug}/bulk-retry-requests/${created.data.id}`;
          const responseRecord = { ...stored, location };
          persistBulkRetry(slug, responseRecord);
          if (
            apiPathFromLocation(location, slug) === null ||
            !storedBulkRetryMatchesResource(responseRecord, created.data)
          ) {
            window.alert(
              "The retry response identity does not match the saved request. " +
                "The unresolved request was retained and no new request will be sent.",
            );
            return;
          }
          if (isTerminalBulkRetry(created.data.status)) {
            clearStoredBulkRetry(slug);
          }
        } else {
          const agents = await api.get<AgentPublic[]>(
            `/projects/${slug}/agents`,
          );
          // A row names no owner, so prefer an advertised retry contract; a
          // long-poll agent that never reported its engines still counts.
          const { targets, unserved } = resolveCommandTargets(
            agents,
            selectedRows,
            "retry_task",
          );
          if (unserved.length > 0) {
            window.alert(
              `No agent that can retry ${unserved.join(", ")} tasks is available. Nothing was sent.`,
            );
            return;
          }
          for (const { row, agent } of targets) {
            await api.post(`/projects/${slug}/commands/retry-task`, {
              agent_id: agent.id,
              engine: row.engine,
              task_id: row.task_id,
              idempotency_key: crypto.randomUUID(),
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
    [slug, stateFilter, priorityFilter, searchQuery, queryClient, totalText],
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
        const agents = await api.get<AgentPublic[]>(
          `/projects/${slug}/agents`,
        );
        // Each row goes to an agent that can cancel on its engine, never
        // simply the project's first agent, which may be a scheduler-only
        // process.
        const { targets, unserved } = resolveCommandTargets(
          agents,
          selectedRows,
          "cancel_task",
        );
        if (unserved.length > 0) {
          window.alert(
            `No agent that can cancel ${unserved.join(", ")} tasks is available. Nothing was sent.`,
          );
          return;
        }
        for (const { row, agent } of targets) {
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

  const filterToolbar = (
    <FilterToolbar
      searchValue={searchQuery}
      onSearchChange={(v) => {
        setSearchQuery(v);
        setCursor(null);
      }}
      searchPlaceholder="Search tasks..."
      activeFilterCount={activeFilterCount}
      onClear={clearFilters}
      trailing={
        <SavedTaskViews
          key={slug}
          slug={slug}
          filters={searchParams}
          onApply={(view) => {
            setCursor(null);
            navigate({ search: view, replace: true });
          }}
        />
      }
      filters={
        <>
          <Select
            value={stateFilter}
            onValueChange={(v) => updateStateFilter(v as TaskState | "all")}
          >
            <SelectTrigger aria-label="Task state" className="w-36 shrink-0">
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
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="w-36 shrink-0 justify-start font-normal"
                aria-label="Filter by priority"
              >
                {priorityFilter.length === 0
                  ? "All priorities"
                  : priorityFilter.length === 1
                    ? priorityFilter[0]
                    : `${priorityFilter.length} priorities`}
                <ChevronDown className="ml-auto size-4 opacity-60" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-44">
              <DropdownMenuLabel>Priorities</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {PRIORITIES.map((priority) => (
                <DropdownMenuCheckboxItem
                  key={priority}
                  checked={priorityFilter.includes(priority)}
                  aria-label={`toggle-${priority}-priority`}
                  onSelect={(event) => event.preventDefault()}
                  onCheckedChange={(checked) => {
                    const selected = new Set(priorityFilter);
                    if (checked) selected.add(priority);
                    else selected.delete(priority);
                    navigate({
                      search: (prev) => ({
                        ...prev,
                        priority: PRIORITIES.filter((value) =>
                          selected.has(value),
                        ),
                      }),
                      replace: true,
                    });
                    setCursor(null);
                  }}
                >
                  {priority}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </>
      }
    />
  );

  return (
    <PageShell>
      <PageHeader
        title="Tasks"
        badges={
          totalText !== undefined ? (
            <Badge
              variant="secondary"
              role="status"
              aria-label={`${totalText} matching tasks`}
            >
              {totalText}
            </Badge>
          ) : undefined
        }
        icon={ClipboardList}
        description="Search, inspect, and act on task history."
        actions={
          <div className="flex items-center gap-2">
            <ExportMenu slug={slug} filters={filters} />
            <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
          </div>
        }
      />

      {/* DataTable with inline toolbar */}

      <DataTable
        isFetching={isFetching}
        isLoading={pendingResults}
        error={isError ? "Unable to load tasks. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={ClipboardList}
            title="no tasks match"
            description={
              activeFilterCount > 0 || searchQuery
                ? "try adjusting your filters or search query"
                : "connect a z4j agent in your worker (Celery, RQ, or Dramatiq) to see tasks here"
            }
          />
        }
        columns={columns}
        data={data?.items ?? []}
        enableSelection
        getRowId={taskRowId}
        selectionScopeKey={taskSelectionScopeKey}
        enableSorting
        pageSize={pageSize}
        onPageSizeChange={(size) => {
          setPageSize(size);
          setCursor(null);
        }}
        hasNextPage={!!data?.next_cursor}
        hasPreviousPage={!!cursor}
        onNextPage={() => setCursor(data?.next_cursor ?? null)}
        onFirstPage={() => setCursor(null)}
        totalCount={totalCount}
        totalLabel={
          totalText !== undefined
            ? `Showing ${pageCount.toLocaleString()} of ${totalText} matching task${totalCount === 1 ? "" : "s"}`
            : `${pageCount.toLocaleString()} on this page · Total unavailable`
        }
        toolbar={(ctx) =>
          ctx.selectedCount > 0 ? (
            // Bulk action bar - replaces filter bar in-place, same height
            <div className="flex min-h-9 flex-wrap items-center gap-3 rounded-md bg-accent px-3 py-2">
              <span className="text-sm font-medium">
                {ctx.allPagesSelected
                  ? `All ${totalText !== undefined ? `${totalText} ` : ""}matching tasks selected`
                  : `${ctx.selectedCount.toLocaleString()} selected`}
              </span>
              {ctx.showSelectAllPages && (
                <Button
                  variant="link"
                  size="sm"
                  className="px-0"
                  onClick={ctx.selectAllPages}
                >
                  Select all {totalText !== undefined ? `${totalText} ` : ""}
                  matching
                </Button>
              )}
              {ctx.allPagesSelected && (
                <Button
                  variant="link"
                  size="sm"
                  className="px-0"
                  onClick={ctx.selectPageOnly}
                >
                  This page only
                </Button>
              )}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {canRetry && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1"
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
                    className="gap-1"
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
                {canDeleteTasks && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1 text-destructive hover:bg-destructive/10"
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
                <Button variant="ghost" size="sm" onClick={ctx.clearSelection}>
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
    </PageShell>
  );
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

function useTaskColumns(
  slug: string,
  list: TasksSearch,
): DataTableColumnDef<TaskPublic>[] {
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
                search={{ list }}
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
        id: "priority",
        accessorFn: (row) =>
          row.priority
            ? { critical: 0, high: 1, normal: 2, low: 3 }[row.priority]
            : null,
        header: "Priority",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <TaskPriorityBadge priority={row.original.priority} />
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
        id: "started_at",
        accessorFn: (row) => sortTimestamp(row.started_at),
        header: "Started",
        cell: ({ row }: { row: { original: TaskPublic } }) => (
          <DateCell value={row.original.started_at} compact />
        ),
        enableSorting: true,
      },
    ],
    [slug, list],
  );
}

// ---------------------------------------------------------------------------
// Export menu
// ---------------------------------------------------------------------------

function ExportMenu({ slug, filters }: { slug: string; filters: TaskFilters }) {
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
              className="flex-1 text-[10px]"
              onClick={() => setFieldSet("metadata")}
            >
              Quick
            </Button>
            <Button
              variant={fieldSet === "full" ? "default" : "outline"}
              size="sm"
              className="flex-1 text-[10px]"
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
