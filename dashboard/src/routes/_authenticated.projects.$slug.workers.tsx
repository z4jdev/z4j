import { sortTimestamp } from "@/lib/table-sorting";
/**
 * Workers list page - Flower-parity worker overview.
 *
 * Columns: Name, State, Queues, Active, Succeeded, Failed, Retried,
 * Processed (= Succeeded + Failed), Concurrency, Load, Heartbeat.
 * Header summary bar AND a Total row at the bottom of the table sum
 * the per-worker counts across the whole project so an operator
 * sees cluster-wide throughput at a glance.
 *
 * Counts come from the events-table aggregation
 * (``WorkerRepository.counts_for_project``); they survive worker
 * restarts and split succeeded vs failed vs retried independently,
 * unlike the old derivation from Celery's ``inspect.stats.total``
 * which only counted successes and reset on every worker restart.
 *
 * Worker name links to the 6-tab detail page.
 */
import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { WorkerStateBadge } from "@/components/domain/state-badges";
import { WorkerLintPanel } from "@/components/domain/worker-lint-panel";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useWorkers } from "@/hooks/use-workers";
import type { WorkerPublic, WorkerState } from "@/lib/api-types";
import { formatCompact } from "@/lib/format";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Cpu } from "lucide-react";
import { useMemo, useState } from "react";

const WORKER_STATES: WorkerState[] = [
  "online",
  "offline",
  "draining",
  "unknown",
];

export const Route = createFileRoute("/_authenticated/projects/$slug/workers")({
  component: WorkersPage,
});

function WorkersPage() {
  const { slug } = Route.useParams();
  const {
    data: workers,
    isLoading,
    isError,
    isFetching,
    refetch,
  } = useWorkers(slug);

  const columns = useWorkerColumns(slug);

  // Filter / search state. Client-side filtering since the workers
  // list is loaded into memory anyway for the summary calculations.
  const [searchQuery, setSearchQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<WorkerState | "all">("all");
  const activeFilterCount =
    (searchQuery ? 1 : 0) + (stateFilter !== "all" ? 1 : 0);

  const filteredWorkers = useMemo(() => {
    if (!workers) return [];
    const q = searchQuery.toLowerCase();
    return workers.filter((w) => {
      if (stateFilter !== "all" && w.state !== stateFilter) return false;
      if (!q) return true;
      return w.name.toLowerCase().includes(q) || w.id.toLowerCase().includes(q);
    });
  }, [workers, searchQuery, stateFilter]);

  // Totals always reflect the FULL fleet, not the filtered view.
  // The summary bar is a "what's actually running" snapshot, so
  // applying the user's filter to it would lie about the cluster.
  const totals = useMemo(() => {
    if (!workers || workers.length === 0) return null;
    return {
      active: workers.reduce((s, w) => s + (w.active_tasks ?? 0), 0),
      processed: workers.reduce((s, w) => s + (w.processed ?? 0), 0),
      succeeded: workers.reduce((s, w) => s + (w.succeeded ?? 0), 0),
      failed: workers.reduce((s, w) => s + (w.failed ?? 0), 0),
      retried: workers.reduce((s, w) => s + (w.retried ?? 0), 0),
      online: workers.filter((w) => w.state === "online").length,
      total: workers.length,
    };
  }, [workers]);

  function clearFilters() {
    setSearchQuery("");
    setStateFilter("all");
  }

  return (
    <PageShell>
      <PageHeader
        title="Workers"
        icon={Cpu}
        description="Inspect worker health, capacity, and task activity."
        actions={
          <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
        }
      />

      {/* Above the table on purpose: a dangerous default is a thing to act on,
          and it should not be something an operator finds only by scrolling. */}

      <DataTable
        isFetching={isFetching}
        isLoading={isLoading}
        error={isError ? "Unable to load workers. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Cpu}
            title={
              activeFilterCount > 0 ? "no workers match" : "no workers seen yet"
            }
            description={
              activeFilterCount > 0
                ? "try adjusting your filters or search query"
                : "workers will appear here once they connect through the z4j agent (Celery, RQ, or Dramatiq)"
            }
          />
        }
        toolbar={() => (
          <FilterToolbar
            searchValue={searchQuery}
            onSearchChange={setSearchQuery}
            searchPlaceholder="Search workers..."
            activeFilterCount={activeFilterCount}
            onClear={clearFilters}
            filters={
              <Select
                value={stateFilter}
                onValueChange={(v) => setStateFilter(v as WorkerState | "all")}
              >
                <SelectTrigger
                  aria-label="Worker state"
                  className="w-36 shrink-0"
                >
                  <SelectValue placeholder="State" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All states</SelectItem>
                  {WORKER_STATES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            }
          />
        )}
        notice={
          <>
            <WorkerLintPanel slug={slug} />
            {totals && (
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border bg-card px-4 py-3 text-sm">
                <div>
                  <span className="text-muted-foreground">Workers: </span>
                  <span className="font-semibold">
                    {totals.online}/{totals.total}
                  </span>
                  <span className="ml-1 text-xs text-muted-foreground">
                    online
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Active: </span>
                  <span className="font-semibold tabular-nums">
                    {totals.active}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Succeeded: </span>
                  <span className="font-semibold tabular-nums text-success">
                    {formatCompact(totals.succeeded)}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Failed: </span>
                  <span className="font-semibold tabular-nums text-destructive">
                    {formatCompact(totals.failed)}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Retried: </span>
                  <span className="font-semibold tabular-nums text-warning">
                    {formatCompact(totals.retried)}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Processed: </span>
                  <span className="font-semibold tabular-nums">
                    {formatCompact(totals.processed)}
                  </span>
                </div>
              </div>
            )}
          </>
        }
        columns={columns}
        data={filteredWorkers}
        enableSorting
        totalLabel={
          activeFilterCount > 0 &&
          (workers?.length ?? 0) !== filteredWorkers.length
            ? `${filteredWorkers.length} of ${workers?.length ?? 0} workers`
            : `${filteredWorkers.length} worker${filteredWorkers.length === 1 ? "" : "s"}`
        }
      />
    </PageShell>
  );
}

function useWorkerColumns(slug: string): DataTableColumnDef<WorkerPublic>[] {
  return useMemo(
    () => [
      {
        accessorKey: "name",
        header: "Worker",
        cell: ({ row }: { row: { original: WorkerPublic } }) => {
          const w = row.original;
          return (
            <Link
              to="/projects/$slug/workers/$workerId"
              params={{ slug, workerId: w.id }}
              className="font-medium text-foreground hover:underline"
            >
              {w.name}
            </Link>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "state",
        header: "State",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <WorkerStateBadge state={row.original.state} />
        ),
        enableSorting: true,
      },
      {
        id: "queues",
        accessorFn: (row) => row.queues.join(", "),
        header: "Queues",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="text-muted-foreground">
            {row.original.queues.length > 0
              ? row.original.queues.join(", ")
              : "-"}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "active_tasks",
        header: "Active",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="tabular-nums">{row.original.active_tasks}</span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "succeeded",
        header: "Succeeded",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="tabular-nums text-success">
            {formatCompact(row.original.succeeded ?? 0)}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "failed",
        header: "Failed",
        cell: ({ row }: { row: { original: WorkerPublic } }) => {
          const v = row.original.failed ?? 0;
          return (
            <span
              className={
                v > 0
                  ? "tabular-nums text-destructive"
                  : "tabular-nums text-muted-foreground"
              }
            >
              {formatCompact(v)}
            </span>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "retried",
        header: "Retried",
        cell: ({ row }: { row: { original: WorkerPublic } }) => {
          const v = row.original.retried ?? 0;
          return (
            <span
              className={
                v > 0
                  ? "tabular-nums text-warning"
                  : "tabular-nums text-muted-foreground"
              }
            >
              {formatCompact(v)}
            </span>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "processed",
        header: "Processed",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="tabular-nums font-medium">
            {formatCompact(row.original.processed ?? 0)}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "concurrency",
        header: "Concurrency",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="tabular-nums">
            {row.original.concurrency ?? "-"}
          </span>
        ),
        enableSorting: true,
      },
      {
        id: "load_average",
        accessorFn: (row) => row.load_average?.[0] ?? null,
        header: "Load",
        cell: ({ row }: { row: { original: WorkerPublic } }) => {
          const la = row.original.load_average;
          if (!la || !Array.isArray(la) || la.length === 0) return "-";
          return (
            <span
              className="whitespace-nowrap text-xs tabular-nums text-muted-foreground"
              title="1, 5 and 15 minute load averages"
            >
              {la.map((v) => Number(v).toFixed(2)).join(" / ")}
            </span>
          );
        },
        enableSorting: true,
      },
      {
        id: "last_heartbeat",
        accessorFn: (row) => sortTimestamp(row.last_heartbeat),
        header: "Heartbeat",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <DateCell value={row.original.last_heartbeat} compact />
        ),
        enableSorting: true,
      },
    ],
    [slug],
  );
}
