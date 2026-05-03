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
import { useMemo } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import { Cpu, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { WorkerStateBadge } from "@/components/domain/state-badges";
import { EmptyState } from "@/components/domain/empty-state";
import { DataTable } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useWorkers } from "@/hooks/use-workers";
import { DateCell } from "@/components/domain/date-cell";
import { formatCompact } from "@/lib/format";
import type { WorkerPublic } from "@/lib/api-types";

export const Route = createFileRoute("/_authenticated/projects/$slug/workers")({
  component: WorkersPage,
});

function WorkersPage() {
  const { slug } = Route.useParams();
  const { data: workers, isLoading, isFetching, refetch } = useWorkers(slug);

  const columns = useWorkerColumns(slug);

  // Compute totals for the summary row + the in-table Total row.
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

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Workers"
        icon={Cpu}
        description="every worker process the agent has observed"
        actions={
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
        }
      />

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}
      {workers && workers.length === 0 && (
        <EmptyState
          icon={Cpu}
          title="no workers seen yet"
          description="workers will appear here once they connect through the z4j agent (Celery, RQ, or Dramatiq)"
        />
      )}
      {workers && workers.length > 0 && (
        <>
          {/* Summary bar */}
          {totals && (
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border bg-card px-4 py-3 text-sm">
              <div>
                <span className="text-muted-foreground">Workers: </span>
                <span className="font-semibold">
                  {totals.online}/{totals.total}
                </span>
                <span className="ml-1 text-xs text-muted-foreground">online</span>
              </div>
              <div>
                <span className="text-muted-foreground">Active: </span>
                <span className="font-semibold tabular-nums">{totals.active}</span>
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
          <DataTable
            columns={columns}
            data={workers}
            enableSorting
            totalLabel={`${workers.length} worker${workers.length === 1 ? "" : "s"}`}
          />
          {/* In-table Total row. Lives outside <DataTable> so the
              column layout matches without forcing the table
              component to grow a footer-row API. */}
          {totals && workers.length > 1 && (
            <div className="rounded-md border bg-muted/30 px-4 py-2 text-xs">
              <span className="font-semibold text-muted-foreground">Total</span>
              <span className="ml-4 inline-flex gap-4 tabular-nums">
                <span>active <strong>{totals.active}</strong></span>
                <span className="text-success">succeeded <strong>{formatCompact(totals.succeeded)}</strong></span>
                <span className="text-destructive">failed <strong>{formatCompact(totals.failed)}</strong></span>
                <span className="text-warning">retried <strong>{formatCompact(totals.retried)}</strong></span>
                <span>processed <strong>{formatCompact(totals.processed)}</strong></span>
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function useWorkerColumns(slug: string): ColumnDef<WorkerPublic, unknown>[] {
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
        accessorKey: "queues",
        header: "Queues",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <span className="text-muted-foreground">
            {row.original.queues.length > 0
              ? row.original.queues.join(", ")
              : "-"}
          </span>
        ),
        enableSorting: false,
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
        accessorKey: "load_average",
        header: "Load",
        cell: ({ row }: { row: { original: WorkerPublic } }) => {
          const la = row.original.load_average;
          if (!la || !Array.isArray(la) || la.length === 0) return "-";
          return (
            <span className="text-xs tabular-nums text-muted-foreground">
              {la.map((v) => Number(v).toFixed(2)).join(", ")}
            </span>
          );
        },
        enableSorting: false,
      },
      {
        accessorKey: "last_heartbeat",
        header: "Heartbeat",
        cell: ({ row }: { row: { original: WorkerPublic } }) => (
          <DateCell value={row.original.last_heartbeat} />
        ),
        enableSorting: true,
      },
    ],
    [slug],
  );
}
