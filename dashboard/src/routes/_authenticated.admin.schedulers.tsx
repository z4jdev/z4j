/**
 * Schedulers fleet overview (docs/SCHEDULER.md §13.1).
 *
 * One-row-per-instance status grid: version, instance_id,
 * uptime, leader status, schedules loaded. Brain fans out to each
 * configured scheduler ``/info`` URL on every refresh.
 *
 * Operators land here when:
 *
 * - First post-deploy sanity check after standing up a scheduler.
 *   The page either shows the new instance ready=true within
 *   seconds, or surfaces the connection error so the operator
 *   can fix it.
 * - Investigating a flapping fire path. Per-instance
 *   ``brain_client_connected`` + ``cache_initial_sync_complete``
 *   isolate which side of the wire is unhealthy.
 * - Capacity planning. ``schedules_loaded`` + ``leader status``
 *   show the per-project distribution at a glance.
 *
 * Configuration: set ``Z4J_SCHEDULER_INFO_URLS=http://...`` on
 * z4j to populate the list. The embedded sidecar is
 * auto-included when ``Z4J_EMBEDDED_SCHEDULER=true`` so the
 * homelab one-container deploy works without operator config.
 */
import { EmptyState } from "@/components/domain/empty-state";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useSchedulersFleet } from "@/hooks/use-schedulers-fleet";
import type { FleetEntry } from "@/lib/api-types";
import { cn } from "@/lib/utils";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2, Clock, Server, WifiOff, XCircle } from "lucide-react";

export const Route = createFileRoute("/_authenticated/admin/schedulers")({
  component: SchedulersFleetPage,
});

function SchedulersFleetPage() {
  const { data, isLoading, isFetching, isError, refetch } =
    useSchedulersFleet();

  return (
    <PageShell>
      <PageHeader
        title="Schedulers"
        icon={Server}
        description="Operator-fleet view across every enrolled z4j-scheduler instance"
        actions={
          <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
        }
      />

      <Table
        searchable
        searchPlaceholder="Search schedulers…"
        isLoading={isLoading}
        error={isError ? "Unable to load scheduler health. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Server}
            title="no schedulers configured"
            description={
              "Set Z4J_SCHEDULER_INFO_URLS on brain to a comma-separated " +
              "list of scheduler /info URLs (e.g. http://scheduler-1:7800," +
              "http://scheduler-2:7800). Brain fans out to each on dashboard " +
              "refresh. If you're using the embedded sidecar " +
              "(Z4J_EMBEDDED_SCHEDULER=true) the local instance will auto-appear here."
            }
          />
        }
        notice={
          data && (
            <SummaryCards
              total={data.total}
              healthy={data.healthy}
              unhealthy={data.total - data.healthy}
            />
          )
        }
      >
        <TableHeader>
          <TableRow>
            <TableHead sortKey="c0">Reachability</TableHead>
            <TableHead sortKey="c1">Instance</TableHead>
            <TableHead sortKey="c2">Version</TableHead>
            <TableHead sortKey="c3">Uptime</TableHead>
            <TableHead sortKey="c4">Brain gRPC</TableHead>
            <TableHead sortKey="c5" className="text-right">
              Schedules
            </TableHead>
            <TableHead sortKey="c6">Subsystems</TableHead>
            <TableHead sortKey="c7">Detail</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(data?.schedulers ?? []).map((entry) => (
            <FleetRow
              sortValues={{
                c0:
                  entry.ok === true
                    ? "online"
                    : entry.ok === false
                      ? "error"
                      : "unreachable",
                c1: entry.info?.instance_id ?? entry.url,
                c2: entry.info?.version,
                c3: entry.info?.uptime_seconds,
                c4: entry.info?.brain_grpc_url,
                c5: entry.info?.schedules_loaded,
                c6: Object.values(entry.info?.subsystems ?? {}).filter(Boolean)
                  .length,
                c7: entry.info?.ready
                  ? "ready"
                  : (entry.error ?? "initialising"),
              }}
              key={entry.url}
              entry={entry}
            />
          ))}
        </TableBody>
      </Table>
    </PageShell>
  );
}

function SummaryCards({
  total,
  healthy,
  unhealthy,
}: {
  total: number;
  healthy: number;
  unhealthy: number;
}) {
  return (
    <div className="grid gap-3 md:grid-cols-3">
      <SummaryCard label="Total" value={total} icon={Server} tone="neutral" />
      <SummaryCard
        label="Healthy"
        value={healthy}
        icon={CheckCircle2}
        tone={total > 0 && healthy === total ? "good" : "neutral"}
      />
      <SummaryCard
        label="Unhealthy"
        value={unhealthy}
        icon={WifiOff}
        tone={unhealthy > 0 ? "bad" : "neutral"}
      />
    </div>
  );
}

function SummaryCard({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  icon: typeof Server;
  tone: "good" | "bad" | "neutral";
}) {
  const toneClass =
    tone === "good"
      ? "border-green-500/40 bg-green-500/5"
      : tone === "bad"
        ? "border-red-500/40 bg-red-500/5"
        : "";
  return (
    <div
      className={cn(
        "flex items-center justify-between rounded-md border bg-card px-4 py-3",
        toneClass,
      )}
    >
      <div>
        <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
          {label}
        </div>
        <div className="text-2xl font-bold tabular-nums">{value}</div>
      </div>
      <Icon className="size-6 text-muted-foreground" />
    </div>
  );
}

function FleetRow({
  entry,
}: { entry: FleetEntry } & import("@/components/ui/table").TableRowSortProps) {
  if (entry.ok !== true) {
    return (
      <TableRow>
        <TableCell>
          <ReachabilityIcon ok={entry.ok} />
        </TableCell>
        <TableCell colSpan={6}>
          <div>
            <div className="font-mono text-xs">{entry.url}</div>
            <div className="text-xs text-destructive">
              {entry.error ?? "unknown error"}
            </div>
          </div>
        </TableCell>
        <TableCell>
          <Badge
            variant="outline"
            className={
              entry.ok === false
                ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                : "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400"
            }
          >
            {entry.ok === false ? "bad response" : "unreachable"}
          </Badge>
        </TableCell>
      </TableRow>
    );
  }
  const info = entry.info ?? {};
  const subsystems = info.subsystems ?? {};
  return (
    <TableRow>
      <TableCell>
        <ReachabilityIcon ok={entry.ok} />
      </TableCell>
      <TableCell>
        <div>
          <div className="font-mono text-sm">{info.instance_id ?? "-"}</div>
          <div className="font-mono text-[10px] text-muted-foreground">
            {entry.url}
          </div>
        </div>
      </TableCell>
      <TableCell>
        <Badge variant="outline" className="font-mono text-[10px]">
          {info.version ?? "-"}
        </Badge>
      </TableCell>
      <TableCell>
        <UptimeCell seconds={info.uptime_seconds} />
      </TableCell>
      <TableCell>
        <span className="font-mono text-xs text-muted-foreground">
          {info.brain_grpc_url ?? "-"}
        </span>
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {info.schedules_loaded ?? 0}
      </TableCell>
      <TableCell>
        <SubsystemDots
          brainConnected={subsystems.brain_client_connected}
          cacheSynced={subsystems.cache_initial_sync_complete}
          leaderUp={subsystems.leader_gate_initialised}
        />
      </TableCell>
      <TableCell>
        {info.ready ? (
          <Badge
            variant="outline"
            className="border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400"
          >
            ready
          </Badge>
        ) : (
          <Badge
            variant="outline"
            className="border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
          >
            initialising
          </Badge>
        )}
      </TableCell>
    </TableRow>
  );
}

function ReachabilityIcon({ ok }: { ok: boolean | null }) {
  if (ok === true)
    return (
      <CheckCircle2 className="size-5 text-green-700 dark:text-green-400" />
    );
  if (ok === false)
    return <XCircle className="size-5 text-amber-700 dark:text-amber-400" />;
  return <WifiOff className="size-5 text-red-700 dark:text-red-400" />;
}

function UptimeCell({ seconds }: { seconds?: number }) {
  if (seconds === undefined) {
    return <span className="text-muted-foreground">-</span>;
  }
  let value: string;
  if (seconds < 60) value = `${Math.round(seconds)}s`;
  else if (seconds < 3600) value = `${Math.round(seconds / 60)}m`;
  else if (seconds < 86400) value = `${(seconds / 3600).toFixed(1)}h`;
  else value = `${(seconds / 86400).toFixed(1)}d`;
  return (
    <span className="inline-flex items-center gap-1 text-xs">
      <Clock className="size-3 text-muted-foreground" />
      <span className="tabular-nums">{value}</span>
    </span>
  );
}

function SubsystemDots({
  brainConnected,
  cacheSynced,
  leaderUp,
}: {
  brainConnected?: boolean;
  cacheSynced?: boolean;
  leaderUp?: boolean;
}) {
  // Three dots: brain client / cache / leader gate. Each green
  // when up, red when down. Tooltip explains which one is which.
  return (
    <div className="flex items-center gap-1">
      <Dot label="brain client" ok={brainConnected} />
      <Dot label="cache sync" ok={cacheSynced} />
      <Dot label="leader gate" ok={leaderUp} />
    </div>
  );
}

function Dot({ label, ok }: { label: string; ok?: boolean }) {
  return (
    <span
      title={`${label}: ${ok ? "up" : "down"}`}
      className={cn(
        "inline-block size-2 rounded-full",
        ok ? "bg-green-600 dark:bg-green-500" : "bg-red-600 dark:bg-red-500",
      )}
    />
  );
}
