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
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
  WifiOff,
  XCircle,
} from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
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

export const Route = createFileRoute("/_authenticated/admin/schedulers")({
  component: SchedulersFleetPage,
});

function SchedulersFleetPage() {
  const { data, isLoading, isFetching, refetch } = useSchedulersFleet();

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Schedulers"
        icon={Server}
        description="Operator-fleet view across every enrolled z4j-scheduler instance"
        actions={
          <Button
            size="sm"
            variant="outline"
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
          {[0, 1].map((i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      )}

      {data && (
        <SummaryCards
          total={data.total}
          healthy={data.healthy}
          unhealthy={data.total - data.healthy}
        />
      )}

      {data && data.schedulers.length === 0 && (
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
      )}

      {data && data.schedulers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Instances ({data.schedulers.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12"></TableHead>
                  <TableHead>Instance</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Uptime</TableHead>
                  <TableHead>Brain gRPC</TableHead>
                  <TableHead className="text-right">Schedules</TableHead>
                  <TableHead>Subsystems</TableHead>
                  <TableHead>Detail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.schedulers.map((entry) => (
                  <FleetRow key={entry.url} entry={entry} />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
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

function FleetRow({ entry }: { entry: FleetEntry }) {
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
          <div className="font-mono text-sm">
            {info.instance_id ?? "-"}
          </div>
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
          ready={info.ready}
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
  ready,
  brainConnected,
  cacheSynced,
  leaderUp,
}: {
  ready?: boolean;
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
        ok
          ? "bg-green-600 dark:bg-green-500"
          : "bg-red-600 dark:bg-red-500",
      )}
    />
  );
}

// Suppress unused-import warning for AlertTriangle - kept around
// for future row-level warning states (e.g. version skew within
// the fleet).
const _unused = AlertTriangle;
