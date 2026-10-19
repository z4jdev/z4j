import { PageHeader } from "@/components/domain/page-header";
/**
 * Worker detail page - Flower-parity 6-tab view.
 *
 * Tabs: Pool, Broker, Queues, Tasks, System, Config
 *
 * Data comes from z4j's /workers/{id} endpoint which
 * stores the agent's control.inspect() results in worker_metadata.
 */
import { PageShell } from "@/components/domain/page-shell";
import { WorkerStateBadge } from "@/components/domain/state-badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAgents } from "@/hooks/use-agents";
import {
  useAddConsumer,
  useCancelConsumer,
  usePoolResize,
  useRestartWorker,
} from "@/hooks/use-commands";
import { useCan } from "@/hooks/use-memberships";
import { useWorkerDetail } from "@/hooks/use-workers";
import { ApiError } from "@/lib/api";
import { formatRelative } from "@/lib/format";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ArrowLeft,
  Minus,
  Plus,
  RefreshCw,
  Server,
  Trash2,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/workers_/$workerId",
)({
  component: WorkerDetailPage,
});

// Safe accessor helpers to avoid runtime crashes on unexpected shapes.
function obj(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null
    ? (v as Record<string, unknown>)
    : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function num(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}
function str(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "object") return JSON.stringify(v, null, 2).slice(0, 500);
  return String(v);
}

function WorkerDetailPage() {
  const { slug, workerId } = Route.useParams();
  const { data: worker, isLoading } = useWorkerDetail(slug, workerId);
  const { data: agents } = useAgents(slug);

  // RBAC UI gate - worker control-plane ops (pool, consumer,
  // restart) are operator+ actions. Backend enforces; this is the
  // UI mirror.
  const canOperate = useCan(slug, "bulk_action");

  // A capability says what an agent can do, not which worker it reports.
  // Missing/ambiguous retained provenance never falls back to another agent.
  const agent = agents?.find((candidate) => candidate.id === worker?.agent_id);
  const agentId = agent?.id;
  const supportsControl = (action: string) => {
    if (!canOperate || !worker || agent?.state !== "online") return false;
    const advertised = agent.capabilities[worker.engine];
    return (
      agent.engine_adapters.includes(worker.engine) &&
      Array.isArray(advertised) &&
      advertised.includes(action)
    );
  };
  const canGrow = supportsControl("pool_grow");
  const canShrink = supportsControl("pool_shrink");
  const canAdd = supportsControl("add_consumer");
  const canRemove = supportsControl("cancel_consumer");
  const canRestart = supportsControl("restart_worker");
  const controlNotice = !worker?.agent_id
    ? "Controls unavailable: retained worker reports do not identify a single reporting agent."
    : !agent || agent.state !== "online"
      ? "Controls unavailable: the reporting agent is not online."
      : ![canGrow, canShrink, canAdd, canRemove, canRestart].every(Boolean)
        ? "Some controls unavailable: the reporting agent has not advertised the required native actions for this engine."
        : null;

  // Command mutations
  const poolResize = usePoolResize(slug);
  const addConsumer = useAddConsumer(slug);
  const cancelConsumer = useCancelConsumer(slug);
  const restartWorker = useRestartWorker(slug);

  const commandInFlight =
    poolResize.isPending ||
    addConsumer.isPending ||
    cancelConsumer.isPending ||
    restartWorker.isPending;

  // Dialog state
  const [addQueueOpen, setAddQueueOpen] = useState(false);
  const [queueName, setQueueName] = useState("");
  const [restartOpen, setRestartOpen] = useState(false);

  // --- Command handlers ---

  async function onPoolResize(delta: number) {
    if (!(delta > 0 ? canGrow : canShrink)) return;
    if (!agentId || !worker) {
      toast.error("No agent available for this project");
      return;
    }
    try {
      await poolResize.mutateAsync({
        agent_id: agentId,
        engine: worker.engine,
        worker_name: worker.name,
        delta,
      });
      toast.success(
        `Pool resize (${delta > 0 ? "+" : ""}${delta}) command issued`,
      );
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`Pool resize failed: ${message}`);
    }
  }

  async function onAddQueue(e: React.FormEvent) {
    e.preventDefault();
    if (!canAdd) return;
    if (!agentId || !worker) {
      toast.error("No agent available for this project");
      return;
    }
    const name = queueName.trim();
    if (!name) return;
    try {
      await addConsumer.mutateAsync({
        agent_id: agentId,
        engine: worker.engine,
        worker_name: worker.name,
        queue: name,
      });
      toast.success(`Add consumer for "${name}" command issued`);
      setQueueName("");
      setAddQueueOpen(false);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`Add consumer failed: ${message}`);
    }
  }

  async function onCancelConsumer(queue: string) {
    if (!canOperate || !canRemove) return;
    if (!agentId || !worker) {
      toast.error("No agent available for this project");
      return;
    }
    try {
      await cancelConsumer.mutateAsync({
        agent_id: agentId,
        engine: worker.engine,
        worker_name: worker.name,
        queue,
      });
      toast.success(`Cancel consumer for "${queue}" command issued`);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`Cancel consumer failed: ${message}`);
    }
  }

  async function onRestartWorker() {
    if (!canRestart) return;
    if (!agentId || !worker) {
      toast.error("No agent available for this project");
      return;
    }
    try {
      await restartWorker.mutateAsync({
        agent_id: agentId,
        engine: worker.engine,
        worker_name: worker.name,
      });
      toast.success("Restart worker command issued");
      setRestartOpen(false);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`Restart worker failed: ${message}`);
    }
  }

  if (isLoading) {
    return (
      <PageShell spacing="sm">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-96 w-full" />
      </PageShell>
    );
  }

  if (!worker) {
    return (
      <PageShell>
        <p className="text-muted-foreground">Worker not found.</p>
      </PageShell>
    );
  }

  const meta = worker.metadata ?? {};
  const stats = obj(meta.stats);
  const pool = obj(stats.pool);
  const broker = obj(stats.broker);
  const rusage = obj(stats.rusage);
  const total = obj(stats.total) as Record<string, number>;
  const activeQueues = arr(meta.active_queues) as Record<string, unknown>[];
  const registered = arr(meta.registered) as string[];
  const conf = obj(meta.conf);
  const loadavg = arr(stats.loadavg);
  const uptime = num(stats.uptime);

  return (
    <>
      <PageShell>
        {/* Header */}
        <div className="flex items-center gap-3">
          <Button asChild variant="ghost" size="sm">
            <Link
              to="/projects/$slug/workers"
              params={{ slug }}
              className="flex items-center gap-1"
            >
              <ArrowLeft className="size-4" />
              Workers
            </Link>
          </Button>
        </div>

        <PageHeader
          title={worker.name}
          icon={Server}
          description="Worker health and process details."
          badges={
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <WorkerStateBadge state={worker.state} />
              <span>PID {worker.pid ?? "-"}</span>
              <span>{worker.engine}</span>
              {uptime !== null && <span>Uptime: {formatUptime(uptime)}</span>}
              {loadavg.length > 0 && (
                <span>
                  Load: {loadavg.map((v) => Number(v).toFixed(2)).join(", ")}
                </span>
              )}
              {worker.last_heartbeat && (
                <span>
                  Last heartbeat: {formatRelative(worker.last_heartbeat)}
                </span>
              )}
            </div>
          }
        />

        {/* Control bar - hidden entirely for non-operators; the worker
          pool / consumer / restart ops are admin+operator surface. */}
        {canOperate && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border bg-card p-3">
            <Button
              variant="outline"
              size="sm"
              disabled={commandInFlight || !canGrow}
              onClick={() => onPoolResize(1)}
            >
              <Plus className="mr-1 size-3.5" />
              Pool +1
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={commandInFlight || !canShrink}
              onClick={() => onPoolResize(-1)}
            >
              <Minus className="mr-1 size-3.5" />
              Pool -1
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={commandInFlight || !canAdd}
              onClick={() => {
                setQueueName("");
                setAddQueueOpen(true);
              }}
            >
              <Plus className="mr-1 size-3.5" />
              Add Queue
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-destructive"
              disabled={commandInFlight || !canRestart}
              onClick={() => setRestartOpen(true)}
            >
              <RefreshCw className="mr-1 size-3.5" />
              Restart Worker
            </Button>
            {controlNotice && (
              <p className="w-full text-sm text-muted-foreground">
                {controlNotice}
              </p>
            )}
          </div>
        )}

        {/* Tabs */}
        <Tabs defaultValue="pool" className="space-y-4">
          <TabsList className="flex-wrap">
            <TabsTrigger value="pool">Pool</TabsTrigger>
            <TabsTrigger value="broker">Broker</TabsTrigger>
            <TabsTrigger value="queues">
              Queues{activeQueues.length > 0 ? ` (${activeQueues.length})` : ""}
            </TabsTrigger>
            <TabsTrigger value="tasks">
              Tasks{registered.length > 0 ? ` (${registered.length})` : ""}
            </TabsTrigger>
            <TabsTrigger value="system">System</TabsTrigger>
            <TabsTrigger value="config">
              Config
              {Object.keys(conf).length > 0
                ? ` (${Object.keys(conf).length})`
                : ""}
            </TabsTrigger>
          </TabsList>

          {/* Pool tab */}
          <TabsContent value="pool">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Worker pool</CardTitle>
              </CardHeader>
              <CardContent>
                <KVTable
                  rows={[
                    ["Implementation", str(pool.implementation ?? stats.pool)],
                    [
                      "Max concurrency",
                      str(pool["max-concurrency"] ?? worker.concurrency),
                    ],
                    [
                      "Processes",
                      Array.isArray(pool.processes)
                        ? (pool.processes as number[]).join(", ")
                        : str(pool.processes),
                    ],
                    ["Max tasks per child", str(pool["max-tasks-per-child"])],
                    ["Worker PID", str(worker.pid)],
                    ["Prefetch count", str(stats.prefetch_count)],
                    ["Active tasks", String(worker.active_tasks)],
                    ["Clock", str(stats.clock)],
                  ]}
                />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Broker tab */}
          <TabsContent value="broker">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Broker connection</CardTitle>
              </CardHeader>
              <CardContent>
                <KVTable
                  rows={[
                    ["Hostname", str(broker.hostname)],
                    ["Port", str(broker.port)],
                    ["Transport", str(broker.transport)],
                    ["Virtual host", str(broker.virtual_host)],
                    ["SSL", str(broker.ssl)],
                    ["Connect timeout", str(broker.connect_timeout)],
                    ["Heartbeat", str(broker.heartbeat)],
                    ["Login method", str(broker.login_method)],
                    ["Failover strategy", str(broker.failover_strategy)],
                  ]}
                />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Queues tab */}
          <TabsContent value="queues">
            <Card className="overflow-hidden">
              <CardHeader>
                <CardTitle className="text-sm">Active queues</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {activeQueues.length === 0 ? (
                  <p className="p-4 text-sm text-muted-foreground">
                    No active queues reported.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead sortKey="c0">Name</TableHead>
                        <TableHead sortKey="c1">Routing key</TableHead>
                        <TableHead sortKey="c2">Durable</TableHead>
                        <TableHead sortKey="c3">Exclusive</TableHead>
                        <TableHead className="text-right"></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {activeQueues.map((q, i) => (
                        <TableRow
                          sortValues={{
                            c0: str(q.name),
                            c1: str(q.routing_key),
                            c2: str(q.durable),
                            c3: str(q.exclusive),
                          }}
                          key={i}
                        >
                          <TableCell className="font-medium">
                            {str(q.name)}
                          </TableCell>
                          <TableCell>{str(q.routing_key)}</TableCell>
                          <TableCell>{str(q.durable)}</TableCell>
                          <TableCell>{str(q.exclusive)}</TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={
                                !canOperate || commandInFlight || !canRemove
                              }
                              onClick={() => onCancelConsumer(String(q.name))}
                            >
                              <Trash2 className="mr-1 size-3.5 text-destructive" />
                              Remove
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tasks tab */}
          <TabsContent value="tasks">
            <div className="space-y-4">
              {/* Processed task counts */}
              {Object.keys(total).length > 0 && (
                <Card className="overflow-hidden">
                  <CardHeader>
                    <CardTitle className="text-sm">Processed tasks</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead sortKey="c0">Task</TableHead>
                          <TableHead sortKey="c1" className="text-right">
                            Count
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {Object.entries(total)
                          .sort(([, a], [, b]) => b - a)
                          .map(([name, count]) => (
                            <TableRow
                              sortValues={{ c0: name, c1: count }}
                              key={name}
                            >
                              <TableCell className="font-mono text-sm">
                                {name}
                              </TableCell>
                              <TableCell className="text-right tabular-nums">
                                {count}
                              </TableCell>
                            </TableRow>
                          ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              )}

              {/* Registered task names */}
              {registered.length > 0 && (
                <Card className="overflow-hidden">
                  <CardHeader>
                    <CardTitle className="text-sm">
                      Registered tasks ({registered.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead sortKey="c0">Task name</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {[...registered].sort().map((name) => (
                          <TableRow sortValues={{ c0: name }} key={name}>
                            <TableCell className="font-mono text-sm">
                              {name}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              )}

              {Object.keys(total).length === 0 && registered.length === 0 && (
                <Card>
                  <CardContent className="py-8 text-center text-sm text-muted-foreground">
                    No task data available yet. Stats populate after the first
                    heartbeat with worker inspection.
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* System tab */}
          <TabsContent value="system">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">System resource usage</CardTitle>
              </CardHeader>
              <CardContent>
                {Object.keys(rusage).length > 0 ? (
                  <KVTable
                    rows={Object.entries(rusage).map(([k, v]) => [
                      k.replace(/_/g, " "),
                      str(v),
                    ])}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">
                    System stats not available yet.
                  </p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Config tab */}
          <TabsContent value="config">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">
                  Worker configuration ({Object.keys(conf).length} keys)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {Object.keys(conf).length > 0 ? (
                  <div className="max-h-[600px] overflow-auto">
                    <KVTable
                      rows={Object.entries(conf)
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([k, v]) => [k, str(v)])}
                    />
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Configuration not available yet.
                  </p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </PageShell>

      {/* Add Queue dialog */}
      <Dialog open={addQueueOpen} onOpenChange={setAddQueueOpen}>
        <DialogContent>
          <form onSubmit={onAddQueue}>
            <DialogHeader>
              <DialogTitle>Add queue consumer</DialogTitle>
              <DialogDescription>
                Asks the worker to start consuming from this queue. Celery
                sends no confirmation; check Active queues on the Queues tab.
              </DialogDescription>
            </DialogHeader>
            <div className="my-6 space-y-2">
              <Label htmlFor="queue-name">Queue name</Label>
              <Input
                id="queue-name"
                required
                value={queueName}
                onChange={(e) => setQueueName(e.target.value)}
                placeholder="my-queue"
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddQueueOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={addConsumer.isPending || !canAdd}>
                Add consumer
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Restart Worker confirmation dialog - engine-aware copy. */}
      <Dialog open={restartOpen} onOpenChange={setRestartOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restart worker</DialogTitle>
            {worker?.engine === "celery" ? (
              <DialogDescription>
                This broadcasts Celery's{" "}
                <span className="font-mono">pool_restart</span> to the worker.
                It takes effect only when the worker enables{" "}
                <span className="font-mono">worker_pool_restarts</span>, is not
                reliable on gevent or eventlet pools, and z4j cannot confirm the
                restart. Continue?
              </DialogDescription>
            ) : (
              <DialogDescription>
                This asks the reporting agent to restart the named worker using
                this engine's native control. Running tasks may be interrupted.
                Continue?
              </DialogDescription>
            )}
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setRestartOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={restartWorker.isPending || !canRestart}
              onClick={onRestartWorker}
            >
              {worker?.engine === "celery" ? "Restart pool" : "Restart worker"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function KVTable({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="divide-y">
      {rows.map(([key, value]) => (
        <div
          className="grid gap-1 px-4 py-3 sm:grid-cols-[minmax(10rem,1fr)_2fr] sm:gap-4"
          key={key}
        >
          <dt className="text-sm font-medium text-muted-foreground">{key}</dt>
          <dd className="min-w-0 break-words font-mono text-sm">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return `${d}d ${h}h`;
}
