import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  AlertCircle,
  ArrowLeft,
  Ban,
  CheckCircle2,
  Clock,
  Gauge,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
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
import { Separator } from "@/components/ui/separator";
import { useTask, useTaskTree } from "@/hooks/use-tasks";
import { useEventsForTask } from "@/hooks/use-events";
import { TaskTree } from "@/components/domain/task-tree";
import { useAgents } from "@/hooks/use-agents";
import {
  useCancelTask,
  useRateLimit,
  useRetryTask,
} from "@/hooks/use-commands";
import { useCan } from "@/hooks/use-memberships";
import { formatAbsolute, formatDuration, formatRelative } from "@/lib/format";
import { ApiError } from "@/lib/api";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/tasks_/$engine/$taskId",
)({
  component: TaskDetailPage,
});

function TaskDetailPage() {
  const { slug, engine, taskId } = Route.useParams();
  const { data: task, isLoading } = useTask(slug, engine, taskId);
  const { data: events } = useEventsForTask(slug, engine, taskId);
  const { data: tree } = useTaskTree(slug, engine, taskId);
  const { data: agents } = useAgents(slug);
  const retry = useRetryTask(slug);
  const cancel = useCancelTask(slug);
  const rateLimit = useRateLimit(slug);

  // RBAC UI gates - mirrored from the server policy (api/deps.py).
  // Backend is the source of truth; this hides buttons so users
  // don't click through to a 403.
  const canRetry = useCan(slug, "retry_task");
  const canCancel = useCan(slug, "cancel_task");
  const canRateLimit = useCan(slug, "bulk_action");

  const [rateOpen, setRateOpen] = useState(false);
  const [rateValue, setRateValue] = useState("");

  // Pick the first agent - v1 is single-agent-per-project in
  // practice. The dispatcher rejects cross-project agent ids
  // server-side anyway.
  const agent = agents?.[0];
  const agentId = agent?.id;
  // ``agent.state`` is one of ``online`` | ``offline`` |
  // ``unknown``. Anything other than ``online`` means a command
  // we issue right now will queue as ``pending delivery`` and
  // sit there until the agent reconnects. We surface that on
  // every action button so the operator isn't confused by a
  // command that "succeeded" but never ran.
  const agentOnline = agent?.state === "online";
  const agentTooltip = !agent
    ? "no agent registered for this project"
    : agentOnline
      ? undefined
      : `agent is ${agent.state}; command will queue until it reconnects`;

  async function onRetry() {
    if (!agentId) {
      toast.error("no agent registered for this project");
      return;
    }
    try {
      await retry.mutateAsync({
        agent_id: agentId,
        engine,
        task_id: taskId,
      });
      toast.success("retry command issued");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`retry failed: ${message}`);
    }
  }

  async function onCancel() {
    if (!agentId) {
      toast.error("no agent registered for this project");
      return;
    }
    try {
      await cancel.mutateAsync({
        agent_id: agentId,
        engine,
        task_id: taskId,
      });
      toast.success("cancel command issued");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`cancel failed: ${message}`);
    }
  }

  async function onRateLimit() {
    if (!agentId || !task) {
      toast.error("no agent registered for this project");
      return;
    }
    try {
      await rateLimit.mutateAsync({
        agent_id: agentId,
        task_name: task.name,
        rate: rateValue.trim(),
      });
      toast.success(
        rateValue.trim() === "0"
          ? `rate limit cleared for "${task.name}"`
          : `rate limit set to ${rateValue} for "${task.name}"`,
      );
      setRateOpen(false);
      setRateValue("");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`rate limit failed: ${message}`);
    }
  }

  return (
    <div className="space-y-6 p-4 md:p-6">
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link
              to="/projects/$slug/tasks"
              params={{ slug }}
              className="flex items-center gap-1"
            >
              <ArrowLeft className="size-4" />
              All tasks
            </Link>
          </Button>
        </div>

        {isLoading && <Skeleton className="h-64 w-full" />}

        {task && (
          <>
            {/* Header card with actions */}
            <Card>
              <CardHeader className="!grid-rows-1 flex-row items-start justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <TaskStateBadge state={task.state} />
                    {task.queue && (
                      <span className="font-mono text-xs text-muted-foreground">
                        queue: {task.queue}
                      </span>
                    )}
                    {task.worker_name && (
                      <span className="font-mono text-xs text-muted-foreground">
                        worker: {task.worker_name}
                      </span>
                    )}
                  </div>
                  <CardTitle className="text-xl">{task.name}</CardTitle>
                  <CardDescription className="font-mono">
                    {task.task_id}
                  </CardDescription>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-2">
                  {agentTooltip && (
                    <p
                      className="text-xs italic text-warning"
                      role="status"
                      aria-live="polite"
                    >
                      {agentTooltip}
                    </p>
                  )}
                  <div className="flex gap-2">
                    {canRateLimit && engine === "celery" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setRateOpen(true)}
                        disabled={rateLimit.isPending || !agentId}
                        title={agentTooltip}
                        aria-label={`Set rate limit for ${task.name}`}
                      >
                        <Gauge className="size-4" />
                        Rate limit
                      </Button>
                    )}
                    {canCancel && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={onCancel}
                        disabled={cancel.isPending}
                        title={agentTooltip}
                      >
                        <Ban className="size-4" />
                        Cancel
                      </Button>
                    )}
                    {canRetry && (
                      <Button
                        size="sm"
                        onClick={onRetry}
                        disabled={retry.isPending}
                        title={agentTooltip}
                      >
                        <RefreshCw
                          className={
                            retry.isPending ? "size-4 animate-spin" : "size-4"
                          }
                        />
                        Retry
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                  <DetailField
                    label="Started"
                    value={formatAbsolute(task.started_at)}
                  />
                  <DetailField
                    label="Finished"
                    value={formatAbsolute(task.finished_at)}
                  />
                  <DetailField
                    label="Runtime"
                    value={formatDuration(task.runtime_ms)}
                  />
                  <DetailField
                    label="Retries"
                    value={String(task.retry_count)}
                  />
                </div>
              </CardContent>
            </Card>

            {/* args / kwargs / result panels */}
            <div className="grid gap-4 lg:grid-cols-2">
              <PayloadCard title="args" value={task.args} />
              <PayloadCard title="kwargs" value={task.kwargs} />
              {task.state === "success" && (
                <PayloadCard title="result" value={task.result} />
              )}
              {task.exception && (
                <Card className="lg:col-span-2 border-destructive/40">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-destructive">
                      <XCircle className="size-4" /> {task.exception}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="overflow-auto rounded-md border bg-card p-3 text-xs">
                      {task.traceback ?? "no traceback recorded"}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* Canvas tree (chains / groups / chords). Rendered
                only when the task is part of a multi-node canvas -
                a standalone task returns a single-node tree which
                we hide to keep the page tidy. */}
            {tree && tree.node_count > 1 && (
              <Card>
                <CardHeader>
                  <CardTitle>Canvas tree</CardTitle>
                  <CardDescription>
                    Every task spawned from the same chain / group /
                    chord. The currently-viewed task is ringed; click
                    any node to navigate.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <TaskTree
                    slug={slug}
                    engine={engine}
                    activeTaskId={taskId}
                    data={tree}
                  />
                </CardContent>
              </Card>
            )}

            {/* Events timeline */}
            <Card>
              <CardHeader>
                <CardTitle>Events</CardTitle>
                <CardDescription>
                  Raw lifecycle events from the agent in reverse chronological order.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {events?.items.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    no events recorded yet
                  </p>
                )}
                {events?.items.map((event, idx) => (
                  <div
                    key={event.id}
                    className="flex items-start gap-3 rounded-md border bg-card/40 p-3"
                  >
                    <EventIcon kind={event.kind} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-sm font-medium">
                          {event.kind}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatRelative(event.occurred_at)}
                        </span>
                      </div>
                      {Object.keys(event.payload).length > 0 && (
                        <pre className="mt-1 overflow-auto rounded bg-muted/40 p-2 text-xs">
                          {JSON.stringify(event.payload, null, 2)}
                        </pre>
                      )}
                    </div>
                    {idx < (events?.items.length ?? 0) - 1 && (
                      <Separator orientation="vertical" />
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          </>
        )}

      <Dialog open={rateOpen} onOpenChange={setRateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set rate limit</DialogTitle>
            <DialogDescription>
              Throttle <span className="font-mono">{task?.name}</span>{" "}
              across every worker on this project. The rate grammar
              is Celery's - <code>0</code> clears the limit,{" "}
              <code>5/s</code> caps the task to 5 executions per
              second. (Rate-limiting is only exposed for engines that
              advertise the <code>rate_limit</code> capability.)
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="rate-limit-input">Rate</Label>
            <Input
              id="rate-limit-input"
              value={rateValue}
              onChange={(e) => setRateValue(e.target.value)}
              placeholder="e.g. 100/m, 5/s, 1000/h, 0 (clear)"
              pattern="^(?:0|[1-9]\d*(?:/[smh])?)$"
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              Accepted: <code>0</code>, <code>&lt;n&gt;</code>,{" "}
              <code>&lt;n&gt;/s</code>, <code>&lt;n&gt;/m</code>,{" "}
              <code>&lt;n&gt;/h</code>.
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRateOpen(false)}
              disabled={rateLimit.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={onRateLimit}
              disabled={
                rateLimit.isPending ||
                !/^(?:0|[1-9]\d*(?:\/[smh])?)$/.test(rateValue.trim())
              }
            >
              <Gauge
                className={
                  rateLimit.isPending ? "size-4 animate-spin" : "size-4"
                }
              />
              Apply
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 font-mono text-sm">{value}</div>
    </div>
  );
}

function PayloadCard({ title, value }: { title: string; value: unknown }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <pre className="overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
          {value === null || value === undefined
            ? "null"
            : JSON.stringify(value, null, 2)}
        </pre>
      </CardContent>
    </Card>
  );
}

function EventIcon({ kind }: { kind: string }) {
  if (kind.endsWith("succeeded"))
    return <CheckCircle2 className="size-4 shrink-0 text-success" />;
  if (kind.endsWith("failed"))
    return <XCircle className="size-4 shrink-0 text-destructive" />;
  if (kind.endsWith("retried"))
    return <RefreshCw className="size-4 shrink-0 text-warning" />;
  if (kind.endsWith("revoked"))
    return <Ban className="size-4 shrink-0 text-muted-foreground" />;
  if (kind.endsWith("started"))
    return <Clock className="size-4 shrink-0 text-primary" />;
  return <AlertCircle className="size-4 shrink-0 text-muted-foreground" />;
}
