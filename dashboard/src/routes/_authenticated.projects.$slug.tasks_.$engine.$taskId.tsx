import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { QueryError } from "@/components/domain/query-error";
import { TaskStateBadge } from "@/components/domain/state-badges";
import { TaskTree } from "@/components/domain/task-tree";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { useAgents } from "@/hooks/use-agents";
import {
  useCancelTask,
  useRateLimit,
  useRetryTask,
} from "@/hooks/use-commands";
import { useEventsForTask } from "@/hooks/use-events";
import { useCan } from "@/hooks/use-memberships";
import { useTask, useTaskTree } from "@/hooks/use-tasks";
import {
  agentsForEngine,
  reportsAdapterInventory,
  supportsAgentAction,
} from "@/lib/agent-capabilities";
import { ApiError } from "@/lib/api";
import { formatAbsolute, formatDuration, formatRelative } from "@/lib/format";
import {
  parseTaskListSearch,
  type TaskListSearch,
} from "@/lib/task-list-search";
import { createFileRoute, Link } from "@tanstack/react-router";
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
import { useState } from "react";
import { toast } from "sonner";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/tasks_/$engine/$taskId",
)({
  component: TaskDetailPage,
  validateSearch: (
    search: Record<string, unknown>,
  ): { list?: TaskListSearch } => ({
    list:
      search.list &&
      typeof search.list === "object" &&
      !Array.isArray(search.list)
        ? parseTaskListSearch(search.list as Record<string, unknown>)
        : undefined,
  }),
});

function TaskDetailPage() {
  const { slug, engine, taskId } = Route.useParams();
  const { list } = Route.useSearch();
  const {
    data: task,
    isLoading,
    isError,
    refetch,
  } = useTask(slug, engine, taskId);
  const {
    data: events,
    isError: eventsError,
    refetch: refetchEvents,
  } = useEventsForTask(slug, engine, taskId);
  const {
    data: tree,
    isError: treeError,
    refetch: refetchTree,
  } = useTaskTree(slug, engine, taskId);
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

  const [selectedAgentId, setSelectedAgentId] = useState("");
  // A long-poll agent never reports its engines, so it stays a candidate for
  // this task; an agent whose hello listed only other engines does not.
  const eligibleAgents = agentsForEngine(agents, engine);
  // With several candidates, preselect the only one whose hello listed this
  // engine; a long-poll agent stays in the list for the operator to choose.
  const reportingAgents = eligibleAgents.filter(reportsAdapterInventory);
  const defaultAgent =
    eligibleAgents.length === 1
      ? eligibleAgents[0]
      : reportingAgents.length === 1
        ? reportingAgents[0]
        : undefined;
  const agent =
    eligibleAgents.find((candidate) => candidate.id === selectedAgentId) ??
    defaultAgent;
  const agentId = agent?.id;
  const agentTooltip = !agent
    ? agents !== undefined && eligibleAgents.length === 0
      ? `No agent in this project runs ${engine} tasks.`
      : "Select the agent that owns this task before issuing a command."
    : agent.state === "online"
      ? undefined
      : `Agent is ${agent.state}; commands wait for it to reconnect.`;

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
    <PageShell>
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link
            to="/projects/$slug/tasks"
            params={{ slug }}
            search={list ?? {}}
            className="flex items-center gap-1"
          >
            <ArrowLeft className="size-4" />
            Back to tasks
          </Link>
        </Button>
      </div>

      {isError && (
        <QueryError
          message="Task details could not be loaded"
          onRetry={() => refetch()}
        />
      )}
      {isLoading && <Skeleton className="h-64 w-full" />}

      {task && (
        <>
          {/* Header card with actions */}
          <PageHeader
            title={task.name}
            description={
              <span className="break-all font-mono">{task.task_id}</span>
            }
            badges={
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
            }
            actions={
              <div className="flex max-w-full shrink-0 flex-col gap-2 xl:max-w-sm xl:items-end">
                {(canRetry || canCancel || canRateLimit) &&
                  eligibleAgents.length > 1 && (
                    <Select
                      value={agentId ?? ""}
                      onValueChange={setSelectedAgentId}
                    >
                      <SelectTrigger
                        aria-label="Command target agent"
                        className="w-full xl:w-72"
                      >
                        <SelectValue placeholder="Select the task’s agent" />
                      </SelectTrigger>
                      <SelectContent>
                        {eligibleAgents.map((candidate) => (
                          <SelectItem key={candidate.id} value={candidate.id}>
                            {candidate.name} · {candidate.state}
                            {!reportsAdapterInventory(candidate) &&
                              " · engines not reported"}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                {agentTooltip && (
                  <p
                    className="text-xs italic text-warning"
                    role="status"
                    aria-live="polite"
                  >
                    {agentTooltip}
                  </p>
                )}
                <div className="flex flex-wrap gap-2">
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
                      disabled={
                        cancel.isPending ||
                        !agentId ||
                        !supportsAgentAction(agent, engine, "cancel_task")
                      }
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
                      disabled={
                        retry.isPending ||
                        !agentId ||
                        !supportsAgentAction(agent, engine, "retry_task")
                      }
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
            }
          />
          <Card>
            <CardContent className="pt-6">
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
                <DetailField label="Retries" value={String(task.retry_count)} />
              </div>
            </CardContent>
          </Card>

          {task.exception && (
            <Card className="border-destructive/30">
              <CardHeader>
                <CardTitle className="flex items-start gap-2 break-words text-destructive">
                  <XCircle className="mt-0.5 size-4 shrink-0" />
                  {task.exception}
                </CardTitle>
                <CardDescription>Recorded failure · {engine}</CardDescription>
              </CardHeader>
              <CardContent>
                <pre className="max-h-80 overflow-auto rounded-lg border bg-background p-4 text-xs leading-relaxed">
                  {task.traceback ?? "No traceback recorded"}
                </pre>
                <Button asChild variant="ghost" size="sm" className="mt-3">
                  <Link to="/projects/$slug/issues" params={{ slug }}>
                    View recurring issues
                  </Link>
                </Button>
              </CardContent>
            </Card>
          )}
          <details className="panel-surface p-5">
            <summary className="cursor-pointer text-sm font-semibold">
              Arguments and result
            </summary>
            <p className="mt-2 text-xs text-muted-foreground">
              Captured payloads are redacted observations. They are not a replay
              recipe.
            </p>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <PayloadCard title="Arguments" value={task.args} />
              <PayloadCard title="Keyword arguments" value={task.kwargs} />
              {task.state === "success" && (
                <PayloadCard title="Result" value={task.result} />
              )}
            </div>
          </details>
          {treeError && (
            <QueryError
              message="Related tasks could not be loaded"
              onRetry={() => refetchTree()}
            />
          )}

          {/* Canvas tree (chains / groups / chords). Rendered
                only when the task is part of a multi-node canvas -
                a standalone task returns a single-node tree which
                we hide to keep the page tidy. */}
          {tree && tree.node_count > 1 && (
            <Card>
              <CardHeader>
                <CardTitle>Canvas tree</CardTitle>
                <CardDescription>
                  Every task spawned from the same chain / group / chord. The
                  currently-viewed task is ringed; click any node to navigate.
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
              <CardTitle>Execution timeline</CardTitle>
              <CardDescription>
                Raw lifecycle events from the agent in reverse chronological
                order.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {eventsError && (
                <QueryError
                  message="Timeline could not be loaded"
                  onRetry={() => refetchEvents()}
                />
              )}
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
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-sm font-medium">
                        {event.kind}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {formatRelative(event.occurred_at)}
                      </span>
                    </div>
                    {Object.keys(event.payload).length > 0 && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-xs text-muted-foreground">
                          Event payload
                        </summary>
                        <pre className="mt-2 overflow-auto rounded bg-muted/40 p-3 text-xs">
                          {JSON.stringify(event.payload, null, 2)}
                        </pre>
                      </details>
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
              Throttle <span className="font-mono">{task?.name}</span> across
              every worker on this project. The rate grammar is Celery's -{" "}
              <code>0</code> clears the limit, <code>5/s</code> caps the task to
              5 executions per second. (Rate-limiting is only exposed for
              engines that advertise the <code>rate_limit</code> capability.)
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
    </PageShell>
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
