/**
 * Per-domain state badges with consistent colors across the app.
 *
 * Colocated so the success/failure/warning palette is one source
 * of truth - every page that renders a task / agent / worker /
 * command state goes through these helpers.
 */
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Flame,
} from "lucide-react";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import type {
  AgentState,
  CommandStatus,
  TaskPriority,
  TaskState,
  WorkerState,
} from "@/lib/api-types";

const TASK_VARIANT: Record<TaskState, BadgeProps["variant"]> = {
  pending: "muted",
  received: "secondary",
  started: "default",
  success: "success",
  failure: "destructive",
  retry: "warning",
  revoked: "muted",
  rejected: "destructive",
  unknown: "outline",
};

export function TaskStateBadge({ state }: { state: TaskState }) {
  return <Badge variant={TASK_VARIANT[state] ?? "outline"}>{state}</Badge>;
}

const AGENT_VARIANT: Record<AgentState, BadgeProps["variant"]> = {
  online: "success",
  offline: "muted",
  unknown: "outline",
};

export function AgentStateBadge({ state }: { state: AgentState }) {
  return <Badge variant={AGENT_VARIANT[state]}>{state}</Badge>;
}

const WORKER_VARIANT: Record<WorkerState, BadgeProps["variant"]> = {
  online: "success",
  offline: "muted",
  draining: "warning",
  unknown: "outline",
};

export function WorkerStateBadge({ state }: { state: WorkerState }) {
  return <Badge variant={WORKER_VARIANT[state]}>{state}</Badge>;
}

const COMMAND_VARIANT: Record<CommandStatus, BadgeProps["variant"]> = {
  pending: "warning",
  dispatched: "secondary",
  completed: "success",
  failed: "destructive",
  timeout: "warning",
  cancelled: "outline",
};

const COMMAND_LABEL: Record<CommandStatus, string> = {
  // ``pending`` historically read like "queued" - operators
  // didn't realise the agent has not yet ack'd. Call it
  // "pending delivery" so the UX surfaces the actual state
  // instead of just echoing the enum value.
  pending: "pending delivery",
  dispatched: "dispatched",
  completed: "completed",
  failed: "failed",
  timeout: "timed out",
  cancelled: "cancelled",
};

export function CommandStatusBadge({ status }: { status: CommandStatus }) {
  return <Badge variant={COMMAND_VARIANT[status]}>{COMMAND_LABEL[status]}</Badge>;
}

const PRIORITY_CONFIG: Record<
  TaskPriority,
  { variant: BadgeProps["variant"]; icon: typeof Flame; label: string }
> = {
  critical: { variant: "destructive", icon: Flame, label: "critical" },
  high: { variant: "warning", icon: ArrowUp, label: "high" },
  normal: { variant: "muted", icon: ArrowDown, label: "normal" },
  low: { variant: "outline", icon: ArrowDown, label: "low" },
};

export function TaskPriorityBadge({
  priority,
  compact = false,
}: {
  priority: TaskPriority;
  compact?: boolean;
}) {
  const config = PRIORITY_CONFIG[priority] ?? PRIORITY_CONFIG.normal;
  const Icon = config.icon;
  if (priority === "normal" && compact) return null;
  return (
    <Badge variant={config.variant} className="gap-1">
      <Icon className="size-3" />
      {!compact && <span>{config.label}</span>}
    </Badge>
  );
}
