import type { TaskPriority, TaskState } from "./api-types";
export interface TaskListSearch {
  state?: TaskState | "all";
  search?: string;
  priority?: TaskPriority[];
}
const states = new Set([
  "pending",
  "received",
  "started",
  "success",
  "failure",
  "retry",
  "revoked",
  "rejected",
  "unknown",
  "all",
]);
const priorities = ["critical", "high", "normal", "low"] as const;
/** Validate deep links before allowing them to define the task selection scope. */
export function parseTaskListSearch(
  value: Record<string, unknown>,
): TaskListSearch {
  const selected = Array.isArray(value.priority) ? value.priority : [];
  return {
    state:
      typeof value.state === "string" && states.has(value.state)
        ? (value.state as TaskState | "all")
        : undefined,
    search:
      typeof value.search === "string" && value.search
        ? value.search.slice(0, 200)
        : undefined,
    priority: selected.length
      ? priorities.filter((p) => selected.includes(p))
      : undefined,
  };
}
