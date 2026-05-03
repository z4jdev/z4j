import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  TaskListResponse,
  TaskPriority,
  TaskPublic,
  TaskState,
} from "@/lib/api-types";

export interface TaskFilters {
  state?: TaskState | "";
  priority?: TaskPriority[];
  name?: string;
  search?: string;
  queue?: string;
  worker?: string;
  since?: string;
  until?: string;
  cursor?: string | null;
  limit?: number;
}

export function useTasks(slug: string, filters: TaskFilters = {}) {
  return useQuery<TaskListResponse>({
    queryKey: ["tasks", slug, filters],
    queryFn: () =>
      api.get<TaskListResponse>(`/projects/${slug}/tasks`, {
        state: filters.state || undefined,
        priority:
          filters.priority && filters.priority.length > 0
            ? filters.priority.join(",")
            : undefined,
        name: filters.name || undefined,
        search: filters.search || undefined,
        queue: filters.queue || undefined,
        worker: filters.worker || undefined,
        since: filters.since || undefined,
        until: filters.until || undefined,
        cursor: filters.cursor ?? undefined,
        limit: filters.limit ?? 50,
      }),
    enabled: !!slug,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useTask(slug: string, engine: string, taskId: string) {
  return useQuery<TaskPublic>({
    queryKey: ["tasks", slug, engine, taskId],
    queryFn: () =>
      api.get<TaskPublic>(`/projects/${slug}/tasks/${engine}/${taskId}`),
    enabled: !!slug && !!engine && !!taskId,
    staleTime: 10_000,
  });
}

/** Canvas (chain / group / chord) tree rooted at the requested task. */
export interface TaskTreeNode {
  task_id: string;
  name: string;
  state: string;
  parent_task_id: string | null;
  root_task_id: string | null;
  received_at: string | null;
  finished_at: string | null;
}
export interface TaskTreeResponse {
  root_task_id: string;
  node_count: number;
  truncated: boolean;
  nodes: TaskTreeNode[];
}

export function useTaskTree(slug: string, engine: string, taskId: string) {
  return useQuery<TaskTreeResponse>({
    queryKey: ["task-tree", slug, engine, taskId],
    queryFn: () =>
      api.get<TaskTreeResponse>(
        `/projects/${slug}/tasks/${engine}/${taskId}/tree`,
      ),
    enabled: !!slug && !!engine && !!taskId,
    staleTime: 30_000,
    // Standalone tasks return a single-node tree - fine to render
    // it (degenerate case shows the same task as the root) but
    // the page can short-circuit if it wants.
  });
}

export type ExportFormat = "csv" | "xlsx" | "json";
export type ExportFieldSet = "metadata" | "full" | "custom";

export function buildExportUrl(
  slug: string,
  format: ExportFormat,
  filters: Omit<TaskFilters, "cursor" | "limit"> = {},
  fieldSet: ExportFieldSet = "metadata",
  customFields?: string[],
): string {
  const params = new URLSearchParams();
  params.set("format", format);
  if (filters.state) params.set("state", filters.state);
  if (filters.priority && filters.priority.length > 0)
    params.set("priority", filters.priority.join(","));
  if (filters.name) params.set("name", filters.name);
  if (filters.search) params.set("search", filters.search);
  if (filters.queue) params.set("queue", filters.queue);
  if (filters.worker) params.set("worker", filters.worker);
  if (filters.since) params.set("since", filters.since);
  if (filters.until) params.set("until", filters.until);
  if (fieldSet === "full") {
    params.set(
      "fields",
      "task_id,name,state,priority,queue,worker,received_at,started_at,finished_at,runtime_ms,retry_count,exception,traceback,args,kwargs,result,tags",
    );
  } else if (fieldSet === "custom" && customFields) {
    params.set("fields", customFields.join(","));
  }
  // "metadata" = server default (no fields param)
  return `/api/v1/projects/${encodeURIComponent(slug)}/tasks?${params.toString()}`;
}
