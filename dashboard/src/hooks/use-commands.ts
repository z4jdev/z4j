import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  CancelTaskRequest,
  CommandListResponse,
  CommandPublic,
  CommandStatus,
  RetryTaskRequest,
} from "@/lib/api-types";

export interface CommandFilters {
  status?: CommandStatus | "";
  cursor?: string | null;
  limit?: number;
}

export function useCommands(slug: string, filters: CommandFilters = {}) {
  return useQuery<CommandListResponse>({
    queryKey: ["commands", slug, filters],
    queryFn: () =>
      api.get<CommandListResponse>(`/projects/${slug}/commands`, {
        status: filters.status || undefined,
        cursor: filters.cursor ?? undefined,
        limit: filters.limit ?? 50,
      }),
    enabled: !!slug,
    // Live updates arrive via /ws/dashboard command.changed.
    placeholderData: keepPreviousData,
    staleTime: 10_000,
  });
}

export function useRetryTask(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RetryTaskRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/retry-task`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      qc.invalidateQueries({ queryKey: ["tasks", slug] });
    },
  });
}

export function useCancelTask(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CancelTaskRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/cancel-task`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      qc.invalidateQueries({ queryKey: ["tasks", slug] });
    },
  });
}

// ---------------------------------------------------------------------------
// Worker control commands
// ---------------------------------------------------------------------------

export interface PoolResizeRequest {
  agent_id: string;
  worker_name: string;
  delta: number;
}

export interface AddConsumerRequest {
  agent_id: string;
  worker_name: string;
  queue: string;
}

export interface CancelConsumerRequest {
  agent_id: string;
  worker_name: string;
  queue: string;
}

export interface RestartWorkerRequest {
  agent_id: string;
  worker_name: string;
}

export interface RateLimitRequest {
  agent_id: string;
  task_name: string;
  /** Celery rate format: "0" to clear, or "<n>", "<n>/s", "<n>/m", "<n>/h". */
  rate: string;
  /** Optional. Omit to broadcast to every worker. */
  worker_name?: string | null;
  idempotency_key?: string | null;
}

export function usePoolResize(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PoolResizeRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/pool-resize`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      // Delayed refetch - pool resize takes time to propagate.
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["workers", slug] });
      }, 5000);
    },
  });
}

export function useAddConsumer(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddConsumerRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/add-consumer`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["workers", slug] });
      }, 5000);
    },
  });
}

export function useCancelConsumer(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CancelConsumerRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/cancel-consumer`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["workers", slug] });
      }, 5000);
    },
  });
}

export function useRestartWorker(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RestartWorkerRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/restart-worker`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["workers", slug] });
      }, 5000);
    },
  });
}

export function useRateLimit(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RateLimitRequest) =>
      api.post<CommandPublic>(
        `/projects/${slug}/commands/rate-limit`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["commands", slug] });
      // Rate-limit changes are immediate broker-side but we
      // refresh tasks as the throttle starts to bite.
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["tasks", slug] });
      }, 2000);
    },
  });
}
