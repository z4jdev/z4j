import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { WorkerPublic } from "@/lib/api-types";

export interface WorkerDetail extends WorkerPublic {
  metadata: {
    stats?: Record<string, unknown>;
    active?: unknown[];
    active_queues?: unknown[];
    registered?: string[];
    conf?: Record<string, unknown>;
  };
}

export function useWorkers(slug: string) {
  return useQuery<WorkerPublic[]>({
    queryKey: ["workers", slug],
    queryFn: () => api.get<WorkerPublic[]>(`/projects/${slug}/workers`),
    enabled: !!slug,
    refetchInterval: 15_000,
  });
}

export function useWorkerDetail(slug: string, workerId: string) {
  return useQuery<WorkerDetail>({
    queryKey: ["workers", slug, workerId],
    queryFn: () =>
      api.get<WorkerDetail>(`/projects/${slug}/workers/${workerId}`),
    enabled: !!slug && !!workerId,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}
