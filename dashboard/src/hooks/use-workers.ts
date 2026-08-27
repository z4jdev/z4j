import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ProjectLintPublic, WorkerPublic } from "@/lib/api-types";

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

// Configuration lint (GET /projects/{slug}/workers/lint). Advisory and
// read-only: it evaluates the configuration workers already report on their
// heartbeat, so it costs one query and collects nothing new.
export function useWorkerLint(slug: string) {
  return useQuery({
    queryKey: ["workers", slug, "lint"],
    queryFn: () => api.get<ProjectLintPublic>(`/projects/${slug}/workers/lint`),
    staleTime: 60_000,
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
