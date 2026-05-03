import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { QueuePublic } from "@/lib/api-types";

export function useQueues(slug: string) {
  return useQuery<QueuePublic[]>({
    queryKey: ["queues", slug],
    queryFn: () => api.get<QueuePublic[]>(`/projects/${slug}/queues`),
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}
