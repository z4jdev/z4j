import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { EventListResponse } from "@/lib/api-types";

export function useEventsForTask(
  slug: string,
  engine: string,
  taskId: string,
) {
  return useQuery<EventListResponse>({
    queryKey: ["events", slug, engine, taskId],
    queryFn: () =>
      api.get<EventListResponse>(`/projects/${slug}/events`, {
        engine,
        task_id: taskId,
        limit: 100,
      }),
    enabled: !!slug && !!engine && !!taskId,
    // Live updates: /ws/dashboard task.changed invalidates ["events", slug].
    staleTime: 10_000,
  });
}
