import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { StatsResponse } from "@/lib/api-types";

export type TimeRange = "1" | "6" | "24" | "72" | "168";

export const TIME_RANGE_LABELS: Record<TimeRange, string> = {
  "1": "Last hour",
  "6": "Last 6 hours",
  "24": "Last 24 hours",
  "72": "Last 3 days",
  "168": "Last 7 days",
};

export function useStats(slug: string, hours: TimeRange = "24") {
  return useQuery<StatsResponse>({
    queryKey: ["stats", slug, hours],
    queryFn: () =>
      api.get<StatsResponse>(`/projects/${slug}/stats`, { hours }),
    enabled: !!slug,
    // Live updates arrive via /ws/dashboard task.changed + agent.changed.
    staleTime: 30_000,
  });
}
