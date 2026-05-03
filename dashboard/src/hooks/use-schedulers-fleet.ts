import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { FleetResponse } from "@/lib/api-types";

/**
 * Poll the brain-side fleet endpoint that fans out to every
 * configured scheduler ``/info``. Refresh cadence matches the
 * scheduler's own /info polling story (operators staring at the
 * page want fresh data without the network cost being absurd).
 */
export function useSchedulersFleet() {
  return useQuery<FleetResponse>({
    queryKey: ["schedulers-fleet"],
    queryFn: () => api.get<FleetResponse>("/schedulers"),
    refetchInterval: 10_000,
  });
}
