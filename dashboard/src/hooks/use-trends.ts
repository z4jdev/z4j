import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export type TrendWindow = "1h" | "6h" | "24h" | "72h" | "7d";
export type TrendBucketSize = "1m" | "5m" | "15m" | "1h" | "1d";

export interface TrendBucket {
  t: string;
  success: number;
  failure: number;
  retry: number;
  revoked: number;
  total: number;
  avg_runtime_ms: number | null;
}

export interface TrendsResponse {
  window: TrendWindow;
  bucket: TrendBucketSize;
  series: TrendBucket[];
}

export function useTrends(
  slug: string | undefined,
  window: TrendWindow,
  bucket: TrendBucketSize,
) {
  return useQuery<TrendsResponse>({
    queryKey: ["trends", slug, window, bucket],
    queryFn: () =>
      api.get<TrendsResponse>(`/projects/${slug}/trends`, { window, bucket }),
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}
