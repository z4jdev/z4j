/**
 * Cross-project activity feed (``/api/v1/activity``).
 *
 * Backed by the brain's v1.6 endpoint. Cursor pagination is keyed
 * on ``(occurred_at, id)`` because the audit-log row id is uuid4
 * (random); the wire form is ``"<iso>|<uuid>"``. (v1.6 audit C8.)
 */
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface ActivityItem {
  id: string;
  project_id: string | null;
  project_slug: string | null;
  user_id: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  result: string;
  outcome: string | null;
  metadata: Record<string, unknown>;
  source_ip: string | null;
  occurred_at: string;
}

export interface ActivityListResponse {
  items: ActivityItem[];
  next_before_cursor: string | null;
  newest_cursor: string | null;
}

export interface ActivityFilters {
  project_slug?: string;
  action_prefix?: string;
  limit?: number;
}

const POLL_INTERVAL_MS = 5_000;

/**
 * Paginated activity feed with live polling.
 *
 * v1.6 audit H12: the dashboard now uses an infinite-query whose
 * first page is keyed only on the filter set (not on a cursor) so
 * polling refetches the head of the timeline. Backward pagination
 * walks ``next_before_cursor``.
 */
export function useActivityInfinite(filters: ActivityFilters = {}) {
  return useInfiniteQuery<ActivityListResponse>({
    queryKey: ["activity-infinite", filters],
    queryFn: ({ pageParam }) =>
      api.get<ActivityListResponse>("/activity", {
        project_slug: filters.project_slug || undefined,
        action_prefix: filters.action_prefix || undefined,
        limit: filters.limit ?? 50,
        before_cursor: pageParam as string | undefined,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_before_cursor ?? undefined,
    refetchInterval: POLL_INTERVAL_MS,
    placeholderData: keepPreviousData,
  });
}

/**
 * Compatibility export for callers that depended on the old
 * single-page hook. Delegates to :func:`useActivityInfinite`;
 * the page itself imports the infinite variant directly.
 */
export function useActivity(filters: ActivityFilters = {}) {
  return useActivityInfinite(filters);
}
