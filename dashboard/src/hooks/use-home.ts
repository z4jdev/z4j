/**
 * Hooks for the cross-project Home dashboard.
 *
 * Two endpoints, both mounted under /api/v1/home:
 *
 *   GET /home/summary          - per-user cross-project overview
 *   GET /home/recent-failures  - global paginated failure feed
 *
 * Both run at a modest refetch cadence (30s) so the Home page feels
 * live without hammering z4j when nothing is happening.
 */
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type HomeProjectHealth = "healthy" | "degraded" | "offline" | "idle";

export interface HomeProjectCard {
  id: string;
  slug: string;
  name: string;
  environment: string;
  role: string | null;
  tasks_24h: number;
  failures_24h: number;
  failure_rate_24h: number;
  workers_online: number;
  workers_total: number;
  agents_online: number;
  agents_total: number;
  stuck_commands: number;
  last_activity_at: string | null;
  health: HomeProjectHealth;
}

export type HomeAttentionKind =
  | "agent_offline"
  | "high_failure_rate"
  | "stuck_commands"
  | "workers_missing";

export interface HomeAttentionItem {
  kind: HomeAttentionKind;
  severity: "warning" | "critical";
  project_id: string;
  project_slug: string;
  project_name: string;
  message: string;
  count: number | null;
}

export interface HomeAggregate {
  tasks_24h: number;
  failures_24h: number;
  failure_rate_24h: number;
  workers_online: number;
  workers_total: number;
  agents_online: number;
  agents_total: number;
  stuck_commands: number;
}

export interface HomeSummary {
  user: {
    id: string;
    email: string;
    display_name: string | null;
    is_admin: boolean;
  };
  aggregate: HomeAggregate;
  projects: HomeProjectCard[];
  attention: HomeAttentionItem[];
}

export interface HomeRecentFailure {
  id: string;
  occurred_at: string;
  project_id: string;
  project_slug: string;
  project_name: string;
  /** Engine that produced this failure (celery | rq | dramatiq | ...).
   *  Required for the /tasks/{engine}/{task_id} deep-link - the
   *  backend stamps it from Event.engine. */
  engine: string;
  task_id: string;
  task_name: string | null;
  worker: string | null;
  exception: string | null;
  priority: string;
}

export interface HomeRecentFailures {
  items: HomeRecentFailure[];
  next_cursor: string | null;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useHomeSummary() {
  return useQuery<HomeSummary>({
    queryKey: ["home", "summary"],
    queryFn: () => api.get<HomeSummary>("/home/summary"),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });
}

export interface RecentFailuresParams {
  limit?: number;
  cursor?: string | null;
}

export function useHomeRecentFailures(params: RecentFailuresParams = {}) {
  const { limit = 50, cursor = null } = params;
  return useQuery<HomeRecentFailures>({
    queryKey: ["home", "recent-failures", limit, cursor],
    queryFn: () =>
      api.get<HomeRecentFailures>("/home/recent-failures", {
        limit,
        cursor: cursor ?? undefined,
      }),
    refetchInterval: 30_000,
    staleTime: 15_000,
    placeholderData: keepPreviousData,
  });
}
