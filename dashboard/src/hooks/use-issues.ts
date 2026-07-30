import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/**
 * One failure fingerprint on a project: the same logical bug grouped
 * across runs and engines. Mirrors the brain's ``IssuePublic`` response
 * model in ``api/issues.py`` (VIEWER role; operational data about tasks
 * the member can already read).
 */
export interface IssuePublic {
  fingerprint: string;
  status: "ongoing" | "recovered";
  occurrences: number;
  open_count: number;
  recovered_count: number;
  first_seen: string | null;
  last_seen: string | null;
  engine_count: number;
  engines: string[];
  sample_exception: string | null;
  sample_task_name: string | null;
}

export interface IssueFilters {
  /** ongoing (still has open failures) or recovered (all copies later succeeded). */
  status?: "ongoing" | "recovered";
  /** Restrict to one engine adapter. */
  engine?: string;
  /** Only issues seen within the last N hours. */
  hours?: number;
}

/**
 * GET /projects/{slug}/issues -- cursor-paginated, flattened to a single
 * array (mirrors ``useSchedules``). The list is small in practice (one
 * row per distinct fingerprint), so a 200-row page walks the whole set in
 * one or two requests; the cursor loop keeps a pathological project with
 * hundreds of distinct bugs correct.
 */
export function useIssues(slug: string, filters: IssueFilters = {}) {
  return useQuery<IssuePublic[]>({
    queryKey: ["issues", slug, filters],
    queryFn: async () => {
      const items: IssuePublic[] = [];
      let cursor: string | null = null;
      do {
        const params = new URLSearchParams();
        params.set("limit", "200");
        if (filters.status) params.set("status", filters.status);
        if (filters.engine) params.set("engine", filters.engine);
        if (filters.hours) params.set("hours", String(filters.hours));
        if (cursor) params.set("cursor", cursor);
        const page = await api.get<{
          items: IssuePublic[];
          next_cursor: string | null;
        }>(`/projects/${slug}/issues?${params.toString()}`);
        items.push(...page.items);
        cursor = page.next_cursor;
      } while (cursor);
      return items;
    },
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}
