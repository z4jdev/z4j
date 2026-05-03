import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  ScheduleDiffRequest,
  ScheduleDiffResponse,
  ScheduleFirePublic,
  SchedulePublic,
} from "@/lib/api-types";

export function useSchedules(slug: string) {
  // v1.1.0: GET /projects/{slug}/schedules now returns
  // ``{items, next_cursor}``. The hook flattens to the legacy
  // array shape so existing call sites keep working; the loop
  // walks the cursor transparently for projects with >500 rows.
  return useQuery<SchedulePublic[]>({
    queryKey: ["schedules", slug],
    queryFn: async () => {
      const items: SchedulePublic[] = [];
      let cursor: string | null = null;
      do {
        const params = new URLSearchParams();
        params.set("limit", "500");
        if (cursor) params.set("cursor", cursor);
        const page = await api.get<{
          items: SchedulePublic[];
          next_cursor: string | null;
        }>(`/projects/${slug}/schedules?${params.toString()}`);
        items.push(...page.items);
        cursor = page.next_cursor;
      } while (cursor);
      return items;
    },
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}

export function useSchedule(slug: string, scheduleId: string | undefined) {
  return useQuery<SchedulePublic>({
    queryKey: ["schedule", slug, scheduleId],
    queryFn: () =>
      api.get<SchedulePublic>(`/projects/${slug}/schedules/${scheduleId}`),
    enabled: !!slug && !!scheduleId,
    refetchInterval: 30_000,
  });
}

// The fire history endpoint defaults to limit=50 (the dashboard panel's
// promised "Last 50 fires" view per docs/SCHEDULER.md §13.1). z4j
// caps the parameter at 1000 server-side; we keep the request small so
// the panel stays snappy on schedules with thousands of historical fires.
export function useScheduleFires(
  slug: string,
  scheduleId: string | undefined,
  limit: number = 50,
) {
  return useQuery<ScheduleFirePublic[]>({
    queryKey: ["schedule-fires", slug, scheduleId, limit],
    queryFn: () =>
      api.get<ScheduleFirePublic[]>(
        `/projects/${slug}/schedules/${scheduleId}/fires?limit=${limit}`,
      ),
    enabled: !!slug && !!scheduleId,
    // Refetch faster than the schedule list since active operators
    // staring at the panel want to see new fires arrive promptly.
    refetchInterval: 10_000,
  });
}

export function useToggleSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      scheduleId,
      enabled,
    }: {
      scheduleId: string;
      enabled: boolean;
    }) =>
      api.post<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/${enabled ? "enable" : "disable"}`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

export function useTriggerSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) =>
      api.post<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/trigger`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

// Reconciliation diff (POST /projects/{slug}/schedules:diff). Pure
// dry-run preview - z4j endpoint does not mutate state and
// writes no audit row. The dashboard reconciliation panel uses this
// to show the operator what would change before they apply via the
// CLI / declarative reconciler in their app process. Backend
// requires ADMIN to mirror :import's role gate.
export function useScheduleDiff(slug: string) {
  return useMutation<ScheduleDiffResponse, Error, ScheduleDiffRequest>({
    mutationFn: (body) =>
      api.post<ScheduleDiffResponse>(
        `/projects/${slug}/schedules:diff`,
        body,
      ),
  });
}

// Apply the same body :diff previewed (POST /schedules:import).
// Closes the loop on the reconciliation page - operators can run
// a clean diff and then apply it without context-switching to the
// CLI. Returns the per-bucket counts brain emitted (insert /
// update / unchanged / deleted / failed + per-row error map).
export interface ScheduleImportResponse {
  inserted: number;
  updated: number;
  unchanged: number;
  failed: number;
  deleted: number;
  errors: Record<number, string>;
}

export function useScheduleImport(slug: string) {
  const qc = useQueryClient();
  return useMutation<ScheduleImportResponse, Error, ScheduleDiffRequest>({
    mutationFn: (body) =>
      api.post<ScheduleImportResponse>(
        `/projects/${slug}/schedules:import`,
        body,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

// Sync now (POST /projects/{slug}/schedules:resync). Forces every
// online agent in the project to re-emit a full schedule inventory
// snapshot. Each agent drains EVERY scheduler adapter it has
// registered (celery-beat, apscheduler, rq-scheduler, arqcron,
// hueyperiodic, taskiqscheduler) and emits one schedule.snapshot
// event per adapter. z4j's event ingestor 3-way diffs each
// snapshot against the DB scoped to (project, scheduler) - inserts
// new rows, updates existing rows, deletes rows missing from the
// snapshot. Added in 1.3.3 to close the long-standing onboarding
// gap where existing celery-beat schedules were invisible until
// the operator edited each one.
export interface ScheduleResyncResponse {
  agents_dispatched: number;
  schedulers_observed: string[];
}

export function useScheduleResync(slug: string) {
  const qc = useQueryClient();
  return useMutation<ScheduleResyncResponse, Error, void>({
    mutationFn: () =>
      api.post<ScheduleResyncResponse>(
        `/projects/${slug}/schedules:resync`,
        {},
      ),
    onSuccess: () => {
      // Snapshot events arrive asynchronously through the WS event
      // pipeline. Refetch immediately AND again after a short delay
      // so the dashboard reflects the reconciliation without the
      // operator hitting Refresh.
      qc.invalidateQueries({ queryKey: ["schedules", slug] });
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["schedules", slug] });
      }, 3000);
    },
  });
}

// CRUD mutations - the dashboard's "manage schedules from a real
// UI" promise (docs/SCHEDULER.md §3.2 wish #3). Each one invalidates
// the schedule list + any open detail page so the dashboard reflects
// the new state without a manual refresh.
//
// Body shapes mirror brain's ScheduleCreateIn / ScheduleUpdateIn so
// the dashboard form can pass through whatever the operator filled in
// without a translation layer. Empty optional fields are dropped at
// the form level (not here) so z4j sees a clean PATCH.

export interface ScheduleCreateBody {
  name: string;
  engine: string;
  kind: "cron" | "interval" | "one_shot" | "solar";
  expression: string;
  task_name: string;
  timezone?: string;
  queue?: string | null;
  args?: unknown[];
  kwargs?: Record<string, unknown>;
  catch_up?: "skip" | "fire_one_missed" | "fire_all_missed";
  is_enabled?: boolean;
  scheduler?: string;
  source?: string;
}

export interface ScheduleUpdateBody {
  engine?: string;
  kind?: "cron" | "interval" | "one_shot" | "solar";
  expression?: string;
  task_name?: string;
  timezone?: string;
  queue?: string | null;
  args?: unknown[];
  kwargs?: Record<string, unknown>;
  catch_up?: "skip" | "fire_one_missed" | "fire_all_missed";
  is_enabled?: boolean;
}

export function useCreateSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation<SchedulePublic, Error, ScheduleCreateBody>({
    mutationFn: (body) =>
      api.post<SchedulePublic>(`/projects/${slug}/schedules`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

export function useUpdateSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation<
    SchedulePublic,
    Error,
    { scheduleId: string; body: ScheduleUpdateBody }
  >({
    mutationFn: ({ scheduleId, body }) =>
      api.patch<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}`,
        body,
      ),
    onSuccess: (_, { scheduleId }) => {
      qc.invalidateQueries({ queryKey: ["schedules", slug] });
      qc.invalidateQueries({ queryKey: ["schedule", slug, scheduleId] });
    },
  });
}

export function useDeleteSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (scheduleId) =>
      api.delete<void>(`/projects/${slug}/schedules/${scheduleId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}
