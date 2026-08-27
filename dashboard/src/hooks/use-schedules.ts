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

/** One detected misfire of a schedule. Mirrors ``ScheduleMisfirePublic``
 *  in api/schedules.py: the brain's misfire detector writes an audit row
 *  each time an enabled schedule's expected fire is late past its grace
 *  window (a dead or partitioned scheduler is the usual cause). */
export interface ScheduleMisfirePublic {
  schedule_id: string;
  detected_at: string;
  expected_fire_at: string | null;
  lateness_seconds: number | null;
  grace_seconds: number | null;
  name: string | null;
  engine: string | null;
  kind: string | null;
}

/** Rolling window for the "recent misfires" banner (M16). */
export const RECENT_MISFIRE_WINDOW_HOURS = 24;
const RECENT_MISFIRE_WINDOW_MS = RECENT_MISFIRE_WINDOW_HOURS * 60 * 60 * 1000;

/** Project-wide misfires (GET /projects/{slug}/schedules/misfires, VIEWER):
 *  every detected misfire across the project's schedules, newest first.
 *  Brain-side because a scheduler that died cannot report its own death. */
export function useProjectMisfires(slug: string) {
  return useQuery<ScheduleMisfirePublic[]>({
    queryKey: ["project-misfires", slug],
    queryFn: () =>
      api.get<ScheduleMisfirePublic[]>(
        `/projects/${slug}/schedules/misfires?limit=50`,
      ),
    // M16: the endpoint has no time window, so once ANY misfire was recorded
    // the destructive-styled banner stayed forever -- until audit retention
    // pruned the rows (typically months) -- even after the scheduler
    // recovered, training operators to ignore the signal. Bound client-side
    // to the last RECENT_MISFIRE_WINDOW_HOURS using detected_at (already in
    // the payload) so the banner clears on its own once misfires stop.
    select: (rows) => {
      const cutoff = Date.now() - RECENT_MISFIRE_WINDOW_MS;
      return rows.filter((m) => {
        const t = Date.parse(m.detected_at);
        return Number.isFinite(t) && t >= cutoff;
      });
    },
    enabled: !!slug,
    refetchInterval: 30_000,
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

// Hold and release. Deliberately separate from useToggleSchedule:
// ``is_enabled`` means retired versus active, while ``paused_at`` means an
// operator put a live schedule on hold. The brain enforces the hold in six
// places and projects it onto the scheduler wire, so a schedule can be enabled
// and held at the same time and the two controls are not interchangeable.
export function usePauseSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) =>
      api.post<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/pause`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

export function useResumeSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) =>
      api.post<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/resume`,
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
  kind: "cron" | "interval" | "clocked" | "solar";
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
  kind?: "cron" | "interval" | "clocked" | "solar";
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
