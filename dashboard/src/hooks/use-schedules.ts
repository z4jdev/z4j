import { useMemo } from "react";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  ScheduleDiffRequest,
  ScheduleDiffResponse,
  ScheduleFirePublic,
  SchedulePublic,
  ProjectPublic,
} from "@/lib/api-types";

interface SchedulesEnvelope {
  items: SchedulePublic[];
  /** Project-wide breaker setting, identical on every page of the list. */
  circuit_breaker_threshold: number;
}

/**
 * One query for the schedule list and the breaker threshold together. The
 * envelope carries both, so reading the threshold with a second request was
 * a wasted round-trip and a five-minute window in which the badge's "N of T"
 * could disagree with the list beside it. Both hooks below share this cache
 * entry and pick their slice with `select`.
 */
function schedulesQuery(slug: string) {
  return {
    queryKey: ["schedules", slug] as const,
    queryFn: async (): Promise<SchedulesEnvelope> => {
      // GET /projects/{slug}/schedules returns ``{items, next_cursor}``; the
      // loop walks the cursor transparently for projects with >500 rows.
      const items: SchedulePublic[] = [];
      let threshold = 0;
      let cursor: string | null = null;
      do {
        const params = new URLSearchParams();
        params.set("limit", "500");
        if (cursor) params.set("cursor", cursor);
        const page = await api.get<{
          items: SchedulePublic[];
          next_cursor: string | null;
          circuit_breaker_threshold?: number;
        }>(`/projects/${slug}/schedules?${params.toString()}`);
        items.push(...page.items);
        threshold = page.circuit_breaker_threshold ?? threshold;
        cursor = page.next_cursor;
      } while (cursor);
      return { items, circuit_breaker_threshold: threshold };
    },
    enabled: !!slug,
    refetchInterval: 30_000,
  };
}

export function useSchedules(slug: string) {
  return useQuery({
    ...schedulesQuery(slug),
    select: (envelope: SchedulesEnvelope) => envelope.items,
  });
}

/** Only the currently authorized native producer can advertise controls. */
export function useNativeScheduleCapabilities(slug: string) {
  return useQuery({
    queryKey: ["native-schedule-capabilities", slug],
    queryFn: () =>
      api.get<Record<string, string[]>>(
        `/projects/${slug}/schedules/native-capabilities`,
      ),
    enabled: !!slug,
    refetchInterval: 15_000,
  });
}

/** Why the enable switch is locked when {@link canManageNativeSchedule} refuses "toggle". */
export const NATIVE_TOGGLE_UNAVAILABLE =
  "This schedule cannot be enabled or disabled here: its definition is static, or no connected scheduler offers enable and disable for it.";

export function canManageNativeSchedule(
  row: Pick<SchedulePublic, "scheduler" | "source">,
  operation: "create" | "update" | "delete" | "toggle" | "trigger_now",
  capabilities: Record<string, string[]> | undefined,
): boolean {
  if (row.scheduler === "z4j-scheduler") return true;
  const caps = capabilities?.[row.scheduler] ?? [];
  if (operation === "trigger_now") return caps.includes("trigger_now");
  if (row.source === "celery-beat:static") return false;
  return (
    caps.includes("external_schedule_mutation_v1") &&
    (operation === "toggle"
      ? caps.includes("enable") && caps.includes("disable")
      : caps.includes(operation))
  );
}

/**
 * The consecutive-failure count at which the brain auto-disables a schedule.
 * 0 means the operator switched the breaker off. Read from the same list
 * query the table renders from, so the two never disagree.
 */
export function useCircuitBreakerThreshold(slug: string) {
  return useQuery({
    ...schedulesQuery(slug),
    select: (envelope: SchedulesEnvelope) => envelope.circuit_breaker_threshold,
  });
}

/** One cell of the cross-run grid. Mirrors ``ScheduleRunCell``. */
export interface ScheduleRunCell {
  fire_id: string;
  status: string;
  scheduled_for: string;
  fired_at: string;
  latency_ms: number | null;
}

export interface ScheduleRunsRow {
  schedule_id: string;
  /** Newest first, at most ``limit``. Fewer means fewer fires in the window. */
  runs: ScheduleRunCell[];
}

export interface ScheduleRunsPublic {
  items: ScheduleRunsRow[];
  limit: number;
  circuit_breaker_threshold: number;
}

/** The brain refuses more than 500 ids per request; well under that keeps
 *  the query string short enough for the common proxy header limits too. */
export const SCHEDULE_RUNS_CHUNK = 100;

async function fetchScheduleRuns(
  slug: string,
  ids: readonly string[],
  limit: number,
): Promise<Map<string, ScheduleRunCell[]>> {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  for (const id of ids) params.append("id", id);
  const page = await api.get<ScheduleRunsPublic>(
    `/projects/${slug}/schedules/runs?${params.toString()}`,
  );
  return new Map(page.items.map((row) => [row.schedule_id, row.runs]));
}

/**
 * Last-N runs for every schedule on the page.
 *
 * The ids are chunked so a project with more schedules than the endpoint
 * accepts per request still gets its strips, and each chunk is keyed by its
 * sorted ids so a re-render with the same rows in a different order hits
 * the cache. The map form is what the grid wants: a row looks itself up by
 * id. `data` fills in chunk by chunk and `isError` reports any chunk that
 * failed, so a caller can say "unavailable" instead of "no fires".
 */
export function useScheduleRuns(
  slug: string,
  scheduleIds: readonly string[],
  limit = 20,
) {
  const ids = [...scheduleIds].sort();
  const chunks: string[][] = [];
  for (let i = 0; i < ids.length; i += SCHEDULE_RUNS_CHUNK) {
    chunks.push(ids.slice(i, i + SCHEDULE_RUNS_CHUNK));
  }
  const results = useQueries({
    queries: chunks.map((chunk) => ({
      queryKey: ["schedule-runs", slug, limit, chunk] as const,
      queryFn: () => fetchScheduleRuns(slug, chunk, limit),
      enabled: !!slug && chunk.length > 0,
      // Same cadence as the fire-history panel: an operator watching a
      // failing schedule wants the newest cell to appear promptly.
      refetchInterval: 10_000,
    })),
  });
  const data = useMemo(() => {
    let merged: Map<string, ScheduleRunCell[]> | undefined;
    for (const r of results) {
      if (!r.data) continue;
      merged ??= new Map();
      for (const [k, v] of r.data) merged.set(k, v);
    }
    return merged;
  }, [results]);
  return {
    data,
    isError: results.some((r) => r.isError),
    isPending: results.some((r) => r.isPending),
  };
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
/** Newest misfires the banner reads. A full page means there may be more. */
export const PROJECT_MISFIRE_LIMIT = 50;
const RECENT_MISFIRE_WINDOW_MS = RECENT_MISFIRE_WINDOW_HOURS * 60 * 60 * 1000;

/** Project-wide misfires (GET /projects/{slug}/schedules/misfires, VIEWER):
 *  every detected misfire across the project's schedules, newest first.
 *  Brain-side because a scheduler that died cannot report its own death. */
export function useProjectMisfires(slug: string) {
  return useQuery<ScheduleMisfirePublic[]>({
    queryKey: ["project-misfires", slug],
    queryFn: () =>
      api.get<ScheduleMisfirePublic[]>(
        `/projects/${slug}/schedules/misfires?limit=${PROJECT_MISFIRE_LIMIT}`,
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
    mutationFn: async ({
      scheduleId,
      enabled,
    }: {
      scheduleId: string;
      enabled: boolean;
    }) => {
      const row = await api.get<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}`,
      );
      if (row.scheduler !== "z4j-scheduler") {
        await nativeScheduleMutation(
          slug,
          "update",
          row.scheduler,
          { is_enabled: enabled },
          row,
        );
        return api.get<SchedulePublic>(
          `/projects/${slug}/schedules/${scheduleId}`,
        );
      }
      const { data, location } = await api.postResource<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/${enabled ? "enable" : "disable"}`,
      );
      if (!location) return data;
      await waitForScheduleControl(location);
      return api.get<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}`,
      );
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

/** An accepted request is still pending until the native source confirms it. */
export async function waitForScheduleControl(location: string): Promise<void> {
  if (
    !location.startsWith("/api/v1/projects/") ||
    !location.includes("/schedules/external-control-operations/")
  ) {
    throw new Error("Schedule operation returned an invalid status address");
  }
  const path = location.slice("/api/v1".length);
  for (let attempt = 0; attempt < 30; attempt++) {
    const operation = await api.get<{ id: string; status: string }>(path);
    if (operation.status === "APPLIED") return;
    if (!["PENDING", "CLAIMED"].includes(operation.status)) {
      throw new Error(
        `Schedule change is ${operation.status.toLowerCase()}. Refresh and check the native schedule before retrying. Operation: ${operation.id}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(
    "Schedule change is still awaiting source confirmation. Refresh its status before issuing another change.",
  );
}

export function useTriggerSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (scheduleId: string) => {
      const { data, location } = await api.postResource<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}/trigger`,
      );
      if (location) await waitForNativeScheduleOperation(location);
      return data;
    },
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
      api.post<ScheduleDiffResponse>(`/projects/${slug}/schedules:diff`, body),
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
// UI" promise (docs/SCHEDULER.md §3.2 wish #3). All invalidate the
// schedule list; update also invalidates the edited detail query.
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
    mutationFn: async (body) => {
      const scheduler =
        body.scheduler ??
        (await api.get<ProjectPublic>(`/projects/${slug}`))
          .default_scheduler_owner;
      if (scheduler !== "z4j-scheduler") {
        const operation = await nativeScheduleMutation(
          slug,
          "create",
          scheduler,
          body,
        );
        if (!operation.schedule_id)
          throw new Error(
            "Native creation was confirmed but the schedule is no longer present. Refresh the list.",
          );
        return api.get<SchedulePublic>(
          `/projects/${slug}/schedules/${operation.schedule_id}`,
        );
      }
      return api.post<SchedulePublic>(`/projects/${slug}/schedules`, body);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

export function useUpdateSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation<
    SchedulePublic,
    Error,
    {
      scheduleId: string;
      body: ScheduleUpdateBody;
      observedSchedule?: SchedulePublic;
    }
  >({
    mutationFn: async ({ scheduleId, body, observedSchedule }) => {
      const row =
        observedSchedule ??
        (await api.get<SchedulePublic>(
          `/projects/${slug}/schedules/${scheduleId}`,
        ));
      if (row.scheduler !== "z4j-scheduler") {
        await nativeScheduleMutation(slug, "update", row.scheduler, body, row);
        return api.get<SchedulePublic>(
          `/projects/${slug}/schedules/${scheduleId}`,
        );
      }
      return api.patch<SchedulePublic>(
        `/projects/${slug}/schedules/${scheduleId}`,
        body,
      );
    },
    onSuccess: (_, { scheduleId }) => {
      qc.invalidateQueries({ queryKey: ["schedules", slug] });
      qc.invalidateQueries({ queryKey: ["schedule", slug, scheduleId] });
    },
  });
}

export function useDeleteSchedule(slug: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string | SchedulePublic>({
    mutationFn: async (selected) => {
      const scheduleId = typeof selected === "string" ? selected : selected.id;
      const row =
        typeof selected === "string"
          ? await api.get<SchedulePublic>(
              `/projects/${slug}/schedules/${scheduleId}`,
            )
          : selected;
      if (row.scheduler !== "z4j-scheduler") {
        await nativeScheduleMutation(slug, "delete", row.scheduler, {}, row);
        return;
      }
      return api.delete<void>(`/projects/${slug}/schedules/${scheduleId}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules", slug] }),
  });
}

interface NativeScheduleOperation {
  id: string;
  status: string;
  schedule_id: string | null;
  error: string | null;
}

async function waitForNativeScheduleOperation(
  location: string,
): Promise<NativeScheduleOperation> {
  if (
    !location.startsWith("/api/v1/projects/") ||
    !location.includes("/schedules/native-operations/")
  ) {
    throw new Error("Schedule operation returned an invalid status address");
  }
  const path = location.slice("/api/v1".length);
  for (let attempt = 0; attempt < 30; attempt++) {
    const state = await api.get<NativeScheduleOperation>(path);
    if (state.status === "APPLIED") return state;
    if (state.status !== "PENDING")
      throw new Error(
        state.error ??
          `Native change is unconfirmed. Refresh and inspect the source before retrying. Operation: ${state.id}`,
      );
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(
    "Native change is awaiting source confirmation. Refresh its status before issuing another change.",
  );
}

async function nativeScheduleMutation(
  slug: string,
  operation: "create" | "update" | "delete",
  scheduler: string,
  body: ScheduleCreateBody | ScheduleUpdateBody,
  row?: SchedulePublic,
): Promise<NativeScheduleOperation> {
  if (row?.source === "celery-beat:static")
    throw new Error(
      "Static Beat schedules are read-only. Edit your application configuration.",
    );
  if (body.catch_up && body.catch_up !== "skip")
    throw new Error("Catch-up policies require a z4j-owned schedule.");
  if (scheduler === "celery-beat" && body.engine && body.engine !== "celery")
    throw new Error("Celery Beat schedules must use the Celery engine.");
  const fields = new Set([
    "name",
    "task_name",
    "kind",
    "expression",
    "timezone",
    "queue",
    "args",
    "kwargs",
    "is_enabled",
  ]);
  const definition = Object.fromEntries(
    Object.entries(body).filter(([key]) => fields.has(key)),
  );
  const state = await api.post<NativeScheduleOperation>(
    `/projects/${slug}/schedules/native-operations`,
    {
      request_id: crypto.randomUUID(),
      scheduler,
      operation,
      schedule_id: row?.id ?? null,
      observed_control_token: row?.control_token ?? null,
      definition,
    },
  );
  return waitForNativeScheduleOperation(
    `/api/v1/projects/${slug}/schedules/native-operations/${state.id}`,
  );
}
