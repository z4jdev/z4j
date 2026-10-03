import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { components } from "@/lib/openapi-types.gen";

/** One background export job, as the brain reports it. */
export type ExportJobPublic = components["schemas"]["ExportJobPublic"];
export type ExportJobListResponse =
  components["schemas"]["ExportJobListResponse"];
export type ExportJobCreate = components["schemas"]["ExportJobCreate"];
export type ExportJobFormat = ExportJobCreate["format"];

/** Poll faster while any job is still moving, slower once they all settled. */
const ACTIVE_POLL_MS = 3_000;
const IDLE_POLL_MS = 30_000;

export function hasActiveExportJob(data: ExportJobListResponse | undefined) {
  return (
    data?.items.some(
      (job) => job.status === "queued" || job.status === "running",
    ) ?? false
  );
}

/** The slice of query state the poll interval decides on. */
export interface ExportJobsPollState {
  status: "pending" | "error" | "success";
  data: ExportJobListResponse | undefined;
}

/**
 * How long until the next list poll, or ``false`` to stop polling.
 *
 * Once the list errors (403 for an operator who deep-links to the audit
 * page, 404 from a proxy that does not forward the route) there is nothing
 * to watch, so the poll stops rather than repeating the failure every 30 s
 * for the life of the tab. A later successful refetch (a mount, a window
 * focus, an invalidate) resumes it.
 */
export function exportJobsRefetchInterval(
  state: ExportJobsPollState,
): number | false {
  if (state.status === "error") return false;
  return hasActiveExportJob(state.data) ? ACTIVE_POLL_MS : IDLE_POLL_MS;
}

export function useExportJobs(slug: string) {
  return useQuery<ExportJobListResponse>({
    queryKey: ["export-jobs", slug],
    queryFn: () =>
      api.get<ExportJobListResponse>(`/projects/${slug}/audit/export-jobs`, {
        limit: 20,
      }),
    enabled: !!slug,
    refetchInterval: (query) => exportJobsRefetchInterval(query.state),
    // A brain without a sink still answers the list (empty, sink null), and
    // so does the demo build; a 404 means the route is absent, where the
    // panel stays quiet.
    retry: false,
  });
}

export function useCreateExportJob(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ExportJobCreate) =>
      api.post<ExportJobPublic>(`/projects/${slug}/audit/export-jobs`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["export-jobs", slug] });
      qc.invalidateQueries({ queryKey: ["audit", slug] });
    },
  });
}

/** Where the dashboard fetches a finished local-sink job's file from. */
export function buildExportJobDownloadUrl(slug: string, jobId: string): string {
  return `/api/v1/projects/${encodeURIComponent(slug)}/audit/export-jobs/${encodeURIComponent(jobId)}/download`;
}

/** Human-readable byte count for the Exports panel. */
export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}
