import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AuditLogListResponse } from "@/lib/api-types";

export interface AuditFilters {
  action_prefix?: string;
  outcome?: string;
  cursor?: string | null;
  limit?: number;
}

export function useAudit(slug: string, filters: AuditFilters = {}) {
  return useQuery<AuditLogListResponse>({
    queryKey: ["audit", slug, filters],
    queryFn: () =>
      api.get<AuditLogListResponse>(`/projects/${slug}/audit`, {
        action_prefix: filters.action_prefix || undefined,
        outcome: filters.outcome || undefined,
        cursor: filters.cursor ?? undefined,
        limit: filters.limit ?? 50,
      }),
    enabled: !!slug,
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
}

export type AuditExportFormat = "csv" | "xlsx" | "json";

/**
 * Build a download URL for the audit export endpoint.
 *
 * The returned URL honours the current filter (same params the
 * list endpoint accepts, minus ``cursor`` / ``limit``) so the
 * file the operator downloads matches what they see in the UI.
 */
export function buildAuditExportUrl(
  slug: string,
  format: AuditExportFormat,
  filters: Omit<AuditFilters, "cursor" | "limit"> = {},
): string {
  const params = new URLSearchParams();
  params.set("format", format);
  if (filters.action_prefix) params.set("action_prefix", filters.action_prefix);
  if (filters.outcome) params.set("outcome", filters.outcome);
  return `/api/v1/projects/${encodeURIComponent(slug)}/audit?${params.toString()}`;
}
