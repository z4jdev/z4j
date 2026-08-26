/**
 * General settings page - brain-wide configuration (admin, read-only).
 *
 * Displays effective retention, limit, and session-policy settings from the
 * running brain.
 * Values are read-only for now - editable in a future phase.
 */
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { ExternalLink, Info, Settings } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { SectionCard } from "@/components/domain/section-card";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/domain/page-header";
import { QueryError } from "@/components/domain/query-error";

export const Route = createFileRoute("/_authenticated/settings/general")({
  component: GeneralSettingsPage,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SystemInfo {
  z4j_version: string;
  python_version: string;
  python_implementation: string;
  os: string;
  architecture: string;
  pid: number;
  database_type: string;
  database_version?: string;
  database_size_mb?: number;
  database_connections?: number;
}

interface SettingItem {
  name: string;
  value: string;
  source: "env" | "config.env" | "secret.env" | ".env" | "default";
  is_secret: boolean;
  description: string;
}

interface AdminSettingsResponse {
  z4j_home: string;
  settings: SettingItem[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function SettingsTable({ rows }: { rows: [string, string][] }) {
  return (
    <Table>
      <TableBody>
        {rows.map(([key, value]) => (
          <TableRow key={key}>
            <TableCell className="w-1/2 py-2.5 font-medium text-muted-foreground">
              {key}
            </TableCell>
            <TableCell className="py-2.5 font-mono text-sm">{value}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GeneralSettingsPage() {
  const systemInfo = useQuery<SystemInfo>({
    queryKey: ["system-info"],
    queryFn: () => api.get<SystemInfo>("/health/system"),
    staleTime: 60_000,
  });
  const runtimeConfig = useQuery<AdminSettingsResponse>({
    queryKey: ["admin-settings"],
    queryFn: () => api.get<AdminSettingsResponse>("/admin/settings"),
    staleTime: 60_000,
  });

  const configured = new Map(
    runtimeConfig.data?.settings.map((setting) => [
      setting.name,
      setting.value,
    ]),
  );
  const numberSetting = (name: string): number | undefined => {
    const value = configured.get(name);
    if (value === undefined || value === "") return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  };
  const effectiveWsFrameBytes = minDefined(
    numberSetting("max_ws_frame_bytes"),
    numberSetting("ws_max_frame_bytes"),
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Settings}
        title="General"
        description="Brain-wide retention, limits, and session policies."
        badges={<Badge variant="muted">read-only</Badge>}
      />

      {runtimeConfig.isLoading && (
        <>
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
        </>
      )}

      {!runtimeConfig.isLoading &&
        (runtimeConfig.isError || !runtimeConfig.data) && (
          <QueryError
            message="Failed to load the current brain configuration"
            onRetry={() => runtimeConfig.refetch()}
          />
        )}

      {!runtimeConfig.isLoading && runtimeConfig.data && (
        <>
          {/* Read-only notice */}
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/50 p-3">
            <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">
              These settings are read-only and reflect the current brain
              configuration. Configure via environment variables or the brain
              config file.
            </p>
          </div>

          {/* Retention */}
          <SectionCard
            title="Retention"
            description="How long z4j keeps event and audit data before automatic cleanup."
            readOnly
          >
            <SettingsTable
              rows={[
                [
                  "Event retention",
                  formatDays(numberSetting("event_retention_days")),
                ],
                [
                  "Audit retention",
                  formatDays(numberSetting("audit_retention_days")),
                ],
              ]}
            />
          </SectionCard>

          {/* Limits */}
          <SectionCard
            title="Limits"
            description="Size constraints enforced by z4j."
            readOnly
          >
            <SettingsTable
              rows={[
                [
                  "Max payload size",
                  formatOptionalBytes(numberSetting("max_payload_size_bytes")),
                ],
                [
                  "Max WebSocket frame size",
                  formatOptionalBytes(effectiveWsFrameBytes),
                ],
              ]}
            />
          </SectionCard>

          {/* Session */}
          <SectionCard
            title="Session"
            description="Authentication and session management policies."
            readOnly
          >
            <SettingsTable
              rows={[
                [
                  "Session lifetime",
                  formatDuration(
                    numberSetting("session_absolute_lifetime_seconds"),
                  ),
                ],
                [
                  "Idle timeout",
                  formatDuration(numberSetting("session_idle_timeout_seconds")),
                ],
                [
                  "Login lockout threshold",
                  formatAttempts(numberSetting("login_lockout_threshold")),
                ],
              ]}
            />
          </SectionCard>

          {/* System info */}
          {systemInfo.data && (
            <SectionCard
              title="System"
              description="Core runtime information for z4j process."
            >
              <SettingsTable
                rows={[
                  ["z4j version", systemInfo.data.z4j_version],
                  [
                    "Python",
                    `${systemInfo.data.python_version} (${systemInfo.data.python_implementation})`,
                  ],
                  ["OS", systemInfo.data.os],
                  ["Architecture", systemInfo.data.architecture],
                  ["Database", systemInfo.data.database_type],
                  ...(systemInfo.data.database_version
                    ? [
                        [
                          "Database version",
                          systemInfo.data.database_version,
                        ] as [string, string],
                      ]
                    : []),
                  ...(systemInfo.data.database_size_mb !== undefined
                    ? [
                        [
                          "Database size",
                          `${systemInfo.data.database_size_mb} MB`,
                        ] as [string, string],
                      ]
                    : []),
                ]}
              />
            </SectionCard>
          )}
          {systemInfo.isError && (
            <QueryError
              message="Failed to load system information"
              onRetry={() => systemInfo.refetch()}
            />
          )}

          {/* About */}
          <SectionCard
            title="About"
            description="License and project resources."
          >
            <SettingsTable rows={[["License", "AGPL-3.0-or-later"]]} />
            <div className="mt-4 flex flex-wrap gap-2">
              <ResourceLink href="https://z4j.com" label="z4j.com" />
              <ResourceLink href="https://z4j.dev" label="Documentation" />
              <ResourceLink href="https://github.com/z4jdev" label="GitHub" />
            </div>
          </SectionCard>
        </>
      )}
    </div>
  );
}

function ResourceLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-muted"
    >
      {label}
      <ExternalLink className="size-3.5 text-muted-foreground" />
    </a>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatOptionalBytes(bytes: number | undefined): string {
  return bytes === undefined ? "Unavailable" : formatBytes(bytes);
}

function formatDays(days: number | undefined): string {
  return days === undefined ? "Unavailable" : `${days} days`;
}

function formatAttempts(attempts: number | undefined): string {
  return attempts === undefined ? "Unavailable" : `${attempts} failed attempts`;
}

function formatDuration(seconds: number | undefined): string {
  if (seconds === undefined) return "Unavailable";
  if (seconds % 3600 === 0) return `${seconds / 3600} hours`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

function minDefined(
  first: number | undefined,
  second: number | undefined,
): number | undefined {
  if (first === undefined) return second;
  if (second === undefined) return first;
  return Math.min(first, second);
}
