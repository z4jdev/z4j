/**
 * General settings page - brain-wide configuration (admin, read-only).
 *
 * Displays system defaults for retention, limits, and session policies.
 * Values are read-only for now - editable in a future phase.
 */
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { ExternalLink, Info } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@/components/ui/table";

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
  event_retention_days?: number;
  audit_retention_days?: number;
  max_payload_bytes?: number;
  max_ws_frame_bytes?: number;
  rate_limit_rpm?: number;
  session_lifetime_hours?: number;
  idle_timeout_minutes?: number;
  login_lockout_threshold?: number;
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

function GeneralSettingsPage() {
  const { data, isLoading } = useQuery<SystemInfo>({
    queryKey: ["system-info"],
    queryFn: () => api.get<SystemInfo>("/health/system"),
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
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
      <Card className="p-6">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">Retention</h3>
          <Badge variant="muted">read-only</Badge>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          How long z4j keeps event and audit data before automatic cleanup.
        </p>
        <div className="mt-4">
          <SettingsTable
            rows={[
              [
                "Event retention",
                data?.event_retention_days
                  ? `${data.event_retention_days} days`
                  : "30 days (default)",
              ],
              [
                "Audit retention",
                data?.audit_retention_days
                  ? `${data.audit_retention_days} days`
                  : "90 days (default)",
              ],
            ]}
          />
        </div>
      </Card>

      {/* Limits */}
      <Card className="p-6">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">Limits</h3>
          <Badge variant="muted">read-only</Badge>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Size and rate constraints enforced by z4j.
        </p>
        <div className="mt-4">
          <SettingsTable
            rows={[
              [
                "Max payload size",
                data?.max_payload_bytes
                  ? formatBytes(data.max_payload_bytes)
                  : "1 MB (default)",
              ],
              [
                "Max WebSocket frame size",
                data?.max_ws_frame_bytes
                  ? formatBytes(data.max_ws_frame_bytes)
                  : "64 KB (default)",
              ],
              [
                "Rate limit",
                data?.rate_limit_rpm
                  ? `${data.rate_limit_rpm} requests/min`
                  : "600 requests/min (default)",
              ],
            ]}
          />
        </div>
      </Card>

      {/* Session */}
      <Card className="p-6">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">Session</h3>
          <Badge variant="muted">read-only</Badge>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Authentication and session management policies.
        </p>
        <div className="mt-4">
          <SettingsTable
            rows={[
              [
                "Session lifetime",
                data?.session_lifetime_hours
                  ? `${data.session_lifetime_hours} hours`
                  : "24 hours (default)",
              ],
              [
                "Idle timeout",
                data?.idle_timeout_minutes
                  ? `${data.idle_timeout_minutes} minutes`
                  : "60 minutes (default)",
              ],
              [
                "Login lockout threshold",
                data?.login_lockout_threshold
                  ? `${data.login_lockout_threshold} failed attempts`
                  : "5 failed attempts (default)",
              ],
            ]}
          />
        </div>
      </Card>

      {/* System info */}
      {data && (
        <Card className="p-6">
          <h3 className="text-sm font-semibold">System</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Core runtime information for z4j process.
          </p>
          <div className="mt-4">
            <SettingsTable
              rows={[
                ["z4j version", data.z4j_version],
                [
                  "Python",
                  `${data.python_version} (${data.python_implementation})`,
                ],
                ["OS", data.os],
                ["Architecture", data.architecture],
                ["Database", data.database_type],
                ...(data.database_version
                  ? [["Database version", data.database_version] as [string, string]]
                  : []),
                ...(data.database_size_mb !== undefined
                  ? [["Database size", `${data.database_size_mb} MB`] as [string, string]]
                  : []),
              ]}
            />
          </div>
        </Card>
      )}

      {/* About */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold">About</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          License and project resources.
        </p>
        <div className="mt-4">
          <SettingsTable
            rows={[["License", "AGPL-3.0-or-later"]]}
          />
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <ResourceLink href="https://z4j.com" label="z4j.com" />
          <ResourceLink href="https://z4j.dev" label="Documentation" />
          <ResourceLink
            href="https://github.com/z4jdev"
            label="GitHub"
          />
        </div>
      </Card>
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
