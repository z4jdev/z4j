/**
 * Global settings - System status section (admin-only).
 *
 * Runtime info for z4j, database health, installed
 * packages. This is global, not project-scoped: nothing here
 * depends on which project is active.
 */
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { SectionCard } from "@/components/domain/section-card";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/domain/page-header";

export const Route = createFileRoute("/_authenticated/settings/system")({
  component: SystemPage,
});

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
  packages?: Record<string, string>;
}

function SystemPage() {
  const { data, isLoading } = useQuery<SystemInfo>({
    queryKey: ["system-info"],
    queryFn: () => api.get<SystemInfo>("/health/system"),
    staleTime: 60_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Activity}
        title="System"
        description="Brain process, database, and installed-package versions."
      />

      {isLoading && <Skeleton className="h-64 w-full" />}

      {!isLoading && data && (
      <>
      <SectionCard
        title="Brain Server"
        description="Core runtime information for z4j process."
      >
        <StatusTable
          rows={[
            ["z4j version", data.z4j_version],
            ["Python", `${data.python_version} (${data.python_implementation})`],
            ["OS", data.os],
            ["Architecture", data.architecture],
            ["PID", String(data.pid)],
          ]}
        />
      </SectionCard>

      <SectionCard
        title="Database"
        description="Connected database information and health."
      >
        <StatusTable
          rows={[
            ["Type", data.database_type],
            ...(data.database_version
              ? [["Version", data.database_version] as [string, string]]
              : []),
            ...(data.database_size_mb !== undefined
              ? [["Size", `${data.database_size_mb} MB`] as [string, string]]
              : []),
            ...(data.database_connections !== undefined
              ? [["Active connections", String(data.database_connections)] as [string, string]]
              : []),
          ]}
        />
      </SectionCard>

      {data.packages && Object.keys(data.packages).length > 0 && (
        <SectionCard
          title="Installed Packages"
          description="Key Python package versions in z4j environment."
        >
          <StatusTable
            rows={Object.entries(data.packages)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([name, version]) => [name, version])}
          />
        </SectionCard>
      )}

      <VersionsCheckCard />
      </>
      )}
    </div>
  );
}

interface VersionsSnapshot {
  schema_version: number;
  generated_at: string;
  generated_by: string;
  canonical_url: string;
  packages: Record<string, string>;
  source: "bundled" | "remote";
  fetched_at: string | null;
  fetched_from: string | null;
  check_for_updates_url: string;
}

/**
 * Operator-initiated *Check for updates* card.
 *
 * Privacy-by-default: z4j ships with a bundled snapshot of
 * the latest known z4j package versions. The button below is the
 * ONLY way z4j ever reaches out to fetch a fresher copy. No
 * background polling, no telemetry. Operators who want zero
 * outbound HTTP set Z4J_VERSION_CHECK_URL to an empty string
 * (z4j returns an empty URL and we hide the button).
 */
function VersionsCheckCard() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery<VersionsSnapshot>({
    queryKey: ["versions-snapshot"],
    queryFn: () =>
      api.get<VersionsSnapshot>("/admin/system/versions"),
    staleTime: 60_000,
  });
  const refresh = useMutation<VersionsSnapshot, Error, void>({
    mutationFn: () =>
      api.post<VersionsSnapshot>("/admin/system/versions/check", {}),
    onSuccess: (snap) => {
      qc.setQueryData(["versions-snapshot"], snap);
      // Refetch agent lists everywhere - the version_status badges
      // recompute against the new snapshot.
      qc.invalidateQueries({ queryKey: ["agents"] });
      const pkgCount = Object.keys(snap.packages).length;
      toast.success(
        `Latest known versions refreshed - ${pkgCount} packages, snapshot ${snap.generated_at}`,
      );
    },
    onError: (err) => {
      const msg =
        err instanceof ApiError ? err.message : "fetch failed";
      toast.error(msg);
    },
  });

  if (isLoading) return <Skeleton className="h-32 w-full" />;
  if (!data) return null;

  const buttonDisabled = !data.check_for_updates_url || refresh.isPending;

  return (
    <SectionCard
      title="Update checks"
      description="Brain ships with a snapshot of the latest known z4j package versions. Click to fetch a fresher snapshot from GitHub. No automatic polling, no telemetry."
      actions={
        <Button
          size="sm"
          onClick={() => refresh.mutate()}
          disabled={buttonDisabled}
        >
          <RefreshCw
            className={refresh.isPending ? "size-4 animate-spin" : "size-4"}
          />
          Check for updates
        </Button>
      }
    >
      <StatusTable
        rows={[
          ["Snapshot generated", data.generated_at || "(unknown)"],
          ["Snapshot built by", data.generated_by || "(unknown)"],
          [
            "Source",
            data.source === "remote"
              ? `remote · last fetched ${data.fetched_at ?? "unknown"}`
              : "bundled with brain wheel",
          ],
          ...(data.source === "remote" && data.fetched_from
            ? [["Fetched from", data.fetched_from] as [string, string]]
            : []),
          [
            "Check URL",
            data.check_for_updates_url ||
              "(disabled - set Z4J_VERSION_CHECK_URL to enable)",
          ],
          ["Packages tracked", String(Object.keys(data.packages).length)],
        ]}
      />
      {!data.check_for_updates_url ? (
        <p className="mt-3 text-xs text-muted-foreground">
          Remote update checks are disabled (Z4J_VERSION_CHECK_URL is
          empty). z4j is using the bundled snapshot only.
        </p>
      ) : null}
    </SectionCard>
  );
}

function StatusTable({ rows }: { rows: [string, string][] }) {
  return (
    <Table>
      <TableBody>
        {rows.map(([key, value]) => (
          <TableRow key={key}>
            <TableCell className="w-1/3 py-2 font-medium text-muted-foreground">
              {key}
            </TableCell>
            <TableCell className="py-2 font-mono text-sm">{value}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
