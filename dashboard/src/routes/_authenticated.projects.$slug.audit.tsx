import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { buildAuditExportUrl, useAudit } from "@/hooks/use-audit";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import {
  buildExportJobDownloadUrl,
  formatBytes,
  useCreateExportJob,
  useExportJobs,
  type ExportJobFormat,
  type ExportJobPublic,
} from "@/hooks/use-export-jobs";
import { ApiError } from "@/lib/api";
import type { AuditLogListResponse } from "@/lib/api-types";
import { sortTimestamp } from "@/lib/table-sorting";
import { createFileRoute } from "@tanstack/react-router";
import { Download, FileClock, Shield } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/projects/$slug/audit")({
  component: AuditPage,
});

const OUTCOMES = ["all", "allow", "deny", "error"] as const;

const columns: DataTableColumnDef<AuditLogListResponse["items"][number]>[] = [
  {
    id: "action",
    header: "Action",
    accessorFn: (row) => row.action,
    cell: ({ row: { original: row } }) => (
      <div className="whitespace-nowrap font-mono text-sm">{row.action}</div>
    ),
  },
  {
    id: "target",
    header: "Target",
    accessorFn: (row) =>
      [row.target_type, row.target_id].filter(Boolean).join(" "),
    cell: ({ row: { original: row } }) => (
      <div>
        <span className="text-xs text-muted-foreground">{row.target_type}</span>
        {row.target_id && (
          <div className="whitespace-nowrap font-mono text-xs">
            {row.target_id}
          </div>
        )}
      </div>
    ),
  },
  {
    id: "outcome",
    header: "Outcome",
    accessorFn: (row) => row.outcome ?? row.result,
    cell: ({ row: { original: row } }) => (
      <div>
        <Badge
          variant={
            row.outcome === "allow"
              ? "success"
              : row.outcome === "deny"
                ? "destructive"
                : "muted"
          }
        >
          {row.outcome ?? row.result}
        </Badge>
      </div>
    ),
  },
  {
    id: "ip",
    header: "Source IP",
    accessorFn: (row) => row.source_ip,
    cell: ({ row: { original: row } }) => (
      <div className="font-mono text-xs text-muted-foreground">
        {row.source_ip ?? "-"}
      </div>
    ),
  },
  {
    id: "when",
    header: "When",
    accessorFn: (row) => sortTimestamp(row.occurred_at),
    cell: ({ row: { original: row } }) => (
      <div className="text-right">
        <DateCell value={row.occurred_at} compact />
      </div>
    ),
  },
];

function AuditPage() {
  const { slug } = Route.useParams();
  const [actionPrefix, setActionPrefix] = useState("");
  const [outcome, setOutcome] = useState<(typeof OUTCOMES)[number]>("all");
  const [cursor, setCursor] = useState<string | null>(null);

  const debouncedPrefix = useDebouncedValue(actionPrefix, 300);
  const { data, isLoading, isError, isFetching, refetch } = useAudit(slug, {
    action_prefix: debouncedPrefix || undefined,
    outcome: outcome === "all" ? undefined : outcome,
    cursor,
  });

  return (
    <>
      <PageShell>
        <PageHeader
          title="Audit log"
          icon={Shield}
          description="Review access decisions and administrative activity."
          actions={
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Download className="size-4" aria-hidden="true" />
                  Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem asChild>
                  <a
                    href={buildAuditExportUrl(slug, "csv", {
                      action_prefix: actionPrefix || undefined,
                      outcome: outcome === "all" ? undefined : outcome,
                    })}
                    download
                  >
                    CSV
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a
                    href={buildAuditExportUrl(slug, "xlsx", {
                      action_prefix: actionPrefix || undefined,
                      outcome: outcome === "all" ? undefined : outcome,
                    })}
                    download
                  >
                    Excel (xlsx)
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a
                    href={buildAuditExportUrl(slug, "json", {
                      action_prefix: actionPrefix || undefined,
                      outcome: outcome === "all" ? undefined : outcome,
                    })}
                    download
                  >
                    JSON
                  </a>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          }
        />

        <DataTable
          isFetching={isFetching}
          columns={columns}
          data={data?.items ?? []}
          isLoading={isLoading}
          error={isError ? "Unable to load audit entries. Try again." : null}
          onRetry={() => refetch()}
          getRowId={(row) => row.id}
          toolbar={() => (
            <FilterToolbar
              searchValue={actionPrefix}
              onSearchChange={(v) => {
                setActionPrefix(v);
                setCursor(null);
              }}
              searchPlaceholder="Search action prefix…"
              activeFilterCount={
                (actionPrefix ? 1 : 0) + (outcome !== "all" ? 1 : 0)
              }
              onClear={() => {
                setActionPrefix("");
                setOutcome("all");
                setCursor(null);
              }}
              filters={
                <Select
                  value={outcome}
                  onValueChange={(v) => {
                    setOutcome(v as (typeof OUTCOMES)[number]);
                    setCursor(null);
                  }}
                >
                  <SelectTrigger
                    aria-label="Audit outcome"
                    className="w-36 shrink-0"
                  >
                    <SelectValue placeholder="outcome" />
                  </SelectTrigger>
                  <SelectContent>
                    {OUTCOMES.map((o) => (
                      <SelectItem key={o} value={o}>
                        {o === "all" ? "All outcomes" : o}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              }
            />
          )}
          emptyState={
            <EmptyState
              icon={Shield}
              title="No audit entries match"
              description="Adjust your filters, or wait for the next operator action."
            />
          }
          hasNextPage={!!data?.next_cursor}
          hasPreviousPage={!!cursor}
          onNextPage={() => setCursor(data?.next_cursor ?? null)}
          onFirstPage={() => setCursor(null)}
          totalLabel={`${data?.items.length ?? 0} audit entries`}
        />

        <ExportJobsPanel
          slug={slug}
          filters={{
            action_prefix: actionPrefix || undefined,
            outcome: outcome === "all" ? undefined : outcome,
          }}
        />
      </PageShell>
    </>
  );
}

// ---------------------------------------------------------------------------
// Exports panel: background export jobs for trails above the download caps
// ---------------------------------------------------------------------------

const EXPORT_FORMATS: { value: ExportJobFormat; label: string }[] = [
  { value: "csv", label: "CSV" },
  { value: "json", label: "JSON" },
  { value: "xlsx", label: "Excel (xlsx)" },
];

function exportStatusVariant(status: string) {
  switch (status) {
    case "done":
      return "success" as const;
    case "failed":
      return "destructive" as const;
    case "running":
      return "warning" as const;
    default:
      return "muted" as const;
  }
}

function ExportJobsPanel({
  slug,
  filters,
}: {
  slug: string;
  filters: { action_prefix?: string; outcome?: string };
}) {
  const { data, isError, error } = useExportJobs(slug);
  const create = useCreateExportJob(slug);

  // A real brain and the demo build both answer the list (empty, with a
  // null sink, when no export sink is configured), so the panel shows its
  // empty state. A 404 means the route itself is absent (a proxy that does
  // not forward it), and that hides the panel rather than reporting an
  // error the operator cannot act on.
  if (isError && error instanceof ApiError && error.status === 404) {
    return null;
  }

  const queue = (format: ExportJobFormat) => {
    create.mutate(
      { format, ...filters },
      {
        onSuccess: () => toast.success(`${format.toUpperCase()} export queued`),
        onError: (err) => {
          const message =
            err instanceof ApiError ? err.message : "request failed";
          toast.error(`could not queue export: ${message}`);
        },
      },
    );
  };

  const sinkConfigured = !!data?.sink;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="flex items-center gap-2">
            <FileClock className="size-4" aria-hidden="true" />
            Exports
          </CardTitle>
          <CardDescription>
            {sinkConfigured
              ? `Background exports of any size, written to ${data?.sink} sink ${data?.sink_location ?? ""}. Queued with the current filters.`
              : "Background exports need an export sink (Z4J_EXPORT_SINK). The download menu above stays available within its row caps."}
          </CardDescription>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              disabled={!sinkConfigured || create.isPending}
            >
              <FileClock className="size-4" aria-hidden="true" />
              Queue export
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {EXPORT_FORMATS.map((item) => (
              <DropdownMenuItem
                key={item.value}
                onSelect={() => queue(item.value)}
              >
                {item.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </CardHeader>
      <CardContent>
        {isError ? (
          <p className="text-sm text-muted-foreground">
            Unable to load export jobs.
          </p>
        ) : !data || data.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No export jobs yet.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead sortKey="c0">Format</TableHead>
                <TableHead sortKey="c1">Status</TableHead>
                <TableHead sortKey="c2" className="text-right">
                  Rows
                </TableHead>
                <TableHead sortKey="c3" className="text-right">
                  Size
                </TableHead>
                <TableHead sortKey="c4">Location</TableHead>
                <TableHead sortKey="c5">Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((job) => (
                <ExportJobRow key={job.id} slug={slug} job={job} />
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function ExportJobRow({ slug, job }: { slug: string; job: ExportJobPublic }) {
  return (
    <TableRow
      sortValues={{
        c0: job.format,
        c1: job.status,
        c2: job.row_count ?? null,
        c3: job.size_bytes ?? null,
        c4: job.location ?? "",
        c5: sortTimestamp(job.created_at),
      }}
    >
      <TableCell className="font-mono text-xs uppercase">
        {job.format}
      </TableCell>
      <TableCell>
        <Badge variant={exportStatusVariant(job.status)}>{job.status}</Badge>
        {job.status === "failed" && job.error && (
          <div
            className="mt-1 max-w-xs truncate text-xs text-destructive"
            title={job.error}
          >
            {job.error}
          </div>
        )}
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {job.row_count ?? "-"}
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {formatBytes(job.size_bytes)}
      </TableCell>
      <TableCell>
        <div
          className="max-w-xs truncate font-mono text-xs text-muted-foreground"
          title={job.location ?? undefined}
        >
          {job.location ?? (job.sink ? `${job.sink} sink` : "-")}
        </div>
      </TableCell>
      <TableCell>
        <DateCell value={job.created_at} compact />
      </TableCell>
      <TableCell className="text-right">
        {job.downloadable ? (
          <Button asChild variant="outline" size="sm">
            <a href={buildExportJobDownloadUrl(slug, job.id)} download>
              <Download className="size-4" aria-hidden="true" />
              Download
            </a>
          </Button>
        ) : (
          <span className="text-xs text-muted-foreground">-</span>
        )}
      </TableCell>
    </TableRow>
  );
}
