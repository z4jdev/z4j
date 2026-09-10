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
import { buildAuditExportUrl, useAudit } from "@/hooks/use-audit";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import type { AuditLogListResponse } from "@/lib/api-types";
import { sortTimestamp } from "@/lib/table-sorting";
import { createFileRoute } from "@tanstack/react-router";
import { Download, Shield } from "lucide-react";
import { useState } from "react";

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
      </PageShell>
    </>
  );
}
