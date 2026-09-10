import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { CommandStatusBadge } from "@/components/domain/state-badges";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useCommands } from "@/hooks/use-commands";
import type { CommandPublic, CommandStatus } from "@/lib/api-types";
import { sortTimestamp } from "@/lib/table-sorting";
import { createFileRoute } from "@tanstack/react-router";
import { Terminal } from "lucide-react";
import { useMemo, useState } from "react";

export const Route = createFileRoute("/_authenticated/projects/$slug/commands")(
  {
    component: CommandsPage,
  },
);

const STATUSES: (CommandStatus | "all")[] = [
  "all",
  "pending",
  "dispatched",
  "completed",
  "failed",
  "timeout",
  "cancelled",
];

function CommandsPage() {
  const { slug } = Route.useParams();
  const [status, setStatus] = useState<CommandStatus | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);

  const { data, isLoading, isError, isFetching, refetch } = useCommands(slug, {
    status: status === "all" ? "" : status,
    cursor,
  });

  const activeFilterCount = (status !== "all" ? 1 : 0) + (searchQuery ? 1 : 0);

  const clearFilters = () => {
    setStatus("all");
    setSearchQuery("");
    setCursor(null);
  };

  // Client-side search filter - the API handles status filtering,
  // but we filter by action/target/error text locally.
  const filteredItems = useMemo(() => {
    if (!data) return [];
    if (!searchQuery) return data.items;
    const q = searchQuery.toLowerCase();
    return data.items.filter(
      (cmd) =>
        cmd.action.toLowerCase().includes(q) ||
        cmd.target_type.toLowerCase().includes(q) ||
        (cmd.target_id && cmd.target_id.toLowerCase().includes(q)) ||
        (cmd.error && cmd.error.toLowerCase().includes(q)),
    );
  }, [data, searchQuery]);

  const columns = useCommandColumns();

  const filterToolbar = (
    <FilterToolbar
      searchValue={searchQuery}
      onSearchChange={setSearchQuery}
      searchPlaceholder="Search this page…"
      activeFilterCount={activeFilterCount}
      onClear={clearFilters}
      filters={
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v as CommandStatus | "all");
            setCursor(null);
          }}
        >
          <SelectTrigger aria-label="Command status" className="w-36 shrink-0">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.filter((s) => s !== "all").map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      }
    />
  );

  return (
    <PageShell>
      <PageHeader
        title="Commands"
        icon={Terminal}
        description="Review operator actions and their delivery status."
        actions={
          <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
        }
      />

      <DataTable
        searchScope="page"
        isFetching={isFetching}
        isLoading={isLoading}
        error={isError ? "Unable to load commands. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Terminal}
            title="no commands yet"
            description={
              activeFilterCount > 0
                ? "try adjusting your filters or search query"
                : "commands appear here when an operator clicks retry / cancel / restart"
            }
          />
        }
        columns={columns}
        data={filteredItems}
        enableSorting
        hasNextPage={!!data?.next_cursor}
        hasPreviousPage={!!cursor}
        onNextPage={() => setCursor(data?.next_cursor ?? null)}
        onFirstPage={() => setCursor(null)}
        totalLabel={`${filteredItems.length} command${filteredItems.length === 1 ? "" : "s"}`}
        toolbar={() => filterToolbar}
      />
    </PageShell>
  );
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

function useCommandColumns(): DataTableColumnDef<CommandPublic>[] {
  return useMemo(
    () => [
      {
        accessorKey: "action",
        header: "Action",
        cell: ({ row }: { row: { original: CommandPublic } }) => {
          const cmd = row.original;
          return (
            <div>
              <div className="whitespace-nowrap font-mono text-sm">
                {cmd.action}
              </div>
              {cmd.error && (
                <div className="mt-1 max-w-md truncate text-xs text-destructive">
                  {cmd.error}
                </div>
              )}
            </div>
          );
        },
        enableSorting: true,
      },
      {
        id: "target_type",
        accessorFn: (row) =>
          [row.target_type, row.target_id].filter(Boolean).join(" "),
        header: "Target",
        cell: ({ row }: { row: { original: CommandPublic } }) => {
          const cmd = row.original;
          return (
            <div>
              <span className="text-xs text-muted-foreground">
                {cmd.target_type}
              </span>
              {cmd.target_id && (
                <div className="whitespace-nowrap font-mono text-xs">
                  {cmd.target_id}
                </div>
              )}
            </div>
          );
        },
        enableSorting: true,
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }: { row: { original: CommandPublic } }) => (
          <CommandStatusBadge status={row.original.status} />
        ),
        enableSorting: true,
      },
      {
        id: "issued_at",
        accessorFn: (row) => sortTimestamp(row.issued_at),
        header: "Issued",
        cell: ({ row }: { row: { original: CommandPublic } }) => (
          <DateCell value={row.original.issued_at} compact />
        ),
        enableSorting: true,
      },
      {
        id: "completed_at",
        accessorFn: (row) => sortTimestamp(row.completed_at),
        header: "Completed",
        cell: ({ row }: { row: { original: CommandPublic } }) => (
          <DateCell value={row.original.completed_at} compact />
        ),
        enableSorting: true,
      },
    ],
    [],
  );
}
