import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useQueues } from "@/hooks/use-queues";
import { sortTimestamp } from "@/lib/table-sorting";
import { createFileRoute } from "@tanstack/react-router";
import { Layers } from "lucide-react";
import { useMemo, useState } from "react";

export const Route = createFileRoute("/_authenticated/projects/$slug/queues")({
  component: QueuesPage,
});

function QueuesPage() {
  const { slug } = Route.useParams();
  const {
    data: queues,
    isLoading,
    isFetching,
    refetch,
    isError,
  } = useQueues(slug);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredQueues = useMemo(() => {
    if (!queues) return [];
    if (!searchQuery) return queues;
    const q = searchQuery.toLowerCase();
    return queues.filter(
      (row) =>
        row.name.toLowerCase().includes(q) ||
        row.engine.toLowerCase().includes(q) ||
        (row.broker_type && row.broker_type.toLowerCase().includes(q)),
    );
  }, [queues, searchQuery]);

  return (
    <PageShell>
      <PageHeader
        title="Queues"
        icon={Layers}
        description="Inspect queues and their latest activity."
        actions={
          <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
        }
      />

      <Table
        toolbar={
          <FilterToolbar
            searchValue={searchQuery}
            onSearchChange={setSearchQuery}
            searchPlaceholder="Search queues..."
            activeFilterCount={searchQuery ? 1 : 0}
            onClear={() => setSearchQuery("")}
          />
        }
        isLoading={isLoading}
        error={isError ? "Unable to load queues. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Layers}
            title={searchQuery ? "no queues match" : "no queues yet"}
            description={
              searchQuery
                ? "try adjusting your search query"
                : "queues will appear once tasks start flowing through the agent"
            }
          />
        }
      >
        <TableHeader>
          <TableRow>
            <TableHead sortKey="c0">Name</TableHead>
            <TableHead sortKey="c1">Engine</TableHead>
            <TableHead sortKey="c2">Broker</TableHead>
            <TableHead sortKey="c3" className="text-right">
              Last seen
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(filteredQueues ?? []).map((q) => (
            <TableRow
              sortValues={{
                c0: q.name,
                c1: q.engine,
                c2: q.broker_type,
                c3: sortTimestamp(q.last_seen_at),
              }}
              key={q.id}
            >
              <TableCell className="font-medium">{q.name}</TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {q.engine}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {q.broker_type ?? "-"}
              </TableCell>
              <TableCell className="text-right">
                <DateCell value={q.last_seen_at} compact />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </PageShell>
  );
}
