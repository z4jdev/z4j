import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Layers, RefreshCw } from "lucide-react";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { RefreshButton } from "@/components/domain/refresh-button";
import { PageHeader } from "@/components/domain/page-header";
import { EmptyState } from "@/components/domain/empty-state";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { useQueues } from "@/hooks/use-queues";
import { DateCell } from "@/components/domain/date-cell";
import { PageShell } from "@/components/domain/page-shell";

export const Route = createFileRoute("/_authenticated/projects/$slug/queues")({
  component: QueuesPage,
});

function QueuesPage() {
  const { slug } = Route.useParams();
  const { data: queues, isLoading, isFetching, refetch } = useQueues(slug);
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
        description="every queue the agent has touched in the recent past"
        actions={
          <RefreshButton
              onRefresh={() => refetch()}
              pending={isFetching}
            />
        }
      />

      <FilterToolbar
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search queues..."
        activeFilterCount={searchQuery ? 1 : 0}
        onClear={() => setSearchQuery("")}
      />

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}
      {queues && filteredQueues.length === 0 && (
        <EmptyState
          icon={Layers}
          title={searchQuery ? "no queues match" : "no queues yet"}
          description={
            searchQuery
              ? "try adjusting your search query"
              : "queues will appear once tasks start flowing through the agent"
          }
        />
      )}
      {queues && filteredQueues.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Engine</TableHead>
                <TableHead>Broker</TableHead>
                <TableHead className="text-right">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredQueues.map((q) => (
                <TableRow key={q.id}>
                  <TableCell className="font-medium">{q.name}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {q.engine}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {q.broker_type ?? "-"}
                  </TableCell>
                  <TableCell className="text-right">
                    <DateCell value={q.last_seen_at} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="border-t px-4 py-2 text-xs text-muted-foreground">
            {filteredQueues.length} queue{filteredQueues.length === 1 ? "" : "s"}
            {searchQuery && queues.length !== filteredQueues.length
              ? ` of ${queues.length}`
              : ""}
          </div>
        </Card>
      )}
    </PageShell>
  );
}
