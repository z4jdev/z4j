import { createFileRoute } from "@tanstack/react-router";
import { Layers, RefreshCw } from "lucide-react";
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

export const Route = createFileRoute("/_authenticated/projects/$slug/queues")({
  component: QueuesPage,
});

function QueuesPage() {
  const { slug } = Route.useParams();
  const { data: queues, isLoading, isFetching, refetch } = useQueues(slug);

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Queues"
        icon={Layers}
        description="every queue the agent has touched in the recent past"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw
              className={isFetching ? "size-4 animate-spin" : "size-4"}
            />
            Refresh
          </Button>
        }
      />

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}
      {queues && queues.length === 0 && (
        <EmptyState
          icon={Layers}
          title="no queues yet"
          description="queues will appear once tasks start flowing through the agent"
        />
      )}
      {queues && queues.length > 0 && (
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
              {queues.map((q) => (
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
            {queues.length} queue{queues.length === 1 ? "" : "s"}
          </div>
        </Card>
      )}
    </div>
  );
}
