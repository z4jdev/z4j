import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DateCell } from "@/components/domain/date-cell";

export interface TelemetryLoss {
  buffer_id: string;
  runtime_id: string;
  capacity_evicted_frames: number;
  content_rejected_frames: number;
  event_records: number;
  command_results: number;
  other_frames: number;
  unclassified_frames: number;
  adapter_events: Record<string, number>;
}
export interface HealthSnapshot {
  id: number;
  captured_at: string;
  worker_id: string | null;
  telemetry_loss: TelemetryLoss | null;
}

export function latestLossSources(samples: HealthSnapshot[]) {
  const buffers = new Map<string, HealthSnapshot>();
  const runtimes = new Map<string, HealthSnapshot>();
  for (const sample of samples) {
    const loss = sample.telemetry_loss;
    if (!loss) continue;
    if (!buffers.has(loss.buffer_id)) buffers.set(loss.buffer_id, sample);
    if (!runtimes.has(loss.runtime_id)) runtimes.set(loss.runtime_id, sample);
  }
  return { buffers: [...buffers.values()], runtimes: [...runtimes.values()] };
}

export function AgentHealthDialog({
  slug,
  agent,
  onClose,
}: {
  slug: string;
  agent: { id: string; name: string } | null;
  onClose: () => void;
}) {
  const query = useQuery<HealthSnapshot[]>({
    queryKey: ["agent-health", slug, agent?.id],
    queryFn: () => api.get(`/projects/${slug}/agents/${agent!.id}/health`),
    enabled: !!agent,
    refetchInterval: agent ? 15_000 : false,
  });
  const sources = latestLossSources(query.data ?? []);
  return (
    <Dialog
      open={!!agent}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-h-[90dvh] grid-cols-[minmax(0,1fr)] overflow-y-auto sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle>Agent health · {agent?.name}</DialogTitle>
          <DialogDescription>
            Telemetry loss from the latest 100 retained status samples. Each
            source reports cumulative counters; repeated samples are not added
            together. Reports can arrive late after an outage. These counts
            describe lost telemetry, not failed task executions.
          </DialogDescription>
        </DialogHeader>
        {query.isPending ? (
          <p role="status">Loading health reports…</p>
        ) : query.isError ? (
          <div role="alert">
            Unable to load health reports.{" "}
            <Button variant="outline" onClick={() => query.refetch()}>
              Try again
            </Button>
          </div>
        ) : sources.buffers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No loss accounting available. The agent may need an update, status
            reporting may be disabled, or retained samples may have expired.
            Absence of a report does not mean zero loss.
          </p>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead sortKey="c0">Buffer / worker</TableHead>
                  <TableHead sortKey="c1">Event records lost</TableHead>
                  <TableHead sortKey="c2">Results lost</TableHead>
                  <TableHead sortKey="c3">Other / unknown frames</TableHead>
                  <TableHead sortKey="c4">Reported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sources.buffers.map((sample) => {
                  const loss = sample.telemetry_loss!;
                  return (
                    <TableRow
                      key={loss.buffer_id}
                      sortValues={{
                        c0: sample.worker_id ?? loss.buffer_id,
                        c1: loss.event_records,
                        c2: loss.command_results,
                        c3: loss.other_frames + loss.unclassified_frames,
                        c4: Date.parse(sample.captured_at),
                      }}
                    >
                      <TableCell className="min-w-48">
                        <div className="font-mono text-xs break-all">
                          {sample.worker_id ?? loss.buffer_id}
                        </div>
                        <div
                          className="text-xs text-muted-foreground"
                          title={loss.buffer_id}
                        >
                          Buffer {loss.buffer_id.slice(-8)}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Capacity:{" "}
                          {loss.capacity_evicted_frames.toLocaleString()} frames
                          · Rejected:{" "}
                          {loss.content_rejected_frames.toLocaleString()} frames
                        </div>
                      </TableCell>
                      <TableCell>
                        {loss.event_records.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {loss.command_results.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {loss.other_frames.toLocaleString()} /{" "}
                        {loss.unclassified_frames.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <DateCell value={sample.captured_at} compact />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <p className="text-xs text-muted-foreground">
              Capacity and rejection count discarded frames. A frame can contain
              many event records. Other frames include heartbeat, status and
              registry updates; unknown frames could not be classified. Buffer
              counters belong to that buffer file.
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead sortKey="c0">Adapter / runtime</TableHead>
                  <TableHead sortKey="c1">Queue events lost</TableHead>
                  <TableHead sortKey="c2">Reported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sources.runtimes.flatMap((sample) =>
                  Object.entries(sample.telemetry_loss!.adapter_events).map(
                    ([name, count]) => (
                      <TableRow
                        key={`${sample.telemetry_loss!.runtime_id}:${name}`}
                        sortValues={{
                          c0: name,
                          c1: count,
                          c2: Date.parse(sample.captured_at),
                        }}
                      >
                        <TableCell>
                          <div>{name}</div>
                          <div className="font-mono text-xs text-muted-foreground break-all">
                            {sample.worker_id ??
                              sample.telemetry_loss!.runtime_id}
                          </div>
                          <div
                            className="text-xs text-muted-foreground"
                            title={sample.telemetry_loss!.runtime_id}
                          >
                            Runtime{" "}
                            {sample.telemetry_loss!.runtime_id.slice(-8)}
                          </div>
                        </TableCell>
                        <TableCell>{count.toLocaleString()}</TableCell>
                        <TableCell>
                          <DateCell value={sample.captured_at} compact />
                        </TableCell>
                      </TableRow>
                    ),
                  ),
                )}
              </TableBody>
            </Table>
            <p className="text-xs text-muted-foreground">
              Adapter counters reset with a new runtime. Only adapters that
              support loss accounting appear. Investigate transport outages,
              content rejection and sustained capture backpressure before
              increasing buffer limits.
            </p>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
