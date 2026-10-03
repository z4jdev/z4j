/**
 * Dead letters page: what an engine has given up on and parked, read live
 * from its dead-letter store through the agent, with a per-row requeue.
 *
 * The engine selector offers only engines some connected agent advertises
 * ``list_dead_letters`` for (RQ, and Dramatiq on its Redis and RabbitMQ
 * brokers); the brain issues one ``dlq.list`` command per page. The requeue
 * button appears only when the engine's agent also advertises
 * ``requeue_dead_letter`` and the operator may retry tasks.
 */
import { useConfirm } from "@/components/domain/confirm-dialog";
import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { Button } from "@/components/ui/button";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAgents } from "@/hooks/use-agents";
import { useRequeueDeadLetter } from "@/hooks/use-commands";
import { useDeadLetters } from "@/hooks/use-dead-letters";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { useCan } from "@/hooks/use-memberships";
import {
  enginesAdvertising,
  pickAgentForAction,
} from "@/lib/agent-capabilities";
import { ApiError } from "@/lib/api";
import type { DeadLetterEntry } from "@/lib/api-types";
import { sortTimestamp } from "@/lib/table-sorting";
import { createFileRoute } from "@tanstack/react-router";
import { MailX } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/dead-letters",
)({
  component: DeadLettersPage,
});

const PAGE_SIZE = 50;

function DeadLettersPage() {
  const { slug } = Route.useParams();
  const { data: agents } = useAgents(slug);
  const listable = useMemo(
    () => enginesAdvertising(agents, "list_dead_letters"),
    [agents],
  );

  const [chosenEngine, setChosenEngine] = useState("");
  // The selection survives an agent reconnect; an engine nobody lists any
  // more falls back to the first one that is still listable.
  const engine =
    chosenEngine && listable.includes(chosenEngine)
      ? chosenEngine
      : (listable[0] ?? "");

  const [queueInput, setQueueInput] = useState("");
  const queue = useDebouncedValue(queueInput.trim(), 300);
  const [cursor, setCursor] = useState<string | null>(null);
  const [earlier, setEarlier] = useState<(string | null)[]>([]);

  const { data, isLoading, isError, error, isFetching, refetch } =
    useDeadLetters(slug, { engine, queue, cursor, limit: PAGE_SIZE });

  const canRequeue = useCan(slug, "retry_task");
  const requeueAgent = useMemo(
    () =>
      engine
        ? pickAgentForAction(agents ?? [], engine, "requeue_dead_letter")
        : undefined,
    [agents, engine],
  );
  const requeue = useRequeueDeadLetter(slug);
  const { confirm, dialog } = useConfirm();

  const entries = data?.entries ?? [];
  const total = data?.total ?? null;

  const resetPaging = () => {
    setCursor(null);
    setEarlier([]);
  };

  const onRequeue = (entry: DeadLetterEntry) => {
    if (!requeueAgent) return;
    confirm({
      title: "Requeue dead letter",
      description: (
        <>
          Put <code>{entry.task_id}</code>
          {entry.task_name ? (
            <>
              {" "}
              (<code>{entry.task_name}</code>)
            </>
          ) : null}{" "}
          back on queue <code>{entry.queue}</code> of {engine}? The engine runs
          it again from the start.
        </>
      ),
      confirmLabel: "Requeue",
      variant: "default",
      onConfirm: async () => {
        try {
          await requeue.mutateAsync({
            agent_id: requeueAgent.id,
            engine,
            task_id: entry.task_id,
          });
          toast.success("requeue command issued");
          await refetch();
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          toast.error(`requeue failed: ${message}`);
        }
      },
    });
  };

  const columns = useDeadLetterColumns({
    requeueable: canRequeue && !!requeueAgent,
    pending: requeue.isPending,
    onRequeue,
  });

  const activeFilterCount = queue ? 1 : 0;

  const filterToolbar = (
    <FilterToolbar
      searchValue={queueInput}
      onSearchChange={(value) => {
        setQueueInput(value);
        resetPaging();
      }}
      searchPlaceholder="Filter by queue name"
      activeFilterCount={activeFilterCount}
      onClear={() => {
        setQueueInput("");
        resetPaging();
      }}
      filters={
        <Select
          value={engine}
          onValueChange={(value) => {
            setChosenEngine(value);
            resetPaging();
          }}
          disabled={listable.length === 0}
        >
          <SelectTrigger aria-label="Engine" className="w-40 shrink-0">
            <SelectValue placeholder="Engine" />
          </SelectTrigger>
          <SelectContent>
            {listable.map((name) => (
              <SelectItem key={name} value={name}>
                {name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      }
    />
  );

  const listableSentence =
    listable.length > 0
      ? `Engines that can list dead letters here: ${listable.join(", ")}.`
      : "No connected agent advertises list_dead_letters; the RQ and Dramatiq adapters do once their agent connects.";

  const emptyState =
    listable.length === 0 ? (
      <EmptyState
        icon={MailX}
        title="no agent can list dead letters"
        description={listableSentence}
      />
    ) : (
      <EmptyState
        icon={MailX}
        title="no dead letters"
        description={`${engine} reports nothing parked${queue ? ` on ${queue}` : ""}. ${listableSentence}`}
      />
    );

  const notices: string[] = [];
  if (
    !isLoading &&
    !isError &&
    engine &&
    entries.length === 0 &&
    cursor === null &&
    total !== null &&
    total > 0
  ) {
    notices.push(
      `${engine} reports ${total} dead letter${total === 1 ? "" : "s"} but cannot list them: this broker has no non-destructive read of a queue.`,
    );
  }
  if (canRequeue && engine && !requeueAgent && entries.length > 0) {
    notices.push(
      `No connected ${engine} agent advertises requeue_dead_letter, so these entries are read-only here.`,
    );
  }

  const totalLabel =
    total !== null
      ? `${entries.length} of ${total} dead letter${total === 1 ? "" : "s"}`
      : `${entries.length} dead letter${entries.length === 1 ? "" : "s"}`;

  return (
    <PageShell>
      <PageHeader
        title="Dead letters"
        icon={MailX}
        description="Tasks the engine gave up on, read live from its dead-letter store. Requeue one to put it back on its queue."
        actions={
          <RefreshButton onRefresh={() => refetch()} pending={isFetching} />
        }
      />

      <DataTable
        searchScope="page"
        isFetching={isFetching}
        isLoading={isLoading && !!engine}
        error={isError ? describeError(error, engine) : null}
        onRetry={() => refetch()}
        emptyState={emptyState}
        columns={columns}
        data={entries}
        enableSorting
        sortingScope="page"
        notice={
          notices.length > 0 ? (
            <div className="space-y-1">
              {notices.map((text) => (
                <p key={text}>{text}</p>
              ))}
            </div>
          ) : undefined
        }
        hasNextPage={!!data?.next_cursor}
        hasPreviousPage={earlier.length > 0}
        onNextPage={() => {
          setEarlier((stack) => [...stack, cursor]);
          setCursor(data?.next_cursor ?? null);
        }}
        onPreviousPage={() => {
          setEarlier((stack) => {
            const next = stack.slice(0, -1);
            setCursor(stack[stack.length - 1] ?? null);
            return next;
          });
        }}
        onFirstPage={resetPaging}
        totalLabel={totalLabel}
        toolbar={() => filterToolbar}
      />
      {dialog}
    </PageShell>
  );
}

/** The reason a listing failed, in the operator's terms. */
function describeError(error: unknown, engine: string): string {
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return `No online agent can list dead letters for ${engine}: ${error.message}`;
    }
    if (error.status === 504) {
      return `The ${engine} agent did not answer the listing in time. Refresh to try again.`;
    }
    if (error.status === 502) {
      return `The ${engine} agent could not read its dead-letter store: ${error.message}`;
    }
    return error.message;
  }
  return "Unable to load dead letters. Try again.";
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

function useDeadLetterColumns({
  requeueable,
  pending,
  onRequeue,
}: {
  requeueable: boolean;
  pending: boolean;
  onRequeue: (entry: DeadLetterEntry) => void;
}): DataTableColumnDef<DeadLetterEntry>[] {
  return useMemo(() => {
    const columns: DataTableColumnDef<DeadLetterEntry>[] = [
      {
        accessorKey: "task_id",
        header: "Task ID",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) => (
          <span
            className="whitespace-nowrap font-mono text-xs"
            title={row.original.task_id}
          >
            {row.original.task_id}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: "task_name",
        header: "Task",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) =>
          row.original.task_name ? (
            <span className="font-mono text-sm">{row.original.task_name}</span>
          ) : (
            <span className="text-xs text-muted-foreground">unknown</span>
          ),
        enableSorting: true,
      },
      {
        accessorKey: "queue",
        header: "Queue",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) => (
          <span className="whitespace-nowrap text-sm">
            {row.original.queue}
          </span>
        ),
        enableSorting: true,
      },
      {
        id: "failed_at",
        accessorFn: (row) => sortTimestamp(row.failed_at),
        header: "Failed",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) => (
          <DateCell value={row.original.failed_at ?? null} />
        ),
        enableSorting: true,
      },
      {
        id: "attempts",
        accessorFn: (row) => row.attempts ?? null,
        header: "Attempts",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) =>
          row.original.attempts == null ? (
            <span className="text-muted-foreground">-</span>
          ) : (
            <span className="tabular-nums">{row.original.attempts}</span>
          ),
        enableSorting: true,
      },
      {
        accessorKey: "error_excerpt",
        header: "Error",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) =>
          row.original.error_excerpt ? (
            <pre
              className="max-w-md overflow-hidden text-ellipsis whitespace-pre-wrap break-words font-mono text-xs text-destructive"
              title={row.original.error_excerpt}
            >
              {lastLines(row.original.error_excerpt, 2)}
            </pre>
          ) : (
            <span className="text-xs text-muted-foreground">-</span>
          ),
        enableSorting: false,
      },
    ];
    if (requeueable) {
      columns.push({
        id: "actions",
        header: "",
        cell: ({ row }: { row: { original: DeadLetterEntry } }) => (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={pending}
            onClick={() => onRequeue(row.original)}
          >
            Requeue
          </Button>
        ),
        enableSorting: false,
      });
    }
    return columns;
  }, [requeueable, pending, onRequeue]);
}

/** The tail of a traceback is where the exception type and message are. */
function lastLines(text: string, count: number): string {
  const lines = text.split("\n").filter((line) => line.trim() !== "");
  return lines.slice(-count).join("\n");
}
