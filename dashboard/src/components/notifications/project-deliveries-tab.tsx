import { PageHeader } from "@/components/domain/page-header";
import { PaginationControls } from "@/components/ui/pagination-controls";
import { sortTimestamp } from "@/lib/table-sorting";
/**
 * Project settings - Delivery Log section.
 *
 * Audit log of every notification sent, failed, or skipped by cooldown.
 * Cursor-paginated (50/page) so a project with thousands of deliveries
 * doesn't crash the dashboard. Admins can wipe the log via the Clear
 * button (destructive; confirms first).
 */
import { useConfirm } from "@/components/domain/confirm-dialog";
import { DateCell } from "@/components/domain/date-cell";
import { EmptyState } from "@/components/domain/empty-state";
import {
  DiscordIcon,
  MicrosoftTeamsIcon,
  PagerDutyIcon,
  SlackIcon,
  TelegramIcon,
} from "@/components/icons/brand-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useIsProjectAdmin } from "@/hooks/use-memberships";
import {
  useClearDeliveries,
  useDeliveries,
  type ChannelType,
} from "@/hooks/use-notifications";
import {
  Globe,
  Lock,
  Mail,
  RefreshCw,
  Send,
  Trash2,
  Webhook,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

// Same icon map the providers page uses, kept local so we don't
// have to break the existing modules out into a shared module just
// for this row label.
const CHANNEL_ICONS = {
  webhook: Webhook,
  email: Mail,
  slack: SlackIcon,
  telegram: TelegramIcon,
  pagerduty: PagerDutyIcon,
  discord: DiscordIcon,
  teams: MicrosoftTeamsIcon,
} as const;

const PAGE_SIZE = 50;

export function ProjectDeliveriesTab({ slug }: { slug: string }) {
  const isAdmin = useIsProjectAdmin(slug);
  const { confirm, dialog: confirmDialog } = useConfirm();

  // Cursor stack so the operator can paginate forward AND back. Each
  // forward click pushes the next_cursor; Back pops it. Empty stack +
  // null cursor = first page. The backend's response envelope is
  // {items, next_cursor} so we don't need to track total counts.
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const currentCursor = cursorStack[cursorStack.length - 1];

  const { data, isLoading, isFetching, isError, refetch } = useDeliveries(
    slug,
    PAGE_SIZE,
    currentCursor,
  );
  const deliveries = data?.items;
  const nextCursor = data?.next_cursor ?? null;
  const hasNext = nextCursor !== null;
  const hasPrev = cursorStack.length > 1;
  const pageNumber = cursorStack.length;

  const clearDeliveries = useClearDeliveries(slug);

  const handleClearClick = () => {
    confirm({
      title: "Clear delivery history?",
      description:
        "This permanently deletes every delivery row for this project (sent + failed + skipped). The notifications themselves were already delivered to their destinations - this only wipes the audit table. Cannot be undone.",
      confirmLabel: "Clear all",
      variant: "destructive",
      onConfirm: () =>
        new Promise<void>((resolve, reject) => {
          clearDeliveries.mutate(undefined, {
            onSuccess: (res) => {
              toast.success(`Cleared ${res.deleted.toLocaleString()} entries`);
              setCursorStack([null]);
              resolve();
            },
            onError: (err) => {
              toast.error(`Clear failed: ${err.message}`);
              reject(err);
            },
          });
        }),
    });
  };

  if (!isAdmin) {
    return (
      <EmptyState
        icon={Lock}
        title="Admin only"
        description="The delivery log is only visible to project admins."
      />
    );
  }

  return (
    <div className="space-y-4">
      {confirmDialog}
      <PageHeader
        level="section"
        title={
          <>
            Delivery History
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </>
        }
        description={
          <>
            Every notification attempt - sent, failed, or skipped by cooldown.
          </>
        }
        actions={
          <>
            {" "}
            <Button
              size="sm"
              variant="outline"
              onClick={handleClearClick}
              disabled={
                clearDeliveries.isPending ||
                !deliveries ||
                (deliveries.length === 0 && !hasPrev)
              }
            >
              <Trash2 className="size-4" />
              {clearDeliveries.isPending ? "Clearing..." : "Clear logs"}
            </Button>{" "}
          </>
        }
      />

      <Table
        searchable
        searchPlaceholder="Search deliveries…"
        isLoading={isLoading}
        error={isError ? "Unable to load deliveries. Try again." : null}
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Send}
            title="No deliveries yet"
            description="Notifications will appear here once subscriptions start firing."
          />
        }
        footer={
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div>
              Page {pageNumber} · showing {deliveries?.length ?? 0} entries
            </div>
            <PaginationControls
              hasPreviousPage={hasPrev}
              hasNextPage={hasNext}
              onPreviousPage={() => setCursorStack((s) => s.slice(0, -1))}
              onNextPage={() => setCursorStack((s) => [...s, nextCursor])}
              pending={isFetching}
            />
          </div>
        }
        sortingScope="page"
      >
        <TableHeader>
          <TableRow>
            <TableHead sortKey="c0">Trigger</TableHead>
            <TableHead sortKey="c1">Channel</TableHead>
            <TableHead sortKey="c2">Task</TableHead>
            <TableHead sortKey="c3">Status</TableHead>
            <TableHead sortKey="c4">Response</TableHead>
            <TableHead sortKey="c5" className="text-right">
              Sent
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(deliveries ?? []).map((d) => {
            // 1.0.14+: test dispatches from the channel-create
            // dialog show up here with trigger="test.dispatch".
            // Render with a different badge variant so operators
            // can scan the log and tell test traffic from real
            // notifications at a glance.
            const isTest = d.trigger === "test.dispatch";
            // Resolve a brand icon for the channel type when
            // we have one. Falls back to a generic globe for
            // unknown / deleted channels.
            const ChannelIcon = d.channel_type
              ? (CHANNEL_ICONS[d.channel_type as ChannelType] ?? Globe)
              : Globe;
            // Display name: prefer the joined channel name
            // (project or user channel). When NULL, the channel
            // was deleted OR this is an unsaved-config preflight
            // test row - both surface a clear placeholder.
            const channelLabel =
              d.channel_name ??
              (d.user_channel_id
                ? "(personal channel deleted)"
                : d.channel_id
                  ? "(channel deleted)"
                  : isTest
                    ? "(unsaved test)"
                    : "-");
            return (
              <TableRow
                sortValues={{
                  c0: isTest ? "test" : d.trigger,
                  c1: channelLabel,
                  c2: d.task_name ?? d.task_id,
                  c3: d.status,
                  c4: d.response_code,
                  c5: sortTimestamp(d.sent_at),
                }}
                key={d.id}
              >
                <TableCell>
                  {isTest ? (
                    <div className="flex flex-col gap-0.5">
                      <Badge variant="secondary" className="self-start">
                        test
                      </Badge>
                      {d.triggered_by_email && (
                        <span
                          className="text-[10px] text-muted-foreground"
                          title={`Triggered by ${d.triggered_by_email}`}
                        >
                          by {d.triggered_by_email}
                        </span>
                      )}
                    </div>
                  ) : (
                    <Badge variant="outline">{d.trigger}</Badge>
                  )}
                </TableCell>
                <TableCell className="max-w-[220px]">
                  <div className="flex items-center gap-2 text-xs">
                    <ChannelIcon className="size-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium">{channelLabel}</div>
                      {d.channel_type && (
                        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          {d.channel_type}
                          {d.user_channel_id && " · personal"}
                        </div>
                      )}
                    </div>
                  </div>
                </TableCell>
                <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                  {d.task_name ?? d.task_id ?? "-"}
                </TableCell>
                <TableCell>
                  <Badge
                    variant={
                      d.status === "sent"
                        ? "success"
                        : d.status === "skipped"
                          ? "muted"
                          : "destructive"
                    }
                  >
                    {d.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {d.response_code ?? "-"}
                  {d.error && (
                    <span className="ml-1 text-destructive" title={d.error}>
                      ⚠
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <DateCell value={d.sent_at} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
