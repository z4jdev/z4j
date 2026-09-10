import { PageHeader } from "@/components/domain/page-header";
import { PaginationControls } from "@/components/ui/pagination-controls";
import { sortTimestamp } from "@/lib/table-sorting";
/**
 * Personal Notifications hub - "My Delivery History" tab (v1.0.18).
 *
 * Cross-project audit of every notification that fired into one of
 * the user's personal subscriptions. Mirrors the per-project
 * Delivery Log tab but unscoped to the user, with an extra Project
 * column. Deliveries from projects the user is no longer a member
 * of still surface (audit data outlives membership) and get a
 * "you left this project" badge so the row reads honestly.
 */
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useUserDeliveries, type ChannelType } from "@/hooks/use-notifications";
import { useProjects } from "@/hooks/use-projects";
import { Globe, LogOut, Mail, RefreshCw, Send, Webhook } from "lucide-react";
import { useMemo, useState } from "react";

// Same icon map the project deliveries tab uses.
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

export function MyDeliveriesTab() {
  // Cursor stack matches the project deliveries pattern - forward
  // pushes, Back pops, empty stack + null cursor = first page.
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const currentCursor = cursorStack[cursorStack.length - 1];

  const { data, isLoading, isFetching, isError, refetch } = useUserDeliveries(
    PAGE_SIZE,
    currentCursor,
  );
  const deliveries = data?.items;
  const nextCursor = data?.next_cursor ?? null;
  const hasNext = nextCursor !== null;
  const hasPrev = cursorStack.length > 1;
  const pageNumber = cursorStack.length;

  // We need to label each row's project, AND mark rows whose
  // project the user is no longer a member of. ``useProjects``
  // returns the projects the caller currently belongs to; rows
  // whose project_id is NOT in that set get the "you left" badge.
  const { data: projects } = useProjects();
  const projectMap = useMemo(
    () => new Map((projects ?? []).map((p) => [p.id, p])),
    [projects],
  );

  return (
    <div className="space-y-4">
      <PageHeader
        level="section"
        title={
          <>
            Global Notification Log
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </>
        }
        description={
          <>
            Every notification you received across all your projects, plus
            channel-test fires you triggered yourself. Includes deliveries from
            projects you have since left (your historical record outlives your
            membership).
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
            description="Notifications will appear here once your subscriptions start firing."
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
            <TableHead sortKey="c0">Project</TableHead>
            <TableHead sortKey="c1">Trigger</TableHead>
            <TableHead sortKey="c2">Channel</TableHead>
            <TableHead sortKey="c3">Task</TableHead>
            <TableHead sortKey="c4">Status</TableHead>
            <TableHead sortKey="c5" className="text-right">
              Sent
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(deliveries ?? []).map((d) => {
            const project = projectMap.get(d.project_id ?? "");
            const isExMember = !project;
            const isChannelTest = d.trigger === "test.dispatch";
            const ChannelIcon = d.channel_type
              ? (CHANNEL_ICONS[d.channel_type as ChannelType] ?? Globe)
              : Globe;
            const channelLabel =
              d.channel_name ??
              (d.user_channel_id
                ? "(personal channel deleted)"
                : d.channel_id
                  ? "(channel deleted)"
                  : isChannelTest
                    ? "(unsaved test)"
                    : "-");
            return (
              <TableRow
                sortValues={{
                  c0: project?.name ?? "You left",
                  c1: isChannelTest ? "channel test" : d.trigger,
                  c2: channelLabel,
                  c3: d.task_name ?? d.task_id,
                  c4: d.status,
                  c5: sortTimestamp(d.sent_at),
                }}
                key={d.id}
              >
                <TableCell>
                  {project ? (
                    <div className="flex flex-col gap-0.5">
                      <span className="text-sm font-medium">
                        {project.name}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {project.slug}
                      </span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5">
                      <Badge
                        variant="muted"
                        className="text-[10px]"
                        title="You're no longer a member of this project. The delivery still belongs to you historically."
                      >
                        <LogOut className="size-3" />
                        you left
                      </Badge>
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  {isChannelTest ? (
                    <div className="flex flex-col gap-0.5">
                      <Badge
                        variant="muted"
                        className="self-start"
                        title="Channel test you triggered yourself, not a real subscription fire."
                      >
                        channel test
                      </Badge>
                      {d.triggered_by_email && (
                        <span className="text-[10px] text-muted-foreground">
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
                  {isExMember && (
                    <span
                      className="ml-1 text-[10px] text-muted-foreground"
                      title="You're no longer a member of this project"
                    >
                      ·
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
