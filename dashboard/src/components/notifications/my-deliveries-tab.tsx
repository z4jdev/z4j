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
import { useMemo, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  Globe,
  LogOut,
  Mail,
  RefreshCw,
  Send,
  Webhook,
} from "lucide-react";
import {
  DiscordIcon,
  PagerDutyIcon,
  SlackIcon,
  TelegramIcon,
} from "@/components/icons/brand-icons";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DateCell } from "@/components/domain/date-cell";
import {
  useUserDeliveries,
  type ChannelType,
} from "@/hooks/use-notifications";
import { useProjects } from "@/hooks/use-projects";

// Same icon map the project deliveries tab uses.
const CHANNEL_ICONS = {
  webhook: Webhook,
  email: Mail,
  slack: SlackIcon,
  telegram: TelegramIcon,
  pagerduty: PagerDutyIcon,
  discord: DiscordIcon,
} as const;

const PAGE_SIZE = 50;

export function MyDeliveriesTab() {
  // Cursor stack matches the project deliveries pattern - forward
  // pushes, Back pops, empty stack + null cursor = first page.
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const currentCursor = cursorStack[cursorStack.length - 1];

  const { data, isLoading, isFetching } = useUserDeliveries(
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
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">
            Global Notification Log
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </h3>
          <p className="text-xs text-muted-foreground">
            Every notification you received across all your projects,
            plus channel-test fires you triggered yourself. Includes
            deliveries from projects you have since left (your
            historical record outlives your membership).
          </p>
        </div>
      </div>

      {isLoading && <Skeleton className="h-32 w-full" />}
      {deliveries && deliveries.length === 0 && !hasPrev && (
        <EmptyState
          icon={Send}
          title="No deliveries yet"
          description="Notifications will appear here once your subscriptions start firing."
        />
      )}
      {deliveries && deliveries.length > 0 && (
        <>
          <Card className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Channel</TableHead>
                  <TableHead>Task</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Sent</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deliveries.map((d) => {
                  const project = projectMap.get(d.project_id ?? "");
                  const isExMember = !project;
                  const isChannelTest = d.trigger === "test.dispatch";
                  const ChannelIcon = d.channel_type
                    ? CHANNEL_ICONS[d.channel_type as ChannelType] ?? Globe
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
                    <TableRow key={d.id}>
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
                            <div className="truncate font-medium">
                              {channelLabel}
                            </div>
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
          </Card>

          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div>
              Page {pageNumber} · showing {deliveries.length} entries
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={!hasPrev || isFetching}
                onClick={() => setCursorStack((s) => s.slice(0, -1))}
              >
                <ChevronLeft className="size-4" />
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={!hasNext || isFetching}
                onClick={() => setCursorStack((s) => [...s, nextCursor])}
              >
                Next
                <ChevronRight className="size-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
