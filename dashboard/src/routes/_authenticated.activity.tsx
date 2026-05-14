/**
 * Live Activity Feed.
 *
 * Cross-project timeline of audit-log rows, scoped to the user's
 * accessible projects. Backed by ``GET /api/v1/activity`` which
 * filters the underlying audit table by project membership (admins
 * see every row; non-admins see only their memberships).
 *
 * Sections top-to-bottom:
 *
 *   1. Filter bar (project, action prefix)
 *   2. Live timeline -- newest first, polls every 5 seconds via
 *      :func:`useActivityInfinite`. The list is grouped visually
 *      by "minutes ago" buckets so the eye picks out activity
 *      spikes without having to read every timestamp.
 *   3. Load older button (walks ``next_before_id`` backwards).
 */
import { useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  History,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { QueryError } from "@/components/domain/query-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useActivityInfinite,
  type ActivityItem,
} from "@/hooks/use-activity";
import { useMe } from "@/hooks/use-auth";
import { useProjects } from "@/hooks/use-projects";

export const Route = createFileRoute("/_authenticated/activity")({
  component: ActivityPage,
});

const ALL_PROJECTS_VALUE = "__all__";

function ActivityPage() {
  const me = useMe();
  const currentUserId = me.data?.id ?? null;
  const [projectSlug, setProjectSlug] = useState<string>(ALL_PROJECTS_VALUE);
  const [actionPrefix, setActionPrefix] = useState("");

  const filters = useMemo(
    () => ({
      project_slug:
        projectSlug === ALL_PROJECTS_VALUE ? undefined : projectSlug,
      action_prefix: actionPrefix.trim() || undefined,
    }),
    [projectSlug, actionPrefix],
  );

  const query = useActivityInfinite(filters);
  const projects = useProjects();

  const items: ActivityItem[] = useMemo(() => {
    if (!query.data) return [];
    return query.data.pages.flatMap((p) => p.items);
  }, [query.data]);

  const newestCursor = query.data?.pages[0]?.newest_cursor ?? null;
  const hasMore = Boolean(
    query.data?.pages[query.data.pages.length - 1]?.next_before_cursor,
  );

  return (
    <PageShell>
      <PageHeader
        icon={History}
        title="Activity"
        description="Cross-project timeline of audit-log rows. Polls every 5 seconds."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => query.refetch()}
            disabled={query.isFetching}
            title="Force refresh"
          >
            <RefreshCw
              className={`size-4 ${query.isFetching ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-col gap-4 p-4 md:flex-row md:items-end">
          <div className="flex flex-col gap-2 md:w-64">
            <Label htmlFor="activity-project">Project</Label>
            <Select value={projectSlug} onValueChange={setProjectSlug}>
              <SelectTrigger id="activity-project">
                <SelectValue placeholder="All projects" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL_PROJECTS_VALUE}>
                  All projects
                </SelectItem>
                {(projects.data ?? []).map((p) => (
                  <SelectItem key={p.slug} value={p.slug}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-1 flex-col gap-2">
            <Label htmlFor="activity-prefix">Action prefix</Label>
            <Input
              id="activity-prefix"
              placeholder="e.g. task. , user. , agent."
              value={actionPrefix}
              onChange={(e) => setActionPrefix(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-3 text-sm text-muted-foreground md:pb-2">
            <span className="inline-flex size-2 rounded-full bg-primary" />
            Live
            <span className="text-xs">
              {newestCursor
                ? `up to ${newestCursor.split("|")[0]?.slice(11, 19) ?? newestCursor.slice(0, 12)}`
                : "no rows yet"}
            </span>
          </div>
        </CardContent>
      </Card>

      {query.isError && (
        <QueryError
          message={
            isRateLimited(query.error)
              ? "Activity feed polling throttled (60 req/min per worker). Click Refresh once the window resets."
              : `Activity feed: ${query.error?.message ?? "failed to load"}`
          }
          onRetry={() => query.refetch()}
        />
      )}

      <div className="flex flex-col gap-2">
        {query.isLoading && items.length === 0 ? (
          <ActivitySkeleton />
        ) : items.length === 0 ? (
          <EmptyActivity
            hasFilters={Boolean(projectSlug !== ALL_PROJECTS_VALUE || actionPrefix.trim())}
            onClear={() => {
              setProjectSlug(ALL_PROJECTS_VALUE);
              setActionPrefix("");
            }}
          />
        ) : (
          <ActivityList items={items} currentUserId={currentUserId} />
        )}

        {hasMore && (
          <div className="flex justify-center pt-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => query.fetchNextPage()}
              disabled={query.isFetchingNextPage}
            >
              {query.isFetchingNextPage ? (
                <>
                  <RefreshCw className="size-4 animate-spin" />
                  Loading…
                </>
              ) : (
                <>
                  <ChevronRight className="size-4 rotate-90" />
                  Load older
                </>
              )}
            </Button>
          </div>
        )}
      </div>
    </PageShell>
  );
}

function ActivityList({
  items,
  currentUserId,
}: {
  items: ActivityItem[];
  currentUserId: string | null;
}) {
  return (
    <ul className="flex flex-col gap-2">
      {items.map((item) => (
        <li key={item.id}>
          <ActivityRow item={item} currentUserId={currentUserId} />
        </li>
      ))}
    </ul>
  );
}

function ActivityRow({
  item,
  currentUserId,
}: {
  item: ActivityItem;
  currentUserId: string | null;
}) {
  const StatusIcon = pickStatusIcon(item.result, item.outcome);
  const statusColor = pickStatusColor(item.result, item.outcome);
  const statusLabel = pickStatusLabel(item.result, item.outcome);
  return (
    <Card>
      <CardContent className="flex items-start gap-3 p-3">
        <StatusIcon
          className={`mt-0.5 size-4 shrink-0 ${statusColor}`}
          aria-label={statusLabel}
          role="img"
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="truncate font-mono text-sm font-medium">
              {item.action}
            </span>
            {item.project_slug && (
              <Link
                to="/projects/$slug"
                params={{ slug: item.project_slug }}
                className="shrink-0"
              >
                <Badge variant="outline" className="font-mono">
                  {item.project_slug}
                </Badge>
              </Link>
            )}
            {!item.project_slug && (() => {
              // v1.6 Round 6 UX fix: user-scoped rows (MFA enroll,
              // password change, etc.) have project_id NULL but
              // user_id == caller. Rendering them as "brain-wide"
              // would lie about the scope; tag as "personal" so
              // operators don't worry their MFA secret leaked.
              // True brain-wide rows (system bootstrap, no user_id)
              // keep the original badge.
              const isPersonal = (
                currentUserId !== null
                && item.user_id !== null
                && item.user_id === currentUserId
              );
              return (
                <Badge
                  variant="secondary"
                  className="shrink-0"
                >
                  {isPersonal ? "personal" : "brain-wide"}
                </Badge>
              );
            })()}
            <span className="text-xs text-muted-foreground">
              {item.target_type}
              {item.target_id ? ` / ${item.target_id}` : ""}
            </span>
            {item.outcome && item.outcome !== "allow" && (
              <Badge variant="destructive" className="shrink-0">
                {item.outcome}
              </Badge>
            )}
          </div>
          {Object.keys(item.metadata ?? {}).length > 0 && (
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
              {compactMetadata(item.metadata)}
            </p>
          )}
        </div>
        <div className="shrink-0 text-right text-xs text-muted-foreground">
          <DateCell value={item.occurred_at} />
          {item.source_ip && (
            <p className="font-mono">{item.source_ip}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ActivitySkeleton() {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: 6 }).map((_, idx) => (
        <Skeleton key={idx} className="h-16 w-full" />
      ))}
    </div>
  );
}

function EmptyActivity({
  hasFilters,
  onClear,
}: {
  hasFilters: boolean;
  onClear: () => void;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
        <Activity className="size-8" />
        {hasFilters ? (
          <>
            <p className="text-sm">No rows match these filters.</p>
            <p className="text-xs">
              Try clearing the project or action-prefix filter.
            </p>
            <Button variant="outline" size="sm" onClick={onClear}>
              Clear filters
            </Button>
          </>
        ) : (
          <>
            <p className="text-sm">No activity yet.</p>
            <p className="text-xs">
              The feed polls every 5 seconds. Activity will appear as
              rows are written to the audit log.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function isRateLimited(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as { status?: number; message?: string };
  if (err.status === 429) return true;
  return typeof err.message === "string"
    && err.message.toLowerCase().includes("rate limit");
}

function pickStatusIcon(result: string, outcome: string | null) {
  if (result === "success" && (outcome === "allow" || outcome === null)) {
    return CheckCircle2;
  }
  if (outcome === "deny" || outcome === "failure") {
    return XCircle;
  }
  return AlertTriangle;
}

function pickStatusColor(result: string, outcome: string | null) {
  if (result === "success" && (outcome === "allow" || outcome === null)) {
    return "text-emerald-500";
  }
  if (outcome === "deny" || outcome === "failure") {
    return "text-destructive";
  }
  return "text-amber-500";
}

function pickStatusLabel(result: string, outcome: string | null): string {
  if (result === "success" && (outcome === "allow" || outcome === null)) {
    return "succeeded";
  }
  if (outcome === "deny") return "denied";
  if (outcome === "failure") return "failed";
  return "warning";
}

function compactMetadata(meta: Record<string, unknown>): string {
  // Render a compact ``key=value`` line so the audit context is
  // visible without expanding into a JSON tree. Truncate aggressively
  // because the row is one line in the timeline.
  const entries = Object.entries(meta).slice(0, 4);
  return (
    entries
      .map(([k, v]) => `${k}=${stringifyValue(v)}`)
      .join("  ")
      .slice(0, 200) + (entries.length < Object.keys(meta).length ? "  …" : "")
  );
}

function stringifyValue(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return v.length > 40 ? `${v.slice(0, 40)}…` : v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v).slice(0, 60);
  } catch {
    return "<object>";
  }
}
