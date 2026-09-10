import { sortTimestamp } from "@/lib/table-sorting";
/**
 * Issues page - task failures grouped by a stable fingerprint (exception
 * class + deepest traceback frames, volatile noise stripped) so the same
 * bug across runs and engines collapses to one row with occurrence counts,
 * an open-vs-recovered split, first/last seen, and the engines affected.
 *
 * VIEWER role: an issue is operational data about tasks the member can
 * already read (no who-did-what), so the whole project can see it. Read
 * only; a rule in the Automation area can condition on a fingerprint to
 * react automatically.
 */

import { EmptyState } from "@/components/domain/empty-state";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
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
import { useIssues, type IssueFilters } from "@/hooks/use-issues";
import { formatRelative } from "@/lib/format";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Bug } from "lucide-react";

export const Route = createFileRoute("/_authenticated/projects/$slug/issues")({
  component: IssuesPage,
  validateSearch: (
    search: Record<string, unknown>,
  ): { status?: StatusFilter } => ({
    status:
      search.status === "ongoing" || search.status === "recovered"
        ? search.status
        : undefined,
  }),
});

type StatusFilter = "all" | "ongoing" | "recovered";

const FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "ongoing", label: "Ongoing" },
  { key: "recovered", label: "Recovered" },
];

function IssuesPage() {
  const { slug } = Route.useParams();
  const { status = "all" } = Route.useSearch();
  const navigate = Route.useNavigate();
  const filters: IssueFilters = status === "all" ? {} : { status };
  const {
    data: issues,
    isLoading,
    isError,
    refetch,
  } = useIssues(slug, filters);

  return (
    <PageShell>
      <PageHeader
        title="Issues"
        icon={Bug}
        description="Recurring failures, grouped across runs and engines."
      />

      <Table
        searchable
        searchPlaceholder="Search issues…"
        isLoading={isLoading}
        error={
          isError
            ? "Issues are unavailable. Their recovery status could not be checked."
            : null
        }
        onRetry={() => refetch()}
        emptyState={
          <EmptyState
            icon={Bug}
            title="No issues in this view"
            description={
              status === "all"
                ? "Nothing has failed on this project yet, or every failure recovered and aged out of the window."
                : `No ${status} issues.`
            }
          />
        }
        filters={
          <div className="flex gap-1">
            {FILTERS.map((f) => (
              <Button
                key={f.key}
                size="sm"
                variant={status === f.key ? "default" : "outline"}
                aria-pressed={status === f.key}
                onClick={() =>
                  navigate({
                    search: { status: f.key === "all" ? undefined : f.key },
                  })
                }
              >
                {f.label}
              </Button>
            ))}
          </div>
        }
      >
        <TableHeader>
          <TableRow>
            <TableHead sortKey="c0">Issue</TableHead>
            <TableHead sortKey="c1">Status</TableHead>
            <TableHead sortKey="c2" className="text-right">
              Occurrences
            </TableHead>
            <TableHead sortKey="c3" className="text-right">
              Open / recovered
            </TableHead>
            <TableHead sortKey="c4">Engines</TableHead>
            <TableHead sortKey="c5">Last seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(issues ?? []).map((issue) => (
            <TableRow
              sortValues={{
                c0: issue.sample_exception,
                c1: issue.status,
                c2: issue.occurrences,
                c3: issue.open_count,
                c4: issue.engines.join(", "),
                c5: sortTimestamp(issue.last_seen),
              }}
              key={issue.fingerprint}
            >
              <TableCell className="max-w-md">
                <details className="group">
                  <summary className="cursor-pointer break-words font-medium">
                    {issue.sample_exception ?? "Unknown error"}
                  </summary>
                  <div className="mt-3 space-y-3 rounded-lg border bg-background p-3 text-sm">
                    <p className="text-muted-foreground">
                      First seen {formatRelative(issue.first_seen)} · Last seen{" "}
                      {formatRelative(issue.last_seen)}
                    </p>
                    <p className="break-all font-mono text-xs">
                      {issue.fingerprint}
                    </p>
                    {issue.sample_task_name && (
                      <Link
                        to="/projects/$slug/tasks"
                        params={{ slug }}
                        search={{ search: issue.sample_task_name }}
                        className="font-medium text-primary underline underline-offset-4"
                      >
                        Search history for this task
                      </Link>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Task history includes other outcomes for this task name.
                    </p>
                  </div>
                </details>
                {issue.sample_task_name ? (
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {issue.sample_task_name}
                  </div>
                ) : null}
                <div className="font-mono text-xs text-muted-foreground">
                  {issue.fingerprint.slice(0, 12)}
                </div>
              </TableCell>
              <TableCell>
                {issue.status === "ongoing" ? (
                  <Badge variant="destructive">ongoing</Badge>
                ) : (
                  <Badge variant="success">recovered</Badge>
                )}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {issue.occurrences}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                <span className={issue.open_count > 0 ? "font-medium" : ""}>
                  {issue.open_count}
                </span>
                <span className="text-muted-foreground">
                  {" / "}
                  {issue.recovered_count}
                </span>
              </TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  {issue.engines.map((engine) => (
                    <Badge key={engine} variant="muted">
                      {engine}
                    </Badge>
                  ))}
                </div>
              </TableCell>
              <TableCell className="whitespace-nowrap text-muted-foreground">
                {formatRelative(issue.last_seen)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </PageShell>
  );
}
