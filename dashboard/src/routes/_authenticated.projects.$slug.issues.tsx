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
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Bug } from "lucide-react";
import { PageShell } from "@/components/domain/page-shell";
import { PageHeader } from "@/components/domain/page-header";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatRelative } from "@/lib/format";
import { useIssues, type IssueFilters } from "@/hooks/use-issues";

export const Route = createFileRoute("/_authenticated/projects/$slug/issues")({
  component: IssuesPage,
});

type StatusFilter = "all" | "ongoing" | "recovered";

const FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "ongoing", label: "Ongoing" },
  { key: "recovered", label: "Recovered" },
];

function IssuesPage() {
  const { slug } = Route.useParams();
  const [status, setStatus] = useState<StatusFilter>("all");
  const filters: IssueFilters = status === "all" ? {} : { status };
  const { data: issues, isLoading } = useIssues(slug, filters);

  return (
    <PageShell>
      <PageHeader
        title="Issues"
        icon={Bug}
        description="task failures grouped by a stable fingerprint, so the same bug across runs and engines collapses to a single issue"
      />

      <div className="flex gap-1">
        {FILTERS.map((f) => (
          <Button
            key={f.key}
            size="sm"
            variant={status === f.key ? "default" : "outline"}
            onClick={() => setStatus(f.key)}
          >
            {f.label}
          </Button>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : !issues || issues.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="no issues"
          description={
            status === "all"
              ? "Nothing has failed on this project yet, or every failure recovered and aged out of the window."
              : `No ${status} issues.`
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Issue</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Occurrences</TableHead>
                <TableHead className="text-right">Open / recovered</TableHead>
                <TableHead>Engines</TableHead>
                <TableHead>Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {issues.map((issue) => (
                <TableRow key={issue.fingerprint}>
                  <TableCell className="max-w-md">
                    <div className="truncate font-medium">
                      {issue.sample_exception ?? "unknown error"}
                    </div>
                    {issue.sample_task_name ? (
                      <div className="truncate font-mono text-xs text-muted-foreground">
                        {issue.sample_task_name}
                      </div>
                    ) : null}
                    <div className="font-mono text-[10px] text-muted-foreground/70">
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
        </div>
      )}
    </PageShell>
  );
}
