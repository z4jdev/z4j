import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Download, Filter, Shield } from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { buildAuditExportUrl, useAudit } from "@/hooks/use-audit";
import { DateCell } from "@/components/domain/date-cell";

export const Route = createFileRoute("/_authenticated/projects/$slug/audit")({
  component: AuditPage,
});

const OUTCOMES = ["all", "allow", "deny", "error"] as const;

function AuditPage() {
  const { slug } = Route.useParams();
  const [actionPrefix, setActionPrefix] = useState("");
  const [outcome, setOutcome] = useState<(typeof OUTCOMES)[number]>("all");
  const [cursor, setCursor] = useState<string | null>(null);

  const { data, isLoading } = useAudit(slug, {
    action_prefix: actionPrefix || undefined,
    outcome: outcome === "all" ? undefined : outcome,
    cursor,
  });

  return (
    <>
      <div className="space-y-6 p-4 md:p-6">
        <PageHeader
          title="Audit log"
          icon={Shield}
          description="filter by action prefix or outcome - admin-only"
        />

        <div className="flex flex-col gap-3 sm:flex-row">
          <Input
            placeholder="action prefix (e.g. command.)"
            value={actionPrefix}
            onChange={(e) => {
              setActionPrefix(e.target.value);
              setCursor(null);
            }}
            className="flex-1"
          />
          <Select
            value={outcome}
            onValueChange={(v) => {
              setOutcome(v as (typeof OUTCOMES)[number]);
              setCursor(null);
            }}
          >
            <SelectTrigger className="w-44">
              <Filter className="size-4 opacity-60" />
              <SelectValue placeholder="outcome" />
            </SelectTrigger>
            <SelectContent>
              {OUTCOMES.map((o) => (
                <SelectItem key={o} value={o}>
                  {o}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="gap-2">
                <Download className="size-4" aria-hidden="true" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <a
                  href={buildAuditExportUrl(slug, "csv", {
                    action_prefix: actionPrefix || undefined,
                    outcome: outcome === "all" ? undefined : outcome,
                  })}
                  download
                >
                  CSV
                </a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a
                  href={buildAuditExportUrl(slug, "xlsx", {
                    action_prefix: actionPrefix || undefined,
                    outcome: outcome === "all" ? undefined : outcome,
                  })}
                  download
                >
                  Excel (xlsx)
                </a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a
                  href={buildAuditExportUrl(slug, "json", {
                    action_prefix: actionPrefix || undefined,
                    outcome: outcome === "all" ? undefined : outcome,
                  })}
                  download
                >
                  JSON
                </a>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <Card className="overflow-hidden">
          {isLoading && (
            <div className="space-y-2 p-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          )}
          {data && data.items.length === 0 && (
            <EmptyState
              icon={Shield}
              title="no audit entries match"
              description="commands and admin actions write here automatically"
            />
          )}
          {data && data.items.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead className="text-right">When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="font-mono text-sm">
                      {row.action}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {row.target_type}
                      </span>
                      {row.target_id && (
                        <div className="font-mono text-xs">
                          {row.target_id}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          row.outcome === "allow"
                            ? "success"
                            : row.outcome === "deny"
                              ? "destructive"
                              : "muted"
                        }
                      >
                        {row.outcome ?? row.result}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {row.source_ip ?? "-"}
                    </TableCell>
                    <TableCell className="text-right">
                      <DateCell value={row.occurred_at} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>

        {data && data.next_cursor && (
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!cursor}
              onClick={() => setCursor(null)}
            >
              Top
            </Button>
            <Button size="sm" onClick={() => setCursor(data.next_cursor)}>
              Next page
            </Button>
          </div>
        )}
      </div>
    </>
  );
}
