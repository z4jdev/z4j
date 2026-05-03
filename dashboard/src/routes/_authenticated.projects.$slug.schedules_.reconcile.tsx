/**
 * Schedules reconciliation diff view (docs/SCHEDULER.md §13.1).
 *
 * Operator pastes the JSON output of their declarative
 * reconciler (Z4J["schedules"] from Django/FastAPI/Flask, or the
 * JSONL from `z4j-scheduler import --dry-run`) into the textarea
 * and gets a 4-bucket preview of what `:import` would do, without
 * any side effects on brain state. Mirrors the CLI's
 * `import --verify` flag.
 *
 * Backend contract: POST /api/v1/projects/{slug}/schedules:diff
 * (see brain api/schedules.py). The endpoint requires ADMIN to
 * mirror :import's role gate.
 */
import { useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  Diff,
  GitCompare,
  MinusCircle,
  PlayCircle,
  PlusCircle,
  Equal,
} from "lucide-react";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { PageHeader } from "@/components/domain/page-header";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import {
  useScheduleDiff,
  useScheduleImport,
} from "@/hooks/use-schedules";
import { ApiError } from "@/lib/api";
import type {
  ScheduleDiffEntry,
  ScheduleDiffRequest,
  ScheduleDiffResponse,
} from "@/lib/api-types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/schedules_/reconcile",
)({
  component: ReconcilePage,
});

const PLACEHOLDER = `[
  {
    "name": "nightly-report",
    "engine": "celery",
    "scheduler": "z4j-scheduler",
    "kind": "cron",
    "expression": "0 3 * * *",
    "task_name": "reports.nightly",
    "source": "declarative:django",
    "source_hash": "abc123..."
  }
]`;

function ReconcilePage() {
  const { slug } = Route.useParams();
  const diff = useScheduleDiff(slug);
  const importSchedules = useScheduleImport(slug);
  const { confirm, dialog: confirmDialog } = useConfirm();

  const [pasted, setPasted] = useState("");
  const [mode, setMode] = useState<ScheduleDiffRequest["mode"]>("upsert");
  const [sourceFilter, setSourceFilter] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  // Parse the textarea on every keystroke so the operator gets
  // immediate feedback if their JSON is malformed - no silent
  // 422 from the backend on Run.
  const parsedSchedules = useMemo(() => {
    if (!pasted.trim()) {
      setParseError(null);
      return null;
    }
    try {
      const value = JSON.parse(pasted);
      if (!Array.isArray(value)) {
        setParseError("Top-level value must be a JSON array of schedules");
        return null;
      }
      setParseError(null);
      return value as Array<Record<string, unknown>>;
    } catch (err) {
      setParseError((err as Error).message);
      return null;
    }
  }, [pasted]);

  async function onRun() {
    if (!parsedSchedules) {
      toast.error("Fix the JSON first");
      return;
    }
    if (mode === "replace_for_source" && !sourceFilter && parsedSchedules.length === 0) {
      toast.error(
        "replace_for_source with an empty batch needs an explicit source_filter",
      );
      return;
    }
    try {
      await diff.mutateAsync({
        mode,
        source_filter: sourceFilter || undefined,
        schedules: parsedSchedules,
      });
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`diff failed: ${message}`);
    }
  }

  const result = diff.data;

  /**
   * Apply the same body that produced ``result`` via :import. The
   * confirmation routes through ``useConfirm`` because (a) for
   * replace_for_source the operator is about to delete schedules
   * the diff just listed, and (b) even upsert mode is a real
   * mutation that deserves a "yes I'm sure" gate. The CLI gate is
   * "you typed it twice"; the dashboard gate is the modal.
   */
  function onApply() {
    if (!parsedSchedules || !result) return;

    const summary = result.summary;
    const destructive = mode === "replace_for_source" && summary.delete > 0;
    confirm({
      title: destructive
        ? `Apply diff and delete ${summary.delete} schedule${summary.delete === 1 ? "" : "s"}?`
        : `Apply diff (${summary.insert + summary.update} change${summary.insert + summary.update === 1 ? "" : "s"})?`,
      description: (
        <>
          About to apply: <strong>{summary.insert} insert</strong> /
          {" "}<strong>{summary.update} update</strong> /
          {" "}<strong>{summary.unchanged} unchanged</strong>
          {destructive && (
            <>
              {" "}/ <strong className="text-destructive">{summary.delete} delete</strong>
            </>
          )}
          .{" "}
          {destructive && (
            <>
              The deletes are permanent. Run the diff again from
              the same source after applying to confirm the result
              matches your expectation.
            </>
          )}
        </>
      ),
      variant: destructive ? "destructive" : "default",
      confirmLabel: destructive ? "Apply + delete" : "Apply",
      onConfirm: async () => {
        try {
          const r = await importSchedules.mutateAsync({
            mode,
            source_filter: sourceFilter || undefined,
            schedules: parsedSchedules,
          });
          const failedCount = r.failed;
          if (failedCount > 0) {
            toast.warning(
              `Applied with ${failedCount} failure${failedCount === 1 ? "" : "s"}: inserted=${r.inserted} updated=${r.updated} deleted=${r.deleted}`,
            );
          } else {
            toast.success(
              `Applied: inserted=${r.inserted} updated=${r.updated} unchanged=${r.unchanged} deleted=${r.deleted}`,
            );
          }
        } catch (err) {
          const message =
            err instanceof ApiError ? err.message : (err as Error).message;
          toast.error(`apply failed: ${message}`);
        }
      },
    });
  }

  return (
    <div className="space-y-6 p-4 md:p-6">
      <Link
        to="/projects/$slug/schedules"
        params={{ slug }}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3" />
        back to schedules
      </Link>

      <PageHeader
        title="Reconciliation diff"
        icon={GitCompare}
        description="Preview what `import` would do, without applying anything"
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Input</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="mode">Mode</Label>
              <Select
                value={mode}
                onValueChange={(v) =>
                  setMode(v as ScheduleDiffRequest["mode"])
                }
              >
                <SelectTrigger id="mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="upsert">upsert</SelectItem>
                  <SelectItem value="replace_for_source">
                    replace_for_source
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="source-filter">
                Source filter{" "}
                <span className="text-xs font-normal text-muted-foreground">
                  (optional, used by replace_for_source to scope the
                  delete bucket)
                </span>
              </Label>
              <Input
                id="source-filter"
                placeholder="declarative:django"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="schedules-json">
              Schedules (JSON array)
            </Label>
            <Textarea
              id="schedules-json"
              className="min-h-[240px] font-mono text-xs"
              placeholder={PLACEHOLDER}
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              spellCheck={false}
            />
            {parseError && (
              <p className="flex items-center gap-1 text-xs text-destructive">
                <AlertTriangle className="size-3" />
                {parseError}
              </p>
            )}
            {parsedSchedules && (
              <p className="text-xs text-muted-foreground">
                Parsed {parsedSchedules.length} schedule
                {parsedSchedules.length === 1 ? "" : "s"}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={onRun}
              disabled={diff.isPending || !!parseError || !parsedSchedules}
            >
              <Diff className="size-4" />
              {diff.isPending ? "Running..." : "Run diff"}
            </Button>
            <span className="text-xs text-muted-foreground">
              No side effects, this never writes to brain.
            </span>
          </div>
        </CardContent>
      </Card>

      {diff.isPending && <Skeleton className="h-40 w-full" />}
      {result && (
        <DiffResultPanel
          result={result}
          onApply={onApply}
          applyDisabled={importSchedules.isPending || !parsedSchedules}
          applyPending={importSchedules.isPending}
        />
      )}
      {confirmDialog}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result panel
// ---------------------------------------------------------------------------

function DiffResultPanel({
  result,
  onApply,
  applyDisabled,
  applyPending,
}: {
  result: ScheduleDiffResponse;
  onApply: () => void;
  applyDisabled: boolean;
  applyPending: boolean;
}) {
  // Apply is enabled whenever there's at least one bucket that
  // would mutate state. A diff that's all-unchanged + zero deletes
  // = no-op; surfacing the button there would be confusing.
  const hasChanges =
    result.summary.insert + result.summary.update + result.summary.delete > 0;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <SummaryBar summary={result.summary} />
        {hasChanges && (
          <Button
            onClick={onApply}
            disabled={applyDisabled}
            className="shrink-0"
          >
            <Check className="size-4" />
            {applyPending ? "Applying..." : "Apply this diff"}
          </Button>
        )}
      </div>

      <DiffBucket
        title="Insert"
        kind="insert"
        entries={result.inserted}
        icon={PlusCircle}
        emptyText="No new schedules in the batch."
      />
      <DiffBucket
        title="Update"
        kind="update"
        entries={result.updated}
        icon={PlayCircle}
        emptyText="No content changes in matching schedules."
      />
      <DiffBucket
        title="Delete"
        kind="delete"
        entries={result.deleted}
        icon={MinusCircle}
        emptyText="No deletions (only populated for replace_for_source mode)."
      />
      <DiffBucket
        title="Unchanged"
        kind="unchanged"
        entries={result.unchanged}
        icon={Equal}
        emptyText="No no-op rows in the batch."
        defaultCollapsed
      />
    </div>
  );
}

function SummaryBar({
  summary,
}: {
  summary: ScheduleDiffResponse["summary"];
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SummaryPill kind="insert" label="insert" count={summary.insert} />
      <SummaryPill kind="update" label="update" count={summary.update} />
      <SummaryPill kind="delete" label="delete" count={summary.delete} />
      <SummaryPill
        kind="unchanged"
        label="unchanged"
        count={summary.unchanged}
      />
      <span className="ml-auto text-xs text-muted-foreground">
        total: {summary.total}
      </span>
    </div>
  );
}

const KIND_STYLE: Record<
  "insert" | "update" | "delete" | "unchanged",
  string
> = {
  insert:
    "border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400",
  update:
    "border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  delete:
    "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
  unchanged:
    "border-muted-foreground/20 bg-muted text-muted-foreground",
};

function SummaryPill({
  kind,
  label,
  count,
}: {
  kind: keyof typeof KIND_STYLE;
  label: string;
  count: number;
}) {
  return (
    <Badge
      variant="outline"
      className={cn("gap-2 px-2.5 py-1 text-xs", KIND_STYLE[kind])}
    >
      <span className="font-mono uppercase tracking-wide">{label}</span>
      <span className="tabular-nums font-bold">{count}</span>
    </Badge>
  );
}

function DiffBucket({
  title,
  kind,
  entries,
  icon: Icon,
  emptyText,
  defaultCollapsed,
}: {
  title: string;
  kind: keyof typeof KIND_STYLE;
  entries: ScheduleDiffEntry[];
  icon: typeof PlusCircle;
  emptyText: string;
  defaultCollapsed?: boolean;
}) {
  const [open, setOpen] = useState(!defaultCollapsed);
  return (
    <Card>
      <CardHeader
        className="flex cursor-pointer flex-row items-center justify-between space-y-0 pb-2"
        onClick={() => setOpen((v) => !v)}
      >
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon className={cn("size-4", KIND_STYLE[kind].split(" ").pop())} />
          {title}
          <Badge variant="outline" className={cn("text-[10px]", KIND_STYLE[kind])}>
            {entries.length}
          </Badge>
        </CardTitle>
        <span className="text-xs text-muted-foreground">
          {open ? "click to collapse" : "click to expand"}
        </span>
      </CardHeader>
      {open && (
        <CardContent>
          {entries.length === 0 && (
            <EmptyState
              icon={Icon}
              title="no rows"
              description={emptyText}
            />
          )}
          {entries.length > 0 && (
            <div className="space-y-3">
              {entries.map((entry) => (
                <DiffEntryCard key={`${entry.scheduler}/${entry.name}`} kind={kind} entry={entry} />
              ))}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function DiffEntryCard({
  kind,
  entry,
}: {
  kind: keyof typeof KIND_STYLE;
  entry: ScheduleDiffEntry;
}) {
  // For UPDATE rows show a side-by-side current/proposed view
  // limited to the fields that actually differ. For INSERT show
  // proposed only; for DELETE show current only; for UNCHANGED
  // show a compact one-liner.
  if (kind === "unchanged") {
    return (
      <div className="flex items-center gap-2 rounded border border-muted-foreground/20 bg-muted/40 px-3 py-1.5 text-xs">
        <span className="font-mono">{entry.name}</span>
        <span className="text-muted-foreground">
          {String(entry.current.kind ?? "?")} ·{" "}
          {String(entry.current.expression ?? "?")} ·{" "}
          {String(entry.current.task_name ?? "?")}
        </span>
      </div>
    );
  }
  if (kind === "insert") {
    return (
      <div className={cn("rounded border p-3", KIND_STYLE[kind])}>
        <div className="mb-1 font-mono text-xs font-semibold">{entry.name}</div>
        <FieldsTable values={entry.proposed} />
      </div>
    );
  }
  if (kind === "delete") {
    return (
      <div className={cn("rounded border p-3", KIND_STYLE[kind])}>
        <div className="mb-1 font-mono text-xs font-semibold">{entry.name}</div>
        <FieldsTable values={entry.current} />
      </div>
    );
  }
  // update
  const diffs = computeFieldDiffs(entry.current, entry.proposed);
  return (
    <div className={cn("rounded border p-3", KIND_STYLE[kind])}>
      <div className="mb-2 font-mono text-xs font-semibold">{entry.name}</div>
      {diffs.length === 0 && (
        <p className="text-xs text-muted-foreground">
          (source_hash differs but tracked fields are equal, operator
          regenerated the hash without semantic change)
        </p>
      )}
      <div className="space-y-1.5">
        {diffs.map(({ key, current, proposed }) => (
          <div
            key={key}
            className="grid grid-cols-[auto,1fr,1fr] gap-3 font-mono text-xs"
          >
            <span className="text-muted-foreground">{key}</span>
            <span className="text-red-700 line-through dark:text-red-400">
              {formatValue(current)}
            </span>
            <span className="text-green-700 dark:text-green-400">
              {formatValue(proposed)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FieldsTable({ values }: { values: Record<string, unknown> }) {
  const ordered = Object.entries(values).filter(([, v]) => v !== null && v !== undefined && v !== "");
  return (
    <div className="space-y-0.5 font-mono text-[11px]">
      {ordered.map(([key, value]) => (
        <div key={key} className="grid grid-cols-[120px,1fr] gap-2">
          <span className="text-muted-foreground">{key}</span>
          <span>{formatValue(value)}</span>
        </div>
      ))}
    </div>
  );
}

function computeFieldDiffs(
  current: Record<string, unknown>,
  proposed: Record<string, unknown>,
): Array<{ key: string; current: unknown; proposed: unknown }> {
  // Skip identity / metadata fields that always match by definition
  // and source_hash (which obviously differs, since that's why we're
  // here - no need to render it).
  const SKIP = new Set(["name", "scheduler", "source_hash"]);
  const keys = new Set([
    ...Object.keys(current),
    ...Object.keys(proposed),
  ]);
  const out: Array<{ key: string; current: unknown; proposed: unknown }> = [];
  for (const key of keys) {
    if (SKIP.has(key)) continue;
    const a = current[key];
    const b = proposed[key];
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      out.push({ key, current: a, proposed: b });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string") return value;
  if (typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  return JSON.stringify(value);
}
