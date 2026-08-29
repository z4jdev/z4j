import { AlertTriangle, CheckCircle2, Info } from "lucide-react";
import { SectionCard } from "@/components/domain/section-card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useWorkerLint } from "@/hooks/use-workers";
import type { LintFindingPublic, WorkerLintPublic } from "@/lib/api-types";

const SEVERITY_VARIANT: Record<string, "destructive" | "warning" | "secondary"> = {
  high: "destructive",
  medium: "warning",
  low: "secondary",
};

function Finding({ finding }: { finding: LintFindingPublic }) {
  return (
    <li className="border-l-2 border-[var(--color-border)] pl-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={SEVERITY_VARIANT[finding.severity] ?? "outline"}>
          {finding.severity}
        </Badge>
        <span className="font-medium">{finding.title}</span>
        <code className="text-xs text-muted-foreground">{finding.setting}</code>
      </div>
      <p className="mt-1 text-sm text-muted-foreground">{finding.detail}</p>
      <p className="mt-1 text-sm">
        <span className="font-medium">Fix: </span>
        {finding.remedy}
      </p>
    </li>
  );
}

function WorkerFindings({ worker }: { worker: WorkerLintPublic }) {
  if (worker.findings.length === 0) return null;
  return (
    <div>
      <div className="mb-2 flex items-center gap-2 text-sm">
        <span className="font-medium">{worker.worker_name}</span>
        <Badge variant="outline">{worker.engine}</Badge>
        {worker.hostname ? (
          <span className="text-muted-foreground">{worker.hostname}</span>
        ) : null}
      </div>
      <ul className="space-y-3">
        {worker.findings.map((f) => (
          <Finding key={`${worker.worker_id}-${f.rule_id}`} finding={f} />
        ))}
      </ul>
    </div>
  );
}

/**
 * Dangerous worker defaults, read from the configuration workers already
 * report on their heartbeat.
 *
 * The panel repeats the endpoint's own honesty about what it did not judge.
 * A worker whose engine has no rules, or which reported no configuration, is
 * counted as not evaluated rather than folded into a clean result, because
 * presenting it as "no problems found" would overstate what the check knows.
 */
export function WorkerLintPanel({ slug }: { slug: string }) {
  const { data, isPending, isError } = useWorkerLint(slug);

  if (isPending) {
    return (
      <SectionCard title="Configuration lint" description="Reading reported worker settings.">
        <Skeleton className="h-16 w-full" />
      </SectionCard>
    );
  }

  // A payload without a workers array is treated like an error: this panel is
  // advisory, and a crash on an unexpected shape would take the Workers page
  // down with it. The shape is guaranteed by the brain, not by every proxy or
  // mock that might sit in front of it. Checked after the pending branch, or
  // the skeleton could never render.
  if (isError || !data || !Array.isArray(data.workers)) return null;

  const withFindings = data.workers.filter((w) => w.findings.length > 0);
  const total = Object.values(data.findings_by_severity).reduce((a, b) => a + b, 0);

  const notEvaluated =
    data.workers_not_evaluated > 0 ? (
      <p className="mt-3 flex items-start gap-2 text-sm text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0" />
        <span>
          {data.workers_not_evaluated}{" "}
          {data.workers_not_evaluated === 1 ? "worker was" : "workers were"} not
          evaluated, because their engine has no rules yet or they reported no
          configuration. That is not the same as a clean result.
        </span>
      </p>
    ) : null;

  return (
    <SectionCard
      title="Configuration lint"
      description="Settings that can lose or duplicate work, read from what each worker already reports."
      badges={
        total > 0 ? (
          <Badge variant="warning">
            {total} {total === 1 ? "finding" : "findings"}
          </Badge>
        ) : (
          <Badge variant="outline">{data.workers_evaluated} evaluated</Badge>
        )
      }
    >
      {withFindings.length === 0 ? (
        <div className="flex items-start gap-2 text-sm">
          <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-[var(--color-success)]" />
          <span>
            No dangerous defaults found on the{" "}
            {data.workers_evaluated}{" "}
            {data.workers_evaluated === 1 ? "worker" : "workers"} that were
            evaluated.
          </span>
        </div>
      ) : (
        <div className="space-y-5">
          <p className="flex items-start gap-2 text-sm text-muted-foreground">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>
              Advisory only. Nothing here changes a worker, and a finding is a
              prompt to look rather than a fault.
            </span>
          </p>
          {withFindings.map((w) => (
            <WorkerFindings key={w.worker_id} worker={w} />
          ))}
        </div>
      )}
      {notEvaluated}
    </SectionCard>
  );
}
