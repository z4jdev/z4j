import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { LineChart } from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { RefreshButton } from "@/components/domain/refresh-button";
import { StatCard } from "@/components/domain/stat-card";
import { TimeRangeSelect } from "@/components/domain/time-range-select";
import { TrendChart } from "@/components/domain/trend-chart";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useTrends,
  type TrendBucketSize,
  type TrendWindow,
} from "@/hooks/use-trends";

export const Route = createFileRoute("/_authenticated/projects/$slug/trends")({
  component: TrendsPage,
});

const WINDOWS: { value: TrendWindow; label: string }[] = [
  { value: "1h", label: "Last 1 hour" },
  { value: "6h", label: "Last 6 hours" },
  { value: "24h", label: "Last 24 hours" },
  { value: "72h", label: "Last 3 days" },
  { value: "7d", label: "Last 7 days" },
];

// Default bucket size per window - keeps bucket count <= 48.
const DEFAULT_BUCKET: Record<TrendWindow, TrendBucketSize> = {
  "1h": "1m",
  "6h": "5m",
  "24h": "15m",
  "72h": "1h",
  "7d": "1h",
};

function TrendsPage() {
  const { slug } = Route.useParams();
  const [window, setWindow] = useState<TrendWindow>("24h");
  const bucket = DEFAULT_BUCKET[window];
  const { data, isLoading, isFetching, refetch } = useTrends(slug, window, bucket);

  const totals = (data?.series ?? []).reduce(
    (acc, b) => ({
      success: acc.success + b.success,
      failure: acc.failure + b.failure,
      retry: acc.retry + b.retry,
      revoked: acc.revoked + b.revoked,
    }),
    { success: 0, failure: 0, retry: 0, revoked: 0 },
  );
  const total = totals.success + totals.failure;
  const failureRate = total > 0 ? totals.failure / total : 0;

  return (
    <PageShell>
      <PageHeader
        title="Trends"
        icon={LineChart}
        description="task outcomes over time"
        actions={
          <div className="flex items-center gap-2">
            <TimeRangeSelect
              value={window}
              onValueChange={setWindow}
              options={WINDOWS}
              aria-label="Trend window"
            />
            <RefreshButton
              onRefresh={() => refetch()}
              pending={isFetching}
            />
          </div>
        }
      />

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Succeeded" value={totals.success.toLocaleString()} />
        <StatCard label="Failed" value={totals.failure.toLocaleString()} />
        <StatCard
          label="Failure rate"
          value={total === 0 ? "-" : `${(failureRate * 100).toFixed(1)}%`}
        />
        <StatCard label="Retries" value={totals.retry.toLocaleString()} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Outcome timeline</CardTitle>
          <CardDescription>
            bucket size: <span className="font-mono">{bucket}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : (
            <TrendChart series={data?.series ?? []} />
          )}
        </CardContent>
      </Card>
    </PageShell>
  );
}

