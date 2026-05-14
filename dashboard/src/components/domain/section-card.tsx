import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

export interface SectionCardProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Right-aligned action area in the card header. */
  actions?: React.ReactNode;
  /** Renders a `read-only` badge inline with the title. */
  readOnly?: boolean;
  /** Custom badges (overrides `readOnly` if provided). */
  badges?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}

/**
 * Canonical Card-with-Header used inside every page. Wraps the
 * shadcn Card primitives so consumers don't have to wire CardHeader,
 * CardTitle, CardDescription, and the title-row layout each time.
 *
 * Visual contract is the same as the other primitives:
 *   - title + description sit in a CardHeader (px-6 py-5).
 *   - badges (e.g. `read-only`) appear inline with the title.
 *   - actions sit on the far right of the header row.
 *   - children render in CardContent (px-6, last-child pb-6).
 *
 * Don't roll your own `<Card className="p-6"><h3>...</h3>` inside
 * a page - it skips the CardHeader padding contract and ends up
 * looking different from every other card in the dashboard.
 */
export function SectionCard({
  title,
  description,
  actions,
  readOnly,
  badges,
  className,
  children,
}: SectionCardProps) {
  const resolvedBadges =
    badges ?? (readOnly ? <Badge variant="muted">read-only</Badge> : null);

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle>{title}</CardTitle>
              {resolvedBadges}
            </div>
            {description && (
              <CardDescription className={cn("mt-1")}>
                {description}
              </CardDescription>
            )}
          </div>
          {actions && (
            <div className="flex shrink-0 items-center gap-2">{actions}</div>
          )}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}
