import { cn } from "@/lib/utils";

export interface PageShellProps {
  children: React.ReactNode;
  /** Override the default vertical rhythm (defaults to `space-y-6`). */
  spacing?: "sm" | "md" | "lg";
  className?: string;
}

const SPACING: Record<NonNullable<PageShellProps["spacing"]>, string> = {
  sm: "space-y-4",
  md: "space-y-6",
  lg: "space-y-8",
};

/**
 * Canonical page shell. EVERY page route renders its content inside
 * this. It guarantees:
 *
 *   - Consistent horizontal + vertical padding (`p-4 md:p-6`).
 *   - Consistent vertical rhythm between sections (`space-y-6`).
 *   - One place to change the page-frame at any time (don't open
 *     27 route files to bump padding).
 *
 * Pages that need a different rhythm (e.g. dense detail pages) pass
 * `spacing="sm"`. Pages that need NO padding (e.g. nested layouts
 * that handle their own frame) should NOT use PageShell at all.
 *
 * Layouts (settings shell, project-settings shell) are the only
 * exception: they own the frame for their child Outlet. The leaves
 * inside those layouts wrap themselves in a plain `<div class="space-y-6">`,
 * not PageShell, so the layout's padding isn't doubled.
 */
export function PageShell({ children, spacing = "md", className }: PageShellProps) {
  return (
    <div className={cn(SPACING[spacing], "p-4 md:p-6", className)}>
      {children}
    </div>
  );
}
