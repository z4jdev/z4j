/**
 * Top-level React error boundary.
 *
 * Catches render-time exceptions anywhere below the boundary and
 * shows a recoverable fallback instead of React's default white
 * screen. The reload button is the simplest reliable recovery
 * action - the dashboard is a SPA, so a hard reload re-runs
 * route loaders and re-mounts the tree.
 *
 * Logs to console.error in production so operators tailing
 * browser devtools see the original stack trace alongside the
 * fallback UI. We deliberately do NOT auto-report - z4j is
 * self-hosted and the operator owns their telemetry pipeline.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error("z4j dashboard caught an unhandled error", error, info);
  }

  private handleReload = (): void => {
    if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
        <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-sm">
          <h1 className="text-lg font-semibold">Something went wrong</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            The dashboard hit an unexpected error and couldn't render this
            view. Reloading usually clears it. If it keeps happening, the
            full stack trace is in your browser devtools console.
          </p>
          <pre className="mt-4 max-h-40 overflow-auto rounded border bg-muted px-3 py-2 font-mono text-xs">
            {error.message}
          </pre>
          <button
            type="button"
            onClick={this.handleReload}
            className="mt-4 inline-flex h-9 cursor-pointer items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
