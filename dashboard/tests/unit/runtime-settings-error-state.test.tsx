/**
 * Regression tests for the Runtime config page's failure rendering.
 *
 * The page used to end its loading branch with `if (!data) return null`,
 * so a failed `GET /api/v1/admin/settings` painted a completely blank
 * pane: no heading, no error, no retry. An operator hitting that during
 * a brain outage cannot tell a broken endpoint from a removed feature.
 *
 * These tests pin the three states the page must always distinguish:
 * loading, failed (with a retry affordance), and loaded.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const getSpy = vi.fn();
vi.mock("@/lib/api", () => ({
  api: {
    get: (...args: unknown[]) => getSpy(...args),
  },
}));

// The route module is imported for its component only. Keep the real
// module (the code-splitter injects other router imports into route
// files) and override just the file-route registration so `Route`
// becomes the plain options object.
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (opts: unknown) => opts,
}));

import { RuntimeSettingsPage } from "@/routes/_authenticated.settings.runtime";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RuntimeSettingsPage />
    </QueryClientProvider>,
  );
}

const OK_PAYLOAD = {
  z4j_home: "/var/lib/z4j",
  settings: [
    {
      name: "log_level",
      value: "INFO",
      source: "env",
      is_secret: false,
      description: "Root log level for the brain process.",
    },
    {
      name: "secret",
      value: "***",
      source: "secret.env",
      is_secret: true,
      description: "Master signing key.",
    },
  ],
};

describe("Runtime config page", () => {
  beforeEach(() => {
    getSpy.mockReset();
  });

  it("keeps the heading visible while the query is in flight", () => {
    getSpy.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText("Runtime config")).toBeInTheDocument();
  });

  it("renders heading, message and a retry control when the query fails", async () => {
    getSpy.mockRejectedValue(new Error("brain unreachable"));
    renderPage();

    // The regression: this heading used to disappear entirely.
    expect(screen.getByText("Runtime config")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("brain unreachable")).toBeInTheDocument();
    });
    expect(
      screen.getByRole("button", { name: /retry/i }),
    ).toBeInTheDocument();
  });

  it("renders an error state rather than a blank pane when data is absent", async () => {
    // A resolved-but-empty body is the other route to `!data`, which the
    // old `return null` also swallowed silently. React Query rejects an
    // `undefined` result outright, so `null` is what actually reaches the
    // `!data` branch with `isError` still false.
    getSpy.mockResolvedValue(null);
    renderPage();

    await waitFor(() => {
      expect(
        screen.getByText(/failed to load runtime configuration/i),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Runtime config")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("renders the settings table once data resolves", async () => {
    getSpy.mockResolvedValue(OK_PAYLOAD);
    renderPage();

    await waitFor(() => {
      expect(screen.getByText("log_level")).toBeInTheDocument();
    });
    expect(screen.getByText("/var/lib/z4j")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /retry/i }),
    ).not.toBeInTheDocument();
  });
});
