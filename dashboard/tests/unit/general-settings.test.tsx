import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const getSpy = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { get: (...args: unknown[]) => getSpy(...args) },
}));

vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (opts: unknown) => opts,
}));

import { GeneralSettingsPage } from "@/routes/_authenticated.settings.general";

const SYSTEM_INFO = {
  z4j_version: "test-build",
  python_version: "test-python",
  python_implementation: "CPython",
  os: "Test OS",
  architecture: "x86_64",
  pid: 1,
  database_type: "PostgreSQL",
};

const CONFIG = {
  z4j_home: "/srv/z4j",
  settings: [
    ["event_retention_days", "17"],
    ["audit_retention_days", "43"],
    ["max_payload_size_bytes", "12288"],
    ["max_ws_frame_bytes", "65536"],
    ["ws_max_frame_bytes", "32768"],
    ["session_absolute_lifetime_seconds", "7200"],
    ["session_idle_timeout_seconds", "900"],
    ["login_lockout_threshold", "8"],
  ].map(([name, value]) => ({
    name,
    value,
    source: "env",
    is_secret: false,
    description: "",
  })),
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <GeneralSettingsPage />
    </QueryClientProvider>,
  );
}

describe("General settings page", () => {
  beforeEach(() => getSpy.mockReset());

  it("renders effective configuration instead of hardcoded defaults", async () => {
    getSpy.mockImplementation((path: string) =>
      Promise.resolve(path === "/admin/settings" ? CONFIG : SYSTEM_INFO),
    );
    renderPage();

    await waitFor(() =>
      expect(screen.getByText("17 days")).toBeInTheDocument(),
    );
    expect(screen.getByText("43 days")).toBeInTheDocument();
    expect(screen.getByText("12 KB")).toBeInTheDocument();
    expect(screen.getByText("32 KB")).toBeInTheDocument();
    expect(screen.getByText("2 hours")).toBeInTheDocument();
    expect(screen.getByText("15 minutes")).toBeInTheDocument();
    expect(screen.getByText("8 failed attempts")).toBeInTheDocument();
    expect(screen.queryByText(/30 days \(default\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/requests\/min/i)).not.toBeInTheDocument();
  });

  it("shows an error instead of invented values when config is unavailable", async () => {
    getSpy.mockImplementation((path: string) =>
      path === "/admin/settings"
        ? Promise.reject(new Error("unavailable"))
        : Promise.resolve(SYSTEM_INFO),
    );
    renderPage();

    await waitFor(() =>
      expect(
        screen.getByText("Failed to load the current brain configuration"),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText(/days \(default\)/i)).not.toBeInTheDocument();
  });
});
