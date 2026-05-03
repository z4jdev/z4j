/**
 * Component tests for ``VersionMismatchBanner``.
 *
 * The banner is the operator's first signal that an agent in the
 * project is advertising an older wire-protocol than the brain
 * currently supports. The decision to render hangs off the
 * computed ``is_outdated`` field returned by the brain; this
 * test exercises the render / no-render boundary and the plural
 * / truncation text paths.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { VersionMismatchBanner } from "@/components/domain/version-mismatch-banner";
import type { AgentPublic } from "@/lib/api-types";

// TanStack Router's ``Link`` needs a router context in tests; we
// shim it to a plain anchor so the banner can render without
// spinning up a full router.
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
  }: {
    children: React.ReactNode;
    className?: string;
  }) => (
    <a href="#" className={className}>
      {children}
    </a>
  ),
}));

const agentsSpy = vi.fn();
vi.mock("@/hooks/use-agents", () => ({
  useAgents: () => agentsSpy(),
}));

function renderBanner() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <VersionMismatchBanner slug="default" />
    </QueryClientProvider>,
  );
}

function agent(name: string, is_outdated: boolean): AgentPublic {
  return {
    id: `id-${name}`,
    project_id: "p",
    name,
    state: "online",
    protocol_version: is_outdated ? "1" : "2",
    framework_adapter: "bare",
    engine_adapters: ["celery"],
    scheduler_adapters: [],
    capabilities: {},
    last_seen_at: null,
    last_connect_at: "2026-04-20T10:00:00Z",
    created_at: "2026-04-20T10:00:00Z",
    is_outdated,
  };
}

describe("VersionMismatchBanner", () => {
  it("renders nothing when no agents are outdated", () => {
    agentsSpy.mockReturnValue({
      data: [agent("web-01", false), agent("worker-01", false)],
    });
    const { container } = renderBanner();
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when the agents query is still loading", () => {
    agentsSpy.mockReturnValue({ data: undefined });
    const { container } = renderBanner();
    expect(container.firstChild).toBeNull();
  });

  it("uses singular copy for exactly one outdated agent", () => {
    agentsSpy.mockReturnValue({
      data: [agent("web-01", true), agent("worker-01", false)],
    });
    renderBanner();
    expect(
      screen.getByText(/1 agent is on an older wire protocol/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/web-01/)).toBeInTheDocument();
  });

  it("uses plural copy and lists every name when <= 3 outdated", () => {
    agentsSpy.mockReturnValue({
      data: [
        agent("a", true),
        agent("b", true),
        agent("c", true),
      ],
    });
    renderBanner();
    expect(
      screen.getByText(/3 agents are on an older wire protocol/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/a, b, c/)).toBeInTheDocument();
  });

  it("truncates with 'and N more' when more than three are outdated", () => {
    agentsSpy.mockReturnValue({
      data: [
        agent("a", true),
        agent("b", true),
        agent("c", true),
        agent("d", true),
        agent("e", true),
      ],
    });
    renderBanner();
    expect(
      screen.getByText(/5 agents are on an older wire protocol/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/a, b, c and 2 more/),
    ).toBeInTheDocument();
  });
});
