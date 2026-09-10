import { render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  project: { data: undefined as { id: string } | undefined, isError: false },
}));
vi.mock("@/hooks/use-projects", () => ({ useProject: () => state.project }));
vi.mock("@/hooks/use-agents", () => ({
  useAgents: () => ({ data: [], refetch: vi.fn() }),
}));
vi.mock("@/hooks/use-tasks", () => ({
  useTasks: () => ({ data: { items: [] }, refetch: vi.fn() }),
}));

import { AgentConnectGuide } from "@/components/domain/agent-connect-guide";

beforeEach(() => {
  state.project = { data: undefined, isError: false };
});

it("waits for the real project UUID before allowing a configuration copy", () => {
  const { rerender } = render(<AgentConnectGuide slug="production" />);
  expect(
    screen.getByRole("button", { name: "Copy environment template" }),
  ).toBeDisabled();
  state.project.data = { id: "00000000-0000-4000-9000-000000000001" };
  rerender(<AgentConnectGuide slug="production" />);
  expect(
    screen.getByRole("button", { name: "Copy environment template" }),
  ).toBeEnabled();
  expect(
    screen.getByText(/Z4J_PROJECT_ID=00000000-0000-4000-9000-000000000001/),
  ).toHaveTextContent("Z4J_TOKEN=<bearer token shown above>");
});

it("makes a failed project lookup visible and keeps incomplete configuration uncopyable", () => {
  state.project.isError = true;
  render(<AgentConnectGuide slug="production" />);
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Project configuration is unavailable",
  );
  expect(
    screen.getByRole("button", { name: "Copy environment template" }),
  ).toBeDisabled();
});
