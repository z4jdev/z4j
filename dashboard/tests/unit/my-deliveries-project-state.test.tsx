import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const state = vi.hoisted(() => ({
  projectId: "id-b" as string | null,
  loading: false,
  projects: undefined as
    { id: string; slug: string; name: string }[] | undefined,
}));
vi.mock("@/hooks/use-projects", () => ({
  useProjects: () => ({ data: state.projects, isLoading: state.loading }),
}));
vi.mock("@/hooks/use-notifications", () => ({
  useUserDeliveries: () => ({
    data: {
      next_cursor: null,
      items: [
        {
          id: "delivery",
          project_id: state.projectId,
          trigger: "test.dispatch",
          status: "sent",
          sent_at: "2026-10-15T12:00:00Z",
          channel_name: "Personal email",
          channel_type: "email",
        },
      ],
    },
    isLoading: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn(),
  }),
}));
import { MyDeliveriesTab } from "@/components/notifications/my-deliveries-tab";

describe("delivery project labels", () => {
  it.each([
    [null, false, [], "No project"],
    ["id-b", true, undefined, "Loading project…"],
    ["id-b", false, undefined, "Project unavailable"],
    ["id-b", false, [], "Project unavailable"],
    [
      "id-b",
      false,
      [{ id: "id-b", name: "Project B", slug: "project-b" }],
      "Project B",
    ],
  ] as const)(
    "labels project %s with loading=%s correctly",
    (id, loading, projects, label) => {
      state.projectId = id;
      state.loading = loading;
      state.projects = projects ? [...projects] : undefined;
      render(<MyDeliveriesTab />);
      expect(screen.getByText(label)).toBeInTheDocument();
      expect(screen.queryByText("you left")).not.toBeInTheDocument();
    },
  );
});
