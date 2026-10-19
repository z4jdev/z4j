import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

const state = vi.hoisted(() => ({
  navigate: vi.fn(),
  markRead: vi.fn(),
  projects: undefined as { id: string; slug: string }[] | undefined,
  data: {} as Record<string, unknown>,
}));

vi.mock("@tanstack/react-router", () => ({
  useParams: () => ({ slug: "project-a" }),
  useNavigate: () => state.navigate,
  Link: ({ children, ...props }: React.ComponentProps<"a">) => (
    <a {...props} href="#">
      {children}
    </a>
  ),
}));
vi.mock("@/hooks/use-projects", () => ({
  useProjects: () => ({ data: state.projects }),
}));
vi.mock("@/hooks/use-notifications", () => ({
  useUnreadCount: () => ({ data: { unread: 1 } }),
  useUserNotifications: () => ({
    data: [
      {
        id: "notice-b",
        project_id: "id-b",
        title: "Project B alert",
        trigger: "task.failed",
        read_at: null,
        body: "",
        data: state.data,
        created_at: "2026-10-15T12:00:00Z",
      },
    ],
  }),
  useMarkRead: () => ({ mutate: state.markRead }),
  useMarkAllRead: () => ({ mutate: vi.fn() }),
}));

import { NotificationBell } from "@/components/layout/notification-bell";

async function openNotification() {
  render(<NotificationBell />);
  fireEvent.keyDown(
    screen.getByRole("button", { name: "1 unread notifications" }),
    { key: "ArrowDown" },
  );
  fireEvent.click(await screen.findByText("Project B alert"));
}

beforeEach(() => {
  vi.clearAllMocks();
  state.projects = [
    { id: "id-a", slug: "project-a" },
    { id: "id-b", slug: "project-b" },
  ];
  state.data = { task_id: "resource-b", engine: "celery" };
});

describe("notification destination project", () => {
  it.each([
    [
      "task",
      "/projects/$slug/tasks/$engine/$taskId",
      { slug: "project-b", engine: "celery", taskId: "resource-b" },
    ],
    [
      "schedule",
      "/projects/$slug/schedules/$scheduleId",
      { slug: "project-b", scheduleId: "resource-b" },
    ],
    ["agent", "/projects/$slug/agents", { slug: "project-b" }],
  ])(
    "opens a %s notification in its own project while viewing another project",
    async (resource, to, params) => {
      state.data.resource_type = resource;
      await openNotification();
      expect(state.navigate).toHaveBeenCalledExactlyOnceWith({ to, params });
      expect(state.markRead).toHaveBeenCalledWith(
        "notice-b",
        expect.any(Object),
      );
    },
  );

  it.each([undefined, [{ id: "id-a", slug: "project-a" }]])(
    "does not substitute the current route when the target project is unavailable",
    async (projects) => {
      state.projects = projects;
      await openNotification();
      expect(state.navigate).not.toHaveBeenCalled();
    },
  );
});
