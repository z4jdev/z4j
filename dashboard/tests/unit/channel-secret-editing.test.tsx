import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

const state = vi.hoisted(() => ({
  channels: [] as Record<string, unknown>[],
  update: vi.fn(),
  create: vi.fn(),
}));

vi.mock("@/hooks/use-notifications", () => {
  const query = () => ({ data: state.channels, isLoading: false });
  const mutation = () => ({ mutate: vi.fn(), isPending: false });
  return {
    useChannels: query,
    useUserChannels: query,
    useCreateChannel: () => ({ mutate: state.create }),
    useCreateUserChannel: () => ({ mutate: state.create }),
    useUpdateChannel: () => ({ mutate: state.update }),
    useUpdateUserChannel: () => ({ mutate: state.update }),
    useDeleteChannel: mutation,
    useDeleteUserChannel: mutation,
    useImportChannelFromUser: mutation,
    useImportUserChannelFromProject: mutation,
    useTestChannel: mutation,
    useTestUserChannel: mutation,
    useTestChannelConfig: mutation,
    useTestUserChannelConfig: mutation,
  };
});
vi.mock("@/hooks/use-projects", () => ({ useProjects: () => ({ data: [] }) }));
vi.mock("@/components/domain/confirm-dialog", () => ({
  useConfirm: () => ({ confirm: vi.fn(), dialog: null }),
}));

import { ProjectChannelsTab } from "@/components/notifications/project-channels-tab";
import { MyChannelsTab } from "@/components/notifications/my-channels-tab";

beforeEach(() => {
  vi.clearAllMocks();
  state.channels = [];
});

describe.each(["project", "personal"])("%s channel credential editing", (scope) => {
  it.each(["webhook", "slack", "discord", "teams"])(
    "renames a saved %s channel while retaining its masked destination",
    (type) => {
      const key = type === "webhook" ? "url" : "webhook_url";
      state.channels = [{
        id: "channel-id", name: "Operations", type, is_active: true,
        config: { [key]: "••••••••" },
        created_at: "2026-10-15T12:00:00Z", updated_at: "2026-10-15T12:00:00Z",
      }];
      render(scope === "project" ? <ProjectChannelsTab slug="team" /> : <MyChannelsTab />);
      fireEvent.click(screen.getByRole("button", { name: "Edit Operations" }));
      const dialog = screen.getByRole("dialog");
      const destination = dialog.querySelector<HTMLInputElement>('input[type="url"]')!;
      expect(destination).toHaveValue("");
      expect(destination).not.toBeRequired();
      expect(destination).toHaveAttribute("placeholder", "Leave blank to keep current");
      fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Renamed" } });
      expect(destination.form!.checkValidity()).toBe(true);
      fireEvent.submit(destination.form!);
      expect(state.update).toHaveBeenLastCalledWith(
        { id: "channel-id", body: { name: "Renamed", config: {} } }, expect.anything(),
      );
      fireEvent.change(destination, { target: { value: "https://replacement.example.com/new" } });
      fireEvent.submit(destination.form!);
      expect(state.update).toHaveBeenLastCalledWith(
        { id: "channel-id", body: { name: "Renamed", config: { [key]: "https://replacement.example.com/new" } } },
        expect.anything(),
      );
    },
  );
});
