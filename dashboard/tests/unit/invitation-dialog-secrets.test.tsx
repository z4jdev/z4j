import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const postSpy = vi.hoisted(() => vi.fn());

vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: (...args: unknown[]) => postSpy(...args),
    delete: vi.fn(),
  },
  apiCall: vi.fn(),
  ApiError: class ApiError extends Error {},
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { InviteDialog } from "@/components/domain/invite-dialog";

function mintedResponse(token: string) {
  return {
    invitation: {
      id: "00000000-0000-0000-0000-000000000001",
      project_id: "00000000-0000-0000-0000-000000000002",
      email: "invitee@example.com",
      role: "viewer",
      invited_by: "00000000-0000-0000-0000-000000000003",
      expires_at: "2030-01-01T00:00:00Z",
      accepted_at: null,
      revoked_at: null,
      created_at: "2029-12-01T00:00:00Z",
    },
    token,
    accept_url_path: `/invite#token=${token}`,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  const rendered = render(
    <QueryClientProvider client={queryClient}>
      <InviteDialog slug="project" />
    </QueryClientProvider>,
  );
  return { ...rendered, queryClient };
}

async function submitMint(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Invite" }));
  await user.type(screen.getByLabelText("Email"), "invitee@example.com");
  await user.click(
    screen.getByRole("button", { name: "Generate invite link" }),
  );
}

beforeEach(() => {
  postSpy.mockReset();
});

describe("InviteDialog one-time secret lifetime", () => {
  it("clears the displayed token synchronously when the dialog closes", async () => {
    const user = userEvent.setup();
    const token = "D".repeat(43);
    const inviteUrl = `${window.location.origin}/invite#token=${token}`;
    postSpy.mockResolvedValue(mintedResponse(token));
    const { queryClient } = renderDialog();

    await submitMint(user);

    expect(await screen.findByDisplayValue(inviteUrl)).toBeInTheDocument();
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Done" }));

    expect(screen.queryByDisplayValue(inviteUrl)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(token);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Invite" }));
    expect(screen.getByLabelText("Email")).toHaveValue("");
    expect(screen.queryByDisplayValue(inviteUrl)).not.toBeInTheDocument();
  });

  it("discards a mint response that arrives after close", async () => {
    const user = userEvent.setup();
    const token = "L".repeat(43);
    const pending = deferred<ReturnType<typeof mintedResponse>>();
    postSpy.mockReturnValue(pending.promise);
    const { queryClient } = renderDialog();

    await submitMint(user);
    await waitFor(() => expect(postSpy).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    await act(async () => {
      pending.resolve(mintedResponse(token));
      await pending.promise;
    });

    expect(document.body.innerHTML).not.toContain(token);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Invite" }));
    expect(screen.getByLabelText("Email")).toHaveValue("");
    expect(screen.queryByText("Invitation link ready")).not.toBeInTheDocument();
  });

  it("does not restore a late token after component unmount", async () => {
    const user = userEvent.setup();
    const token = "U".repeat(43);
    const pending = deferred<ReturnType<typeof mintedResponse>>();
    postSpy.mockReturnValue(pending.promise);
    const { queryClient, unmount } = renderDialog();

    await submitMint(user);
    await waitFor(() => expect(postSpy).toHaveBeenCalledTimes(1));
    unmount();

    await act(async () => {
      pending.resolve(mintedResponse(token));
      await pending.promise;
    });

    expect(document.body.innerHTML).not.toContain(token);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  });
});
