import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiCallSpy = vi.hoisted(() => vi.fn());
const postSpy = vi.hoisted(() => vi.fn());

vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: (...args: unknown[]) => postSpy(...args),
    delete: vi.fn(),
  },
  apiCall: (...args: unknown[]) => apiCallSpy(...args),
}));

import {
  useAcceptInvitation,
  useInvitationPreview,
  useMintInvitation,
} from "@/hooks/use-invitations";

function harness() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  apiCallSpy.mockReset();
  postSpy.mockReset();
});

describe("invitation bearer transport", () => {
  it("does not retain a successful one-time mint response", async () => {
    const token = "M".repeat(43);
    const minted = {
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
    postSpy.mockResolvedValue(minted);
    const { queryClient, wrapper } = harness();
    const { result } = renderHook(() => useMintInvitation("project"), {
      wrapper,
    });

    await act(async () => {
      await expect(
        result.current.mutateAsync({
          email: "invitee@example.com",
          role: "viewer",
        }),
      ).resolves.toEqual(minted);
    });

    expect(result.current.isPending).toBe(false);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(JSON.stringify(result.current)).not.toContain(token);
  });

  it("does not retain reflected data after a failed mint", async () => {
    const reflected = "R".repeat(43);
    postSpy.mockRejectedValue(new Error(`failed ${reflected}`));
    const { queryClient, wrapper } = harness();
    const { result } = renderHook(() => useMintInvitation("project"), {
      wrapper,
    });

    await act(async () => {
      await expect(
        result.current.mutateAsync({
          email: "invitee@example.com",
          role: "viewer",
        }),
      ).rejects.toThrow("failed");
    });

    expect(result.current.isPending).toBe(false);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(JSON.stringify(result.current)).not.toContain(reflected);
  });

  it("posts preview in JSON without putting the token in URL or query caches", async () => {
    const token = "T".repeat(43);
    const preview = {
      email: "invitee@example.com",
      role: "viewer",
      project_slug: "secret-project",
      project_name: "Secret Project",
      expires_at: "2030-01-01T00:00:00Z",
    };
    apiCallSpy.mockResolvedValue(preview);
    const { queryClient, wrapper } = harness();

    const { result } = renderHook(() => useInvitationPreview(token), {
      wrapper,
    });

    await waitFor(() => expect(result.current.data).toEqual(preview));

    expect(apiCallSpy).toHaveBeenCalledTimes(1);
    const [path, options] = apiCallSpy.mock.calls[0] as [
      string,
      Record<string, unknown>,
    ];
    expect(path).toBe("/invitations/preview");
    expect(path).not.toContain(token);
    expect(options).toMatchObject({ method: "POST", body: { token } });
    expect(options).not.toHaveProperty("query");
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(JSON.stringify(result.current)).not.toContain(token);
  });

  it("retains only a generic preview error flag", async () => {
    const token = "E".repeat(43);
    apiCallSpy.mockRejectedValue(
      new Error(`transport accidentally reflected ${token}`),
    );
    const { queryClient, wrapper } = harness();

    const { result } = renderHook(() => useInvitationPreview(token), {
      wrapper,
    });

    await waitFor(() => expect(result.current.isError).toBe(true));

    expect(result.current.data).toBeUndefined();
    expect(JSON.stringify(result.current)).not.toContain(token);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  });

  it("does not retain accept credentials in mutation-cache metadata", async () => {
    const token = "A".repeat(43);
    const body = {
      token,
      display_name: "Invitee",
      password: "Correct-Horse-Battery-9!",
    };
    const accepted = {
      user_id: "00000000-0000-0000-0000-000000000001",
      project_slug: "secret-project",
      role: "viewer",
    };
    postSpy.mockResolvedValue(accepted);
    const { queryClient, wrapper } = harness();
    const { result } = renderHook(() => useAcceptInvitation(), { wrapper });

    await act(async () => {
      await expect(result.current.mutateAsync(body)).resolves.toEqual(accepted);
    });

    expect(postSpy).toHaveBeenCalledWith("/invitations/accept", body);
    expect(result.current.isPending).toBe(false);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(JSON.stringify(result.current)).not.toContain(token);
  });

  it("does not retain accept credentials after failure", async () => {
    const token = "F".repeat(43);
    const password = "Correct-Horse-Battery-9!";
    postSpy.mockRejectedValue(new Error(`failed ${token} ${password}`));
    const { queryClient, wrapper } = harness();
    const { result } = renderHook(() => useAcceptInvitation(), { wrapper });

    await act(async () => {
      await expect(
        result.current.mutateAsync({
          token,
          display_name: "Invitee",
          password,
        }),
      ).rejects.toThrow("failed");
    });

    expect(result.current.isPending).toBe(false);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    const retainedState = JSON.stringify(result.current);
    expect(retainedState).not.toContain(token);
    expect(retainedState).not.toContain(password);
  });
});
