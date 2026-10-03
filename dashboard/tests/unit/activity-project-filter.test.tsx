/**
 * The activity feed's project filter offers only the projects whose rows
 * the caller can see (instance admin, or the auditor or admin role on the
 * project), and a caller without the audit tier anywhere is told so instead
 * of being offered projects that end in "No rows match these filters".
 */
import { act, render, screen } from "@testing-library/react";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UserMePublic } from "@/lib/api-types";

const state = vi.hoisted(() => ({
  me: undefined as UserMePublic | undefined,
}));

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const React = await import("react");
  const original =
    await importOriginal<typeof import("@tanstack/react-router")>();
  return {
    ...original,
    createFileRoute: (path: string) => (options: Record<string, unknown>) => ({
      ...options,
      options,
      fullPath: path,
    }),
    Link: ({ children }: { children: ReactNode }) =>
      React.createElement("a", { href: "#route" }, children),
  };
});

vi.mock("@/hooks/use-auth", () => ({
  useMe: () => ({ isSuccess: state.me !== undefined, data: state.me }),
}));

vi.mock("@/hooks/use-projects", () => ({
  useProjects: () => ({
    data: [
      { slug: "alpha", name: "Alpha" },
      { slug: "beta", name: "Beta" },
    ],
  }),
}));

vi.mock("@/hooks/use-activity", () => ({
  useActivityInfinite: () => ({
    data: {
      pages: [{ items: [], next_before_cursor: null, newest_cursor: null }],
    },
    error: null,
    isLoading: false,
    isError: false,
    isFetching: false,
    isFetchingNextPage: false,
    refetch: vi.fn(),
    fetchNextPage: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-debounced-value", () => ({
  useDebouncedValue: <T,>(value: T) => value,
}));

vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: ReactNode }) =>
    React.createElement("div", null, children);
  return {
    Select: ({
      children,
      disabled,
    }: {
      children?: ReactNode;
      disabled?: boolean;
    }) =>
      React.createElement(
        "div",
        { role: "listbox", "aria-disabled": disabled ? "true" : "false" },
        children,
      ),
    SelectContent: Part,
    SelectItem: ({ children }: { children?: ReactNode }) =>
      React.createElement("div", { role: "option" }, children),
    SelectTrigger: Part,
    SelectValue: () => null,
  };
});

vi.mock("@/components/domain/filter-toolbar", async () => {
  const React = await import("react");
  return {
    FilterToolbar: ({ filters }: { filters?: ReactNode }) =>
      React.createElement("div", null, filters),
  };
});

vi.mock("@/components/domain/page-header", async () => {
  const React = await import("react");
  return {
    PageHeader: ({ title }: { title: string }) =>
      React.createElement("h1", null, title),
  };
});

vi.mock("@/components/domain/page-shell", async () => {
  const React = await import("react");
  return {
    PageShell: ({ children }: { children: ReactNode }) =>
      React.createElement("main", null, children),
  };
});

vi.mock("@/components/domain/query-error", () => ({ QueryError: () => null }));
vi.mock("@/components/ui/skeleton", () => ({ Skeleton: () => null }));

import { Route as ActivityRoute } from "@/routes/_authenticated.activity";

type PreloadableRouteComponent = ComponentType & {
  preload?: () => Promise<void>;
};

const ActivityPage = (
  ActivityRoute as unknown as {
    options: { component: PreloadableRouteComponent };
  }
).options.component;

// The route component is code-split: resolve the chunk, then render it
// inside the Suspense boundary the router would provide.
async function renderPage() {
  await ActivityPage.preload?.();
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <ActivityPage />
      </Suspense>,
    );
    await Promise.resolve();
  });
}

const NOTE =
  "Project activity needs the auditor or admin role; your own account activity is listed.";

function caller(
  is_admin: boolean,
  memberships: UserMePublic["memberships"],
): UserMePublic {
  return {
    id: "user-1",
    email: "someone@example.com",
    is_admin,
    memberships,
  } as unknown as UserMePublic;
}

function offered(): string[] {
  return screen.getAllByRole("option").map((o) => o.textContent ?? "");
}

beforeEach(() => {
  state.me = undefined;
});

describe("the activity feed's project filter", () => {
  it("offers nothing and explains when the caller holds no audit tier", async () => {
    state.me = caller(false, [
      { project_id: "p1", project_slug: "alpha", role: "viewer" },
      { project_id: "p2", project_slug: "beta", role: "operator" },
    ]);
    await renderPage();
    expect(offered()).toEqual(["All projects"]);
    expect(screen.getByRole("listbox")).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(screen.getByRole("note")).toHaveTextContent(NOTE);
  });

  it("offers only the projects the caller may audit", async () => {
    state.me = caller(false, [
      { project_id: "p1", project_slug: "alpha", role: "auditor" },
      { project_id: "p2", project_slug: "beta", role: "viewer" },
    ]);
    await renderPage();
    expect(offered()).toEqual(["All projects", "Alpha"]);
    expect(screen.getByRole("listbox")).toHaveAttribute(
      "aria-disabled",
      "false",
    );
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("offers an instance admin every project", async () => {
    state.me = caller(true, []);
    await renderPage();
    expect(offered()).toEqual(["All projects", "Alpha", "Beta"]);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("neither offers nor explains before the caller is known", async () => {
    await renderPage();
    expect(offered()).toEqual(["All projects"]);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});
