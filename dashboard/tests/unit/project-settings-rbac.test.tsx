/**
 * Project settings are admin-only on the server (the memberships and
 * invitations lists, the notification routing). The rail's Project Settings
 * link, the settings layout's entries and the pending-invitations block all
 * follow the same capability list, so a viewer never lands on "Unable to
 * load members" or an invitations table that is silently empty.
 */
import { act, render, screen } from "@testing-library/react";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ProjectCapability, ProjectRole } from "@/hooks/use-memberships";

const state = vi.hoisted(() => ({
  role: null as ProjectRole | null,
  meLoaded: true,
  invitations: [] as Array<Record<string, unknown>>,
}));

const invitationsQuery = vi.hoisted(() => vi.fn());

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
      useParams: () => ({ slug: "alpha" }),
    }),
    Link: ({
      children,
      to,
      params,
    }: {
      children: ReactNode;
      to: string;
      params?: { slug?: string };
    }) =>
      React.createElement(
        "a",
        { href: to.replace("$slug", params?.slug ?? "") },
        children,
      ),
    Outlet: () => React.createElement("output", { "data-testid": "outlet" }),
    useParams: () => ({ slug: "alpha" }),
    useRouterState: () => "/projects/alpha",
  };
});

vi.mock("@/hooks/use-auth", () => ({
  useMe: () => ({
    isSuccess: state.meLoaded,
    data: state.meLoaded
      ? { id: "user-1", is_admin: false, memberships: [] }
      : undefined,
  }),
}));

vi.mock("@/hooks/use-memberships", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("@/hooks/use-memberships")>();
  return {
    ...original,
    useCurrentUserRole: () => state.role,
    useIsProjectAdmin: () => state.role === "admin",
    useCan: (_slug: string | undefined, action: ProjectCapability) =>
      original.canProjectRole(state.role, action),
  };
});

vi.mock("@/hooks/use-invitations", () => ({
  useInvitations: (slug: string | undefined) => {
    invitationsQuery(slug);
    return { data: slug ? state.invitations : undefined, isLoading: false };
  },
  useRevokeInvitation: () => ({ mutateAsync: vi.fn() }),
}));

vi.mock("@/components/domain/confirm-dialog", () => ({
  useConfirm: () => ({ confirm: vi.fn(), dialog: null }),
}));

vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

vi.mock("@/components/domain/page-shell", async () => {
  const React = await import("react");
  return {
    PageShell: ({ children }: { children: ReactNode }) =>
      React.createElement("main", null, children),
  };
});

vi.mock("@/components/layout/project-switcher", () => ({
  ProjectSwitcher: () => null,
}));

vi.mock("@/components/layout/sidebar-context", () => ({
  useSidebar: () => ({
    collapsed: false,
    mobileOpen: false,
    setMobileOpen: vi.fn(),
  }),
}));

vi.mock("@/components/ui/tooltip", async () => {
  const React = await import("react");
  const Pass = ({ children }: { children?: ReactNode }) =>
    React.createElement(React.Fragment, null, children);
  return {
    Tooltip: Pass,
    TooltipContent: Pass,
    TooltipProvider: Pass,
    TooltipTrigger: Pass,
  };
});

// The mobile drawer is closed in these tests; rendering it would duplicate
// every rail entry.
vi.mock("@/components/ui/dialog", () => ({
  Dialog: () => null,
  DialogContent: () => null,
  DialogDescription: () => null,
  DialogTitle: () => null,
}));

vi.mock("@/components/z4j-mark", () => ({ Z4jMark: () => null }));

import { AppSidebar } from "@/components/layout/app-sidebar";
import { projectSettingsNavigation } from "@/components/layout/project-navigation";
import { PendingInvitations } from "@/components/domain/pending-invitations";
import { Route as SettingsRoute } from "@/routes/_authenticated.projects.$slug.settings";

type PreloadableRouteComponent = ComponentType & {
  preload?: () => Promise<void>;
};

const SettingsLayout = (
  SettingsRoute as unknown as {
    options: { component: PreloadableRouteComponent };
  }
).options.component;

// Route components are code-split: resolve the chunk, then render it inside
// the Suspense boundary the router would provide.
async function renderRoute(Page: PreloadableRouteComponent) {
  await Page.preload?.();
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <Page />
      </Suspense>,
    );
    await Promise.resolve();
  });
}

const invitation = {
  id: "00000000-0000-0000-0000-000000000001",
  project_id: "00000000-0000-0000-0000-000000000002",
  email: "invitee@example.com",
  role: "viewer",
  invited_by: null,
  expires_at: "2030-01-01T00:00:00Z",
  accepted_at: null,
  revoked_at: null,
  created_at: "2029-12-01T00:00:00Z",
};

beforeEach(() => {
  state.role = null;
  state.meLoaded = true;
  state.invitations = [];
  invitationsQuery.mockReset();
});

describe("projectSettingsNavigation", () => {
  it.each<ProjectRole | null>([null, "viewer", "auditor", "operator"])(
    "offers nothing below admin (%s)",
    (role) => {
      expect(projectSettingsNavigation(role)).toEqual([]);
    },
  );

  it("offers admins the members and notifications pages", () => {
    expect(projectSettingsNavigation("admin").map((i) => i.label)).toEqual([
      "Members",
      "Notifications",
    ]);
  });
});

describe("the workspace rail's Project Settings link", () => {
  it.each<ProjectRole>(["viewer", "auditor", "operator"])(
    "is absent for a %s while Global Settings stays",
    (role) => {
      state.role = role;
      render(<AppSidebar />);
      expect(screen.queryByText("Project Settings")).not.toBeInTheDocument();
      expect(screen.getByText("Global Settings")).toBeInTheDocument();
    },
  );

  it("leads an admin to the members page", () => {
    state.role = "admin";
    render(<AppSidebar />);
    expect(screen.getByText("Project Settings").closest("a")).toHaveAttribute(
      "href",
      "/projects/alpha/settings/members",
    );
  });
});

describe("the project settings layout", () => {
  it("tells a viewer who lands by URL why there is nothing here", async () => {
    state.role = "viewer";
    await renderRoute(SettingsLayout);
    expect(screen.queryByText("Members")).not.toBeInTheDocument();
    expect(screen.queryByTestId("outlet")).not.toBeInTheDocument();
    expect(
      screen.getByText("Project settings need the admin role"),
    ).toBeInTheDocument();
  });

  it("lists both pages and renders the child route for an admin", async () => {
    state.role = "admin";
    await renderRoute(SettingsLayout);
    expect(screen.getByText("Members").closest("a")).toHaveAttribute(
      "href",
      "/projects/alpha/settings/members",
    );
    expect(screen.getByText("Notifications")).toBeInTheDocument();
    expect(screen.getByTestId("outlet")).toBeInTheDocument();
  });

  it("does not refuse before the caller is known", async () => {
    state.role = null;
    state.meLoaded = false;
    await renderRoute(SettingsLayout);
    expect(
      screen.queryByText("Project settings need the admin role"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("outlet")).toBeInTheDocument();
  });
});

describe("the pending invitations block", () => {
  it("neither asks for nor renders the list below admin", () => {
    state.role = "operator";
    state.invitations = [invitation];
    const { container } = render(<PendingInvitations slug="alpha" />);
    expect(invitationsQuery).toHaveBeenCalledWith(undefined);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists an admin's outstanding invitations", () => {
    state.role = "admin";
    state.invitations = [invitation];
    render(<PendingInvitations slug="alpha" />);
    expect(invitationsQuery).toHaveBeenCalledWith("alpha");
    expect(screen.getByText("Pending invitations")).toBeInTheDocument();
    expect(screen.getByText("invitee@example.com")).toBeInTheDocument();
  });
});
