import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { api, ApiError } from "@/lib/api";
import type { UserMePublic } from "@/lib/api-types";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { DemoBanner } from "@/components/layout/demo-banner";
import { MfaEnrollmentBanner } from "@/components/domain/mfa-enrollment-banner";
import { SidebarProvider } from "@/components/layout/sidebar-context";
import { Topbar } from "@/components/layout/topbar";
import {
  CommandPalette,
  useCommandPalette,
} from "@/components/command-palette";
import { ShortcutsDialog } from "@/components/shortcuts-dialog";
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcuts";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async () => {
    try {
      const me = await api.get<UserMePublic>("/auth/me");
      return { user: me };
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        throw redirect({ to: "/login" });
      }
      throw err;
    }
  },
  component: AuthenticatedLayout,
});

function AuthenticatedLayout() {
  const palette = useCommandPalette();
  const shortcuts = useKeyboardShortcuts();

  return (
    <SidebarProvider>
      <div className="app-shell flex min-h-dvh w-full bg-background">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-card focus:p-3"
        >
          Skip to content
        </a>
        <AppSidebar />
        <main
          id="main-content"
          tabIndex={-1}
          className="flex min-w-0 flex-1 flex-col"
        >
          <Topbar onOpenSearch={() => palette.setOpen(true)} />
          {/* Enrollment is enforced by the brain on every non-exempt
              route. Without this the user only sees a permission error,
              so it belongs in the shell rather than on one page. */}
          <MfaEnrollmentBanner />
          <Outlet />
        </main>
      </div>
      <DemoBanner />

      {/* Global overlays */}
      <CommandPalette
        open={palette.open}
        onOpenChange={palette.setOpen}
        onOpenShortcuts={() => shortcuts.setHelpOpen(true)}
      />
      <ShortcutsDialog
        open={shortcuts.helpOpen}
        onOpenChange={shortcuts.setHelpOpen}
      />
    </SidebarProvider>
  );
}
