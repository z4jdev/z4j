import { useEffect } from "react";
import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { api, ApiError } from "@/lib/api";
import type { UserMePublic } from "@/lib/api-types";
import { AppSidebar } from "@/components/layout/app-sidebar";
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

  // Apply saved primary color on mount.
  // Round-8 audit fix R8-Dash-LOW (Apr 2026): clamp hue to
  // [0, 360]. The OKLCH parser silently drops out-of-range
  // values so this is cosmetic, but bounding here keeps the
  // CSS valid for any future hue-derived property + protects
  // against an attacker who can write to localStorage on a
  // shared kiosk machine.
  useEffect(() => {
    const raw = localStorage.getItem("z4j-primary-hue");
    if (raw === null) return;
    const parsed = parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 360) return;
    const h = parsed;
    const root = document.documentElement;
    root.style.setProperty("--primary", `oklch(0.55 0.18 ${h})`);
    root.style.setProperty("--primary-foreground", `oklch(0.99 0.005 ${h})`);
    root.style.setProperty("--ring", `oklch(0.55 0.18 ${h})`);
    root.style.setProperty("--sidebar-primary", `oklch(0.55 0.18 ${h})`);
    root.style.setProperty("--sidebar-primary-foreground", `oklch(0.99 0.005 ${h})`);
  }, []);

  return (
    <SidebarProvider>
      {/* min-h-0 + flex-1 (rather than min-h-screen) so this layout
          fills the parent flex-column's remaining space exactly.
          In production the parent is min-h-screen flex-col with this
          as the only flex child -- net effect is identical to
          min-h-screen here. In demo mode the DemoBanner sibling
          takes its natural height first; this layout fills what is
          left, so total page height stays at viewport height with
          no extra vertical scroll. */}
      <div className="flex min-h-0 w-full flex-1 bg-background">
        <AppSidebar />
        <main className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <Outlet />
        </main>
      </div>

      {/* Global overlays */}
      <CommandPalette open={palette.open} onOpenChange={palette.setOpen} />
      <ShortcutsDialog
        open={shortcuts.helpOpen}
        onOpenChange={shortcuts.setHelpOpen}
      />
    </SidebarProvider>
  );
}
