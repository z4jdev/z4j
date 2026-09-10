/**
 * Settings layout route - unified settings hub.
 *
 * Grouped links stay visible at every width: a vertical list on laptops and
 * larger screens, and a wrapping index above the content on compact screens.
 */
import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import {
  Activity,
  Bell,
  FolderKanban,
  KeyRound,
  Palette,
  Settings,
  Shield,
  SlidersHorizontal,
  UserCircle,
  Users,
  Users2,
} from "lucide-react";
import { useMe } from "@/hooks/use-auth";
import { PageShell } from "@/components/domain/page-shell";

export const Route = createFileRoute("/_authenticated/settings")({
  component: SettingsLayout,
});

interface SettingsNavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface SettingsNavSection {
  title: string;
  items: SettingsNavItem[];
  adminOnly?: boolean;
}

function SettingsLayout() {
  const { data: me } = useMe();
  const isAdmin = me?.is_admin ?? false;

  const sections: SettingsNavSection[] = [
    {
      title: "User",
      items: [
        { label: "Account", to: "/settings/account", icon: UserCircle },
        // 1.6.0: Security is its own top-level page (MFA, trusted
        // devices, active sessions). Previously these lived as a
        // sub-tab inside Account; the second factor is meaningful
        // enough to deserve a top-level destination.
        { label: "Security", to: "/settings/security", icon: Shield },
        { label: "My Memberships", to: "/settings/memberships", icon: Users2 },
        { label: "Appearance", to: "/settings/appearance", icon: Palette },
        { label: "API Keys", to: "/settings/api-keys", icon: KeyRound },
        // v1.0.18: My Channels merged into the Notifications hub
        // as a tab. The /settings/channels route now redirects.
        { label: "Notifications", to: "/settings/notifications", icon: Bell },
      ],
    },
    {
      title: "Administration",
      adminOnly: true,
      items: [
        { label: "Users", to: "/settings/users", icon: Users },
        { label: "Projects", to: "/settings/projects", icon: FolderKanban },
        { label: "General", to: "/settings/general", icon: Settings },
        { label: "System", to: "/settings/system", icon: Activity },
        // 1.5.0: read-only effective-config view; mirrors `z4j config show`.
        // Sits next to System because both are diagnostic/observability
        // surfaces, and operators reach for them together.
        {
          label: "Runtime config",
          to: "/settings/runtime",
          icon: SlidersHorizontal,
        },
      ],
    },
  ];

  const visibleSections = sections.filter(
    (section) => !section.adminOnly || isAdmin,
  );
  return (
    <PageShell>
      <div className="flex flex-col gap-6 lg:flex-row">
        <nav
          aria-label="Settings"
          className="shrink-0 border-b pb-5 lg:w-48 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4"
        >
          <div className="space-y-4 lg:sticky lg:top-24 lg:max-h-[calc(100dvh-7.5rem-var(--demo-footer-height,0px))] lg:space-y-6 lg:overflow-y-auto">
            {visibleSections.map((section) => (
              <div key={section.title} role="group" aria-label={section.title}>
                <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {section.title}
                </p>
                <ul className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,10.5rem),1fr))] gap-1 lg:grid-cols-1 lg:gap-0.5">
                  {section.items.map((item) => (
                    <li key={item.to}>
                      <Link
                        to={item.to}
                        className="navigation-link min-h-11 px-2 py-2 lg:min-h-9 lg:py-1.5"
                        activeProps={{
                          className: "navigation-link-active",
                        }}
                      >
                        <item.icon
                          className="size-4 shrink-0"
                          aria-hidden="true"
                        />
                        <span>{item.label}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </nav>

        {/* Content area */}
        <div className="min-w-0 flex-1">
          <Outlet />
        </div>
      </div>
    </PageShell>
  );
}
