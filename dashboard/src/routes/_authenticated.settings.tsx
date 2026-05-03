/**
 * Settings layout route - unified settings hub.
 *
 * Left sidebar navigation (like GitHub settings) with section headers
 * and nav links. Renders an Outlet for the active settings page.
 *
 * Sections:
 *   USER            - Account, Appearance, API Keys
 *   ADMINISTRATION  - Users, General (admin-only)
 */
import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import {
  Activity,
  Bell,
  FolderKanban,
  KeyRound,
  Palette,
  Send,
  Settings,
  UserCircle,
  Users,
  Users2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useMe } from "@/hooks/use-auth";

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
      ],
    },
  ];

  return (
    <div className="space-y-6 p-4 md:p-6">
      {/* Mobile navigation (horizontal scroll) */}
      <div className="flex gap-1 overflow-x-auto border-b pb-3 md:hidden">
        {sections
          .filter((s) => !s.adminOnly || isAdmin)
          .flatMap((s) => s.items)
          .map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={cn(
                "flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
              activeProps={{
                className: "bg-accent text-accent-foreground",
              }}
            >
              <item.icon className="size-4" />
              {item.label}
            </Link>
          ))}
      </div>

      <div className="flex gap-8">
        {/* Left sidebar navigation */}
        <nav className="hidden w-[220px] shrink-0 md:block">
          <div className="space-y-6">
            {sections.map((section) => {
              if (section.adminOnly && !isAdmin) return null;
              return (
                <div key={section.title}>
                  <h4 className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {section.title}
                  </h4>
                  <ul className="space-y-0.5">
                    {section.items.map((item) => (
                      <li key={item.to}>
                        <Link
                          to={item.to}
                          className={cn(
                            "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm font-medium transition-colors",
                            "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                          )}
                          activeProps={{
                            className:
                              "bg-accent text-accent-foreground",
                          }}
                        >
                          <item.icon className="size-4 shrink-0" />
                          <span>{item.label}</span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </nav>

        {/* Content area */}
        <div className="min-w-0 flex-1">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
