/**
 * Project settings layout route.
 *
 * Left sidebar navigation (mirrors the global settings layout) with a
 * single "Project" section. Renders an Outlet for the active child
 * settings page (members, notifications hub).
 *
 * v1.0.18: the three notification entries (Project Channels,
 * Default Subscriptions, Delivery Log) collapsed into one
 * admin-only "Notifications" entry that points at the unified
 * Project Notifications hub. Hidden from non-admin members
 * because every tab inside is admin-only - members manage their
 * own subscriptions in Global Notifications under their account.
 */
import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { BellRing, Settings2, Users } from "lucide-react";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/domain/page-header";
import { useIsProjectAdmin } from "@/hooks/use-memberships";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings",
)({
  component: ProjectSettingsLayout,
});

interface SettingsNavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  adminOnly?: boolean;
}

interface SettingsNavSection {
  title: string;
  items: SettingsNavItem[];
}

function ProjectSettingsLayout() {
  const { slug } = Route.useParams();
  const isAdmin = useIsProjectAdmin(slug);

  const sections: SettingsNavSection[] = [
    {
      title: "Project",
      items: [
        {
          label: "Members",
          to: "/projects/$slug/settings/members",
          icon: Users,
        },
        {
          // v1.0.18: collapses Project Channels + Default
          // Subscriptions + Delivery Log into one admin-only
          // hub page. Non-admins never see this entry; if they
          // URL-jump in directly the inner tabs render their own
          // admin-only EmptyState.
          label: "Notifications",
          to: "/projects/$slug/settings/notifications",
          icon: BellRing,
          adminOnly: true,
        },
      ],
    },
  ];

  const visibleSections: SettingsNavSection[] = sections.map((s) => ({
    ...s,
    items: s.items.filter((i) => !i.adminOnly || isAdmin),
  }));

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Project Settings"
        icon={Settings2}
        description={`configuration for project ${slug}`}
      />

      {/* Mobile navigation (horizontal scroll) */}
      <div className="flex gap-1 overflow-x-auto border-b pb-3 md:hidden">
        {visibleSections
          .flatMap((s) => s.items)
          .map((item) => (
            <Link
              key={item.to}
              to={item.to}
              params={{ slug }}
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
            {visibleSections.map((section) => (
              <div key={section.title}>
                <h4 className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {section.title}
                </h4>
                <ul className="space-y-0.5">
                  {section.items.map((item) => (
                    <li key={item.to}>
                      <Link
                        to={item.to}
                        params={{ slug }}
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
            ))}
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
