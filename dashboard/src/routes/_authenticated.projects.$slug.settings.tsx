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
import { BellRing, Users } from "lucide-react";
import { useIsProjectAdmin } from "@/hooks/use-memberships";
import { PageShell } from "@/components/domain/page-shell";

export const Route = createFileRoute("/_authenticated/projects/$slug/settings")(
  {
    component: ProjectSettingsLayout,
  },
);

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
    <PageShell>
      {/* Each child route renders its own PageHeader. The shell only
       * provides the navigation. Project scope is conveyed by the
       * project switcher in the workspace sidebar. */}

      <div className="flex flex-col gap-6 lg:flex-row">
        <nav
          aria-label="Project settings"
          className="shrink-0 border-b pb-5 lg:w-48 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4"
        >
          <div className="space-y-4 lg:sticky lg:top-24">
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
                        params={{ slug }}
                        className="navigation-link min-h-11 px-2 py-2 lg:min-h-9 lg:py-1.5"
                        activeProps={{ className: "navigation-link-active" }}
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
