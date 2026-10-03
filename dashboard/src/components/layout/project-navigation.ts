import { canProjectRole, type ProjectRole } from "@/hooks/use-memberships";
import {
  BellRing,
  Bug,
  ClipboardList,
  Cpu,
  History,
  Layers,
  LayoutDashboard,
  LineChart,
  MailX,
  Network,
  Shield,
  Terminal,
  Users,
  Zap,
  type LucideIcon,
} from "lucide-react";

export interface ProjectNavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  group: "Monitor" | "Infrastructure" | "Control";
  shortcut?: string;
}

export interface ProjectSettingsNavItem {
  label: string;
  /** Route path with the ``$slug`` parameter, for a typed router Link. */
  to:
    | "/projects/$slug/settings/members"
    | "/projects/$slug/settings/notifications";
  icon: LucideIcon;
}

/**
 * Project settings entries the role may open.
 *
 * Every page under project settings reads an admin-only collection: the
 * brain refuses the memberships and invitations lists, and the notification
 * routing, below the admin role. Offering the entry to a viewer led to
 * "Unable to load members" and a silently empty invitations block, so the
 * rail's Project Settings link follows this list and disappears with it.
 */
export function projectSettingsNavigation(
  role: ProjectRole | null,
): ProjectSettingsNavItem[] {
  return [
    ...(canProjectRole(role, "manage_members")
      ? [
          {
            label: "Members",
            to: "/projects/$slug/settings/members" as const,
            icon: Users,
          },
        ]
      : []),
    ...(canProjectRole(role, "manage_channels")
      ? [
          {
            label: "Notifications",
            to: "/projects/$slug/settings/notifications" as const,
            icon: BellRing,
          },
        ]
      : []),
  ];
}

/** One navigation model for the rail, command palette and keyboard shortcuts. */
export function projectNavigation(
  slug: string | undefined,
  role: ProjectRole | null,
): ProjectNavItem[] {
  if (!slug || !role) return [];
  const base = `/projects/${encodeURIComponent(slug)}`;
  const items: ProjectNavItem[] = [
    {
      label: "Overview",
      to: base,
      icon: LayoutDashboard,
      group: "Monitor",
      shortcut: "o",
    },
    {
      label: "Tasks",
      to: `${base}/tasks`,
      icon: ClipboardList,
      group: "Monitor",
      shortcut: "t",
    },
    {
      label: "Dead letters",
      to: `${base}/dead-letters`,
      icon: MailX,
      group: "Monitor",
    },
    {
      label: "Issues",
      to: `${base}/issues`,
      icon: Bug,
      group: "Monitor",
      shortcut: "i",
    },
    {
      label: "Trends",
      to: `${base}/trends`,
      icon: LineChart,
      group: "Monitor",
    },
    {
      label: "Workers",
      to: `${base}/workers`,
      icon: Cpu,
      group: "Infrastructure",
      shortcut: "w",
    },
    {
      label: "Queues",
      to: `${base}/queues`,
      icon: Layers,
      group: "Infrastructure",
      shortcut: "q",
    },
    ...(role === "admin"
      ? [
          {
            label: "Agents",
            to: `${base}/agents`,
            icon: Network,
            group: "Infrastructure" as const,
            shortcut: "a",
          },
        ]
      : []),
    {
      label: "Schedules",
      to: `${base}/schedules`,
      icon: History,
      group: "Control",
    },
    {
      label: "Automation",
      to: `${base}/automation`,
      icon: Zap,
      group: "Control",
    },
    {
      label: "Commands",
      to: `${base}/commands`,
      icon: Terminal,
      group: "Control",
    },
    ...(canProjectRole(role, "read_audit")
      ? [
          {
            label: "Audit log",
            to: `${base}/audit`,
            icon: Shield,
            group: "Control" as const,
          },
        ]
      : []),
  ];
  return items;
}
