import type { ProjectRole } from "@/hooks/use-memberships";
import {
  Bug,
  ClipboardList,
  Cpu,
  History,
  Layers,
  LayoutDashboard,
  LineChart,
  Network,
  Shield,
  Terminal,
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
    ...(role === "admin"
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
