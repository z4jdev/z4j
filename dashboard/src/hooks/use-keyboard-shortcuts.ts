/**
 * Global keyboard shortcuts.
 *
 * Shortcuts only fire when no input/textarea/select is focused
 * (so typing in a search box doesn't trigger navigation).
 *
 * Navigation shortcuts use a two-key "g + letter" pattern:
 *   g o → Overview
 *   g t → Tasks
 *   g w → Workers
 *   g q → Queues
 *   g a → Agents
 *   g s → Settings
 *   g u → Users (admin)
 *
 * Single-key shortcuts:
 *   ?   → show shortcut help (toggles)
 *   r   → refresh current page data
 *   /   → focus the search input (if visible)
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { projectNavigation } from "@/components/layout/project-navigation";
import { useCurrentUserRole } from "@/hooks/use-memberships";
import { useMe } from "@/hooks/use-auth";
import { useQueryClient } from "@tanstack/react-query";

export interface KeyboardShortcutsState {
  helpOpen: boolean;
  setHelpOpen: (v: boolean) => void;
}

export function useKeyboardShortcuts(): KeyboardShortcutsState {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const slug = (params as { slug?: string }).slug;
  const role = useCurrentUserRole(slug);
  const { data: me } = useMe();
  const qc = useQueryClient();
  const [helpOpen, setHelpOpen] = useState(false);
  const pendingG = useRef(false);
  const gTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isInputFocused = useCallback((): boolean => {
    const el = document.activeElement;
    if (!el) return false;
    const tag = el.tagName.toLowerCase();
    return (
      tag === "input" ||
      tag === "textarea" ||
      tag === "select" ||
      (el as HTMLElement).isContentEditable
    );
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (
        isInputFocused() ||
        document.querySelector('[role="dialog"]') ||
        e.altKey ||
        e.metaKey ||
        e.ctrlKey
      )
        return;
      const key = e.key.toLowerCase();

      // Two-key navigation: g + <letter>
      if (pendingG.current) {
        pendingG.current = false;
        if (gTimer.current) clearTimeout(gTimer.current);

        const routes: Record<string, string> = {
          h: "/home",
          s: "/settings/account",
        };
        for (const item of projectNavigation(slug, role)) {
          if (item.shortcut) routes[item.shortcut] = item.to;
        }
        if (me?.is_admin) routes.u = "/settings/users";
        const target = routes[key];
        if (target) {
          e.preventDefault();
          navigate({ to: target });
        }
        return;
      }

      if (key === "g" && !e.metaKey && !e.ctrlKey) {
        pendingG.current = true;
        gTimer.current = setTimeout(() => {
          pendingG.current = false;
        }, 500);
        return;
      }

      // Single-key shortcuts
      if (key === "?" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        setHelpOpen((prev) => !prev);
        return;
      }

      if (key === "r" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        qc.invalidateQueries();
        return;
      }

      if (key === "/" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        const searchInput = document.querySelector<HTMLInputElement>(
          'input[type="search"], input[placeholder*="search" i]',
        );
        searchInput?.focus();
      }
    };

    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      if (gTimer.current) clearTimeout(gTimer.current);
      pendingG.current = false;
    };
  }, [isInputFocused, navigate, slug, role, me?.is_admin, qc]);

  return { helpOpen, setHelpOpen };
}

export const SHORTCUT_GROUPS = [
  {
    title: "Navigation",
    shortcuts: [
      { keys: "g h", description: "Go to workspace Home" },
      { keys: "g i", description: "Go to Issues" },
      { keys: "g o", description: "Go to Overview" },
      { keys: "g t", description: "Go to Tasks" },
      { keys: "g w", description: "Go to Workers" },
      { keys: "g q", description: "Go to Queues" },
      { keys: "g a", description: "Go to Agents" },
      { keys: "g s", description: "Go to Settings" },
      { keys: "g u", description: "Go to Users" },
    ],
  },
  {
    title: "Actions",
    shortcuts: [
      { keys: "⌘K", description: "Open command palette" },
      { keys: "r", description: "Refresh data" },
      { keys: "/", description: "Focus search" },
      { keys: "?", description: "Toggle this help" },
    ],
  },
] as const;
