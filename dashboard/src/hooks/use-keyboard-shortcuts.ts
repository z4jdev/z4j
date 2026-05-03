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
import { useQueryClient } from "@tanstack/react-query";

export interface KeyboardShortcutsState {
  helpOpen: boolean;
  setHelpOpen: (v: boolean) => void;
}

export function useKeyboardShortcuts(): KeyboardShortcutsState {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const slug = (params as { slug?: string }).slug ?? "default";
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
      if (isInputFocused()) return;
      const key = e.key.toLowerCase();

      // Two-key navigation: g + <letter>
      if (pendingG.current) {
        pendingG.current = false;
        if (gTimer.current) clearTimeout(gTimer.current);

        const routes: Record<string, string> = {
          o: `/projects/${slug}`,
          t: `/projects/${slug}/tasks`,
          w: `/projects/${slug}/workers`,
          q: `/projects/${slug}/queues`,
          a: `/projects/${slug}/agents`,
          s: `/projects/${slug}/settings`,
          u: "/admin/users",
        };
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
          'input[type="search"], input[placeholder*="search"]',
        );
        searchInput?.focus();
      }
    };

    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [isInputFocused, navigate, slug, qc]);

  return { helpOpen, setHelpOpen };
}

export const SHORTCUT_GROUPS = [
  {
    title: "Navigation",
    shortcuts: [
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
