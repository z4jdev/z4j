/**
 * Command palette (⌘K / Ctrl+K).
 *
 * Global keyboard-triggered command palette powered by cmdk.
 * Features:
 *
 * - **Navigate** - jump to any page (Overview, Tasks, Agents, ...)
 * - **Search tasks** - type a task name or ID, select to open detail
 * - **Quick actions** - refresh, toggle theme, switch project
 * - **Keyboard shortcuts help** - shows the shortcut sheet
 *
 * Mounted once at the app root level. Opens on ⌘K (Mac) or Ctrl+K
 * (Windows/Linux). ESC closes it.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { Command } from "cmdk";
import {
  ClipboardList,
  Home,
  Keyboard,
  Moon,
  Search,
  Settings,
  Sun,
  Users,
  X,
} from "lucide-react";
import { projectNavigation } from "@/components/layout/project-navigation";
import { useCurrentUserRole } from "@/hooks/use-memberships";
import { useMe } from "@/hooks/use-auth";
import { useTheme } from "@/components/layout/theme-provider";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useTasks } from "@/hooks/use-tasks";
import {
  TaskPriorityBadge,
  TaskStateBadge,
} from "@/components/domain/state-badges";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onOpenShortcuts: () => void;
}

export function CommandPalette({
  open,
  onOpenChange,
  onOpenShortcuts,
}: CommandPaletteProps) {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const activeSlug = (params as { slug?: string }).slug;
  const slug = activeSlug ?? "";
  const role = useCurrentUserRole(activeSlug);
  const { data: me } = useMe();
  const navigation = projectNavigation(activeSlug, role);
  const { setTheme, resolvedTheme } = useTheme();
  const [search, setSearch] = useState("");

  // Debounce the search input so we don't hammer /tasks on every
  // keystroke. 200ms is below the ~250ms human-perceived "instant"
  // threshold; shorter keeps results feeling live, longer risks
  // perceptible lag.
  const debouncedSearch = useDebouncedValue(search, 200);
  const taskQueryEnabled =
    open && Boolean(activeSlug) && debouncedSearch.trim().length >= 2;
  const { data: taskResults } = useTasks(
    taskQueryEnabled ? slug : "",
    taskQueryEnabled ? { search: debouncedSearch.trim(), limit: 8 } : {},
  );
  const taskMatches = useMemo(() => {
    if (!taskQueryEnabled) return [];
    return taskResults?.items ?? [];
  }, [taskQueryEnabled, taskResults]);

  const close = useCallback(() => {
    onOpenChange(false);
    setSearch("");
  }, [onOpenChange]);

  const go = useCallback(
    (to: string) => {
      close();
      navigate({ to });
    },
    [close, navigate],
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => (nextOpen ? onOpenChange(true) : close())}
    >
      <DialogContent
        showCloseButton={false}
        onCloseAutoFocus={() => setSearch("")}
        className="overflow-hidden p-0 shadow-overlay sm:max-w-[520px]"
      >
        <DialogTitle className="sr-only">Search pages and tasks</DialogTitle>
        <DialogDescription className="sr-only">
          {activeSlug
            ? `Search tasks in ${activeSlug}, navigate or change appearance.`
            : "Choose a project to search its tasks, or open a workspace page."}
        </DialogDescription>
        <Command
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-muted-foreground"
          loop
        >
          <div className="flex items-center gap-2 border-b px-3">
            <Search className="size-4 shrink-0 opacity-50" aria-hidden="true" />
            <Command.Input
              aria-label="Search pages and tasks"
              placeholder={
                activeSlug
                  ? `Search in ${activeSlug}…`
                  : "Search pages or choose a project…"
              }
              value={search}
              onValueChange={setSearch}
              className="h-12 min-w-0 flex-1 rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
            />
            <DialogClose asChild>
              <Button
                variant="ghost"
                size="sm"
                className="min-w-9 shrink-0 gap-2 px-2"
                aria-label="Close search"
              >
                <kbd
                  aria-hidden="true"
                  className="hidden rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline-flex"
                >
                  Esc
                </kbd>
                <X className="size-4" aria-hidden="true" />
              </Button>
            </DialogClose>
          </div>
          <Command.List className="max-h-[360px] overflow-y-auto p-2">
            <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
              No results found.
            </Command.Empty>

            {/* Task matches - rendered above Navigate so the palette
                prioritises the specific thing the operator typed over
                the generic page list. Only present when we're inside
                a project context AND the query is >= 2 chars (below
                that every task would match and the list is noise). */}
            {taskMatches.length > 0 && (
              <Command.Group heading="Tasks">
                {taskMatches.map((t) => (
                  <Command.Item
                    key={t.id}
                    value={`task:${t.engine}:${t.task_id}:${t.name}`}
                    onSelect={() =>
                      go(`/projects/${slug}/tasks/${t.engine}/${t.task_id}`)
                    }
                    className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-2 text-sm aria-selected:bg-accent aria-selected:text-accent-foreground"
                  >
                    <ClipboardList className="size-4 shrink-0 opacity-60" />
                    <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                      <span className="truncate font-mono text-xs">
                        {t.name}
                      </span>
                      <span className="truncate text-[11px] text-muted-foreground">
                        {t.engine} · {t.task_id}
                        {t.queue ? ` · ${t.queue}` : ""}
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <TaskStateBadge state={t.state} />
                      <TaskPriorityBadge priority={t.priority} />
                    </div>
                  </Command.Item>
                ))}
              </Command.Group>
            )}

            <Command.Group
              heading={activeSlug ? `Project · ${activeSlug}` : "Workspace"}
            >
              <PaletteItem
                icon={Home}
                label="Workspace home"
                shortcut="G H"
                onSelect={() => go("/home")}
              />
              {navigation.map((item) => (
                <PaletteItem
                  key={item.to}
                  icon={item.icon}
                  label={item.label}
                  shortcut={
                    item.shortcut
                      ? `G ${item.shortcut.toUpperCase()}`
                      : undefined
                  }
                  onSelect={() => go(item.to)}
                />
              ))}
              <PaletteItem
                icon={Settings}
                label="Account settings"
                onSelect={() => go("/settings/account")}
              />
              {me?.is_admin && (
                <PaletteItem
                  icon={Users}
                  label="User Management"
                  onSelect={() => go("/settings/users")}
                />
              )}
            </Command.Group>
            <Command.Group heading="Switch project">
              {me?.memberships?.map((m) => (
                <PaletteItem
                  key={m.project_id}
                  icon={Home}
                  label={m.project_slug}
                  onSelect={() =>
                    go(`/projects/${encodeURIComponent(m.project_slug)}`)
                  }
                />
              ))}
            </Command.Group>

            {/* Quick Actions */}
            <Command.Group heading="Actions">
              <PaletteItem
                icon={resolvedTheme === "dark" ? Sun : Moon}
                label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} mode`}
                onSelect={() => {
                  setTheme(resolvedTheme === "dark" ? "light" : "dark");
                  close();
                }}
              />
              <PaletteItem
                icon={Keyboard}
                label="Keyboard shortcuts"
                shortcut="?"
                onSelect={() => {
                  close();
                  onOpenShortcuts();
                }}
              />
            </Command.Group>
          </Command.List>
        </Command>
      </DialogContent>
    </Dialog>
  );
}

function PaletteItem({
  icon: Icon,
  label,
  shortcut,
  onSelect,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  shortcut?: string;
  onSelect: () => void;
}) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-2 text-sm aria-selected:bg-accent aria-selected:text-accent-foreground"
    >
      <Icon className="size-4 shrink-0 opacity-60" />
      <span className="flex-1">{label}</span>
      {shortcut && (
        <kbd className="pointer-events-none hidden text-xs text-muted-foreground sm:inline-flex">
          {shortcut}
        </kbd>
      )}
    </Command.Item>
  );
}

/**
 * Trailing-edge debounce for fast-typed search inputs.
 *
 * Returns ``value`` after it has been stable for ``delay`` ms.
 * The effect clears its timer on every re-render so the latest
 * keystroke always wins.
 */
function useDebouncedValue<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

/**
 * Hook to manage command palette open state + global keybinding.
 *
 * Usage:
 * ```tsx
 * const { open, setOpen } = useCommandPalette();
 * <CommandPalette open={open} onOpenChange={setOpen} />
 * ```
 */
export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  return { open, setOpen };
}
