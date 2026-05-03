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
  Bell,
  ClipboardList,
  Cpu,
  History,
  Keyboard,
  Layers,
  LayoutDashboard,
  Moon,
  Network,
  Search,
  Settings,
  Shield,
  Sun,
  Terminal,
  Users,
} from "lucide-react";
import { useTheme } from "@/components/layout/theme-provider";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { useTasks } from "@/hooks/use-tasks";
import {
  TaskPriorityBadge,
  TaskStateBadge,
} from "@/components/domain/state-badges";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const activeSlug = (params as { slug?: string }).slug;
  const slug = activeSlug ?? "default";
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
    taskQueryEnabled
      ? { search: debouncedSearch.trim(), limit: 8 }
      : {},
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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="overflow-hidden p-0 shadow-lg sm:max-w-[520px]">
        <Command
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-muted-foreground"
          loop
        >
          <div className="flex items-center border-b px-3">
            <Search className="mr-2 size-4 shrink-0 opacity-50" />
            <Command.Input
              placeholder="Search commands, pages, tasks..."
              value={search}
              onValueChange={setSearch}
              className="flex h-12 w-full rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
            />
            <kbd className="pointer-events-none ml-2 hidden h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
              ESC
            </kbd>
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
                      go(
                        `/projects/${slug}/tasks/${t.engine}/${t.task_id}`,
                      )
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

            {/* Navigation */}
            <Command.Group heading="Navigate">
              <PaletteItem
                icon={LayoutDashboard}
                label="Overview"
                shortcut="G O"
                onSelect={() => go(`/projects/${slug}`)}
              />
              <PaletteItem
                icon={ClipboardList}
                label="Tasks"
                shortcut="G T"
                onSelect={() => go(`/projects/${slug}/tasks`)}
              />
              <PaletteItem
                icon={Cpu}
                label="Workers"
                shortcut="G W"
                onSelect={() => go(`/projects/${slug}/workers`)}
              />
              <PaletteItem
                icon={Layers}
                label="Queues"
                shortcut="G Q"
                onSelect={() => go(`/projects/${slug}/queues`)}
              />
              <PaletteItem
                icon={History}
                label="Schedules"
                onSelect={() => go(`/projects/${slug}/schedules`)}
              />
              <PaletteItem
                icon={Terminal}
                label="Commands"
                onSelect={() => go(`/projects/${slug}/commands`)}
              />
              <PaletteItem
                icon={Network}
                label="Agents"
                shortcut="G A"
                onSelect={() => go(`/projects/${slug}/agents`)}
              />
              <PaletteItem
                icon={Shield}
                label="Audit Log"
                onSelect={() => go(`/projects/${slug}/audit`)}
              />
              <PaletteItem
                icon={Settings}
                label="Settings & Notifications"
                onSelect={() => go(`/projects/${slug}/settings`)}
              />
              <PaletteItem
                icon={Users}
                label="User Management"
                onSelect={() => go("/admin/users")}
              />
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
                icon={Bell}
                label="Add notification rule"
                onSelect={() => go(`/projects/${slug}/settings`)}
              />
              <PaletteItem
                icon={Keyboard}
                label="Keyboard shortcuts"
                shortcut="?"
                onSelect={close}
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
