/**
 * User settings - notification subscriptions.
 *
 * Shows every subscription the user has across all their projects,
 * grouped by project. Each row = one (project, trigger) subscription
 * with filters, channel set, mute state, and active toggle.
 */
import { useMemo, useState } from "react";
import { Bell, BellOff, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/domain/page-header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useChannels,
  useCreateUserSubscription,
  useDeleteUserSubscription,
  useUpdateUserSubscription,
  useUserChannels,
  useUserSubscriptions,
  type TriggerType,
  type UserSubscription,
} from "@/hooks/use-notifications";
import { useProjects } from "@/hooks/use-projects";
import type { ProjectPublic } from "@/lib/api-types";
import { parseTimestamp } from "@/lib/format";

const TRIGGERS: { value: TriggerType; label: string }[] = [
  { value: "task.failed", label: "Task failed" },
  { value: "task.succeeded", label: "Task succeeded" },
  { value: "task.retried", label: "Task retried" },
  { value: "task.slow", label: "Task slow" },
  { value: "agent.offline", label: "Agent offline" },
  { value: "agent.online", label: "Agent online" },
];

const PRIORITIES = ["critical", "high", "normal", "low"] as const;

function triggerLabel(t: TriggerType | string): string {
  return TRIGGERS.find((x) => x.value === t)?.label ?? t;
}

export function MySubscriptionsTab() {
  const { data: subs, isLoading, isFetching } = useUserSubscriptions();
  const { data: projects } = useProjects();
  const deleteSub = useDeleteUserSubscription();
  const updateSub = useUpdateUserSubscription();
  const [dialogOpen, setDialogOpen] = useState(false);
  // v1.0.18: edit pencil. ``editing=null`` opens the dialog in
  // CREATE mode; setting it to a row opens it in EDIT mode with
  // pre-filled values. Same pattern as the project defaults page.
  const [editing, setEditing] = useState<UserSubscription | null>(null);
  const { confirm, dialog: confirmDialog } = useConfirm();

  const openCreate = () => {
    setEditing(null);
    setDialogOpen(true);
  };
  const openEdit = (sub: UserSubscription) => {
    setEditing(sub);
    setDialogOpen(true);
  };
  const closeDialog = () => {
    setDialogOpen(false);
    // Defer clearing ``editing`` so the dialog body doesn't visibly
    // flip to create mode mid-close-animation.
    setTimeout(() => setEditing(null), 150);
  };

  const projectMap = useMemo(
    () => new Map((projects ?? []).map((p) => [p.id, p])),
    [projects],
  );

  const grouped = useMemo(() => {
    const groups = new Map<string, UserSubscription[]>();
    for (const sub of subs ?? []) {
      const list = groups.get(sub.project_id) ?? [];
      list.push(sub);
      groups.set(sub.project_id, list);
    }
    return Array.from(groups.entries());
  }, [subs]);

  return (
    <div className="space-y-6">
      {confirmDialog}
      <PageHeader
        title={
          <>
            Notifications
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </>
        }
        description="Choose which events you want to hear about, and where to deliver them."
        actions={
          <Dialog
            open={dialogOpen}
            onOpenChange={(open) => {
              if (!open) closeDialog();
              else setDialogOpen(true);
            }}
          >
            <DialogTrigger asChild>
              <Button
                size="sm"
                disabled={!projects || projects.length === 0}
                onClick={openCreate}
              >
                <Plus className="size-4" />
                New subscription
              </Button>
            </DialogTrigger>
            <DialogContent>
              <SubscriptionDialog
                projects={projects ?? []}
                existing={editing}
                onSaved={closeDialog}
              />
            </DialogContent>
          </Dialog>
        }
      />

      {isLoading && <Skeleton className="h-32 w-full" />}

      {subs && subs.length === 0 && (
        <EmptyState
          icon={Bell}
          title="No subscriptions yet"
          description="Create a subscription to start receiving notifications when tasks fail, agents go offline, etc."
        />
      )}

      {grouped.length > 0 && (
        <div className="space-y-6">
          {grouped.map(([projectId, projectSubs]) => {
            const project = projectMap.get(projectId);
            return (
              <Card key={projectId} className="overflow-hidden p-0">
                <div className="border-b bg-muted/30 px-4 py-2">
                  {project ? (
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold">
                        {project.name}
                      </span>
                      <Badge variant="outline" className="font-mono text-xs">
                        {project.slug}
                      </Badge>
                    </div>
                  ) : (
                    <code className="text-xs">{projectId}</code>
                  )}
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Trigger</TableHead>
                      <TableHead>Channels</TableHead>
                      <TableHead>Filters</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Active</TableHead>
                      <TableHead className="w-10" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {projectSubs.map((sub) => (
                      <TableRow key={sub.id}>
                        <TableCell>
                          <Badge variant="outline">
                            {triggerLabel(sub.trigger)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {channelSummary(sub)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {filterSummary(sub.filters)}
                        </TableCell>
                        <TableCell>
                          {sub.muted_until &&
                          parseTimestamp(sub.muted_until).getTime() >
                            Date.now() ? (
                            <Badge variant="muted">
                              <BellOff className="size-3" />
                              muted
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              -
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={sub.is_active}
                            onCheckedChange={(checked) => {
                              updateSub.mutate(
                                {
                                  id: sub.id,
                                  body: { is_active: checked },
                                },
                                {
                                  onSuccess: () =>
                                    toast.success(
                                      checked
                                        ? "Subscription enabled"
                                        : "Subscription disabled",
                                    ),
                                  onError: (err) => {
                                    const msg =
                                      err instanceof Error
                                        ? err.message
                                        : "Request failed";
                                    toast.error(msg);
                                  },
                                },
                              );
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Edit ${triggerLabel(sub.trigger)} subscription`}
                              className="text-muted-foreground hover:text-foreground"
                              onClick={() => openEdit(sub)}
                            >
                              <Pencil className="size-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Delete ${triggerLabel(sub.trigger)} subscription`}
                              className="text-muted-foreground hover:text-destructive"
                            onClick={() =>
                              confirm({
                                title: "Delete subscription",
                                description: (
                                  <>
                                    Stop receiving the{" "}
                                    <code>{triggerLabel(sub.trigger)}</code>{" "}
                                    notification for this project?
                                  </>
                                ),
                                confirmLabel: "Delete",
                                onConfirm: () =>
                                  deleteSub.mutate(sub.id, {
                                    onSuccess: () =>
                                      toast.success("Subscription deleted"),
                                    onError: (err) => {
                                      const msg =
                                        err instanceof Error
                                          ? err.message
                                          : "Request failed";
                                      toast.error(msg);
                                    },
                                  }),
                              })
                            }
                          >
                            <Trash2 className="size-4" />
                          </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function channelSummary(sub: UserSubscription): string {
  const parts: string[] = [];
  if (sub.in_app) parts.push("In-app");
  const extra =
    sub.project_channel_ids.length + sub.user_channel_ids.length;
  if (extra > 0) {
    parts.push(`${extra} channel${extra === 1 ? "" : "s"}`);
  }
  return parts.length > 0 ? parts.join(" + ") : "-";
}

function filterSummary(filters: Record<string, unknown>): string {
  const keys = Object.keys(filters);
  if (keys.length === 0) return "-";
  const bits: string[] = [];
  if (Array.isArray(filters.priority)) {
    bits.push(`priority: ${(filters.priority as string[]).join(",")}`);
  }
  if (typeof filters.task_name_pattern === "string") {
    bits.push(`name: ${filters.task_name_pattern}`);
  }
  return bits.length > 0 ? bits.join("; ") : JSON.stringify(filters);
}

// ---------------------------------------------------------------------------
// Subscription dialog (create + edit, v1.0.18)
// ---------------------------------------------------------------------------

/**
 * Unified create / edit dialog for personal subscriptions.
 *
 * - ``existing=null`` => CREATE mode, all fields blank, project
 *   picker enabled, POST to /user/subscriptions on save.
 * - ``existing=row``  => EDIT mode, fields prefilled, project
 *   picker DISABLED (you can't move a sub between projects -
 *   delete and recreate), PATCH to /user/subscriptions/{id}.
 *
 * v1.0.18 also added:
 * - ``queue`` filter (backend SubscriptionFilters supports it;
 *   the dialog just never rendered the input)
 * - inline help on the priority filter explaining
 *   ``@z4j_meta(priority="critical")`` requirement
 */
function SubscriptionDialog({
  projects,
  existing,
  onSaved,
}: {
  projects: ProjectPublic[];
  existing: UserSubscription | null;
  onSaved: () => void;
}) {
  const isEdit = existing !== null;
  const createSub = useCreateUserSubscription();
  const updateSub = useUpdateUserSubscription();
  const { data: userChannels } = useUserChannels();

  const [projectId, setProjectId] = useState(
    existing?.project_id ?? projects[0]?.id ?? "",
  );
  // Project channels for the CURRENTLY-SELECTED project so a user
  // can route through admin-managed shared channels in addition
  // to personal ones. The hook is keyed by slug so it re-fetches
  // automatically when the user picks a different project in
  // CREATE mode (in EDIT mode the project picker is disabled and
  // projectId never changes).
  const currentProjectSlug =
    projects.find((p) => p.id === projectId)?.slug ?? "";
  const { data: projectChannels } = useChannels(currentProjectSlug);

  // Wrap setProjectId to also clear the project-channel selection
  // when the project changes, channel IDs from project A don't
  // exist in project B and would 409 on save. EDIT mode disables
  // the picker so this only fires in CREATE mode.
  const handleProjectChange = (newProjectId: string) => {
    if (newProjectId !== projectId) {
      setSelectedProjectChannels([]);
    }
    setProjectId(newProjectId);
  };
  const [trigger, setTrigger] = useState<TriggerType>(
    (existing?.trigger as TriggerType) ?? "task.failed",
  );
  const existingFilters = (existing?.filters ?? {}) as Record<string, unknown>;
  const [priorities, setPriorities] = useState<string[]>(
    Array.isArray(existingFilters.priority)
      ? (existingFilters.priority as string[])
      : [],
  );
  const [taskNamePattern, setTaskNamePattern] = useState(
    typeof existingFilters.task_name_pattern === "string"
      ? (existingFilters.task_name_pattern as string)
      : "",
  );
  const [queueFilter, setQueueFilter] = useState(
    typeof existingFilters.queue === "string"
      ? (existingFilters.queue as string)
      : "",
  );
  const [inApp, setInApp] = useState(existing?.in_app ?? true);
  const [selectedUserChannels, setSelectedUserChannels] = useState<string[]>(
    existing?.user_channel_ids ?? [],
  );
  const [selectedProjectChannels, setSelectedProjectChannels] = useState<
    string[]
  >(existing?.project_channel_ids ?? []);
  const [cooldown, setCooldown] = useState(
    String(existing?.cooldown_seconds ?? 300),
  );

  const isPending = isEdit ? updateSub.isPending : createSub.isPending;

  const togglePriority = (p: string) => {
    setPriorities((cur) =>
      cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p],
    );
  };
  const toggleUserChannel = (id: string) => {
    setSelectedUserChannels((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );
  };
  const toggleProjectChannel = (id: string) => {
    setSelectedProjectChannels((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectId) {
      toast.error("Please pick a project");
      return;
    }
    const filters: Record<string, unknown> = {};
    if (priorities.length > 0) filters.priority = priorities;
    if (taskNamePattern.trim())
      filters.task_name_pattern = taskNamePattern.trim();
    if (queueFilter.trim()) filters.queue = queueFilter.trim();

    const cooldownSeconds = parseInt(cooldown, 10) || 0;
    if (isEdit && existing) {
      updateSub.mutate(
        {
          id: existing.id,
          body: {
            trigger,
            filters,
            in_app: inApp,
            project_channel_ids: selectedProjectChannels,
            user_channel_ids: selectedUserChannels,
            cooldown_seconds: cooldownSeconds,
          },
        },
        {
          onSuccess: () => {
            toast.success("Subscription updated");
            onSaved();
          },
          onError: (err) => toast.error(`Failed: ${err.message}`),
        },
      );
    } else {
      createSub.mutate(
        {
          project_id: projectId,
          trigger,
          filters,
          in_app: inApp,
          project_channel_ids: selectedProjectChannels,
          user_channel_ids: selectedUserChannels,
          cooldown_seconds: cooldownSeconds,
        },
        {
          onSuccess: () => {
            toast.success("Subscription created");
            onSaved();
          },
          onError: (err) => toast.error(`Failed: ${err.message}`),
        },
      );
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>
          {isEdit ? "Edit Subscription" : "New Subscription"}
        </DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="sub-dialog-project">Project</Label>
          <Select
            value={projectId}
            onValueChange={handleProjectChange}
            disabled={isEdit}
          >
            <SelectTrigger id="sub-dialog-project">
              <SelectValue placeholder="Select a project" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name} ({p.slug})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {isEdit && (
            <p className="text-xs text-muted-foreground">
              Project can&apos;t be changed. Delete and recreate to move
              this subscription to a different project.
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="sub-dialog-trigger">Trigger</Label>
          <Select
            value={trigger}
            onValueChange={(v) => setTrigger(v as TriggerType)}
          >
            <SelectTrigger id="sub-dialog-trigger">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TRIGGERS.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Priority filter, v1.0.18 added the inline help line so
            users know it requires @z4j_meta annotation on the task. */}
        <div
          className="space-y-2"
          role="group"
          aria-labelledby="sub-dialog-priority-heading"
        >
          <div className="flex items-baseline justify-between">
            <span
              id="sub-dialog-priority-heading"
              className="text-sm font-medium leading-none"
            >
              Priority filter
            </span>
            <span className="text-xs text-muted-foreground">
              Empty = all priorities
            </span>
          </div>
          <div className="rounded-md border p-3">
            <div className="flex flex-wrap gap-3">
              {PRIORITIES.map((p) => (
                <label
                  key={p}
                  className="flex items-center gap-1.5 text-sm cursor-pointer"
                >
                  <Checkbox
                    checked={priorities.includes(p)}
                    onCheckedChange={() => togglePriority(p)}
                  />
                  <span className="capitalize">{p}</span>
                </label>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Only fires for tasks annotated with{" "}
              <code className="rounded bg-muted px-1 py-0.5">
                @z4j_meta(priority="critical")
              </code>{" "}
              etc. Tasks without an explicit priority default to{" "}
              <code>normal</code>.
            </p>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="sub-dialog-task-pattern">
            Task name pattern (optional)
          </Label>
          <Input
            id="sub-dialog-task-pattern"
            placeholder="e.g. app.tasks.critical.* (fnmatch)"
            value={taskNamePattern}
            onChange={(e) => setTaskNamePattern(e.target.value)}
          />
        </div>

        {/* v1.0.18: queue filter input. Backend supported it from
            day 1 but the personal sub dialog never rendered it. */}
        <div className="space-y-2">
          <Label htmlFor="sub-dialog-queue">Queue filter (optional)</Label>
          <Input
            id="sub-dialog-queue"
            placeholder="e.g. billing (exact match; empty = all queues)"
            value={queueFilter}
            onChange={(e) => setQueueFilter(e.target.value)}
          />
        </div>

        <div
          className="space-y-2"
          role="group"
          aria-labelledby="sub-dialog-deliver-heading"
        >
          <span
            id="sub-dialog-deliver-heading"
            className="text-sm font-medium leading-none"
          >
            Deliver via
          </span>
          <div className="space-y-2 rounded-md border p-3">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <Checkbox
                checked={inApp}
                onCheckedChange={(c) => setInApp(c === true)}
              />
              <span>In-app (the bell menu)</span>
            </label>

            {userChannels && userChannels.length > 0 && (
              <div className="space-y-1.5 border-t pt-2">
                <p className="text-xs font-medium text-muted-foreground">
                  Your personal channels
                </p>
                {userChannels.map((ch) => (
                  <label
                    key={ch.id}
                    className="flex items-center gap-2 text-sm cursor-pointer"
                  >
                    <Checkbox
                      checked={selectedUserChannels.includes(ch.id)}
                      onCheckedChange={() => toggleUserChannel(ch.id)}
                    />
                    <span>{ch.name}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {ch.type}
                    </Badge>
                  </label>
                ))}
              </div>
            )}

            {projectChannels && projectChannels.length > 0 && (
              <div className="space-y-1.5 border-t pt-2">
                <p className="text-xs font-medium text-muted-foreground">
                  Project channels (shared)
                </p>
                {projectChannels.map((ch) => (
                  <label
                    key={ch.id}
                    className="flex items-center gap-2 text-sm cursor-pointer"
                  >
                    <Checkbox
                      checked={selectedProjectChannels.includes(ch.id)}
                      onCheckedChange={() => toggleProjectChannel(ch.id)}
                    />
                    <span>{ch.name}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {ch.type}
                    </Badge>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="sub-dialog-cooldown">Cooldown (seconds)</Label>
          <Input
            id="sub-dialog-cooldown"
            type="number"
            min={0}
            max={86400}
            value={cooldown}
            onChange={(e) => setCooldown(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            Minimum interval between firings for the same task name. 0 = no
            cooldown.
          </p>
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button type="submit" disabled={isPending}>
          {isPending
            ? isEdit
              ? "Saving..."
              : "Creating..."
            : isEdit
              ? "Save Changes"
              : "Create Subscription"}
        </Button>
      </DialogFooter>
    </form>
  );
}
