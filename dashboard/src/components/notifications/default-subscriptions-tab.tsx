/**
 * Project settings - Default subscriptions (admin onboarding templates).
 *
 * Admins define what notifications new members start with. These rows
 * are copied into each member's personal subscription list when they
 * join; existing members are not retroactively affected.
 */
import { useState } from "react";
import { BellRing, Lock, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { EmptyState } from "@/components/domain/empty-state";
import { useIsProjectAdmin } from "@/hooks/use-memberships";
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
  useCreateDefaultSubscription,
  useDefaultSubscriptions,
  useDeleteDefaultSubscription,
  useUpdateDefaultSubscription,
  type NotificationChannel,
  type ProjectDefaultSubscription,
  type TriggerType,
} from "@/hooks/use-notifications";

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

export function DefaultSubscriptionsTab({ slug }: { slug: string }) {
  const isAdmin = useIsProjectAdmin(slug);
  const { data: defaults, isLoading, isFetching } =
    useDefaultSubscriptions(slug);
  const { data: channels } = useChannels(slug);
  const deleteDefault = useDeleteDefaultSubscription(slug);
  const [dialogOpen, setDialogOpen] = useState(false);
  // When set, the dialog opens in EDIT mode pre-filled with this
  // row's values. When null, the dialog is in CREATE mode. v1.0.18
  // unified the two modes so admins can adjust an existing default
  // without the delete + recreate workaround.
  const [editing, setEditing] = useState<ProjectDefaultSubscription | null>(
    null,
  );
  const { confirm, dialog: confirmDialog } = useConfirm();

  const openCreate = () => {
    setEditing(null);
    setDialogOpen(true);
  };
  const openEdit = (d: ProjectDefaultSubscription) => {
    setEditing(d);
    setDialogOpen(true);
  };
  const closeDialog = () => {
    setDialogOpen(false);
    // Defer clearing ``editing`` so the dialog content doesn't
    // visibly flip to create mode mid-close-animation.
    setTimeout(() => setEditing(null), 150);
  };

  const channelMap = new Map((channels ?? []).map((c) => [c.id, c]));

  if (!isAdmin) {
    return (
      <EmptyState
        icon={Lock}
        title="Admin only"
        description="Project subscriptions can only be configured by project admins."
      />
    );
  }

  return (
    <div className="space-y-4">
      {confirmDialog}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">
            Project Subscriptions
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </h3>
          <p className="text-xs text-muted-foreground">
            What should new members automatically subscribe to?
          </p>
        </div>
        <Dialog
          open={dialogOpen}
          onOpenChange={(open) => {
            if (!open) closeDialog();
            else setDialogOpen(true);
          }}
        >
          <DialogTrigger asChild>
            <Button size="sm" onClick={openCreate}>
              <Plus className="size-4" />
              New subscription
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DefaultSubscriptionDialog
              slug={slug}
              channels={channels ?? []}
              existing={editing}
              onSaved={closeDialog}
            />
          </DialogContent>
        </Dialog>
      </div>

      <div className="rounded-md border border-dashed bg-muted/40 px-4 py-3 text-xs text-muted-foreground">
        These templates are copied into each new member&apos;s subscriptions
        when they join. Existing members are not affected.
      </div>

      {isLoading && <Skeleton className="h-32 w-full" />}
      {defaults && defaults.length === 0 && (
        <EmptyState
          icon={BellRing}
          title="No project subscriptions configured"
          description="Add a project subscription so new members automatically receive key notifications."
        />
      )}
      {defaults && defaults.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Trigger</TableHead>
                <TableHead>In-app</TableHead>
                <TableHead>Project channels</TableHead>
                <TableHead>Cooldown</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {defaults.map((d) => (
                <TableRow key={d.id}>
                  <TableCell>
                    <Badge variant="outline">
                      {triggerLabel(d.trigger)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {d.in_app ? (
                      <Badge variant="success">yes</Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">no</span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {d.project_channel_ids.length === 0
                      ? "-"
                      : d.project_channel_ids
                          .map(
                            (id) =>
                              channelMap.get(id)?.name ?? "deleted",
                          )
                          .join(", ")}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {d.cooldown_seconds}s
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Edit ${triggerLabel(d.trigger)} project subscription`}
                        className="text-muted-foreground hover:text-foreground"
                        onClick={() => openEdit(d)}
                      >
                        <Pencil className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Delete ${triggerLabel(d.trigger)} project subscription`}
                        className="text-muted-foreground hover:text-destructive"
                        onClick={() =>
                          confirm({
                            title: "Delete project subscription",
                            description: (
                              <>
                                Stop auto-subscribing new members to the{" "}
                                <code>{triggerLabel(d.trigger)}</code> trigger?
                                Existing members are not affected.
                              </>
                            ),
                            confirmLabel: "Delete",
                            onConfirm: () =>
                              deleteDefault.mutate(d.id, {
                                onSuccess: () =>
                                  toast.success("Default deleted"),
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
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Default subscription dialog (create + edit, v1.0.18)
// ---------------------------------------------------------------------------

/**
 * Unified create/edit dialog. When ``existing`` is null the dialog
 * is in CREATE mode and POSTs to /defaults; when ``existing`` is a
 * row, the form is pre-filled with that row's values and the
 * submit button PATCHes /defaults/{id}. Lets admins adjust an
 * existing default's channels / in-app / cooldown / trigger
 * without the delete + recreate workaround.
 */
function DefaultSubscriptionDialog({
  slug,
  channels,
  existing,
  onSaved,
}: {
  slug: string;
  channels: NotificationChannel[];
  existing: ProjectDefaultSubscription | null;
  onSaved: () => void;
}) {
  const isEdit = existing !== null;
  const createDefault = useCreateDefaultSubscription(slug);
  const updateDefault = useUpdateDefaultSubscription(slug);
  const [trigger, setTrigger] = useState<TriggerType>(
    (existing?.trigger as TriggerType) ?? "task.failed",
  );
  const [inApp, setInApp] = useState(existing?.in_app ?? true);
  const [selectedChannels, setSelectedChannels] = useState<string[]>(
    existing?.project_channel_ids ?? [],
  );
  const [cooldown, setCooldown] = useState(
    String(existing?.cooldown_seconds ?? 300),
  );
  // v1.0.18: filter parity with personal subscriptions. Backend
  // SubscriptionFilters has supported priority/task_name/queue
  // since v1.0.x; the defaults dialog just never rendered them.
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

  const isPending = isEdit ? updateDefault.isPending : createDefault.isPending;

  const toggleChannel = (id: string) => {
    setSelectedChannels((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );
  };
  const togglePriority = (p: string) => {
    setPriorities((cur) =>
      cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p],
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const filters: Record<string, unknown> = {};
    if (priorities.length > 0) filters.priority = priorities;
    if (taskNamePattern.trim())
      filters.task_name_pattern = taskNamePattern.trim();
    if (queueFilter.trim()) filters.queue = queueFilter.trim();
    const body = {
      trigger,
      filters,
      in_app: inApp,
      project_channel_ids: selectedChannels,
      cooldown_seconds: parseInt(cooldown, 10) || 0,
    };
    if (isEdit && existing) {
      updateDefault.mutate(
        { id: existing.id, body },
        {
          onSuccess: () => {
            toast.success("Default updated");
            onSaved();
          },
          onError: (err) => toast.error(`Failed: ${err.message}`),
        },
      );
    } else {
      createDefault.mutate(body, {
        onSuccess: () => {
          toast.success("Default created");
          onSaved();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      });
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>
          {isEdit ? "Edit Project Subscription" : "New Project Subscription"}
        </DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="default-dialog-trigger">Trigger</Label>
          <Select
            value={trigger}
            onValueChange={(v) => setTrigger(v as TriggerType)}
          >
            <SelectTrigger id="default-dialog-trigger">
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

        {/* v1.0.18, filter parity with personal subscriptions.
            Optional narrowing so a default can scope to e.g.
            "only critical task.failed in queue=billing". Empty
            = no filter (matches all). */}
        <div
          className="space-y-2"
          role="group"
          aria-labelledby="defaults-priority-heading"
        >
          <div className="flex items-baseline justify-between">
            <span
              id="defaults-priority-heading"
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
          <Label htmlFor="default-dialog-task-name">
            Task name pattern
          </Label>
          <Input
            id="default-dialog-task-name"
            type="text"
            value={taskNamePattern}
            onChange={(e) => setTaskNamePattern(e.target.value)}
            placeholder="e.g. billing.* (fnmatch syntax; max 5 wildcards)"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="default-dialog-queue">Queue filter</Label>
          <Input
            id="default-dialog-queue"
            type="text"
            value={queueFilter}
            onChange={(e) => setQueueFilter(e.target.value)}
            placeholder="e.g. billing (exact match; empty = all queues)"
          />
        </div>

        <div
          className="space-y-2"
          role="group"
          aria-labelledby="defaults-delivery-heading"
        >
          {/* Section heading for a group of controls; a Label with
              htmlFor would need a single target and we have many,
              so this is the correct ARIA pattern. */}
          <span
            id="defaults-delivery-heading"
            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
          >
            Delivery
          </span>
          <div className="space-y-2 rounded-md border p-3">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <Checkbox
                checked={inApp}
                onCheckedChange={(c) => setInApp(c === true)}
              />
              <span>In-app (the bell menu)</span>
            </label>

            {channels.length > 0 && (
              <div className="space-y-1.5 border-t pt-2">
                <p className="text-xs font-medium text-muted-foreground">
                  Project channels
                </p>
                {channels.map((ch) => (
                  <label
                    key={ch.id}
                    className="flex items-center gap-2 text-sm cursor-pointer"
                  >
                    <Checkbox
                      checked={selectedChannels.includes(ch.id)}
                      onCheckedChange={() => toggleChannel(ch.id)}
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
          <Label htmlFor="default-dialog-cooldown">Cooldown (seconds)</Label>
          <Input
            id="default-dialog-cooldown"
            type="number"
            min={0}
            max={86400}
            value={cooldown}
            onChange={(e) => setCooldown(e.target.value)}
          />
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
              : "Create Default"}
        </Button>
      </DialogFooter>
    </form>
  );
}
