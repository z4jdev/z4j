/**
 * User settings - personal notification channels.
 *
 * CRUD for the user's own delivery destinations. These can be attached
 * to any subscription the user creates across all their projects.
 *
 * Feature parity with the project-level Providers page
 * (``_authenticated.projects.$slug.settings.providers.tsx``): create,
 * edit, test, delete + SMTP quick presets + Gmail app-password hint.
 * The two pages share the same test-payload + result shape so the
 * dashboard toast renderer works against either.
 */
import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Globe,
  Mail,
  Pencil,
  Plus,
  RefreshCw,
  TestTube,
  Trash2,
  Webhook,
  X,
  XCircle,
} from "lucide-react";
import {
  DiscordIcon,
  PagerDutyIcon,
  SlackIcon,
  TelegramIcon,
} from "@/components/icons/brand-icons";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { EmptyState } from "@/components/domain/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { PageHeader } from "@/components/domain/page-header";
import { api } from "@/lib/api";
import {
  useChannels,
  useCreateUserChannel,
  useDeleteUserChannel,
  useImportUserChannelFromProject,
  useTestUserChannel,
  useTestUserChannelConfig,
  useUpdateUserChannel,
  useUserChannels,
  type ChannelTestResult,
  type ChannelType,
  type NotificationChannel,
  type UserChannel,
} from "@/hooks/use-notifications";
import { useProjects } from "@/hooks/use-projects";

const CHANNEL_ICONS = {
  webhook: Webhook,
  email: Mail,
  slack: SlackIcon,
  telegram: TelegramIcon,
  pagerduty: PagerDutyIcon,
  discord: DiscordIcon,
} as const;

const MASK = "••••••••";

export function MyChannelsTab() {
  const { data: channels, isLoading, isFetching } = useUserChannels();
  const deleteChannel = useDeleteUserChannel();
  const testChannel = useTestUserChannel();
  const [dialogState, setDialogState] = useState<
    | { mode: "closed" }
    | { mode: "create" }
    | { mode: "edit"; channel: UserChannel }
    | { mode: "import" }
  >({ mode: "closed" });
  // Per-card test result so the Test button produces visible
  // feedback even if the corner toast is missed. See providers.tsx
  // for the rationale - mirrored here for parity. Persistent,
  // dismissed manually via the × button.
  const [testResults, setTestResults] = useState<
    Record<string, ChannelTestResult>
  >({});
  const { confirm, dialog: confirmDialog } = useConfirm();

  const closeDialog = () => setDialogState({ mode: "closed" });

  const recordTestResult = (id: string, res: ChannelTestResult) => {
    setTestResults((prev) => ({ ...prev, [id]: res }));
  };

  const dismissTestResult = (id: string) => {
    setTestResults((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {confirmDialog}
      <PageHeader
        title={
          <>
            Global Channels
            {isFetching && !isLoading && (
              <RefreshCw className="ml-2 inline size-3 animate-spin text-muted-foreground" />
            )}
          </>
        }
        description="Your personal delivery destinations - webhook, email, Slack, or Telegram. Attach these to any subscription across all your projects."
        actions={
          <>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm">
                  <Plus className="size-4" />
                  Add Channel
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuItem
                  onClick={() => setDialogState({ mode: "create" })}
                  className="flex flex-col items-start gap-0.5"
                >
                  <span className="font-medium">From scratch</span>
                  <span className="text-xs text-muted-foreground">
                    Create a new personal channel and enter credentials.
                  </span>
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => setDialogState({ mode: "import" })}
                  className="flex flex-col items-start gap-0.5"
                >
                  <span className="font-medium">Copy from a project</span>
                  <span className="text-xs text-muted-foreground">
                    Import a project's channel as a personal copy.
                  </span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Dialog
              open={dialogState.mode !== "closed"}
              onOpenChange={(open) => {
                if (!open) closeDialog();
              }}
            >
              <DialogContent>
                {dialogState.mode === "create" || dialogState.mode === "edit" ? (
                  <UserChannelDialog
                    mode={dialogState.mode}
                    channel={
                      dialogState.mode === "edit"
                        ? dialogState.channel
                        : undefined
                    }
                    onClose={closeDialog}
                  />
                ) : dialogState.mode === "import" ? (
                  <ImportFromProjectDialog onClose={closeDialog} />
                ) : null}
              </DialogContent>
            </Dialog>
          </>
        }
      />

      {isLoading && <Skeleton className="h-32 w-full" />}
      {channels && channels.length === 0 && (
        <EmptyState
          icon={Globe}
          title="No channels yet"
          description="Add a personal webhook, email, Slack, or Telegram destination."
        />
      )}
      {channels && channels.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {channels.map((ch) => {
            const Icon = CHANNEL_ICONS[ch.type] ?? Globe;
            const testingThis =
              testChannel.isPending && testChannel.variables === ch.id;
            const testResult = testResults[ch.id];
            return (
              <Card key={ch.id} className="flex flex-col gap-3 p-4">
                <div className="flex items-start gap-3">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold">{ch.name}</span>
                    <Badge variant={ch.is_active ? "success" : "muted"}>
                      {ch.is_active ? "active" : "disabled"}
                    </Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {ch.type}
                    {ch.type === "webhook" &&
                      typeof ch.config.url === "string" &&
                      ` · ${ch.config.url.slice(0, 40)}...`}
                    {ch.type === "email" &&
                      typeof ch.config.smtp_host === "string" &&
                      ` · ${ch.config.smtp_host}`}
                    {ch.type === "slack" &&
                      typeof ch.config.webhook_url === "string" &&
                      ` · hooks.slack.com`}
                    {ch.type === "telegram" &&
                      typeof ch.config.chat_id === "string" &&
                      ` · chat ${ch.config.chat_id}`}
                    {ch.type === "pagerduty" &&
                      typeof ch.config.severity_default === "string" &&
                      ` · default severity: ${ch.config.severity_default}`}
                    {ch.type === "discord" &&
                      typeof ch.config.webhook_url === "string" &&
                      ` · discord.com/api/webhooks/...`}
                  </p>
                </div>
                <div className="flex shrink-0 items-center">
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Test ${ch.name}`}
                    title="Send a test notification"
                    disabled={testingThis}
                    className="text-muted-foreground hover:text-primary"
                    onClick={() =>
                      testChannel.mutate(ch.id, {
                        // Card-level test: inline banner only, no
                        // toast. See providers.tsx for rationale -
                        // the card anchors the result, so a
                        // duplicate toast was pure visual noise.
                        onSuccess: (res) => recordTestResult(ch.id, res),
                        onError: (err) =>
                          recordTestResult(ch.id, {
                            success: false,
                            status_code: null,
                            response_body: null,
                            error:
                              err instanceof Error
                                ? err.message
                                : "Test failed",
                          }),
                      })
                    }
                  >
                    {testingThis ? (
                      <RefreshCw className="size-4 animate-spin" />
                    ) : (
                      <TestTube className="size-4" />
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Edit ${ch.name}`}
                    title="Edit channel"
                    className="text-muted-foreground hover:text-primary"
                    onClick={() =>
                      setDialogState({ mode: "edit", channel: ch })
                    }
                  >
                    <Pencil className="size-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Delete ${ch.name}`}
                    title="Delete channel"
                    className="text-muted-foreground hover:text-destructive"
                    onClick={() =>
                      confirm({
                        title: "Delete channel",
                        description: (
                          <>
                            This removes <code>{ch.name}</code> and any
                            subscriptions pointing to it.
                          </>
                        ),
                        confirmLabel: "Delete",
                        onConfirm: () =>
                          deleteChannel.mutate(ch.id, {
                            onSuccess: () =>
                              toast.success("Channel deleted"),
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
                </div>
                {testResult && (
                  <div
                    role="status"
                    aria-live="polite"
                    className={
                      testResult.success
                        ? "rounded-md border border-success/40 bg-success/10 px-3 py-2 text-xs text-success"
                        : "rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
                    }
                  >
                    <div className="flex items-start gap-2">
                      {testResult.success ? (
                        <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-success" />
                      ) : (
                        <XCircle className="mt-0.5 size-3.5 shrink-0" />
                      )}
                      <div className="min-w-0 flex-1">
                        <p className="font-medium">
                          {testResult.success
                            ? testResult.status_code
                              ? `Test sent (HTTP ${testResult.status_code})`
                              : "Test sent"
                            : "Test failed"}
                        </p>
                        {!testResult.success && testResult.error && (
                          <p className="mt-0.5 break-words opacity-90">
                            {testResult.error}
                          </p>
                        )}
                      </div>
                      <button
                        type="button"
                        aria-label="Dismiss test result"
                        onClick={() => dismissTestResult(ch.id)}
                        className="shrink-0 rounded p-0.5 opacity-70 transition-opacity hover:opacity-100 focus:opacity-100 focus:outline-none focus:ring-1 focus:ring-current"
                      >
                        <X className="size-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// User channel dialog - handles create AND edit
// ---------------------------------------------------------------------------

interface ImportFromProjectDialogProps {
  onClose: () => void;
}

/**
 * Picker dialog for copying a project's channel into the operator's
 * personal channels. Two-step pick: project first, then channel.
 * Backend-side copy: the secret never crosses the wire (see
 * useImportUserChannelFromProject).
 */
function ImportFromProjectDialog({ onClose }: ImportFromProjectDialogProps) {
  const { data: projects, isLoading: projectsLoading } = useProjects();
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const { data: projectChannels, isLoading: channelsLoading } = useChannels(
    selectedProject ?? "",
  );
  const importChannel = useImportUserChannelFromProject();
  // Multi-select: a Set of channel IDs the operator has checked. Each
  // confirmation fires N independent import calls (one per ID); we
  // batch the toasts to a single summary at the end so a 5-import run
  // doesn't pop 5 stacked toasts.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);

  const toggleSelected = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const allChecked =
    projectChannels !== undefined &&
    projectChannels.length > 0 &&
    selectedIds.size === projectChannels.length;

  const toggleAll = () => {
    if (!projectChannels) return;
    if (allChecked) setSelectedIds(new Set());
    else setSelectedIds(new Set(projectChannels.map((c) => c.id)));
  };

  const handleImport = async () => {
    if (!selectedProject || selectedIds.size === 0) return;
    setSubmitting(true);
    let okCount = 0;
    const failures: string[] = [];
    for (const id of selectedIds) {
      const ch = projectChannels?.find((c) => c.id === id);
      try {
        await importChannel.mutateAsync({
          project_slug: selectedProject,
          channel_id: id,
        });
        okCount += 1;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        failures.push(`${ch?.name ?? id}: ${msg}`);
      }
    }
    setSubmitting(false);
    if (okCount > 0) {
      toast.success(
        okCount === 1
          ? "Imported 1 channel"
          : `Imported ${okCount} channels`,
      );
    }
    if (failures.length > 0) {
      toast.error(
        failures.length === 1
          ? `Import failed: ${failures[0]}`
          : `${failures.length} imports failed (e.g. ${failures[0]})`,
      );
    }
    if (okCount > 0 && failures.length === 0) onClose();
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Copy from a Project</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <p className="text-sm text-muted-foreground">
          Pick one or more channels from a project to copy into your
          personal channels. Secrets are copied server-side and never
          displayed. Each imported channel is named &quot;Copy of
          {" "}{"{name}"}&quot;.
        </p>

        <div className="space-y-2">
          <Label htmlFor="import-project">Project</Label>
          {projectsLoading && <Skeleton className="h-9 w-full" />}
          {projects && projects.length === 0 && (
            <div className="rounded-md border border-border bg-muted/40 p-4 text-sm text-muted-foreground">
              You're not a member of any project yet.
            </div>
          )}
          {projects && projects.length > 0 && (
            <Select
              value={selectedProject ?? ""}
              onValueChange={(v) => {
                setSelectedProject(v);
                setSelectedIds(new Set());
              }}
            >
              <SelectTrigger id="import-project">
                <SelectValue placeholder="Select a project..." />
              </SelectTrigger>
              <SelectContent>
                {projects.map((p) => (
                  <SelectItem key={p.id} value={p.slug}>
                    {p.name}{" "}
                    <span className="text-xs text-muted-foreground">
                      · {p.slug}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {selectedProject && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Source channels</Label>
              {projectChannels && projectChannels.length > 0 && (
                <button
                  type="button"
                  onClick={toggleAll}
                  className="text-xs text-primary hover:underline"
                >
                  {allChecked ? "Clear all" : "Select all"}
                </button>
              )}
            </div>
            {channelsLoading && <Skeleton className="h-32 w-full" />}
            {projectChannels && projectChannels.length === 0 && (
              <div className="rounded-md border border-border bg-muted/40 p-4 text-sm text-muted-foreground">
                This project has no channels yet.
              </div>
            )}
            {projectChannels && projectChannels.length > 0 && (
              <div className="max-h-72 overflow-y-auto rounded-md border border-border">
                {projectChannels.map((ch) => {
                  const Icon =
                    CHANNEL_ICONS[ch.type as keyof typeof CHANNEL_ICONS] ??
                    Globe;
                  const isChecked = selectedIds.has(ch.id);
                  return (
                    <label
                      key={ch.id}
                      className={`flex cursor-pointer items-center gap-3 border-b border-border/50 px-3 py-2.5 text-sm last:border-b-0 hover:bg-muted/50 ${
                        isChecked ? "bg-primary/10" : ""
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSelected(ch.id)}
                        className="size-4 shrink-0 cursor-pointer accent-primary"
                      />
                      <Icon className="size-4 shrink-0 text-muted-foreground" />
                      <div className="min-w-0 flex-1">
                        <div className="font-medium">{ch.name}</div>
                        <div className="text-xs text-muted-foreground">
                          {ch.type}
                          {!ch.is_active && " · disabled"}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
      <DialogFooter className="mt-6">
        <Button
          type="button"
          variant="outline"
          onClick={onClose}
          disabled={submitting}
        >
          Cancel
        </Button>
        <Button
          type="button"
          onClick={handleImport}
          disabled={
            !selectedProject || selectedIds.size === 0 || submitting
          }
        >
          {submitting
            ? `Importing ${selectedIds.size}...`
            : selectedIds.size === 0
              ? "Import"
              : selectedIds.size === 1
                ? "Import 1 channel"
                : `Import ${selectedIds.size} channels`}
        </Button>
      </DialogFooter>
    </>
  );
}

interface UserChannelDialogProps {
  mode: "create" | "edit";
  channel?: UserChannel;
  onClose: () => void;
}

function UserChannelDialog({ mode, channel, onClose }: UserChannelDialogProps) {
  const createChannel = useCreateUserChannel();
  const updateChannel = useUpdateUserChannel();
  const testConfig = useTestUserChannelConfig();

  // Test-result alert rendered inline inside the dialog body.
  // Sonner toasts render behind the dimmed Dialog overlay from the
  // user's point of view - inline Alert puts feedback where they're
  // looking.
  const [testResult, setTestResult] = useState<ChannelTestResult | null>(null);
  const [testingSaved, setTestingSaved] = useState(false);

  const initial = extractFormFields(mode === "edit" ? channel : undefined);

  const [type, setType] = useState<ChannelType>(
    mode === "edit" && channel ? channel.type : "webhook",
  );
  const [name, setName] = useState(initial.name);
  const [url, setUrl] = useState(initial.url);
  const [smtpHost, setSmtpHost] = useState(initial.smtpHost);
  const [smtpPort, setSmtpPort] = useState(initial.smtpPort);
  const [smtpUser, setSmtpUser] = useState(initial.smtpUser);
  const [smtpPass, setSmtpPass] = useState(initial.smtpPass);
  const [fromAddr, setFromAddr] = useState(initial.fromAddr);
  const [toAddrs, setToAddrs] = useState(initial.toAddrs);
  const [slackUrl, setSlackUrl] = useState(initial.slackUrl);
  const [botToken, setBotToken] = useState(initial.botToken);
  const [chatId, setChatId] = useState(initial.chatId);
  const [pdKey, setPdKey] = useState(initial.pdKey);
  const [pdSeverity, setPdSeverity] = useState(initial.pdSeverity);
  const [discordUrl, setDiscordUrl] = useState(initial.discordUrl);

  // Clear type-specific state when the user switches channel type in
  // create mode so an abandoned-webhook URL doesn't leak into the
  // Slack field.
  useEffect(() => {
    if (mode === "edit") return;
    setUrl("");
    setSmtpHost("");
    setSmtpPort("587");
    setSmtpUser("");
    setSmtpPass("");
    setFromAddr("");
    setToAddrs("");
    setSlackUrl("");
    setBotToken("");
    setChatId("");
    setPdKey("");
    setPdSeverity("warning");
    setDiscordUrl("");
  }, [type, mode]);

  /**
   * Build the config dict for create (full) or edit (merge-friendly).
   *
   * In edit mode, secret fields that the user left blank are
   * OMITTED from the payload. Backend's ``_safe_merge_config``
   * preserves the stored value when the key is missing or equal to
   * the mask. Sending an empty string overwrites - bug we don't
   * reintroduce.
   */
  const buildConfig = (): Record<string, unknown> => {
    const editing = mode === "edit";
    const keepIfBlank = (v: string): string | undefined =>
      editing && !v ? undefined : v;

    switch (type) {
      case "webhook":
        return { url };
      case "email": {
        const cfg: Record<string, unknown> = {
          smtp_host: smtpHost,
          smtp_port: parseInt(smtpPort, 10),
          smtp_user: smtpUser,
          smtp_tls: true,
          from_addr: fromAddr || smtpUser,
          to_addrs: toAddrs.split(",").map((s) => s.trim()).filter(Boolean),
        };
        const pass = keepIfBlank(smtpPass);
        if (pass !== undefined) cfg.smtp_pass = pass;
        return cfg;
      }
      case "slack":
        return { webhook_url: slackUrl };
      case "telegram": {
        const cfg: Record<string, unknown> = { chat_id: chatId };
        const tok = keepIfBlank(botToken);
        if (tok !== undefined) cfg.bot_token = tok;
        return cfg;
      }
      case "pagerduty": {
        const cfg: Record<string, unknown> = {
          severity_default: pdSeverity || "warning",
        };
        const key = keepIfBlank(pdKey);
        if (key !== undefined) cfg.integration_key = key;
        return cfg;
      }
      case "discord":
        return { webhook_url: discordUrl };
      default:
        return {};
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const config = buildConfig();
    if (mode === "edit" && channel) {
      updateChannel.mutate(
        { id: channel.id, body: { name, config } },
        {
          onSuccess: () => {
            toast.success("Channel updated");
            onClose();
          },
          onError: (err) => toast.error(`Failed: ${err.message}`),
        },
      );
    } else {
      createChannel.mutate(
        { name, type, config },
        {
          onSuccess: () => {
            toast.success("Channel created");
            onClose();
          },
          onError: (err) => toast.error(`Failed: ${err.message}`),
        },
      );
    }
  };

  const handleTest = () => {
    // Reset so the new test's outcome replaces any stale alert.
    setTestResult(null);

    if (mode === "edit" && channel) {
      // Test the saved config - form state is incomplete because
      // secrets are masked in the list response.
      setTestingSaved(true);
      void testSavedUserChannel(channel.id)
        .then((res) => setTestResult(res))
        .catch((err) =>
          setTestResult({
            success: false,
            status_code: null,
            response_body: null,
            error: err instanceof Error ? err.message : "Test failed",
          }),
        )
        .finally(() => setTestingSaved(false));
      return;
    }
    testConfig.mutate(
      { type, config: buildConfig() },
      {
        onSuccess: (res) => setTestResult(res),
        onError: (err) =>
          setTestResult({
            success: false,
            status_code: null,
            response_body: null,
            error: err instanceof Error ? err.message : "Test failed",
          }),
      },
    );
  };

  const submitting = createChannel.isPending || updateChannel.isPending;
  const testing = testConfig.isPending || testingSaved;
  const title =
    mode === "edit" ? "Edit Personal Channel" : "Add Personal Channel";
  const submitLabel = mode === "edit" ? "Save Changes" : "Create Channel";

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="user-channel-type">Channel type</Label>
          <Select
            value={type}
            onValueChange={(v) => setType(v as ChannelType)}
            disabled={mode === "edit"}
          >
            <SelectTrigger id="user-channel-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="webhook">Webhook</SelectItem>
              <SelectItem value="email">Email (SMTP)</SelectItem>
              <SelectItem value="slack">Slack</SelectItem>
              <SelectItem value="telegram">Telegram</SelectItem>
              <SelectItem value="pagerduty">PagerDuty</SelectItem>
              <SelectItem value="discord">Discord</SelectItem>
            </SelectContent>
          </Select>
          {mode === "edit" && (
            <p className="text-xs text-muted-foreground">
              Channel type is locked after creation. To switch type, delete
              and re-create.
            </p>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="user-channel-name">Name</Label>
          <Input
            id="user-channel-name"
            placeholder="e.g. My phone, personal email"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>

        {type === "webhook" && (
          <div className="space-y-2">
            <Label htmlFor="user-channel-webhook-url">Webhook URL</Label>
            <Input
              id="user-channel-webhook-url"
              type="url"
              pattern="https://.*"
              placeholder="https://..."
              title="Must start with https://"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </div>
        )}

        {type === "email" && (
          <>
            {/* SMTP provider presets - one-click host + port fill.
                Identical set to the project-level Providers page so
                users don't have to remember "is Brevo on the other
                page too?". */}
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">
                Quick presets
              </Label>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSmtpHost("smtp.gmail.com");
                    setSmtpPort("587");
                  }}
                >
                  Gmail / Workspace
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSmtpHost("smtp.mailgun.org");
                    setSmtpPort("587");
                  }}
                >
                  Mailgun
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSmtpHost("smtp-relay.brevo.com");
                    setSmtpPort("587");
                  }}
                >
                  Brevo
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSmtpHost("smtp.sendgrid.net");
                    setSmtpPort("587");
                  }}
                >
                  SendGrid
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSmtpHost("smtp.postmarkapp.com");
                    setSmtpPort("587");
                  }}
                >
                  Postmark
                </Button>
              </div>
              {smtpHost === "smtp.gmail.com" && (
                <p className="text-xs text-muted-foreground">
                  Gmail requires 2-step verification + an{" "}
                  <a
                    href="https://support.google.com/accounts/answer/185833"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline hover:no-underline"
                  >
                    app password
                  </a>
                  . Use your full Gmail address as the username and the
                  16-character app password as the SMTP password.
                </p>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="user-channel-smtp-host">SMTP Host</Label>
                <Input
                  id="user-channel-smtp-host"
                  placeholder="smtp.gmail.com"
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="user-channel-smtp-port">Port</Label>
                <Input
                  id="user-channel-smtp-port"
                  type="number"
                  value={smtpPort}
                  onChange={(e) => setSmtpPort(e.target.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="user-channel-smtp-user">Username</Label>
                <Input
                  id="user-channel-smtp-user"
                  value={smtpUser}
                  onChange={(e) => setSmtpUser(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="user-channel-smtp-pass">Password</Label>
                <Input
                  id="user-channel-smtp-pass"
                  type="password"
                  value={smtpPass}
                  onChange={(e) => setSmtpPass(e.target.value)}
                  placeholder={
                    mode === "edit" ? "Leave blank to keep current" : undefined
                  }
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-channel-from">From address</Label>
              <Input
                id="user-channel-from"
                type="email"
                placeholder="alerts@example.com"
                value={fromAddr}
                onChange={(e) => setFromAddr(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-channel-to">
                To addresses (comma-separated)
              </Label>
              <Input
                id="user-channel-to"
                placeholder="me@example.com"
                value={toAddrs}
                onChange={(e) => setToAddrs(e.target.value)}
                required
              />
            </div>
          </>
        )}

        {type === "slack" && (
          <div className="space-y-2">
            <Label htmlFor="user-channel-slack-url">Slack Webhook URL</Label>
            <Input
              id="user-channel-slack-url"
              type="url"
              pattern="https://hooks\.slack\.com/.*"
              placeholder="https://hooks.slack.com/services/..."
              title="Must be a Slack webhook URL starting with https://hooks.slack.com/"
              value={slackUrl}
              onChange={(e) => setSlackUrl(e.target.value)}
              required
            />
          </div>
        )}

        {type === "telegram" && (
          <>
            <div className="space-y-2">
              <Label htmlFor="user-channel-bot-token">Bot Token</Label>
              <Input
                id="user-channel-bot-token"
                placeholder={
                  mode === "edit"
                    ? "Leave blank to keep current"
                    : "123456:ABC-DEF..."
                }
                value={botToken}
                onChange={(e) => setBotToken(e.target.value)}
                required={mode === "create"}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-channel-chat-id">Chat ID</Label>
              <Input
                id="user-channel-chat-id"
                placeholder="-100123456789"
                value={chatId}
                onChange={(e) => setChatId(e.target.value)}
                required
              />
            </div>
          </>
        )}

        {type === "pagerduty" && (
          <>
            <div className="space-y-2">
              <Label htmlFor="user-channel-pd-key">Integration key</Label>
              <Input
                id="user-channel-pd-key"
                placeholder={
                  mode === "edit"
                    ? "Leave blank to keep current"
                    : "32-char routing key from PagerDuty"
                }
                value={pdKey}
                onChange={(e) => setPdKey(e.target.value)}
                required={mode === "create"}
              />
              <p className="text-xs text-muted-foreground">
                In PagerDuty: Service → Integrations → +Add Integration →
                Events API v2. Copy the{" "}
                <span className="font-mono">Integration Key</span>.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-channel-pd-severity">
                Default severity
              </Label>
              <Select
                value={pdSeverity}
                onValueChange={(v) => setPdSeverity(v)}
              >
                <SelectTrigger id="user-channel-pd-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">critical</SelectItem>
                  <SelectItem value="error">error</SelectItem>
                  <SelectItem value="warning">warning (default)</SelectItem>
                  <SelectItem value="info">info</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                z4j auto-maps known triggers (
                <span className="font-mono">agent.offline</span> →{" "}
                <span className="font-mono">critical</span>,{" "}
                <span className="font-mono">task.failed</span> →{" "}
                <span className="font-mono">error</span>). This default
                applies to anything else.
              </p>
            </div>
          </>
        )}

        {type === "discord" && (
          <div className="space-y-2">
            <Label htmlFor="user-channel-discord-url">
              Discord webhook URL
            </Label>
            <Input
              id="user-channel-discord-url"
              type="url"
              pattern="https://discord(app)?\.com/api/webhooks/.*"
              placeholder="https://discord.com/api/webhooks/.../..."
              title="Must be a Discord webhook URL"
              value={discordUrl}
              onChange={(e) => setDiscordUrl(e.target.value)}
              required
            />
            <p className="text-xs text-muted-foreground">
              In Discord: Server Settings → Integrations → Webhooks → New
              Webhook. Paste the canonical URL, z4j auto-appends{" "}
              <span className="font-mono">/slack</span> at dispatch time.
            </p>
          </div>
        )}
      </div>
      {testResult && (
        <Alert
          variant={testResult.success ? "success" : "destructive"}
          className="mt-4"
        >
          {testResult.success ? (
            <CheckCircle2 />
          ) : (
            <XCircle />
          )}
          <AlertTitle>
            {testResult.success
              ? testResult.status_code
                ? `Test sent (HTTP ${testResult.status_code})`
                : "Test sent"
              : "Test failed"}
          </AlertTitle>
          <AlertDescription>
            {testResult.success ? (
              <p>
                Check the destination inbox / channel for the z4j test
                message. If it doesn&apos;t arrive, verify spam folder and
                the recipient list before saving.
              </p>
            ) : (
              <>
                <p className="break-words">
                  {testResult.error ?? "Unknown error"}
                </p>
                {testResult.response_body && (
                  <p className="mt-1 font-mono text-xs opacity-80">
                    {testResult.response_body}
                  </p>
                )}
              </>
            )}
          </AlertDescription>
        </Alert>
      )}
      <DialogFooter className="mt-6 flex-row-reverse justify-between sm:flex-row-reverse sm:justify-between">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Saving..." : submitLabel}
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={handleTest}
          disabled={testing || submitting}
        >
          {testing ? (
            <>
              <RefreshCw className="size-4 animate-spin" />
              Testing...
            </>
          ) : (
            <>
              <TestTube className="size-4" />
              Test
            </>
          )}
        </Button>
      </DialogFooter>
    </form>
  );
}

/**
 * One-off call to the saved-user-channel test endpoint.
 *
 * The edit dialog routes here (not ``useTestUserChannelConfig``)
 * because secrets are masked in the list response - the form state
 * is incomplete, and the operator's real question is "does the
 * stored channel still work?".
 */
async function testSavedUserChannel(
  channelId: string,
): Promise<ChannelTestResult> {
  return api.post<ChannelTestResult>(`/user/channels/${channelId}/test`, {});
}

interface FormFields {
  name: string;
  url: string;
  smtpHost: string;
  smtpPort: string;
  smtpUser: string;
  smtpPass: string;
  fromAddr: string;
  toAddrs: string;
  slackUrl: string;
  botToken: string;
  chatId: string;
  pdKey: string;
  pdSeverity: string;
  discordUrl: string;
}

function extractFormFields(ch: UserChannel | undefined): FormFields {
  const empty: FormFields = {
    name: "",
    url: "",
    smtpHost: "",
    smtpPort: "587",
    smtpUser: "",
    smtpPass: "",
    fromAddr: "",
    toAddrs: "",
    slackUrl: "",
    botToken: "",
    chatId: "",
    pdKey: "",
    pdSeverity: "warning",
    discordUrl: "",
  };
  if (!ch) return empty;
  const cfg = ch.config ?? {};
  const str = (v: unknown): string => (typeof v === "string" ? v : "");
  const toAddrsVal = (v: unknown): string =>
    Array.isArray(v) ? v.join(", ") : str(v);
  // Masked secrets come back as MASK. Present as empty so the
  // user can leave the field alone (keeps current) or type a new
  // value (replaces).
  const unmask = (v: unknown): string => {
    const s = str(v);
    return s === MASK ? "" : s;
  };
  // Discord and Slack both store webhook in cfg.webhook_url -
  // disambiguate by ch.type so an edit on one doesn't pre-fill the
  // other's input.
  const isDiscord = ch.type === "discord";
  const isSlack = ch.type === "slack";
  return {
    name: ch.name,
    url: str(cfg.url),
    smtpHost: str(cfg.smtp_host),
    smtpPort:
      typeof cfg.smtp_port === "number"
        ? String(cfg.smtp_port)
        : str(cfg.smtp_port) || "587",
    smtpUser: str(cfg.smtp_user),
    smtpPass: unmask(cfg.smtp_pass),
    fromAddr: str(cfg.from_addr),
    toAddrs: toAddrsVal(cfg.to_addrs),
    slackUrl: isSlack ? str(cfg.webhook_url) : "",
    botToken: unmask(cfg.bot_token),
    chatId: str(cfg.chat_id),
    pdKey: unmask(cfg.integration_key),
    pdSeverity: str(cfg.severity_default) || "warning",
    discordUrl: isDiscord ? str(cfg.webhook_url) : "",
  };
}
