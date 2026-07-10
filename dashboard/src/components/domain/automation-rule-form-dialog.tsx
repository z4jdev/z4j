/**
 * Create / edit dialog for a single automation rule.
 *
 * Wraps brain's POST /automation/rules and PATCH /automation/rules/{id}.
 * A single component handles both modes (``existing`` prop present =>
 * edit). Like the schedule dialog this is intentionally plain React
 * state, no react-hook-form. Validation is structural (name / trigger
 * present, conditions is a JSON object, actions is a non-empty JSON
 * array) plus server-side (brain 422s on the fixed-grammar rule spec and
 * surfaces the reasons in ``details.errors``).
 *
 * New rules default to dry_run=true: they evaluate + audit what they
 * WOULD do without acting, so an operator can validate a rule against
 * live traffic before arming it. Destructive actions (retry / cancel)
 * require ADMIN + fresh MFA; the dialog warns when the actions JSON
 * contains one and the current user is not an admin, but the backend is
 * the real gate (a 403 that needs step-up is handled by the query client).
 */
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  useCreateAutomationRule,
  useUpdateAutomationRule,
  type AutomationRuleCreateBody,
  type AutomationRulePublic,
  type AutomationRuleUpdateBody,
} from "@/hooks/use-automation-rules";
import { ApiError } from "@/lib/api";

// Triggers the backend actually dispatches (DISPATCHED_TRIGGERS).
// worker.offline is emitted by the brain's agent-health worker when an
// agent's heartbeat goes stale past the alert grace; task.orphaned is
// emitted when reconciliation confirms a stuck task actually finished
// (its terminal event was lost). Keep in sync with the backend set.
const TRIGGERS = [
  "task.failed",
  "task.succeeded",
  "task.retried",
  "task.orphaned",
  "worker.offline",
  "schedule.misfired",
] as const;

// Action types that flip the RBAC gate to ADMIN + fresh MFA.
const DESTRUCTIVE_ACTION_TYPES = new Set([
  "retry",
  "cancel",
  "revoke",
  "purge",
  "pause_schedule",
]);

interface FormState {
  name: string;
  trigger: string;
  conditions: string; // JSON text
  actions: string; // JSON text
  dry_run: boolean;
  is_enabled: boolean;
  max_executions_per_window: string;
  window_seconds: string;
}

const EMPTY: FormState = {
  name: "",
  trigger: "task.failed",
  conditions: "{}",
  actions: '[\n  { "type": "notify" }\n]',
  dry_run: true,
  is_enabled: true,
  max_executions_per_window: "100",
  window_seconds: "3600",
};

function fromExisting(r: AutomationRulePublic): FormState {
  return {
    name: r.name,
    trigger: r.trigger,
    conditions: JSON.stringify(r.conditions ?? {}, null, 2),
    actions: JSON.stringify(r.actions ?? [], null, 2),
    dry_run: r.dry_run,
    is_enabled: r.is_enabled,
    max_executions_per_window: String(r.max_executions_per_window),
    window_seconds: String(r.window_seconds),
  };
}

function actionsAreDestructive(actions: Array<Record<string, unknown>>): boolean {
  return actions.some(
    (a) => typeof a.type === "string" && DESTRUCTIVE_ACTION_TYPES.has(a.type),
  );
}

interface Props {
  slug: string;
  open: boolean;
  onClose: () => void;
  existing?: AutomationRulePublic;
  isAdmin: boolean;
}

export function AutomationRuleFormDialog({
  slug,
  open,
  onClose,
  existing,
  isAdmin,
}: Props) {
  const mode = existing ? "edit" : "create";
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<Partial<Record<keyof FormState, string>>>(
    {},
  );

  const create = useCreateAutomationRule(slug);
  const update = useUpdateAutomationRule(slug);
  const pending = create.isPending || update.isPending;

  useEffect(() => {
    if (open) {
      setForm(existing ? fromExisting(existing) : EMPTY);
      setErrors({});
    }
  }, [open, existing]);

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (errors[key]) setErrors((e) => ({ ...e, [key]: undefined }));
  }

  // Parse the current actions JSON best-effort so the destructive-action
  // hint can react live as the operator types.
  const parsedActions = useMemo<Array<Record<string, unknown>>>(() => {
    try {
      const p = JSON.parse(form.actions || "[]");
      return Array.isArray(p) ? (p as Array<Record<string, unknown>>) : [];
    } catch {
      return [];
    }
  }, [form.actions]);

  const isDestructive = actionsAreDestructive(parsedActions);

  function validate():
    | {
        ok: true;
        conditions: Record<string, unknown>;
        actions: Array<Record<string, unknown>>;
        maxExec: number;
        windowSeconds: number;
      }
    | { ok: false } {
    const next: typeof errors = {};
    if (!form.name.trim()) next.name = "required";
    if (!form.trigger.trim()) next.trigger = "required";

    let conditions: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(form.conditions || "{}");
      if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
        next.conditions = "must be a JSON object";
      } else {
        conditions = parsed as Record<string, unknown>;
      }
    } catch {
      next.conditions = "invalid JSON";
    }

    let actions: Array<Record<string, unknown>> = [];
    try {
      const parsed = JSON.parse(form.actions || "[]");
      if (!Array.isArray(parsed) || parsed.length === 0) {
        next.actions = "must be a non-empty JSON array";
      } else if (!parsed.every((a) => a && typeof a === "object" && "type" in a)) {
        next.actions = 'each action must be an object with a "type"';
      } else {
        actions = parsed as Array<Record<string, unknown>>;
      }
    } catch {
      next.actions = "invalid JSON";
    }

    const maxExec = Number(form.max_executions_per_window);
    if (!Number.isInteger(maxExec) || maxExec < 1 || maxExec > 100_000) {
      next.max_executions_per_window = "integer 1..100000";
    }
    const windowSeconds = Number(form.window_seconds);
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 604_800) {
      next.window_seconds = "integer 1..604800";
    }

    setErrors(next);
    if (Object.keys(next).length > 0) return { ok: false };
    return { ok: true, conditions, actions, maxExec, windowSeconds };
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const v = validate();
    if (!v.ok) return;
    try {
      if (mode === "create") {
        const body: AutomationRuleCreateBody = {
          name: form.name.trim(),
          trigger: form.trigger.trim(),
          conditions: v.conditions,
          actions: v.actions,
          dry_run: form.dry_run,
          is_enabled: form.is_enabled,
          max_executions_per_window: v.maxExec,
          window_seconds: v.windowSeconds,
        };
        await create.mutateAsync(body);
        toast.success(`rule "${body.name}" created`);
      } else if (existing) {
        const body: AutomationRuleUpdateBody = {
          name: form.name.trim(),
          trigger: form.trigger.trim(),
          conditions: v.conditions,
          actions: v.actions,
          dry_run: form.dry_run,
          is_enabled: form.is_enabled,
          max_executions_per_window: v.maxExec,
          window_seconds: v.windowSeconds,
        };
        await update.mutateAsync({ ruleId: existing.id, body });
        toast.success(`rule "${existing.name}" updated`);
      }
      onClose();
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      const details =
        err instanceof ApiError && Array.isArray(err.details?.errors)
          ? ` (${(err.details.errors as string[]).join("; ")})`
          : "";
      toast.error(`save failed: ${message}${details}`);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !pending && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New automation rule" : `Edit “${existing?.name}”`}
          </DialogTitle>
          <DialogDescription>
            {mode === "create"
              ? "A rule matches a trigger, evaluates its conditions, and runs its actions. New rules start in dry-run: they audit what they would do without acting."
              : "Updates write through to brain immediately and apply to the next matching event."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name" error={errors.name}>
              <Input
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="retry-flaky-emails"
              />
            </Field>
            <Field label="Trigger" error={errors.trigger}>
              <Select
                value={form.trigger}
                onValueChange={(v) => set("trigger", v)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TRIGGERS.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </div>

          <Field
            label="Conditions (JSON object)"
            error={errors.conditions}
            hint='Flat AND-ed filters, e.g. {"engine": "celery", "task_name": "send_email"}. Empty {} matches every event of the trigger.'
          >
            <Textarea
              value={form.conditions}
              onChange={(e) => set("conditions", e.target.value)}
              className="font-mono text-xs"
              rows={3}
            />
          </Field>

          <Field
            label="Actions (JSON array)"
            error={errors.actions}
            hint='Each is {"type": ...}. Supported today: notify, retry, cancel.'
          >
            <Textarea
              value={form.actions}
              onChange={(e) => set("actions", e.target.value)}
              className="font-mono text-xs"
              rows={4}
            />
          </Field>

          {isDestructive && !isAdmin && (
            <div className="flex gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-400">
              <AlertTriangle className="size-4 shrink-0" />
              <div>
                This rule includes a destructive action (retry / cancel).
                Arming it requires the admin role and a fresh MFA check, which
                you do not currently have. You can still save a notify-only
                rule.
              </div>
            </div>
          )}

          <div className="grid gap-3 md:grid-cols-2">
            <Field
              label="Max executions / window"
              error={errors.max_executions_per_window}
              hint="Circuit breaker: over this many firings per window the rule trips to notify-only failsafe."
            >
              <Input
                value={form.max_executions_per_window}
                onChange={(e) => set("max_executions_per_window", e.target.value)}
                inputMode="numeric"
                className="font-mono text-xs"
              />
            </Field>
            <Field
              label="Window (seconds)"
              error={errors.window_seconds}
              hint="Rolling window the breaker counts firings over."
            >
              <Input
                value={form.window_seconds}
                onChange={(e) => set("window_seconds", e.target.value)}
                inputMode="numeric"
                className="font-mono text-xs"
              />
            </Field>
          </div>

          <div className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2">
            <div>
              <div className="text-sm font-medium">Dry run</div>
              <div className="text-xs text-muted-foreground">
                Evaluate and audit what the rule would do, but take no action.
              </div>
            </div>
            <Switch
              checked={form.dry_run}
              onCheckedChange={(v) => set("dry_run", v)}
            />
          </div>

          <div className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2">
            <div>
              <div className="text-sm font-medium">Enabled</div>
              <div className="text-xs text-muted-foreground">
                Disabled rules exist but never fire.
              </div>
            </div>
            <Switch
              checked={form.is_enabled}
              onCheckedChange={(v) => set("is_enabled", v)}
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={pending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending
                ? "Saving..."
                : mode === "create"
                  ? "Create rule"
                  : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Field({
  label,
  error,
  hint,
  children,
}: {
  label: string;
  error?: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {error && <p className="text-xs text-destructive">{error}</p>}
      {!error && hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
