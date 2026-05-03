/**
 * Create / edit dialog for a single schedule.
 *
 * Wraps brain's POST /schedules and PATCH /schedules/{id} - both
 * endpoints share most of their body shape, so a single form
 * component handles both modes. The mode prop drives:
 *
 * - "create": all fields editable, name + scheduler are required
 * - "edit":   name + scheduler are read-only (they're the identity
 *             tuple alongside project_id), everything else patches
 *
 * The form is intentionally plain React state, no react-hook-form
 * dependency. Validation is structural (kind/expression sanity) +
 * server-side (brain returns 422 on bad enum / missing field). The
 * args/kwargs textareas accept JSON; we parse on submit and surface
 * a clear error if it's malformed.
 *
 * Per docs/SCHEDULER.md §3.2 wish #3: "manage schedules from a real
 * UI, not Django admin." This dialog is the operator's daily
 * touchpoint after migrating off celery-beat.
 */
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Info } from "lucide-react";
import { toast } from "sonner";
import { computeDstWarning } from "@/lib/dst-warnings";
import { capsForEngine } from "@/lib/engine-capabilities";
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
  useCreateSchedule,
  useUpdateSchedule,
  type ScheduleCreateBody,
  type ScheduleUpdateBody,
} from "@/hooks/use-schedules";
import { ApiError } from "@/lib/api";
import type { SchedulePublic } from "@/lib/api-types";

type Kind = "cron" | "interval" | "one_shot" | "solar";
type CatchUp = "skip" | "fire_one_missed" | "fire_all_missed";

interface FormState {
  name: string;
  engine: string;
  scheduler: string;
  kind: Kind;
  expression: string;
  task_name: string;
  timezone: string;
  queue: string;
  args: string; // JSON text
  kwargs: string; // JSON text
  catch_up: CatchUp;
  is_enabled: boolean;
}

const EMPTY: FormState = {
  name: "",
  engine: "celery",
  scheduler: "z4j-scheduler",
  kind: "cron",
  expression: "0 * * * *",
  task_name: "",
  timezone: "UTC",
  queue: "",
  args: "[]",
  kwargs: "{}",
  catch_up: "skip",
  is_enabled: true,
};

function fromExisting(s: SchedulePublic): FormState {
  return {
    name: s.name,
    engine: s.engine,
    scheduler: s.scheduler,
    kind: s.kind as Kind,
    expression: s.expression,
    task_name: s.task_name,
    timezone: s.timezone,
    queue: s.queue ?? "",
    args: JSON.stringify(s.args ?? [], null, 2),
    kwargs: JSON.stringify(s.kwargs ?? {}, null, 2),
    catch_up: s.catch_up,
    is_enabled: s.is_enabled,
  };
}

interface Props {
  slug: string;
  open: boolean;
  onClose: () => void;
  // When set, the dialog is in edit mode and prefills from this row.
  // Undefined = create mode.
  existing?: SchedulePublic;
}

export function ScheduleFormDialog({ slug, open, onClose, existing }: Props) {
  const mode = existing ? "edit" : "create";
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<Partial<Record<keyof FormState, string>>>({});

  const create = useCreateSchedule(slug);
  const update = useUpdateSchedule(slug);
  const pending = create.isPending || update.isPending;

  // Reset whenever the dialog re-opens with a different existing
  // row. Without this the form keeps stale values from the
  // previous schedule between Edit clicks.
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

  function validate(): { ok: true; args: unknown[]; kwargs: Record<string, unknown> } | { ok: false } {
    const next: typeof errors = {};
    if (!form.name.trim()) next.name = "required";
    if (!form.engine.trim()) next.engine = "required";
    if (!form.task_name.trim()) next.task_name = "required";
    if (!form.expression.trim()) next.expression = "required";
    let args: unknown[] = [];
    let kwargs: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(form.args || "[]");
      if (!Array.isArray(parsed)) {
        next.args = "must be a JSON array";
      } else {
        args = parsed;
      }
    } catch {
      next.args = "invalid JSON";
    }
    try {
      const parsed = JSON.parse(form.kwargs || "{}");
      if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
        next.kwargs = "must be a JSON object";
      } else {
        kwargs = parsed as Record<string, unknown>;
      }
    } catch {
      next.kwargs = "invalid JSON";
    }
    setErrors(next);
    if (Object.keys(next).length > 0) return { ok: false };
    return { ok: true, args, kwargs };
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const v = validate();
    if (!v.ok) return;
    try {
      if (mode === "create") {
        const body: ScheduleCreateBody = {
          name: form.name.trim(),
          engine: form.engine.trim(),
          scheduler: form.scheduler.trim() || "z4j-scheduler",
          kind: form.kind,
          expression: form.expression.trim(),
          task_name: form.task_name.trim(),
          timezone: form.timezone.trim() || "UTC",
          queue: form.queue.trim() || null,
          args: v.args,
          kwargs: v.kwargs,
          catch_up: form.catch_up,
          is_enabled: form.is_enabled,
          source: "dashboard",
        };
        await create.mutateAsync(body);
        toast.success(`schedule "${body.name}" created`);
      } else if (existing) {
        const body: ScheduleUpdateBody = {
          engine: form.engine.trim(),
          kind: form.kind,
          expression: form.expression.trim(),
          task_name: form.task_name.trim(),
          timezone: form.timezone.trim() || "UTC",
          queue: form.queue.trim() || null,
          args: v.args,
          kwargs: v.kwargs,
          catch_up: form.catch_up,
          is_enabled: form.is_enabled,
        };
        await update.mutateAsync({ scheduleId: existing.id, body });
        toast.success(`schedule "${existing.name}" updated`);
      }
      onClose();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`save failed: ${message}`);
    }
  }

  // Per-kind expression hint shown under the field. Operators
  // arriving from celery-beat usually know cron 5-field syntax;
  // interval / one_shot / solar are less obvious so we spell them
  // out. Solar gets a dedicated picker rendered separately
  // (event dropdown + lat/lon inputs) since "sunset:51.5074:-0.1278"
  // is hostile UX for a form field.
  const expressionHint = useMemo(() => {
    if (form.kind === "cron") {
      return "5-field crontab string (or 6-field with seconds), e.g. \"0 3 * * *\"";
    }
    if (form.kind === "interval") {
      return "Interval like \"30s\" / \"5m\" / \"2h\" / \"1d\", or a bare integer (seconds)";
    }
    if (form.kind === "solar") {
      return "event:lat:lon (use the picker below to fill this in)";
    }
    return "ISO-8601 timestamp, e.g. \"2026-12-25T09:00:00Z\"";
  }, [form.kind]);

  // For solar schedules, parse the current expression string into
  // its (event, lat, lon) parts so the picker can hydrate. Defaults
  // to a sensible starting state (sunrise at 0,0) when the field
  // is empty or unparseable.
  const solarParts = useMemo(() => {
    if (form.kind !== "solar") return null;
    const parts = form.expression.split(":");
    return {
      event: parts[0] || "sunrise",
      lat: parts[1] || "0",
      lon: parts[2] || "0",
    };
  }, [form.kind, form.expression]);

  function setSolarPart(key: "event" | "lat" | "lon", value: string) {
    if (!solarParts) return;
    const next = { ...solarParts, [key]: value };
    set("expression", `${next.event}:${next.lat}:${next.lon}`);
  }

  // DST fall-back / spring-forward warning. §5.5 promise: warn the
  // operator when their cron + timezone combination would produce
  // a fall-back duplicate (or a spring-forward shift) so the
  // choice is INFORMED rather than discovered in production.
  // ``computeDstWarning`` returns null when there's nothing to flag.
  const dstWarning = useMemo(
    () => computeDstWarning(form.kind, form.expression, form.timezone),
    [form.kind, form.expression, form.timezone],
  );

  // Per-engine capability gating (§13.1). The ``kind`` dropdown
  // hides options the chosen engine doesn't support; the queue +
  // timezone fields disable themselves for engines that don't
  // route on queues / kinds that don't use timezones. Picking an
  // unknown engine falls through to the permissive default so we
  // don't break a future adapter's first dashboard interaction.
  const engineCaps = useMemo(
    () => capsForEngine(form.engine),
    [form.engine],
  );

  // If the operator switches engines and the current kind is no
  // longer supported, snap back to "cron" (universal) so the
  // form never holds an invalid (engine, kind) combo.
  useEffect(() => {
    if (!engineCaps.kinds.includes(form.kind)) {
      setForm((prev) => ({ ...prev, kind: "cron" }));
    }
  }, [engineCaps, form.kind]);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !pending && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New schedule" : `Edit “${existing?.name}”`}
          </DialogTitle>
          <DialogDescription>
            {mode === "create"
              ? "Schedules created here are tagged source=\"dashboard\" and survive declarative reconciles."
              : "Updates write through to brain immediately. The next tick after save uses the new values."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name" error={errors.name}>
              <Input
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                disabled={mode === "edit"}
                placeholder="nightly-report"
              />
            </Field>
            <Field label="Task name" error={errors.task_name}>
              <Input
                value={form.task_name}
                onChange={(e) => set("task_name", e.target.value)}
                placeholder="myapp.tasks.nightly_report"
                className="font-mono text-xs"
              />
            </Field>
            <Field label="Engine" error={errors.engine}>
              <Select
                value={form.engine}
                onValueChange={(v) => set("engine", v)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="celery">celery</SelectItem>
                  <SelectItem value="rq">rq</SelectItem>
                  <SelectItem value="dramatiq">dramatiq</SelectItem>
                  <SelectItem value="arq">arq</SelectItem>
                  <SelectItem value="huey">huey</SelectItem>
                  <SelectItem value="taskiq">taskiq</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label="Scheduler">
              <Input
                value={form.scheduler}
                onChange={(e) => set("scheduler", e.target.value)}
                disabled={mode === "edit"}
              />
            </Field>
            <Field
              label="Kind"
              hint={
                engineCaps.kinds.length < 4
                  ? `${form.engine} adapter supports: ${engineCaps.kinds.join(", ")}`
                  : undefined
              }
            >
              <Select
                value={form.kind}
                onValueChange={(v) => set("kind", v as Kind)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {engineCaps.kinds.includes("cron") && (
                    <SelectItem value="cron">cron</SelectItem>
                  )}
                  {engineCaps.kinds.includes("interval") && (
                    <SelectItem value="interval">interval</SelectItem>
                  )}
                  {engineCaps.kinds.includes("one_shot") && (
                    <SelectItem value="one_shot">one_shot</SelectItem>
                  )}
                  {engineCaps.kinds.includes("solar") && (
                    <SelectItem value="solar">solar</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Catch-up">
              <Select
                value={form.catch_up}
                onValueChange={(v) => set("catch_up", v as CatchUp)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="skip">skip</SelectItem>
                  <SelectItem value="fire_one_missed">fire_one_missed</SelectItem>
                  <SelectItem value="fire_all_missed">fire_all_missed</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </div>

          <Field label="Expression" error={errors.expression} hint={expressionHint}>
            <Input
              value={form.expression}
              onChange={(e) => set("expression", e.target.value)}
              className="font-mono text-xs"
            />
          </Field>

          {form.kind === "solar" && solarParts && (
            <div className="grid gap-3 md:grid-cols-3 rounded-md border border-amber-500/20 bg-amber-500/5 p-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Solar event</Label>
                <Select
                  value={solarParts.event}
                  onValueChange={(v) => setSolarPart("event", v)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sunrise">sunrise</SelectItem>
                    <SelectItem value="sunset">sunset</SelectItem>
                    <SelectItem value="dawn">dawn (astronomical)</SelectItem>
                    <SelectItem value="dusk">dusk (astronomical)</SelectItem>
                    <SelectItem value="noon">noon (solar)</SelectItem>
                    <SelectItem value="solar_noon">solar_noon (alias)</SelectItem>
                    <SelectItem value="midnight">midnight (solar)</SelectItem>
                    <SelectItem value="solar_midnight">solar_midnight (alias)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Latitude</Label>
                <Input
                  value={solarParts.lat}
                  onChange={(e) => setSolarPart("lat", e.target.value)}
                  placeholder="37.7749"
                  className="font-mono text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Longitude</Label>
                <Input
                  value={solarParts.lon}
                  onChange={(e) => setSolarPart("lon", e.target.value)}
                  placeholder="-122.4194"
                  className="font-mono text-xs"
                />
              </div>
              <div className="md:col-span-3 text-xs text-muted-foreground">
                Range: latitude [-90, 90], longitude [-180, 180].
                Polar latitudes (|lat| &gt; ~66.5°) skip days where
                the chosen event doesn't occur. Resolved expression:{" "}
                <code className="font-mono">{form.expression}</code>
              </div>
            </div>
          )}

          {dstWarning && (
            <div
              className={
                dstWarning.level === "warning"
                  ? "flex gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-400"
                  : "flex gap-2 rounded-md border border-blue-500/40 bg-blue-500/10 p-3 text-xs text-blue-700 dark:text-blue-400"
              }
            >
              {dstWarning.level === "warning" ? (
                <AlertTriangle className="size-4 shrink-0" />
              ) : (
                <Info className="size-4 shrink-0" />
              )}
              <div>
                <div className="mb-0.5 font-semibold uppercase tracking-wide">
                  DST {dstWarning.level === "warning" ? "warning" : "note"}
                </div>
                <div>{dstWarning.message}</div>
              </div>
            </div>
          )}

          <div className="grid gap-3 md:grid-cols-2">
            <Field
              label="Timezone"
              hint={
                form.kind !== "cron"
                  ? "Only used for cron-kind schedules; intervals and one_shot fire on absolute UTC instants."
                  : undefined
              }
            >
              <Input
                value={form.timezone}
                onChange={(e) => set("timezone", e.target.value)}
                placeholder="UTC"
                disabled={form.kind !== "cron"}
              />
            </Field>
            <Field
              label="Queue (optional)"
              hint={engineCaps.queueHint || undefined}
            >
              <Input
                value={form.queue}
                onChange={(e) => set("queue", e.target.value)}
                placeholder={engineCaps.hasQueues ? "default" : "(not used)"}
                disabled={!engineCaps.hasQueues}
              />
            </Field>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <Field label="args (JSON array)" error={errors.args}>
              <Textarea
                value={form.args}
                onChange={(e) => set("args", e.target.value)}
                className="font-mono text-xs"
                rows={4}
              />
            </Field>
            <Field label="kwargs (JSON object)" error={errors.kwargs}>
              <Textarea
                value={form.kwargs}
                onChange={(e) => set("kwargs", e.target.value)}
                className="font-mono text-xs"
                rows={4}
              />
            </Field>
          </div>

          <div className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2">
            <div>
              <div className="text-sm font-medium">Enabled</div>
              <div className="text-xs text-muted-foreground">
                Disabled schedules exist but do not fire.
              </div>
            </div>
            <Switch
              checked={form.is_enabled}
              onCheckedChange={(v) => set("is_enabled", v)}
            />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending
                ? "Saving..."
                : mode === "create"
                  ? "Create schedule"
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
      {!error && hint && (
        <p className="text-xs text-muted-foreground">{hint}</p>
      )}
    </div>
  );
}
