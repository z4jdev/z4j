/**
 * Automation page - list + create/edit/delete of a project's automation
 * rules, plus the per-project kill switch.
 *
 * A rule matches a trigger, evaluates its conditions, and runs its
 * actions (notify / retry / cancel) under a per-rule circuit breaker.
 * The whole area is OPERATOR+ to manage; destructive-action arming is
 * gated to ADMIN + fresh MFA by the backend (the form warns non-admins,
 * and the query client handles the MFA step-up redirect).
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Pencil, Plus, RotateCcw, Trash2, Zap } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/domain/page-header";
import { PageShell } from "@/components/domain/page-shell";
import { EmptyState } from "@/components/domain/empty-state";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { AutomationRuleFormDialog } from "@/components/domain/automation-rule-form-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useCan, useIsProjectAdmin } from "@/hooks/use-memberships";
import {
  useAutomationRules,
  useAutomationSettings,
  useDeleteAutomationRule,
  useResetAutomationCircuit,
  useSetAutomationSettings,
  type AutomationRulePublic,
} from "@/hooks/use-automation-rules";
import { ApiError } from "@/lib/api";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/automation",
)({
  component: AutomationPage,
});

function apiMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : (err as Error).message;
}

function AutomationPage() {
  const { slug } = Route.useParams();
  const { data: rules, isLoading } = useAutomationRules(slug);
  const settings = useAutomationSettings(slug);
  const setSettings = useSetAutomationSettings(slug);
  const del = useDeleteAutomationRule(slug);
  const resetCircuit = useResetAutomationCircuit(slug);
  const { confirm, dialog: confirmDialog } = useConfirm();

  const canManage = useCan(slug, "manage_automation");
  const isAdmin = useIsProjectAdmin(slug);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AutomationRulePublic | undefined>(
    undefined,
  );

  const automationEnabled = settings.data?.automation_enabled ?? true;

  function onCreate() {
    setEditing(undefined);
    setFormOpen(true);
  }

  function onEdit(rule: AutomationRulePublic) {
    setEditing(rule);
    setFormOpen(true);
  }

  function onDelete(rule: AutomationRulePublic) {
    confirm({
      title: `Delete rule “${rule.name}”?`,
      description:
        "This permanently removes the rule. It stops firing immediately.",
      confirmLabel: "Delete",
      onConfirm: async () => {
        try {
          await del.mutateAsync(rule.id);
          toast.success(`rule “${rule.name}” deleted`);
        } catch (err) {
          toast.error(`delete failed: ${apiMessage(err)}`);
        }
      },
    });
  }

  async function onResetCircuit(rule: AutomationRulePublic) {
    try {
      await resetCircuit.mutateAsync(rule.id);
      toast.success(`breaker reset for “${rule.name}”`);
    } catch (err) {
      toast.error(`reset failed: ${apiMessage(err)}`);
    }
  }

  async function onToggleKillSwitch(next: boolean) {
    try {
      await setSettings.mutateAsync(next);
      toast.success(next ? "automation enabled" : "automation disabled");
    } catch (err) {
      toast.error(`could not update: ${apiMessage(err)}`);
    }
  }

  return (
    <PageShell>
      <PageHeader
        title="Automation"
        icon={Zap}
        description="rules that react to task and scheduler events by notifying an operator or issuing a retry or cancel"
        badges={
          !canManage ? <Badge variant="muted">read-only</Badge> : undefined
        }
        actions={
          canManage ? (
            <Button size="sm" onClick={onCreate}>
              <Plus className="size-4" />
              New rule
            </Button>
          ) : undefined
        }
      />

      {/* Per-project kill switch. Disabling stops ALL automation for the
          project instantly; enabling requires admin + fresh MFA. */}
      <div className="flex items-center justify-between rounded-md border bg-muted/30 px-4 py-3">
        <div>
          <div className="text-sm font-medium">Project automation</div>
          <div className="text-xs text-muted-foreground">
            {automationEnabled
              ? "Rules on this project are active."
              : "The kill switch is OFF - no rule on this project fires."}
          </div>
        </div>
        <Switch
          checked={automationEnabled}
          onCheckedChange={onToggleKillSwitch}
          disabled={!isAdmin || setSettings.isPending || settings.isLoading}
          aria-label="toggle project automation"
        />
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : !rules || rules.length === 0 ? (
        <EmptyState
          icon={Zap}
          title="no automation rules"
          description={
            canManage
              ? "Create a rule to react automatically to task failures, retries, or a scheduler misfire."
              : "No rules have been created for this project yet."
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Actions</TableHead>
                <TableHead>Status</TableHead>
                {canManage && (
                  <TableHead className="text-right">Manage</TableHead>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell className="font-medium">{rule.name}</TableCell>
                  <TableCell>
                    <code className="font-mono text-xs">{rule.trigger}</code>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {rule.actions
                      .map((a) =>
                        typeof a.type === "string" ? a.type : "?",
                      )
                      .join(", ") || "-"}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {rule.is_enabled ? (
                        <Badge variant="success">enabled</Badge>
                      ) : (
                        <Badge variant="muted">disabled</Badge>
                      )}
                      {rule.dry_run && (
                        <Badge variant="warning">dry-run</Badge>
                      )}
                      {rule.cb_tripped && (
                        <Badge variant="destructive">breaker tripped</Badge>
                      )}
                    </div>
                  </TableCell>
                  {canManage && (
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        {rule.cb_tripped && (
                          <Button
                            variant="ghost"
                            size="icon"
                            title="Reset circuit breaker"
                            onClick={() => onResetCircuit(rule)}
                            disabled={resetCircuit.isPending}
                          >
                            <RotateCcw className="size-4" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit"
                          onClick={() => onEdit(rule)}
                        >
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Delete"
                          onClick={() => onDelete(rule)}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <AutomationRuleFormDialog
        slug={slug}
        open={formOpen}
        onClose={() => setFormOpen(false)}
        existing={editing}
        isAdmin={isAdmin}
      />
      {confirmDialog}
    </PageShell>
  );
}
