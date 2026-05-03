import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Copy, Network, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { PageHeader } from "@/components/domain/page-header";
import { AgentStateBadge } from "@/components/domain/state-badges";
import { EmptyState } from "@/components/domain/empty-state";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useAgents,
  useCreateAgent,
  useRevokeAgent,
} from "@/hooks/use-agents";
import { useCan } from "@/hooks/use-memberships";
import { DateCell } from "@/components/domain/date-cell";
import { ApiError } from "@/lib/api";

export const Route = createFileRoute("/_authenticated/projects/$slug/agents")({
  component: AgentsPage,
});

function AgentsPage() {
  const { slug } = Route.useParams();
  const { data: agents, isLoading } = useAgents(slug);
  const createAgent = useCreateAgent(slug);
  const revokeAgent = useRevokeAgent(slug);
  const canManageAgents = useCan(slug, "manage_agents");

  const [createOpen, setCreateOpen] = useState(false);
  const [agentName, setAgentName] = useState("");
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [mintedHmacSecret, setMintedHmacSecret] = useState<string | null>(null);
  const { confirm, dialog: confirmDialog } = useConfirm();

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const result = await createAgent.mutateAsync({
        name: agentName.trim(),
      });
      setMintedToken(result.token);
      setMintedHmacSecret(result.hmac_secret);
      setAgentName("");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : (err as Error).message;
      toast.error(`mint failed: ${message}`);
    }
  }

  function onRevoke(id: string, name: string) {
    confirm({
      title: "Revoke agent token",
      description: (
        <>
          Revoke <code>{name}</code>? In-flight commands will fail and the
          worker will need a new token to come back online.
        </>
      ),
      confirmLabel: "Revoke",
      onConfirm: async () => {
        try {
          await revokeAgent.mutateAsync(id);
          toast.success("agent revoked");
        } catch (err) {
          const message =
            err instanceof ApiError ? err.message : (err as Error).message;
          toast.error(`revoke failed: ${message}`);
        }
      },
    });
  }

  function copyTokenToClipboard() {
    if (!mintedToken) return;
    navigator.clipboard.writeText(mintedToken).then(
      () => toast.success("token copied"),
      () => toast.error("clipboard unavailable"),
    );
  }

  function copyHmacToClipboard() {
    if (!mintedHmacSecret) return;
    navigator.clipboard.writeText(mintedHmacSecret).then(
      () => toast.success("hmac secret copied"),
      () => toast.error("clipboard unavailable"),
    );
  }

  function closeMintDialog() {
    setMintedToken(null);
    setMintedHmacSecret(null);
    setCreateOpen(false);
  }

  return (
    <>
      {confirmDialog}
      <div className="space-y-6 p-4 md:p-6">
        <PageHeader
          title="Agents"
          icon={Network}
          description="mint a token here, paste it into your worker's z4j config (Celery, RQ, or Dramatiq), and watch it come online"
          actions={
            canManageAgents ? (
              <Button
                onClick={() => {
                  setCreateOpen(true);
                  setMintedToken(null);
                  setAgentName("");
                }}
              >
                <Plus className="size-4" />
                New agent
              </Button>
            ) : undefined
          }
        />

        <Card className="overflow-hidden">
          {isLoading && (
            <div className="space-y-2 p-4">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          )}
          {agents && agents.length === 0 && (
            <EmptyState
              icon={Network}
              title="no agents registered"
              description="click 'new agent' to mint a token, then add it to your worker (Celery, RQ, or Dramatiq)"
            />
          )}
          {agents && agents.length > 0 && (
            <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Framework</TableHead>
                  <TableHead>Engines</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead className="text-right">Last seen</TableHead>
                  <TableHead className="text-right"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {agents.map((agent) => (
                  <TableRow key={agent.id}>
                    <TableCell>
                      <div className="font-medium">{agent.name}</div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {agent.id.slice(0, 8)}
                      </div>
                    </TableCell>
                    <TableCell>
                      {agent.host_name ? (
                        <span className="font-mono text-sm">{agent.host_name}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground/60">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <AgentStateBadge state={agent.state} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {agent.framework_adapter}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {agent.engine_adapters.join(", ") || "-"}
                    </TableCell>
                    <TableCell>
                      <AgentVersionCell
                        version={agent.agent_version ?? null}
                        status={agent.version_status ?? null}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <DateCell value={agent.last_seen_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      {canManageAgents && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => onRevoke(agent.id, agent.name)}
                          aria-label="revoke agent"
                        >
                          <Trash2 className="size-4 text-destructive" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="border-t px-4 py-2 text-xs text-muted-foreground">
              {agents.length} agent{agents.length === 1 ? "" : "s"}
            </div>
            </>
          )}
        </Card>
      </div>

      {/* Mint dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          {mintedToken === null ? (
            <form onSubmit={onCreate}>
              <DialogHeader>
                <DialogTitle>Mint a new agent token</DialogTitle>
                <DialogDescription>
                  Pick a friendly name. The plaintext token is shown
                  exactly once on the next screen.
                </DialogDescription>
              </DialogHeader>
              <div className="my-6 space-y-2">
                <Label htmlFor="agent-name">Agent name</Label>
                <Input
                  id="agent-name"
                  required
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  placeholder="worker-prod-01"
                />
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setCreateOpen(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={createAgent.isPending}>
                  Mint token
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle>Token minted</DialogTitle>
                <DialogDescription>
                  Copy BOTH values now. Neither is shown again.
                </DialogDescription>
              </DialogHeader>
              <div className="my-6 space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="agent-bearer-token">Bearer token</Label>
                  <div className="flex gap-2">
                    <Input
                      id="agent-bearer-token"
                      readOnly
                      value={mintedToken}
                      className="font-mono text-xs"
                      onFocus={(e) => e.currentTarget.select()}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={copyTokenToClipboard}
                      aria-label="copy bearer token"
                    >
                      <Copy className="size-4" />
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Set this as <code className="font-mono">Z4J_TOKEN</code> in
                    your worker's environment.
                  </p>
                </div>
                {mintedHmacSecret && (
                  <div className="space-y-2">
                    <Label htmlFor="agent-hmac-secret">HMAC secret</Label>
                    <div className="flex gap-2">
                      <Input
                        id="agent-hmac-secret"
                        readOnly
                        value={mintedHmacSecret}
                        className="font-mono text-xs"
                        onFocus={(e) => e.currentTarget.select()}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        onClick={copyHmacToClipboard}
                        aria-label="copy hmac secret"
                      >
                        <Copy className="size-4" />
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Set this as{" "}
                      <code className="font-mono">Z4J_HMAC_SECRET</code> in the
                      same environment. The agent refuses to start without it.
                    </p>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button type="button" onClick={closeMintDialog}>
                  Done
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}


/**
 * Render the agent's z4j-core version string with an "update available"
 * (or "incompatible") badge driven by z4j's bundled
 * versions.json snapshot. z4j computes ``version_status``
 * server-side; we only translate it into colors and copy.
 *
 * 1.3.4+. Pre-1.3.4 brains return ``agent_version: null`` and
 * ``version_status: null`` for every row; we render a plain dash.
 */
function AgentVersionCell({
  version,
  status,
}: {
  version: string | null;
  status: string | null;
}) {
  if (!version) {
    return <span className="text-xs text-muted-foreground/60">-</span>;
  }
  let badge: { label: string; className: string; title: string } | null = null;
  switch (status) {
    case "outdated":
      badge = {
        label: "update available",
        className:
          "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
        title:
          "An update is available. Run pip install --upgrade z4j-bare on the agent box and restart the host process.",
      };
      break;
    case "incompatible":
      badge = {
        label: "incompatible",
        className:
          "border-destructive/40 bg-destructive/10 text-destructive",
        title:
          "Major version mismatch with z4j's snapshot. Upgrade z4j-bare to a compatible major version.",
      };
      break;
    case "newer_than_known":
      badge = {
        label: "newer than known",
        className:
          "border-muted-foreground/30 bg-muted text-muted-foreground",
        title:
          "Agent is newer than z4j's snapshot. z4j itself may be out of date - try Settings → System → Check for updates.",
      };
      break;
    case "unknown":
      // No badge - just show the version. The reason can be the
      // package being missing from the snapshot or the agent string
      // being unparseable; either way an explicit "unknown" badge
      // would be more confusing than informative.
      break;
    case "current":
    default:
      // No badge for current. Clean default state.
      break;
  }
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-sm">{version}</span>
      {badge ? (
        <span
          title={badge.title}
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${badge.className}`}
        >
          {badge.label}
        </span>
      ) : null}
    </div>
  );
}
