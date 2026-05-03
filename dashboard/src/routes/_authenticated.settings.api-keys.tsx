/**
 * API Keys settings page - standalone entry point.
 *
 * This is a convenience route that renders the same API key management
 * UI available in the Account page's "API Keys" tab, but as a dedicated
 * page accessible from the settings sidebar.
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import {
  Check,
  Copy,
  Key,
  Loader2,
  Plus,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/components/domain/empty-state";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { formatAbsolute } from "@/lib/format";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { QueryError } from "@/components/domain/query-error";

export const Route = createFileRoute("/_authenticated/settings/api-keys")({
  component: ApiKeysPage,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  project_id: string | null;
  project_slug: string | null;
  last_used_at: string | null;
  last_used_ip: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  created_at: string;
}

interface ScopeCatalogue {
  scopes: string[];
  admin_only: string[];
}

interface CreateApiKeyResponse extends ApiKey {
  token: string;
}

interface ProjectLite {
  id: string;
  slug: string;
  name: string;
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function ApiKeysPage() {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const { confirm, dialog: confirmDialog } = useConfirm();

  const { data: keys, isLoading, isError, error, refetch } = useQuery<ApiKey[]>({
    queryKey: ["api-keys"],
    queryFn: () => api.get<ApiKey[]>("/api-keys"),
    staleTime: 30_000,
  });

  const revokeKey = useMutation({
    mutationFn: (keyId: string) => api.delete<void>(`/api-keys/${keyId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success("API key revoked");
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Keys"
        description="Personal tokens for authenticating with the z4j API."
        actions={
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="size-4" />
                Create API Key
              </Button>
            </DialogTrigger>
            <DialogContent>
              <CreateApiKeyDialog onCreated={() => setDialogOpen(false)} />
            </DialogContent>
          </Dialog>
        }
      />

      {confirmDialog}

      {isLoading && <Skeleton className="h-32 w-full" />}

      {isError && (
        <QueryError
          message={error instanceof Error ? error.message : "Failed to load API keys"}
          onRetry={() => refetch()}
        />
      )}

      {keys && keys.length === 0 && (
        <EmptyState
          icon={Key}
          title="No API keys"
          description="Create a personal API key to authenticate with the z4j API programmatically."
        />
      )}

      {keys && keys.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell className="font-medium">{key.name}</TableCell>
                  <TableCell>
                    {key.scopes.length === 0 ? (
                      <span className="text-xs text-muted-foreground">
                        none
                      </span>
                    ) : key.scopes.includes("admin:*") ? (
                      <span className="rounded bg-destructive/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-destructive">
                        admin
                      </span>
                    ) : (
                      <span
                        className="text-xs text-muted-foreground"
                        title={key.scopes.join(", ")}
                      >
                        {key.scopes.length} scope{key.scopes.length === 1 ? "" : "s"}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">
                    {key.project_slug ? (
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {key.project_slug}
                      </code>
                    ) : (
                      <span className="text-muted-foreground">global</span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {key.prefix}...
                  </TableCell>
                  <TableCell>
                    {key.last_used_at
                      ? <DateCell value={key.last_used_at} />
                      : "Never"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {key.expires_at
                      ? formatAbsolute(key.expires_at)
                      : "Never"}
                  </TableCell>
                  <TableCell>
                    <DateCell value={key.created_at} />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={`Revoke ${key.name}`}
                      title={`Revoke ${key.name}`}
                      className="text-muted-foreground hover:text-destructive"
                      disabled={revokeKey.isPending}
                      onClick={() =>
                        confirm({
                          title: "Revoke API key",
                          description: (
                            <>
                              Revoke <code>{key.name}</code>? Any client
                              using it will start receiving 401s
                              immediately. This cannot be undone.
                            </>
                          ),
                          confirmLabel: "Revoke",
                          onConfirm: () => revokeKey.mutate(key.id),
                        })
                      }
                    >
                      <Trash2 className="size-4" />
                    </Button>
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
// Create API key dialog
// ---------------------------------------------------------------------------

const EXPIRY_OPTIONS = [
  { value: "never", label: "Never" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
] as const;

function CreateApiKeyDialog({ onCreated }: { onCreated: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("never");
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [projectId, setProjectId] = useState<string>("__global__");
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Scope catalogue and visible projects - the UI gates what the
  // user can grant to what the server has already vetted.
  const { data: catalogue } = useQuery<ScopeCatalogue>({
    queryKey: ["api-keys", "scopes"],
    queryFn: () => api.get<ScopeCatalogue>("/api-keys/scopes"),
    staleTime: 5 * 60_000,
  });
  const { data: projects } = useQuery<ProjectLite[]>({
    queryKey: ["projects"],
    queryFn: () => api.get<ProjectLite[]>("/projects"),
  });

  const createKey = useMutation({
    mutationFn: (body: {
      name: string;
      scopes: string[];
      project_id: string | null;
      expires_in_days?: number;
    }) => api.post<CreateApiKeyResponse>("/api-keys", body),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setToken(data.token);
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const toggleScope = (s: string) => {
    setScopes((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (scopes.size === 0) {
      toast.error("Pick at least one scope - a tokenless key has no access.");
      return;
    }
    const body: {
      name: string;
      scopes: string[];
      project_id: string | null;
      expires_in_days?: number;
    } = {
      name,
      scopes: Array.from(scopes),
      project_id: projectId === "__global__" ? null : projectId,
    };
    if (expiry !== "never") {
      body.expires_in_days = parseInt(expiry, 10);
    }
    createKey.mutate(body);
  };

  const handleCopy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      toast.success("Token copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy to clipboard");
    }
  };

  const handleClose = () => {
    setName("");
    setExpiry("never");
    setToken(null);
    setCopied(false);
    onCreated();
  };

  // After creation, show the token
  if (token) {
    return (
      <>
        <DialogHeader>
          <DialogTitle>API Key Created</DialogTitle>
        </DialogHeader>
        <div className="mt-4 space-y-4">
          <div className="rounded-md border bg-muted/50 p-4">
            <p className="mb-2 text-xs font-semibold text-destructive">
              This token is shown once. Copy it now - you will not be able to
              see it again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded bg-background px-3 py-2 font-mono text-sm">
                {token}
              </code>
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={handleCopy}
                aria-label={copied ? "Copied" : "Copy token to clipboard"}
              >
                {copied ? (
                  <Check className="size-4 text-green-600" />
                ) : (
                  <Copy className="size-4" />
                )}
              </Button>
            </div>
          </div>
        </div>
        <DialogFooter className="mt-6">
          <Button type="button" onClick={handleClose}>
            Done
          </Button>
        </DialogFooter>
      </>
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Create API Key</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="apikey-name">Name</Label>
          <Input
            id="apikey-name"
            placeholder="e.g. CI pipeline, local dev"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="apikey-project">Project scope</Label>
          <Select value={projectId} onValueChange={setProjectId}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__global__">
                Global (all projects you can see)
              </SelectItem>
              {(projects ?? []).map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name} <code className="ml-1 text-xs">{p.slug}</code>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            A project-scoped key only reaches URLs under that project.
            Global keys are bounded by your memberships.
          </p>
        </div>
        <div className="space-y-2" role="group" aria-labelledby="apikey-scopes-heading">
          <div className="flex items-center justify-between">
            {/* Section heading for a group of scope checkboxes; not
                a single-target Label, so we use role/aria-labelledby. */}
            <span
              id="apikey-scopes-heading"
              className="text-sm font-medium leading-none"
            >
              Scopes
            </span>
            <div className="flex gap-2 text-xs">
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground"
                onClick={() =>
                  setScopes(new Set(catalogue?.scopes.filter((s) =>
                    s.endsWith(":read"),
                  ) ?? []))
                }
              >
                read-only
              </button>
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground"
                onClick={() => setScopes(new Set())}
              >
                none
              </button>
            </div>
          </div>
          <div className="max-h-64 space-y-1 overflow-y-auto rounded-md border p-3">
            {(catalogue?.scopes ?? []).map((s) => {
              const isAdmin = catalogue?.admin_only.includes(s);
              const isChecked = scopes.has(s);
              return (
                <label
                  key={s}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-sm hover:bg-accent/50"
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleScope(s)}
                    className="size-3.5 cursor-pointer"
                  />
                  <code className="flex-1 text-xs">{s}</code>
                  {isAdmin && (
                    <span className="rounded bg-destructive/10 px-1.5 text-[10px] font-semibold uppercase text-destructive">
                      admin
                    </span>
                  )}
                </label>
              );
            })}
          </div>
          <p className="text-xs text-muted-foreground">
            Grant the least privilege needed. A token with ``tasks:write``
            automatically gets ``tasks:read``.
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="apikey-expires">Expires</Label>
          <Select value={expiry} onValueChange={setExpiry}>
            <SelectTrigger id="apikey-expires">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {EXPIRY_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button type="submit" disabled={createKey.isPending}>
          {createKey.isPending ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Creating...
            </>
          ) : (
            "Create Key"
          )}
        </Button>
      </DialogFooter>
    </form>
  );
}
