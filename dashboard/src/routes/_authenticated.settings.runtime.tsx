/**
 * Global settings - Runtime configuration (admin, read-only).
 *
 * Mirrors `z4j config show`: surfaces every effective Settings field
 * the brain is currently using, the source label (env / config.env /
 * secret.env / .env / default), and the description from the Pydantic
 * model. Secrets are masked server-side.
 *
 * Read-only on purpose. The file is the source of truth; this page
 * exists for visibility ("what's actually live") and to scratch the
 * "let me copy current as a .env" UX itch. Edits happen by editing
 * `~/.z4j/config.env` (or the environment) and restarting the brain.
 *
 * Backend: GET /api/v1/admin/settings, requires admin (Settings.is_admin).
 */
import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Copy, Search } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export const Route = createFileRoute("/_authenticated/settings/runtime")({
  component: RuntimeSettingsPage,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * One effective-settings row from `GET /api/v1/admin/settings`.
 * Mirrors the backend `SettingItem` Pydantic model exactly.
 */
interface SettingItem {
  name: string;
  value: string;
  source: "env" | "config.env" | "secret.env" | ".env" | "default";
  is_secret: boolean;
  description: string;
}

interface AdminSettingsResponse {
  z4j_home: string;
  settings: SettingItem[];
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function RuntimeSettingsPage() {
  const { data, isLoading } = useQuery<AdminSettingsResponse>({
    queryKey: ["admin-settings"],
    queryFn: () => api.get<AdminSettingsResponse>("/admin/settings"),
    // Settings only change at brain restart, so a long stale time is
    // safe and keeps the page snappy on tab-switch.
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-96 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }
  if (!data) return null;

  return (
    <TooltipProvider>
      <div className="space-y-6">
        <Header />
        <Z4jHomeCard z4jHome={data.z4j_home} />
        <SettingsTableCard settings={data.settings} />
        <ActionsCard settings={data.settings} z4jHome={data.z4j_home} />
      </div>
    </TooltipProvider>
  );
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function Header() {
  return (
    <div>
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold">Settings (read-only)</h2>
        <Badge variant="muted">read-only</Badge>
      </div>
      <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
        These values are loaded at brain startup from environment
        variables, <code className="font-mono">~/.z4j/config.env</code>, or
        code defaults. Edit{" "}
        <code className="font-mono">~/.z4j/config.env</code> (or your
        environment) and restart the brain to change them.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Z4J_HOME card
// ---------------------------------------------------------------------------

function Z4jHomeCard({ z4jHome }: { z4jHome: string }) {
  return (
    <Card className="p-6">
      <h3 className="text-sm font-semibold">Z4J_HOME</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Resolved data directory. <code className="font-mono">config.env</code>{" "}
        and <code className="font-mono">secret.env</code> live here.
      </p>
      <div className="mt-4 flex items-center gap-2">
        <code className="flex-1 truncate rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-sm">
          {z4jHome}
        </code>
        <CopyButton value={z4jHome} label="Copy path" />
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Settings table
// ---------------------------------------------------------------------------

const SOURCE_VARIANT: Record<
  SettingItem["source"],
  { variant: "default" | "secondary" | "success" | "warning" | "muted" | "outline"; label: string }
> = {
  // Tailwind class hints encoded via Badge's variant tokens. We
  // reuse the existing variants instead of introducing new color
  // tokens. The colors map roughly to the spec's intent:
  //   env -> blue-ish (default/primary)
  //   config.env -> green (success)
  //   secret.env -> gray (muted)
  //   .env -> yellow (warning)
  //   default -> light gray (outline)
  env: { variant: "default", label: "env" },
  "config.env": { variant: "success", label: "config.env" },
  "secret.env": { variant: "muted", label: "secret.env" },
  ".env": { variant: "warning", label: ".env" },
  default: { variant: "outline", label: "default" },
};

function SettingsTableCard({ settings }: { settings: SettingItem[] }) {
  const [filterRaw, setFilterRaw] = React.useState("");
  const [filter, setFilter] = React.useState("");

  // Debounce the filter so a fast typist doesn't re-render the
  // table on every keystroke. 150ms is the dashboard's general
  // search-debounce convention.
  React.useEffect(() => {
    const id = window.setTimeout(() => setFilter(filterRaw.trim()), 150);
    return () => window.clearTimeout(id);
  }, [filterRaw]);

  const filtered = React.useMemo(() => {
    if (!filter) return settings;
    const needle = filter.toLowerCase();
    return settings.filter((row) =>
      row.name.toLowerCase().includes(needle),
    );
  }, [settings, filter]);

  return (
    <Card className="p-6">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold">Effective settings</h3>
        <Badge variant="muted">{settings.length} fields</Badge>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        Every field on the brain's <code className="font-mono">Settings</code>{" "}
        model with its current value and where it came from.
      </p>

      <div className="relative mt-4">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Filter by name..."
          value={filterRaw}
          onChange={(e) => setFilterRaw(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="mt-4 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[28%]">Name</TableHead>
              <TableHead className="w-[36%]">Value</TableHead>
              <TableHead className="w-[14%]">Source</TableHead>
              <TableHead className="w-[22%]">Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={4}
                  className="py-6 text-center text-sm text-muted-foreground"
                >
                  No fields match "{filter}"
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((row) => <SettingRow key={row.name} row={row} />)
            )}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}

function SettingRow({ row }: { row: SettingItem }) {
  const sourceMeta = SOURCE_VARIANT[row.source] ?? SOURCE_VARIANT.default;
  return (
    <TableRow>
      <TableCell className="py-2.5 font-mono text-xs font-medium">
        {row.name}
      </TableCell>
      <TableCell className="py-2.5 font-mono text-xs">
        {row.is_secret ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-help text-muted-foreground">***</span>
            </TooltipTrigger>
            <TooltipContent>
              value masked because field is marked secret
            </TooltipContent>
          </Tooltip>
        ) : (
          <span className="break-all">{row.value || <em className="text-muted-foreground">empty</em>}</span>
        )}
      </TableCell>
      <TableCell className="py-2.5">
        <Badge variant={sourceMeta.variant}>{sourceMeta.label}</Badge>
      </TableCell>
      <TableCell className="py-2.5 text-xs text-muted-foreground">
        {row.description ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="line-clamp-2 cursor-help">
                {row.description}
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-sm whitespace-pre-line">
              {row.description}
            </TooltipContent>
          </Tooltip>
        ) : (
          <span className="text-muted-foreground/60">--</span>
        )}
      </TableCell>
    </TableRow>
  );
}

// ---------------------------------------------------------------------------
// Actions card
// ---------------------------------------------------------------------------

function ActionsCard({
  settings,
  z4jHome,
}: {
  settings: SettingItem[];
  z4jHome: string;
}) {
  const dotenv = React.useMemo(
    () => buildDotenvBlock(settings, z4jHome),
    [settings, z4jHome],
  );

  return (
    <Card className="p-6">
      <h3 className="text-sm font-semibold">Actions</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Copy the current effective settings as a{" "}
        <code className="font-mono">.env</code> block, or restart the brain
        to pick up edits to <code className="font-mono">~/.z4j/config.env</code>.
      </p>

      <div className="mt-4 flex flex-wrap gap-2">
        <CopyButton
          value={dotenv}
          label="Copy current as .env"
          successMessage=".env block copied to clipboard"
        />
      </div>

      <div className="mt-6">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Reload after editing config.env
        </h4>
        <p className="mt-2 text-xs text-muted-foreground">
          Pick the line that matches your deployment. z4j re-reads its
          config files at startup, so a restart is enough -- no special
          reload command exists.
        </p>
        <div className="mt-3 space-y-2">
          <ReloadInstruction
            label="systemd"
            command="sudo systemctl restart z4j"
          />
          <ReloadInstruction
            label="Docker Compose"
            command="docker compose restart z4j"
          />
          <ReloadInstruction
            label="Kubernetes"
            command="kubectl rollout restart deployment/z4j"
          />
          <ReloadInstruction
            label="macOS launchd"
            command="sudo launchctl kickstart -k system/z4j"
          />
          <ReloadInstruction
            label="bare process (POSIX)"
            command="kill -HUP $(pidof z4j)"
          />
          <ReloadInstruction
            label="Windows Service"
            command="Restart-Service z4j"
          />
        </div>
      </div>
    </Card>
  );
}

function ReloadInstruction({
  label,
  command,
}: {
  label: string;
  command: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="w-32 shrink-0 text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <code className="flex-1 truncate rounded-md border border-border bg-muted/40 px-2 py-1 font-mono text-xs">
        {command}
      </code>
      <CopyButton value={command} label="Copy" compact />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a `.env`-style block from the effective settings list.
 *
 * Each row becomes `Z4J_<UPPER_NAME>=<value>`. Secrets remain masked
 * as `***`. A leading comment block points at the source so an
 * operator who pastes this into version control later remembers it
 * was a snapshot, not a configuration intent.
 */
function buildDotenvBlock(
  settings: SettingItem[],
  z4jHome: string,
): string {
  const header = [
    "# z4j brain effective settings (read-only snapshot)",
    `# Z4J_HOME=${z4jHome}`,
    "# Secrets are masked as ***. Replace them before deploying.",
    "",
  ];
  const lines = settings.map((row) => {
    const key = `Z4J_${row.name.toUpperCase()}`;
    return `${key}=${row.value}`;
  });
  return [...header, ...lines, ""].join("\n");
}

// ---------------------------------------------------------------------------
// Reusable copy button
// ---------------------------------------------------------------------------

function CopyButton({
  value,
  label,
  successMessage,
  compact = false,
}: {
  value: string;
  label: string;
  successMessage?: string;
  compact?: boolean;
}) {
  const [copied, setCopied] = React.useState(false);
  return (
    <Button
      type="button"
      size={compact ? "sm" : "sm"}
      variant={compact ? "ghost" : "outline"}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          toast.success(successMessage ?? "Copied to clipboard");
          window.setTimeout(() => setCopied(false), 2000);
        } catch {
          toast.error("Copy failed; clipboard access denied");
        }
      }}
    >
      <Copy className="size-3.5" />
      {copied ? "Copied" : label}
    </Button>
  );
}

