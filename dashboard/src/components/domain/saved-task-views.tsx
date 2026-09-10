import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bookmark, ChevronDown, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useMe } from "@/hooks/use-auth";
import { api } from "@/lib/api";
import type { components } from "@/lib/openapi-types.gen";
import {
  parseTaskListSearch,
  type TaskListSearch,
} from "@/lib/task-list-search";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useConfirm } from "@/components/domain/confirm-dialog";

type SavedView = components["schemas"]["SavedViewPublic"];
type ViewWrite = components["schemas"]["SavedViewWrite"];

function describe(filters: SavedView["filters"]) {
  return (
    [
      filters.state,
      filters.priority?.join(", "),
      filters.search && `Search: ${filters.search}`,
    ]
      .filter(Boolean)
      .join(" · ") || "All tasks"
  );
}

export function SavedTaskViews({
  slug,
  filters,
  onApply,
}: {
  slug: string;
  filters: TaskListSearch;
  onApply: (filters: TaskListSearch) => void;
}) {
  const trigger = useRef<HTMLButtonElement>(null);
  const { data: user } = useMe();
  const client = useQueryClient();
  const queryKey = ["saved-views", slug, user?.id];
  const path = `/projects/${encodeURIComponent(slug)}/saved-views`;
  const views = useQuery({
    queryKey,
    queryFn: () => api.get<SavedView[]>(path),
    enabled: !!user,
  });
  const [panel, setPanel] = useState<"create" | "manage" | SavedView | null>(
    null,
  );
  const [name, setName] = useState("");
  const [replaceFilters, setReplaceFilters] = useState(false);
  const [error, setError] = useState("");
  const { confirm, dialog: confirmation } = useConfirm();
  const editing = typeof panel === "object" ? panel : null;
  const current: ViewWrite["filters"] = {
    state: filters.state && filters.state !== "all" ? filters.state : null,
    priority: filters.priority ?? [],
    search: filters.search ?? "",
  };
  const save = useMutation({
    mutationFn: ({ id, body }: { id?: string; body: ViewWrite }) =>
      id
        ? api.put<SavedView>(`${path}/${id}`, body)
        : api.post<SavedView>(path, body),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey });
      setPanel(editing ? "manage" : null);
      toast.success(editing ? "Saved view updated" : "View saved");
    },
    onError: (cause: Error) => setError(cause.message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`${path}/${id}`),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey });
      toast.success("Saved view deleted");
    },
  });
  const pending = save.isPending || remove.isPending;
  const open = (value: typeof panel) => {
    setError("");
    setName(typeof value === "object" && value ? value.name : "");
    setReplaceFilters(false);
    setPanel(value);
  };
  const apply = (view: SavedView) => {
    onApply(parseTaskListSearch(view.filters));
    setPanel(null);
  };

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger ref={trigger} asChild>
          <Button
            variant="outline"
            aria-label="Saved views"
            className="shrink-0"
          >
            <Bookmark className="size-4" /> Saved views{" "}
            <ChevronDown className="size-4 opacity-60" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          onInteractOutside={(event) => {
            // The trigger owns its toggle, including during the exit animation.
            // An outside dismissal must not immediately undo a fast reopen.
            const target = event.detail.originalEvent.target;
            if (target instanceof Node && trigger.current?.contains(target)) {
              event.preventDefault();
            }
          }}
          className="max-h-[min(24rem,var(--radix-dropdown-menu-content-available-height))] w-72 max-w-[calc(100vw-2rem)] overflow-y-auto"
        >
          <DropdownMenuLabel>Your task views</DropdownMenuLabel>
          {views.isPending && (
            <DropdownMenuItem disabled>Loading views…</DropdownMenuItem>
          )}
          {views.isError ? (
            <DropdownMenuItem onSelect={() => void views.refetch()}>
              Could not load views · Retry
            </DropdownMenuItem>
          ) : (
            views.data?.map((view) => (
              <DropdownMenuItem
                key={view.id}
                onSelect={() => apply(view)}
                className="block"
              >
                <span className="block truncate">{view.name}</span>
                <span className="block truncate text-xs text-muted-foreground">
                  {describe(view.filters)}
                </span>
              </DropdownMenuItem>
            ))
          )}
          {views.data?.length === 0 && (
            <DropdownMenuItem disabled>No saved views yet</DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            disabled={
              views.isPending ||
              views.isError ||
              (views.data?.length ?? 0) >= 100
            }
            onSelect={() => open("create")}
          >
            <Plus className="size-4" /> Save current filters…
          </DropdownMenuItem>
          <DropdownMenuItem
            disabled={!views.data?.length || views.isError}
            onSelect={() => open("manage")}
          >
            <Pencil className="size-4" /> Manage views…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog
        open={panel !== null}
        onOpenChange={(value) => {
          if (!value && !pending) open(null);
        }}
      >
        <DialogContent
          className="max-h-[85dvh] overflow-y-auto"
          onCloseAutoFocus={(event) => {
            // The opening menu item is gone; return to the persistent toolbar
            // trigger unless another dialog or destination already owns focus.
            event.preventDefault();
            const focused = document.activeElement;
            if (
              focused === document.body ||
              focused?.closest('[role="dialog"][data-state="closed"]')
            ) {
              trigger.current?.focus();
            }
          }}
        >
          <DialogHeader>
            <DialogTitle>
              {panel === "manage"
                ? "Manage saved views"
                : editing
                  ? "Edit saved view"
                  : "Save task view"}
            </DialogTitle>
            <DialogDescription>
              Personal task filters for {slug}. Only you can see and change
              these views.
            </DialogDescription>
          </DialogHeader>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          {panel === "manage" ? (
            <div className="space-y-3">
              {views.isError && (
                <p role="alert">
                  Could not load saved views.{" "}
                  <Button variant="link" onClick={() => void views.refetch()}>
                    Retry
                  </Button>
                </p>
              )}
              {views.data?.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No saved views. Save a set of filters from the Tasks toolbar.
                </p>
              )}
              {views.data?.map((view) => (
                <div
                  key={view.id}
                  className="panel-surface flex flex-wrap items-center gap-3 p-3"
                >
                  <div className="min-w-0 flex-1 basis-48">
                    <p className="break-words text-sm font-medium">
                      {view.name}
                    </p>
                    <p className="break-words text-xs text-muted-foreground">
                      {describe(view.filters)}
                    </p>
                  </div>
                  <div className="flex gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={pending || views.isError}
                      onClick={() => apply(view)}
                      aria-label={`Apply ${view.name}`}
                    >
                      Apply
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={pending || views.isError}
                      onClick={() => open(view)}
                      aria-label={`Edit ${view.name}`}
                    >
                      <Pencil className="size-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={pending || views.isError}
                      aria-label={`Delete ${view.name}`}
                      onClick={() =>
                        confirm({
                          title: "Delete saved view",
                          description: `Delete “${view.name}”? Task history and your current filters are unchanged.`,
                          confirmLabel: "Delete view",
                          onConfirm: async () => {
                            try {
                              await remove.mutateAsync(view.id);
                            } catch (cause) {
                              setError(
                                cause instanceof Error
                                  ? cause.message
                                  : "Could not delete saved view.",
                              );
                            }
                          },
                        })
                      }
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                setError("");
                save.mutate({
                  id: editing?.id,
                  body: {
                    name: name.trim(),
                    filters:
                      editing && !replaceFilters ? editing.filters : current,
                  },
                });
              }}
            >
              <div className="space-y-2">
                <Label htmlFor="saved-view-name">View name</Label>
                <Input
                  id="saved-view-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  maxLength={80}
                  required
                  disabled={pending}
                  placeholder="Failed payment tasks"
                />
              </div>
              {editing && (
                <label className="flex items-start gap-2 text-sm">
                  <Checkbox
                    checked={replaceFilters}
                    onCheckedChange={(checked) =>
                      setReplaceFilters(checked === true)
                    }
                    disabled={pending}
                    className="mt-1"
                  />
                  Replace saved filters with the current task filters
                </label>
              )}
              <div className="rounded-md border bg-muted/30 p-3 text-sm break-words">
                <span className="font-medium">Filters: </span>
                {describe(
                  editing && !replaceFilters ? editing.filters : current,
                )}
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => open(editing ? "manage" : null)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={pending || !name.trim()}>
                  {pending ? "Saving…" : editing ? "Save changes" : "Save view"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
      {confirmation}
    </>
  );
}
