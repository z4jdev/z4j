/**
 * Canvas-tree visualiser for one Celery chain / group / chord.
 *
 * Pure SVG, hand-rolled. We deliberately do NOT pull in a chart
 * or graph library - the leanness rule from SECURITY.md §16
 * applies, and this view is a single tidy-tree layout where
 * `dagre`/`d3-tree` would be massive overkill (and add hundreds
 * of transitive npm packages to the bundle).
 *
 * Layout:
 *   - Walk every node's ``parent_task_id`` to build a tree
 *     rooted at ``root_task_id``. Orphans (whose parent is
 *     missing from the response - usually because the parent
 *     finished before z4j was watching) are attached to the root
 *     so they still render.
 *   - Lay out top-down: each level is a horizontal row,
 *     children evenly spaced under their parent. No fancy
 *     compaction; readable up to ~50 nodes which covers every
 *     real-world canvas the founder has seen.
 *   - State badges colour the node fills. Click a node to jump
 *     to that task's detail page. The currently-active task is
 *     ringed.
 */
import { Link } from "@tanstack/react-router";
import type { TaskTreeNode, TaskTreeResponse } from "@/hooks/use-tasks";

/** SVG sizing. Constants on purpose - the layout is tidy not adaptive. */
const NODE_WIDTH = 180;
const NODE_HEIGHT = 60;
const COL_GAP = 24;
const ROW_GAP = 56;
const PAD = 12;

/** Map task state → fill class. Source of truth: Tailwind theme tokens. */
const STATE_FILL: Record<string, string> = {
  success: "fill-success",
  failure: "fill-destructive",
  retry: "fill-warning",
  revoked: "fill-muted",
  rejected: "fill-destructive",
  pending: "fill-muted",
  received: "fill-secondary",
  started: "fill-primary",
  unknown: "fill-muted",
};

interface PositionedNode extends TaskTreeNode {
  x: number;
  y: number;
}

function layoutTree(
  nodes: TaskTreeNode[],
  rootId: string,
): { positioned: PositionedNode[]; width: number; height: number } {
  // 1. Index nodes by id and group children by parent.
  const byId = new Map(nodes.map((n) => [n.task_id, n]));
  const childrenOf = new Map<string, TaskTreeNode[]>();
  for (const n of nodes) {
    let parentKey = n.parent_task_id ?? rootId;
    if (n.task_id !== rootId && (!parentKey || !byId.has(parentKey))) {
      parentKey = rootId;
    }
    if (n.task_id === rootId) continue;
    if (!childrenOf.has(parentKey)) childrenOf.set(parentKey, []);
    childrenOf.get(parentKey)!.push(n);
  }

  // 2. Tidy-tree layout: compute each subtree's width first
  //    (post-order), then place the root of each subtree centered
  //    over its children (pre-order). This makes fan-outs
  //    (group / chord parents) render as a wide row of siblings
  //    directly under the parent, which is the DAG-flavored look
  //    we want without actually needing multi-parent edges.
  const subtreeWidth = new Map<string, number>();
  const visitedSizing = new Set<string>();
  const computeWidth = (id: string): number => {
    if (visitedSizing.has(id)) {
      return subtreeWidth.get(id) ?? NODE_WIDTH;
    }
    visitedSizing.add(id);
    const kids = childrenOf.get(id) ?? [];
    if (kids.length === 0) {
      subtreeWidth.set(id, NODE_WIDTH);
      return NODE_WIDTH;
    }
    let total = 0;
    for (let i = 0; i < kids.length; i++) {
      total += computeWidth(kids[i]!.task_id);
      if (i > 0) total += COL_GAP;
    }
    const w = Math.max(total, NODE_WIDTH);
    subtreeWidth.set(id, w);
    return w;
  };
  computeWidth(rootId);

  // 3. Orphans / cycles not reachable from root: re-parent to root
  //    so they still render. Re-size after re-parenting.
  for (const n of nodes) {
    if (n.task_id === rootId) continue;
    if (subtreeWidth.has(n.task_id)) continue;
    const rootKids = childrenOf.get(rootId) ?? [];
    rootKids.push(n);
    childrenOf.set(rootId, rootKids);
    computeWidth(n.task_id);
  }
  visitedSizing.clear();
  subtreeWidth.clear();
  computeWidth(rootId);

  // 4. Pre-order placement.
  const positioned: PositionedNode[] = [];
  const placed = new Set<string>();
  let maxX = 0;
  let maxY = 0;
  const place = (id: string, depth: number, leftX: number): void => {
    if (placed.has(id)) return;
    placed.add(id);
    const node = byId.get(id);
    if (!node) return;
    const w = subtreeWidth.get(id) ?? NODE_WIDTH;
    const y = PAD + depth * (NODE_HEIGHT + ROW_GAP);
    const x = leftX + (w - NODE_WIDTH) / 2;
    positioned.push({ ...node, x, y });
    if (x + NODE_WIDTH > maxX) maxX = x + NODE_WIDTH;
    if (y + NODE_HEIGHT > maxY) maxY = y + NODE_HEIGHT;
    let cursor = leftX;
    for (const child of childrenOf.get(id) ?? []) {
      const childW = subtreeWidth.get(child.task_id) ?? NODE_WIDTH;
      place(child.task_id, depth + 1, cursor);
      cursor += childW + COL_GAP;
    }
  };
  place(rootId, 0, PAD);

  return {
    positioned,
    width: Math.max(maxX + PAD, NODE_WIDTH + 2 * PAD),
    height: Math.max(maxY + PAD, NODE_HEIGHT + 2 * PAD),
  };
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

interface NodeTimings {
  /** received_at -> started_at: time the task sat in the queue. */
  waitMs: number | null;
  /** started_at -> finished_at: time a worker spent running it. */
  execMs: number | null;
  /** received_at -> finished_at, the span the node occupied overall. */
  totalMs: number;
}

/**
 * Split a node's span into queue-wait and execution.
 *
 * Before started_at reached this shape the node could only show one number,
 * received_at -> finished_at, labelled "runtime". That figure is really total
 * latency: a task that ran for 40ms after waiting four minutes for a free
 * worker looked identical to one that ground away for four minutes. Those are
 * opposite problems and they want opposite fixes, which is the whole point of
 * separating them.
 *
 * waitMs is null when started_at is absent, which is normal for a task that
 * never ran or for history written before the field existed; the bar then
 * renders as a single undifferentiated span rather than guessing.
 */
export function nodeTimings(node: TaskTreeNode): NodeTimings | null {
  if (!node.received_at || !node.finished_at) return null;
  const received = Date.parse(node.received_at);
  const finished = Date.parse(node.finished_at);
  if (!Number.isFinite(received) || !Number.isFinite(finished)) return null;
  const totalMs = Math.max(0, finished - received);

  const started = node.started_at ? Date.parse(node.started_at) : NaN;
  if (!Number.isFinite(started)) {
    return { waitMs: null, execMs: null, totalMs };
  }
  // Clamp into the span. A worker clock slightly ahead of the brain's can put
  // started_at outside [received, finished], and a negative segment would
  // render as a bar pointing the wrong way.
  const clamped = Math.min(Math.max(started, received), finished);
  return {
    waitMs: clamped - received,
    execMs: finished - clamped,
    totalMs,
  };
}

interface Props {
  slug: string;
  engine: string;
  /** The task the user is viewing - ringed in the diagram. */
  activeTaskId: string;
  data: TaskTreeResponse;
}

export function TaskTree({ slug, engine, activeTaskId, data }: Props) {
  const { positioned, width, height } = layoutTree(
    data.nodes,
    data.root_task_id,
  );
  const byId = new Map(positioned.map((n) => [n.task_id, n]));

  return (
    <div className="space-y-2">
      <div className="flex items-baseline gap-3 text-xs text-muted-foreground">
        <span>
          <strong className="text-foreground">{data.node_count}</strong> tasks
          in this canvas
        </span>
        {data.truncated && (
          <span className="text-warning">
            (showing the first 500 - the full tree is larger)
          </span>
        )}
        <span
          className="flex items-baseline gap-1.5"
          title={
            "Queue wait is measured from when the brain observed the task, " +
            "not from when your client called apply_async, so it is a close " +
            "lower bound rather than an exact figure."
          }
        >
          <span
            aria-hidden
            className="inline-block h-[3px] w-4 rounded-sm bg-muted-foreground/35"
          />
          waiting
          <span
            aria-hidden
            className="ml-1.5 inline-block h-[3px] w-4 rounded-sm bg-muted-foreground"
          />
          running
          <span className="ml-1 opacity-70">(wait is approximate)</span>
        </span>
      </div>
      <div className="panel-surface overflow-auto">
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`Canvas tree with ${data.node_count} tasks`}
          className="block"
        >
          {/* Edges first so they render under the nodes. */}
          {positioned.map((n) => {
            if (!n.parent_task_id) return null;
            const parent = byId.get(n.parent_task_id);
            if (!parent) return null;
            const x1 = parent.x + NODE_WIDTH / 2;
            const y1 = parent.y + NODE_HEIGHT;
            const x2 = n.x + NODE_WIDTH / 2;
            const y2 = n.y;
            // Vertical bezier - subtle curve.
            const midY = (y1 + y2) / 2;
            return (
              <path
                key={`edge-${n.task_id}`}
                d={`M ${x1} ${y1} C ${x1} ${midY} ${x2} ${midY} ${x2} ${y2}`}
                className="stroke-border"
                strokeWidth={1.5}
                fill="none"
              />
            );
          })}
          {/* Nodes. */}
          {positioned.map((n) => {
            const fill = STATE_FILL[n.state] ?? "fill-muted";
            const isActive = n.task_id === activeTaskId;
            const timings = nodeTimings(n);
            return (
              <Link
                key={n.task_id}
                to="/projects/$slug/tasks/$engine/$taskId"
                params={{ slug, engine, taskId: n.task_id }}
              >
                <g transform={`translate(${n.x}, ${n.y})`}>
                  <title>
                    {timings === null
                      ? n.name
                      : timings.waitMs === null
                        ? `${n.name}: ${formatMs(timings.totalMs)} total`
                        : `${n.name}: ${formatMs(timings.waitMs)} waiting, ` +
                          `${formatMs(timings.execMs ?? 0)} running`}
                  </title>
                  <rect
                    width={NODE_WIDTH}
                    height={NODE_HEIGHT}
                    rx={6}
                    className={`${fill} ${isActive ? "stroke-foreground" : "stroke-border"}`}
                    strokeWidth={isActive ? 2 : 1}
                    opacity={0.85}
                  />
                  <text
                    x={10}
                    y={18}
                    className="fill-background text-[11px] font-medium"
                    style={{ pointerEvents: "none" }}
                  >
                    {n.name.length > 26 ? n.name.slice(0, 25) + "…" : n.name}
                  </text>
                  <text
                    x={10}
                    y={36}
                    className="fill-background font-mono text-[10px]"
                    style={{ pointerEvents: "none", opacity: 0.85 }}
                  >
                    {n.task_id.slice(0, 18)}
                    {n.task_id.length > 18 ? "…" : ""}
                  </text>
                  {timings && (
                    <text
                      x={NODE_WIDTH - 10}
                      y={36}
                      textAnchor="end"
                      className="fill-background font-mono text-[10px]"
                      style={{ pointerEvents: "none", opacity: 0.9 }}
                    >
                      {formatMs(timings.totalMs)}
                    </text>
                  )}
                  {timings && timings.totalMs > 0 && (
                    <g style={{ pointerEvents: "none" }} aria-hidden>
                      {/* Track, so a mostly-executing bar still reads as a bar. */}
                      <rect
                        x={10}
                        y={NODE_HEIGHT - 13}
                        width={NODE_WIDTH - 20}
                        height={6}
                        rx={2}
                        className="fill-background"
                        opacity={0.18}
                      />
                      {(() => {
                        // Wait on the left, execution on the right, a one-unit
                        // gap between them when both exist, and the right edge
                        // exactly on the track's.
                        const track = NODE_WIDTH - 20;
                        const wait = timings.waitMs;
                        const waitWidth =
                          wait === null ? 0 : (track * wait) / timings.totalMs;
                        const gapPx = wait !== null && waitWidth > 0 ? 1 : 0;
                        const execX = 10 + waitWidth + gapPx;
                        const execWidth = Math.max(
                          0,
                          track - waitWidth - gapPx,
                        );
                        return (
                          <>
                            {wait !== null && waitWidth > 0 && (
                              <rect
                                x={10}
                                y={NODE_HEIGHT - 13}
                                width={waitWidth}
                                height={6}
                                rx={2}
                                className="fill-background"
                                opacity={0.35}
                              />
                            )}
                            <rect
                              x={execX}
                              y={NODE_HEIGHT - 13}
                              width={execWidth}
                              height={6}
                              rx={2}
                              className="fill-background"
                              opacity={1}
                            />
                          </>
                        );
                      })()}
                    </g>
                  )}
                </g>
              </Link>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
