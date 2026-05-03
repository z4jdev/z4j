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
const NODE_HEIGHT = 48;
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

function formatRuntime(node: TaskTreeNode): string | null {
  if (!node.received_at || !node.finished_at) return null;
  const start = Date.parse(node.received_at);
  const end = Date.parse(node.finished_at);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  const ms = Math.max(0, end - start);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
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
          <strong className="text-foreground">{data.node_count}</strong>{" "}
          tasks in this canvas
        </span>
        {data.truncated && (
          <span className="text-warning">
            (showing the first 500 - the full tree is larger)
          </span>
        )}
      </div>
      <div className="overflow-auto rounded-md border bg-card">
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
            const runtime = formatRuntime(n);
            return (
              <Link
                key={n.task_id}
                to="/projects/$slug/tasks/$engine/$taskId"
                params={{ slug, engine, taskId: n.task_id }}
              >
                <g transform={`translate(${n.x}, ${n.y})`}>
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
                  {runtime && (
                    <text
                      x={NODE_WIDTH - 10}
                      y={36}
                      textAnchor="end"
                      className="fill-background font-mono text-[10px]"
                      style={{ pointerEvents: "none", opacity: 0.9 }}
                    >
                      {runtime}
                    </text>
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
