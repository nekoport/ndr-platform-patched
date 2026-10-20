"use client";

// Attack graph renderer (Phase 4 - automatic attack reconstruction).
//
// Layered left-to-right by kill-chain phase. Nodes are entities
// (ip/domain/hash), edges are observed (solid) or chain-inferred
// (dashed) relations. Pure SVG - no external graph library - so it
// stays deterministic and SSR-safe, consistent with the other NDR
// visual components.

import { useMemo, useState } from "react";
import { File, Globe, HelpCircle, Network, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { AttackEdge, AttackNode, AttackPhase } from "@/lib/ndr/types";

export const PHASES: AttackPhase[] = [
  "recon", "initial_access", "delivery", "c2", "lateral", "impact",
];

export const PHASE_META: Record<AttackPhase, { label: string; color: string; dim: string }> = {
  recon: { label: "Recon", color: "#38bdf8", dim: "rgba(56,189,248,0.14)" },
  initial_access: { label: "Initial Access", color: "#f87171", dim: "rgba(248,113,113,0.14)" },
  delivery: { label: "Delivery", color: "#fbbf24", dim: "rgba(251,191,36,0.14)" },
  c2: { label: "C2", color: "#c084fc", dim: "rgba(192,132,252,0.14)" },
  lateral: { label: "Lateral", color: "#fb923c", dim: "rgba(251,146,60,0.14)" },
  impact: { label: "Impact", color: "#fb7185", dim: "rgba(251,113,133,0.14)" },
  unknown: { label: "Context", color: "#71717a", dim: "rgba(113,113,122,0.14)" },
};

const ROLE_COLORS: Record<string, string> = {
  attacker: "#ef4444",
  c2_infra: "#a855f7",
  compromised_host: "#f97316",
  exfil_target: "#f59e0b",
  payload: "#ec4899",
  delivery_infra: "#eab308",
  target_range: "#f87171",
  entity: "#71717a",
};

const NODE_W = 158;
const NODE_H = 54;
const COL_GAP = 92;
const ROW_H = 78;

// v0.12.7 render cap: reconstructed stories can carry up to MAX_NODES
// entities; drawing every context node made incident pages heavy and
// drowned the attack chain in decoration. Show the most SIGNIFICANT 60
// (signal roles first, then confidence) and hide pure context noise.
const MAX_RENDER_NODES = 60;

const ROLE_PRIORITY: Record<string, number> = {
  attacker: 0, compromised_host: 0, target_range: 0,
  c2_infra: 1, payload: 1, delivery_infra: 1, exfil_target: 1,
};

function kindIcon(kind: string) {
  if (kind === "domain") return Globe;
  if (kind === "hash") return File;
  if (kind === "ip") return Network;
  return HelpCircle;
}

function edgePath(x1: number, y1: number, x2: number, y2: number): string {
  const midX = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
}

export function AttackGraph({
  nodes, edges,
}: {
  nodes: AttackNode[];
  edges: AttackEdge[];
}) {
  const [selected, setSelected] = useState<string | null>(null);

  // v0.12.7: pick the entities to draw (see MAX_RENDER_NODES note)
  const shown = useMemo(() => {
    if (nodes.length <= MAX_RENDER_NODES) return { nodes, hidden: 0 };
    const ranked = [...nodes].sort((a, b) =>
      ((ROLE_PRIORITY[a.role ?? ""] ?? 2)
        - (ROLE_PRIORITY[b.role ?? ""] ?? 2))
      || ((b.confidence ?? 50) - (a.confidence ?? 50))
      || a.key.localeCompare(b.key));
    const kept = ranked.slice(0, MAX_RENDER_NODES);
    return { nodes: kept, hidden: nodes.length - kept.length };
  }, [nodes]);

  const layout = useMemo(() => {
    // group nodes by phase column (kill-chain order, unknown last)
    const displayNodes = shown.nodes;
    const columns: { phase: AttackPhase; items: AttackNode[] }[] = [];
    const order = [...PHASES, "unknown" as AttackPhase];
    order.forEach((phase) => {
      const items = displayNodes.filter((n) => (n.phase ?? "unknown") === phase);
      if (items.length) columns.push({ phase, items });
    });
    const positions = new Map<string, { x: number; y: number }>();
    const maxRows = Math.max(...columns.map((c) => c.items.length), 1);
    columns.forEach((col, ci) => {
      col.items.forEach((node, ri) => {
        positions.set(node.key, {
          x: 16 + ci * (NODE_W + COL_GAP),
          y: 44 + ri * ROW_H,
        });
      });
    });
    const width = 16 * 2 + columns.length * (NODE_W + COL_GAP) - COL_GAP;
    const height = 44 + maxRows * ROW_H + 8;
    return { columns, positions, width, height };
  }, [shown]);

  // only edges whose both endpoints survived the render cap
  const displayEdges = useMemo(
    () => edges.filter((e) => layout.positions.has(e.src)
                        && layout.positions.has(e.dst)),
    [edges, layout]);

  if (!nodes.length) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-zinc-500">
        No entities in this reconstruction.
      </div>
    );
  }

  const sel = selected ? shown.nodes.find((n) => n.key === selected) : null;

  return (
    <div>
      <div className="overflow-x-auto rounded-lg border border-zinc-800/80 bg-zinc-950/60">
        <svg width={layout.width} height={layout.height}
             viewBox={`0 0 ${layout.width} ${layout.height}`}
             className="min-w-full">
          <defs>
            <marker id="ag-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#52525b" />
            </marker>
            <marker id="ag-arrow-sel" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#38bdf8" />
            </marker>
          </defs>

          {/* column headers */}
          {layout.columns.map((col, ci) => {
            const x = 16 + ci * (NODE_W + COL_GAP);
            const meta = PHASE_META[col.phase];
            return (
              <g key={col.phase}>
                <rect x={x - 6} y={6} width={NODE_W + 12} height={26} rx={6}
                      fill={meta.dim} />
                <text x={x + NODE_W / 2} y={23} textAnchor="middle"
                      fontSize={11} fontWeight={600} fill={meta.color}>
                  {meta.label.toUpperCase()}
                </text>
              </g>
            );
          })}

          {/* edges */}
          {displayEdges.map((e, i) => {
            const p1 = layout.positions.get(e.src);
            const p2 = layout.positions.get(e.dst);
            if (!p1 || !p2) return null;
            const x1 = p1.x + NODE_W;
            const y1 = p1.y + NODE_H / 2;
            const x2 = p2.x;
            const y2 = p2.y + NODE_H / 2;
            const highlight = selected != null && (e.src === selected || e.dst === selected);
            const stroke = highlight ? "#38bdf8" : "#52525b";
            return (
              <g key={`${e.src}-${e.dst}-${e.relation}-${i}`}>
                <path d={edgePath(x1, y1, x2, y2)} fill="none"
                      stroke={stroke} strokeWidth={highlight ? 2 : 1.4}
                      strokeDasharray={e.inferred ? "5 4" : undefined}
                      markerEnd={highlight ? "url(#ag-arrow-sel)" : "url(#ag-arrow)"}
                      opacity={highlight ? 1 : 0.75}>
                  {highlight && (
                    <animate attributeName="stroke-dashoffset"
                             from="18" to="0" dur="0.9s"
                             repeatCount="indefinite" />
                  )}
                </path>
                {/* v0.12.7: relation labels render ONLY for the selected
                    node's edges - labels on every edge made large graphs
                    slow to paint and impossible to read */}
                {highlight && (
                  <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 5}
                        textAnchor="middle" fontSize={9}
                        fill="#38bdf8">
                    {e.relation}{e.inferred ? " *" : ""}
                  </text>
                )}
              </g>
            );
          })}

          {/* nodes */}
          {shown.nodes.map((n) => {
            const pos = layout.positions.get(n.key);
            if (!pos) return null;
            const meta = PHASE_META[(n.phase ?? "unknown") as AttackPhase];
            const roleColor = ROLE_COLORS[n.role ?? "entity"] ?? meta.color;
            const Icon = kindIcon(n.kind);
            const isSel = selected === n.key;
            return (
              <g key={n.key}
                 onClick={() => setSelected(isSel ? null : n.key)}
                 className="cursor-pointer">
                <rect x={pos.x} y={pos.y} width={NODE_W} height={NODE_H} rx={10}
                      fill={isSel ? "rgba(52,211,153,0.10)" : "rgba(39,39,42,0.92)"}
                      stroke={isSel ? "#38bdf8" : roleColor}
                      strokeWidth={isSel ? 2 : 1.2} />
                <rect x={pos.x} y={pos.y} width={4} height={NODE_H} rx={2}
                      fill={roleColor} />
                <g transform={`translate(${pos.x + 12}, ${pos.y + 11})`}>
                  <Icon size={13} color={roleColor} />
                </g>
                <text x={pos.x + 32} y={pos.y + 22} fontSize={11.5}
                      fontWeight={600} fill="#e4e4e7">
                  {n.label.length > 20 ? `${n.label.slice(0, 19)}…` : n.label}
                </text>
                <text x={pos.x + 12} y={pos.y + 40} fontSize={9.5} fill="#a1a1aa">
                  {(n.role ?? n.kind)}{n.attrs?.ti_match ? " · TI ✓" : ""}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-3 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1.5">
          <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="#52525b" strokeWidth="1.6" /></svg>
          observed relation
        </span>
        <span className="flex items-center gap-1.5">
          <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="#52525b" strokeWidth="1.6" strokeDasharray="5 4" /></svg>
          inferred (entity/temporal context) *
        </span>
        <span>click a node to inspect it</span>
        {shown.hidden > 0 && (
          <span className="text-amber-300/80">
            + {shown.hidden} context entities hidden (top {MAX_RENDER_NODES} shown) -
            the evidence list and the incident report cover them all
          </span>
        )}
      </div>

      {sel && (
        <div className="mt-3 rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-3">
          <div className="mb-2 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-emerald-400" />
            <span className="text-sm font-semibold text-zinc-100">{sel.label}</span>
            <Badge variant="outline" className="border-zinc-700 text-zinc-400">{sel.kind}</Badge>
            {sel.role && (
              <Badge variant="outline"
                     className="border-zinc-700"
                     style={{ color: ROLE_COLORS[sel.role] ?? "#a1a1aa" }}>
                {sel.role}
              </Badge>
            )}
          </div>
          <div className="grid gap-1 text-xs text-zinc-400 sm:grid-cols-2">
            <div>phase: <span style={{ color: PHASE_META[(sel.phase ?? "unknown") as AttackPhase].color }}>
              {PHASE_META[(sel.phase ?? "unknown") as AttackPhase].label}
            </span></div>
            <div>confidence: {sel.confidence ?? 50}/100 (heuristic)</div>
            <div>first seen: {sel.first_seen ?? "n/a"}</div>
            <div>last seen: {sel.last_seen ?? "n/a"}</div>
            {Object.entries(sel.attrs ?? {}).filter(([, v]) => v != null).map(([k, v]) => (
              <div key={k} className="truncate">
                {k}: <span className="text-zinc-300">{String(v)}</span>
              </div>
            ))}
          </div>
          <div className="mt-2 border-t border-zinc-800/70 pt-2">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              related evidence
            </div>
            <div className="space-y-0.5 text-xs text-zinc-400">
              {displayEdges.filter((e) => e.src === sel.key || e.dst === sel.key)
                .map((e, i) => (
                  <div key={i} className="truncate">
                    <span className="text-zinc-300">{e.relation}</span>
                    {" → "}
                    {(e.src === sel.key
                      ? shown.nodes.find((n) => n.key === e.dst)?.label
                      : shown.nodes.find((n) => n.key === e.src)?.label) ?? "?"}
                    {e.inferred ? " (inferred)" : ""}
                  </div>
                ))}
              {!displayEdges.some((e) => e.src === sel.key || e.dst === sel.key) && (
                <div className="text-zinc-600">no relations recorded</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
