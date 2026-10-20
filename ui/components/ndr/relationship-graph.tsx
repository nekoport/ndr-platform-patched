"use client";

// Attack Relationship Graph (Phase 5) - the campaign investigation
// centerpiece.
//
// Force-directed, deterministic layout (pure function of node order).
// Every edge carries its correlation reasons; every node carries its
// campaigns. Solid edge = observed relation, dashed = inferred
// (entity/temporal context), amber dashed = cross-campaign correlation
// on shared infrastructure. Time proximity alone never draws an edge.

import { useMemo, useRef } from "react";
import {
  ArrowRight, Crosshair, File, Globe, HelpCircle,
  Info, Network, ShieldAlert, Target,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { PHASE_META } from "./attack-graph";
import { alertTitle, fmtNumber, PanZoomControls, timeAgo, usePanZoom } from "./shared";
import type {
  EntityPivot, GraphEdge, GraphNode, RelationshipGraph,
} from "@/lib/ndr/types";

const W = 980;
const H = 600;

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

const CORR_COLOR = "#f59e0b";

function kindIcon(kind: string) {
  if (kind === "domain") return Globe;
  if (kind === "hash") return File;
  if (kind === "ip") return Network;
  return HelpCircle;
}

function nodeColor(n: GraphNode): string {
  const role = n.roles[0];
  if (role && ROLE_COLORS[role]) return ROLE_COLORS[role];
  return ROLE_COLORS[n.kind] ?? "#71717a";
}

function nodeRadius(n: GraphNode): number {
  return 9 + Math.min(13, Math.sqrt(n.evidence_count) * 3.4);
}

// -------------------------------------------------------- force layout

function computeLayout(nodes: GraphNode[], edges: GraphEdge[]):
  Map<string, { x: number; y: number }> {
  const pos = new Map<string, { x: number; y: number }>();
  const n = nodes.length;
  if (!n) return pos;
  const idx = new Map<string, number>();
  nodes.forEach((node, i) => {
    idx.set(node.key, i);
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    pos.set(node.key, {
      x: W / 2 + Math.cos(angle) * W * 0.32,
      y: H / 2 + Math.sin(angle) * H * 0.34,
    });
  });
  const links = edges
    .map((e) => ({ a: idx.get(e.src), b: idx.get(e.dst) }))
    .filter((l): l is { a: number; b: number } =>
      l.a !== undefined && l.b !== undefined);
  const rest = 120;
  const kRep = 24_000;
  let temp = 1;
  for (let iter = 0; iter < 220; iter++) {
    const fx = new Array(n).fill(0);
    const fy = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const p1 = pos.get(nodes[i].key)!;
        const p2 = pos.get(nodes[j].key)!;
        let dx = p1.x - p2.x;
        let dy = p1.y - p2.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = (i - j) * 0.7 + 0.3; dy = (j - i) * 0.5 + 0.4; d2 = dx * dx + dy * dy; }
        const d = Math.sqrt(d2);
        const f = kRep / d2;
        fx[i] += (dx / d) * f;
        fy[i] += (dy / d) * f;
        fx[j] -= (dx / d) * f;
        fy[j] -= (dy / d) * f;
      }
    }
    for (const l of links) {
      const p1 = pos.get(nodes[l.a].key)!;
      const p2 = pos.get(nodes[l.b].key)!;
      const dx = p2.x - p1.x;
      const dy = p2.y - p1.y;
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const f = (d - rest) * 0.045;
      fx[l.a] += (dx / d) * f * d * 0.02;
      fy[l.a] += (dy / d) * f * d * 0.02;
      fx[l.b] -= (dx / d) * f * d * 0.02;
      fy[l.b] -= (dy / d) * f * d * 0.02;
    }
    // gentle centering
    for (let i = 0; i < n; i++) {
      const p = pos.get(nodes[i].key)!;
      fx[i] += (W / 2 - p.x) * 0.008;
      fy[i] += (H / 2 - p.y) * 0.008;
      const dx = Math.max(-22, Math.min(22, fx[i] * temp));
      const dy = Math.max(-22, Math.min(22, fy[i] * temp));
      p.x = Math.max(46, Math.min(W - 46, p.x + dx));
      p.y = Math.max(46, Math.min(H - 46, p.y + dy));
    }
    temp = Math.max(0.02, temp * 0.978);
  }
  return pos;
}

// ------------------------------------------------------------ component

export interface RelationshipGraphProps {
  graph: RelationshipGraph;
  selectedNode: string | null;
  onSelectNode: (key: string | null) => void;
  selectedEdge: string | null;
  onSelectEdge: (key: string | null) => void;
  selectedCampaign: string | null;
  onSelectCampaign: (id: string | null) => void;
  tiOverlay: boolean;
  pivot: EntityPivot | null;
  pivotLoading: boolean;
  onOpenOnGeoMap?: (ip: string) => void;
}

export function RelationshipGraphView({
  graph, selectedNode, onSelectNode, selectedEdge, onSelectEdge,
  selectedCampaign, onSelectCampaign, tiOverlay, pivot, pivotLoading,
  onOpenOnGeoMap,
}: RelationshipGraphProps) {
  const { nodes, edges, campaigns } = graph;
  const svgRef = useRef<SVGSVGElement | null>(null);
  const pz = usePanZoom(W, H, svgRef);

  const layout = useMemo(
    () => computeLayout(nodes, edges), [nodes, edges]);

  const campaignKeys = useMemo(() => {
    if (!selectedCampaign) return null;
    return new Set(campaigns.find((c) => c.id === selectedCampaign)
      ?.node_keys ?? []);
  }, [campaigns, selectedCampaign]);

  const neighborKeys = useMemo(() => {
    if (!selectedNode) return null;
    const s = new Set<string>([selectedNode]);
    edges.forEach((e) => {
      if (e.src === selectedNode) s.add(e.dst);
      if (e.dst === selectedNode) s.add(e.src);
    });
    return s;
  }, [edges, selectedNode]);

  const selNode = selectedNode
    ? nodes.find((n) => n.key === selectedNode) ?? null : null;
  const selEdge = selectedEdge
    ? edges.find((e) => `${e.src}|${e.dst}|${e.relation}`
        === selectedEdge) ?? null : null;

  const edgeStyle = (e: GraphEdge): { stroke: string; dash?: string; width: number; opacity: number } => {
    const active = neighborKeys
      ? neighborKeys.has(e.src) && neighborKeys.has(e.dst) : true;
    const inCampaign = campaignKeys
      ? e.incident_ids.some((i) => campaignKeys.has(i))
        && campaignKeys.has(e.src) && campaignKeys.has(e.dst) : true;
    return {
      stroke: e.relation === "correlated_with" ? CORR_COLOR
        : active && inCampaign ? "#5eead4" : "#3f3f46",
      dash: e.inferred ? "5 4" : undefined,
      width: 1 + Math.min(3.5, e.evidence_count / 2.5),
      opacity: active && inCampaign ? 0.85 : 0.14,
    };
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
      <div className="space-y-3">
        {/* campaign selector */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-1 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
            <Target className="h-3.5 w-3.5" /> Campaign
          </span>
          <button
            onClick={() => onSelectCampaign(null)}
            className={cn("rounded-full border px-2.5 py-1 text-[11px] transition-colors",
              !selectedCampaign
                ? "border-emerald-700 bg-emerald-950/70 text-emerald-300"
                : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200")}>
            All campaigns ({campaigns.length})
          </button>
          {campaigns.map((c) => (
            <button key={c.id}
                    onClick={() => onSelectCampaign(
                      selectedCampaign === c.id ? null : c.id)}
                    className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition-colors",
                      selectedCampaign === c.id
                        ? "border-emerald-700 bg-emerald-950/70 text-emerald-300"
                        : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200")}
                    title={`${c.title} - confidence ${c.confidence}/100 (heuristic)`}>
              <span className="h-1.5 w-1.5 rounded-full"
                    style={{ background: c.severity === "critical"
                      ? "#f87171" : c.severity === "high" ? "#fb923c"
                      : c.severity === "medium" ? "#fbbf24" : "#60a5fa" }} />
              <span className="max-w-[240px] truncate">{c.title}</span>
              <span className="tabular-nums text-zinc-500">{c.confidence}</span>
            </button>
          ))}
        </div>

        {/* graph canvas */}
        <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-[#0a0f0d]">
          <svg ref={svgRef} viewBox={`${pz.view.x} ${pz.view.y} ${pz.view.w} ${pz.view.h}`}
               className="w-full touch-none select-none"
               style={{ minHeight: 420, cursor: pz.grabbing ? "grabbing" : "grab" }}
               {...pz.handlers}>
            <defs>
              <marker id="rg-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                      markerWidth="6.5" markerHeight="6.5"
                      orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#3f3f46" />
              </marker>
              <marker id="rg-arrow-hi" viewBox="0 0 10 10" refX="9" refY="5"
                      markerWidth="6.5" markerHeight="6.5"
                      orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#5eead4" />
              </marker>
            </defs>

            {/* edges */}
            {edges.map((e) => {
              const p1 = layout.get(e.src);
              const p2 = layout.get(e.dst);
              if (!p1 || !p2) return null;
              const st = edgeStyle(e);
              const key = `${e.src}|${e.dst}|${e.relation}`;
              const isSel = selectedEdge === key;
              const mx = (p1.x + p2.x) / 2;
              const my = (p1.y + p2.y) / 2;
              return (
                <g key={key} className="cursor-pointer"
                   onClick={(ev) => {
                     ev.stopPropagation();
                     if (pz.didDrag()) return; // pan ended here - not a selection
                     onSelectEdge(isSel ? null : key);
                   }}>
                  <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
                        stroke={isSel ? "#38bdf8" : st.stroke}
                        strokeWidth={isSel ? st.width + 1.4 : st.width}
                        strokeDasharray={st.dash}
                        strokeOpacity={isSel ? 1 : st.opacity}
                        markerEnd={isSel || st.stroke === "#5eead4"
                          ? "url(#rg-arrow-hi)" : undefined} />
                  {isSel && (
                    <animate attributeName="stroke-dashoffset"
                             from="18" to="0" dur="0.9s"
                             repeatCount="indefinite" />
                  )}
                  {(isSel) && (
                    <text x={mx} y={my - 5} textAnchor="middle"
                          fontSize={9.5}
                          fill={"#38bdf8"}>
                      {e.relation}
                      {e.inferred ? " *" : ""}
                    </text>
                  )}
                  <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
                        stroke="transparent" strokeWidth={12} />
                </g>
              );
            })}

            {/* nodes */}
            {nodes.map((n) => {
              const p = layout.get(n.key);
              if (!p) return null;
              const r = nodeRadius(n);
              const color = nodeColor(n);
              const Icon = kindIcon(n.kind);
              const isSel = selectedNode === n.key;
              const dimByCampaign = campaignKeys
                ? !campaignKeys.has(n.key) : false;
              const dimByNeighbor = neighborKeys
                ? !neighborKeys.has(n.key) : false;
              const dim = dimByCampaign || dimByNeighbor;
              return (
                <g key={n.key}
                   transform={`translate(${p.x}, ${p.y})`}
                   className="cursor-pointer"
                   opacity={dim ? 0.16 : 1}
                   onClick={(ev) => {
                     ev.stopPropagation();
                     if (pz.didDrag()) return; // pan ended here - not a selection
                     onSelectNode(isSel ? null : n.key);
                   }}>
                  <title>
                    {`${n.label} (${n.kind})${n.roles.length ? ` - ${n.roles.join(", ")}` : ""} - evidence ${n.evidence_count} - confidence ${n.confidence}/100 (heuristic)${n.ti_match ? " - TI MATCH" : ""}`}
                  </title>
                  {n.ti_match && tiOverlay && (
                    <circle r={r + 5} fill="none" stroke="#a855f7"
                            strokeOpacity={0.85} strokeWidth={1.6}
                            strokeDasharray="3 3">
                      <animate attributeName="stroke-opacity"
                               values="0.85;0.25;0.85" dur="2s"
                               repeatCount="indefinite" />
                    </circle>
                  )}
                  {isSel && (
                    <circle r={r + 9} fill="none" stroke="#38bdf8"
                            strokeOpacity={0.9} strokeWidth={2} />
                  )}
                  <circle r={r} fill={isSel ? "rgba(52,211,153,0.16)"
                    : "rgba(24,24,27,0.95)"} stroke={color}
                          strokeWidth={isSel ? 2.2 : 1.5} />
                  <g transform={`translate(${-7}, ${-7})`}>
                    <Icon size={14} color={color} />
                  </g>
                  {n.ti_match && (
                    <circle cx={r - 2} cy={-r + 2} r={4.4} fill="#a855f7"
                            stroke="#0a0f0d" strokeWidth={1} />
                  )}
                  <text y={r + 13} textAnchor="middle" fontSize={10.5}
                        fontWeight={600} fill="#e4e4e7">
                    {n.label.length > 26
                      ? `${n.label.slice(0, 25)}…` : n.label}
                  </text>
                  <text y={r + 24} textAnchor="middle" fontSize={8.5}
                        fill="#71717a">
                    {n.roles[0] ?? n.kind} · ev {n.evidence_count}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* legend */}
          <div className="pointer-events-none absolute bottom-2 left-3 flex flex-wrap items-center gap-3 text-[10px] text-zinc-500">
            <span className="text-zinc-600">drag to pan &middot; scroll to zoom &middot; click node/edge for detail</span>
            <span className="flex items-center gap-1.5">
              <svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="#5eead4" strokeWidth="1.8" /></svg>
              observed
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="#71717a" strokeWidth="1.8" strokeDasharray="5 4" /></svg>
              inferred *
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke={CORR_COLOR} strokeWidth="1.8" strokeDasharray="5 4" /></svg>
              cross-campaign (shared infra)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-[#a855f7] bg-transparent" />
              TI match
            </span>
          </div>
          <div className="pointer-events-none absolute bottom-2 right-3 rounded bg-zinc-950/70 px-2 py-1 text-[10px] text-zinc-400">
            {graph.meta.node_count} entities · {graph.meta.edge_count} relations · {graph.meta.campaign_count} campaigns
          </div>
          <PanZoomControls pz={pz} />
        </div>

        <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-zinc-500">
          <Info className="mt-0.5 h-3 w-3 shrink-0" />
          {graph.meta.basis}. {graph.meta.disclaimer} Edges never rely on
          time proximity alone - open an edge to read its correlation
          reason and evidence.
        </p>
      </div>

      {/* detail panel */}
      <div className="space-y-3">
        {selNode && (
          <NodePanel node={selNode} pivot={pivot} pivotLoading={pivotLoading}
                     onSelectCampaign={onSelectCampaign}
                     onOpenOnGeoMap={onOpenOnGeoMap} />
        )}
        {!selNode && selEdge && (
          <EdgePanel edge={selEdge} nodes={nodes}
                     onSelectNode={onSelectNode}
                     onSelectCampaign={onSelectCampaign} />
        )}
        {!selNode && !selEdge && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 text-xs leading-relaxed text-zinc-500">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-zinc-300">
              <Crosshair className="h-4 w-4 text-emerald-400" />
              Investigate
            </div>
            Click a <span className="text-zinc-300">node</span> to inspect
            the entity: its campaigns, relations with correlation reasons,
            evidence pivot and blast radius. Click an{" "}
            <span className="text-zinc-300">edge</span> to read why two
            entities are linked. Pick a campaign above to isolate one
            chain and see its attack sequence.
          </div>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------- panels

function NodePanel({ node, pivot, pivotLoading, onSelectCampaign,
                     onOpenOnGeoMap }: {
  node: GraphNode;
  pivot: EntityPivot | null;
  pivotLoading: boolean;
  onSelectCampaign: (id: string | null) => void;
  onOpenOnGeoMap?: (ip: string) => void;
}) {
  const color = nodeColor(node);
  const phase = PHASE_META[node.phase] ?? PHASE_META.unknown;
  const ip = node.kind === "ip" ? node.label : null;
  const isExternal = ip ? node.internal === false : false;
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-emerald-400" />
          <span className="font-mono text-sm font-semibold text-zinc-100">
            {node.label}
          </span>
          <Badge variant="outline" className="border-zinc-700 text-zinc-400">
            {node.kind}
          </Badge>
          {node.roles.map((r) => (
            <Badge key={r} variant="outline" style={{ color: ROLE_COLORS[r] ?? "#a1a1aa" }}
                   className="border-zinc-700">
              {r}
            </Badge>
          ))}
          {node.ti_match && (
            <Badge variant="outline"
                   className="border-purple-800 bg-purple-950/50 text-purple-300">
              TI match
            </Badge>
          )}
        </div>

        <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs text-zinc-400">
          <div>phase: <span style={{ color: phase.color }}>{phase.label}</span></div>
          <div>confidence: <span className="tabular-nums text-zinc-200">{node.confidence}/100</span> <span className="text-zinc-600">(heuristic)</span></div>
          <div>first seen: {node.first_seen ? timeAgo(node.first_seen) : "n/a"}</div>
          <div>last seen: {node.last_seen ? timeAgo(node.last_seen) : "n/a"}</div>
          <div>evidence items: <span className="tabular-nums text-zinc-200">{node.evidence_count}</span></div>
          <div>relations: <span className="tabular-nums text-zinc-200">{node.degree}</span></div>
        </div>

        {/* TI provenance */}
        {node.ti_match && (
          <div className="mt-3 rounded-lg border border-purple-900/50 bg-purple-950/20 p-2.5 text-[11px] text-purple-200">
            <div className="font-semibold">Threat intelligence overlay</div>
            <div className="mt-0.5 text-purple-300/80">
              source: {String(node.attrs.ti_source ?? "threat-intel feed")}
              {node.attrs.ti_updated
                ? ` · updated ${String(node.attrs.ti_updated)}`
                : ""}
              {node.attrs.malware
                ? ` · malware: ${String(node.attrs.malware)}` : ""}
            </div>
            <div className="mt-0.5 text-purple-300/60">
              IOC match is contextual evidence supporting investigation -
              not proof of compromise by itself.
            </div>
          </div>
        )}

        {/* attributes (TI fields render in the overlay box above) */}
        {Object.entries(node.attrs).filter(
          ([k, v]) => k !== "ti_match" && !k.startsWith("ti_")
            && v !== null && v !== undefined,
        ).length > 0 && (
          <div className="mt-3 space-y-0.5 text-[11px] text-zinc-400">
            {Object.entries(node.attrs)
              .filter(([k, v]) => k !== "ti_match" && !k.startsWith("ti_")
                && v !== null && v !== undefined)
              .slice(0, 6)
              .map(([k, v]) => (
                <div key={k} className="truncate">
                  <span className="text-zinc-500">{k}:</span>{" "}
                  <span className="text-zinc-300">{String(v)}</span>
                </div>
              ))}
          </div>
        )}

        {/* campaigns */}
        <div className="mt-3">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            campaigns
          </div>
          <div className="flex flex-wrap gap-1.5">
            {node.incident_ids.map((id) => (
              <button key={id} onClick={() => onSelectCampaign(id)}
                      className="rounded border border-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-400 transition-colors hover:border-emerald-800 hover:text-emerald-300">
                {id}
              </button>
            ))}
          </div>
        </div>

        {isExternal && onOpenOnGeoMap && (
          <Button size="sm" variant="outline"
                  className="mt-3 h-7 border-zinc-800 text-xs text-zinc-300 hover:bg-zinc-800"
                  onClick={() => onOpenOnGeoMap(ip!)}>
            <Globe className="mr-1.5 h-3 w-3" />
            Show on geographic map
          </Button>
        )}
      </div>

      {/* blast radius */}
      {pivot && (
        <BlastRadiusCard radius={pivot.blast_radius} />
      )}
      {pivotLoading && !pivot && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 text-xs text-zinc-500">
          loading pivot + blast radius...
        </div>
      )}

      {/* evidence pivot */}
      {pivot && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
          <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            evidence pivot
          </div>
          {pivot.alerts.length > 0 && (
            <div className="mb-3 space-y-1.5">
              {pivot.alerts.map((a, i) => (
                <div key={i} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-zinc-200">{alertTitle(a.title)}</span>
                    <span className={cn("shrink-0 text-[10px] font-semibold uppercase",
                      a.severity === "high" || a.severity === "critical"
                        ? "text-red-400" : "text-amber-400")}>
                      {a.severity}
                    </span>
                  </div>
                  {a.index && a.alert_id && (
                    <div className="mt-0.5 truncate font-mono text-[10px] text-zinc-600">
                      {a.index}:{a.alert_id}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {pivot.events_sample.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                session metadata (recent)
              </div>
              <div className="space-y-1">
                {pivot.events_sample.slice(0, 5).map((e, i) => (
                  <div key={i} className="flex items-center justify-between gap-2 rounded-md border border-zinc-800/70 bg-zinc-950/40 px-2 py-1 font-mono text-[10px] text-zinc-400">
                    <span className="truncate">
                      {e.source_ip} → {e.destination_ip}
                      {e.destination_port ? `:${e.destination_port}` : ""}
                      {e.tls_sni ? ` · sni ${e.tls_sni}` : ""}
                      {e.dns_query ? ` · dns ${e.dns_query}` : ""}
                    </span>
                    <span className="shrink-0 text-zinc-600">
                      {e.network_bytes
                        ? fmtNumber(Number(e.network_bytes)) : ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {pivot.alerts.length === 0 && pivot.events_sample.length === 0 && (
            <div className="text-xs text-zinc-600">
              No recent alerts or session metadata for this entity in the
              search window.
            </div>
          )}
          <p className="mt-2 border-t border-zinc-800/70 pt-2 text-[10px] leading-relaxed text-zinc-600">
            {pivot.disclaimer}
          </p>
        </div>
      )}
    </div>
  );
}

function BlastRadiusCard({ radius }: {
  radius: EntityPivot["blast_radius"];
}) {
  const { direct, indirect, internal_hosts } = radius;
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          blast radius
        </span>
        <span className="text-[10px] text-zinc-500">
          {internal_hosts.length} internal host
          {internal_hosts.length === 1 ? "" : "s"} potentially affected
        </span>
      </div>
      {direct.length === 0 && indirect.length === 0 && (
        <div className="text-xs text-zinc-600">
          No other entities reachable from this node.
        </div>
      )}
      {internal_hosts.length > 0 && (
        <div className="space-y-1.5">
          {internal_hosts.slice(0, 6).map((h) => (
            <div key={h.key}
                 className={cn("flex items-center justify-between rounded-md border px-2 py-1.5 text-xs",
                   h.observed_path
                     ? "border-red-900/60 bg-red-950/20"
                     : "border-amber-900/50 bg-amber-950/10")}>
              <div className="min-w-0">
                <div className="truncate font-mono text-zinc-200">
                  {h.label}
                </div>
                <div className="truncate text-[10px] text-zinc-500">
                  hop {h.hop} via {h.relation}
                  {h.reasons[0] ? ` - ${h.reasons[0]}` : ""}
                </div>
              </div>
              <span className={cn("shrink-0 text-[9px] font-semibold uppercase",
                h.observed_path ? "text-red-300" : "text-amber-300")}>
                {h.observed_path ? "direct" : "indirect"}
              </span>
            </div>
          ))}
        </div>
      )}
      <div className="mt-2 text-[10px] leading-relaxed text-zinc-600">
        direct = reached via observed relations only; indirect = chain
        includes inferred context. Impact is a correlation estimate, not
        confirmation of compromise.
      </div>
    </div>
  );
}

function EdgePanel({ edge, nodes, onSelectNode, onSelectCampaign }: {
  edge: GraphEdge;
  nodes: GraphNode[];
  onSelectNode: (key: string | null) => void;
  onSelectCampaign: (id: string | null) => void;
}) {
  const src = nodes.find((n) => n.key === edge.src);
  const dst = nodes.find((n) => n.key === edge.dst);
  const phase = PHASE_META[edge.phase] ?? PHASE_META.unknown;
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="mb-3 flex items-center justify-center gap-2 text-sm">
        <button onClick={() => onSelectNode(edge.src)}
                className="font-mono text-emerald-300 hover:underline">
          {src?.label ?? edge.src}
        </button>
        <ArrowRight className="h-3.5 w-3.5 text-zinc-500" />
        <button onClick={() => onSelectNode(edge.dst)}
                className="font-mono text-emerald-300 hover:underline">
          {dst?.label ?? edge.dst}
        </button>
      </div>
      <div className="mb-3 flex flex-wrap items-center justify-center gap-2">
        <Badge variant="outline" className="border-zinc-700 text-zinc-300">
          {edge.relation}
        </Badge>
        {edge.inferred && (
          <Badge variant="outline"
                 className="border-amber-800 bg-amber-950/40 text-amber-300">
            inferred
          </Badge>
        )}
        <Badge variant="outline" style={{ color: phase.color }}
               className="border-zinc-700">
          {phase.label}
        </Badge>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-zinc-400">
        <div>evidence: <span className="tabular-nums text-zinc-200">{edge.evidence_count}</span></div>
        <div>confidence: <span className="tabular-nums text-zinc-200">{edge.confidence}/100</span></div>
        <div>first: {edge.first_seen ? timeAgo(edge.first_seen) : "n/a"}</div>
        <div>last: {edge.last_seen ? timeAgo(edge.last_seen) : "n/a"}</div>
      </div>
      <div className="mt-3">
        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          why are these linked? (checkable reasons)
        </div>
        <ul className="space-y-1 text-xs leading-relaxed text-zinc-300">
          {edge.reasons.map((r, i) => (
            <li key={i} className="flex gap-1.5">
              <span className="text-emerald-500">•</span>
              <span>{r}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-3">
        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          campaigns
        </div>
        <div className="flex flex-wrap gap-1.5">
          {edge.incident_ids.map((id) => (
            <button key={id} onClick={() => onSelectCampaign(id)}
                    className="rounded border border-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-400 hover:border-emerald-800 hover:text-emerald-300">
              {id}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
