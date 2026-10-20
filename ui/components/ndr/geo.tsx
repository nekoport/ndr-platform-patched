"use client";

// Geo / topology visualizations: dotted world map with animated attack arcs,
// and an SVG network topology diagram with animated packet flow.

import type { ExternalEntity, GeoFlow, HostAsset } from "@/lib/ndr/types";
import { fmtBytes, fmtNumber, PanZoomControls, usePanZoom } from "./shared";
import { cn } from "@/lib/utils";
import { Sparkline } from "./charts";
import { useRef } from "react";

// ----------------------------------------------------------------- projection helpers
export const W = 1000;
export const H = 470;
const LAT_TOP = 78;
const LAT_BOT = -67;

export const px = (lon: number) => ((lon + 180) / 360) * W;
export const py = (lat: number) => ((LAT_TOP - lat) / (LAT_TOP - LAT_BOT)) * H;

// coarse continent outlines (lon, lat) — stylized, good enough for dot rendering
const LAND: number[][][] = [
  // North America
  [[-166,68],[-160,70],[-145,70],[-130,70],[-120,72],[-100,73],[-85,70],[-75,63],[-60,60],[-55,52],[-65,47],[-70,44],[-75,40],[-76,35],[-80,31],[-81,26],[-84,30],[-89,29],[-94,29],[-97,26],[-97,22],[-94,18],[-90,16],[-87,13],[-83,9],[-79,8],[-83,8],[-87,12],[-92,15],[-97,17],[-102,19],[-106,24],[-112,28],[-118,33],[-123,39],[-125,44],[-124,48],[-130,54],[-136,58],[-146,60],[-152,58],[-158,56],[-166,60]],
  // Greenland
  [[-52,60],[-43,60],[-30,68],[-22,70],[-20,76],[-25,80],[-38,83],[-50,82],[-58,76],[-55,70]],
  // South America
  [[-79,9],[-72,12],[-63,11],[-56,6],[-50,3],[-44,-2],[-38,-5],[-35,-8],[-37,-14],[-40,-20],[-46,-24],[-51,-30],[-57,-35],[-62,-39],[-65,-45],[-68,-52],[-72,-54],[-73,-48],[-72,-42],[-71,-35],[-70,-28],[-70,-20],[-74,-15],[-77,-8],[-80,-3],[-80,3]],
  // Eurasia
  [[-9,37],[-9,43],[-2,44],[-1,46],[-5,48],[-2,50],[3,51],[7,54],[9,57],[13,55],[18,56],[21,59],[25,58],[28,60],[24,65],[30,70],[42,68],[55,68],[68,69],[80,72],[95,76],[110,76],[125,72],[140,72],[155,70],[170,68],[179,66],[179,62],[163,60],[160,55],[150,53],[143,47],[140,42],[135,38],[128,36],[122,32],[121,26],[115,22],[110,18],[108,12],[104,9],[100,7],[98,10],[95,16],[90,22],[87,21],[84,18],[80,12],[77,7],[73,16],[70,21],[66,25],[60,25],[56,26],[52,28],[48,29],[44,29],[40,32],[35,34],[32,36],[27,37],[23,38],[19,40],[16,42],[13,45],[10,44],[7,43],[3,42],[-2,40]],
  // Africa
  [[-17,14],[-17,21],[-13,27],[-9,32],[-5,35],[0,36],[10,37],[19,32],[29,31],[33,30],[36,24],[38,18],[40,15],[43,11],[48,12],[51,11],[47,4],[42,-1],[40,-10],[36,-18],[33,-26],[28,-33],[22,-35],[17,-33],[14,-27],[12,-18],[13,-10],[9,-2],[8,3],[2,5],[-4,5],[-8,4],[-13,9]],
  // Australia
  [[114,-22],[114,-34],[118,-35],[124,-33],[130,-32],[136,-35],[140,-38],[146,-39],[150,-37],[153,-30],[153,-25],[149,-20],[145,-15],[142,-11],[137,-12],[132,-11],[128,-15],[122,-17],[117,-20]],
  // UK + Ireland
  [[-5,50],[1,51],[0,53],[-2,56],[-4,58],[-6,55],[-5,52]],
  [[-10,52],[-6,52],[-6,54],[-8,55],[-10,54]],
  // Japan
  [[130,31],[132,34],[136,35],[140,37],[141,41],[142,45],[145,44],[141,42],[139,38],[135,34],[131,32]],
  // Indonesia
  [[95,5],[99,3],[103,-2],[106,-5],[103,-6],[98,0],[95,3]],
  [[105,-6],[110,-7],[114,-8],[112,-8.5],[106,-7]],
  [[109,1],[112,3],[116,5],[118,2],[116,-2],[112,-3],[109,-1]],
  [[119,0],[122,1],[124,-2],[121,-4],[119,-2]],
  // Philippines
  [[120,18],[122,16],[124,13],[125,9],[123,8],[121,13],[119,16]],
  // New Guinea
  [[131,-1],[136,-2],[141,-3],[146,-6],[148,-9],[143,-8],[138,-5],[133,-3]],
  // NZ
  [[172,-34],[175,-37],[178,-38],[175,-41],[171,-44],[167,-46],[170,-42],[173,-39]],
  // Madagascar
  [[44,-13],[48,-15],[50,-19],[48,-24],[45,-25],[43,-21],[44,-16]],
  // Iceland
  [[-24,64],[-19,63],[-14,65],[-18,66],[-23,66]],
];

function inPoly(lon: number, lat: number, poly: number[][]): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if (((yi > lat) !== (yj > lat)) && (lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi)) {
      inside = !inside;
    }
  }
  return inside;
}

let landDots: { x: number; y: number }[] | null = null;
export function getLandDots() {
  if (landDots) return landDots;
  const dots: { x: number; y: number }[] = [];
  for (let lat = LAT_TOP; lat >= LAT_BOT; lat -= 3.4) {
    for (let lon = -180; lon <= 180; lon += 3.2) {
      if (LAND.some((p) => inPoly(lon, lat, p))) {
        dots.push({ x: px(lon), y: py(lat) });
      }
    }
  }
  landDots = dots;
  return dots;
}

const HQ = { lon: 106.85, lat: -6.2 }; // Jakarta HQ
export { HQ };

export function arcPath(fromLat: number, fromLon: number, toLat: number,
                        toLon: number): string {
  const x1 = px(fromLon), y1 = py(fromLat);
  const x2 = px(toLon), y2 = py(toLat);
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - Math.abs(x2 - x1) * 0.22 - 24;
  return `M${x1},${y1} Q${mx},${my} ${x2},${y2}`;
}

const REP_COLOR: Record<string, string> = {
  clean: "#38bdf8",
  suspicious: "#fbbf24",
  malicious: "#f87171",
};

export const CATEGORY_COLOR: Record<string, string> = {
  cdn: "#38bdf8", cloud: "#60a5fa", saas: "#a78bfa", dns: "#22d3ee",
  social: "#f472b6", scanning: "#fb923c", tor: "#fbbf24", malicious: "#f87171", other: "#71717a",
};

// ----------------------------------------------------------------- world map
export function ThreatMap({ externals, flows, onSelectExternal }: {
  externals: ExternalEntity[];
  flows: GeoFlow[];
  onSelectExternal?: (e: ExternalEntity) => void;
}) {
  const dots = getLandDots();
  const hq = { x: px(HQ.lon), y: py(HQ.lat) };
  const byIp = new Map(externals.map((e) => [e.ip, e]));
  const visibleFlows = flows.filter((f) => byIp.has(f.external_ip));
  const flaggedFlows = visibleFlows.filter((f) => f.flagged);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const pz = usePanZoom(W, H, svgRef);

  return (
    <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-[#0a0f0d]">
      <svg ref={svgRef} viewBox={`${pz.view.x} ${pz.view.y} ${pz.view.w} ${pz.view.h}`}
           className={cn("w-full touch-none select-none",
                         pz.grabbing ? "cursor-grabbing" : "cursor-grab")}
           {...pz.handlers}>
        <defs>
          <radialGradient id="mapGlow" cx="50%" cy="50%" r="70%">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity={0.06} />
            <stop offset="100%" stopColor="#0a0f0d" stopOpacity={0} />
          </radialGradient>
        </defs>
        <rect width={W} height={H} fill="url(#mapGlow)" />
        {/* land dots */}
        {dots.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r={2} fill="#1f3d33" />
        ))}
        {/* arcs */}
        {visibleFlows.map((f, i) => {
          const e = byIp.get(f.external_ip)!;
          const outbound = f.direction === "outbound";
          const color = REP_COLOR[e.reputation] ?? "#71717a";
          const d = outbound
            ? arcPath(HQ.lat, HQ.lon, e.lat, e.lon)
            : arcPath(e.lat, e.lon, HQ.lat, HQ.lon);
          return (
            <g key={`fl-${i}`}>
              <path d={d} fill="none" stroke={color} strokeOpacity={f.flagged ? 0.65 : 0.28}
                    strokeWidth={f.flagged ? 1.6 : 1}
                    className={f.flagged ? "ndr-arc-flagged" : "ndr-arc"} />
              <circle r={f.flagged ? 3 : 2.2} fill={color}>
                <animateMotion dur={`${6 + (i % 5)}s`} repeatCount="indefinite" path={d} />
                <animate attributeName="opacity" values="0.2;1;0.2" dur={`${6 + (i % 5)}s`} repeatCount="indefinite" />
              </circle>
            </g>
          );
        })}
        {/* HQ node */}
        <g>
          <circle cx={hq.x} cy={hq.y} r={10} fill="#0ea5e9" fillOpacity={0.15} stroke="#38bdf8" strokeWidth={1.5} />
          <circle cx={hq.x} cy={hq.y} r={4} fill="#38bdf8" />
          <circle cx={hq.x} cy={hq.y} r={10} fill="none" stroke="#38bdf8" strokeOpacity={0.5}>
            <animate attributeName="r" values="10;26" dur="2.4s" repeatCount="indefinite" />
            <animate attributeName="stroke-opacity" values="0.5;0" dur="2.4s" repeatCount="indefinite" />
          </circle>
          <text x={hq.x + 16} y={hq.y + 4} fill="#bae6fd" fontSize={13} fontWeight={600}>HQ Jakarta</text>
        </g>
        {/* external nodes */}
        {externals.map((e) => {
          const x = px(e.lon), y = py(e.lat);
          const color = REP_COLOR[e.reputation] ?? "#71717a";
          const malicious = e.reputation === "malicious";
          return (
            <g key={e.ip} className={onSelectExternal ? "cursor-pointer" : ""}
               onClick={() => { if (!pz.didDrag()) onSelectExternal?.(e); }}>
              <title>{`${e.ip} - ${e.asn} - ${e.country}${e.note ? ` - ${e.note}` : ""}`}</title>
              {malicious && (
                <circle cx={x} cy={y} r={7} fill="none" stroke={color} strokeOpacity={0.7} strokeWidth={1}>
                  <animate attributeName="r" values="6;15" dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="stroke-opacity" values="0.7;0" dur="1.8s" repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={x} cy={y} r={malicious ? 4.5 : 3.2} fill={color} fillOpacity={malicious ? 0.95 : 0.7} />
              <circle cx={x} cy={y} r={9} fill="transparent" />
            </g>
          );
        })}
      </svg>
      {/* legend */}
      <div className="absolute bottom-2 left-3 flex flex-wrap items-center gap-3 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-400" />clean</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-400" />suspicious</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-400" />malicious</span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0.5 w-5 bg-red-400/70" />attack path ({flaggedFlows.length})
        </span>
        <span className="text-zinc-600">drag to pan &middot; scroll to zoom</span>
      </div>
      <div className="absolute bottom-2 right-3 rounded bg-zinc-950/70 px-2 py-1 text-[10px] text-zinc-400">
        equirectangular - {externals.length} external endpoints - {fmtNumber(flows.reduce((s, f) => s + f.conns, 0))} conns/24h
      </div>
      <PanZoomControls pz={pz} />
    </div>
  );
}

// ----------------------------------------------------------------- topology diagram
const ZONE_META: Record<HostAsset["zone"], { label: string; color: string }> = {
  dmz: { label: "DMZ", color: "#fb923c" },
  servers: { label: "Servers", color: "#38bdf8" },
  workstations: { label: "Workstations", color: "#60a5fa" },
  iot: { label: "IoT / OT", color: "#f472b6" },
  management: { label: "Management", color: "#a78bfa" },
};

export function NetworkTopology({ hosts, selectedIp, onSelectHost }: {
  hosts: HostAsset[];
  selectedIp?: string | null;
  onSelectHost?: (h: HostAsset) => void;
}) {
  const zones: HostAsset["zone"][] = ["dmz", "servers", "workstations", "iot", "management"];
  const boxW = 182;
  const gap = 12;
  const startX = (980 - (5 * boxW + 4 * gap)) / 2;
  const switchPt = { x: 490, y: 285 };
  const sensorPt = { x: 490, y: 165 };
  const internetPt = { x: 490, y: 58 };
  const atRisk = hosts.filter((h) => h.status === "at_risk").length;
  const watch = hosts.filter((h) => h.status === "watch").length;

  const zoneBoxTop = (i: number) => ({ x: startX + i * (boxW + gap), y: 385 });

  return (
    <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-[#0a0f0d]">
      <svg viewBox="0 0 980 640" className="w-full">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#3f6f5f" />
          </marker>
        </defs>

        {/* internet */}
        <g>
          <ellipse cx={internetPt.x} cy={internetPt.y} rx={120} ry={34} fill="#101c17" stroke="#274036" strokeWidth={1.4} />
          <text x={internetPt.x} y={internetPt.y - 2} textAnchor="middle" fill="#9ca3af" fontSize={13} fontWeight={700}>INTERNET</text>
          <text x={internetPt.x} y={internetPt.y + 14} textAnchor="middle" fill="#5f7466" fontSize={10}>upstream - 16 external endpoints</text>
        </g>
        {/* external risk chips */}
        {[{ ip: "91.245.77.10", c: "#f87171", t: "C2" }, { ip: "203.0.113.25", c: "#f87171", t: "SQLi src" },
          { ip: "198.51.100.7", c: "#fbbf24", t: "scanner" }, { ip: "45.155.205.233", c: "#f87171", t: "bruteforce" }].map((e, i) => {
          const cx = i < 2 ? 250 : 730;
          const cy = 38 + (i % 2) * 30;
          return (
            <g key={e.ip}>
              <line x1={cx + (i < 2 ? 105 : -105) * 0.4} y1={cy} x2={i < 2 ? internetPt.x - 118 : internetPt.x + 118}
                    y2={internetPt.y} stroke={e.c} strokeOpacity={0.3} strokeDasharray="3 4" />
              <rect x={cx} y={cy - 10} rx={6} width={110} height={20} fill="#141018" stroke={e.c} strokeOpacity={0.5} />
              <circle cx={cx + 10} cy={cy} r={3} fill={e.c} />
              <text x={cx + 19} y={cy + 3.5} fill="#d4d4d8" fontSize={9.5} fontFamily="monospace">{e.ip}</text>
              <text x={cx + 19} y={cy + 13} fill={e.c} fontSize={7.5}>{e.t}</text>
            </g>
          );
        })}

        {/* internet -> sensor */}
        <line x1={internetPt.x} y1={internetPt.y + 34} x2={sensorPt.x} y2={sensorPt.y - 26}
              stroke="#3f6f5f" strokeWidth={1.6} markerEnd="url(#arrow)" />
        <circle r={3.2} fill="#38bdf8">
          <animateMotion dur="2.2s" repeatCount="indefinite"
                         path={`M${internetPt.x},${internetPt.y + 34} L${sensorPt.x},${sensorPt.y - 26}`} />
        </circle>

        {/* sensor */}
        <g>
          <rect x={sensorPt.x - 105} y={sensorPt.y - 26} rx={10} width={210} height={52}
                fill="#0c2d44" stroke="#0ea5e9" strokeWidth={1.6} />
          <text x={sensorPt.x} y={sensorPt.y - 5} textAnchor="middle" fill="#7dd3fc" fontSize={13} fontWeight={700}>ndr-sensor-01</text>
          <text x={sensorPt.x} y={sensorPt.y + 12} textAnchor="middle" fill="#5f7466" fontSize={9.5}>Zeek - Suricata - Arkime - tap: SPAN core-sw</text>
          <circle cx={sensorPt.x + 96} cy={sensorPt.y - 17} r={4} fill="#38bdf8">
            <animate attributeName="opacity" values="1;0.3;1" dur="1.6s" repeatCount="indefinite" />
          </circle>
        </g>

        {/* sensor -> switch */}
        <line x1={sensorPt.x} y1={sensorPt.y + 26} x2={switchPt.x} y2={switchPt.y - 20}
              stroke="#3f6f5f" strokeWidth={1.6} markerEnd="url(#arrow)" />
        <circle r={2.6} fill="#60a5fa">
          <animateMotion dur="1.8s" repeatCount="indefinite"
                         path={`M${sensorPt.x},${sensorPt.y + 26} L${switchPt.x},${switchPt.y - 20}`} />
        </circle>

        {/* switch */}
        <g>
          <rect x={switchPt.x - 80} y={switchPt.y - 20} rx={8} width={160} height={40}
                fill="#101a22" stroke="#274036" strokeWidth={1.4} />
          <text x={switchPt.x} y={switchPt.y + 5} textAnchor="middle" fill="#9ca3af" fontSize={12} fontWeight={600}>core-sw-01</text>
        </g>

        {/* switch -> zones */}
        {zones.map((z, i) => {
          const p = zoneBoxTop(i);
          const cx = p.x + boxW / 2;
          const meta = ZONE_META[z];
          return (
            <g key={`edge-${z}`}>
              <line x1={switchPt.x} y1={switchPt.y + 20} x2={cx} y2={p.y - 4}
                    stroke="#274036" strokeWidth={1.2} markerEnd="url(#arrow)" />
              <circle r={2.4} fill={meta.color} fillOpacity={0.85}>
                <animateMotion dur={`${2 + i * 0.4}s`} repeatCount="indefinite"
                               path={`M${switchPt.x},${switchPt.y + 20} L${cx},${p.y - 4}`} />
              </circle>
            </g>
          );
        })}

        {/* zone boxes + hosts */}
        {zones.map((z, i) => {
          const p = zoneBoxTop(i);
          const meta = ZONE_META[z];
          const zh = hosts.filter((h) => h.zone === z);
          return (
            <g key={`zone-${z}`}>
              <rect x={p.x} y={p.y} rx={10} width={boxW} height={230} fill="#0c1310" stroke={meta.color} strokeOpacity={0.45} strokeWidth={1.2} />
              <rect x={p.x} y={p.y} rx={10} width={boxW} height={26} fill={meta.color} fillOpacity={0.12} />
              <text x={p.x + 10} y={p.y + 17} fill={meta.color} fontSize={11} fontWeight={700}>{meta.label.toUpperCase()}</text>
              <text x={p.x + boxW - 8} y={p.y + 17} textAnchor="end" fill="#5f7466" fontSize={9}>{zh.length} hosts</text>
              {zh.map((h, hi) => {
                const col = hi % 2, row = Math.floor(hi / 2);
                const cw = (boxW - 14) / 2;
                const hx = p.x + 7 + col * (cw + 4);
                const hy = p.y + 34 + row * 32;
                const selected = selectedIp === h.ip;
                const stroke =
                  h.status === "at_risk" ? "#f87171" : h.status === "watch" ? "#fbbf24" : "#2a4a3c";
                return (
                  <g key={h.ip} className={onSelectHost ? "cursor-pointer" : ""}
                     onClick={() => onSelectHost?.(h)}>
                    <title>{`${h.hostname} (${h.ip}) - risk ${h.risk_score}`}</title>
                    <rect x={hx} y={hy} rx={5} width={cw} height={27}
                          fill={selected ? "#12251d" : "#0f1613"}
                          stroke={selected ? "#38bdf8" : stroke} strokeWidth={selected ? 1.6 : 1} />
                    <circle cx={hx + 8} cy={hy + 13.5} r={2.6}
                            fill={h.status === "at_risk" ? "#f87171" : h.status === "watch" ? "#fbbf24" : "#38bdf8"}>
                      {h.status === "at_risk" && (
                        <animate attributeName="opacity" values="1;0.25;1" dur="1.4s" repeatCount="indefinite" />
                      )}
                    </circle>
                    <text x={hx + 15} y={hy + 11} fill="#d4d4d8" fontSize={8.6} fontFamily="monospace">{h.hostname}</text>
                    <text x={hx + 15} y={hy + 21} fill="#5f7466" fontSize={7.6} fontFamily="monospace">{h.ip}</text>
                  </g>
                );
              })}
            </g>
          );
        })}
      </svg>
      <div className="absolute bottom-2 left-3 flex items-center gap-3 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-400" />healthy</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-400" />watch ({watch})</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-400" />at risk ({atRisk})</span>
        <span>click a host for detail</span>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- host detail card (used by topology + assets)
export function HostRiskBadge({ score }: { score: number }) {
  const color = score >= 70 ? "text-red-300 border-red-800 bg-red-950/60"
    : score >= 45 ? "text-amber-300 border-amber-800 bg-amber-950/60"
    : "text-emerald-300 border-emerald-800 bg-emerald-950/60";
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold tabular-nums", color)}>
      risk {score}
    </span>
  );
}

export function HostDetailContent({ host, flows, externals }: {
  host: HostAsset; flows: GeoFlow[]; externals: ExternalEntity[];
}) {
  const byIp = new Map(externals.map((e) => [e.ip, e]));
  const hostFlows = flows.filter((f) => f.internal_ip === host.ip);
  const maxBytes = Math.max(...hostFlows.map((f) => f.bytes), 1);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div><div className="text-xs text-zinc-500">IP address</div><div className="font-mono text-zinc-200">{host.ip}</div></div>
        <div><div className="text-xs text-zinc-500">Zone</div><div className="capitalize text-zinc-200">{host.zone}</div></div>
        <div className="col-span-2"><div className="text-xs text-zinc-500">Role</div><div className="text-zinc-200">{host.role}</div></div>
        <div><div className="text-xs text-zinc-500">OS</div><div className="text-zinc-200">{host.os}</div></div>
        <div><div className="text-xs text-zinc-500">Criticality</div><div className="capitalize text-zinc-200">{host.criticality}</div></div>
        <div><div className="text-xs text-zinc-500">Open ports</div><div className="font-mono text-zinc-200">{host.open_ports.length ? host.open_ports.join(", ") : "-"}</div></div>
        <div><div className="text-xs text-zinc-500">Alerts (24h)</div><div className="tabular-nums text-zinc-200">{host.alerts_24h}</div></div>
        <div><div className="text-xs text-zinc-500">Traffic 24h</div><div className="tabular-nums text-zinc-200">in {fmtBytes(host.bytes_in)} / out {fmtBytes(host.bytes_out)}</div></div>
        <div><div className="text-xs text-zinc-500">Connections</div><div className="tabular-nums text-zinc-200">{fmtNumber(host.conns_24h)}</div></div>
      </div>

      <div>
        <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-zinc-500">Traffic last 24h</div>
        <SparklineBox data={host.traffic_24h} />
      </div>

      {host.last_alert_title && (
        <div className="rounded-lg border border-red-900/60 bg-red-950/30 p-3">
          <div className="text-xs font-medium text-red-300">Latest alert on this host</div>
          <div className="mt-0.5 text-sm text-zinc-200">{host.last_alert_title}</div>
        </div>
      )}

      {!!hostFlows.length && (
        <div>
          <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-zinc-500">External communication</div>
          <div className="space-y-2">
            {hostFlows.map((f, i) => {
              const e = byIp.get(f.external_ip);
              const color = e ? REP_COLOR[e.reputation] : "#71717a";
              return (
                <div key={i} className="rounded-md border border-zinc-800 bg-zinc-900/70 p-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-zinc-300">{f.external_ip}</span>
                    <span className="tabular-nums text-zinc-400">{fmtBytes(f.bytes)} - {fmtNumber(f.conns)} conns</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <MiniBar2 value={f.bytes} max={maxBytes} color={color} />
                    <span className="w-24 shrink-0 truncate text-right text-[10px]" style={{ color }}>
                      {e ? `${e.country_code} ${e.category}` : "unknown"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function SparklineBox({ data }: { data: number[] }) {
  return <Sparkline data={data} color="#38bdf8" height={56} />;
}
function MiniBar2({ value, max, color }: { value: number; max: number; color: string }) {
  return (
    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
      <div className="h-full rounded-full" style={{ width: `${Math.max(4, (value / (max || 1)) * 100)}%`, background: color }} />
    </div>
  );
}
