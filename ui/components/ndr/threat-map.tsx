"use client";

// Threat Map view v2 (Phase 5).
//
// Two linked visualizations sharing ONE correlation dataset:
//   A. Attack Relationship Graph - the campaign investigation
//      centerpiece (logical relations between IPs, hosts, domains,
//      IOCs, campaigns - every edge carries a checkable reason)
//   B. Geographic Threat Map - supporting view for the geographic
//      spread of external <-> monitored-network communication
//
// Cross-navigation: clicking an IP on the geo map opens the same
// `ip:<address>` node in the relationship graph, and vice versa.
// GeoIP is treated as an approximate network location; internal IPs
// and addresses without geo data are LISTED, never plotted.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDownLeft, ArrowUpRight, ChevronRight, Globe2, Info, Loader2,
  Maximize2, Minimize2, ShieldAlert, Table2, Waypoints,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader,
         TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  VizPanel,
} from "./charts";
import {
  arcPath, getLandDots, H, HQ, px, py, W,
} from "./geo";
import {
  PHASE_META,
} from "./attack-graph";
import {
  Paginator, fmtBytes, fmtNumber, PanZoomControls, timeAgo, usePanZoom,
} from "./shared";
import {
  getAlertRelationship, getEntityPivot, getGeoMap, getIncidentDetail,
  getRelationshipGraph,
} from "@/lib/ndr/api";
import type {
  AlertRelationship, EntityPivot, EvidenceItem, GeoBundle, GeoFlowV2,
  RelationshipGraph,
} from "@/lib/ndr/types";
import { RelationshipGraphView } from "./relationship-graph";

const FLOW_COLOR = {
  ioc: "#f87171",      // TI-matched traffic
  alert: "#fbbf24",    // alert-bearing traffic
  inbound: "#fb923c",
  outbound: "#38bdf8",
};

function flowColor(f: GeoFlowV2): string {
  if (f.ioc_hits > 0) return FLOW_COLOR.ioc;
  if (f.alert_hits > 0) return FLOW_COLOR.alert;
  return f.direction === "inbound" ? FLOW_COLOR.inbound
    : FLOW_COLOR.outbound;
}

export function ThreatMapView({ alertFocus, onOpenIncident }: {
  /** v0.12.9: cross-navigation from Alert Center/DGA - render the FOCUSED
   * attack relationship of THIS alert only (incident subgraph or honest
   * single-alert graph). Replaces the old IP-focus jump that landed on
   * the heavy global/geographic view. */
  alertFocus?: { alertId: string; nonce: number } | null;
  /** Jump into Incidents focused on a linked incident (focus banner). */
  onOpenIncident?: (incidentId: string) => void;
}) {
  const [tab, setTab] = useState<"graph" | "geo">("graph");
  const [graph, setGraph] = useState<RelationshipGraph | null>(null);
  const [geo, setGeo] = useState<GeoBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // v0.12.9 focused-alert relationship state
  const [alertRel, setAlertRel] = useState<AlertRelationship | null>(null);
  const [alertRelLoading, setAlertRelLoading] = useState(false);
  const [alertRelError, setAlertRelError] = useState<string | null>(null);
  const [focusDismissed, setFocusDismissed] = useState(false);

  // relationship graph state
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(
    null);
  const [tiOverlay, setTiOverlay] = useState(true);
  const [pivot, setPivot] = useState<EntityPivot | null>(null);
  const [pivotLoading, setPivotLoading] = useState(false);
  const [campaignTimeline, setCampaignTimeline] = useState<
    { title: string; items: EvidenceItem[] } | null
  >(null);

  // geographic state
  const [geoSelected, setGeoSelected] = useState<string | null>(null);

  // v0.12.9: the GLOBAL graph/geo load is heavy (merged campaign graph +
  // geo aggregation). When jumping from an alert we SKIP it entirely and
  // load only the tiny focused relationship payload; the global view is
  // fetched lazily when the analyst explicitly opens it.
  const loadGlobal = useCallback(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const [g, geoBundle] = await Promise.all([
          getRelationshipGraph(),
          getGeoMap(),
        ]);
        if (!alive) return;
        setGraph(g);
        setGeo(geoBundle);
      } catch (e) {
        if (alive) setError(String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (alertFocus) {
      // focused mode: global data not needed yet
      setLoading(false);
      return;
    }
    return loadGlobal();
  }, [alertFocus, loadGlobal]);

  // entity pivot follows node selection
  useEffect(() => {
    if (!selectedNode) {
      setPivot(null);
      return;
    }
    let alive = true;
    setPivotLoading(true);
    getEntityPivot(selectedNode)
      .then((p) => { if (alive) setPivot(p); })
      .catch(() => { if (alive) setPivot(null); })
      .finally(() => { if (alive) setPivotLoading(false); });
    return () => { alive = false; };
  }, [selectedNode]);

  // campaign timeline follows campaign selection
  useEffect(() => {
    if (!selectedCampaign) {
      setCampaignTimeline(null);
      return;
    }
    let alive = true;
    getIncidentDetail(selectedCampaign)
      .then((d) => {
        if (!alive) return;
        const items = [...d.evidence].sort((a, b) =>
          (a.ts ?? "").localeCompare(b.ts ?? ""));
        setCampaignTimeline({ title: d.title, items });
      })
      .catch(() => { if (alive) setCampaignTimeline(null); });
    return () => { alive = false; };
  }, [selectedCampaign]);

  // ---- cross-navigation ---------------------------------------------
  const openIpInGraph = useCallback((ip: string) => {
    const key = `ip:${ip}`;
    if (graph?.nodes.some((n) => n.key === key)) {
      setTab("graph");
      setSelectedEdge(null);
      setSelectedNode(key);
    }
  }, [graph]);

  const openIpOnGeoMap = useCallback((ip: string) => {
    setTab("geo");
    setGeoSelected(ip);
  }, []);

  // cross-navigation from Alert Center: fetch the FOCUSED relationship
  // for this alert (v0.12.9) - never the global campaign graph
  useEffect(() => {
    if (!alertFocus?.alertId) return;
    let alive = true;
    setFocusDismissed(false);
    setAlertRel(null);
    setAlertRelError(null);
    setAlertRelLoading(true);
    setSelectedEdge(null);
    setSelectedCampaign(null);
    getAlertRelationship(alertFocus.alertId)
      .then((rel) => {
        if (!alive) return;
        setAlertRel(rel);
        const startIp = rel.alert.source_ip ?? rel.alert.destination_ip;
        setSelectedNode(startIp ? `ip:${startIp}` : null);
      })
      .catch((e) => { if (alive) setAlertRelError(String(e)); })
      .finally(() => { if (alive) setAlertRelLoading(false); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertFocus?.alertId, alertFocus?.nonce]);

  const inFocusMode = !!alertFocus && !focusDismissed;

  if (loading && !inFocusMode) {
    return (
      <div className="flex h-64 items-center justify-center gap-2 text-sm text-zinc-500">
        <Loader2 className="h-4 w-4 animate-spin text-emerald-500" />
        Building correlation view...
      </div>
    );
  }

  // ---------------- focused alert relationship view (v0.12.9) ----------
  if (inFocusMode) {
    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-sky-900/60 bg-sky-950/25 p-3">
          {alertRelLoading && (
            <div className="flex items-center gap-2 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
              Building focused relationship for this alert...
            </div>
          )}
          {!alertRelLoading && alertRelError && (
            <div className="text-sm text-red-300">
              Failed to load the focused relationship: {alertRelError}
            </div>
          )}
          {!alertRelLoading && !alertRelError && alertRel && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0 text-sky-400" />
                <span className="text-sm font-medium text-zinc-100">
                  {alertRel.alert.title ?? alertRel.alert.alert_id}
                </span>
                {alertRel.alert.severity && (
                  <Badge variant="outline" className="text-[10px] border-zinc-700 text-zinc-300">
                    {alertRel.alert.severity}
                  </Badge>
                )}
                {alertRel.alert.alert_type && (
                  <Badge variant="outline" className="font-mono text-[10px] border-zinc-800 text-zinc-400">
                    {alertRel.alert.alert_type}
                  </Badge>
                )}
                <Badge variant="outline" className={
                  alertRel.basis === "incident"
                    ? "text-[10px] border-violet-900 bg-violet-950/40 text-violet-300"
                    : alertRel.basis === "alert"
                      ? "text-[10px] border-sky-900 bg-sky-950/40 text-sky-300"
                      : "text-[10px] border-zinc-800 text-zinc-400"}>
                  basis: {alertRel.basis}
                </Badge>
                <Button size="sm" variant="outline"
                        className="ml-auto h-7 border-zinc-700 text-[11px] text-zinc-300 hover:bg-zinc-800"
                        onClick={() => {
                          setFocusDismissed(true);
                          setAlertRel(null);
                          if (!graph || !geo) loadGlobal();
                        }}>
                  <Waypoints className="mr-1 h-3 w-3" /> Show full threat map
                </Button>
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-400">
                {alertRel.note}
              </p>
              {alertRel.incidents.length > 0 && onOpenIncident && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {alertRel.incidents.map((r) => (
                    <button key={r.incident_id}
                            onClick={() => onOpenIncident(r.incident_id)}
                            className="rounded border border-violet-900 bg-violet-950/30 px-2 py-1 text-[11px] text-violet-300 hover:bg-violet-950/60">
                      open incident: {r.title} <ChevronRight className="inline h-3 w-3" />
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
        {!alertRelLoading && !alertRelError && alertRel &&
          (alertRel.graph.nodes.length === 0 ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-8 text-center text-sm text-zinc-500">
              Nothing to draw - this alert carries no source/destination
              entities. Check its evidence and "Verify in Event Search"
              from the Alert Center detail instead.
            </div>
          ) : (
            <RelationshipGraphView
              graph={alertRel.graph}
              selectedNode={selectedNode}
              onSelectNode={(k) => { setSelectedNode(k); setSelectedEdge(null); }}
              selectedEdge={selectedEdge}
              onSelectEdge={(k) => { setSelectedEdge(k); if (k) setSelectedNode(null); }}
              selectedCampaign={selectedCampaign}
              onSelectCampaign={setSelectedCampaign}
              tiOverlay={tiOverlay}
              pivot={pivot}
              pivotLoading={pivotLoading} />
          ))}
      </div>
    );
  }

  // ---------------- global view (no alert focus) -----------------------
  if (error || !graph || !geo) {
    return (
      <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-6 text-sm text-red-300">
        Failed to load threat map data: {error ?? "empty response"}
      </div>
    );
  }

  const tiCount = graph.nodes.filter((n) => n.ti_match).length;

  return (
    <div className="space-y-4">
      {/* header stats */}
      <div className="grid gap-2 sm:grid-cols-4">
        <MiniStat icon={<Waypoints className="h-4 w-4" />}
                  label="Entities linked"
                  value={String(graph.meta.node_count)}
                  sub={`${graph.meta.edge_count} evidence-backed relations`} />
        <MiniStat icon={<ShieldAlert className="h-4 w-4" />}
                  label="Campaigns"
                  value={String(graph.meta.campaign_count)}
                  sub="reconstructed attack chains" tone="alert" />
        <MiniStat icon={<Info className="h-4 w-4" />}
                  label="TI-matched entities"
                  value={String(tiCount)}
                  sub="threat intelligence overlay" />
        <MiniStat icon={<Globe2 className="h-4 w-4" />}
                  label="Geo flows (24h)"
                  value={String(geo.flows.length)}
                  sub={`${geo.unmapped.length} unmapped - listed, not plotted`} />
      </div>

      {/* tabs */}
      <div className="flex flex-wrap items-center gap-2">
        <TabButton active={tab === "graph"}
                   onClick={() => setTab("graph")}
                   icon={<Waypoints className="h-4 w-4" />}
                   label="Attack Relationships"
                   sub="campaign investigation" />
        <TabButton active={tab === "geo"}
                   onClick={() => setTab("geo")}
                   icon={<Globe2 className="h-4 w-4" />}
                   label="Geographic Map"
                   sub="external spread" />
        <div className="ml-auto">
          {tab === "graph" && (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-zinc-400">
              <input type="checkbox" checked={tiOverlay}
                     onChange={(e) => setTiOverlay(e.target.checked)}
                     className="accent-purple-500" />
              TI overlay
            </label>
          )}
        </div>
      </div>

      {tab === "graph" && (
        <>
          <RelationshipGraphView
            graph={graph}
            selectedNode={selectedNode}
            onSelectNode={(k) => { setSelectedNode(k); setSelectedEdge(null); }}
            selectedEdge={selectedEdge}
            onSelectEdge={(k) => { setSelectedEdge(k); if (k) setSelectedNode(null); }}
            selectedCampaign={selectedCampaign}
            onSelectCampaign={setSelectedCampaign}
            tiOverlay={tiOverlay}
            pivot={pivot}
            pivotLoading={pivotLoading}
            onOpenOnGeoMap={openIpOnGeoMap} />
          {campaignTimeline && (
            <CampaignTimeline title={campaignTimeline.title}
                              items={campaignTimeline.items} />
          )}
        </>
      )}

      {tab === "geo" && (
        <GeoTab geo={geo} graph={graph} selectedIp={geoSelected}
                onSelectIp={setGeoSelected}
                onOpenInGraph={openIpInGraph} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- geo tab
// v0.12.8 REDESIGN - reference: Kaspersky Cyberthreat Live Map, Fortinet
// Outbreak Threat Map, Zscaler ThreatLabz dashboard. The old geo view drew
// one arc PER FLOW (up to 120 arcs converging on a single HQ point) which
// read as an unreadable hairball. Industry threat maps aggregate: ONE arc
// per ORIGIN COUNTRY (thickness = aggregated connections), a ranked
// country list on the side, endpoint detail one click deeper. We follow
// the same structure - country-aggregated arcs, ranked panels, and the
// per-flow matrix stays available (paginated) below the map.

interface CountryAgg {
  country: string;
  conns: number;
  bytes: number;
  ioc: number;
  alerts: number;
  inbound: number;
  outbound: number;
  lat: number;
  lon: number;
  endpoints: GeoFlowV2[];
}

function countryWeight(c: CountryAgg): number {
  return c.ioc * 5 + c.alerts * 2 + c.conns;
}

function GeoTab({ geo, graph, selectedIp, onSelectIp, onOpenInGraph }: {
  geo: GeoBundle;
  graph: RelationshipGraph;
  selectedIp: string | null;
  onSelectIp: (ip: string | null) => void;
  onOpenInGraph: (ip: string) => void;
}) {
  // v0.12.8: country selection filters the endpoint panel
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);

  const countries = useMemo<CountryAgg[]>(() => {
    const m = new Map<string, CountryAgg>();
    geo.flows.forEach((f) => {
      const g = f.geo;
      if (!g) return;
      let c = m.get(g.country);
      if (!c) {
        c = { country: g.country, conns: 0, bytes: 0, ioc: 0, alerts: 0,
              inbound: 0, outbound: 0, lat: 0, lon: 0, endpoints: [] };
        m.set(g.country, c);
      }
      c.conns += f.conns;
      c.bytes += f.bytes;
      c.ioc += f.ioc_hits;
      c.alerts += f.alert_hits;
      if (f.direction === "inbound") c.inbound += f.conns;
      else c.outbound += f.conns;
      c.lat += g.lat * f.conns;
      c.lon += g.lon * f.conns;
      c.endpoints.push(f);
    });
    return Array.from(m.values())
      .map((c) => ({ ...c, lat: c.lat / c.conns, lon: c.lon / c.conns }))
      .sort((a, b) => countryWeight(b) - countryWeight(a));
  }, [geo.flows]);

  const byExternal = useMemo(() => {
    const m = new Map<string, GeoFlowV2[]>();
    geo.flows.forEach((f) => {
      const list = m.get(f.external_ip) ?? [];
      list.push(f);
      m.set(f.external_ip, list);
    });
    return m;
  }, [geo.flows]);

  const selectedFlows = selectedIp ? byExternal.get(selectedIp) ?? [] : [];
  const selectedAgg = useMemo(() => {
    if (!selectedIp) return null;
    const flows = selectedFlows;
    const node = graph.nodes.find((n) => n.key === `ip:${selectedIp}`);
    return {
      ip: selectedIp,
      country: flows.find((f) => f.geo)?.geo?.country ?? null,
      asn: flows.find((f) => f.geo)?.geo?.asn_org ?? null,
      conns: flows.reduce((s, f) => s + f.conns, 0),
      bytes: flows.reduce((s, f) => s + f.bytes, 0),
      ioc: flows.reduce((s, f) => s + f.ioc_hits, 0),
      alerts: flows.reduce((s, f) => s + f.alert_hits, 0),
      incidentIds: node?.incident_ids ?? [],
      inGraph: !!node,
      unmappedReason: geo.unmapped.find((u) => u.ip === selectedIp)?.reason
        ?? null,
    };
  }, [selectedIp, selectedFlows, graph.nodes, geo.unmapped]);

  // endpoints shown in the right panel: filtered by selected country,
  // ranked by threat signal then volume (cap 25)
  const endpointRows = useMemo(() => {
    const flows = selectedCountry
      ? geo.flows.filter((f) => f.geo?.country === selectedCountry)
      : geo.flows;
    const m = new Map<string, {
      ip: string; country: string | null; conns: number;
      bytes: number; ioc: number; alerts: number;
    }>();
    flows.forEach((f) => {
      const cur = m.get(f.external_ip) ?? {
        ip: f.external_ip, country: f.geo?.country ?? null,
        conns: 0, bytes: 0, ioc: 0, alerts: 0,
      };
      cur.conns += f.conns;
      cur.bytes += f.bytes;
      cur.ioc += f.ioc_hits;
      cur.alerts += f.alert_hits;
      m.set(f.external_ip, cur);
    });
    return Array.from(m.values())
      .sort((a, b) => ((b.ioc - a.ioc) || (b.alerts - a.alerts)
                       || (b.conns - a.conns)))
      .slice(0, 25);
  }, [geo.flows, selectedCountry]);

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[236px_1fr_300px]">
        {/* left: ranked origin countries (reference: Fortinet "Countries
            last 24 hours" panel) */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              Origin countries
            </span>
            {selectedCountry && (
              <button className="text-[10px] text-zinc-500 hover:text-zinc-300"
                      onClick={() => setSelectedCountry(null)}>
                clear
              </button>
            )}
          </div>
          <div className="space-y-1">
            {countries.slice(0, 18).map((c, i) => {
              const active = selectedCountry === c.country;
              return (
                <button key={c.country}
                        onClick={() => setSelectedCountry(active ? null : c.country)}
                        className={cn("flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                          active
                            ? "border-sky-700 bg-sky-950/40"
                            : "border-transparent hover:bg-zinc-800/60")}>
                  <span className="w-4 shrink-0 text-right font-mono text-[10px] text-zinc-600">{i + 1}</span>
                  <span className="min-w-0 flex-1 truncate text-zinc-300" title={c.country}>
                    {c.country}
                  </span>
                  {c.ioc > 0 && <span className="h-2 w-2 shrink-0 rounded-full bg-red-400" title={`${c.ioc} IOC hits`} />}
                  {c.ioc === 0 && c.alerts > 0 && (
                    <span className="h-2 w-2 shrink-0 rounded-full bg-amber-400" title={`${c.alerts} alert-bearing flows`} />
                  )}
                  <span className="shrink-0 tabular-nums text-[10px] text-zinc-500">
                    {fmtNumber(c.conns)}
                  </span>
                </button>
              );
            })}
            {!countries.length && (
              <p className="text-xs text-zinc-600">No geo-mapped traffic in the last 24h.</p>
            )}
          </div>
          {!!geo.unmapped.length && (
            <p className="mt-2 border-t border-zinc-800/70 pt-2 text-[10px] leading-relaxed text-zinc-600">
              {geo.unmapped.length} endpoint{geo.unmapped.length === 1 ? "" : "s"} without
              GeoIP data are listed, never plotted (see the list on the right).
            </p>
          )}
        </div>

        {/* center: the map */}
        <GeoMapV3 geo={geo} countries={countries}
                  selectedCountry={selectedCountry}
                  onSelectCountry={setSelectedCountry} />
        {/* center bottom: selected endpoint detail */}
        {selectedAgg && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-4 xl:col-start-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold text-zinc-100">
                {selectedAgg.ip}
              </span>
              {selectedAgg.country && (
                <Badge variant="outline" className="border-zinc-700 text-zinc-400">
                  {selectedAgg.country}
                </Badge>
              )}
              {selectedAgg.asn && (
                <Badge variant="outline" className="border-zinc-700 text-zinc-400">
                  {selectedAgg.asn}
                </Badge>
              )}
              {selectedAgg.ioc > 0 && (
                <Badge variant="outline"
                       className="border-red-800 bg-red-950/50 text-red-300">
                  {selectedAgg.ioc} IOC hits
                </Badge>
              )}
              {selectedAgg.alerts > 0 && (
                <Badge variant="outline"
                       className="border-amber-800 bg-amber-950/50 text-amber-300">
                  {selectedAgg.alerts} alert-bearing flows
                </Badge>
              )}
              {selectedAgg.unmappedReason && (
                <Badge variant="outline"
                       className="border-zinc-700 text-zinc-500">
                  not plotted - {selectedAgg.unmappedReason}
                </Badge>
              )}
              <button className="ml-auto text-xs text-zinc-500 hover:text-zinc-300"
                      onClick={() => onSelectIp(null)}>
                close
              </button>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-zinc-400">
              <span>frequency: <span className="tabular-nums text-zinc-200">{fmtNumber(selectedAgg.conns)}</span> conns / 24h</span>
              <span>volume: <span className="tabular-nums text-zinc-200">{fmtBytes(selectedAgg.bytes)}</span></span>
              <span>campaigns: {selectedAgg.incidentIds.length
                ? selectedAgg.incidentIds.map((id) => (
                  <Badge key={id} variant="outline"
                         className="ml-1 border-zinc-800 font-mono text-[10px] text-zinc-400">
                    {id}
                  </Badge>
                ))
                : <span className="text-zinc-600">no reconstructed campaign covers this IP yet</span>}
              </span>
            </div>
            <div className="mt-3 space-y-1.5">
              {selectedFlows.map((f, i) => (
                <div key={i}
                     className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-1.5 text-xs">
                  <span className="font-mono text-zinc-300">
                    {f.direction === "outbound"
                      ? `${f.internal_ip} -> ${f.external_ip}`
                      : `${f.external_ip} -> ${f.internal_ip}`}
                  </span>
                  <span className="flex items-center gap-3 text-zinc-500">
                    <span>{fmtBytes(f.bytes)}</span>
                    <span className="tabular-nums">{fmtNumber(f.conns)} conns</span>
                    {f.ioc_hits > 0 && (
                      <span className="font-semibold text-red-400">
                        {f.ioc_hits} IOC
                      </span>
                    )}
                    {f.last_seen && <span>{timeAgo(f.last_seen)}</span>}
                  </span>
                </div>
              ))}
              {!selectedFlows.length && (
                <p className="text-xs text-zinc-500">
                  This address has no geo-mapped flows; see the unmapped
                  list on the right.
                </p>
              )}
            </div>
            {selectedAgg.inGraph && (
              <Button size="sm" variant="outline"
                      className="mt-3 h-7 border-emerald-900 text-xs text-emerald-300 hover:bg-emerald-950/40"
                      onClick={() => onOpenInGraph(selectedAgg.ip)}>
                <Waypoints className="mr-1.5 h-3 w-3" />
                Open in attack relationship graph
              </Button>
            )}
          </div>
        )}

        {/* right: external endpoints (filtered by selected country) */}
        <div className="space-y-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                External endpoints
              </span>
              <span className="text-[10px] text-zinc-600">
                {selectedCountry ? selectedCountry : "all countries"}
              </span>
            </div>
            <p className="mb-2 text-[10px] text-zinc-600">
              ranked by TI / alert signal, then volume - click for detail
            </p>
            <div className="space-y-1">
              {endpointRows.map((e) => {
                const active = selectedIp === e.ip;
                return (
                  <button key={e.ip}
                          onClick={() => onSelectIp(active ? null : e.ip)}
                          className={cn("flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                            active
                              ? "border-sky-700 bg-sky-950/40"
                              : "border-zinc-800 bg-zinc-950/50 hover:border-zinc-700")}>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-zinc-300">{e.ip}</span>
                      <span className="block truncate text-[10px] text-zinc-600">
                        {e.country ?? "no geo"} · {fmtNumber(e.conns)} conns
                      </span>
                    </span>
                    {e.ioc > 0 && (
                      <span className="shrink-0 rounded bg-red-950/80 px-1 py-0.5 text-[9px] font-semibold text-red-300">
                        {e.ioc} IOC
                      </span>
                    )}
                    {e.ioc === 0 && e.alerts > 0 && (
                      <span className="shrink-0 rounded bg-amber-950/80 px-1 py-0.5 text-[9px] text-amber-300">
                        {e.alerts}
                      </span>
                    )}
                  </button>
                );
              })}
              {!endpointRows.length && (
                <p className="text-xs text-zinc-600">No endpoints in this filter.</p>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              Not on the map ({geo.unmapped.length})
            </div>
            <p className="mb-2 text-[10px] text-zinc-600">
              internal IPs / no GeoIP data - listed, never forced onto the map
            </p>
            <div className="space-y-1.5">
              {geo.unmapped.slice(0, 8).map((u) => (
                <button key={u.ip}
                        onClick={() => onSelectIp(
                          selectedIp === u.ip ? null : u.ip)}
                        className={cn("flex w-full items-center justify-between rounded-md border px-2.5 py-1.5 text-left text-xs transition-colors",
                          selectedIp === u.ip
                            ? "border-sky-800 bg-sky-950/30"
                            : "border-zinc-800 bg-zinc-950/50 hover:border-zinc-700")}>
                  <span className="font-mono text-zinc-300">{u.ip}</span>
                  <span className="ml-2 flex-1 truncate text-right text-[10px] text-zinc-600">
                    {u.reason}
                  </span>
                  <span className="ml-2 shrink-0 tabular-nums text-zinc-500">
                    {fmtNumber(u.conns)}
                  </span>
                </button>
              ))}
              {!geo.unmapped.length && (
                <div className="text-xs text-zinc-600">
                  All flows had geo data.
                </div>
              )}
              {geo.unmapped.length > 8 && (
                <div className="text-[10px] text-zinc-600">
                  +{geo.unmapped.length - 8} more
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* full-width flow matrix, now paginated (v0.12.8) */}
      <FlowMatrix geo={geo} selectedIp={selectedIp} onSelectIp={onSelectIp} />

      <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-zinc-500">
        <Info className="mt-0.5 h-3 w-3 shrink-0" />
        {geo.note} One arc per origin country: line thickness follows the
        AGGREGATED connection count of that country, color follows the
        strongest signal (red = TI-matched, amber = alert-bearing). Click a
        country to filter the endpoint panel; click an endpoint for its
        per-flow detail.
        {geo.geo_enabled
          ? " GeoIP enrichment is active on this deployment."
          : " GeoIP enrichment is disabled on this deployment - enable GEOIP_MMDB_PATH / GEOIP_JSON_PATH to plot flows."}
      </p>
    </div>
  );
}

// v0.12.8: full-width matrix with real client-side pagination (used to
// hard-truncate at 40 rows).
function FlowMatrix({ geo, selectedIp, onSelectIp }: {
  geo: GeoBundle;
  selectedIp: string | null;
  onSelectIp: (ip: string | null) => void;
}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  useEffect(() => { setPage(1); }, [geo]);
  const pageRows = geo.flows.slice((page - 1) * pageSize, page * pageSize);
  return (
    <VizPanel
      title="External communication matrix"
      icon={<Table2 className="h-4 w-4 text-emerald-400" />}
      sub={`every external<->internal flow, last 24h (${geo.flows.length}) - click a row for detail`}>
      <Table>
        <TableHeader>
          <TableRow className="border-zinc-800 hover:bg-transparent">
            <TableHead className="text-zinc-500">Direction</TableHead>
            <TableHead className="text-zinc-500">External</TableHead>
            <TableHead className="text-zinc-500">Geo (approx.)</TableHead>
            <TableHead className="text-zinc-500">Internal host</TableHead>
            <TableHead className="text-right text-zinc-500">Conns</TableHead>
            <TableHead className="text-right text-zinc-500">Bytes</TableHead>
            <TableHead className="text-zinc-500">IOC</TableHead>
            <TableHead className="text-zinc-500">Seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {pageRows.map((f, i) => (
            <TableRow key={(page - 1) * pageSize + i}
                      className={cn("cursor-pointer border-zinc-800/60",
                        f.ioc_hits > 0 && "bg-red-950/10",
                        selectedIp === f.external_ip && "bg-emerald-950/20")}
                      onClick={() => onSelectIp(
                        selectedIp === f.external_ip
                          ? null : f.external_ip)}>
              <TableCell>
                {f.direction === "outbound"
                  ? <ArrowUpRight className="h-3.5 w-3.5 text-sky-400" />
                  : <ArrowDownLeft className="h-3.5 w-3.5 text-orange-400" />}
              </TableCell>
              <TableCell className="font-mono text-xs text-zinc-300">
                {f.external_ip}
              </TableCell>
              <TableCell className="text-xs">
                {f.geo
                  ? <span className="text-zinc-400">{f.geo.country}
                      {f.geo.asn_org
                        ? <span className="text-zinc-600"> · {f.geo.asn_org}</span>
                        : null}
                    </span>
                  : <span className="text-zinc-600">no data</span>}
              </TableCell>
              <TableCell className="font-mono text-xs text-zinc-400">
                {f.internal_ip}
              </TableCell>
              <TableCell className="text-right tabular-nums text-zinc-300">
                {fmtNumber(f.conns)}
              </TableCell>
              <TableCell className="text-right tabular-nums text-zinc-400">
                {fmtBytes(f.bytes)}
              </TableCell>
              <TableCell>
                {f.ioc_hits > 0
                  ? <span className="font-semibold text-red-400">{f.ioc_hits}</span>
                  : <span className="text-zinc-700">-</span>}
              </TableCell>
              <TableCell className="whitespace-nowrap text-xs text-zinc-500">
                {f.last_seen ? timeAgo(f.last_seen) : "-"}
              </TableCell>
            </TableRow>
          ))}
          {!pageRows.length && (
            <TableRow className="border-zinc-800/60">
              <TableCell colSpan={8} className="py-8 text-center text-sm text-zinc-500">
                No external flows recorded in the last 24h
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      <Paginator page={page} pageSize={pageSize} total={geo.flows.length}
                 onPage={setPage}
                 onPageSize={(s) => { setPageSize(s); setPage(1); }} />
    </VizPanel>
  );
}

function GeoMapV3({ geo, countries, selectedCountry, onSelectCountry }: {
  geo: GeoBundle;
  countries: CountryAgg[];
  selectedCountry: string | null;
  onSelectCountry: (country: string | null) => void;
}) {
  const dots = getLandDots();
  const hq = { x: px(HQ.lon), y: py(HQ.lat) };
  const svgRef = useRef<SVGSVGElement | null>(null);
  const pz = usePanZoom(W, H, svgRef);
  // Big-screen mode: CSS-based fullscreen that also works inside preview
  // iframes where the native Fullscreen API is unavailable. Esc exits.
  const [big, setBig] = useState(false);
  useEffect(() => {
    if (!big) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setBig(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [big]);

  const maxCountryConns = Math.max(...countries.map((c) => c.conns), 1);
  // v0.12.8: ONE arc per country (max 20), animated packets only on the
  // top 10 - the map stays readable at NOC-wall distance, per the
  // Kaspersky/Fortinet reference structure.
  const plotCountries = useMemo(
    () => countries.slice(0, 20), [countries]);
  const iocTotal = useMemo(
    () => geo.flows.reduce((s, f) => s + f.ioc_hits, 0), [geo.flows]);
  const alertTotal = useMemo(
    () => geo.flows.reduce((s, f) => s + f.alert_hits, 0), [geo.flows]);

  return (
    <div className={cn(
      "relative overflow-hidden rounded-lg border border-zinc-800 bg-[#0a0f0d] transition-all",
      big && "fixed inset-0 z-[100] rounded-none")}>
      <svg ref={svgRef} viewBox={`${pz.view.x} ${pz.view.y} ${pz.view.w} ${pz.view.h}`}
           className={cn("w-full touch-none select-none",
                         big && "h-[calc(100vh-24px)]",
                         pz.grabbing ? "cursor-grabbing" : "cursor-grab")}
           {...pz.handlers}>
        <defs>
          <radialGradient id="mapGlow2" cx="50%" cy="50%" r="70%">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity={0.07} />
            <stop offset="100%" stopColor="#0a0f0d" stopOpacity={0} />
          </radialGradient>
          <filter id="arcGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="dotGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </radialGradient>
        </defs>
        <rect width={W} height={H} fill="url(#mapGlow2)" />

        {/* graticule: subtle lat/lon grid */}
        <g stroke="#142822" strokeWidth={0.6} strokeDasharray="1 5">
          {Array.from({ length: 11 }, (_, i) => -180 + i * 36).map((lon) => (
            <line key={`gx-${lon}`} x1={px(lon)} y1={0} x2={px(lon)} y2={H} />
          ))}
          {Array.from({ length: 4 }, (_, i) => 60 - i * 40).map((lat) => (
            <line key={`gy-${lat}`} x1={0} y1={py(lat)} x2={W} y2={py(lat)} />
          ))}
          <line x1={0} y1={py(0)} x2={W} y2={py(0)} stroke="#1c3a30" strokeWidth={0.9} />
        </g>

        {/* land dots */}
        {dots.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r={2} fill="#1f3d33" />
        ))}

        {/* ONE arc per origin country -> HQ. Thickness = aggregated
            conns; color = strongest signal; animated packet only on the
            top 10 countries (SMIL cost stays bounded). */}
        {plotCountries.map((c, i) => {
          const color = c.ioc > 0 ? FLOW_COLOR.ioc
            : c.alerts > 0 ? FLOW_COLOR.alert
            : c.inbound >= c.outbound ? FLOW_COLOR.inbound
            : FLOW_COLOR.outbound;
          const width = 1 + (c.conns / maxCountryConns) * 4.5;
          const d = c.inbound >= c.outbound
            ? arcPath(c.lat, c.lon, HQ.lat, HQ.lon)
            : arcPath(HQ.lat, HQ.lon, c.lat, c.lon);
          const sel = selectedCountry === c.country;
          const animated = i < 10;
          return (
            <g key={`c-${c.country}`}
               className="cursor-pointer"
               filter={c.ioc > 0 || sel ? "url(#arcGlow)" : undefined}
               onClick={() => { if (!pz.didDrag()) onSelectCountry(sel ? null : c.country); }}>
              <title>
                {`${c.country} - ${c.conns} conns / 24h${c.ioc ? ` - ${c.ioc} IOC hits` : ""}${c.alerts ? ` - ${c.alerts} alert-bearing` : ""} - click to filter`}
              </title>
              <path d={d} fill="none" stroke={color}
                    strokeOpacity={sel ? 0.95
                      : c.ioc > 0 ? 0.7 : c.alerts > 0 ? 0.55 : 0.32}
                    strokeWidth={sel ? width + 1.6 : width}
                    className={c.ioc > 0 ? "ndr-arc-flagged" : "ndr-arc"} />
              {animated && (
                <circle r={sel ? 3.8 : 2.6} fill={color}>
                  <animateMotion dur={`${5 + (i % 5)}s`}
                                 repeatCount="indefinite" path={d} />
                  <animate attributeName="opacity" values="0.25;1;0.25"
                           dur={`${5 + (i % 5)}s`}
                           repeatCount="indefinite" />
                </circle>
              )}
            </g>
          );
        })}

        {/* country bubbles at the weighted centroid */}
        {plotCountries.map((c) => {
          const r = 3 + Math.min(9, Math.sqrt(c.conns / maxCountryConns) * 7);
          const sel = selectedCountry === c.country;
          const color = c.ioc > 0 ? FLOW_COLOR.ioc
            : c.alerts > 0 ? FLOW_COLOR.alert : "#93c5fd";
          return (
            <g key={`b-${c.country}`} className="cursor-pointer"
               onClick={() => { if (!pz.didDrag()) onSelectCountry(sel ? null : c.country); }}>
              <title>
                {`${c.country} - ${c.conns} conns${c.ioc ? ` - ${c.ioc} IOC hits` : ""}`}
              </title>
              {c.ioc > 0 && (
                <circle cx={px(c.lon)} cy={py(c.lat)}
                        r={r + 4} fill="none" stroke={FLOW_COLOR.ioc}
                        strokeOpacity={0.7} strokeWidth={1}
                        filter="url(#arcGlow)">
                  <animate attributeName="r" values={`${r};${r + 11}`}
                           dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="stroke-opacity"
                           values="0.7;0" dur="1.8s"
                           repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={px(c.lon)} cy={py(c.lat)} r={sel ? r + 2.5 : r}
                      fill={color}
                      fillOpacity={c.ioc > 0 ? 0.95 : 0.75}
                      stroke={sel ? "#38bdf8" : "none"} strokeWidth={1.6} />
              <text x={px(c.lon)} y={py(c.lat) - r - 5} textAnchor="middle"
                    fontSize={8.5} fill="#a1a1aa" opacity={sel || c.ioc > 0 ? 0.95 : 0.55}>
                {c.country}
              </text>
            </g>
          );
        })}

        {countries.length > plotCountries.length && (
          <text x={16} y={H - 16} fontSize={11} fill="#71717a">
            + {countries.length - plotCountries.length} further countries listed in the ranking (top {plotCountries.length} plotted)
          </text>
        )}

        {/* HQ node */}
        <g>
          <circle cx={hq.x} cy={hq.y} r={22} fill="url(#dotGlow)" opacity={0.5}>
            <animate attributeName="opacity" values="0.2;0.55;0.2" dur="3s" repeatCount="indefinite" />
          </circle>
          <circle cx={hq.x} cy={hq.y} r={10} fill="#0ea5e9"
                  fillOpacity={0.15} stroke="#38bdf8" strokeWidth={1.5} />
          <circle cx={hq.x} cy={hq.y} r={4} fill="#38bdf8" />
          <circle cx={hq.x} cy={hq.y} r={10} fill="none" stroke="#38bdf8"
                  strokeOpacity={0.5}>
            <animate attributeName="r" values="10;26" dur="2.4s"
                     repeatCount="indefinite" />
            <animate attributeName="stroke-opacity" values="0.5;0"
                     dur="2.4s" repeatCount="indefinite" />
          </circle>
          <text x={hq.x + 16} y={hq.y + 4} fill="#bae6fd" fontSize={13}
                fontWeight={600}>
            Monitored network
          </text>
        </g>
      </svg>

      {/* KPI chips (top-left) */}
      <div className="absolute left-3 top-2 flex flex-wrap gap-1.5">
        <span className="rounded bg-zinc-950/80 px-2 py-1 text-[10px] text-zinc-300">
          <Globe2 className="mr-1 inline h-3 w-3 text-emerald-400" />
          {countries.length} countries
        </span>
        <span className="rounded bg-zinc-950/80 px-2 py-1 text-[10px] text-zinc-300">
          {fmtNumber(geo.flows.length)} flows / 24h
        </span>
        {iocTotal > 0 && (
          <span className="rounded bg-red-950/80 px-2 py-1 text-[10px] text-red-300">
            {iocTotal} IOC hits
          </span>
        )}
        {alertTotal > 0 && (
          <span className="rounded bg-amber-950/80 px-2 py-1 text-[10px] text-amber-300">
            {alertTotal} alert-bearing
          </span>
        )}
      </div>

      {/* fullscreen toggle (top-right, under pan/zoom cluster) */}
      <button
        onClick={() => setBig(!big)}
        title={big ? "Exit fullscreen (Esc)" : "Fullscreen for big screens / NOC walls"}
        aria-label="Toggle fullscreen"
        className="absolute right-3 top-11 flex h-7 items-center gap-1.5 rounded border border-zinc-700 bg-zinc-950/80 px-2 text-xs text-zinc-300 transition-colors hover:border-emerald-600 hover:text-emerald-300">
        {big ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
        {big ? "Exit" : "Fullscreen"}
      </button>

      <div className="absolute bottom-2 left-3 flex flex-wrap items-center gap-3 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-red-400" />TI-matched
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-amber-400" />alert-bearing
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-orange-400" />inbound
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-sky-400" />outbound
        </span>
        <span>one arc per country · width = aggregated conns · click to filter</span>
        <span className="text-zinc-600">drag to pan &middot; scroll to zoom</span>
      </div>
      <div className="absolute bottom-2 right-3 rounded bg-zinc-950/70 px-2 py-1 text-[10px] text-zinc-400">
        equirectangular · {countries.length} mapped countries ·{" "}
        {geo.unmapped.length} listed unmapped
      </div>
      <PanZoomControls pz={pz} />
    </div>
  );
}

// ------------------------------------------------------------ timeline

function CampaignTimeline({ title, items }: {
  title: string;
  items: EvidenceItem[];
}) {
  const [open, setOpen] = useState(false);
  if (!items.length) return null;
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <button className="flex w-full items-center gap-2 text-left"
              onClick={() => setOpen(!open)}>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          attack sequence - {title}
        </span>
        <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
          {items.length} evidence items, time-ordered
        </Badge>
        <span className="ml-auto text-xs text-zinc-500">
          {open ? "hide" : "show"}
        </span>
      </button>
      {open && (
        <ol className="mt-3 space-y-2 border-l border-zinc-800 pl-4">
          {items.map((e, i) => {
            const phase = PHASE_META[(e.phase ?? "unknown") as keyof typeof PHASE_META]
              ?? PHASE_META.unknown;
            return (
              <li key={i} className="relative">
                <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-zinc-950"
                      style={{ background: phase.color }} />
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] tabular-nums text-zinc-500">
                    {e.ts ?? "-"}
                  </span>
                  <Badge variant="outline" style={{ color: phase.color }}
                         className="border-zinc-800 text-[9px]">
                    {phase.label}
                  </Badge>
                  <span className={cn("text-[10px] font-semibold uppercase",
                    e.severity === "high" || e.severity === "critical"
                      ? "text-red-400" : "text-zinc-500")}>
                    {e.source}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-zinc-200">{e.title}</div>
                {e.summary && (
                  <div className="text-[11px] leading-relaxed text-zinc-500">
                    {e.summary}
                  </div>
                )}
                {e.ref_index && e.ref_id && e.ref_index !== "ctx" && (
                  <div className="mt-0.5 font-mono text-[10px] text-zinc-600">
                    ref {e.ref_index}:{e.ref_id}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

// ------------------------------------------------------------- shared

function TabButton({ active, onClick, icon, label, sub }: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  sub: string;
}) {
  return (
    <button onClick={onClick}
            className={cn("flex items-center gap-2.5 rounded-xl border px-4 py-2 text-left transition-colors",
              active
                ? "border-emerald-800 bg-emerald-950/40"
                : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700")}>
      <span className={active ? "text-emerald-400" : "text-zinc-500"}>
        {icon}
      </span>
      <span>
        <span className={cn("block text-sm font-semibold",
          active ? "text-emerald-300" : "text-zinc-300")}>
          {label}
        </span>
        <span className="block text-[10px] text-zinc-500">{sub}</span>
      </span>
    </button>
  );
}

function MiniStat({ icon, label, value, sub, tone }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  tone?: "alert";
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3">
      <span className={cn("rounded-lg border border-zinc-800 bg-zinc-950 p-2",
        tone === "alert" ? "text-red-400" : "text-emerald-400")}>
        {icon}
      </span>
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500">
          {label}
        </div>
        <div className={cn("text-lg font-semibold tabular-nums",
          tone === "alert" ? "text-red-300" : "text-zinc-100")}>
          {value}
        </div>
        {sub && (
          <div className="truncate text-[10px] text-zinc-600">{sub}</div>
        )}
      </div>
    </div>
  );
}
