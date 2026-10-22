// API client for the NDR console.
//
// Demo mode (NEXT_PUBLIC_DEMO_MODE=true, sandbox preview): serves bundled
// fixtures and simulates login with any credentials.
// Live mode: talks to the NDR API through the same-origin /backend proxy
// (cookie-based session, see api/app/security.py).

import {
  assetNameLookup, buildRichOverview, buildThreatIntel, demoAddAllowlist,
  demoAlerts, demoAudit,
  demoAssetRegistry, demoChangePassword, demoCreateAsset, demoCreateCustomRule,
  demoCreateFeed,
  demoCreateUser, demoDeleteAsset,
  demoDeleteCustomRule, demoDeleteUser, demoDiagnose, demoEvidenceSessions,
  demoEvents, demoHealth, demoMustChangePassword, demoNtpStatus,
  demoPcapExportCreate, demoPcapExports, demoPcapStorage, demoPatchBranding,
  demoPatchNetwork, demoPatchNtp, demoPatchSystem, demoRemoveAllowlist,
  demoRoleMatrix, demoRules, demoRulesSummary, demoSettings, demoSensors,
  demoStats, demoTiAllowlist, demoTiFeeds, demoTiIocs, demoTiMatches,
  demoToggleRule,
  demoTriggerFeedUpdate, demoUpdateAsset, demoUpdateCustomRule,
  demoUpdateUser, demoUsers, demoValidateRuleText, demoZeekScripts,
  DEMO_USER, makeEpsTick, makeFeedItem,
  demoAllowlist,
} from "./demo";
import type { AllowEntry, AllowStatus, AllowSummary, AllowLayer, AllowEntityField,
  AlertDoc, AlertRelationship, AlertStats, AllowRow, AuditRow, DiagnoseResult,
  DiagnoseTool, DgaSummary, EventDoc, EvidenceSessions, Health,
  IocActivity, IocMatchRow, IocRow, NetworkConfig, OverviewStats,
  PcapCoverage, PcapExportCreate, PcapExportRecord, PcapExportsList,
  RegisteredAsset, RelatedIncident, RichOverview, Role,
  RoleMatrix, RuleRow, RuleToggleResult,
  RuleValidateResult, RulesList, RulesStatus, RulesSummary, RulesUpdateResult,
  SessionUser, SensorRow, SystemSettings, TIFeed,
  TIJob, ThreatIntelData, TIOverview, TopItem, UserRow, ZeekScriptList,
  GraphCampaign, GraphEdge, GraphNode,
  DnsHit, DnsSummary, ExportAlertBody, FilterAst, GamblingSummary,
  RuleStatsList, ServiceMetric, TlsSummary,
} from "./types";

export interface SearchFilters {
  index: string;
  query: string;      // JSON DSL string (advanced) or simple keyword (simple)
  mode: "simple" | "advanced";
  time_from?: string;
  time_to?: string;
  size?: number;
  /** v0.16.1 (P2-4): minta total eksak tanpa cap 10.000 */
  exact_total?: boolean;
  from?: number;
  sort?: unknown;
}

export const API_BASE = "/backend";
export const DEMO_MODE =
  process.env.NEXT_PUBLIC_DEMO_MODE === "true" ||
  (typeof window !== "undefined" &&
    new URLSearchParams(window.location.search).get("demo") === "1");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    credentials: "include",
  });
  if (res.status === 401) {
    throw new UnauthorizedError();
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch { /* keep default */ }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export class UnauthorizedError extends Error {
  constructor() {
    super("Not authenticated");
    this.name = "UnauthorizedError";
  }
}

// --------------------------------------------------------------- session
export async function login(username: string, password: string): Promise<SessionUser> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 350));
    // v0.12.2: first login mirrors the live bootstrap-admin flow
    return { ...DEMO_USER, username: username || DEMO_USER.username,
             must_change_password: demoMustChangePassword() };
  }
  const body = await request<{ username: string; role: SessionUser["role"]; must_change_password?: boolean }>(
    "/api/auth/login",
    { method: "POST", body: JSON.stringify({ username, password }) });
  return { username: body.username, role: body.role, must_change_password: body.must_change_password };
}

export async function logout(): Promise<void> {
  if (DEMO_MODE) return;
  await request("/api/auth/logout", { method: "POST" }).catch(() => undefined);
}

export async function me(): Promise<SessionUser> {
  if (DEMO_MODE) return { ...DEMO_USER };
  return request<SessionUser>("/api/auth/me");
}

// v0.12.2: change own password. Backend revokes every existing session
// (token_version bump), so the caller must return the user to the login
// screen after success.
export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  if (DEMO_MODE) {
    await demoChangePassword();
    return;
  }
  await request("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

// --------------------------------------------------------------- overview
export async function getHealth(): Promise<Health> {
  if (DEMO_MODE) return demoHealth;
  return request<Health>("/api/health");
}

export async function getOverviewStats(): Promise<OverviewStats> {
  if (DEMO_MODE) return demoStats;
  return request<OverviewStats>("/api/stats/overview");
}

// Rich bundle for the visual dashboard. Demo mode returns the full synthetic
// dataset; live mode derives what it can from existing endpoints (graceful).
// v0.13.0: dashboard timeline comes from the REAL aggregation endpoint
// GET /api/events/timeline (anti-fabrication - the old code fabricated a
// curve from a constant EPS).
export async function fetchEventsTimeline(hours = 24): Promise<{
  hours: number; interval: string; total: number;
  points: { ts: string; count: number; engines?: Record<string, number> }[];
}> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 80));
    const now = Date.now();
    const points = Array.from({ length: 24 }, (_, i) => ({
      ts: new Date(now - (23 - i) * 3_600_000).toISOString(),
      count: 40 + Math.round(30 * Math.sin(i / 3)),
      engines: { zeek: 25 + i, suricata: 10 + (i % 7) },
    }));
    return { hours, interval: "1h", total: points.reduce((a, p) => a + p.count, 0), points };
  }
  return request(`/api/events/timeline?hours=${hours}`);
}

export async function getRichOverview(): Promise<RichOverview> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return buildRichOverview();
  }
  // v0.16.2 (BUG-0161-01): timeline diambil 48 JAM (bukan 24) sehingga
  // perbandingan "vs prev 24h" di Dashboard punya data, dan tiap titik
  // membawa `count` (total eksak seluruh engine) dari API.
  const [health, stats, timeline] = await Promise.all([
    getHealth(),
    getOverviewStats(),
    fetchEventsTimeline(48).catch(() => ({ points: [] as {
      ts: string; count: number; engines?: Record<string, number> }[] })),
  ]);
  // v0.16.1 (P1-2): Dashboard/Topology/Assets/Reports kini dibekali data
  // agregasi NYATA dari /api/stats/overview (hosts, zone_traffic,
  // protocols, top_dns/http/tls/ports, mttr, pipeline components).
  // Dulu semuanya kosong karena tidak pernah dipetakan dari backend.
  const s = stats as OverviewStats & Record<string, unknown>;
  const richHosts = (s.hosts ?? []) as unknown as RichOverview["hosts"];
  const pipelineComponents = ((health as Health & { pipeline?:
    { components?: { name: string; ok: boolean; detail?: string }[] } })
    .pipeline?.components) ?? [];
  const services: ServiceMetric[] = pipelineComponents.map((c) => ({
    name: c.name, ok: !!c.ok, detail: c.detail ?? "",
    cpu_pct: 0, mem_pct: 0, uptime_days: 0, cpu_history: [],
  }));
  return {
    generated_at: health.time,
    health,
    stats,
    hosts: richHosts,
    externals: [], flows: [],
    // v0.16.2 (BUG-0161-01): simpan `count` eksak dari API; zeek/suricata
    // tetap dipetakan untuk chart split engine.
    timeline: (timeline.points ?? []).map((p) => ({
      ts: p.ts,
      count: p.count ?? (p.engines?.zeek ?? 0) + (p.engines?.suricata ?? 0),
      zeek: Math.round(p.engines?.zeek ?? 0),
      suricata: Math.round(p.engines?.suricata ?? 0),
      arkime: Math.round(p.engines?.arkime ?? 0),
      bytes: 0,
      alerts_critical: 0, alerts_high: 0, alerts_medium: 0, alerts_low: 0,
    })),
    // v0.16.2 (BUG-0161-02): volume deteksi harian 7d + split severity
    // NYATA dari stats.alert_daily_7d (dulu chart Reports selalu kosong
    // karena membaca alerts_* hardcode-0 dari timeline events).
    alert_daily: ((s.alert_daily_7d ?? []) as NonNullable<
      OverviewStats["alert_daily_7d"]>).map((d) => ({
      ts: d.day,
      zeek: 0, suricata: 0, arkime: 0, bytes: 0,
      alerts_critical: d.critical ?? 0,
      alerts_high: d.high ?? 0,
      alerts_medium: d.medium ?? 0,
      alerts_low: d.low ?? 0,
    })),
    alert_heatmap: [],
    top_internal_talkers: richHosts.slice(0, 8).map((h) => ({
      key: String(h.ip), count: Number(h.conns_24h ?? 0),
    })) as TopItem[],
    top_external_dests: (stats.top_alert_titles ?? []).map((t2) => ({ key: t2.key, count: t2.count })),
    top_ports: (s.top_ports ?? []) as TopItem[],
    protocols: (s.protocols ?? []) as unknown as RichOverview["protocols"],
    top_dns: (s.top_dns ?? []) as TopItem[],
    top_http_hosts: (s.top_http_hosts ?? []) as TopItem[],
    top_tls_sni: (s.top_tls_sni ?? []) as TopItem[],
    rule_stats: [], services,
    live_feed: [],
    zone_traffic: (s.zone_traffic ?? []) as unknown as RichOverview["zone_traffic"],
    eps_history: [],
    mttr: (s.mttr ?? []) as unknown as RichOverview["mttr"],
    new_alerts_today: stats.alerts_by_status?.find((s2) => s2.key === "new")?.count ?? 0,
    critical_open: stats.alerts_by_severity?.find((s2) => s2.key === "critical")?.count ?? 0,
    mean_time_to_ack_min: (s.mean_time_to_ack_min as number | null) ?? 0,
  };
}

// Live ticker helpers (demo mode only; live mode uses pipeline health polling)
export function demoTickEps(prev: number): number {
  return makeEpsTick(prev);
}
export function demoNewFeedItem() {
  return makeFeedItem();
}

// --------------------------------------------------------------- alerts
// v0.12.7: shared DSL builder - /search (table pages + sample window)
// and /stats (exact chart buckets) MUST apply the identical filter so
// the header charts always describe the paginated result set.
function alertQueryFilter(filters: {
  severity?: string;
  status?: string;
  keyword?: string;
  outcome?: string;
  /** v0.12.8: DGA focus view - pre-filter to specific alert types. */
  alert_types?: string[];
}): unknown[] {
  const filter: unknown[] = [];
  if (filters.severity && filters.severity !== "all") {
    filter.push({ term: { severity: filters.severity } });
  }
  if (filters.status && filters.status !== "all") {
    filter.push({ term: { status: filters.status } });
  }
  // v0.12.7: verdict filter moved server-side so pagination stays
  // consistent (it used to slice only the loaded 500-row window)
  if (filters.outcome && filters.outcome !== "all") {
    filter.push({ term: { outcome: filters.outcome } });
  }
  // v0.12.8: alert-type lens (e.g. the DGA Activity menu shows only
  // dga_suspected + dns_nxdomain_burst alerts)
  if (filters.alert_types?.length) {
    filter.push({ terms: { alert_type: filters.alert_types } });
  }
  if (filters.keyword) {
    filter.push({
      bool: { should: [
        { match_phrase: { title: filters.keyword } },
        { term: { "source.ip": filters.keyword } },
        { term: { "destination.ip": filters.keyword } },
      ] },
    });
  }
  return filter;
}

export async function searchAlerts(filters: {
  severity?: string;
  status?: string;
  keyword?: string;
  outcome?: string;
  /** v0.12.8: alert-type lens (DGA Activity menu). */
  alert_types?: string[];
  time_from?: string;
  time_to?: string;
  size?: number;
  /** Server-side offset (v0.12.7 real pagination - the backend window
   *  is capped at 500 rows per response, `from` walks past it). */
  from?: number;
  /** v0.14.0: include whitelist-suppressed (L1) alerts. */
  show_suppressed?: boolean;
}): Promise<{ total: number; hits: AlertDoc[] }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    let hits = filters.show_suppressed
      ? demoAlerts
      : demoAlerts.filter((a) => !a.suppressed);
    if (filters.severity && filters.severity !== "all") {
      hits = hits.filter((a) => a.severity === filters.severity);
    }
    if (filters.status && filters.status !== "all") {
      hits = hits.filter((a) => a.status === filters.status);
    }
    if (filters.alert_types?.length) {
      hits = hits.filter((a) => filters.alert_types!.includes(a.alert_type));
    }
    if (filters.outcome && filters.outcome !== "all") {
      hits = hits.filter(
        (a) => (a.outcome ?? "indeterminate") === filters.outcome);
    }
    if (filters.time_from) {
      hits = hits.filter((a) => a.last_seen >= filters.time_from!);
    }
    if (filters.time_to) {
      hits = hits.filter((a) => a.first_seen <= filters.time_to!);
    }
    if (filters.keyword) {
      const kw = filters.keyword.toLowerCase();
      hits = hits.filter((a) =>
        a.title.toLowerCase().includes(kw) ||
        a.source?.ip?.includes(kw) || a.destination?.ip?.includes(kw));
    }
    // asset-name enrichment is applied live so manually registered assets
    // immediately label existing alerts (v0.10)
    const names = assetNameLookup();
    const from = Math.max(0, filters.from ?? 0);
    return {
      total: hits.length,
      hits: hits.slice(from, from + (filters.size ?? 100)).map((a) => ({
        ...a,
        source_asset_name: (a.source?.ip && names.get(a.source.ip)) || a.source_asset_name || null,
        destination_asset_name: (a.destination?.ip && names.get(a.destination.ip)) || a.destination_asset_name || null,
      })),
    };
  }
  const filter = alertQueryFilter(filters);
  // v0.12.5: the API returns NESTED hits ({id, source}); the Alerts view,
  // its detail panel and escalate/update all expect FLAT AlertDoc fields
  // (the Events view unwraps ev.source, this one never did - alert rows
  // rendered '-' / severity 'unknown' and alert_id was missing, so
  // escalate/update silently broke). Flatten once here; alert_id falls
  // back to the hit id when the doc lacks it.
  const res = await request<{
    total: number;
    hits: Array<{ id: string; source: Partial<AlertDoc> | null }>;
  }>("/api/alerts/search", {
    method: "POST",
    body: JSON.stringify({
      index: "ndr-alerts-read",
      size: filters.size ?? 100,
      // v0.12.7: server-side result window offset (real pagination)
      from: Math.max(0, filters.from ?? 0),
      query: filter.length ? { bool: { filter } } : {},
      time_from: filters.time_from,
      time_to: filters.time_to,
    }),
  });
  return {
    total: res.total,
    hits: res.hits.map((h) => {
      const src = (h.source ?? {}) as AlertDoc;
      return { ...src, alert_id: src.alert_id ?? h.id };
    }),
  };
}

// v0.12.7: EXACT chart buckets for the Alert Center header. The charts
// used to aggregate the newest-500 sample window - wrong whenever more
// than 500 alerts matched. /api/alerts/stats runs the same guarded
// filter as /search with size 0 and returns exact per-field counts, so
// severity mix / triage funnel / badge counts are correct for any
// result-set size.
export async function alertStats(filters: {
  severity?: string;
  status?: string;
  keyword?: string;
  outcome?: string;
  /** v0.12.8: alert-type lens (DGA Activity menu). */
  alert_types?: string[];
  time_from?: string;
  time_to?: string;
  /** v0.14.0: include whitelist-suppressed (L1) alerts. */
  show_suppressed?: boolean;
}): Promise<AlertStats> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 80));
    let hits = filters.show_suppressed
      ? demoAlerts
      : demoAlerts.filter((a) => !a.suppressed);
    if (filters.severity && filters.severity !== "all") {
      hits = hits.filter((a) => a.severity === filters.severity);
    }
    if (filters.alert_types?.length) {
      hits = hits.filter((a) => filters.alert_types!.includes(a.alert_type));
    }
    if (filters.status && filters.status !== "all") {
      hits = hits.filter((a) => a.status === filters.status);
    }
    if (filters.outcome && filters.outcome !== "all") {
      hits = hits.filter(
        (a) => (a.outcome ?? "indeterminate") === filters.outcome);
    }
    if (filters.time_from) {
      hits = hits.filter((a) => a.last_seen >= filters.time_from!);
    }
    if (filters.time_to) {
      hits = hits.filter((a) => a.first_seen <= filters.time_to!);
    }
    if (filters.keyword) {
      const kw = filters.keyword.toLowerCase();
      hits = hits.filter((a) =>
        a.title.toLowerCase().includes(kw) ||
        a.source?.ip?.includes(kw) || a.destination?.ip?.includes(kw));
    }
    const bucket = (field: (a: AlertDoc) => string) => {
      const counts = new Map<string, number>();
      hits.forEach((a) => {
        const k = field(a);
        counts.set(k, (counts.get(k) ?? 0) + 1);
      });
      return Array.from(counts.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count);
    };
    return {
      total: hits.length,
      relation: "eq",
      severity: bucket((a) => a.severity),
      status: bucket((a) => a.status),
      outcome: bucket((a) => a.outcome ?? "indeterminate"),
    };
  }
  const filter = alertQueryFilter(filters);
  return request<AlertStats>("/api/alerts/stats", {
    method: "POST",
    body: JSON.stringify({
      index: "ndr-alerts-read",
      query: filter.length ? { bool: { filter } } : {},
      time_from: filters.time_from,
      time_to: filters.time_to,
    }),
  });
}

// v0.12.8: DGA Activity menu - aggregation-only summary over the two
// DGA-family alert types. The backend returns bucket counts only
// (guarded_aggregate, size 0); no documents, no new detector.
export async function getDgaSummary(hours = 24): Promise<DgaSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 80));
    const since = new Date(Date.now() - hours * 3600_000).toISOString();
    const hits = demoAlerts.filter((a) =>
      (a.alert_type === "dga_suspected"
       || a.alert_type === "dns_nxdomain_burst")
      && a.last_seen >= since);
    const srcCounts = new Map<string, number>();
    hits.forEach((a) => {
      const ip = a.source?.ip;
      if (ip) srcCounts.set(ip, (srcCounts.get(ip) ?? 0) + a.event_count);
    });
    const now = Date.now();
    const timeline: { ts: string; count: number }[] = [];
    for (let i = 11; i >= 0; i--) {
      const from = now - (i + 1) * 3600_000;
      const to = now - i * 3600_000;
      const count = hits.filter((a) => {
        const t = +new Date(a.last_seen);
        return t >= from && t < to;
      }).length;
      const d = new Date(to - 1);
      timeline.push({
        ts: d.toISOString().slice(0, 13) + ":00:00Z",
        count,
      });
    }
    const newest = hits.reduce<string | null>(
      (acc, a) => (!acc || a.last_seen > acc ? a.last_seen : acc), null);
    return {
      hours,
      total: hits.length,
      relation: "eq",
      alert_types: ["dga_suspected", "dns_nxdomain_burst"],
      sources: Array.from(srcCounts.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count).slice(0, 10),
      timeline,
      last_seen: newest,
    };
  }
  return request<DgaSummary>(
    `/api/alerts/dga/summary?hours=${encodeURIComponent(String(hours))}`);
}

// v0.12.8: incidents whose recorded evidence references this alert.
// Honest linkage only - the correlation engine (or a manual escalation)
// must have actually recorded the alert as incident evidence.
export async function getAlertRelatedIncidents(
  alertId: string,
): Promise<{ items: RelatedIncident[] }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 60));
    const { demoRelatedIncidentsForAlert } = await import("./incidents-demo");
    return { items: demoRelatedIncidentsForAlert(alertId) };
  }
  return request<{ items: RelatedIncident[] }>(
    `/api/alerts/${encodeURIComponent(alertId)}/related-incident`);
}

// v0.12.9: FOCUSED attack relationship for ONE alert - what the Alert
// Center threat-map jump renders (this alert's incident subgraph when it
// is recorded incident evidence, else an honest single-alert graph).
export async function getAlertRelationship(
  alertId: string,
): Promise<AlertRelationship> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 80));
    const { demoRelatedIncidentsForAlert } = await import("./incidents-demo");
    const { buildRelationshipGraph } = await import("./graph-demo");
    const alert = demoAlerts.find((a) => a.alert_id === alertId);
    if (!alert) throw new Error("Alert not found");
    const srcIp = alert.source?.ip ?? null;
    const dstIp = alert.destination?.ip ?? null;
    const incidents = demoRelatedIncidentsForAlert(alertId);
    // demo mirrors the real backend contract: an incident-linked alert
    // returns THAT incident's subgraph (filtered from the demo graph),
    // anything else gets the honest single-alert mini graph
    let nodes: GraphNode[] = [];
    let edges: GraphEdge[] = [];
    let campaigns: GraphCampaign[] = [];
    const alertOnlyNodes = [srcIp, dstIp].filter(Boolean).map((ip, i) => ({
      key: `ip:${ip}` as string,
      kind: "ip" as const,
      label: ip as string,
      roles: [i === 0 ? "compromised_host" : "c2_infra"],
      phase: "c2" as const,
      confidence: 70,
      first_seen: alert.first_seen,
      last_seen: alert.last_seen,
      evidence_count: 1,
      incident_ids: incidents.map((r) => r.incident_id),
      ti_match: false,
      attrs: { via: `alert ${alertId}` },
      internal: i === 0,
      degree: srcIp && dstIp ? 1 : 0,
    }));
    const alertOnlyEdges = srcIp && dstIp ? [{
      src: `ip:${srcIp}`, dst: `ip:${dstIp}`,
      relation: "alerted_activity", phase: "c2" as const,
      inferred: false,
      first_seen: alert.first_seen, last_seen: alert.last_seen,
      evidence_count: 1, confidence: 70, incident_ids: [] as string[],
      reasons: [`alert ${alertId}: '${alert.title}' observed ${alert.first_seen} to ${alert.last_seen}`],
    }] : [];
    if (incidents.length) {
      const g = buildRelationshipGraph();
      const incIds = new Set(incidents.map((r) => r.incident_id));
      campaigns = g.campaigns.filter((c) => incIds.has(c.id));
      const keys = new Set(campaigns.flatMap((c) => c.node_keys));
      // keep incident nodes + this alert's own entities (visible anchor)
      if (srcIp) keys.add(`ip:${srcIp}`);
      if (dstIp) keys.add(`ip:${dstIp}`);
      nodes = g.nodes.filter((n) => keys.has(n.key)).map((n) => ({
        ...n,
        incident_ids: Array.from(new Set([
          ...n.incident_ids.filter((i) => incIds.has(i)),
        ])),
      }));
      const nodeKeys = new Set(nodes.map((n) => n.key));
      edges = g.edges.filter((e) => nodeKeys.has(e.src) && nodeKeys.has(e.dst));
    } else {
      nodes = alertOnlyNodes;
      edges = alertOnlyEdges;
    }
    const note = incidents.length
      ? `This alert is recorded evidence of ${incidents.length} reconstructed incident(s) - showing the incident attack chain(s) it belongs to.`
      : "Showing what THIS alert alone proves - its own source/destination entities with the alert as the single cited source. No correlation is guessed.";
    return {
      alert: {
        id: alertId, alert_id: alertId, title: alert.title,
        alert_type: alert.alert_type, severity: alert.severity,
        status: alert.status, source_ip: srcIp, destination_ip: dstIp,
        first_seen: alert.first_seen, last_seen: alert.last_seen,
        event_count: alert.event_count,
      },
      basis: incidents.length ? "incident" : "alert",
      note,
      incidents,
      graph: {
        nodes, edges,
        campaigns,
        meta: {
          generated_at: new Date().toISOString(),
          node_count: nodes.length, edge_count: edges.length,
          campaign_count: campaigns.length, basis: note,
          disclaimer: "Focused relationship view - correlations carry cited evidence, not proof of compromise.",
          full_counts: { nodes: nodes.length, edges: edges.length },
          render_limits: { max_nodes: 60, max_edges: 200 },
          pruned: false,
        },
      },
    };
  }
  return request<AlertRelationship>(
    `/api/alerts/${encodeURIComponent(alertId)}/relationship`);
}

// v0.12.9: per-IOC activity (store record + what happened on THIS network
// + the ioc_match alerts recorded for this indicator).
export async function getIocActivity(
  iocValue: string, hours = 168,
): Promise<IocActivity> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 90));
    const ioc = demoTiIocs.find((i) => i.ioc_value === iocValue);
    if (!ioc) throw new Error("IOC not found");
    const matches = demoTiMatches.filter(
      (m) => m.ioc_value === iocValue &&
        +new Date(m["@timestamp"]) >= Date.now() - hours * 3600_000);
    const hosts = new Map<string, number>();
    matches.forEach((m) => {
      if (m.source_ip) hosts.set(m.source_ip, (hosts.get(m.source_ip) ?? 0) + 1);
    });
    const fields = new Map<string, number>();
    matches.forEach((m) => {
      if (m.match_field) fields.set(m.match_field, (fields.get(m.match_field) ?? 0) + 1);
    });
    const sortedTs = matches.map((m) => m["@timestamp"]).sort();
    const alerts = demoAlerts.filter(
      (a) => a.alert_type === "ioc_match" &&
        (a.top_rules ?? []).some((r) => r.signature === `ioc:${iocValue}`));
    return {
      ioc: { ...ioc, provenance: [{
        feed: ioc.malware ?? "threat-intel", first_seen: ioc.first_seen,
        last_seen: ioc.last_seen, confidence: ioc.confidence,
        malware: ioc.malware,
      }] },
      hours,
      activity: {
        matches_total: matches.length, relation: "eq",
        unique_source_hosts: hosts.size,
        first_match: sortedTs[0] ?? null,
        last_match: sortedTs[sortedTs.length - 1] ?? null,
        top_source_hosts: [...hosts.entries()]
          .map(([key, count]) => ({ key, count }))
          .sort((a, b) => b.count - a.count).slice(0, 8),
        match_fields: [...fields.entries()]
          .map(([key, count]) => ({ key, count }))
          .sort((a, b) => b.count - a.count),
      },
      recent_matches: matches.slice(0, 10).map((m) => ({
        id: m.id, "@timestamp": m["@timestamp"], event_id: m.event_id,
        event_index: m.event_index, source_ip: m.source_ip,
        destination_ip: m.destination_ip, match_field: m.match_field,
        zone: m.zone,
      })),
      related_alerts: {
        total: alerts.length,
        items: alerts.slice(0, 10).map((a) => ({
          alert_id: a.alert_id, title: a.title, severity: a.severity,
          alert_type: a.alert_type, status: a.status,
          first_seen: a.first_seen, last_seen: a.last_seen,
          source_ip: a.source?.ip ?? null,
          destination_ip: a.destination?.ip ?? null,
        })),
      },
    };
  }
  return request<IocActivity>(
    `/api/ti/iocs/activity?value=${encodeURIComponent(iocValue)}&hours=${hours}`);
}

/**
 * Manually raise one alert into a new incident (v0.10). The incident
 * starts with exactly the alert's own entities/evidence and NO invented
 * relations; the correlation engine may merge it later when related
 * evidence appears.
 */
export async function escalateAlert(
  alertId: string, reason?: string,
): Promise<{ incident_id: string; title: string }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 300));
    const alert = demoAlerts.find((a) => a.alert_id === alertId);
    if (!alert) throw new Error("alert not found");
    const { demoEscalateAlert } = await import("./incidents-demo");
    const inc = demoEscalateAlert(alert, DEMO_USER.username, reason);
    return { incident_id: inc.id, title: inc.title };
  }
  return request(`/api/alerts/${encodeURIComponent(alertId)}/escalate`, {
    method: "POST",
    body: JSON.stringify({ reason: reason ?? null }),
  });
}

export async function updateAlert(alertId: string, patch: {
  status?: string; assignee?: string | null; notes?: string | null;
}): Promise<void> {
  if (DEMO_MODE) {
    const alert = demoAlerts.find((a) => a.alert_id === alertId);
    if (alert) Object.assign(alert, patch);
    await new Promise((r) => setTimeout(r, 200));
    return;
  }
  await request(`/api/alerts/${alertId}`, {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

// --------------------------------------------------------------- events
export async function searchEvents(filters: SearchFilters): Promise<{ total: number; hits: EventDoc[]; error?: string }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    if (filters.mode === "advanced") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(filters.query || "{}");
      } catch {
        return { total: 0, hits: [], error: "Invalid JSON in DSL query" };
      }
      const forbidden = ["script", "regexp", "fuzzy", "query_string", "wildcard", "nested"];
      const text = JSON.stringify(parsed);
      if (forbidden.some((k) => text.includes(`"${k}"`))) {
        return { total: 0, hits: [], error: "Query rejected: forbidden clause (script/regexp/fuzzy/wildcard/query_string/nested)" };
      }
    }
    const kw = filters.mode === "simple" ? filters.query.toLowerCase() : "";
    // deep-link support (v0.12.1): advanced DSL with a term on event_id
    // (used by Threat Intel "Open in Event Search") narrows to that event
    let eventIdFilter: string | null = null;
    if (filters.mode === "advanced") {
      try {
        const parsedQ = JSON.parse(filters.query || "{}") as Record<string, unknown>;
        const stack: unknown[] = [parsedQ];
        while (stack.length && eventIdFilter === null) {
          const node = stack.pop();
          if (node && typeof node === "object") {
            for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
              if (k === "event_id" && (typeof v === "string" || typeof v === "number")) {
                eventIdFilter = String(v);
              } else if (v && typeof v === "object") {
                stack.push(v);
              }
            }
          }
        }
      } catch { /* handled above */ }
    }
    const hits = demoEvents.filter((e) => {
      if (eventIdFilter !== null) {
        return e.source.event_id === eventIdFilter || e.id === eventIdFilter;
      }
      if (!kw) return true;
      const s = JSON.stringify(e.source).toLowerCase();
      return s.includes(kw);
    });
    return { total: hits.length, hits: hits.slice(0, filters.size ?? 50) };
  }
  if (filters.mode === "simple") {
    // v0.16.1 (P0-5): mode simple TIDAK lagi membangun DSL di client.
    // Dulu term teks (mis. "dns") dikirim ke field bertipe ip -> parsing
    // gagal, hasil SELALU 0. Kini kirim query_text; API yang membangun
    // query benar (event_type fast-path, IP fast-path, wildcard whitelist).
    return request<{ total: number; relation?: string; hits: EventDoc[] }>(
      "/api/events/search", {
        method: "POST",
        body: JSON.stringify({
          index: filters.index,
          size: filters.size ?? 50,
          query_text: filters.query.trim(),
          exact_total: filters.exact_total ?? false,
          time_from: filters.time_from,
          time_to: filters.time_to,
        }),
      });
  }
  // advanced: send raw DSL as query
  let parsed: unknown;
  try {
    parsed = JSON.parse(filters.query || "{}");
  } catch {
    return { total: 0, hits: [], error: "Invalid JSON in DSL query" };
  }
  return request<{ total: number; relation?: string; hits: EventDoc[] }>(
    "/api/events/search", {
    method: "POST",
    // v0.13.0: time_to travels too - Verify-in-Event-Search used to open
    // an UNBOUNDED window (only time_from was sent)
    // v0.16.1 (P2-4): exact_total opsional
    body: JSON.stringify({ index: filters.index, size: filters.size ?? 50,
                           query: parsed, time_from: filters.time_from,
                           time_to: filters.time_to,
                           exact_total: filters.exact_total ?? false }),
  });
}

// ============ v0.14.0 alert whitelist (allowlist) ============
export async function listAlertAllowlist(params?: {
  status?: AllowStatus; alert_type?: string;
}): Promise<AllowEntry[]> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return demoAllowlist.filter((e) =>
      (!params?.status || e.status === params.status)
      && (!params?.alert_type || e.alert_type === params.alert_type));
  }
  const qs = new URLSearchParams();
  if (params?.status) qs.set("status", params.status);
  if (params?.alert_type) qs.set("alert_type", params.alert_type);
  const q = qs.toString();
  return request(`/api/allowlist${q ? `?${q}` : ""}`);
}

export async function allowlistSummary(): Promise<AllowSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 80));
    const active = demoAllowlist.filter((e) => e.status === "active");
    const pending = demoAllowlist.filter((e) => e.status === "pending");
    const expired = demoAllowlist.filter((e) => e.status === "expired");
    const rejected = demoAllowlist.filter((e) => e.status === "rejected");
    const top = [...active].sort((a, b) => b.hit_count - a.hit_count).slice(0, 5);
    return {
      active: active.length, pending: pending.length,
      expired: expired.length, rejected: rejected.length,
      total_hits: active.reduce((s, e) => s + e.hit_count, 0),
      l0: active.filter((e) => e.layer === "L0").length,
      l1: active.filter((e) => e.layer === "L1").length,
      top: top.map((e) => ({ id: e.id, alert_type: e.alert_type,
        entity_field: e.entity_field, entity_value: e.entity_value,
        layer: e.layer, hit_count: e.hit_count,
        last_hit_at: e.last_hit_at ?? null })),
    };
  }
  return request("/api/allowlist/summary");
}

export interface AllowCreateInput {
  alert_type: string;
  signature?: string | null;
  entity_field: AllowEntityField;
  entity_value: string;
  layer: AllowLayer;
  reason: string;
  ttl_hours?: number | null;
  retroactive?: boolean;
}

export async function createAlertAllowlist(
  input: AllowCreateInput,
): Promise<AllowEntry> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    const isAdmin = DEMO_USER.role === "administrator"
      || DEMO_USER.role === "security_engineer";
    const now = new Date().toISOString();
    const dupe = demoAllowlist.find((e) =>
      e.alert_type === input.alert_type
      && e.entity_field === input.entity_field
      && e.entity_value === input.entity_value
      && (e.signature ?? null) === (input.signature ?? null)
      && (e.status === "active" || e.status === "pending"));
    if (dupe) throw new Error("an entry with this scope already exists");
    const entry: AllowEntry = {
      id: Math.max(0, ...demoAllowlist.map((e) => e.id)) + 1,
      alert_type: input.alert_type, signature: input.signature ?? null,
      entity_field: input.entity_field, entity_value: input.entity_value,
      layer: input.layer,
      status: isAdmin ? "active" : "pending",
      reason: input.reason,
      retroactive: input.retroactive ?? false,
      created_by: DEMO_USER.username, created_at: now,
      approved_by: isAdmin ? DEMO_USER.username : null,
      approved_at: isAdmin ? now : null,
      expires_at: input.ttl_hours
        ? new Date(Date.now() + input.ttl_hours * 3_600_000).toISOString()
        : null,
      hit_count: isAdmin && input.retroactive ? 4 : 0,
      last_hit_at: null,
      retro_tagged: isAdmin && input.retroactive ? 4 : 0,
    };
    demoAllowlist.push(entry);
    if (entry.status === "active" && input.layer === "L1") {
      // demo: tag matching L1 alerts so the effect is visible
      demoAlerts.forEach((a) => {
        if (a.suppressed) return;
        if (a.alert_type !== input.alert_type) return;
        const ip = input.entity_field === "src_ip" ? a.source?.ip
          : input.entity_field === "dst_ip" ? a.destination?.ip : null;
        const dom = (a.dns_domains ?? []);
        const hit = input.entity_field === "dst_domain"
          ? dom.some((d) => d.endsWith(input.entity_value))
          : ip === input.entity_value;
        if (hit) { a.suppressed = true; a.suppressed_by = entry.id; }
      });
    }
    return entry;
  }
  return request("/api/allowlist", {
    method: "POST", body: JSON.stringify(input),
  });
}

function demoAllowlistAction(id: number, patch: Partial<AllowEntry>) {
  const e = demoAllowlist.find((x) => x.id === id);
  if (!e) throw new Error("whitelist entry not found");
  Object.assign(e, patch);
  return e;
}

export async function approveAlertAllowlist(id: number): Promise<AllowEntry> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    return demoAllowlistAction(id, {
      status: "active", approved_by: DEMO_USER.username,
      approved_at: new Date().toISOString(),
    });
  }
  return request(`/api/allowlist/${id}/approve`, { method: "POST" });
}

export async function rejectAlertAllowlist(id: number): Promise<AllowEntry> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    return demoAllowlistAction(id, {
      status: "rejected", approved_by: DEMO_USER.username,
      approved_at: new Date().toISOString(),
    });
  }
  return request(`/api/allowlist/${id}/reject`, { method: "POST" });
}

export async function extendAlertAllowlist(id: number, days: number):
Promise<AllowEntry> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    return demoAllowlistAction(id, {
      status: "active",
      expires_at: new Date(Date.now() + days * 86_400_000).toISOString(),
    });
  }
  return request(`/api/allowlist/${id}/extend`, {
    method: "POST", body: JSON.stringify({ days }),
  });
}

export async function deleteAlertAllowlist(id: number): Promise<void> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    const idx = demoAllowlist.findIndex((x) => x.id === id);
    if (idx >= 0) demoAllowlist.splice(idx, 1);
    return;
  }
  await request(`/api/allowlist/${id}`, { method: "DELETE" });
}

// --------------------------------------------------------------- admin
export async function listSensors(): Promise<SensorRow[]> {
  if (DEMO_MODE) return demoSensors;
  return request<SensorRow[]>("/api/sensors");
}

export async function listUsers(): Promise<UserRow[]> {
  // fresh copies: demoCreateUser mutates the fixture array in place, and
  // identical references would defeat downstream useMemo caching
  if (DEMO_MODE) return demoUsers.map((u) => ({ ...u }));
  return request<UserRow[]>("/api/users");
}

// --- user management CRUD (v0.10; backend: user_admin capability) ---
export async function createUser(input: {
  username: string; role: Role; full_name?: string; password?: string;
}): Promise<UserRow> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoCreateUser({ ...input, actor: DEMO_USER.username });
  }
  return request("/api/users", { method: "POST", body: JSON.stringify(input) });
}

// v0.13.0 (backport fix VM): users are addressed BY USERNAME. The old
// code sent the row UUID to /api/users/{username} -> always 404, masked
// by demo mode. Demo store accepts either id or username.
export async function updateUser(username: string, patch: {
  role?: Role; full_name?: string; is_active?: boolean; new_password?: string;
}): Promise<UserRow> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoUpdateUser(username, patch);
  }
  return request(`/api/users/${encodeURIComponent(username)}`, {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function deleteUser(username: string): Promise<void> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    demoDeleteUser(username, DEMO_USER.username);
    return;
  }
  await request(`/api/users/${encodeURIComponent(username)}`,
                { method: "DELETE" });
}

/**
 * RBAC capability matrix as enforced by the backend (GET /api/roles).
 * Demo mode mirrors api/app/security.py PERMISSIONS.
 */
export async function getRoles(): Promise<RoleMatrix> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return demoRoleMatrix;
  }
  return request<RoleMatrix>("/api/roles");
}

// --- manual asset registry CRUD (v0.10) ---
export async function listAssets(): Promise<RegisteredAsset[]> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return demoAssetRegistry.map((a) => ({ ...a }));
  }
  return request<RegisteredAsset[]>("/api/assets");
}

export async function createAsset(input: {
  ip: string; hostname: string; zone: string; role: string;
  criticality: RegisteredAsset["criticality"]; notes?: string;
}): Promise<RegisteredAsset> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoCreateAsset({ ...input, created_by: DEMO_USER.username });
  }
  return request("/api/assets", { method: "POST", body: JSON.stringify(input) });
}

export async function updateAsset(id: string, patch: {
  hostname?: string; zone?: string; role?: string;
  criticality?: RegisteredAsset["criticality"]; notes?: string;
}): Promise<RegisteredAsset> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoUpdateAsset(id, patch);
  }
  return request(`/api/assets/${encodeURIComponent(id)}`, {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function deleteAsset(id: string): Promise<void> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    demoDeleteAsset(id);
    return;
  }
  await request(`/api/assets/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function listAudit(params?: { action?: string }): Promise<{ total: number; records: AuditRow[] }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    const records = params?.action
      ? demoAudit.filter((r) => r.action === params.action)
      : demoAudit;
    return { total: records.length, records };
  }
  // v0.13.0: request the server cap (500) instead of the old default 100
  const qs = new URLSearchParams();
  if (params?.action) qs.set("action", params.action);
  qs.set("limit", "500");
  return request(`/api/audit?${qs.toString()}`);
}

// --------------------------------------------------------------- threat intelligence (Phase 3)
export async function getThreatIntel(): Promise<ThreatIntelData> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 180));
    return buildThreatIntel();
  }
  const [overview, feeds, jobs, iocs, matchesRaw, allowlist] = await Promise.all([
    request<TIOverview>("/api/ti/overview"),
    request<TIFeed[]>("/api/ti/feeds"),
    request<TIJob[]>("/api/ti/jobs?limit=20"),
    request<{ total: number; items: IocRow[] }>("/api/ti/iocs?limit=500"),
    request<{ total: number; hits: IocMatchRow[] }>("/api/ti/matches?size=200&hours=48"),
    request<AllowRow[]>("/api/ti/allowlist"),
  ]);
  let matches = matchesRaw;
  // v0.13.0 (backport fix VM): the backend returns {id, source} rows -
  // FLATTEN them so the first row is not an empty object in the table.
  // Tolerant of both nested and already-flat shapes.
  const flatHits: IocMatchRow[] = (matches.hits || []).map((h) => {
    const raw = h as unknown as Record<string, unknown>;
    const src = raw.source;
    const row = (src && typeof src === "object"
      ? src as Record<string, unknown> : raw);
    const id = raw.id ?? row.id;
    return { ...row, id } as unknown as IocMatchRow;
  });
  matches = { ...matches, hits: flatHits };
  // derive a 24h match trend client-side from the match hits (hourly buckets)
  const buckets = new Map<string, number>();
  const now = Date.now();
  for (let h = 23; h >= 0; h -= 1) {
    buckets.set(new Date(now - h * 3_600_000).setMinutes(0, 0, 0).toString(), 0);
  }
  matches.hits.forEach((m) => {
    const key = new Date(m["@timestamp"]).setMinutes(0, 0, 0).toString();
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) ?? 0) + 1);
  });
  const match_trend = Array.from(buckets.entries())
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([ts, count]) => ({ ts: new Date(Number(ts)).toISOString(), count }));
  return { overview, feeds, jobs, iocs, matches, allowlist, match_trend };
}

export async function updateFeedNow(feedId: string): Promise<{ job_id: string; status: string }> {
  if (DEMO_MODE) {
    const job = demoTriggerFeedUpdate(feedId);
    return { job_id: job.id, status: job.status };
  }
  return request(`/api/ti/feeds/${feedId}/update`, { method: "POST" });
}

export async function listTiAllowlist(): Promise<AllowRow[]> {
  if (DEMO_MODE) return demoTiAllowlist;
  return request<AllowRow[]>("/api/ti/allowlist");
}

export async function addTiAllowlist(entry: {
  ioc_type: IocRow["ioc_type"]; ioc_value: string; reason: string;
}): Promise<AllowRow> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoAddAllowlist(entry);
  }
  return request("/api/ti/allowlist", { method: "POST", body: JSON.stringify(entry) });
}

export async function removeTiAllowlist(id: number): Promise<void> {
  if (DEMO_MODE) {
    demoRemoveAllowlist(id);
    await new Promise((r) => setTimeout(r, 200));
    return;
  }
  await request(`/api/ti/allowlist/${id}`, { method: "DELETE" });
}

export async function updateTIFeed(feedId: string, patch: {
  enabled?: boolean; schedule_min?: number; ttl_days?: number;
}): Promise<TIFeed> {
  if (DEMO_MODE) {
    const feed = demoTiFeeds.find((f) => f.id === feedId);
    if (!feed) throw new Error("feed not found");
    Object.assign(feed, patch);
    await new Promise((r) => setTimeout(r, 200));
    return feed;
  }
  return request(`/api/ti/feeds/${feedId}`, {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

// --------------------------------------------------------------- incidents (Phase 4)
import {
  buildCampaignDetail, buildCampaignList, buildIncidentDetail,
  buildIncidentList, buildIncidentReportMd, buildIncidentStats,
  demoAddIncidentNote, demoAttachToCampaign, demoCreateCampaign,
  demoDetachFromCampaign, demoReportVersionMd, demoReportVersionsList,
  demoSaveReportVersion, demoUpdateCampaign, demoUpdateIncidentStatus,
} from "./incidents-demo";
import type {
  CampaignDetail, CampaignSummary, IncidentDetail, IncidentStats,
  IncidentSummary, ReportVersionMeta,
} from "./types";
export interface IncidentListFilters {
  status?: string;
  severity?: string;
  q?: string;
  time_from?: string | null;
  time_to?: string | null;
}

export async function getIncidents(
  filters?: IncidentListFilters,
): Promise<{ total: number; items: IncidentSummary[] }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 160));
    return buildIncidentList(filters);
  }
  const params = new URLSearchParams();
  if (filters?.status && filters.status !== "all") params.set("status", filters.status);
  if (filters?.severity && filters.severity !== "all") params.set("severity", filters.severity);
  if (filters?.q) params.set("q", filters.q);
  if (filters?.time_from) params.set("time_from", filters.time_from);
  if (filters?.time_to) params.set("time_to", filters.time_to);
  // v0.13.0: fetch ALL pages (cap 200/req, hard cap 1000) - the old call
  // silently stopped at the first 50, hiding most incidents.
  params.set("size", "200");
  const PAGE = 200, HARD_CAP = 1000;
  const first = await request<{ total: number; items: IncidentSummary[] }>(
    `/api/incidents?${params.toString()}`);
  const all: IncidentSummary[] = [...(first.items ?? [])];
  const total = first.total ?? all.length;
  while (all.length < Math.min(total, HARD_CAP)) {
    params.set("offset", String(all.length));
    const page = await request<{ total: number; items: IncidentSummary[] }>(
      `/api/incidents?${params.toString()}`);
    if (!page.items?.length) break;
    all.push(...page.items);
  }
  return { total, items: all };
}

export async function getIncidentStats(): Promise<IncidentStats> {
  if (DEMO_MODE) return buildIncidentStats();
  return request<IncidentStats>("/api/incidents/summary");
}

export async function getIncidentDetail(id: string): Promise<IncidentDetail> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    const inc = buildIncidentDetail(id);
    if (!inc) throw new Error("incident not found");
    return inc;
  }
  return request<IncidentDetail>(`/api/incidents/${id}`);
}

export async function updateIncidentStatus(
  id: string, status: IncidentDetail["status"], note?: string,
): Promise<void> {
  if (DEMO_MODE) {
    const user = DEMO_USER.username;
    demoUpdateIncidentStatus(id, status, note ?? null, user);
    await new Promise((r) => setTimeout(r, 220));
    return;
  }
  await request(`/api/incidents/${id}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, note: note || null }),
  });
}

export async function addIncidentNote(id: string, body: string): Promise<void> {
  if (DEMO_MODE) {
    demoAddIncidentNote(id, body, DEMO_USER.username);
    await new Promise((r) => setTimeout(r, 200));
    return;
  }
  await request(`/api/incidents/${id}/notes`, {
    method: "POST", body: JSON.stringify({ body }),
  });
}

export async function getIncidentReport(id: string): Promise<string> {
  if (DEMO_MODE) {
    const inc = buildIncidentDetail(id);
    if (!inc) throw new Error("incident not found");
    return buildIncidentReportMd(inc);
  }
  const res = await fetch(`${API_BASE}/api/incidents/${id}/report`, {
    credentials: "include",
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

// --------------------------------------------------------------- campaigns (v0.12)
export async function getCampaigns(params?: {
  status?: string; q?: string;
}): Promise<{ total: number; items: CampaignSummary[] }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    return buildCampaignList(params);
  }
  const p = new URLSearchParams();
  if (params?.status && params.status !== "all") p.set("status", params.status);
  if (params?.q) p.set("q", params.q);
  // v0.13.0: loop-fetch all pages (cap 200/req, hard cap 1000)
  p.set("size", "200");
  const first = await request<{ total: number; items: CampaignSummary[] }>(
    `/api/campaigns?${p.toString()}`);
  const all: CampaignSummary[] = [...(first.items ?? [])];
  const total = first.total ?? all.length;
  while (all.length < Math.min(total, 1000)) {
    p.set("offset", String(all.length));
    const page = await request<{ total: number; items: CampaignSummary[] }>(
      `/api/campaigns?${p.toString()}`);
    if (!page.items?.length) break;
    all.push(...page.items);
  }
  return { total, items: all };
}

export async function getCampaignDetail(id: string): Promise<CampaignDetail> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 180));
    const c = buildCampaignDetail(id);
    if (!c) throw new Error("campaign not found");
    return c;
  }
  return request<CampaignDetail>(`/api/campaigns/${id}`);
}

export async function createCampaign(
  title: string, description: string, incidentIds: string[],
): Promise<CampaignSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    return demoCreateCampaign(title, description, incidentIds,
      DEMO_USER.username);
  }
  return request<CampaignSummary>("/api/campaigns", {
    method: "POST",
    body: JSON.stringify({ title, description, incident_ids: incidentIds }),
  });
}

export async function attachToCampaign(
  campaignId: string, incidentIds: string[],
): Promise<CampaignSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    const c = demoAttachToCampaign(campaignId, incidentIds,
      DEMO_USER.username);
    if (!c) throw new Error("campaign not found");
    return c;
  }
  return request<CampaignSummary>(`/api/campaigns/${campaignId}/incidents`, {
    method: "POST", body: JSON.stringify({ incident_ids: incidentIds }),
  });
}

export async function detachFromCampaign(
  campaignId: string, incidentId: string,
): Promise<CampaignSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 200));
    const c = demoDetachFromCampaign(campaignId, incidentId,
      DEMO_USER.username);
    if (!c) throw new Error("incident is not a member of this campaign");
    return c;
  }
  return request<CampaignSummary>(
    `/api/campaigns/${campaignId}/incidents/${incidentId}`, {
      method: "DELETE",
    });
}

export async function updateCampaign(
  campaignId: string,
  patch: { title?: string; description?: string; status?: string },
): Promise<CampaignSummary> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 180));
    const c = demoUpdateCampaign(campaignId, patch, DEMO_USER.username);
    if (!c) throw new Error("campaign not found");
    return c;
  }
  return request<CampaignSummary>(`/api/campaigns/${campaignId}`, {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

// ------------------------------------------------ report versions (v0.12)
export async function saveReportVersion(
  id: string,
): Promise<ReportVersionMeta> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoSaveReportVersion(id, DEMO_USER.username);
  }
  return request<ReportVersionMeta>(`/api/incidents/${id}/reports`, {
    method: "POST",
  });
}

export async function getReportVersions(
  id: string,
): Promise<{ items: ReportVersionMeta[]; total: number }> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return demoReportVersionsList(id);
  }
  return request(`/api/incidents/${id}/reports`);
}

export async function getReportVersionMd(
  id: string, version: number,
): Promise<string> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    const md = demoReportVersionMd(id, version);
    if (md === null) throw new Error("report version not found");
    return md;
  }
  const res = await fetch(
    `${API_BASE}/api/incidents/${id}/reports/${version}`, {
      credentials: "include",
    });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

// --------------------------------------------------------------- threat map graph (Phase 5)
import {
  buildEntityPivot, buildGeoBundle, buildRelationshipGraph,
} from "./graph-demo";
import type {
  EntityPivot, GeoBundle, RelationshipGraph,
} from "./types";

export interface GraphFilters {
  status?: string;
  severity_min?: string;
  q?: string;
  limit?: number;
}

export async function getRelationshipGraph(
  filters?: GraphFilters,
): Promise<RelationshipGraph> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 180));
    return buildRelationshipGraph();
  }
  const params = new URLSearchParams();
  if (filters?.status) params.set("status", filters.status);
  if (filters?.severity_min) params.set("severity_min", filters.severity_min);
  if (filters?.q) params.set("q", filters.q);
  if (filters?.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  return request(`/api/graph/relationships${qs ? `?${qs}` : ""}`);
}

export async function getGeoMap(hours = 24): Promise<GeoBundle> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 150));
    return buildGeoBundle();
  }
  return request<GeoBundle>(`/api/graph/geo?hours=${hours}`);
}

export async function getEntityPivot(
  key: string, hours = 48,
): Promise<EntityPivot> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 160));
    const pivot = buildEntityPivot(key);
    if (!pivot) throw new Error("entity not found in any reconstructed campaign");
    return pivot;
  }
  return request<EntityPivot>(
    `/api/graph/entity/${encodeURIComponent(key)}?hours=${hours}`);
}

// --------------------------------------------------------------- rule manager (Phase 6)
export async function getRulesSummary(): Promise<RulesSummary> {
  if (DEMO_MODE) return demoRulesSummary;
  return request<RulesSummary>("/api/rules/summary");
}

// v0.16.1 (P1-3): status ringan ruleset+sensor (tanpa parsing 45 MB) -
// sumber KPI kartu Rule Manager, tetap hidup walau parsing lambat/500.
export async function getRulesStatus(): Promise<RulesStatus | null> {
  if (DEMO_MODE) return null;
  try {
    return await request<RulesStatus>("/api/rules/status");
  } catch {
    return null;  // degrade: UI menampilkan "tidak diketahui", bukan klaim
  }
}

export async function listRules(params?: {
  q?: string; category?: string; status?: "all" | "enabled" | "disabled";
  source?: "all" | "local" | "suricata";
  limit?: number; offset?: number;
}): Promise<RulesList> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    let items = [...demoRules];
    if (params?.q) {
      const n = params.q.toLowerCase();
      items = items.filter((r) =>
        (r.msg ?? "").toLowerCase().includes(n) ||
        String(r.sid).includes(n) ||
        (r.classtype ?? "").toLowerCase().includes(n));
    }
    if (params?.category) {
      items = items.filter((r) => (r.classtype ?? "unclassified") === params.category);
    }
    if (params?.status && params.status !== "all") {
      items = items.filter((r) => r.enabled === (params.status === "enabled"));
    }
    // v0.12.7: source filter mirrors the backend taxonomy
    if (params?.source && params.source !== "all") {
      items = items.filter((r) => (r.source ?? (r.custom ? "local" : "suricata")) === params.source);
    }
    return {
      total: items.length, skipped_lines: 0,
      rules_file_updated: demoRulesSummary.rules_file_updated,
      items: items.slice(params?.offset ?? 0, (params?.offset ?? 0) + (params?.limit ?? 100)),
    };
  }
  const qs = new URLSearchParams();
  if (params?.q) qs.set("q", params.q);
  if (params?.category) qs.set("category", params.category);
  if (params?.status) qs.set("status", params.status);
  // v0.12.7: rule source filter (local | suricata)
  if (params?.source) qs.set("source", params.source);
  qs.set("limit", String(params?.limit ?? 100));
  qs.set("offset", String(params?.offset ?? 0));
  return request<RulesList>(`/api/rules?${qs.toString()}`);
}

// v0.12.7: Zeek policy inventory (Rule Manager "Zeek" tab, read-only)
export async function listZeekRules(): Promise<ZeekScriptList> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 100));
    return demoZeekScripts;
  }
  return request<ZeekScriptList>("/api/rules/zeek");
}

export async function toggleRule(sid: number, enabled: boolean, username: string): Promise<RuleToggleResult> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    demoToggleRule(sid, enabled, username);
    return { sid, enabled, update_ok: true,
             reloaded: DEMO_MODE ? true : false,
             reload_detail: "live reload simulated (demo)",
             error: null };
  }
  // v0.13.0 (B3): ask for the ASYNC job (wait=0) and poll progress -
  // suricata-update + live reload can take minutes; the old UI spun for
  // the whole time with no feedback and could hit client timeouts.
  const start = await request<{ job_id?: string }>(`/api/rules/${sid}/toggle`, {
    method: "POST", body: JSON.stringify({ enabled }),
  }).catch(async (e) => {
    // very old backends answered synchronously without wait param support
    if (String(e).includes("wait")) {
      return request<{ job_id?: string }>(`/api/rules/${sid}/toggle?wait=1`, {
        method: "POST", body: JSON.stringify({ enabled }),
      });
    }
    throw e;
  });
  if (!start?.job_id) {
    return start as unknown as RuleToggleResult;
  }
  for (let i = 0; i < 90; i += 1) {
    await new Promise((r) => setTimeout(r, 1000));
    const job = await request<{ status: string; result?: RuleToggleResult;
                                error?: string }>(
      `/api/rules/jobs/${start.job_id}`).catch(() => null);
    if (!job) continue;
    if (job.status === "done" && job.result) return job.result;
    if (job.status === "failed") {
      return { sid, enabled, update_ok: false, reloaded: false,
               reload_detail: "", error: job.error ?? "toggle job failed" };
    }
  }
  // job still running after 90s: report honestly, rule state is
  // authoritative on the next list refresh
  return { sid, enabled, update_ok: true, reloaded: false,
           reload_detail: "still applying in the background (poll timed out)",
           error: null };
}

export async function updateRulesNow(): Promise<RulesUpdateResult> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 700));
    return { ok: true, reloaded: true,
             output: "suricata-update (demo): 3 new rules, 1 modified.\nLoaded 30 rules - fully initialized, is ready",
             error: null, reload_detail: "live reload simulated (demo)",
             rules_loaded: demoRules.length,
             rules_file_updated: new Date().toISOString() };
  }
  return request("/api/rules/update", { method: "POST" });
}

// ------------------------- custom rule editor (v0.11) ----------------------
export async function validateRuleText(ruleText: string): Promise<RuleValidateResult> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return demoValidateRuleText(ruleText);
  }
  return request("/api/rules/validate", {
    method: "POST", body: JSON.stringify({ rule_text: ruleText }),
  });
}

export async function createCustomRule(input: {
  rule_text: string; enabled?: boolean; sid?: number | null;
}): Promise<RuleRow> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 300));
    return demoCreateCustomRule({
      ...input, enabled: input.enabled ?? true,
      created_by: DEMO_USER.username,
    });
  }
  return request("/api/rules/custom", {
    method: "POST", body: JSON.stringify(input),
  });
}

export async function updateCustomRule(sid: number, patch: {
  rule_text?: string; enabled?: boolean;
}): Promise<RuleRow> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 280));
    return demoUpdateCustomRule(sid, patch, DEMO_USER.username);
  }
  return request(`/api/rules/custom/${sid}`, {
    method: "PUT", body: JSON.stringify(patch),
  });
}

export async function deleteCustomRule(sid: number): Promise<void> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 220));
    demoDeleteCustomRule(sid);
    return;
  }
  await request(`/api/rules/custom/${sid}`, { method: "DELETE" });
}

// ------------------------- TI feed creation + adapters (v0.11) -------------
export async function createTIFeed(input: {
  name: string; adapter: TIFeed["adapter"]; url?: string | null;
  enabled?: boolean; schedule_min?: number; ttl_days?: number;
  config?: Record<string, unknown>;
}): Promise<TIFeed> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 300));
    return demoCreateFeed(input);
  }
  return request("/api/ti/feeds", {
    method: "POST", body: JSON.stringify(input),
  });
}

// ------------------------------- system settings (v0.11) -------------------
export async function getSettings(): Promise<SystemSettings> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return JSON.parse(JSON.stringify(demoSettings)) as SystemSettings;
  }
  return request<SystemSettings>("/api/settings");
}

export async function patchSystemName(patch: {
  name?: string; tagline?: string;
}): Promise<SystemSettings["system"]> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoPatchSystem(patch);
  }
  return request("/api/settings/system", {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function patchBranding(patch: {
  logo_data_url?: string; favicon_data_url?: string;
  reset_logo?: boolean; reset_favicon?: boolean;
}): Promise<SystemSettings["branding"]> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoPatchBranding(patch);
  }
  return request("/api/settings/branding", {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function patchNtp(patch: {
  servers?: string[]; timezone?: string; enabled?: boolean;
}): Promise<SystemSettings["ntp"]> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 250));
    return demoPatchNtp(patch);
  }
  return request("/api/settings/ntp", {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function getNtpStatus(): Promise<{
  available: boolean; tool: string | null; output: string;
  first_server_resolvable?: boolean; config: SystemSettings["ntp"];
}> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 400));
    return demoNtpStatus();
  }
  return request("/api/settings/ntp/status", { method: "POST" });
}

export async function getNetworkInfo(): Promise<NetworkConfig> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 120));
    return JSON.parse(JSON.stringify(demoSettings.network)) as NetworkConfig;
  }
  return request("/api/settings/network");
}

export async function patchNetwork(patch: {
  hostname?: string; dns_servers?: string[];
}): Promise<NetworkConfig> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 300));
    return demoPatchNetwork(patch);
  }
  return request("/api/settings/network", {
    method: "PATCH", body: JSON.stringify(patch),
  });
}

export async function runDiagnosis(body: {
  tool: DiagnoseTool; target: string; count?: number; port?: number | null;
}): Promise<DiagnoseResult> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 500));
    return demoDiagnose(body.tool, body.target, body.count ?? 4, body.port ?? null);
  }
  return request("/api/settings/diagnosis", {
    method: "POST", body: JSON.stringify(body),
  });
}

// ------------------- PCAP & evidence workflow (doc section 15) ------------
export async function getAlertSessions(alertId: string): Promise<EvidenceSessions> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 350));
    return demoEvidenceSessions("alert", alertId);
  }
  return request(`/api/evidence/alerts/${encodeURIComponent(alertId)}/sessions`);
}

export async function getIncidentSessions(incidentId: string): Promise<EvidenceSessions> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 350));
    return demoEvidenceSessions("incident", incidentId);
  }
  return request(`/api/evidence/incidents/${encodeURIComponent(incidentId)}/sessions`);
}

export async function getPcapStorage(): Promise<PcapCoverage> {
  if (DEMO_MODE) return demoPcapStorage();
  return request("/api/evidence/pcap/storage");
}

export async function listPcapExports(): Promise<PcapExportsList> {
  if (DEMO_MODE) return demoPcapExports();
  return request("/api/evidence/pcap/exports");
}

export async function createPcapExport(body: PcapExportCreate): Promise<PcapExportRecord> {
  if (DEMO_MODE) {
    await new Promise((r) => setTimeout(r, 900));
    return demoPcapExportCreate(body);
  }
  return request("/api/evidence/pcap/export", {
    method: "POST", body: JSON.stringify(body),
  });
}

export function pcapExportDownloadUrl(exportId: string): string {
  return `${API_BASE}/api/evidence/pcap/exports/${encodeURIComponent(exportId)}/download`;
}

// ==================================================================== v0.16.0
// R6: export alert xlsx/csv (window WAJIB; backend cap EXPORT_MAX_ROWS).
// Mengembalikan blob untuk di-download sebagai file.
export async function exportAlerts(body: ExportAlertBody): Promise<Blob> {
  const res = await fetch(`${API_BASE}/api/alerts/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).detail ?? ""; } catch { /* noop */ }
    throw new Error(detail || `export failed (${res.status})`);
  }
  return res.blob();
}

// R7: DNS explorer
export async function getDnsExplorerSummary(hours = 24): Promise<DnsSummary> {
  return request<DnsSummary>(`/api/dns/summary?hours=${hours}`);
}

export async function searchDns(body: {
  time_from?: string; time_to?: string;
  query?: Record<string, unknown>; filter?: FilterAst;
  size?: number; from?: number;
}): Promise<{ total: number; hits: DnsHit[] }> {
  return request("/api/dns/search", {
    method: "POST",
    body: JSON.stringify({ index: "ndr-zeek-dns-read", ...body }),
  });
}

// R9: TLS insights
export async function getTlsSummary(hours = 24): Promise<TlsSummary> {
  return request<TlsSummary>(`/api/tls/summary?hours=${hours}`);
}

// R18: Judi Online
export async function getGamblingSummary(hours = 24): Promise<GamblingSummary> {
  return request<GamblingSummary>(`/api/gambling/summary?hours=${hours}`);
}

export async function getGamblingEvents(hours = 24, size = 100): Promise<{
  total: number; hits: EventDoc[];
}> {
  return request(`/api/gambling/events?hours=${hours}&size=${size}`);
}

// R14+15: rule hit statistics
export async function getRuleStats(refresh = false): Promise<RuleStatsList> {
  return request<RuleStatsList>(`/api/rules/stats${refresh ? "?refresh=1" : ""}`);
}

// R5: search alerts dengan filter DSL AST (di luar preset lama)
export async function searchAlertsDsl(body: {
  time_from?: string; time_to?: string;
  query?: Record<string, unknown>;
  filter?: FilterAst;
  size?: number; from?: number;
  sort?: unknown[];
}): Promise<{ total: number; relation?: string; hits: { id: string; source: AlertDoc }[] }> {
  return request("/api/alerts/search", {
    method: "POST",
    body: JSON.stringify({ index: "ndr-alerts-read", ...body }),
  });
}
