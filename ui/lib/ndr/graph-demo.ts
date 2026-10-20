// Threat-map demo engine (Phase 5).
//
// Mirrors the backend graph service (api/app/graph.py) on top of the
// demo incidents: entity aggregation across campaigns, cross-campaign
// correlation on SHARED CHECKABLE INFRASTRUCTURE ONLY (never time
// proximity), blast radius BFS, and a geographic bundle. RFC 5737 /
// .test values throughout.

import type {
  AttackPhase, BlastRadius, BlastRadiusEntry, EntityPivot, GeoBundle,
  GeoFlowV2, GraphCampaign, GraphEdge, GraphNode, RelationshipGraph,
  Severity,
} from "./types";
import { demoIncidents } from "./incidents-demo";
import { demoExternals, demoFlows } from "./demo";

const CORRELATION_ROLES = new Set([
  "c2_infra", "payload", "delivery_infra", "exfil_target",
]);

const SEV_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, informational: 0,
}

// kill-chain order for phase comparison (mirrors pipeline taxonomy)
const PHASE_RANK: Record<string, number> = {
  unknown: -1, recon: 0, initial_access: 1, delivery: 2,
  c2: 3, lateral: 4, impact: 5,
};

function isInternalIp(ip: string | null | undefined): boolean | null {
  if (!ip) return null;
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fc|fd|fe80)/
    .test(ip);
}

// ---------------------------------------------------------------- graph

function isoMin(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return a < b ? a : b;
}

function isoMax(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return a > b ? a : b;
}

class DemoGraph {
  nodes = new Map<string, GraphNode>();
  edges = new Map<string, GraphEdge>();
  campaigns = new Map<string, GraphCampaign>();

  addNode(key: string, incidentId: string, patch?: Partial<GraphNode>) {
    let n = this.nodes.get(key);
    if (!n) {
      const kind = key.split(":")[0] as GraphNode["kind"];
      n = {
        key, kind, label: key.split(":").slice(1).join(":") || key,
        roles: [], phase: "unknown", confidence: 50, first_seen: null,
        last_seen: null, evidence_count: 0, incident_ids: [],
        ti_match: false, attrs: {}, internal:
          kind === "ip" ? isInternalIp(key.slice(3)) : null,
        degree: 0,
      };
      this.nodes.set(key, n);
    }
    if (patch) {
      if (patch.roles) {
        patch.roles.forEach((r) => {
          if (!n!.roles.includes(r)) n!.roles.push(r);
        });
      }
      if (patch.phase
          && (PHASE_RANK[patch.phase] ?? -1)
            > (PHASE_RANK[n.phase] ?? -1)) n.phase = patch.phase;
      n.confidence = Math.max(n.confidence, patch.confidence ?? 0);
      n.first_seen = isoMin(n.first_seen, patch.first_seen ?? null);
      n.last_seen = isoMax(n.last_seen, patch.last_seen ?? null);
      n.ti_match = n.ti_match || !!patch.ti_match;
      if (patch.attrs) {
        Object.entries(patch.attrs).forEach(([k, v]) => {
          if (v !== null && v !== undefined) n!.attrs[k] = n!.attrs[k] ?? v;
        });
      }
    }
    n.evidence_count += 1;
    if (!n.incident_ids.includes(incidentId)) {
      n.incident_ids.push(incidentId);
    }
    return n;
  }

  addEdge(e: Omit<GraphEdge, "incident_ids" | "reasons">,
          incidentId: string) {
    const k = `${e.src}|${e.dst}|${e.relation}`;
    let edge = this.edges.get(k);
    const reason = e.inferred
      ? `inferred from entity/temporal context (${e.relation}, campaign ${incidentId})`
      : `observed ${e.relation} events in campaign ${incidentId}`;
    if (!edge) {
      edge = { ...e, incident_ids: [], reasons: [] };
      this.edges.set(k, edge);
      for (const key of [e.src, e.dst]) {
        const n = this.nodes.get(key);
        if (n) n.degree += 1;
      }
    } else {
      edge.evidence_count += e.evidence_count;
      edge.confidence = Math.max(edge.confidence, e.confidence);
      edge.first_seen = isoMin(edge.first_seen, e.first_seen);
      edge.last_seen = isoMax(edge.last_seen, e.last_seen);
      if (e.inferred) edge.inferred = true;
    }
    if (!edge.incident_ids.includes(incidentId)) {
      edge.incident_ids.push(incidentId);
    }
    if (!edge.reasons.includes(reason)) edge.reasons.push(reason);
    return edge;
  }

  addCampaign(id: string, nodeKeys: string[]) {
    const inc = demoIncidents.find((i) => i.id === id);
    if (!inc) return;
    this.campaigns.set(id, {
      id, title: inc.title, status: inc.status, severity: inc.severity,
      confidence: inc.confidence, first_seen: inc.first_seen,
      last_seen: inc.last_seen, outcome_label: inc.outcome_label,
      node_keys: nodeKeys, analyst: inc.analyst ?? null,
    });
  }

  linked(a: string, b: string): boolean {
    for (const e of this.edges.values()) {
      if ((e.src === a && e.dst === b) || (e.src === b && e.dst === a)) {
        return true;
      }
    }
    return false;
  }

  principal(campaignId: string): string | null {
    const cands = [...this.nodes.values()].filter(
      (n) => n.incident_ids.includes(campaignId)
        && (n.roles.includes("attacker")
          || n.roles.includes("compromised_host")));
    if (!cands.length) return null;
    const attackers = cands.filter((n) => n.roles.includes("attacker"));
    const pool = attackers.length ? attackers : cands;
    return pool.reduce((best, n) =>
      (n.evidence_count * 100 + n.confidence
        > best.evidence_count * 100 + best.confidence ? n : best)).key;
  }

  crossCorrelate(): void {
    const shared: Array<[string, string[]]> = [];
    for (const n of this.nodes.values()) {
      if (n.incident_ids.length < 2) continue;
      if (n.ti_match || n.roles.some((r) => CORRELATION_ROLES.has(r))) {
        shared.push([n.key, n.incident_ids]);
      }
    }
    for (const [sharedKey, incIds] of shared) {
      const node = this.nodes.get(sharedKey)!;
      const perCampaign = new Map<string, string[]>();
      for (const e of this.edges.values()) {
        if (e.relation === "correlated_with") continue;
        let other: string | null = null;
        if (e.dst === sharedKey) other = e.src;
        else if (e.src === sharedKey && e.relation === "resolved_to") {
          other = e.dst;
        }
        if (!other || !this.nodes.has(other)) continue;
        if (e.inferred && e.relation !== "resolved_to"
            && e.relation !== "queried") continue;
        for (const iid of e.incident_ids) {
          if (!incIds.includes(iid)) continue;
          const members = perCampaign.get(iid) ?? [];
          if (!members.includes(other)) members.push(other);
          perCampaign.set(iid, members);
        }
      }
      const campaigns = [...perCampaign.keys()].sort();
      const baseReason = `shared ${node.kind} infrastructure: `
        + `${node.label}${node.ti_match ? " (TI-matched)" : ""}`;
      for (let a = 0; a < campaigns.length; a++) {
        for (let b = a + 1; b < campaigns.length; b++) {
          const ia = campaigns[a], ib = campaigns[b];
          const done = new Set<string>();
          for (const l of (perCampaign.get(ia) ?? []).slice(0, 3)) {
            for (const r of (perCampaign.get(ib) ?? []).slice(0, 3)) {
              if (l === r || this.linked(l, r)) continue;
              done.add(`${l}|${r}`);
              this.addCorrEdge(l, r, sharedKey, [ia, ib],
                `${baseReason} - both entities have evidence-backed links to it`);
            }
          }
          const pa = this.principal(ia), pb = this.principal(ib);
          if (pa && pb && pa !== pb && !done.has(`${pa}|${pb}`)
              && !this.linked(pa, pb)) {
            this.addCorrEdge(pa, pb, sharedKey, [ia, ib],
              `${baseReason} - their campaigns ${ia} and ${ib} both link to it`);
          }
        }
      }
    }
  }

  addCorrEdge(left: string, right: string, sharedKey: string,
              incIds: string[], reason: string) {
    const node = this.nodes.get(sharedKey)!;
    const l = this.nodes.get(left)!, r = this.nodes.get(right)!;
    this.edges.set(`${left}|${right}|correlated_with`, {
      src: left, dst: right, relation: "correlated_with",
      phase: node.phase, inferred: true, first_seen: node.first_seen,
      last_seen: node.last_seen, evidence_count: 2,
      confidence: Math.min(90, Math.min(l.confidence, r.confidence) + 5),
      incident_ids: incIds, reasons: [reason],
    });
    l.degree += 1;
    r.degree += 1;
  }
}

function buildGraphInternal(includeAllStatuses = false): DemoGraph {
  const g = new DemoGraph();
  // mirror the API status filters: relationships uses open+confirmed,
  // the entity pivot searches across all statuses
  const included = includeAllStatuses ? demoIncidents
    : demoIncidents.filter(
      (i) => i.status === "open" || i.status === "confirmed");
  for (const inc of included) {
    for (const n of inc.nodes) {
      g.addNode(n.key, inc.id, {
        roles: n.role ? [n.role] : [], phase: n.phase ?? "unknown",
        confidence: n.confidence ?? 50, first_seen: n.first_seen ?? null,
        last_seen: n.last_seen ?? null, ti_match:
          !!(n.attrs as { ti_match?: boolean } | undefined)?.ti_match,
        attrs: (n.attrs ?? {}) as Record<string, unknown>,
      });
    }
    const touched = new Set(inc.nodes.map((n) => n.key));
    for (const e of inc.edges) {
      for (const endpoint of [e.src, e.dst]) {
        if (!g.nodes.has(endpoint)) {
          g.addNode(endpoint, inc.id);
          touched.add(endpoint);
        } else {
          const n = g.nodes.get(endpoint)!;
          if (!n.incident_ids.includes(inc.id)) {
            n.incident_ids.push(inc.id);
            touched.add(endpoint);
          }
        }
      }
      g.addEdge({
        src: e.src, dst: e.dst, relation: e.relation,
        phase: (e.phase ?? "unknown") as AttackPhase,
        inferred: !!e.inferred, first_seen: e.first_seen ?? null,
        last_seen: e.last_seen ?? null,
        evidence_count: e.evidence_count ?? 1,
        confidence: e.confidence ?? 50,
      }, inc.id);
    }
    g.addCampaign(inc.id, [...touched]);
  }
  g.crossCorrelate();
  return g;
}

export function buildRelationshipGraph(): RelationshipGraph {
  const g = buildGraphInternal();
  const nodes = [...g.nodes.values()].sort(
    (a, b) => b.evidence_count - a.evidence_count || a.key.localeCompare(b.key));
  const edges = [...g.edges.values()].sort(
    (a, b) => b.evidence_count - a.evidence_count
      || a.src.localeCompare(b.src) || a.dst.localeCompare(b.dst));
  const campaigns = [...g.campaigns.values()].sort(
    (a, b) => b.confidence - a.confidence || a.id.localeCompare(b.id));
  return {
    nodes, edges, campaigns,
    meta: {
      generated_at: new Date().toISOString(),
      node_count: nodes.length,
      edge_count: edges.length,
      campaign_count: campaigns.length,
      basis: "merged reconstructed incidents (evidence-backed); solid "
        + "edges = observed relations, dashed = inferred from "
        + "entity/temporal context; cross-campaign links exist only on "
        + "shared checkable infrastructure",
      disclaimer: "Graph relationships are correlations with cited "
        + "evidence, not proof of compromise.",
    },
  };
}

// ---------------------------------------------------------------- pivot

function blastRadius(g: DemoGraph, root: string, maxHops = 2): BlastRadius {
  const adjacency = new Map<string, Array<{ peer: string; e: GraphEdge }>>();
  for (const e of g.edges.values()) {
    if (!adjacency.has(e.src)) adjacency.set(e.src, []);
    if (!adjacency.has(e.dst)) adjacency.set(e.dst, []);
    adjacency.get(e.src)!.push({ peer: e.dst, e });
    adjacency.get(e.dst)!.push({ peer: e.src, e });
  }
  const direct: BlastRadiusEntry[] = [];
  const indirect: BlastRadiusEntry[] = [];
  const seen = new Set([root]);
  let frontier: Array<{ key: string; path: string[]; observed: boolean }> = [
    { key: root, path: [], observed: true },
  ];
  for (let hop = 1; hop <= maxHops; hop++) {
    const next: typeof frontier = [];
    for (const cur of frontier) {
      for (const { peer, e } of adjacency.get(cur.key) ?? []) {
        if (seen.has(peer)) continue;
        seen.add(peer);
        const observed = cur.observed && !e.inferred;
        const n = g.nodes.get(peer);
        const entry: BlastRadiusEntry = {
          key: peer,
          label: n?.label ?? peer,
          kind: n?.kind ?? "ioc",
          internal: n?.internal ?? null,
          phase: n?.phase ?? "unknown",
          confidence: n?.confidence ?? 50,
          hop, via: cur.path.slice(1),
          relation: e.relation, observed_path: observed,
          reasons: e.reasons.slice(0, 2),
        };
        (observed ? direct : indirect).push(entry);
        next.push({ key: peer, path: [...cur.path, cur.key], observed });
      }
    }
    frontier = next;
  }
  return {
    root, direct, indirect,
    internal_hosts: [...direct, ...indirect].filter(
      (e) => e.internal && e.kind === "ip"),
  };
}

const DEMO_PIVOT_ALERTS: Record<string, Array<{ title: string; severity: string; alert_type?: string; last_seen?: string; source_ip?: string; destination_ip?: string }>> = {
  "ip:203.0.113.25": [
    { title: "Port scan suspected from 203.0.113.25", severity: "medium", alert_type: "portscan_suspected", last_seen: "2026-10-12T10:00:08Z", source_ip: "203.0.113.25", destination_ip: "10.0.20.15" },
    { title: "Suricata: ET WEB_SERVER Exploit Request", severity: "high", alert_type: "suricata_alert_group", last_seen: "2026-10-12T10:00:10Z", source_ip: "203.0.113.25", destination_ip: "10.0.20.15" },
  ],
  "domain:update-checkserve.net": [
    { title: "IOC match: update-checkserve.net (CobaltStrike-demo infra)", severity: "high", alert_type: "ioc_match", last_seen: "2026-10-12T10:04:55Z" },
  ],
};

const DEMO_PIVOT_EVENTS: Record<string, Array<Record<string, unknown>>> = {
  "ip:203.0.113.25": [
    { "@timestamp": "2026-10-12T10:00:01Z", event_type: "conn", source_engine: "zeek", source_ip: "203.0.113.25", destination_ip: "10.0.20.15", destination_port: 8080, network_transport: "tcp", network_bytes: 4210, session_id: "CfXy1Z2abC01" },
    { "@timestamp": "2026-10-12T10:00:08Z", event_type: "http", source_engine: "zeek", source_ip: "203.0.113.25", destination_ip: "10.0.20.15", destination_port: 8080, http_host: "web-prod-02.internal", network_transport: "tcp", session_id: "CfXy1Z2abC02" },
    { "@timestamp": "2026-10-12T10:00:52Z", event_type: "fileinfo", source_engine: "suricata", source_ip: "203.0.113.25", destination_ip: "10.0.20.15", network_transport: "tcp", network_bytes: 412672, session_id: "CfXy1Z2abC03" },
  ],
  "ip:10.0.20.15": [
    { "@timestamp": "2026-10-12T10:01:40Z", event_type: "tls", source_engine: "zeek", source_ip: "10.0.20.15", destination_ip: "198.51.100.77", destination_port: 443, tls_sni: "update-checkserve.net", network_transport: "tcp", network_bytes: 88_412, session_id: "CfXy1Z2abC07" },
    { "@timestamp": "2026-10-12T10:02:30Z", event_type: "conn", source_engine: "zeek", source_ip: "10.0.20.15", destination_ip: "10.0.20.31", destination_port: 445, network_transport: "tcp", network_bytes: 12_640, session_id: "CfXy1Z2abC11" },
  ],
};

export function buildEntityPivot(key: string): EntityPivot | null {
  const g = buildGraphInternal(true);
  const entity = g.nodes.get(key);
  if (!entity) return null;
  const related = [...g.edges.values()]
    .filter((e) => e.src === key || e.dst === key)
    .map((e) => {
      const peerKey = e.src === key ? e.dst : e.src;
      const peer = g.nodes.get(peerKey);
      return {
        direction: (e.src === key ? "out" : "in") as "in" | "out",
        peer_key: peerKey,
        peer_label: peer?.label ?? peerKey,
        peer_kind: peer?.kind ?? null,
        relation: e.relation, inferred: e.inferred,
        evidence_count: e.evidence_count, confidence: e.confidence,
        reasons: e.reasons, incident_ids: e.incident_ids,
      };
    })
    .sort((a, b) => b.evidence_count - a.evidence_count
      || a.peer_key.localeCompare(b.peer_key));
  const campaigns = [...g.campaigns.values()].filter(
    (c) => c.node_keys.includes(key));
  return {
    entity, related, campaigns, blast_radius: blastRadius(g, key),
    alerts: DEMO_PIVOT_ALERTS[key]?.map((a) => ({
      ...a, index: "ndr-alerts-2026.10.12",
      alert_id: a.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 48),
    })) ?? [],
    events_sample: DEMO_PIVOT_EVENTS[key]?.map((e) => ({
      ...e, index: "ndr-zeek-2026.10.12",
      doc_id: `demo-${key.replace(/[^a-z0-9]+/gi, "-")}-${String(e["@timestamp"])}`,
    })) as EntityPivot["events_sample"] ?? [],
    disclaimer: "Relationships are evidence-backed correlations, not "
      + "proof of compromise. Verify via the referenced incidents and "
      + "alerts.",
  };
}

// ---------------------------------------------------------------- geo

// Campaign-relevant flow pairs that mirror the flagship / secondary
// chains (the generic demo flows come from demo.ts FLOW_PAIRS).
const CAMPAIGN_FLOWS: Array<{
  external_ip: string; internal_ip: string; direction: "inbound" | "outbound";
  bytes: number; conns: number; ioc_hits: number; alert_hits: number;
  last_seen: string; geo: GeoFlowV2["geo"];
}> = [
  { external_ip: "203.0.113.25", internal_ip: "10.0.20.15", direction: "inbound", bytes: 14_620_000, conns: 149, ioc_hits: 0, alert_hits: 3, last_seen: "2026-10-12T10:00:52Z", geo: { country: "United States", lat: 32.77, lon: -96.79, asn_org: "AS20473 Vultr" } },
  { external_ip: "198.51.100.77", internal_ip: "10.0.20.15", direction: "outbound", bytes: 41_800_000, conns: 23, ioc_hits: 3, alert_hits: 1, last_seen: "2026-10-12T10:04:40Z", geo: null },
  { external_ip: "198.51.100.77", internal_ip: "10.0.10.45", direction: "outbound", bytes: 9_240_000, conns: 19, ioc_hits: 3, alert_hits: 1, last_seen: "2026-10-12T10:04:55Z", geo: null },
  { external_ip: "198.51.100.120", internal_ip: "10.0.20.15", direction: "outbound", bytes: 2_310_000_000, conns: 14, ioc_hits: 0, alert_hits: 1, last_seen: "2026-10-12T10:05:00Z", geo: null },
  { external_ip: "45.155.204.10", internal_ip: "10.0.10.12", direction: "inbound", bytes: 310_000, conns: 310, ioc_hits: 0, alert_hits: 2, last_seen: "2026-10-12T06:22:01Z", geo: { country: "Russia", lat: 59.93, lon: 30.33, asn_org: "AS210644 AEZA" } },
  { external_ip: "198.51.100.205", internal_ip: "10.0.10.77", direction: "outbound", bytes: 2_140_000, conns: 31, ioc_hits: 0, alert_hits: 1, last_seen: "2026-10-12T04:03:30Z", geo: null },
];

export function buildGeoBundle(): GeoBundle {
  const byExternal = new Map(demoExternals.map((e) => [e.ip, e]));
  const flows: GeoFlowV2[] = [];
  const unmapped = new Map<string, { ip: string; reason: string; conns: number }>();

  const pushFlow = (f: GeoFlowV2) => {
    if (f.geo) flows.push(f);
    else {
      const cur = unmapped.get(f.external_ip) ?? {
        ip: f.external_ip,
        reason: isInternalIp(f.external_ip)
          ? "internal or reserved address - not placed on the world map"
          : "no GeoIP data on events (enrichment disabled or IP not resolved)",
        conns: 0,
      };
      cur.conns += f.conns;
      unmapped.set(f.external_ip, cur);
    }
  };

  for (const f of demoFlows) {
    const ext = byExternal.get(f.external_ip);
    pushFlow({
      external_ip: f.external_ip, internal_ip: f.internal_ip,
      direction: f.direction, bytes: f.bytes, conns: f.conns,
      engines: ["zeek"], ioc_hits:
        ext?.reputation === "malicious" ? 2 : 0,
      alert_hits: f.flagged ? 1 : 0, last_seen: f.last_seen,
      geo: ext
        ? { country: ext.country, lat: ext.lat, lon: ext.lon,
            asn_org: ext.asn }
        : null,
    });
  }
  for (const f of CAMPAIGN_FLOWS) pushFlow({ ...f, engines: ["zeek", "suricata"] });

  flows.sort((a, b) => b.conns - a.conns || b.bytes - a.bytes);
  return {
    hours: 24,
    geo_enabled: true,
    flows,
    unmapped: [...unmapped.values()].sort((a, b) => b.conns - a.conns),
    note: "GeoIP is an approximate network location, not proof of the "
      + "attacker's physical location. Internal IPs and addresses "
      + "without geo data are listed, never plotted.",
    generated_at: new Date().toISOString(),
  };
}

export const GRAPH_SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f87171", high: "#fb923c", medium: "#fbbf24",
  low: "#60a5fa", informational: "#94a3b8",
};

// expose internal builder for tests / debugging
export function _demoGraphForTest(): ReturnType<typeof buildGraphInternal> {
  return buildGraphInternal();
}
