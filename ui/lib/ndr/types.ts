// NDR console shared types (mirrors API DTOs + rich visual views)

export type Role =
  | "administrator"
  | "security_engineer"
  | "soc_analyst"
  | "soc_lead"
  | "auditor";

export interface SessionUser {
  username: string;
  role: Role;
  full_name?: string | null;
  must_change_password?: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type AlertStatus = "new" | "acknowledged" | "in_progress" | "closed" | "false_positive";

/**
 * Attack-result verdict at ALERT level (v0.10). Same vocabulary as the
 * incident-level OutcomeLabel; `strong_success` is reserved for the
 * correlation engine (chain-level evidence), never set on a single alert.
 */
export type AlertOutcome =
  | "attempted" | "suspected_success" | "strong_success" | "indeterminate";

export interface AlertDoc {
  /** v0.14.0: L1 whitelist tag - alert indexed but kept out of triage. */
  suppressed?: boolean;
  suppressed_by?: number;
  /** v0.13.0: structured sampled domains (DGA/NXDOMAIN/tunneling). */
  dns_domains?: string[];
  alert_id: string;
  alert_type: string;
  title: string;
  group_key: string;
  severity: Severity;
  severity_score?: number;
  status: AlertStatus;
  assignee?: string | null;
  confidence: string;
  rationale: string;
  reasons: string[];
  event_count: number;
  source_count: number;
  destination_count: number;
  first_seen: string;
  last_seen: string;
  updated_by?: string;
  sensor_id: string;
  source?: { ip?: string };
  destination?: { ip?: string };
  network?: { transport?: string; protocol?: string };
  top_sources?: { ip: string; count: number }[];
  top_destinations?: { ip: string; count: number }[];
  top_rules?: { signature?: string; count: number }[];
  evidence?: { event_id: string; index: string; "@timestamp": string }[];
  notes?: string | null;
  // visual extras (demo-rich, optional in live mode; mitre + kill_chain
  // are now REAL fields produced by the doc-11 dual-framework classifier)
  mitre?: { tactic: string; technique: string; technique_id: string }[];
  kill_chain?: KillChainClassification;
  sla_minutes?: number;
  risk_score?: number;
  /** Attack-result verdict, determined at detection time (see OUTCOME_DETERMINATION). */
  outcome?: AlertOutcome;
  /** Hostname of the registered/known asset when source IP matches the asset inventory. */
  source_asset_name?: string | null;
  /** Hostname of the registered/known asset when destination IP matches the asset inventory. */
  destination_asset_name?: string | null;
  // ---------------------------------------------------------------- v0.16.0
  /** req 3: status keberhasilan serangan (kosakata tender). */
  attack_status?: string;
  /** req 8: skor DGA ternormalisasi 0-100 (dga_suspected). */
  dga_score?: number;
  /** req 18: campaign tag watchlist (mis. "judi-online"). */
  campaign?: string;
  /** req 10: CVE diekstrak dari signature/reason. */
  cve?: string[];
  /** req 13: penjelasan display-only (index:false di template). */
  explanation?: string;
  /** req 12: geo/ASN sumber & tujuan (GeoIP enrichment pipeline). */
  geo_src?: { country?: string; country_iso_code?: string;
              asn_org?: string };
  geo_dst?: { country?: string; country_iso_code?: string;
              asn_org?: string };
}

export interface EventDoc {
  id: string;
  index: string;
  source: Record<string, unknown> & {
    "@timestamp"?: string;
    source_engine?: string;
    event_type?: string;
    severity?: Severity;
    source?: { ip?: string; port?: number };
    destination?: { ip?: string; port?: number };
    network?: { transport?: string; protocol?: string; bytes?: number };
    dns?: { query?: string; rcode?: string };
    http?: { host?: string; url?: string; method?: string; status_code?: number };
    tls?: { sni?: string };
    alert?: { signature?: string };
  };
}

export interface PipelineHealth {
  ok: boolean;
  sensor_id?: string;
  eps?: number;
  eps_by_engine?: Record<string, number>;
  events_indexed?: number;
  parse_errors?: number;
  duplicates?: number;
  queue_depth?: number;
  last_event_time?: string | null;
  backlog_seconds?: number | null;
  error?: string;
}

export interface Health {
  status: string;
  time: string;
  retention_days: number;
  postgres: { ok: boolean };
  opensearch: { ok: boolean; status?: string; unassigned_shards?: number };
  pipeline: PipelineHealth;
  disk?: { total_gb: number; free_gb: number; used_pct: number };
  sensors?: { id: string; hostname: string; status: string; last_seen_at: string | null }[];
}

export interface OverviewStats {
  alerts_24h: number;
  events_24h: number;
  events_1h: number;
  eps?: number | null;
  eps_by_engine?: Record<string, number>;
  alerts_by_severity?: { key: string; count: number }[];
  alerts_by_status?: { key: string; count: number }[];
  top_alert_titles?: { key: string; count: number }[];
  alert_trend?: { ts: string; count: number }[];
}

export interface SensorRow {
  id: string;
  hostname: string;
  capture_iface?: string | null;
  software_versions?: Record<string, string>;
  status: string;
  last_seen_at?: string | null;
  notes?: string | null;
  pipeline?: { sensor_id: string; last_event_time?: string; eps?: number } | null;
}

export interface UserRow {
  id: string;
  username: string;
  role: Role;
  full_name?: string | null;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at?: string | null;
  created_at: string;
}

// ------------------------------------------------------------- RBAC matrix
export interface RoleInfo {
  role: Role;
  label: string;
  description: string;
}

export interface CapabilityInfo {
  capability: string;
  description: string;
  roles: Role[];
}

export interface RoleMatrix {
  roles: RoleInfo[];
  capabilities: CapabilityInfo[];
}

// ------------------------------------------------------- asset registry (v0.10)
/**
 * Manual asset registry entry. Merged with auto-discovered hosts
 * (from traffic telemetry) in the Assets view; alerts whose source or
 * destination IP matches a registry entry are labeled with the hostname.
 */
export interface RegisteredAsset {
  id: string;
  ip: string;
  hostname: string;
  zone: string;
  role: string;
  criticality: "low" | "medium" | "high" | "critical";
  notes?: string | null;
  created_by?: string | null;
  created_at: string;
}

export interface AuditRow {
  id: number;
  occurred_at: string;
  actor: string;
  actor_role?: string | null;
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  result: string;
  source_ip?: string | null;
  detail?: Record<string, unknown>;
}

// ------------------------------------------------------------------ rich visual model

export interface HostAsset {
  ip: string;
  hostname: string;
  zone: "dmz" | "servers" | "workstations" | "iot" | "management";
  role: string;
  os: string;
  risk_score: number;          // 0-100 heuristic
  criticality: "low" | "medium" | "high" | "critical";
  open_ports: number[];
  status: "healthy" | "watch" | "at_risk";
  bytes_in: number;
  bytes_out: number;
  conns_24h: number;
  alerts_24h: number;
  traffic_24h: number[];       // 24 points, sparkline
  last_alert_title?: string | null;
}

export interface ExternalEntity {
  ip: string;
  asn: string;
  country: string;
  country_code: string;
  lat: number;
  lon: number;
  category: "cdn" | "cloud" | "saas" | "dns" | "social" | "scanning" | "tor" | "malicious" | "other";
  reputation: "clean" | "suspicious" | "malicious";
  note?: string;
}

export interface GeoFlow {
  external_ip: string;
  internal_ip: string;
  bytes: number;
  conns: number;
  direction: "inbound" | "outbound";
  last_seen: string;
  flagged: boolean;
}

export interface TimelinePoint {
  ts: string;
  zeek: number;
  suricata: number;
  arkime: number;
  bytes: number;
  alerts_critical: number;
  alerts_high: number;
  alerts_medium: number;
  alerts_low: number;
}

export interface TopItem {
  key: string;
  count: number;
  bytes?: number;
  meta?: string;
}

export interface ProtocolSlice {
  name: string;
  value: number;
  color: string;
}

export interface RuleStat {
  rule: string;
  name: string;
  fired_7d: number;
  by_severity: Record<string, number>;
  avg_confidence: number;
  est_false_positive: number; // %
  status: "enabled" | "tuning";
}

export interface ServiceMetric {
  name: string;
  ok: boolean;
  detail: string;
  cpu_pct: number;
  mem_pct: number;
  uptime_days: number;
  cpu_history: number[];
}

export interface FeedEvent {
  id: string;
  ts: string;
  engine: "zeek" | "suricata" | "pipeline";
  event_type: string;
  src_ip: string;
  dst_ip: string;
  dst_port?: number;
  transport?: string;
  severity?: Severity | null;
  summary: string;
  flagged?: boolean;
}

export interface HeatCell {
  day: number;   // 0=6 days ago .. 6=today
  hour: number;  // 0-23
  value: number; // alert count
}

export interface MtrPoint {
  day: string;
  mttr_hours: number;
  closed: number;
}

export interface ZoneTraffic {
  zone: string;
  in_mbps: number;
  out_mbps: number;
  hosts: number;
  color: string;
}

// Full bundle powering the rich dashboard (demo mode generates all of it;
// live mode derives what it can from existing API endpoints).
export interface RichOverview {
  generated_at: string;
  health: Health;
  stats: OverviewStats;
  hosts: HostAsset[];
  externals: ExternalEntity[];
  flows: GeoFlow[];
  timeline: TimelinePoint[];      // 7d hourly
  alert_heatmap: HeatCell[];      // 7x24
  top_internal_talkers: TopItem[];
  top_external_dests: TopItem[];
  top_ports: TopItem[];
  protocols: ProtocolSlice[];
  top_dns: TopItem[];
  top_http_hosts: TopItem[];
  top_tls_sni: TopItem[];
  rule_stats: RuleStat[];
  services: ServiceMetric[];
  live_feed: FeedEvent[];
  zone_traffic: ZoneTraffic[];
  eps_history: number[];          // last 60s sparkline source
  mttr: MtrPoint[];
  new_alerts_today: number;
  critical_open: number;
  mean_time_to_ack_min: number;
}

// ------------------------------------------------------------------ threat intelligence (Phase 3)

export type IocType = "ip" | "domain" | "url" | "md5" | "sha1" | "sha256";
export type IocStatus = "active" | "expired";
export type FeedJobStatus = "queued" | "running" | "success" | "partial_success" | "failed";

export interface TIFeed {
  id: string;
  name: string;
  adapter: "urlhaus" | "threatfox" | "feodo" | "file"
    | "stix" | "taxii" | "misp";
  url: string | null;
  enabled: boolean;
  schedule_min: number;
  ttl_days: number;
  last_success_at: string | null;
  last_status: FeedJobStatus | null;
  created_at: string;
  updated_at: string;
  config?: Record<string, unknown>;
  // visual extras (demo-rich)
  ioc_count?: number;
  last_job?: TIJob | null;
}

export interface TIJob {
  id: string;
  feed_id: string | null;
  feed_name: string | null;
  trigger: "manual" | "schedule";
  status: FeedJobStatus;
  counts: {
    new?: number; changed?: number; unchanged?: number; total?: number;
    expired_total?: number; warnings?: string[];
    feed_version?: Record<string, unknown>;
  };
  error: string | null;
  created_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface IocRow {
  id: number;
  ioc_type: IocType;
  ioc_value: string;
  status: IocStatus;
  confidence: "high" | "medium" | "low";
  malware: string | null;
  tags: string[];
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
}

export interface IocMatchRow {
  id: string;
  "@timestamp": string;
  event_id: string;
  event_index?: string;
  sensor_id: string;
  ioc_type: IocType;
  ioc_value: string;
  ioc_source: string;
  ioc_confidence: string;
  match_field?: string;
  source_ip?: string;
  destination_ip?: string;
  zone?: string | null;
  /** IOC lifecycle from the intel store (v0.12.1 match detail enrichment) */
  first_seen?: string | null;
  last_seen?: string | null;
  expires_at?: string | null;
}

export interface AllowRow {
  id: number;
  ioc_type: IocType;
  ioc_value: string;
  reason: string;
  created_by: string | null;
  created_at: string;
}

export interface TIOverview {
  iocs_total: number;
  iocs_active: number;
  iocs_expired: number;
  by_type_active: Record<string, number>;
  feeds_total: number;
  feeds_enabled: number;
  feeds_degraded: number;
  iocs_expiring_3d: number;
  matches_24h: number;
  matches_by_type: Record<string, number>;
  matches_by_source: Record<string, number>;
}

export interface ThreatIntelData {
  overview: TIOverview;
  feeds: TIFeed[];
  jobs: TIJob[];
  iocs: { total: number; items: IocRow[] };
  matches: { total: number; hits: IocMatchRow[] };
  allowlist: AllowRow[];
  match_trend: { ts: string; count: number }[];
}

// ------------------------------------------------------------------ attack reconstruction (Phase 4)

export type AttackPhase =
  | "recon" | "initial_access" | "delivery" | "c2" | "lateral" | "impact"
  | "unknown";

export type IncidentStatus = "open" | "confirmed" | "benign" | "closed";

export type OutcomeLabel =
  | "attempted" | "suspected_success" | "strong_success" | "indeterminate";

export interface PhaseProgress {
  phase: AttackPhase;
  status: "none" | "suspected" | "observed";
  evidence_count: number;
  signal_count: number;
  context_count: number;
}

// -------------------------------------------------- Cyber Kill Chain (doc 11)
// Lockheed Martin 7-stage chain, dual-framework with MITRE ATT&CK.
// NOT a mandatory sequence: stages may be skipped, parallel, or
// undeterminable from network telemetry alone.

export type KillChainStage =
  | "reconnaissance"
  | "weaponization"
  | "delivery"
  | "exploitation"
  | "installation"
  | "command_and_control"
  | "actions_on_objectives";

export type KillChainStatus =
  | "observed"
  | "suspected"
  | "not_observed"
  | "insufficient_telemetry";

export interface MitreTechnique {
  tactic: string;
  technique_id: string;
  technique: string;
}

export interface StageProgress {
  stage: KillChainStage;
  label: string;
  status: KillChainStatus;
  evidence_count: number;
  signal_count: number;
  context_count: number;
  confidence: number;
  attck: MitreTechnique[];
  reason: string;
}

export interface StageHistoryEntry {
  ts?: string | null;
  ts_epoch?: number;
  stage: KillChainStage | string;
  from: KillChainStatus | null;
  to: KillChainStatus;
  evidence_ref?: string;
}

export interface KillChainClassification {
  stage: KillChainStage | string;
  stage_label: string;
  basis: string;
  reason: string;
}

export interface IncidentSummary {
  id: string;
  title: string;
  campaign_id?: string | null;
  campaign_title?: string | null;
  status: IncidentStatus;
  severity: Severity;
  confidence: number;
  confidence_basis?: string;
  first_seen: string | null;
  last_seen: string | null;
  updated_at?: string | null;
  entity_count: number;
  edge_count: number;
  evidence_count: number;
  signal_count: number;
  outcome_label: OutcomeLabel;
  phases: PhaseProgress[];
  deepest_stage?: KillChainStage | string | null;
  analyst?: string | null;
  created_at?: string | null;
}

export interface AttackNode {
  key: string;
  kind: "ip" | "domain" | "hash" | "ioc";
  label: string;
  role?: string | null;
  phase?: AttackPhase | null;
  confidence?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  attrs?: Record<string, unknown>;
  evidence_count?: number;
}

export interface AttackEdge {
  src: string;
  dst: string;
  relation: string;
  phase?: AttackPhase | null;
  inferred?: boolean;
  first_seen?: string | null;
  last_seen?: string | null;
  evidence_count?: number;
  confidence?: number;
}

export interface EvidenceItem {
  ts: string | null;
  kind?: string;
  source?: string;
  ref_index?: string;
  ref_id?: string;
  title?: string;
  severity?: Severity | string;
  phase?: AttackPhase | string;
  summary?: string;
  detail?: Record<string, unknown>;
  stage?: KillChainStage | string | null;
  attck?: MitreTechnique[];
}

export interface IncidentNoteRow {
  author: string | null;
  body: string;
  created_at: string | null;
}

export interface IncidentHistoryRow {
  occurred_at: string | null;
  actor: string | null;
  action: string;
  detail?: Record<string, unknown>;
}

export interface IncidentOutcome {
  label: OutcomeLabel;
  proven: string[];
  suspected: string[];
  unknown: string[];
  markers?: string[];
  disclaimer?: string;
}

export interface IncidentDetail extends IncidentSummary {
  outcome: IncidentOutcome;
  phase_progression: PhaseProgress[];
  stage_progression?: StageProgress[];
  stage_history?: StageHistoryEntry[];
  nodes: AttackNode[];
  edges: AttackEdge[];
  evidence: EvidenceItem[];
  notes: IncidentNoteRow[];
  history: IncidentHistoryRow[];
}

export interface IncidentStats {
  total: number;
  by_status: Record<string, number>;
  open_by_severity: Record<string, number>;
  by_outcome: Record<string, number>;
  open_total: number;
}

// ------------------------------------------------- report versions (v0.12)

export interface ReportVersionMeta {
  version: number;
  generated_by: string | null;
  incident_status: string | null;
  severity: string | null;
  outcome_label: string | null;
  evidence_count: number;
  signal_count: number;
  created_at: string | null;
}

// ------------------------------------------------------- campaigns (v0.12)

export interface CampaignSummary {
  id: string;
  title: string;
  description: string;
  status: "open" | "closed";
  created_by: string | null;
  incident_count: number;
  severity: Severity;
  first_seen: string | null;
  last_seen: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface CampaignDetail extends CampaignSummary {
  incidents: IncidentSummary[];
}

// ------------------------------------------------------------------ threat map / relationship graph (Phase 5)

export interface GraphNode {
  key: string;               // "ip:203.0.113.25" | "domain:x" | "hash:y"
  kind: "ip" | "domain" | "hash" | "ioc";
  label: string;
  roles: string[];
  phase: AttackPhase;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  evidence_count: number;
  incident_ids: string[];
  ti_match: boolean;
  attrs: Record<string, unknown>;
  internal: boolean | null;
  degree: number;
}

export interface GraphEdge {
  src: string;
  dst: string;
  relation: string;
  phase: AttackPhase;
  inferred: boolean;
  first_seen: string | null;
  last_seen: string | null;
  evidence_count: number;
  confidence: number;
  incident_ids: string[];
  reasons: string[];
}

export interface GraphCampaign {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  outcome_label: OutcomeLabel;
  node_keys: string[];
  analyst?: string | null;
}

export interface GraphMeta {
  generated_at: string;
  node_count: number;
  edge_count: number;
  campaign_count: number;
  basis: string;
  disclaimer: string;
  /** v0.12.7 render-cap transparency (server-side prune) */
  full_counts?: { nodes: number; edges: number };
  render_limits?: { max_nodes: number; max_edges: number };
  pruned?: boolean;
  note?: string;
}

export interface RelationshipGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  campaigns: GraphCampaign[];
  meta: GraphMeta;
}

export interface GeoFlowV2 {
  external_ip: string;
  internal_ip: string;
  direction: "inbound" | "outbound";
  bytes: number;
  conns: number;
  engines: string[];
  ioc_hits: number;
  alert_hits: number;
  last_seen: string | null;
  geo: {
    country: string;
    lat: number;
    lon: number;
    asn_org?: string | null;
  } | null;
}

export interface UnmappedIp {
  ip: string;
  reason: string;
  conns: number;
}

export interface GeoBundle {
  hours: number;
  geo_enabled: boolean;
  flows: GeoFlowV2[];
  unmapped: UnmappedIp[];
  note: string;
  generated_at: string;
}

export interface PivotRelated {
  direction: "in" | "out";
  peer_key: string;
  peer_label: string;
  peer_kind?: string | null;
  relation: string;
  inferred: boolean;
  evidence_count: number;
  confidence: number;
  reasons: string[];
  incident_ids: string[];
}

export interface BlastRadiusEntry {
  key: string;
  label: string;
  kind: string;
  internal: boolean | null;
  phase: AttackPhase;
  confidence: number;
  hop: number;
  via: string[];
  relation: string;
  observed_path: boolean;
  reasons: string[];
}

export interface BlastRadius {
  root: string;
  direct: BlastRadiusEntry[];
  indirect: BlastRadiusEntry[];
  internal_hosts: BlastRadiusEntry[];
}

export interface AlertRef {
  index?: string;
  alert_id?: string;
  title?: string;
  severity?: string;
  alert_type?: string;
  last_seen?: string;
  source_ip?: string;
  destination_ip?: string;
}

export interface EventRef {
  index?: string;
  doc_id?: string;
  "@timestamp"?: string;
  event_type?: string;
  source_engine?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  network_transport?: string;
  network_bytes?: number;
  dns_query?: string;
  tls_sni?: string;
  http_host?: string;
  session_id?: string;
}

export interface EntityPivot {
  entity: GraphNode;
  related: PivotRelated[];
  campaigns: GraphCampaign[];
  blast_radius: BlastRadius;
  alerts: AlertRef[];
  events_sample: EventRef[];
  disclaimer: string;
}

// ------------------------------------------------- rule manager (Phase 6)
export interface RuleRow {
  sid: number;
  gid: number;
  rev: number | null;
  action: string;
  protocol: string;
  src: string | null;
  sport: string | null;
  dst: string | null;
  dport: string | null;
  msg: string | null;
  classtype: string | null;
  priority: number | null;
  enabled: boolean;
  changed_by: string | null;
  changed_at: string | null;
  hits_7d?: number;
  // v0.16.0 (req 14/15): rule hit statistics dari tabel rule_stats
  hits_24h?: number | null;
  sev_max?: string | null;
  last_hit_at?: string | null;
  noisy?: boolean;
  // v0.12.7 rule-source taxonomy: local = operator-authored,
  // suricata = subscribed ET ruleset (zeek is a separate endpoint)
  source?: "local" | "suricata";
  // v0.11 custom rule editor
  custom?: boolean;
  rule_text?: string | null;
  created_by?: string | null;
  created_at?: string | null;
  updated_by?: string | null;
  updated_at?: string | null;
}

export interface RulesSummary {
  total: number;
  enabled: number;
  disabled: number;
  actions: Record<string, number>;
  // v0.12.7: counts per rule source (local vs suricata)
  by_source?: Record<string, number>;
  top_categories: Record<string, number>;
  rules_file_updated: string | null;
  rules_file_exists: boolean;
  skipped_lines: number;
  sensor_online: boolean;
  update_tool: string;
}

// v0.16.1 (P1-3): status ruleset/sensor TANPA parsing - sumber KPI
export interface RulesStatus {
  rules_file: string;
  rules_dir?: string;
  rules_file_exists: boolean;
  rules_file_updated: string | null;
  rules_file_size?: number | null;
  disable_conf?: string;
  disable_conf_exists?: boolean;
  suricata_conf?: string;
  suricata_conf_exists?: boolean;
  unix_socket: string;
  socket_present: boolean;
  sensor_online: boolean;
  cache_warm?: boolean;
  cached_rules?: number;
  zeek_local_conf?: string;
  zeek_local_exists?: boolean;
  container?: string;
  note?: string;
}

export interface RulesList {
  total: number;
  skipped_lines: number;
  rules_file_updated: string | null;
  // v0.16.0: true bila tabel rule_stats terisi (join berhasil)
  stats_available?: boolean;
  items: RuleRow[];
}

// v0.12.7: exact aggregation buckets for the Alert Center header charts
// (POST /api/alerts/stats - same guarded filter as /search, size 0)
export interface AlertStatBucket {
  key: string;
  count: number;
}

export interface AlertStats {
  total: number;
  relation?: string;
  // v0.16.0 (bug A6 fix): kontrak UI = LIST {key,count}; bentuk dict
  // vendor lama tetap tersedia di bawah aggregations.
  severity: AlertStatBucket[];
  status: AlertStatBucket[];
  outcome: AlertStatBucket[];
  attack_status?: AlertStatBucket[];
  kill_chain?: AlertStatBucket[];
  aggregations?: {
    severity: Record<string, number>;
    status: Record<string, number>;
    outcome: Record<string, number>;
    attack_status?: Record<string, number>;
    kill_chain?: Record<string, number>;
  };
}

// v0.12.8: DGA Activity focus view - aggregation-only summary over the
// two DGA-family alert types (dga_suspected + dns_nxdomain_burst).
export interface DgaSummary {
  hours: number;
  total: number;
  relation?: string;
  alert_types: string[];
  sources: { key: string; count: number }[];
  timeline: { ts: string; count: number }[];
  last_seen?: string | number | null;
}

// v0.12.8: incidents whose recorded evidence references an alert
// (honest Alert -> Incident linkage, no similarity guessing).
export interface RelatedIncident {
  incident_id: string;
  title: string;
  status: string;
  severity: string;
  outcome_label: string;
}

// v0.12.9: FOCUSED attack relationship for ONE alert (Alert Center ->
// Threat Map jump). basis tells the analyst exactly WHAT is drawn:
//   incident - the alert is recorded evidence of the returned incident
//              chain(s); alert - honest minimal graph from the alert's
//              own entities; none - nothing drawable (kept honest).
export type AlertRelationshipBasis = "incident" | "alert" | "none";

export interface AlertRelationship {
  alert: {
    id: string;
    alert_id: string;
    title: string | null;
    alert_type: string | null;
    severity: string | null;
    status: string | null;
    source_ip: string | null;
    destination_ip: string | null;
    first_seen: string | null;
    last_seen: string | null;
    event_count: number | null;
  };
  basis: AlertRelationshipBasis;
  note: string;
  incidents: RelatedIncident[];
  graph: RelationshipGraph;
}

// v0.12.9: per-IOC activity feed (Threat Intel IOC detail sheet).
export interface IocProvenanceEntry {
  feed: string;
  first_seen: string;
  last_seen: string;
  confidence: string;
  reference?: string | null;
  malware?: string | null;
}

export interface IocActivity {
  ioc: IocRow & { provenance: IocProvenanceEntry[] };
  hours: number;
  activity: {
    matches_total: number;
    relation: string;
    unique_source_hosts: number;
    first_match: string | null;
    last_match: string | null;
    top_source_hosts: { key: string; count: number }[];
    match_fields: { key: string; count: number }[];
  };
  recent_matches: {
    id: string;
    "@timestamp": string;
    event_id: string;
    event_index?: string;
    source_ip?: string;
    destination_ip?: string;
    match_field?: string;
    zone?: string | null;
  }[];
  related_alerts: {
    total: number;
    items: {
      alert_id: string;
      title: string | null;
      severity: string | null;
      alert_type: string | null;
      status: string | null;
      first_seen: string | null;
      last_seen: string | null;
      source_ip: string | null;
      destination_ip: string | null;
    }[];
  };
}

// v0.12.7: read-only Zeek policy inventory (Rule Manager "Zeek" tab).
// Zeek has no toggleable rules in the Suricata sense - its detection
// logic lives in policy scripts activated from local.zeek, so this is
// presented as an inventory, not an editable rule list.
export interface ZeekScriptItem {
  line: number;
  kind: "load" | "load-sigs" | "directive" | "redef" | "other";
  text: string;
}

export interface ZeekScriptList {
  exists: boolean;
  path: string;
  total_lines?: number;
  comment_lines?: number;
  load_count?: number;
  items: ZeekScriptItem[];
  note?: string;
}

export interface RulesUpdateResult {
  ok: boolean;
  output: string;
  error: string | null;
  reloaded: boolean;
  reload_detail: string;
  rules_loaded?: number;
  rules_file_updated?: string | null;
}

export interface RuleToggleResult {
  sid: number;
  enabled: boolean;
  update_ok: boolean;
  reloaded: boolean;
  reload_detail: string;
  error: string | null;
}

// ---------------- PCAP & evidence workflow (doc section 15) --------------
export type PcapStatus =
  | "available"
  | "partially_available"
  | "expired"
  | "not_captured";

export interface SessionRow {
  doc_id: string;
  index?: string;
  "@timestamp"?: string;
  session_id?: string | null;
  source_engine?: string | null;
  event_type?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  network_transport?: string | null;
  network_bytes?: number | null;
  dns_query?: string | null;
  tls_sni?: string | null;
  http_host?: string | null;
  pcap_status: PcapStatus;
  pcap_note?: string;
  arkime_url?: string | null;
}

export interface ArkimeStatus {
  reachable: boolean;
  viewer_url: string;
  expression?: string | null;
  url?: string | null;
  error?: string | null;
  http_status?: number | null;
  latency_ms?: number | null;
}

export interface PcapCoverage {
  pcap_dir?: string;
  dir_exists?: boolean;
  file_count?: number;
  total_bytes?: number;
  oldest_file?: string | null;
  newest_file?: string | null;
  coverage_from?: string | null;
  coverage_to?: string | null;
  free_bytes?: number | null;
  disk_total_bytes?: number | null;
  used_pct?: number | null;
  granularity?: string;
  note?: string;
}

export interface EvidenceSessions {
  scope: "alert" | "incident";
  scope_id: string;
  window: { from?: string | null; to?: string | null };
  entities: { ips: string[]; domains: string[] };
  pcap: PcapCoverage;
  arkime_viewer_url: string;
  arkime?: ArkimeStatus;
  capture_buffer_minutes?: number;
  sessions: SessionRow[];
  total: number;
}

export interface PcapExportFile {
  name: string;
  bytes: number;
  sha256: string;
}

export interface PcapExportRecord {
  id: string;
  actor: string;
  actor_role?: string | null;
  alert_id?: string | null;
  incident_id?: string | null;
  reason: string;
  session_count: number;
  sessions?: { doc_id: string; "@timestamp"?: string }[];
  window: { from?: string | null; to?: string | null };
  files: PcapExportFile[];
  total_bytes: number;
  bundle_name?: string | null;
  bundle_sha256?: string | null;
  status: "ready" | "expired" | "failed";
  error?: string | null;
  created_at?: string | null;
  expires_at?: string | null;
}

export interface PcapExportsList {
  items: PcapExportRecord[];
  ttl_minutes: number;
  limits: { max_files: number; max_bytes: number; max_sessions: number };
}

export interface PcapExportCreate {
  alert_id?: string;
  incident_id?: string;
  reason: string;
  sessions: string[];
}

// ------------------------------------------------- system settings (v0.11)
export interface BrandingConfig {
  logo: string | null;
  favicon: string | null;
}

export interface NtpConfig {
  servers: string[];
  timezone: string;
  enabled: boolean;
}

export interface NetworkInterface {
  name: string | null;
  state: string;
  mac: string | null;
  addrs: string[];
}

export interface NetworkConfig {
  hostname: string;
  dns_servers: string[];
  system_dns?: string[];
  interfaces?: NetworkInterface[];
  applied?: boolean;
  notes?: string[];
}

export interface SystemSettings {
  version: string;
  system: { name: string; tagline: string };
  branding: BrandingConfig;
  ntp: NtpConfig;
  network: NetworkConfig;
}

export type DiagnoseTool = "ping" | "traceroute" | "dns" | "port";

export interface DiagnoseResult {
  tool: DiagnoseTool;
  target: string;
  ok: boolean;
  output: string;
  at: string;
}

export interface RuleValidateResult {
  ok: boolean;
  error: string | null;
  parsed?: {
    sid: number; action: string; protocol: string; msg: string;
    classtype: string | null; priority: number | null; rev: number | null;
  };
}


// ============ v0.14.0 alert whitelist (allowlist) ============
export type AllowLayer = "L0" | "L1";
export type AllowStatus = "pending" | "active" | "rejected" | "expired";
export type AllowEntityField = "src_ip" | "dst_ip" | "dst_domain";

export interface AllowEntry {
  id: number;
  alert_type: string;
  signature: string | null;
  entity_field: AllowEntityField;
  entity_value: string;
  layer: AllowLayer;
  status: AllowStatus;
  reason: string;
  retroactive?: boolean;
  created_by?: string | null;
  created_at?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  expires_at?: string | null;
  hit_count: number;
  last_hit_at?: string | null;
  retro_tagged?: number;
}

export interface AllowSummary {
  active: number;
  pending: number;
  expired: number;
  rejected: number;
  total_hits: number;
  l0: number;
  l1: number;
  top: { id: number; alert_type: string; entity_field: AllowEntityField;
         entity_value: string; layer: AllowLayer; hit_count: number;
         last_hit_at?: string | null }[];
}

// ==================================================================== v0.16.0
// R5: filter DSL AST (and/or/not + is/is_one/include/exclude/cidr/range)
export type FilterOp =
  | "is" | "is_one" | "include" | "exclude"
  | "gt" | "gte" | "lt" | "lte" | "cidr";

export interface FilterLeaf {
  field: string;
  op: FilterOp;
  value: string | number | (string | number)[];
}

export interface FilterGroup {
  and?: (FilterGroup | FilterLeaf)[];
  or?: (FilterGroup | FilterLeaf)[];
  not?: FilterGroup | FilterLeaf;
}

export type FilterAst = FilterGroup | FilterLeaf;

// R6: export alert body
export interface ExportAlertBody {
  format: "csv" | "xlsx";
  time_from: string;
  time_to: string;
  filter?: FilterAst;
  query?: Record<string, unknown>;
  columns?: string[];
  max_rows?: number;
}

// R7: DNS explorer
export interface DnsSummary {
  hours: number;
  total: number;
  // v0.16.1 (P1-4): penyebut rasio = dokumen dengan dns.rcode (response)
  // - eksak, bukan lagi hits.total yang ter-cap 10.000 (bug rasio 9133%)
  transactions: number;
  resolved: number;
  unresolved: number;
  no_response?: number;
  resolved_pct: number;
  rcodes: { key: string; count: number; pct?: number }[];
  top_queried: { domain: string; count: number }[];
  top_clients: { ip: string; count: number }[];
}

export interface DnsHit {
  id: string;
  "@timestamp": string | null;
  client: string | null;
  server: string | null;
  query: string | null;
  qtype: string | null;
  rcode: string | null;
  resolved: boolean;
  answer_count: number;
  answers: unknown[];
  campaign?: string | null;
}

// R9: TLS insights (metadata-only)
export interface TlsSummary {
  hours: number;
  total: number;
  capped_total?: number;
  sources?: string[];
  versions: { key: string; count: number }[];
  top_ja3: { key: string; count: number }[];
  top_sni: { key: string; count: number }[];
  issuers: { key: string; count: number }[];
}

// R18: Judi Online watchlist view
export interface GamblingSummary {
  hours: number;
  campaign: string;
  total_events: number;
  top_clients: { key: string; count: number }[];
  top_domains: { key: string; count: number }[];
  top_hosts: { key: string; count: number }[];
  by_engine: { key: string; count: number }[];
  timeline_hourly: { ts: string; count: number }[];
  keywords: string[];
  note: string;
}

// R14+15: rule hit statistics
export interface RuleStatRow {
  rule_key: string;
  source: string;
  signature?: string | null;
  hits_24h: number;
  hits_7d: number;
  sev_max?: string | null;
  last_hit_at?: string | null;
  sample_alert_id?: string | null;
  noisy?: boolean;
}

export interface RuleStatsList {
  updated_at?: string | null;
  total: number;
  noisy: number;
  items: RuleStatRow[];
}

// R19: one SSE tick of /api/metrics/live
export interface LiveMetricTick {
  ts: string;
  eps?: number | null;
  eps_by_engine?: Record<string, number>;
  queue_depth?: number | null;
  queue_capacity?: number | null;
  backlog_seconds?: number | null;
  alerts_5m?: number | null;
  events_5m?: number | null;
}
