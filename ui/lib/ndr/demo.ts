// Demo dataset engine for the sandbox preview / UI development.
// Deterministic (seeded RNG) so charts look identical between reloads,
// with a live-ticker layer simulated client-side.
// Clearly labeled "demo" in the console header when active.

import type { AllowEntry,
  AlertDoc, AllowRow, AuditRow, DiagnoseResult, DiagnoseTool, EventDoc,
  ExternalEntity, FeedEvent, GeoFlow, Health, HeatCell, HostAsset,
  IocMatchRow, IocRow, MtrPoint, NetworkConfig, OverviewStats,
  EvidenceSessions, PcapCoverage, PcapExportCreate, PcapExportRecord,
  PcapExportsList, ProtocolSlice, RegisteredAsset, RichOverview, Role,
  RoleMatrix, RuleRow, RuleStat,
  RuleValidateResult, RulesSummary, SensorRow, ServiceMetric, SessionRow,
  SystemSettings, TIFeed, TIJob, ZeekScriptList,
  ThreatIntelData, TimelinePoint, TIOverview, TopItem, UserRow, ZoneTraffic,
} from "./types";

const NOW = Date.now();
const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (ms: number) => new Date(ms).toISOString();

// ----------------------------------------------------------------- seeded RNG
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(20261012);
const pick = <T,>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];
const ri = (min: number, max: number) => min + Math.floor(rnd() * (max - min + 1));

export const DEMO_USER = {
  username: "admin",
  role: "administrator" as const,
  full_name: "Demo Administrator",
  must_change_password: false,
};

// v0.12.2: simulate the production first-login flow - the bootstrap admin
// is created with must_change_password=true, so the first demo login forces
// the password dialog; a successful change clears it (like the backend's
// token_version revocation would in live mode).
let demoMustChangePw = true;
export function demoMustChangePassword(): boolean {
  return demoMustChangePw;
}
export async function demoChangePassword(): Promise<void> {
  await new Promise((r) => setTimeout(r, 300));
  demoMustChangePw = false;
}

// ----------------------------------------------------------------- host inventory
interface HostSeed {
  ip: string; hostname: string; zone: HostAsset["zone"]; role: string; os: string;
  crit: HostAsset["criticality"]; ports: number[]; base: number; // base traffic multiplier
}

const HOST_SEEDS: HostSeed[] = [
  { ip: "192.168.1.50", hostname: "web-01", zone: "dmz", role: "Web server (nginx reverse proxy)", os: "Ubuntu 22.04", crit: "critical", ports: [80, 443], base: 9.5 },
  { ip: "192.168.1.51", hostname: "web-02", zone: "dmz", role: "Web server (app backend)", os: "Ubuntu 22.04", crit: "critical", ports: [80, 443, 8080], base: 7.8 },
  { ip: "192.168.1.52", hostname: "mail-01", zone: "dmz", role: "Mail gateway (SMTP/IMAP)", os: "Debian 12", crit: "high", ports: [25, 465, 993], base: 4.2 },
  { ip: "192.168.1.53", hostname: "proxy-01", zone: "dmz", role: "Egress proxy (Squid)", os: "Ubuntu 22.04", crit: "high", ports: [3128], base: 8.9 },
  { ip: "192.168.2.10", hostname: "dc-01", zone: "servers", role: "Active Directory / DNS", os: "Windows Server 2022", crit: "critical", ports: [53, 88, 389, 445], base: 6.1 },
  { ip: "192.168.2.11", hostname: "db-01", zone: "servers", role: "PostgreSQL primary", os: "Ubuntu 24.04", crit: "critical", ports: [5432], base: 5.4 },
  { ip: "192.168.2.12", hostname: "file-01", zone: "servers", role: "File share (SMB)", os: "Windows Server 2019", crit: "high", ports: [445], base: 4.8 },
  { ip: "192.168.2.13", hostname: "app-01", zone: "servers", role: "Internal ERP application", os: "Ubuntu 22.04", crit: "high", ports: [443, 8443], base: 3.9 },
  { ip: "192.168.2.14", hostname: "backup-01", zone: "servers", role: "Backup repository", os: "Ubuntu 24.04", crit: "medium", ports: [10000], base: 2.6 },
  { ip: "192.168.2.15", hostname: "monitor-01", zone: "servers", role: "Monitoring / NDR pipeline", os: "Ubuntu 24.04", crit: "medium", ports: [3000, 9200], base: 3.1 },
  { ip: "192.168.3.21", hostname: "ws-fin-01", zone: "workstations", role: "Finance workstation", os: "Windows 11", crit: "medium", ports: [], base: 2.2 },
  { ip: "192.168.3.22", hostname: "ws-hr-02", zone: "workstations", role: "HR workstation", os: "Windows 11", crit: "medium", ports: [], base: 1.8 },
  { ip: "192.168.3.23", hostname: "ws-it-03", zone: "workstations", role: "IT admin workstation", os: "Windows 11", crit: "high", ports: [3389], base: 2.9 },
  { ip: "192.168.3.24", hostname: "ws-eng-04", zone: "workstations", role: "Engineering workstation", os: "Ubuntu 24.04", crit: "low", ports: [22], base: 2.4 },
  { ip: "192.168.3.25", hostname: "ws-mkt-05", zone: "workstations", role: "Marketing workstation", os: "Windows 11", crit: "low", ports: [], base: 1.6 },
  { ip: "192.168.3.26", hostname: "ws-dev-06", zone: "workstations", role: "Developer workstation", os: "Ubuntu 24.04", crit: "medium", ports: [22], base: 2.7 },
  { ip: "192.168.3.27", hostname: "ws-fin-07", zone: "workstations", role: "Finance workstation", os: "Windows 10", crit: "medium", ports: [], base: 1.9 },
  { ip: "192.168.3.28", hostname: "ws-ops-08", zone: "workstations", role: "Operations workstation", os: "Windows 11", crit: "low", ports: [], base: 1.4 },
  { ip: "192.168.4.51", hostname: "cam-lobby", zone: "iot", role: "IP camera (lobby)", os: "Embedded", crit: "low", ports: [554, 8001], base: 1.5 },
  { ip: "192.168.4.52", hostname: "cam-parking", zone: "iot", role: "IP camera (parking)", os: "Embedded", crit: "low", ports: [554, 8001], base: 1.4 },
  { ip: "192.168.4.53", hostname: "printer-hr", zone: "iot", role: "Network printer", os: "Embedded", crit: "low", ports: [9100, 631], base: 0.6 },
  { ip: "192.168.4.54", hostname: "printer-mgt", zone: "iot", role: "Network printer", os: "Embedded", crit: "low", ports: [9100], base: 0.5 },
  { ip: "192.168.4.55", hostname: "iot-thermo", zone: "iot", role: "HVAC thermostat", os: "Embedded", crit: "low", ports: [1883], base: 0.4 },
  { ip: "192.168.4.56", hostname: "voip-gw", zone: "iot", role: "VoIP gateway", os: "Embedded", crit: "medium", ports: [5060, 5061], base: 1.2 },
  { ip: "192.168.10.9", hostname: "jump-01", zone: "management", role: "Admin jump host (SSH)", os: "Ubuntu 24.04", crit: "critical", ports: [22], base: 1.3 },
  { ip: "192.168.10.24", hostname: "soc-ws-01", zone: "management", role: "SOC analyst console", os: "Ubuntu 24.04", crit: "high", ports: [], base: 1.1 },
  { ip: "192.168.10.31", hostname: "soc-ws-02", zone: "management", role: "Security engineer console", os: "Ubuntu 24.04", crit: "high", ports: [], base: 1.0 },
];

// risk profile overrides: hosts involved in the demo storyline
const RISK_OVERRIDES: Record<string, { risk: number; status: HostAsset["status"]; alert?: string }> = {
  "192.168.1.50": { risk: 92, status: "at_risk", alert: "SQL injection attempts from 203.0.113.25" },
  "192.168.1.51": { risk: 58, status: "watch", alert: "Reconnaissance activity observed" },
  "192.168.3.26": { risk: 74, status: "at_risk", alert: "Possible C2 beaconing to 91.245.77.10" },
  "192.168.4.56": { risk: 61, status: "watch", alert: "Beaconing pattern - firmware check suspected" },
  "192.168.4.55": { risk: 47, status: "watch", alert: "NXDOMAIN burst (DGA-like lookups)" },
  "192.168.1.53": { risk: 39, status: "watch" },
};

export const demoHosts: HostAsset[] = HOST_SEEDS.map((h) => {
  const ov = RISK_OVERRIDES[h.ip];
  const risk = ov?.risk ?? Math.min(70, 12 + h.base * 3 + (h.crit === "critical" ? 14 : h.crit === "high" ? 8 : 2) + ri(0, 6));
  const traffic = Array.from({ length: 24 }, (_, hr) => {
    const shape = hr >= 8 && hr <= 18 ? 1 : hr >= 19 && hr <= 22 ? 0.55 : 0.18;
    const spike = h.ip === "192.168.1.50" && hr === 14 ? 3.2 : 1;
    return Math.round(h.base * shape * spike * 42 * (0.8 + rnd() * 0.4)) / 10;
  });
  return {
    ip: h.ip, hostname: h.hostname, zone: h.zone, role: h.role, os: h.os,
    risk_score: Math.round(risk),
    criticality: h.crit,
    open_ports: h.ports,
    status: ov?.status ?? (risk > 70 ? "at_risk" : risk > 45 ? "watch" : "healthy"),
    bytes_in: Math.round(h.base * 3.1e9 * (0.7 + rnd() * 0.6)),
    bytes_out: Math.round(h.base * 1.4e9 * (0.7 + rnd() * 0.6)),
    conns_24h: Math.round(h.base * 1800 * (0.7 + rnd() * 0.6)),
    alerts_24h: ov ? ri(2, 9) : risk > 60 ? ri(1, 3) : 0,
    traffic_24h: traffic,
    last_alert_title: ov?.alert ?? null,
  };
});

// ----------------------------------------------------------------- external entities
export const demoExternals: ExternalEntity[] = [
  { ip: "91.245.77.10", asn: "AS49505 Selectel", country: "Russia", country_code: "RU", lat: 55.75, lon: 37.61, category: "malicious", reputation: "malicious", note: "Known C2 infrastructure - multiple TI feeds" },
  { ip: "203.0.113.25", asn: "AS20473 Vultr", country: "United States", country_code: "US", lat: 32.77, lon: -96.79, category: "scanning", reputation: "malicious", note: "Repeated web attack source" },
  { ip: "198.51.100.7", asn: "AS64512 Example-ISP", country: "Netherlands", country_code: "NL", lat: 52.37, lon: 4.89, category: "scanning", reputation: "suspicious", note: "Full TCP port scan observed" },
  { ip: "185.220.101.34", asn: "AS200651 FlokiNET", country: "Iceland", country_code: "IS", lat: 64.14, lon: -21.94, category: "tor", reputation: "suspicious", note: "Tor exit node" },
  { ip: "45.155.205.233", asn: "AS210644 AEZA", country: "Russia", country_code: "RU", lat: 59.93, lon: 30.33, category: "malicious", reputation: "malicious", note: "SSH brute-force source" },
  { ip: "193.106.191.35", asn: "AS49447 BrainStorm", country: "Ukraine", country_code: "UA", lat: 50.45, lon: 30.52, category: "malicious", reputation: "malicious", note: "NXDOMAIN DGA resolution attempts" },
  { ip: "104.18.32.7", asn: "AS13335 Cloudflare", country: "United States", country_code: "US", lat: 37.77, lon: -122.41, category: "cdn", reputation: "clean" },
  { ip: "142.250.4.139", asn: "AS15169 Google", country: "United States", country_code: "US", lat: 37.42, lon: -122.08, category: "saas", reputation: "clean" },
  { ip: "20.42.65.92", asn: "AS8075 Microsoft", country: "United States", country_code: "US", lat: 47.44, lon: -122.11, category: "cloud", reputation: "clean" },
  { ip: "13.107.42.14", asn: "AS8075 Microsoft", country: "United States", country_code: "US", lat: 47.64, lon: -122.13, category: "saas", reputation: "clean" },
  { ip: "31.13.95.17", asn: "AS32934 Meta", country: "Ireland", country_code: "IE", lat: 53.34, lon: -6.26, category: "social", reputation: "clean" },
  { ip: "199.232.46.132", asn: "AS54113 Fastly", country: "United States", country_code: "US", lat: 39.04, lon: -77.48, category: "cdn", reputation: "clean" },
  { ip: "8.8.8.8", asn: "AS15169 Google", country: "United States", country_code: "US", lat: 37.38, lon: -122.05, category: "dns", reputation: "clean" },
  { ip: "1.1.1.1", asn: "AS13335 Cloudflare", country: "Australia", country_code: "AU", lat: -33.86, lon: 151.2, category: "dns", reputation: "clean" },
  { ip: "52.96.165.18", asn: "AS16552 Amazon", country: "United States", country_code: "US", lat: 45.52, lon: -122.67, category: "saas", reputation: "clean" },
  { ip: "162.159.135.234", asn: "AS13335 Cloudflare", country: "United States", country_code: "US", lat: 37.86, lon: -122.26, category: "cdn", reputation: "clean" },
  { ip: "51.210.47.198", asn: "AS16276 OVH", country: "France", country_code: "FR", lat: 50.69, lon: 3.17, category: "scanning", reputation: "suspicious", note: "Masscan fingerprint" },
  { ip: "103.75.190.11", asn: "AS135377 UCloud", country: "Singapore", country_code: "SG", lat: 1.35, lon: 103.82, category: "other", reputation: "suspicious", note: "Uncommon TLS JA3 mix" },
];

// ----------------------------------------------------------------- geo flows
const FLOW_PAIRS: Array<[string, string, number, number, GeoFlow["direction"], boolean]> = [
  ["203.0.113.25", "192.168.1.50", 14.2e6, 4821, "inbound", true],
  ["91.245.77.10", "192.168.3.26", 41.8e6, 358, "outbound", true],
  ["198.51.100.7", "192.168.1.51", 2.1e6, 1290, "inbound", true],
  ["45.155.205.233", "192.168.10.9", 0.9e6, 214, "inbound", true],
  ["193.106.191.35", "192.168.4.55", 0.2e6, 87, "outbound", true],
  ["185.220.101.34", "192.168.1.50", 0.4e6, 66, "inbound", false],
  ["51.210.47.198", "192.168.1.52", 1.1e6, 431, "inbound", true],
  ["103.75.190.11", "192.168.4.56", 8.6e6, 212, "outbound", true],
  ["104.18.32.7", "192.168.1.53", 612e6, 48211, "outbound", false],
  ["142.250.4.139", "192.168.3.25", 231e6, 18322, "outbound", false],
  ["20.42.65.92", "192.168.3.23", 486e6, 9210, "outbound", false],
  ["13.107.42.14", "192.168.3.21", 297e6, 12455, "outbound", false],
  ["31.13.95.17", "192.168.3.22", 88e6, 4211, "outbound", false],
  ["199.232.46.132", "192.168.3.24", 154e6, 8233, "outbound", false],
  ["8.8.8.8", "192.168.2.10", 42e6, 61234, "outbound", false],
  ["1.1.1.1", "192.168.2.10", 18e6, 24311, "outbound", false],
  ["52.96.165.18", "192.168.2.13", 122e6, 5210, "outbound", false],
  ["162.159.135.234", "192.168.3.27", 64e6, 3122, "outbound", false],
  ["104.18.32.7", "192.168.2.12", 77e6, 9821, "outbound", false],
  ["142.250.4.139", "192.168.3.26", 12e6, 812, "outbound", false],
];

export const demoFlows: GeoFlow[] = FLOW_PAIRS.map(([ext, intr, bytes, conns, dir, flagged]) => ({
  external_ip: ext, internal_ip: intr, bytes, conns, direction: dir, flagged,
  last_seen: iso(NOW - ri(1, 55) * MIN),
}));

// ----------------------------------------------------------------- timeline (7d hourly)
const BUSY = [0.28, 0.22, 0.18, 0.16, 0.2, 0.35, 0.62, 0.85, 1.0, 1.05, 1.0, 0.98, 0.94, 1.02, 1.06, 1.0, 0.92, 0.85, 0.7, 0.55, 0.45, 0.4, 0.36, 0.3];

function buildTimeline(): TimelinePoint[] {
  const pts: TimelinePoint[] = [];
  for (let d = 6; d >= 0; d--) {
    const weekend = new Date(NOW - d * DAY).getDay() === 0 || new Date(NOW - d * DAY).getDay() === 6;
    for (let h = 0; h < 24; h++) {
      const ts = NOW - d * DAY - (23 - h) * HOUR;
      const dayFactor = weekend ? 0.35 : 1;
      const base = 92 * BUSY[h] * dayFactor * (0.9 + rnd() * 0.2);
      // story anomalies: scan spike 2d ago 14:00, c2 beacon irregular pulses
      const scanSpike = d === 2 && h === 14 ? 1.9 : 1;
      const zeek = Math.round(base * 0.62 * scanSpike);
      const suricata = Math.round(base * 0.38 * scanSpike);
      const sevBase = base * dayFactor;
      pts.push({
        ts: iso(ts), zeek, suricata, arkime: Math.round(zeek * 0.05),
        bytes: Math.round(base * 1.35e6),
        alerts_critical: d <= 1 && h >= 10 && h <= 16 && rnd() > 0.75 ? ri(1, 3) : 0,
        alerts_high: Math.round(sevBase / 34 * (rnd() > 0.5 ? 1 : 0) + (scanSpike > 1 ? 6 : 0)),
        alerts_medium: Math.round(sevBase / 19 * (rnd() > 0.35 ? 1 : 0)),
        alerts_low: Math.round(sevBase / 11 * (rnd() > 0.25 ? 1 : 0)),
      });
    }
  }
  return pts;
}
export const demoTimeline: TimelinePoint[] = buildTimeline();

// v0.16.2 (BUG-0161-02): agregasi harian 7d + split severity utk Reports
// (demo mode) - mencerminkan stats.alert_daily_7d pada live mode.
function buildAlertDaily(): TimelinePoint[] {
  const byDay = new Map<string, TimelinePoint>();
  for (const t of demoTimeline) {
    const day = t.ts.slice(0, 10);
    const cur = byDay.get(day) ?? {
      ts: day, zeek: 0, suricata: 0, arkime: 0, bytes: 0,
      alerts_critical: 0, alerts_high: 0, alerts_medium: 0, alerts_low: 0,
    };
    cur.alerts_critical += t.alerts_critical;
    cur.alerts_high += t.alerts_high;
    cur.alerts_medium += t.alerts_medium;
    cur.alerts_low += t.alerts_low;
    byDay.set(day, cur);
  }
  return [...byDay.values()];
}
export const demoAlertDaily: TimelinePoint[] = buildAlertDaily();

export const demoHeatmap: HeatCell[] = demoTimeline.map((p, i) => ({
  day: 6 - Math.floor(i / 24), hour: i % 24,
  value: p.alerts_critical + p.alerts_high + p.alerts_medium + p.alerts_low,
}));

// ----------------------------------------------------------------- top lists
export const topInternalTalkers: TopItem[] = [...demoHosts]
  .sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out))
  .slice(0, 8)
  .map((h) => ({ key: h.hostname, count: h.conns_24h, bytes: h.bytes_in + h.bytes_out, meta: h.ip }));

export const topExternalDests: TopItem[] = [
  { key: "104.18.32.7", count: 48211, bytes: 612e6, meta: "Cloudflare CDN" },
  { key: "20.42.65.92", count: 9210, bytes: 486e6, meta: "Microsoft Azure" },
  { key: "13.107.42.14", count: 12455, bytes: 297e6, meta: "Microsoft 365" },
  { key: "142.250.4.139", count: 18322, bytes: 231e6, meta: "Google" },
  { key: "91.245.77.10", count: 358, bytes: 41.8e6, meta: "MALICIOUS - C2" },
  { key: "199.232.46.132", count: 8233, bytes: 154e6, meta: "Fastly CDN" },
  { key: "52.96.165.18", count: 5210, bytes: 122e6, meta: "AWS WorkMail" },
  { key: "203.0.113.25", count: 4821, bytes: 14.2e6, meta: "MALICIOUS - scanner" },
];

export const topPorts: TopItem[] = [
  { key: "443", count: 412338, meta: "HTTPS" },
  { key: "53", count: 118442, meta: "DNS" },
  { key: "80", count: 64210, meta: "HTTP" },
  { key: "22", count: 8433, meta: "SSH" },
  { key: "445", count: 5121, meta: "SMB" },
  { key: "3389", count: 2130, meta: "RDP" },
  { key: "993", count: 1844, meta: "IMAPS" },
  { key: "8080", count: 1622, meta: "HTTP-alt" },
  { key: "25", count: 987, meta: "SMTP" },
  { key: "554", count: 622, meta: "RTSP" },
];

export const demoProtocols: ProtocolSlice[] = [
  { name: "HTTPS/TLS", value: 54.2, color: "#38bdf8" },
  { name: "DNS", value: 17.8, color: "#60a5fa" },
  { name: "HTTP", value: 9.4, color: "#a78bfa" },
  { name: "QUIC", value: 6.1, color: "#f472b6" },
  { name: "SSH", value: 3.2, color: "#fbbf24" },
  { name: "SMB", value: 2.6, color: "#fb923c" },
  { name: "RDP", value: 2.1, color: "#f87171" },
  { name: "Other", value: 4.6, color: "#71717a" },
];

export const topDNS: TopItem[] = [
  { key: "api.internal-corp.example", count: 18422, meta: "NOERROR" },
  { key: "updates.microsoft.com", count: 9211, meta: "NOERROR" },
  { key: "cdn.jsdelivr.net", count: 7432, meta: "NOERROR" },
  { key: "mail.internal-corp.example", count: 5120, meta: "NOERROR" },
  { key: "xj2kdmf4oqw.example-dga.com", count: 87, meta: "NXDOMAIN - DGA-like" },
  { key: "q8zpwn3lm1v.example-dga.com", count: 74, meta: "NXDOMAIN - DGA-like" },
  { key: "telemetry.vendor.example", count: 3911, meta: "NOERROR" },
  { key: "backup.internal-corp.example", count: 2140, meta: "NOERROR" },
  { key: "camlive.local-iot.example", count: 1822, meta: "NOERROR" },
  { key: "ntp.pool.example", count: 1622, meta: "NOERROR" },
];

export const topHTTPHosts: TopItem[] = [
  { key: "intranet.internal-corp.example", count: 8422 },
  { key: "erp.internal-corp.example", count: 5121 },
  { key: "update.microsoft.com", count: 3921 },
  { key: "repo.ubuntu.com", count: 2844 },
  { key: "api.telegram.org", count: 622, meta: "review - uncommon for WS-DEV-06" },
  { key: "pkg-containers.githubusercontent.com", count: 511 },
  { key: "intranet.internal-corp.example/login", count: 412, meta: "targeted by SQLi" },
];

export const topTLSSNI: TopItem[] = [
  { key: "outlook.office365.com", count: 12455 },
  { key: "api.vendor.example", count: 8422 },
  { key: "teams.microsoft.com", count: 7210 },
  { key: "updates.vendor.example", count: 3922 },
  { key: "backup-store.example-cdn.net", count: 2140 },
  { key: "91-245-77-10.static.example-host.com", count: 358, meta: "C2 endpoint" },
  { key: "gateway.iot-thermo.example", count: 922 },
];

// ----------------------------------------------------------------- rule stats
export const demoRuleStats: RuleStat[] = [
  { rule: "suricata_alert_group", name: "Suricata signature grouping", fired_7d: 218, by_severity: { critical: 12, high: 96, medium: 74, low: 36 }, avg_confidence: 0.72, est_false_positive: 18, status: "enabled" },
  { rule: "portscan_suspected", name: "Port scan suspected", fired_7d: 31, by_severity: { critical: 0, high: 4, medium: 19, low: 8 }, avg_confidence: 0.58, est_false_positive: 32, status: "enabled" },
  { rule: "beaconing_possible", name: "Beaconing possible (C2-like)", fired_7d: 44, by_severity: { critical: 3, high: 11, medium: 22, low: 8 }, avg_confidence: 0.66, est_false_positive: 24, status: "enabled" },
  { rule: "dns_nxdomain_burst", name: "DNS NXDOMAIN burst (DGA-like)", fired_7d: 17, by_severity: { critical: 0, high: 2, medium: 6, low: 9 }, avg_confidence: 0.49, est_false_positive: 41, status: "tuning" },
];

// ----------------------------------------------------------------- services
export const demoServices: ServiceMetric[] = [
  { name: "OpenSearch", ok: true, detail: "cluster green - 14 shards", cpu_pct: 41, mem_pct: 68, uptime_days: 12, cpu_history: [38, 42, 45, 40, 39, 44, 41, 38, 42, 46, 43, 41] },
  { name: "Ingest pipeline", ok: true, detail: "118 eps - backlog 2s", cpu_pct: 33, mem_pct: 44, uptime_days: 12, cpu_history: [30, 33, 36, 31, 29, 34, 33, 30, 35, 38, 34, 33] },
  { name: "PostgreSQL", ok: true, detail: "24 conns - replication ok", cpu_pct: 8, mem_pct: 22, uptime_days: 26, cpu_history: [6, 8, 9, 7, 8, 9, 8, 7, 9, 10, 8, 8] },
  { name: "Zeek", ok: true, detail: "af_packet - drops 0.002%", cpu_pct: 52, mem_pct: 31, uptime_days: 6, cpu_history: [48, 52, 55, 50, 49, 54, 52, 50, 53, 56, 54, 52] },
  { name: "Suricata", ok: true, detail: "rules 32411 - live reload ok", cpu_pct: 61, mem_pct: 38, uptime_days: 6, cpu_history: [55, 61, 64, 58, 57, 63, 61, 59, 62, 66, 63, 61] },
  { name: "Arkime", ok: true, detail: "PCAP 600GB quota - 41% used", cpu_pct: 24, mem_pct: 47, uptime_days: 12, cpu_history: [20, 24, 26, 22, 23, 25, 24, 22, 25, 27, 25, 24] },
  { name: "NDR API", ok: true, detail: "p95 84ms - 0 errors 1h", cpu_pct: 6, mem_pct: 18, uptime_days: 9, cpu_history: [5, 6, 7, 6, 5, 7, 6, 6, 7, 8, 7, 6] },
  { name: "NDR UI", ok: true, detail: "standalone build - cache hit 98%", cpu_pct: 2, mem_pct: 9, uptime_days: 9, cpu_history: [2, 2, 3, 2, 2, 3, 2, 2, 3, 3, 2, 2] },
];

// ----------------------------------------------------------------- zone traffic
export const demoZoneTraffic: ZoneTraffic[] = [
  { zone: "DMZ", in_mbps: 42.6, out_mbps: 18.2, hosts: 4, color: "#fb923c" },
  { zone: "Servers", in_mbps: 31.4, out_mbps: 24.8, hosts: 6, color: "#38bdf8" },
  { zone: "Workstations", in_mbps: 18.9, out_mbps: 12.4, hosts: 8, color: "#60a5fa" },
  { zone: "IoT", in_mbps: 6.2, out_mbps: 3.1, hosts: 6, color: "#f472b6" },
  { zone: "Management", in_mbps: 2.4, out_mbps: 1.8, hosts: 3, color: "#a78bfa" },
];

// ----------------------------------------------------------------- MTTR
export const demoMTTR: MtrPoint[] = [
  { day: "Mon", mttr_hours: 6.4, closed: 12 },
  { day: "Tue", mttr_hours: 4.2, closed: 18 },
  { day: "Wed", mttr_hours: 5.1, closed: 14 },
  { day: "Thu", mttr_hours: 3.8, closed: 22 },
  { day: "Fri", mttr_hours: 4.9, closed: 16 },
  { day: "Sat", mttr_hours: 7.2, closed: 6 },
  { day: "Sun", mttr_hours: 2.9, closed: 9 },
];

// ----------------------------------------------------------------- asset registry (v0.10)
// Manual asset registry: machines the SOC explicitly registered. Merged
// with auto-discovered hosts (demoHosts, derived from traffic telemetry)
// in the Assets view; alerts referencing these IPs carry the hostname.
export const demoAssetRegistry: RegisteredAsset[] = [
  { id: "ra-1", ip: "192.168.2.30", hostname: "vault-app-01", zone: "servers",
    role: "Payment vault application", criticality: "critical",
    notes: "PCI scope - registered manually by security_engineer",
    created_by: "engineer", created_at: iso(NOW - 9 * DAY) },
  { id: "ra-2", ip: "192.168.3.40", hostname: "ws-contractor-01", zone: "workstations",
    role: "Contractor laptop (unmanaged)", criticality: "medium",
    notes: "Third-party device - alerting tuned to be sensitive",
    created_by: "admin", created_at: iso(NOW - 4 * DAY) },
  { id: "ra-3", ip: "192.168.4.70", hostname: "ot-plc-pilot", zone: "iot",
    role: "OT PLC (pilot line)", criticality: "high",
    notes: "OT asset - change window Saturdays 22:00-23:00",
    created_by: "engineer", created_at: iso(NOW - 2 * DAY) },
];

let assetSeq = demoAssetRegistry.length;

export function demoCreateAsset(input: {
  ip: string; hostname: string; zone: string; role: string;
  criticality: RegisteredAsset["criticality"]; notes?: string;
  created_by?: string;
}): RegisteredAsset {
  if (demoAssetRegistry.some((a) => a.ip === input.ip)) {
    throw new Error(`Asset with IP ${input.ip} already registered`);
  }
  assetSeq += 1;
  const asset: RegisteredAsset = {
    id: `ra-${assetSeq}`,
    ip: input.ip,
    hostname: input.hostname,
    zone: input.zone,
    role: input.role,
    criticality: input.criticality,
    notes: input.notes ?? null,
    created_by: input.created_by ?? "admin",
    created_at: new Date().toISOString(),
  };
  demoAssetRegistry.push(asset);
  return asset;
}

export function demoUpdateAsset(id: string, patch: {
  hostname?: string; zone?: string; role?: string;
  criticality?: RegisteredAsset["criticality"]; notes?: string;
}): RegisteredAsset {
  const asset = demoAssetRegistry.find((a) => a.id === id);
  if (!asset) throw new Error("registered asset not found");
  if (patch.hostname !== undefined) asset.hostname = patch.hostname;
  if (patch.zone !== undefined) asset.zone = patch.zone;
  if (patch.role !== undefined) asset.role = patch.role;
  if (patch.criticality !== undefined) asset.criticality = patch.criticality;
  if (patch.notes !== undefined) asset.notes = patch.notes;
  return asset;
}

export function demoDeleteAsset(id: string): boolean {
  const idx = demoAssetRegistry.findIndex((a) => a.id === id);
  if (idx === -1) return false;
  demoAssetRegistry.splice(idx, 1);
  return true;
}

// ----------------------------------------------------------------- alerts
interface AlertSeed {
  title: string; n: number; sev: AlertDoc["severity"]; alert_type: string;
  source?: { ip?: string }; destination?: { ip?: string };
  group_key: string; rationale: string; reasons: string[];
  mitre: { tactic: string; technique: string; technique_id: string }[];
  kill_chain: string; rules?: { signature?: string; count: number }[];
  risk: number;
  // v0.12.8: DGA demo seeds land inside the last 12h so the DGA
  // Activity menu's default 24h window shows them
  recent?: boolean;
  // v0.10: explicit L7 protocol + attack-result verdict per detection class
  protocol?: string;
  transport?: "tcp" | "udp" | "icmp";
  outcome?: AlertDoc["outcome"];
}

// doc 11 dual-framework shape (identical to the live API classifier)
const KC_LABEL_TO_STAGE: Record<string, { stage: string; label: string; basis: string }> = {
  "Reconnaissance": { stage: "reconnaissance", label: "Reconnaissance", basis: "demo: detection rule mapping" },
  "Weaponization": { stage: "weaponization", label: "Weaponization", basis: "demo: not observable from network" },
  "Delivery": { stage: "delivery", label: "Delivery", basis: "demo: file/behavior rule mapping" },
  "Exploitation": { stage: "exploitation", label: "Exploitation", basis: "demo: suricata category mapping" },
  "Installation": { stage: "installation", label: "Installation", basis: "demo: needs endpoint telemetry" },
  "Command & Control": { stage: "command_and_control", label: "Command & Control", basis: "demo: behavior rule mapping" },
  "Actions on Objective": { stage: "actions_on_objectives", label: "Actions on Objectives", basis: "demo: behavior rule mapping" },
};

function kc(label: string): NonNullable<AlertDoc["kill_chain"]> {
  const m = KC_LABEL_TO_STAGE[label] ?? KC_LABEL_TO_STAGE["Reconnaissance"];
  return {
    stage: m.stage,
    stage_label: m.label,
    basis: m.basis,
    reason: `${m.basis} classified as ${m.label} (doc 11 dual-framework)`,
  };
}

const alertSeeds: AlertSeed[] = [
  {
    title: "Suricata: ET WEB_SERVER SQL Injection Attempt", n: 42, sev: "high",
    alert_type: "suricata_alert_group",
    source: { ip: "203.0.113.25" }, destination: { ip: "192.168.1.50" },
    group_key: "2016645|203.0.113.25", risk: 88,
    rationale: "Suricata raised 42 events for signature 'ET WEB_SERVER SQL Injection Attempt' from the same source within the grouping window. Signature alert indicates an attempt was observed; it does not by itself prove exploitation succeeded.",
    reasons: [
      "42 alert events with same signature_id 2016645 from source 203.0.113.25",
      "target: web server 192.168.1.50 (zone: dmz, hostname web-01)",
      "payload samples contained UNION SELECT and OR 1=1 patterns",
      "source also present in 2 other attack groups within 24h",
    ],
    mitre: [
      { tactic: "Reconnaissance", technique: "Gather Victim Host Information", technique_id: "T1592" },
      { tactic: "Initial Access", technique: "Exploit Public-Facing Application", technique_id: "T1190" },
    ],
    kill_chain: "Exploitation",
    rules: [{ signature: "ET WEB_SERVER SQL Injection Attempt", count: 42 }],
    protocol: "http",
    outcome: "attempted",
  },
  {
    title: "Port scan suspected from 198.51.100.7", n: 3, sev: "medium",
    alert_type: "portscan_suspected", source: { ip: "198.51.100.7" },
    group_key: "198.51.100.7", risk: 62,
    rationale: "Source 198.51.100.7 touched 312 unique ports on 8 hosts within the window. This pattern is consistent with reconnaissance; benign scanners and inventory tools can also trigger it - verify before escalation.",
    reasons: [
      "unique destination ports in window: 312 (threshold 100)",
      "unique destination hosts in window: 8 (threshold 50)",
      "SYN-only ratio 0.94 - consistent with half-open scanning",
    ],
    mitre: [{ tactic: "Reconnaissance", technique: "Network Service Scanning", technique_id: "T1595.002" }],
    kill_chain: "Reconnaissance",
    protocol: "tcp",
    outcome: "indeterminate",
  },
  {
    title: "Possible beaconing 192.168.3.26 -> 91.245.77.10:443", n: 2, sev: "high",
    alert_type: "beaconing_possible",
    source: { ip: "192.168.3.26" }, destination: { ip: "91.245.77.10" },
    group_key: "192.168.3.26|91.245.77.10|443", risk: 84,
    rationale: "58 connections from 192.168.3.26 (ws-dev-06) to 91.245.77.10:443 with mean interval 62s and jitter coefficient 0.06. Consistent with C2 beaconing but also with monitoring agents and keepalives. Destination IP is listed as malicious in 3 TI feeds. Connection existence does not prove host compromise.",
    reasons: [
      "connections: 58 >= 20",
      "mean interval 62s within [10, 3600]s",
      "jitter 0.06 <= 0.2",
      "destination 91.245.77.10 flagged malicious (TI feed: internal blocklist, abuse.ch)",
      "TLS SNI mismatch: certificate self-signed, JA3 uncommon for this host",
    ],
    mitre: [
      { tactic: "Command and Control", technique: "Application Layer Protocol: Web Protocols", technique_id: "T1071.001" },
      { tactic: "Command and Control", technique: "Encrypted Channel", technique_id: "T1573" },
    ],
    kill_chain: "Command & Control",
    protocol: "tls",
    outcome: "indeterminate",
  },
  {
    title: "NXDOMAIN burst from 192.168.4.55", n: 2, sev: "low",
    alert_type: "dns_nxdomain_burst", source: { ip: "192.168.4.55" },
    group_key: "192.168.4.55", risk: 41, recent: true,
    rationale: "Source 192.168.4.55 (iot-thermo) produced 87/120 NXDOMAIN DNS responses (ratio 0.73) within the window. High NXDOMAIN volume is a weak DGA indicator; misconfigured resolvers and applications can also cause it. Score is heuristic and uncalibrated.",
    reasons: [
      "NXDOMAIN ratio 0.73 >= threshold 0.5",
      "sample queries: xj2kdmf4oqw.example-dga[.]com, q8zpwn3lm1v.example-dga[.]com",
    ],
    mitre: [{ tactic: "Command and Control", technique: "Dynamic Resolution: Domain Generation Algorithms", technique_id: "T1568.002" }],
    kill_chain: "Command & Control",
    protocol: "dns",
    transport: "udp",
    outcome: "indeterminate",
  },
  {
    // v0.12.8: DGA Activity menu demo seed (same shape the pipeline
    // emits). Title matches the demo incident evidence entry
    // (incidents-demo.ts) so the alert -> incident linkage demos.
    title: "Possible DGA queries from 10.0.10.77 (14 unique domains)", n: 2, sev: "medium",
    alert_type: "dga_suspected", source: { ip: "10.0.10.77" },
    group_key: "10.0.10.77", risk: 58, recent: true,
    rationale: "Host 10.0.10.77 queried 14 unique domains with mean label entropy 3.9 in the window. High-entropy unique domain bursts are consistent with algorithmically generated C2 domains, but CDN/BYOD apps and monitoring agents can look similar. Treat as a C2 candidate, not a verdict.",
    reasons: [
      "unique domains: 14 >= 20 (window includes prior hour)",
      "mean label entropy 3.9 >= 3.0",
      "sample high-entropy queries: xj2kdmf4oqw.example-dga.com, q8zpwn3lm1v.example-dga.com, t4hwn9xpe2r.example-dga.com, v7ql2okm8zs.example-dga.com",
    ],
    mitre: [{ tactic: "Command and Control", technique: "Dynamic Resolution: Domain Generation Algorithms", technique_id: "T1568.002" }],
    kill_chain: "Command & Control",
    protocol: "dns",
    transport: "udp",
    outcome: "indeterminate",
  },
  {
    title: "Suricata: GPL ATTACK_RESPONSE code 19", n: 3, sev: "critical",
    alert_type: "suricata_alert_group",
    source: { ip: "203.0.113.25" }, destination: { ip: "192.168.1.50" },
    group_key: "2000001|203.0.113.25", risk: 95,
    rationale: "Attack-response signature observed toward 192.168.1.50. Response signatures often follow a successful action, but outcome needs confirmation from additional evidence (PCAP, server logs).",
    reasons: [
      "3 alert events with signature_id 2000001",
      "outcome: Attempt Observed - success not confirmed",
      "follows SQL injection group from same source (temporal correlation)",
    ],
    mitre: [
      { tactic: "Initial Access", technique: "Exploit Public-Facing Application", technique_id: "T1190" },
      { tactic: "Execution", technique: "Unix Shell", technique_id: "T1059.004" },
    ],
    kill_chain: "Exploitation",
    rules: [{ signature: "GPL ATTACK_RESPONSE id check returned root", count: 3 }],
    protocol: "http",
    outcome: "suspected_success",
  },
  {
    title: "SSH brute force from 45.155.205.233 (61 attempts)", n: 8, sev: "high",
    alert_type: "suricata_alert_group", source: { ip: "45.155.205.233" },
    destination: { ip: "192.168.10.9" },
    group_key: "2027865|45.155.205.233", risk: 79,
    rationale: "61 SSH authentication attempts to jump-01 within 10 minutes from a single source with 58 failures. Consistent with credential brute force; verify whether any authentication succeeded and whether source is an authorized administration host.",
    reasons: [
      "61 auth attempts, 58 failures, 3 pending/unknown outcome",
      "target port 22 on management zone host",
      "source in brute-force TI list",
    ],
    mitre: [{ tactic: "Credential Access", technique: "Brute Force", technique_id: "T1110" }],
    kill_chain: "Delivery",
    rules: [{ signature: "ET SCAN Potential SSH Scan", count: 61 }],
    protocol: "ssh",
    outcome: "attempted",
  },
  {
    title: "Suricata: ET SCAN Suricata Portscan", n: 17, sev: "low",
    alert_type: "suricata_alert_group", source: { ip: "203.0.113.99" },
    group_key: "2001219|203.0.113.99", risk: 38,
    rationale: "Suricata raised 17 events for signature 'ET SCAN Suricata Portscan' from the same source within the grouping window.",
    reasons: ["17 alert events with same signature_id 2001219"],
    mitre: [{ tactic: "Reconnaissance", technique: "Network Service Scanning", technique_id: "T1595" }],
    kill_chain: "Reconnaissance",
    protocol: "tcp",
    outcome: "indeterminate",
  },
  {
    title: "Beaconing pattern 192.168.4.56 -> 103.75.190.11:5061", n: 1, sev: "medium",
    alert_type: "beaconing_possible",
    source: { ip: "192.168.4.56" }, destination: { ip: "103.75.190.11" },
    group_key: "192.168.4.56|103.75.190.11|5061", risk: 55,
    rationale: "34 periodic TLS connections from voip-gw to 103.75.190.11:5061, mean interval 300s, jitter 0.12. Pattern consistent with SIP registrar keepalive; vendor firmware phones home to similar endpoints. Not classified malicious.",
    reasons: [
      "connections: 34 >= 20", "mean interval 300s within [10, 3600]s", "jitter 0.12 <= 0.2",
    ],
    mitre: [{ tactic: "Command and Control", technique: "Application Layer Protocol", technique_id: "T1071" }],
    kill_chain: "Command & Control",
    protocol: "sip",
    transport: "udp",
    outcome: "indeterminate",
  },
  {
    title: "Unusual SMB volume ws-it-03 -> file-01 (4.2 GB)", n: 1, sev: "medium",
    alert_type: "beaconing_possible", source: { ip: "192.168.3.23" },
    destination: { ip: "192.168.2.12" },
    group_key: "192.168.3.23|192.168.2.12|445", risk: 48,
    rationale: "SMB transfer volume from ws-it-03 to file-01 exceeded the 7-day baseline by 6.1x during off-hours. Could be legitimate backup/migration; verify with change calendar before escalating.",
    reasons: [
      "volume 4.2 GB vs baseline 0.69 GB (6.1x)",
      "observed 01:00-03:00 local (off-hours for this host)",
    ],
    mitre: [{ tactic: "Collection", technique: "Archive Collected Data", technique_id: "T1560" }],
    kill_chain: "Actions on Objective",
    protocol: "smb",
    outcome: "indeterminate",
  },
  {
    title: "DGA-like DNS burst ws-dev-06 (12 queries)", n: 1, sev: "medium",
    alert_type: "dns_nxdomain_burst", source: { ip: "192.168.3.26" },
    group_key: "192.168.3.26", risk: 67,
    rationale: "12 NXDOMAIN queries with high-entropy labels from ws-dev-06 within 5 minutes, shortly before beaconing connections to 91.245.77.10. Combined evidence raises concern of staged DGA resolution.",
    reasons: [
      "NXDOMAIN ratio 0.86 >= threshold 0.5",
      "correlates with beaconing alert on same host (+4 min)",
    ],
    mitre: [{ tactic: "Command and Control", technique: "Dynamic Resolution: Domain Generation Algorithms", technique_id: "T1568.002" }],
    kill_chain: "Command & Control",
    protocol: "dns",
    transport: "udp",
    outcome: "indeterminate",
  },
];

const statuses: AlertDoc["status"][] = ["new", "acknowledged", "in_progress", "closed", "false_positive"];

// ip -> hostname for known inventory (discovered hosts + manual registry).
// Alerts are labeled with the asset hostname so analysts immediately see
// WHICH machine fired (v0.10 asset-name enrichment).
export function assetNameLookup(): Map<string, string> {
  const m = new Map<string, string>();
  demoHosts.forEach((h) => m.set(h.ip, h.hostname));
  demoAssetRegistry.forEach((a) => m.set(a.ip, a.hostname));
  return m;
}

function buildAlerts(): AlertDoc[] {
  const alerts: AlertDoc[] = [];
  let idc = 0;
  const names = assetNameLookup();
  alertSeeds.forEach((seed) => {
    for (let i = 0; i < seed.n; i++) {
      idc += 1;
      // spread across 35 days so time-range presets (7d/14d/30d) are
      // measurably different instead of all alerts landing in one week;
      // v0.12.8: DGA seeds stay inside the last 12h (DGA menu window)
      const lastSeen = seed.recent
        ? NOW - Math.floor(rnd() * 12 * 3600_000)
        : NOW - Math.floor(rnd() * 35 * DAY) - i * MIN;
      const firstSeen = lastSeen - Math.floor(5 * MIN + rnd() * 40 * MIN);
      const id = `a-${String(idc).padStart(4, "0")}-${rnd().toString(36).slice(2, 8)}`;
      const status = seed.n === 1 ? pick(statuses.slice(0, 3)) : pick(statuses);
      alerts.push({
        alert_id: id,
        alert_type: seed.alert_type,
        title: seed.title,
        group_key: seed.group_key,
        severity: seed.sev,
        severity_score: seed.sev === "critical" ? 95 : seed.sev === "high" ? 78 : seed.sev === "medium" ? 52 : 26,
        status,
        assignee: rnd() > 0.6 ? pick(["analyst", "engineer", "lead"]) : null,
        confidence: "heuristic-uncalibrated",
        rationale: seed.rationale,
        reasons: seed.reasons,
        event_count: seed.n > 1 ? Math.max(seed.n, Math.floor(seed.n * (0.7 + rnd() * 0.6))) : Math.floor(3 + rnd() * 40),
        source_count: 1,
        destination_count: seed.title?.includes("scan") ? 8 : 1,
        first_seen: iso(firstSeen),
        last_seen: iso(lastSeen),
        updated_by: "ndr-pipeline",
        sensor_id: "sensor-01",
        source: seed.source,
        destination: seed.destination,
        network: {
          transport: seed.transport ?? (seed.protocol === "dns" ? "udp" : "tcp"),
          protocol: seed.protocol,
        },
        outcome: seed.outcome,
        source_asset_name: seed.source?.ip ? names.get(seed.source.ip) ?? null : null,
        destination_asset_name: seed.destination?.ip ? names.get(seed.destination.ip) ?? null : null,
        top_sources: seed.source?.ip ? [{ ip: seed.source.ip, count: seed.n }] : [],
        top_destinations: seed.destination?.ip ? [{ ip: seed.destination.ip, count: seed.n }] : [],
        top_rules: seed.rules ?? [],
        evidence: Array.from({ length: Math.min(5, Math.max(3, seed.n)) }, (_, k) => ({
          event_id: `ev-${idc}-${k}`,
          index: seed.alert_type === "dns_nxdomain_burst" || seed.alert_type === "dga_suspected"
            ? "ndr-zeek-dns-2026.10" : "ndr-suricata-2026.10",
          "@timestamp": iso(lastSeen - k * MIN),
        })),
        notes: null,
        mitre: seed.mitre,
        kill_chain: kc(seed.kill_chain),
        sla_minutes: seed.sev === "critical" ? 30 : seed.sev === "high" ? 120 : 480,
        risk_score: seed.risk,
      });
    }
  });
  return alerts.sort((a, b) => +new Date(b.last_seen) - +new Date(a.last_seen));
}

export const demoAlerts: AlertDoc[] = buildAlerts();

// ----------------------------------------------------------------- events
function makeEvent(i: number): EventDoc {
  const kinds = ["conn", "dns", "http", "tls", "alert", "files", "ssl", "weird"];
  const kind = kinds[i % kinds.length];
  const ts = NOW - i * 37_000;
  const internalHost = pick(demoHosts);
  const external = pick(demoExternals);
  const base = {
    "@timestamp": iso(ts),
    ingest_time: iso(ts + 800),
    event_id: `ev-demo-${i}`,
    sensor_id: "sensor-01",
    source_engine: i % 3 === 0 ? "suricata" : "zeek",
    event_type: kind,
    source: { ip: internalHost.ip, port: 40000 + (i % 1000) },
    destination: { ip: kind === "dns" ? "10.0.0.1" : external.ip, port: kind === "dns" ? 53 : kind === "http" ? 80 : 443 },
    network: { transport: kind === "dns" ? "udp" : "tcp", protocol: kind, bytes: 500 + i * 137 },
  };
  if (kind === "dns") {
    const dga = i % 7 === 0;
    return { id: `ev-demo-${i}`, index: "ndr-zeek-dns-2026.10", source: { ...base, dns: { query: dga ? "xj2kdmf4oqw.example-dga.com" : pick(topDNS).key, rcode: dga ? "NXDOMAIN" : "NOERROR" } } };
  }
  if (kind === "http") {
    return { id: `ev-demo-${i}`, index: "ndr-zeek-http-2026.10", source: { ...base, http: { host: i % 6 === 0 ? "intranet.internal-corp.example/login" : pick(topHTTPHosts).key, url: i % 6 === 0 ? "/search?q=1%27+OR+1%3D1" : "/v3/manifest.json", method: "GET", status_code: pick([200, 200, 200, 301, 404, 500]) } } };
  }
  if (kind === "tls" || kind === "ssl") {
    return { id: `ev-demo-${i}`, index: "ndr-zeek-tls-2026.10", source: { ...base, tls: { sni: pick(topTLSSNI).key } } };
  }
  if (kind === "alert") {
    return { id: `ev-demo-${i}`, index: "ndr-suricata-2026.10", source: { ...base, severity: pick(["high", "medium", "low"]), alert: { signature: "ET WEB_SERVER SQL Injection Attempt" } } };
  }
  if (kind === "files") {
    return { id: `ev-demo-${i}`, index: "ndr-zeek-files-2026.10", source: { ...base, files: { filename: pick(["quarterly-report.pdf", "installer.exe", "backup.tar.gz", "photo-jpg", "macro-invoice.docm"]), mime_type: pick(["application/pdf", "application/x-dosexec", "application/gzip", "image/jpeg"]), source: "HTTP" } } };
  }
  if (kind === "weird") {
    return { id: `ev-demo-${i}`, index: "ndr-zeek-weird-2026.10", source: { ...base, weird: { name: pick(["Truncated_JSON_payload", "unknown_protocol", "TCP_seq_mismatch"]), notice: false } } };
  }
  return { id: `ev-demo-${i}`, index: "ndr-zeek-conn-2026.10", source: base };
}

export const demoEvents: EventDoc[] = Array.from({ length: 80 }, (_, i) => makeEvent(i));

// ----------------------------------------------------------------- health
export const demoHealth: Health = {
  status: "healthy",
  time: iso(NOW),
  retention_days: 60,
  postgres: { ok: true },
  opensearch: { ok: true, status: "green", unassigned_shards: 0 },
  pipeline: {
    ok: true, sensor_id: "sensor-01", eps: 118.4,
    eps_by_engine: { zeek: 71.2, suricata: 47.2 },
    events_indexed: 9_842_113, parse_errors: 214, duplicates: 1_237,
    queue_depth: 312, last_event_time: iso(NOW - 2_000), backlog_seconds: 2.0,
  },
  disk: { total_gb: 3072, free_gb: 2140, used_pct: 30.3 },
  sensors: [{ id: "sensor-01", hostname: "ndr-sensor-01", status: "online", last_seen_at: iso(NOW - 2_000) }],
};

// ----------------------------------------------------------------- live feed
const FEED_SUMMARIES = [
  (s: string, d: string, p: number) => `TCP ${s} > ${d}:${p} established (conn)`,
  (s: string, d: string) => `DNS query ${s} -> resolver`,
  (s: string, d: string, p: number) => `TLS handshake ${s} > ${d}:${p}`,
  (s: string, d: string, p: number) => `HTTP GET ${s} > ${d}:${p} 200`,
  (s: string, d: string, p: number) => `SSH session ${s} > ${d}:${p}`,
  (s: string, d: string, p: number) => `SMB2 negotiate ${s} > ${d}:${p}`,
  (s: string, d: string, p: number) => `RTSP stream ${s} > ${d}:${p}`,
  (s: string, d: string, p: number) => `SMTP starttls ${s} > ${d}:${p}`,
];

let feedSeq = 0;
export function makeFeedItem(): FeedEvent {
  feedSeq += 1;
  const internal = pick(demoHosts);
  const external = pick(demoExternals);
  const port = pick([443, 443, 53, 80, 22, 445, 993, 5061, 554]);
  const flagged = ["91.245.77.10", "203.0.113.25", "198.51.100.7", "45.155.205.233"].includes(external.ip);
  return {
    id: `feed-${Date.now()}-${feedSeq}`,
    ts: iso(Date.now()),
    engine: rnd() > 0.38 ? "zeek" : "suricata",
    event_type: pick(["conn", "dns", "http", "tls", "ssh", "smb", "alert"]),
    src_ip: rnd() > 0.5 ? internal.ip : external.ip,
    dst_ip: rnd() > 0.5 ? external.ip : internal.ip,
    dst_port: port,
    transport: port === 53 ? "udp" : "tcp",
    severity: flagged ? (rnd() > 0.6 ? "high" : "medium") : null,
    summary: pick(FEED_SUMMARIES)(internal.ip, external.ip, port),
    flagged,
  };
}

export const demoLiveFeed: FeedEvent[] = Array.from({ length: 14 }, () => {
  const item = makeFeedItem();
  return { ...item, ts: iso(Date.now() - ri(2, 90) * 1000) };
}).sort((a, b) => +new Date(b.ts) - +new Date(a.ts));

// ----------------------------------------------------------------- eps ticker
export const demoEpsHistory: number[] = Array.from({ length: 60 }, () => 100 + rnd() * 40);

export function makeEpsTick(prev: number): number {
  const next = prev + (rnd() - 0.5) * 12;
  return Math.max(62, Math.min(178, next));
}

// ----------------------------------------------------------------- overview stats (kept API-compatible)
export const demoStats: OverviewStats = {
  alerts_24h: demoAlerts.length,
  events_24h: demoTimeline.slice(-24).reduce((s, p) => s + p.zeek + p.suricata, 0),
  events_1h: Math.round(demoTimeline[demoTimeline.length - 1].zeek + demoTimeline[demoTimeline.length - 1].suricata),
  eps: 118.4,
  eps_by_engine: { zeek: 71.2, suricata: 47.2 },
  alerts_by_severity: ["critical", "high", "medium", "low", "informational"].map((k) => ({
    key: k, count: demoAlerts.filter((a) => a.severity === k).length,
  })),
  alerts_by_status: statuses.map((s) => ({
    key: s, count: demoAlerts.filter((a) => a.status === s).length,
  })),
  top_alert_titles: alertSeeds.map((s) => ({ key: s.title, count: s.n })),
  alert_trend: Array.from({ length: 24 }, (_, h) => {
    const bucket = demoTimeline.slice(-24)[h];
    return { ts: bucket.ts, count: bucket.alerts_critical + bucket.alerts_high + bucket.alerts_medium + bucket.alerts_low };
  }),
};

// ----------------------------------------------------------------- rich bundle
export function buildRichOverview(): RichOverview {
  return {
    generated_at: iso(NOW),
    health: demoHealth,
    stats: demoStats,
    hosts: demoHosts,
    externals: demoExternals,
    flows: demoFlows,
    timeline: demoTimeline,
    alert_heatmap: demoHeatmap,
    top_internal_talkers: topInternalTalkers,
    top_external_dests: topExternalDests,
    top_ports: topPorts,
    protocols: demoProtocols,
    top_dns: topDNS,
    top_http_hosts: topHTTPHosts,
    top_tls_sni: topTLSSNI,
    rule_stats: demoRuleStats,
    services: demoServices,
    live_feed: demoLiveFeed,
    zone_traffic: demoZoneTraffic,
    eps_history: demoEpsHistory,
    mttr: demoMTTR,
    alert_daily: demoAlertDaily,
    new_alerts_today: demoAlerts.filter((a) => a.status === "new").length,
    critical_open: demoAlerts.filter((a) => a.severity === "critical" && !["closed", "false_positive"].includes(a.status)).length,
    mean_time_to_ack_min: 14,
  };
}

// ----------------------------------------------------------------- sensors / users / audit
export const demoSensors: SensorRow[] = [
  {
    id: "sensor-01", hostname: "ndr-sensor-01", capture_iface: "ens160",
    software_versions: { zeek: "7.0-lts", suricata: "8.0.1", arkime: "5.6.2" },
    status: "online", last_seen_at: iso(NOW - 2_000), notes: "SPAN from core-sw-01 (port Gi1/0/24)",
    pipeline: { sensor_id: "sensor-01", last_event_time: iso(NOW - 2_000), eps: 118.4 },
  },
];



// ============ v0.14.0 alert whitelist demo store ============
export const demoAllowlist: AllowEntry[] = [
  {
    id: 1, alert_type: "beaconing_possible", signature: null,
    entity_field: "dst_ip", entity_value: "10.0.106.24",
    layer: "L0", status: "active",
    reason: "internal backup server beacons nightly to the NAS - verified with infra team",
    retroactive: false,
    created_by: "engineer", created_at: "2026-10-14T02:11:00Z",
    approved_by: "admin", approved_at: "2026-10-14T08:30:00Z",
    expires_at: null, hit_count: 37,
    last_hit_at: "2026-10-16T01:45:00Z",
  },
  {
    id: 2, alert_type: "portscan_suspected", signature: null,
    entity_field: "src_ip", entity_value: "10.0.106.232",
    layer: "L1", status: "active",
    reason: "vulnerability scanner (OpenVAS) - periodic internal scans are expected",
    retroactive: true,
    created_by: "analyst", created_at: "2026-10-15T04:02:00Z",
    approved_by: "engineer", approved_at: "2026-10-15T05:10:00Z",
    expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    hit_count: 12, last_hit_at: "2026-10-16T03:22:00Z",
  },
  {
    id: 3, alert_type: "dga_suspected", signature: null,
    entity_field: "dst_domain", entity_value: ".monitoring.internal.id",
    layer: "L1", status: "pending",
    reason: "monitoring agent high-entropy subdomains - awaiting infra confirmation",
    retroactive: false,
    created_by: "analyst", created_at: "2026-10-16T03:40:00Z",
    approved_by: null, approved_at: null,
    expires_at: null, hit_count: 0, last_hit_at: null,
  },
];

export const demoUsers: UserRow[] = [
  { id: "u1", username: "admin", role: "administrator", full_name: "Demo Administrator", is_active: true, must_change_password: false, last_login_at: iso(NOW - HOUR), created_at: iso(NOW - 30 * DAY) },
  { id: "u2", username: "analyst", role: "soc_analyst", full_name: "Rina Putri (SOC Analyst 1)", is_active: true, must_change_password: false, last_login_at: iso(NOW - 3 * HOUR), created_at: iso(NOW - 20 * DAY) },
  { id: "u3", username: "engineer", role: "security_engineer", full_name: "Budi Santoso (Security Engineer)", is_active: true, must_change_password: false, last_login_at: iso(NOW - 26 * HOUR), created_at: iso(NOW - 20 * DAY) },
  { id: "u4", username: "lead", role: "soc_lead", full_name: "Dewi Lestari (SOC Lead)", is_active: true, must_change_password: false, last_login_at: iso(NOW - 50 * HOUR), created_at: iso(NOW - 15 * DAY) },
  { id: "u5", username: "auditor", role: "auditor", full_name: "Compliance Auditor", is_active: false, must_change_password: false, last_login_at: null, created_at: iso(NOW - 10 * DAY) },
];

let userSeq = demoUsers.length;

export function demoCreateUser(input: {
  username: string; role: Role; full_name?: string; actor: string;
}): UserRow {
  if (!input.username.trim()) throw new Error("Username is required");
  if (demoUsers.some((u) => u.username === input.username)) {
    throw new Error("Username already exists");
  }
  userSeq += 1;
  const user: UserRow = {
    id: `u${userSeq}`,
    username: input.username.trim(),
    role: input.role,
    full_name: input.full_name ?? null,
    is_active: true,
    must_change_password: true,           // initial password must be rotated
    last_login_at: null,
    created_at: new Date().toISOString(),
  };
  demoUsers.push(user);
  return user;
}

export function demoUpdateUser(id: string, patch: {
  role?: Role; full_name?: string; is_active?: boolean;
}): UserRow {
  const user = demoUsers.find((u) => u.id === id);
  if (!user) throw new Error("User not found");
  if (patch.role !== undefined) user.role = patch.role;
  if (patch.full_name !== undefined) user.full_name = patch.full_name;
  if (patch.is_active !== undefined) {
    // guard: never disable the last active administrator
    if (user.role === "administrator" && !patch.is_active) {
      const activeAdmins = demoUsers.filter(
        (u) => u.role === "administrator" && u.is_active && u.id !== user.id);
      if (!activeAdmins.length) {
        throw new Error("Cannot disable the last active administrator");
      }
    }
    user.is_active = patch.is_active;
  }
  return user;
}

export function demoDeleteUser(id: string, actor: string): boolean {
  const user = demoUsers.find((u) => u.id === id);
  if (!user) throw new Error("User not found");
  if (user.username === actor) {
    throw new Error("You cannot delete your own account");
  }
  if (user.role === "administrator") {
    const otherAdmins = demoUsers.filter(
      (u) => u.role === "administrator" && u.is_active && u.id !== user.id);
    if (!otherAdmins.length) {
      throw new Error("Cannot delete the last active administrator");
    }
  }
  const idx = demoUsers.findIndex((u) => u.id === id);
  demoUsers.splice(idx, 1);
  return true;
}

// RBAC capability matrix - mirrors api/app/security.py PERMISSIONS exactly
// (the live endpoint GET /api/roles returns the server-side source of truth;
// this demo copy keeps the preview identical without a backend).
export const demoRoleMatrix: RoleMatrix = {
  roles: [
    { role: "administrator", label: "Administrator",
      description: "Full platform control: users, sensors, rules, feeds, evidence export." },
    { role: "security_engineer", label: "Security Engineer",
      description: "Detection engineering: Suricata rules, TI feeds, sensors, asset registry." },
    { role: "soc_lead", label: "SOC Lead",
      description: "Triage oversight: confirms/closes incidents, assigns analysts." },
    { role: "soc_analyst", label: "SOC Analyst",
      description: "Day-to-day triage: works alerts and incidents, escalates, requests PCAP." },
    { role: "auditor", label: "Auditor",
      description: "Read-only compliance access: dashboard and audit log, no response actions." },
  ],
  capabilities: [
    { capability: "view", description: "View dashboards and entity detail", roles: ["administrator", "security_engineer", "soc_analyst", "soc_lead", "auditor"] },
    { capability: "search", description: "Search events, alerts, incidents", roles: ["administrator", "security_engineer", "soc_analyst", "soc_lead", "auditor"] },
    { capability: "alert_update", description: "Change alert status / assignee / notes", roles: ["administrator", "security_engineer", "soc_analyst", "soc_lead"] },
    { capability: "incident_update", description: "Triage incidents (confirm, benign, close, notes)", roles: ["administrator", "security_engineer", "soc_analyst", "soc_lead"] },
    { capability: "evidence_export", description: "Export PCAP / evidence bundles", roles: ["administrator", "security_engineer", "soc_analyst", "soc_lead"] },
    { capability: "rule_admin", description: "Enable/disable Suricata rules, run rule updates", roles: ["administrator", "security_engineer"] },
    { capability: "ti_admin", description: "Manage TI feeds, IOC allowlist", roles: ["administrator", "security_engineer"] },
    { capability: "sensor_admin", description: "Register/modify capture sensors", roles: ["administrator", "security_engineer"] },
    { capability: "user_admin", description: "Create, edit, delete users", roles: ["administrator"] },
    { capability: "audit_read", description: "Read the audit log", roles: ["administrator", "auditor"] },
  ],
};

export const demoAudit: AuditRow[] = [
  { id: 1042, occurred_at: iso(NOW - 4 * MIN), actor: "analyst", actor_role: "soc_analyst", action: "events.search", target_type: "index", target_id: "ndr-events-read", result: "success", source_ip: "192.168.10.24" },
  { id: 1041, occurred_at: iso(NOW - 12 * MIN), actor: "analyst", actor_role: "soc_analyst", action: "alerts.update", target_type: "alert", target_id: demoAlerts[0].alert_id, result: "success", source_ip: "192.168.10.24", detail: { after: { status: "in_progress" } } },
  { id: 1040, occurred_at: iso(NOW - 31 * MIN), actor: "admin", actor_role: "administrator", action: "auth.login", target_type: "user", target_id: "admin", result: "success", source_ip: "192.168.10.9" },
  { id: 1039, occurred_at: iso(NOW - 47 * MIN), actor: "unknown", actor_role: null, action: "auth.login", target_type: "user", target_id: "root", result: "failure", source_ip: "203.0.113.7" },
  { id: 1038, occurred_at: iso(NOW - 2 * HOUR), actor: "engineer", actor_role: "security_engineer", action: "sensor.update", target_type: "sensor", target_id: "sensor-01", result: "success", source_ip: "192.168.10.31" },
  { id: 1037, occurred_at: iso(NOW - 3 * HOUR), actor: "lead", actor_role: "soc_lead", action: "alerts.update", target_type: "alert", target_id: demoAlerts[1].alert_id, result: "success", source_ip: "192.168.10.24", detail: { after: { status: "closed" } } },
  { id: 1036, occurred_at: iso(NOW - 5 * HOUR), actor: "engineer", actor_role: "security_engineer", action: "events.search", target_type: "index", target_id: "ndr-events-read", result: "denied", source_ip: "192.168.10.31", detail: { reason: "time range exceeds retention cap" } },
  { id: 1035, occurred_at: iso(NOW - 7 * HOUR), actor: "analyst", actor_role: "soc_analyst", action: "auth.login", target_type: "user", target_id: "analyst", result: "success", source_ip: "192.168.10.24" },
];

// ----------------------------------------------------------------- threat intelligence (Phase 3)
// Deterministic synthetic feeds / IOCs / matches for the Threat Intel view.
// Values use RFC 5737 documentation ranges and .test TLD - never real IOCs.

const TI_MALWARE = ["Emotet", "CobaltStrike", "AgentTesla", "Qakbot", "AsyncRAT", "IcedID", "RedLine", "Mirai"];
const TI_TAGS = ["botnet_cc", "payload_delivery", "c2", "phishing", "scanner", "credential-theft"];

const TI_IOC_SEEDS: Array<[string, string, string, string | null, string | null]> = [
  // [type, value, confidence, malware, tags]
  ["ip", "203.0.113.25", "high", "CobaltStrike", "botnet_cc"],
  ["ip", "203.0.113.66", "high", "Emotet", "botnet_cc"],
  ["ip", "198.51.100.7", "medium", "Qakbot", "botnet_cc"],
  ["ip", "198.51.100.208", "medium", "AsyncRAT", "c2"],
  ["ip", "192.0.2.146", "low", "Mirai", "scanner"],
  ["ip", "192.0.2.88", "medium", "IcedID", "botnet_cc"],
  ["domain", "update-service.evil-example.test", "high", "CobaltStrike", "c2"],
  ["domain", "cdn-metrics.evil-example.test", "medium", "AgentTesla", "c2"],
  ["domain", "secure-login-verify.test", "high", "RedLine", "phishing"],
  ["domain", "api-telemetry-bad.test", "medium", "Qakbot", "c2"],
  ["domain", "dga-worker-8471.test", "medium", "Emotet", "botnet_cc"],
  ["domain", "mail-cdn-sync.test", "low", "IcedID", "phishing"],
  ["url", "http://payload.evil-example.test/1.exe", "medium", "AgentTesla", "payload_delivery"],
  ["url", "http://update-service.evil-example.test/gate.php", "high", "CobaltStrike", "c2"],
  ["url", "http://secure-login-verify.test/auth", "high", "RedLine", "phishing"],
  ["url", "http://192.0.2.146/bins/mips.bin", "low", "Mirai", "payload_delivery"],
  ["sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "low", null, "payload_delivery"],
  ["sha256", "d41d8cd98f00b204e9800998ecf8427ea1b2c3d4f5e6f708192a3b4c5d6e7f80", "medium", "Emotet", "payload_delivery"],
  ["sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "low", null, "payload_delivery"],
  ["md5", "0d955a18ec6b0f2e2b1a1b2c3d4e5f6a", "medium", "Qakbot", "payload_delivery"],
];

function buildTiIocs(): IocRow[] {
  return TI_IOC_SEEDS.map(([type, value, confidence, malware, tags], i) => {
    const published = NOW - ri(6, 40) * DAY;
    const expired = i % 9 === 8;
    return {
      id: 9000 + i,
      ioc_type: type as IocRow["ioc_type"],
      ioc_value: value,
      status: expired ? "expired" : "active",
      confidence: confidence as IocRow["confidence"],
      malware,
      tags: tags ? [tags, ...[pick(TI_TAGS)]].filter((t, ix, a) => a.indexOf(t) === ix) : [pick(TI_TAGS)],
      first_seen: iso(published),
      last_seen: iso(published + ri(1, 10) * DAY),
      expires_at: iso(published + 14 * DAY),
    };
  });
}
export const demoTiIocs = buildTiIocs();

const TI_FEED_DEFS: Array<{
  name: string; adapter: TIFeed["adapter"]; url: string; schedule_min: number;
  ttl_days: number; enabled: boolean; status: TIFeed["last_status"];
  lastSuccessMin: number; iocCount: number;
}> = [
  { name: "feodo-c2", adapter: "feodo", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json", schedule_min: 60, ttl_days: 14, enabled: true, status: "success", lastSuccessMin: 24, iocCount: 42 },
  { name: "urlhaus-recent", adapter: "urlhaus", url: "https://urlhaus.abuse.ch/downloads/csv_recent/", schedule_min: 120, ttl_days: 14, enabled: true, status: "success", lastSuccessMin: 95, iocCount: 518 },
  { name: "threatfox-2d", adapter: "threatfox", url: "https://threatfox.abuse.ch/api/v1/", schedule_min: 120, ttl_days: 14, enabled: true, status: "partial_success", lastSuccessMin: 130, iocCount: 231 },
  { name: "misp-community", adapter: "misp", url: "https://misp.example.org/feeds/1", schedule_min: 360, ttl_days: 30, enabled: true, status: "failed", lastSuccessMin: 1490, iocCount: 0 },
  { name: "stix-partner", adapter: "stix", url: "https://cis.example.org/stix/bundle.json", schedule_min: 360, ttl_days: 30, enabled: true, status: "success", lastSuccessMin: 210, iocCount: 127 },
  { name: "taxii-national-csirt", adapter: "taxii", url: "https://taxii.example.csirt/discovery", schedule_min: 360, ttl_days: 30, enabled: false, status: null, lastSuccessMin: 0, iocCount: 0 },
  { name: "internal-honeypot", adapter: "file", url: "file:///var/lib/ndr/ti/honeypot.jsonl", schedule_min: 30, ttl_days: 7, enabled: true, status: "success", lastSuccessMin: 11, iocCount: 18 },
  { name: "otx-sample", adapter: "threatfox", url: "https://otx.alienvault.com/api/v1/indicators/export", schedule_min: 0, ttl_days: 30, enabled: false, status: null, lastSuccessMin: 0, iocCount: 0 },
];

function buildTiFeeds(): TIFeed[] {
  return TI_FEED_DEFS.map((f, i) => ({
    id: `feed-${100 + i}`,
    name: f.name,
    adapter: f.adapter,
    url: f.url,
    enabled: f.enabled,
    schedule_min: f.schedule_min,
    ttl_days: f.ttl_days,
    last_success_at: f.lastSuccessMin ? iso(NOW - f.lastSuccessMin * MIN) : null,
    last_status: f.status,
    created_at: iso(NOW - 25 * DAY),
    updated_at: iso(NOW - (f.lastSuccessMin || 600) * MIN),
    config: f.adapter === "threatfox" ? { days: 2, api_key: "*****" }
      : f.adapter === "taxii" ? { username: "csirt-svc", password: "*****", collection_id: "national-iocs" }
      : f.adapter === "misp" ? { max_events: 50 }
      : {},
    ioc_count: f.iocCount,
    last_job: null,
  }));
}
export const demoTiFeeds = buildTiFeeds();

export function demoCreateFeed(input: {
  name: string; adapter: TIFeed["adapter"]; url?: string | null;
  enabled?: boolean; schedule_min?: number; ttl_days?: number;
  config?: Record<string, unknown>;
}): TIFeed {
  const name = (input.name || "").trim();
  if (!name || demoTiFeeds.some((f) => f.name === name))
    throw new Error(`feed '${name}' already exists`);
  if (input.adapter !== "file" && !input.url)
    throw new Error(`adapter '${input.adapter}' requires a url`);
  const feed: TIFeed = {
    id: `feed-${Math.random().toString(36).slice(2, 8)}`,
    name,
    adapter: input.adapter,
    url: input.url ?? null,
    enabled: input.enabled ?? false,
    schedule_min: input.schedule_min ?? 0,
    ttl_days: input.ttl_days ?? 14,
    last_success_at: null,
    last_status: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    config: input.config ?? {},
    ioc_count: 0,
    last_job: null,
  };
  demoTiFeeds.push(feed);
  return feed;
}

function buildTiJobs(): TIJob[] {
  const jobs: TIJob[] = [];
  const seq = [
    ["urlhaus-recent", "schedule", "success", 12, 506, 0, 40],
    ["feodo-c2", "schedule", "success", 3, 39, 0, 22],
    ["misp-community", "schedule", "failed", 0, 0, 0, 0],
    ["threatfox-2d", "manual", "partial_success", 31, 189, 11, 130],
    ["internal-honeypot", "schedule", "success", 1, 17, 0, 11],
    ["urlhaus-recent", "schedule", "success", 8, 512, 2, 215],
    ["threatfox-2d", "schedule", "success", 44, 187, 0, 250],
    ["feodo-c2", "schedule", "success", 2, 40, 1, 82],
    ["urlhaus-recent", "manual", "success", 15, 503, 0, 355],
    ["internal-honeypot", "schedule", "success", 0, 18, 0, 41],
  ] as const;
  seq.forEach(([feed, trigger, status, nw, unchanged, changed, minAgo], i) => {
    const feedObj = demoTiFeeds.find((f) => f.name === feed);
    const warnings = status === "partial_success"
      ? ["17 rows skipped (invalid/private)"]
      : undefined;
    jobs.push({
      id: `job-${500 + i}`,
      feed_id: feedObj?.id ?? null,
      feed_name: feed,
      trigger: trigger as TIJob["trigger"],
      status: status as TIJob["status"],
      counts: {
        new: nw, changed, unchanged, total: nw + changed + unchanged,
        expired_total: i % 3 === 0 ? ri(1, 6) : 0,
        warnings,
        feed_version: { rows: nw + changed + unchanged },
      },
      error: status === "failed"
        ? "HTTPError: 503 Service Unavailable (upstream feed); no IOC changes applied"
        : null,
      created_by: trigger === "manual" ? "engineer" : null,
      created_at: iso(NOW - minAgo * MIN),
      started_at: iso(NOW - (minAgo - 0.2) * MIN),
      finished_at: iso(NOW - (minAgo - 1.1) * MIN),
    });
  });
  return jobs;
}
export const demoTiJobs = buildTiJobs();
demoTiFeeds.forEach((f) => {
  f.last_job = demoTiJobs.find((j) => j.feed_id === f.id) ?? null;
});

const MATCH_IPS = ["192.168.3.23", "192.168.3.21", "192.168.1.50", "192.168.1.52", "192.168.2.14", "192.168.3.24"];
const MATCH_FIELDS = ["dns.query", "destination", "tls.sni", "http.host", "destination", "destination"];

function buildTiMatches(): IocMatchRow[] {
  const active = demoTiIocs.filter((i) => i.status === "active");
  const rows: IocMatchRow[] = [];
  for (let i = 0; i < 34; i += 1) {
    const ioc = pick(active);
    const ts = NOW - ri(2, 1400) * MIN;
    // point at a real demo event so "Open in Event Search" lands on it
    const linked = demoEvents[(i * 7) % demoEvents.length];
    rows.push({
      id: `match-${i}`,
      "@timestamp": iso(ts),
      event_id: (linked.source as { event_id?: string }).event_id ?? linked.id,
      event_index: linked.index,
      sensor_id: "sensor-01",
      ioc_type: ioc.ioc_type,
      ioc_value: ioc.ioc_value,
      ioc_source: ioc.malware ?? "threat-intel",
      ioc_confidence: ioc.confidence,
      match_field: ioc.ioc_type === "ip" ? pick(MATCH_FIELDS.slice(1, 3)) : pick(MATCH_FIELDS.slice(0, 1)),
      source_ip: pick(MATCH_IPS),
      destination_ip: ioc.ioc_type === "ip" ? ioc.ioc_value : undefined,
      zone: pick(["workstations", "dmz", "servers", undefined]),
      first_seen: ioc.first_seen,
      last_seen: ioc.last_seen,
      expires_at: iso(NOW + ri(1, 14) * DAY),
    });
  }
  return rows.sort((a, b) => +new Date(b["@timestamp"]) - +new Date(a["@timestamp"]));
}
export const demoTiMatches = buildTiMatches();

export const demoTiAllowlist: AllowRow[] = [
  { id: 1, ioc_type: "domain", ioc_value: "cdn-metrics.evil-example.test", reason: "Internal lab domain used by red-team exercise 2026-09 (ticket RT-118)", created_by: "engineer", created_at: iso(NOW - 5 * DAY) },
  { id: 2, ioc_type: "ip", ioc_value: "198.51.100.208", reason: "Business partner SMTP relay - FP confirmed with owner (doc 9.2 workflow)", created_by: "admin", created_at: iso(NOW - 8 * DAY) },
  { id: 3, ioc_type: "url", ioc_value: "http://secure-login-verify.test/auth", reason: "Phishing simulation platform - ongoing campaign", created_by: "lead", created_at: iso(NOW - 2 * DAY) },
];

function buildTiOverview(): TIOverview {
  const active = demoTiIocs.filter((i) => i.status === "active");
  const byType: Record<string, number> = {};
  active.forEach((i) => { byType[i.ioc_type] = (byType[i.ioc_type] ?? 0) + 1; });
  const bySource: Record<string, number> = {};
  demoTiMatches.forEach((m) => { bySource[m.ioc_source] = (bySource[m.ioc_source] ?? 0) + 1; });
  const enabledFeeds = demoTiFeeds.filter((f) => f.enabled);
  return {
    iocs_total: demoTiIocs.length,
    iocs_active: active.length,
    iocs_expired: demoTiIocs.length - active.length,
    by_type_active: byType,
    feeds_total: demoTiFeeds.length,
    feeds_enabled: enabledFeeds.length,
    feeds_degraded: enabledFeeds.filter((f) => f.last_status === "failed" || f.last_status === null).length,
    iocs_expiring_3d: 4,
    matches_24h: demoTiMatches.filter((m) => NOW - +new Date(m["@timestamp"]) < DAY).length,
    matches_by_type: byType,
    matches_by_source: bySource,
  };
}

function buildMatchTrend(): { ts: string; count: number }[] {
  return Array.from({ length: 24 }, (_, h) => ({
    ts: iso(NOW - (23 - h) * HOUR),
    count: ri(0, 6) === 0 ? 0 : Math.max(0, Math.round(2 + 3 * Math.sin(h / 3.8) + ri(-2, 2))),
  }));
}

export function buildThreatIntel(): ThreatIntelData {
  return {
    overview: buildTiOverview(),
    feeds: demoTiFeeds,
    jobs: demoTiJobs,
    iocs: { total: demoTiIocs.length, items: demoTiIocs },
    matches: { total: demoTiMatches.length, hits: demoTiMatches },
    allowlist: demoTiAllowlist,
    match_trend: buildMatchTrend(),
  };
}

// simulated "Update Now" in demo mode: job runs queued -> running -> success
let tiJobSeq = 900;
export function demoTriggerFeedUpdate(feedId: string): TIJob {
  tiJobSeq += 1;
  const feed = demoTiFeeds.find((f) => f.id === feedId);
  const job: TIJob = {
    id: `job-${tiJobSeq}`,
    feed_id: feedId,
    feed_name: feed?.name ?? "unknown",
    trigger: "manual",
    status: "queued",
    counts: {},
    error: null,
    created_by: "admin",
    created_at: iso(Date.now()),
    started_at: null,
    finished_at: null,
  };
  demoTiJobs.unshift(job);
  if (feed) {
    feed.last_status = "queued";
    setTimeout(() => {
      job.status = "running";
      job.started_at = iso(Date.now());
      if (feed) feed.last_status = "running";
    }, 1200);
    setTimeout(() => {
      job.status = feed?.name === "misp-community" ? "failed" : "success";
      job.finished_at = iso(Date.now());
      job.counts = {
        new: ri(0, 9), changed: ri(0, 4), unchanged: ri(20, 200),
        total: ri(25, 210), expired_total: ri(0, 3),
      };
      if (feed) {
        feed.last_status = job.status;
        feed.last_success_at = job.status === "success" ? job.finished_at : feed.last_success_at;
      }
    }, 3200);
  }
  return job;
}

let allowSeq = 100;
export function demoAddAllowlist(entry: { ioc_type: IocRow["ioc_type"]; ioc_value: string; reason: string }): AllowRow {
  allowSeq += 1;
  const row: AllowRow = { id: allowSeq, ...entry, created_by: "admin", created_at: iso(Date.now()) };
  demoTiAllowlist.unshift(row);
  // suppress matching IOCs visually
  demoTiIocs.forEach((i) => {
    if (i.ioc_value === entry.ioc_value) i.status = "expired";
  });
  return row;
}

export function demoRemoveAllowlist(id: number): void {
  const idx = demoTiAllowlist.findIndex((a) => a.id === id);
  if (idx >= 0) demoTiAllowlist.splice(idx, 1);
}

// ------------------------------------------------- rule manager (Phase 6)
type DemoRule = RuleRow;

const mkRule = (
  sid: number, action: "alert" | "drop" | "pass", protocol: string,
  msg: string, classtype: string, priority: number,
  enabled: boolean, hits_7d: number,
  changed?: { by: string; at: string },
): DemoRule => ({
  sid, gid: 1, rev: 1 + (sid % 7), action, protocol,
  src: "$HOME_NET", sport: "any", dst: "$EXTERNAL_NET", dport: "any",
  msg, classtype, priority, enabled, hits_7d,
  changed_by: changed?.by ?? null, changed_at: changed?.at ?? null,
});

export const demoRules: DemoRule[] = [
  mkRule(2001219, "alert", "http", "ET MALWARE Known C2 Domain (Cobalt Strike) DNS Query", "command-and-control", 1, true, 42),
  mkRule(2016645, "alert", "http", "ET MALWARE Cobalt Strike Malleable C2 Profile (download)", "command-and-control", 1, true, 37),
  mkRule(2027865, "alert", "http", "ET MALWARE Win32/Emotet Payload Delivery", "trojan-activity", 1, true, 19),
  mkRule(2024317, "alert", "http", "ET SCAN Nmap User-Agent Detected", "attempted-recon", 3, true, 88),
  mkRule(2024375, "alert", "http", "ET SCAN Possible Nmap User-Agent Observed", "attempted-recon", 3, true, 54),
  mkRule(2033715, "alert", "tls", "ET MALWARE Cobalt Strike Beacon Observed (Malleable SNI)", "command-and-control", 1, true, 61),
  mkRule(2034913, "drop", "http", "ET MALWARE Ursnif/Gozi CnC Host Observed", "command-and-control", 1, true, 7),
  mkRule(2042150, "drop", "http", "ET EXPLOIT-KIT MegaCortex Redirection Attempt", "exploit-kit", 1, true, 2),
  mkRule(2043526, "alert", "dns", "ET MALWARE DGA Domain in DNS Lookup (xn-- TLD)", "misc-activity", 2, true, 23),
  mkRule(2046218, "alert", "tls", "ET MALWARE TA450 Mafalda TLS SNI", "command-and-control", 1, true, 11),
  mkRule(2047904, "alert", "dns", "ET MALWARE DNS Query for Placeholder DGA Domain", "misc-activity", 2, true, 15),
  mkRule(2048811, "alert", "http", "ET MALWARE Vidar Stealer Config Retrieval", "trojan-activity", 1, true, 9),
  mkRule(2050244, "alert", "dns", "ET MALWARE Cerber DGA DNS Lookup", "misc-activity", 2, true, 0),
  mkRule(2051735, "alert", "http", "ET MALWARE Snake Keylogger CnC Check-in", "trojan-activity", 1, true, 4),
  mkRule(2052562, "drop", "http", "ET POLICY Suspicious PowerShell Web Request", "policy", 2, true, 31),
  mkRule(2053109, "alert", "http", "ET MALWARE Agentic Loader Payload Fetch", "trojan-activity", 1, true, 6),
  mkRule(2054177, "alert", "tls", "ET MALWARE Redline Stealer TLS Activity", "command-and-control", 1, true, 13),
  mkRule(2055201, "alert", "http", "ET EXPLOIT-KIT Keitaro TDS Landing Detected", "exploit-kit", 1, true, 1),
  mkRule(2056110, "alert", "dns", "ET MALWARE BitRAT DGA Lookup", "misc-activity", 2, true, 0),
  mkRule(2057488, "alert", "http", "ET MALWARE AsyncRAT Config Fetch", "command-and-control", 1, true, 5),
  mkRule(2058230, "alert", "http", "ET SCAN Advanced IP Scanner User-Agent", "attempted-recon", 3, true, 27),
  mkRule(2059601, "drop", "tls", "ET MALWARE Known Botnet TLS Fingerprint (JA3)", "command-and-control", 1, true, 8),
  mkRule(2060155, "alert", "http", "ET POLICY Plain Password POST to External Host", "policy", 2, false, 0, { by: "admin", at: "2026-10-09T02:15:00Z" }),
  mkRule(2061288, "alert", "http", "ET USER_AGENTS Suspicious Generic UA (wide deployment)", "policy", 3, false, 0, { by: "soc.lead", at: "2026-10-08T07:40:00Z" }),
  mkRule(2062341, "alert", "dns", "ET DNS Query to .top TLD - Possible Malicious", "badunknown", 3, true, 46),
  mkRule(2063172, "alert", "http", "ET MALWARE XWorm CnC Traffic", "command-and-control", 1, true, 3),
  mkRule(2064059, "alert", "http", "ET MALWARE Formbook Form Grabbing Check-in", "trojan-activity", 1, true, 12),
  mkRule(2065120, "alert", "tls", "ET MALWARE Agent Tesla Exfil TLS SNI", "trojan-activity", 1, true, 2),
  mkRule(2066034, "alert", "http", "ET SCAN Masscan Banner Observed", "attempted-recon", 2, true, 17),
  mkRule(2067148, "alert", "dns", "ET MALWARE Lumma Stealer DGA Domain", "misc-activity", 2, true, 21),
];

export const demoRulesSummary: RulesSummary = {
  total: demoRules.length,
  enabled: demoRules.filter((r) => r.enabled).length,
  disabled: demoRules.filter((r) => !r.enabled).length,
  actions: { alert: demoRules.filter((r) => r.action === "alert").length,
             drop: demoRules.filter((r) => r.action === "drop").length },
  top_categories: Object.fromEntries(Object.entries(
    demoRules.reduce<Record<string, number>>((acc, r) => {
      const k = r.classtype ?? "unclassified";
      acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, {}))),
  // v0.12.7: demo mirrors the backend source taxonomy (ET vs local)
  by_source: {
    suricata: demoRules.filter((r) => !r.custom).length,
    local: demoRules.filter((r) => !!r.custom).length,
  },
  rules_file_updated: "2026-10-12T01:30:00Z",
  rules_file_exists: true,
  skipped_lines: 0,
  sensor_online: true,
  update_tool: "suricata-update",
};

// v0.12.7: demo inventory of the sensor's local.zeek (Rule Manager
// "Zeek" tab) - mirrors sensor/zeek/local.zeek in the repo.
export const demoZeekScripts: ZeekScriptList = {
  exists: true,
  path: "/opt/zeek/share/zeek/site/local.zeek",
  total_lines: 14,
  comment_lines: 4,
  load_count: 6,
  items: [
    { line: 1, kind: "other", text: "# local.zeek - sensor policy entrypoint" },
    { line: 3, kind: "load", text: "@load base/frameworks/notice" },
    { line: 4, kind: "load", text: "@load policy/protocols/conn/known-hosts" },
    { line: 5, kind: "load", text: "@load policy/protocols/ssl/known-certs" },
    { line: 6, kind: "load", text: "@load policy/protocols/dns/download-executables" },
    { line: 8, kind: "load-sigs", text: "@load-sigs ./my-signatures.sig" },
    { line: 10, kind: "redef", text: "redef ignore_checksums = T;" },
    { line: 12, kind: "load", text: "@load policy/tuning/defaults" },
  ],
  note: "read-only inventory of the Zeek policy scripts "
        + "loaded on the sensor (local.zeek)",
};

export function demoToggleRule(sid: number, enabled: boolean,
                               user: string): RuleRow {
  const rule = demoRules.find((r) => r.sid === sid);
  if (!rule) throw new Error("rule not found");
  rule.enabled = enabled;
  rule.changed_by = user;
  rule.changed_at = new Date().toISOString();
  demoRulesSummary.enabled = demoRules.filter((r) => r.enabled).length;
  demoRulesSummary.disabled = demoRules.filter((r) => !r.enabled).length;
  return rule;
}

// ------------------------------------------- custom rule editor (v0.11)
const CUSTOM_RULE_TEXTS: Record<number, string> = {
  1000001: 'alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"NDRLAB Internal asset beaconing UA"; flow:established,to_server; http.user_agent; content:"ndr-lab-agent/1.0"; classtype:attempted-recon; sid:1000001; rev:1;)',
  1000002: 'alert dns $HOME_NET any -> any 53 (msg:"NDRLAB Dev *.lab.internal suffix never resolved externally"; dns.query; content:".lab.internal"; endswith; classtype:policy; sid:1000002; rev:1;)',
};

const mkCustomRule = (sid: number, action: "alert" | "drop", protocol: string,
                      msg: string, classtype: string, priority: number,
                      enabled: boolean, hits_7d: number): RuleRow => ({
  sid, gid: 1, rev: 1, action, protocol,
  src: "$HOME_NET", sport: "any", dst: "$EXTERNAL_NET", dport: "any",
  msg, classtype, priority, enabled, hits_7d,
  changed_by: "admin", changed_at: iso(NOW - 3 * DAY),
  custom: true, rule_text: CUSTOM_RULE_TEXTS[sid] ?? null,
  created_by: "admin", created_at: iso(NOW - 3 * DAY),
  updated_by: null, updated_at: iso(NOW - 3 * DAY),
});

export const demoCustomRules: RuleRow[] = [
  mkCustomRule(1000001, "alert", "http",
    "NDRLAB Internal asset beaconing UA", "attempted-recon", 3, true, 5),
  mkCustomRule(1000002, "alert", "dns",
    "NDRLAB Dev *.lab.internal suffix never resolved externally",
    "policy", 3, true, 12),
];
demoRules.push(...demoCustomRules);
demoRulesSummary.total = demoRules.length;
demoRulesSummary.enabled = demoRules.filter((r) => r.enabled).length;
demoRulesSummary.disabled = demoRules.filter((r) => !r.enabled).length;

export function demoValidateRuleText(text: string): RuleValidateResult {
  const line = (text || "").trim();
  const m = line.match(
    /^(alert|drop|pass|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s*(->|<>)\s*(\S+)\s+(\S+)\s*\((.*)\)\s*$/);
  if (!line) return { ok: false, error: "rule text is empty" };
  if (!m) return { ok: false, error: "invalid rule syntax - expected '<action> <protocol> <src> <sport> -> <dst> <dport> (...)'", };
  const opts = m[8];
  const sidM = opts.match(/(?:^|;)\s*sid\s*:\s*(\d+)/);
  const msgM = opts.match(/(?:^|;)\s*msg\s*:\s*"([^"]*)"/);
  if (!sidM) return { ok: false, error: "rule has no sid: option (mandatory)" };
  if (!msgM || !msgM[1].trim())
    return { ok: false, error: "rule has no msg: option (mandatory)" };
  const sid = Number(sidM[1]);
  if (sid < 1_000_000 || sid > 1_999_999)
    return { ok: false, error: `custom rule sid must be inside the reserved local range 1000000-1999999 (got ${sid})` };
  const revM = opts.match(/(?:^|;)\s*rev\s*:\s*(\d+)/);
  const clsM = opts.match(/(?:^|;)\s*classtype\s*:\s*([^;]+)/);
  const prioM = opts.match(/(?:^|;)\s*priority\s*:\s*(\d+)/);
  return {
    ok: true, error: null,
    parsed: {
      sid, action: m[1], protocol: m[2].toLowerCase(), msg: msgM[1],
      classtype: clsM ? clsM[1].trim() : null,
      priority: prioM ? Number(prioM[1]) : null,
      rev: revM ? Number(revM[1]) : null,
    },
  };
}

function syncDemoRuleCounts() {
  demoRulesSummary.total = demoRules.length;
  demoRulesSummary.enabled = demoRules.filter((r) => r.enabled).length;
  demoRulesSummary.disabled = demoRules.filter((r) => !r.enabled).length;
}

export function demoCreateCustomRule(input: {
  rule_text: string; enabled: boolean; sid?: number | null;
  created_by: string;
}): RuleRow {
  const v = demoValidateRuleText(input.rule_text);
  if (!v.ok) throw new Error(v.error ?? "invalid rule");
  let sid = v.parsed!.sid;
  let text = input.rule_text.trim();
  if (input.sid && input.sid !== sid) {
    text = text.replace(/\bsid\s*:\s*\d+/, `sid:${input.sid}`);
    sid = input.sid;
  }
  if (demoRules.some((r) => r.sid === sid))
    throw new Error(`rule sid ${sid} already exists`);
  const parsed = demoValidateRuleText(text);
  if (!parsed.ok) throw new Error(parsed.error ?? "invalid rule");
  const row: RuleRow = {
    sid, gid: 1, rev: parsed.parsed!.rev ?? 1,
    action: parsed.parsed!.action, protocol: parsed.parsed!.protocol,
    src: "$HOME_NET", sport: "any", dst: "$EXTERNAL_NET", dport: "any",
    msg: parsed.parsed!.msg, classtype: parsed.parsed!.classtype,
    priority: parsed.parsed!.priority, enabled: input.enabled,
    changed_by: input.created_by, changed_at: new Date().toISOString(),
    custom: true, rule_text: text,
    created_by: input.created_by, created_at: new Date().toISOString(),
    updated_by: null, updated_at: new Date().toISOString(),
  };
  demoRules.push(row);
  syncDemoRuleCounts();
  return row;
}

export function demoUpdateCustomRule(sid: number, patch: {
  rule_text?: string; enabled?: boolean;
}, user: string): RuleRow {
  const rule = demoRules.find((r) => r.sid === sid && r.custom);
  if (!rule) throw new Error("custom rule not found");
  if (patch.enabled !== undefined && patch.enabled !== rule.enabled) {
    rule.enabled = patch.enabled;
    rule.changed_by = user;
    rule.changed_at = new Date().toISOString();
  }
  if (patch.rule_text !== undefined && patch.rule_text.trim() !== rule.rule_text) {
    const v = demoValidateRuleText(patch.rule_text);
    if (!v.ok) throw new Error(v.error ?? "invalid rule");
    if (v.parsed!.sid !== sid)
      throw new Error(`rule text declares sid ${v.parsed!.sid}, but this rule is ${sid}`);
    rule.rule_text = patch.rule_text.trim();
    rule.msg = v.parsed!.msg;
    rule.action = v.parsed!.action;
    rule.protocol = v.parsed!.protocol;
    rule.classtype = v.parsed!.classtype;
    rule.priority = v.parsed!.priority;
    rule.rev = v.parsed!.rev ?? 1;
    rule.updated_by = user;
    rule.updated_at = new Date().toISOString();
  }
  syncDemoRuleCounts();
  return rule;
}

export function demoDeleteCustomRule(sid: number): void {
  const idx = demoRules.findIndex((r) => r.sid === sid && r.custom);
  if (idx < 0) throw new Error("custom rule not found");
  demoRules.splice(idx, 1);
  syncDemoRuleCounts();
}

// ----------------------------------------------- system settings (v0.11)
export const demoSettings: SystemSettings = {
  version: "0.11.0-demo",
  system: { name: "NDR Console", tagline: "network detection & response" },
  branding: { logo: null, favicon: null },
  ntp: { servers: ["time.google.com", "id.pool.ntp.org"],
         timezone: "Asia/Jakarta", enabled: true },
  network: { hostname: "ndr-node-01", dns_servers: ["1.1.1.1", "8.8.8.8"],
             system_dns: ["1.1.1.1", "8.8.8.8"],
             interfaces: [
               { name: "eth0", state: "up", mac: "52:54:00:9a:1c:11",
                 addrs: ["203.0.113.10/24"] },
               { name: "eth1", state: "up", mac: "52:54:00:9a:1c:12",
                 addrs: ["10.10.0.1/24"] },
             ] },
};

const BRANDING_KEY = "ndr.demo.branding";
try {
  const saved = localStorage.getItem(BRANDING_KEY);
  if (saved) {
    const b = JSON.parse(saved) as { logo?: string | null; favicon?: string | null };
    demoSettings.branding.logo = b.logo ?? null;
    demoSettings.branding.favicon = b.favicon ?? null;
  }
} catch { /* SSR / storage disabled */ }

export function demoPatchSystem(patch: { name?: string; tagline?: string }) {
  if (patch.name !== undefined) demoSettings.system.name = patch.name;
  if (patch.tagline !== undefined) demoSettings.system.tagline = patch.tagline;
  return demoSettings.system;
}

export function demoPatchBranding(patch: {
  logo_data_url?: string | null; favicon_data_url?: string | null;
  reset_logo?: boolean; reset_favicon?: boolean;
}) {
  if (patch.reset_logo) demoSettings.branding.logo = null;
  else if (patch.logo_data_url) demoSettings.branding.logo = patch.logo_data_url;
  if (patch.reset_favicon) demoSettings.branding.favicon = null;
  else if (patch.favicon_data_url) demoSettings.branding.favicon = patch.favicon_data_url;
  try {
    localStorage.setItem(BRANDING_KEY, JSON.stringify(demoSettings.branding));
  } catch { /* storage disabled */ }
  return demoSettings.branding;
}

export function demoPatchNtp(patch: {
  servers?: string[]; timezone?: string; enabled?: boolean;
}) {
  if (patch.servers?.length) demoSettings.ntp.servers = patch.servers;
  if (patch.timezone) demoSettings.ntp.timezone = patch.timezone;
  if (patch.enabled !== undefined) demoSettings.ntp.enabled = patch.enabled;
  return demoSettings.ntp;
}

export function demoNtpStatus() {
  return {
    available: true, tool: "timedatectl",
    output: "System clock synchronized: yes\n"
      + `              NTP service: ${demoSettings.ntp.enabled ? "active" : "inactive"}\n`
      + `          Time zone: ${demoSettings.ntp.timezone} (WIB, +0700)`,
    config: demoSettings.ntp,
  };
}

export function demoPatchNetwork(patch: {
  hostname?: string; dns_servers?: string[];
}): NetworkConfig {
  if (patch.hostname) demoSettings.network.hostname = patch.hostname;
  if (patch.dns_servers) demoSettings.network.dns_servers = patch.dns_servers;
  return { ...demoSettings.network, applied: true,
           notes: ["demo: changes persisted in the sandbox session only"] };
}

const DIAG_HOSTS = new Set(["localhost", "ndr-node-01", "127.0.0.1"]);
export function demoDiagnose(tool: DiagnoseTool, target: string,
                             count = 4, port?: number | null): DiagnoseResult {
  const known = DIAG_HOSTS.has(target) || target.endsWith(".example.org")
    || target === "time.google.com" || target === "id.pool.ntp.org";
  const at = new Date().toISOString();
  if (tool === "dns") {
    if (!known)
      return { tool, target, ok: false, at,
               output: `DNS resolution failed: NXDOMAIN (demo)` };
    return { tool, target, ok: true, at,
             output: `${target} resolves to: ${target === "localhost" || target === "127.0.0.1" ? "127.0.0.1" : "203.0.113.10"}` };
  }
  if (tool === "ping") {
    if (!known)
      return { tool, target, ok: false, at,
               output: `ping: ${target}: Name or service not known (demo)` };
    const lines = [`PING ${target} 56(84) bytes of data.`];
    for (let i = 1; i <= count; i++)
      lines.push(`64 bytes from ${target}: icmp_seq=${i} ttl=64 time=${(0.2 + i * 0.07).toFixed(1)} ms`);
    lines.push("", `--- ${target} ping statistics ---`,
               `${count} packets transmitted, ${count} received, 0% packet loss`);
    return { tool, target, ok: true, at, output: lines.join("\n") };
  }
  if (tool === "traceroute") {
    if (!known)
      return { tool, target, ok: false, at,
               output: `traceroute: ${target}: Name or service not known (demo)` };
    const hops = ["192.168.1.1", "10.20.0.1", "203.0.113.1", target];
    const lines = [`traceroute to ${target}, 15 hops max (demo)`];
    hops.forEach((h, i) =>
      lines.push(` ${i + 1}  ${h}  ${(0.4 + i * 1.3).toFixed(1)} ms`));
    return { tool, target, ok: true, at, output: lines.join("\n") };
  }
  // port
  const open = known && [22, 80, 443, 3000, 9200].includes(port ?? 0);
  return { tool, target, ok: open, at,
           output: open ? `TCP ${target}:${port} open`
             : `TCP ${target}:${port} not reachable: connection refused (demo)` };
}

// ------------------------------------------------- PCAP & evidence (doc 15)
const demoPseudoSha = (seed: string) => {
  let h = "";
  for (let i = 0; i < 8; i++) {
    let x = 0;
    for (const ch of seed + i) x = (x * 31 + ch.charCodeAt(0)) >>> 0;
    h += x.toString(16).padStart(8, "0");
  }
  return h;
};

export function demoPcapStorage(): PcapCoverage {
  const oldest = NOW - 26 * HOUR;
  return {
    pcap_dir: "/var/lib/ndr/pcap",
    dir_exists: true,
    file_count: 104,
    total_bytes: 41.6 * 1024 * 1024 * 1024,
    oldest_file: iso(oldest),
    newest_file: iso(NOW - 2 * MIN),
    coverage_from: iso(oldest - 15 * MIN),
    coverage_to: iso(NOW - 2 * MIN + 15 * MIN),
    free_bytes: 412 * 1024 * 1024 * 1024,
    disk_total_bytes: 3 * 1024 * 1024 * 1024 * 1024,
    used_pct: 86.2,
    granularity: "file-level",
    note: "Demo: rolling capture files from Arkime (simple writer).",
  };
}

const demoSessionRows = (): SessionRow[] => [
  {
    doc_id: "evt-9f21c2", index: "ndr-events-2026.10.12",
    "@timestamp": iso(NOW - 8 * MIN), session_id: "flow-771120",
    source_engine: "suricata", event_type: "alert",
    source_ip: "45.134.30.77", destination_ip: "192.168.1.50",
    destination_port: 443, network_transport: "tcp",
    network_bytes: 128_450, tls_sni: "updates-cdn-secure.top",
    pcap_status: "available", pcap_note: "within the retained capture window",
  },
  {
    doc_id: "evt-9f21c3", index: "ndr-events-2026.10.12",
    "@timestamp": iso(NOW - 11 * MIN), session_id: "zeek-UHyLtm4aS",
    source_engine: "zeek", event_type: "tls",
    source_ip: "45.134.30.77", destination_ip: "192.168.1.50",
    destination_port: 443, network_transport: "tcp",
    network_bytes: 96_211, tls_sni: "updates-cdn-secure.top",
    pcap_status: "available", pcap_note: "within the retained capture window",
  },
  {
    doc_id: "evt-9f21c4", index: "ndr-events-2026.10.12",
    "@timestamp": iso(NOW - 19 * MIN), session_id: "flow-771098",
    source_engine: "suricata", event_type: "alert",
    source_ip: "45.134.30.77", destination_ip: "192.168.1.51",
    destination_port: 80, network_transport: "tcp",
    network_bytes: 41_880, http_host: "updates-cdn-secure.top",
    pcap_status: "available", pcap_note: "within the retained capture window",
  },
  {
    doc_id: "evt-9f21c5", index: "ndr-events-2026.10.12",
    "@timestamp": iso(NOW - 24 * MIN), session_id: "zeek-UHyLtw91Q",
    source_engine: "zeek", event_type: "http",
    source_ip: "192.168.1.50", destination_ip: "45.134.30.77",
    destination_port: 8080, network_transport: "tcp",
    network_bytes: 512_004, http_host: "stage-2-payload.top",
    pcap_status: "available", pcap_note: "within the retained capture window",
  },
  {
    doc_id: "evt-8a01b7", index: "ndr-events-2026.10.11",
    "@timestamp": iso(NOW - 31 * HOUR), session_id: "flow-702231",
    source_engine: "suricata", event_type: "alert",
    source_ip: "45.134.30.77", destination_ip: "192.168.1.50",
    destination_port: 443, network_transport: "tcp",
    network_bytes: 88_112, tls_sni: "updates-cdn-secure.top",
    pcap_status: "expired",
    pcap_note: "older than the retained capture window - pruned by rolling retention",
  },
];

export function demoEvidenceSessions(
  scope: "alert" | "incident", scopeId: string): EvidenceSessions {
  const cov = demoPcapStorage();
  // v0.12 PCAP telemetry: the demo builds the SAME sanitized expression
  // the backend would build, but honestly reports Arkime as unreachable
  // (no Arkime runs in demo mode) and provides no deep link.
  const ips = ["45.134.30.77", "192.168.1.50", "192.168.1.51"];
  const domains = ["updates-cdn-secure.top"];
  const safe = (v: string) => /^[A-Za-z0-9._:-]{1,253}$/.test(v);
  const expr = [
    ...ips.filter(safe).map((ip) => `ip == "${ip}"`),
    ...domains.filter(safe).map((d) => `host == "${d}"`),
  ].join(" || ");
  return {
    scope, scope_id: scopeId,
    window: { from: iso(NOW - 6 * HOUR), to: iso(NOW + 5 * MIN) },
    entities: { ips, domains },
    pcap: cov,
    arkime_viewer_url: "http://203.0.113.10:8005",
    arkime: {
      reachable: false,
      viewer_url: "http://203.0.113.10:8005",
      expression: expr,
      url: null,
      error: "demo mode - Arkime viewer is not running in this environment",
    },
    capture_buffer_minutes: 5,
    sessions: demoSessionRows(),
    total: 5,
  };
}

const demoExports: PcapExportRecord[] = [
  {
    id: "3f7a1c9e-5b21-4c0d-9a11-demo00000001",
    actor: "admin", actor_role: "administrator",
    alert_id: "ALR-20261012-0001", incident_id: null,
    reason: "Incident INC-102 follow-up: payload re-download analysis",
    session_count: 3,
    sessions: [{ doc_id: "evt-9f21c2", "@timestamp": iso(NOW - 8 * MIN) }],
    window: { from: iso(NOW - 25 * MIN), to: iso(NOW - 3 * MIN) },
    files: [{ name: "eth0-1760260000.pcap", bytes: 41_880 * 12, sha256: demoPseudoSha("pcap1") }],
    total_bytes: 41_880 * 12,
    bundle_name: "pcap-export-demo-1.zip",
    bundle_sha256: demoPseudoSha("bundle1"),
    status: "ready",
    error: null,
    created_at: iso(NOW - 40 * MIN),
    expires_at: iso(NOW + 20 * MIN),
  },
  {
    id: "6b2d8f41-90cc-4d1e-8a55-demo00000002",
    actor: "analyst.rina", actor_role: "soc_analyst",
    alert_id: "ALR-20261011-0044", incident_id: null,
    reason: "Verification for report draft v2",
    session_count: 1,
    sessions: [],
    window: { from: iso(NOW - 30 * HOUR), to: iso(NOW - 29 * HOUR) },
    files: [],
    total_bytes: 0,
    bundle_name: "pcap-export-demo-2.zip",
    bundle_sha256: demoPseudoSha("bundle2"),
    status: "expired",
    error: null,
    created_at: iso(NOW - 29 * HOUR),
    expires_at: iso(NOW - 28 * HOUR),
  },
];

const createdExports: PcapExportRecord[] = [];

export function demoPcapExports(): PcapExportsList {
  return {
    items: [...createdExports, ...demoExports],
    ttl_minutes: 60,
    limits: { max_files: 5, max_bytes: 2_000_000_000, max_sessions: 50 },
  };
}

export function demoPcapExportCreate(body: PcapExportCreate): PcapExportRecord {
  const now = Date.now();
  const rec: PcapExportRecord = {
    id: `demo-${Math.floor(now / 1000).toString(16)}`,
    actor: DEMO_USER.username, actor_role: DEMO_USER.role,
    alert_id: body.alert_id ?? null, incident_id: body.incident_id ?? null,
    reason: body.reason,
    session_count: body.sessions.length,
    sessions: body.sessions.map((doc_id) => ({ doc_id })),
    window: { from: iso(now - 30 * MIN), to: iso(now - 2 * MIN) },
    files: [{ name: "eth0-1760260100.pcap", bytes: 502_011, sha256: demoPseudoSha(body.sessions.join() + now) }],
    total_bytes: 502_011,
    bundle_name: `pcap-export-demo-${now}.zip`,
    bundle_sha256: demoPseudoSha("new" + now),
    status: "ready",
    error: null,
    created_at: iso(now),
    expires_at: iso(now + 60 * MIN),
  };
  createdExports.unshift(rec);
  return rec;
}
