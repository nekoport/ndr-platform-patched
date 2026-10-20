// Attack reconstruction demo engine (Phase 4).
//
// Builds synthetic incidents whose flagship story mirrors the worked
// example in the product brief: scan -> exploit attempt -> suspicious
// response -> C2 -> lateral movement -> large outbound transfer. All
// RFC 5737 / .test values; confidence values are heuristic-uncalibrated
// and every view carries the no-overclaim disclaimer.

import type {
  AlertDoc, AttackEdge, AttackNode, AttackPhase, CampaignDetail,
  CampaignSummary, EvidenceItem, IncidentDetail, IncidentStats,
  IncidentSummary, KillChainStatus, OutcomeLabel, PhaseProgress,
  ReportVersionMeta, Severity,
} from "./types";
// v0.12.8: demo alert titles are matched against recorded evidence titles
import { demoAlerts } from "./demo";

const PHASE_ORDER: AttackPhase[] = [
  "recon", "initial_access", "delivery", "c2", "lateral", "impact",
];

function ts(h: number, m: number, s: number): string {
  return `2026-10-12T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}Z`;
}

function phases(partial: Partial<Record<AttackPhase, [number, number]>>): PhaseProgress[] {
  // [signal_count, context_count] -> status derived
  return PHASE_ORDER.map((phase) => {
    const counts = partial[phase];
    const signal_count = counts?.[0] ?? 0;
    const context_count = counts?.[1] ?? 0;
    const status = signal_count > 0 ? "observed"
      : context_count > 0 ? "suspected" : "none";
    return {
      phase, status,
      evidence_count: signal_count + context_count,
      signal_count, context_count,
    } as PhaseProgress;
  });
}

function outcome(
  label: OutcomeLabel,
  proven: string[],
  suspected: string[],
  markers: string[],
): IncidentDetail["outcome"] {
  return {
    label, proven, suspected, markers,
    unknown: [
      "Process/payload execution on host (not visible from network)",
      "Whether transferred data was sensitive (content not inspected)",
      "Persistence or further attacker access",
    ],
    disclaimer: "Network-only assessment: proves observed traffic, not host "
      + "state. Endpoint or server logs are required to confirm execution "
      + "and data sensitivity.",
  };
}

// ---------------------------------------------------------------- doc 11 stage data
// Mirrors the backend dual-framework classifier so demo mode renders the
// same Kill Chain assessment the live pipeline produces.
const DEMO_STAGE_ORDER = [
  "reconnaissance", "weaponization", "delivery", "exploitation",
  "installation", "command_and_control", "actions_on_objectives",
] as const;

const DEMO_STAGE_LABELS: Record<string, string> = {
  reconnaissance: "Reconnaissance", weaponization: "Weaponization",
  delivery: "Delivery", exploitation: "Exploitation",
  installation: "Installation", command_and_control: "Command & Control",
  actions_on_objectives: "Actions on Objectives",
};

const DEMO_PHASE_TO_STAGE: Record<string, string> = {
  recon: "reconnaissance", initial_access: "exploitation",
  delivery: "delivery", c2: "command_and_control",
  lateral: "actions_on_objectives", impact: "actions_on_objectives",
};

const DEMO_ATTCK_FOR_STAGE: Record<string, { tactic: string; technique_id: string; technique: string }[]> = {
  reconnaissance: [{ tactic: "Reconnaissance", technique_id: "T1595", technique: "Active Scanning" }],
  delivery: [{ tactic: "Command and Control", technique_id: "T1105", technique: "Ingress Tool Transfer" }],
  exploitation: [{ tactic: "Initial Access", technique_id: "T1190", technique: "Exploit Public-Facing Application" }],
  command_and_control: [{ tactic: "Command and Control", technique_id: "T1071", technique: "Application Layer Protocol" }],
  actions_on_objectives: [{ tactic: "Exfiltration", technique_id: "T1041", technique: "Exfiltration Over C2 Channel" }],
  weaponization: [], installation: [],
};

function stageData(inc: IncidentDetail): Pick<IncidentDetail,
  "stage_progression" | "stage_history" | "deepest_stage"> {
  const counts = new Map<string, { sig: number; ctx: number; firstTs: string | null }>();
  for (const p of inc.phase_progression ?? []) {
    const stage = DEMO_PHASE_TO_STAGE[p.phase] ?? "actions_on_objectives";
    const cur = counts.get(stage) ?? { sig: 0, ctx: 0, firstTs: null };
    cur.sig += p.signal_count;
    cur.ctx += p.context_count;
    counts.set(stage, cur);
  }
  for (const ev of inc.evidence ?? []) {
    const stage = DEMO_PHASE_TO_STAGE[String(ev.phase)] ?? "actions_on_objectives";
    const cur = counts.get(stage) ?? { sig: 0, ctx: 0, firstTs: null };
    if (!cur.firstTs || (ev.ts && ev.ts < cur.firstTs)) cur.firstTs = ev.ts;
    counts.set(stage, cur);
  }
  const progression = DEMO_STAGE_ORDER.map((stage) => {
    const c = counts.get(stage) ?? { sig: 0, ctx: 0, firstTs: null };
    const blind = stage === "weaponization" || stage === "installation";
    const status: KillChainStatus = c.sig > 0 ? "observed" : c.ctx > 0 ? "suspected"
      : blind ? "insufficient_telemetry" : "not_observed";
    const reason = c.sig > 0
      ? `${c.sig} direct signal(s) mapped to this stage`
      : c.ctx > 0
        ? `No direct signal, but ${c.ctx} context record(s) are consistent with this stage`
        : blind
          ? (stage === "weaponization"
            ? "Weaponization happens on attacker infrastructure - network traffic cannot observe it"
            : "Installation requires endpoint telemetry; network-only data cannot confirm or deny it")
          : "Network telemetry covers this stage, but no evidence appeared in this attack story";
    const confidence = c.sig > 0 ? Math.min(95, 55 + (c.sig + c.ctx) * 6)
      : c.ctx > 0 ? Math.min(60, 25 + c.ctx * 5) : 0;
    return {
      stage, label: DEMO_STAGE_LABELS[stage], status,
      evidence_count: c.sig + c.ctx, signal_count: c.sig,
      context_count: c.ctx, confidence,
      attck: DEMO_ATTCK_FOR_STAGE[stage] ?? [], reason,
    };
  });
  let deepest = "reconnaissance";
  for (const s of progression) {
    if (s.status === "observed" || s.status === "suspected") deepest = s.stage;
  }
  const history: NonNullable<IncidentDetail["stage_history"]> = [];
  for (const s of progression) {
    if (s.status === "observed" || s.status === "suspected") {
      history.push({
        ts: s.evidence_count ? inc.first_seen : inc.first_seen,
        stage: s.stage, from: "not_observed", to: s.status,
        evidence_ref: "demo chain",
      });
    }
  }
  return {
    stage_progression: progression,
    stage_history: history,
    deepest_stage: deepest,
  };
}

// ---------------------------------------------------------------- flagship story
function buildFlagship(): IncidentDetail {
  const nodes: AttackNode[] = [
    { key: "ip:203.0.113.25", kind: "ip", label: "203.0.113.25", role: "attacker", phase: "recon", confidence: 78, first_seen: ts(10, 0, 1), last_seen: ts(10, 0, 8), attrs: { geo: "External network (RFC 5737 demo)", asn: "AS64512 demo-vendor" } },
    { key: "ip:10.0.20.15", kind: "ip", label: "10.0.20.15", role: "compromised_host", phase: "initial_access", confidence: 74, first_seen: ts(10, 0, 8), last_seen: ts(10, 5, 0), attrs: { zone: "servers", hostname: "web-prod-02" } },
    { key: "domain:update-checkserve.net", kind: "domain", label: "update-checkserve.net", role: "c2_infra", phase: "c2", confidence: 88, first_seen: ts(10, 1, 15), last_seen: ts(10, 4, 40), attrs: { ti_match: true, ti_confidence: "high", malware: "CobaltStrike-demo" } },
    { key: "ip:198.51.100.77", kind: "ip", label: "198.51.100.77", role: "c2_infra", phase: "c2", confidence: 82, first_seen: ts(10, 1, 15), last_seen: ts(10, 4, 40), attrs: { resolved_from: "update-checkserve.net" } },
    { key: "ip:10.0.20.31", kind: "ip", label: "10.0.20.31", role: "compromised_host", phase: "lateral", confidence: 58, first_seen: ts(10, 2, 30), last_seen: ts(10, 2, 55), attrs: { zone: "servers", hostname: "db-prod-01" } },
    { key: "ip:198.51.100.120", kind: "ip", label: "198.51.100.120", role: "exfil_target", phase: "impact", confidence: 52, first_seen: ts(10, 5, 0), last_seen: ts(10, 5, 0), attrs: { note: "candidate destination - reputation unknown" } },
  ];
  const edges: AttackEdge[] = [
    { src: "ip:203.0.113.25", dst: "ip:10.0.20.15", relation: "probed", phase: "recon", inferred: false, first_seen: ts(10, 0, 1), last_seen: ts(10, 0, 1), evidence_count: 1, confidence: 70 },
    { src: "ip:203.0.113.25", dst: "ip:10.0.20.15", relation: "targeted", phase: "initial_access", inferred: false, first_seen: ts(10, 0, 8), last_seen: ts(10, 0, 10), evidence_count: 2, confidence: 66 },
    { src: "ip:10.0.20.15", dst: "domain:update-checkserve.net", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(10, 1, 15), last_seen: ts(10, 4, 40), evidence_count: 3, confidence: 80 },
    { src: "domain:update-checkserve.net", dst: "ip:198.51.100.77", relation: "resolved_to", phase: "c2", inferred: true, first_seen: ts(10, 1, 15), last_seen: ts(10, 1, 15), evidence_count: 1, confidence: 75 },
    { src: "ip:10.0.20.15", dst: "ip:198.51.100.77", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(10, 1, 15), last_seen: ts(10, 4, 40), evidence_count: 2, confidence: 78 },
    { src: "ip:10.0.20.15", dst: "ip:10.0.20.31", relation: "lateral_to", phase: "lateral", inferred: false, first_seen: ts(10, 2, 30), last_seen: ts(10, 2, 55), evidence_count: 1, confidence: 60 },
    { src: "ip:10.0.20.15", dst: "ip:198.51.100.120", relation: "transferred_to", phase: "impact", inferred: false, first_seen: ts(10, 5, 0), last_seen: ts(10, 5, 0), evidence_count: 1, confidence: 45 },
  ];
  const evidence: EvidenceItem[] = [
    { ts: ts(10, 0, 1), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "portscan-203.0.113.25", title: "Port scan suspected from 203.0.113.25", severity: "medium", phase: "recon", stage: "reconnaissance", attck: [{ tactic: "reconnaissance", technique_id: "T1595", technique: "Active Scanning" }], summary: "142 unique ports on 3 hosts within 10 minutes - consistent with reconnaissance", detail: { alert_type: "portscan_suspected", event_count: 142 } },
    { ts: ts(10, 0, 8), kind: "alert", source: "suricata", ref_index: "ndr-alerts-2026.10.12", ref_id: "suri-exploit-b", title: "Suricata: ET WEB_SERVER Exploit Request", severity: "high", phase: "initial_access", stage: "exploitation", attck: [{ tactic: "initial_access", technique_id: "T1190", technique: "Exploit Public-Facing Application" }], summary: "Exploit-pattern requests from 203.0.113.25 to 10.0.20.15 /api/upload - signature alert indicates an attempt, not proof of success", detail: { alert_type: "suricata_alert_group", category: "web-application-attack" } },
    { ts: ts(10, 0, 10), kind: "alert", source: "suricata", ref_index: "ndr-alerts-2026.10.12", ref_id: "suri-response-b", title: "Suricata: Suspicious server response to exploit probe", severity: "high", phase: "initial_access", stage: "exploitation", attck: [{ tactic: "initial_access", technique_id: "T1190", technique: "Exploit Public-Facing Application" }], summary: "Server response pattern (200 + encoded payload trace) supports - but does not prove - exploitation success", detail: { alert_type: "suricata_alert_group" } },
    { ts: ts(10, 0, 52), kind: "context", source: "zeek", ref_index: "ctx", ref_id: "fileinfo|10:00:52|invoice_pack.exe", title: "File transfer: invoice_pack.exe (application/x-dosexec, 412 KB)", severity: "low", phase: "delivery", stage: "delivery", attck: [{ tactic: "command_and_control", technique_id: "T1105", technique: "Ingress Tool Transfer" }], summary: "Executable downloaded by 10.0.20.15 from 203.0.113.25", detail: { file_name: "invoice_pack.exe", mime_type: "application/x-dosexec", size: 412_672 } },
    { ts: ts(10, 1, 15), kind: "context", source: "zeek", ref_index: "ctx", ref_id: "dns|10:01:15|update-checkserve.net", title: "DNS resolution: update-checkserve.net -> 198.51.100.77", severity: "informational", phase: "c2", stage: "command_and_control", summary: "Resolved 4 minutes before first outbound session", detail: { answers: [{ name: "update-checkserve.net", type: "A", data: "198.51.100.77" }] } },
    { ts: ts(10, 1, 15), kind: "ioc_event", source: "threat-intel", ref_index: "ndr-ioc-matches-2026.10.12", ref_id: "ioc-dom-update-checkserve", title: "IOC match: update-checkserve.net (domain, high confidence)", severity: "high", phase: "c2", stage: "command_and_control", summary: "Domain matched threat intelligence (CobaltStrike-demo infrastructure). Contextual evidence - supports investigation, not proof by itself", detail: { ioc_type: "domain", ioc_source: "urlhaus-demo", confidence: "high" } },
    { ts: ts(10, 1, 40), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "beacon-b-77", title: "Possible beaconing 10.0.20.15 -> 198.51.100.77:443", severity: "medium", phase: "c2", stage: "command_and_control", attck: [{ tactic: "command_and_control", technique_id: "T1071.001", technique: "Web Protocols" }], summary: "23 connections, mean interval 62s, jitter 0.08 - consistent with C2, also with monitoring agents", detail: { alert_type: "beaconing_possible" } },
    { ts: ts(10, 2, 30), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "lateral-b-c", title: "Internal lateral access 10.0.20.15 -> 10.0.20.31:445", severity: "high", phase: "lateral", stage: "actions_on_objectives", attck: [{ tactic: "lateral_movement", technique_id: "T1021.001", technique: "Remote Services: SMB" }], summary: "18 SMB connections crossing servers->servers zone within window - remote-service pattern fits lateral movement, validate against asset roles", detail: { alert_type: "internal_lateral_suspected", dst_port: 445 } },
    { ts: ts(10, 5, 0), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "exfil-b-120", title: "Large outbound transfer 10.0.20.15 -> 198.51.100.120 (2.31 GB)", severity: "medium", phase: "impact", stage: "actions_on_objectives", attck: [{ tactic: "exfiltration", technique_id: "T1041", technique: "Exfiltration Over C2 Channel" }], summary: "2.31 GB across 14 connections - exfiltration candidate requiring validation (content not inspected)", detail: { alert_type: "large_outbound_transfer", bytes: 2_310_000_000 } },
  ];
  return {
    id: "story-flagship-01",
    title: "203.0.113.25 -> web-prod-02 (Recon > Initial Access > C2 > Lateral > Impact)",
    status: "open",
    severity: "critical",
    confidence: 86,
    confidence_basis: "heuristic-uncalibrated",
    first_seen: ts(10, 0, 1),
    last_seen: ts(10, 5, 0),
    updated_at: ts(10, 5, 0),
    entity_count: nodes.length,
    edge_count: edges.length,
    evidence_count: evidence.length,
    signal_count: 6,
    outcome_label: "strong_success",
    phase_progression: phases({
      recon: [1, 0], initial_access: [2, 0], delivery: [0, 1],
      c2: [2, 2], lateral: [1, 0], impact: [1, 0],
    }),
    phases: phases({
      recon: [1, 0], initial_access: [2, 0], delivery: [0, 1],
      c2: [2, 2], lateral: [1, 0], impact: [1, 0],
    }),
    analyst: null,
    created_at: ts(10, 5, 30),
    outcome: outcome(
      "strong_success",
      [
        "Reconnaissance against web-prod-02 was observed (142 ports probed)",
        "An exploitation attempt against /api/upload was observed",
        "Communication matched high-confidence C2 threat intelligence",
        "Executable download followed by C2 contact within 60 seconds",
      ],
      [
        "Host compromise is strongly supported by TI + chain continuity, pending endpoint validation",
        "Large outbound transfer (2.31 GB) is an exfiltration candidate - data sensitivity unknown",
        "db-prod-01 may be reachable via SMB from the compromised host",
      ],
      ["recon_observed", "access_attempted", "delivery_observed", "c2_observed", "c2_ioc_high", "lateral_observed", "impact_observed"],
    ),
    nodes, edges, evidence,
    notes: [
      { author: "s.oktaviani", body: "Server response evidence attached; requesting web-prod-02 EDR triage before containment call.", created_at: ts(10, 12, 0) },
    ],
    history: [
      { occurred_at: ts(10, 5, 30), actor: "ndr-pipeline", action: "story_updated", detail: { evidence: 9 } },
      { occurred_at: ts(10, 0, 5), actor: "ndr-pipeline", action: "story_created", detail: { seed: "portscan-203.0.113.25" } },
    ],
  };
}

// ---------------------------------------------------------------- secondary stories
function buildScanner(): IncidentDetail {
  const evidence: EvidenceItem[] = [
    { ts: ts(6, 14, 2), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "portscan-45.155.204.10", title: "Port scan suspected from 45.155.204.10", severity: "medium", phase: "recon", stage: "reconnaissance", attck: [{ tactic: "reconnaissance", technique_id: "T1595", technique: "Active Scanning" }], summary: "310 unique ports on 22 hosts within 10 minutes", detail: { alert_type: "portscan_suspected" } },
    { ts: ts(6, 21, 40), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "portscan-45.155.204.10-2", title: "Port scan suspected from 45.155.204.10 (second wave)", severity: "medium", phase: "recon", stage: "reconnaissance", attck: [{ tactic: "reconnaissance", technique_id: "T1595", technique: "Active Scanning" }], summary: "Repeat scan pattern 7 hours later - opportunistic mass scanner profile", detail: { alert_type: "portscan_suspected" } },
    { ts: ts(6, 22, 1), kind: "context", source: "zeek", ref_index: "ctx", ref_id: "conn|06:22:01|sweep", title: "Connection sweep across DMZ subnet 10.0.10.0/24", severity: "informational", phase: "recon", stage: "reconnaissance", summary: "Short-lived connections (<2s) across 18 distinct destinations", detail: {} },
  ];
  return {
    id: "story-scanner-02",
    title: "45.155.204.10 -> multiple DMZ hosts (Recon)",
    status: "open",
    severity: "low",
    confidence: 34,
    confidence_basis: "heuristic-uncalibrated",
    first_seen: ts(6, 14, 2),
    last_seen: ts(6, 22, 1),
    updated_at: ts(6, 22, 1),
    entity_count: 2,
    edge_count: 1,
    evidence_count: evidence.length,
    signal_count: 2,
    outcome_label: "indeterminate",
    phase_progression: phases({ recon: [2, 1] }),
    phases: phases({ recon: [2, 1] }),
    analyst: null,
    created_at: ts(6, 22, 5),
    outcome: outcome("indeterminate",
      ["Reconnaissance waves against the DMZ were observed"],
      ["No exploitation, C2 or lateral evidence so far - chain did not progress"],
      ["recon_observed"]),
    nodes: [
      { key: "ip:45.155.204.10", kind: "ip", label: "45.155.204.10", role: "attacker", phase: "recon", confidence: 55, first_seen: ts(6, 14, 2), last_seen: ts(6, 22, 1), attrs: { note: "known mass-scanner range (demo)" } },
      { key: "ip:10.0.10.0/24", kind: "ioc", label: "10.0.10.0/24 (DMZ)", role: "target_range", phase: "recon", confidence: 40, first_seen: ts(6, 14, 2), last_seen: ts(6, 22, 1), attrs: {} },
    ],
    edges: [
      { src: "ip:45.155.204.10", dst: "ip:10.0.10.0/24", relation: "probed", phase: "recon", inferred: false, first_seen: ts(6, 14, 2), last_seen: ts(6, 22, 1), evidence_count: 2, confidence: 50 },
    ],
    evidence,
    notes: [],
    history: [{ occurred_at: ts(6, 22, 5), actor: "ndr-pipeline", action: "story_created", detail: {} }],
  };
}

function buildDga(): IncidentDetail {
  const evidence: EvidenceItem[] = [
    { ts: ts(4, 2, 11), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "nxdomain-ws77", title: "NXDOMAIN burst from 10.0.10.77", severity: "low", phase: "recon", stage: "reconnaissance", summary: "38/51 NXDOMAIN responses - weak DGA indicator", detail: { alert_type: "dns_nxdomain_burst" } },
    { ts: ts(4, 2, 40), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "dga-ws77", title: "Possible DGA queries from 10.0.10.77 (14 unique domains)", severity: "medium", phase: "c2", stage: "command_and_control", attck: [{ tactic: "command_and_control", technique_id: "T1568.002", technique: "Domain Generation Algorithms" }], summary: "Mean label entropy 3.9 - consistent with algorithmically generated C2 domains", detail: { alert_type: "dga_suspected" } },
    { ts: ts(4, 3, 5), kind: "context", source: "zeek", ref_index: "ctx", ref_id: "dns|04:03:05|qzkjwm03idor.test", title: "DNS resolution: qzkjwm03idor.test -> 198.51.100.205", severity: "informational", phase: "c2", stage: "command_and_control", summary: "One DGA domain resolved successfully", detail: {} },
    { ts: ts(4, 3, 30), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "beacon-ws77", title: "Possible beaconing 10.0.10.77 -> 198.51.100.205:8443", severity: "medium", phase: "c2", stage: "command_and_control", attck: [{ tactic: "command_and_control", technique_id: "T1071.001", technique: "Web Protocols" }], summary: "31 connections, mean interval 90s, jitter 0.11", detail: { alert_type: "beaconing_possible" } },
  ];
  return {
    id: "story-dga-03",
    title: "10.0.10.77 -> qzkjwm03idor.test (C2)",
    status: "confirmed",
    severity: "high",
    confidence: 71,
    confidence_basis: "heuristic-uncalibrated",
    first_seen: ts(4, 2, 11),
    last_seen: ts(4, 3, 30),
    updated_at: ts(4, 9, 0),
    entity_count: 4,
    edge_count: 3,
    evidence_count: evidence.length,
    signal_count: 3,
    outcome_label: "suspected_success",
    phase_progression: phases({ recon: [1, 0], c2: [2, 1] }),
    phases: phases({ recon: [1, 0], c2: [2, 1] }),
    analyst: "d.wijaya",
    created_at: ts(4, 3, 40),
    outcome: outcome("suspected_success",
      ["NXDOMAIN burst followed by successful resolution of a high-entropy domain", "Periodic sessions to the resolved address were observed"],
      ["DGA + beaconing chain is consistent with staged C2; initial access was NOT observed in the window and may predate telemetry", "Host compromise suspected - pending endpoint validation"],
      ["recon_observed", "c2_observed"]),
    nodes: [
      { key: "ip:10.0.10.77", kind: "ip", label: "10.0.10.77", role: "compromised_host", phase: "c2", confidence: 66, first_seen: ts(4, 2, 11), last_seen: ts(4, 3, 30), attrs: { zone: "workstations", hostname: "ws-fin-07" } },
      { key: "domain:qzkjwm03idor.test", kind: "domain", label: "qzkjwm03idor.test", role: "c2_infra", phase: "c2", confidence: 64, first_seen: ts(4, 3, 5), last_seen: ts(4, 3, 5), attrs: { entropy: 3.9 } },
      { key: "ip:198.51.100.205", kind: "ip", label: "198.51.100.205", role: "c2_infra", phase: "c2", confidence: 60, first_seen: ts(4, 3, 5), last_seen: ts(4, 3, 30), attrs: {} },
      { key: "ip:10.0.0.1", kind: "ip", label: "10.0.0.1 (resolver)", role: "entity", phase: "recon", confidence: 30, first_seen: ts(4, 2, 11), last_seen: ts(4, 2, 11), attrs: {} },
    ],
    edges: [
      { src: "ip:10.0.10.77", dst: "domain:qzkjwm03idor.test", relation: "queried", phase: "c2", inferred: true, first_seen: ts(4, 2, 40), last_seen: ts(4, 2, 40), evidence_count: 2, confidence: 60 },
      { src: "domain:qzkjwm03idor.test", dst: "ip:198.51.100.205", relation: "resolved_to", phase: "c2", inferred: true, first_seen: ts(4, 3, 5), last_seen: ts(4, 3, 5), evidence_count: 1, confidence: 60 },
      { src: "ip:10.0.10.77", dst: "ip:198.51.100.205", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(4, 3, 30), last_seen: ts(4, 3, 30), evidence_count: 1, confidence: 62 },
    ],
    evidence,
    notes: [
      { author: "d.wijaya", body: "Confirmed pattern matches staging behavior; host isolated at 09:00 pending reimage. TI lookup for the domain did not match existing feeds - submitted for extraction.", created_at: ts(4, 9, 5) },
    ],
    history: [
      { occurred_at: ts(4, 9, 0), actor: "d.wijaya", action: "status_change", detail: { from: "open", to: "confirmed" } },
      { occurred_at: ts(4, 3, 40), actor: "ndr-pipeline", action: "story_created", detail: {} },
    ],
  };
}

function buildBenign(): IncidentDetail {
  const evidence: EvidenceItem[] = [
    { ts: ts(2, 18, 0), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "beacon-backup", title: "Possible beaconing 10.0.20.40 -> 10.0.30.8:445", severity: "medium", phase: "c2", stage: "command_and_control", attck: [{ tactic: "command_and_control", technique_id: "T1071", technique: "Application Layer Protocol" }], summary: "Low-jitter periodic SMB sessions every 300s", detail: { alert_type: "beaconing_possible" } },
  ];
  return {
    id: "story-benign-04",
    title: "10.0.20.40 -> backup-01 (C2)",
    status: "benign",
    severity: "medium",
    confidence: 41,
    confidence_basis: "heuristic-uncalibrated",
    first_seen: ts(2, 18, 0),
    last_seen: ts(2, 22, 0),
    updated_at: ts(2, 23, 10),
    entity_count: 2,
    edge_count: 1,
    evidence_count: evidence.length,
    signal_count: 1,
    outcome_label: "attempted",
    phase_progression: phases({ c2: [1, 0] }),
    phases: phases({ c2: [1, 0] }),
    analyst: "s.oktaviani",
    created_at: ts(2, 22, 10),
    outcome: outcome("attempted",
      ["Periodic SMB sessions were observed"],
      ["Analyst verdict: scheduled backup job (Veeam demo), not C2 - rule tuned to exclude this pair"],
      ["c2_observed"]),
    nodes: [
      { key: "ip:10.0.20.40", kind: "ip", label: "10.0.20.40", role: "entity", phase: "c2", confidence: 30, first_seen: ts(2, 18, 0), last_seen: ts(2, 22, 0), attrs: { hostname: "bk-mgr-01" } },
      { key: "ip:10.0.30.8", kind: "ip", label: "10.0.30.8", role: "entity", phase: "c2", confidence: 30, first_seen: ts(2, 18, 0), last_seen: ts(2, 22, 0), attrs: { hostname: "backup-01" } },
    ],
    edges: [
      { src: "ip:10.0.20.40", dst: "ip:10.0.30.8", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(2, 18, 0), last_seen: ts(2, 22, 0), evidence_count: 1, confidence: 35 },
    ],
    evidence,
    notes: [
      { author: "s.oktaviani", body: "Verified against backup schedule: nightly full sync at 18:00. Marked benign; beaconing rule threshold raised for this pair via allowlist note.", created_at: ts(2, 23, 10) },
    ],
    history: [
      { occurred_at: ts(2, 23, 10), actor: "s.oktaviani", action: "status_change", detail: { from: "open", to: "benign" } },
    ],
  };
}

// Secondary infection story: a DIFFERENT internal host contacting the
// SAME C2 domain as the flagship chain. This is what powers the
// cross-campaign "shared C2 infrastructure" correlation in the threat
// map relationship graph (multi-IP campaign demo).
function buildC2Secondary(): IncidentDetail {
  const evidence: EvidenceItem[] = [
    { ts: ts(10, 3, 12), kind: "context", source: "zeek", ref_index: "ctx", ref_id: "dns|10:03:12|update-checkserve.net", title: "DNS resolution: update-checkserve.net -> 198.51.100.77", severity: "informational", phase: "c2", stage: "command_and_control", summary: "Resolved by 10.0.10.45 (ws-hr-03) 2 minutes after web-prod-02 contacted it", detail: { answers: [{ name: "update-checkserve.net", type: "A", data: "198.51.100.77" }] } },
    { ts: ts(10, 3, 15), kind: "ioc_event", source: "threat-intel", ref_index: "ndr-ioc-matches-2026.10.12", ref_id: "ioc-dom-update-checkserve-ws45", title: "IOC match: update-checkserve.net (domain, high confidence)", severity: "high", phase: "c2", stage: "command_and_control", summary: "Same TI-matched C2 domain contacted by a second internal host", detail: { ioc_type: "domain", ioc_source: "urlhaus-demo", confidence: "high" } },
    { ts: ts(10, 3, 40), kind: "alert", source: "pipeline", ref_index: "ndr-alerts-2026.10.12", ref_id: "beacon-ws45-77", title: "Possible beaconing 10.0.10.45 -> 198.51.100.77:443", severity: "high", phase: "c2", stage: "command_and_control", attck: [{ tactic: "command_and_control", technique_id: "T1071.001", technique: "Web Protocols" }], summary: "19 connections, mean interval 62s, jitter 0.09 - interval matches the web-prod-02 beacon profile", detail: { alert_type: "beaconing_possible" } },
  ];
  return {
    id: "story-c2-05",
    title: "10.0.10.45 -> update-checkserve.net (C2)",
    status: "open",
    severity: "high",
    confidence: 77,
    confidence_basis: "heuristic-uncalibrated",
    first_seen: ts(10, 3, 12),
    last_seen: ts(10, 4, 55),
    updated_at: ts(10, 4, 55),
    entity_count: 3,
    edge_count: 2,
    evidence_count: evidence.length,
    signal_count: 2,
    outcome_label: "suspected_success",
    phase_progression: phases({ c2: [2, 1] }),
    phases: phases({ c2: [2, 1] }),
    analyst: null,
    created_at: ts(10, 5, 0),
    outcome: outcome("suspected_success",
      [
        "The TI-matched C2 domain update-checkserve.net was contacted by a second internal host",
        "Beacon interval and jitter match the profile observed on web-prod-02",
      ],
      [
        "Host compromise suspected - shares C2 infrastructure with the flagship chain, pending endpoint validation",
        "Initial access for this host was NOT observed in the window",
      ],
      ["c2_observed", "c2_ioc_high"]),
    nodes: [
      { key: "ip:10.0.10.45", kind: "ip", label: "10.0.10.45", role: "compromised_host", phase: "c2", confidence: 70, first_seen: ts(10, 3, 12), last_seen: ts(10, 4, 55), attrs: { zone: "workstations", hostname: "ws-hr-03" } },
      { key: "domain:update-checkserve.net", kind: "domain", label: "update-checkserve.net", role: "c2_infra", phase: "c2", confidence: 88, first_seen: ts(10, 3, 12), last_seen: ts(10, 4, 55), attrs: { ti_match: true, ti_confidence: "high", malware: "CobaltStrike-demo", ti_source: "urlhaus-demo", ti_updated: "2026-10-12T09:30:00Z" } },
      { key: "ip:198.51.100.77", kind: "ip", label: "198.51.100.77", role: "c2_infra", phase: "c2", confidence: 82, first_seen: ts(10, 3, 12), last_seen: ts(10, 4, 55), attrs: { resolved_from: "update-checkserve.net" } },
    ],
    edges: [
      { src: "ip:10.0.10.45", dst: "domain:update-checkserve.net", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(10, 3, 12), last_seen: ts(10, 4, 55), evidence_count: 3, confidence: 80 },
      { src: "ip:10.0.10.45", dst: "ip:198.51.100.77", relation: "contacted", phase: "c2", inferred: false, first_seen: ts(10, 3, 40), last_seen: ts(10, 4, 55), evidence_count: 2, confidence: 76 },
    ],
    evidence,
    notes: [
      { author: "d.wijaya", body: "Second host on the same C2 domain as story-flagship-01 - linked in the relationship graph via shared infrastructure. Isolation queue raised for ws-hr-03.", created_at: ts(10, 11, 0) },
    ],
    history: [
      { occurred_at: ts(10, 5, 0), actor: "ndr-pipeline", action: "story_created", detail: { seed: "beacon-ws45-77" } },
    ],
  };
}

const demoIncidents: IncidentDetail[] = [
  buildFlagship(), buildC2Secondary(), buildDga(), buildScanner(),
  buildBenign(),
];
// attach doc-11 Kill Chain assessment derived from the phase data
for (const inc of demoIncidents) {
  Object.assign(inc, stageData(inc));
}
export { demoIncidents };

// ------------------------------------------------- campaigns (v0.12)
// Analyst bookkeeping demo: group related incidents into one campaign.
// Rollups (severity / window / count) are recomputed exactly like the
// backend does on every membership change. Membership NEVER rewrites
// the incidents' evidence, entities or relations.

const SEV_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, informational: 0,
};

let campaignSeq = 0;

const demoCampaigns: CampaignSummary[] = [
  {
    id: "cmp-demo-c2infra",
    title: "update-checkserve.net C2 infrastructure",
    description:
      "Flagship compromise (web-prod-02) and the secondary beaconing host " +
      "(10.0.10.45) share the same C2 domain - tracked by the SOC as one " +
      "campaign. Membership is analyst bookkeeping only.",
    status: "open",
    created_by: "admin",
    incident_count: 2,
    severity: "critical",
    first_seen: ts(10, 0, 1),
    last_seen: ts(10, 5, 0),
    created_at: ts(10, 6, 0),
    updated_at: ts(10, 6, 0),
  },
];

for (const inc of demoIncidents) {
  if (inc.id === "story-flagship-01" || inc.id === "story-c2-05") {
    inc.campaign_id = "cmp-demo-c2infra";
  }
}

function demoCampaignTitle(campaignId: string | null | undefined):
    string | null {
  if (!campaignId) return null;
  return demoCampaigns.find((c) => c.id === campaignId)?.title
    ?? campaignId;
}

function recomputeCampaign(c: CampaignSummary): void {
  const members = demoIncidents.filter((i) => i.campaign_id === c.id);
  c.incident_count = members.length;
  if (members.length === 0) {
    c.severity = "low";
    c.first_seen = null;
    c.last_seen = null;
  } else {
    c.severity = members.reduce(
      (a, b) => ((SEV_RANK[b.severity] ?? 0) > (SEV_RANK[a.severity] ?? 0)
        ? b : a),
    ).severity;
    const fs = members.map((m) => m.first_seen).filter(Boolean) as string[];
    const ls = members.map((m) => m.last_seen).filter(Boolean) as string[];
    c.first_seen = fs.length ? fs.sort()[0] : null;
    c.last_seen = ls.length ? ls.sort()[ls.length - 1] : null;
  }
  c.updated_at = new Date().toISOString();
}

export function buildCampaignList(params?: {
  status?: string; q?: string;
}): { total: number; items: CampaignSummary[] } {
  let items = [...demoCampaigns];
  if (params?.status && params.status !== "all") {
    items = items.filter((c) => c.status === params.status);
  }
  if (params?.q) {
    const kw = params.q.toLowerCase();
    items = items.filter((c) => c.title.toLowerCase().includes(kw)
      || c.id.toLowerCase().includes(kw));
  }
  return { total: items.length, items };
}

export function buildCampaignDetail(id: string): CampaignDetail | null {
  const c = demoCampaigns.find((x) => x.id === id);
  if (!c) return null;
  const incidents = demoIncidents
    .filter((i) => i.campaign_id === id)
    .map((i) => {
      const { outcome: _o, nodes: _n, edges: _e, evidence: _e2,
        notes: _n2, history: _h, phase_progression: _p, ...summary } = i;
      return summary as IncidentSummary;
    });
  return { ...c, incidents };
}

export function demoCreateCampaign(
  title: string, description: string, incidentIds: string[], actor: string,
): CampaignSummary {
  campaignSeq += 1;
  const c: CampaignSummary = {
    id: `cmp-demo-${String(campaignSeq).padStart(3, "0")}`,
    title, description, status: "open", created_by: actor,
    incident_count: 0, severity: "low", first_seen: null, last_seen: null,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  };
  demoCampaigns.unshift(c);
  for (const iid of incidentIds) {
    const inc = demoIncidents.find((i) => i.id === iid);
    if (inc) {
      inc.campaign_id = c.id;
      inc.history = [{ occurred_at: new Date().toISOString(), actor,
        action: "campaign_merge", detail: { campaign_id: c.id } },
        ...inc.history];
    }
  }
  recomputeCampaign(c);
  return c;
}

export function demoAttachToCampaign(
  campaignId: string, incidentIds: string[], actor: string,
): CampaignSummary | null {
  const c = demoCampaigns.find((x) => x.id === campaignId);
  if (!c) return null;
  for (const iid of incidentIds) {
    const inc = demoIncidents.find((i) => i.id === iid);
    if (inc) {
      inc.campaign_id = c.id;
      inc.history = [{ occurred_at: new Date().toISOString(), actor,
        action: "campaign_merge", detail: { campaign_id: c.id } },
        ...inc.history];
    }
  }
  recomputeCampaign(c);
  return c;
}

export function demoDetachFromCampaign(
  campaignId: string, incidentId: string, actor: string,
): CampaignSummary | null {
  const c = demoCampaigns.find((x) => x.id === campaignId);
  const inc = demoIncidents.find(
    (i) => i.id === incidentId && i.campaign_id === campaignId);
  if (!c || !inc) return null;
  inc.campaign_id = null;
  inc.history = [{ occurred_at: new Date().toISOString(), actor,
    action: "campaign_split", detail: { campaign_id: c.id } },
    ...inc.history];
  recomputeCampaign(c);
  return c;
}

export function demoUpdateCampaign(
  campaignId: string,
  patch: { title?: string; description?: string; status?: string },
  actor: string,
): CampaignSummary | null {
  const c = demoCampaigns.find((x) => x.id === campaignId);
  if (!c) return null;
  if (patch.title !== undefined) c.title = patch.title;
  if (patch.description !== undefined) c.description = patch.description;
  if (patch.status !== undefined) {
    c.status = patch.status as CampaignSummary["status"];
  }
  c.updated_at = new Date().toISOString();
  if (patch.status || patch.title) {
    for (const inc of demoIncidents) {
      if (inc.campaign_id === c.id) {
        inc.history = [{ occurred_at: new Date().toISOString(), actor,
          action: "campaign_update", detail: { campaign_id: c.id } },
          ...inc.history];
      }
    }
  }
  return c;
}

export function buildIncidentList(params?: {
  status?: string; severity?: string; q?: string;
  time_from?: string | null; time_to?: string | null;
}): { total: number; items: IncidentSummary[] } {
  let items = [...demoIncidents];
  const { status, severity, q } = params ?? {};
  if (status && status !== "all") {
    const wanted = new Set(status.split(",").map((s) => s.trim()));
    items = items.filter((i) => wanted.has(i.status));
  }
  if (severity && severity !== "all") {
    const wanted = new Set(severity.split(",").map((s) => s.trim()));
    items = items.filter((i) => wanted.has(i.severity));
  }
  if (params?.time_from) {
    items = items.filter((i) => !!i.last_seen && i.last_seen >= params.time_from!);
  }
  if (params?.time_to) {
    items = items.filter((i) => !!i.first_seen && i.first_seen <= params.time_to!);
  }
  if (q) {
    const kw = q.toLowerCase();
    items = items.filter((i) => i.title.toLowerCase().includes(kw)
      || i.id.toLowerCase().includes(kw));
  }
  return {
    total: items.length,
    items: items.map((i) => {
      const { outcome: _o, nodes: _n, edges: _e, evidence: _e2,
        notes: _n2, history: _h, phase_progression: _p, ...summary } = i;
      return {
        ...summary,
        campaign_title: demoCampaignTitle(summary.campaign_id),
      } as IncidentSummary;
    }),
  };
}

export function buildIncidentStats(): IncidentStats {
  const by_status: Record<string, number> = {};
  const open_by_severity: Record<string, number> = {};
  const by_outcome: Record<string, number> = {};
  demoIncidents.forEach((i) => {
    by_status[i.status] = (by_status[i.status] ?? 0) + 1;
    if (i.status === "open" || i.status === "confirmed") {
      open_by_severity[i.severity] = (open_by_severity[i.severity] ?? 0) + 1;
    }
    by_outcome[i.outcome_label] = (by_outcome[i.outcome_label] ?? 0) + 1;
  });
  return {
    total: demoIncidents.length,
    by_status,
    open_by_severity,
    by_outcome,
    open_total: (by_status.open ?? 0) + (by_status.confirmed ?? 0),
  };
}

export function buildIncidentDetail(id: string): IncidentDetail | null {
  const inc = demoIncidents.find((i) => i.id === id) ?? null;
  if (inc) inc.campaign_title = demoCampaignTitle(inc.campaign_id);
  return inc;
}

// v0.12.8: incidents whose recorded evidence references an alert id.
// Honest linkage only - mirrors the live /related-incident endpoint.
// Demo note: live demo alerts get generated ids, so the demo matcher
// ALSO accepts an exact title match against recorded evidence titles
// (the demo incidents reuse the exact detection titles) - live mode
// always matches by recorded alert id only.
export function demoRelatedIncidentsForAlert(alertId: string): Array<{
  incident_id: string; title: string; status: string; severity: string;
  outcome_label: string;
}> {
  const alert = demoAlerts.find((a) => a.alert_id === alertId);
  return demoIncidents
    .filter((i) => (i.evidence ?? []).some(
      (ev) => ev.ref_id === alertId
        || (!!alert?.title && ev.title === alert.title)))
    .slice(0, 5)
    .map((i) => ({
      incident_id: i.id,
      title: i.title,
      status: i.status,
      severity: i.severity,
      outcome_label: i.outcome_label,
    }));
}

// ------------------------------------------- report versions (v0.12)
// Immutable snapshots of the generated Markdown report. Each version
// records what the platform claimed at save time; later changes never
// rewrite history.

const demoReportVersions: Record<string, ReportVersionMeta[]> = {};
const demoReportMds: Record<string, Record<number, string>> = {};

export function demoSaveReportVersion(
  id: string, actor: string,
): ReportVersionMeta {
  const inc = demoIncidents.find((i) => i.id === id);
  if (!inc) throw new Error("incident not found");
  const list = demoReportVersions[id] ?? [];
  const version = list.length
    ? Math.max(...list.map((v) => v.version)) + 1 : 1;
  const md = buildIncidentReportMd(inc);
  const meta: ReportVersionMeta = {
    version,
    generated_by: actor,
    incident_status: inc.status,
    severity: inc.severity,
    outcome_label: inc.outcome_label,
    evidence_count: inc.evidence_count,
    signal_count: inc.signal_count,
    created_at: new Date().toISOString(),
  };
  demoReportVersions[id] = [meta, ...list];
  demoReportMds[id] = { ...(demoReportMds[id] ?? {}), [version]: md };
  inc.history = [{ occurred_at: new Date().toISOString(), actor,
    action: "report_version_saved", detail: { version } }, ...inc.history];
  return meta;
}

export function demoReportVersionsList(
  id: string,
): { items: ReportVersionMeta[]; total: number } {
  return { items: demoReportVersions[id] ?? [], total:
    (demoReportVersions[id] ?? []).length };
}

export function demoReportVersionMd(
  id: string, version: number,
): string | null {
  return demoReportMds[id]?.[version] ?? null;
}

export function demoUpdateIncidentStatus(
  id: string, status: string, note: string | null, analyst: string,
): boolean {
  const inc = demoIncidents.find((i) => i.id === id);
  if (!inc) return false;
  const from = inc.status;
  inc.status = status as IncidentDetail["status"];
  inc.analyst = analyst;
  inc.updated_at = new Date().toISOString();
  if (note) {
    inc.notes = [...inc.notes,
      { author: analyst, body: note, created_at: new Date().toISOString() }];
  }
  inc.history = [
    { occurred_at: new Date().toISOString(), actor: analyst,
      action: "status_change", detail: { from, to: status } },
    ...inc.history,
  ];
  return true;
}

export function demoAddIncidentNote(id: string, body: string,
                                    analyst: string): boolean {
  const inc = demoIncidents.find((i) => i.id === id);
  if (!inc) return false;
  inc.notes = [...inc.notes,
    { author: analyst, body, created_at: new Date().toISOString() }];
  inc.history = [
    { occurred_at: new Date().toISOString(), actor: analyst,
      action: "note_added", detail: {} },
    ...inc.history,
  ];
  return true;
}

// ------------------------------------------------- manual escalation (v0.10)
// An analyst can raise ONE alert into a brand-new incident. The new
// incident honestly carries exactly what the alert proves: its own
// entities and evidence. NO edges are invented - relations only ever
// come from the automatic correlation engine (edge = reason + confidence).

let manualSeq = 0;

const STAGE_TO_PHASE: Record<string, AttackPhase> = {
  reconnaissance: "recon",
  delivery: "delivery",
  exploitation: "initial_access",
  command_and_control: "c2",
  actions_on_objectives: "impact",
};

const RFC1918 = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/;

export function demoEscalateAlert(
  alert: AlertDoc, actor: string, reason?: string,
): IncidentDetail {
  const existing = demoIncidents.find(
    (i) => i.history?.some(
      (h) => h.action === "created_by_manual_escalation"
        && (h.detail as { alert_id?: string } | undefined)?.alert_id === alert.alert_id));
  if (existing) {
    throw new Error("This alert is already escalated to incident " + existing.id);
  }
  manualSeq += 1;
  const now = new Date().toISOString();
  const stage = String(alert.kill_chain && typeof alert.kill_chain === "object"
    ? alert.kill_chain.stage : "reconnaissance");
  const phase: AttackPhase = STAGE_TO_PHASE[stage] ?? "recon";

  const nodes: AttackNode[] = [];
  if (alert.source?.ip) {
    nodes.push({
      key: `ip:${alert.source.ip}`, kind: "ip", label: alert.source.ip,
      role: RFC1918.test(alert.source.ip) ? "compromised_host" : "attacker",
      phase, confidence: alert.risk_score ?? 50,
      first_seen: alert.first_seen, last_seen: alert.last_seen,
      evidence_count: 1,
      attrs: { via: "manual escalation", alert_type: alert.alert_type },
    });
  }
  if (alert.destination?.ip) {
    nodes.push({
      key: `ip:${alert.destination.ip}`, kind: "ip", label: alert.destination.ip,
      role: RFC1918.test(alert.destination.ip) ? "target_range" : "c2_infra",
      phase, confidence: alert.risk_score ?? 50,
      first_seen: alert.first_seen, last_seen: alert.last_seen,
      evidence_count: 1,
      attrs: { via: "manual escalation", alert_type: alert.alert_type },
    });
  }

  const cleanTitle = alert.title.replace(/\s*\(\d+x\)\s*$/, "").trim();
  const evidence: EvidenceItem[] = [{
    ts: alert.last_seen,
    kind: "alert_ref",
    source: alert.alert_type,
    ref_index: "ndr-alerts-read",
    ref_id: alert.alert_id,
    title: cleanTitle,
    severity: alert.severity,
    phase,
    summary: alert.rationale,
    detail: {
      alert_id: alert.alert_id,
      group_key: alert.group_key,
      event_count: alert.event_count,
      escalation_reason: reason ?? null,
    },
  }];

  const phaseProgression: PhaseProgress[] = PHASE_ORDER.map((p) => ({
    phase: p,
    status: p === phase ? "observed" : "none",
    evidence_count: p === phase ? 1 : 0,
    signal_count: p === phase ? 1 : 0,
    context_count: 0,
  }));

  const inc: IncidentDetail = {
    id: `inc-manual-${String(manualSeq).padStart(3, "0")}`,
    title: `Manual escalation: ${cleanTitle}`,
    status: "open",
    severity: alert.severity,
    confidence: alert.risk_score ?? 50,
    confidence_basis: "heuristic-uncalibrated (manual escalation)",
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    updated_at: now,
    entity_count: nodes.length,
    edge_count: 0,   // honest: no reconstructed relation from one alert alone
    evidence_count: 1,
    signal_count: 1,
    outcome_label: (alert.outcome ?? "indeterminate") as OutcomeLabel,
    phases: phaseProgression,
    analyst: actor,
    created_at: now,
    outcome: {
      label: (alert.outcome ?? "indeterminate") as OutcomeLabel,
      proven: [
        `Alert ${cleanTitle} observed ${alert.first_seen} to ${alert.last_seen} (${alert.event_count} events)`,
      ],
      suspected: [],
      unknown: [
        "Whether this single alert is part of a wider chain - the correlation engine will merge this incident if related evidence appears",
        "Host state after the observed activity (needs endpoint/server logs)",
      ],
      markers: ["manual escalation"],
      disclaimer: "Manually raised by an analyst from a single alert. No relations are inferred without corroborating evidence.",
    },
    phase_progression: phaseProgression,
    nodes,
    edges: [] as AttackEdge[],
    evidence,
    notes: reason ? [{ author: actor, body: reason, created_at: now }] : [],
    history: [{
      occurred_at: now,
      actor,
      action: "created_by_manual_escalation",
      detail: { alert_id: alert.alert_id, reason: reason ?? null },
    }],
  };
  Object.assign(inc, stageData(inc));
  demoIncidents.push(inc);
  return inc;
}

const SEV_LABEL: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low",
  informational: "informational",
};

export function buildIncidentReportMd(inc: IncidentDetail): string {
  const L: string[] = [];
  const label = inc.outcome.label;
  L.push(`# Incident Report - ${inc.id}`);
  L.push("");
  L.push(`**Title:** ${inc.title}`);
  L.push("");
  L.push(`**Status:** ${inc.status}  |  **Severity:** ${inc.severity}  |  `
    + `**Confidence:** ${inc.confidence}/100 (heuristic-uncalibrated)`);
  L.push("");
  L.push(`**First seen:** ${inc.first_seen ?? "n/a"}  |  **Last seen:** ${inc.last_seen ?? "n/a"}`);
  L.push("");
  L.push(`**Generated:** ${new Date().toISOString()}  |  **Evidence items:** ${inc.evidence.length}  |  **Entities:** ${inc.nodes.length}`);
  L.push("");
  L.push("---");
  L.push("");
  L.push("## Executive Summary");
  L.push("");
  L.push(`**Attack outcome assessment: ${label.replace("_", " ")}**`);
  L.push("");
  const observed = inc.phase_progression.filter((p) => p.status === "observed");
  if (observed.length) {
    L.push(`The reconstruction correlates ${inc.signal_count} signals into one `
      + `chain covering: ${observed.map((p) => p.phase).join(" -> ")}. `
      + `${inc.evidence.length} evidence items from Zeek, Suricata and `
      + `threat intelligence support this timeline.`);
  } else {
    L.push("Isolated signals without a multi-phase chain.");
  }
  L.push("");
  L.push("## Outcome Assessment");
  L.push("");
  L.push("### Proven (directly observed)");
  (inc.outcome.proven ?? []).forEach((p) => L.push(`- ${p}`));
  L.push("");
  L.push("### Suspected (chain-inferred, needs validation)");
  (inc.outcome.suspected ?? []).forEach((p) => L.push(`- ${p}`));
  L.push("");
  L.push("### Unknown (network-only blindness)");
  (inc.outcome.unknown ?? []).forEach((p) => L.push(`- ${p}`));
  L.push("");
  L.push(`> ${inc.outcome.disclaimer ?? ""}`);
  L.push("");
  if (inc.stage_progression?.length) {
    L.push("## Kill Chain Stage Assessment (doc 11)");
    L.push("");
    L.push("Evidence-based assessment over the 7 Lockheed Martin stages. "
      + "This is NOT a mandatory sequence: stages may be skipped, run in "
      + "parallel, or lack sufficient telemetry.");
    L.push("");
    L.push("| Stage | Status | Confidence | Evidence | ATT&CK | Reason |");
    L.push("|-------|--------|------------|----------|--------|--------|");
    const statusText: Record<string, string> = {
      observed: "OBSERVED", suspected: "SUSPECTED",
      not_observed: "NOT OBSERVED", insufficient_telemetry: "INSUFFICIENT TELEMETRY",
    };
    inc.stage_progression.forEach((s) => {
      const attck = (s.attck ?? []).map((t) => t.technique_id)
        .filter((v, i, a) => a.indexOf(v) === i).join(", ") || "-";
      L.push(`| ${s.label} | ${statusText[s.status] ?? s.status} ` +
        `| ${s.confidence}% | ${s.evidence_count} | ${attck} ` +
        `| ${s.reason.slice(0, 110)} |`);
    });
    L.push("");
  }
  L.push("## Attack Timeline");
  L.push("");
  L.push("| Time | Phase | Kill-chain stage | Source | Event | Severity |");
  L.push("|------|-------|------------------|--------|-------|----------|");
  [...inc.evidence]
    .sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""))
    .forEach((e) => {
      L.push(`| ${e.ts ?? "-"} | ${e.phase ?? "-"} | ${e.stage ?? "-"} ` +
        `| ${e.source ?? "-"} | ${(e.title ?? "").slice(0, 110)} ` +
        `| ${e.severity ?? "-"} |`);
    });
  L.push("");
  L.push("## Evidence per Phase");
  L.push("");
  inc.phase_progression.forEach((p) => {
    const statusText = p.status === "observed" ? "OBSERVED (direct evidence)"
      : p.status === "suspected" ? "SUSPECTED (indirect/context only)"
      : "not observed";
    L.push(`### ${p.phase} - ${statusText}`);
    L.push("");
    const items = inc.evidence.filter((e) => e.phase === p.phase);
    if (items.length) {
      items.slice(0, 10).forEach((e) => {
        L.push(`- ${e.ts ?? "-"} - ${e.title ?? "(untitled)"}`
          + (e.ref_index && e.ref_id ? ` \`[${e.ref_index}:${e.ref_id}]\`` : ""));
      });
    } else {
      L.push("_No evidence for this phase._");
    }
    L.push("");
  });
  L.push("## Attack Graph (entities and relations)");
  L.push("");
  L.push("| Entity | Kind | Role | Phase |");
  L.push("|--------|------|------|-------|");
  inc.nodes.slice(0, 30).forEach((n) => {
    L.push(`| ${n.label} | ${n.kind} | ${n.role ?? "-"} | ${n.phase ?? "-"} |`);
  });
  L.push("");
  L.push("| From | Relation | To | Phase | Evidence |");
  L.push("|------|----------|----|-------|----------|");
  const labelOf = (k: string) =>
    inc.nodes.find((n) => n.key === k)?.label ?? k;
  inc.edges.slice(0, 40).forEach((e) => {
    L.push(`| ${labelOf(e.src)} | ${e.relation}${e.inferred ? " (inferred)" : ""} | ${labelOf(e.dst)} | ${e.phase ?? "-"} | ${e.evidence_count ?? 0} |`);
  });
  L.push("");
  L.push("## Analyst Notes");
  L.push("");
  if (inc.notes.length) {
    inc.notes.forEach((n) => L.push(`- **${n.author ?? "unknown"} (${n.created_at ?? ""}):** ${n.body}`));
  } else {
    L.push("_No analyst notes yet._");
  }
  L.push("");
  L.push("---");
  L.push("");
  L.push("_Generated by NDR attack reconstruction (Phase 4). All conclusions "
    + "derive from network telemetry and threat-intelligence context; they "
    + "are heuristic and uncalibrated. Validate with endpoint/server logs "
    + "before containment actions._");
  return L.join("\n");
}

// severity helper re-export for the view
export const SEVERITY_LABELS = SEV_LABEL as Record<Severity, string>;
