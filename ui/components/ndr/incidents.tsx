"use client";

// Incidents view (Phase 4 - automatic attack reconstruction).
//
// The analyst opens ONE incident and sees: where the activity started,
// which hosts were targeted, how the attack progressed phase by phase,
// which alerts/events are related, TI matches, supporting evidence and
// - critically - what is PROVEN vs SUSPECTED vs UNKNOWN.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { RefreshControls } from "./refresh-controls";
import {
  ArrowLeft, Ban, CheckCircle2, ChevronDown, ChevronRight, Clock, Copy,
  Download, FileText, FolderKanban, FolderMinus, FolderOutput, GitBranch,
  Layers, ListChecks, Loader2, RefreshCw, Route, Search, ShieldAlert,
  Waypoints, X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AttackGraph, PHASE_META, PHASES } from "@/components/ndr/attack-graph";
import { EvidencePanel } from "@/components/ndr/evidence";
import {
  DEFAULT_TIME_RANGE, Paginator, SeverityBadge, TimeRangePicker, alertTitle,
  fmtTime, resolveTimeRange, timeAgo,
} from "@/components/ndr/shared";
import type { TimeRange } from "@/components/ndr/shared";
import {
  addIncidentNote, attachToCampaign, createCampaign, detachFromCampaign,
  getCampaignDetail, getCampaigns, getIncidentDetail, getIncidentReport,
  getIncidents, getIncidentStats, getReportVersionMd, getReportVersions,
  saveReportVersion, updateCampaign, updateIncidentStatus,
  UnauthorizedError,
} from "@/lib/ndr/api";
import type {
  CampaignDetail, CampaignSummary, AttackEdge, AttackNode, AttackPhase,
  EvidenceItem, IncidentDetail, IncidentStats, IncidentSummary,
  KillChainStage, OutcomeLabel, PhaseProgress, ReportVersionMeta,
  StageHistoryEntry, StageProgress,
} from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

const OUTCOME_META: Record<OutcomeLabel, { label: string; cls: string; hint: string }> = {
  strong_success: {
    label: "Strong evidence of success",
    cls: "border-red-800 bg-red-950/50 text-red-200",
    hint: "High-confidence TI match on the chain - validate with endpoint before containment",
  },
  suspected_success: {
    label: "Suspected successful compromise",
    cls: "border-orange-800 bg-orange-950/40 text-orange-200",
    hint: "Chain continued past access - confirm with server/endpoint logs",
  },
  attempted: {
    label: "Attempted attack",
    cls: "border-amber-800 bg-amber-950/30 text-amber-200",
    hint: "Attack activity observed; no post-access evidence so far",
  },
  indeterminate: {
    label: "Indeterminate",
    cls: "border-zinc-700 bg-zinc-900/60 text-zinc-300",
    hint: "Insufficient evidence to characterize the outcome",
  },
};

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "confirmed", label: "Confirmed" },
  { value: "benign", label: "Benign / false positive" },
  { value: "closed", label: "Closed" },
];

function statusBadgeCls(status: string): string {
  switch (status) {
    case "open": return "bg-sky-950 text-sky-300 border-sky-800";
    case "confirmed": return "bg-red-950 text-red-300 border-red-800";
    case "benign": return "bg-zinc-900 text-zinc-400 border-zinc-700";
    case "closed": return "bg-emerald-950 text-emerald-300 border-emerald-800";
    default: return "bg-zinc-900 text-zinc-400 border-zinc-700";
  }
}

function ConfidenceRing({ value }: { value: number }) {
  const r = 22;
  const c = 2 * Math.PI * r;
  const filled = (Math.min(100, Math.max(0, value)) / 100) * c;
  const color = value >= 70 ? "#fb7185" : value >= 45 ? "#fbbf24" : "#71717a";
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="56" height="56" viewBox="0 0 56 56">
        <circle cx="28" cy="28" r={r} fill="none" stroke="#27272a" strokeWidth="5" />
        <circle cx="28" cy="28" r={r} fill="none" stroke={color} strokeWidth="5"
                strokeLinecap="round"
                strokeDasharray={`${filled} ${c - filled}`}
                transform="rotate(-90 28 28)" />
        <text x="28" y="31" textAnchor="middle" fontSize="13" fontWeight="700"
              fill="#e4e4e7">{value}</text>
      </svg>
      <span className="text-[9px] uppercase tracking-wider text-zinc-500">confidence</span>
    </div>
  );
}

function PhaseChips({ phases }: { phases: PhaseProgress[] }) {
  const active = phases.filter((p) => p.status !== "none");
  if (!active.length) return <span className="text-xs text-zinc-600">no phase data</span>;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {active.map((p, i) => {
        const meta = PHASE_META[p.phase as AttackPhase] ?? PHASE_META.unknown;
        return (
          <span key={p.phase} className="flex items-center gap-1">
            {i > 0 && <ChevronRight className="h-3 w-3 text-zinc-700" />}
            <span
              className="rounded px-1.5 py-0.5 text-[10px] font-medium"
              style={{
                color: meta.color,
                backgroundColor: p.status === "observed" ? meta.dim : "transparent",
                border: `1px solid ${p.status === "observed" ? meta.color + "55" : meta.color + "30"}`,
              }}
              title={p.status === "observed"
                ? `${p.evidence_count} direct evidence`
                : `${p.context_count} indirect/context only`}>
              {meta.label}{p.status === "suspected" ? "?" : ""}
            </span>
          </span>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------- timeline
function AttackTimeline({ detail }: { detail: IncidentDetail }) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const items = useMemo(
    () => [...detail.evidence].sort((a, b) =>
      (a.ts ?? "").localeCompare(b.ts ?? "")),
    [detail.evidence]);

  if (!items.length) {
    return <div className="py-8 text-center text-sm text-zinc-500">No evidence recorded.</div>;
  }
  return (
    <div className="relative pl-6">
      <div className="absolute bottom-2 left-[9px] top-2 w-px bg-zinc-800" />
      <div className="space-y-3">
        {items.map((ev, i) => {
          const meta = PHASE_META[(ev.phase ?? "unknown") as AttackPhase] ?? PHASE_META.unknown;
          const open = expanded.has(i);
          return (
            <div key={i} className="relative">
              <span className="absolute -left-6 top-1.5 h-3.5 w-3.5 rounded-full border-2"
                    style={{
                      backgroundColor: "#09090b",
                      borderColor: meta.color,
                      boxShadow: ev.kind === "ioc_event" ? `0 0 8px ${meta.color}` : undefined,
                    }} />
              <button
                onClick={() => {
                  const next = new Set(expanded);
                  if (open) next.delete(i); else next.add(i);
                  setExpanded(next);
                }}
                className="w-full rounded-lg border border-zinc-800/70 bg-zinc-900/50 p-3 text-left transition-colors hover:border-zinc-700">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] tabular-nums text-zinc-400">
                    {fmtTime(ev.ts)}
                  </span>
                  <Badge variant="outline" className="border-zinc-700 text-[10px]"
                         style={{ color: meta.color }}>
                    {meta.label}
                  </Badge>
                  <Badge variant="outline" className="border-zinc-800 text-[10px] text-zinc-400">
                    {ev.source ?? "pipeline"}
                  </Badge>
                  {ev.kind === "ioc_event" && (
                    <Badge variant="outline"
                           className="border-purple-800 bg-purple-950/40 text-[10px] text-purple-300">
                      TI match
                    </Badge>
                  )}
                  {ev.kind === "context" && (
                    <Badge variant="outline"
                           className="border-zinc-800 bg-zinc-900 text-[10px] text-zinc-500">
                      context
                    </Badge>
                  )}
                  <SeverityBadge severity={ev.severity} />
                  <span className="ml-auto text-[10px] text-zinc-600">
                    {open ? "collapse" : "expand"}
                  </span>
                </div>
                <div className="mt-1.5 text-sm font-medium text-zinc-100">
                  {ev.title ? alertTitle(ev.title) : "(untitled evidence)"}
                </div>
                {ev.summary && (
                  <div className="mt-0.5 text-xs leading-relaxed text-zinc-400">
                    {ev.summary}
                  </div>
                )}
                {open && (
                  <div className="mt-2 space-y-1.5 border-t border-zinc-800/70 pt-2">
                    {ev.ref_index && ev.ref_id && ev.kind !== "context" && (
                      <div className="font-mono text-[10px] text-zinc-500">
                        evidence ref: {ev.ref_index} / {ev.ref_id}
                      </div>
                    )}
                    <pre className="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-[10px] leading-relaxed text-zinc-400"
                         style={{ maxHeight: 200 }}>
                      {JSON.stringify(ev.detail ?? {}, null, 2)}
                    </pre>
                  </div>
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- phase cards
function PhaseCards({ phases }: { phases: PhaseProgress[] }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {PHASES.map((phase) => {
        const p = phases.find((x) => x.phase === phase);
        const meta = PHASE_META[phase];
        const status = p?.status ?? "none";
        return (
          <div key={phase}
               className="rounded-lg border p-3"
               style={{
                 borderColor: status === "none" ? "rgba(63,63,70,0.5)" : meta.color + "66",
                 backgroundColor: status === "observed" ? meta.dim : "rgba(24,24,27,0.4)",
               }}>
            <div className="flex flex-col items-start gap-1.5">
              <span className="text-xs font-semibold" style={{ color: meta.color }}>
                {meta.label}
              </span>
              {status === "observed" && (
                <Badge variant="outline" className="border-emerald-800 bg-emerald-950/50 text-[9px] text-emerald-300">
                  OBSERVED
                </Badge>
              )}
              {status === "suspected" && (
                <Badge variant="outline" className="border-amber-800 bg-amber-950/40 text-[9px] text-amber-300">
                  SUSPECTED
                </Badge>
              )}
              {status === "none" && (
                <Badge variant="outline" className="border-zinc-800 text-[9px] text-zinc-600">
                  none
                </Badge>
              )}
            </div>
            <div className="mt-2 space-y-0.5 text-[11px] text-zinc-500">
              <div>{p?.signal_count ?? 0} direct signal(s)</div>
              <div>{p?.context_count ?? 0} context item(s)</div>
              <div>{p?.evidence_count ?? 0} evidence total</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------- kill chain (doc 11)
// Lockheed Martin Cyber Kill Chain - dual-framework presentation layer.
// Colors are presentation-only; statuses are always evidence-driven.

const STAGE_META: Record<string, { label: string; short: string; color: string; desc: string }> = {
  reconnaissance: { label: "Reconnaissance", short: "Recon", color: "#22d3ee", desc: "Scanning / target information gathering" },
  weaponization: { label: "Weaponization", short: "Weaponize", color: "#a78bfa", desc: "Exploit + payload preparation (attacker side)" },
  delivery: { label: "Delivery", short: "Delivery", color: "#f472b6", desc: "Payload / exploit transmitted toward target" },
  exploitation: { label: "Exploitation", short: "Exploit", color: "#fb923c", desc: "Vulnerability exploitation observed on the wire" },
  installation: { label: "Installation", short: "Install", color: "#facc15", desc: "Malware / persistence installed (needs endpoint)" },
  command_and_control: { label: "Command & Control", short: "C2", color: "#fb7185", desc: "Beaconing / traffic to C2 infrastructure" },
  actions_on_objectives: { label: "Actions on Objectives", short: "Actions", color: "#f87171", desc: "Lateral movement, exfiltration, goal activity" },
};

const STAGE_ORDER: KillChainStage[] = [
  "reconnaissance", "weaponization", "delivery", "exploitation",
  "installation", "command_and_control", "actions_on_objectives",
];

const STAGE_STATUS_STYLE: Record<string, { badge: string; dot: string; label: string; hint: string }> = {
  observed: { badge: "border-emerald-800 bg-emerald-950/50 text-emerald-300", dot: "#38bdf8", label: "OBSERVED", hint: "direct evidence" },
  suspected: { badge: "border-amber-800 bg-amber-950/40 text-amber-300", dot: "#fbbf24", label: "SUSPECTED", hint: "context only" },
  not_observed: { badge: "border-zinc-800 bg-zinc-950/40 text-zinc-500", dot: "#52525b", label: "NOT OBSERVED", hint: "no evidence arrived" },
  insufficient_telemetry: { badge: "border-slate-700 bg-slate-950/40 text-slate-400 border-dashed", dot: "#94a3b8", label: "INSUFFICIENT TELEMETRY", hint: "not assessable from network data" },
};

function stageMeta(stage: string) {
  return STAGE_META[stage] ?? { label: stage, short: stage, color: "#71717a", desc: "" };
}

/** Horizontal 7-stage strip - deliberately NOT a filled sequence:
 *  every cell carries its own evidence-based status. */
function KillChainStrip({ stages }: { stages: StageProgress[] }) {
  const byStage = new Map(stages.map((s) => [s.stage, s]));
  return (
    <div className="flex flex-wrap items-stretch gap-1">
      {STAGE_ORDER.map((stage, i) => {
        const s = byStage.get(stage);
        const meta = stageMeta(stage);
        const status = s?.status ?? "not_observed";
        const style = STAGE_STATUS_STYLE[status];
        const title = `${meta.label} - ${style.label}\n${s?.reason ?? "no assessment"}`
          + (s?.attck?.length ? `\nATT&CK: ${s.attck.map((t) => t.technique_id).join(", ")}` : "");
        return (
          <div key={stage} className="flex items-stretch gap-1">
            {i > 0 && <div className="my-3 w-2 rounded bg-zinc-800" aria-hidden />}
            <div
              className="min-w-[92px] flex-1 rounded-md border px-2 py-2"
              style={{
                borderColor: status === "observed" ? meta.color + "88"
                  : status === "suspected" ? meta.color + "44"
                  : "rgba(63,63,70,0.6)",
                backgroundColor: status === "observed" ? meta.color + "14"
                  : status === "suspected" ? meta.color + "0a"
                  : "rgba(24,24,27,0.5)",
                borderStyle: status === "insufficient_telemetry" ? "dashed" : "solid",
              }}
              title={title}>
              <div className="flex items-center gap-1">
                <span className="font-mono text-[9px] text-zinc-600">{i + 1}</span>
                <span className="truncate text-[11px] font-semibold" style={{ color: meta.color }}>
                  {meta.label}
                </span>
              </div>
              <div className="mt-1.5 flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: style.dot }} />
                <span className={`text-[9px] font-medium ${style.badge.split(" ").slice(2).join(" ")}`}>
                  {style.label}
                </span>
              </div>
              {(status === "observed" || status === "suspected") && (
                <div className="mt-1 text-[9px] text-zinc-500">
                  {s?.evidence_count ?? 0} evidence · conf {s?.confidence ?? 0}%
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Evidence + reason + ATT&CK mapping for every assessed stage. */
function StageDetailGrid({ stages }: { stages: StageProgress[] }) {
  const assessed = stages.filter((s) => s.status === "observed" || s.status === "suspected");
  if (!assessed.length) {
    return <div className="text-xs text-zinc-600">No stage has observed or suspected evidence yet.</div>;
  }
  return (
    <div className="mt-3 grid gap-2 md:grid-cols-2">
      {assessed.map((s) => {
        const meta = stageMeta(s.stage);
        const style = STAGE_STATUS_STYLE[s.status];
        return (
          <div key={s.stage} className="rounded-md border border-zinc-800 bg-zinc-950/50 p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold" style={{ color: meta.color }}>{s.label}</span>
              <Badge variant="outline" className={`text-[9px] ${style.badge}`}>{style.label}</Badge>
              <span className="ml-auto font-mono text-[10px] text-zinc-500">conf {s.confidence}%</span>
            </div>
            <div className="mt-1 text-[11px] text-zinc-400">{s.reason}</div>
            <div className="mt-1 text-[10px] text-zinc-600">
              {s.signal_count} direct · {s.context_count} context · {s.evidence_count} evidence total
            </div>
            {!!s.attck?.length && (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {s.attck.map((t) => (
                  <span key={t.technique_id}
                        className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 font-mono text-[9px] text-zinc-400"
                        title={`${t.tactic}: ${t.technique}`}>
                    {t.technique_id} {t.technique}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** Assessment changes over time (doc 11: perubahan penilaian). */
function StageHistoryCard({ history }: { history: StageHistoryEntry[] }) {
  if (!history.length) return null;
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-zinc-300">Stage assessment history</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-1.5">
          {history.slice(-12).reverse().map((h, i) => {
            const meta = stageMeta(h.stage);
            const toStyle = STAGE_STATUS_STYLE[h.to];
            return (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[11px]">
                <span className="font-mono text-[10px] text-zinc-500">{fmtTime(h.ts)}</span>
                <span className="font-medium" style={{ color: meta.color }}>{meta.label}</span>
                <span className="text-zinc-600">
                  {h.from ? STAGE_STATUS_STYLE[h.from]?.label.toLowerCase() : "initial"}
                  <ChevronRight className="inline h-3 w-3" />
                  <span className={toStyle.badge.split(" ").slice(2).join(" ")}>{h.to.replace("_", " ")}</span>
                </span>
                {h.evidence_ref && <span className="font-mono text-[9px] text-zinc-700">{h.evidence_ref}</span>}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------- report tab
function ReportTab({ incidentId, canEdit }: { incidentId: string; canEdit: boolean }) {
  const [md, setMd] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // report versioning (v0.12)
  const [versions, setVersions] = useState<ReportVersionMeta[]>([]);
  const [viewingVersion, setViewingVersion] = useState<number | null>(null);
  const [savingVersion, setSavingVersion] = useState(false);
  const { toast } = useToast();

  const loadVersions = useCallback(async () => {
    try {
      const r = await getReportVersions(incidentId);
      setVersions(r.items);
    } catch {
      /* version list is auxiliary - keep the report tab usable */
    }
  }, [incidentId]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setMd(await getIncidentReport(incidentId));
      setViewingVersion(null);
    } catch (e) {
      toast({ title: "Report generation failed", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }, [incidentId, toast]);

  useEffect(() => { loadVersions(); }, [loadVersions]);

  function download() {
    if (!md) return;
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = viewingVersion
      ? `incident-${incidentId}-v${viewingVersion}.md`
      : `incident-${incidentId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function saveVersion() {
    setSavingVersion(true);
    try {
      const meta = await saveReportVersion(incidentId);
      toast({ title: `Report version v${meta.version} saved`,
        description: "Immutable snapshot: status, severity, outcome and evidence counts are frozen as of now." });
      await loadVersions();
      setViewingVersion(meta.version);
      setMd(await getReportVersionMd(incidentId, meta.version));
    } catch (e) {
      toast({ title: "Failed to save version", description: String(e), variant: "destructive" });
    } finally {
      setSavingVersion(false);
    }
  }

  async function viewVersion(v: number) {
    setLoading(true);
    try {
      setMd(await getReportVersionMd(incidentId, v));
      setViewingVersion(v);
    } catch (e) {
      toast({ title: "Failed to load version", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" onClick={load} disabled={loading}
                className="border-zinc-700 text-zinc-300">
          {loading
            ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            : <FileText className="mr-1.5 h-3.5 w-3.5" />}
          {viewingVersion === null
            ? (md ? "Regenerate" : "Generate incident report")
            : "Back to current draft"}
        </Button>
        {md && (
          <>
            <Button size="sm" variant="outline"
                    className="border-zinc-700 text-zinc-300"
                    onClick={() => {
                      navigator.clipboard.writeText(md).then(() =>
                        toast({ title: "Report copied to clipboard" }));
                    }}>
              <Copy className="mr-1.5 h-3.5 w-3.5" /> Copy
            </Button>
            <Button size="sm" variant="outline"
                    className="border-zinc-700 text-zinc-300"
                    onClick={download}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              {viewingVersion ? `Download v${viewingVersion}.md` : "Download .md"}
            </Button>
            {canEdit && (
              <Button size="sm" onClick={saveVersion} disabled={savingVersion}
                      className="bg-emerald-900 text-emerald-100 hover:bg-emerald-800">
                {savingVersion
                  ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                  : <Layers className="mr-1.5 h-3.5 w-3.5" />}
                  Save as version v{(versions[0]?.version ?? 0) + 1}
              </Button>
            )}
          </>
        )}
        {viewingVersion !== null && (
          <Badge variant="outline"
                 className="border-amber-800 bg-amber-950/40 text-[10px] text-amber-200">
            Immutable snapshot v{viewingVersion}
          </Badge>
        )}
      </div>

      {versions.length > 0 && (
        <div className="mb-3 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-wider text-zinc-500">
            Saved versions ({versions.length}) - immutable snapshots
          </div>
          <div className="flex flex-wrap gap-2">
            {versions.map((v) => (
              <button key={v.version}
                      onClick={() => viewVersion(v.version)}
                      className={`rounded-md border px-2.5 py-1.5 text-left text-[11px] transition-colors ${
                        viewingVersion === v.version
                          ? "border-emerald-700 bg-emerald-950/40 text-emerald-200"
                          : "border-zinc-800 bg-zinc-950/60 text-zinc-300 hover:border-emerald-900"
                      }`}
                      title={`Generated by ${v.generated_by ?? "?"} at ${v.created_at ?? "?"}`}>
                <span className="font-semibold">v{v.version}</span>
                <span className="ml-1.5 text-zinc-500">
                  {v.incident_status} · {v.severity} · {v.evidence_count} ev
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {md ? (
        <pre className="whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-xs leading-relaxed text-zinc-300">
          {md}
        </pre>
      ) : (
        <div className="rounded-lg border border-dashed border-zinc-800 p-8 text-center text-sm text-zinc-500">
          The report renders the reconstruction (timeline, phase evidence,
          graph, proven/suspected/unknown) as a shareable Markdown document.
          Every claim keeps its evidence reference. Save immutable versions
          to prove what the platform claimed at each point in time.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- detail
// v0.12.8: Relations ledger - EVERY reconstructed relation printed as an
// auditable row (from -> relation -> to, evidence count, window,
// confidence, observed vs inferred). The graph shows the shape; this
// ledger is the checkable receipt: each row's evidence_count points at
// the concrete evidence items that produced the link.
function RelationsLedger({ nodes, edges }: { nodes: AttackNode[]; edges: AttackEdge[] }) {
  const label = useMemo(() => {
    const m = new Map<string, string>();
    nodes.forEach((n) => m.set(n.key, n.label));
    return m;
  }, [nodes]);
  if (!edges.length) {
    return (
      <p className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-4 text-center text-xs text-zinc-500">
        This reconstruction has no relations yet - single-entity evidence only.
      </p>
    );
  }
  const observed = edges.filter((e) => !e.inferred).length;
  const inferred = edges.length - observed;
  return (
    <div className="rounded-lg border border-zinc-800">
      <div className="flex flex-wrap items-center gap-3 border-b border-zinc-800 bg-zinc-950/70 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
        <span>Relations ledger ({edges.length})</span>
        <span className="flex items-center gap-1.5 normal-case text-zinc-400">
          <span className="h-1.5 w-1.5 rounded-full bg-sky-400" /> {observed} observed
        </span>
        <span className="flex items-center gap-1.5 normal-case text-zinc-400">
          <span className="h-1.5 w-1.5 rounded-full border border-dashed border-zinc-500" /> {inferred} inferred
        </span>
        <span className="ml-auto normal-case font-normal text-zinc-600">
          every link lists its evidence count - cross-check rows against the Evidence tab
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-xs">
          <thead className="bg-zinc-950/50 text-[10px] uppercase tracking-wider text-zinc-600">
            <tr>
              <th className="px-3 py-1.5">From</th>
              <th className="px-3 py-1.5">Relation</th>
              <th className="px-3 py-1.5">To</th>
              <th className="px-3 py-1.5 text-right">Evidence</th>
              <th className="px-3 py-1.5">Window</th>
              <th className="px-3 py-1.5 text-right">Confidence</th>
              <th className="px-3 py-1.5">Basis</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {edges.map((e, i) => (
              <tr key={`${e.src}-${e.dst}-${e.relation}-${i}`}
                  className={cn("hover:bg-zinc-900/60", e.inferred && "text-zinc-400")}>
                <td className="px-3 py-1.5 font-mono text-[11px] text-zinc-300">
                  {label.get(e.src) ?? e.src}
                </td>
                <td className="px-3 py-1.5 text-zinc-400">{e.relation}</td>
                <td className="px-3 py-1.5 font-mono text-[11px] text-zinc-300">
                  {label.get(e.dst) ?? e.dst}
                </td>
                <td className="px-3 py-1.5 text-right tabular-nums text-zinc-300">
                  {e.evidence_count ?? 0}
                </td>
                <td className="whitespace-nowrap px-3 py-1.5 text-[10px] text-zinc-500">
                  {e.first_seen ? fmtTime(e.first_seen) : "?"} → {e.last_seen ? fmtTime(e.last_seen) : "?"}
                </td>
                <td className="px-3 py-1.5 text-right tabular-nums text-zinc-400">
                  {e.confidence ?? "-"}
                </td>
                <td className="px-3 py-1.5">
                  {e.inferred
                    ? <span className="text-[10px] text-amber-300/80">inferred (entity/temporal context)</span>
                    : <span className="text-[10px] text-sky-300/80">observed (direct evidence)</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// v0.12.8: one evidence row + its expandable detail payload. Expanding
// shows exactly what the engine stored for this item (the context query,
// alert refs, host/file facts) so every claim in the reconstruction can
// be traced to its recorded source.
function EvidenceRowWithDetail({ ev, meta, sMeta, open, onToggle }: {
  ev: EvidenceItem;
  meta: { label: string; color: string; dim: string };
  sMeta: { label: string; color: string } | null;
  open: boolean;
  onToggle: () => void;
}) {
  const detailStr = useMemo(() => {
    try {
      return JSON.stringify(ev.detail ?? {}, null, 2);
    } catch {
      return "{}";
    }
  }, [ev.detail]);
  const hasDetail = !!ev.detail && Object.keys(ev.detail).length > 0;
  return (
    <>
      <tr className={cn("cursor-pointer text-zinc-300 hover:bg-zinc-900/60",
                        open && "bg-zinc-900/60")}
          onClick={onToggle}>
        <td className="px-3 py-2 text-zinc-500">
          {open ? <ChevronDown className="h-3.5 w-3.5" />
                : <ChevronRight className="h-3.5 w-3.5" />}
        </td>
        <td className="whitespace-nowrap px-3 py-2 font-mono text-[10px] text-zinc-400">{fmtTime(ev.ts)}</td>
        <td className="px-3 py-2" style={{ color: meta.color }}>{meta.label}</td>
        <td className="px-3 py-2" style={{ color: sMeta?.color }}>
          {sMeta ? sMeta.label : "-"}
          {!!ev.attck?.length && (
            <span className="ml-1 font-mono text-[9px] text-zinc-600">
              {ev.attck.map((t) => t.technique_id).join(",")}
            </span>
          )}
        </td>
        <td className="px-3 py-2 text-zinc-400">{ev.source ?? "-"}</td>
        <td className="px-3 py-2">{alertTitle(ev.title)}</td>
        <td className="px-3 py-2"><SeverityBadge severity={ev.severity} /></td>
        <td className="px-3 py-2 font-mono text-[10px] text-zinc-500">
          {ev.kind === "context" ? "context (derived)" : `${ev.ref_index ?? "-"}`}
        </td>
      </tr>
      {open && (
        <tr className="bg-zinc-950/80">
          <td colSpan={8} className="px-6 py-3">
            <div className="space-y-2">
              {ev.summary && (
                <p className="text-[11px] leading-relaxed text-zinc-400">
                  <span className="font-semibold uppercase tracking-wider text-zinc-500">summary: </span>
                  {ev.summary}
                </p>
              )}
              <div className="grid grid-cols-2 gap-2 text-[10px] text-zinc-500 sm:grid-cols-4">
                <div>kind: <span className="text-zinc-300">{ev.kind}</span></div>
                <div>ref_index: <span className="font-mono text-zinc-300">{ev.ref_index ?? "-"}</span></div>
                <div className="truncate">ref_id: <span className="font-mono text-zinc-300" title={ev.ref_id ?? ""}>{ev.ref_id ?? "-"}</span></div>
                <div>stage: <span className="text-zinc-300">{ev.stage ?? "-"}</span></div>
              </div>
              {hasDetail && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                    detail payload (recorded at reconstruction time)
                  </div>
                  <pre className="max-h-48 overflow-auto rounded-md border border-zinc-800 bg-black/40 p-2.5 font-mono text-[10px] leading-relaxed text-zinc-400">
                    {detailStr}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function IncidentDetailPanel({
  detail, canEdit, onBack, onChanged, onOpenNote,
}: {
  detail: IncidentDetail;
  canEdit: boolean;
  onBack: () => void;
  onChanged: () => void;
  onOpenNote: (mode: "status" | "note", status?: string) => void;
}) {
  const outcome = OUTCOME_META[detail.outcome?.label ?? "indeterminate"];
  // v0.12.8: expandable evidence rows (detail payload per evidence item)
  const [openEvidence, setOpenEvidence] = useState<Set<number>>(new Set());
  useEffect(() => { setOpenEvidence(new Set()); }, [detail.id]);
  const toggleEvidence = (i: number) => {
    setOpenEvidence((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      return next;
    });
  };
  return (
    <div>
      <Button size="sm" variant="ghost" onClick={onBack}
              className="mb-3 -ml-2 text-zinc-400 hover:text-zinc-200">
        <ArrowLeft className="mr-1.5 h-4 w-4" /> All incidents
      </Button>

      {/* header */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardContent className="flex flex-wrap items-center gap-4 py-4">
          <div className="min-w-0 flex-1">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={detail.severity} />
              <Badge variant="outline" className={statusBadgeCls(detail.status)}>
                {detail.status}
              </Badge>
              {detail.campaign_title && (
                <Badge variant="outline"
                       className="border-emerald-800 bg-emerald-950/40 text-[10px] text-emerald-300"
                       title={`Part of campaign: ${detail.campaign_title}`}>
                  <FolderKanban className="mr-1 h-3 w-3" />
                  {detail.campaign_title}
                </Badge>
              )}
              <Badge variant="outline"
                     className="border-zinc-700 text-[10px] text-zinc-400">
                {detail.confidence_basis ?? "heuristic-uncalibrated"}
              </Badge>
              {detail.analyst && (
                <span className="text-[10px] text-zinc-500">
                  analyst: {detail.analyst}
                </span>
              )}
            </div>
            <h2 className="text-base font-semibold leading-snug text-zinc-100">
              {detail.title}
            </h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-zinc-500">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" /> {fmtTime(detail.first_seen)} → {fmtTime(detail.last_seen)}
              </span>
              <span>{detail.entity_count} entities · {detail.edge_count} relations · {detail.evidence_count} evidence · {detail.signal_count} signals</span>
              <span>updated {timeAgo(detail.updated_at ?? detail.last_seen)}</span>
            </div>
          </div>
          <ConfidenceRing value={detail.confidence} />
          {canEdit && (
            <div className="flex flex-col gap-2">
              <div className="flex gap-2">
                <Button size="sm" onClick={() => onOpenNote("status", "confirmed")}
                        className="bg-red-950 text-red-200 hover:bg-red-900">
                  <CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Confirm
                </Button>
                <Button size="sm" variant="outline" onClick={() => onOpenNote("status", "benign")}
                        className="border-zinc-700 text-zinc-300">
                  <Ban className="mr-1 h-3.5 w-3.5" /> Benign
                </Button>
                <Button size="sm" variant="outline" onClick={() => onOpenNote("status", "closed")}
                        className="border-zinc-700 text-zinc-300">
                  Close
                </Button>
              </div>
              <Button size="sm" variant="ghost" onClick={() => onOpenNote("note")}
                      className="text-zinc-400">
                <FileText className="mr-1 h-3.5 w-3.5" /> Add note
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* outcome banner */}
      <div className={`mt-4 rounded-lg border p-4 ${outcome.cls}`}>
        <div className="flex flex-wrap items-center gap-2">
          <ShieldAlert className="h-4 w-4" />
          <span className="text-sm font-semibold">
            Outcome: {outcome.label}
          </span>
          <span className="text-xs opacity-75">— {outcome.hint}</span>
        </div>
        <div className="mt-3 grid gap-3 text-xs md:grid-cols-3">
          <div className="rounded-md bg-black/20 p-2.5">
            <div className="mb-1 font-semibold uppercase tracking-wider text-[10px] opacity-80">
              Proven (directly observed)
            </div>
            <ul className="list-disc space-y-1 pl-4 opacity-90">
              {(detail.outcome.proven ?? []).map((p, i) => <li key={i}>{p}</li>)}
              {!detail.outcome.proven?.length && <li className="list-none opacity-60">Nothing beyond raw activity.</li>}
            </ul>
          </div>
          <div className="rounded-md bg-black/20 p-2.5">
            <div className="mb-1 font-semibold uppercase tracking-wider text-[10px] opacity-80">
              Suspected (needs validation)
            </div>
            <ul className="list-disc space-y-1 pl-4 opacity-90">
              {(detail.outcome.suspected ?? []).map((p, i) => <li key={i}>{p}</li>)}
              {!detail.outcome.suspected?.length && <li className="list-none opacity-60">None.</li>}
            </ul>
          </div>
          <div className="rounded-md bg-black/20 p-2.5">
            <div className="mb-1 font-semibold uppercase tracking-wider text-[10px] opacity-80">
              Unknown (network-only blindness)
            </div>
            <ul className="list-disc space-y-1 pl-4 opacity-90">
              {(detail.outcome.unknown ?? []).map((p, i) => <li key={i}>{p}</li>)}
            </ul>
          </div>
        </div>
        {detail.outcome.disclaimer && (
          <div className="mt-2 text-[10px] opacity-60">{detail.outcome.disclaimer}</div>
        )}
      </div>

      {/* Cyber Kill Chain assessment (doc 11) - dual framework with ATT&CK */}
      <Card className="mt-4 bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-zinc-300">
            <GitBranch className="mr-1.5 inline h-4 w-4 text-emerald-400" />
            Cyber Kill Chain assessment
            <span className="ml-2 text-[10px] font-normal text-zinc-500">
              Lockheed Martin 7 stages · dual-mapped with MITRE ATT&CK
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <KillChainStrip stages={detail.stage_progression ?? []} />
          <StageDetailGrid stages={detail.stage_progression ?? []} />
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-zinc-800/70 pt-2 text-[10px] text-zinc-500">
            <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "#38bdf8" }} /> observed (direct evidence)</span>
            <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "#fbbf24" }} /> suspected (context only)</span>
            <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "#52525b" }} /> not observed</span>
            <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full border border-dashed border-slate-400" /> insufficient telemetry</span>
            <span className="text-zinc-600">Not a mandatory sequence — stages can be skipped, parallel, or undeterminable from network data.</span>
          </div>
        </CardContent>
      </Card>

      {/* tabs */}
      <Tabs defaultValue="graph" className="mt-4">
        <TabsList className="bg-zinc-900">
          <TabsTrigger value="graph" className="data-[state=active]:text-emerald-300">
            <Route className="mr-1.5 h-3.5 w-3.5" /> Attack Graph
          </TabsTrigger>
          <TabsTrigger value="timeline" className="data-[state=active]:text-emerald-300">
            <Clock className="mr-1.5 h-3.5 w-3.5" /> Timeline
          </TabsTrigger>
          <TabsTrigger value="evidence" className="data-[state=active]:text-emerald-300">
            <ListChecks className="mr-1.5 h-3.5 w-3.5" /> Evidence
          </TabsTrigger>
          <TabsTrigger value="report" className="data-[state=active]:text-emerald-300">
            <FileText className="mr-1.5 h-3.5 w-3.5" /> Report
          </TabsTrigger>
        </TabsList>

        <TabsContent value="graph" className="mt-3">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-zinc-300">
                    <GitBranch className="mr-1.5 inline h-4 w-4 text-emerald-400" />
                    Attack graph - entity & relation reconstruction
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <AttackGraph nodes={detail.nodes} edges={detail.edges} />
                </CardContent>
              </Card>
            </div>
            <div className="space-y-4">
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-zinc-300">Phase progression</CardTitle>
                </CardHeader>
                <CardContent>
                  <PhaseCards phases={detail.phase_progression ?? detail.phases} />
                </CardContent>
              </Card>
              {!!detail.stage_history?.length && (
                <StageHistoryCard history={detail.stage_history} />
              )}
              {(detail.notes?.length ?? 0) > 0 && (
                <Card className="bg-zinc-900/60 border-zinc-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-zinc-300">Analyst notes</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {detail.notes.map((n, i) => (
                      <div key={i} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-2.5">
                        <div className="text-[10px] text-zinc-500">
                          {n.author ?? "unknown"} · {fmtTime(n.created_at)}
                        </div>
                        <div className="mt-1 text-xs text-zinc-300">{n.body}</div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
              {(detail.history?.length ?? 0) > 0 && (
                <Card className="bg-zinc-900/60 border-zinc-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-zinc-300">History</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1.5">
                      {detail.history.slice(0, 8).map((h, i) => (
                        <div key={i} className="flex items-center gap-2 text-[11px] text-zinc-500">
                          <span className="font-mono">{fmtTime(h.occurred_at)}</span>
                          <span className="text-zinc-300">{h.action.replace("_", " ")}</span>
                          <span>{h.actor ? `by ${h.actor}` : ""}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
          {/* v0.12.8: auditable relation rows - the checkable receipt of
              every link drawn in the graph above */}
          <div className="mt-4">
            <RelationsLedger nodes={detail.nodes} edges={detail.edges} />
          </div>
        </TabsContent>

        <TabsContent value="timeline" className="mt-3">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="py-4">
              <AttackTimeline detail={detail} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evidence" className="mt-3">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="py-3">
              <div className="mb-2 flex flex-wrap items-center gap-2 px-1 text-[10px] text-zinc-500">
                <ListChecks className="h-3 w-3" />
                Click a row to inspect its detail payload (the exact query / event refs behind it).
              </div>
              <div className="rounded-lg border border-zinc-800">
                <table className="w-full text-left text-xs">
                  <thead className="bg-zinc-950/80 text-[10px] uppercase tracking-wider text-zinc-500">
                    <tr>
                      <th className="w-8 px-3 py-2"></th>
                      <th className="px-3 py-2">Time</th>
                      <th className="px-3 py-2">Phase</th>
                      <th className="px-3 py-2">Kill chain</th>
                      <th className="px-3 py-2">Source</th>
                      <th className="px-3 py-2">Event</th>
                      <th className="px-3 py-2">Severity</th>
                      <th className="px-3 py-2">Reference</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/70">
                    {[...detail.evidence]
                      .sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""))
                      .map((ev: EvidenceItem, i) => {
                        const meta = PHASE_META[(ev.phase ?? "unknown") as AttackPhase] ?? PHASE_META.unknown;
                        const sMeta = ev.stage ? stageMeta(String(ev.stage)) : null;
                        const open = openEvidence.has(i);
                        return (
                          <EvidenceRowWithDetail key={`${ev.ref_id ?? "ev"}-${i}`} ev={ev}
                                                 meta={meta} sMeta={sMeta}
                                                 open={open}
                                                 onToggle={() => toggleEvidence(i)} />
                        );
                      })}
                  </tbody>
                </table>
              </div>
              {/* PCAP & evidence workflow (doc section 15) */}
              <div className="mt-4 border-t border-zinc-800 pt-3">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  PCAP &amp; sessions (doc 15)
                </div>
                <EvidencePanel scope="incident" scopeId={detail.id} canExport={canEdit} />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="report" className="mt-3">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="py-4">
              <ReportTab incidentId={detail.id} canEdit={canEdit} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------------------------------------------------------------- main view
// ------------------------------------------------ campaigns (v0.12)
// Analyst bookkeeping: group related incidents into one campaign.
// Membership NEVER rewrites evidence or relations - rollups
// (severity / window / count) are recomputed from current members.

function CampStatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={`text-[10px] ${statusBadgeCls(status)}`}>
      {status === "open" ? "open" : "closed"}
    </Badge>
  );
}

function CreateCampaignDialog({
  open, onOpenChange, preselect, onDone,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  preselect: string[];
  onDone: (id: string) => void;
}) {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [pool, setPool] = useState<IncidentSummary[]>([]);
  const [sel, setSel] = useState<Set<string>>(new Set(preselect));
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTitle("");
    setDesc("");
    setSel(new Set(preselect));
    getIncidents({}).then((r) => setPool(r.items)).catch(() => setPool([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function submit() {
    setBusy(true);
    try {
      const c = await createCampaign(title.trim(), desc.trim(), [...sel]);
      toast({ title: "Campaign created",
        description: `${sel.size} incident(s) merged into "${c.title}". Membership is bookkeeping only - evidence and relations are untouched.` });
      onOpenChange(false);
      onDone(c.id);
    } catch (e) {
      toast({ title: "Failed to create campaign", description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">New campaign</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="text-xs text-zinc-500">
            A campaign groups related incidents for SOC tracking (merge).
            It never modifies the incidents themselves.
          </div>
          <Input value={title} onChange={(e) => setTitle(e.target.value)}
                 placeholder="Campaign title (e.g. Intrusion wave 203.0.113.0/24)"
                 className="border-zinc-800 bg-zinc-900 text-sm" />
          <Textarea value={desc} onChange={(e) => setDesc(e.target.value)}
                    placeholder="Why are these incidents related? (optional)"
                    className="min-h-16 border-zinc-800 bg-zinc-900 text-sm" />
          <div>
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-500">
              Member incidents ({sel.size} selected)
            </div>
            <ScrollArea className="h-44 rounded-md border border-zinc-800">
              <div className="space-y-1 p-2">
                {pool.map((inc) => (
                  <label key={inc.id}
                         className="flex cursor-pointer items-start gap-2 rounded p-1.5 text-xs hover:bg-zinc-900">
                    <input type="checkbox" className="mt-0.5 h-3.5 w-3.5 accent-emerald-500"
                           checked={sel.has(inc.id)}
                           onChange={() => {
                             const next = new Set(sel);
                             if (next.has(inc.id)) next.delete(inc.id);
                             else next.add(inc.id);
                             setSel(next);
                           }} />
                    <span className="min-w-0">
                      <span className="block truncate text-zinc-200">{inc.title}</span>
                      <span className="text-[10px] text-zinc-500">
                        {inc.id} · {inc.severity}
                        {inc.campaign_title ? ` · in campaign: ${inc.campaign_title} (will be moved)` : ""}
                      </span>
                    </span>
                  </label>
                ))}
                {pool.length === 0 && (
                  <div className="p-3 text-xs text-zinc-500">No incidents found.</div>
                )}
              </div>
            </ScrollArea>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}
                  className="text-zinc-400">Cancel</Button>
          <Button onClick={submit}
                  disabled={busy || title.trim().length < 3 || sel.size === 0}>
            {busy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            Create campaign
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AttachToCampaignDialog({
  open, onOpenChange, incidentIds, onDone,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  incidentIds: string[];
  onDone: () => void;
}) {
  const { toast } = useToast();
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTarget("");
    getCampaigns({}).then((r) => setCampaigns(r.items)).catch(() => setCampaigns([]));
  }, [open]);

  async function submit() {
    setBusy(true);
    try {
      const c = await attachToCampaign(target, incidentIds);
      toast({ title: "Merged into campaign",
        description: `${incidentIds.length} incident(s) added to "${c.title}".` });
      onOpenChange(false);
      onDone();
    } catch (e) {
      toast({ title: "Failed to merge", description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">
            Add {incidentIds.length} incident(s) to campaign
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <div className="text-xs text-zinc-500">
            Incidents already in another campaign are MOVED (last write wins);
            both campaigns&apos; rollups are recomputed.
          </div>
          <Select value={target} onValueChange={setTarget}>
            <SelectTrigger className="border-zinc-800 bg-zinc-900">
              <SelectValue placeholder="Select campaign" />
            </SelectTrigger>
            <SelectContent className="bg-zinc-900 border-zinc-800">
              {campaigns.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.title} ({c.incident_count})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}
                  className="text-zinc-400">Cancel</Button>
          <Button onClick={submit} disabled={busy || !target}>
            {busy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            Merge
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CampaignDetailView({
  campaignId, canEdit, onBack, onOpenIncident,
}: {
  campaignId: string;
  canEdit: boolean;
  onBack: () => void;
  onOpenIncident: (id: string) => void;
}) {
  const { toast } = useToast();
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [pool, setPool] = useState<IncidentSummary[]>([]);
  const [addSel, setAddSel] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setDetail(await getCampaignDetail(campaignId));
    } catch (e) {
      toast({ title: "Failed to load campaign", description: String(e), variant: "destructive" });
    }
  }, [campaignId, toast]);
  useEffect(() => { load(); }, [load]);

  function openAdd() {
    setAddSel(new Set());
    getIncidents({}).then((r) => setPool(r.items)).catch(() => setPool([]));
    setAddOpen(true);
  }

  async function submitAdd() {
    setBusy(true);
    try {
      await attachToCampaign(campaignId, [...addSel]);
      toast({ title: "Incidents merged into campaign" });
      setAddOpen(false);
      await load();
    } catch (e) {
      toast({ title: "Failed to merge", description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  async function detach(incidentId: string) {
    try {
      await detachFromCampaign(campaignId, incidentId);
      toast({ title: "Incident split out of campaign" });
      await load();
    } catch (e) {
      toast({ title: "Failed to split", description: String(e), variant: "destructive" });
    }
  }

  async function setStatus(status: "open" | "closed") {
    try {
      await updateCampaign(campaignId, { status });
      toast({ title: `Campaign ${status === "closed" ? "closed" : "reopened"}` });
      await load();
    } catch (e) {
      toast({ title: "Failed to update campaign", description: String(e), variant: "destructive" });
    }
  }

  if (!detail) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-zinc-500">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading campaign...
      </div>
    );
  }

  return (
    <div>
      <Button size="sm" variant="ghost" onClick={onBack}
              className="mb-3 -ml-2 text-zinc-400 hover:text-zinc-200">
        <ArrowLeft className="mr-1.5 h-4 w-4" /> All campaigns
      </Button>
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardContent className="py-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={detail.severity} />
            <CampStatusBadge status={detail.status} />
            <span className="text-[10px] text-zinc-500">
              {detail.incident_count} incident(s) · window {fmtTime(detail.first_seen)} → {fmtTime(detail.last_seen)}
              {detail.created_by ? ` · created by ${detail.created_by}` : ""}
            </span>
            {canEdit && (
              <span className="ml-auto flex gap-2">
                <Button size="sm" variant="outline"
                        className="border-zinc-700 text-zinc-300"
                        onClick={openAdd}>
                  <FolderOutput className="mr-1.5 h-3.5 w-3.5" /> Add incidents
                </Button>
                {detail.status === "open" ? (
                  <Button size="sm" variant="outline"
                          className="border-zinc-700 text-zinc-300"
                          onClick={() => setStatus("closed")}>
                    Close campaign
                  </Button>
                ) : (
                  <Button size="sm" variant="outline"
                          className="border-zinc-700 text-zinc-300"
                          onClick={() => setStatus("open")}>
                    Reopen
                  </Button>
                )}
              </span>
            )}
          </div>
          <h2 className="mt-2 text-base font-semibold text-zinc-100">{detail.title}</h2>
          {detail.description && (
            <p className="mt-1 text-xs leading-relaxed text-zinc-400">{detail.description}</p>
          )}
        </CardContent>
      </Card>

      <div className="mt-3 space-y-2">
        {detail.incidents.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800 p-6 text-center text-sm text-zinc-500">
            No incidents in this campaign. Use &quot;Add incidents&quot; to merge some.
          </div>
        ) : detail.incidents.map((inc) => (
          <div key={inc.id}
               className="flex items-center gap-3 rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-3">
            <button onClick={() => onOpenIncident(inc.id)}
                    className="min-w-0 flex-1 text-left">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={inc.severity} />
                <Badge variant="outline" className={`text-[10px] ${statusBadgeCls(inc.status)}`}>
                  {inc.status}
                </Badge>
                <span className="text-[10px] text-zinc-600">{inc.id}</span>
              </div>
              <div className="mt-1 truncate text-sm text-zinc-100">{inc.title}</div>
              <div className="mt-0.5 text-[10px] text-zinc-500">
                {inc.evidence_count} evidence · {fmtTime(inc.first_seen)} → {fmtTime(inc.last_seen)}
              </div>
            </button>
            {canEdit && (
              <Button size="sm" variant="ghost" onClick={() => detach(inc.id)}
                      className="text-zinc-500 hover:text-red-300"
                      title="Split this incident out of the campaign">
                <FolderMinus className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        ))}
      </div>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              Merge incidents into &quot;{detail.title}&quot;
            </DialogTitle>
          </DialogHeader>
          <ScrollArea className="h-56 rounded-md border border-zinc-800">
            <div className="space-y-1 p-2">
              {pool.map((inc) => (
                <label key={inc.id}
                       className="flex cursor-pointer items-start gap-2 rounded p-1.5 text-xs hover:bg-zinc-900">
                  <input type="checkbox" className="mt-0.5 h-3.5 w-3.5 accent-emerald-500"
                         checked={addSel.has(inc.id)}
                         onChange={() => {
                           const next = new Set(addSel);
                           if (next.has(inc.id)) next.delete(inc.id);
                           else next.add(inc.id);
                           setAddSel(next);
                         }} />
                  <span className="min-w-0">
                    <span className="block truncate text-zinc-200">{inc.title}</span>
                    <span className="text-[10px] text-zinc-500">
                      {inc.id} · {inc.severity}
                      {inc.campaign_id === campaignId ? " · already member" :
                        inc.campaign_title ? ` · in campaign: ${inc.campaign_title} (will be moved)` : ""}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </ScrollArea>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setAddOpen(false)}
                    className="text-zinc-400">Cancel</Button>
            <Button onClick={submitAdd} disabled={busy || addSel.size === 0}>
              {busy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
              Merge {addSel.size || ""}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CampaignsView({
  canEdit, onOpenIncident,
}: {
  canEdit: boolean;
  onOpenIncident: (id: string) => void;
}) {
  const { toast } = useToast();
  const [items, setItems] = useState<CampaignSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [statusF, setStatusF] = useState("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const load = useCallback(async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) setLoading(true);
    try {
      const r = await getCampaigns({ status: statusF, q: q || undefined });
      setItems(r.items);
    } catch (e) {
      if (!(e instanceof UnauthorizedError)) {
        toast({ title: "Failed to load campaigns", description: String(e), variant: "destructive" });
      }
    } finally {
      setLoading(false);
    }
  }, [statusF, q, toast]);
  useEffect(() => { load(); }, [load]);

  if (openId) {
    return (
      <CampaignDetailView campaignId={openId} canEdit={canEdit}
                          onBack={() => { setOpenId(null); load(); }}
                          onOpenIncident={onOpenIncident} />
    );
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <Select value={statusF} onValueChange={setStatusF}>
          <SelectTrigger className="w-40 border-zinc-800 bg-zinc-900">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-zinc-900 border-zinc-800">
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative min-w-56 flex-1">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <Input value={q} onChange={(e) => setQ(e.target.value)}
                 placeholder="Search campaigns..."
                 className="border-zinc-800 bg-zinc-900 pl-8 text-sm" />
        </div>
        {canEdit && (
          <Button size="sm" onClick={() => setCreateOpen(true)}
                  className="bg-emerald-900 text-emerald-100 hover:bg-emerald-800">
            <FolderKanban className="mr-1.5 h-3.5 w-3.5" /> New campaign
          </Button>
        )}
      </div>

      <ScrollArea className="mt-3" style={{ height: "calc(100vh - 420px)" }}>
        <div className="space-y-2 pr-2">
          {loading ? (
            <div className="flex h-40 items-center justify-center text-sm text-zinc-500">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading campaigns...
            </div>
          ) : items.length === 0 ? (
            <div className="flex h-40 flex-col items-center justify-center gap-2 text-sm text-zinc-500">
              <FolderKanban className="h-6 w-6 text-zinc-700" />
              No campaigns yet - select incidents and merge them into one.
            </div>
          ) : items.map((c) => (
            <button key={c.id} onClick={() => setOpenId(c.id)}
                    className="w-full rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-4 text-left transition-colors hover:border-emerald-900/70 hover:bg-zinc-900">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={c.severity} />
                <CampStatusBadge status={c.status} />
                <span className="ml-auto text-[10px] text-zinc-600">
                  {c.incident_count} incident(s)
                </span>
              </div>
              <div className="mt-2 text-sm font-medium text-zinc-100">{c.title}</div>
              {c.description && (
                <div className="mt-1 line-clamp-2 text-xs text-zinc-400">{c.description}</div>
              )}
              <div className="mt-2 flex flex-wrap items-center gap-x-4 text-[11px] text-zinc-500">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" /> {fmtTime(c.first_seen)} → {fmtTime(c.last_seen)}
                </span>
                {c.created_by && <span>created by {c.created_by}</span>}
                <ChevronRight className="ml-auto h-4 w-4 text-zinc-600" />
              </div>
            </button>
          ))}
        </div>
      </ScrollArea>

      <CreateCampaignDialog open={createOpen} onOpenChange={setCreateOpen}
                            preselect={[]}
                            onDone={(id) => { load({ silent: true }); setOpenId(id); }} />
    </div>
  );
}

export function IncidentsView({ canEdit, focusIncidentId }: {
  canEdit: boolean;
  /** v0.12.8: deep-link from Alert Center "open in Incidents" - open this
   *  incident's detail as soon as it changes. */
  focusIncidentId?: string | null;
}) {
  const { toast } = useToast();
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [stats, setStats] = useState<IncidentStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [q, setQ] = useState("");
  const [timeRange, setTimeRange] = useState<TimeRange>(DEFAULT_TIME_RANGE);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [viewMode, setViewMode] = useState("incidents");

  // campaign bulk actions (v0.12)
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [createOpen, setCreateOpen] = useState(false);
  const [attachOpen, setAttachOpen] = useState(false);

  function toggleSelect(id: string) {
    setSelection((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // triage dialog
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogMode, setDialogMode] = useState<"status" | "note">("status");
  const [dialogStatus, setDialogStatus] = useState("confirmed");
  const [dialogNote, setDialogNote] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadList = useCallback(async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) setLoading(true);
    try {
      const window = resolveTimeRange(timeRange);
      const [list, st] = await Promise.all([
        getIncidents({
          status: statusFilter, severity: sevFilter, q: q || undefined,
          time_from: window.from, time_to: window.to,
        }),
        getIncidentStats(),
      ]);
      setItems(list.items);
      setStats(st);
    } catch (e) {
      if (!(e instanceof UnauthorizedError)) {
        toast({ title: "Failed to load incidents", description: String(e), variant: "destructive" });
      }
    } finally {
      setLoading(false);
    }
  }, [statusFilter, sevFilter, q, timeRange, toast]);

  const loadDetail = useCallback(async (id: string) => {
    setDetailLoading(true);
    try {
      setDetail(await getIncidentDetail(id));
    } catch (e) {
      toast({ title: "Failed to load incident", description: String(e), variant: "destructive" });
      setSelectedId(null);
    } finally {
      setDetailLoading(false);
    }
  }, [toast]);

  useEffect(() => { loadList(); setPage(1); }, [loadList]);
  useEffect(() => {
    if (selectedId) loadDetail(selectedId);
    else setDetail(null);
  }, [selectedId, loadDetail]);
  // v0.12.8: cross-navigation from Alert Center / DGA Activity
  useEffect(() => {
    if (focusIncidentId) setSelectedId(focusIncidentId);
  }, [focusIncidentId]);

  const pagedItems = useMemo(
    () => items.slice((page - 1) * pageSize, page * pageSize),
    [items, page, pageSize]);
  // auto refresh list every 30s while in list mode
  useEffect(() => {
    if (selectedId) return;
    const t = setInterval(() => loadList({ silent: true }), 30_000);
    return () => clearInterval(t);
  }, [selectedId, loadList]);

  function openTriage(mode: "status" | "note", status?: string) {
    setDialogMode(mode);
    setDialogStatus(status ?? "confirmed");
    setDialogNote("");
    setDialogOpen(true);
  }

  async function submitTriage() {
    if (!detail) return;
    setSubmitting(true);
    try {
      if (dialogMode === "status") {
        await updateIncidentStatus(detail.id, dialogStatus as IncidentDetail["status"],
          dialogNote || undefined);
        toast({ title: `Incident marked ${dialogStatus}`, description: "Change recorded in incident history + audit log." });
      } else {
        await addIncidentNote(detail.id, dialogNote);
        toast({ title: "Note added" });
      }
      setDialogOpen(false);
      await loadDetail(detail.id);
      loadList({ silent: true });
    } catch (e) {
      toast({ title: "Action failed", description: String(e), variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  const triageDialog = (
    <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
      <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">
            {dialogMode === "status"
              ? `Mark incident as ${dialogStatus}`
              : "Add analyst note"}
          </DialogTitle>
        </DialogHeader>
        {dialogMode === "status" && (
          <div className="space-y-2">
            <div className="text-xs text-zinc-500">
              The status change and this note are appended to the incident
              history and the platform audit log.
            </div>
            <Select value={dialogStatus} onValueChange={setDialogStatus}>
              <SelectTrigger className="border-zinc-800 bg-zinc-900">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-900 border-zinc-800">
                {STATUS_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        <Textarea
          value={dialogNote}
          onChange={(e) => setDialogNote(e.target.value)}
          placeholder={dialogMode === "status"
            ? "Why? (recorded with the status change)"
            : "What did you verify?"}
          className="min-h-24 border-zinc-800 bg-zinc-900 text-sm" />
        <DialogFooter>
          <Button variant="ghost" onClick={() => setDialogOpen(false)}
                  className="text-zinc-400">
            Cancel
          </Button>
          <Button onClick={submitTriage} disabled={submitting || (dialogMode === "note" && dialogNote.trim().length < 2)}>
            {submitting && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            {dialogMode === "status" ? "Apply" : "Save note"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );

  if (selectedId) {
    return (
      <>
        {detailLoading && !detail ? (
          <div className="flex h-64 items-center justify-center text-sm text-zinc-500">
            <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Reconstructing incident...
          </div>
        ) : detail ? (
          <IncidentDetailPanel
            detail={detail}
            canEdit={canEdit}
            onBack={() => setSelectedId(null)}
            onChanged={() => loadList({ silent: true })}
            onOpenNote={openTriage}
          />
        ) : null}
        {triageDialog}
      </>
    );
  }

  const selectedIds = [...selection];
  return (
    <div className="space-y-3">
      {/* v0.14.0: manual refresh + auto-refresh choice (auto already ran
          silently every 30 s; now the user SEES and CONTROLS it) */}
      <div className="flex justify-end">
        <RefreshControls storageKey="incidents" onRefresh={() => { void loadList({ silent: true }); }} loading={loading} />
      </div>
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { title: "Open incidents", value: stats?.open_total ?? "-", tone: (stats?.open_total ?? 0) > 0 ? "alert" : "ok" },
          { title: "Confirmed", value: stats?.by_status?.confirmed ?? 0 },
          { title: "Benign / FP", value: stats?.by_status?.benign ?? 0 },
          { title: "Total stories", value: stats?.total ?? "-" },
        ].map((k) => (
          <Card key={k.title} className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="py-3">
              <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">{k.title}</div>
              <div className={`mt-0.5 text-2xl font-semibold tabular-nums ${k.tone === "alert" ? "text-orange-300" : "text-zinc-100"}`}>
                {k.value}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs value={viewMode} onValueChange={setViewMode} className="mt-3">
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="incidents" className="text-xs">
            <Waypoints className="mr-1.5 h-3.5 w-3.5" /> Incidents
          </TabsTrigger>
          <TabsTrigger value="campaigns" className="text-xs">
            <FolderKanban className="mr-1.5 h-3.5 w-3.5" /> Campaigns
          </TabsTrigger>
        </TabsList>

        <TabsContent value="incidents">
          {/* filters */}
          <div className="flex flex-wrap items-center gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-44 border-zinc-800 bg-zinc-900">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent className="bg-zinc-900 border-zinc-800">
                <SelectItem value="all">All statuses</SelectItem>
                {STATUS_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={sevFilter} onValueChange={setSevFilter}>
              <SelectTrigger className="w-40 border-zinc-800 bg-zinc-900">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent className="bg-zinc-900 border-zinc-800">
                <SelectItem value="all">All severities</SelectItem>
                {["critical", "high", "medium", "low"].map((s) => (
                  <SelectItem key={s} value={s}>{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <TimeRangePicker value={timeRange} onChange={setTimeRange} />
            <div className="relative min-w-56 flex-1">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
              <Input value={q} onChange={(e) => setQ(e.target.value)}
                     placeholder="Search title / entity..."
                     className="border-zinc-800 bg-zinc-900 pl-8 text-sm" />
            </div>
            <Button size="sm" variant="outline" onClick={() => loadList()}
                    className="border-zinc-700 text-zinc-300">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>

          {/* disclaimer - how incidents come to exist */}
          <div className="mt-3 rounded-lg border border-zinc-800/80 bg-zinc-900/40 px-3 py-2 text-[11px] leading-relaxed text-zinc-500">
            <Waypoints className="mr-1.5 inline h-3.5 w-3.5 text-emerald-500" />
            <span className="text-zinc-300">How incidents are determined:</span> the correlation
            engine reconstructs incidents AUTOMATICALLY by linking alerts, IOC matches and
            cross-log context through shared entities and behavior - every relation carries its
            reason + confidence, and time proximity alone never draws a link. Parameters:
            shared IP/domain/hash between detections, TI match on the chain, behavior rules
            (e.g. DGA burst followed by beaconing on the same host), identical source/destination
            pair across signatures. Analysts can also raise an alert MANUALLY: use the lightning
            icon on any alert in Alert Center to escalate it into a new open incident (no links
            are invented - related evidence found later is merged by the engine). Campaigns are
            analyst bookkeeping on top: merging/splitting never rewrites evidence or relations.
            Confidence is heuristic and uncalibrated; outcome labels separate <span className="text-zinc-300">proven</span>,
            <span className="text-zinc-300"> suspected</span> and
            <span className="text-zinc-300"> unknown</span> - network data alone cannot prove host
            state (doc section 10).
          </div>

          {/* bulk action bar (v0.12 campaigns) */}
          {canEdit && selectedIds.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-emerald-900/60 bg-emerald-950/20 px-3 py-2">
              <Layers className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-xs text-emerald-200">
                {selectedIds.length} incident(s) selected
              </span>
              <Button size="sm" variant="outline"
                      className="ml-auto border-emerald-800 text-emerald-200"
                      onClick={() => setCreateOpen(true)}>
                <FolderKanban className="mr-1.5 h-3.5 w-3.5" /> New campaign
              </Button>
              <Button size="sm" variant="outline"
                      className="border-zinc-700 text-zinc-300"
                      onClick={() => setAttachOpen(true)}>
                <FolderOutput className="mr-1.5 h-3.5 w-3.5" /> Add to campaign
              </Button>
              <Button size="sm" variant="ghost" className="text-zinc-500"
                      onClick={() => setSelection(new Set())}>
                <X className="mr-1 h-3.5 w-3.5" /> Clear
              </Button>
            </div>
          )}

          {/* incident list */}
          <ScrollArea className="mt-3" style={{ height: "calc(100vh - 500px)" }}>
            <div className="space-y-2 pr-2">
              {loading ? (
                <div className="flex h-40 items-center justify-center text-sm text-zinc-500">
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Correlating signals...
                </div>
              ) : pagedItems.length === 0 ? (
                <div className="flex h-40 flex-col items-center justify-center gap-2 text-sm text-zinc-500">
                  <Waypoints className="h-6 w-6 text-zinc-700" />
                  No reconstructed incidents match the filters.
                </div>
              ) : pagedItems.map((inc) => (
                <div key={inc.id}
                     className="relative w-full rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-4 text-left transition-colors hover:border-emerald-900/70 hover:bg-zinc-900">
                  {canEdit && (
                    <input type="checkbox"
                           aria-label={`Select incident ${inc.title}`}
                           className="absolute left-3 top-5 h-3.5 w-3.5 cursor-pointer accent-emerald-500"
                           checked={selection.has(inc.id)}
                           onClick={(e) => e.stopPropagation()}
                           onChange={() => toggleSelect(inc.id)} />
                  )}
                  <button onClick={() => setSelectedId(inc.id)}
                          className={`w-full text-left ${canEdit ? "pl-5" : ""}`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={inc.severity} />
                      <Badge variant="outline" className={`text-[10px] ${statusBadgeCls(inc.status)}`}>
                        {inc.status}
                      </Badge>
                      <Badge variant="outline"
                             className={`text-[10px] ${OUTCOME_META[inc.outcome_label]?.cls ?? ""}`}>
                        {OUTCOME_META[inc.outcome_label]?.label ?? inc.outcome_label}
                      </Badge>
                      {inc.campaign_title && (
                        <Badge variant="outline"
                               className="border-emerald-800 bg-emerald-950/40 text-[10px] text-emerald-300"
                               title={`Part of campaign: ${inc.campaign_title}`}>
                          <FolderKanban className="mr-1 h-3 w-3" />
                          {inc.campaign_title}
                        </Badge>
                      )}
                      <span className="ml-auto text-[10px] text-zinc-600">
                        {inc.evidence_count} evidence · {inc.entity_count} entities · {inc.signal_count} signals
                      </span>
                    </div>
                    <div className="mt-2 text-sm font-medium text-zinc-100">
                      {inc.title}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5">
                      <PhaseChips phases={inc.phases} />
                      {inc.deepest_stage && (
                        <span className="rounded border border-zinc-800 bg-zinc-950/60 px-1.5 py-0.5 text-[10px]"
                              style={{ color: stageMeta(String(inc.deepest_stage)).color }}
                              title="Deepest kill-chain stage assessed (observed or suspected)">
                          KC: {stageMeta(String(inc.deepest_stage)).label}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-4 text-[11px] text-zinc-500">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {fmtTime(inc.first_seen)} → {fmtTime(inc.last_seen)}
                      </span>
                      <span>confidence {inc.confidence}/100</span>
                      {inc.analyst && <span>analyst: {inc.analyst}</span>}
                      <ChevronRight className="ml-auto h-4 w-4 text-zinc-600" />
                    </div>
                  </button>
                </div>
              ))}
            </div>
          </ScrollArea>

          <Paginator page={page} pageSize={pageSize} total={items.length}
                     onPage={(p) => setPage(p)}
                     onPageSize={(s) => { setPageSize(s); setPage(1); }} />
        </TabsContent>

        <TabsContent value="campaigns">
          <CampaignsView canEdit={canEdit}
                         onOpenIncident={(id) => setSelectedId(id)} />
        </TabsContent>
      </Tabs>

      {triageDialog}
      <CreateCampaignDialog open={createOpen} onOpenChange={(v) => { setCreateOpen(v); }}
                            preselect={selectedIds}
                            onDone={() => { setSelection(new Set()); loadList({ silent: true }); }} />
      <AttachToCampaignDialog open={attachOpen} onOpenChange={setAttachOpen}
                              incidentIds={selectedIds}
                              onDone={() => { setSelection(new Set()); loadList({ silent: true }); }} />
    </div>
  );
}
