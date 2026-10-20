"use client";

// Alert detail sheet (v0.12.8) - extracted from alerts.tsx so BOTH the
// Alert Center and the dedicated DGA Activity menu render the exact same
// detail workflow (verdicts, evidence, PCAP, notes, escalation).
//
// v0.12.8 additions (correlation readability / provability):
//   - "Correlation & incident linkage" section: incidents whose recorded
//     EVIDENCE references this alert (honest link - recorded by the
//     correlation engine or a manual escalation, never guessed), with a
//     one-click jump into Incidents.
//   - "Verify in Event Search": re-run the raw events behind this alert
//     (source/destination pair + the alert's own time window) so every
//     claim on this page can be re-checked against the raw event store.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { WhitelistDialog } from "./whitelist-dialog";
import { SEV_COLORS } from "./charts";
import {
  OutcomeBadge, SeverityBadge, StatusBadge, alertTitle, fmtNumber, fmtTime,
  JsonViewer, timeAgo,
} from "./shared";
import {
  ChevronRight, FileText, Info, Loader2, Search, ShieldAlert, Waypoints, Zap,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  getAlertRelatedIncidents, updateAlert,
} from "@/lib/ndr/api";
import type { AlertDoc, RelatedIncident } from "@/lib/ndr/types";
import { EvidencePanel } from "./evidence";
import { cn } from "@/lib/utils";

export function protocolOf(a: AlertDoc): string {
  return (a.network?.protocol ?? a.network?.transport ?? "-").toUpperCase();
}

export interface VerifyEventRequest {
  src?: string;
  dst?: string;
  from: string;
  to: string;
}

export function AlertDetailSheet({ alert, canEdit, onClose, onAlertChanged, onOpenThreatMap, onOpenIncident, onVerifyEvents, onEscalate, canApproveWhitelist }: {
  alert: AlertDoc | null;
  canEdit: boolean;
  /** v0.14.0: administrator/security_engineer -> whitelist self-approve. */
  canApproveWhitelist?: boolean;
  onClose: () => void;
  /** Sync one updated alert back into the parent list state. */
  onAlertChanged?: (updated: AlertDoc) => void;
  /** v0.12.9: open the FOCUSED attack relationship of THIS alert (not the
   * global/geographic map) in the Threat Map view. */
  onOpenThreatMap?: (alert: AlertDoc) => void;
  /** v0.12.8: jump into Incidents focused on a linked incident. */
  onOpenIncident?: (incidentId: string) => void;
  /** v0.12.8: re-verify this alert against raw events in Event Search. */
  onVerifyEvents?: (req: VerifyEventRequest) => void;
  /** Delegate escalation to the parent view (shared dialog + audit). */
  onEscalate?: (alert: AlertDoc) => void;
}) {
  const { toast } = useToast();
  const [notesDraft, setNotesDraft] = useState("");
  // v0.14.0: whitelist dialog state
  const [wlOpen, setWlOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  // v0.12.8: honest alert -> incident linkage
  const [related, setRelated] = useState<RelatedIncident[] | null>(null);
  const [relatedLoading, setRelatedLoading] = useState(false);

  useEffect(() => {
    setNotesDraft(alert?.notes ?? "");
  }, [alert?.alert_id, alert?.notes]);

  useEffect(() => {
    if (!alert?.alert_id) {
      setRelated(null);
      return;
    }
    let alive = true;
    setRelatedLoading(true);
    getAlertRelatedIncidents(alert.alert_id)
      .then((res) => { if (alive) setRelated(res.items); })
      .catch(() => { if (alive) setRelated(null); })
      .finally(() => { if (alive) setRelatedLoading(false); });
    return () => { alive = false; };
  }, [alert?.alert_id]);

  async function applyStatus(next: AlertDoc["status"]) {
    if (!alert) return;
    setSaving(true);
    try {
      await updateAlert(alert.alert_id, { status: next });
      const updated = { ...alert, status: next };
      onAlertChanged?.(updated);
      toast({
        title: "Alert updated",
        description: `${alertTitle(alert.title)} -> ${next.replace("_", " ")}`,
      });
    } catch (e) {
      toast({ title: "Update failed", description: String(e), variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  async function saveNotes() {
    if (!alert) return;
    setSaving(true);
    try {
      await updateAlert(alert.alert_id, { notes: notesDraft });
      const updated = { ...alert, notes: notesDraft };
      onAlertChanged?.(updated);
      toast({ title: "Notes saved" });
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  // v0.12.8: verification window = the alert's own activity window,
  // padded by 15 minutes on both sides.
  function verifyWindow(): VerifyEventRequest | null {
    if (!alert) return null;
    const src = alert.source?.ip;
    const dst = alert.destination?.ip;
    if (!src && !dst) return null;
    const pad = (iso: string, deltaMs: number) => {
      const t = new Date(iso).getTime();
      if (Number.isNaN(t)) return undefined;
      return new Date(t + deltaMs).toISOString();
    };
    const from = pad(alert.first_seen, -15 * 60_000);
    const to = pad(alert.last_seen, +15 * 60_000);
    if (!from || !to) return null;
    return { src, dst, from, to };
  }

  const selected = alert;

  return (
    <Sheet open={!!selected} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto border-zinc-800 bg-zinc-950 sm:max-w-2xl">
        {selected && (
          <>
            <SheetHeader className="pb-2">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={selected.severity} />
                <StatusBadge status={selected.status} />
                <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">{selected.alert_type}</Badge>
                <OutcomeBadge outcome={selected.outcome} />
                <Badge variant="outline" className="border-zinc-800 font-mono text-[10px] text-zinc-400">
                  {protocolOf(selected)}
                </Badge>
                {selected.kill_chain && typeof selected.kill_chain === "object" ? (
                  <Badge variant="outline"
                         className="border-violet-900 text-[10px] text-violet-300"
                         title={selected.kill_chain.reason}>
                    kill chain: {selected.kill_chain.stage_label}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="border-violet-900 text-[10px] text-violet-300">
                    kill chain: {typeof selected.kill_chain === "string" ? selected.kill_chain : "n/a"}
                  </Badge>
                )}
              </div>
              <SheetTitle className="text-left text-lg leading-snug text-zinc-100">{alertTitle(selected.title)}</SheetTitle>
              <p className="text-xs text-zinc-500">
                {fmtTime(selected.first_seen)} &rarr; {fmtTime(selected.last_seen)} - sensor {selected.sensor_id}
                {selected.sla_minutes ? ` - SLA ${selected.sla_minutes}m` : ""}
              </p>
            </SheetHeader>

            <div className="space-y-4 px-4 pb-8">
              {canEdit && (
                <div className="flex flex-wrap gap-2">
                  {(["acknowledged", "in_progress", "closed", "false_positive"] as const).map((s) => (
                    <Button key={s} size="sm" variant="outline"
                            disabled={saving || selected.status === s}
                            onClick={() => applyStatus(s)}
                            className="border-zinc-700 bg-zinc-900 text-xs text-zinc-300 hover:bg-zinc-800">
                      {s.replace("_", " ")}
                    </Button>
                  ))}
                  {(onEscalate || canEdit) && (
                    <Button size="sm"
                            onClick={() => onEscalate?.(selected)}
                            className="bg-amber-600 text-xs text-white hover:bg-amber-500">
                      <Zap className="mr-1 h-3.5 w-3.5" /> Escalate to incident
                    </Button>
                  )}
                  {selected.alert_id && onOpenThreatMap && (
                    <Button size="sm" variant="outline"
                            onClick={() => onOpenThreatMap(selected)}
                            className="border-emerald-800 bg-zinc-900 text-xs text-emerald-300 hover:bg-emerald-950/40">
                      <Waypoints className="mr-1 h-3.5 w-3.5" /> View its attack relationship
                    </Button>
                  )}
                </div>
              )}

              {/* risk + confidence */}
              <div className="grid grid-cols-3 gap-3">
                <ScoreBox label="Risk score" value={selected.risk_score ?? selected.severity_score ?? 0}
                          color={(selected.risk_score ?? 0) >= 70 ? "#f87171" : (selected.risk_score ?? 0) >= 45 ? "#fbbf24" : "#38bdf8"} />
                <ScoreBox label="Severity score" value={selected.severity_score ?? 0} color={SEV_COLORS[selected.severity] ?? "#71717a"} />
                <ScoreBox label="Events in group" value={Math.min(100, selected.event_count)} display={fmtNumber(selected.event_count)} color="#60a5fa" />
              </div>

              {/* Attack result / verdict (v0.10) */}
              <div className="rounded-lg border border-amber-900/50 bg-amber-950/15 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                    Attack result (verdict)
                  </span>
                  <OutcomeBadge outcome={selected.outcome} />
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-400">
                  Determined by the pipeline at detection time:
                </p>
                <ul className="mt-1 list-inside list-disc space-y-0.5 text-[11px] text-zinc-500">
                  <li><span className="text-zinc-300">attempted</span> - attack-class activity observed, no evidence it went past the attempt (default for signature alerts)</li>
                  <li><span className="text-zinc-300">suspected_success</span> - a server-reaction signature (e.g. ATTACK_RESPONSE) or follow-on activity fired on the same source/destination pair</li>
                  <li><span className="text-zinc-300">strong_success</span> - reserved for the correlation engine: full chain with TI-matched infrastructure and success markers</li>
                  <li><span className="text-zinc-300">indeterminate</span> - recon/behavioral detections where the activity itself may be benign</li>
                </ul>
                <p className="mt-1.5 flex items-start gap-1 text-[10px] text-zinc-600">
                  <Info className="mt-0.5 h-3 w-3 shrink-0" />
                  The title above mirrors the detection rule message verbatim - a word like
                  &quot;Attempt&quot; is part of the Suricata signature name (e.g. &quot;ET WEB_SERVER SQL
                  Injection Attempt&quot;), NOT the verdict. The verdict lives in this separate field.
                </p>
              </div>

              {/* Kill chain classification (doc 11 dual framework) */}
              {selected.kill_chain && typeof selected.kill_chain === "object" && (
                <div className="rounded-lg border border-violet-900/60 bg-violet-950/20 px-3 py-2.5">
                  <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                    Kill chain stage (doc 11)
                  </div>
                  <div className="mt-1 text-sm font-semibold text-violet-200">
                    {selected.kill_chain.stage_label}
                  </div>
                  <div className="mt-0.5 text-[11px] text-zinc-400">{selected.kill_chain.reason}</div>
                </div>
              )}

              {/* MITRE */}
              {!!selected.mitre?.length && (
                <div>
                  <CardTitle className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">MITRE ATT&CK mapping</CardTitle>
                  <div className="flex flex-wrap gap-2">
                    {selected.mitre.map((m) => (
                      <div key={m.technique_id} className="rounded-lg border border-violet-900/60 bg-violet-950/25 px-2.5 py-1.5">
                        <div className="text-[10px] font-semibold text-violet-300">{m.technique_id}</div>
                        <div className="text-[11px] text-zinc-300">{m.technique}</div>
                        <div className="text-[9px] uppercase tracking-wide text-zinc-600">{m.tactic}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Section title="Why this alert fired (rationale)">
                <p className="text-sm leading-relaxed text-zinc-300">{selected.rationale}</p>
                <ul className="mt-2 list-inside list-disc space-y-1 text-xs text-zinc-400">
                  {(selected.reasons ?? []).map((r, i) => <li key={i}>{r}</li>)}
                </ul>
                <p className="mt-2 flex items-center gap-1.5 text-[11px] text-zinc-600">
                  <ShieldAlert className="h-3 w-3" />
                  Confidence: {selected.confidence} - heuristic thresholds, not calibrated probabilities.
                </p>
              </Section>

              {/* v0.12.8: honest alert -> incident linkage + raw-event
                  verification path. An incident appears here ONLY when the
                  correlation engine or a manual escalation actually recorded
                  this alert as incident evidence. */}
              <Section title="Correlation & incident linkage">
                {relatedLoading ? (
                  <p className="flex items-center gap-2 text-xs text-zinc-500">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> checking incident evidence...
                  </p>
                ) : related && related.length > 0 ? (
                  <div className="space-y-2">
                    {related.map((r) => (
                      <div key={r.incident_id}
                           className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2">
                        <FileText className="h-3.5 w-3.5 shrink-0 text-violet-400" />
                        <span className="min-w-0 flex-1 truncate text-xs text-zinc-200"
                              title={r.title}>
                          {r.title}
                        </span>
                        <Badge variant="outline" className="border-zinc-700 text-[9px] uppercase text-zinc-400">
                          {r.status}
                        </Badge>
                        <Badge variant="outline" className="border-zinc-700 text-[9px] uppercase text-zinc-400">
                          outcome: {r.outcome_label}
                        </Badge>
                        <button className="text-[11px] text-sky-400 hover:text-sky-300"
                                onClick={() => onOpenIncident?.(r.incident_id)}>
                          open in Incidents <ChevronRight className="inline h-3 w-3" />
                        </button>
                      </div>
                    ))}
                    <p className="text-[10px] text-zinc-600">
                      These incidents list THIS alert in their evidence (recorded by the
                      correlation engine or a manual escalation) - the linkage is
                      evidence-backed, never inferred by similarity.
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-zinc-500">
                    No reconstructed incident references this alert yet. The
                    correlation engine links alerts into incidents only through shared,
                    evidence-backed entities - if that happens later, the link appears
                    here automatically.
                  </p>
                )}
                {verifyWindow() && onVerifyEvents && (
                  <Button size="sm" variant="outline"
                          className="mt-2.5 border-sky-800 bg-zinc-900 text-xs text-sky-300 hover:bg-sky-950/40"
                          onClick={() => {
                            const w = verifyWindow();
                            if (w) onVerifyEvents(w);
                          }}>
                    <Search className="mr-1.5 h-3.5 w-3.5" />
                    Verify in Event Search (raw events, window +/-15m)
                  </Button>
                )}
                {/* v0.14.0: false-positive control straight from the case */}
                {canEdit && (
                  <Button size="sm" variant="outline"
                          className="mt-2.5 border-emerald-800 bg-zinc-900 text-xs text-emerald-300 hover:bg-emerald-950/40"
                          onClick={() => setWlOpen(true)}>
                    <ShieldCheck className="mr-1.5 h-3.5 w-3.5" />
                    Whitelist similar detections&hellip;
                  </Button>
                )}
              </Section>

              <Separator className="bg-zinc-800" />

              <Section title="Network context">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <Field label="Source" value={selected.source?.ip ?? "-"} mono
                         sub={selected.source_asset_name ?? undefined} />
                  <Field label="Destination" value={selected.destination?.ip ?? "-"} mono
                         sub={selected.destination_asset_name ?? undefined} />
                  <Field label="Event count" value={fmtNumber(selected.event_count)} />
                  <Field label="Destinations" value={fmtNumber(selected.destination_count)} />
                  <Field label="Protocol" value={protocolOf(selected)}
                         sub={selected.network?.protocol && selected.network?.transport
                           ? `transport ${selected.network.transport}` : undefined} />
                  <Field label="Detection rule" value={selected.alert_type} mono
                         sub={selected.group_key ? `group key: ${selected.group_key}` : undefined} />
                  <Field label="Assignee" value={selected.assignee ?? "unassigned"} />
                  <Field label="Alert id" value={selected.alert_id} mono />
                </div>
                {!!(selected.top_destinations ?? []).length && (
                  <div className="mt-3">
                    <div className="mb-1 text-xs text-zinc-500">Top destinations</div>
                    <div className="flex flex-wrap gap-1.5">
                      {(selected.top_destinations ?? []).map((d, i) => (
                        <Badge key={i} variant="outline" className="border-zinc-700 font-mono text-[11px] text-zinc-300">
                          {d.ip} ({d.count})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {!!(selected.top_sources ?? []).length && (
                  <div className="mt-3">
                    <div className="mb-1 text-xs text-zinc-500">Top sources</div>
                    <div className="flex flex-wrap gap-1.5">
                      {(selected.top_sources ?? []).map((d, i) => (
                        <Badge key={i} variant="outline" className="border-zinc-700 font-mono text-[11px] text-zinc-300">
                          {d.ip} ({d.count})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </Section>

              {/* v0.12.6: the standalone trigger-events list was merged
                  into the panel below - the analyst saw the same events
                  twice, stacked one after the other (user report).
                  Trigger refs now render inside the PCAP & evidence
                  panel and survive session lookup errors. */}
              <Separator className="bg-zinc-800" />

              {/* PCAP & evidence workflow (doc section 15) */}
              <Section title="PCAP & evidence (doc 15)">
                <EvidencePanel scope="alert" scopeId={selected.alert_id}
                               canExport={canEdit}
                               evidence={selected.evidence} />
              </Section>

              {canEdit && (
                <>
                  <Separator className="bg-zinc-800" />
                  <Section title="Analyst notes">
                    <Textarea value={notesDraft} onChange={(e) => setNotesDraft(e.target.value)}
                              placeholder="Document triage decisions, context, and follow-up..."
                              className="min-h-24 border-zinc-800 bg-zinc-900 text-sm text-zinc-200" />
                    <Button size="sm" onClick={saveNotes} disabled={saving}
                            className="mt-2 bg-emerald-600 text-white hover:bg-emerald-500">
                      {saving && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />} Save notes
                    </Button>
                  </Section>
                </>
              )}

              <Separator className="bg-zinc-800" />
              <Section title="Raw alert document">
                <JsonViewer data={selected} maxHeight={240} />
              </Section>
              <p className="flex items-start gap-1.5 text-[10px] leading-relaxed text-zinc-600">
                <Info className="mt-0.5 h-3 w-3 shrink-0" />
                Provenance: every field on this page comes from the detection pipeline at
                alert time (rule, rationale, reasons, evidence refs) or from analyst edits
                (status, notes) - all analyst actions are in the audit log.
              </p>
            </div>
          </>
        )}
      </SheetContent>
          {/* v0.14.0: whitelist (allowlist) dialog */}
      <WhitelistDialog
        alert={wlOpen && selected ? selected : null}
        canApprove={canApproveWhitelist ?? false}
        onClose={() => setWlOpen(false)}
      />
</Sheet>
  );
}

export function ScoreBox({ label, value, color, display }: { label: string; value: number; color: string; display?: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-2.5">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="text-lg font-semibold tabular-nums text-zinc-100">{display ?? value}</span>
        {!display && <span className="text-[10px] text-zinc-600">/100</span>}
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-zinc-800">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(100, value)}%`, background: color }} />
      </div>
    </div>
  );
}

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <CardTitle className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">{title}</CardTitle>
      {children}
    </div>
  );
}

export function Field({ label, value, mono, sub }: { label: string; value: string; mono?: boolean; sub?: string }) {
  return (
    <div>
      <div className="text-xs text-zinc-500">{label}</div>
      <div className={cn(`${mono ? "font-mono" : ""} text-sm text-zinc-200`)}>{value}</div>
      {sub && <div className="text-[10px] text-emerald-400/80">{sub}</div>}
    </div>
  );
}
