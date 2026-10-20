"use client";

// DGA Activity view (v0.12.8) - a dedicated FOCUS MENU for the two
// DGA-family detections the pipeline already emits:
//   - dga_suspected      (high-entropy unique-domain burst, Phase 4)
//   - dns_nxdomain_burst (weak DGA signal, doc 8.7)
// This is a lens over existing alerts - NO new detector. Everything on
// this page links back to checkable evidence: alert rationale/reasons,
// sampled domains (recorded by the detector at alert time), trigger
// events and the shared alert detail sheet.

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import {
  BookOpenCheck, ChevronDown, Dna, Globe2, Hourglass, ShieldQuestion, Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { alertStats, getDgaSummary, searchAlerts } from "@/lib/ndr/api";
import type { AlertDoc, DgaSummary } from "@/lib/ndr/types";
import { AlertDetailSheet, protocolOf } from "./alert-detail";
import { RefreshControls } from "./refresh-controls";
import type { VerifyEventRequest } from "./alert-detail";
import { Paginator, StatCard, fmtNumber, fmtTime, timeAgo } from "./shared";
import { OutcomeBadge, SeverityBadge, StatusBadge, alertTitle } from "./shared";
import { cn } from "@/lib/utils";

const DGA_ALERT_TYPES = ["dga_suspected", "dns_nxdomain_burst"];

const WINDOW_OPTIONS = [
  { value: 24, label: "24h" },
  { value: 168, label: "7d" },
  { value: 336, label: "14d" },
];

/**
 * Domains the DETECTOR recorded in the alert reasons ("sample queries:
 * a, b"). v0.12.9 reasons carry per-domain entropy "domain (4.12)" - the
 * score suffix is stripped for the domain list (and shown next to it
 * where useful). Pure presentation of already-stored evidence - nothing
 * is re-inferred here. Bracket-defanged domains (a[.]b) are shown as-is.
 */
function sampledDomains(alerts: AlertDoc[]): { domain: string; count: number }[] {
  const counts = new Map<string, number>();
  alerts.forEach((a) => {
    (a.reasons ?? []).forEach((r) => {
      const m = r.match(/sample (?:high-entropy )?queries?\s*:\s*(.+)/i);
      if (!m) return;
      m[1].split(/,\s*/).forEach((raw) => {
        const d = raw.trim().replace(/\s*\(\d+\.\d+\)\s*$/, "").replace(/^/, "");
        if (d && d.includes(".")) counts.set(d, (counts.get(d) ?? 0) + 1);
      });
    });
  });
  return Array.from(counts.entries())
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);
}

export function DgaView({ canEdit, onOpenIncident, onVerifyEvents, onOpenThreatMap, canApproveWhitelist }: {
  canEdit: boolean;
  /** v0.14.0: whitelist self-approve (admin/security_engineer). */
  canApproveWhitelist?: boolean;
  onOpenIncident?: (incidentId: string) => void;
  onVerifyEvents?: (req: VerifyEventRequest) => void;
  /** v0.12.9: open the FOCUSED attack relationship of THIS alert. */
  onOpenThreatMap?: (alert: AlertDoc) => void;
}) {
  const { toast } = useToast();
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<DgaSummary | null>(null);
  const [alerts, setAlerts] = useState<AlertDoc[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AlertDoc | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);

  const fetchPage = useCallback(async (p: number, s: number, h: number) => {
    setLoading(true);
    try {
      const since = new Date(Date.now() - h * 3600_000).toISOString();
      const res = await searchAlerts({
        alert_types: DGA_ALERT_TYPES,
        time_from: since,
        size: s,
        from: (p - 1) * s,
      });
      setAlerts(res.hits);
      setTotal(res.total);
      if (res.total > 0 && (p - 1) * s >= res.total) {
        const last = Math.max(1, Math.ceil(res.total / s));
        setPage(last);
        const again = await searchAlerts({
          alert_types: DGA_ALERT_TYPES, time_from: since,
          size: s, from: (last - 1) * s,
        });
        setAlerts(again.hits);
      }
    } catch (e) {
      toast({ title: "Failed to load DGA alerts", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const load = useCallback(async (h: number) => {
    try {
      setSummary(await getDgaSummary(h));
    } catch (e) {
      // the table below still works; the summary strip degrades honestly
      setSummary(null);
      toast({ title: "DGA summary unavailable", description: String(e), variant: "destructive" });
    }
  }, [toast]);

  useEffect(() => {
    void fetchPage(page, pageSize, hours);
    void load(hours);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hours, page, pageSize]);

  const handleAlertChanged = (updated: AlertDoc) => {
    setAlerts((prev) => prev.map((a) => (a.alert_id === updated.alert_id ? updated : a)));
    setSelected((prev) => (prev?.alert_id === updated.alert_id ? updated : prev));
  };

  // severity mix for the KPI sub-line (exact buckets from /stats)
  const [sevMix, setSevMix] = useState<{ key: string; count: number }[]>([]);
  useEffect(() => {
    const since = new Date(Date.now() - hours * 3600_000).toISOString();
    alertStats({ alert_types: DGA_ALERT_TYPES, time_from: since })
      .then((s) => setSevMix(s.severity))
      .catch(() => setSevMix([]));
  }, [hours]);

  const domains = useMemo(() => sampledDomains(alerts), [alerts]);
  const maxTimeline = Math.max(1, ...(summary?.timeline ?? []).map((t) => t.count));

  return (
    <div className="space-y-4">
      {/* v0.14.0: in-page refresh + selectable auto-refresh */}
      <div className="flex justify-end">
        <RefreshControls storageKey="dga" onRefresh={() => { void load(hours); }} loading={loading} />
      </div>
      {/* intro */}
      <div className="flex flex-wrap items-start gap-2 rounded-xl border border-zinc-800 bg-zinc-900/50 p-3 text-xs text-zinc-400">
        <Dna className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
        <p className="flex-1">
          Focused view for <span className="text-zinc-200">DGA-family detections</span>:
          <code className="mx-1 rounded bg-zinc-800 px-1">dga_suspected</code> (high-entropy unique-domain
          burst) and <code className="mx-1 rounded bg-zinc-800 px-1">dns_nxdomain_burst</code> (NXDOMAIN ratio burst).
          These are heuristics over DNS behaviour - CDN/BYOD apps and monitoring agents can look similar;
          every alert carries its sampled domains and raw-event refs so you can verify before acting.
        </p>
        <div className="flex gap-1">
          {WINDOW_OPTIONS.map((w) => (
            <button key={w.value}
                    onClick={() => { setHours(w.value); setPage(1); }}
                    className={cn("rounded-md border px-2.5 py-1 text-[11px] transition-colors",
                      hours === w.value
                        ? "ndr-gloss border-sky-600/60 font-medium text-sky-100"
                        : "border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:bg-zinc-800/60")}>
              {w.label}
            </button>
          ))}
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard title="DGA alerts" value={summary ? fmtNumber(summary.total) : "..."}
                  sub={sevMix.length
                    ? sevMix.slice(0, 3).map((s) => `${s.key}: ${s.count}`).join(" / ")
                    : "last " + (summary?.hours ?? hours) + "h"}
                  tone={summary && summary.total > 0 ? "alert" : "default"} />
        <StatCard title="Querying hosts" value={summary ? fmtNumber(summary.sources.length) : "..."}
                  sub={summary?.sources?.[0]
                    ? `top: ${summary.sources[0].key} (${fmtNumber(summary.sources[0].count)} events)`
                    : "no flagged source in window"}
                  tone="ok" />
        <StatCard title="Sampled domains" value={domains.length ? fmtNumber(domains.length) : "-"}
                  sub="recorded in alert evidence (this page)"
                  tone="default" />
        <StatCard title="Last alert" value={summary?.last_seen ? timeAgo(String(summary.last_seen)) : "-"}
                  sub={summary?.last_seen ? fmtTime(String(summary.last_seen)) : "no DGA-family alert in window"}
                  tone={summary?.last_seen ? "ok" : "default"} />
      </div>

      {/* hourly timeline (aggregation bucket from /dga/summary) */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3">
        <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          <Hourglass className="h-3 w-3" />
          Alert volume per {hours <= 48 ? "hour" : "day"} (window {hours}h)
          {summary?.relation === "gte" && (
            <Badge variant="outline" className="border-amber-900 text-[9px] text-amber-300">count capped at 10k</Badge>
          )}
        </div>
        {summary ? (
          <div className="flex h-16 items-end gap-1">
            {summary.timeline.map((t, i) => (
              <div key={i} className="group relative flex-1" title={`${t.ts} - ${t.count} alerts`}>
                <div className={cn("w-full rounded-t-sm transition-all",
                  t.count > 0 ? "bg-sky-500/70 group-hover:bg-sky-400" : "bg-zinc-800")}
                     style={{ height: `${Math.max(2, (t.count / maxTimeline) * 60)}px` }} />
              </div>
            ))}
          </div>
        ) : (
          <Skeleton className="h-16 bg-zinc-900" />
        )}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        {/* alert table */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500">Last seen</TableHead>
                <TableHead className="text-zinc-500">Severity</TableHead>
                <TableHead className="text-zinc-500">Detection</TableHead>
                <TableHead className="text-zinc-500">Source host</TableHead>
                <TableHead className="text-zinc-500">Protocol</TableHead>
                <TableHead className="text-zinc-500">Verdict</TableHead>
                <TableHead className="text-right text-zinc-500">Events</TableHead>
                <TableHead className="text-zinc-500">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i} className="border-zinc-800/60">
                    <TableCell colSpan={8}><Skeleton className="h-10 bg-zinc-900" /></TableCell>
                  </TableRow>
                ))
              ) : (
                <>
                  {alerts.map((a) => (
                    <TableRow key={a.alert_id}
                              className="cursor-pointer border-zinc-800/60 hover:bg-zinc-800/40"
                              onClick={() => setSelected(a)}>
                      <TableCell className="whitespace-nowrap text-xs text-zinc-300">
                        <div>{fmtTime(a.last_seen)}</div>
                        <div className="text-[10px] text-zinc-600">{timeAgo(a.last_seen)}</div>
                      </TableCell>
                      <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                      <TableCell className="max-w-[280px]">
                        <div className="truncate font-medium text-zinc-200" title={alertTitle(a.title)}>
                          {alertTitle(a.title)}
                        </div>
                        <div className="text-[10px] font-mono text-zinc-600">{a.alert_type}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-400">
                        {a.source?.ip ?? "-"}
                      </TableCell>
                      <TableCell>
                        <span className="rounded bg-zinc-800/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                          {protocolOf(a)}
                        </span>
                      </TableCell>
                      <TableCell><OutcomeBadge outcome={a.outcome} /></TableCell>
                      <TableCell className="text-right tabular-nums text-zinc-300">{fmtNumber(a.event_count)}</TableCell>
                      <TableCell><StatusBadge status={a.status} /></TableCell>
                    </TableRow>
                  ))}
                  {!alerts.length && (
                    <TableRow className="border-zinc-800/60">
                      <TableCell colSpan={8} className="py-10 text-center text-sm text-zinc-500">
                        No DGA-family alerts in this window - nothing to triage
                      </TableCell>
                    </TableRow>
                  )}
                </>
              )}
            </TableBody>
          </Table>
          <Paginator page={page} pageSize={pageSize} total={total}
                     onPage={(p) => setPage(p)}
                     onPageSize={(s) => { setPageSize(s); setPage(1); }} />
        </div>

        {/* side panels */}
        <div className="space-y-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              <Users className="h-3 w-3" /> Top querying hosts (alert events)
            </div>
            {summary?.sources?.length ? (
              <div className="space-y-1.5">
                {summary.sources.map((s) => (
                  <button key={s.key}
                          onClick={() => {
                            const hit = alerts.find((a) => a.source?.ip === s.key);
                            if (hit) setSelected(hit);
                          }}
                          className="flex w-full items-center justify-between rounded-md border border-zinc-800 bg-zinc-950/60 px-2.5 py-1.5 text-left text-xs hover:border-zinc-700">
                    <span className="font-mono text-zinc-300">{s.key}</span>
                    <span className="tabular-nums text-zinc-500">{fmtNumber(s.count)}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-xs text-zinc-600">No flagged source in this window.</p>
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              <Globe2 className="h-3 w-3" /> Sampled flagged domains
            </div>
            <p className="mb-2 text-[10px] leading-relaxed text-zinc-600">
              Domains the detector recorded inside the alert evidence currently on this
              page - a sample, not the full query list. Open an alert for its complete
              rationale and raw-event refs.
            </p>
            {domains.length ? (
              <div className="space-y-1">
                {domains.map((d) => (
                  <div key={d.domain}
                       className="flex items-center justify-between rounded bg-zinc-950/70 px-2 py-1.5">
                    <span className="truncate font-mono text-[11px] text-zinc-300" title={d.domain}>
                      {d.domain}
                    </span>
                    <span className="ml-2 shrink-0 text-[10px] text-zinc-600">x{d.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-zinc-600">No sampled domains on this page.</p>
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3 text-[11px] leading-relaxed text-zinc-500">
            <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              <ShieldQuestion className="h-3 w-3" /> How to act on this page
            </div>
            Open an alert to see its recorded rationale, sample domains and trigger
            events; use <span className="text-zinc-300">Verify in Event Search</span> to
            re-check the raw DNS events, and escalate to an incident only when the
            evidence supports it. DGA alerts are candidates, not verdicts.
          </div>

          {/* v0.12.9: honest mechanism + references panel (user request:
              check internet references for DGA detection design) */}
          <details className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3">
            <summary className="flex cursor-pointer select-none items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              <BookOpenCheck className="h-3 w-3" /> How this detection works
              <ChevronDown className="ml-auto h-3 w-3" />
            </summary>
            <div className="mt-2 space-y-2.5 text-[11px] leading-relaxed text-zinc-400">
              <p>
                <span className="text-zinc-200">Mechanism (dga_suspected):</span>{" "}
                per source host, in a 10-minute window, the detector counts unique
                queried domains and computes Shannon entropy of the LONGEST
                non-TLD label per domain. Alert fires at &ge;10 unique
                non-allowlisted domains with mean label entropy &ge;3.5
                (tune: <code className="rounded bg-zinc-800 px-1">DETECT_DGA_MIN_UNIQUE</code>,{" "}
                <code className="rounded bg-zinc-800 px-1">DETECT_DGA_ENTROPY_MIN</code>).
              </p>
              <p>
                <span className="text-zinc-200">False-positive control:</span> popular
                and CDN domains (google.com, cloudfront.net, dsb - built-in list,
                extend via <code className="rounded bg-zinc-800 px-1">DETECT_DGA_ALLOWLIST</code>)
                are excluded from the count and reported transparently in the alert
                reasons - the standard allowlist practice used by Splunk/Elastic DGA
                analytics to cut CDN-driven FPs.
              </p>
              <p>
                <span className="text-zinc-200">Where this sits in the literature:</span>{" "}
                entropy scoring is the classic first-pass detector (Wong 2023,
                arXiv:2304.07943); stronger approaches add n-gram/lexical features
                (Notos/Kopis, USENIX 2010-2011), char-level deep learning (Woodbridge
                dkk. 2016, arXiv:1611.00791 - the basis of the Elastic DGA ML
                integration) and NXDOMAIN-rate behaviour (CERT.pl 2015 - implemented
                here as <code className="rounded bg-zinc-800 px-1">dns_nxdomain_burst</code>,
                the weak-signal companion). Tranco-list allowlists (NDSS 2019) are
                the de-facto FP filter.
              </p>
              <p className="text-amber-300/80">
                <span className="font-semibold">Known limits:</span> dictionary-based
                DGAs (Gozi/Matsnu class) keep entropy low and pass under this
                threshold; attackers can deliberately lower entropy. Combine with
                NXDOMAIN bursts, IOC matches and event verification before acting.
              </p>
            </div>
          </details>
        </div>
      </div>

      <AlertDetailSheet alert={selected} canEdit={canEdit}
                   canApproveWhitelist={canApproveWhitelist}
                        onClose={() => setSelected(null)}
                        onAlertChanged={handleAlertChanged}
                        onOpenThreatMap={onOpenThreatMap}
                        onOpenIncident={onOpenIncident}
                        onVerifyEvents={onVerifyEvents} />
    </div>
  );
}
