"use client";

// Alert Center - triage workbench with analytics header, scatter timeline,
// MITRE mapping, attack-result verdicts and a full detail sheet.
//
// v0.10 additions (all presentation-only; detection semantics unchanged):
//   - Time range filter (today / 24h / 7d / 14d / 30d / all / custom)
//   - Verdict column: attack-result taxonomy (alert.outcome, determined
//     at detection time - see the determination note in the detail sheet)
//   - Protocol column (L7 protocol, falling back to transport)
//   - Timestamps: absolute first/last seen (hover = full precision)
//   - Per-alert actions: escalate to incident, open in Threat Map
//   - Asset-name enrichment: source/destination show the registered
//     or discovered hostname under the IP
//   - Client-side pagination over the filtered result set

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { RefreshControls } from "./refresh-controls";
import { AlertScatter, DonutChart, SEV_COLORS, StatusFunnel, VizPanel } from "./charts";
import {
  DEFAULT_TIME_RANGE, OutcomeBadge, Paginator, SeverityBadge, StatusBadge,
  TimeRangePicker, alertTitle, fmtNumber, fmtTime, resolveTimeRange, timeAgo,
} from "./shared";
import type { TimeRange } from "./shared";
import {
  ChevronRight, Filter, Loader2, Search, Swords, Timer, Waypoints, Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { alertStats, escalateAlert, searchAlerts } from "@/lib/ndr/api";
import type { AlertDoc, AlertStats } from "@/lib/ndr/types";
import { AlertDetailSheet, protocolOf } from "./alert-detail";
import type { VerifyEventRequest } from "./alert-detail";
import { cn } from "@/lib/utils";

const OUTCOME_FILTERS = [
  { value: "all", label: "All verdicts" },
  { value: "attempted", label: "Attempted" },
  { value: "suspected_success", label: "Suspected success" },
  { value: "strong_success", label: "Strong success" },
  { value: "indeterminate", label: "Indeterminate" },
];

export function AlertsView({ canEdit, onOpenThreatMap, onOpenIncident, onVerifyEvents, canApproveWhitelist }: {
  canEdit: boolean;
  /** v0.14.0: whitelist self-approve (admin/security_engineer). */
  canApproveWhitelist?: boolean;
  /** v0.12.9: open the FOCUSED attack relationship of THIS alert (not the
   * global/geographic map) in the Threat Map view. */
  onOpenThreatMap?: (alert: AlertDoc) => void;
  /** v0.12.8: jump into Incidents focused on a linked incident. */
  onOpenIncident?: (incidentId: string) => void;
  /** v0.12.8: re-verify an alert against raw events in Event Search. */
  onVerifyEvents?: (req: VerifyEventRequest) => void;
}) {
  const { toast } = useToast();
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const [keyword, setKeyword] = useState("");
  const [timeRange, setTimeRange] = useState<TimeRange>(DEFAULT_TIME_RANGE);
  const [loading, setLoading] = useState(true);
  // v0.14.0: show whitelist-suppressed (L1) alerts in the queue
  const [showSuppressed, setShowSuppressed] = useState(false);
  // v0.12.7: REAL server-side pagination. `alerts` holds only the CURRENT
  // page (the backend caps each response at 500 rows); `stats` carries
  // EXACT severity/status/verdict buckets from the /stats aggregation
  // endpoint (same guarded filter, any result size); `sample` is the
  // newest-500 window ONLY for the scatter bubbles + MITRE tags; `total`
  // comes from the server so paging walks the FULL result set, not just
  // the first 500 rows (the old client-side pagination silently hid
  // everything past row 500).
  const [alerts, setAlerts] = useState<AlertDoc[]>([]);
  const [sample, setSample] = useState<AlertDoc[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<AlertDoc | null>(null);

  // pagination (server-driven)
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // escalation dialog
  const [escTarget, setEscTarget] = useState<AlertDoc | null>(null);
  const [escReason, setEscReason] = useState("");
  const [escBusy, setEscBusy] = useState(false);

  // shared filter bundle (server applies severity/status/verdict/
  // keyword/time - demo mode mirrors it client-side)
  const buildFilters = (size: number, from: number) => {
    const w = resolveTimeRange(timeRange);
    return {
      severity, status, keyword, outcome,
      size, from,
      time_from: w.from ?? undefined,
      time_to: w.to ?? undefined,
      // v0.14.0: whitelist-suppressed (L1) alerts opt-in
      show_suppressed: showSuppressed,
    };
  };

  // analytics windows: exact buckets from the /stats aggregation + a
  // newest-500 sample for the scatter bubbles and MITRE tag cloud
  const loadAnalytics = async () => {
    const f = buildFilters(500, 0);
    // exact buckets - must not fail the page when the agg route hiccups;
    // the UI falls back to the sample window in that case
    alertStats({
      severity: f.severity, status: f.status, keyword: f.keyword,
      outcome: f.outcome, time_from: f.time_from, time_to: f.time_to,
    }).then(setStats).catch(() => {});
    try {
      const res = await searchAlerts(f);
      setSample(res.hits);
      setTotal(res.total);
    } catch {
      // page fetch surfaces backend errors; analytics is best-effort
    }
  };

  // fetch one table page explicitly (p = 1-based page, s = page size)
  const fetchPage = async (p: number, s: number) => {
    setLoading(true);
    try {
      const res = await searchAlerts(buildFilters(s, (p - 1) * s));
      setAlerts(res.hits);
      setTotal(res.total);
      // result set shrank under us - snap back to the last valid page
      if (res.total > 0 && (p - 1) * s >= res.total) {
        const last = Math.max(1, Math.ceil(res.total / s));
        setPage(last);
        const again = await searchAlerts(buildFilters(s, (last - 1) * s));
        setAlerts(again.hits);
      }
    } catch (e) {
      toast({ title: "Failed to load alerts", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  // filter change / Apply button: reset to page 1 + refresh both windows
  const load = () => {
    setPage(1);
    void fetchPage(1, pageSize);
    void loadAnalytics();
  };

  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [severity, status, outcome, timeRange]);
  // v0.14.0: "Show suppressed" toggles the whitelist filter
  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [showSuppressed]);

  // v0.12.8: status/notes updates live inside AlertDetailSheet; the
  // updated document is synced back into the list states here.
  const handleAlertChanged = (updated: AlertDoc) => {
    setAlerts((prev) => prev.map((a) => (a.alert_id === updated.alert_id ? updated : a)));
    setSample((prev) => prev.map((a) => (a.alert_id === updated.alert_id ? updated : a)));
    setSelected((prev) => (prev?.alert_id === updated.alert_id ? updated : prev));
  };

  async function submitEscalate() {
    if (!escTarget) return;
    setEscBusy(true);
    try {
      const res = await escalateAlert(escTarget.alert_id, escReason.trim() || undefined);
      toast({
        title: "Alert escalated to incident",
        description: `${res.incident_id} created - open Incidents to triage it.`,
      });
      setEscTarget(null);
      setEscReason("");
    } catch (e) {
      toast({ title: "Escalation failed", description: String(e), variant: "destructive" });
    } finally {
      setEscBusy(false);
    }
  }

  // v0.12.7: severity/status/verdict counts come from the EXACT /stats
  // buckets (any result size); the sample window only feeds the scatter
  // bubbles and the MITRE tag cloud
  const analytics = useMemo(() => {
    const bucket = (bs: { key: string; count: number }[]) =>
      new Map(bs.map((b) => [b.key, b.count]));
    const sevMap = stats ? bucket(stats.severity) : null;
    const statusMap = stats ? bucket(stats.status) : null;
    const bySev = ["critical", "high", "medium", "low", "informational"]
      .map((k) => ({
        name: k,
        value: sevMap ? (sevMap.get(k) ?? 0)
          : sample.filter((a) => a.severity === k).length,
        color: SEV_COLORS[k],
      }))
      .filter((s) => s.value > 0);
    const byStatus = ["new", "acknowledged", "in_progress", "closed", "false_positive"]
      .map((k) => ({
        key: k,
        count: statusMap ? (statusMap.get(k) ?? 0)
          : sample.filter((a) => a.status === k).length,
      }));
    const scatter = sample.map((a) => ({
      ts: +new Date(a.last_seen), severity: a.severity, risk: a.risk_score ?? a.severity_score ?? 30, title: alertTitle(a.title),
    }));
    const mitreTags = new Map<string, number>();
    sample.forEach((a) => a.mitre?.forEach((m) => {
      const key = `${m.technique_id} ${m.technique}`;
      mitreTags.set(key, (mitreTags.get(key) ?? 0) + 1);
    }));
    return {
      bySev, byStatus, scatter,
      topMitre: Array.from(mitreTags.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6),
      newCount: statusMap ? (statusMap.get("new") ?? 0)
        : sample.filter((a) => a.status === "new").length,
      criticalCount: sevMap ? (sevMap.get("critical") ?? 0)
        : sample.filter((a) => a.severity === "critical").length,
    };
  }, [sample, stats]);

  return (
    <div className="space-y-4">
      {/* v0.14.0: in-page refresh + selectable auto-refresh */}
      <div className="flex justify-end">
        <RefreshControls storageKey="alerts" onRefresh={() => { setPage(1); void fetchPage(1, pageSize); void loadAnalytics(); }} loading={loading} />
      </div>
      {/* v0.14.0: whitelist-suppressed alerts opt-in */}
      <div className="flex items-center justify-end gap-2 text-[11px] text-zinc-400">
        <label className="flex cursor-pointer items-center gap-1.5">
          <input type="checkbox" checked={showSuppressed}
                 onChange={(e) => setShowSuppressed(e.target.checked)}
                 className="h-3.5 w-3.5 accent-sky-500" />
          Show suppressed (whitelist)
        </label>
      </div>
            {/* analytics header */}
      <div className="grid gap-4 lg:grid-cols-4">
        <VizPanel title="Severity mix" sub={`${fmtNumber(total)} alerts in range`}>
          {analytics.bySev.length
            ? <DonutChart data={analytics.bySev} centerValue={fmtNumber(total)} centerLabel="alerts" height={150} />
            : <p className="py-10 text-center text-xs text-zinc-600">No alerts match filters</p>}
        </VizPanel>
        <VizPanel title="Triage funnel" sub="status distribution">
          <StatusFunnel data={analytics.byStatus} />
        </VizPanel>
        <VizPanel className="lg:col-span-2" title="Alert timeline" sub="bubble size = risk score - newest 500 sample window">
          {analytics.scatter.length
            ? <AlertScatter data={analytics.scatter} height={170} />
            : <p className="py-10 text-center text-xs text-zinc-600">No data</p>}
        </VizPanel>
      </div>

      {/* MITRE strip */}
      {!!analytics.topMitre.length && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3">
          <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            <Swords className="h-3.5 w-3.5" /> ATT&CK techniques in range
          </span>
          {analytics.topMitre.map(([tag, n]) => (
            <Badge key={tag} variant="outline" className="border-violet-900/70 bg-violet-950/30 text-[10px] text-violet-300">
              {tag} <span className="ml-1 text-violet-500">x{n}</span>
            </Badge>
          ))}
          {analytics.criticalCount > 0 && (
            <Badge variant="outline" className="ml-auto border-red-900 bg-red-950/40 text-red-300">
              <Timer className="mr-1 h-3 w-3" /> {analytics.criticalCount} critical need triage
            </Badge>
          )}
        </div>
      )}

      {/* filters */}
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
          <Input placeholder="Search title, source or destination IP..." value={keyword}
                 onChange={(e) => setKeyword(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && load()}
                 className="border-zinc-800 bg-zinc-900 pl-8 text-zinc-200 placeholder:text-zinc-600" />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-full md:w-40 border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectItem value="all">All severities</SelectItem>
            {["critical", "high", "medium", "low"].map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-full md:w-44 border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectItem value="all">All statuses</SelectItem>
            {["new", "acknowledged", "in_progress", "closed", "false_positive"].map((s) => (
              <SelectItem key={s} value={s}>{s.replace("_", " ")}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={outcome} onValueChange={setOutcome}>
          <SelectTrigger className="w-full md:w-44 border-zinc-800 bg-zinc-900 text-zinc-300"
                         title="Attack-result verdict (alert.outcome)">
            <SelectValue placeholder="Verdict" />
          </SelectTrigger>
          <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
            {OUTCOME_FILTERS.map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <TimeRangePicker value={timeRange} onChange={setTimeRange} />
        <Button onClick={load} variant="outline"
                className="border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800">
          <Filter className="mr-1.5 h-4 w-4" /> Apply
        </Button>
      </div>

      <div className="flex flex-wrap gap-2 text-xs text-zinc-500">
        <Badge variant="outline" className="border-sky-900 bg-sky-950/60 text-sky-300"
               title="Server-side count over the FULL filtered result set - pagination walks every page, not just the first 500 rows">
          {fmtNumber(total)} matches (server-side)
        </Badge>
        <Badge variant="outline" className="border-zinc-700 text-zinc-400">{analytics.newCount} new</Badge>
        <Badge variant="outline" className="border-red-900 bg-red-950/60 text-red-300">{analytics.criticalCount} critical</Badge>
      </div>

      {/* table */}
      {loading ? (
        <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-14 bg-zinc-900" />)}</div>
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500">Last seen</TableHead>
                <TableHead className="text-zinc-500">Severity</TableHead>
                <TableHead className="text-zinc-500">Title</TableHead>
                <TableHead className="text-zinc-500">Source</TableHead>
                <TableHead className="text-zinc-500">Destination</TableHead>
                <TableHead className="text-zinc-500"
                           title="Layer-7 protocol when identified by the pipeline, otherwise the transport (TCP/UDP)">
                  Protocol
                </TableHead>
                <TableHead className="text-zinc-500"
                           title="Attack-result verdict determined by the pipeline at detection time">
                  Verdict
                </TableHead>
                <TableHead className="text-right text-zinc-500"
                           title="Frequency: number of underlying events aggregated into this alert (event_count)">
                  Frequency
                </TableHead>
                <TableHead className="text-zinc-500">Status</TableHead>
                <TableHead className="w-28 text-right text-zinc-500">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.map((a) => (
                <TableRow key={a.alert_id}
                          className="cursor-pointer border-zinc-800/60 hover:bg-zinc-800/40"
                          onClick={() => setSelected(a)}>
                  <TableCell className="whitespace-nowrap text-xs text-zinc-300"
                             title={`first seen: ${fmtTime(a.first_seen)}`}>
                    <div>{fmtTime(a.last_seen)}</div>
                    <div className="text-[10px] text-zinc-600">{timeAgo(a.last_seen)}</div>
                  </TableCell>
                  <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                  <TableCell className="max-w-[300px]">
                    <div className="truncate font-medium text-zinc-200"
                         title={`${alertTitle(a.title)} - the title mirrors the detection rule message verbatim (e.g. "Attempt" is part of the Suricata signature name, not our verdict)`}>
                      {alertTitle(a.title)}
                      {(a as AlertDoc).suppressed && (
                        <span
                          className="ml-1.5 inline-flex items-center rounded border border-sky-900 bg-sky-950/40 px-1 py-0.5 align-middle text-[9px] uppercase tracking-wide text-sky-400"
                          title={"whitelisted (entry #" + String((a as AlertDoc).suppressed_by ?? "?") + ")"}
                        >
                          suppressed
                        </span>
                      )}
                    </div>
                    {!!a.mitre?.length && (
                      <div className="mt-0.5 flex gap-1">
                        {a.mitre.slice(0, 2).map((m) => (
                          <span key={m.technique_id} className="rounded bg-violet-950/50 px-1 text-[9px] text-violet-400">{m.technique_id}</span>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-400">
                    {a.source?.ip ?? "-"}
                    {a.source_asset_name && (
                      <div className="font-sans text-[10px] text-emerald-400/80">{a.source_asset_name}</div>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-400">
                    {a.destination?.ip ?? "-"}
                    {a.destination_asset_name && (
                      <div className="font-sans text-[10px] text-emerald-400/80">{a.destination_asset_name}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="rounded bg-zinc-800/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                      {protocolOf(a)}
                    </span>
                  </TableCell>
                  <TableCell><OutcomeBadge outcome={a.outcome} /></TableCell>
                  <TableCell className="text-right tabular-nums text-zinc-300">{fmtNumber(a.event_count)}</TableCell>
                  <TableCell><StatusBadge status={a.status} /></TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                      <button
                        title="Open the focused attack relationship for this alert (its incident chain, or what this alert alone proves)"
                        className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-emerald-700 hover:text-emerald-300"
                        onClick={() => { if (onOpenThreatMap) onOpenThreatMap(a); }}>
                        <Waypoints className="h-3.5 w-3.5" />
                      </button>
                      {canEdit && (
                        <button
                          title="Escalate to incident (manually raise this alert as a new incident)"
                          className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-amber-600 hover:text-amber-300"
                          onClick={() => { setEscTarget(a); setEscReason(""); }}>
                          <Zap className="h-3.5 w-3.5" />
                        </button>
                      )}
                      <ChevronRight className="h-4 w-4 text-zinc-600" />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {!alerts.length && (
                <TableRow className="border-zinc-800/60">
                  <TableCell colSpan={10} className="py-10 text-center text-sm text-zinc-500">
                    No alerts match the current filters
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <Paginator page={page} pageSize={pageSize} total={total}
                     onPage={(p) => { setPage(p); void fetchPage(p, pageSize); }}
                     onPageSize={(s) => { setPageSize(s); setPage(1); void fetchPage(1, s); }} />
        </div>
      )}

      {/* escalation dialog */}
      <Dialog open={!!escTarget} onOpenChange={(open) => !open && setEscTarget(null)}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">Escalate to incident</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 text-sm">
            <p className="text-xs text-zinc-500">
              Raises <span className="text-zinc-300">{escTarget ? alertTitle(escTarget.title) : ""}</span> as a
              NEW open incident. It starts with exactly this alert&apos;s entities and
              evidence - no relations are invented; if the correlation engine later finds
              linked evidence, the incidents are merged automatically.
            </p>
            <Textarea value={escReason} onChange={(e) => setEscReason(e.target.value)}
                      placeholder="Why are you escalating? (recorded in incident history + audit log)"
                      className="min-h-20 border-zinc-800 bg-zinc-900 text-sm" />
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEscTarget(null)} className="text-zinc-400">Cancel</Button>
            <Button onClick={submitEscalate} disabled={escBusy}
                    className="bg-amber-600 text-white hover:bg-amber-500">
              {escBusy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
              Escalate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* v0.12.8: detail sheet extracted to alert-detail.tsx so the
          Alert Center and the DGA Activity menu share one workflow
          (verdicts, correlation linkage, evidence, PCAP, notes). */}
      <AlertDetailSheet alert={selected} canEdit={canEdit}
                   canApproveWhitelist={canApproveWhitelist} onClose={() => setSelected(null)}
                        onAlertChanged={handleAlertChanged}
                        onOpenThreatMap={onOpenThreatMap}
                        onOpenIncident={onOpenIncident}
                        onVerifyEvents={onVerifyEvents}
                        onEscalate={(a) => { setEscTarget(a); setEscReason(""); }} />
    </div>
  );
}
