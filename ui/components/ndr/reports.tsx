"use client";

// Reports - weekly executive summary with detection quality metrics.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DonutChart, HBarList, MiniBar, MttrChart, SEV_COLORS, SeverityStackedArea, VizPanel } from "./charts";
import { HostRiskBadge } from "./geo";
import { fmtNumber } from "./shared";
import { Download, FileBarChart } from "lucide-react";
import type { RichOverview } from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

export function ReportsView({ rich }: { rich: RichOverview | null }) {
  if (!rich) {
    return <p className="py-20 text-center text-sm text-zinc-500">Report data unavailable</p>;
  }

  // v0.16.2 (BUG-0161-02): KPI Reports kini membaca angka NYATA dari
  // /api/stats/overview (alerts_7d, events_7d, mttr_hours_avg, closed_7d).
  // Dulu menjumlah timeline.alerts_* (tidak pernah dikirim backend ->
  // hardcode 0) dan timeline.zeek+suricata (24h + engines kosong) sehingga
  // SEMUA kartu Reports menampilkan 0 meski data ada.
  const total7d = rich.stats.alerts_7d
    ?? rich.timeline.reduce((s, t) => s + t.alerts_critical + t.alerts_high + t.alerts_medium + t.alerts_low, 0);
  const events7d = rich.stats.events_7d
    ?? rich.timeline.reduce((s, t) => s + (t.count ?? t.zeek + t.suricata), 0);
  const closed = rich.stats.alerts_by_status?.find((s) => s.key === "closed")?.count ?? 0;
  // MTTR: rata-rata tertimbang dari backend; fallback hitung lokal.
  const avgMttr = rich.stats.mttr_hours_avg
    ?? (rich.mttr.length
      ? rich.mttr.reduce((s, m) => s + m.mttr_hours * m.closed, 0)
        / (rich.mttr.reduce((s, m) => s + m.closed, 0) || 1)
      : 0);
  const closedTotal = rich.stats.closed_7d
    ?? rich.mttr.reduce((s, m) => s + m.closed, 0);
  const topHosts = [...rich.hosts].sort((a, b) => b.risk_score - a.risk_score).slice(0, 8);
  const worstTechnique = (rich.rule_stats ?? []).slice().sort((a, b) => b.fired_7d - a.fired_7d)[0];
  const period = `${new Date(Date.now() - 6 * 864e5).toLocaleDateString("en-GB", { day: "2-digit", month: "short" })} - ${new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}`;

  return (
    <div className="space-y-4" id="weekly-report">
      {/* header */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-emerald-900 bg-emerald-950/50 p-2.5 text-emerald-400">
            <FileBarChart className="h-5 w-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-zinc-100">Weekly Detection Report</div>
            <div className="text-xs text-zinc-500">Period {period} - generated {new Date().toLocaleString("en-GB")} - sensor {rich.health.pipeline.sensor_id ?? "n/a"}</div>
          </div>
        </div>
        <Button variant="outline" onClick={() => window.print()}
                className="border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800">
          <Download className="mr-1.5 h-4 w-4" /> Print / PDF
        </Button>
      </div>

      {/* executive KPIs */}
      <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Alerts (7d)" value={fmtNumber(total7d)} />
        <Kpi label="Events processed" value={fmtNumber(events7d)} />
        <Kpi label="Closed / FP" value={`${closed} / ${rich.stats.alerts_by_status?.find((s) => s.key === "false_positive")?.count ?? 0}`} />
        <Kpi label="Avg MTTR" value={`${avgMttr.toFixed(1)}h`} tone="ok" />
        <Kpi label="Avg MTTA" value={`${rich.mean_time_to_ack_min}m`} tone="ok" />
        <Kpi label="Busiest rule" value={worstTechnique?.name.split(" (")[0] ?? "-"} small />
      </div>

      {/* narrative summary */}
      <VizPanel title="Executive summary" icon={<FileBarChart className="h-4 w-4 text-emerald-400" />}>
        <div className="space-y-2 text-sm leading-relaxed text-zinc-300">
          <p>
            During the reporting period the platform processed <b className="text-zinc-100">{fmtNumber(events7d)}</b> normalized events
            from {rich.hosts.length} monitored hosts and produced <b className="text-zinc-100">{fmtNumber(total7d)}</b> heuristic detections.
            SOC triaged {fmtNumber(closedTotal)} alerts to closure with an average time-to-acknowledge of{" "}
            <b className="text-zinc-100">{rich.mean_time_to_ack_min} minutes</b> and average time-to-resolve of{" "}
            <b className="text-zinc-100">{avgMttr.toFixed(1)} hours</b>.
          </p>
          <p>
            The most active detection was <b className="text-zinc-100">{worstTechnique?.name}</b> ({fmtNumber(worstTechnique?.fired_7d ?? 0)} firings,
            estimated false-positive share {worstTechnique?.est_false_positive ?? 0}%). The highest-risk asset is{" "}
            <b className="text-zinc-100">{topHosts[0]?.hostname}</b> (risk {topHosts[0]?.risk_score}) with recurring web-attack
            evidence from external sources. Confirmed-malicious endpoints observed:{" "}
            <b className="text-red-300">{rich.externals.filter((e) => e.reputation === "malicious").length}</b>;
            suspicious: <b className="text-amber-300">{rich.externals.filter((e) => e.reputation === "suspicious").length}</b>.
          </p>
          <p className="text-xs text-zinc-500">
            Method note: severities and risk scores are heuristic and uncalibrated. Findings indicate observed activity worth review,
            not proven compromise. All detections retain raw-event evidence with SHA-256 references for retrospective validation.
          </p>
        </div>
      </VizPanel>

      {/* charts */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel className="lg:col-span-2" title="Detection volume - 7 days" sub="alerts per day, stacked by severity">
          <SeverityStackedArea data={rich.alert_daily} height={200} />
        </VizPanel>
        <VizPanel title="Resolution trend" sub="mean hours to resolve, daily">
          <MttrChart data={rich.mttr} height={200} />
        </VizPanel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel title="Detection rule performance" sub="fired vs estimated FP share">
          <div className="space-y-4">
            {(rich.rule_stats ?? []).map((r) => (
              <div key={r.rule}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 text-zinc-300">
                    {r.name}
                    <Badge variant="outline" className={cn("text-[9px]",
                      r.status === "enabled" ? "border-emerald-900 text-emerald-400" : "border-amber-900 text-amber-400")}>
                      {r.status}
                    </Badge>
                  </span>
                  <span className="tabular-nums text-zinc-400">{fmtNumber(r.fired_7d)} firings</span>
                </div>
                <MiniBar value={r.avg_confidence * 100} max={100} color="#38bdf8" />
                <div className="mt-1 flex justify-between text-[10px] text-zinc-600">
                  <span>avg confidence {(r.avg_confidence * 100).toFixed(0)}%</span>
                  <span>est. FP {r.est_false_positive}%</span>
                </div>
              </div>
            ))}
          </div>
        </VizPanel>

        <VizPanel title="Top risk assets" sub="heuristic asset scores">
          <div className="space-y-2">
            {topHosts.map((h) => (
              <div key={h.ip} className="flex items-center gap-2 rounded-md border border-zinc-800/70 bg-zinc-900/40 px-2.5 py-1.5">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-mono text-xs text-zinc-200">{h.hostname}</span>
                    <HostRiskBadge score={h.risk_score} />
                  </div>
                  <div className="truncate text-[10px] text-zinc-600">{h.zone} - {h.alerts_24h} alerts 24h</div>
                </div>
              </div>
            ))}
          </div>
        </VizPanel>

        <VizPanel title="External exposure" sub="unique external endpoints by reputation">
          <DonutChart
            data={[
              { name: "clean", value: rich.externals.filter((e) => e.reputation === "clean").length, color: "#38bdf8" },
              { name: "suspicious", value: rich.externals.filter((e) => e.reputation === "suspicious").length, color: "#fbbf24" },
              { name: "malicious", value: rich.externals.filter((e) => e.reputation === "malicious").length, color: "#f87171" },
            ]}
            centerValue={String(rich.externals.length)} centerLabel="endpoints" height={160} />
          <div className="mt-3">
            <HBarList items={rich.top_external_dests.slice(0, 4)} color="#60a5fa" valueFmt={fmtNumber} subFmt={(i) => i.meta ?? ""} />
          </div>
        </VizPanel>
      </div>

      <p className="text-center text-[11px] text-zinc-600">
        This report is generated from pipeline metrics and detection output. For incident-grade conclusions, corroborate with PCAP evidence via Arkime and host telemetry.
      </p>
    </div>
  );
}

function Kpi({ label, value, tone, small }: { label: string; value: string; tone?: "ok"; small?: boolean }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={cn("mt-0.5 font-semibold tabular-nums text-zinc-100",
        small ? "truncate text-sm" : "text-xl", tone === "ok" && "text-emerald-300")}>
        {value}
      </div>
    </div>
  );
}
