"use client";

// Overview - flagship SOC dashboard with live tickers and rich visuals.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { allowlistSummary } from "@/lib/ndr/api";
import type { AllowSummary } from "@/lib/ndr/types";
import {
  AlertHeatmap, DonutChart, EpsLiveChart, HBarList, ProtocolDonut, RingGauge,
  RuleRadar, SEV_COLORS, SeverityStackedArea, Sparkline, TrafficTimeline, VizPanel,
} from "./charts";
import { HostRiskBadge } from "./geo";
import { fmtBytes, fmtNumber, fmtTime, timeAgo } from "./shared";
import {
  Activity, ArrowDownRight, ArrowUpRight, BellRing, Cpu, Database, Gauge,
  Globe2, Network, Radio, Server, ShieldAlert, Zap,
  AlertTriangle,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { LiveTrafficWidget } from "./live-traffic";
import { DEMO_MODE, demoNewFeedItem, demoTickEps } from "@/lib/ndr/api";
import type { FeedEvent, RichOverview } from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

// ----------------------------------------------------------------- KPI card
function Kpi({ title, value, sub, icon, tone, spark, sparkColor, delta }: {
  title: string;
  value: string;
  sub?: string;
  icon: React.ReactNode;
  tone?: "default" | "alert" | "ok" | "warn";
  spark?: number[];
  sparkColor?: string;
  delta?: number | null;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60 p-3.5">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-zinc-500">
            <span className="text-zinc-600">{icon}</span>{title}
          </div>
          <div className={cn(
            "mt-1.5 text-2xl font-semibold tabular-nums tracking-tight",
            tone === "alert" ? "text-red-300" : tone === "warn" ? "text-amber-300" : tone === "ok" ? "text-emerald-300" : "text-zinc-100"
          )}>
            {value}
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-zinc-500">
            {delta != null && (
              <span className={cn("flex items-center gap-0.5 font-medium",
                delta > 0 ? "text-red-400" : delta < 0 ? "text-emerald-400" : "text-zinc-500")}>
                {delta > 0 ? <ArrowUpRight className="h-3 w-3" /> : delta < 0 ? <ArrowDownRight className="h-3 w-3" /> : null}
                {Math.abs(delta)}%
              </span>
            )}
            {sub && <span className="truncate">{sub}</span>}
          </div>
        </div>
      </div>
      {spark && (
        <div className="pointer-events-none absolute inset-x-0 bottom-0 opacity-70">
          <Sparkline data={spark} color={sparkColor ?? "#38bdf8"} height={30} />
        </div>
      )}
    </div>
  );
}

// ----------------------------------------------------------------- live feed item
function FeedRow({ item }: { item: FeedEvent }) {
  return (
    <div className={cn(
      "flex items-center gap-2.5 rounded-md border px-2.5 py-1.5 text-xs",
      item.flagged ? "border-red-900/50 bg-red-950/20" : "border-zinc-800/70 bg-zinc-900/40"
    )}>
      <span className="shrink-0 font-mono text-[10px] text-zinc-500">
        {new Date(item.ts).toLocaleTimeString("en-GB", { hour12: false })}
      </span>
      <Badge variant="outline" className={cn(
        "shrink-0 border text-[9px] uppercase",
        item.engine === "zeek" ? "border-emerald-900 text-emerald-400"
          : item.engine === "suricata" ? "border-sky-900 text-sky-400" : "border-violet-900 text-violet-400"
      )}>
        {item.engine}
      </Badge>
      <span className="min-w-0 flex-1 truncate font-mono text-zinc-300">{item.summary}</span>
      {item.flagged && <ShieldAlert className="h-3.5 w-3.5 shrink-0 animate-pulse text-red-400" />}
    </div>
  );
}

// ----------------------------------------------------------------- main view
type LiveState = {
  src: RichOverview | null;
  eps: number | null;
  series: { ts: string; eps: number }[];
  feed: FeedEvent[];
};

export function OverviewView({ rich, loading, onOpenAlerts, loadError, onRetry }: {
  rich: RichOverview | null;
  loading: boolean;
  onOpenAlerts?: () => void;
  /** v0.14.0: honest load-failure state (the old UI silently showed empty
   * cards when the API was unreachable). */
  loadError?: string | null;
  onRetry?: () => void;
}) {
  const [live, setLive] = useState<LiveState>({ src: null, eps: null, series: [], feed: [] });
  const tickRef = useRef(0);
  const allowSummaryRef = useRef<() => void>(() => undefined);
  // v0.14.0: whitelist impact card (transparency requirement)
  const [allow, setAllow] = useState<AllowSummary | null>(null);
  useEffect(() => {
    let cancelled = false;
    allowSummaryRef.current = () => { cancelled = true; };
    allowlistSummary()
      .then((s) => { if (!cancelled) setAllow(s); })
      .catch(() => { /* whitelist card is optional */ });
    return () => { cancelled = true; };
  }, [rich]);

  // initialize live state when a new dataset arrives (setState during render
  // is the documented React pattern for derived-state reset)
  if (rich && live.src !== rich) {
    const hist = rich.eps_history ?? [];
    setLive({
      src: rich,
      eps: rich.health.pipeline.eps ?? 118,
      series: Array.from({ length: 40 }, (_, i) => ({
        ts: new Date(Date.now() - (40 - i) * 2000).toLocaleTimeString("en-GB", { hour12: false, minute: "2-digit", second: "2-digit" }),
        eps: hist[i % (hist.length || 1)] ?? 118,
      })),
      feed: rich.live_feed,
    });
  }

  // live tick (demo mode): EPS jitter + streaming feed
  useEffect(() => {
    if (!rich || !DEMO_MODE) return;
    const t = setInterval(() => {
      tickRef.current += 1;
      setLive((prev) => {
        const nextEps = demoTickEps(prev.eps ?? 118);
        const feed = tickRef.current % 2 === 0
          ? [demoNewFeedItem(), ...prev.feed].slice(0, 14)
          : prev.feed;
        return {
          ...prev,
          eps: nextEps,
          series: [...prev.series.slice(-59), {
            ts: new Date().toLocaleTimeString("en-GB", { hour12: false, minute: "2-digit", second: "2-digit" }),
            eps: nextEps,
          }],
          feed,
        };
      });
    }, 2000);
    return () => clearInterval(t);
  }, [rich]);

  const alertSpark = useMemo(
    () => (rich?.stats.alert_trend ?? []).map((t) => t.count),
    [rich]);
  const eventSpark = useMemo(
    () => (rich?.timeline.slice(-48) ?? []).map((t) => t.zeek + t.suricata),
    [rich]);
  const bytesSpark = useMemo(
    () => (rich?.timeline.slice(-48) ?? []).map((t) => Math.round(t.bytes / 1e6)),
    [rich]);

  // v0.14.0: honest failure state - the old UI silently rendered EMPTY
  // cards (all zeros) whenever the API was unreachable, which users read
  // as "the dashboard is broken/empty".
  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24 bg-zinc-900" />)}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-72 bg-zinc-900 lg:col-span-2" />
          <Skeleton className="h-72 bg-zinc-900" />
        </div>
      </div>
    );
  }

  // v0.14.0: honest failure state - the old UI silently rendered EMPTY
  // cards (all zeros) whenever the API was unreachable.
  if (!rich) {
    return (
      <div className="space-y-4">
        <div className="flex flex-col items-start gap-3 rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-red-300">
            <AlertTriangle className="h-4 w-4" />
            Dashboard data unavailable
          </div>
          <p className="max-w-2xl text-xs leading-relaxed text-zinc-400">
            The API could not be reached or returned an error
            {loadError ? `: ${loadError}` : "."} Pipeline, OpenSearch and the
            API container must all be up for the dashboard to fill in. Raw
            evidence is not lost - this is a display-level problem.
          </p>
          {onRetry && (
            <Button size="sm" variant="outline" onClick={onRetry}
                    className="border-zinc-700 text-zinc-200">
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry now
            </Button>
          )}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24 bg-zinc-900" />)}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-72 bg-zinc-900 lg:col-span-2" />
          <Skeleton className="h-72 bg-zinc-900" />
        </div>
      </div>
    );
  }

  const p = rich.health.pipeline;
  const epsNow = live.eps ?? p.eps ?? 0;
  const sevData = (rich.stats.alerts_by_severity ?? [])
    .filter((s) => s.count > 0)
    .map((s) => ({ name: s.key, value: s.count, color: SEV_COLORS[s.key] ?? "#71717a" }));
  const radarData = (rich.rule_stats ?? []).map((r) => ({ rule: r.name.split(" (")[0], fired: r.fired_7d }));
  const last24 = rich.timeline.slice(-24);
  const prev24 = rich.timeline.slice(-48, -24);
  const events24 = last24.reduce((s, t) => s + t.zeek + t.suricata, 0);
  const eventsPrev = prev24.reduce((s, t) => s + t.zeek + t.suricata, 0);
  const deltaEvents = eventsPrev ? Math.round(((events24 - eventsPrev) / eventsPrev) * 100) : null;
  const diskUsed = rich.health.disk?.used_pct ?? 0;
  const totalInMbps = rich.zone_traffic.reduce((s, z) => s + z.in_mbps, 0);

  return (
    <div className="space-y-4">
      {/* KPI row */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <Kpi title="Alerts (24h)" value={fmtNumber(rich.stats.alerts_24h)}
             sub={`${rich.new_alerts_today} new`} delta={null}
             icon={<BellRing className="h-3.5 w-3.5" />} tone={rich.critical_open > 0 ? "alert" : "default"}
             spark={alertSpark} sparkColor="#fb923c" />
        <Kpi title="Critical open" value={fmtNumber(rich.critical_open)}
             sub="needs triage now" icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={rich.critical_open ? "alert" : "ok"} />
        <Kpi title="Events (24h)" value={fmtNumber(events24)}
             sub="vs prev 24h" delta={deltaEvents} icon={<Zap className="h-3.5 w-3.5" />}
             spark={eventSpark} sparkColor="#38bdf8" />
        <Kpi title="Ingest rate" value={`${epsNow.toFixed(0)} eps`}
             sub={`zeek ${(epsNow * 0.6).toFixed(0)} / suri ${(epsNow * 0.4).toFixed(0)}`}
             icon={<Gauge className="h-3.5 w-3.5" />} tone="ok"
             spark={live.series.slice(-40).map((e) => e.eps)} sparkColor="#60a5fa" />
        <Kpi title="Throughput" value={`${totalInMbps.toFixed(1)} Mbps`}
             sub="aggregate across zones" icon={<Radio className="h-3.5 w-3.5" />}
             spark={bytesSpark} sparkColor="#a78bfa" />
        <Kpi title="Hosts monitored" value={`${rich.hosts.length}`}
             sub={`${rich.hosts.filter((h) => h.status === "at_risk").length} at risk - ${rich.hosts.filter((h) => h.status === "watch").length} watch`}
             icon={<Server className="h-3.5 w-3.5" />}
             tone={rich.hosts.some((h) => h.status === "at_risk") ? "warn" : "ok"} />
        {/* v0.14.0: whitelist transparency card */}
        <Kpi title="Whitelisted"
             value={fmtNumber(allow?.total_hits ?? 0)}
             sub={allow
               ? `${allow.active} active (${allow.l0} L0 / ${allow.l1} L1)${allow.pending ? ` - ${allow.pending} pending` : ""}`
               : "loading..."}
             icon={<ShieldCheck className="h-3.5 w-3.5" />} tone="ok" />
      </div>

      {/* v0.16.0 (req 19): grafik trafik realtime SSE - pps-like EPS,
          alert/event rate 5 menit, antrean pipeline (tick 2 detik) */}
      <LiveTrafficWidget />

      {/* live EPS + severity */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel
          className="lg:col-span-2"
          title="Live ingest rate"
          icon={<Activity className="h-4 w-4 text-emerald-400" />}
          sub={DEMO_MODE ? "simulated stream (demo) - refresh 2s" : "pipeline metrics"}
          action={
            <Badge variant="outline" className="border-emerald-900 bg-emerald-950/40 text-emerald-300">
              <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
              live
            </Badge>
          }>
          <EpsLiveChart data={DEMO_MODE ? live.series : (rich.stats.alert_trend ?? []).map((t) => ({ ts: fmtTime(t.ts), eps: t.count }))} height={190} />
          <div className="mt-2 grid grid-cols-4 gap-2 text-center">
            <MiniMetric label="EPS now" value={epsNow.toFixed(1)} />
            <MiniMetric label="Events indexed" value={fmtNumber(p.events_indexed ?? 0)} />
            <MiniMetric label="Parse errors" value={fmtNumber(p.parse_errors ?? 0)} />
            <MiniMetric label="Backlog" value={`${p.backlog_seconds ?? 0}s`} />
          </div>
        </VizPanel>

        <VizPanel title="Alerts by severity (24h)" icon={<BellRing className="h-4 w-4 text-orange-400" />}
                  sub="click Alert Center to investigate">
          <DonutChart data={sevData} centerValue={fmtNumber(rich.stats.alerts_24h)} centerLabel="total 24h" height={185} />
          <Button variant="outline" size="sm" onClick={onOpenAlerts}
                  className="mt-3 w-full border-zinc-800 bg-zinc-900 text-xs text-zinc-300 hover:bg-zinc-800">
            Open Alert Center
          </Button>
        </VizPanel>
      </div>

      {/* 7d stacked + radar */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel className="lg:col-span-2" title="Alert trend - 7 days"
                  icon={<Activity className="h-4 w-4 text-emerald-400" />}
                  sub="stacked by severity, hourly buckets">
          <SeverityStackedArea data={rich.timeline} height={210} />
        </VizPanel>
        <VizPanel title="Detections by rule" icon={<RadarIcon />}
                  sub="fired events last 7 days">
          <RuleRadar data={radarData} height={210} />
          <div className="mt-1 grid grid-cols-2 gap-x-4 gap-y-1.5">
            {(rich.rule_stats ?? []).map((r) => (
              <div key={r.rule} className="flex items-center justify-between text-[11px]">
                <span className="min-w-0 truncate text-zinc-400">{r.name.split(" (")[0]}</span>
                <span className="tabular-nums text-zinc-300">{fmtNumber(r.fired_7d)}</span>
              </div>
            ))}
          </div>
        </VizPanel>
      </div>

      {/* traffic + top talkers */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel className="lg:col-span-2" title="Event volume by engine - 7 days"
                  icon={<Database className="h-4 w-4 text-emerald-400" />}
                  sub="zeek + suricata + arkime index events, hourly">
          <TrafficTimeline data={rich.timeline} height={190} />
        </VizPanel>
        <VizPanel title="Top internal talkers" icon={<Network className="h-4 w-4 text-emerald-400" />}
                  sub="total bytes in + out, 24h">
          <HBarList items={rich.top_internal_talkers.slice(0, 7)} color="#38bdf8"
                    valueFmt={(n) => fmtNumber(n)} subFmt={(i) => fmtBytes(i.bytes ?? 0)} />
        </VizPanel>
      </div>

      {/* heatmap + external + protocols */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel className="lg:col-span-2" title="Alert density heatmap - 7 x 24h"
                  icon={<Gauge className="h-4 w-4 text-emerald-400" />}
                  sub="hourly alert count, greener = quiet, red = hot">
          <AlertHeatmap cells={rich.alert_heatmap} height={140} />
        </VizPanel>
        <VizPanel title="Top external destinations" icon={<Globe2 className="h-4 w-4 text-emerald-400" />}
                  sub="outbound connections, 24h">
          <HBarList items={rich.top_external_dests.slice(0, 7)} color="#60a5fa"
                    valueFmt={fmtNumber} subFmt={(i) => i.meta ?? ""} />
        </VizPanel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel title="Protocol mix" icon={<Network className="h-4 w-4 text-emerald-400" />}
                  sub="share of observed L7 traffic">
          <ProtocolDonut data={rich.protocols} height={175} />
        </VizPanel>

        <VizPanel title="Zone throughput" icon={<Radio className="h-4 w-4 text-emerald-400" />}
                  sub="ingress / egress Mbps">
          <div className="space-y-3">
            {rich.zone_traffic.map((z) => (
              <div key={z.zone}>
                <div className="mb-1 flex justify-between text-xs">
                  <span className="text-zinc-300">{z.zone} <span className="text-zinc-600">({z.hosts} hosts)</span></span>
                  <span className="tabular-nums text-zinc-400">
                    <span className="text-emerald-400">↓{z.in_mbps.toFixed(1)}</span>{" "}
                    <span className="text-sky-400">↑{z.out_mbps.toFixed(1)}</span> Mbps
                  </span>
                </div>
                <div className="flex h-2 gap-0.5 overflow-hidden rounded-full bg-zinc-800">
                  <div className="h-full rounded-l-full" style={{ width: `${(z.in_mbps / 50) * 100}%`, background: z.color }} />
                  <div className="h-full rounded-r-full opacity-60" style={{ width: `${(z.out_mbps / 50) * 100}%`, background: z.color }} />
                </div>
              </div>
            ))}
          </div>
        </VizPanel>

        <VizPanel title="Platform health" icon={<Cpu className="h-4 w-4 text-emerald-400" />}
                  sub="core services">
          <div className="flex items-center justify-around pb-2">
            <RingGauge value={diskUsed} size={86} color={diskUsed > 80 ? "#f87171" : diskUsed > 65 ? "#fbbf24" : "#38bdf8"}
                       sub={`disk ${diskUsed}%`} />
            <RingGauge value={epsNow} max={300} size={86} color="#60a5fa"
                       label={epsNow.toFixed(0)} sub="eps vs 300 cap" />
            <RingGauge value={(rich.services.filter((s) => s.ok).length / Math.max(1, rich.services.length)) * 100}
                       size={86} color="#a78bfa" sub="services up" />
          </div>
          <div className="space-y-1">
            {rich.services.slice(0, 4).map((s) => (
              <div key={s.name} className="flex items-center gap-2 rounded bg-zinc-900/70 px-2 py-1 text-[11px]">
                <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", s.ok ? "bg-emerald-400" : "bg-red-400")} />
                <span className="min-w-0 flex-1 truncate text-zinc-300">{s.name}</span>
                <span className="tabular-nums text-zinc-500">cpu {s.cpu_pct}%</span>
              </div>
            ))}
          </div>
        </VizPanel>
      </div>

      {/* live feed + watchlist */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel className="lg:col-span-2"
                  title="Live event stream"
                  icon={<Zap className="h-4 w-4 text-emerald-400" />}
                  sub={DEMO_MODE ? "synthetic tail (demo)" : "latest normalized events"}
                  action={<Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">tail -f</Badge>}>
          <ScrollArea className="h-64">
            <div className="space-y-1.5 pr-3">
              {live.feed.map((f) => <FeedRow key={f.id} item={f} />)}
              {!live.feed.length && <p className="py-8 text-center text-xs text-zinc-600">Waiting for events...</p>}
            </div>
          </ScrollArea>
        </VizPanel>

        <VizPanel title="Highest risk hosts" icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
                  sub="heuristic asset risk score">
          <div className="space-y-1.5">
            {[...rich.hosts].sort((a, b) => b.risk_score - a.risk_score).slice(0, 7).map((h) => (
              <div key={h.ip} className="flex items-center gap-2 rounded-md border border-zinc-800/70 bg-zinc-900/40 px-2.5 py-1.5">
                <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full",
                  h.status === "at_risk" ? "animate-pulse bg-red-400" : h.status === "watch" ? "bg-amber-400" : "bg-emerald-400")} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-mono text-xs text-zinc-200">{h.hostname}</span>
                    <HostRiskBadge score={h.risk_score} />
                  </div>
                  <div className="truncate text-[10px] text-zinc-600">{h.last_alert_title ?? `${h.zone} - ${h.role}`}</div>
                </div>
              </div>
            ))}
          </div>
        </VizPanel>
      </div>

      <p className="text-center text-[11px] text-zinc-600">
        Severity & risk scores are heuristic interpretations of observed evidence - they indicate activity worth review, not proof of compromise.
      </p>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-zinc-800/70 bg-zinc-900/60 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-zinc-600">{label}</div>
      <div className="text-sm font-medium tabular-nums text-zinc-200">{value}</div>
    </div>
  );
}

function RadarIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4 text-emerald-400" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><path d="M12 12 19 5" />
    </svg>
  );
}
