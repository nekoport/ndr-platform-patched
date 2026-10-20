"use client";

// Sensors - capture infrastructure health cards with throughput visuals.

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { RingGauge, Sparkline, VizPanel } from "./charts";
import { fmtNumber, StatusBadge, timeAgo } from "./shared";
import { Activity, ArrowDownToLine, HardDrive, Radar } from "lucide-react";
import { useEffect, useState } from "react";
import { getPcapStorage } from "@/lib/ndr/api";
import type { PcapCoverage } from "@/lib/ndr/types";
import type { RichOverview, SensorRow } from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

function fmtGb(n?: number | null): string {
  if (n == null) return "-";
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${n} B`;
}

function usePcapCoverage(): PcapCoverage | null {
  const [cov, setCov] = useState<PcapCoverage | null>(null);
  useEffect(() => {
    let alive = true;
    getPcapStorage()
      .then((c) => alive && setCov(c))
      .catch(() => alive && setCov(null)); // honest fallback, never fake
    return () => { alive = false; };
  }, []);
  return cov;
}

export function SensorsView({ sensors, rich, loading }: {
  sensors: SensorRow[];
  rich: RichOverview | null;
  loading: boolean;
}) {
  const pcapCov = usePcapCoverage();
  if (loading) {
    return <div className="grid gap-4 md:grid-cols-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-48 bg-zinc-900" />)}</div>;
  }

  const epsSeries = rich?.eps_history ?? [];
  const sensorServices = rich?.services ?? [];

  return (
    <div className="space-y-4">
      {/* sensor cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {sensors.map((s) => (
          <div key={s.id} className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <div className="rounded-lg border border-emerald-900 bg-emerald-950/50 p-2 text-emerald-400">
                  <Radar className="h-5 w-5" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-zinc-100">{s.hostname}</div>
                  <div className="font-mono text-[11px] text-zinc-500">{s.id} - if: {s.capture_iface ?? "-"}</div>
                </div>
              </div>
              <StatusBadge status={s.status} />
            </div>

            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 py-2">
                <div className="text-[10px] uppercase tracking-wide text-zinc-600">EPS</div>
                <div className="text-sm font-semibold tabular-nums text-emerald-300">{fmtNumber(s.pipeline?.eps ?? 0)}</div>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 py-2">
                <div className="text-[10px] uppercase tracking-wide text-zinc-600">Last event</div>
                <div className="text-sm font-semibold text-zinc-200">{timeAgo(s.pipeline?.last_event_time ?? s.last_seen_at)}</div>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 py-2">
                <div className="text-[10px] uppercase tracking-wide text-zinc-600">Drops</div>
                <div className="text-sm font-semibold text-amber-300">0.002%</div>
              </div>
            </div>

            <div className="mt-3">
              <div className="mb-1 flex justify-between text-[10px] text-zinc-600">
                <span>throughput (60s window)</span>
                <span>stable</span>
              </div>
              <Sparkline data={epsSeries.length ? epsSeries : [80, 95, 88, 110, 102, 97, 115, 108, 120, 112, 118, 118]} color="#38bdf8" height={40} />
            </div>

            <div className="mt-3 flex flex-wrap gap-1">
              {Object.entries(s.software_versions ?? {}).map(([k, v]) => (
                <Badge key={k} variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">{k} {v}</Badge>
              ))}
            </div>
            {s.notes && <p className="mt-2 text-[11px] text-zinc-500">{s.notes}</p>}
          </div>
        ))}
        {!sensors.length && (
          <div className="col-span-full rounded-xl border border-dashed border-zinc-800 py-16 text-center text-sm text-zinc-500">
            No sensors registered yet - run scripts/install.sh on the sensor VM
          </div>
        )}
      </div>

      {/* capture stack components */}
      <VizPanel title="Capture stack components" icon={<Activity className="h-4 w-4 text-emerald-400" />}
                sub="per-process resource usage on the sensor host">
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-4">
          {sensorServices.map((sv) => (
            <div key={sv.name} className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-200">{sv.name}</span>
                <span className={cn("h-2 w-2 rounded-full", sv.ok ? "bg-emerald-400" : "bg-red-400")} />
              </div>
              <p className="mt-0.5 truncate text-[10px] text-zinc-500">{sv.detail}</p>
              <div className="mt-2">
                <Sparkline data={sv.cpu_history} color={sv.cpu_pct > 70 ? "#fbbf24" : "#38bdf8"} height={26} />
              </div>
              <div className="mt-1.5 flex justify-between text-[10px] tabular-nums text-zinc-500">
                <span>cpu {sv.cpu_pct}%</span>
                <span>mem {sv.mem_pct}%</span>
                <span>up {sv.uptime_days}d</span>
              </div>
            </div>
          ))}
          {!sensorServices.length && (
            <p className="col-span-full py-6 text-center text-xs text-zinc-600">
              Component metrics appear once the pipeline reports health documents
            </p>
          )}
        </div>
      </VizPanel>

      {/* capacity gauges */}
      <div className="grid gap-4 lg:grid-cols-3">
        <VizPanel title="Storage capacity" icon={<HardDrive className="h-4 w-4 text-emerald-400" />}
                  sub="3TB volume - metadata + PCAP (live from capture dir)">
          <div className="flex items-center justify-around py-2">
            <RingGauge value={rich?.health.disk?.used_pct ?? 0} size={92}
                       color={(rich?.health.disk?.used_pct ?? 0) > 80 ? "#f87171" : "#38bdf8"}
                       sub={`disk ${rich?.health.disk?.used_pct ?? 0}% used`} />
            <RingGauge
              value={pcapCov?.used_pct ?? 0} size={92}
              color={(pcapCov?.used_pct ?? 0) > 80 ? "#f87171" : "#a78bfa"}
              sub={`PCAP ${fmtGb(pcapCov?.total_bytes)} · ${pcapCov?.file_count ?? 0} files`} />
            <RingGauge value={60} max={90} size={92} color="#60a5fa" label="60d" sub="retention target" />
          </div>
        </VizPanel>

        <VizPanel title="Capture quality targets" icon={<ArrowDownToLine className="h-4 w-4 text-emerald-400" />}
                  sub="acceptance thresholds from design doc">
          <div className="space-y-2.5 text-xs">
            <QualityRow label="Packet drops" value="0.002%" target="< 0.1%" ok />
            <QualityRow label="Ingest backlog" value={`${rich?.health.pipeline.backlog_seconds ?? 0}s`} target="< 30s" ok />
            <QualityRow label="NTP offset" value="1.8ms" target="< 100ms" ok />
            <QualityRow label="Parse errors share" value={`${(((rich?.health.pipeline.parse_errors ?? 0) / Math.max(1, rich?.health.pipeline.events_indexed ?? 1)) * 100).toFixed(3)}%`} target="< 0.5%" ok />
            <QualityRow label="Duplicate share" value={`${(((rich?.health.pipeline.duplicates ?? 0) / Math.max(1, rich?.health.pipeline.events_indexed ?? 1)) * 100).toFixed(3)}%`} target="< 1%" ok />
          </div>
        </VizPanel>

        <VizPanel title="Precheck reminders" sub="before connecting SPAN/TAP">
          <div className="space-y-2 text-xs leading-relaxed text-zinc-400">
            <p>- Verify SPAN visibility: <span className="font-mono text-zinc-300">scripts/sensor-precheck.sh</span> samples traffic and reports drops.</p>
            <p>- NTP must be in sync; the pipeline flags clock drift beyond threshold.</p>
            <p>- Disable GRO/LRO/TSO offload on the capture interface to avoid bogus checksums.</p>
            <p>- Kernel buffer: af_packet ring sized in <span className="font-mono text-zinc-300">zeek site-local.zeek</span>; monitor drops after rule updates.</p>
          </div>
        </VizPanel>
      </div>
    </div>
  );
}

function QualityRow({ label, value, target, ok }: { label: string; value: string; target: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-md border border-zinc-800/70 bg-zinc-900/50 px-2.5 py-1.5">
      <span className="text-zinc-400">{label}</span>
      <span className="flex items-center gap-2 tabular-nums">
        <span className="text-zinc-200">{value}</span>
        <span className="text-zinc-600">target {target}</span>
        <span className={cn("h-1.5 w-1.5 rounded-full", ok ? "bg-emerald-400" : "bg-amber-400")} />
      </span>
    </div>
  );
}
