"use client";

// Chart primitives for the NDR console (recharts + hand-rolled SVG).

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { cn } from "@/lib/utils";
import type { HeatCell, ProtocolSlice, TimelinePoint, TopItem } from "@/lib/ndr/types";
import { fmtBytes, fmtNumber } from "./shared";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, Scatter, ScatterChart, XAxis, YAxis, ZAxis } from "recharts";

export const SEV_COLORS: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#a1a1aa",
  informational: "#71717a",
};

// ----------------------------------------------------------------- sparkline (pure SVG)
export function Sparkline({ data, color = "#38bdf8", height = 34, fill = true, strokeWidth = 1.6, className }: {
  data: number[];
  color?: string;
  height?: number;
  fill?: boolean;
  strokeWidth?: number;
  className?: string;
}) {
  if (!data.length) return <div style={{ height }} className={className} />;
  const W = 120;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const pts = data.map((v, i) => [
    (i / (data.length - 1 || 1)) * W,
    height - 3 - ((v - min) / span) * (height - 6),
  ] as const);
  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `${line} L${W},${height} L0,${height} Z`;
  const gid = `sg-${color.replace("#", "")}`;
  return (
    <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" className={cn("w-full", className)} style={{ height }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.35} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${gid})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ----------------------------------------------------------------- EPS live area
const epsConfig = {
  eps: { label: "events/s", color: "#38bdf8" },
} satisfies ChartConfig;

export function EpsLiveChart({ data, height = 200 }: { data: { ts: string; eps: number; zeek?: number; suricata?: number }[]; height?: number }) {
  return (
    <ChartContainer config={epsConfig} className="w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -14, bottom: 0 }}>
        <defs>
          <linearGradient id="epsFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tick={{ fill: "#71717a", fontSize: 10 }} tickFormatter={(v: string) => v} stroke="#3f3f46" minTickGap={40} />
        <YAxis tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46" allowDecimals={false} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Area type="monotone" dataKey="eps" stroke="#38bdf8" strokeWidth={2} fill="url(#epsFill)" isAnimationActive={false} />
      </AreaChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- stacked severity area (7d)
const sevAreaConfig = {
  alerts_critical: { label: "Critical", color: SEV_COLORS.critical },
  alerts_high: { label: "High", color: SEV_COLORS.high },
  alerts_medium: { label: "Medium", color: SEV_COLORS.medium },
  alerts_low: { label: "Low", color: SEV_COLORS.low },
} satisfies ChartConfig;

export function SeverityStackedArea({ data, height = 220 }: { data: TimelinePoint[]; height?: number }) {
  return (
    <ChartContainer config={sevAreaConfig} className="w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46"
               tickFormatter={(v: string) => {
                 const d = new Date(v);
                 // v0.16.2 (BUG-0161-02): dukung bucket harian (ts "YYYY-MM-DD")
                 if (v && v.length === 10 && !v.includes("T")) {
                   return `${d.getDate()}/${d.getMonth() + 1}`;
                 }
                 return `${d.getDate()}/${d.getHours()}:00`;
               }} minTickGap={48} />
        <YAxis tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46" allowDecimals={false} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Area type="monotone" dataKey="alerts_low" stackId="1" stroke={SEV_COLORS.low} fill={SEV_COLORS.low} fillOpacity={0.35} strokeWidth={1} />
        <Area type="monotone" dataKey="alerts_medium" stackId="1" stroke={SEV_COLORS.medium} fill={SEV_COLORS.medium} fillOpacity={0.35} strokeWidth={1} />
        <Area type="monotone" dataKey="alerts_high" stackId="1" stroke={SEV_COLORS.high} fill={SEV_COLORS.high} fillOpacity={0.4} strokeWidth={1} />
        <Area type="monotone" dataKey="alerts_critical" stackId="1" stroke={SEV_COLORS.critical} fill={SEV_COLORS.critical} fillOpacity={0.55} strokeWidth={1.5} />
      </AreaChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- traffic timeline (stacked engine volume)
const trafficConfig = {
  zeek: { label: "Zeek events", color: "#38bdf8" },
  suricata: { label: "Suricata events", color: "#60a5fa" },
  arkime: { label: "Arkime (pcap idx)", color: "#a78bfa" },
} satisfies ChartConfig;

export function TrafficTimeline({ data, height = 200 }: { data: TimelinePoint[]; height?: number }) {
  return (
    <ChartContainer config={trafficConfig} className="w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46"
               tickFormatter={(v: string) => {
                 const d = new Date(v);
                 return `${d.getDate()}/${d.getHours()}:00`;
               }} minTickGap={48} />
        <YAxis tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46" allowDecimals={false} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Area type="monotone" dataKey="zeek" stackId="1" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.3} strokeWidth={1.5} />
        <Area type="monotone" dataKey="suricata" stackId="1" stroke="#60a5fa" fill="#60a5fa" fillOpacity={0.3} strokeWidth={1.5} />
        <Area type="monotone" dataKey="arkime" stackId="1" stroke="#a78bfa" fill="#a78bfa" fillOpacity={0.25} strokeWidth={1} />
      </AreaChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- donut (severity / protocols)
export function DonutChart({ data, centerValue, centerLabel, height = 210, valueFmt = fmtNumber }: {
  data: { name: string; value: number; color: string }[];
  centerValue?: string;
  centerLabel?: string;
  height?: number;
  valueFmt?: (n: number) => string;
}) {
  return (
    <div className="flex items-center gap-3">
      <div className="relative shrink-0" style={{ width: height, height }}>
        <ChartContainer config={{}} className="aspect-square w-full">
          <PieChart>
            <ChartTooltip content={<ChartTooltipContent />} />
            <Pie data={data} dataKey="value" nameKey="name" innerRadius="62%" outerRadius="88%" paddingAngle={2} strokeWidth={0}>
              {data.map((d) => <Cell key={d.name} fill={d.color} />)}
            </Pie>
          </PieChart>
        </ChartContainer>
        {centerValue && (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-xl font-semibold tabular-nums text-zinc-100">{centerValue}</div>
            {centerLabel && <div className="text-[10px] uppercase tracking-wider text-zinc-500">{centerLabel}</div>}
          </div>
        )}
      </div>
      <div className="min-w-0 flex-1 space-y-1.5">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: d.color }} />
            <span className="min-w-0 flex-1 truncate text-zinc-400">{d.name}</span>
            <span className="tabular-nums text-zinc-200">{valueFmt(d.value)}</span>
            <span className="w-10 text-right tabular-nums text-zinc-500">
              {data.reduce((s, x) => s + x.value, 0) > 0
                ? `${Math.round((d.value / data.reduce((s, x) => s + x.value, 0)) * 100)}%`
                : "0%"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ProtocolDonut({ data, height = 200 }: { data: ProtocolSlice[]; height?: number }) {
  return <DonutChart data={data.map((p) => ({ name: p.name, value: p.value, color: p.color }))}
                     centerValue="9.6" centerLabel="avg Mbps" valueFmt={(n) => `${n}%`} height={height} />;
}

// ----------------------------------------------------------------- radar (detection rules)
export function RuleRadar({ data, height = 220 }: { data: { rule: string; fired: number }[]; height?: number }) {
  const config = {} satisfies ChartConfig;
  return (
    <ChartContainer config={config} className="w-full" style={{ height }}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke="#27272a" />
        <PolarAngleAxis dataKey="rule" tick={{ fill: "#a1a1aa", fontSize: 10 }} />
        <PolarRadiusAxis tick={{ fill: "#52525b", fontSize: 9 }} stroke="#3f3f46" />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Radar name="fired (7d)" dataKey="fired" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.35} />
      </RadarChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- horizontal ranked bars (div-based)
export function HBarList({ items, color = "#38bdf8", valueFmt = fmtNumber, subFmt, max: maxOverride, onPick }: {
  items: TopItem[];
  color?: string | ((item: TopItem, idx: number) => string);
  valueFmt?: (n: number) => string;
  subFmt?: (item: TopItem) => string | null | undefined;
  max?: number;
  onPick?: (item: TopItem) => void;
}) {
  const max = maxOverride ?? Math.max(...items.map((i) => i.count), 1);
  return (
    <div className="space-y-2">
      {items.map((item, idx) => {
        const c = typeof color === "function" ? color(item, idx) : color;
        const flagged = /malicious|dga|c2|attack|sqli/i.test(item.meta ?? "") || /dga|attack|malicious/i.test(item.key);
        return (
          <div key={`${item.key}-${idx}`} className={cn("group rounded-md px-1.5 py-1", onPick && "cursor-pointer hover:bg-zinc-800/50")}
               onClick={() => onPick?.(item)}>
            <div className="mb-1 flex items-baseline justify-between gap-2 text-xs">
              <span className={cn("min-w-0 truncate font-medium", flagged ? "text-red-300" : "text-zinc-300")} title={item.key}>
                {item.key}
              </span>
              <span className="shrink-0 tabular-nums text-zinc-400">{valueFmt(item.count)}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
                <div className="h-full rounded-full transition-all duration-500"
                     style={{ width: `${Math.max(3, (item.count / max) * 100)}%`, background: flagged ? "#f87171" : c }} />
              </div>
              {subFmt && <span className="w-28 shrink-0 truncate text-right text-[10px] text-zinc-500">{subFmt(item)}</span>}
            </div>
          </div>
        );
      })}
      {!items.length && <p className="py-6 text-center text-xs text-zinc-600">No data available</p>}
    </div>
  );
}

// ----------------------------------------------------------------- heatmap 7x24
export function AlertHeatmap({ cells, height = 150 }: { cells: HeatCell[]; height?: number }) {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const max = Math.max(...cells.map((c) => c.value), 1);
  const color = (v: number) => {
    const t = v / max;
    if (t === 0) return "#18181b";
    if (t < 0.25) return "rgba(52,211,153,0.35)";
    if (t < 0.5) return "rgba(251,191,36,0.55)";
    if (t < 0.75) return "rgba(251,146,60,0.7)";
    return "rgba(248,113,113,0.85)";
  };
  return (
    <div>
      <div className="flex gap-1" style={{ height }}>
        <div className="flex w-8 shrink-0 flex-col justify-between py-0.5 text-right text-[9px] text-zinc-600">
          {Array.from({ length: 7 }, (_, d) => <div key={d}>{days[d]}</div>)}
        </div>
        <div className="grid flex-1 gap-1" style={{ gridTemplateRows: "repeat(7, 1fr)", gridTemplateColumns: "repeat(24, 1fr)" }}>
          {cells.map((c) => (
            <div key={`${c.day}-${c.hour}`}
                 title={`${days[c.day]} ${String(c.hour).padStart(2, "0")}:00 - ${c.value} alerts`}
                 className="rounded-[2px] transition-transform hover:scale-110 hover:ring-1 hover:ring-zinc-400"
                 style={{ background: color(c.value) }} />
          ))}
        </div>
      </div>
      <div className="mt-1.5 flex items-center justify-between pl-9 text-[9px] text-zinc-600">
        <span>00:00</span>
        <span>06:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>23:00</span>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- ring gauge (SVG)
export function RingGauge({ value, max = 100, size = 96, color = "#38bdf8", label, sub, thickness = 8 }: {
  value: number; max?: number; size?: number; color?: string; label?: string; sub?: string; thickness?: number;
}) {
  const pct = Math.min(1, Math.max(0, value / max));
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#27272a" strokeWidth={thickness} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={thickness}
                  strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct)}
                  style={{ transition: "stroke-dashoffset 0.8s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-sm font-semibold tabular-nums text-zinc-100">{label ?? `${Math.round(pct * 100)}%`}</span>
        </div>
      </div>
      {sub && <span className="text-center text-[10px] text-zinc-500">{sub}</span>}
    </div>
  );
}

// ----------------------------------------------------------------- scatter (alert timeline)
export function AlertScatter({ data, height = 200 }: { data: { ts: number; severity: string; risk: number; title: string }[]; height?: number }) {
  const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
  return (
    <ChartContainer config={{}} className="w-full" style={{ height }}>
      <ScatterChart margin={{ top: 10, right: 12, left: -18, bottom: 0 }}>
        <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
        <XAxis dataKey="ts" type="number" domain={["dataMin", "dataMax"]}
               tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46"
               tickFormatter={(v: number) => new Date(v).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })} />
        <YAxis dataKey="sevIdx" type="number" domain={[-0.5, 4.5]} ticks={[0, 1, 2, 3, 4]}
               tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46"
               tickFormatter={(v: number) => (["info", "low", "medium", "high", "crit"] as const)[v] ?? ""} />
        <ZAxis dataKey="risk" range={[30, 240]} />
        <ChartTooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null;
            const d = payload[0].payload as { title: string; severity: string; risk: number; ts: number };
            return (
              <div className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow-xl">
                <div className="mb-0.5 max-w-56 font-medium text-zinc-200">{d.title}</div>
                <div className="text-zinc-500">
                  {new Date(d.ts).toLocaleString("en-GB")} - {d.severity} - risk {d.risk}
                </div>
              </div>
            );
          }} />
        <Scatter data={data.map((d) => ({ ...d, sevIdx: sevOrder[d.severity] ?? 0 }))} fillOpacity={0.65}>
          {data.map((d, i) => <Cell key={i} fill={SEV_COLORS[d.severity] ?? "#71717a"} />)}
        </Scatter>
      </ScatterChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- mini bar (inline)
export function MiniBar({ value, max, color = "#38bdf8", className }: { value: number; max: number; color?: string; className?: string }) {
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-zinc-800", className)}>
      <div className="h-full rounded-full" style={{ width: `${Math.min(100, (value / (max || 1)) * 100)}%`, background: color }} />
    </div>
  );
}

// ----------------------------------------------------------------- funnel (alert status)
export function StatusFunnel({ data }: { data: { key: string; count: number }[] }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  const colors: Record<string, string> = {
    new: "#38bdf8", acknowledged: "#fbbf24", in_progress: "#a78bfa",
    closed: "#38bdf8", false_positive: "#71717a",
  };
  return (
    <div className="space-y-2.5">
      {data.map((d) => (
        <div key={d.key}>
          <div className="mb-1 flex justify-between text-xs">
            <span className="capitalize text-zinc-400">{d.key.replace("_", " ")}</span>
            <span className="tabular-nums text-zinc-300">{fmtNumber(d.count)}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-zinc-800">
            <div className="h-full rounded-full transition-all duration-700"
                 style={{ width: `${(d.count / max) * 100}%`, background: colors[d.key] ?? "#71717a" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ----------------------------------------------------------------- MTTR bar chart
export function MttrChart({ data, height = 180 }: { data: { day: string; mttr_hours: number; closed: number }[]; height?: number }) {
  const config = {
    mttr_hours: { label: "MTTR (hours)", color: "#60a5fa" },
  } satisfies ChartConfig;
  return (
    <ChartContainer config={config} className="w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="mttrFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#60a5fa" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#60a5fa" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="day" tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46" />
        <YAxis tick={{ fill: "#71717a", fontSize: 10 }} stroke="#3f3f46" allowDecimals={false} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Area type="monotone" dataKey="mttr_hours" stroke="#60a5fa" strokeWidth={2} fill="url(#mttrFill)" />
      </AreaChart>
    </ChartContainer>
  );
}

// ----------------------------------------------------------------- panel wrapper
export function VizPanel({ title, icon, sub, children, className, action }: {
  title: string; icon?: React.ReactNode; sub?: string; children: React.ReactNode;
  className?: string; action?: React.ReactNode;
}) {
  return (
    <Card className={cn("border-zinc-800 bg-zinc-900/60", className)}>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <div>
          <CardTitle className="flex items-center gap-2 text-sm font-medium text-zinc-300">
            {icon}{title}
          </CardTitle>
          {sub && <p className="mt-0.5 text-[11px] text-zinc-600">{sub}</p>}
        </div>
        {action}
      </CardHeader>
      <CardContent className="pt-1">{children}</CardContent>
    </Card>
  );
}

// re-export for views
export { fmtBytes, fmtNumber };
