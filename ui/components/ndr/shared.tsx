"use client";

// Shared presentational helpers for the NDR console.

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { AlertOutcome } from "@/lib/ndr/types";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export type { AlertOutcome };

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const map: Record<string, string> = {
    critical: "bg-red-950 text-red-300 border-red-800",
    high: "bg-orange-950 text-orange-300 border-orange-800",
    medium: "bg-amber-950 text-amber-300 border-amber-800",
    low: "bg-zinc-800 text-zinc-300 border-zinc-700",
    informational: "bg-zinc-900 text-zinc-400 border-zinc-800",
  };
  if (!severity) return <span className="text-xs text-zinc-500">-</span>;
  return (
    <Badge variant="outline" className={cn("capitalize", map[severity] ?? map.low)}>
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status?: string | null }) {
  const map: Record<string, string> = {
    new: "bg-sky-950 text-sky-300 border-sky-800",
    acknowledged: "bg-amber-950 text-amber-300 border-amber-800",
    in_progress: "bg-violet-950 text-violet-300 border-violet-800",
    closed: "bg-emerald-950 text-emerald-300 border-emerald-800",
    false_positive: "bg-zinc-900 text-zinc-400 border-zinc-700",
    online: "bg-emerald-950 text-emerald-300 border-emerald-800",
    degraded: "bg-amber-950 text-amber-300 border-amber-800",
    offline: "bg-red-950 text-red-300 border-red-800",
    unknown: "bg-zinc-900 text-zinc-400 border-zinc-700",
    success: "bg-emerald-950 text-emerald-300 border-emerald-800",
    failure: "bg-red-950 text-red-300 border-red-800",
    denied: "bg-orange-950 text-orange-300 border-orange-800",
  };
  const label = (status ?? "unknown").replace("_", " ");
  return (
    <Badge variant="outline" className={cn("capitalize", map[status ?? "unknown"] ?? map.unknown)}>
      {label}
    </Badge>
  );
}

export function StatCard({ title, value, sub, tone }: {
  title: string;
  value: string | number;
  sub?: string;
  tone?: "default" | "alert" | "ok";
}) {
  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className={cn(
          "text-2xl font-semibold tabular-nums",
          tone === "alert" && "text-orange-300",
          tone === "ok" && "text-emerald-300"
        )}>
          {value}
        </div>
        {sub && <p className="mt-1 text-xs text-zinc-500">{sub}</p>}
      </CardContent>
    </Card>
  );
}

export function ServiceDot({ ok, label, detail }: { ok: boolean; label: string; detail?: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5">
      <span className={cn(
        "h-2.5 w-2.5 shrink-0 rounded-full",
        ok ? "bg-emerald-400 shadow-[0_0_8px] shadow-emerald-500/50"
           : "bg-red-400 shadow-[0_0_8px] shadow-red-500/50"
      )} />
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-zinc-200">{label}</div>
        {detail && <div className="truncate text-xs text-zinc-500">{detail}</div>}
      </div>
    </div>
  );
}

export function JsonViewer({ data, maxHeight = 320 }: { data: unknown; maxHeight?: number }) {
  return (
    <pre
      className="overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs leading-relaxed text-zinc-300"
      style={{ maxHeight }}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export function timeAgo(value?: string | null): string {
  if (!value) return "-";
  const diff = Date.now() - new Date(value).getTime();
  if (Number.isNaN(diff)) return "-";
  const s = Math.max(1, Math.floor(diff / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function fmtTime(value?: string | null): string {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function fmtBytes(n?: number | null): string {
  if (n == null) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u += 1; }
  return `${v.toFixed(v >= 10 || u === 0 ? 0 : 1)} ${units[u]}`;
}

export function fmtNumber(n?: number | null): string {
  if (n == null) return "-";
  return new Intl.NumberFormat("en-US").format(Math.round(n));
}

/**
 * Legacy alert docs (pre-0.9.1) embedded the aggregation count in the
 * title, e.g. "Suricata: SIG (42x)". Frequency now lives in the separate
 * `event_count` field, so strip the suffix from stored titles at render
 * time - new alerts never carry it (pipeline contract, test_detection).
 */
export function alertTitle(title?: string | null): string {
  if (!title) return "-";
  const stripped = title.replace(/\s*\(\d+x\)\s*$/, "").trim();
  return stripped || title;
}

// --------------------------------------------------------------- pan & zoom
export interface PanZoomView { x: number; y: number; w: number; h: number; }

/**
 * Pan (pointer drag) + zoom (wheel / buttons) for fixed-coordinate SVG maps.
 * Pure viewport transform: apply as viewBox={`${view.x} ${view.y} ${view.w}
 * ${view.h}`} - node coordinates, distances and measured values stay in map
 * space, so all rendered data remains accurate while the user navigates.
 *
 * didDrag() lets click handlers ignore the click that terminates a pan.
 */
export function usePanZoom(W: number, H: number,
                           svgRef: React.RefObject<SVGSVGElement | null>,
                           maxZoom = 8) {
  const [view, setView] = useState<PanZoomView>({ x: 0, y: 0, w: W, h: H });
  const [grabbing, setGrabbing] = useState(false);
  const moved = useRef(false);
  const viewRef = useRef(view);
  useEffect(() => { viewRef.current = view; });

  // keep the map reachable: view must intersect map bounds + 25% overscroll
  const clampView = (v: PanZoomView): PanZoomView => {
    const m = 0.25;
    const xMin = -W * m, xMax = W * (1 + m) - v.w;
    const yMin = -H * m, yMax = H * (1 + m) - v.h;
    const cx = Math.min(Math.max(v.x, xMin), xMax);
    const cy = Math.min(Math.max(v.y, yMin), yMax);
    return { x: Number.isFinite(cx) ? cx : 0, y: Number.isFinite(cy) ? cy : 0,
             w: v.w, h: v.h };
  };

  const zoomAt = (mx: number, my: number, factor: number) => {
    setView((v) => {
      const nw = Math.min(W, Math.max(W / maxZoom, v.w * factor));
      const nh = nw * (H / W);
      const k = nw / v.w;
      return clampView({ w: nw, h: nh,
                         x: mx - (mx - v.x) * k, y: my - (my - v.y) * k });
    });
  };

  // wheel zoom must be a native non-passive listener (React attaches
  // onWheel passively - preventDefault there is a no-op and the page scrolls)
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const v = viewRef.current;
      const mx = v.x + ((e.clientX - rect.left) / rect.width) * v.w;
      const my = v.y + ((e.clientY - rect.top) / rect.height) * v.h;
      zoomAt(mx, my, e.deltaY > 0 ? 1.18 : 1 / 1.18);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    // Drag WITHOUT setPointerCapture: capturing the pointer on the SVG root
    // retargets the terminating `click` event to the root element, which
    // silently breaks node/edge onClick handlers (Threat Map click bug).
    // Instead the drag is tracked with window-level listeners and clicks
    // bubble normally; didDrag() lets child handlers ignore the click that
    // terminates a pan.
    moved.current = false;
    const startX = e.clientX;
    const startY = e.clientY;
    let lastX = e.clientX;
    let lastY = e.clientY;
    setGrabbing(true);
    const onMove = (ev: PointerEvent) => {
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect || !rect.width || !rect.height) return;
      if (Math.abs(ev.clientX - startX) + Math.abs(ev.clientY - startY) > 4) {
        moved.current = true;
      }
      const dx = ((ev.clientX - lastX) / rect.width) * viewRef.current.w;
      const dy = ((ev.clientY - lastY) / rect.height) * viewRef.current.h;
      lastX = ev.clientX;
      lastY = ev.clientY;
      setView((v) => clampView({ ...v, x: v.x - dx, y: v.y - dy }));
    };
    const onUp = () => {
      setGrabbing(false);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  };

  const reset = () => setView({ x: 0, y: 0, w: W, h: H });
  const zoomIn = () => zoomAt(viewRef.current.x + viewRef.current.w / 2,
                              viewRef.current.y + viewRef.current.h / 2, 1 / 1.35);
  const zoomOut = () => zoomAt(viewRef.current.x + viewRef.current.w / 2,
                               viewRef.current.y + viewRef.current.h / 2, 1.35);

  return {
    view, grabbing, reset, zoomIn, zoomOut,
    handlers: { onPointerDown },
    didDrag: () => moved.current,
  };
}

/** Small overlay control cluster for pan/zoom maps (used by Threat Map views). */
export function PanZoomControls({ pz }: {
  pz: ReturnType<typeof usePanZoom>;
}) {
  const btn = "flex h-7 w-7 items-center justify-center rounded border "
    + "border-zinc-700 bg-zinc-950/80 text-zinc-300 transition-colors "
    + "hover:border-zinc-500 hover:text-zinc-100";
  return (
    <div className="absolute right-3 top-2 flex items-center gap-1.5">
      <button className={btn} onClick={pz.zoomIn} title="Zoom in"
              aria-label="Zoom in">+</button>
      <button className={btn} onClick={pz.zoomOut} title="Zoom out"
              aria-label="Zoom out">&minus;</button>
      <button className={btn} onClick={pz.reset}
              title="Reset view" aria-label="Reset view">&#8962;</button>
    </div>
  );
}

// ------------------------------------------------------- alert outcome (v0.10)
// Attack-result taxonomy for ALERT level. Same enum as the incident-level
// OutcomeLabel so alert verdicts and reconstructed-campaign outcomes use
// one consistent vocabulary. "strong_success" is reserved for the
// correlation engine (chain-level), never set on a single alert.

export const OUTCOME_BADGE: Record<AlertOutcome, {
  label: string; cls: string; hint: string;
}> = {
  attempted: {
    label: "Attempted",
    cls: "border-amber-800 bg-amber-950/40 text-amber-200",
    hint: "Attack activity observed; no post-access evidence so far",
  },
  suspected_success: {
    label: "Suspected success",
    cls: "border-orange-800 bg-orange-950/50 text-orange-200",
    hint: "Server-reaction / follow-on evidence suggests the action went past the attempt",
  },
  strong_success: {
    label: "Strong evidence of success",
    cls: "border-red-800 bg-red-950/50 text-red-200",
    hint: "Set only by the correlation engine for TI-matched chains with success markers",
  },
  indeterminate: {
    label: "Indeterminate",
    cls: "border-zinc-700 bg-zinc-900/60 text-zinc-300",
    hint: "Activity may be benign or hostile - network evidence alone cannot characterize an outcome",
  },
};

export function OutcomeBadge({ outcome, className }: {
  outcome?: string | null; className?: string;
}) {
  if (!outcome) return <span className="text-xs text-zinc-600">-</span>;
  const meta = OUTCOME_BADGE[outcome as AlertOutcome]
    ?? OUTCOME_BADGE.indeterminate;
  return (
    <Badge variant="outline" title={meta.hint}
           className={cn("text-[10px]", meta.cls, className)}>
      {meta.label}
    </Badge>
  );
}

// ----------------------------------------------------------------- pagination
export function Paginator({ page, pageSize, total, onPage, onPageSize }: {
  page: number;               // 1-based
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  onPageSize?: (size: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  const btn = "flex h-7 items-center gap-0.5 rounded border border-zinc-700 "
    + "bg-zinc-950 px-2 text-xs text-zinc-300 transition-colors "
    + "hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed "
    + "disabled:opacity-40";
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 px-1 py-2">
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <span>{from}&ndash;{to} of <span className="tabular-nums text-zinc-300">{total}</span></span>
        {onPageSize && (
          <select
            value={pageSize}
            onChange={(e) => onPageSize(Number(e.target.value))}
            className="rounded border border-zinc-700 bg-zinc-950 px-1.5 py-0.5 text-xs text-zinc-300"
            aria-label="Rows per page">
            {[10, 25, 50, 100].map((n) => (
              <option key={n} value={n}>{n} / page</option>
            ))}
          </select>
        )}
      </div>
      <div className="flex items-center gap-1.5">
        <button className={btn} disabled={page <= 1}
                onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft className="h-3.5 w-3.5" /> Prev
        </button>
        <span className="px-1 text-xs tabular-nums text-zinc-400">
          page {page} / {pages}
        </span>
        <button className={btn} disabled={page >= pages}
                onClick={() => onPage(page + 1)} aria-label="Next page">
          Next <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------- time range
export type TimeRangePreset =
  | "today" | "24h" | "7d" | "14d" | "30d" | "all" | "custom";

export interface TimeRange {
  preset: TimeRangePreset;
  from: string | null;  // ISO
  to: string | null;    // ISO
}

export const DEFAULT_TIME_RANGE: TimeRange = { preset: "7d", from: null, to: null };

/** Resolve a range to concrete ISO bounds (to=null means "now"). */
export function resolveTimeRange(range: TimeRange): {
  from: string | null; to: string | null; label: string;
} {
  const now = Date.now();
  const DAY = 24 * 3_600_000;
  switch (range.preset) {
    case "today": {
      const d = new Date();
      d.setHours(0, 0, 0, 0);
      return { from: d.toISOString(), to: null, label: "today" };
    }
    case "24h": return { from: new Date(now - DAY).toISOString(), to: null, label: "last 24 hours" };
    case "7d": return { from: new Date(now - 7 * DAY).toISOString(), to: null, label: "last 7 days" };
    case "14d": return { from: new Date(now - 14 * DAY).toISOString(), to: null, label: "last 14 days" };
    case "30d": return { from: new Date(now - 30 * DAY).toISOString(), to: null, label: "last 30 days" };
    case "all": return { from: null, to: null, label: "all time" };
    case "custom":
      return {
        from: range.from, to: range.to,
        label: `custom (${range.from ? range.from.slice(0, 16).replace("T", " ") : "..."} → ${range.to ? range.to.slice(0, 16).replace("T", " ") : "now"})`,
      };
  }
}

/** True when an ISO timestamp falls inside the resolved range. */
export function inTimeRange(ts: string | null | undefined,
                            range: TimeRange): boolean {
  if (!ts) return true;                       // undated rows stay visible
  const { from, to } = resolveTimeRange(range);
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return true;
  if (from && t < new Date(from).getTime()) return false;
  if (to && t > new Date(to).getTime()) return false;
  return true;
}

const RANGE_OPTIONS: { value: TimeRangePreset; label: string }[] = [
  { value: "today", label: "Today" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "14d", label: "Last 14 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "all", label: "All time" },
  { value: "custom", label: "Custom range" },
];

export function TimeRangePicker({ value, onChange, className }: {
  value: TimeRange;
  onChange: (r: TimeRange) => void;
  className?: string;
}) {
  const { label } = resolveTimeRange(value);
  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      <select
        value={value.preset}
        onChange={(e) => onChange({ ...value, preset: e.target.value as TimeRangePreset })}
        className="h-8 rounded-md border border-zinc-800 bg-zinc-900 px-2 text-xs text-zinc-300"
        aria-label="Time range">
        {RANGE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      {value.preset === "custom" && (
        <span className="flex items-center gap-1.5 text-xs text-zinc-500">
          <input
            type="datetime-local"
            value={value.from ? value.from.slice(0, 16) : ""}
            onChange={(e) => onChange({
              ...value,
              from: e.target.value ? new Date(e.target.value).toISOString() : null,
            })}
            className="h-8 rounded-md border border-zinc-800 bg-zinc-900 px-2 text-xs text-zinc-300"
            aria-label="From" />
          <span>&rarr;</span>
          <input
            type="datetime-local"
            value={value.to ? value.to.slice(0, 16) : ""}
            onChange={(e) => onChange({
              ...value,
              to: e.target.value ? new Date(e.target.value).toISOString() : null,
            })}
            className="h-8 rounded-md border border-zinc-800 bg-zinc-900 px-2 text-xs text-zinc-300"
            aria-label="To" />
        </span>
      )}
      <span className="hidden text-[10px] text-zinc-600 lg:inline">{label}</span>
    </div>
  );
}
