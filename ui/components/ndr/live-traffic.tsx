"use client";

// Live Traffic widget (v0.16.0 - requirement 19).
// SSE ke /api/metrics/live (tick 2 detik): EPS + antrean + alerts_5m/
// events_5m. Sengaja EventSource (bukan websocket) - tahan reverse-proxy
// dan tanpa dependensi baru. Data demo mode = simulasi pola harian.

import { Badge } from "@/components/ui/badge";
import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Gauge, Radio } from "lucide-react";
import {
  ResponsiveContainer, Line, LineChart,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";
import { DEMO_MODE } from "@/lib/ndr/api";
import type { LiveMetricTick } from "@/lib/ndr/types";
import { fmtNumber } from "./shared";

const MAX_POINTS = 150; // ~5 menit rolling pada tick 2 detik

function makeDemoTick(seq: number): LiveMetricTick {
  const wave = Math.sin(seq / 9) * 220 + Math.sin(seq / 3.3) * 60;
  const eps = Math.max(40, 320 + wave + (Math.random() * 40 - 20));
  return {
    ts: new Date().toISOString(),
    eps: Math.round(eps * 10) / 10,
    eps_by_engine: {
      suricata: Math.round(eps * 0.55),
      zeek: Math.round(eps * 0.45),
    },
    queue_depth: Math.max(0, Math.round(wave + 20)),
    queue_capacity: 8000,
    backlog_seconds: Math.max(0.1, Math.abs(wave) / 400),
    alerts_5m: Math.max(0, Math.round(seq / 40)),
    events_5m: Math.round(eps * 300),
  };
}

export function LiveTrafficWidget({ compact = false }: { compact?: boolean }) {
  const [points, setPoints] = useState<LiveMetricTick[]>([]);
  const [connected, setConnected] = useState(false);
  const [closed, setClosed] = useState(false);
  const seq = useRef(0);

  useEffect(() => {
    if (closed) return;
    if (DEMO_MODE) {
      const t = setInterval(() => {
        seq.current += 1;
        const tick = makeDemoTick(seq.current);
        setPoints((prev) => [...prev.slice(-(MAX_POINTS - 1)), tick]);
        setConnected(true);
      }, 2000);
      return () => clearInterval(t);
    }
    // SSE live: browser reconnect otomatis bila putus; onerror menandai
    // badge status, bukan mematikan widget (degrade jujur).
    let es: EventSource | null = null;
    try {
      es = new EventSource("/backend/api/metrics/live");
      es.onopen = () => setConnected(true);
      es.onmessage = (ev) => {
        try {
          const tick = JSON.parse(ev.data) as LiveMetricTick;
          setPoints((prev) => [...prev.slice(-(MAX_POINTS - 1)), tick]);
          setConnected(true);
        } catch { /* tick rusak diabaikan */ }
      };
      es.onerror = () => setConnected(false);
    } catch {
      setConnected(false);
    }
    return () => { es?.close(); };
  }, [closed]);

  const last = points[points.length - 1];
  const chart = points.map((p) => ({
    t: new Date(p.ts).toLocaleTimeString("id-ID",
      { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    eps: p.eps ?? null,
    alerts: p.alerts_5m ?? null,
    events: p.events_5m ?? null,
  }));

  const status = connected
    ? <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 gap-1">
        <Radio className="h-3 w-3" /> live
      </Badge>
    : <Badge variant="outline" className="text-zinc-400 gap-1">
        <AlertTriangle className="h-3 w-3" /> terputus
      </Badge>;

  if (compact) {
    return (
      <div className="flex items-center gap-2 text-xs text-zinc-400">
        {status}
        <span className="flex items-center gap-1">
          <Activity className="h-3.5 w-3.5 text-sky-400" />
          {last?.eps != null ? `${fmtNumber(last.eps)} eps` : "- eps"}
        </span>
        <span className="flex items-center gap-1">
          <Gauge className="h-3.5 w-3.5 text-amber-400" />
          {last?.queue_depth != null
            ? `${fmtNumber(last.queue_depth)} antrean`
            : "- antrean"}
        </span>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-sm font-medium text-zinc-200">
          <Activity className="h-4 w-4 text-sky-400" />
          Trafik Realtime (SSE 2 detik)
          {status}
        </div>
        <button
          className="text-xs text-zinc-500 hover:text-zinc-300"
          onClick={() => setPoints([])}>
          reset
        </button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
        <div className="rounded-lg bg-zinc-950/60 border border-zinc-800 p-2">
          <div className="text-xs text-zinc-500">EPS sekarang</div>
          <div className="text-lg font-semibold text-sky-300">
            {last?.eps != null ? fmtNumber(last.eps) : "-"}
          </div>
        </div>
        <div className="rounded-lg bg-zinc-950/60 border border-zinc-800 p-2">
          <div className="text-xs text-zinc-500">Alert / 5 menit</div>
          <div className="text-lg font-semibold text-rose-300">
            {last?.alerts_5m != null ? fmtNumber(last.alerts_5m) : "-"}
          </div>
        </div>
        <div className="rounded-lg bg-zinc-950/60 border border-zinc-800 p-2">
          <div className="text-xs text-zinc-500">Event / 5 menit</div>
          <div className="text-lg font-semibold text-emerald-300">
            {last?.events_5m != null ? fmtNumber(last.events_5m) : "-"}
          </div>
        </div>
        <div className="rounded-lg bg-zinc-950/60 border border-zinc-800 p-2">
          <div className="text-xs text-zinc-500">Antrean pipeline</div>
          <div className="text-lg font-semibold text-amber-300">
            {last?.queue_depth != null
              ? `${fmtNumber(last.queue_depth)}${last.queue_capacity
                ? ` / ${fmtNumber(last.queue_capacity)}`
                : ""}`
              : "-"}
          </div>
        </div>
      </div>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chart}>
            <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fill: "#71717a", fontSize: 10 }}
                   minTickGap={40} />
            <YAxis tick={{ fill: "#71717a", fontSize: 10 }} width={50} />
            <Tooltip contentStyle={{
              background: "#18181b", border: "#3f3f46",
              borderRadius: 8, fontSize: 12,
            }} />
            <Legend wrapperStyle={{ fontSize: 11, color: "#a1a1aa" }} />
            <Line type="monotone" dataKey="eps" name="EPS"
                  stroke="#38bdf8" dot={false} strokeWidth={2}
                  isAnimationActive={false} />
            <Line type="monotone" dataKey="events" name="Event/5m"
                  stroke="#34d399" dot={false} strokeWidth={1}
                  isAnimationActive={false} />
            <Line type="monotone" dataKey="alerts" name="Alert/5m"
                  stroke="#fb7185" dot={false} strokeWidth={1}
                  isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-xs text-zinc-500">
        Stream langsung dari pipeline health (req 19). Tab ditutup =
        koneksi berhenti otomatis; server menutup koneksi ke-21 dengan 429.
      </p>
    </div>
  );
}
