"use client";

/**
 * v0.14.0 RefreshControls - per-page manual refresh + selectable
 * auto-refresh (off / 10s / 30s / 1m / 5m).
 *
 * Why: users had to hit F5 in the BROWSER to see fresh data (Incidents,
 * Alert Center, DGA Activity, Threat Intel). Each page now carries its
 * own refresh button, and auto-refresh re-runs the page loader on a
 * chosen interval WITHOUT remounting (state & scroll preserved).
 * The chosen interval persists per page in localStorage.
 */

import { useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";

export const REFRESH_INTERVALS = [
  { value: 0, label: "Off" },
  { value: 10, label: "10 s" },
  { value: 30, label: "30 s" },
  { value: 60, label: "1 min" },
  { value: 300, label: "5 min" },
] as const;

const LS_KEY = "ndr-autorefresh-";

export function RefreshControls({
  onRefresh,
  loading = false,
  storageKey,
  title = "Refresh data",
  compact = false,
}: {
  /** Re-runs the page loader (must be idempotent & cheap to re-enter). */
  onRefresh: () => void | Promise<void>;
  /** True while the loader is in flight - the icon spins. */
  loading?: boolean;
  /** localStorage suffix, e.g. "incidents" -> ndr-autorefresh-incidents */
  storageKey: string;
  title?: string;
  /** Render without the surrounding card padding (header placement). */
  compact?: boolean;
}) {
  const [seconds, setSeconds] = useState<number>(() => {
    if (typeof window === "undefined") return 0;
    const raw = window.localStorage.getItem(LS_KEY + storageKey);
    const n = raw ? Number(raw) : 0;
    return REFRESH_INTERVALS.some((i) => i.value === n) ? n : 0;
  });
  const [spin, setSpin] = useState(false);
  const cbRef = useRef(onRefresh);
  cbRef.current = onRefresh;

  // manual refresh: optimistic spin for at least ~450ms so the click
  // always feels acknowledged even on instant loaders
  function manual() {
    setSpin(true);
    void Promise.resolve(cbRef.current()).finally(() => {
      window.setTimeout(() => setSpin(false), 450);
    });
  }

  // auto-refresh loop: one interval, reset when seconds changes
  useEffect(() => {
    window.localStorage.setItem(LS_KEY + storageKey, String(seconds));
    if (!seconds) return;
    const t = window.setInterval(() => {
      void Promise.resolve(cbRef.current());
    }, seconds * 1000);
    return () => window.clearInterval(t);
  }, [seconds, storageKey]);

  const spinning = loading || spin;

  return (
    <div
      className={`flex items-center gap-1.5 ${compact ? "" : "rounded-lg border border-zinc-800 bg-zinc-950/60 px-2 py-1.5"}`}
      title={`${title} + auto-refresh interval`}
    >
      <button
        onClick={manual}
        disabled={spinning}
        aria-label={title}
        className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-zinc-800 text-zinc-400 transition-colors hover:border-zinc-600 hover:text-zinc-100 disabled:opacity-60"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${spinning ? "animate-spin" : ""}`} />
      </button>
      <select
        value={seconds}
        onChange={(e) => setSeconds(Number(e.target.value))}
        aria-label="Auto-refresh interval"
        className="h-7 rounded-md border border-zinc-800 bg-zinc-950 px-1.5 text-[11px] text-zinc-300 outline-none focus:border-zinc-600"
      >
        {REFRESH_INTERVALS.map((i) => (
          <option key={i.value} value={i.value}>
            {i.value === 0 ? "Auto: off" : `Auto: ${i.label}`}
          </option>
        ))}
      </select>
    </div>
  );
}
